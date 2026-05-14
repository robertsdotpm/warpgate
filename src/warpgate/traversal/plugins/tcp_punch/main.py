"""Traversal plugin for TCP hole punching via coordinated port prediction.

Timeout budget (PLUGIN_CONF["timeout"] = 180):
  180 s = max-rendezvous-wait (window=42 + max_clock_error=20 ≈ 62 s)
        + primary spray (~3 s) + primary monitor (~3 s)
        + secondary rendezvous wait (window=42 s) for two-bucket dual-fire
        + secondary spray (~3 s) + secondary monitor (~3 s)
        + worker dispatch / engine setup overhead (varies by host,
          ~5-15 s on slow stacks)
        + the post-punch reverse-bridge accept (typically <1 s)
        + a safety margin for slow stacks (Vista / older BSDs) so the
          run_plugin wait_for doesn't cancel the awaiting
          reverse_server.accept before the worker has had a chance to
          connect back.  The previous 80 s left only ~10 s margin
          which the v13 sweep ate on slow pairs, manifesting as
          WinError 10061 on the worker's connect-back to a listener
          that had just been torn down by the cancellation
          propagating from the timeout firing.  XP cross-NAT
          tcp_punch is routed away to udp_punch / turn (see
          project_xp_tcp_punch_simul_open_rst memory) so the budget
          here doesn't need to accommodate XP specifically anymore.

PROTO_MESSAGES is consumed by plugin_loader: it merges each entry into
TraversalManager.sig_proto so PunchMsg dispatches without core
proto_msg.py edits.  Each tuple is (msg_class, strategy_enum, ttl_secs);
plugin_loader derives the wire name as "<plugin_name>.<class>" and
patches it onto the class -- no enum allocation needed.

route_types: NIC_BIND covers the same-LAN case (kernel handles local
routing for same-subnet peers); EXT_BIND covers the cross-WAN case via
predicted NAT mappings.  LOOPBACK_BIND has no NAT in the path and the
predict_alloc / rendezvous machinery produces no useful work over
loopback, so we opt out of it declaratively -- auto_combos won't
generate punch+LOOPBACK_BIND combos for us.

Platform gotchas: Windows Firewall and Windows Defender Real-Time
Protection can silently block or delay the punched TCP connections
even after the hole-punch exchange completes successfully.  Symptoms:
PunchMsg exchange finishes normally (both sides log the rendezvous),
the punch process runs, but the TCP connect never completes or the
first data packet is dropped.  During development / testing, disable
both Windows Defender Firewall (all profiles) and Windows Security >
Virus & threat protection > Real-time protection.  On production
machines the right fix is an explicit inbound/outbound allow rule for
the Python executable (or the specific port range used by the punch
allocator).
"""
import asyncio
import time
from aionetiface import log, fstr, NIC_BIND, EXT_BIND, TCP, SysClock, async_wrap_errors, cancel_task, get_running_loop, shutdown_proc_pool
from ....protocol.proto_defs import P2P_PUNCH
from .proto import PunchMsg
from .boundary_lib import FAST_PUNCH_PARAMS, PLUGIN_PIN_OFFSET, compute_rendezvous  # noqa: F401
from .punch_client import PunchClient
from .boundary_alloc import boundary_port_alloc
from .nat_predict_alloc import NATPredictAlloc
from .punch_defs import TCP_PUNCH_LAN
from .punch_process import start_punching_process
from .nat_predict import NATMapping
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ....node.node_utils import get_pp_executors

@register(phase="punch")
class PunchPlugin(Plugin):
    """Traversal plugin implementing TCP hole-punching via coordinated port prediction."""

    name = "tcp_punch"
    transport = TCP
    route_types = (NIC_BIND, EXT_BIND)
    conf = {"timeout": 180}
    proto_messages = (
        (PunchMsg, P2P_PUNCH, 20),
    )

    @classmethod
    async def setup(cls, node):
        if not node.conf.get("enable_punching", True):
            return None
        factory = await PunchPluginFactory.create(node.stun_clients, node.sys_clock)
        node.resources.punch_factory = factory
        node.resources.register(factory)
        return factory

    async def run(self, reply=None):
        """Coordinate the hole-punch exchange and launch the background punching process."""
        log("[PUNCH-RUN] enter plugin_id={0} reply={1} completed={2}".format(
            self.plugin_id,
            reply is not None,
            self.plugin_id in self.completed_pipe_ids,
        ))
        if self.plugin_id in self.completed_pipe_ids:
            log("[PUNCH-RUN] already completed; returning early plugin_id={0}".format(
                self.plugin_id,
            ))
            return

        # Pre-bucket clock-truth sanity check.  When a peer reply
        # carries tx_unix + clock_uncertainty (added 2026; older peers
        # send 0/0.0 and we fall through), check whether the inferred
        # skew between our clocks could possibly fit inside the
        # bucket's max_clock_error budget.  If not, bail out NOW
        # rather than waiting the full ~14 s rendezvous to discover
        # the punch missed.  Strictly a pre-bucket guard -- the bucket
        # algorithm itself remains the sole authority for fire time
        # (see the DO NOT replace... comment above
        # delayed_start_punching_proc).
        if reply is not None:
            peer_tx = getattr(reply.payload, "tx_unix", 0)
            if peer_tx:
                from .boundary_lib import FAST_PUNCH_PARAMS
                peer_unc = float(getattr(reply.payload, "clock_uncertainty", 0.0))
                our_unc = float(getattr(self.sys_clock, "uncertainty", 0.0))
                max_err = FAST_PUNCH_PARAMS.get("max_clock_error", 4)
                our_now = int(self.sys_clock.time())
                # Allow signal-channel latency on top of the clock
                # tolerance: a slow MQTT broker hop can easily add a
                # few seconds between tx_unix and arrival.  Budget
                # 10 s for signal latency; anything beyond that plus
                # the combined uncertainty plus the bucket tolerance
                # is a clock the bucket math cannot bridge.
                SIGNAL_LATENCY_BUDGET = 10
                budget = our_unc + peer_unc + max_err + SIGNAL_LATENCY_BUDGET
                skew = abs(our_now - peer_tx)
                if skew > budget:
                    log("[PUNCH-RUN] pre-bucket bailout: clock skew "
                        "{0}s exceeds budget {1}s (our_unc={2:.2f} "
                        "peer_unc={3:.2f} max_err={4} latency={5}); "
                        "plugin_id={6}".format(
                            skew, int(budget), our_unc, peer_unc,
                            max_err, SIGNAL_LATENCY_BUDGET,
                            self.plugin_id,
                        ))
                    if not self.result.done():
                        self.result.set_result(None)
                    return

        # --- Get or create the PunchClient for this session ---
        puncher = self.punch_clients.get(self.plugin_id)
        if puncher is None:
            # First call: build a PunchClient with routing, timing, and port allocators.
            log("[PUNCH-RUN] first call; setup_puncher_client plugin_id={0}".format(
                self.plugin_id,
            ))
            try:
                puncher, stuns = await self.setup_puncher_client(reply)
            except BaseException as exc:
                raise
            if puncher is None:
                log("[PUNCH-RUN] PunchPlugin: no STUN clients available; aborting punch.")
                if not self.result.done():
                    self.result.set_result(None)
                return

            # A concurrent run() may have raced through the await above and already
            # registered a client.  Reuse it to avoid a duplicate punching process.
            puncher = self.punch_clients.get(self.plugin_id) or puncher
            if self.plugin_id not in self.punch_clients:
                log("[PUNCH-RUN] configure_puncher_process plugin_id={0}".format(
                    self.plugin_id,
                ))
                try:
                    puncher = await self.configure_puncher_process(puncher, stuns)
                except BaseException as exc:
                    raise
        else:
            log("[PUNCH-RUN] reusing existing puncher plugin_id={0}".format(
                self.plugin_id,
            ))

        # --- Advance the NAT traversal exchange ---
        # Each call computes the next round of port predictions and checks
        # whether both sides have exchanged enough mappings to attempt punching.
        try:
            outgoing_msg = await self.advance_punching_protocol(
                puncher, reply, puncher.punch_time
            )
        except BaseException as exc:
            raise

        # Instrumentation: when a reply with mappings just landed, log
        # the round-trip from our outgoing send to this receipt.  The
        # send timestamp is stashed on self.outgoing_sent_at below
        # before send_signal fires.
        if (reply is not None
                and getattr(self, "outgoing_sent_at", None) is not None):
            rtt_ms = int((time.time() - self.outgoing_sent_at) * 1000)
            log("[PUNCH-RTT] tcp_punch signal_rtt={0}ms plugin_id={1}".format(
                rtt_ms, self.plugin_id,
            ))
            self.outgoing_sent_at = None

        # None signals the exchange is complete; the background punch process
        # takes it from here.
        if outgoing_msg is None:
            log("[PUNCH-RUN] advance returned None; exchange done plugin_id={0}".format(
                self.plugin_id,
            ))
            return

        # --- Send our port predictions to the peer ---
        log("[PUNCH-RUN] sending outgoing PunchMsg plugin_id={0}".format(self.plugin_id))
        self.outgoing_sent_at = time.time()
        await self.send_signal(outgoing_msg)

    async def setup_puncher_client(self, reply):
        """
        Determines the source/destination addresses and the decider IP,
        creates a new PunchClient, and sets the coordinated time references.
        """
        if_index = self.src["if_index"]
        # Safe two-level lookup: load_stun_clients populates entries
        # only for the (af, if_index) combinations that successfully
        # resolved a STUN server during node startup. On hosts where
        # v6 STUN never came up (Vista without a working v6 path, or
        # any host where the v6 default route briefly flapped at
        # startup) the inner dict is missing the if_index entirely,
        # and bare self.stun_clients[af][if_index] raises KeyError
        # before the "no STUN clients loaded" guard below ever runs.
        stuns = self.stun_clients.get(self.af, {}).get(if_index, [])

        # Lazy retry: load_stun_clients ran once at node startup and
        # cached whatever get_n_stun_clients returned. The win10 /
        # win81 mobile-NIC paths and Windows v6 STUN paths on this
        # matrix periodically come back empty when the STUN servers
        # were temporarily unreachable at startup; the cached
        # emptiness then disables the punch responder for the rest
        # of the process. Retry once on first responder run -- by
        # the time an inbound PunchMsg arrives, the path is usually
        # working again. This was observed in 9 listener logs across
        # the v4 + v6 sweeps (always win10 or win81).
        if not stuns:
            from aionetiface import (
                get_n_stun_clients, TCP, RFC5389, USE_MAP_NO,
            )
            from .punch_defs import PUNCH_CONF
            try:
                retry = await asyncio.wait_for(
                    get_n_stun_clients(
                        af=self.af, n=USE_MAP_NO, mode=RFC5389,
                        interface=self.nic, proto=TCP, conf=PUNCH_CONF,
                    ),
                    timeout=4.0,
                )
            except (OSError, ConnectionError, asyncio.TimeoutError):
                retry = None
            if retry:
                stuns = retry
                self.stun_clients.setdefault(self.af, {})[if_index] = retry

        # Skip if no STUN clients loaded.
        if not stuns:
            return None, None

        # Resolved by the manager via resolve_pair: src["ip"] is
        # the local-bind IP and dest["ip"] is the dial target,
        # already %scope-patched for v6 link-local and chosen for the
        # active route_type (NIC_BIND vs EXT_BIND). No routing logic
        # in the plugin.
        src_ip = self.src["ip"]
        dest_ip = self.dest["ip"]

        # Defensive: punching to our own resolved bind IP is a malformed
        # configuration -- the rendezvous would loop back through the
        # local stack and the port-prediction state machine has
        # historically crashed the whole node when it tries it.
        if src_ip and dest_ip and str(src_ip) == str(dest_ip):
            log("PunchPlugin: dest matches own bind IP ({0}); aborting".format(dest_ip))
            return None, None

        # Master/slave role selection works fine off the local bind IP
        # for both NIC_BIND and EXT_BIND -- both peers see the same
        # (src_ip, dest_ip) pair from opposite ends and pick the same
        # role deterministically.
        decider_ip = src_ip

        # Create and configure the PunchClient.
        # FAST_PUNCH_PARAMS is used for network-protocol punching: the punch_time
        # is communicated between peers via PunchMsg so we do not need the large
        # WINDOW / MAX_CLOCK_ERROR values used by the CLI standalone mode.  The
        # tight window (6 s) and short reply_delay (0.5 s, plus the
        # mapping_reply future short-circuiting it on healthy paths)
        # cut total punch latency roughly in half compared to the
        # conservative CLI defaults.
        puncher = PunchClient(
            dest_ip,
            src_ip,
            decider_ip,
            self.nic.get_nic_id(self.af),
            same_machine=self.same_machine,
            params=FAST_PUNCH_PARAMS,
            our_os=(self.src_map.get("os") if self.src_map else None),
            their_os=(self.dest_map.get("os") if self.dest_map else None),
        )

        # Set coordinated time references.
        timestamp = self.sys_clock.time()
        puncher.set_timestamp(timestamp)

        # NTP-pinned future start.  The connector picks an absolute
        # punch moment (now + PLUGIN_PIN_OFFSET) and the listener reads
        # the value back out of the inbound PunchMsg's payload.ntp
        # field.  No bucket math, no compute_rendezvous, no two-bucket
        # secondary -- both sides agree on one wall-clock instant via
        # the signal exchange itself.  The CLI standalone path in
        # punch_client.py __main__ keeps compute_rendezvous because it
        # has no PunchMsg channel to communicate the pin.
        if reply is not None and getattr(reply.payload, "ntp", 0):
            # Listener: take the connector's pinned moment verbatim.
            punch_time = float(reply.payload.ntp)
        else:
            # Connector: pin a near-future absolute moment.
            punch_time = timestamp + PLUGIN_PIN_OFFSET

        puncher.set_punch_time(punch_time)

        # Deterministic predictions based on boundary math.
        # PunchClient.add_port_allocator forwards self.params to the allocator
        # so it uses the same window / error constants for bucket derivation.
        puncher.add_port_allocator(boundary_port_alloc)

        # Return the new puncher and the STUN clients
        return puncher, stuns

    async def configure_puncher_process(self, puncher, stuns):
        """
        Initializes the NAT Prediction Allocator, saves the PunchClient,
        and schedules the delayed asynchronous punching process.
        """
        # Register the puncher so subsequent run() calls can find it.
        self.punch_clients[self.plugin_id] = puncher

        # Initialize the NAT prediction allocator.
        # Note: this just wraps nat_predict.py.
        # There's an aweful lot of bloat just to use code thats already written.
        self.nat_alloc = NATPredictAlloc(stuns)
        self.nat_alloc.set_nat_info(self.src["nat"], self.dest["nat"])
        self.nat_alloc.set_punch_mode(self.same_machine, self.dest["ip"])

        # Future the worker-spawn task waits on instead of sleeping a
        # fixed interval.  advance_punching_protocol resolves it the
        # moment the peer's mappings have been folded into
        # puncher.port_allocs; the worker spawns as soon as that
        # happens rather than at a pessimistic timer mark.  A
        # wait_for(reply_delay) in delayed_start_punching_proc bounds
        # the wait so a lost / late signal doesn't stall the worker
        # indefinitely (LAN-mode short-circuit, which never folds in
        # peer mappings, falls through the timeout and uses the
        # boundary-aligned port_allocs that setup_puncher_client
        # already populated).
        self.mapping_reply = asyncio.get_event_loop().create_future()

        # Schedule the punching process.
        if self.plugin_id not in self.punch_proc:
            self.punch_proc[self.plugin_id] = asyncio.create_task(
                async_wrap_errors(self.delayed_start_punching_proc(self.nic, puncher))
            )

        return puncher

    async def advance_punching_protocol(self, puncher, reply, punch_time):
        """Compute the next round of port predictions and return an outgoing PunchMsg, or None when done."""
        # For LAN, STUN is useless (returns each side's own port).
        # Boundary ports from setup_puncher_client already align both sides.
        # Sender's clock witness: NTP time at moment of send + bounded
        # uncertainty from SysClock's Marzullo intersection.  The
        # receiver uses these to abort doomed punches BEFORE the 14 s
        # rendezvous wait (see PunchPlugin.run pre-bucket bailout).
        tx_unix = int(self.sys_clock.time())
        clock_uncertainty = float(getattr(self.sys_clock, "uncertainty", 0.0))

        # Send one empty PunchMsg to trigger the recipient; return None on reply.
        if self.nat_alloc.punch_mode == TCP_PUNCH_LAN:
            if reply is not None:
                return None
            msg = PunchMsg(
                {
                    "payload": {
                        "punch_mode": self.nat_alloc.punch_mode,
                        "mappings": [],
                        "ntp": punch_time,
                        "tx_unix": tx_unix,
                        "clock_uncertainty": clock_uncertainty,
                    },
                }
            )
            msg.meta.plugin_name = "tcp_punch"
            return msg

        # Convert raw mappings from the peer into internal objects.
        recv_mappings = None
        if reply is not None:
            recv_mappings = [NATMapping(m) for m in reply.payload.mappings]
            if not recv_mappings:
                log("[TCP-PUNCH] advance_punching_protocol: peer sent empty mappings list; dropping")
                return None

        # Re-entry guard: same shape as udp_punch's guard.  sidewire
        # republishes the punch msg until app-ack'd, and the
        # multi-broker fan-out means several duplicates can arrive at
        # the listener within seconds.  Each one re-enters run() and
        # lands here; nat_alloc.port_alloc() walks a state machine
        # that asserts on invalid progressions, so the second call
        # raises AssertionError.  Drop duplicates once port_allocs is
        # already populated.
        if recv_mappings is not None and puncher.port_allocs:
            log(fstr(
                "[TCP-PUNCH] advance_punching_protocol: duplicate reply "
                "ignored (port_allocs already populated, plugin_id={0})",
                (self.plugin_id,),
            ))
            return None

        # Compute the next round of port predictions.
        port_alloc, is_end = await self.nat_alloc.port_alloc(recv_mappings)
        puncher.port_allocs += port_alloc

        # Signal the worker-spawn task: the peer's mappings have been
        # folded in and port_allocs is now valid.  Guarded by not done()
        # because advance_punching_protocol may be re-entered across
        # signal rounds (mapping refresh), and resolving an
        # already-resolved future raises InvalidStateError.
        reply_future = getattr(self, "mapping_reply", None)
        if reply_future is not None and not reply_future.done():
            reply_future.set_result(True)

        # End of protocol.
        if is_end == 1:
            return None

        # Gather our mappings and build the outgoing control message.
        mappings = [m.to_json() for m in self.nat_alloc.send_mappings]
        msg = PunchMsg(
            {
                "payload": {
                    "punch_mode": self.nat_alloc.punch_mode,
                    "mappings": mappings,
                    "ntp": punch_time,
                    "tx_unix": tx_unix,
                    "clock_uncertainty": clock_uncertainty,
                },
            }
        )

        msg.meta.plugin_name = "tcp_punch"
        return msg

    # DO NOT replace the bucket algorithm. The bucket algorithm
    # (compute_rendezvous / quantized_bucket / sleep_until in run_engine)
    # is the sole authority for WHEN punch sockets fire. It uses NTP-quorum
    # SysClock so both peers agree on the same fire moment via their
    # respective clocks -- no RTT measurement, ACK-relative timing, or
    # other "let's get the peers in sync" scheme is needed or wanted at
    # this layer. reply_delay below is the timeout ceiling on the
    # mapping_reply future -- normally the future resolves the moment
    # advance_punching_protocol has folded the peer's mappings into
    # puncher.port_allocs, and the worker spawns immediately.  Only the
    # pathological "peer's signal never arrived" path actually consumes
    # the full reply_delay before the worker proceeds anyway with
    # whatever port_allocs are already set.  Do NOT make reply_delay
    # derive from RTT or anything else clock-adjacent -- it's a
    # fallback ceiling, not a synchronisation primitive.
    async def delayed_start_punching_proc(self, nic, puncher):
        """Wait for mapping_reply (or reply_delay timeout) then launch the punching process and resolve the result."""
        reply_delay = puncher.params.get("reply_delay", 2.0)
        log("[PUNCH-DELAY] enter plugin_id={0} reply_delay={1}s".format(
            self.plugin_id, reply_delay,
        ))
        try:
            try:
                await asyncio.wait_for(self.mapping_reply, reply_delay)
                log("[PUNCH-DELAY] mapping_reply resolved; calling start_punching_process plugin_id={0}".format(
                    self.plugin_id,
                ))
            except asyncio.TimeoutError:
                log("[PUNCH-DELAY] mapping_reply timed out after {0}s; proceeding plugin_id={1}".format(
                    reply_delay, self.plugin_id,
                ))
            pipe = await start_punching_process(
                nic,
                puncher,
                self.stop_reader,
                self.proc_pool,
                node_msg_cb=getattr(self, "node_msg_cb", None),
            )
            log("[PUNCH-DELAY] start_punching_process returned plugin_id={0} pipe={1}".format(
                self.plugin_id, pipe is not None,
            ))

            # Guard against a second concurrent call resolving the same future,
            # which would raise asyncio.InvalidStateError.
            if not self.result.done():
                self.result.set_result(pipe)
            elif pipe is not None:
                # result was already cancelled/resolved by race_combos while
                # start_punching_process was in flight; close the orphaned pipe.
                await async_wrap_errors(pipe.close())
        except asyncio.CancelledError:
            log("[PUNCH-DELAY] CANCELLED plugin_id={0}".format(self.plugin_id))
            raise
        except Exception as exc:  # pylint: disable=broad-except
            log("[PUNCH-DELAY] EXCEPTION plugin_id={0} {1}: {2}".format(
                self.plugin_id, type(exc).__name__, repr(exc),
            ))
            raise
        finally:
            # Per-run cleanup intentionally does NOT pop punch_proc /
            # punch_clients here. Popping mid-run lets a peer's follow-up
            # signal re-enter run() and spawn a SECOND engine task with
            # the same predicted ports while the first worker is still
            # holding them -- bind_punch_sockets then fails 4/4 with
            # EADDRINUSE 10048 and the bridge is wired to a dead engine.
            # close() is the only place that pops; cleanup semantics
            # will be revisited in a dedicated session.
            log("[PUNCH-DELAY] finally plugin_id={0}".format(self.plugin_id))
            self.completed_pipe_ids.add(self.plugin_id)

    async def close(self):
        """Cancel any in-flight punch task and remove this plugin's shared state.

        Safe to call multiple times: pop() is a no-op when the key is absent
        and task/future guards check done() before acting.
        """
        task = self.punch_proc.pop(self.plugin_id, None)
        self.punch_clients.pop(self.plugin_id, None)
        log("[PUNCH-CLOSE] plugin_id={0} task_was_pending={1}".format(
            self.plugin_id,
            task is not None and not task.done() if task else False,
        ))
        await cancel_task(task)

        # Cancel the result future if nobody resolved it (e.g. outer timeout).
        if not self.result.done():
            self.result.cancel()
        self.completed_pipe_ids.add(self.plugin_id)


class PunchPluginFactory:
    """Creates and configures PunchPlugin instances sharing STUN clients and process pools."""

    def __init__(
self,
        stun_clients,
        sys_clock=None,
        punch_clients=None,
        proc_pool=None,
    ):
        self.stun_clients = stun_clients
        self.sys_clock = sys_clock or SysClock(None, 0.1)
        self.proc_pool = proc_pool
        self.max_workers = 0
        self.punch_clients = punch_clients if punch_clients is not None else {}
        self.punch_proc = {}
        self.completed_pipe_ids = set()

    @classmethod
    async def create(cls, stun_clients, sys_clock):
        """Async factory that allocates a process pool executor and returns a ready factory."""
        factory = cls(stun_clients, sys_clock)
        factory.max_workers, factory.proc_pool = await get_pp_executors()
        factory.active_punchers = 0
        return factory

    def build_plugin(self):
        """Create a new PunchPlugin wired to this factory's shared STUN clients and state."""
        plugin = PunchPlugin()
        plugin.stun_clients = self.stun_clients
        plugin.sys_clock = self.sys_clock
        plugin.proc_pool = self.proc_pool
        plugin.punch_clients = self.punch_clients
        plugin.punch_proc = self.punch_proc
        plugin.completed_pipe_ids = self.completed_pipe_ids
        return plugin

    async def close(self):
        """Shut down the process pool executor used for running punch workers."""
        if not self.proc_pool:
            return
        await shutdown_proc_pool(self.proc_pool)
        self.proc_pool = None


