"""Traversal plugin for UDP hole-punching with predictable NAT mappings.

Mirrors tcp_punch.PunchPlugin's protocol exchange (NAT prediction +
boundary-time rendezvous) but uses a UDP engine for the actual fire/
verify phase.  UDP requires no SYN-ACK so the engine returns its
result socket directly -- no process pool, no reverse-connect tunnel.

Like tcp_punch, this plugin opts out of LOOPBACK_BIND: the loopback
path has no NAT to traverse so port prediction does no useful work.
For symmetric NAT pairs, use the random_probe plugin instead --
udp_punch only handles cone NATs and predictable-symmetric NATs.
"""
import asyncio
import os
import socket as _socket

from aionetiface import (
    EXT_BIND, NIC_BIND, Pipe, SysClock, UDP, fstr, get_running_loop, log, log_exception,
    rand_b,
)
from aionetiface.net.selector_proxy import selector_proxy

from ....protocol.proto_defs import P2P_PUNCH
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ..tcp_punch.boundary_alloc import boundary_port_alloc
from ..tcp_punch.boundary_lib import (
    PLUGIN_PIN_OFFSET, PLUGIN_PIN_OFFSET_PREDICT,
    compute_rendezvous,  # noqa: F401
)
from aionetiface.nic.nat.nat_defs import EQUAL_DELTA, NA_DELTA
from ..tcp_punch.nat_predict import NATMapping
from ..tcp_punch.nat_predict_alloc import NATPredictAlloc
from ..tcp_punch.punch_client import PunchClient
from ..tcp_punch.punch_defs import TCP_PUNCH_LAN, TCP_PUNCH_REMOTE
from .proto import UdpPunchMsg
from .udp_punch_defs import (
    UDP_PUNCH_FRAME_LEN,
    UDP_PUNCH_MAGIC,
    UDP_PUNCH_NONCE_LEN,
    UDP_PUNCH_PARAMS,
    parse_frame,
)
from .udp_punch_engine import drain_punch_residue, udp_punch_engine


@register(phase="spray")
class UdpPunchPlugin(Plugin):
    """Traversal plugin implementing UDP hole-punching via coordinated port prediction."""

    name = "udp_punch"
    transport = UDP
    # Same exclusions as tcp_punch -- loopback has no NAT so prediction
    # does no useful work over it. Symmetric NAT goes to random_probe,
    # not here.
    route_types = (NIC_BIND, EXT_BIND)
    # 15s gives engine + bridge enough headroom on Windows.  The 5s value
    # was right at the edge: spray (1.5s) + watch (1.5s) + signal_rtt
    # (~1s) + clock_settle (~0.6s) lands ~5s; cleanup_loop checks
    # expires_at every 5s and reaped the plugin mid-bridge when the
    # engine ran long, killing master's CONFIRM-send before the wire
    # got it.  Wire capture showed Win10's PROBEs arriving at p2pd.net
    # but zero Out packets from p2pd.net in response.
    conf = {"timeout": 15}
    proto_messages = (
        (UdpPunchMsg, P2P_PUNCH, 20),
    )

    @classmethod
    async def setup(cls, node):
        if not node.conf.get("enable_punching", True):
            return None
        factory = await UdpPunchPluginFactory.create(node.stun_clients, node.sys_clock)
        # Late-claim NIC ownership: stash on the factory so the first
        # plugin run claims at engine-start time.  Eager claim here
        # would raise on collision, which the loader swallows -- and
        # udp_punch would silently drop out of the registry.  Late
        # surfacing only flags collisions when an actual punch attempt
        # would have failed anyway.
        claims = []
        for nic in node.ifs:
            nic_id = getattr(nic, "id", None)
            if not nic_id:
                continue
            for af in nic.supported():
                try:
                    primary_ip = nic.nic(af)
                except (ValueError, LookupError, AttributeError):
                    primary_ip = None
                if primary_ip:
                    claims.append((nic_id, str(primary_ip), af))
        factory.pending_claims = claims
        return factory

    async def run(self, reply=None):
        """Coordinate the punch exchange and fire the in-process UDP engine."""
        # Pre-bucket clock-truth sanity check (mirrors tcp_punch's
        # equivalent at the top of its run()).  If the peer's reply
        # carries a tx_unix timestamp and the observed skew is larger
        # than what (clock_uncertainty + max_clock_error + signal
        # latency budget) can bridge, the bucket math literally cannot
        # converge -- bail immediately rather than waste ~5 s of
        # rendezvous wait + spray on a doomed punch.  The bucket
        # algorithm itself remains the sole authority for fire time
        # (see DO NOT comment above tcp_punch.delayed_start_punching_proc).
        if reply is not None:
            peer_tx = getattr(reply.payload, "tx_unix", 0)
            if peer_tx:
                peer_unc = float(getattr(reply.payload, "clock_uncertainty", 0.0))
                our_unc = float(getattr(self.sys_clock, "uncertainty", 0.0))
                max_err = UDP_PUNCH_PARAMS.get("max_clock_error", 4)
                our_now = int(self.sys_clock.time())
                SIGNAL_LATENCY_BUDGET = 10
                budget = our_unc + peer_unc + max_err + SIGNAL_LATENCY_BUDGET
                skew = abs(our_now - peer_tx)
                if skew > budget:
                    log("[UDP-PUNCH-RUN] pre-bucket bailout: clock skew "
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

        puncher = self.punch_clients.get(self.plugin_id)
        if puncher is None:
            puncher, stuns = await self.setup_puncher_client(reply)
            if puncher is None:
                log("UdpPunchPlugin: no STUN clients available; aborting punch.")
                if not self.result.done():
                    self.result.set_result(None)
                return

            # Concurrent run() may have raced through; reuse the registered client.
            puncher = self.punch_clients.get(self.plugin_id) or puncher
            if self.plugin_id not in self.punch_clients:
                puncher = await self.configure_puncher_process(puncher, stuns)

        # Compute the next round of port predictions.
        outgoing_msg = await self.advance_punching_protocol(
            puncher, reply, puncher.punch_time
        )

        # Instrumentation: log signal RTT when a reply with mappings
        # just landed.  Mirrors tcp_punch/main.py's PUNCH-RTT line.
        if (reply is not None
                and getattr(self, "outgoing_sent_at", None) is not None):
            import time as _time
            rtt_ms = int((_time.time() - self.outgoing_sent_at) * 1000)
            log("[PUNCH-RTT] udp_punch signal_rtt={0}ms plugin_id={1}".format(
                rtt_ms, self.plugin_id,
            ))
            self.outgoing_sent_at = None

        # None signals the exchange is complete; the in-process engine
        # task takes over from here.
        if outgoing_msg is None:
            return

        # The first message in a session carries the session nonce so the
        # peer knows what magic to look for in inbound probes. We attach
        # it on every outbound -- repeated copies cost nothing and let
        # late-arriving peers join.
        # send_mappings is only populated after nat_alloc.port_alloc()
        # runs; the TCP_PUNCH_LAN short-circuit in
        # advance_punching_protocol returns before that call so the
        # attribute may not exist. Default to whatever the LAN path
        # already put on payload.mappings (empty list).
        send_mappings = getattr(self.nat_alloc, "send_mappings", None)
        if send_mappings:
            outgoing_msg.payload.mappings = [
                m.to_json() for m in send_mappings
            ]

        import time as _time
        self.outgoing_sent_at = _time.time()
        await self.send_signal(outgoing_msg)

    async def setup_puncher_client(self, reply):
        """Build a fresh PunchClient + decide on a session nonce for this attempt."""
        if_index = self.src["if_index"]
        # Safe two-level lookup; same rationale as tcp_punch's
        # setup_puncher_client: hosts without working v6 STUN
        # (XP / Vista) never populate the inner dict for
        # (af=AF_INET6, if_index), and bare indexing raises KeyError
        # before the "no STUN clients loaded" guard runs.
        stuns = self.stun_clients.get(self.af, {}).get(if_index, [])
        # Lazy retry mirrors tcp_punch.setup_puncher_client: empty
        # cached lists from startup get a one-shot retry here so
        # the responder isn't disabled for the whole process when
        # STUN happened to be temporarily unreachable on first
        # boot. See tcp_punch comment for the matrix data behind
        # this.
        if not stuns:
            from aionetiface import (
                get_n_stun_clients, RFC5389, TCP, USE_MAP_NO,
            )
            from ..tcp_punch.punch_defs import PUNCH_CONF
            try:
                # proto=TCP matches load_stun_clients in
                # node_utils so the cache slot we're filling stays
                # consistent with what tcp_punch sees on the same
                # (af, if_index). NATPredictAlloc only uses these
                # for STUN-protocol port-mapping prediction; the
                # transport doesn't matter to it.
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
        if not stuns:
            return None, None

        # Resolved by the manager via resolve_pair: src["ip"] is
        # the local-bind IP and dest["ip"] is the dial target,
        # already %scope-patched for v6 link-local and chosen for the
        # active route_type (NIC_BIND vs EXT_BIND). No routing logic
        # in the plugin.
        src_ip = self.src["ip"]
        dest_ip = self.dest["ip"]

        # Defensive: punching to our own resolved bind IP would loop
        # the predictions back through the local stack with no NAT
        # involvement.
        if src_ip and dest_ip and str(src_ip) == str(dest_ip):
            log("UdpPunchPlugin: dest matches own bind IP ({0}); aborting".format(dest_ip))
            return None, None

        # delayed_run_engine forwards puncher.route to the engine for
        # NIC pinning; bind it via the Plugin.bind helper to use the
        # already-resolved src_ip.
        route = await self.bind()

        # Master/slave role selection works fine off the local bind IP
        # for both NIC_BIND and EXT_BIND -- both peers see the same
        # (src_ip, dest_ip) pair from opposite ends and pick the same
        # role deterministically.
        decider_ip = src_ip

        puncher = PunchClient(
            dest_ip,
            src_ip,
            decider_ip,
            self.nic.get_nic_id(self.af),
            same_machine=self.same_machine,
            params=UDP_PUNCH_PARAMS,
            our_os=(self.src_map.get("os") if self.src_map else None),
            their_os=(self.dest_map.get("os") if self.dest_map else None),
        )
        # Attach the bound route so delayed_run_engine can forward it
        # to bind_punch_sockets for NIC pinning. PunchClient itself is
        # tcp_punch's API and stays unaware of route -- udp_punch
        # alone needs this for multi-NIC correctness.
        puncher.route = route

        # Session nonce: pulled from the peer's first message if we're
        # the responder, otherwise generated locally and sent on our
        # outgoing PunchMsg.payload.mappings (we tag it onto every msg
        # via this object so both sides converge to the same value).
        if reply is not None and getattr(reply.payload, "nonce", None):
            try:
                puncher.udp_nonce = bytes.fromhex(reply.payload.nonce)
            except (ValueError, TypeError):
                puncher.udp_nonce = rand_b(UDP_PUNCH_NONCE_LEN)
        else:
            puncher.udp_nonce = rand_b(UDP_PUNCH_NONCE_LEN)

        timestamp = self.sys_clock.time()
        puncher.set_timestamp(timestamp)

        # NTP-pinned future start (ported from tcp_punch).  The
        # connector picks ONE absolute punch moment and ships it in the
        # outgoing PunchMsg; the listener reads it back out of
        # payload.ntp and uses it verbatim.  This replaces
        # compute_rendezvous bucket math, whose independent per-peer
        # quantisation forked when two peers' calls straddled a bucket
        # boundary -- the pair then fired seconds apart and zero
        # sockets converged.  One shared punch_time = no fork.
        #
        # boundary_port_alloc derives ports deterministically from the
        # time bucket; that only matches the peer's real external
        # ports when BOTH NATs allocate predictably (EQUAL_DELTA, or
        # NA_DELTA = no NAT).  For INDEPENDENT / DEPENDENT / RANDOM /
        # PRESERV deltas the bucket-derived ports are wrong, so the
        # boundary allocator is skipped and the punch relies solely on
        # the STUN NAT predictor (advance_punching_protocol ->
        # nat_alloc.port_alloc).  The same flag picks the pin offset:
        # the predictor path runs 3 STUN round trips on the listener
        # before it can fire, which does not fit in PLUGIN_PIN_OFFSET,
        # so it gets the larger PLUGIN_PIN_OFFSET_PREDICT.  Mirrors
        # tcp_punch.setup_puncher_client.
        src_delta = (self.src.get("nat") or {}).get("delta") or {}
        dest_delta = (self.dest.get("nat") or {}).get("delta") or {}
        boundary_ok = (
            src_delta.get("type") in (EQUAL_DELTA, NA_DELTA)
            and dest_delta.get("type") in (EQUAL_DELTA, NA_DELTA)
        )
        pin_offset = PLUGIN_PIN_OFFSET if boundary_ok else PLUGIN_PIN_OFFSET_PREDICT

        if reply is not None and getattr(reply.payload, "ntp", 0):
            # Listener: take the connector's pinned moment verbatim.
            punch_time = float(reply.payload.ntp)
        else:
            # Connector: pin a near-future absolute moment.
            punch_time = timestamp + pin_offset
        puncher.set_punch_time(punch_time)

        if boundary_ok:
            # n=1, single socket per side.  The old n=2 two-bucket
            # overlap existed only to survive the bucket-fork: forked
            # peers picked {B,B+1} and {B+1,B+2}, overlapping on
            # exactly one bucket, so n=2 guaranteed one matching pair.
            # With NTP-pin there is no fork -- both peers derive
            # identical buckets -- so n=2 would instead yield TWO
            # matching pairs, and UDP's first-CONFIRM-wins race is
            # only safe with exactly ONE candidate socket per side.
            # n=1 restores that single deterministic candidate.
            # Seeded with punch_time so both peers (sharing punch_time
            # verbatim) derive the same bucket regardless of local-
            # clock skew between their create_puncher calls.
            puncher.add_port_allocator(boundary_port_alloc, n=1, seed=punch_time)
        elif os.environ.get("WG_DISABLE_PREDICT", "").strip() == "1":
            # Predictor is also disabled, so without forcing the boundary
            # allocator we'd end up with port_allocs=[] and the engine
            # would bind 0/0 sockets and abort.  Force the deterministic
            # boundary path even though delta != EQUAL/NA so the punch
            # still has SOMETHING to fire from.  The candidate port may
            # not match what the peer's actual NAT picks (because the
            # delta isn't EQUAL), so this is best-effort -- it's the
            # only path we have under WG_DISABLE_PREDICT.
            log(fstr(
                "[UDP-PUNCH] WG_DISABLE_PREDICT=1 forces boundary_port_alloc "
                "despite non-EQUAL delta (src={0} dest={1})",
                (src_delta.get("type"), dest_delta.get("type")),
            ))
            puncher.add_port_allocator(boundary_port_alloc, n=1, seed=punch_time)
        else:
            log(fstr(
                "[UDP-PUNCH] non-deterministic NAT delta "
                "(src={0} dest={1}); skipping boundary_port_alloc, "
                "using STUN NAT predictor only",
                (src_delta.get("type"), dest_delta.get("type")),
            ))

        return puncher, stuns

    async def configure_puncher_process(self, puncher, stuns):
        """Register the puncher and schedule the in-process punch engine."""
        self.punch_clients[self.plugin_id] = puncher

        # WG_DISABLE_PREDICT=1 skips the STUN-based NAT predictor, so the
        # punch runs with the boundary_port_alloc fast-path only (n=1
        # deterministic socket per side derived from the NTP bucket).
        # Diagnostic: predictor adds 8 socket spray with multi-port
        # destinations, which on consumer routers / lossy paths produces
        # n*sprays packets that overshoot per-host UDP burst thresholds
        # and starve out the boundary socket's traffic.  With predictor
        # off, master sprays 1 socket * 50Hz * 3s = 150 packets total
        # instead of ~2550; the one deterministic candidate is enough
        # for EQUAL+EQUAL or EQUAL+NA pairs (boundary_port_alloc's
        # supported set).  Punches that genuinely need predictor (PRESERV
        # / INDEPENDENT / DEPENDENT / RANDOM on either side) will fail
        # under this flag; that's the trade-off for a clean test signal.
        if os.environ.get("WG_DISABLE_PREDICT", "").strip() == "1":
            log("[UDP-PUNCH] WG_DISABLE_PREDICT=1; skipping NATPredictAlloc")
            self.nat_alloc = None
        else:
            self.nat_alloc = NATPredictAlloc(stuns)
            self.nat_alloc.set_nat_info(self.src["nat"], self.dest["nat"])
            self.nat_alloc.set_punch_mode(self.same_machine, self.dest["ip"])

        # Future the engine task waits on instead of sleeping a fixed
        # interval.  advance_punching_protocol resolves it the moment
        # the peer's mappings have been folded into puncher.port_allocs;
        # the engine wakes up as soon as that happens rather than at a
        # pessimistic timer mark.  A wait_for(reply_delay) in
        # delayed_run_engine bounds the wait so a lost / late signal
        # doesn't stall the engine indefinitely.
        self.mapping_reply = asyncio.get_event_loop().create_future()

        if self.plugin_id not in self.punch_proc:
            self.punch_proc[self.plugin_id] = asyncio.create_task(
                self.delayed_run_engine(puncher)
            )
        return puncher

    async def advance_punching_protocol(self, puncher, reply, punch_time):
        """Compute the next round of port predictions; return outgoing UdpPunchMsg or None when done."""
        # Clock-truth witness fields: peer reads these to run the
        # pre-bucket bailout in its own run() (see top of run()).
        # Both fields cost nothing to send and the bailout saves
        # ~5 s of doomed rendezvous on bad clock pairs.
        tx_unix = int(self.sys_clock.time())
        clock_uncertainty = float(getattr(self.sys_clock, "uncertainty", 0.0))

        # For LAN, STUN is useless (returns each side's own port).
        # boundary_port_alloc in delayed_run_engine handles port
        # alignment between peers via NTP-aligned bucket. Send one
        # empty-mappings UdpPunchMsg to trigger the recipient; return
        # None on any reply. Mirrors tcp_punch's LAN short-circuit
        # (commit cb7a765). Nonce stays in payload.nonce so the
        # responder still sees it without the mappings round-trip.
        #
        # WG_DISABLE_PREDICT=1 takes the same short-circuit path
        # regardless of punch_mode -- with nat_alloc=None we have no
        # STUN-predicted mappings to fold; the boundary_port_alloc
        # socket added in setup_puncher_client carries the entire punch.
        if self.nat_alloc is None or self.nat_alloc.punch_mode == TCP_PUNCH_LAN:
            if reply is not None:
                return None
            # Use mode=2 (REMOTE) as default when nat_alloc was disabled.
            punch_mode_for_msg = (
                self.nat_alloc.punch_mode if self.nat_alloc is not None
                else TCP_PUNCH_REMOTE
            )
            msg = UdpPunchMsg({
                "payload": {
                    "punch_mode": punch_mode_for_msg,
                    "mappings": [],
                    "ntp": punch_time,
                    "nonce": puncher.udp_nonce.hex(),
                    "tx_unix": tx_unix,
                    "clock_uncertainty": clock_uncertainty,
                },
            })
            msg.meta.plugin_name = "udp_punch"
            return msg

        recv_mappings = None
        if reply is not None:
            recv_mappings = [NATMapping(m) for m in reply.payload.mappings]
            if not recv_mappings:
                log("[UDP-PUNCH] advance_punching_protocol: peer sent empty mappings list; dropping")
                return None

        # Re-entry guard: sidewire's republish loop and the multi-broker
        # rendezvous can both deliver duplicates of the same signed msg
        # to the listener, which re-enters run() and lands here again
        # with reply.payload.mappings populated.  nat_alloc.port_alloc()
        # is stateful (NATPredictAlloc walks a state machine that
        # asserts on invalid progressions) and a second call fires
        # `AssertionError("Invalid nat predict state progression.")`.
        # Drop the duplicate before it crashes the predictor.
        #
        # The discriminator MUST be "have we already folded the peer's
        # mappings?" -- NOT "is puncher.port_allocs non-empty?".
        # setup_puncher runs add_port_allocator(boundary_port_alloc)
        # which fills port_allocs BEFORE advance_punching_protocol is
        # ever reached, so the old port_allocs check fired on the very
        # first legitimate call, returned None without folding the
        # peer mappings, and never resolved mapping_reply.  Same bug
        # fixed in tcp_punch.
        if recv_mappings is not None and getattr(self, "peer_mappings_folded", False):
            log(fstr(
                "[UDP-PUNCH] advance_punching_protocol: duplicate reply "
                "ignored (peer mappings already folded, plugin_id={0})",
                (self.plugin_id,),
            ))
            return None

        port_alloc, is_end = await self.nat_alloc.port_alloc(recv_mappings)
        puncher.port_allocs += port_alloc
        # Only fold-then-signal when recv_mappings was supplied: for
        # the INITIATOR's first call we've only sent OUR predictions
        # out and the peer hasn't responded yet, so puncher.port_allocs
        # contains only our initial template / WE-DICTATE values.
        # Releasing the worker at that point binds sockets to those
        # values and fires PROBE bursts before update_for_reply_ports
        # has a chance to re-target them at the peer's actual reply-
        # ports.  This is the asymmetric-direction bug tcp_punch had
        # (EQUAL-initiator / PRESERV-responder failed) -- same shared
        # NATPredictAlloc state machine here.  The PRESERV-initiator
        # case is unaffected (its first send_mappings are already the
        # WE-DICTATE answer), and the reply_delay fallback timeout in
        # delayed_run_engine still fires the worker if the peer never
        # replies.
        if recv_mappings is not None:
            self.peer_mappings_folded = True

            # Signal the engine task: the peer's mappings have been folded
            # in and port_allocs is now valid for spawning the worker.
            # Guarded by not done() because configure_puncher_process /
            # advance_punching_protocol may be re-entered across signal
            # rounds (mapping refresh), and resolving an already-resolved
            # future raises InvalidStateError.
            reply_future = getattr(self, "mapping_reply", None)
            if reply_future is not None and not reply_future.done():
                reply_future.set_result(True)

        if is_end == 1:
            return None

        mappings = [m.to_json() for m in self.nat_alloc.send_mappings]
        msg = UdpPunchMsg({
            "payload": {
                "punch_mode": self.nat_alloc.punch_mode,
                "mappings": mappings,
                "ntp": punch_time,
                "nonce": puncher.udp_nonce.hex(),
                "tx_unix": tx_unix,
                "clock_uncertainty": clock_uncertainty,
            },
        })
        msg.meta.plugin_name = "udp_punch"
        return msg

    async def delayed_run_engine(self, puncher):
        """Wait for the peer's mapping reply (or reply_delay timeout), set up bridge, dispatch worker that runs engine + bridge.

        Previously slept ``coordinator_delay`` unconditionally on the
        theory that the peer's reply would have arrived in that time.
        That was racy on slow signal paths (worker started without
        port_allocs populated) and wasteful on fast paths (worker
        idled until the timer expired even though the mappings landed
        in 50 ms).  Now we ``wait_for`` the ``mapping_reply`` future
        that ``advance_punching_protocol`` resolves the instant the
        peer's mappings have been folded into ``puncher.port_allocs``.
        The ``reply_delay`` param caps the wait so a dropped signal
        doesn't stall the engine indefinitely; on TimeoutError we
        proceed with whatever ``port_allocs`` is already set
        (LAN-mode short-circuit relies on this, as do single-side
        mapping-only runs).
        """
        reply_delay = puncher.params.get("reply_delay", 2.0)
        try:
            try:
                await asyncio.wait_for(self.mapping_reply, reply_delay)
            except asyncio.TimeoutError:
                log(fstr(
                    "udp_punch.delayed_run_engine: mapping_reply timed "
                    "out after {0}s; spawning worker with current port_allocs",
                    (reply_delay,),
                ))

            # ---- Bridge setup (main side) ----
            #
            # Architecture (mirrors tcp_punch's reverse_server pattern,
            # adapted for UDP's connectionless model):
            #
            #   worker thread             |     main asyncio loop
            #   ------------------------- |     ----------------------
            #   punched_sock (peer-       |     listener_sock (Pipe)
            #     facing UDP, bound to    |       on (loopback, 0)
            #     puncher.src_ip:port)    |
            #          ^                  |          ^
            #          | selector_proxy   |          | datagrams via
            #          | bridge (DGRAM)   |          | asyncio loop
            #          v                  |          v
            #   worker_sock (loopback,    | --->  recvfrom -> msg_cbs
            #     UDP-connected to        | <---  pipe.send -> sendto
            #     listener_sock)          |
            #
            # Why both sockets are pre-built in main:
            # - Pre-creating both sockets lets us know the worker's
            #   bridge addr BEFORE the worker starts. Without this,
            #   the connector side's pipe.send(ECHO) -- which fires
            #   immediately after plugin.result resolves -- would
            #   have no dest_tup until the first inbound datagram
            #   from the worker, which never comes if the connector
            #   is the one with data to send first.
            # - The wrapped Pipe is built on listener_sock which has
            #   never been touched by select() in a worker thread,
            #   so asyncio's selector sees a clean fd. Avoids the
            #   "deaf wrap" failure that the rebind workaround was
            #   trying (and only partially succeeding) to dodge.
            # - Pre-populating msg_cbs on the wrapped Pipe before
            #   dispatching the worker covers the wireup race the
            #   same way tcp_punch's reverse_server does.

            if puncher.af == 2:
                loopback_host = "127.0.0.1"
                family = _socket.AF_INET
            else:
                loopback_host = "::1"
                family = _socket.AF_INET6

            try:
                listener_sock = _socket.socket(family, _socket.SOCK_DGRAM)
                listener_sock.setsockopt(
                    _socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1,
                )
                listener_sock.setblocking(False)
                listener_sock.bind((loopback_host, 0))

                worker_sock = _socket.socket(family, _socket.SOCK_DGRAM)
                worker_sock.setsockopt(
                    _socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1,
                )
                worker_sock.setblocking(False)
                worker_sock.bind((loopback_host, 0))
                self.bridge_socks = [listener_sock, worker_sock]

                # getsockname() returns a 2-tuple for v4 and a 4-tuple
                # for v6 (host, port, flowinfo, scope_id). Both the
                # socket.connect() calls below and the wrapped Pipe
                # take the full tuple as-is: resolve_dest accepts the
                # v6 4-tuple (reads ip + port positionally, re-derives
                # scope from the route), so no flattening is needed and
                # both AFs go through the same path. The bridge binds
                # ::1 loopback so scope_id/flowinfo are 0 regardless.
                listener_addr = listener_sock.getsockname()
                worker_addr = worker_sock.getsockname()
                worker_addr_for_pipe = worker_addr
                # UDP-connect both ends so recv/send default to the
                # known peer and the kernel filters incoming.
                listener_sock.connect(worker_addr)
                worker_sock.connect(listener_addr)
            except OSError as exc:
                log(fstr(
                    "udp_punch.delayed_run_engine: bridge setup failed: {0}",
                    (repr(exc),),
                ))
                log_exception()
                if not self.result.done():
                    self.result.set_result(None)
                return

            log(fstr(
                "udp_punch.delayed_run_engine: bridge listener={0} worker={1}",
                (listener_addr, worker_addr),
            ))

            # Wrap listener_sock as a UDP Pipe -- main owns it from
            # creation, asyncio sees a fresh fd, dest_tup is set to
            # worker_addr so pipe.send works immediately.
            try:
                route = self.nic.route(self.af)
                pipe = await Pipe(
                    UDP, dest=worker_addr_for_pipe,
                    route=route, sock=listener_sock,
                ).connect()
            except (OSError, ConnectionError, asyncio.TimeoutError):
                log_exception()
                pipe = None
                for s in (listener_sock, worker_sock):
                    try:
                        s.close()
                    except OSError:
                        pass

            if pipe is None:
                log("udp_punch.delayed_run_engine: Pipe.connect() returned None")
                if not self.result.done():
                    self.result.set_result(None)
                return

            # Hand the wrapped Pipe to close() so teardown can shut the
            # asyncio UDP datagram transport down through its own
            # .close() -- which unregisters the loop reader. Raw
            # sock.close() on listener_sock (which the transport owns)
            # leaves the transport registered and the connector's loop
            # spins recvfrom -> EBADF every iteration, starving the
            # tcp_punch winner pipe's reader.
            self.bridge_pipe = pipe

            try:
                wrapped_addr = pipe.sock.getsockname()
            except (OSError, AttributeError):
                wrapped_addr = None
            log(fstr(
                "udp_punch.delayed_run_engine: wrapped Pipe local={0} dest={1}",
                (wrapped_addr, worker_addr),
            ))

            # Pre-populate msg_cbs with the node-level dispatcher
            # BEFORE dispatching the worker. Mirrors the wireup-race
            # fix in tcp_punch's start_punching_process.
            node_msg_cb = getattr(self, "node_msg_cb", None)
            if (
                node_msg_cb is not None
                and getattr(pipe, "pipe_events", None) is not None
            ):
                pe = pipe.pipe_events
                before = len(pe.msg_cbs)
                pe.msg_cbs.add(node_msg_cb)
                if len(pe.msg_cbs) != before:
                    log(fstr(
                        "udp_punch.delayed_run_engine: pre-populated "
                        "pipe.msg_cbs (count={0})",
                        (len(pe.msg_cbs),),
                    ))

            # Snapshot puncher state for the worker thread.
            af = puncher.af
            nic_id = puncher.nic_id
            port_allocs = list(puncher.port_allocs)
            src_ip = puncher.src_ip
            dest_ip = puncher.dest_ip
            same_machine = puncher.same_machine
            params = puncher.params
            nonce = puncher.udp_nonce
            f_sleep_until = puncher.sleep_until
            puncher_route = puncher.route
            stop_reader = self.stop_reader

            loop = get_running_loop()
            # convergence is resolved by the worker via call_soon_threadsafe
            # the moment the engine returns a winner and selector_proxy is
            # ready to read worker_sock. Until that happens, ECHO bytes the
            # demo writes to listener_sock just queue in worker_sock's recv
            # buffer with nobody draining them. Resolving plugin.result
            # before the bridge is alive caused the matrix to hit
            # echo-recv timeout 100% of the time -- demo's 1 s pre-sleep
            # + 4 s recv timeout < spray (3 s) + listen (3 s) = 6 s engine
            # window, so the demo always gave up before selector_proxy
            # started forwarding. Mirrors tcp_punch's start_punching_process
            # which only returns the pipe after the worker has converged.
            convergence = asyncio.Future()

            def signal_convergence(success):
                if not convergence.done():
                    convergence.set_result(success)

            def f_engine(af, nic_id, port_allocs, src_ip, dest_ip,
                         f_sleep_until, our_ip, same_machine, params,
                         route=None):
                # Adapter: PunchClient.run_engine calls f_engine with
                # the tcp_punch signature (our_ip + route).  We close
                # over the UDP-specific extras (nonce, stop_reader) and
                # ignore our_ip.  Prefer the route the client passes;
                # fall back to the closed-over puncher_route.
                del our_ip
                return udp_punch_engine(
                    af=af,
                    nic_id=nic_id,
                    port_allocs=port_allocs,
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    f_sleep_until=f_sleep_until,
                    nonce=nonce,
                    same_machine=same_machine,
                    params=params,
                    stop_reader=stop_reader,
                    route=route if route is not None else puncher_route,
                )

            def punch_and_bridge():
                """Worker: run UDP engine (with dual-fire), signal main, then bridge."""
                try:
                    result = puncher.run_engine(f_engine)
                except Exception:  # pylint: disable=broad-except
                    log_exception()
                    loop.call_soon_threadsafe(signal_convergence, False)
                    return
                if result is None:
                    log("[UDP-WORKER] engine returned None")
                    loop.call_soon_threadsafe(signal_convergence, False)
                    return

                punched_sock, peer_addr = result
                try:
                    local_addr = punched_sock.getsockname()
                except OSError:
                    local_addr = None
                log(fstr(
                    "[UDP-WORKER] engine WINNER local={0} peer={1} fd={2}",
                    (local_addr, peer_addr, punched_sock.fileno()),
                ))

                # Drain residual PROBE/CONFIRM still buffered on the
                # punched sock from the spray window; otherwise the
                # bridge would forward them to main where the stream
                # filter would have to drop each.
                drained = drain_punch_residue(punched_sock, nonce)
                log(fstr(
                    "[UDP-WORKER] drained {0} residual frames",
                    (drained,),
                ))

                # UDP-connect punched_sock to peer so recv() filters
                # to the peer and send() targets the peer.
                try:
                    punched_sock.connect(peer_addr)
                except OSError as exc:
                    log(fstr(
                        "[UDP-WORKER] punched_sock.connect failed: {0}",
                        (repr(exc),),
                    ))
                    log_exception()
                    try:
                        punched_sock.close()
                    except OSError:
                        pass
                    loop.call_soon_threadsafe(signal_convergence, False)
                    return

                # Drain residual punch probes that arrived after
                # drain_punch_residue ran and flush stale ICMP errors.
                # fire_probes sends to ALL predicted dest_ports; probes
                # that hit closed ports on the peer generate ICMP port-
                # unreachable responses queued on the winner socket as
                # async errors.  connect(peer_addr) does NOT clear
                # that error queue, so the first recv() in
                # selector_proxy returns ECONNREFUSED even though
                # peer_addr is reachable -- on Linux the streak counter
                # hits 8 and closes the pair; on BSD each ICMP fires
                # once then clears, leaving the proxy idle.
                # recv() consumes one datagram or one queued error per
                # call on all platforms; loop until clean.
                stale_drained = 0
                stale_errors = 0
                for _ in range(256):
                    try:
                        punched_sock.recv(UDP_PUNCH_FRAME_LEN + 64)
                        stale_drained += 1
                    except BlockingIOError:
                        break
                    except (ConnectionRefusedError, OSError):
                        stale_errors += 1
                if stale_drained or stale_errors:
                    log(fstr(
                        "[UDP-WORKER] post-connect stale drain: {0} frames {1} errors",
                        (stale_drained, stale_errors),
                    ))

                # Hand off to selector_proxy.  Convergence is NOT
                # signalled here -- selector_proxy fires ready_writer
                # the moment its copy loop is live, and the main side's
                # reader on the paired socket resolves convergence off
                # that.  Signalling here (before the loop entered)
                # raced: main resolved plugin.result and the demo's
                # ECHO bytes queued in worker_sock with nobody draining
                # them yet.  Mirrors tcp_punch's bridge-ready socketpair.
                log(fstr(
                    "[UDP-WORKER] bridging punched <-> worker_sock {0}",
                    (worker_addr,),
                ))
                try:
                    selector_proxy(
                        punched_sock,
                        listener_addr,
                        stop_reader,
                        sock_proto=_socket.SOCK_DGRAM,
                        socket_r=worker_sock,
                        ready_writer=ready_worker,
                    )
                except Exception:  # pylint: disable=broad-except
                    log_exception()
                log("[UDP-WORKER] selector_proxy returned; worker exiting")

            # Bridge-ready socketpair (ported from tcp_punch).
            # selector_proxy writes one byte to ready_worker the moment
            # its copy loop is live; the reader below picks that up on
            # the main thread and resolves convergence True -- so the
            # plugin result is only handed back once the bridge is
            # actually draining worker_sock.  Failure paths still
            # resolve convergence False directly from the worker.
            ready_main, ready_worker = _socket.socketpair()
            ready_main.setblocking(False)

            def bridge_ready_cb():
                try:
                    ready_main.recv(1)
                except OSError:
                    pass
                try:
                    loop.remove_reader(ready_main.fileno())
                except (OSError, ValueError):
                    pass
                signal_convergence(True)

            loop.add_reader(ready_main.fileno(), bridge_ready_cb)

            worker_fut = loop.run_in_executor(None, punch_and_bridge)

            def worker_done(fut):
                try:
                    exc = fut.exception()
                except (asyncio.CancelledError, Exception):  # pylint: disable=broad-except
                    exc = None
                if exc is not None:
                    log(fstr(
                        "[UDP-WORKER] future raised {0}: {1}",
                        (type(exc).__name__, repr(exc)),
                    ))
                else:
                    log("[UDP-WORKER] future completed cleanly")
                # Belt-and-braces: if the worker crashed before
                # signalling convergence, unblock main so plugin.result
                # gets a None instead of hanging on plugin timeout.
                if not convergence.done():
                    convergence.set_result(False)
                # The worker has exited -- selector_proxy is done with
                # ready_worker.  Drop the reader and close both ends.
                try:
                    loop.remove_reader(ready_main.fileno())
                except (OSError, ValueError):
                    pass
                for s in (ready_main, ready_worker):
                    try:
                        s.close()
                    except OSError:
                        pass
            worker_fut.add_done_callback(worker_done)

            if pipe is not None:
                # Late-arriving PROBE/CONFIRM frames also need to be
                # filtered at the pipe-stream layer: PipeEvents queues
                # data via stream.add_msg before node_protocol fires,
                # so without this hook pipe.recv(SUB_ALL) returns
                # frame bytes ahead of the actual application reply.
                # Mirrors random_probe's stream.add_msg monkey-patch.
                drop_count = [0]
                pass_count = [0]
                try:
                    stream = pipe.pipe_events.stream
                    original_add_msg = stream.add_msg
                    nonce_bytes = puncher.udp_nonce

                    def filtered_add_msg(data, client_tup):
                        # Drop any frame parse_frame() recognises whose
                        # nonce matches this session's.  Covers both
                        # native P2UP (21B) and STUN-shape (20-32B
                        # Binding Request/Success).  Compare on the
                        # first 12 bytes because the STUN-shape only
                        # carries the truncated 12-byte TXID over the
                        # wire (parse_frame zero-pads back to 16).
                        buf = bytes(data)
                        kind, recv_nonce = parse_frame(buf)
                        if kind is not None and recv_nonce[:12] == nonce_bytes[:12]:
                            drop_count[0] += 1
                            if drop_count[0] <= 3 or drop_count[0] % 50 == 0:
                                log(fstr(
                                    "udp_punch.filter: dropped punch frame #{0} from {1}",
                                    (drop_count[0], client_tup),
                                ))
                            return
                        pass_count[0] += 1
                        if pass_count[0] <= 3 or pass_count[0] % 50 == 0:
                            preview = bytes(data[:8]) if len(data) >= 8 else bytes(data)
                            log(fstr(
                                "udp_punch.filter: PASSING msg #{0} from {1} len={2} preview={3}",
                                (pass_count[0], client_tup, len(data), repr(preview)),
                            ))
                        return original_add_msg(data, client_tup)

                    stream.add_msg = filtered_add_msg
                    log("udp_punch.delayed_run_engine: stream filter installed")
                except (AttributeError, TypeError) as exc:
                    log(fstr(
                        "udp_punch.delayed_run_engine: filter install FAILED: {0}",
                        (repr(exc),),
                    ))

            # Block until the worker either converges (engine winner +
            # selector_proxy ready) or fails. The ceiling has to cover
            # the FULL pre-spray sleep_until wait (up to ~max_sleep
            # seconds while we wait for the next NTP rendezvous bucket)
            # plus spray + listen + a small slop for residue drain and
            # connect. Without that the wait fires before sleep_until
            # even returns and every pair records as no-convergence.
            engine_ceiling = (
                params.get("max_sleep", 65)
                + params.get("connect_timeout", 3.0)
                + params.get("monitor_timeout", 3.0)
                + 5.0
            )
            try:
                converged = await asyncio.wait_for(
                    convergence, timeout=engine_ceiling,
                )
            except asyncio.TimeoutError:
                log(fstr(
                    "udp_punch.delayed_run_engine: convergence wait timed "
                    "out after {0}s; treating as no-convergence",
                    (engine_ceiling,),
                ))
                converged = False

            log(fstr(
                "udp_punch.delayed_run_engine: convergence={0}",
                (converged,),
            ))

            if not self.result.done():
                self.result.set_result(pipe if converged else None)
        except asyncio.CancelledError:
            if not self.result.done():
                self.result.set_result(None)
            raise
        except Exception:  # pylint: disable=broad-except
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
        # NOTE: do NOT pop punch_proc / punch_clients here -- not on the
        # success path and not on the exception path. The asyncio task
        # ends as soon as set_result fires, but the executor worker keeps
        # running for ~9 s of spray + listen plus the lifetime of the
        # bridge. If the peer's next signal arrives during that window
        # and run() is re-entered, popped state forces a fresh
        # setup_puncher_client + new engine task whose bind_punch_sockets
        # collides on the same predicted ports the first worker still
        # holds (Windows EADDRINUSE 10048). close() is the only place
        # that pops; cleanup semantics will be revisited in a dedicated
        # session.

    async def close(self):
        """Cancel any in-flight engine task and clear the per-session state."""
        task = self.punch_proc.pop(self.plugin_id, None)
        self.punch_clients.pop(self.plugin_id, None)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        # Close the wrapped UDP Pipe through its own .close() so the
        # asyncio datagram transport unregisters its event-loop reader.
        # Raw-closing listener_sock (the transport's fd) instead leaves
        # a dead fd registered and the connector's loop EBADF-storms
        # recvfrom every iteration, starving the tcp_punch winner pipe.
        pipe = getattr(self, "bridge_pipe", None)
        wrapped_sock = getattr(pipe, "sock", None) if pipe is not None else None
        if pipe is not None:
            try:
                await pipe.close()
            except asyncio.CancelledError:
                raise
            except (OSError, ConnectionError, asyncio.TimeoutError):
                pass
            except Exception:  # pylint: disable=broad-except
                log_exception()
            self.bridge_pipe = None

        # worker_sock is the genuinely-raw selector_proxy end -- no
        # asyncio transport owns it, so a plain close() is correct.
        # listener_sock is owned by the Pipe closed above and must NOT
        # be raw-closed here.
        for sock in getattr(self, "bridge_socks", []):
            if wrapped_sock is not None and sock is wrapped_sock:
                continue
            try:
                sock.close()
            except OSError:
                pass
        self.bridge_socks = []

        if not self.result.done():
            self.result.cancel()


# Process-level registry keyed by (nic_id, primary_route_ip, af).
# Two warpgate Nodes binding udp_punch sockets on the same (NIC, source
# IP, address family) tuple collide: both compute identical time-
# based port predictions via boundary_port_alloc, both try to bind
# those ports on the same source IP, the second bind hits
# EADDRINUSE, and (per our silent-skip-on-bind-failure path) the
# engine quietly proceeds with fewer sockets. The resulting failure
# looks identical to a NAT-prediction miss but is actually a self-
# collision.
#
# Different IPs on the same NIC don't collide (different bind
# tuples), and different AFs don't collide (separate v4/v6 socket
# tables in the kernel) -- so the key is the full tuple, not just
# the nic_id.
PUNCH_NIC_OWNERS = {}


class UdpPunchPluginFactory:
    """Creates UdpPunchPlugin instances sharing STUN clients + per-plugin state."""

    def __init__(
        self,
        stun_clients,
        sys_clock=None,
        punch_clients=None,
    ):
        self.stun_clients = stun_clients
        self.sys_clock = sys_clock or SysClock(None, 0.1)
        self.punch_clients = punch_clients if punch_clients is not None else {}
        self.punch_proc = {}
        self.nic_ids_owned = []
        # Populated by setup_plugin with (nic_id, ip, af) tuples this
        # factory wants to claim. Actual claim happens lazily on
        # first build_plugin so registration never fails on collision.
        self.pending_claims = []

    @classmethod
    async def create(cls, stun_clients, sys_clock):
        """Async factory; UDP punch needs no process pool so this is a thin wrapper."""
        return cls(stun_clients, sys_clock)

    def claim_nics(self, claims):
        """Register this factory as the udp_punch owner for each (nic_id, ip, af) tuple; raise ValueError on cross-factory collision.

        Self-collision (same key appearing twice in our own claims) is
        treated as a no-op. Windows multi-name NIC enumeration can
        report the same physical adapter via both the hardware name
        and the friendly name (e.g. "Intel(R) PRO/1000 MT Network
        Connection" + "Local Area Connection" both pointing at the
        same primary IP), so node.ifs yields multiple nic objects
        whose (nic_id, primary_ip, af) tuples collapse to the same
        key. Without this, the first inbound UdpPunchMsg's call to
        build_plugin -> claim_nics tripped on its own duplicate and
        raised, taking the udp_punch responder offline for the whole
        process.
        """
        for key in claims:
            existing = PUNCH_NIC_OWNERS.get(key)
            if existing is self:
                continue
            if existing is not None:
                nic_id, ip_str, af = key
                raise ValueError(
                    "udp_punch is already active on (nic={0!r}, ip={1!r}, "
                    "af={2}) in this process. Two warpgate Nodes cannot run "
                    "udp_punch with the same source IP and address family "
                    "on the same NIC -- their port-prediction allocations "
                    "would collide on bind(). Run the second Node on a "
                    "different NIC, a different IP on this NIC, or in a "
                    "separate process.".format(nic_id, ip_str, af)
                )
            PUNCH_NIC_OWNERS[key] = self
            self.nic_ids_owned.append(key)

    def build_plugin(self):
        """Create a fresh UdpPunchPlugin wired to this factory's shared state."""
        # Claim the (nic, ip, af) tuples lazily on first plugin
        # build. Raises ValueError if another factory in this process
        # already owns one of them -- caller (traversal manager) can
        # decide to skip / log / propagate. After the first claim
        # succeeds, pending_claims is cleared so re-builds don't
        # re-raise spuriously.
        if self.pending_claims:
            claims = self.pending_claims
            self.pending_claims = []
            self.claim_nics(claims)
        plugin = UdpPunchPlugin()
        plugin.stun_clients = self.stun_clients
        plugin.sys_clock = self.sys_clock
        plugin.punch_clients = self.punch_clients
        plugin.punch_proc = self.punch_proc
        return plugin

    async def close(self):
        """Release the NIC ownership claims so a fresh Node can re-create the factory."""
        for nic_id in self.nic_ids_owned:
            if PUNCH_NIC_OWNERS.get(nic_id) is self:
                del PUNCH_NIC_OWNERS[nic_id]
        self.nic_ids_owned = []


