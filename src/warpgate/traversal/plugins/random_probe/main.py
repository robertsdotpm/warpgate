"""Random-probe traversal plugin (Tailscale-style symmetric NAT traversal).

Designed for the (full-cone, symmetric) NAT pair.  The cone side
fires N UDP probes at random destination ports on the symmetric
peer's external IP; the symmetric side fires one probe from each
of N source-port-distinct sockets at the cone peer's known
(ext_ip, ext_port).  Birthday-paradox collision: with N=256 each,
~63% of attempts produce a 4-tuple that bridges both NATs.

The plugin uses the punch plugin's boundary algorithm purely for
*timing* -- both sides synchronise the moment they start firing so
the burst arrives within a NAT-mapping lifetime of itself.  The
transport is UDP-only because TCP simultaneous open is too fragile
for random-probe; see the design note at the bottom of this file.
"""

import asyncio
import os
import socket as socket_mod
import time

from aionetiface import (
    EXT_BIND,
    LOOPBACK_BIND,
    NIC_BIND,
    Pipe,
    SysClock,
    UDP,
    get_running_loop,
    log,
    log_exception,
    rand_b,
    to_s,
)
from aionetiface.nic.nat.nat_defs import SYMMETRIC_NAT

from ....protocol.proto_defs import P2P_RANDOM_PROBE
from .proto import RandomProbeMsg
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from aionetiface.net.selector_proxy import selector_proxy
from ..tcp_punch.boundary_lib import FAST_PUNCH_PARAMS, compute_rendezvous

from .random_probe_defs import (
    RANDOM_PROBE_DEFAULT_COUNT,
    PROBE_LISTEN_TIMEOUT,
)
from .random_probe_engine import sync_run_bidirectional_spray
from .random_probe_utils import (
    decode_probe,
    drain_probe_residue,
    looks_like_random_probe,
    make_udp_socket,
    sync_stun_discover_mapping,
)


def is_symmetric_nat(nat_info):
    """
    True iff *nat_info* describes a symmetric NAT.

    The random-probe algorithm only cares about this single bit:
    is the peer's external port predictable per outbound flow?
    Symmetric NATs randomise it (the case the algorithm is
    designed to fix); everything else -- open internet (no NAT),
    full cone, restricted, port-restricted -- preserves enough
    structure that the peer can play the "fixed-port" role and
    publish a single (ip, port) the symmetric peer can aim at.

    A missing / empty nat_info is treated as non-symmetric: when
    the classifier didn't run (or hasn't finished), assume the
    permissive case so the algorithm gets to try.

    All non-symmetric callers in the plugin use ``not is_symmetric_nat()``
    directly; we don't expose a positively-worded counterpart
    because every potential name ("is_cone_nat",
    "is_predictable_nat") would be misleading -- the set is
    "everything except symmetric", not any specific NAT shape.
    """
    if not nat_info:
        return False
    return nat_info.get("type") == SYMMETRIC_NAT


@register(phase="spray")
class RandomProbePlugin(Plugin):
    """Tailscale-style random UDP probe rendezvous for one (cone, sym) pair.

    The pair must be (one cone-NAT side, one symmetric-NAT side).
    auto_combos is responsible for not generating combos that don't
    fit -- we still defensively bail in run() on malformed pairs.

    Only EXT_BIND is meaningful: random-probe is exactly the path
    you take when neither side can be reached on the LAN and direct
    public-IP punching has failed.
    """

    name = "random_probe"
    transport = UDP
    # EXT_BIND is the production path; NIC_BIND is allowed so the
    # matrix sweep can exercise the algorithm on LAN where the IP
    # selection just collapses to NIC addresses (no NAT involved).
    # LOOPBACK_BIND stays out -- random_probe over loopback is
    # degenerate (kernel short-circuit, nothing to verify).
    route_types = (EXT_BIND, NIC_BIND)
    conf = {"timeout": 10}
    proto_messages = (
        (RandomProbeMsg, P2P_RANDOM_PROBE, 18),
    )

    @classmethod
    def setup(cls, node):
        return RandomProbePluginFactory(sys_clock=node.sys_clock)

    def run(self, reply=None):
        """Drive the random-probe rendezvous from initiator or responder side."""
        self.bridge_socks = []
        # Loopback is excluded above; any other route_type passes
        # through. The IP-selection block below picks NIC vs EXT
        # addresses so the algorithm runs correctly on either path.
        if self.route_type == LOOPBACK_BIND:
            self.set_failed_result()
            raise ValueError(
                "random_probe over loopback is degenerate "
                "(kernel short-circuit, no probes needed)."
            )

        my_nat = self.src.get("nat") or {}
        peer_nat = self.dest.get("nat") or {}

        # Wire-advertised "address each side identifies itself by" --
        # used for the role-decider comparison and as the value placed
        # on RandomProbeMsg.payload.ext_ip.  This is NOT necessarily
        # self.src["ip"]: resolve_pair leaves src["ip"] as the local
        # *bind* IP, which is the LAN IP even on the EXT_BIND path.
        # For EXT_BIND we need the route's external (NAT-observable)
        # IP so the peer fires probes at something reachable across
        # the internet -- self.nic.route(af).ext() returns that.
        # For NIC_BIND / same_machine the bind IP is also the peer-
        # observable IP, so src["ip"] is correct.
        self.peer_addr_ip = str(self.dest.get("ip") or "")
        if self.route_type == NIC_BIND:
            self.my_addr_ip = str(self.src.get("ip") or "")
        else:
            # src["ext"] is an IPRange object (set by topology.py); cast
            # to str for downstream comparisons and on-wire encoding.
            # The combo generator guarantees src["ext"] is populated for
            # EXT_BIND combos and that the two sides' ext IPs differ;
            # see the combo-level validation in traversal_utils.
            self.my_addr_ip = str(self.src["ext"])

        # Role assignment by NAT restrictiveness, then by IP:
        #   1. Whichever side has the *higher* NAT type number plays
        #      "sym" -- nat_defs.py orders types from least to most
        #      restrictive (OPEN_INTERNET=1, FULL_CONE=3, RESTRICT=4,
        #      RESTRICT_PORT=5, SYMMETRIC=6, BLOCKED=7).  The more
        #      restrictive peer is the one that benefits from the
        #      256-sockets-burst pattern, since its outbound is the
        #      one that's hardest for the other side to predict.
        #   2. On a tie (same NAT type number, both ends of the link
        #      classified the same way), fall back to sorted IP --
        #      the side with the lexicographically smaller addr_ip
        #      plays "non_sym", the other plays "sym".  Both peers
        #      see the same pair of strings, so they always pick
        #      opposite roles.
        my_nat_n = int(my_nat.get("type") or 0)
        peer_nat_n = int(peer_nat.get("type") or 0)
        if my_nat_n > peer_nat_n:
            my_role = "sym"
        elif my_nat_n < peer_nat_n:
            my_role = "non_sym"
        else:
            # NAT-type tie.  Decide by IP order so both peers pick
            # opposite roles deterministically.  The combo generator
            # guarantees the two sides' addr_ips differ, so the IP
            # compare always picks a definite role.
            if self.my_addr_ip < self.peer_addr_ip:
                my_role = "non_sym"
            else:
                my_role = "sym"

        if reply is None:
            # Initiator: pick a session nonce + rendezvous time and
            # send a RandomProbeMsg out.  Stash both on self so we
            # can match them when the peer's reply arrives.
            self.session_nonce = rand_b(16)
            self.session_role = my_role
            # NTP-aligned timestamp via SysClock.  Old VMs / boxes
            # without time-sync drift far enough that plain
            # time.time() blows the FAST_PUNCH_PARAMS.max_clock_error
            # (2 s) budget; SysClock samples a quorum of NTP servers
            # so both peers agree on the same Unix second within
            # the allowed error.
            timestamp = self.sys_clock.time()
            p = FAST_PUNCH_PARAMS
            _, punch_time = compute_rendezvous(
                timestamp,
                window=p["window"],
                min_run_window=p["min_run_window"],
                max_error=p["max_clock_error"],
            )
            self.punch_time = punch_time

            # If we're the non-sym side, pre-bind our UDP socket
            # right now so the port it ends up on can travel to the
            # peer in the message we're about to send.  Without
            # this, known_port = 0 and the symmetric side fires its
            # 256 probes at port 0 -- guaranteed no convergence.
            if my_role == "non_sym":
                self.prebind_non_sym_sock()

            outgoing = self.build_msg(my_role, punch_time, to_s(self.session_nonce.hex()))
            outgoing.meta.plugin_name = "random_probe"
            self.send_signal(outgoing)
            return

        # Responder: extract peer's params, lock our role, fire.
        #
        # The previous code aborted when peer_role == my_role.  That was
        # a real failure mode when NAT-info propagation races mean each
        # side computes its role from a partially-populated peer_nat
        # dict and both pick "sym" (or both pick "non_sym").  But the
        # spray engine is direction-agnostic: it converges as long as
        # both sides actually fire, regardless of which role label they
        # carry.  Letting the round proceed is strictly better than
        # giving up.
        peer_role = reply.payload.role
        nonce = bytes.fromhex(reply.payload.magic)
        if len(nonce) != 16:
            log("RandomProbePlugin: bad nonce length in peer reply")
            if not self.result.done():
                self.result.set_result(None)
            return

        # We use self.peer_addr_ip = self.dest["ip"] (set in the
        # initial run() block).  Don't override from the peer's
        # wire-advertised ext_ip -- that introduced an asymmetry
        # between what each side compared in the election.
        peer_known_port = reply.payload.known_port
        probe_count = reply.payload.probe_count or RANDOM_PROBE_DEFAULT_COUNT
        punch_time = reply.payload.punch_time

        # If the peer addr is a v6 link-local IP (fe80::...), bake OUR
        # local scope_id into it so resolve_dest_tup downstream produces
        # the (host, port, flowinfo, scope_id) 4-tuple Windows needs to
        # actually send to the right interface.  Same fix applied to
        # tcp_punch (commits 10f4977 + 87148ae) and udp_punch -- without
        # it Windows sendto silently lands on the OS-default NIC and
        # the probes never reach the peer.  get_nic_id(af) handles XP's
        # split TCPIP / TCPIP6 ifindex spaces correctly.
        if self.peer_addr_ip and self.peer_addr_ip.lower().startswith("fe80"):
            try:
                from aionetiface.net.bind.bind_utils import ip6_patch_bind_ip
                v6_scope = self.nic.get_nic_id(self.af)
                self.peer_addr_ip = ip6_patch_bind_ip(
                    self.peer_addr_ip.split("%", 1)[0], v6_scope,
                )
            except (ImportError, AttributeError, OSError):
                pass

        # If we're the responder we still owe the peer a reply with
        # our own external IP / known port.  Send it immediately so
        # they have what they need before the rendezvous fires.
        if not getattr(self, "session_nonce", None):
            self.session_nonce = nonce
            self.session_role = my_role
            self.punch_time = punch_time
            # Same pre-bind requirement as the initiator path: the
            # non-sym side has to commit to a port BEFORE building
            # the response, otherwise the peer fires at port 0.
            if my_role == "non_sym":
                self.prebind_non_sym_sock()
            our_msg = self.build_msg(my_role, punch_time, reply.payload.magic)
            our_msg.meta.plugin_name = "random_probe"
            self.send_signal(our_msg)

        # Guard against MQTT redelivery: the peer's RandomProbeMsg
        # gets fanned out across multiple brokers, so this run() can
        # be called several times in quick succession with reply set.
        # Without a guard each call awaits wait_until + spawns its own
        # 256-socket algorithm instance; the first converges, the rest
        # race for the same prebound port and self-loop on each
        # other's probes -- log evidence: many [RP-FIRE-DONE]
        # res=None (timeout) immediately after one res=<converged>.
        # Same shape udp_punch dodges via configure_puncher_process's
        # "if plugin_id not in punch_proc" check.
        if getattr(self, "algorithm_started", False):
            return
        self.algorithm_started = True

        # Synchronise to the rendezvous time using NTP-corrected clock
        # (self.sys_clock) so that machines with a skewed OS clock (XP:
        # ~39 s fast, Vista: ~22 s fast) fire at the agreed rendezvous
        # instead of too early.  wait_until() uses time.time() which
        # reflects the raw OS clock and fires immediately on skewed hosts.
        #
        # Use float subtraction (not int(sys_clock.time())) so we don't
        # truncate up to a full second of pre-rendezvous wait and fire
        # too early near the boundary.
        ntp_delay = punch_time - self.sys_clock.time()
        if 0 < ntp_delay <= p_or_default("max_sleep"):
            asyncio.sleep(ntp_delay)

        try:
            route = self.bind()
        except (OSError, ValueError):
            log("RandomProbePlugin: route bind failed; aborting")
            if not self.result.done():
                self.result.set_result(None)
            return
        bind_ip = self.src["ip"]


        # Master/slave election: strict per-route_type IP source so both
        # peers compare the SAME class of address.  Mixing NIC-vs-ext
        # across peers used to let both elect SLAVE (live failure 2026-
        # 05-25 on CGNAT pool: src["ext"] missing -> fell back to bind_ip
        # locally, peer still compared against STUN-mapped WAN).  Combo
        # generator guarantees src["ext"] is populated for EXT_BIND.
        if self.route_type == EXT_BIND:
            own_ext_ip = str(self.src["ext"])
        else:
            own_ext_ip = str(bind_ip)


        # Algorithm phase runs in a thread executor with PURE
        # blocking-socket I/O (select + recvfrom) -- no
        # asyncio.add_reader anywhere on these socks.  asyncio's
        # create_datagram_endpoint(sock=existing) doesn't fire
        # _read_ready reliably on a sock that's been cycled
        # through add_reader/remove_reader many times during the
        # algorithm phase (verified on real cross-NAT path:
        # kernel queue has data, transport reader never fires).
        # Keeping the algorithm sync side-steps the bug
        # entirely: when the plugin hands the winning sock to
        # Pipe.connect, asyncio's selector sees a fresh fd.
        # Direction-agnostic spray: both sides always run the same
        # algorithm regardless of role / NAT-detection result.
        # Symmetric mobile NAT + endpoint-independent home NAT used to
        # only converge in one direction (LAN connector dialing mobile
        # listener) because the asymmetric algorithm hard-coded which
        # side did spray vs single-known-port. Bidirectional spray
        # gives up the "one side can use a single port" optimisation
        # in exchange for working in either direction; the bandwidth
        # is the same (probe_count probes each way) and the expected
        # collision count is probe_count^2 / 65000 ~= 1 with N=256.
        # See investigation in 2026-05-03 commit history for the full
        # case.
        loop_for_algo = get_running_loop()
        res = loop_for_algo.run_in_executor(
            None,
            lambda: sync_run_bidirectional_spray(
                bind_ip=bind_ip,
                peer_ext_ip=self.peer_addr_ip,
                nonce=nonce,
                probe_count=probe_count,
                listen_timeout=PROBE_LISTEN_TIMEOUT,
                route=route,
                own_ext_ip=own_ext_ip,
            ),
        )


        if res is None:
            log("RandomProbePlugin: round did not converge; aborting")
            if not self.result.done():
                self.result.set_result(None)
            return

        # NOTE: drain + sock.connect(peer) deliberately moved into
        # the bridge_worker below (match udp_punch's structure).
        # Doing them in main between algorithm-return and bridge-
        # start was the prior approach; it left a window where
        # asyncio could see the punched fd via the running loop's
        # internal bookkeeping (resolve_route, async_drain_probe_residue's
        # asyncio.sleep yields), which is exactly the deaf-wrap risk
        # the bridge is meant to side-step. Keep punched_sock
        # untouched by main; do all of it in the worker.

        # ---- Bridge setup (mirrors tcp_punch reverse_server / udp_punch d5ad7fe) ----
        #
        # Side-step the "deaf wrap" failure by never registering
        # the punched sock with asyncio. Main owns a fresh
        # listener_sock on loopback (asyncio sees a never-touched
        # fd); a worker-thread selector_proxy forwards bytes
        # between the punched sock and a paired worker_sock that
        # loops back to the listener.
        #
        # Trade-off vs the previous direct-wrap approach: the
        # punched sock is now connect()ed to res["peer"] so
        # selector_proxy's connected-DGRAM recv/send work. That
        # means a peer NAT that remaps the source for follow-up
        # datagrams will have its replies dropped at the kernel
        # filter -- acceptable for the matrix (LAN) and for the
        # cone-NAT path; revisit selector_proxy with an
        # unconnected-DGRAM mode if symmetric-vs-symmetric ever
        # needs to traverse this code.
        if self.af == 2:
            loopback_host = "127.0.0.1"
            family = socket_mod.AF_INET
        else:
            loopback_host = "::1"
            family = socket_mod.AF_INET6

        try:
            listener_sock = socket_mod.socket(family, socket_mod.SOCK_DGRAM)
            listener_sock.setsockopt(
                socket_mod.SOL_SOCKET, socket_mod.SO_REUSEADDR, 1,
            )
            listener_sock.setblocking(False)
            listener_sock.bind((loopback_host, 0))
            worker_sock = socket_mod.socket(family, socket_mod.SOCK_DGRAM)
            worker_sock.setsockopt(
                socket_mod.SOL_SOCKET, socket_mod.SO_REUSEADDR, 1,
            )
            worker_sock.setblocking(False)
            worker_sock.bind((loopback_host, 0))
            # getsockname() may return a 4-tuple on IPv6.  Use the full
            # address for both connect() and the Pipe dest so the asyncio
            # transport's self._address comparison never mismatches.
            listener_addr = listener_sock.getsockname()
            worker_addr = worker_sock.getsockname()
            worker_addr_for_pipe = worker_addr
            listener_sock.connect(worker_addr)
            worker_sock.connect(listener_addr)
        except OSError as exc:
            log("RandomProbePlugin: bridge setup failed: " + repr(exc))
            for s in (res["sock"], listener_sock, worker_sock):
                try:
                    s.close()
                except (OSError, NameError):
                    pass
            if not self.result.done():
                self.result.set_result(None)
            return

        self.bridge_socks = [res["sock"], listener_sock, worker_sock]

        log("RandomProbePlugin: bridge listener={0} worker={1}".format(
            listener_addr, worker_addr,
        ))

        from aionetiface import Pipe, UDP
        try:
            pipe = Pipe(
                UDP, dest=worker_addr_for_pipe,
                route=route, sock=listener_sock,
            ).connect()
        except (OSError, ConnectionError, ValueError, asyncio.TimeoutError):
            log("RandomProbePlugin: bridge Pipe wrap failed")
            for s in (listener_sock, worker_sock, res["sock"]):
                try:
                    s.close()
                except OSError:
                    pass
            if not self.result.done():
                self.result.set_result(None)
            return

        # Pre-populate node_msg_cb on the listener pipe BEFORE
        # set_result. Same wireup race tcp_punch fixed in 7fda794
        # and udp_punch mirrors. msg_cbs is a set so the later
        # on_plugin_done attach is idempotent.
        node_msg_cb = getattr(self, "node_msg_cb", None)
        if (
            node_msg_cb is not None
            and getattr(pipe, "pipe_events", None) is not None
        ):
            pe = pipe.pipe_events
            before = len(pe.msg_cbs)
            pe.msg_cbs.add(node_msg_cb)
            if len(pe.msg_cbs) != before:
                log("RandomProbePlugin: pre-populated pipe.msg_cbs "
                    "(count={0})".format(len(pe.msg_cbs)))

        # Probe-dropping filter on the listener pipe stream so any
        # stray probe forwarded across the bridge gets dropped before
        # reaching subscription queues / msg_cbs.
        try:
            from aionetiface import SUB_ALL
            stream = pipe.pipe_events.stream
            stream.subs = {}
            pipe.subscribe(SUB_ALL)
            original_add_msg = stream.add_msg

            def filtered_add_msg(data, client_tup):
                if looks_like_random_probe(bytes(data)):
                    return
                return original_add_msg(data, client_tup)

            stream.add_msg = filtered_add_msg
        except (AttributeError, TypeError):
            pass

        # Bridge worker: drains probe residue, connects punched_sock
        # to peer, signals convergence, then forwards bytes via
        # selector_proxy. Mirrors udp_punch's punch_and_bridge pattern:
        # the worker signals bridge_ready BEFORE entering selector_proxy
        # so main only resolves result AFTER the bridge is live.
        # Without this, result.set_result fires before bridge_worker
        # starts; demo echo bytes queue in worker_sock with nobody
        # reading them and the 4s echo timeout fires before
        # selector_proxy ever begins forwarding.
        loop_for_bridge = get_running_loop()
        punched_sock_ref = res["sock"]
        peer_ref = res["peer"]
        nonce_ref = nonce
        stop_reader = self.stop_reader
        listener_addr_ref = listener_addr
        worker_sock_ref = worker_sock

        bridge_ready_fut = loop_for_bridge.create_future()

        def signal_bridge_ready(success):
            if not bridge_ready_fut.done():
                bridge_ready_fut.set_result(success)

        def bridge_worker():
            try:
                try:
                    bw_local = punched_sock_ref.getsockname()
                except OSError:
                    bw_local = None
                log("[RP-WORKER] enter local={0} peer_ref={1} fd={2}".format(
                    bw_local, peer_ref, punched_sock_ref.fileno(),
                ))
                drained = drain_probe_residue(punched_sock_ref, nonce_ref)
                log("[RP-WORKER] drained {0} residual frames".format(drained))
                # Short polling window (~0.8s) to absorb late probes
                # the carrier buffered between sym's last send and
                # arrival on the cone's NIC.
                deadline = time.monotonic() + 0.8
                late = 0
                while time.monotonic() < deadline:
                    try:
                        data, _ = punched_sock_ref.recvfrom(
                            4096, socket_mod.MSG_PEEK,
                        )
                    except (BlockingIOError, OSError):
                        time.sleep(0.05)
                        continue
                    if decode_probe(data, nonce_ref) is None:
                        time.sleep(0.05)
                        continue
                    try:
                        punched_sock_ref.recvfrom(4096)
                        late += 1
                    except OSError:
                        break

                log("[RP-WORKER] late_probes={0}; about to connect punched_sock "
                    "to peer_ref={1}".format(late, peer_ref))
                try:
                    punched_sock_ref.connect(peer_ref)
                except OSError as exc:
                    log("[RP-WORKER] punched_sock.connect FAILED " + repr(exc))
                    loop_for_bridge.call_soon_threadsafe(
                        signal_bridge_ready, False,
                    )
                    return
                log("[RP-WORKER] connect OK")

                # Skip the post-connect stale drain entirely.  random_probe's
                # SLAVE side enters bridge_worker noticeably later than MASTER
                # (slave waits for CONFIRM, master commits on first PROBE) --
                # by the time slave reaches "post-connect", the peer has
                # already sent its WG-LIVENESS-PING through the bridge.  On
                # Windows that PING sits in the punched_sock recv queue;
                # SIO_UDP_CONNRESET=FALSE silently suppresses the ICMP
                # backwash this drain was originally meant to consume, so
                # recv() returns *real bytes* and the drain happily eats the
                # incoming PING (confirmed live with head-byte logging:
                # heads=[b'RPCV...canary', b'WG-LIVENESS-PING:...']).  On
                # Linux/BSD, ICMP-unreachable from stale spray probes does
                # surface as ConnectionRefusedError on the next recv, but
                # selector_proxy already handles that via its
                # UDP_ECONNREFUSED_LIMIT=8 streak counter -- so we can leave
                # the cleanup to selector_proxy on all platforms and avoid
                # ever consuming legitimate inbound here.
                log("[RP-WORKER] skipping post-connect stale drain "
                    "(SIO_UDP_CONNRESET=FALSE on Windows / selector_proxy "
                    "ECONNREFUSED streak handles Linux)")

                # Signal convergence BEFORE entering selector_proxy so
                # main can resolve result and the demo can start sending.
                # selector_proxy starts on the very next line -- by the
                # time asyncio processes the call_soon_threadsafe the
                # proxy is already in its select() loop.
                loop_for_bridge.call_soon_threadsafe(
                    signal_bridge_ready, True,
                )
                log("[RP-WORKER] entering selector_proxy")
                selector_proxy(
                    punched_sock_ref,
                    listener_addr_ref,
                    stop_reader,
                    sock_proto=socket_mod.SOCK_DGRAM,
                    socket_r=worker_sock_ref,
                )
                log("[RP-WORKER] selector_proxy returned; worker exiting")
            except Exception:  # pylint: disable=broad-except
                log("[RP-WORKER] worker EXC")
                log_exception()
                loop_for_bridge.call_soon_threadsafe(
                    signal_bridge_ready, False,
                )

        worker_fut = loop_for_bridge.run_in_executor(None, bridge_worker)

        def worker_done(fut):
            if not bridge_ready_fut.done():
                bridge_ready_fut.set_result(False)
        worker_fut.add_done_callback(worker_done)

        # Wait until the bridge is live (drain + connect done) before
        # handing the pipe to the caller. Ceiling covers drain (~0.8s)
        # + connect + small slop.
        bridge_ceiling = 5.0
        try:
            bridge_ready = asyncio.wait_for(
                bridge_ready_fut, timeout=bridge_ceiling,
            )
        except asyncio.TimeoutError:
            bridge_ready = False

        if not self.result.done():
            # Return PipeEvents (not the outer Pipe wrapper) so
            # verify_pipe_alive's liveness-future registration and the
            # subsequent inbound-msg_cb dispatch agree on which object
            # holds liveness_pong_futures.  Same fix as udp_punch's
            # set_result; see that plugin for the full writeup.  Without
            # it, PONG arrives at PipeEvents (data-bearing layer) but
            # the future was registered on the outer Pipe, never
            # resolves, verify_pipe_alive times out -> DEAD.
            returned_pipe = pipe.pipe_events if (
                bridge_ready and getattr(pipe, "pipe_events", None) is not None
            ) else (pipe if bridge_ready else None)
            self.result.set_result(returned_pipe)

        # Diagnostic: send a literal RAW-SOCK probe directly on
        # the underlying sock (bypassing the Pipe entirely) to
        # test whether the issue is the sock or the Pipe wrap.
        # If sym's [RP-INBOUND] shows this msg, the sock works
        # post-Pipe-wrap and the bug is in pipe.send.  If it
        # doesn't, the sock itself stopped working after wrap.

    def close(self):
        """Close bridge sockets and cancel the result future.

        Mirrors udp_punch's close() so close_plugin() in traversal_utils
        can call it on timeout/CancelledError paths. The bridge_worker
        thread sees EBADF/OSError on the closed sockets and exits.
        """
        for sock in getattr(self, "bridge_socks", []):
            try:
                sock.close()
            except OSError:
                pass
        self.bridge_socks = []

        prebound = getattr(self, "prebound_sock", None)
        if prebound is not None:
            try:
                prebound.close()
            except OSError:
                pass
            self.prebound_sock = None

        if not self.result.done():
            self.result.cancel()

    # ── helpers ─────────────────────────────────────────────────

    def set_failed_result(self):
        """Resolve self.result with None so node.connect returns
        promptly instead of waiting out the plugin timeout."""
        if not self.result.done():
            self.result.set_result(None)

    def build_msg(self, role, punch_time, magic):
        """Build the RandomProbeMsg this side sends to its peer.

        ext_ip in the payload carries whichever address the algorithm
        will actually fire at:
          * NIC_BIND (LAN test path): always use my_addr_ip (the
            local NIC IP). Skipping the STUN-derived mapped_ip
            here is essential -- on a NAT'd host STUN returns the
            WAN address, but for LAN testing both peers fire at
            each other's LAN IPs and the WAN advertisement would
            cause the peer to spray packets out their NIC instead
            of locally.
          * Otherwise (EXT_BIND production): STUN-discovered mapped
            IP first, falling back to my_addr_ip when STUN didn't
            run (sym side) or didn't return a mapping.
        """
        if self.route_type == NIC_BIND:
            ext_ip = getattr(self, "my_addr_ip", "") or ""
        else:
            ext_ip = (
                getattr(self, "mapped_ip", None)
                or getattr(self, "my_addr_ip", "")
                or ""
            )
        return RandomProbeMsg({
            "payload": {
                "role": role,
                "punch_time": int(punch_time),
                "magic": magic,
                "ext_ip": str(ext_ip),
                "known_port": self.our_known_port(),
                "probe_count": RANDOM_PROBE_DEFAULT_COUNT,
            },
        })

    def prebind_non_sym_sock(self):
        """Bind the non-sym side's UDP socket *before* signaling +
        STUN-discover the (mapped_ip, mapped_port) it lands at.

        Stashed on self.prebound_sock and reused by run_non_sym_side
        at fire time.  The peer needs the *mapped* (external) IP and
        port to aim at, not the local bind port -- on a real NAT the
        external port is whatever the router assigned, not necessarily
        the local source port.  Without this STUN step the peer fires
        256 probes at a port the cone's NAT has no mapping for, every
        one gets dropped at the cone's NAT, and the round can never
        converge.

        Deadlined against ``self.punch_time``: STUN discovery is on the
        critical path between "send the signal" and "fire the spray",
        and a slow-responding STUN pool used to burn up to 16 s here
        (4 servers * 2.0 s timeout * 2 retries) while the rendezvous
        ticked by silently.  We give STUN at most STUN_SAFETY seconds
        less than the time until punch_time, fail-fast on the remainder,
        and fall back to local port if nothing replied in time.

        Falls back to (local_ip, local_port) when no STUN servers are
        available or the queries time out -- in that case the
        algorithm only works on full-cone NATs that happen to do port
        preservation, which matches the pre-STUN behaviour and is
        still useful for same-machine / loopback testing.
        """
        try:
            route = self.bind()
        except (OSError, ValueError):
            log("RandomProbePlugin: pre-bind route bind failed")
            return
        try:
            self.prebound_sock = make_udp_socket(
                self.src["ip"], 0, route=route,
            )
            self.prebound_port = self.prebound_sock.getsockname()[1]
        except OSError:
            log("RandomProbePlugin: pre-bind UDP socket failed")
            self.prebound_sock = None
            self.prebound_port = 0
            return

        # STUN-discover the external mapping.  We pull UDP STUN
        # servers via get_infra (the existing node.stun_clients are
        # TCP-only -- they're for the punch plugin) and try each in
        # turn; the first one that replies wins.  On total failure
        # we leave self.mapped_* unset and fall back to the local
        # port (cone-NAT-with-port-preservation case + same-machine
        # local tests where there's no NAT in the path).
        self.mapped_ip = None
        self.mapped_port = None
        stun_servers = self.udp_stun_servers()
        if not stun_servers:
            log("RandomProbePlugin: no UDP STUN servers available, "
                "advertising local port as known_port (works only "
                "for full-cone-with-port-preservation peers)")
            return

        # Deadline STUN discovery against the rendezvous: STUN must
        # finish in time to advertise the mapping in the outgoing
        # RandomProbeMsg, which we only get to send if punch_time is
        # still ahead.  STUN_SAFETY leaves the post-STUN signal+settle
        # window of the punch protocol.  Without this gate a slow STUN
        # pool burned up to 16s here while punch_time ticked by silently
        # (4 servers * 2s timeout * 2 retries) and we missed the bucket.
        STUN_SAFETY = 2.0
        punch_time = getattr(self, "punch_time", None)
        if punch_time is None:
            stun_budget = None
        else:
            stun_budget = punch_time - self.sys_clock.time() - STUN_SAFETY
            if stun_budget <= 0:
                log("RandomProbePlugin: no STUN budget; punch_time too "
                    "close (rendezvous in {0:.1f}s); skipping STUN".format(
                        punch_time - self.sys_clock.time(),
                    ))
                return

        loop = get_running_loop()
        for stun_server in stun_servers:
            if stun_budget is not None and stun_budget <= 0:
                log("RandomProbePlugin: STUN budget exhausted before "
                    "trying all servers; falling back to local port")
                break
            try:
                t0 = self.sys_clock.time()
                resolved = self.resolve_stun_dest(stun_server)
            except (OSError, ConnectionError, asyncio.TimeoutError):
                if stun_budget is not None:
                    stun_budget -= self.sys_clock.time() - t0
                continue
            # Per-server timeout: bound to whichever is smaller -- the
            # default 2s probe budget or the remaining STUN_BUDGET so
            # we never bleed into the punch_time window.
            if stun_budget is not None:
                per_server_timeout = max(0.5, min(2.0, stun_budget))
            else:
                per_server_timeout = 2.0
            # Run the STUN query in a thread executor using
            # sync blocking I/O -- the prebound sock should
            # never get touched by asyncio.add_reader before
            # Pipe.connect takes ownership post-algorithm.
            mapping = loop.run_in_executor(
                None,
                lambda srv=resolved, t=per_server_timeout: sync_stun_discover_mapping(
                    self.prebound_sock, srv, self.af,
                    timeout=t, retries=2,
                ),
            )
            if stun_budget is not None:
                stun_budget -= self.sys_clock.time() - t0
            if mapping is not None:
                self.mapped_ip, self.mapped_port = mapping
                log("RandomProbePlugin: STUN discovered mapping "
                    "{0}:{1} for prebound local port {2}".format(
                        self.mapped_ip, self.mapped_port,
                        self.prebound_port,
                    ))
                return
        log("RandomProbePlugin: STUN discovery failed on all servers; "
            "falling back to local port {0}".format(self.prebound_port))

    def udp_stun_servers(self):
        """Return up to 4 UDP STUN server (ip, port) tuples for our AF.

        Pulls from aionetiface's get_infra rather than node.stun_clients
        because the latter holds *TCP* STUN clients used by the punch
        plugin -- random_probe is UDP-only and needs UDP servers.
        """
        try:
            from aionetiface import get_infra, UDP
        except ImportError:
            return []
        try:
            entries = get_infra(self.af, UDP, "STUN(see_ip)", no=4)
        except (KeyError, ValueError):
            return []
        out = []
        for entry in entries:
            # get_infra returns lists of dicts; first dict has ip/port.
            try:
                rec = entry[0] if isinstance(entry, list) else entry
                out.append((rec["ip"], int(rec["port"])))
            except (KeyError, IndexError, TypeError, ValueError):
                continue
        return out

    def resolve_stun_dest(self, dest):
        """DNS-resolve *dest* using the plugin's NIC + AF context."""
        from aionetiface import resolv_dest
        return resolv_dest(self.af, dest, self.nic)

    def our_known_port(self):
        """Known external port to advertise; 0 when we're playing sym role.

        Checks our *assigned role* (set in run() based on the
        NAT-restrictiveness comparison + IP tie-break), NOT our raw
        NAT type.  Both nodes can have SYMMETRIC_NAT and one still
        plays "non_sym" via the tie-breaker -- in that case the
        non_sym side has a prebound socket whose mapped port the
        peer NEEDS to know, otherwise sym fires all 256 probes at
        port 0 and the round can never converge.
        """
        if getattr(self, "session_role", None) == "sym":
            return 0
        # Prefer the STUN-discovered mapped port -- that's the port
        # the peer's probes actually need to target on a real NAT.
        mapped = getattr(self, "mapped_port", None)
        if mapped:
            return int(mapped)
        # Fall back to the local prebind port: only correct when the
        # NAT does port preservation (full cone, single ext = local)
        # or when there's no NAT at all (same-machine / loopback).
        prebound = getattr(self, "prebound_port", 0)
        if prebound:
            return int(prebound)
        bp = self.src.get("bind_port") or 0
        return int(bp)


def p_or_default(key):
    """Look up *key* in FAST_PUNCH_PARAMS with a sensible fallback."""
    return float(FAST_PUNCH_PARAMS.get(key, 8.0))


class RandomProbePluginFactory:
    """Builds RandomProbePlugin instances with a shared SysClock.

    UDP STUN servers are pulled on-demand via get_infra inside
    prebind_non_sym_sock (the node's own stun_clients dict is TCP,
    used by the punch plugin).
    """

    def __init__(self, sys_clock=None):
        self.sys_clock = sys_clock or SysClock(None, 0.1)

    def build_plugin(self):
        """Create a new RandomProbePlugin wired to this factory's SysClock."""
        plugin = RandomProbePlugin()
        plugin.sys_clock = self.sys_clock
        return plugin

    def close(self):
        """No-op: the factory holds no socket / process state."""
        return None




# ─────────────────────────────────────────────────────────────────
# Design note: why UDP, not TCP
# ─────────────────────────────────────────────────────────────────
# The punch plugin uses TCP because port prediction (predictable
# symmetric or LAN) gives both sides a fixed target before they
# fire, so simultaneous-open is workable.  The random-probe path
# does NOT have a fixed target: the symmetric side burns a fresh
# external port per probe and the cone side has to land a SYN on
# one of those random ports while the symmetric NAT still treats
# it as "established" rather than dropping it as unsolicited.
# That's a much narrower race than UDP's "any datagram delivered
# wins", and many consumer NATs / Windows TCP stacks drop the
# inbound SYN-on-our-mapping case outright.  Tailscale's blog is
# explicit that their random-probe path is UDP-only; this plugin
# follows suit.
