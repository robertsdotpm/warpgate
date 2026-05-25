"""
random_probe spray engine: direction-agnostic NAT punch.

Algorithm
---------
Open ``probe_count`` UDP sockets on random local source ports, fire
one probe from each to a random destination port on ``peer_ext_ip``,
then ``select()`` across all sockets for the first incoming probe
carrying the matching nonce.

Why it works for any NAT pair:

* Each fired probe creates an outbound NAT mapping for
  ``(local_src_port, peer_ext_ip, peer_dst_port)``.
* For a peer probe to land here, the peer must hit one of the
  ``probe_count`` open mappings.  With N=256 each side that's
  ~``probe_count^2 / 65000`` ≈ 1 expected collision per round.
* No assumption about NAT type on either end -- symmetric (mobile
  carrier), full-cone, address- / port-restricted all work.

Convergence protocol (master / slave, modelled on tcp_punch)
------------------------------------------------------------
master: locks on the first matching frame to land (PROBE or CONFIRM)
on any of its sockets, sends a 5x CONFIRM burst from that socket
back to peer.  The burst is the "I picked this path" marker the
slave is waiting for; redundancy hides single-packet loss on the
return leg.

slave: refuses to lock on PROBEs (those race each side's independent
first-arrival, which is what broke the previous algorithm).  Reflects
a CONFIRM back on each PROBE arrival so the master has paths to
choose from and so master's NAT pinhole stays warm, but only commits
to a socket once a CONFIRM arrives -- by construction that CONFIRM
came from master AFTER master picked, so both sides agree on the path.

Election
--------
``is_master`` is decided by ``IPRange(own_ext_ip) > IPRange(peer_ext_ip)``.
Both sides MUST compare the same pair for the result to be symmetric:
they receive the peer's wire-advertised ext_ip in the RandomProbeMsg
payload, and their own ``own_ext_ip`` MUST be the same value they
themselves wire-advertise.  Falling back to bind_ip (LAN-side) when
the peer holds STUN-mapped WAN produces NIC-vs-ext asymmetry and
can land both peers on SLAVE.  See main.py's caller for how
``own_ext_ip`` is computed.
"""
import socket
import time

from aionetiface.net.address import resolve_dest_tup
from aionetiface.net.net_utils import zero_v6_flowinfo
from aionetiface.utility.error_logger import log

from .random_probe_defs import (
    RANDOM_PROBE_DEFAULT_COUNT,
    PROBE_IDX_CONFIRM,
    PROBE_LISTEN_TIMEOUT,
    ROLE_SYM,
)
from .random_probe_utils import (
    close_all,
    decode_probe,
    encode_probe,
    make_udp_socket,
    normalize_ip6,
    random_probe_ports,
)


def sync_run_bidirectional_spray(
    bind_ip,
    peer_ext_ip,
    nonce,
    probe_count=RANDOM_PROBE_DEFAULT_COUNT,
    listen_timeout=PROBE_LISTEN_TIMEOUT,
    rng=None,
    route=None,
    own_ext_ip=None,
    max_rounds=2,
):
    """Direction-agnostic random-probe punch.

    Returns ``{"sock": winning_socket, "peer": (ip,port), "role": "spray-*"}``
    on success, or None on timeout.  Caller closes the returned sock.

    ``max_rounds`` controls how many full spray+listen rounds to run
    before giving up.  Each round opens a fresh set of ``probe_count``
    sockets (closed at the end of the round on no_winner).  Reusing
    sockets across rounds was rejected because it doubles the
    simultaneous NAT-mapping count (256 mappings * 2 rounds) and
    consumer routers silently drop v6 UDP past ~256 mappings per host
    (see project_consumer_router_v6_flow_cap memory).
    """
    import select as select_mod
    peer_ext_ip = normalize_ip6(peer_ext_ip)

    log("[RP-SPRAY] enter bind_ip={0} peer_ext_ip={1} own_ext_ip={2} "
        "probe_count={3} listen_timeout={4} max_rounds={5}".format(
            bind_ip, peer_ext_ip, own_ext_ip, probe_count,
            listen_timeout, max_rounds,
        ))

    own_ip_for_election = (
        normalize_ip6(own_ext_ip) if own_ext_ip else normalize_ip6(bind_ip)
    )


    from ..tcp_punch.punch_utils import is_master_by_ext
    is_master = is_master_by_ext(own_ip_for_election, peer_ext_ip)

    log("[RP-SPRAY] role={0} (own_ip_for_election={1} vs peer_ext_ip={2})".format(
        "MASTER" if is_master else "SLAVE", own_ip_for_election, peer_ext_ip,
    ))

    for round_idx in range(max_rounds):
        if round_idx > 0:
            log("[RP-SPRAY] round {0}/{1}: re-spraying with fresh sockets".format(
                round_idx + 1, max_rounds,
            ))
        result = run_spray_round(
            bind_ip=bind_ip,
            peer_ext_ip=peer_ext_ip,
            nonce=nonce,
            probe_count=probe_count,
            listen_timeout=listen_timeout,
            rng=rng,
            route=route,
            own_ip_for_election=own_ip_for_election,
            is_master=is_master,
            select_mod=select_mod,
        )
        if result is not None:
            return result
    log("[RP-SPRAY] FAIL all {0} rounds exhausted".format(max_rounds))
    return None


def run_spray_round(
    bind_ip,
    peer_ext_ip,
    nonce,
    probe_count,
    listen_timeout,
    rng,
    route,
    own_ip_for_election,
    is_master,
    select_mod,
):
    """One spray+listen round.  Closes its own sockets on no_winner; on
    success returns ``{sock, peer, role}`` and the caller owns the sock.
    """
    src_ports = random_probe_ports(probe_count, rng=rng)
    dst_ports = random_probe_ports(probe_count, rng=rng)
    socks = []
    for sp in src_ports:
        try:
            socks.append(make_udp_socket(bind_ip, sp, route=route))
        except OSError:
            continue
    if not socks:
        log("[RP-SPRAY] FAIL no sockets bound out of {0} attempts".format(
            probe_count,
        ))
        return None
    for s in socks:
        s.setblocking(False)
    log("[RP-SPRAY] bound {0} sockets src_ports[0..4]={1}".format(
        len(socks), src_ports[:4],
    ))

    # Fire one probe from each socket to a random destination port.
    # ROLE_SYM marker is kept for backward-compat with peers still
    # running the old asymmetric algorithm (they look for ROLE_SYM
    # and will treat us as the sym peer they expect).  The receive
    # side accepts any role so long as the nonce matches.
    #
    # Rate-governor: cap egress at PROBE_RATE_PPS pps (~10 ms apart).
    # An unrate-limited spray of probe_count sockets * 1 probe each
    # fires the whole burst in milliseconds.  Consumer routers and
    # mobile carriers commonly trigger a port-scan heuristic at
    # ~150 distinct dst-tuples and then drop inbound from the source
    # for ~30 seconds.  That explains the symptom where verify_pipe_alive
    # PING/PONG (right after the spray, before the heuristic fully
    # kicks in) succeeds but the gate-echo round-trip 5 s later fails.
    # The matching sync paths in the old random_probe_lib.py shipped
    # the same governor; restoring it here closes the gap.
    PROBE_RATE_PPS = 100
    INTER_PROBE_S = 1.0 / PROBE_RATE_PPS
    probes_sent = 0
    send_failures = 0
    for idx, (s, dp) in enumerate(zip(socks, dst_ports)):
        try:
            s.sendto(
                encode_probe(nonce, ROLE_SYM, probes_sent),
                resolve_dest_tup(s.family, peer_ext_ip, dp, socket.SOCK_DGRAM),
            )
            probes_sent += 1
        except OSError:
            send_failures += 1
            continue
        if idx + 1 < len(socks):
            time.sleep(INTER_PROBE_S)
    log("[RP-SPRAY] probes_sent={0} send_failures={1} dst_ports[0..4]={2} pps={3}".format(
        probes_sent, send_failures, dst_ports[:4], PROBE_RATE_PPS,
    ))

    deadline = time.monotonic() + listen_timeout
    winner = None
    datagrams_seen = 0
    parsed_ok = 0
    parsed_fail = 0
    peer_ip_mismatch = 0
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            ready, _, _ = select_mod.select(socks, [], [], min(remaining, 1.0))
        except (OSError, select_mod.error):
            break
        if not ready:
            continue
        for s in ready:
            try:
                data, peer = s.recvfrom(2048, socket.MSG_PEEK)
            except ConnectionResetError:
                # WSAECONNRESET = ICMP port-unreachable from one of our
                # probes.  MSG_PEEK does not consume the error on Windows
                # -- every peek fires again until a bare recvfrom drains.
                try:
                    s.recvfrom(2048)
                except (OSError, BlockingIOError):
                    pass
                continue
            except (BlockingIOError, InterruptedError, OSError):
                continue
            # Zero v6 flowinfo (XP OverflowError workaround) + compress
            # the v6 IP for reuse downstream.  zero_v6_flowinfo handles
            # the universal flowinfo+scope_id concern; normalize_ip6 is
            # random_probe-specific (the udp_punch site leaves the IP
            # un-normalised because the existing kernel-returned form
            # is fine for its sendto path).
            peer = zero_v6_flowinfo(peer)
            if len(peer) == 4:
                peer = (normalize_ip6(peer[0]), peer[1], peer[2], peer[3])
            datagrams_seen += 1
            parsed = decode_probe(data, nonce)
            if parsed is None:
                parsed_fail += 1
                # Non-probe -- leave for Pipe; could be early data.
                # Brief sleep so the same datagram at head of queue
                # doesn't spin select() at full speed.
                time.sleep(0.001)
                continue
            parsed_ok += 1
            try:
                s.recvfrom(2048)
            except (BlockingIOError, OSError):
                continue
            # Self-loop guard only.  Don't reject by "peer IP doesn't
            # match the expected ext IP" -- CGNAT-style mobile carriers
            # pool multiple WAN egress IPs and pick per-flow by hash, so
            # the IP STUN reported (against a third-party STUN server)
            # is often NOT the IP that's actually used for traffic to
            # the peer's specific dest.  The 16-byte nonce already
            # provides 2^72 collision space for peer identification --
            # IP matching is redundant defense AND blocks legitimate
            # convergence on CGNAT pools (observed live: 2026-05-25
            # local 2-NIC demo run, mobile-side spray arrived at LAN
            # from an unexpected pool IP and got rejected by this
            # filter; both sides ended at FAIL no_winner).
            if own_ip_for_election and peer[0] == own_ip_for_election:
                peer_ip_mismatch += 1  # reused counter: now "self-loop count"
                continue

            is_confirm = parsed["idx"] == PROBE_IDX_CONFIRM

            if is_master:
                # Master commits on first arrival.  Send a CONFIRM burst
                # from this socket so the slave's listener picks up the
                # marker even under packet loss.  Initial burst is 5
                # frames; the post-commit reinforcement loop (below)
                # adds periodic CONFIRMs over the rest of the listen
                # window so a slave whose first batch of CONFIRMs was
                # dropped still has a chance to lock on a later one.
                for _ in range(5):
                    try:
                        s.sendto(
                            encode_probe(nonce, ROLE_SYM, PROBE_IDX_CONFIRM),
                            peer,
                        )
                    except OSError:
                        pass
                winner = {"sock": s, "peer": peer, "role": "spray-master"}
                break

            # Slave path: only CONFIRMs lock us in.  A plain PROBE gets a
            # CONFIRM-back so master's NAT pinhole on this 4-tuple stays
            # warm and master has at least one path to choose from.
            if is_confirm:
                winner = {"sock": s, "peer": peer, "role": "spray-slave"}
                break
            for _ in range(2):
                try:
                    s.sendto(
                        encode_probe(nonce, ROLE_SYM, PROBE_IDX_CONFIRM),
                        peer,
                    )
                except OSError:
                    pass
        if winner is not None:
            break

    if winner is None:
        log("[RP-SPRAY] FAIL no_winner datagrams_seen={0} parsed_ok={1} "
            "parsed_fail={2} peer_ip_mismatch={3} is_master={4}".format(
                datagrams_seen, parsed_ok, parsed_fail,
                peer_ip_mismatch, is_master,
            ))
        close_all(socks)
        return None

    try:
        winner_local = winner["sock"].getsockname()
    except OSError:
        winner_local = None
    log("[RP-SPRAY] WINNER role={0} datagrams_seen={1} parsed_ok={2} "
        "parsed_fail={3} self_loops={4} winner_local={5} winner_peer={6} "
        "is_master={7}".format(
            winner["role"], datagrams_seen, parsed_ok, parsed_fail,
            peer_ip_mismatch, winner_local, winner["peer"], is_master,
        ))

    # Master post-commit reinforcement: keep firing CONFIRM bursts at
    # the chosen peer 4-tuple for ~2s so a slave that missed the
    # initial 5-packet burst (mobile packet loss, flow-table pressure
    # after the spray) still has a chance to lock.  Without this,
    # master succeeds locally on first PROBE arrival while slave hits
    # PROBE_LISTEN_TIMEOUT no_winner -- master then enters its bridge
    # with a half-open path (PING from master never PONG-ed).
    #
    # Runs in a daemon thread so the engine returns immediately and
    # master's bridge setup proceeds in parallel with reinforcement.
    # The winner sock is shared with the caller -- safe because UDP
    # sendto on the same sock from two threads is atomic per-datagram
    # on POSIX + Windows.  drain_probe_residue in the bridge worker
    # only reads, so no read/write contention.
    if is_master:
        import threading

        def reinforce_confirms():
            reinforce_deadline = time.time() + 2.0
            next_burst = time.time()
            while time.time() < reinforce_deadline:
                now = time.time()
                if now >= next_burst:
                    for _ in range(3):
                        try:
                            winner["sock"].sendto(
                                encode_probe(
                                    nonce, ROLE_SYM, PROBE_IDX_CONFIRM,
                                ),
                                winner["peer"],
                            )
                        except OSError:
                            return  # socket closed by bridge teardown
                    next_burst = now + 0.25
                time.sleep(0.05)

        t = threading.Thread(target=reinforce_confirms, daemon=True)
        t.start()

    # Close losers.
    for s in socks:
        if s is not winner["sock"]:
            try:
                s.close()
            except OSError:
                pass
    return winner
