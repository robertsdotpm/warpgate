"""Pure-sync UDP hole-punch engine.

UDP is connectionless, so the engine is simpler than tcp_punch:

  1. bind one DGRAM socket per (src_bind, dst_port) port_alloc
  2. wait until punch_time (NTP-synchronised barrier)
  3. spray PROBE frames from each bound socket to (peer_ext_ip,
     dst_port) for spray_duration seconds
  4. concurrently watch every bound socket via select() for inbound
  5. first valid PROBE inbound -> reply with CONFIRM on the same
     4-tuple; first valid CONFIRM inbound -> winner.

No process pool / no reverse-connect: UDP success is in-process so
the engine returns the winning socket directly. The caller wraps
that socket in a Pipe(UDP, dest, route, sock=existing).

Lessons re-applied from random_probe:
  * Pure blocking sockets + select(); never register on asyncio
    selectors during the algorithm phase. After ~256 add_reader/
    remove_reader cycles asyncio's selector silently stops firing
    _read_ready and the wrap goes deaf.
  * MSG_PEEK to look at unrecognised frames so application traffic
    arriving early on the bound port isn't drained by the punch
    loop -- the post-punch Pipe wrap needs that data.
"""
import select
import socket
import sys
import time

from aionetiface import fstr, log, sock_has_data
from aionetiface.net.address import resolve_dest_tup
from aionetiface.net.net_utils import zero_v6_flowinfo

from ..tcp_punch.tcp_punch_utils import bind_punch_sockets
from .udp_punch_defs import (
    UDP_PUNCH_KIND_CONFIRM,
    UDP_PUNCH_KIND_PROBE,
    UDP_PUNCH_MAX_FRAME_LEN,
    build_frame,
    parse_frame,
)


# Peek / drain buffer wide enough for the longest punch frame we
# accept.  All frames are STUN now (Binding Request 20 bytes or
# Binding Success Response with optional XOR-MAPPED-ADDRESS up to
# ~44 bytes for IPv6); UDP_PUNCH_MAX_FRAME_LEN gives generous
# headroom.  Sizing too small would: (a) truncate STUN frames on
# MSG_PEEK so parse_frame rejects them on length, and (b) on Windows
# trigger WSAEMSGSIZE on the drain recvfrom because the kernel
# discards the unread tail.
PUNCH_RECV_BUFLEN = UDP_PUNCH_MAX_FRAME_LEN


# Module-level fallbacks. Per-call params dicts override these.
SPRAY_DURATION = 5.0
LISTEN_DURATION = 6.0
from ..tcp_punch.punch_defs import RETRY_INTERVAL  # noqa: E402 reuse tcp_punch's value
# Aggressive 50 Hz (0.02s) sprayed 17 sockets * 50 * 3s = 2550 packets total,
# triggering router UDP-burst caps on the inbound side -- wire capture showed
# master sending 2437 Out and slave receiving 17 (~0.7% delivery).  Drop to
# 0.5s (2 Hz) -- 17 sockets * 2 Hz * 3s = ~102 packets total, well under
# any consumer-router burst threshold while still giving each socket 6 PROBE
# retransmits.  Convergence only needs ONE PROBE through each direction +
# one CONFIRM back; the CONFIRM-spread above provides 10 reply attempts.
SPRAY_INTERVAL = 0.5


def fire_probes(
    bound_socks,
    dest_ip,
    nonce,
    spray_duration,
    spray_interval=SPRAY_INTERVAL,
    stop_reader=None,
):
    """Spray PROBE frames at the destination for spray_duration seconds.

    Each bound socket sends to (dest_ip, alloc.dest_port) so the
    cross-product covers every predicted (src_port, dst_port) tuple
    the NAT could have allocated. spray_interval throttles to avoid
    thundering-herd on the local NAT and the peer's NIC.

    stop_reader is the project-wide stop socket (Plugin's
    self.stop_reader / Node.stop_rw[0]). When node_stop fires,
    sock_has_data flips True and the spray loop bails on the next
    iteration so the executor thread exits before the asyncio loop
    closes, killing the 'Event loop is closed' callback noise at
    teardown.
    """
    frame = build_frame(UDP_PUNCH_KIND_PROBE, nonce)
    end = time.monotonic() + spray_duration
    # Resolve the v6-link-local 4-tuple ONCE per dest_port and reuse
    # it every spray round. getaddrinfo is synchronous + IP-literal
    # so it costs ~microseconds, but doing it inside the inner loop
    # would still be wasteful at spray rates.
    af = bound_socks[0][1].family if bound_socks else socket.AF_INET
    dest_tups = [
        resolve_dest_tup(af, dest_ip, a.dest_port, socket.SOCK_DGRAM)
        for a, _ in bound_socks
    ]
    log(fstr(
        "udp_punch.fire_probes: starting spray dest_ip={0} sockets={1} dest_tups={2} duration={3}s nonce={4}",
        (dest_ip, len(bound_socks), dest_tups, spray_duration, nonce.hex()),
    ))
    rounds = 0
    sendto_errors = 0
    sock_has_data_errors = 0
    last_heartbeat = time.monotonic()
    try:
        while time.monotonic() < end:
            try:
                stop_signalled = (
                    stop_reader is not None and sock_has_data(stop_reader)
                )
            except (OSError, ValueError):
                # stop_reader can be closed by node_stop while the
                # spray is still running (worker thread outlives the
                # demo's natural exit). Treat as "no stop signal" so
                # the spray completes its window rather than dying.
                sock_has_data_errors += 1
                if sock_has_data_errors <= 3:
                    log("udp_punch.fire_probes: sock_has_data on stop_reader "
                        "raised an OSError/ValueError; treating as no-stop")
                stop_signalled = False
            if stop_signalled:
                log("udp_punch.fire_probes: stop_reader signalled; aborting spray")
                return
            for (_, s), tup in zip(bound_socks, dest_tups):
                try:
                    s.sendto(frame, tup)
                except OSError as exc:
                    # ICMP-unreachable on some NATs surfaces as ECONNREFUSED
                    # the NEXT sendto. Ignore -- next round will retry.
                    sendto_errors += 1
                    if sendto_errors <= 3 or sendto_errors % 50 == 0:
                        log("udp_punch.fire_probes: sendto err #" +
                            str(sendto_errors) + " on tup=" + str(tup) +
                            ": " + repr(exc))
            rounds += 1
            now = time.monotonic()
            if now - last_heartbeat >= 0.5:
                elapsed = "{0:.2f}".format(now - (end - spray_duration))
                remaining = "{0:.2f}".format(end - now)
                log(fstr(
                    "udp_punch.fire_probes: heartbeat round={0} elapsed={1}s remaining={2}s",
                    (rounds, elapsed, remaining),
                ))
                last_heartbeat = now
            time.sleep(spray_interval)
    except Exception as exc:  # pylint: disable=broad-except
        log("udp_punch.fire_probes: LOOP RAISED " + repr(exc) +
            " at round=" + str(rounds))
        raise
    log(fstr(
        "udp_punch.fire_probes: spray ended after {0} rounds dest_ip={1} sendto_errs={2} stop_errs={3}",
        (rounds, dest_ip, sendto_errors, sock_has_data_errors),
    ))


def log_sock_addr(sock):
    """Format a socket's bound address as host:port for logs (best-effort)."""
    try:
        addr = sock.getsockname()
        return "{0}:{1}".format(addr[0], addr[1])
    except OSError:
        return "<closed>"




def watch_for_winner(
    bound_socks,
    nonce,
    listen_duration,
    retry_interval=RETRY_INTERVAL,
    stop_reader=None,
    is_master=False,
):
    """Watch every bound socket for inbound; return (winner_sock, peer_addr) or None.

    Master/slave protocol (modelled on tcp_punch's choose_winning_tcp_sock):

      * Master locks on the FIRST matching frame to land on any of its
        bound sockets (PROBE or CONFIRM).  Sends a 5x CONFIRM burst
        from that socket so the slave's listener picks up the marker
        even under packet loss.

      * Slave refuses to lock on PROBEs -- those race each side's
        independent first-arrival, which is the bug we're fixing.
        Reflects a CONFIRM back on each PROBE arrival so the master
        has paths to choose from and master's NAT pinhole stays warm,
        but only commits to a socket once a CONFIRM lands -- by
        construction that CONFIRM came from master AFTER master
        picked, so both sides agree on the path.

    With n=1 (single boundary port) is_master is irrelevant -- there
    is only one socket on each side, no race to break.  Multi-socket
    cases (boundary + STUN-derived ports for NAT prediction) are where
    the master/slave election bites: without it, A's first CONFIRM
    arrival could land on a different socket than B's first CONFIRM,
    leaving each side connected to a closed peer port.

    Non-frame datagrams are LEFT in the kernel queue (we use
    MSG_PEEK). Real application traffic arriving on a bound port
    before convergence ends up routed to the wrapping Pipe, not
    consumed here.
    """
    socks = [s for _, s in bound_socks]
    if not socks:
        log("udp_punch.watch_for_winner: no bound sockets; nothing to watch")
        return None

    # confirm_frame is built per-PROBE arrival in the loop below.  A
    # STUN Binding Success Response must carry an XOR-MAPPED-ADDRESS
    # attribute describing the peer's reflexive address (RFC 5389
    # §6.3.3), so the frame depends on the peer addr we just learned
    # from recvfrom -- can't be precomputed.
    end = time.monotonic() + listen_duration
    log(fstr(
        "udp_punch.watch_for_winner: watching {0} sockets at {1} duration={2}s nonce={3}",
        (len(socks), [log_sock_addr(s) for s in socks], listen_duration, nonce.hex()),
    ))
    probes_seen = 0
    confirms_seen = 0
    foreign_seen = 0

    while time.monotonic() < end:
        if stop_reader is not None and sock_has_data(stop_reader):
            log("udp_punch.watch_for_winner: stop_reader signalled; aborting")
            return None
        timeout = min(retry_interval, end - time.monotonic())
        if timeout < 0:
            break
        try:
            ready, _, _ = select.select(socks, [], [], timeout)
        except (OSError, ValueError):
            break

        for s in ready:
            # MSG_PEEK: don't drain unrecognised data.
            try:
                buf, addr = s.recvfrom(PUNCH_RECV_BUFLEN, socket.MSG_PEEK)
            except OSError:
                continue

            # Zero v6 flowinfo for XP-stack OverflowError protection.
            addr = zero_v6_flowinfo(addr)

            kind, recv_nonce = parse_frame(buf)
            if kind is None or recv_nonce[:12] != nonce[:12]:
                # Not a punch frame from this session (wrong nonce or format).
                # Drain it so the queue advances to real punch frames.
                # MSG_PEEK always surfaces the oldest datagram — a stuck
                # foreign packet blocks every punch frame behind it and
                # causes select() to spin at 100% CPU until the window ends.
                try:
                    s.recvfrom(65535)
                except OSError:
                    pass
                foreign_seen += 1
                continue

            # It IS a punch frame -- consume the bytes off the queue.
            try:
                s.recvfrom(PUNCH_RECV_BUFLEN)
            except OSError:
                continue

            # XP flowinfo already zeroed above; reuse the same addr.
            sendto_addr = addr

            if kind == UDP_PUNCH_KIND_PROBE:
                probes_seen += 1
                log(fstr(
                    "udp_punch.watch_for_winner: PROBE on {0} from {1} (probes={2}); replying CONFIRM",
                    (log_sock_addr(s), addr, probes_seen),
                ))
                # Reflect a CONFIRM so the peer sees this path.  Slave
                # only sends one (master-driven path is enough); master
                # sprays the CONFIRM over time so the slave's recv loop
                # has multiple chances to land one through high inbound
                # UDP loss on the slave's NAT.  A tight 5x burst at
                # ~0.7% delivery (observed on consumer-router LAN here)
                # has expected = 0 CONFIRMs through; spreading the
                # CONFIRMs across ~1s with 100ms gaps gives the slave's
                # 3s watch window 10 separate landing opportunities and
                # stays well under any burst-rate cap.  Slave's reply
                # stays at burst=1 -- master locks on the FIRST PROBE
                # arrival, so it doesn't need a long reply window.
                if is_master:
                    confirm_burst = 10
                    confirm_interval = 0.1
                else:
                    confirm_burst = 1
                    confirm_interval = 0.0
                # Build CONFIRM per peer addr -- STUN Binding Success
                # Response needs an XOR-MAPPED-ADDRESS attribute pointing
                # at the peer's reflexive transport address (the addr we
                # just got from recvfrom).  Native P2UP mode ignores
                # peer_addr.
                confirm_frame = build_frame(
                    UDP_PUNCH_KIND_CONFIRM, nonce, peer_addr=sendto_addr,
                )
                for i in range(confirm_burst):
                    try:
                        s.sendto(confirm_frame, sendto_addr)
                    except OSError as exc:
                        log(fstr(
                            "udp_punch.watch_for_winner: CONFIRM sendto failed on {0} to {1}: {2}",
                            (log_sock_addr(s), sendto_addr, repr(exc)),
                        ))
                        break
                    if confirm_interval and i < confirm_burst - 1:
                        time.sleep(confirm_interval)
                if is_master:
                    log(fstr(
                        "udp_punch.watch_for_winner: MASTER locking on PROBE arrival; sock={0} peer={1}",
                        (log_sock_addr(s), addr),
                    ))
                    return (s, addr)
                # Slave keeps listening for the master's CONFIRM marker.
                continue

            if kind == UDP_PUNCH_KIND_CONFIRM:
                confirms_seen += 1
                log(fstr(
                    "udp_punch.watch_for_winner: CONFIRM on {0} from {1} -- WINNER",
                    (log_sock_addr(s), addr),
                ))
                return (s, addr)

    log(fstr(
        "udp_punch.watch_for_winner: listen_duration ended -- probes={0} confirms={1} foreign={2}",
        (probes_seen, confirms_seen, foreign_seen),
    ))

    # Fallback: no CONFIRM arrived but we may have replied to a PROBE.
    # Walk sockets once more peeking for any pending CONFIRM that
    # arrived just as we exited the loop.
    #
    # Slave grace window: if we replied to at least one of master's PROBEs
    # but never received the master's 5x CONFIRM burst, give 20ms for the
    # burst to arrive in-flight.  A PROBE arriving near the last ms of
    # listen_duration would cause master to send its burst right as we
    # exited the loop; 20ms is 2x a typical LAN RTT and safely below any
    # meaningful timeout.  Master doesn't need this because it returns
    # immediately on its first PROBE arrival.
    fallback_timeout = 0.0
    if not is_master and probes_seen > 0 and confirms_seen == 0:
        fallback_timeout = 0.020
        log("udp_punch.watch_for_winner: slave grace window 20ms (probes_seen={0})".format(
            probes_seen,
        ))
    try:
        ready, _, _ = select.select(socks, [], [], fallback_timeout)
    except (OSError, ValueError):
        ready = []
    for s in ready:
        try:
            buf, addr = s.recvfrom(PUNCH_RECV_BUFLEN, socket.MSG_PEEK)
        except OSError:
            continue
        addr = zero_v6_flowinfo(addr)
        kind, recv_nonce = parse_frame(buf)
        if kind == UDP_PUNCH_KIND_CONFIRM and recv_nonce[:12] == nonce[:12]:
            try:
                s.recvfrom(PUNCH_RECV_BUFLEN)
            except OSError:
                pass
            return (s, addr)
        # Drain foreign datagram so it doesn't hide a CONFIRM sitting behind it.
        try:
            s.recvfrom(65535)
        except OSError:
            pass

    return None


def drain_punch_residue(sock, nonce):
    """Synchronously drain queued PROBE/CONFIRM frames sitting in the kernel
    buffer for *sock* before it's wrapped in a Pipe.

    Same shape as random_probe.drain_probe_residue: peek at each
    pending datagram via MSG_PEEK; when the leading bytes match a
    punch frame with our session nonce, consume it; otherwise stop
    so non-frame application data passes through to the wrapping
    Pipe untouched.
    """
    sock.setblocking(False)
    drained = 0
    while True:
        try:
            buf, _ = sock.recvfrom(PUNCH_RECV_BUFLEN, socket.MSG_PEEK)
        except (BlockingIOError, OSError):
            break
        kind, recv_nonce = parse_frame(buf)
        if kind is None or recv_nonce[:12] != nonce[:12]:
            break
        try:
            sock.recvfrom(PUNCH_RECV_BUFLEN)
        except OSError:
            break
        drained += 1
    return drained


def udp_punch_engine(
    af,
    nic_id,
    port_allocs,
    src_ip,
    dest_ip,
    f_sleep_until,
    nonce,
    same_machine=False,
    params=None,
    stop_reader=None,
    route=None,
    decider_ip=None,
):
    """Drive a full UDP punch: bind, barrier-sleep, fire, watch, return winner.

    Returns (sock, peer_addr) for the winning 4-tuple, or None.

    nonce: 16 random bytes both sides agreed on via PunchMsg. Required
           to distinguish a real punch arrival from random scanner
           traffic that happened to hit a predicted src_port.
    """
    if params is not None:
        spray_duration = params.get("connect_timeout", SPRAY_DURATION)
        listen_duration = params.get("monitor_timeout", LISTEN_DURATION)
        retry_interval = params.get("retry_interval", RETRY_INTERVAL)
    else:
        spray_duration = SPRAY_DURATION
        listen_duration = LISTEN_DURATION
        retry_interval = RETRY_INTERVAL

    bound_socks = bind_punch_sockets(
        af, nic_id, port_allocs, src_ip,
        sock_type=socket.SOCK_DGRAM, route=route,
    )
    log(fstr(
        "udp_punch_engine: af={0} src_ip={1} dest_ip={2} bound={3}/{4}",
        (af, src_ip, dest_ip, len(bound_socks), len(port_allocs)),
    ))
    if not bound_socks:
        log("udp_punch_engine: NO sockets bound; aborting")
        return None

    # Master/slave election: same `our_ip > their_ip` trick tcp_punch
    # uses.  Caller (udp_punch/main.py) computes decider_ip with the
    # route-type branch (ext for EXT_BIND, src for NIC_BIND) so both
    # peers compare the same peer-symmetric quantity.  Engine no
    # longer runs its own route.ext()-always heuristic which was
    # wrong for NIC_BIND peers behind a shared NAT (both peers' ext
    # was identical → equality → both went slave → deadlock).
    # Falls back to src_ip if the caller didn't pass decider_ip
    # (legacy callers / standalone CLI).
    own_ip_for_election = decider_ip or src_ip
    from ..tcp_punch.punch_utils import is_master_by_ext
    is_master = is_master_by_ext(own_ip_for_election, dest_ip)

    # Synchronised barrier: wait for the agreed punch_time so both
    # sides spray in the same window.
    f_sleep_until()

    # Slave-side low-TTL NAT priming (R7-1): the slave fires one PROBE
    # per socket with TTL=4 immediately after the barrier.  TTL=4 crosses
    # the local LAN + CPE router + one ISP aggregation hop and then
    # expires (ICMP TTL-exceeded returned); it never reaches the remote
    # peer, but it opens the outbound NAT mapping in this side's router
    # so the master's first arriving PROBE finds an already-open pinhole
    # instead of hitting a closed port-restricted entry.  The master does
    # NOT prime: its role is to be the first to send the real probes that
    # the slave's pinhole will accept.
    #
    # SKIP ON WINDOWS: when the TTL-expired router replies with ICMP
    # Time Exceeded, Windows marks the originating UDP socket as
    # broken (WinError 10052 "keep-alive activity detected failure"
    # on the next recvfrom).  Every subsequent operation on that
    # socket then fails, so the watch_for_winner loop receives zero
    # bytes from the master.  Verified live 2026-05-24 -- the prime
    # is the root cause of the 0/14 Windows udp_punch fail rate.
    # Linux/macOS quietly drop ICMP for UDP and aren't affected.
    # The 3 s spray that follows already opens the NAT mapping on
    # its own, so the prime adds no value when it can't be done
    # safely.
    if not is_master and sys.platform != "win32":
        sock_family = bound_socks[0][1].family if bound_socks else socket.AF_INET
        if sock_family == socket.AF_INET6:
            # socket.IPPROTO_IPV6 / IPV6_UNICAST_HOPS are not always
            # exposed as attributes of the socket module on Windows --
            # they are missing on the Vista Python 3.7 build. Without a
            # fallback the v6 spray's TTL setup raises AttributeError
            # and the whole udp_punch engine aborts, which is exactly
            # why udp_punch was v6-0/5 on vista. Fall back to the fixed
            # IANA protocol/option numbers (IPPROTO_IPV6=41,
            # IPV6_UNICAST_HOPS=4).
            ttl_level = getattr(socket, "IPPROTO_IPV6", 41)
            ttl_opt = getattr(socket, "IPV6_UNICAST_HOPS", 4)
        else:
            ttl_level = socket.IPPROTO_IP
            ttl_opt = socket.IP_TTL
        af_for_prime = sock_family
        prime_frame = build_frame(UDP_PUNCH_KIND_PROBE, nonce)
        prime_tups = [
            resolve_dest_tup(af_for_prime, dest_ip, a.dest_port, socket.SOCK_DGRAM)
            for a, _ in bound_socks
        ]
        for (_, s), tup in zip(bound_socks, prime_tups):
            try:
                orig_ttl = s.getsockopt(ttl_level, ttl_opt)
                s.setsockopt(ttl_level, ttl_opt, 4)
                s.sendto(prime_frame, tup)
                s.setsockopt(ttl_level, ttl_opt, orig_ttl)
            except OSError:
                pass
        log("udp_punch_engine: slave TTL-prime sent on {0} sockets".format(
            len(bound_socks),
        ))

    log("udp_punch_engine: entering fire_probes")
    try:
        fire_probes(
            bound_socks, dest_ip, nonce,
            spray_duration=spray_duration, stop_reader=stop_reader,
        )
    except Exception:
        for _, s in bound_socks:
            try:
                s.close()
            except OSError:
                pass
        raise

    log(fstr(
        "udp_punch_engine: fire_probes returned; entering watch_for_winner role={0} own={1} peer={2}",
        ("MASTER" if is_master else "SLAVE", own_ip_for_election, dest_ip),
    ))
    winner = watch_for_winner(
        bound_socks, nonce, listen_duration,
        retry_interval=retry_interval, stop_reader=stop_reader,
        is_master=is_master,
    )
    log(fstr(
        "udp_punch_engine: watch_for_winner returned {0}",
        ("WINNER" if winner else "None",),
    ))

    if winner is None:
        log("udp_punch_engine: no convergence; returning None")
        # No converge; close every socket so we don't leak FDs.
        for _, s in bound_socks:
            try:
                s.close()
            except OSError:
                pass
        return None

    winner_sock, peer_addr = winner
    log(fstr(
        "udp_punch_engine: WINNER local={0} peer={1}",
        (log_sock_addr(winner_sock), peer_addr),
    ))
    # Close all OTHER sockets; the caller only needs the winner.
    for _, s in bound_socks:
        if s is winner_sock:
            continue
        try:
            s.close()
        except OSError:
            pass

    return (winner_sock, peer_addr)
