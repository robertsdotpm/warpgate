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
from aionetiface.utility.error_logger import log

from .random_probe_defs import (
    DEFAULT_PROBE_COUNT,
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
    probe_count=DEFAULT_PROBE_COUNT,
    listen_timeout=PROBE_LISTEN_TIMEOUT,
    rng=None,
    interface=None,
    own_ext_ip=None,
):
    """Direction-agnostic random-probe punch.

    Returns ``{"sock": winning_socket, "peer": (ip,port), "role": "spray-*"}``
    on success, or None on timeout.  Caller closes the returned sock.
    """
    import select as select_mod
    peer_ext_ip = normalize_ip6(peer_ext_ip)

    log("[RP-SPRAY] enter bind_ip={0} peer_ext_ip={1} own_ext_ip={2} "
        "probe_count={3} listen_timeout={4}".format(
            bind_ip, peer_ext_ip, own_ext_ip, probe_count, listen_timeout,
        ))

    own_ip_for_election = (
        normalize_ip6(own_ext_ip) if own_ext_ip else normalize_ip6(bind_ip)
    )


    # IPRange comparison for NUMERIC IP semantics.  Raw `>` on string
    # form mis-elects whenever one peer's IP lex-sorts above the
    # other's but is numerically smaller.
    from aionetiface import IPRange
    is_master = IPRange(own_ip_for_election) > IPRange(peer_ext_ip)

    log("[RP-SPRAY] role={0} (own_ip_for_election={1} vs peer_ext_ip={2})".format(
        "MASTER" if is_master else "SLAVE", own_ip_for_election, peer_ext_ip,
    ))

    src_ports = random_probe_ports(probe_count, rng=rng)
    dst_ports = random_probe_ports(probe_count, rng=rng)
    socks = []
    for sp in src_ports:
        try:
            socks.append(make_udp_socket(bind_ip, sp, interface=interface))
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
    probes_sent = 0
    send_failures = 0
    for s, dp in zip(socks, dst_ports):
        try:
            s.sendto(
                encode_probe(nonce, ROLE_SYM, probes_sent),
                resolve_dest_tup(s.family, peer_ext_ip, dp, socket.SOCK_DGRAM),
            )
            probes_sent += 1
        except OSError:
            send_failures += 1
            continue
    log("[RP-SPRAY] probes_sent={0} send_failures={1} dst_ports[0..4]={2}".format(
        probes_sent, send_failures, dst_ports[:4],
    ))

    deadline = time.time() + listen_timeout
    winner = None
    datagrams_seen = 0
    parsed_ok = 0
    parsed_fail = 0
    peer_ip_mismatch = 0
    while time.time() < deadline:
        remaining = deadline - time.time()
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
            # Normalize v6 peer addr (XP flowinfo workaround).
            if len(peer) == 4:
                scope_id = peer[3] if str(peer[0]).lower().startswith("fe80") else 0
                peer = (normalize_ip6(peer[0]), peer[1], 0, scope_id)
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
            if peer_ext_ip and peer[0] != peer_ext_ip:
                peer_ip_mismatch += 1
                continue

            is_confirm = parsed["idx"] == PROBE_IDX_CONFIRM

            if is_master:
                # Master commits on first arrival.  Send a CONFIRM burst
                # from this socket so the slave's listener picks up the
                # marker even under packet loss.
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
        "parsed_fail={3} peer_ip_mismatch={4} winner_local={5} winner_peer={6} "
        "is_master={7}".format(
            winner["role"], datagrams_seen, parsed_ok, parsed_fail,
            peer_ip_mismatch, winner_local, winner["peer"], is_master,
        ))

    # Close losers.
    for s in socks:
        if s is not winner["sock"]:
            try:
                s.close()
            except OSError:
                pass
    return winner
