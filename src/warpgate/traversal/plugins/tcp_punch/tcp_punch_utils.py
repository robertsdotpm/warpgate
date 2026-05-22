"""Utilities for the simple TCP selector punch engine."""
import asyncio
import os
import socket
import struct
import sys
import time
from aionetiface import fstr, log, log_exception
from aionetiface.net.bind.bind_rules import binder_sync
from aionetiface.net.net_utils import ip_strip_if
from aionetiface.net.socket import apply_nic_pin_sockopts
"""
These magic sock options are required for TCP hole punching on
different operating systems.
"""


def sock_opt_voodoo(s):
    """Apply non-blocking mode and the platform-correct address-reuse sockopt for hole punching.

    Windows: SO_REUSEADDR has the *opposite* semantics of POSIX -- it
    permits two sockets to share an exact 4-tuple, which lets a stray
    listener hijack our bound port and confuses the TCP state machine
    during simultaneous-open. SO_EXCLUSIVEADDRUSE is the Windows-correct
    flag: it tells the kernel "no other socket may steal this binding"
    so the simul-open SYN/SYN match converges unambiguously on our
    socket.

    POSIX: SO_REUSEADDR + SO_REUSEPORT (where available) are required
    so the engine can re-bind the predicted port across retries
    without hitting TIME_WAIT, and so multiple punch sockets can share
    the local port if needed.
    """
    s.setblocking(False)
    if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        except OSError:
            # Older Windows / restricted contexts may reject the flag.
            # Fall back to REUSEADDR so the bind still succeeds rather
            # than tearing down the engine.
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Windows' Python socket module has no SO_REUSEPORT attribute at all
        # (raising AttributeError before setsockopt is even called), while some
        # Unixes have the attribute but reject it at runtime (OSError). Both
        # cases are non-fatal here -- punch works without REUSEPORT on platforms
        # that don't support it.
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                # If we are on FreeBSD, this failure is likely fatal for TCP punching
                if sys.platform.startswith("freebsd"):
                    log("Warning: Failed to set SO_REUSEPORT on FreeBSD. Punching will likely fail.")
    """
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_SYNCNT, 2)
    except Exception:
        pass
    """


def bind_punch_sockets(
    af,
    nic_id,
    port_allocs,
    src_ip=None,
    sock_type=socket.SOCK_STREAM,
    route=None,
):
    """Create and bind one socket per port allocation; returns (alloc, sock) pairs.

    Shared by tcp_punch (sock_type=SOCK_STREAM, default) and udp_punch
    (sock_type=SOCK_DGRAM). The socket-opt voodoo, binder_sync call,
    and per-alloc collision handling are identical for both protocols
    so we have one implementation, not two.

    When route is provided, apply_nic_pin_sockopts pins each socket to
    route.interface so egress and bound source agree on multi-NIC
    hosts (LAN + cellular, multi-homed corporate). Without it the
    kernel may pick a different NIC than the one whose IP we bound
    to, the peer sees punch packets from an unexpected external IP,
    and CONFIRMs land on whichever socket happens to have a NAT
    mapping -- typically the demo's main listener, not the engine's
    bound socket.
    """
    if src_ip:
        bind_ip = src_ip
    else:
        bind_ip = "0.0.0.0" if af == socket.AF_INET else "::"

    log("bind_punch_sockets: ENTER sock_type={0} af={1} nic_id={2} src_ip={3} route={4} route.interface={5}".format(
        sock_type, af, nic_id, src_ip,
        "None" if route is None else "<Route>",
        "None" if (route is None or route.interface is None) else getattr(route.interface, "name", "?"),
    ))

    bound_socks = []
    bind_failures = []
    for p in port_allocs:
        s = socket.socket(af, sock_type)
        sock_opt_voodoo(s)
        apply_nic_pin_sockopts(s, route)
        # Bump the receive buffer so burst arrivals during executor
        # stall don't overflow the default 64 KB Windows socket buffer.
        # Applies to both DGRAM (PROBE bursts) and STREAM (SYN-ACK DATA
        # arriving before userspace drains the SYN-ACK notification).
        # Best-effort: the kernel may cap below what we ask for.
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
        except OSError:
            pass
        # SO_LINGER {l_onoff=1, l_linger=0} on TCP punch sockets so close()
        # sends RST instead of FIN -- bypasses TIME_WAIT entirely. Without
        # this, Windows refuses to reuse the same 4-tuple for ~240 s and
        # logs Event 4227 ("selected local endpoint was recently used");
        # back-to-back punches in the same NTP bucket get blocked at the
        # kernel before the SYN ever leaves. Best-effort: ignore failures.
        if sock_type == socket.SOCK_STREAM:
            try:
                s.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack("ii", 1, 0),
                )
            except OSError:
                pass
        # Windows UDP: a sendto to a closed port draws an ICMP
        # port-unreachable, and Windows then makes the *next* recvfrom
        # on that socket raise WSAECONNRESET (WinError 10054). The punch
        # spray fires at many predicted ports -- most closed -- so this
        # fires constantly and aborts the engine's recvfrom loop before
        # the one converging probe is read. SIO_UDP_CONNRESET=False
        # turns the behaviour off so recvfrom only returns real
        # datagrams. v4 punch mostly escaped it (v4 ICMP unreachables
        # are widely rate-limited / filtered in transit); v6 did not
        # (ICMPv6 unreachables come back reliably), which is why
        # udp_punch was v6-0/5 on the Windows matrix VMs.
        if sock_type == socket.SOCK_DGRAM and hasattr(socket, "SIO_UDP_CONNRESET"):
            try:
                s.ioctl(socket.SIO_UDP_CONNRESET, False)
            except OSError:
                pass
        bind_tup = binder_sync(af, ip_strip_if(bind_ip), p.src_port, nic_id)
        bound = False
        for retry in range(4):
            try_port = p.src_port + retry
            if try_port > 65535:
                break
            try_tup = binder_sync(af, ip_strip_if(bind_ip), try_port, nic_id)
            try:
                s.bind(try_tup)
                bound_socks.append((p, s))
                bound = True
                if retry:
                    log(fstr(
                        "bind_punch_sockets: port collision on {0}; rebind to +{1} succeeded",
                        (bind_tup, retry),
                    ))
                break
            except OSError as exc:
                if retry == 3:
                    bind_failures.append((bind_tup, repr(exc)))
        if not bound:
            s.close()

    if bind_failures:
        log(fstr(
            "bind_punch_sockets: {0}/{1} bind(s) FAILED on {2} (af={3} type={4})",
            (len(bind_failures), len(port_allocs), bind_ip, af,
             "DGRAM" if sock_type == socket.SOCK_DGRAM else "STREAM"),
        ))
        for bt, err in bind_failures:
            log(fstr("  bind {0} -> {1}", (bt, err)))
    log(fstr(
        "bind_punch_sockets: {0}/{1} bound on {2} (af={3} type={4})",
        (len(bound_socks), len(port_allocs), bind_ip, af,
         "DGRAM" if sock_type == socket.SOCK_DGRAM else "STREAM"),
    ))

    return bound_socks


def bind_tcp_sockets(
    af,
    nic_id,
    port_allocs,
    src_ip=None,
    route=None,
):
    """Create and bind one TCP socket per port allocation, returning successful (alloc, socket) pairs."""
    return bind_punch_sockets(
        af, nic_id, port_allocs, src_ip,
        sock_type=socket.SOCK_STREAM, route=route,
    )


def listen_on_tcp_sockets(bound_infos):
    """Call listen() on each bound socket, returning those that succeed."""
    listen_infos = []
    for bound_info in bound_infos:
        p, s = bound_info
        try:
            s.listen(1)
            listen_infos.append((p, s))
        except OSError:
            s.close()

    return listen_infos


def connect_on_tcp_sockets(
    same_machine,
    bound_infos,
    dest_ip,
    spray_duration=5.0,
):
    """Spray SYN packets at the destination for `spray_duration` seconds.

    Loops over the bound sockets calling connect_ex on each.  Both peers
    need to be in SYN_SENT when the other's SYN arrives for simul-open
    to fire; repeated user-space pokes maximise the chance of overlap
    even when one side starts slightly later than the other.  Cross-LAN
    runs sleep 5ms between iterations to avoid busy-spin; same-machine
    iterates flat-out since the loopback path has no RTT slack.

    spray_duration: how long to keep spraying (seconds).

    DO NOT add an early-exit on "first ESTABLISHED" here.  We tried
    it (reverted in commit 0c4c2c7) and it raced the TCP simul-open
    four-way handshake: the local socket transitions to ESTABLISHED
    after our kernel sees the peer's SYN-ACK, but the peer may not
    have observed *our* SYN-ACK yet, so the connection is only half-
    confirmed.  Returning early at that point hands choose_winning a
    socket whose peer-side state is still SYN_RECEIVED, which then
    times out / RSTs as soon as we try to use it -- the cascade sees
    `pipe=True` and the first real send fails.  Letting the spray
    run the full window keeps re-firing connect_ex so both kernels
    finish the handshake before socket_event_monitor confirms.  The
    socket_event_monitor pass downstream has its own short
    grace-after-first-success window (50ms, see its docstring) which
    is the only safe spot for an early exit, because by then we've
    already drained the selector events that confirm the handshake
    completed bidirectionally.
    """
    start = time.monotonic()
    end = start + spray_duration
    first_iter = True
    while time.monotonic() < end:
        for p, s in bound_infos:
            try:
                err = s.connect_ex((dest_ip, p.dest_port))
                if first_iter and err not in (0, 36, 115, 10035):
                    log("[ENGINE-DBG] connect_ex({0}:{1}) from src_port={2} -> errno={3}".format(
                        dest_ip, p.dest_port, p.src_port, err,
                    ))
            except OSError as exc:
                if first_iter:
                    log("[ENGINE-DBG] connect_ex raised: " + repr(exc))
        first_iter = False

        if not same_machine:
            time.sleep(0.005)
