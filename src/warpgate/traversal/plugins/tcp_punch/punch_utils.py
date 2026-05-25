"""Low-level helpers for the punch engine."""
import time
import socket
import struct
import selectors
import asyncio
from aionetiface import EXT_BIND, IPRange, fstr, log, SysClock
from .punch_defs import (
    MAX_NTP_RETRIES,
    NTP_DELTA,
    NTP_PACKET_SIZE,
    NTP_PORT,
    NTP_SERVER,
    NTP_TIMEOUT,
    PUNCH_END,
    TCP_PUNCH_LAN,
    TCP_PUNCH_REMOTE,
    TCP_PUNCH_SELF,
)


def compute_decider_ip(route_type, src_map):
    """Return the IP that this side identifies as for master/slave election.

    Single source of truth for the EXT_BIND-vs-NIC_BIND branch that
    used to live in tcp_punch / udp_punch / tcp_punch_pcap main.py with
    three drifted bodies:

      - tcp_punch:      ``if NIC_BIND: src["ip"] else: src.get("ext")``
                        -- returned None on missing "ext"
      - udp_punch:      ``if EXT_BIND: src.get("ext") else: src_ip``
                        -- returned None on missing "ext"
      - tcp_punch_pcap: ``if EXT_BIND: src.get("ext") or src_ip else: src_ip``
                        -- correct: falls back to src_ip on missing "ext"

    The OPEN_INTERNET / loopback / pre-classify case where src lacks an
    "ext" key would silently return None from the first two; downstream
    IPRange(None) would crash.  Pick the pcap branch's behaviour --
    always fall back to bind IP if "ext" is missing.

    Returns a string suitable for IPRange() construction.
    """
    src_ip = src_map["ip"] if isinstance(src_map, dict) else src_map
    if route_type == EXT_BIND:
        return src_map.get("ext") or src_ip
    return src_ip


def is_master_by_ext(own_decider_ip, peer_decider_ip):
    """Symmetric master/slave election by IPRange comparison.

    Both peers MUST feed the same pair of decider IPs (their own and the
    peer's wire-advertised ext) for the result to be consistent.  Returns
    False (slave) when either side is missing -- caller's responsibility
    to ensure both inputs are populated before relying on the result.
    """
    if not own_decider_ip or not peer_decider_ip:
        return False
    return IPRange(own_decider_ip) > IPRange(peer_decider_ip)


def timestamp_from_ntp(
server=NTP_SERVER,
    port=NTP_PORT,
    retries=MAX_NTP_RETRIES,
    timeout=NTP_TIMEOUT,
):
    """
    Fetches the Unix timestamp from an NTP server using UDP sockets,
    with built-in retry logic for reliability.
    """
    # NTP request message: 48 bytes, setting mode=3 (client), version=4
    # The first byte is 0b00100011 (0x23)
    request_data = b"\x23" + 47 * b"\0"

    for attempt in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                # Send the request
                s.sendto(request_data, (server, port))
                # Receive the response
                response_data, _ = s.recvfrom(NTP_PACKET_SIZE)

                if len(response_data) < NTP_PACKET_SIZE:
                    raise ValueError("NTP response too short")

                # The Transmit Timestamp is the last 8 bytes (offset 40)
                # It is a 64-bit unsigned fixed-point number (seconds + fraction)
                # We unpack the first 4 bytes (seconds part)
                ntp_time_seconds = struct.unpack("!I", response_data[40:44])[0]

                # Convert from NTP epoch (1900) to Unix epoch (1970)
                unix_time = ntp_time_seconds - NTP_DELTA

                return int(unix_time)

        except socket.timeout:
            time.sleep(0.1)
        except (OSError, struct.error):
            # Handle other socket errors or unpacking issues
            time.sleep(0.1)

    raise OSError("Failed to get reliable network time")


"""
The function bellow is used to adjust sleep parameters
for the punching algorithm. Sleep time is reduced
based on how close the destination is.
"""


def get_punch_mode(af, dest_ip, same_machine):
    """Return the punch mode constant (remote, LAN, or self) for the given destination IP."""
    host_limit = 0
    dest_ipr = IPRange(dest_ip, bitlen=host_limit)

    # Calculate punch mode
    if dest_ipr.is_public:
        return TCP_PUNCH_REMOTE
    else:
        if same_machine:
            return TCP_PUNCH_SELF
        else:
            return TCP_PUNCH_LAN


def wait_for_first_with_data(sockets, timeout):
    """
    Wait until one of the sockets has data, then read and return it.
    Returns (socket, data) or (None, None) if timed out.
    """
    sel = selectors.DefaultSelector()

    for s in sockets:
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ)

    deadline = time.monotonic() + timeout
    try:
        while True:
            wait_time = deadline - time.monotonic()
            if wait_time <= 0:
                return None

            events = sel.select(timeout=wait_time)
            if not events:
                return None

            for key, _ in events:
                s = key.fileobj
                try:
                    data = s.recv(1)
                    if data:  # data available
                        return s
                    # else: recv returned 0 → socket closed
                    # let caller handle it if needed
                except BlockingIOError:
                    continue  # not actually ready
                except OSError:
                    continue  # ignore closed/reset sockets
    finally:
        sel.close()


def peer_symmetric_4tuple_key(sock):
    """Sort key that both peers compute identically for the same
    connection. Mirrors tcp_punch_pcap.pcap_engine.sort_key_ft.

    Each peer sees its own ``getsockname()`` as "local" and the
    other end's address as "remote" -- but if we sort the (ip, port)
    pair before returning, both peers produce the SAME tuple for
    the same TCP connection. That gives a deterministic canonical
    winner regardless of which sockets each side happened to see
    establish first.
    """
    try:
        local = sock.getsockname()
        remote = sock.getpeername()
    except (OSError, socket.error):
        return ((), ())
    a = (str(local[0]), int(local[1]))
    b = (str(remote[0]), int(remote[1]))
    return tuple(sorted((a, b)))


# In a LAN = lan ip, or for WAN targets = wan IPs.
def choose_winning_tcp_sock(their_ip, sock_list, our_ip=None, sentinel_wait=None):
    """Select one winning socket from a punched connection set,
    closing the rest.

    The master side picks a canonical winner deterministically by
    sorting ``sock_list`` on the peer-symmetric 4-tuple key (see
    ``peer_symmetric_4tuple_key``) and taking the LAST element.
    Both peers see the same set of 4-tuples in the same canonical
    order, so the master's chosen winner is the same connection the
    non-master is willing to keep. This replaces an earlier
    ``sock_list.pop()`` against the unsorted ``successful`` list,
    which produced a non-deterministic winner depending on which
    sockets happened to reach ESTABLISHED first in the punch monitor
    window.

    ``sentinel_wait`` is the timeout (seconds) the non-master side
    waits for the master's ``b"$"`` sentinel byte to land on one of
    the candidate sockets.  Callers should pass the engine's
    ``monitor_timeout`` (from FAST_PUNCH_PARAMS) so the wait scales
    with the configured punch profile instead of carrying a stale
    hardcoded value.
    """
    # No open sockets.
    if not sock_list:
        return None

    # Master side closes all others immediately.  Wrap both IPs in
    # IPRange for NUMERIC comparison -- the old `our_ip > their_ip`
    # was a Python string compare, which mis-elects when one peer's
    # IP lex-sorts higher than the other's but is numerically smaller
    # (single-digit first octet vs three-digit first octet).
    # IPRange.__lt__ parses both sides via ipaddress.ip_address so
    # the comparison is correct for both v4 and v6.
    from aionetiface import IPRange
    our_ip = our_ip or sock_list[0].getsockname()[0]
    if IPRange(our_ip) > IPRange(their_ip):
        sorted_socks = sorted(sock_list, key=peer_symmetric_4tuple_key)
        winner = sorted_socks[-1]
        losers = [s for s in sorted_socks if s is not winner]
        try:
            winner.send(b"$")
        except OSError:
            try:
                winner.close()
            except OSError:
                pass
            winner = None
        for loser in losers:
            try:
                loser.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

            loser.close()
    else:
        # Non-master side waits for the first completed connection.
        # sentinel_wait=None preserves the legacy 5.0s default for
        # callers that haven't been updated to pass the configured
        # value, but engine callers should always pass monitor_timeout.
        if sentinel_wait is None:
            sentinel_wait = 5.0
        winner = wait_for_first_with_data(sock_list, sentinel_wait)
        for loser in sock_list:
            if loser is not winner:
                try:
                    loser.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                loser.close()

    return winner
