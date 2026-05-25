"""
random_probe shared helpers: wire format, sockets, drain, STUN.

Wire format
-----------
Each probe is an RFC 5389 STUN Binding Request, exactly PROBE_LEN (20)
bytes.  The 12-byte STUN Transaction ID carries our session data:

    txid[0:9]   first 9 bytes of the 16-byte session nonce
    txid[9:10]  role byte (ROLE_CONE or ROLE_SYM)
    txid[10:12] 2-byte probe index (big-endian)

9 bytes of nonce is 2^72 collision space; the remaining 7 nonce bytes
stay node-local.  The STUN shape gives ALG / DPI middleboxes no reason
to deprioritise the spray -- traffic is indistinguishable from
legitimate STUN Binding Requests.

Socket helpers
--------------
``make_udp_socket`` is the canonical bind primitive: non-blocking,
SO_REUSEADDR (+ SO_REUSEPORT where available), SIO_UDP_CONNRESET=FALSE
on Windows to silence ICMP-unreachable backwash from the spray,
SO_BINDTODEVICE on Linux for non-default NICs (multi-homed routing).

``drain_probe_residue`` consumes leftover probe datagrams from the
winner socket without eating real user data (MSG_PEEK first; only
consume datagrams that decode as one of our probes).

STUN discovery
--------------
``sync_stun_discover_mapping`` sends one Binding Request and parses
the reply for the mapped (ip, port).  Sync + select-based so it can
run from a thread executor without interacting with the asyncio loop.
"""
import socket
import struct
import sys
import time

from .random_probe_defs import (
    PROBE_IDX_CONFIRM,
    PROBE_LEN,
    PROBE_PORT_HI,
    PROBE_PORT_LO,
    ROLE_CONE,
    ROLE_SYM,
)


IS_WINDOWS = sys.platform == "win32"


# ─────────────────────────────────────────────────────────────────
# Wire format
# ─────────────────────────────────────────────────────────────────


# Wire-format msg_type byte for the only class we emit and accept on
# random_probe: STUN Binding Request (Binding | Request | 0x3fff mask).
# Aliased to STUNMsgTypes.Binding so the same single constant feeds
# both random_probe and udp_punch's BINDING_REQUEST_WIRE_TYPE.
from aionetiface.protocol.stun.stun_defs import STUNMsgTypes
RANDOM_PROBE_WIRE_TYPE = STUNMsgTypes.Binding  # b"\x00\x01"

# Layout offsets inside the 12-byte STUN Transaction ID.
TXID_NONCE_LEN = 9
TXID_ROLE_OFFSET = 9
TXID_IDX_OFFSET = 10


def encode_probe(nonce, role, idx):
    """Pack one probe datagram as a STUN Binding Request.

    *nonce* must be exactly 16 bytes; *role* must be ROLE_CONE or
    ROLE_SYM; *idx* is a per-probe sequence number in [0, 65535]
    (idx=PROBE_IDX_CONFIRM is the cone's terminal CONFIRM marker).

    The result is always PROBE_LEN bytes (20) and parses as a
    bare-bones Binding Request to any RFC 5389 decoder.
    """
    from aionetiface.protocol.stun.stun_defs import (
        RFC5389, STUNMsg, STUNMsgCodes, STUNMsgTypes,
    )

    if len(nonce) != 16:
        raise ValueError("probe nonce must be 16 bytes")
    if role not in (ROLE_CONE, ROLE_SYM):
        raise ValueError("probe role must be ROLE_CONE or ROLE_SYM")

    txid = (
        bytes(nonce[:TXID_NONCE_LEN])
        + bytes(role)
        + struct.pack("!H", idx & 0xFFFF)
    )
    msg = STUNMsg(
        msg_type=STUNMsgTypes.Binding,
        msg_code=STUNMsgCodes.Request,
        mode=RFC5389,
    )
    msg.txn_id = txid
    return msg.pack()


def decode_probe(data, want_nonce):
    """
    Validate that *data* is one of *our* probes for the session
    identified by *want_nonce*.  Returns the parsed fields on hit,
    or None when the datagram doesn't belong to us (wrong length,
    bad magic cookie, wrong msg_type, wrong nonce prefix, unknown
    role).
    """
    if len(data) != PROBE_LEN:
        return None

    from aionetiface.protocol.stun.stun_defs import (
        RFC5389, STUNMsg, STUN_MAGIC_COOKIE,
    )

    if bytes(data[4:8]) != STUN_MAGIC_COOKIE:
        return None
    try:
        msg, _ = STUNMsg.unpack(bytes(data), mode=RFC5389)
    except Exception:  # pylint: disable=broad-except
        return None
    if bytes(msg.msg_type) != RANDOM_PROBE_WIRE_TYPE:
        return None

    txid = bytes(msg.txn_id)
    if txid[:TXID_NONCE_LEN] != bytes(want_nonce[:TXID_NONCE_LEN]):
        return None
    role = txid[TXID_ROLE_OFFSET:TXID_ROLE_OFFSET + 1]
    if role not in (ROLE_CONE, ROLE_SYM):
        return None
    idx = struct.unpack("!H", txid[TXID_IDX_OFFSET:TXID_IDX_OFFSET + 2])[0]
    return {"role": role, "idx": idx}


def looks_like_random_probe(data):
    """Coarse predicate: does *data* have the wire shape of one of our
    probe datagrams?

    Used by stream filters that need to drop probe-shaped residue from
    a post-convergence socket queue without keeping a reference to the
    session nonce.  Does NOT verify nonce or role -- false positives
    are rare (legitimate STUN Binding Requests not from us could match,
    but in practice the filter sits on a punched UDP socket where the
    only incoming traffic is from the peer).  Callers that need
    nonce-tight verification should use decode_probe instead.
    """
    if len(data) != PROBE_LEN:
        return False
    if bytes(data[0:2]) != RANDOM_PROBE_WIRE_TYPE:
        return False
    from aionetiface.protocol.stun.stun_defs import STUN_MAGIC_COOKIE
    if bytes(data[4:8]) != STUN_MAGIC_COOKIE:
        return False
    return True


# ─────────────────────────────────────────────────────────────────
# Probe-port set generation
# ─────────────────────────────────────────────────────────────────


def random_probe_ports(count, rng=None):
    """Return *count* distinct random ports in [PROBE_PORT_LO, PROBE_PORT_HI].

    The cone uses these as destination ports it fires at; the
    symmetric side uses them as source ports it binds from.  Either
    way they need to be unique within the side's own probe set --
    duplicates would just waste probes.
    """
    import random
    if rng is None:
        rng = random.SystemRandom()
    span = PROBE_PORT_HI - PROBE_PORT_LO + 1
    if count > span:
        raise ValueError(
            "probe count {0} exceeds available port range {1}".format(count, span)
        )
    return rng.sample(range(PROBE_PORT_LO, PROBE_PORT_HI + 1), count)


# ─────────────────────────────────────────────────────────────────
# Socket helpers
# ─────────────────────────────────────────────────────────────────


def make_udp_socket(bind_ip, bind_port=0, route=None):
    """Create a non-blocking UDP socket bound to (bind_ip, bind_port).

    The cross-platform NIC-egress pinning (Linux SO_BINDTODEVICE,
    macOS IP_BOUND_IF, BSD, Windows IP_UNICAST_IF) lives in
    ``aionetiface.net.socket.apply_nic_pin_sockopts`` -- we delegate
    to it instead of re-implementing.  The same helper backs the
    async socket_factory + the sync tcp_punch path; this is the
    single source of truth for "bind a socket to a specific NIC".

    *route* is the Route object the caller obtained from
    ``await self.bind()`` -- it carries both .interface and .af and
    is what apply_nic_pin_sockopts needs.

    SO_REUSEADDR (+ SO_REUSEPORT where available) so the symmetric
    side can bind many sockets in close succession even when the
    kernel still holds TIME_WAIT entries from prior runs.

    Windows-only: SIO_UDP_CONNRESET=FALSE silences ICMP-unreachable
    backwash from spray probes that hit closed ports.
    """
    fam = socket.AF_INET6 if ":" in bind_ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    from aionetiface.net.socket import (
        apply_nic_pin_sockopts, disable_udp_connreset_on_windows,
    )
    from ..tcp_punch.tcp_punch_utils import sock_opt_voodoo
    # sock_opt_voodoo handles the Windows REUSEADDR-vs-EXCLUSIVEADDRUSE
    # split + POSIX REUSEPORT.  Before this delegation, make_udp_socket
    # set bare SO_REUSEADDR on Windows -- which has the *opposite*
    # semantics from POSIX (it lets a stray listener hijack the port)
    # -- so two random_probe spray sockets could share a 4-tuple and
    # confuse the engine.  Matches the bug class fixed for the NIC pin
    # by 09e1bb5 (delegating to apply_nic_pin_sockopts).
    sock_opt_voodoo(s)
    disable_udp_connreset_on_windows(s)

    if route is not None:
        apply_nic_pin_sockopts(s, route)

    s.bind((bind_ip, bind_port))
    return s


def normalize_ip6(addr):
    """Return canonical (compressed, no leading zeros) IPv6 address string.

    Strips any %scope suffix before normalising so the result is safe
    to pass to sendto 2-tuples and string comparisons alike.  IPv4
    addresses are returned unchanged.
    """
    if ":" not in addr:
        return addr
    try:
        import ipaddress
        return str(ipaddress.ip_address(addr.split("%")[0]))
    except (ValueError, AttributeError):
        return addr


def close_all(socks):
    """Close every socket; never raises (best-effort cleanup)."""
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


# ─────────────────────────────────────────────────────────────────
# Probe-residue drain
# ─────────────────────────────────────────────────────────────────


def drain_probe_residue(sock, want_nonce):
    """Drain in-flight probe datagrams from *sock* without blocking.

    Uses MSG_PEEK to look without consuming -- only consumes
    datagrams that decode as one of *our* probes.  Real user
    payload at the head of the queue is left alone for the Pipe
    layer to deliver (a plain recvfrom would consume it AND
    leave us with no way to re-queue, eating user data).

    Stops at the first non-probe at the head.
    """
    drained = 0
    sock.setblocking(False)
    while True:
        try:
            data, _addr = sock.recvfrom(4096, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            break
        except OSError:
            break
        if decode_probe(data, want_nonce) is None:
            break
        try:
            sock.recvfrom(4096)
        except (BlockingIOError, OSError):
            break
        drained += 1
    return drained


# ─────────────────────────────────────────────────────────────────
# STUN
# ─────────────────────────────────────────────────────────────────


def sync_stun_discover_mapping(sock, stun_server, af, timeout=3.0, retries=3):
    """Sync STUN-discover the (mapped_ip, mapped_port) for *sock*.

    No asyncio.  Uses select() for the wait, plain recvfrom for
    delivery.  Run from a thread executor or after switching the
    sock to plain blocking mode.  Leaves the sock in non-blocking
    mode at exit.

    The NAT mapping installed by this round-trip (local_ip,
    local_port -> wan_ip, mapped_port) is exactly what the peer
    needs to aim at, so we want the same socket to keep that
    mapping alive through the spray phase.
    """
    from aionetiface.protocol.stun.stun_defs import (
        RFC5389, STUNMsg, STUNMsgCodes, STUNMsgTypes,
    )
    from aionetiface.protocol.stun.stun_utils import stun_proto
    import select as select_mod

    sock.setblocking(False)
    for _ in range(retries):
        msg = STUNMsg(
            msg_type=STUNMsgTypes.Binding,
            msg_code=STUNMsgCodes.Request,
            mode=RFC5389,
        )
        txid = bytes(msg.txn_id)
        try:
            sock.sendto(msg.pack(), stun_server)
        except OSError:
            return None
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                ready, _, _ = select_mod.select([sock], [], [], remaining)
            except (OSError, select_mod.error):
                break
            if not ready:
                break
            try:
                data, _addr = sock.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                return None
            if len(data) < 20 or bytes(data[8:20]) != txid:
                continue
            try:
                reply, _ = stun_proto(data, af)
            except (ValueError, IndexError):
                continue
            rtup = getattr(reply, "rtup", None)
            if rtup is None:
                continue
            return (str(rtup[0]), int(rtup[1]))
    return None
