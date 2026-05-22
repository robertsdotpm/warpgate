"""Wire-format constants for the UDP punch CONFIRM probe.

The UDP punch engine fires datagrams at every predicted (peer_ext_ip,
peer_ext_port) tuple and listens on every locally-bound src_port for
inbound. To distinguish a real peer-from-NAT-mapping arrival from
random internet scanner traffic / NAT misroute, every probe carries a
fixed magic prefix + a session nonce both sides agreed on via the
PunchMsg exchange. CONFIRM is the second-leg ack: the receiver sees a
probe, fires CONFIRM back on the same 4-tuple, and the originator
locks the socket as the winner.

Frame layout (all big-endian):

    [0:4]   MAGIC = b"P2UP"
    [4]     KIND  -- 0x01 PROBE, 0x02 CONFIRM
    [5:21]  16-byte session nonce (must equal PunchMsg.nonce)

Total length: 21 bytes. The validator drops any datagram that doesn't
exactly match length + magic + matching nonce so application traffic
sharing the post-punch socket is not interfered with.
"""

UDP_PUNCH_MAGIC = b"P2UP"
UDP_PUNCH_KIND_PROBE = 0x01
UDP_PUNCH_KIND_CONFIRM = 0x02
UDP_PUNCH_NONCE_LEN = 16
UDP_PUNCH_FRAME_LEN = 4 + 1 + UDP_PUNCH_NONCE_LEN  # 21


# udp_punch's own punch-timing params, independent of tcp_punch's
# FAST_PUNCH_PARAMS.  udp_punch used to import FAST_PUNCH_PARAMS
# directly -- but PunchClient stores `self.params = params` by
# reference, so a single module-level dict shared between the two
# plugins means either plugin's PunchClient can mutate timing the
# other reads, and any retune of FAST_PUNCH_PARAMS for tcp_punch
# silently changes udp_punch too.  A separate dict decouples them.
#
# Values now mirror tcp_punch's tight FAST_PUNCH_PARAMS profile
# (window=3 / max_clock_error=1 / min_run_window=1, connect_timeout
# and monitor_timeout = 1.5).  The pre-tightening profile (10/4/3 +
# 3.0s timeouts) was sized for udp_punch's old 18-socket 50 Hz spray,
# whose executor thread couldn't keep up with a 2.0 s window under
# MQTT churn.  The NTP-pin re-apply dropped the boundary allocator to
# n=1 -- a single socket per side -- so that spray-load reason is
# gone, and the tight 1.5 s timeouts apply.  The dict stays separate
# from FAST_PUNCH_PARAMS purely for the by-reference mutation hazard
# above; the values are intentionally kept in sync for now.
from ..tcp_punch.boundary_lib import derive_max_sleep  # noqa: E402

UDP_PUNCH_PARAMS = {
    # Pre-tightening profile -- the values udp_punch ran the matrix on
    # historically (full_sweep_v4 9/9).  6b05a78 re-tightened to
    # tcp_punch's tight (3/1/1, 1.5s) values on the assumption that
    # boundary-allocator's n=1 had removed the spray-load reason for
    # 3.0s engine timing.  That assumption only holds when the punch
    # actually takes the boundary fast-path; the predictor path
    # (PRESERV / INDEPENDENT / DEPENDENT / RANDOM on either side, and
    # the asymmetric / mobile-NIC carrier CGNAT cases we exercise in
    # the matrix) still uses 9-17 sockets at 50Hz spray.  Wire capture
    # showed Windows udp_punch losing ~98% of inbound PROBEs under
    # consumer-router UDP burst caps when the engine raced through the
    # tight 1.5s window.  3.0s windows give the burst room to spread
    # below the cap and the executor thread room to keep up under MQTT
    # churn.
    "window": 10,
    "max_clock_error": 4,
    "min_run_window": 3,
    "connect_timeout": 3.0,
    "monitor_timeout": 3.0,
    "retry_interval": 0.05,
    "reply_delay": 2,
}
# derive_max_sleep(3, 1) -- matches FAST_PUNCH_PARAMS's derived value.
UDP_PUNCH_PARAMS["max_sleep"] = derive_max_sleep(
    UDP_PUNCH_PARAMS["window"], UDP_PUNCH_PARAMS["max_clock_error"],
)


import os

# Experimental: WG_PROBE_STUN_FORMAT=1 makes PROBE / CONFIRM frames look
# like RFC 5389 STUN Binding Request / Success Response, so consumer
# routers with STUN-aware ALG give them the same favourable treatment
# (longer NAT mapping timeouts, less aggressive burst filtering,
# Endpoint-Independent Mapping promotion) as real STUN traffic.
#
# Wire shape (20 bytes, big-endian):
#   [0:2]   Message Type  -- 0x0001 (Binding Request) for PROBE,
#                            0x0101 (Binding Success Response) for
#                            CONFIRM.  Matches RFC 5389 exactly so a
#                            STUN-decoding ALG sees a well-formed
#                            request/response pair flowing both ways.
#   [2:4]   Message Length -- 0x0000 (no STUN attributes).
#   [4:8]   Magic Cookie  -- 0x2112A442 (RFC 5389 magic).
#   [8:20]  Transaction ID -- first 12 bytes of session nonce.
#
# We truncate the 16-byte session nonce to STUN's 12-byte TXID width.
# That still leaves 96 bits of entropy -- collision space remains
# astronomically large for the session lifetimes involved.  The peer
# stores the full nonce locally and only the truncated form crosses
# the wire; both sides truncate identically.
STUN_MAGIC_COOKIE = b"\x21\x12\xa4\x42"
STUN_TYPE_BINDING_REQUEST = b"\x00\x01"
STUN_TYPE_BINDING_SUCCESS = b"\x01\x01"
STUN_ATTR_XOR_MAPPED_ADDRESS = b"\x00\x20"
STUN_HEADER_LEN = 20  # 2 (type) + 2 (length) + 4 (cookie) + 12 (TXID)
STUN_TXID_LEN = 12
STUN_FRAME_LEN_BARE = STUN_HEADER_LEN  # request with no attributes
STUN_FRAME_LEN_WITH_XMA = STUN_HEADER_LEN + 12  # +XOR-MAPPED-ADDRESS for IPv4


def stun_format_enabled():
    """True iff WG_PROBE_STUN_FORMAT=1 in the env."""
    # Strip trailing whitespace -- cmd.exe's `set X=1 &&` syntax bakes a
    # trailing space into the value, so a literal `== "1"` check fails
    # on Windows-launched processes.
    return os.environ.get("WG_PROBE_STUN_FORMAT", "").strip() == "1"


def _build_xor_mapped_address_v4(ip_str, port):
    """Build the XOR-MAPPED-ADDRESS attribute (12 bytes) for an IPv4 peer.

    RFC 5389 §15.2.  The port is XOR'd with the top 16 bits of the
    magic cookie; the IPv4 address is XOR'd with the full 32-bit
    cookie.  This is what real STUN servers send in Binding Success
    responses, so a STUN-aware NAT or DPI scanner can validate the
    response against the request it just saw.
    """
    import socket
    ip_bytes = socket.inet_aton(ip_str)
    cookie_u32 = int.from_bytes(STUN_MAGIC_COOKIE, "big")
    cookie_u16 = (cookie_u32 >> 16) & 0xffff
    xor_port = (port ^ cookie_u16).to_bytes(2, "big")
    xor_ip = bytes(b ^ c for b, c in zip(ip_bytes, STUN_MAGIC_COOKIE))
    # Attribute: type=XOR-MAPPED-ADDRESS, length=8, value=8 bytes
    #   reserved(1) + family=IPv4(1) + xor_port(2) + xor_ip(4)
    attr_value = b"\x00\x01" + xor_port + xor_ip
    return STUN_ATTR_XOR_MAPPED_ADDRESS + b"\x00\x08" + attr_value


def build_frame(kind, nonce, peer_addr=None):
    """Build a punch frame for the given kind + nonce.

    Default format is the 21-byte P2UP magic + kind + 16-byte nonce.
    With WG_PROBE_STUN_FORMAT=1, emit a STUN-shaped frame:
      * PROBE  -> 20-byte Binding Request (no attributes).
      * CONFIRM -> 32-byte Binding Success Response with an
        XOR-MAPPED-ADDRESS attribute (IPv4) describing peer_addr.
        peer_addr (IPv4 tuple ('ip', port)) is REQUIRED for CONFIRM
        under STUN format -- a Binding Success without a mapped
        address is malformed and a DPI scanner can reject it.  If
        the peer's family isn't IPv4 the attribute is omitted and
        we fall back to the bare 20-byte success response.
    """
    if len(nonce) != UDP_PUNCH_NONCE_LEN:
        raise ValueError("nonce must be {0} bytes".format(UDP_PUNCH_NONCE_LEN))
    if stun_format_enabled():
        if kind == UDP_PUNCH_KIND_PROBE:
            msg_type = STUN_TYPE_BINDING_REQUEST
            attrs = b""
        elif kind == UDP_PUNCH_KIND_CONFIRM:
            msg_type = STUN_TYPE_BINDING_SUCCESS
            attrs = b""
            if peer_addr is not None:
                try:
                    peer_ip, peer_port = peer_addr[0], peer_addr[1]
                    # Only IPv4 attributes implemented; skip for v6.
                    if peer_ip and "." in peer_ip:
                        attrs = _build_xor_mapped_address_v4(peer_ip, peer_port)
                except (ValueError, TypeError, OSError):
                    attrs = b""
        else:
            raise ValueError("unknown kind {0}".format(kind))
        msg_length = len(attrs).to_bytes(2, "big")
        return msg_type + msg_length + STUN_MAGIC_COOKIE + nonce[:STUN_TXID_LEN] + attrs
    return UDP_PUNCH_MAGIC + bytes([kind]) + nonce


def parse_frame(buf):
    """Parse a punch frame; returns (kind, nonce) or (None, None) on mismatch.

    Accepts both the native P2UP format and the STUN-shaped format.
    Under STUN format, the message length field indicates how many
    bytes of attributes follow the 20-byte header.  We accept any
    length >= 0 -- the TXID identifies the session regardless of
    how many attributes the peer chose to include.
    """
    if len(buf) == UDP_PUNCH_FRAME_LEN and buf[:4] == UDP_PUNCH_MAGIC:
        return (buf[4], buf[5:5 + UDP_PUNCH_NONCE_LEN])
    if len(buf) >= STUN_HEADER_LEN and buf[4:8] == STUN_MAGIC_COOKIE:
        # Sanity: declared attribute-payload length matches actual.
        declared = int.from_bytes(buf[2:4], "big")
        if STUN_HEADER_LEN + declared != len(buf):
            return (None, None)
        msg_type = buf[0:2]
        if msg_type == STUN_TYPE_BINDING_REQUEST:
            kind = UDP_PUNCH_KIND_PROBE
        elif msg_type == STUN_TYPE_BINDING_SUCCESS:
            kind = UDP_PUNCH_KIND_CONFIRM
        else:
            return (None, None)
        # Return the truncated TXID padded back to 16 bytes so the
        # downstream nonce-match check works against the locally-
        # stored 16-byte nonce truncated identically.
        return (kind, buf[8:8 + STUN_TXID_LEN] + b"\x00" * 4)
    return (None, None)
