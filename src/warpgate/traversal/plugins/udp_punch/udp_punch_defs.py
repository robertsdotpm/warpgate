"""Wire-format helpers for the UDP punch PROBE / CONFIRM exchange.

Frames are real RFC 5389 STUN Binding messages, built and parsed via
the ``STUNMsg`` machinery in ``aionetiface.protocol.stun``.  Looking
identical to STUN traffic on the wire gives consumer-router ALGs and
DPI middleboxes no reason to deprioritise or rate-limit the spray --
yesterday's matrix (2026-05-22) showed STUN-shape going end-to-end on
Win11 where raw-magic P2UP frames were getting silently dropped by
the consumer ALG between Linux ens34 and the Win11 listener.

Wire shape:

  PROBE     = STUN Binding Request   (msg_type=Binding, class=Request)
  CONFIRM   = STUN Binding Success Response
                                     (msg_type=Binding, class=SuccessResp)
                + XOR-MAPPED-ADDRESS attribute carrying the peer's
                  reflexive address (the ``(ip, port)`` that the
                  CONFIRM-sender observed the PROBE arriving from)

Per-session correlation: STUN's 12-byte Transaction ID carries the
first 12 bytes of our 16-byte session nonce.  The remaining 4 bytes
of nonce stay node-local and never cross the wire; nonce comparisons
on receive use only the first 12 bytes (TXID-width).  96 bits of
entropy is well above session lifetime collision risk.

API surface (unchanged from the prior dual-mode implementation, so
engine.py / main.py keep their imports):

  build_frame(kind, nonce, peer_addr=None) -> bytes
      kind     : UDP_PUNCH_KIND_PROBE | UDP_PUNCH_KIND_CONFIRM
      nonce    : 16-byte session nonce
      peer_addr: (ip_str, port) of the peer's reflexive address,
                 required for CONFIRM, ignored for PROBE.  IPv6
                 supported; falls back to a bare Binding Success
                 Response with no XOR-MAPPED-ADDRESS only when
                 peer_addr is None or malformed.

  parse_frame(buf) -> (kind, nonce_bytes) or (None, None)
      Validates STUN magic cookie + recognised message class; returns
      the kind and a 16-byte buffer whose first 12 bytes are the
      decoded TXID (last 4 zero-padded so callers can keep treating
      it as a 16-byte nonce slot).
"""
from ..tcp_punch.boundary_lib import derive_max_sleep


# Internal kind tags (engine / main use these to dispatch).
UDP_PUNCH_KIND_PROBE = 0x01
UDP_PUNCH_KIND_CONFIRM = 0x02

# Session nonce length.  Truncated to STUN_TXID_LEN on the wire; the
# remaining 4 bytes stay node-local for cache / logging.
UDP_PUNCH_NONCE_LEN = 16
STUN_TXID_LEN = 12

# Generous upper bound on a punch frame: 20-byte STUN header + room
# for a v6 XOR-MAPPED-ADDRESS attribute (4-byte attr header + 20-byte
# v6 attr data) and a bit of slack.  Used as the recv buffer size so
# Windows' WSAEMSGSIZE-on-truncate behaviour doesn't bite us.
UDP_PUNCH_MAX_FRAME_LEN = 64


# udp_punch's punch-timing params, independent of tcp_punch's
# FAST_PUNCH_PARAMS.  Decoupling rationale: PunchClient stored
# ``self.params = params`` by reference, so a single module-level dict
# shared between the two plugins meant either plugin's PunchClient
# could mutate the other's timing.  A separate dict here decouples
# them; values stay in the pre-tightening profile (10/4/3, 3.0s
# timeouts) that the matrix runs proved stable for udp_punch's spray
# behaviour across the OS surface.
UDP_PUNCH_PARAMS = {
    "window": 10,
    "max_clock_error": 4,
    "min_run_window": 3,
    "connect_timeout": 3.0,
    "monitor_timeout": 3.0,
    "retry_interval": 0.05,
    "reply_delay": 2,
}
UDP_PUNCH_PARAMS["max_sleep"] = derive_max_sleep(
    UDP_PUNCH_PARAMS["window"], UDP_PUNCH_PARAMS["max_clock_error"],
)


# ----- STUN frame build / parse -------------------------------------------


# Wire-format msg_type bytes for the two classes we accept.  Derived
# from STUNMsgTypes.Binding OR'd with STUNMsgCodes.{Request,SuccessResp}
# and AND-masked to 0x3fff (RFC 5389 §6 message-type encoding).  We
# reuse STUNMsgTypes.Binding directly for the request shape (single
# source of truth shared with random_probe); the success-response
# shape stays inline because it has no central constant.
from aionetiface.protocol.stun.stun_defs import STUNMsgTypes
BINDING_REQUEST_WIRE_TYPE = STUNMsgTypes.Binding  # b"\x00\x01"
BINDING_SUCCESS_WIRE_TYPE = b"\x01\x01"           # Binding | SuccessResp


def build_frame(kind, nonce, peer_addr=None):
    """Build a real STUN Binding message for the given kind + nonce.

    PROBE   -> Binding Request, TXID = nonce[:12].
    CONFIRM -> Binding Success Response, TXID = nonce[:12], optionally
               carrying an XOR-MAPPED-ADDRESS attribute for peer_addr.
    """
    # Lazy import keeps udp_punch_defs cheap to import; STUNMsg pulls
    # in hmac / hashlib / struct / etc.
    from aionetiface.protocol.stun.stun_defs import (
        RFC5389,
        STUNAddrTup,
        STUNAttrs,
        STUNMsg,
        STUNMsgCodes,
        STUNMsgTypes,
    )
    from aionetiface.net.net_defs import IP4, IP6

    if len(nonce) != UDP_PUNCH_NONCE_LEN:
        raise ValueError("nonce must be {0} bytes".format(UDP_PUNCH_NONCE_LEN))

    if kind == UDP_PUNCH_KIND_PROBE:
        msg_code = STUNMsgCodes.Request
    elif kind == UDP_PUNCH_KIND_CONFIRM:
        msg_code = STUNMsgCodes.SuccessResp
    else:
        raise ValueError("unknown kind {0}".format(kind))

    msg = STUNMsg(
        msg_type=STUNMsgTypes.Binding,
        msg_code=msg_code,
        mode=RFC5389,
    )
    msg.txn_id = bytes(nonce[:STUN_TXID_LEN])

    # CONFIRM carries the peer's reflexive address so a STUN-aware ALG
    # can validate the response against the request it just saw -- a
    # Binding Success without a mapped address is malformed per RFC
    # 5389 §6.3.3 and DPI scanners can drop it.
    if kind == UDP_PUNCH_KIND_CONFIRM and peer_addr is not None:
        try:
            peer_ip = peer_addr[0]
            peer_port = peer_addr[1]
            af = IP4 if (peer_ip and "." in peer_ip) else IP6
            addr_tup = STUNAddrTup(
                ip=peer_ip,
                port=peer_port,
                af=af,
                txid=msg.txn_id,
                magic_cookie=msg.magic_cookie,
            )
            msg.write_attr(STUNAttrs.XorMappedAddress, addr_tup)
        except (ValueError, TypeError, OSError):
            # Fall back to a bare Binding Success Response when peer
            # addr is malformed.  ALG scanners are stricter, but we'd
            # rather emit something parseable than fail to reply.
            pass

    return msg.pack()


def parse_frame(buf):
    """Parse a STUN-shaped punch frame.

    Returns (kind, nonce_bytes) where kind is UDP_PUNCH_KIND_PROBE or
    UDP_PUNCH_KIND_CONFIRM, and nonce_bytes is a 16-byte buffer whose
    first 12 bytes are the decoded TXID and last 4 bytes are zero
    (callers compare on TXID-width / first 12 bytes).

    Returns (None, None) on anything not recognisable as a STUN
    Binding Request / Success Response.
    """
    # Quick reject before doing the structured decode work.
    if len(buf) < 20:
        return (None, None)

    from aionetiface.protocol.stun.stun_defs import (
        RFC5389,
        STUNMsg,
        STUN_MAGIC_COOKIE,
    )

    if bytes(buf[4:8]) != STUN_MAGIC_COOKIE:
        return (None, None)

    try:
        msg, _trailing = STUNMsg.unpack(bytes(buf), mode=RFC5389)
    except Exception:  # pylint: disable=broad-except
        return (None, None)

    msg_type_bytes = bytes(msg.msg_type)
    if msg_type_bytes == BINDING_REQUEST_WIRE_TYPE:
        kind = UDP_PUNCH_KIND_PROBE
    elif msg_type_bytes == BINDING_SUCCESS_WIRE_TYPE:
        kind = UDP_PUNCH_KIND_CONFIRM
    else:
        return (None, None)

    # Pad TXID back to 16-byte nonce slot so downstream nonce-match
    # checks against the locally-stored 16-byte nonce keep their
    # existing first-12-bytes comparison logic.
    nonce_bytes = bytes(msg.txn_id) + b"\x00" * (UDP_PUNCH_NONCE_LEN - STUN_TXID_LEN)
    return (kind, nonce_bytes)
