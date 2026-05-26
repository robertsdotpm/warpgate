"""libp2p AutoNAT v1 -- /libp2p/autonat/1.0.0.

Lets a peer ask other peers "can you reach me at these addresses?"
which is the canonical way to detect NAT reachability in the
libp2p ecosystem.

Wire protocol (libp2p-specs/autonat/protocol.md):

    message Message {
        enum MessageType {
            DIAL          = 0;
            DIAL_RESPONSE = 1;
        }
        message PeerInfo {
            optional bytes id = 1;
            repeated bytes addrs = 2;
        }
        message Dial {
            optional PeerInfo peer = 1;
        }
        enum ResponseStatus {
            OK                = 0;
            E_DIAL_ERROR      = 100;
            E_DIAL_REFUSED    = 101;
            E_BAD_REQUEST     = 200;
            E_INTERNAL_ERROR  = 300;
        }
        message DialResponse {
            optional ResponseStatus status = 1;
            optional string statusText     = 2;
            optional bytes addr            = 3;  // the SUCCESSFUL dial addr
        }

        optional MessageType type        = 1;
        optional Dial dial               = 2;
        optional DialResponse dialResponse = 3;
    }

Client (the peer asking "am I reachable?"):
  1. Open stream to a peer (must be a third party -- AutoNAT
     refuses requests that would dial the requester from itself).
  2. multistream-select /libp2p/autonat/1.0.0.
  3. Send Message{type=DIAL, dial=Dial{peer=PeerInfo{id, addrs}}}.
  4. Read Message{type=DIAL_RESPONSE, dialResponse=...}.
  5. If status=OK, the peer successfully dialed back at ``addr``;
     that address is publicly reachable.  Anything else: not.

Server (responding):
  1. Receive DIAL with PeerInfo{id, addrs}.
  2. Attempt a fresh outbound TCP connection to ONE of the addrs
     (filtering for non-private IPs so we don't get used as a
     port-scanner-by-proxy).
  3. Reply OK + the addr we successfully dialed, or an error code.

For warpgate this lets a node learn whether its punched / direct /
upnp address is actually reachable from a third party -- useful
input for the cascade's plugin selection.
"""
import asyncio

from . import pb_lite
from . import varint
from .stream_io import read_exactly


AUTONAT_PROTOCOL = "/libp2p/autonat/1.0.0"

TYPE_DIAL = 0
TYPE_DIAL_RESPONSE = 1

STATUS_OK = 0
STATUS_DIAL_ERROR = 100
STATUS_DIAL_REFUSED = 101
STATUS_BAD_REQUEST = 200
STATUS_INTERNAL_ERROR = 300


# ---- Encode / decode ---------------------------------------------------


def encode_peer_info(peer_id_bytes, addrs=()):
    out = b""
    if peer_id_bytes:
        out += pb_lite.encode_bytes_field(1, peer_id_bytes)
    for a in addrs:
        out += pb_lite.encode_bytes_field(2, a)
    return out


def decode_peer_info(buf):
    fields = pb_lite.parse_message(buf)
    pid = fields.get(1, [b""])[-1]
    addrs = fields.get(2, [])
    return pid, addrs


def encode_dial_request(peer_id_bytes, addrs):
    dial_msg = pb_lite.encode_message_field(1, encode_peer_info(peer_id_bytes, addrs))
    return (
        pb_lite.encode_varint_field(1, TYPE_DIAL)
        + pb_lite.encode_message_field(2, dial_msg)
    )


def encode_dial_response(status, status_text="", addr_bytes=b""):
    inner_parts = [pb_lite.encode_varint_field(1, status)]
    if status_text:
        inner_parts.append(pb_lite.encode_string_field(2, status_text))
    if addr_bytes:
        inner_parts.append(pb_lite.encode_bytes_field(3, addr_bytes))
    return (
        pb_lite.encode_varint_field(1, TYPE_DIAL_RESPONSE)
        + pb_lite.encode_message_field(3, b"".join(inner_parts))
    )


def decode_message(buf):
    fields = pb_lite.parse_message(buf)
    out = {"type": fields.get(1, [0])[-1]}
    if 2 in fields:
        # Dial wrapper -> peer field 1 -> PeerInfo
        dial_fields = pb_lite.parse_message(fields[2][-1])
        if 1 in dial_fields:
            out["dial_peer"] = decode_peer_info(dial_fields[1][-1])
    if 3 in fields:
        resp_fields = pb_lite.parse_message(fields[3][-1])
        out["response"] = {
            "status": resp_fields.get(1, [0])[-1],
            "status_text": (
                resp_fields[2][-1].decode("utf-8", errors="replace")
                if 2 in resp_fields and isinstance(resp_fields[2][-1], (bytes, bytearray))
                else ""
            ),
            "addr": resp_fields.get(3, [b""])[-1],
        }
    return out


# ---- Wire helpers ------------------------------------------------------


async def write_msg(stream, blob):
    await stream.write(varint.encode(len(blob)) + blob)


async def read_msg(stream, max_len=64 * 1024):
    length = await varint.read_varint(stream)
    if length > max_len:
        raise ValueError("autonat: message too large")
    if length == 0:
        return b""
    return await read_exactly(stream, length)


# ---- Client side -------------------------------------------------------


async def client_request_dial(stream, my_peer_id, my_addrs, timeout=15.0):
    """Run the client side of AutoNAT against an already-negotiated stream.

    ``my_peer_id`` + ``my_addrs`` is what we're asking the peer to
    dial back to.  Returns a dict with keys ``status``, ``status_text``,
    and (on OK) ``addr``.
    """
    await write_msg(stream, encode_dial_request(my_peer_id, my_addrs))
    reply_buf = await asyncio.wait_for(read_msg(stream), timeout=timeout)
    reply = decode_message(reply_buf)
    if reply.get("type") != TYPE_DIAL_RESPONSE:
        raise ConnectionError("autonat: unexpected reply type {0}".format(reply.get("type")))
    return reply.get("response", {"status": STATUS_INTERNAL_ERROR})


# ---- Server side -------------------------------------------------------


async def server_handle(stream, src_session, autonat_dialer, timeout=15.0):
    """Service one AutoNAT request on a freshly-negotiated stream.

    ``autonat_dialer(addr_bytes, expected_peer_id) -> bool`` is
    supplied by the caller -- attempts a fresh outbound dial and
    returns True iff it succeeded.  This module deliberately
    avoids implementing the dialer itself so the policy choice
    (which AFs to dial, what timeout, refusal for private IPs)
    lives in the Libp2pNode layer.

    Per spec, the AutoNAT responder MUST NOT dial the requester's
    address if it's the same network endpoint we're already
    connected to them on (anti-amplification).  Callers should
    enforce that in ``autonat_dialer``.
    """
    try:
        req_buf = await asyncio.wait_for(read_msg(stream), timeout=timeout)
    except asyncio.TimeoutError:
        return
    req = decode_message(req_buf)
    if req.get("type") != TYPE_DIAL:
        await write_msg(stream, encode_dial_response(STATUS_BAD_REQUEST, "expected DIAL"))
        return
    dial_peer = req.get("dial_peer")
    if dial_peer is None:
        await write_msg(stream, encode_dial_response(STATUS_BAD_REQUEST, "missing dial.peer"))
        return
    target_pid, addrs = dial_peer
    if not target_pid or target_pid != src_session.remote_peer_id:
        # Spec: the request MUST identify the requester, and we
        # MUST only dial-back the source peer (not arbitrary
        # third parties).
        await write_msg(
            stream, encode_dial_response(STATUS_BAD_REQUEST, "peer id mismatch")
        )
        return
    if not addrs:
        await write_msg(
            stream, encode_dial_response(STATUS_DIAL_REFUSED, "no addrs"),
        )
        return

    # Try each addr in turn; first to succeed wins.
    successful_addr = None
    last_err = ""
    for a in addrs:
        try:
            ok = await asyncio.wait_for(
                autonat_dialer(a, target_pid), timeout=timeout,
            )
        except asyncio.TimeoutError:
            ok = False
            last_err = "timeout"
        except (OSError, ConnectionError, ValueError) as e:
            ok = False
            last_err = str(e)
        if ok:
            successful_addr = a
            break

    if successful_addr is not None:
        await write_msg(
            stream, encode_dial_response(STATUS_OK, "", successful_addr),
        )
    else:
        await write_msg(
            stream, encode_dial_response(STATUS_DIAL_ERROR, last_err),
        )
