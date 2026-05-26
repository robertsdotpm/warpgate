"""libp2p Circuit Relay v2 -- client + relay-service.

Three roles:

  * **Client** (the peer behind a NAT) -- asks a relay to RESERVE
    a slot, then advertises the relayed address to peers, then
    eventually accepts incoming relayed dials via the /stop
    protocol.
  * **Relay** -- accepts /hop streams, maintains reservations,
    accepts /hop CONNECT requests, opens a /stop stream to the
    target, splices the two streams byte-for-byte.
  * **Destination** -- accepts /stop streams; once the relay's
    /stop CONNECT lands, treats the relayed stream as if it were
    a fresh inbound libp2p connection from the source peer.

Wire protocol (libp2p-specs/relay/circuit-v2.md):

    HopMessage {
        Type type = 1;  // RESERVE, CONNECT, STATUS
        optional Peer peer = 2;             // present on CONNECT
        optional Reservation reservation = 3;
        optional Limit limit = 4;
        optional Status status = 5;         // present on STATUS
    }
    StopMessage {
        Type type = 1;  // CONNECT, STATUS
        optional Peer peer = 2;             // src peer on CONNECT
        optional Limit limit = 3;
        optional Status status = 4;
    }
    Peer { bytes id = 1; repeated bytes addrs = 2; }
    Reservation {
        int64 expire = 1;
        repeated bytes addrs = 2;
        optional bytes voucher = 3;
    }
    Limit { uint32 duration = 1; uint64 data = 2; }

Status enum values (only the ones we use):
    OK = 100
    RESERVATION_REFUSED = 200
    RESOURCE_LIMIT_EXCEEDED = 201
    PERMISSION_DENIED = 202
    CONNECTION_FAILED = 203
    NO_RESERVATION = 204
    MALFORMED_MESSAGE = 400

This module implements both the wire-format pack/parse AND the
high-level state machine for each role; node_core registers the
HOP_PROTOCOL + STOP_PROTOCOL handlers on its session dispatcher
and exposes a ``dial_through_relay()`` method that orchestrates
the RESERVE then CONNECT side from the client's perspective.
"""
import asyncio
import time

from . import pb_lite
from . import varint
from .stream_io import read_exactly


HOP_PROTOCOL = "/libp2p/circuit/relay/0.2.0/hop"
STOP_PROTOCOL = "/libp2p/circuit/relay/0.2.0/stop"

# HopMessage / StopMessage types.
TYPE_RESERVE = 1
TYPE_CONNECT = 2
TYPE_STATUS = 3

# StopMessage types.
STOP_TYPE_CONNECT = 1
STOP_TYPE_STATUS = 2

# Status codes.
STATUS_OK = 100
STATUS_RESERVATION_REFUSED = 200
STATUS_RESOURCE_LIMIT_EXCEEDED = 201
STATUS_PERMISSION_DENIED = 202
STATUS_CONNECTION_FAILED = 203
STATUS_NO_RESERVATION = 204
STATUS_MALFORMED = 400


# ---- Encode/decode -----------------------------------------------------


def encode_peer(peer_id_bytes, addrs=()):
    """Marshal a Peer{id, addrs} sub-message."""
    out = pb_lite.encode_bytes_field(1, peer_id_bytes)
    for a in addrs:
        out += pb_lite.encode_bytes_field(2, a)
    return out


def decode_peer(buf):
    """Return (peer_id_bytes, [addr_bytes,...]) from a Peer sub-message."""
    fields = pb_lite.parse_message(buf)
    pid = fields.get(1, [b""])[-1]
    addrs = fields.get(2, [])
    return pid, addrs


def encode_reservation(expire_unix_seconds, addrs=(), voucher=b""):
    out = pb_lite.encode_varint_field(1, expire_unix_seconds)
    for a in addrs:
        out += pb_lite.encode_bytes_field(2, a)
    if voucher:
        out += pb_lite.encode_bytes_field(3, voucher)
    return out


def decode_reservation(buf):
    fields = pb_lite.parse_message(buf)
    expire = fields.get(1, [0])[-1]
    addrs = fields.get(2, [])
    voucher = fields.get(3, [b""])[-1]
    return expire, addrs, voucher


def encode_limit(duration_seconds=0, max_data_bytes=0):
    parts = b""
    if duration_seconds:
        parts += pb_lite.encode_varint_field(1, duration_seconds)
    if max_data_bytes:
        parts += pb_lite.encode_varint_field(2, max_data_bytes)
    return parts


def decode_limit(buf):
    fields = pb_lite.parse_message(buf)
    duration = fields.get(1, [0])[-1]
    data = fields.get(2, [0])[-1]
    return duration, data


# HopMessage --------------------------------------------------

def encode_hop_reserve():
    return pb_lite.encode_varint_field(1, TYPE_RESERVE)


def encode_hop_connect(peer_id_bytes, addrs=()):
    """CONNECT carries the target peer's id (+ optional addrs)."""
    return (
        pb_lite.encode_varint_field(1, TYPE_CONNECT)
        + pb_lite.encode_message_field(2, encode_peer(peer_id_bytes, addrs))
    )


def encode_hop_status(status_code, reservation_bytes=b"", limit_bytes=b""):
    out = pb_lite.encode_varint_field(1, TYPE_STATUS)
    if reservation_bytes:
        out += pb_lite.encode_message_field(3, reservation_bytes)
    if limit_bytes:
        out += pb_lite.encode_message_field(4, limit_bytes)
    out += pb_lite.encode_varint_field(5, status_code)
    return out


def decode_hop_message(buf):
    """Return a dict with the populated HopMessage fields."""
    fields = pb_lite.parse_message(buf)
    out = {"type": fields.get(1, [0])[-1]}
    if 2 in fields:
        out["peer"] = decode_peer(fields[2][-1])
    if 3 in fields:
        out["reservation"] = decode_reservation(fields[3][-1])
    if 4 in fields:
        out["limit"] = decode_limit(fields[4][-1])
    if 5 in fields:
        out["status"] = fields[5][-1]
    return out


# StopMessage --------------------------------------------------

def encode_stop_connect(src_peer_id_bytes, src_addrs=(), limit_bytes=b""):
    out = (
        pb_lite.encode_varint_field(1, STOP_TYPE_CONNECT)
        + pb_lite.encode_message_field(2, encode_peer(src_peer_id_bytes, src_addrs))
    )
    if limit_bytes:
        out += pb_lite.encode_message_field(3, limit_bytes)
    return out


def encode_stop_status(status_code):
    return (
        pb_lite.encode_varint_field(1, STOP_TYPE_STATUS)
        + pb_lite.encode_varint_field(4, status_code)
    )


def decode_stop_message(buf):
    fields = pb_lite.parse_message(buf)
    out = {"type": fields.get(1, [0])[-1]}
    if 2 in fields:
        out["peer"] = decode_peer(fields[2][-1])
    if 3 in fields:
        out["limit"] = decode_limit(fields[3][-1])
    if 4 in fields:
        out["status"] = fields[4][-1]
    return out


# ---- Wire framing helpers (varint-length-prefixed) ---------------------


async def write_msg(writer, blob):
    """Write one varint-length-prefixed circuit-relay message."""
    await writer.write(varint.encode(len(blob)) + blob)


async def read_msg(reader, max_len=64 * 1024):
    length = await varint.read_varint(reader)
    if length > max_len:
        raise ValueError("circuit_relay: message too large ({0} bytes)".format(length))
    if length == 0:
        return b""
    return await read_exactly(reader, length)


# ---- Client-side flows -------------------------------------------------


class Reservation(object):
    """Result of a successful HOP RESERVE."""

    def __init__(self, expire, addrs, voucher, limit_duration, limit_data):
        self.expire = expire
        self.addrs = list(addrs)
        self.voucher = voucher
        self.limit_duration = limit_duration
        self.limit_data = limit_data

    def expired(self):
        return self.expire and time.time() >= self.expire


async def client_reserve(stream):
    """Send HOP RESERVE on ``stream``; await STATUS+Reservation reply.

    Returns a Reservation on success.  Raises ConnectionError on
    any non-OK status.  Caller is responsible for the prior
    multistream-select to ``/libp2p/circuit/relay/0.2.0/hop``.
    """
    await write_msg(stream, encode_hop_reserve())
    reply_buf = await read_msg(stream)
    reply = decode_hop_message(reply_buf)
    if reply.get("type") != TYPE_STATUS:
        raise ConnectionError(
            "circuit_relay: expected STATUS, got type {0}".format(reply.get("type"))
        )
    status = reply.get("status", 0)
    if status != STATUS_OK:
        raise ConnectionError(
            "circuit_relay: RESERVE refused (status={0})".format(status)
        )
    reservation = reply.get("reservation")
    limit = reply.get("limit", (0, 0))
    if reservation is None:
        raise ConnectionError("circuit_relay: OK status without Reservation field")
    expire, addrs, voucher = reservation
    return Reservation(expire, addrs, voucher, limit[0], limit[1])


async def client_connect_to(stream, dest_peer_id, dest_addrs=()):
    """Send HOP CONNECT(dest_peer_id) on ``stream``; await STATUS.

    On STATUS=OK, the stream becomes a transparent byte conduit to
    the destination -- the caller wraps it as the inner layer that
    a normal libp2p handshake would run on top of.

    Raises ConnectionError on any non-OK status.
    """
    await write_msg(stream, encode_hop_connect(dest_peer_id, dest_addrs))
    reply_buf = await read_msg(stream)
    reply = decode_hop_message(reply_buf)
    if reply.get("type") != TYPE_STATUS:
        raise ConnectionError("circuit_relay: connect expected STATUS")
    status = reply.get("status", 0)
    if status != STATUS_OK:
        raise ConnectionError("circuit_relay: CONNECT refused (status={0})".format(status))
    # The stream is now a transparent forwarder; caller continues
    # libp2p on top of it.
    return reply.get("limit", (0, 0))


# ---- Destination-side flows --------------------------------------------


async def destination_handle_stop(stream):
    """Accept a /stop CONNECT message; reply OK; return src peer info.

    The relay opens a /stop stream against us, sends a STOP CONNECT
    naming the source peer.  We reply STATUS OK and from this point
    on the stream is a transparent conduit to the source peer.

    Returns (src_peer_id_bytes, [src_addrs], (duration_s, max_bytes)).
    """
    msg_buf = await read_msg(stream)
    msg = decode_stop_message(msg_buf)
    if msg.get("type") != STOP_TYPE_CONNECT:
        # Bad protocol use; reply MALFORMED so the relay knows.
        await write_msg(stream, encode_stop_status(STATUS_MALFORMED))
        raise ConnectionError(
            "circuit_relay: stop got non-CONNECT type {0}".format(msg.get("type"))
        )
    peer = msg.get("peer")
    limit = msg.get("limit", (0, 0))
    if peer is None:
        await write_msg(stream, encode_stop_status(STATUS_MALFORMED))
        raise ConnectionError("circuit_relay: stop CONNECT missing peer field")
    await write_msg(stream, encode_stop_status(STATUS_OK))
    return peer[0], peer[1], limit


# ---- Relay-side service ------------------------------------------------


class RelayService(object):
    """Bookkeeping for a relay-role libp2p node.

    Tracks active reservations (peer_id -> Reservation expiry) and
    looks up active sessions by remote_peer_id so it can open /stop
    streams to a previously-reserved peer when a /hop CONNECT
    arrives.
    """

    # Default per-reservation quota: 30 minutes / 256 MiB.  Real
    # relays let operators configure this; here it's tuned for the
    # "warpgate fallback" use case where relays exist among peers.
    DEFAULT_DURATION = 30 * 60
    DEFAULT_DATA = 256 * 1024 * 1024

    def __init__(self, libp2p_node):
        self.node = libp2p_node
        # peer_id_bytes -> (expire_unix, session)
        self.reservations = {}

    async def handle_hop(self, stream, src_session):
        """Service a freshly-opened /hop stream.

        Dispatches by the first HopMessage's type:
          - RESERVE: record the reservation, reply OK + addrs.
          - CONNECT: validate the destination has an active
            reservation, open /stop to dest, splice byte-for-byte.
        """
        try:
            first_buf = await read_msg(stream)
            msg = decode_hop_message(first_buf)
            mtype = msg.get("type")
            if mtype == TYPE_RESERVE:
                await self.handle_reserve(stream, src_session)
            elif mtype == TYPE_CONNECT:
                await self.handle_connect(stream, src_session, msg)
            else:
                await write_msg(stream, encode_hop_status(STATUS_MALFORMED))
        except (ConnectionError, OSError, ValueError, asyncio.TimeoutError):
            try:
                await write_msg(stream, encode_hop_status(STATUS_MALFORMED))
            except Exception:
                pass

    async def handle_reserve(self, stream, src_session):
        """Record a fresh reservation for ``src_session.remote_peer_id``."""
        peer_id_bytes = src_session.remote_peer_id
        expire = int(time.time()) + self.DEFAULT_DURATION
        self.reservations[peer_id_bytes] = (expire, src_session)
        # Reply OK + the relay's own listen multiaddrs as the
        # "reachable through" set the client should advertise.
        addrs = list(self.node.listen_multiaddrs)
        reservation_blob = encode_reservation(expire, addrs)
        limit_blob = encode_limit(self.DEFAULT_DURATION, self.DEFAULT_DATA)
        await write_msg(
            stream, encode_hop_status(STATUS_OK, reservation_blob, limit_blob),
        )
        # NOTE: we deliberately keep ``stream`` open after this --
        # libp2p convention is that the client's reservation is
        # tied to the underlying session staying alive, so the
        # /hop stream can be torn down independently.  Close it
        # cleanly.
        try:
            await stream.close()
        except (OSError, ConnectionError):
            pass

    async def handle_connect(self, stream, src_session, msg):
        """Forward a /hop CONNECT to the destination via /stop, then splice."""
        peer = msg.get("peer")
        if peer is None:
            await write_msg(stream, encode_hop_status(STATUS_MALFORMED))
            return
        dst_peer_id = peer[0]
        entry = self.reservations.get(dst_peer_id)
        if entry is None:
            await write_msg(stream, encode_hop_status(STATUS_NO_RESERVATION))
            return
        expire, dst_session = entry
        if expire and time.time() >= expire:
            self.reservations.pop(dst_peer_id, None)
            await write_msg(stream, encode_hop_status(STATUS_NO_RESERVATION))
            return
        if dst_session.mux_session.closed:
            self.reservations.pop(dst_peer_id, None)
            await write_msg(stream, encode_hop_status(STATUS_CONNECTION_FAILED))
            return

        # Open a fresh stream to the destination's mux session,
        # multistream-select STOP_PROTOCOL on it, then send the
        # /stop CONNECT carrying the source peer's id.
        from .multistream import negotiate_initiator
        try:
            dst_stream = await dst_session.mux_session.open_stream()
            chosen = await negotiate_initiator(
                dst_stream, dst_stream, [STOP_PROTOCOL],
            )
            if chosen != STOP_PROTOCOL:
                await write_msg(stream, encode_hop_status(STATUS_CONNECTION_FAILED))
                try:
                    await dst_stream.close()
                except (OSError, ConnectionError):
                    pass
                return
            await write_msg(
                dst_stream,
                encode_stop_connect(src_session.remote_peer_id),
            )
            reply_buf = await read_msg(dst_stream)
            reply = decode_stop_message(reply_buf)
            if reply.get("type") != STOP_TYPE_STATUS or reply.get("status") != STATUS_OK:
                await write_msg(stream, encode_hop_status(STATUS_CONNECTION_FAILED))
                try:
                    await dst_stream.close()
                except (OSError, ConnectionError):
                    pass
                return
        except (ConnectionError, OSError, ValueError, asyncio.TimeoutError):
            await write_msg(stream, encode_hop_status(STATUS_CONNECTION_FAILED))
            return

        # Both ends agreed -- tell the src side STATUS OK, then
        # splice bytes both directions until either side closes.
        await write_msg(stream, encode_hop_status(STATUS_OK))
        await self.splice(stream, dst_stream)

    async def splice(self, a, b):
        """Forward bytes bidirectionally between two streams until one closes."""

        async def pump(src, dst):
            try:
                while True:
                    chunk = await src.read(4096)
                    if not chunk:
                        return
                    await dst.write(chunk)
            except (ConnectionError, OSError):
                return

        t1 = asyncio.ensure_future(pump(a, b))
        t2 = asyncio.ensure_future(pump(b, a))
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in (t1, t2):
            if not t.done():
                t.cancel()
        for s in (a, b):
            try:
                await s.close()
            except (OSError, ConnectionError):
                pass
