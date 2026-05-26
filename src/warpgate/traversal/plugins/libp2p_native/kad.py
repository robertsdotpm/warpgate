"""libp2p Kad-DHT wire protocol -- /ipfs/kad/1.0.0.

Adapts the generic Kademlia algorithm in ``warpgate.kademlia`` to
the libp2p stream-based wire format.

Wire layout: each message is a varint-length-prefixed protobuf
``Message`` (libp2p-spec dht/pb/dht.proto):

    message Message {
        enum MessageType {
            PUT_VALUE     = 0;
            GET_VALUE     = 1;
            ADD_PROVIDER  = 2;
            GET_PROVIDERS = 3;
            FIND_NODE     = 4;
            PING          = 5;
        }
        enum ConnectionType {
            NOT_CONNECTED  = 0;
            CONNECTED      = 1;
            CAN_CONNECT    = 2;
            CANNOT_CONNECT = 3;
        }
        message Peer {
            bytes id              = 1;
            repeated bytes addrs  = 2;
            ConnectionType connection = 3;
        }
        message Record {
            bytes key            = 1;
            bytes value          = 2;
            string time_received = 5;
        }

        MessageType type        = 1;
        int32 cluster_level_raw = 10;   // (deprecated; always 0)
        bytes key               = 2;
        Record record           = 3;
        repeated Peer closer_peers   = 8;
        repeated Peer provider_peers = 9;
    }

This file implements ALL the message types -- FIND_NODE is the
foundation lookup primitive; PUT_VALUE / GET_VALUE move small
typed records (the actual "put data, get data" primitive);
ADD_PROVIDER / GET_PROVIDERS exchange "who has this content"
records for content-routing use cases.

Each operation runs on a fresh yamux stream per query (libp2p
convention).  The client opens, multistream-selects /ipfs/kad/1.0.0,
sends one request Message, reads one reply Message, closes the
stream.

The "target key" libp2p Kad-DHT uses is the **SHA-256 of the
target PeerID multihash bytes** for peer-lookup queries (libp2p
Kad-DHT spec section 1.2).  For value/provider records the key is
application-defined opaque bytes.
"""
import asyncio
import hashlib

from . import pb_lite
from . import varint
from .multistream import negotiate_initiator, negotiate_responder
from .stream_io import read_exactly
from ....kademlia.routing import PeerInfo


KAD_PROTOCOL = "/ipfs/kad/1.0.0"

TYPE_PUT_VALUE = 0
TYPE_GET_VALUE = 1
TYPE_ADD_PROVIDER = 2
TYPE_GET_PROVIDERS = 3
TYPE_FIND_NODE = 4
TYPE_PING = 5


# ---- Protobuf encode/decode ---------------------------------------------


def encode_kad_peer(peer_id_bytes, addrs=()):
    """Encode a Peer{id, addrs, connection} sub-message."""
    out = pb_lite.encode_bytes_field(1, peer_id_bytes)
    for a in addrs:
        out += pb_lite.encode_bytes_field(2, a)
    # connection field omitted -> defaults to NOT_CONNECTED=0
    return out


def decode_kad_peer(buf):
    """Return (peer_id_bytes, [addr_bytes,...], connection_int)."""
    fields = pb_lite.parse_message(buf)
    pid = fields.get(1, [b""])[-1]
    addrs = fields.get(2, [])
    conn = fields.get(3, [0])[-1]
    return pid, addrs, conn


def encode_find_node(target_key):
    """Encode a FIND_NODE request looking up ``target_key`` (bytes)."""
    return (
        pb_lite.encode_varint_field(1, TYPE_FIND_NODE)
        + pb_lite.encode_bytes_field(2, target_key)
    )


# ---- Record (key, value, time) ----------------------------------------

def encode_record(key, value, time_received=""):
    """Marshal a Kad-DHT Record sub-message.

    ``time_received`` is an RFC3339 timestamp string per the spec
    (e.g. "2026-05-27T12:00:00Z").  Default-empty is allowed but
    real go-libp2p validators may reject; callers SHOULD fill it.
    """
    parts = [
        pb_lite.encode_bytes_field(1, key),
        pb_lite.encode_bytes_field(2, value),
    ]
    if time_received:
        parts.append(pb_lite.encode_string_field(5, time_received))
    return b"".join(parts)


def decode_record(buf):
    """Return (key, value, time_received_str) parsed from a Record."""
    fields = pb_lite.parse_message(buf)
    key = fields.get(1, [b""])[-1]
    value = fields.get(2, [b""])[-1]
    time_field = fields.get(5, [b""])[-1]
    if isinstance(time_field, (bytes, bytearray)):
        time_str = bytes(time_field).decode("utf-8", errors="replace")
    else:
        time_str = ""
    return key, value, time_str


# ---- PUT_VALUE / GET_VALUE / ADD_PROVIDER / GET_PROVIDERS -------------

def encode_put_value(key, record_bytes):
    """Encode a PUT_VALUE request.

    ``record_bytes`` is the output of ``encode_record`` -- the
    request carries the FULL record so the receiver can validate
    the key field inside matches the top-level key field (the
    libp2p Kad-DHT spec asks the validator to enforce this).
    """
    return (
        pb_lite.encode_varint_field(1, TYPE_PUT_VALUE)
        + pb_lite.encode_bytes_field(2, key)
        + pb_lite.encode_message_field(3, record_bytes)
    )


def encode_get_value(key):
    """Encode a GET_VALUE request for ``key``."""
    return (
        pb_lite.encode_varint_field(1, TYPE_GET_VALUE)
        + pb_lite.encode_bytes_field(2, key)
    )


def encode_get_value_reply(key, record_bytes=b"", closer_peers=()):
    """Encode a GET_VALUE reply: optional Record + closer_peers."""
    parts = [
        pb_lite.encode_varint_field(1, TYPE_GET_VALUE),
        pb_lite.encode_bytes_field(2, key),
    ]
    if record_bytes:
        parts.append(pb_lite.encode_message_field(3, record_bytes))
    for p in closer_peers:
        parts.append(
            pb_lite.encode_message_field(8, encode_kad_peer(p.peer_id, p.addrs))
        )
    return b"".join(parts)


def encode_add_provider(key, provider_peer_id, provider_addrs=()):
    """Encode an ADD_PROVIDER request announcing ``peer_id`` provides ``key``.

    The libp2p Kad-DHT spec puts the announcing peer's info into
    ``provider_peers``; receivers store the (key -> [providers])
    mapping with TTL.
    """
    return (
        pb_lite.encode_varint_field(1, TYPE_ADD_PROVIDER)
        + pb_lite.encode_bytes_field(2, key)
        + pb_lite.encode_message_field(
            9, encode_kad_peer(provider_peer_id, provider_addrs),
        )
    )


def encode_get_providers(key):
    """Encode a GET_PROVIDERS request for ``key``."""
    return (
        pb_lite.encode_varint_field(1, TYPE_GET_PROVIDERS)
        + pb_lite.encode_bytes_field(2, key)
    )


def encode_get_providers_reply(key, providers=(), closer_peers=()):
    """Encode a GET_PROVIDERS reply: provider_peers + closer_peers."""
    parts = [
        pb_lite.encode_varint_field(1, TYPE_GET_PROVIDERS),
        pb_lite.encode_bytes_field(2, key),
    ]
    for p in providers:
        parts.append(
            pb_lite.encode_message_field(9, encode_kad_peer(p.peer_id, p.addrs))
        )
    for p in closer_peers:
        parts.append(
            pb_lite.encode_message_field(8, encode_kad_peer(p.peer_id, p.addrs))
        )
    return b"".join(parts)


def decode_message(buf):
    """Parse a Kad-DHT Message protobuf into a dict.

    Returned dict keys:
        type:           int (the MessageType enum value)
        key:            bytes (field 2)
        record:         (key, value, time_str) or None  (field 3)
        closer_peers:   list of (peer_id, [addrs], conn)  (field 8)
        provider_peers: list of (peer_id, [addrs], conn)  (field 9)
    """
    fields = pb_lite.parse_message(buf)
    out = {
        "type": fields.get(1, [0])[-1],
        "key": fields.get(2, [b""])[-1],
        "record": (
            decode_record(fields[3][-1]) if 3 in fields else None
        ),
        "closer_peers": [decode_kad_peer(b) for b in fields.get(8, [])],
        "provider_peers": [decode_kad_peer(b) for b in fields.get(9, [])],
    }
    return out


# ---- Wire framing -------------------------------------------------------


async def write_kad_msg(stream, blob):
    """Send one varint-length-prefixed Kad message on ``stream``."""
    await stream.write(varint.encode(len(blob)) + blob)


async def read_kad_msg(stream, max_len=1 << 20):
    """Receive one varint-length-prefixed Kad message."""
    length = await varint.read_varint(stream)
    if length > max_len:
        raise ValueError("kad: response too large ({0} bytes)".format(length))
    if length == 0:
        return b""
    return await read_exactly(stream, length)


# ---- Key derivation -----------------------------------------------------


def key_for_peer_id(peer_id_bytes):
    """Map a libp2p PeerID to the 32-byte Kad-DHT lookup key.

    Per the libp2p Kad-DHT spec, keys in the DHT keyspace are
    SHA-256 of the original namespace key.  For peer lookups, the
    "original namespace key" is the peer's multihash bytes.
    """
    return hashlib.sha256(peer_id_bytes).digest()


# ---- Datastore (in-memory) --------------------------------------------


class KadDatastore(object):
    """In-memory K/V + provider store for the responder side of Kad.

    Two surfaces:

      - ``values`` : key_bytes -> (value_bytes, time_received_str)
        Populated by PUT_VALUE; consulted by GET_VALUE.
      - ``providers`` : key_bytes -> dict(peer_id_bytes ->
                                          (addrs, unix_seconds_added))
        Populated by ADD_PROVIDER; consulted by GET_PROVIDERS.

    Expiry policy is intentionally permissive for Phase 1 -- we
    keep everything forever.  Production deployments would TTL
    records at the libp2p-spec defaults (24h for values, 24h for
    providers).  The methods take a ``time.time()`` second
    argument so a future TTL pass is a local edit.
    """

    MAX_VALUE_BYTES = 4096
    MAX_KEY_BYTES = 256

    def __init__(self):
        self.values = {}
        self.providers = {}

    def put_value(self, key, value, time_received_str):
        if len(key) == 0 or len(key) > self.MAX_KEY_BYTES:
            raise ValueError("kad datastore: bad key length")
        if len(value) > self.MAX_VALUE_BYTES:
            raise ValueError("kad datastore: value too large")
        self.values[bytes(key)] = (bytes(value), time_received_str)

    def get_value(self, key):
        """Return (value, time_received_str) or (None, None)."""
        entry = self.values.get(bytes(key))
        if entry is None:
            return (None, None)
        return entry

    def add_provider(self, key, peer_id, addrs, now_unix):
        if len(key) == 0 or len(key) > self.MAX_KEY_BYTES:
            raise ValueError("kad datastore: bad key length")
        bucket = self.providers.setdefault(bytes(key), {})
        bucket[bytes(peer_id)] = (list(addrs), now_unix)

    def get_providers(self, key):
        """Return a list of (peer_id_bytes, addrs)."""
        bucket = self.providers.get(bytes(key))
        if not bucket:
            return []
        return [(pid, addrs) for pid, (addrs, _t) in bucket.items()]


# ---- Libp2pKadTransport -------------------------------------------------


class Libp2pKadTransport(object):
    """Implements ``warpgate.kademlia.KadTransport`` over libp2p streams.

    Resolves a PeerInfo to a session in this order:

      1. An existing session in ``node.sessions`` (cheap).
      2. If ``node.auto_dial_during_walks`` is True, try dialling
         the peer using the multiaddrs attached to its PeerInfo --
         best-effort, swallowed errors mean "no path".

    Auto-dial is opt-in because in the warpgate-MQTT-rendezvous
    use case we don't WANT to spend cycles dialling random peers
    discovered through a Kad walk; we just want to use the
    rendezvous-introduced session.  For real-public-DHT mesh
    participation the opposite is true -- the walk only progresses
    if you dial as you discover.
    """

    def __init__(self, node, session_for_peer=None):
        self.node = node
        if session_for_peer is None:
            session_for_peer = self.default_session_for_peer
        self.session_for_peer = session_for_peer
        # Cache of in-progress dials so concurrent walks don't all
        # race to open a session to the same fresh peer.
        self.pending_dials = {}

    def default_session_for_peer(self, peer_id):
        for s in self.node.sessions:
            if s.remote_peer_id == peer_id:
                return s
        return None

    async def resolve_session(self, peer_info):
        """Return an active LibP2PSession for ``peer_info`` or raise.

        Checks ``session_for_peer`` first; if that returns None and
        the node has ``auto_dial_during_walks`` set, tries each
        multiaddr the routing table learned for the peer until one
        successfully completes the libp2p handshake (Noise +
        yamux, no app stream).  Caches the in-flight dial so two
        concurrent walks don't fight over the same peer.
        """
        s = self.session_for_peer(peer_info.peer_id)
        if s is not None:
            return s
        if not getattr(self.node, "auto_dial_during_walks", False):
            raise ConnectionError(
                "kad: no session to peer {0}".format(peer_info.peer_id.hex()[:16])
            )
        # Auto-dial path.  De-dup via pending_dials.
        existing = self.pending_dials.get(peer_info.peer_id)
        if existing is not None:
            try:
                return await existing
            except Exception:
                raise ConnectionError(
                    "kad: concurrent dial to {0} failed".format(
                        peer_info.peer_id.hex()[:16]
                    )
                )
        fut = asyncio.ensure_future(
            self.dial_peer_info(peer_info)
        )
        self.pending_dials[peer_info.peer_id] = fut
        try:
            return await fut
        finally:
            # Keep the entry so a successful future is reused; only
            # forget failed ones so a later walk can retry.
            try:
                if fut.exception() is not None:
                    self.pending_dials.pop(peer_info.peer_id, None)
            except asyncio.CancelledError:
                self.pending_dials.pop(peer_info.peer_id, None)
                raise
            except Exception:
                self.pending_dials.pop(peer_info.peer_id, None)

    async def dial_peer_info(self, peer_info):
        """Try each multiaddr on ``peer_info`` until one dials successfully."""
        from . import multiaddr as ma
        from aionetiface import IP4, IP6, Interface
        iface = await Interface()
        for addr_bytes in peer_info.addrs:
            try:
                parts = ma.decode(addr_bytes)
            except (ValueError, OSError):
                continue
            if ma.contains_circuit(parts):
                # Skip /p2p-circuit addresses on this fast path --
                # they'd need a separate "dial through relay" flow.
                continue
            ip, port = ma.extract_first_ip_tcp(parts)
            if ip is None or port is None:
                continue
            af = IP6 if ":" in ip else IP4
            try:
                route = await iface.route(af).bind(ips=None, port=0)
            except (OSError, ValueError):
                continue
            try:
                _stream, _pid, session = await self.node.dial(
                    ip, port, route,
                    expected_peer_id=peer_info.peer_id,
                    timeout=10.0,
                    open_app_stream=False,
                )
                return session
            except (OSError, ConnectionError, asyncio.TimeoutError, ValueError):
                continue
        raise ConnectionError(
            "kad: auto-dial exhausted all addrs for {0}".format(
                peer_info.peer_id.hex()[:16]
            )
        )

    async def open_kad_stream(self, peer_info):
        """Open + multistream-select /ipfs/kad/1.0.0 to ``peer_info``.

        Common prologue for every per-peer Kad query.  Returns the
        ready-to-use yamux Stream.
        """
        session = await self.resolve_session(peer_info)
        stream = await session.mux_session.open_stream()
        try:
            chosen = await negotiate_initiator(stream, stream, [KAD_PROTOCOL])
            if chosen != KAD_PROTOCOL:
                raise ConnectionError("kad: peer refused /ipfs/kad/1.0.0")
        except Exception:
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass
            raise
        return stream

    async def find_node(self, peer_info, target_key):
        """Open a /ipfs/kad/1.0.0 stream to ``peer_info``, send FIND_NODE.

        Returns a list of ``PeerInfo`` from the response's
        closer_peers field.  Raises on any error (caller treats as
        a failed query).
        """
        stream = await self.open_kad_stream(peer_info)
        try:
            await write_kad_msg(stream, encode_find_node(target_key))
            reply_buf = await read_kad_msg(stream)
            reply = decode_message(reply_buf)
            out = []
            for pid, addrs, _conn in reply.get("closer_peers", []):
                if not pid:
                    continue
                out.append(PeerInfo(pid, addrs=addrs))
            return out
        finally:
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass

    async def put_value(self, peer_info, key, record_bytes):
        """Send PUT_VALUE to ``peer_info``; no useful reply expected.

        We DO read the response anyway -- libp2p convention is
        echo-the-message-back-with-record-field-set so the caller
        can tell whether storage succeeded.  Most go-libp2p
        implementations just echo the input; we treat any non-error
        read as success.
        """
        stream = await self.open_kad_stream(peer_info)
        try:
            await write_kad_msg(stream, encode_put_value(key, record_bytes))
            # The peer may or may not reply; some implementations
            # close the stream after PUT_VALUE.  Read with a short
            # tolerance -- a closed stream is fine, a returned
            # message is fine, only OSError on write or non-empty
            # garbled reply matters.
            try:
                _ = await read_kad_msg(stream)
            except (ConnectionError, ValueError):
                pass
            return True
        finally:
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass

    async def get_value(self, peer_info, key):
        """Send GET_VALUE; return (value, time_str, [closer_peers]).

        ``value`` is None if the peer has no record for that key.
        ``closer_peers`` is always populated -- callers iterate the
        walk through them just like FIND_NODE.
        """
        stream = await self.open_kad_stream(peer_info)
        try:
            await write_kad_msg(stream, encode_get_value(key))
            reply_buf = await read_kad_msg(stream)
            reply = decode_message(reply_buf)
            record = reply.get("record")
            value = None
            time_str = ""
            if record is not None:
                _rkey, value, time_str = record
                if value == b"":
                    value = None
            closer = []
            for pid, addrs, _conn in reply.get("closer_peers", []):
                if pid:
                    closer.append(PeerInfo(pid, addrs=addrs))
            return value, time_str, closer
        finally:
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass

    async def add_provider(self, peer_info, key, provider_peer_id, provider_addrs):
        """Send ADD_PROVIDER; no useful reply."""
        stream = await self.open_kad_stream(peer_info)
        try:
            await write_kad_msg(
                stream,
                encode_add_provider(key, provider_peer_id, provider_addrs),
            )
            try:
                _ = await read_kad_msg(stream)
            except (ConnectionError, ValueError):
                pass
            return True
        finally:
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass

    async def get_providers(self, peer_info, key):
        """Send GET_PROVIDERS; return ([providers], [closer_peers])."""
        stream = await self.open_kad_stream(peer_info)
        try:
            await write_kad_msg(stream, encode_get_providers(key))
            reply_buf = await read_kad_msg(stream)
            reply = decode_message(reply_buf)
            providers = []
            for pid, addrs, _conn in reply.get("provider_peers", []):
                if pid:
                    providers.append(PeerInfo(pid, addrs=addrs))
            closer = []
            for pid, addrs, _conn in reply.get("closer_peers", []):
                if pid:
                    closer.append(PeerInfo(pid, addrs=addrs))
            return providers, closer
        finally:
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass


# ---- Responder side -----------------------------------------------------


async def handle_kad_stream(stream, node):
    """Service a freshly-negotiated /ipfs/kad/1.0.0 stream.

    Reads one request, dispatches by Message.type:

      FIND_NODE      -> closer_peers from kad_routing_table
      GET_VALUE      -> record from kad_datastore (if any) +
                        closer_peers
      PUT_VALUE      -> stash record in kad_datastore (if the
                        request key matches the record.key)
      GET_PROVIDERS  -> provider_peers from kad_datastore +
                        closer_peers
      ADD_PROVIDER   -> remember the announced provider
      PING           -> echo

    The store-side methods reject malformed input (oversized key,
    record.key mismatch) silently so a malformed peer doesn't get
    us to allocate.  Closer-peers responses are filtered to peers
    OTHER than the requester so the walk doesn't bounce back.
    """
    import time
    try:
        msg_buf = await read_kad_msg(stream)
        msg = decode_message(msg_buf)
        mtype = msg.get("type", 0)
        key = msg.get("key", b"")

        # The kad-keyspace routing key.  For FIND_NODE the wire-
        # level ``key`` field is already the 32-byte SHA-256 image
        # (callers hash before dispatch).  For PUT/GET/PROVIDE the
        # wire-level key is the raw application-level bytes; we
        # hash it here to land in the same 256-bit keyspace
        # before consulting the routing table.
        if mtype == TYPE_FIND_NODE:
            routing_key = key
        else:
            routing_key = hashlib.sha256(key).digest()

        if mtype == TYPE_FIND_NODE:
            closest = node.kad_routing_table.find_closest(
                routing_key, node.kad_routing_table.k,
            ) if node.kad_routing_table is not None else []
            reply_parts = [pb_lite.encode_varint_field(1, TYPE_FIND_NODE)]
            for p in closest:
                reply_parts.append(
                    pb_lite.encode_message_field(8, encode_kad_peer(p.peer_id, p.addrs))
                )
            await write_kad_msg(stream, b"".join(reply_parts))

        elif mtype == TYPE_GET_VALUE:
            value, time_str = (None, None)
            if node.kad_datastore is not None:
                value, time_str = node.kad_datastore.get_value(key)
            record_bytes = b""
            if value is not None:
                record_bytes = encode_record(key, value, time_str or "")
            closest = node.kad_routing_table.find_closest(
                routing_key, node.kad_routing_table.k,
            ) if node.kad_routing_table is not None else []
            await write_kad_msg(
                stream, encode_get_value_reply(key, record_bytes, closest),
            )

        elif mtype == TYPE_PUT_VALUE:
            record = msg.get("record")
            if record is not None and node.kad_datastore is not None:
                rkey, rvalue, rtime = record
                # Spec: top-level key MUST match record.key.
                if rkey == key:
                    try:
                        node.kad_datastore.put_value(key, rvalue, rtime)
                    except ValueError:
                        log_exception()
            # Echo the request back -- most go-libp2p PUT_VALUE
            # responders mirror the input as the confirmation.
            await write_kad_msg(stream, msg_buf)

        elif mtype == TYPE_GET_PROVIDERS:
            providers = []
            if node.kad_datastore is not None:
                for pid, addrs in node.kad_datastore.get_providers(key):
                    providers.append(PeerInfo(pid, addrs=addrs))
            closest = node.kad_routing_table.find_closest(
                routing_key, node.kad_routing_table.k,
            ) if node.kad_routing_table is not None else []
            await write_kad_msg(
                stream, encode_get_providers_reply(key, providers, closest),
            )

        elif mtype == TYPE_ADD_PROVIDER:
            # provider_peers list carries the announcing peer's
            # info; for now we accept ALL announcers (no
            # spam-filtering by source peer_id) but a future
            # tighten could check the source session matches
            # provider_peers[0].peer_id.
            if node.kad_datastore is not None:
                for pid, addrs, _conn in msg.get("provider_peers", []):
                    if not pid:
                        continue
                    try:
                        node.kad_datastore.add_provider(
                            key, pid, addrs, int(time.time()),
                        )
                    except ValueError:
                        log_exception()
            await write_kad_msg(stream, msg_buf)

        elif mtype == TYPE_PING:
            await write_kad_msg(stream, pb_lite.encode_varint_field(1, TYPE_PING))

        else:
            # Unknown type -- send empty same-type reply so the
            # peer doesn't hang.
            await write_kad_msg(stream, pb_lite.encode_varint_field(1, mtype))
    except (ConnectionError, asyncio.TimeoutError, OSError, ValueError):
        pass
    finally:
        try:
            await stream.close()
        except (OSError, ConnectionError):
            pass


def log_exception():
    # Local lazy import so this module stays importable without
    # the rest of aionetiface present (e.g. for unit-test stubs).
    try:
        from aionetiface import log_exception as ext_log_exception
        ext_log_exception()
    except ImportError:
        import traceback
        traceback.print_exc()
