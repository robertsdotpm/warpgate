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

For Phase 1 we wire FIND_NODE only; PUT_VALUE / GET_VALUE / provider
records can be added later for content-routing use cases.  FIND_NODE
is the foundation -- with it we can resolve PeerID -> reachability
addresses via the global libp2p mesh.

Each FIND_NODE is one fresh yamux stream per query (libp2p
convention).  The client opens, multistream-selects /ipfs/kad/1.0.0,
sends a FIND_NODE message naming the target key in field 2, reads
back one Message reply containing closer_peers, closes the stream.

The "target key" libp2p Kad-DHT uses is the **SHA-256 of the
target PeerID multihash bytes** (libp2p Kad-DHT spec section 1.2:
"keys are SHA-256 hashes of the original namespace key").
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


def decode_message(buf):
    """Parse a Kad-DHT Message protobuf into a dict.

    Returned dict keys:
        type:          int (the MessageType enum value)
        key:           bytes (field 2)
        closer_peers:  list of (peer_id, [addrs], conn)
        provider_peers: list of (peer_id, [addrs], conn)
    """
    fields = pb_lite.parse_message(buf)
    out = {
        "type": fields.get(1, [0])[-1],
        "key": fields.get(2, [b""])[-1],
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


# ---- Libp2pKadTransport -------------------------------------------------


class Libp2pKadTransport(object):
    """Implements ``warpgate.kademlia.KadTransport`` over libp2p streams.

    Holds a reference to a Libp2pNode and a callback for "given a
    PeerInfo, give me a session I can use to talk to that peer".
    The callback is needed because the routing table holds peers
    we might not have an open session to -- the transport must
    decide whether to dial fresh or surface a "no path" error.

    For the warpgate-MQTT-rendezvous use case, the callback can
    walk Libp2pNode.sessions for an existing session OR (in
    autorelay/circuit-relay scenarios) open a new dial.  This file
    defaults to a simple "use any existing session with that
    peer_id" -- it doesn't try to dial peers we don't yet have a
    session to, leaving that policy choice to the caller.
    """

    def __init__(self, node, session_for_peer=None):
        self.node = node
        # session_for_peer(peer_id_bytes) -> LibP2PSession or None.
        # Default: walk node.sessions and return any session whose
        # remote_peer_id matches.
        if session_for_peer is None:
            session_for_peer = self.default_session_for_peer
        self.session_for_peer = session_for_peer

    def default_session_for_peer(self, peer_id):
        for s in self.node.sessions:
            if s.remote_peer_id == peer_id:
                return s
        return None

    async def find_node(self, peer_info, target_key):
        """Open a /ipfs/kad/1.0.0 stream to ``peer_info``, send FIND_NODE.

        Returns a list of ``PeerInfo`` from the response's
        closer_peers field.  Raises on any error (caller treats as
        a failed query).
        """
        session = self.session_for_peer(peer_info.peer_id)
        if session is None:
            raise ConnectionError(
                "kad: no session to peer {0}".format(peer_info.peer_id.hex()[:16])
            )
        stream = await session.mux_session.open_stream()
        try:
            chosen = await negotiate_initiator(stream, stream, [KAD_PROTOCOL])
            if chosen != KAD_PROTOCOL:
                raise ConnectionError("kad: peer refused /ipfs/kad/1.0.0")
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


# ---- Responder side -----------------------------------------------------


async def handle_kad_stream(stream, node):
    """Service a freshly-negotiated /ipfs/kad/1.0.0 stream.

    Read one request, build a reply from ``node.kad_routing_table``,
    write it back, close.  Supports FIND_NODE today; PING is a
    trivial no-op reply; PUT_VALUE / GET_VALUE / providers are
    intentionally unimplemented for Phase 1 (return empty
    closer_peers so well-behaved peers move on).
    """
    try:
        msg_buf = await read_kad_msg(stream)
        msg = decode_message(msg_buf)
        mtype = msg.get("type", 0)
        if mtype == TYPE_FIND_NODE:
            target = msg.get("key", b"")
            closest = node.kad_routing_table.find_closest(
                target, node.kad_routing_table.k,
            ) if node.kad_routing_table is not None else []
            reply_parts = [pb_lite.encode_varint_field(1, TYPE_FIND_NODE)]
            for p in closest:
                reply_parts.append(
                    pb_lite.encode_message_field(8, encode_kad_peer(p.peer_id, p.addrs))
                )
            await write_kad_msg(stream, b"".join(reply_parts))
        elif mtype == TYPE_PING:
            # Echo PING type back, no payload.
            await write_kad_msg(stream, pb_lite.encode_varint_field(1, TYPE_PING))
        else:
            # Unsupported request type -- send an empty FIND_NODE-shaped
            # reply with no closer_peers so the peer doesn't hang.
            await write_kad_msg(
                stream, pb_lite.encode_varint_field(1, mtype),
            )
    except (ConnectionError, asyncio.TimeoutError, OSError, ValueError):
        pass
    finally:
        try:
            await stream.close()
        except (OSError, ConnectionError):
            pass
