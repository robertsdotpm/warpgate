"""libp2p Identify protocol -- /ipfs/id/1.0.0.

Once a session is up, either side may open a yamux stream and run
multistream-select on it for ``/ipfs/id/1.0.0``.  The responder
then sends back exactly one length-prefixed Identify protobuf, which
tells the peer:

  * which libp2p PublicKey identifies them
  * which network addresses they listen on (multiaddr bytes)
  * which protocols they handle
  * the address WE appeared to connect from (observedAddr) -- handy
    feedback for STUN-free NAT-discovery
  * a human-readable protocol/agent version

After the responder writes its Identify, it closes the stream
(FIN).  The initiator reads the message, parses it, hands the
result back to its caller.

Wire schema (libp2p/specs/identify):

    message Identify {
        optional string protocolVersion = 5;
        optional string agentVersion    = 6;
        optional bytes  publicKey       = 1;
        repeated bytes  listenAddrs     = 2;
        repeated string protocols       = 3;
        optional bytes  observedAddr    = 4;
    }

For Phase 1 we marshall the fields warpgate-relevant peers care
about (publicKey, listenAddrs, protocols, observedAddr); the
version fields default to constants.  For Phase 1 we ALSO parse
out a peer's observedAddr -- the warpgate cascade can use that
as an extra NAT-mapping reading from a third-party perspective.
"""
from . import pb_lite
from . import varint
from .stream_io import read_exactly


IDENTIFY_PROTOCOL = "/ipfs/id/1.0.0"

PROTOCOL_VERSION = "warpgate-libp2p/1.0"
AGENT_VERSION = "warpgate-libp2p-native/0.1"


def encode_identify(public_key_marshalled, listen_addrs_bytes,
                    protocols, observed_addr_bytes=b"",
                    protocol_version=PROTOCOL_VERSION,
                    agent_version=AGENT_VERSION):
    """Marshal an Identify protobuf.

    ``listen_addrs_bytes`` is a list of multiaddr-encoded bytes
    (one per advertised listen endpoint).  ``protocols`` is a list
    of protocol-id strings.  ``observed_addr_bytes`` may be empty.
    """
    parts = []
    parts.append(pb_lite.encode_bytes_field(1, public_key_marshalled))
    for la in listen_addrs_bytes:
        parts.append(pb_lite.encode_bytes_field(2, la))
    for proto in protocols:
        parts.append(pb_lite.encode_string_field(3, proto))
    if observed_addr_bytes:
        parts.append(pb_lite.encode_bytes_field(4, observed_addr_bytes))
    parts.append(pb_lite.encode_string_field(5, protocol_version))
    parts.append(pb_lite.encode_string_field(6, agent_version))
    return b"".join(parts)


class IdentifyResult(object):
    """Parsed view of a peer's Identify response."""

    def __init__(self, public_key=b"", listen_addrs=(), protocols=(),
                 observed_addr=b"", protocol_version="", agent_version=""):
        self.public_key = public_key
        self.listen_addrs = list(listen_addrs)
        self.protocols = list(protocols)
        self.observed_addr = observed_addr
        self.protocol_version = protocol_version
        self.agent_version = agent_version


def decode_identify(buf):
    """Parse an Identify protobuf into an IdentifyResult."""
    fields = pb_lite.parse_message(buf)
    public_key = fields.get(1, [b""])[-1]
    listen_addrs = fields.get(2, [])
    protocols = [
        p.decode("utf-8", errors="replace") for p in fields.get(3, [])
    ]
    observed_addr = fields.get(4, [b""])[-1]
    pv = fields.get(5, [b""])[-1]
    av = fields.get(6, [b""])[-1]
    return IdentifyResult(
        public_key=public_key,
        listen_addrs=listen_addrs,
        protocols=protocols,
        observed_addr=observed_addr,
        protocol_version=pv.decode("utf-8", errors="replace") if isinstance(pv, (bytes, bytearray)) else pv,
        agent_version=av.decode("utf-8", errors="replace") if isinstance(av, (bytes, bytearray)) else av,
    )


# ---- Wire helpers -----------------------------------------------------------


async def send_identify(writer, public_key_marshalled, listen_addrs_bytes,
                        protocols, observed_addr_bytes=b""):
    """Marshal + send a length-prefixed Identify message on ``writer``.

    The Identify wire framing per libp2p spec is one length-prefixed
    protobuf blob; ``writer`` is the post-multistream-select stream
    we just negotiated on.
    """
    blob = encode_identify(
        public_key_marshalled, listen_addrs_bytes, protocols,
        observed_addr_bytes,
    )
    await writer.write(varint.encode(len(blob)) + blob)


async def recv_identify(reader):
    """Read one length-prefixed Identify protobuf and return IdentifyResult."""
    length = await varint.read_varint(reader)
    if length == 0:
        return IdentifyResult()
    if length > 1 << 20:
        # 1 MiB hard cap so a malformed peer can't get us to allocate.
        raise ValueError("identify: response too large ({0} bytes)".format(length))
    buf = await read_exactly(reader, length)
    return decode_identify(buf)
