"""multistream-select 1.0.0 protocol negotiation.

The simplest libp2p sub-protocol: each side writes a length-prefixed
(varint length + bytes) message, where the message is an ASCII
protocol identifier ending in "\\n".

Initiator wire flow (client speaks first):
    -> "/multistream/1.0.0\\n"
    <- "/multistream/1.0.0\\n"
    -> "/<chosen-protocol>\\n"
    <- "/<chosen-protocol>\\n"  (accept) | "na\\n" (reject)

Optimistic protocols ARE the norm in libp2p (initiator just guesses
the next protocol; responder either echoes "ok" or sends "na" so
the initiator picks again).  We use that fast path here -- in the
fail case we raise so the cascade can fall through to a different
plugin.

Reader/writer surface (uniform across PipeStream and yamux.Stream):
    - reader: object with ``async read(n)``
    - writer: object with ``async write(b)``

The yamux.Stream's write awaits per-stream send-window credit, so
all writes upstream are async too -- the protocol layers above
don't need to know whether they're talking to a raw socket or a
multiplexed stream.
"""
import asyncio

from . import varint
from .stream_io import read_exactly


MULTISTREAM_HEADER = "/multistream/1.0.0\n"
NA = "na\n"


def encode_msg(s):
    """Encode a single multistream-select message: varint(len) + ascii bytes."""
    data = s.encode("ascii") if isinstance(s, str) else bytes(s)
    return varint.encode(len(data)) + data


async def read_msg(reader):
    """Read one multistream-select message and return it as a str.

    Frame: varint(len) + bytes.  We don't enforce that the message
    ends in \\n here (some go-libp2p versions skip the newline in
    inner negotiations) -- callers compare against the expected
    protocol with strip().
    """
    length = await varint.read_varint(reader)
    if length > 1024:
        raise ValueError("multistream.read_msg: oversize message ({0} bytes)".format(length))
    data = await read_exactly(reader, length)
    return data.decode("ascii", errors="replace")


async def negotiate_initiator(reader, writer, protocols):
    """Initiator side: send the multistream header + try each protocol
    in ``protocols`` in order, returning the first accepted one.

    ``protocols`` is a list/tuple of ascii strings (e.g. ["/plaintext/2.0.0",
    "/noise"]).  Each candidate is sent optimistically; if the peer
    replies with "na" we move on.  If none accepts we raise
    ConnectionError so the plugin can fail cleanly.

    Returns the chosen protocol string with trailing \\n stripped.
    """
    # Send header + first candidate as a single batch so go-libp2p
    # doesn't fragment its response and force us to read in two go's.
    await writer.write(encode_msg(MULTISTREAM_HEADER))

    header_reply = await read_msg(reader)
    if header_reply.strip() != MULTISTREAM_HEADER.strip():
        raise ConnectionError(
            "multistream.negotiate_initiator: bad header reply {0!r}".format(header_reply)
        )

    for candidate in protocols:
        if not candidate.endswith("\n"):
            candidate_msg = candidate + "\n"
        else:
            candidate_msg = candidate
        await writer.write(encode_msg(candidate_msg))

        reply = await read_msg(reader)
        if reply.strip() == candidate.strip():
            return candidate.strip()
        if reply.strip() == NA.strip():
            continue
        raise ConnectionError(
            "multistream.negotiate_initiator: unexpected reply {0!r}".format(reply)
        )

    raise ConnectionError("multistream.negotiate_initiator: no candidate accepted")


async def negotiate_responder(reader, writer, supported_protocols):
    """Responder side: read the header, echo it, then for each protocol
    the peer proposes either accept it (echo) or reject with "na".

    ``supported_protocols`` is an ordered tuple of str -- the responder
    accepts the FIRST proposal whose stripped form matches any entry
    in this list, then returns it.  Earlier rejections drive the
    initiator's fallback loop.

    Returns the chosen protocol string (no trailing \\n).
    """
    header = await read_msg(reader)
    if header.strip() != MULTISTREAM_HEADER.strip():
        raise ConnectionError(
            "multistream.negotiate_responder: bad header {0!r}".format(header)
        )
    await writer.write(encode_msg(MULTISTREAM_HEADER))

    supported_stripped = [p.strip() for p in supported_protocols]
    # Cap proposals so a misbehaving peer doesn't spin us forever.
    for i in range(32):
        proposal = await read_msg(reader)
        prop_stripped = proposal.strip()
        if prop_stripped in supported_stripped:
            # Echo the proposal exactly as received (including trailing \\n).
            await writer.write(encode_msg(proposal))
            return prop_stripped
        # Unsupported -- reply na and let the initiator try the next.
        await writer.write(encode_msg(NA))
    raise ConnectionError("multistream.negotiate_responder: too many rejected proposals")
