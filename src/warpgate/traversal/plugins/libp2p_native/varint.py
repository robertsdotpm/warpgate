"""Unsigned LEB128 varint -- the framing primitive used everywhere
in libp2p (multistream length prefix, plaintext exchange length,
yamux header in newer versions, etc).

Bytewise, low-order group of 7 bits first, MSB set on every byte
except the final one.  Same as Protobuf's varint.

This module has zero dependencies on anything else in warpgate so
it can be imported during plugin_loader.import_internal_plugins
without circular concerns.
"""


def encode(n):
    """Encode a non-negative integer as an unsigned LEB128 varint."""
    if n < 0:
        raise ValueError("varint.encode: negative int not supported")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def decode_from(buf, offset=0):
    """Decode a varint starting at ``offset`` in ``buf``.

    Returns (value, new_offset).  Raises ValueError if the varint is
    incomplete (no terminator byte before end-of-buffer).  Caps at
    9 continuation bytes (63 bits payload) so a malicious 10-byte
    sequence can't overflow int math on small platforms.
    """
    val = 0
    shift = 0
    pos = offset
    end = len(buf)
    for i in range(10):
        if pos >= end:
            raise ValueError("varint.decode_from: truncated varint")
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7
        if shift >= 63:
            raise ValueError("varint.decode_from: varint too long")
    raise ValueError("varint.decode_from: no terminator after 10 bytes")


async def read_varint(reader):
    """Read a varint from an awaitable reader exposing ``read(n)``.

    The reader is something like an asyncio StreamReader -- we ask
    for one byte at a time, append until we see a byte with the high
    bit cleared, then return the decoded int.

    Mirrors the receive side of varint.encode -- streams use this
    to consume length-prefixed frames.
    """
    shift = 0
    val = 0
    for i in range(10):
        chunk = await reader.read(1)
        if not chunk:
            raise ConnectionError("varint.read_varint: peer closed mid-varint")
        b = chunk[0] if isinstance(chunk, (bytes, bytearray)) else chunk
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val
        shift += 7
        if shift >= 63:
            raise ValueError("varint.read_varint: varint too long")
    raise ValueError("varint.read_varint: no terminator after 10 bytes")
