"""Wire framing helpers for Yggdrasil + ironwood.

Both yggdrasil-go and ironwood share a tiny set of binary
serialisation primitives that everything else builds on:

  * Single-byte packet-type enums (``ironwood/network/wire.go``).
  * Go-flavour unsigned varints (``binary.Uvarint`` style) for
    lengths, peer-port lists, and the source-routing paths.
  * A "chop" pattern -- functions that consume a prefix of a byte
    slice and advance a cursor -- used throughout the routing
    layer so a decoder can read a packet field-by-field without
    extra allocation.

This module is the Python equivalent.  Encode/decode is symmetric
with the Go code so a packet built in Python is byte-identical to
one built in Go for the same inputs (validated in
``tests/test_yggdrasil_wire.py`` against captures of real upstream
encode output).
"""
from aionetiface import fstr


# Wire packet types -- single byte at the head of every wire packet.
# Order MUST match ironwood/network/wire.go's wirePacketType iota.
WIRE_DUMMY = 0
WIRE_KEEP_ALIVE = 1
WIRE_PROTO_SIG_REQ = 2
WIRE_PROTO_SIG_RES = 3
WIRE_PROTO_ANNOUNCE = 4
WIRE_PROTO_BLOOM_FILTER = 5
WIRE_PROTO_PATH_LOOKUP = 6
WIRE_PROTO_PATH_NOTIFY = 7
WIRE_PROTO_PATH_BROKEN = 8
WIRE_TRAFFIC = 9


# Useful for log lines.  Same order as the constants above.
WIRE_TYPE_NAMES = {
    WIRE_DUMMY: "dummy",
    WIRE_KEEP_ALIVE: "keepalive",
    WIRE_PROTO_SIG_REQ: "sig_req",
    WIRE_PROTO_SIG_RES: "sig_res",
    WIRE_PROTO_ANNOUNCE: "announce",
    WIRE_PROTO_BLOOM_FILTER: "bloom",
    WIRE_PROTO_PATH_LOOKUP: "path_lookup",
    WIRE_PROTO_PATH_NOTIFY: "path_notify",
    WIRE_PROTO_PATH_BROKEN: "path_broken",
    WIRE_TRAFFIC: "traffic",
}


# Maximum varint length in bytes.  Go uses ``binary.MaxVarintLen64 = 10``
# because a 64-bit unsigned value is at most ceil(64/7) = 10 bytes.
MAX_VARINT_LEN = 10


def encode_uvarint(value):
    """Encode a non-negative integer as a Go-style unsigned varint.

    Layout (LEB128, little-endian groups of 7 bits): each byte's
    high bit is a continuation flag (1 = more bytes follow, 0 =
    last byte).  ``binary.AppendUvarint`` semantics; symmetric
    with ``decode_uvarint``.
    """
    if value < 0:
        raise ValueError("encode_uvarint: value must be non-negative")
    if value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("encode_uvarint: value > uint64 max")
    out = bytearray()
    v = value
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v & 0x7F)
    return bytes(out)


def decode_uvarint(data, offset=0):
    """Decode a Go-style unsigned varint from ``data`` at ``offset``.

    Returns ``(value, bytes_consumed)``.  Raises ``ValueError`` on
    truncated or oversize input -- matches Go's ``binary.Uvarint``
    returning ``(0, <= 0)`` semantically, but raises so the caller
    can't accidentally treat a decode failure as a valid value of 0.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError("decode_uvarint: data must be bytes-like")
    value = 0
    shift = 0
    pos = offset
    end = len(data)
    while pos < end:
        b = data[pos]
        pos += 1
        if shift >= 64:
            raise ValueError("decode_uvarint: overflow (varint > 64 bits)")
        if b < 0x80:
            # Last byte of the varint.  Mark complete.
            value |= b << shift
            return value, pos - offset
        value |= (b & 0x7F) << shift
        shift += 7
    raise ValueError("decode_uvarint: truncated input")


def varint_size(value):
    """Number of bytes ``value`` would occupy when varint-encoded.

    Mirrors Go's ``wireSizeUint`` -- used by length-prefix encoders
    that need to pre-size their output buffer.
    """
    if value < 0:
        raise ValueError("varint_size: value must be non-negative")
    if value == 0:
        return 1
    n = 0
    v = value
    while v > 0:
        n += 1
        v >>= 7
    return n


class WireCursor(object):
    """Read-only cursor over a bytes buffer, mirroring Go's chop pattern.

    Wraps a buffer + offset and exposes ``chop_*`` methods that read
    a typed prefix and advance the offset.  Raises ``ValueError``
    when the underlying buffer doesn't have enough bytes -- this is
    the Python analogue of the upstream functions returning a bool
    false.  Callers wrap the decode in a try/except to recover.

    Single-pass forward only.  No seeking back, no copying the
    underlying bytes.
    """

    def __init__(self, data, offset=0):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValueError("WireCursor: data must be bytes-like")
        self.data = data
        self.offset = offset

    def remaining(self):
        """Number of bytes left to read."""
        return len(self.data) - self.offset

    def chop_byte(self):
        """Read one byte; advance.  Returns int 0-255."""
        if self.remaining() < 1:
            raise ValueError("chop_byte: truncated input")
        b = self.data[self.offset]
        self.offset += 1
        return b

    def chop_slice(self, n):
        """Read exactly ``n`` bytes; advance; return a bytes copy."""
        if self.remaining() < n:
            raise ValueError(fstr(
                "chop_slice: wanted {0}, have {1}",
                (n, self.remaining()),
            ))
        out = bytes(self.data[self.offset : self.offset + n])
        self.offset += n
        return out

    def chop_uvarint(self):
        """Read one varint; advance; return its value."""
        value, consumed = decode_uvarint(self.data, self.offset)
        self.offset += consumed
        return value

    def chop_path(self):
        """Read a port-list path -- varints terminated by a literal 0.

        Mirrors ``wireChopPath`` in ironwood: peer ports are written
        as varints with a single trailing 0 to delimit the list.
        The terminator IS consumed; returned list is the ports
        only.  Bounded at 128 hops upstream; we apply the same
        bound to refuse memory-amp attacks via malicious inputs.
        """
        ports = []
        while True:
            if len(ports) > 128:
                raise ValueError("chop_path: path > 128 hops, refused")
            value = self.chop_uvarint()
            if value == 0:
                break
            ports.append(value)
        return ports


def encode_path(ports):
    """Encode a list of peer-port integers as varints + trailing 0 byte.

    Symmetric with ``WireCursor.chop_path``.  Used by source-route
    bearing packets in Phase 5 (bloom-filter routing).
    """
    out = bytearray()
    for p in ports:
        if p == 0:
            raise ValueError("encode_path: port 0 is reserved as terminator")
        out.extend(encode_uvarint(p))
    out.extend(encode_uvarint(0))
    return bytes(out)


def encode_packet_type(packet_type, body):
    """Prefix ``body`` with a single ``packet_type`` byte.

    Mirrors ironwood's ``wireEncode`` for the case where the body
    is already a complete byte string (we don't need the
    ``wireEncodeable`` interface dance because Python doesn't have
    Go's "write into a passed slice" optimisation).
    """
    if not 0 <= packet_type <= 0xFF:
        raise ValueError("encode_packet_type: type must fit in one byte")
    return bytes([packet_type]) + bytes(body)
