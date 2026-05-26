"""Routing-protocol message codecs -- byte-compat with ironwood.

Ports the eight wire-typed messages defined in
``ironwood/network/router.go``, ``pathfinder.go``, ``traffic.go``,
and ``bloomfilter.go``.  Every encode method produces exactly the
bytes upstream produces; every decode method accepts bytes the
upstream encoder produces.  This is what lets a real Yggdrasil
peer's traffic flow through us correctly even before we have full
routing intelligence (Phase 5b).

Message hierarchy on the wire (single-byte type tag + body):

  WIRE_PROTO_SIG_REQ      (2) -- RouterSigReq:     seq, nonce
  WIRE_PROTO_SIG_RES      (3) -- RouterSigRes:     sig_req fields + port + psig(64)
  WIRE_PROTO_ANNOUNCE     (4) -- RouterAnnounce:   key(32) + parent(32) + sig_res + sig(64)
  WIRE_PROTO_BLOOM_FILTER (5) -- Bloom:            flags0(16) + flags1(16) + nontrivial-uint64s
  WIRE_PROTO_PATH_LOOKUP  (6) -- PathLookup:       source(32) + dest(32) + from(path)
  WIRE_PROTO_PATH_NOTIFY  (7) -- PathNotify:       path + watermark + source(32) + dest(32) + info
  WIRE_PROTO_PATH_BROKEN  (8) -- PathBroken:       path + watermark + source(32) + dest(32)
  WIRE_TRAFFIC            (9) -- Traffic:          path + from + source(32) + dest(32) + watermark + payload

All ``[]peerPort`` paths use the varint-encoded + zero-terminated
form from ``wire.encode_path``; all fixed-size 32-byte fields are
ed25519 public keys (or signatures, 64 bytes).
"""
import struct

from aionetiface import fstr

from .wire import (
    WIRE_PROTO_SIG_REQ,
    WIRE_PROTO_SIG_RES,
    WIRE_PROTO_ANNOUNCE,
    WIRE_PROTO_BLOOM_FILTER,
    WIRE_PROTO_PATH_LOOKUP,
    WIRE_PROTO_PATH_NOTIFY,
    WIRE_PROTO_PATH_BROKEN,
    WIRE_TRAFFIC,
    WireCursor,
    decode_uvarint,
    encode_path,
    encode_uvarint,
    varint_size,
)


PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64

# Bloom filter sizing -- matches ironwood/network/bloomfilter.go constants.
BLOOM_FILTER_F = 16                       # number of bytes used for flags
BLOOM_FILTER_U = BLOOM_FILTER_F * 8       # number of uint64s in backing array
BLOOM_FILTER_B = BLOOM_FILTER_U * 8       # number of bytes
BLOOM_FILTER_M = BLOOM_FILTER_B * 8       # number of bits
BLOOM_FILTER_K = 8                        # number of hash functions per insert


class DecodeError(Exception):
    """Raised when wire bytes can't be parsed as the expected message type."""


def check_keylike(buf, name, size=PUBLIC_KEY_SIZE):
    """Validate a bytes-like value is the right fixed size."""
    if not isinstance(buf, (bytes, bytearray)):
        raise ValueError(fstr("{0}: must be bytes", (name,)))
    if len(buf) != size:
        raise ValueError(fstr(
            "{0}: length {1}, expected {2}",
            (name, len(buf), size),
        ))


class RouterSigReq(object):
    """Tree-signing request: ``seq`` + ``nonce`` (both varint).

    Sent by a peer that wants the parent to sign its position in
    the spanning tree.  The signed payload is
    ``node_pub || parent_pub || encode(req)``.
    """

    def __init__(self, seq=0, nonce=0):
        self.seq = int(seq)
        self.nonce = int(nonce)

    def size(self):
        return varint_size(self.seq) + varint_size(self.nonce)

    def encode(self):
        return encode_uvarint(self.seq) + encode_uvarint(self.nonce)

    @classmethod
    def decode(cls, data):
        cursor = WireCursor(data)
        seq = cursor.chop_uvarint()
        nonce = cursor.chop_uvarint()
        if cursor.remaining() != 0:
            raise DecodeError("RouterSigReq: trailing bytes")
        return cls(seq=seq, nonce=nonce)

    def bytes_for_sig(self, node_pub, parent_pub):
        """Return the canonical byte string signed by the parent.

        Layout: ``node_pub || parent_pub || encode(self)``.  The
        parent signs this with ed25519 to produce ``psig`` in the
        SigRes / Announce that follows.
        """
        check_keylike(node_pub, "node_pub")
        check_keylike(parent_pub, "parent_pub")
        return bytes(node_pub) + bytes(parent_pub) + self.encode()


class RouterSigRes(object):
    """Tree-signing response: SigReq fields + port + psig.

    The parent's reply with a signature over (node, parent, req).
    ``port`` is the parent-side peer_port number for the child.
    """

    def __init__(self, seq=0, nonce=0, port=0, psig=b"\x00" * SIGNATURE_SIZE):
        check_keylike(psig, "psig", size=SIGNATURE_SIZE)
        self.req = RouterSigReq(seq=seq, nonce=nonce)
        self.seq = self.req.seq
        self.nonce = self.req.nonce
        self.port = int(port)
        self.psig = bytes(psig)

    def size(self):
        return self.req.size() + varint_size(self.port) + SIGNATURE_SIZE

    def encode(self):
        return (self.req.encode()
                + encode_uvarint(self.port)
                + self.psig)

    @classmethod
    def chop(cls, cursor):
        seq = cursor.chop_uvarint()
        nonce = cursor.chop_uvarint()
        port = cursor.chop_uvarint()
        psig = cursor.chop_slice(SIGNATURE_SIZE)
        return cls(seq=seq, nonce=nonce, port=port, psig=psig)

    @classmethod
    def decode(cls, data):
        cursor = WireCursor(data)
        msg = cls.chop(cursor)
        if cursor.remaining() != 0:
            raise DecodeError("RouterSigRes: trailing bytes")
        return msg

    def bytes_for_sig(self, node_pub, parent_pub):
        """Bytes that the *parent* signs to produce ``psig``."""
        return (self.req.bytes_for_sig(node_pub, parent_pub)
                + encode_uvarint(self.port))


class RouterAnnounce(object):
    """Tree-announcement: tells peers about (node, parent, sig_res, sig)."""

    def __init__(self, key=b"\x00" * PUBLIC_KEY_SIZE,
                 parent=b"\x00" * PUBLIC_KEY_SIZE,
                 sig_res=None, sig=b"\x00" * SIGNATURE_SIZE):
        check_keylike(key, "key")
        check_keylike(parent, "parent")
        check_keylike(sig, "sig", size=SIGNATURE_SIZE)
        self.key = bytes(key)
        self.parent = bytes(parent)
        self.sig_res = sig_res if sig_res is not None else RouterSigRes()
        self.sig = bytes(sig)

    def size(self):
        return (PUBLIC_KEY_SIZE * 2 + self.sig_res.size() + SIGNATURE_SIZE)

    def encode(self):
        return (self.key + self.parent
                + self.sig_res.encode()
                + self.sig)

    @classmethod
    def decode(cls, data):
        cursor = WireCursor(data)
        key = cursor.chop_slice(PUBLIC_KEY_SIZE)
        parent = cursor.chop_slice(PUBLIC_KEY_SIZE)
        sig_res = RouterSigRes.chop(cursor)
        sig = cursor.chop_slice(SIGNATURE_SIZE)
        if cursor.remaining() != 0:
            raise DecodeError("RouterAnnounce: trailing bytes")
        return cls(key=key, parent=parent, sig_res=sig_res, sig=sig)


class Bloom(object):
    """Bloom-filter packet -- 16+16 byte flag header + non-trivial uint64s.

    Mirrors ``ironwood/network/bloomfilter.go``'s wire shape.  This
    class handles the WIRE FORMAT only; the actual Bloom set logic
    (Add / Test / Merge) lives in ``bloom.py`` because it needs a
    hash function (murmur3) that's orthogonal to the framing.

    Encoded form holds ``BLOOM_FILTER_U == 128`` slots.  Each slot
    is one of: all-zero (flagged in flags0), all-one (flagged in
    flags1), or an arbitrary uint64 (8 bytes BE in the data
    section).  Decoding rebuilds the full 128-slot array.
    """

    def __init__(self, slots=None):
        if slots is None:
            slots = [0] * BLOOM_FILTER_U
        if len(slots) != BLOOM_FILTER_U:
            raise ValueError(fstr(
                "Bloom: slot count {0}, expected {1}",
                (len(slots), BLOOM_FILTER_U),
            ))
        self.slots = list(slots)

    def size(self):
        size = BLOOM_FILTER_F * 2  # two flag byte arrays
        for u in self.slots:
            if u != 0 and u != (1 << 64) - 1:
                size += 8
        return size

    def encode(self):
        flags0 = bytearray(BLOOM_FILTER_F)
        flags1 = bytearray(BLOOM_FILTER_F)
        body = bytearray()
        all_ones = (1 << 64) - 1
        for idx, u in enumerate(self.slots):
            if u == 0:
                flags0[idx // 8] |= 0x80 >> (idx % 8)
                continue
            if u == all_ones:
                flags1[idx // 8] |= 0x80 >> (idx % 8)
                continue
            body.extend(struct.pack(">Q", u))
        return bytes(flags0) + bytes(flags1) + bytes(body)

    @classmethod
    def decode(cls, data):
        if len(data) < BLOOM_FILTER_F * 2:
            raise DecodeError("Bloom: truncated flag header")
        flags0 = data[:BLOOM_FILTER_F]
        flags1 = data[BLOOM_FILTER_F : BLOOM_FILTER_F * 2]
        body = data[BLOOM_FILTER_F * 2 :]
        body_offset = 0
        slots = []
        all_ones = (1 << 64) - 1
        for idx in range(BLOOM_FILTER_U):
            byte_idx = idx // 8
            bit = 0x80 >> (idx % 8)
            f0 = flags0[byte_idx] & bit
            f1 = flags1[byte_idx] & bit
            if f0 and f1:
                raise DecodeError("Bloom: conflicting flag bits")
            if f0:
                slots.append(0)
            elif f1:
                slots.append(all_ones)
            else:
                if body_offset + 8 > len(body):
                    raise DecodeError("Bloom: truncated body")
                slots.append(struct.unpack(
                    ">Q", body[body_offset : body_offset + 8]
                )[0])
                body_offset += 8
        if body_offset != len(body):
            raise DecodeError("Bloom: trailing body bytes")
        return cls(slots=slots)


class PathLookup(object):
    """Multicast path-discovery request: source, dest, return path."""

    def __init__(self, source=b"\x00" * PUBLIC_KEY_SIZE,
                 dest=b"\x00" * PUBLIC_KEY_SIZE,
                 from_path=None):
        check_keylike(source, "source")
        check_keylike(dest, "dest")
        self.source = bytes(source)
        self.dest = bytes(dest)
        self.from_path = list(from_path or [])

    def size(self):
        # encode_path's exact length: sum(varint_size(p)) + 1 (terminator).
        return (PUBLIC_KEY_SIZE * 2 + len(encode_path(self.from_path)))

    def encode(self):
        return self.source + self.dest + encode_path(self.from_path)

    @classmethod
    def decode(cls, data):
        cursor = WireCursor(data)
        source = cursor.chop_slice(PUBLIC_KEY_SIZE)
        dest = cursor.chop_slice(PUBLIC_KEY_SIZE)
        from_path = cursor.chop_path()
        if cursor.remaining() != 0:
            raise DecodeError("PathLookup: trailing bytes")
        return cls(source=source, dest=dest, from_path=from_path)


class PathNotifyInfo(object):
    """Inner block of PathNotify: seq + path + signature over (seq, path).

    The signature uses ed25519 on bytes ``encode_uvarint(seq) ||
    encode_path(path)``.  The notifying node's key verifies the
    signature on receive.
    """

    def __init__(self, seq=0, path=None, sig=b"\x00" * SIGNATURE_SIZE):
        check_keylike(sig, "sig", size=SIGNATURE_SIZE)
        self.seq = int(seq)
        self.path = list(path or [])
        self.sig = bytes(sig)

    def size(self):
        return (varint_size(self.seq)
                + len(encode_path(self.path))
                + SIGNATURE_SIZE)

    def bytes_for_sig(self):
        return encode_uvarint(self.seq) + encode_path(self.path)

    def encode(self):
        return self.bytes_for_sig() + self.sig

    @classmethod
    def decode(cls, data):
        cursor = WireCursor(data)
        seq = cursor.chop_uvarint()
        path = cursor.chop_path()
        sig = cursor.chop_slice(SIGNATURE_SIZE)
        if cursor.remaining() != 0:
            raise DecodeError("PathNotifyInfo: trailing bytes")
        return cls(seq=seq, path=path, sig=sig)


class PathNotify(object):
    """Reply to PathLookup: path back to dest + watermark + signed PathNotifyInfo."""

    def __init__(self, path=None, watermark=0,
                 source=b"\x00" * PUBLIC_KEY_SIZE,
                 dest=b"\x00" * PUBLIC_KEY_SIZE,
                 info=None):
        check_keylike(source, "source")
        check_keylike(dest, "dest")
        self.path = list(path or [])
        self.watermark = int(watermark)
        self.source = bytes(source)
        self.dest = bytes(dest)
        self.info = info if info is not None else PathNotifyInfo()

    def size(self):
        return (len(encode_path(self.path))
                + varint_size(self.watermark)
                + PUBLIC_KEY_SIZE * 2
                + self.info.size())

    def encode(self):
        return (encode_path(self.path)
                + encode_uvarint(self.watermark)
                + self.source + self.dest
                + self.info.encode())

    @classmethod
    def decode(cls, data):
        cursor = WireCursor(data)
        path = cursor.chop_path()
        watermark = cursor.chop_uvarint()
        source = cursor.chop_slice(PUBLIC_KEY_SIZE)
        dest = cursor.chop_slice(PUBLIC_KEY_SIZE)
        info = PathNotifyInfo.decode(bytes(cursor.data[cursor.offset:]))
        return cls(path=path, watermark=watermark, source=source,
                   dest=dest, info=info)


class PathBroken(object):
    """Notification that a previously-known path no longer works."""

    def __init__(self, path=None, watermark=0,
                 source=b"\x00" * PUBLIC_KEY_SIZE,
                 dest=b"\x00" * PUBLIC_KEY_SIZE):
        check_keylike(source, "source")
        check_keylike(dest, "dest")
        self.path = list(path or [])
        self.watermark = int(watermark)
        self.source = bytes(source)
        self.dest = bytes(dest)

    def size(self):
        return (len(encode_path(self.path))
                + varint_size(self.watermark)
                + PUBLIC_KEY_SIZE * 2)

    def encode(self):
        return (encode_path(self.path)
                + encode_uvarint(self.watermark)
                + self.source + self.dest)

    @classmethod
    def decode(cls, data):
        cursor = WireCursor(data)
        path = cursor.chop_path()
        watermark = cursor.chop_uvarint()
        source = cursor.chop_slice(PUBLIC_KEY_SIZE)
        dest = cursor.chop_slice(PUBLIC_KEY_SIZE)
        if cursor.remaining() != 0:
            raise DecodeError("PathBroken: trailing bytes")
        return cls(path=path, watermark=watermark, source=source,
                   dest=dest)


class Traffic(object):
    """User data packet: src+dest pubkeys, source-routed path + payload.

    Unlike the protocol messages above, ``path`` here is NOT
    zero-terminated -- it's wire-encoded by the framing layer
    (varints with terminator) but stored in-struct as a plain list.
    The payload runs to the end of the wire packet.
    """

    def __init__(self, path=None, from_path=None,
                 source=b"\x00" * PUBLIC_KEY_SIZE,
                 dest=b"\x00" * PUBLIC_KEY_SIZE,
                 watermark=0, payload=b""):
        check_keylike(source, "source")
        check_keylike(dest, "dest")
        self.path = list(path or [])
        self.from_path = list(from_path or [])
        self.source = bytes(source)
        self.dest = bytes(dest)
        self.watermark = int(watermark)
        self.payload = bytes(payload)

    def size(self):
        return (len(encode_path(self.path))
                + len(encode_path(self.from_path))
                + PUBLIC_KEY_SIZE * 2
                + varint_size(self.watermark)
                + len(self.payload))

    def encode(self):
        return (encode_path(self.path)
                + encode_path(self.from_path)
                + self.source + self.dest
                + encode_uvarint(self.watermark)
                + self.payload)

    @classmethod
    def decode(cls, data):
        cursor = WireCursor(data)
        path = cursor.chop_path()
        from_path = cursor.chop_path()
        source = cursor.chop_slice(PUBLIC_KEY_SIZE)
        dest = cursor.chop_slice(PUBLIC_KEY_SIZE)
        watermark = cursor.chop_uvarint()
        # Remaining bytes are the payload, no terminator.
        payload = bytes(cursor.data[cursor.offset:])
        return cls(path=path, from_path=from_path, source=source,
                   dest=dest, watermark=watermark, payload=payload)


# Wire-type → decoder dispatch table.  Routing-layer code that
# receives a packet of unknown type can look up the decoder here.
DECODER_FOR_TYPE = {
    WIRE_PROTO_SIG_REQ: RouterSigReq,
    WIRE_PROTO_SIG_RES: RouterSigRes,
    WIRE_PROTO_ANNOUNCE: RouterAnnounce,
    WIRE_PROTO_BLOOM_FILTER: Bloom,
    WIRE_PROTO_PATH_LOOKUP: PathLookup,
    WIRE_PROTO_PATH_NOTIFY: PathNotify,
    WIRE_PROTO_PATH_BROKEN: PathBroken,
    WIRE_TRAFFIC: Traffic,
}


def decode_routing_packet(packet_type, payload):
    """Decode a routing payload by wire type; return the typed object.

    Raises ``DecodeError`` if the type is unrecognised or the
    payload doesn't conform to the type's wire shape.
    """
    decoder = DECODER_FOR_TYPE.get(packet_type)
    if decoder is None:
        raise DecodeError(fstr(
            "decode_routing_packet: unknown type {0}", (packet_type,),
        ))
    return decoder.decode(payload)
