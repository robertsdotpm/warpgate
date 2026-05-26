"""Yggdrasil version-metadata handshake codec -- byte-compat with upstream.

Port of ``src/core/version.go`` from yggdrasil-go.  The
``version_metadata`` struct is the very first message exchanged when
a TCP/TLS link is established between two Yggdrasil peers; both
sides send theirs concurrently and must agree on the major/minor
protocol version before any other traffic is processed.

Wire format (all integers big-endian):

  4 bytes:  literal ``b"meta"`` preamble
  2 bytes:  body_length (uint16) -- excludes this 6-byte header,
            includes the TLV body AND the trailing signature
  TLV body (in canonical order):
    op=0 (VersionMajor), oplen=2, value: uint16 major
    op=1 (VersionMinor), oplen=2, value: uint16 minor
    op=2 (PublicKey),    oplen=32, value: ed25519 public key
    op=3 (Priority),     oplen=1,  value: byte (link priority, 0-255)
  Signature (64 bytes): ed25519 signature, over
            blake2b-512-keyed(password)(public_key)

The decoder accepts the TLVs in any order (matches upstream).  Empty
``password`` is the unauthenticated path; both peers must use the
same password or signature verification fails.

ed25519 sign/verify come from the ``ecdsa`` package (already a
warpgate dep, native-binary-free, Python 3.5+ compatible).  Blake2b
comes from our pure-Python implementation in ``blake2b.py`` so the
3.5 floor doesn't need ``hashlib.blake2b`` (added in 3.6) or any
C-backed wheel.
"""
import struct

from aionetiface import fstr
from ecdsa import SigningKey, VerifyingKey, Ed25519
from ecdsa.keys import BadSignatureError

from .blake2b import blake2b_hash


# Current protocol version constants -- update only when upstream does.
PROTOCOL_VERSION_MAJOR = 0
PROTOCOL_VERSION_MINOR = 5

# TLV operation IDs -- order matches upstream's iota in version.go.
META_VERSION_MAJOR = 0
META_VERSION_MINOR = 1
META_PUBLIC_KEY = 2
META_PRIORITY = 3

# Fixed sizes from upstream.
PREAMBLE = b"meta"
PREAMBLE_LEN = 4
LENGTH_FIELD_LEN = 2
HEADER_LEN = PREAMBLE_LEN + LENGTH_FIELD_LEN  # 6
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64


class HandshakeError(Exception):
    """Raised when the decode-side rejects a handshake message.

    Mirrors upstream's ``handshakeError`` typed-string family --
    each instance carries the same short reason string upstream
    uses (``invalid handshake, remote side is not Yggdrasil`` etc.)
    so log lines and downstream code can match against them.
    """


ERR_INVALID_PREAMBLE = "invalid handshake, remote side is not Yggdrasil"
ERR_INVALID_LENGTH = "invalid handshake length, possible version mismatch"
ERR_INVALID_PASSWORD = "invalid password supplied, check your config"
ERR_HASH_FAILURE = "invalid hash length"
ERR_INCORRECT_PASSWORD = "password does not match remote side"


class VersionMetadata(object):
    """A single ``version_metadata`` value -- in-memory form of the handshake."""

    def __init__(self, major_ver=PROTOCOL_VERSION_MAJOR,
                 minor_ver=PROTOCOL_VERSION_MINOR,
                 public_key=b"",
                 priority=0):
        self.major_ver = int(major_ver)
        self.minor_ver = int(minor_ver)
        self.public_key = bytes(public_key)
        self.priority = int(priority) & 0xFF

    def check(self):
        """Return True if this struct matches the local node's expected protocol.

        Upstream's ``(*version_metadata).check()``: rejects wrong
        major, wrong minor, or wrong-sized public key.
        """
        if self.major_ver != PROTOCOL_VERSION_MAJOR:
            return False
        if self.minor_ver != PROTOCOL_VERSION_MINOR:
            return False
        if len(self.public_key) != ED25519_PUBLIC_KEY_SIZE:
            return False
        return True

    def encode(self, private_key_seed, password=b""):
        """Serialise to wire bytes, signing with ``private_key_seed``.

        ``private_key_seed`` is the 32-byte ed25519 seed (NOT the
        64-byte Go-style "expanded" private key).  ``password`` is
        the optional shared link password; pass ``b""`` for the
        unauthenticated case (most peerings).
        """
        if not isinstance(private_key_seed, (bytes, bytearray)):
            raise ValueError("encode: private_key_seed must be bytes")
        if len(private_key_seed) != ED25519_PUBLIC_KEY_SIZE:
            raise ValueError(fstr(
                "encode: private_key_seed length {0}, expected {1}",
                (len(private_key_seed), ED25519_PUBLIC_KEY_SIZE),
            ))
        if not isinstance(password, (bytes, bytearray)):
            raise ValueError("encode: password must be bytes")
        if len(self.public_key) != ED25519_PUBLIC_KEY_SIZE:
            raise ValueError(fstr(
                "encode: public_key length {0}, expected {1}",
                (len(self.public_key), ED25519_PUBLIC_KEY_SIZE),
            ))

        # Build the TLV body in the canonical encoder order (note
        # the encoder ALWAYS emits in this order even though the
        # decoder accepts any order).
        body = bytearray()
        body.extend(self.encode_tlv_uint16(META_VERSION_MAJOR, self.major_ver))
        body.extend(self.encode_tlv_uint16(META_VERSION_MINOR, self.minor_ver))
        body.extend(self.encode_tlv_bytes(META_PUBLIC_KEY, self.public_key))
        body.extend(self.encode_tlv_byte(META_PRIORITY, self.priority))

        # Sign blake2b-512-keyed(password)(public_key).  This is the
        # piece that proves the encoder owns the private key, AND
        # (via the keyed hash) proves it knows the shared password.
        hash_payload = blake2b_hash(self.public_key, key=bytes(password),
                                    digest_size=64)
        sk = SigningKey.from_string(bytes(private_key_seed), curve=Ed25519)
        signature = sk.sign(hash_payload)
        if len(signature) != ED25519_SIGNATURE_SIZE:
            raise HandshakeError(ERR_HASH_FAILURE)
        body.extend(signature)

        # Header: preamble + body length.  Body length excludes the
        # 6 header bytes themselves (upstream subtracts 6 here).
        out = bytearray()
        out.extend(PREAMBLE)
        out.extend(struct.pack(">H", len(body)))
        out.extend(body)
        return bytes(out)

    @staticmethod
    def encode_tlv_uint16(op_id, value):
        """Build a TLV with a uint16 BE value."""
        return struct.pack(">HHH", op_id, 2, value & 0xFFFF)

    @staticmethod
    def encode_tlv_byte(op_id, value):
        """Build a TLV with a single byte value."""
        return struct.pack(">HHB", op_id, 1, value & 0xFF)

    @staticmethod
    def encode_tlv_bytes(op_id, value):
        """Build a TLV with arbitrary-length bytes."""
        if len(value) > 0xFFFF:
            raise ValueError("encode_tlv_bytes: value too long")
        return struct.pack(">HH", op_id, len(value)) + bytes(value)

    @classmethod
    def decode(cls, buf, password=b""):
        """Decode wire bytes into a ``VersionMetadata`` and verify the signature.

        ``buf`` is the full wire bytes -- preamble through signature
        inclusive.  Returns a new VersionMetadata on success; raises
        ``HandshakeError`` on any failure with the same reason
        strings upstream uses (so log diffs against the Go peer are
        easy to read).
        """
        if not isinstance(buf, (bytes, bytearray)):
            raise ValueError("decode: buf must be bytes")
        if len(buf) < HEADER_LEN:
            raise HandshakeError(ERR_INVALID_LENGTH)
        if buf[:PREAMBLE_LEN] != PREAMBLE:
            raise HandshakeError(ERR_INVALID_PREAMBLE)
        body_len = struct.unpack(">H", buf[PREAMBLE_LEN:HEADER_LEN])[0]
        if body_len < ED25519_SIGNATURE_SIZE:
            raise HandshakeError(ERR_INVALID_LENGTH)
        if len(buf) < HEADER_LEN + body_len:
            raise HandshakeError(ERR_INVALID_LENGTH)
        body = buf[HEADER_LEN : HEADER_LEN + body_len]
        sig = body[-ED25519_SIGNATURE_SIZE:]
        tlv_bytes = body[: -ED25519_SIGNATURE_SIZE]

        meta = cls()
        # Walk TLVs in whatever order they arrive.  Upstream allows
        # arbitrary order and unknown ops are silently skipped --
        # we follow suit so a newer peer can add forward-compatible
        # TLVs without breaking us.
        cursor = 0
        while cursor + 4 <= len(tlv_bytes):
            op_id = struct.unpack(">H", tlv_bytes[cursor : cursor + 2])[0]
            oplen = struct.unpack(">H", tlv_bytes[cursor + 2 : cursor + 4])[0]
            cursor += 4
            if cursor + oplen > len(tlv_bytes):
                raise HandshakeError(ERR_INVALID_LENGTH)
            field = bytes(tlv_bytes[cursor : cursor + oplen])
            cursor += oplen

            if op_id == META_VERSION_MAJOR:
                if oplen != 2:
                    raise HandshakeError(ERR_INVALID_LENGTH)
                meta.major_ver = struct.unpack(">H", field)[0]
            elif op_id == META_VERSION_MINOR:
                if oplen != 2:
                    raise HandshakeError(ERR_INVALID_LENGTH)
                meta.minor_ver = struct.unpack(">H", field)[0]
            elif op_id == META_PUBLIC_KEY:
                if oplen != ED25519_PUBLIC_KEY_SIZE:
                    raise HandshakeError(ERR_INVALID_LENGTH)
                meta.public_key = field
            elif op_id == META_PRIORITY:
                if oplen != 1:
                    raise HandshakeError(ERR_INVALID_LENGTH)
                meta.priority = field[0] if isinstance(field[0], int) \
                    else ord(field[0])
            # else: unknown TLV -- skip silently for forward compat.

        if cursor != len(tlv_bytes):
            raise HandshakeError(ERR_INVALID_LENGTH)

        # Verify the signature over blake2b-512-keyed(password)(public_key).
        # Missing public_key would have made the verification step
        # impossible AND would be a check() failure; raise the same
        # password-mismatch error upstream raises in that case so
        # the on-wire error story matches.
        if len(meta.public_key) != ED25519_PUBLIC_KEY_SIZE:
            raise HandshakeError(ERR_INCORRECT_PASSWORD)
        hash_payload = blake2b_hash(meta.public_key, key=bytes(password),
                                    digest_size=64)
        vk = VerifyingKey.from_string(meta.public_key, curve=Ed25519)
        try:
            vk.verify(sig, hash_payload)
        except BadSignatureError:
            raise HandshakeError(ERR_INCORRECT_PASSWORD)
        return meta
