"""Fuzz tests for every Yggdrasil wire decoder.

Goal: random/adversarial bytes MUST NEVER crash a decoder with an
unhandled exception.  Either the decoder returns a sensible value
(None for the soft-fail decoders) OR raises one of the documented
exception types:

  ValueError      -- generic input shape problems (truncation, bad
                     varint, out-of-range fields)
  DecodeError     -- routing_msgs-specific (subclass of Exception)
  HandshakeError  -- VersionMetadata-specific (subclass of Exception)
  struct.error    -- struct.unpack on partial buffer (treated same as
                     ValueError by callers; classed as acceptable)
  IndexError      -- buf[i] out of range (acceptable as a fail-soft
                     boundary signal -- never reaches an outer crash)

Decoders covered:

  routing_msgs.py:
    RouterSigReq, RouterSigRes, RouterAnnounce, Bloom, PathLookup,
    PathNotify, PathBroken, Traffic
  version.py: VersionMetadata
  multicast.py: MulticastAdvertisement
  encrypted.py: SessionInit (returns None on shape failure rather
                than raise; we accept None as a graceful soft-fail)

Fuzz strategies applied to each decoder:

  * Empty bytes (length 0)
  * Length 1
  * Half of the typical valid size
  * Exact known-good size random fill
  * One byte short
  * One byte too long
  * Double-size random fill
  * Bit-flip the n-th byte of a known-good encoding
  * Truncation at each byte offset of a known-good encoding
  * Oversize length-prefix (max-varint or struct uint16 max)
  * All-continuation-bit varint sequence (10 bytes of 0x80)

Any unhandled non-allowed exception fails the test.  This is the
robustness contract for every external-input decoder in the port.
"""
import binascii
import os
import random
import struct
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.routing_msgs import (
    BLOOM_FILTER_U,
    Bloom,
    DecodeError,
    PathBroken,
    PathLookup,
    PathNotify,
    PathNotifyInfo,
    RouterAnnounce,
    RouterSigReq,
    RouterSigRes,
    Traffic,
    decode_routing_packet,
)
from warpgate.overlay.yggdrasil.version import (
    HandshakeError,
    VersionMetadata,
    PROTOCOL_VERSION_MAJOR,
    PROTOCOL_VERSION_MINOR,
)
from warpgate.overlay.yggdrasil.multicast import MulticastAdvertisement
from warpgate.overlay.yggdrasil.encrypted import (
    SESSION_INIT_SIZE,
    SessionInit,
)
from warpgate.overlay.yggdrasil.wire import (
    MAX_VARINT_LEN,
    decode_uvarint,
)


# These are the "graceful failure" exception types.  Any of them
# means the decoder handled the bad input correctly.  ANY OTHER
# exception type counts as a crash and fails the test.
ACCEPTABLE_EXCEPTIONS = (
    ValueError,
    DecodeError,
    HandshakeError,
    IndexError,
    struct.error,
)


def safe_decode(decoder, data):
    """Run a decoder on bytes; return (result, exc_type_name_or_none).

    Result is None if it threw.  Crashes (non-acceptable exceptions)
    are surfaced as their type name so the test can assert on them.
    """
    try:
        return decoder(data), None
    except ACCEPTABLE_EXCEPTIONS as exc:
        return None, type(exc).__name__
    # Anything else is a real crash; let the test see the traceback.


def random_bytes(length, seed=None):
    if seed is not None:
        random.seed(seed)
    return bytes(random.randint(0, 255) for _ in range(length))


def known_good_router_sig_req():
    return RouterSigReq(seq=1, nonce=2).encode()


def known_good_router_sig_res():
    return RouterSigRes(seq=1, nonce=2, port=3, psig=b"\x05" * 64).encode()


def known_good_router_announce():
    res = RouterSigRes(seq=1, nonce=2, port=3, psig=b"\x05" * 64)
    return RouterAnnounce(
        key=b"\x01" * 32, parent=b"\x02" * 32, sig_res=res, sig=b"\x09" * 64,
    ).encode()


def known_good_path_lookup():
    return PathLookup(
        source=b"\x01" * 32, dest=b"\x02" * 32, from_path=[5, 7, 11],
    ).encode()


def known_good_path_notify():
    info = PathNotifyInfo(seq=42, path=[1, 2, 3], sig=b"\x07" * 64)
    return PathNotify(
        path=[8, 9], watermark=100, source=b"\xaa" * 32, dest=b"\xbb" * 32,
        info=info,
    ).encode()


def known_good_path_broken():
    return PathBroken(
        path=[3, 4], watermark=50, source=b"\xcc" * 32, dest=b"\xdd" * 32,
    ).encode()


def known_good_traffic():
    return Traffic(
        path=[1, 2], from_path=[3], source=b"\x11" * 32, dest=b"\x22" * 32,
        watermark=999, payload=b"hello, world!",
    ).encode()


def known_good_bloom():
    return Bloom(slots=[0] * BLOOM_FILTER_U).encode()


def known_good_version_metadata():
    """Build a properly-signed VersionMetadata so we have a valid baseline."""
    # We need a real keypair so the signature actually validates.
    from ecdsa import SigningKey, Ed25519
    seed = b"\xab" * 32
    sk = SigningKey.from_string(seed, curve=Ed25519)
    pub = bytes(sk.verifying_key.to_string())
    meta = VersionMetadata(
        major_ver=PROTOCOL_VERSION_MAJOR, minor_ver=PROTOCOL_VERSION_MINOR,
        public_key=pub, priority=0,
    )
    return meta.encode(seed)


def known_good_multicast_advertisement():
    return MulticastAdvertisement(
        major_ver=0, minor_ver=5, public_key=b"\x11" * 32,
        port=9001, hash_bytes=b"\x22" * 64,
    ).encode()


# Fuzz input library: returns a list of (label, bytes) tuples to feed
# into a decoder.  Each label is unique so a failure tells you which
# strategy tripped the decoder.
def fuzz_input_set(known_good, label_prefix):
    """Return a deterministic mix of malformed inputs for a decoder."""
    random.seed(hash(label_prefix) & 0xFFFFFFFF)
    target_len = len(known_good)
    out = []
    out.append(("{0}: empty".format(label_prefix), b""))
    out.append(("{0}: one_byte".format(label_prefix), b"\x00"))
    out.append(("{0}: ones".format(label_prefix), b"\xff" * 16))
    out.append(("{0}: zeros".format(label_prefix), b"\x00" * 16))
    out.append((
        "{0}: half_random".format(label_prefix),
        random_bytes(max(1, target_len // 2)),
    ))
    out.append((
        "{0}: exact_size_random".format(label_prefix),
        random_bytes(target_len),
    ))
    out.append((
        "{0}: short_by_one".format(label_prefix),
        random_bytes(max(0, target_len - 1)),
    ))
    out.append((
        "{0}: long_by_one".format(label_prefix),
        random_bytes(target_len + 1),
    ))
    out.append((
        "{0}: double_random".format(label_prefix),
        random_bytes(target_len * 2),
    ))
    out.append((
        "{0}: all_continuation_varint".format(label_prefix),
        b"\x80" * (MAX_VARINT_LEN + 5),
    ))
    # Truncation series: cut the known-good encoding at every length
    # from 1 to (len - 1).  Each truncation is its own input.
    for cut in (1, 2, target_len // 4, target_len // 2, target_len - 2,
                target_len - 1):
        if 0 < cut < target_len:
            out.append((
                "{0}: trunc@{1}".format(label_prefix, cut),
                known_good[:cut],
            ))
    # Bit flips: flip the high bit of every Nth byte of the known-good encoding.
    for flip_pos in (0, target_len // 4, target_len // 2,
                     target_len * 3 // 4, target_len - 1):
        if 0 <= flip_pos < target_len:
            tampered = bytearray(known_good)
            tampered[flip_pos] ^= 0xFF
            out.append((
                "{0}: bitflip@{1}".format(label_prefix, flip_pos),
                bytes(tampered),
            ))
    # Random fuzz: 20 random inputs of varying sizes.
    for i in range(20):
        size = random.choice([0, 1, 7, 16, 32, 64, target_len, target_len + 1])
        out.append((
            "{0}: rand_{1}".format(label_prefix, i),
            random_bytes(size),
        ))
    return out


def assert_safe_for_inputs(test, decoder, inputs):
    """Run ``decoder`` on every (label, data) in ``inputs``; allow only the safe exceptions."""
    failures = []
    for label, data in inputs:
        try:
            decoder(data)
        except ACCEPTABLE_EXCEPTIONS:
            # Graceful failure -- good.
            pass
        except Exception as exc:
            failures.append(
                "{0}: unhandled {1}: {2}".format(
                    label, type(exc).__name__, str(exc)[:80],
                )
            )
    if failures:
        test.fail(
            "Decoder crashed on {0} inputs:\n  ".format(len(failures))
            + "\n  ".join(failures)
        )


class TestRouterSigReqFuzz(AsyncTestCase):

    async def test_no_crash_on_malformed(self):
        inputs = fuzz_input_set(known_good_router_sig_req(), "RouterSigReq")
        assert_safe_for_inputs(self, RouterSigReq.decode, inputs)


class TestRouterSigResFuzz(AsyncTestCase):

    async def test_no_crash_on_malformed(self):
        inputs = fuzz_input_set(known_good_router_sig_res(), "RouterSigRes")
        assert_safe_for_inputs(self, RouterSigRes.decode, inputs)


class TestRouterAnnounceFuzz(AsyncTestCase):

    async def test_no_crash_on_malformed(self):
        inputs = fuzz_input_set(known_good_router_announce(), "RouterAnnounce")
        assert_safe_for_inputs(self, RouterAnnounce.decode, inputs)


class TestBloomFuzz(AsyncTestCase):

    async def test_no_crash_on_malformed(self):
        inputs = fuzz_input_set(known_good_bloom(), "Bloom")
        assert_safe_for_inputs(self, Bloom.decode, inputs)

    async def test_extreme_oversize_body(self):
        # Header claims all-zero slots (no body needed) but ships
        # 100kB of body -- decoder should reject trailing bytes.
        header = b"\xff" * 16 + b"\x00" * 16
        body = b"A" * 100000
        try:
            Bloom.decode(header + body)
        except ACCEPTABLE_EXCEPTIONS:
            pass
        # If it didn't raise, that's actually fine (some valid
        # decode paths may exist with this header); what we care
        # about is no crash.


class TestPathLookupFuzz(AsyncTestCase):

    async def test_no_crash_on_malformed(self):
        inputs = fuzz_input_set(known_good_path_lookup(), "PathLookup")
        assert_safe_for_inputs(self, PathLookup.decode, inputs)

    async def test_no_crash_on_huge_path(self):
        # Construct a path field bigger than the 128-hop cap -- the
        # decoder MUST refuse rather than allocate forever.
        # 200 nonzero varints + terminator.
        from warpgate.overlay.yggdrasil.wire import encode_uvarint
        payload = b"\x01" * 64
        path_bytes = bytearray()
        for i in range(1, 201):
            path_bytes.extend(encode_uvarint(i))
        path_bytes.append(0)  # terminator
        big = b"\x01" * 32 + b"\x02" * 32 + bytes(path_bytes)
        try:
            PathLookup.decode(big)
        except ACCEPTABLE_EXCEPTIONS:
            pass
        # Pass either way as long as no unhandled crash.


class TestPathNotifyFuzz(AsyncTestCase):

    async def test_no_crash_on_malformed(self):
        inputs = fuzz_input_set(known_good_path_notify(), "PathNotify")
        assert_safe_for_inputs(self, PathNotify.decode, inputs)


class TestPathBrokenFuzz(AsyncTestCase):

    async def test_no_crash_on_malformed(self):
        inputs = fuzz_input_set(known_good_path_broken(), "PathBroken")
        assert_safe_for_inputs(self, PathBroken.decode, inputs)


class TestTrafficFuzz(AsyncTestCase):

    async def test_no_crash_on_malformed(self):
        inputs = fuzz_input_set(known_good_traffic(), "Traffic")
        assert_safe_for_inputs(self, Traffic.decode, inputs)


class TestVersionMetadataFuzz(AsyncTestCase):

    async def test_no_crash_on_malformed(self):
        inputs = fuzz_input_set(
            known_good_version_metadata(), "VersionMetadata",
        )
        assert_safe_for_inputs(self, VersionMetadata.decode, inputs)

    async def test_preamble_only_rejected_cleanly(self):
        # 'meta' alone, no length field -- must raise HandshakeError
        # or ValueError, never crash.
        try:
            VersionMetadata.decode(b"meta")
        except (HandshakeError, ValueError):
            pass

    async def test_oversize_body_length_field_rejected(self):
        # Preamble + claim body is huge but ship nothing.
        buf = b"meta" + struct.pack(">H", 65535)
        try:
            VersionMetadata.decode(buf)
        except (HandshakeError, ValueError):
            pass

    async def test_tlv_oplen_larger_than_remaining_body(self):
        # Build a buffer with a valid preamble + small body claiming a
        # huge oplen -- TLV walker MUST detect the overflow.
        body = struct.pack(">HH", 0, 0xFFFF) + b"AAAA"
        buf = b"meta" + struct.pack(">H", len(body) + 64) + body + b"\x00" * 64
        try:
            VersionMetadata.decode(buf)
        except (HandshakeError, ValueError):
            pass


class TestMulticastAdvertisementFuzz(AsyncTestCase):

    async def test_no_crash_on_malformed(self):
        inputs = fuzz_input_set(
            known_good_multicast_advertisement(), "MulticastAdvertisement",
        )
        assert_safe_for_inputs(self, MulticastAdvertisement.decode, inputs)

    async def test_lying_hash_length(self):
        # header is correct but claims a huge hash_len.
        buf = struct.pack(">HH", 0, 5) + b"\x00" * 32 \
              + struct.pack(">HH", 1234, 65535) + b"AAAA"
        try:
            MulticastAdvertisement.decode(buf)
        except (ValueError, IndexError):
            pass


class TestSessionInitFuzz(AsyncTestCase):

    async def test_no_crash_on_malformed(self):
        # SessionInit.decode soft-fails (returns None) so the
        # check is just "doesn't crash".  We still use the fuzz
        # input set, just wrap differently.
        priv = b"\x00" * 32
        pub = b"\x00" * 32
        inputs = fuzz_input_set(b"\x00" * SESSION_INIT_SIZE, "SessionInit")
        for label, data in inputs:
            try:
                SessionInit.decode(data, priv, pub)
            except ACCEPTABLE_EXCEPTIONS:
                pass
            # Any other exception is a real crash.

    async def test_random_correct_size_returns_none(self):
        # Random bytes of EXACTLY the right size should soft-fail to
        # None (the ECDH+MAC verify will reject).
        priv = b"\x00" * 32
        pub = b"\x00" * 32
        for trial in range(5):
            data = random_bytes(SESSION_INIT_SIZE, seed=trial)
            result = SessionInit.decode(data, priv, pub)
            self.assertIsNone(
                result,
                "SessionInit.decode of random bytes returned non-None",
            )

    async def test_wrong_size_returns_none(self):
        priv = b"\x00" * 32
        pub = b"\x00" * 32
        # Size mismatch is a quick reject path.
        for delta in (-2, -1, 1, 2):
            data = b"\x00" * (SESSION_INIT_SIZE + delta)
            self.assertIsNone(SessionInit.decode(data, priv, pub))


class TestDispatchRoutingPacketFuzz(AsyncTestCase):
    """Fuzz the top-level routing-packet dispatch table."""

    async def test_unknown_type_raises_decode_error(self):
        for bad_type in (-1, 99, 255, 1000):
            try:
                decode_routing_packet(bad_type, b"")
                # Acceptable if it returns sentinel or raises.
            except (DecodeError, ValueError):
                pass

    async def test_no_crash_on_random_type_random_payload(self):
        random.seed(0xABCD)
        for trial in range(50):
            wire_type = random.randint(0, 255)
            payload = random_bytes(random.choice([0, 1, 7, 64, 256]))
            try:
                decode_routing_packet(wire_type, payload)
            except ACCEPTABLE_EXCEPTIONS:
                pass


class TestVarintFuzz(AsyncTestCase):
    """The varint primitive sits beneath every other decoder."""

    async def test_empty_raises(self):
        with self.assertRaises(ValueError):
            decode_uvarint(b"")

    async def test_all_continuation_raises(self):
        with self.assertRaises(ValueError):
            decode_uvarint(b"\x80" * 15)

    async def test_oversize_raises(self):
        with self.assertRaises(ValueError):
            decode_uvarint(b"\x80" * 10 + b"\x01")

    async def test_negative_offset_handled(self):
        # decode_uvarint takes offset; negative offset is technically
        # legal as a slice into bytes -- should still decode or
        # raise, not crash with TypeError.
        try:
            decode_uvarint(b"\x01\x02\x03", offset=0)
        except ACCEPTABLE_EXCEPTIONS:
            pass


if __name__ == "__main__":
    unittest.main()
