"""Blake2b correctness tests -- RFC 7693 vectors + keyed-mode sanity."""
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.blake2b import Blake2b, blake2b_hash


# RFC 7693 Appendix A: blake2b('abc') with 64-byte output, no key.
RFC_ABC_DIGEST = bytes.fromhex(
    "ba80a53f981c4d0d6a2797b69f12f6e9"
    "4c212f14685ac4b74b12bb6fdbffa2d1"
    "7d87c5392aab792dc252d5de4533cc95"
    "18d38aa8dbf1925ab92386edd4009923"
)

# Blake2b of empty input with 64-byte digest, from the RFC test suite.
RFC_EMPTY_DIGEST = bytes.fromhex(
    "786a02f742015903c6c6fd852552d272"
    "912f4740e15847618a86e217f71f5419"
    "d25e1031afee585313896444934eb04b"
    "903a685b1448b755d56f701afe9be2ce"
)


class TestBlake2bRFC(AsyncTestCase):
    """Match the canonical RFC 7693 reference vectors."""

    async def test_abc_default_64_bytes(self):
        self.assertEqual(Blake2b(b"abc").digest(), RFC_ABC_DIGEST)

    async def test_empty_default_64_bytes(self):
        self.assertEqual(Blake2b(b"").digest(), RFC_EMPTY_DIGEST)

    async def test_one_shot_helper_matches_class(self):
        self.assertEqual(
            blake2b_hash(b"abc", digest_size=64),
            Blake2b(b"abc", digest_size=64).digest(),
        )

    async def test_digest_idempotent(self):
        h = Blake2b(b"abc")
        d1 = h.digest()
        d2 = h.digest()
        self.assertEqual(d1, d2)

    async def test_streaming_matches_oneshot(self):
        full = Blake2b(b"hello world this is a test of streaming input").digest()
        s = Blake2b()
        s.update(b"hello world ")
        s.update(b"this is a test ")
        s.update(b"of streaming input")
        self.assertEqual(s.digest(), full)

    async def test_streaming_block_boundary(self):
        """Exactly one block (128 bytes) split across many updates."""
        data = bytes(range(256))[:128]
        full = Blake2b(data).digest()
        s = Blake2b()
        for chunk_size in (1, 2, 3, 5, 7, 11, 13, 17, 19, 23):
            local = Blake2b()
            for i in range(0, len(data), chunk_size):
                local.update(data[i : i + chunk_size])
            self.assertEqual(local.digest(), full)

    async def test_multi_block_input(self):
        # > 1 block: 200 bytes of pattern data
        data = b"\xaa" * 200
        full = Blake2b(data).digest()
        s = Blake2b()
        s.update(data[:100])
        s.update(data[100:])
        self.assertEqual(s.digest(), full)


class TestBlake2bSizes(AsyncTestCase):

    async def test_32_byte_digest(self):
        d = Blake2b(b"abc", digest_size=32).digest()
        self.assertEqual(len(d), 32)
        # First 32 bytes must NOT just be a truncation of the
        # 64-byte digest -- Blake2b mixes the digest_size into
        # the parameter block in h[0].  Different size = different
        # output.
        d64 = Blake2b(b"abc", digest_size=64).digest()
        self.assertNotEqual(d, d64[:32])

    async def test_one_byte_digest(self):
        d = Blake2b(b"abc", digest_size=1).digest()
        self.assertEqual(len(d), 1)

    async def test_rejects_zero_digest_size(self):
        with self.assertRaises(ValueError):
            Blake2b(b"abc", digest_size=0)

    async def test_rejects_oversize_digest_size(self):
        with self.assertRaises(ValueError):
            Blake2b(b"abc", digest_size=65)


class TestBlake2bKeyed(AsyncTestCase):

    async def test_keyed_differs_from_unkeyed(self):
        unkeyed = Blake2b(b"hello").digest()
        keyed = Blake2b(b"hello", key=b"secret").digest()
        self.assertNotEqual(unkeyed, keyed)

    async def test_different_keys_produce_different_digests(self):
        a = Blake2b(b"hello", key=b"key1").digest()
        b = Blake2b(b"hello", key=b"key2").digest()
        self.assertNotEqual(a, b)

    async def test_rejects_oversize_key(self):
        with self.assertRaises(ValueError):
            Blake2b(b"hello", key=b"\x00" * 65)


# Reference vectors generated from CPython 3.12 hashlib.blake2b
# (the OpenSSL-backed implementation that matches RFC 7693).  These
# exercise the keyed-mode + multi-block boundaries that aren't in the
# RFC 7693 Appendix A 'abc' vector.  Key form: bytes(range(64))
# (full 64-byte key), per the canonical blake2-kat test suite layout.
KAT_KEY = bytes(range(64))

# (input_length, expected_digest_hex) tuples -- input is bytes(range(n)).
KAT_KEYED_VECTORS = (
    (0, "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786"
        "b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"),
    (1, "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4"
        "187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd"),
    (16, "a0c65bddde8adef57282b04b11e7bc8aab105b99231b750c021f4a735cb1bcfa"
         "b87553bba3abb0c3e64a0b6955285185a0bd35fb8cfde557329bebb1f629ee93"),
    (64, "65676d800617972fbd87e4b9514e1c67402b7a331096d3bfac22f1abb95374ab"
         "c942f16e9ab0ead33b87c91968a6e509e119ff07787b3ef483e1dcdccf6e3022"),
    # 127 = one byte short of two full blocks (one full + 127-byte partial,
    # but with the keyed prefix this is one whole block keyed + 127-byte msg
    # which fits inside the next block).  Boundary stress.
    (127, "76d2d819c92bce55fa8e092ab1bf9b9eab237a25267986cacf2b8ee14d214d73"
          "0dc9a5aa2d7b596e86a1fd8fa0804c77402d2fcd45083688b218b1cdfa0dcbcb"),
    # 128 = exactly one block of msg payload.  Both blocks fully consumed.
    (128, "72065ee4dd91c2d8509fa1fc28a37c7fc9fa7d5b3f8ad3d0d7a25626b57b1b44"
          "788d4caf806290425f9890a3a2a35a905ab4b37acfd0da6e4517b2525c9651e4"),
    # 129 = just over one block; exercises the 'hold last block' path.
    (129, "64475dfe7600d7171bea0b394e27c9b00d8e74dd1e416a79473682ad3dfdbb70"
          "6631558055cfc8a40e07bd015a4540dcdea15883cbbf31412df1de1cd4152b91"),
    (200, "3095a349d245708c7cf550118703d7302c27b60af5d4e67fc978f8a4e60953c7"
          "a04f92fcf41aee64321ccb707a895851552b1e37b00bc5e6b72fa5bcef9e3fff"),
    (255, "142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e9248"
          "4be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461"),
)


class TestBlake2bKeyedReferenceVectors(AsyncTestCase):
    """Byte-parity keyed-mode vectors against CPython 3.12 hashlib.blake2b.

    Yggdrasil's handshake uses keyed Blake2b on every peer link, so
    breakage in this path silently corrupts handshake auth.  These
    vectors lock the keyed-mode bytes against an external trusted
    implementation across a representative set of message lengths.
    """

    async def test_keyed_vectors_match_reference(self):
        for length, expected_hex in KAT_KEYED_VECTORS:
            data = bytes(range(length))
            digest = Blake2b(data, key=KAT_KEY).digest()
            self.assertEqual(
                digest.hex(), expected_hex,
                "length={0}: digest mismatch".format(length),
            )

    async def test_keyed_vectors_streaming_matches_oneshot(self):
        """Same vectors but with the input chunked across update() calls."""
        for length, expected_hex in KAT_KEYED_VECTORS:
            data = bytes(range(length))
            # Stream in 17-byte chunks (prime, doesn't align with block size).
            h = Blake2b(key=KAT_KEY)
            for i in range(0, len(data), 17):
                h.update(data[i:i + 17])
            self.assertEqual(
                h.digest().hex(), expected_hex,
                "length={0}: streamed digest mismatch".format(length),
            )

    async def test_short_key_matches_reference(self):
        """16-byte key (not max-length 64) must still byte-match the reference."""
        # Generated via CPython 3.12: hashlib.blake2b(b"abc", key=bytes(range(16))).hexdigest()
        import hashlib
        if not hasattr(hashlib, "blake2b"):
            self.skipTest("hashlib.blake2b not in stdlib (Python 3.5)")
        ref = hashlib.blake2b(b"abc", key=bytes(range(16))).hexdigest()
        ours = Blake2b(b"abc", key=bytes(range(16))).digest().hex()
        self.assertEqual(ours, ref)


class TestBlake2bDigestSizesByteParity(AsyncTestCase):
    """Output-size variants must match the reference for the same input."""

    async def test_digest_size_variants_match_reference(self):
        import hashlib
        if not hasattr(hashlib, "blake2b"):
            self.skipTest("hashlib.blake2b not in stdlib (Python 3.5)")
        # Each size produces a different digest (size is mixed into h[0]).
        for size in (1, 16, 32, 48, 63, 64):
            ref = hashlib.blake2b(b"abc", digest_size=size).hexdigest()
            ours = Blake2b(b"abc", digest_size=size).digest().hex()
            self.assertEqual(
                ours, ref,
                "digest_size={0} mismatch".format(size),
            )

    async def test_digest_size_keyed_variants_match_reference(self):
        """Keyed mode with varying digest_size."""
        import hashlib
        if not hasattr(hashlib, "blake2b"):
            self.skipTest("hashlib.blake2b not in stdlib (Python 3.5)")
        for size in (16, 32, 64):
            ref = hashlib.blake2b(
                b"abc", key=b"secretkey", digest_size=size,
            ).hexdigest()
            ours = Blake2b(
                b"abc", key=b"secretkey", digest_size=size,
            ).digest().hex()
            self.assertEqual(
                ours, ref,
                "keyed digest_size={0} mismatch".format(size),
            )


class TestBlake2bLargeInputs(AsyncTestCase):
    """Multi-block / large-input paths.

    Blake2b processes 128-byte blocks; we want coverage at the
    1KB / 10KB / 100KB scales to make sure the t (byte counter) +
    block-loop path stays correct over many iterations.
    """

    async def test_1kb_input_matches_reference(self):
        import hashlib
        if not hasattr(hashlib, "blake2b"):
            self.skipTest("hashlib.blake2b not in stdlib (Python 3.5)")
        data = bytes([(i * 7 + 3) % 256 for i in range(1024)])
        ref = hashlib.blake2b(data).hexdigest()
        ours = Blake2b(data).digest().hex()
        self.assertEqual(ours, ref)

    async def test_10kb_input_matches_reference(self):
        import hashlib
        if not hasattr(hashlib, "blake2b"):
            self.skipTest("hashlib.blake2b not in stdlib (Python 3.5)")
        data = bytes([(i * 13) % 256 for i in range(10240)])
        ref = hashlib.blake2b(data).hexdigest()
        ours = Blake2b(data).digest().hex()
        self.assertEqual(ours, ref)

    async def test_keyed_large_input_matches_reference(self):
        import hashlib
        if not hasattr(hashlib, "blake2b"):
            self.skipTest("hashlib.blake2b not in stdlib (Python 3.5)")
        data = b"\xa5" * 5000
        key = b"a-test-key"
        ref = hashlib.blake2b(data, key=key).hexdigest()
        ours = Blake2b(data, key=key).digest().hex()
        self.assertEqual(ours, ref)

    async def test_streaming_large_input_matches_oneshot(self):
        # Self-consistency: even without an external reference, the
        # one-shot path and the chunked path must agree.
        data = bytes([(i * 17) % 256 for i in range(2048)])
        full = Blake2b(data).digest()
        h = Blake2b()
        for i in range(0, len(data), 33):
            h.update(data[i:i + 33])
        self.assertEqual(h.digest(), full)


if __name__ == "__main__":
    unittest.main()
