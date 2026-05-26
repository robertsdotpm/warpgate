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


if __name__ == "__main__":
    unittest.main()
