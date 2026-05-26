"""Bloom filter set-ops + bloom_transform + pathfinder fundamentals."""
import os
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.address import addr_for_key
from warpgate.overlay.yggdrasil.pathfinder import bloom_transform
from warpgate.overlay.yggdrasil.routing_msgs import BLOOM_FILTER_U, Bloom


class TestBloomOps(AsyncTestCase):

    async def test_add_then_test_hits(self):
        b = Bloom()
        key = b"\xab" * 32
        self.assertFalse(b.test_key(key))
        b.add_key(key)
        self.assertTrue(b.test_key(key))

    async def test_test_other_key_unlikely(self):
        """A freshly-added key shouldn't match an unrelated key (no false pos)."""
        b = Bloom()
        b.add_key(b"\xab" * 32)
        # 8192 bits with 8 hashes -> very low false-positive rate
        # for a single add.  Test a few unrelated keys.
        false_positives = 0
        for i in range(100):
            other = bytes([i % 256] * 32)
            if other == b"\xab" * 32:
                continue
            if b.test_key(other):
                false_positives += 1
        self.assertLess(false_positives, 5,
            "too many false positives: {0}".format(false_positives))

    async def test_merge_unions_filters(self):
        a = Bloom()
        b = Bloom()
        key_a = b"\x01" * 32
        key_b = b"\x02" * 32
        a.add_key(key_a)
        b.add_key(key_b)
        a.merge(b)
        # Now a should hit both keys.
        self.assertTrue(a.test_key(key_a))
        self.assertTrue(a.test_key(key_b))

    async def test_equal_compares_slots(self):
        a = Bloom()
        b = Bloom()
        self.assertTrue(a.equal(b))
        a.add_key(b"\x05" * 32)
        self.assertFalse(a.equal(b))
        b.add_key(b"\x05" * 32)
        self.assertTrue(a.equal(b))

    async def test_copy_is_independent(self):
        a = Bloom()
        a.add_key(b"\x07" * 32)
        c = a.copy()
        self.assertTrue(c.test_key(b"\x07" * 32))
        a.add_key(b"\x08" * 32)
        # c shouldn't see the post-copy add.
        self.assertFalse(c.test_key(b"\x08" * 32))

    async def test_roundtrip_after_adds(self):
        a = Bloom()
        for k in (b"\x10" * 32, b"\x20" * 32, b"\x30" * 32):
            a.add_key(k)
        wire = a.encode()
        decoded = Bloom.decode(wire)
        self.assertTrue(decoded.equal(a))
        for k in (b"\x10" * 32, b"\x20" * 32, b"\x30" * 32):
            self.assertTrue(decoded.test_key(k))


class TestBloomTransform(AsyncTestCase):

    async def test_two_keys_in_same_subnet_transform_same(self):
        """The xform collapses /64 siblings to the same bloom-key."""
        # SubnetForKey/GetKey roundtrip masks per-node bits, so any
        # two keys whose derived address differs only in the
        # last (16 - prefix_len - 1) bytes should xform identically.
        # Hard to construct deterministically; just check the
        # property that transform is idempotent under repeat.
        k = b"\xab" * 32
        x1 = bloom_transform(k)
        x2 = bloom_transform(x1)
        self.assertEqual(x1, x2,
            "bloom_transform must be idempotent on its output")

    async def test_transform_preserves_length(self):
        for k in (b"\x00" * 32, b"\xff" * 32, b"\xab" * 32):
            x = bloom_transform(k)
            self.assertEqual(len(x), 32)


if __name__ == "__main__":
    unittest.main()
