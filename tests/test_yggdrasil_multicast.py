"""Multicast advertisement codec tests + basic Pipe loopback."""
import os
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.multicast import (
    MULTICAST_GROUP,
    MULTICAST_PORT,
    MulticastAdvertisement,
)
from warpgate.overlay.yggdrasil.version import (
    PROTOCOL_VERSION_MAJOR,
    PROTOCOL_VERSION_MINOR,
)


class TestMulticastAdvertisementCodec(AsyncTestCase):

    async def test_roundtrip(self):
        adv = MulticastAdvertisement(
            major_ver=PROTOCOL_VERSION_MAJOR,
            minor_ver=PROTOCOL_VERSION_MINOR,
            public_key=b"\xab" * 32,
            port=9001,
            hash_bytes=b"\xcd" * 16,
        )
        wire = adv.encode()
        decoded = MulticastAdvertisement.decode(wire)
        self.assertEqual(decoded.major_ver, PROTOCOL_VERSION_MAJOR)
        self.assertEqual(decoded.minor_ver, PROTOCOL_VERSION_MINOR)
        self.assertEqual(decoded.public_key, b"\xab" * 32)
        self.assertEqual(decoded.port, 9001)
        self.assertEqual(decoded.hash_bytes, b"\xcd" * 16)

    async def test_wire_layout_matches_go(self):
        """Go produces: major(2 BE) | minor(2 BE) | pubkey(32) | port(2 BE)
                       | hash_len(2 BE) | hash_bytes
        """
        adv = MulticastAdvertisement(
            major_ver=0, minor_ver=5,
            public_key=b"\x11" * 32, port=0x1234,
            hash_bytes=b"\xaa\xbb",
        )
        wire = adv.encode()
        # major BE
        self.assertEqual(wire[0:2], b"\x00\x00")
        # minor BE
        self.assertEqual(wire[2:4], b"\x00\x05")
        # pubkey
        self.assertEqual(wire[4:36], b"\x11" * 32)
        # port BE
        self.assertEqual(wire[36:38], b"\x12\x34")
        # hash_len BE
        self.assertEqual(wire[38:40], b"\x00\x02")
        # hash
        self.assertEqual(wire[40:42], b"\xaa\xbb")

    async def test_decode_rejects_truncated(self):
        with self.assertRaises(ValueError):
            MulticastAdvertisement.decode(b"\x00" * 10)

    async def test_decode_rejects_truncated_hash_body(self):
        # Advertise hash_len=100 but only 5 bytes of hash present.
        wire = (b"\x00\x05"             # major
                + b"\x00\x00"           # minor
                + b"\x00" * 32          # pubkey
                + b"\x00\x00"           # port
                + b"\x00\x64"           # hash_len = 100
                + b"\x01" * 5)
        with self.assertRaises(ValueError):
            MulticastAdvertisement.decode(wire)

    async def test_constants_match_upstream(self):
        self.assertEqual(MULTICAST_GROUP, "ff02::114")
        self.assertEqual(MULTICAST_PORT, 9001)


if __name__ == "__main__":
    unittest.main()
