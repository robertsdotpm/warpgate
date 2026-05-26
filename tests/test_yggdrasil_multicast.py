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


class FakeNodeCore(object):
    """Minimal NodeCore stand-in for multicast tests."""

    def __init__(self, public_key=None, listen_port=12345):
        self.public_key = public_key if public_key is not None else b"\x77" * 32
        self.listen_port = listen_port


class TestMulticastHashFormulaMatchesGo(AsyncTestCase):
    """The blake2b hash carried in the beacon must match upstream.

    Upstream multicast.go:214-230 + :430-441 compute the hash as
    ``blake2b-512-keyed(password)(pubkey)`` -- the password is the
    KEY of the blake2b construction, and the data hashed is the
    sender's public key.  Python originally hashed JUST the
    password, which made the wire form silently incompatible with
    every real Yggdrasil peer: hashes never matched, beacons were
    silently rejected, peers never dialled each other.
    """

    async def test_hash_matches_upstream_formula(self):
        from warpgate.overlay.yggdrasil.blake2b import blake2b_hash
        from warpgate.overlay.yggdrasil.multicast import MulticastDiscovery
        pubkey = b"\x42" * 32
        password = b"my-shared-password"
        core = FakeNodeCore(public_key=pubkey)
        disc = MulticastDiscovery(core, password=password)
        expected = blake2b_hash(pubkey, key=password, digest_size=64)
        self.assertEqual(
            disc.hash_bytes, expected,
            "beacon hash must be blake2b-keyed(password)(pubkey),"
            " matching upstream multicast.go:214-230",
        )

    async def test_hash_changes_with_pubkey(self):
        """Different nodes (different pubkeys) must produce different hashes
        even with the same password -- proves the pubkey is in the hash input."""
        from warpgate.overlay.yggdrasil.multicast import MulticastDiscovery
        password = b"same-password"
        disc_a = MulticastDiscovery(
            FakeNodeCore(public_key=b"\x01" * 32), password=password,
        )
        disc_b = MulticastDiscovery(
            FakeNodeCore(public_key=b"\x02" * 32), password=password,
        )
        self.assertNotEqual(
            disc_a.hash_bytes, disc_b.hash_bytes,
            "two nodes with different pubkeys must produce different"
            " beacon hashes even with the same password",
        )


class TestMulticastBeaconAcceptance(AsyncTestCase):
    """Verify beacon-handling logic against the upstream protocol rules."""

    async def test_inbound_beacon_with_matching_hash_is_accepted(self):
        """A beacon whose hash matches blake2b-keyed(password)(adv.pubkey)
        must pass the hash check."""
        from warpgate.overlay.yggdrasil.blake2b import blake2b_hash
        from warpgate.overlay.yggdrasil.multicast import (
            MulticastAdvertisement, MulticastDiscovery,
        )
        from warpgate.overlay.yggdrasil.version import (
            PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
        )
        password = b"shared"
        our_pub = b"\x01" * 32
        peer_pub = b"\x02" * 32
        disc = MulticastDiscovery(
            FakeNodeCore(public_key=our_pub), password=password,
        )
        peer_hash = blake2b_hash(peer_pub, key=password, digest_size=64)
        adv = MulticastAdvertisement(
            major_ver=PROTOCOL_VERSION_MAJOR,
            minor_ver=PROTOCOL_VERSION_MINOR,
            public_key=peer_pub, port=1515,
            hash_bytes=peer_hash,
        )
        # Sub for last_seen to make handle_beacon idempotent.
        disc.last_seen = {}
        # handle_beacon doesn't dial (we don't have the source IP),
        # but it should record the last_seen entry on success.
        await disc.handle_beacon(adv)
        self.assertIn(peer_pub, disc.last_seen,
                      "matching beacon should populate last_seen")

    async def test_inbound_beacon_with_mismatched_password_rejected(self):
        """Beacon hash computed under a different password must NOT be accepted."""
        from warpgate.overlay.yggdrasil.blake2b import blake2b_hash
        from warpgate.overlay.yggdrasil.multicast import (
            MulticastAdvertisement, MulticastDiscovery,
        )
        from warpgate.overlay.yggdrasil.version import (
            PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
        )
        peer_pub = b"\x02" * 32
        disc = MulticastDiscovery(
            FakeNodeCore(public_key=b"\x01" * 32), password=b"alice",
        )
        # Peer hashed with a different password.
        bad_hash = blake2b_hash(peer_pub, key=b"bob", digest_size=64)
        adv = MulticastAdvertisement(
            major_ver=PROTOCOL_VERSION_MAJOR,
            minor_ver=PROTOCOL_VERSION_MINOR,
            public_key=peer_pub, port=1515,
            hash_bytes=bad_hash,
        )
        disc.last_seen = {}
        await disc.handle_beacon(adv)
        self.assertNotIn(
            peer_pub, disc.last_seen,
            "mismatched password should reject the beacon",
        )

    async def test_inbound_own_beacon_skipped(self):
        """Loopback of our own beacon must be ignored."""
        from warpgate.overlay.yggdrasil.blake2b import blake2b_hash
        from warpgate.overlay.yggdrasil.multicast import (
            MulticastAdvertisement, MulticastDiscovery,
        )
        from warpgate.overlay.yggdrasil.version import (
            PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
        )
        our_pub = b"\x77" * 32
        disc = MulticastDiscovery(
            FakeNodeCore(public_key=our_pub), password=b"",
        )
        our_hash = blake2b_hash(our_pub, key=b"", digest_size=64)
        adv = MulticastAdvertisement(
            major_ver=PROTOCOL_VERSION_MAJOR,
            minor_ver=PROTOCOL_VERSION_MINOR,
            public_key=our_pub, port=1515,
            hash_bytes=our_hash,
        )
        disc.last_seen = {}
        await disc.handle_beacon(adv)
        self.assertNotIn(our_pub, disc.last_seen,
                         "own beacon must be ignored even with matching hash")

    async def test_inbound_beacon_wrong_version_rejected(self):
        """Major/minor mismatch must skip the beacon."""
        from warpgate.overlay.yggdrasil.blake2b import blake2b_hash
        from warpgate.overlay.yggdrasil.multicast import (
            MulticastAdvertisement, MulticastDiscovery,
        )
        from warpgate.overlay.yggdrasil.version import (
            PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
        )
        peer_pub = b"\x02" * 32
        disc = MulticastDiscovery(
            FakeNodeCore(public_key=b"\x01" * 32), password=b"",
        )
        peer_hash = blake2b_hash(peer_pub, key=b"", digest_size=64)
        adv = MulticastAdvertisement(
            major_ver=PROTOCOL_VERSION_MAJOR + 1,  # bumped major
            minor_ver=PROTOCOL_VERSION_MINOR,
            public_key=peer_pub, port=1515,
            hash_bytes=peer_hash,
        )
        disc.last_seen = {}
        await disc.handle_beacon(adv)
        self.assertNotIn(peer_pub, disc.last_seen)


if __name__ == "__main__":
    unittest.main()
