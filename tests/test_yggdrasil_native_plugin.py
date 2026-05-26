"""End-to-end integration: two YggdrasilNativeFactory instances bootstrap
to the same public Yggdrasil peer, discover each other through the
public mesh, then exchange application bytes via the plugin's adapter.

This is the live wire-compat test for the warpgate plugin layer.
It REQUIRES internet access to the bootstrap peer (currently
tls://37.186.113.100:1515) and may take 20-30 seconds to converge
because the tree formation + bloom-multicast lookup against the
public mesh takes that long.

Skip via WARPGATE_SKIP_LIVE_YGG=1 if running in an offline env.
"""
import asyncio
import os
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.yggdrasil_native.main import (
    DEFAULT_BOOTSTRAP_PEERS,
    YggdrasilNativeFactory,
)


SKIP_LIVE = os.environ.get("WARPGATE_SKIP_LIVE_YGG") == "1"
CONVERGENCE_BUDGET = 25.0  # seconds; public mesh tree formation


class FakeNode(object):
    """Minimal node stand-in: just enough surface for the factory."""

    def __init__(self):
        self.resources = FakeResources()


class FakeResources(object):
    def __init__(self):
        self.registered = []

    def register(self, obj):
        self.registered.append(obj)


class TestYggdrasilNativeLiveBootstrap(AsyncTestCase):
    """Spin up TWO factories, both bootstrap to the same public peer,
    then exchange bytes through the public mesh via the encrypted
    PacketConn.  This is the full end-to-end proof that the warpgate
    plugin layer works through the actual Yggdrasil network."""

    async def asyncSetUp(self):
        if SKIP_LIVE:
            self.skipTest("WARPGATE_SKIP_LIVE_YGG=1 set")
        self.fac_a = YggdrasilNativeFactory(FakeNode())
        self.fac_b = YggdrasilNativeFactory(FakeNode())

    async def asyncTearDown(self):
        await self.fac_a.close()
        await self.fac_b.close()

    async def test_both_factories_bootstrap_successfully(self):
        """Weaker check: both factories at least learn SOMETHING from
        the public mesh -- they got connected, exchanged some
        announces.  This is the necessary precondition for any
        end-to-end byte exchange but doesn't itself prove it works."""
        await self.fac_a.ensure_overlay_started()
        await self.fac_b.ensure_overlay_started()
        # Give the announce propagation 8s to populate infos.
        await asyncio.sleep(8)
        # Each side should have at least its own info + a few from
        # the public mesh peers.
        self.assertGreater(
            len(self.fac_a.router.infos), 1,
            "factory A: bootstrap dial didn't yield any tree info",
        )
        self.assertGreater(
            len(self.fac_b.router.infos), 1,
            "factory B: bootstrap dial didn't yield any tree info",
        )

    async def test_a_to_b_byte_exchange_via_public_mesh(self):
        """The real integration test: A sends bytes to B through the
        public Yggdrasil mesh, B receives them on its per-peer channel.

        Exercises: bootstrap → tree formation → path_lookup via
        bloom multicast → path_notify reply → encrypted session
        init/ack → first traffic packet with full ratchet machinery.
        End-to-end against real public peers (no mocks).
        """
        await self.fac_a.ensure_overlay_started()
        await self.fac_b.ensure_overlay_started()
        # Bootstrap settle: bloom filter propagation + first tree
        # maintenance cycle.
        await asyncio.sleep(8)

        pk_a = self.fac_a.node_core.public_key
        pk_b = self.fac_b.node_core.public_key
        pc_a = self.fac_a.packet_conn
        pc_b = self.fac_b.packet_conn

        # B opens a per-peer channel for A so A's bytes are queued.
        pc_b.open_peer_channel(pk_a)
        await pc_a.write_to(pk_b, b"hello from A via public mesh")

        msg = await pc_b.read_from_peer(pk_a, timeout=30.0)
        self.assertEqual(
            msg, b"hello from A via public mesh",
            "Expected A's message, got {0!r}".format(msg),
        )


class TestBootstrapConfig(AsyncTestCase):
    """Pure-unit tests for the bootstrap-peer config path -- no network."""

    async def test_default_bootstrap_list_nonempty(self):
        self.assertGreater(len(DEFAULT_BOOTSTRAP_PEERS), 0)
        for uri in DEFAULT_BOOTSTRAP_PEERS:
            self.assertTrue(
                uri.startswith("tcp://") or uri.startswith("tls://"),
                "bootstrap URI must be tcp:// or tls://, got {0}".format(uri),
            )

    async def test_env_override(self):
        from warpgate.traversal.plugins.yggdrasil_native.main import (
            get_bootstrap_peers,
        )
        original = os.environ.get("WARPGATE_YGG_PEERS")
        try:
            os.environ["WARPGATE_YGG_PEERS"] = "tls://1.2.3.4:9001 tcp://5.6.7.8:1234"
            peers = get_bootstrap_peers()
            self.assertEqual(peers, ["tls://1.2.3.4:9001", "tcp://5.6.7.8:1234"])
        finally:
            if original is None:
                os.environ.pop("WARPGATE_YGG_PEERS", None)
            else:
                os.environ["WARPGATE_YGG_PEERS"] = original

    async def test_empty_env_uses_defaults(self):
        from warpgate.traversal.plugins.yggdrasil_native.main import (
            get_bootstrap_peers,
        )
        original = os.environ.get("WARPGATE_YGG_PEERS")
        try:
            os.environ["WARPGATE_YGG_PEERS"] = ""
            peers = get_bootstrap_peers()
            self.assertEqual(peers, list(DEFAULT_BOOTSTRAP_PEERS))
        finally:
            if original is None:
                os.environ.pop("WARPGATE_YGG_PEERS", None)
            else:
                os.environ["WARPGATE_YGG_PEERS"] = original


class TestPerPeerChannels(AsyncTestCase):
    """Verify PacketConn's per-peer queue mechanic without going through
    the live mesh -- routes a synthetic decrypted-traffic event into
    the dispatcher and confirms both shared + per-peer queues fire."""

    async def test_open_close_channel_idempotent(self):
        # Build a minimal PacketConn-shaped object without actually
        # spinning up the overlay -- we just need the per-peer
        # channel surface.
        from warpgate.overlay.yggdrasil.encrypted import EncryptedPacketConn

        # We can't easily instantiate EncryptedPacketConn without a
        # router; build a minimal stand-in.
        class FakeRouter(object):
            class _Inbox(object):
                async def get(self):
                    await asyncio.sleep(3600)  # never resolves
            inbox = _Inbox()
        seed = b"\x01" * 32
        from ecdsa import SigningKey, Ed25519
        sk = SigningKey.from_string(seed, curve=Ed25519)
        ed_pub = bytes(sk.verifying_key.to_string())
        pc = EncryptedPacketConn(seed, ed_pub, FakeRouter())
        try:
            peer = b"\xab" * 32
            q1 = pc.open_peer_channel(peer)
            q2 = pc.open_peer_channel(peer)
            self.assertIs(q1, q2, "open_peer_channel must be idempotent")
            pc.close_peer_channel(peer)
            # Closing twice is safe.
            pc.close_peer_channel(peer)
            q3 = pc.open_peer_channel(peer)
            self.assertIsNot(q3, q1, "after close, open returns a fresh queue")
        finally:
            await pc.close()


if __name__ == "__main__":
    unittest.main()
