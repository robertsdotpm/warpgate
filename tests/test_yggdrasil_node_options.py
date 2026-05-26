"""Ports of upstream peer-options / allow-list tests.

Covers:
  - ``TestAllowedPublicKeys`` (core/core_test.go:226) -- peers
    whose pubkey isn't in the allow-list don't end up registered.
  - ``TestAllowedPublicKeysLocal`` (core/core_test.go:259) -- the
    same gate applies to all peers regardless of dial direction.
  - ``TestAddEmptyPeer`` (core/options_test.go:43) -- empty URI
    raises rather than crashing later.
  - ``TestDuplicatePeerAtStartup`` (core/options_test.go:13) -- N
    duplicate add_peer_uri calls are idempotent (no exception, no
    crash).
  - ``TestDuplicatePeerFromAPI`` (core/options_test.go:28) -- intent
    matches our chosen API contract: idempotent (no error).
    Upstream raises; we documented this divergence in the test
    so any future behaviour change is a conscious choice.
"""
import asyncio
import os
import unittest

from aionetiface import IP6
from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.node_core import NodeCore, derive_pubkey


class TestNodeCoreAllowedPubkeys(AsyncTestCase):
    """Peers outside the allow-list must NOT end up in the peer table."""

    async def test_unallowed_inbound_is_rejected(self):
        # Node A only accepts a fake pubkey (b'\xab' * 32).
        # Node B has its own real key -> not allowed.
        fake_allowed = b"\xab" * 32
        node_a = NodeCore(seed=os.urandom(32), allowed_pubkeys=[fake_allowed])
        node_b = NodeCore(seed=os.urandom(32))
        try:
            await node_a.start_listener(bind_addr="::1", port=0, af=IP6)
            uri = "tcp://[::1]:{0}".format(node_a.listen_port)
            await node_b.add_peer_uri(uri)
            # Give the dial / handshake a second to complete +
            # the reject path to fire.
            await asyncio.sleep(1.5)
            # The allow-list rejection runs AFTER handshake but
            # BEFORE peer-table insertion; node_a must have an
            # empty peer table.
            self.assertEqual(
                len(list(node_a.peers.peers())), 0,
                "node_a should have rejected the non-allowed peer",
            )
        finally:
            await node_a.close()
            await node_b.close()

    async def test_allowed_inbound_is_accepted(self):
        # Node A's allow-list contains node B's pubkey -> peering
        # should complete normally.
        seed_b = os.urandom(32)
        pub_b = derive_pubkey(seed_b)
        node_a = NodeCore(seed=os.urandom(32), allowed_pubkeys=[pub_b])
        node_b = NodeCore(seed=seed_b)
        try:
            await node_a.start_listener(bind_addr="::1", port=0, af=IP6)
            uri = "tcp://[::1]:{0}".format(node_a.listen_port)
            await node_b.add_peer_uri(uri)
            # Wait up to 5 s for the peering to land.
            for _ in range(50):
                if node_a.peers.get_peer(pub_b) is not None:
                    break
                await asyncio.sleep(0.1)
            self.assertIsNotNone(
                node_a.peers.get_peer(pub_b),
                "node_a should have accepted the allowed peer",
            )
        finally:
            await node_a.close()
            await node_b.close()

    async def test_constructor_rejects_bad_pubkey_length(self):
        with self.assertRaises(ValueError):
            NodeCore(seed=os.urandom(32), allowed_pubkeys=[b"\x01" * 16])

    async def test_no_allow_list_accepts_everyone(self):
        # When allowed_pubkeys is None, the gate is a no-op.  This
        # is the default behaviour every other test in the suite
        # depends on.
        node = NodeCore(seed=os.urandom(32))
        self.assertIsNone(node.allowed_pubkeys)


class TestNodeCoreAddPeerValidation(AsyncTestCase):
    """add_peer_uri input validation -- empty / malformed must raise."""

    async def asyncSetUp(self):
        self.node = NodeCore(seed=os.urandom(32))

    async def asyncTearDown(self):
        await self.node.close()

    async def test_empty_uri_raises(self):
        with self.assertRaises(ValueError):
            await self.node.add_peer_uri("")

    async def test_no_scheme_raises(self):
        with self.assertRaises(ValueError):
            await self.node.add_peer_uri("1.2.3.4:4321")

    async def test_unsupported_scheme_raises(self):
        with self.assertRaises(ValueError):
            await self.node.add_peer_uri("http://1.2.3.4:80")

    async def test_missing_port_raises(self):
        with self.assertRaises(ValueError):
            await self.node.add_peer_uri("tcp://1.2.3.4")


class TestNodeCoreDuplicatePeer(AsyncTestCase):
    """Idempotent add_peer_uri -- N adds of the same URI is a no-op.

    Upstream Go raises on duplicate from the admin API.  We
    intentionally diverge: NodeCore is one layer below the admin
    surface, and idempotency is more useful when startup configs
    contain duplicates (which upstream's TestDuplicatePeerAtStartup
    explicitly relies on -- the startup path is permissive there).
    Pinning the chosen behaviour with a test so any future
    refactor that flips it is a conscious change, not a regression.
    """

    async def asyncSetUp(self):
        self.node = NodeCore(seed=os.urandom(32))

    async def asyncTearDown(self):
        await self.node.close()

    async def test_duplicate_add_is_idempotent(self):
        uri = "tcp://198.51.100.42:1234"
        await self.node.add_peer_uri(uri)
        first_count = len(self.node.dialer_tasks)
        for _ in range(4):
            await self.node.add_peer_uri(uri)
        self.assertEqual(
            len(self.node.dialer_tasks), first_count,
            "duplicate add_peer_uri should not create extra dialer tasks",
        )

    async def test_five_duplicate_uris_at_startup(self):
        """Mirrors upstream's TestDuplicatePeerAtStartup -- 5 adds
        must not crash.  This is the test that justifies our
        idempotent-add design choice."""
        uri = "tcp://198.51.100.42:4321"
        for _ in range(5):
            await self.node.add_peer_uri(uri)


if __name__ == "__main__":
    unittest.main()
