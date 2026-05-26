"""Active router tests: two-node tree formation + traffic forwarding."""
import asyncio
import os
import unittest

from aionetiface import IP6
from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.node_core import NodeCore
from warpgate.overlay.yggdrasil.router_active import (
    ActiveRouter,
    RouterInfo,
    key_less,
    sign,
    verify,
)
from warpgate.overlay.yggdrasil.routing_msgs import (
    PathBroken, RouterAnnounce, RouterSigReq, RouterSigRes, Traffic,
)
from warpgate.overlay.yggdrasil.wire import (
    WIRE_PROTO_ANNOUNCE, WIRE_PROTO_SIG_REQ, WIRE_TRAFFIC,
)


class TestSignVerify(AsyncTestCase):
    async def test_sign_verify_roundtrip(self):
        from ecdsa import SigningKey, Ed25519
        seed = os.urandom(32)
        sk = SigningKey.from_string(seed, curve=Ed25519)
        pub = bytes(sk.verifying_key.to_string())
        msg = b"hello world"
        sig = sign(seed, msg)
        self.assertTrue(verify(pub, msg, sig))

    async def test_verify_rejects_bad_sig(self):
        from ecdsa import SigningKey, Ed25519
        seed = os.urandom(32)
        pub = bytes(SigningKey.from_string(seed, curve=Ed25519).verifying_key.to_string())
        self.assertFalse(verify(pub, b"hi", b"\x00" * 64))

    async def test_key_less_lexicographic(self):
        self.assertTrue(key_less(b"\x00" * 32, b"\x01" + b"\x00" * 31))
        self.assertFalse(key_less(b"\xff" * 32, b"\x00" * 32))
        self.assertFalse(key_less(b"\x05" * 32, b"\x05" * 32))


class TestActiveRouterBecomeRoot(AsyncTestCase):
    """Bare ActiveRouter startup -- becomes root, self-info is valid."""

    async def test_constructor_makes_self_root(self):
        seed = os.urandom(32)
        node = NodeCore(seed=seed)
        router = ActiveRouter(node)
        # We should have an info for ourselves and be our own parent.
        self_info = router.infos.get(node.public_key)
        self.assertIsNotNone(self_info)
        self.assertEqual(self_info.parent, node.public_key)
        self.assertEqual(self_info.port, 0)
        # The signature should verify.
        bs = self_info.sig_res.bytes_for_sig(node.public_key, node.public_key)
        self.assertTrue(verify(node.public_key, bs, self_info.sig))

    async def test_get_root_and_path_for_self_is_root_with_empty_path(self):
        seed = os.urandom(32)
        node = NodeCore(seed=seed)
        router = ActiveRouter(node)
        root, path = router.get_root_and_path(node.public_key)
        self.assertEqual(root, node.public_key)
        self.assertEqual(path, [])


class TestTwoNodeTreeFormation(AsyncTestCase):
    """Two nodes peer; verify both can exchange announces + see each other's info."""

    async def asyncSetUp(self):
        self.node_a = NodeCore(seed=os.urandom(32))
        self.node_b = NodeCore(seed=os.urandom(32))
        self.router_a = ActiveRouter(self.node_a)
        self.router_b = ActiveRouter(self.node_b)
        self.node_a.packet_handler = self.router_a.on_packet
        self.node_b.packet_handler = self.router_b.on_packet
        await self.node_a.start_listener(bind_addr="::1", port=0, af=IP6)
        await self.node_b.start_listener(bind_addr="::1", port=0, af=IP6)
        self.router_a.start()
        self.router_b.start()

    async def asyncTearDown(self):
        self.router_a.stop()
        self.router_b.stop()
        await self.node_a.close()
        await self.node_b.close()

    async def test_peers_exchange_announces(self):
        uri = "tcp://[::1]:{0}".format(self.node_b.listen_port)
        await self.node_a.add_peer_uri(uri)
        # Wait for peering.
        for _ in range(50):
            if (self.node_a.peers.get_peer(self.node_b.public_key) is not None
                    and self.node_b.peers.get_peer(self.node_a.public_key)
                    is not None):
                break
            await asyncio.sleep(0.1)
        # Wait an extra tick to let the maintenance loop send announces.
        await asyncio.sleep(2.5)
        # Each side should know about the other's root info.
        # At minimum both nodes know their own info; if announces
        # exchanged at least once, each knows the other too.
        # We assert >= 1 announce received on each side.
        a_announces = self.router_a.counters[WIRE_PROTO_ANNOUNCE]
        b_announces = self.router_b.counters[WIRE_PROTO_ANNOUNCE]
        self.assertGreaterEqual(a_announces, 1,
            "router A never received an announce from B")
        self.assertGreaterEqual(b_announces, 1,
            "router B never received an announce from A")
        # And each should have stored info for the other key.
        self.assertIn(self.node_b.public_key, self.router_a.infos)
        self.assertIn(self.node_a.public_key, self.router_b.infos)

    async def test_sig_req_gets_signed_reply(self):
        uri = "tcp://[::1]:{0}".format(self.node_b.listen_port)
        await self.node_a.add_peer_uri(uri)
        for _ in range(50):
            if self.node_a.peers.get_peer(self.node_b.public_key) is not None:
                break
            await asyncio.sleep(0.1)
        entry = self.node_a.peers.get_peer(self.node_b.public_key)
        self.assertIsNotNone(entry)
        # A sends a sig_req to B.  B should sign + reply with sig_res.
        # First seed A's pending request map so the response gets stored.
        req = RouterSigReq(seq=1, nonce=12345)
        self.router_a.requests[self.node_b.public_key] = req
        await entry.link.send_packet(WIRE_PROTO_SIG_REQ, req.encode())
        for _ in range(40):
            if self.node_b.public_key in self.router_a.responses:
                break
            await asyncio.sleep(0.1)
        res = self.router_a.responses.get(self.node_b.public_key)
        self.assertIsNotNone(res, "no sig_res arrived from B")
        # The signature should verify against B's pubkey.
        bs = res.bytes_for_sig(self.node_a.public_key, self.node_b.public_key)
        self.assertTrue(verify(self.node_b.public_key, bs, res.psig))


if __name__ == "__main__":
    unittest.main()
