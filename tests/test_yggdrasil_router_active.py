"""Active router tests: two-node tree formation + traffic forwarding."""
import asyncio
import os
import time
import unittest

from aionetiface import IP6
from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.node_core import NodeCore
from warpgate.overlay.yggdrasil.pathfinder import PathInfo, bloom_transform
from warpgate.overlay.yggdrasil.router_active import (
    ActiveRouter,
    RouterInfo,
    key_less,
    sign,
    verify,
)
from warpgate.overlay.yggdrasil.routing_msgs import (
    PathBroken, PathNotify, PathNotifyInfo,
    RouterAnnounce, RouterSigReq, RouterSigRes, Traffic,
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


class TestLocalSeqAfterUseResponse(AsyncTestCase):
    """When we adopt a peer's parent via use_response, our local_seq
    must be brought up to the peer-supplied seq.  Otherwise the next
    sig_req we send will have a stale seq, and update_info will
    reject it -- breaking tree convergence.

    This mirrors the Go invariant that ``_newReq`` uses
    ``r.infos[selfKey].seq + 1``; the Python port held seq state
    separately in ``local_seq`` and didn't sync it after use_response.
    """

    async def test_use_response_syncs_local_seq(self):
        seed_a = os.urandom(32)
        seed_b = os.urandom(32)
        node_a = NodeCore(seed=seed_a)
        node_b = NodeCore(seed=seed_b)
        router_a = ActiveRouter(node_a)
        # Simulate: B sends back a sig_res with a much higher seq
        # than A's local_seq.  After A adopts B as parent, A's
        # local_seq must match res.seq -- not stay at the old
        # become_root value.
        peer_seq = 999
        peer_nonce = 12345
        res = RouterSigRes(
            seq=peer_seq, nonce=peer_nonce, port=42,
            psig=b"\x00" * 64,
        )
        # Sign as B (acting as parent).
        bs = res.bytes_for_sig(node_a.public_key, node_b.public_key)
        res.psig = sign(seed_b, bs)
        router_a.use_response(node_b.public_key, res)
        # After use_response, our self-info should have seq = peer_seq.
        self.assertEqual(router_a.infos[node_a.public_key].seq, peer_seq)
        # And our local_seq tracker should also be at peer_seq so
        # the next sig_req we send is peer_seq+1 (matches Go's
        # _newReq semantics).
        self.assertGreaterEqual(router_a.local_seq, peer_seq,
            "local_seq must be >= adopted self-info seq, else "
            "future sig_reqs use stale seqs and update_info rejects "
            "fresh responses from peers")


class TestHandleNotifyDropsUnsolicited(AsyncTestCase):
    """Path notifies must be dropped unless we have an outstanding rumor
    for this destination OR an existing path entry.  Otherwise an
    arbitrary peer can pollute our path cache by sending valid-looking
    notifies for keys we never asked about.

    Upstream Go pathfinder._handleNotify enforces this gate (lines
    104-124 of pathfinder.go); the Python port accepted unsolicited
    notifies that passed the signature check.
    """

    async def test_unsolicited_notify_does_not_populate_paths(self):
        seed_a = os.urandom(32)
        seed_b = os.urandom(32)
        node_a = NodeCore(seed=seed_a)
        node_b = NodeCore(seed=seed_b)
        router_a = ActiveRouter(node_a)
        # Build a perfectly valid signed notify FROM B TO A.
        path_to_b = [1, 2, 3]
        info = PathNotifyInfo(seq=42, path=list(path_to_b),
                              sig=b"\x00" * 64)
        info.sig = sign(seed_b, info.bytes_for_sig())
        notify = PathNotify(
            path=[], watermark=(1 << 64) - 1,
            source=node_b.public_key,
            dest=node_a.public_key,
            info=info,
        )
        # A has NO rumor and NO existing path for B.  Notify must be dropped.
        await router_a.pathfinder.handle_notify(node_b.public_key, notify)
        self.assertNotIn(node_b.public_key, router_a.pathfinder.paths,
            "notify with no preceding rumor/path was wrongly accepted "
            "into the path cache; this is a path-cache pollution bug")


class TestHandleSigResMatchesRequest(AsyncTestCase):
    """The sig_res we accept must match the seq+nonce of the sig_req we sent.

    Without this check, a stale response (from a previous, since-
    overwritten request) can race ahead of the current one and
    overwrite our state.  Upstream router._handleResponse (line
    425) requires ``r.requests[p.key] == res.routerSigReq`` before
    updating responses[].
    """

    async def test_handle_sig_res_rejects_stale_seq(self):
        seed_a = os.urandom(32)
        seed_b = os.urandom(32)
        node_a = NodeCore(seed=seed_a)
        node_b = NodeCore(seed=seed_b)
        router_a = ActiveRouter(node_a)
        # A has an outstanding request for B at seq=100.
        current_req = RouterSigReq(seq=100, nonce=9999)
        router_a.requests[node_b.public_key] = current_req
        # B replies with a STALE response: seq=50 (from a request
        # that was overwritten by network re-order).  Sign it
        # correctly so it would pass signature verification.
        stale_res = RouterSigRes(
            seq=50, nonce=4242, port=3,
            psig=b"\x00" * 64,
        )
        bs = stale_res.bytes_for_sig(node_a.public_key, node_b.public_key)
        stale_res.psig = sign(seed_b, bs)
        # Simulate a fake link object so handle_sig_res can use it.

        class FakeLink(object):
            def __init__(self, pubkey, addr="200::1"):
                self.remote_pubkey = pubkey
                self.remote_addr = addr
        link = FakeLink(node_b.public_key)
        router_a.handle_sig_res(link, stale_res)
        stored = router_a.responses.get(node_b.public_key)
        self.assertIsNone(stored,
            "stale sig_res (seq mismatch with current request) was "
            "wrongly accepted; this allows out-of-order responses "
            "to overwrite valid current-request state")


if __name__ == "__main__":
    unittest.main()
