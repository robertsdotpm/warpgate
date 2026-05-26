"""Targeted tests for the F4 / F6 / F8 / F12 router fixes.

Each test maps to one specific finding from the Go-vs-Python diff:
- F4: info expiry on the maintenance tick
- F6: handle_announce refresh-on-self-update + echo-back-on-reject
- F8: build_bloom_for_peer merges peer recv-blooms
- F12: handle_lookup drops off-tree peers
"""
import asyncio
import os
import time
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil import router_active as ra
from warpgate.overlay.yggdrasil.node_core import NodeCore, derive_pubkey
from warpgate.overlay.yggdrasil.routing_msgs import (
    RouterAnnounce,
    RouterSigRes,
)
from warpgate.overlay.yggdrasil.router_active import (
    ActiveRouter,
    RouterInfo,
    sign,
)


def make_router(seed=None):
    seed = seed or os.urandom(32)
    node = NodeCore(seed=seed)
    return node, ActiveRouter(node)


def make_self_announce(seed):
    """Construct a valid root-style announce for the given seed."""
    pub = derive_pubkey(seed)
    res = RouterSigRes(seq=1, nonce=42, port=0, psig=b"\x00" * 64)
    bs = res.bytes_for_sig(pub, pub)
    psig = sign(seed, bs)
    res.psig = psig
    return RouterAnnounce(key=pub, parent=pub, sig_res=res, sig=psig)


class TestF4InfoExpiry(AsyncTestCase):
    """F4: infos older than ROUTER_TIMEOUT_SECONDS are swept on tick."""

    async def test_sweep_drops_old_info(self):
        node, router = make_router()
        try:
            # Inject a synthetic info for a fake peer + backdate its
            # timestamp past the TTL.
            fake_key = b"\xaa" * 32
            fake_info = RouterInfo(
                parent=b"\xbb" * 32,
                sig_res=RouterSigRes(seq=1, nonce=1, port=1, psig=b"\x00" * 64),
                sig=b"\x00" * 64,
            )
            router.infos[fake_key] = fake_info
            router.info_timestamps[fake_key] = (
                time.monotonic() - (ra.ROUTER_TIMEOUT_SECONDS + 1)
            )
            router.sweep_expired_infos()
            self.assertNotIn(fake_key, router.infos)
            self.assertNotIn(fake_key, router.info_timestamps)
        finally:
            await node.close()

    async def test_sweep_keeps_fresh_info(self):
        node, router = make_router()
        try:
            fake_key = b"\xcc" * 32
            router.infos[fake_key] = RouterInfo(
                parent=b"\xdd" * 32,
                sig_res=RouterSigRes(seq=1, nonce=1, port=1, psig=b"\x00" * 64),
                sig=b"\x00" * 64,
            )
            router.info_timestamps[fake_key] = time.monotonic()
            router.sweep_expired_infos()
            self.assertIn(fake_key, router.infos)
        finally:
            await node.close()

    async def test_sweep_never_drops_self(self):
        node, router = make_router()
        try:
            # Self is in router.infos from become_root but should
            # have no timestamp entry (exempt).
            self_pub = router.public_key
            self.assertIn(bytes(self_pub), [bytes(k) for k in router.infos])
            self.assertNotIn(bytes(self_pub), router.info_timestamps)
            router.sweep_expired_infos()
            self.assertIn(bytes(self_pub), [bytes(k) for k in router.infos])
        finally:
            await node.close()


class TestF6RefreshOnSelfEcho(AsyncTestCase):
    """F6: handle_announce sets refresh=True if a peer echoes our own info."""

    async def test_self_echo_triggers_refresh(self):
        node, router = make_router()
        try:
            self_seed = router.seed
            ann = make_self_announce(self_seed)
            # Bump seq above our existing one so update_info accepts.
            ann.sig_res = RouterSigRes(
                seq=router.infos[bytes(router.public_key)].seq + 5,
                nonce=999, port=0, psig=b"\x00" * 64,
            )
            bs = ann.sig_res.bytes_for_sig(ann.key, ann.parent)
            ann.sig_res.psig = sign(self_seed, bs)
            ann.sig = ann.sig_res.psig

            class FakeLink(object):
                remote_pubkey = b"\xee" * 32
                remote_addr = "200::e"
            self.assertFalse(router.refresh)
            router.handle_announce(FakeLink(), ann)
            self.assertTrue(router.refresh,
                "self-echo did not trigger refresh flag")
        finally:
            await node.close()

    async def test_rejection_does_not_set_refresh(self):
        node, router = make_router()
        try:
            # Send an announce for some OTHER key -- should NOT
            # touch refresh either way.
            other_seed = os.urandom(32)
            ann = make_self_announce(other_seed)

            class FakeLink(object):
                remote_pubkey = b"\xff" * 32
                remote_addr = "200::f"
            router.handle_announce(FakeLink(), ann)
            self.assertFalse(router.refresh)
        finally:
            await node.close()


class TestF8BloomMergesPeerFilters(AsyncTestCase):
    """F8: build_bloom_for_peer unions peer recv-blooms for transitive reachability."""

    async def test_merge_includes_third_party_bloom_bits(self):
        from warpgate.overlay.yggdrasil.pathfinder import bloom_transform
        from warpgate.overlay.yggdrasil.routing_msgs import Bloom

        node, router = make_router()
        try:
            # Simulate two peers, each having received a bloom.
            peer_a = b"\xaa" * 32
            peer_b = b"\xbb" * 32
            # Peer A's recv bloom contains transformed key "X".
            target_x = b"\x42" * 32
            bloom_a = Bloom()
            bloom_a.add_key(bloom_transform(target_x))
            router.peer_recv_bloom[peer_a] = bloom_a

            # Peer B's recv bloom contains transformed key "Y".
            target_y = b"\x43" * 32
            bloom_b = Bloom()
            bloom_b.add_key(bloom_transform(target_y))
            router.peer_recv_bloom[peer_b] = bloom_b

            # Bloom built FOR peer A should include B's bits (Y)
            # but exclude A's own bits.  Plus self.
            built = router.build_bloom_for_peer(peer_a)
            self.assertTrue(built.test_key(bloom_transform(router.public_key)),
                "self xform should be in our outbound bloom")
            self.assertTrue(built.test_key(bloom_transform(target_y)),
                "peer B's bloom bits should be merged into outbound")
            # A's own bits are NOT necessarily excluded by this design
            # (upstream's bloom test is "anything reachable") -- we
            # just don't merge A's filter into itself.
        finally:
            await node.close()


class TestF9PeriodicBloomResend(AsyncTestCase):
    """F9: maintenance tick re-sends bloom if it changed.

    Without this, the initial bloom we sent each peer is stuck
    forever, and F8's transitive-reachability merges never
    propagate to existing peers as our peer_recv_bloom map
    learns more keys.
    """

    async def test_resend_only_fires_on_change(self):
        from warpgate.overlay.yggdrasil.pathfinder import bloom_transform
        from warpgate.overlay.yggdrasil.routing_msgs import Bloom

        node, router = make_router()
        try:
            # Two fake peers, both already in sent[] (i.e. past
            # the sync_peers gate).  Stub out send_packet_safe so
            # we can count outbound bloom sends per peer.
            peer_a = b"\xa1" * 32
            peer_b = b"\xa2" * 32

            class FakeLink(object):
                def __init__(self, pk):
                    self.remote_pubkey = pk
            class FakeEntry(object):
                def __init__(self, pk):
                    self.link = FakeLink(pk)
            entries = [FakeEntry(peer_a), FakeEntry(peer_b)]

            class FakePeers(object):
                def peers(self): return entries
            router.node_core.peers = FakePeers()
            router.sent[peer_a] = set()
            router.sent[peer_b] = set()

            sent_calls = []
            async def fake_send(link, ptype, payload):
                sent_calls.append((bytes(link.remote_pubkey), ptype, payload))
            router.send_packet_safe = fake_send

            # First tick: no prior bloom, should send to both peers.
            router.resend_changed_blooms()
            # Drain the ensure_future calls.
            await asyncio.sleep(0.05)
            self.assertEqual(len(sent_calls), 2,
                "first resend should hit both peers")
            sent_calls.clear()

            # Second tick: nothing changed, expect zero sends.
            router.resend_changed_blooms()
            await asyncio.sleep(0.05)
            self.assertEqual(len(sent_calls), 0,
                "second resend with no change should not fire")

            # Now: simulate a third party teaching peer_a's recv-bloom
            # about a new key.  Peer B's outbound bloom needs to merge
            # this change in (per F8), so the resend should now fire
            # to peer B but NOT to peer A (we don't merge A into A).
            external_key = b"\x88" * 32
            new_bloom_for_a = Bloom()
            new_bloom_for_a.add_key(bloom_transform(external_key))
            router.peer_recv_bloom[peer_a] = new_bloom_for_a
            router.resend_changed_blooms()
            await asyncio.sleep(0.05)
            target_peers = set(c[0] for c in sent_calls)
            self.assertIn(peer_b, target_peers,
                "peer B's bloom should resend after A's update")
        finally:
            await node.close()


class TestF12PathLookupOffTreeGate(AsyncTestCase):
    """F12: handle_lookup drops lookups from peers not in our tree neighborhood."""

    async def test_off_tree_lookup_is_dropped(self):
        from warpgate.overlay.yggdrasil.routing_msgs import PathLookup

        node, router = make_router()
        try:
            # Self issues a lookup -- always allowed.
            lookup = PathLookup(
                source=router.public_key,
                dest=b"\xab" * 32,
                from_path=[1, 2, 3],
            )
            # Off-tree peer (no infos entry, not our parent, no peer
            # info pointing at us, NO live link): handle_lookup
            # should early-return.  We synthesize a key that has
            # neither tree edge nor a NodeCore.peers entry.
            off_tree_key = b"\xde" * 32
            called = [False]
            async def fake_multicast(*args, **kwargs):
                called[0] = True
            router.bloom_multicast = fake_multicast
            await router.pathfinder.handle_lookup(off_tree_key, lookup)
            self.assertFalse(called[0],
                "off-tree lookup should not have triggered multicast")
        finally:
            await node.close()

    async def test_self_lookup_is_always_allowed(self):
        from warpgate.overlay.yggdrasil.routing_msgs import PathLookup

        node, router = make_router()
        try:
            lookup = PathLookup(
                source=router.public_key,
                dest=b"\xab" * 32,
                from_path=[1, 2, 3],
            )
            called = [False]
            async def fake_multicast(*args, **kwargs):
                called[0] = True
            router.bloom_multicast = fake_multicast
            await router.pathfinder.handle_lookup(router.public_key, lookup)
            self.assertTrue(called[0],
                "self-issued lookup must bypass the on-tree gate")
        finally:
            await node.close()


if __name__ == "__main__":
    unittest.main()
