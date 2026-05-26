"""Kademlia + libp2p Kad-DHT tests.

Unit coverage (warpgate.kademlia generic core):
    * xor_distance, common_prefix_length
    * KBucket add/refresh/full eviction
    * RoutingTable.find_closest ordering
    * iterative_find_node over a synthetic transport

Unit coverage (libp2p kad wire):
    * Kad Message protobuf encode/decode round-trip
    * key_for_peer_id stable / matches SHA-256

Integration (real-TCP over Noise XX + yamux):
    * Three Libp2pNode instances form a private DHT.  A new node D
      bootstraps off A, asks for "find peer C", and gets back C's
      info through B's routing table.
"""
import asyncio
import hashlib
import unittest

from aionetiface import IP4, Interface
from aionetiface.testing import AsyncTestCase

from warpgate.kademlia import (
    KBucket, PeerInfo, RoutingTable, KadTransport,
    iterative_find_node, xor_distance, common_prefix_length,
)
from warpgate.traversal.plugins.libp2p_native import kad as kad_mod
from warpgate.traversal.plugins.libp2p_native import peer_id
from warpgate.traversal.plugins.libp2p_native.node_core import Libp2pNode


class TestGenericKademlia(unittest.TestCase):
    def test_xor_distance(self):
        a = b"\x00" * 31 + b"\x01"
        b = b"\x00" * 31 + b"\x02"
        self.assertEqual(xor_distance(a, b), 3)
        self.assertEqual(xor_distance(a, a), 0)

    def test_common_prefix_length(self):
        zero = b"\x00" * 32
        almost_zero = b"\x00" * 31 + b"\x01"
        # Differ at the very last bit -> CPL = 255.
        self.assertEqual(common_prefix_length(zero, almost_zero), 255)
        self.assertEqual(common_prefix_length(zero, zero), 256)

    def test_kbucket_refresh_moves_to_head(self):
        b = KBucket(capacity=3)
        p1 = PeerInfo(b"\x01" * 32)
        p2 = PeerInfo(b"\x02" * 32)
        p3 = PeerInfo(b"\x03" * 32)
        b.add(p1)
        b.add(p2)
        b.add(p3)
        # Most recently added is head.
        self.assertEqual([p.peer_id[0] for p in b.entries], [3, 2, 1])
        # Refreshing p1 moves it to head.
        b.add(p1)
        self.assertEqual([p.peer_id[0] for p in b.entries], [1, 3, 2])

    def test_kbucket_full_reports_lru(self):
        b = KBucket(capacity=2)
        b.add(PeerInfo(b"\x01" * 32))
        b.add(PeerInfo(b"\x02" * 32))
        status, evict = b.add(PeerInfo(b"\x03" * 32))
        self.assertEqual(status, "full")
        self.assertEqual(evict.peer_id, b"\x01" * 32)

    def test_routing_table_find_closest_ordering(self):
        local = bytes(32)
        rt = RoutingTable(local, k=20, key_bits=256)
        for i in range(1, 17):
            rt.add_peer(PeerInfo(b"\x00" * 31 + bytes([i])))
        target = b"\x00" * 31 + b"\x08"
        closest = rt.find_closest(target, 3)
        self.assertEqual(closest[0].peer_id[-1], 8)  # zero distance to self
        # Distance grows monotonically.
        d_seq = [xor_distance(c.peer_id, target) for c in closest]
        self.assertEqual(d_seq, sorted(d_seq))


class MockTransport(KadTransport):
    """Synthetic transport: ``network`` maps peer_id -> [neighbor_peer_ids]."""

    def __init__(self, network, info_map):
        self.network = network
        self.info_map = info_map  # peer_id -> PeerInfo (for richer responses)

    async def find_node(self, peer_info, target_key):
        neighbors = self.network.get(peer_info.peer_id, [])
        return [self.info_map[nid] for nid in neighbors]


class TestIterativeFindNode(AsyncTestCase):
    async def test_walks_to_closer_neighbor(self):
        # Build a Kad-realistic network: a "hub" peer that knows
        # every other peer, and target T near it.  Starting from
        # a table that contains only the hub, the iterative walk
        # should find T by querying the hub.
        info_map = {}
        hub_pid = b"\x80" + b"\x00" * 31    # high-bit set, far from us
        target_pid = b"\x80" + b"\x00" * 30 + b"\x01"  # near hub
        far_pid = b"\xff" * 32              # far from target
        for pid in (hub_pid, target_pid, far_pid):
            info_map[pid] = PeerInfo(pid)
        # Hub knows both target and far.  Target and far know nothing.
        network = {
            hub_pid: [target_pid, far_pid],
            target_pid: [],
            far_pid: [],
        }
        rt = RoutingTable(bytes(32), k=8, key_bits=256)
        rt.add_peer(info_map[hub_pid])
        transport = MockTransport(network, info_map)
        # Look up the target_pid's kad key (identity_key in this
        # synthetic setup -- key_fn is identity for this RT).
        result = await iterative_find_node(rt, target_pid, transport, alpha=2, k=4)
        self.assertIn(target_pid, [r.peer_id for r in result])

    async def test_terminates_when_no_progress(self):
        # Hub knows nobody closer to the target than the hub itself
        # -- the algorithm should terminate gracefully without
        # an infinite loop.
        hub_pid = b"\x80" + b"\x00" * 31
        target_pid = b"\x00" * 32
        info_map = {hub_pid: PeerInfo(hub_pid)}
        network = {hub_pid: []}
        rt = RoutingTable(bytes(32), k=8, key_bits=256)
        # Important: hub IS in our table but isn't us (we're zeros).
        rt.add_peer(info_map[hub_pid])
        # Use a non-local target so the table actually has something
        # closer to consider; the hub will be the only candidate
        # and will return empty.  Algorithm should converge to [hub].
        result = await iterative_find_node(
            rt, target_pid, MockTransport(network, info_map),
            alpha=2, k=4,
        )
        self.assertEqual([p.peer_id for p in result], [hub_pid])


class TestKadWireEncoding(unittest.TestCase):
    def test_find_node_round_trip(self):
        key = b"\xab" * 32
        blob = kad_mod.encode_find_node(key)
        msg = kad_mod.decode_message(blob)
        self.assertEqual(msg["type"], kad_mod.TYPE_FIND_NODE)
        self.assertEqual(msg["key"], key)

    def test_kad_peer_round_trip(self):
        pid = b"\xcd" * 38
        addrs = [b"/maddr1", b"/maddr2"]
        blob = kad_mod.encode_kad_peer(pid, addrs)
        out_pid, out_addrs, conn = kad_mod.decode_kad_peer(blob)
        self.assertEqual(out_pid, pid)
        self.assertEqual(out_addrs, addrs)
        self.assertEqual(conn, 0)

    def test_key_for_peer_id_is_sha256(self):
        pid = b"\x00\x24\x08\x01\x12\x20" + b"\xaa" * 32
        self.assertEqual(kad_mod.key_for_peer_id(pid), hashlib.sha256(pid).digest())


class TestThreeNodeDHT(AsyncTestCase):
    """Three Libp2pNode instances form a private DHT.

    Topology:
        A on 127.0.0.1
        B on 127.0.0.2
        C on 127.0.0.3

    All three discover each other through bootstrap-style dials:
      - A is the "rendezvous": both B and C dial A.
      - After both sessions complete, A's kad routing table holds
        SHA-256 keys for both B's and C's PeerIDs (via the
        on_session_established hook).
      - B then calls find_peer(C.peer_id).  Kad walks: queries A
        (which knows C as a closer peer), returns C's key.

    This validates that the generic kademlia walk + the libp2p
    Kad wire transport + the routing-table-on-session-up hook
    work together end-to-end.
    """

    async def asyncSetUp(self):
        self.iface = await Interface("default")
        self.id_a = peer_id.Identity.generate()
        self.id_b = peer_id.Identity.generate()
        self.id_c = peer_id.Identity.generate()
        self.a = Libp2pNode(self.id_a)
        self.b = Libp2pNode(self.id_b)
        self.c = Libp2pNode(self.id_c)

    async def asyncTearDown(self):
        await self.a.close()
        await self.b.close()
        await self.c.close()

    async def test_dht_walk_finds_third_node(self):
        # A is the rendezvous; B and C both dial A.
        a_ip, a_port = await self.a.listen(
            self.iface, IP4, ips="127.0.0.1", port=0,
        )
        route_b = await self.iface.route(IP4).bind(ips="127.0.0.2", port=0)
        route_c = await self.iface.route(IP4).bind(ips="127.0.0.3", port=0)

        await self.b.dial(
            a_ip, a_port, route_b,
            expected_peer_id=self.id_a.peer_id, timeout=10.0,
        )
        await self.c.dial(
            a_ip, a_port, route_c,
            expected_peer_id=self.id_a.peer_id, timeout=10.0,
        )

        # Both B and C are now known to A's Kad routing table.
        # Table is keyed by libp2p PeerID directly; the kad-key
        # (SHA-256 of the PeerID) is derived on demand for
        # distance calculations.
        self.assertIsNotNone(
            self.a.kad_routing_table.bucket_for(self.id_b.peer_id).find(
                self.id_b.peer_id
            )
        )
        self.assertIsNotNone(
            self.a.kad_routing_table.bucket_for(self.id_c.peer_id).find(
                self.id_c.peer_id
            )
        )

        # B asks A "find peer C".  A is currently the only peer in
        # B's routing table.  A's FIND_NODE response returns C's
        # PeerID as a closer peer; the walk completes with C in
        # the result.
        result = await self.b.find_peer(self.id_c.peer_id, timeout=10.0)
        result_pids = [p.peer_id for p in result]
        self.assertIn(
            self.id_c.peer_id, result_pids,
            "find_peer didn't surface C via A's routing table",
        )


if __name__ == "__main__":
    unittest.main()
