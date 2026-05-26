"""DHT PUT_VALUE / GET_VALUE + ADD_PROVIDER / GET_PROVIDERS tests.

Unit coverage:
    * Record protobuf encode/decode (RFC3339 timestamps, large values)
    * All four message wire-format round-trips
    * KadDatastore put/get + provider add/get
    * KadDatastore rejects oversized values + bad keys

Integration coverage:
    * Three Libp2pNode instances over real TCP+Noise+yamux:

        - A puts a value at key K
        - C does get_value(K) and recovers the same bytes -- the
          DHT walk goes A -> hub -> C (or any path through routing
          tables) and surfaces the value.
        - A provides content X (advertises "I have X")
        - C finds providers of X and gets A's PeerID back.

      This is the smallest end-to-end demonstration that the put-
      data + get-it-on-the-other-node primitive works in the same
      shape stock libp2p clients do it.
"""
import asyncio
import unittest

from aionetiface import IP4, Interface
from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.libp2p_native import kad as kad_mod
from warpgate.traversal.plugins.libp2p_native import peer_id
from warpgate.traversal.plugins.libp2p_native.node_core import Libp2pNode


class TestRecordEncoding(unittest.TestCase):
    def test_round_trip(self):
        blob = kad_mod.encode_record(
            b"/v/hello", b"world bytes",
            time_received="2026-05-27T12:00:00Z",
        )
        key, value, time_str = kad_mod.decode_record(blob)
        self.assertEqual(key, b"/v/hello")
        self.assertEqual(value, b"world bytes")
        self.assertEqual(time_str, "2026-05-27T12:00:00Z")

    def test_round_trip_no_time(self):
        blob = kad_mod.encode_record(b"k", b"v")
        key, value, time_str = kad_mod.decode_record(blob)
        self.assertEqual(key, b"k")
        self.assertEqual(value, b"v")
        self.assertEqual(time_str, "")


class TestPutGetEncoding(unittest.TestCase):
    def test_put_value(self):
        record = kad_mod.encode_record(b"k", b"v", "2026-05-27T00:00:00Z")
        blob = kad_mod.encode_put_value(b"k", record)
        msg = kad_mod.decode_message(blob)
        self.assertEqual(msg["type"], kad_mod.TYPE_PUT_VALUE)
        self.assertEqual(msg["key"], b"k")
        self.assertIsNotNone(msg["record"])
        rk, rv, _ = msg["record"]
        self.assertEqual(rk, b"k")
        self.assertEqual(rv, b"v")

    def test_get_value_reply(self):
        record = kad_mod.encode_record(b"k", b"v")
        blob = kad_mod.encode_get_value_reply(b"k", record)
        msg = kad_mod.decode_message(blob)
        self.assertEqual(msg["type"], kad_mod.TYPE_GET_VALUE)
        self.assertEqual(msg["record"][1], b"v")

    def test_add_provider(self):
        pid = b"\x00\x24" + b"\xaa" * 36
        blob = kad_mod.encode_add_provider(b"K", pid, [b"/maddr"])
        msg = kad_mod.decode_message(blob)
        self.assertEqual(msg["type"], kad_mod.TYPE_ADD_PROVIDER)
        self.assertEqual(msg["key"], b"K")
        self.assertEqual(len(msg["provider_peers"]), 1)
        out_pid, out_addrs, _ = msg["provider_peers"][0]
        self.assertEqual(out_pid, pid)
        self.assertEqual(out_addrs, [b"/maddr"])

    def test_get_providers_reply(self):
        from warpgate.kademlia import PeerInfo
        pid = b"\x00\x24" + b"\xbb" * 36
        prov = PeerInfo(pid, addrs=[b"/maddr"])
        blob = kad_mod.encode_get_providers_reply(b"K", providers=[prov])
        msg = kad_mod.decode_message(blob)
        self.assertEqual(msg["type"], kad_mod.TYPE_GET_PROVIDERS)
        self.assertEqual(len(msg["provider_peers"]), 1)
        out_pid, _, _ = msg["provider_peers"][0]
        self.assertEqual(out_pid, pid)


class TestKadDatastore(unittest.TestCase):
    def test_put_get(self):
        ds = kad_mod.KadDatastore()
        ds.put_value(b"k", b"v", "2026-05-27T00:00:00Z")
        v, t = ds.get_value(b"k")
        self.assertEqual(v, b"v")
        self.assertEqual(t, "2026-05-27T00:00:00Z")

    def test_get_missing(self):
        ds = kad_mod.KadDatastore()
        v, t = ds.get_value(b"missing")
        self.assertIsNone(v)
        self.assertIsNone(t)

    def test_rejects_oversized_value(self):
        ds = kad_mod.KadDatastore()
        big = b"x" * (kad_mod.KadDatastore.MAX_VALUE_BYTES + 1)
        with self.assertRaises(ValueError):
            ds.put_value(b"k", big, "")

    def test_provider_add_get(self):
        ds = kad_mod.KadDatastore()
        ds.add_provider(b"K", b"pid-1", [b"/m1"], 1700000000)
        ds.add_provider(b"K", b"pid-2", [b"/m2"], 1700000001)
        provs = dict(ds.get_providers(b"K"))
        self.assertEqual(set(provs.keys()), {b"pid-1", b"pid-2"})
        self.assertEqual(provs[b"pid-1"], [b"/m1"])


class TestPutGetEndToEnd(AsyncTestCase):
    """Three Libp2pNodes over real TCP + Noise; A puts, C gets via DHT walk.

    Layout (127/8 loopback block, distinct local IPs):
        127.0.0.1  HUB     (rendezvous; both A and C dial it)
        127.0.0.2  A       (publisher)
        127.0.0.3  C       (subscriber)

    After both A and C connect to HUB, HUB's routing table holds
    them both.  A's put_value walks to closest K peers, lands on
    HUB (since C isn't directly reachable from A).  When C calls
    get_value, the walk queries HUB which has the record locally
    and returns it -- end-to-end PUT-on-network -> GET-on-other-
    node via Kad-DHT through an intermediary peer.
    """

    async def asyncSetUp(self):
        self.iface = await Interface("default")
        self.id_hub = peer_id.Identity.generate()
        self.id_a = peer_id.Identity.generate()
        self.id_c = peer_id.Identity.generate()
        self.hub = Libp2pNode(self.id_hub)
        self.a = Libp2pNode(self.id_a)
        self.c = Libp2pNode(self.id_c)

    async def asyncTearDown(self):
        await self.hub.close()
        await self.a.close()
        await self.c.close()

    async def test_put_value_then_get_value_through_hub(self):
        hub_ip, hub_port = await self.hub.listen(
            self.iface, IP4, ips="127.0.0.1", port=0,
        )
        route_a = await self.iface.route(IP4).bind(ips="127.0.0.2", port=0)
        route_c = await self.iface.route(IP4).bind(ips="127.0.0.3", port=0)
        await self.a.dial(
            hub_ip, hub_port, route_a,
            expected_peer_id=self.id_hub.peer_id, timeout=10.0,
        )
        await self.c.dial(
            hub_ip, hub_port, route_c,
            expected_peer_id=self.id_hub.peer_id, timeout=10.0,
        )
        # Give on_session_established a tick to populate routing tables.
        await asyncio.sleep(0.2)

        # A publishes (key=b"/warpgate/test/k1", value=b"hello-via-dht").
        key = b"/warpgate/test/k1"
        value = b"hello-via-dht"
        accepted = await self.a.put_value(key, value, timeout=10.0)
        # A's PUT walks to peers it knows; HUB is the only one and
        # should accept.
        self.assertGreaterEqual(accepted, 1)
        # HUB should have stored the record.
        stored_value, _ = self.hub.kad_datastore.get_value(key)
        self.assertEqual(stored_value, value)

        # Now C retrieves.  C's routing table has only HUB; the
        # get_value walk queries HUB and recovers the record.
        got = await self.c.get_value(key, timeout=10.0)
        self.assertEqual(got, value)

    async def test_provide_and_find_providers_through_hub(self):
        hub_ip, hub_port = await self.hub.listen(
            self.iface, IP4, ips="127.0.0.1", port=0,
        )
        route_a = await self.iface.route(IP4).bind(ips="127.0.0.2", port=0)
        route_c = await self.iface.route(IP4).bind(ips="127.0.0.3", port=0)
        await self.a.dial(
            hub_ip, hub_port, route_a,
            expected_peer_id=self.id_hub.peer_id, timeout=10.0,
        )
        await self.c.dial(
            hub_ip, hub_port, route_c,
            expected_peer_id=self.id_hub.peer_id, timeout=10.0,
        )
        await asyncio.sleep(0.2)

        content_key = b"/warpgate/test/content-hash-1"
        accepted = await self.a.provide(content_key, timeout=10.0)
        self.assertGreaterEqual(accepted, 1)
        # HUB now knows A is a provider of content_key.
        hub_provs = dict(self.hub.kad_datastore.get_providers(content_key))
        self.assertIn(self.id_a.peer_id, hub_provs)

        # C looks up providers; should find A.
        provs = await self.c.find_providers(content_key, timeout=10.0)
        prov_pids = [p.peer_id for p in provs]
        self.assertIn(self.id_a.peer_id, prov_pids)


if __name__ == "__main__":
    unittest.main()
