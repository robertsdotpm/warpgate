"""End-to-end NodeCore tests.

Spin up two NodeCore instances on different loopback ports, have
one dial the other, verify both end up with a peer entry pointing
at the matching pubkey.

These are heavy tests (real listener sockets + real handshakes),
so this file holds exactly one test class per the heavy-test rule.
"""
import asyncio
import os
import unittest

from aionetiface import IP6
from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.address import addr_for_key, ipv6_str_from_bytes
from warpgate.overlay.yggdrasil.node_core import NodeCore, parse_peer_uri
from warpgate.overlay.yggdrasil.peer_table import (
    BackoffCounter,
    DuplicatePeerError,
    PeerTable,
)
from warpgate.overlay.yggdrasil.wire import WIRE_TRAFFIC


class TestPeerTable(AsyncTestCase):
    """Pure unit tests for PeerTable -- no sockets."""

    class FakeLink(object):
        def __init__(self, pubkey, addr="200::1"):
            self.remote_pubkey = pubkey
            self.remote_addr = addr
            self.closed = False
            self.link_type = "test"

        async def close(self):
            self.closed = True

    async def test_add_then_get(self):
        table = PeerTable()
        link = self.FakeLink(b"\x01" * 32)
        entry = table.add_peer(link)
        self.assertEqual(entry.port, 1)
        self.assertIs(table.get_peer(b"\x01" * 32), entry)
        self.assertEqual(len(table), 1)

    async def test_add_allocates_distinct_ports(self):
        table = PeerTable()
        e1 = table.add_peer(self.FakeLink(b"\x01" * 32))
        e2 = table.add_peer(self.FakeLink(b"\x02" * 32))
        e3 = table.add_peer(self.FakeLink(b"\x03" * 32))
        self.assertEqual([e1.port, e2.port, e3.port], [1, 2, 3])

    async def test_remove_frees_port(self):
        table = PeerTable()
        e1 = table.add_peer(self.FakeLink(b"\x01" * 32))
        e2 = table.add_peer(self.FakeLink(b"\x02" * 32))
        # Remove the first; next add should reuse port 1.
        self.assertTrue(table.remove_peer(b"\x01" * 32))
        e3 = table.add_peer(self.FakeLink(b"\x03" * 32))
        self.assertEqual(e3.port, 1)

    async def test_duplicate_pubkey_raises(self):
        table = PeerTable()
        table.add_peer(self.FakeLink(b"\x01" * 32))
        with self.assertRaises(DuplicatePeerError):
            table.add_peer(self.FakeLink(b"\x01" * 32))

    async def test_peers_iteration_order_is_added_at(self):
        table = PeerTable()
        for i in range(1, 6):
            table.add_peer(self.FakeLink(bytes([i]) * 32))
        peers = list(table.peers())
        self.assertEqual([p.added_at for p in peers], [1, 2, 3, 4, 5])


class TestBackoffCounter(AsyncTestCase):

    async def test_doubles_each_call(self):
        b = BackoffCounter()
        self.assertEqual(b.next_delay(), 1.0)
        self.assertEqual(b.next_delay(), 2.0)
        self.assertEqual(b.next_delay(), 4.0)
        self.assertEqual(b.next_delay(), 8.0)

    async def test_caps_at_max(self):
        b = BackoffCounter(max_seconds=10.0)
        b.next_delay()  # 1
        b.next_delay()  # 2
        b.next_delay()  # 4
        b.next_delay()  # 8
        self.assertEqual(b.next_delay(), 10.0)  # would be 16, clamped
        self.assertEqual(b.next_delay(), 10.0)  # still clamped

    async def test_reset(self):
        b = BackoffCounter()
        b.next_delay()
        b.next_delay()
        b.next_delay()
        b.reset()
        self.assertEqual(b.next_delay(), 1.0)


class TestParsePeerURI(AsyncTestCase):

    async def test_parses_valid_tcp_uri(self):
        scheme, host, port = parse_peer_uri("tcp://1.2.3.4:9001")
        self.assertEqual(scheme, "tcp")
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 9001)

    async def test_parses_ipv6_uri(self):
        scheme, host, port = parse_peer_uri("tcp://[2001:db8::1]:9001")
        self.assertEqual(scheme, "tcp")
        self.assertEqual(host, "2001:db8::1")
        self.assertEqual(port, 9001)

    async def test_accepts_tls_scheme(self):
        scheme, host, port = parse_peer_uri("tls://1.2.3.4:9001")
        self.assertEqual(scheme, "tls")
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 9001)

    async def test_rejects_non_tcp_non_tls_scheme(self):
        with self.assertRaises(ValueError):
            parse_peer_uri("https://example.com")
        with self.assertRaises(ValueError):
            parse_peer_uri("quic://1.2.3.4:9001")

    async def test_rejects_missing_port(self):
        with self.assertRaises(ValueError):
            parse_peer_uri("tcp://example.com")


class TestNodeCorePeering(AsyncTestCase):
    """Two NodeCores, dialer-listener, verify pubkey + addr exchange."""

    async def asyncSetUp(self):
        self.node_a = NodeCore(seed=os.urandom(32))
        self.node_b = NodeCore(seed=os.urandom(32))
        await self.node_a.start_listener(bind_addr="::1", port=0, af=IP6)
        await self.node_b.start_listener(bind_addr="::1", port=0, af=IP6)

    async def asyncTearDown(self):
        await self.node_a.close()
        await self.node_b.close()

    async def test_node_addresses_derive_from_pubkey(self):
        expected_a = ipv6_str_from_bytes(addr_for_key(self.node_a.public_key))
        expected_b = ipv6_str_from_bytes(addr_for_key(self.node_b.public_key))
        self.assertEqual(self.node_a.address, expected_a)
        self.assertEqual(self.node_b.address, expected_b)
        # Addresses must start with 200::/8 (node prefix).
        self.assertTrue(self.node_a.address.startswith("2"))
        self.assertTrue(self.node_b.address.startswith("2"))

    async def test_outbound_dial_creates_peer_entry_on_both_sides(self):
        # A dials B over loopback.  After a short wait the peer
        # table on each side should have the OTHER's pubkey.
        uri = "tcp://[::1]:{0}".format(self.node_b.listen_port)
        await self.node_a.add_peer_uri(uri)

        # Poll for up to a few seconds for the peering to come up.
        for _ in range(50):
            if (self.node_a.peers.get_peer(self.node_b.public_key) is not None
                    and self.node_b.peers.get_peer(self.node_a.public_key)
                    is not None):
                break
            await asyncio.sleep(0.1)
        self.assertIsNotNone(
            self.node_a.peers.get_peer(self.node_b.public_key),
            "node_a never registered node_b as a peer",
        )
        self.assertIsNotNone(
            self.node_b.peers.get_peer(self.node_a.public_key),
            "node_b never registered node_a as a peer",
        )

    async def test_packet_round_trip_via_peer_handler(self):
        # Install a packet_handler on each side that drops payloads
        # into a future the test can await.
        received_on_b = asyncio.Future()

        async def b_handler(link, packet_type, payload):
            if packet_type == WIRE_TRAFFIC and not received_on_b.done():
                received_on_b.set_result((packet_type, payload))

        self.node_b.packet_handler = b_handler

        uri = "tcp://[::1]:{0}".format(self.node_b.listen_port)
        await self.node_a.add_peer_uri(uri)
        # Wait for the peering to come up.
        for _ in range(50):
            entry_a = self.node_a.peers.get_peer(self.node_b.public_key)
            if entry_a is not None:
                break
            await asyncio.sleep(0.1)
        self.assertIsNotNone(entry_a)

        # Send a WIRE_TRAFFIC packet from A.
        await entry_a.link.send_packet(WIRE_TRAFFIC, b"hello b")
        ptype, payload = await asyncio.wait_for(received_on_b, timeout=5)
        self.assertEqual(ptype, WIRE_TRAFFIC)
        self.assertEqual(payload, b"hello b")


if __name__ == "__main__":
    unittest.main()
