"""Identify protocol tests.

Unit coverage:
    * Identify protobuf round-trips (encode -> decode -> equal)
    * Empty-optional-fields tolerated
    * Multiple listenAddrs preserved in order
    * Multiple protocols preserved

Integration coverage:
    * Two Libp2pNode instances complete the libp2p handshake on real
      TCP loopback; the dialer then opens a fresh yamux stream and
      runs ``/ipfs/id/1.0.0`` against the responder.  Result must
      contain the responder's pubkey, listen multiaddr, and the
      protocols it advertises (/warpgate/relay/1.0.0 + /ipfs/id/1.0.0).
"""
import asyncio
import unittest

from aionetiface import IP4, Interface
from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.libp2p_native import identify as identify_mod
from warpgate.traversal.plugins.libp2p_native import multiaddr, peer_id
from warpgate.traversal.plugins.libp2p_native.node_core import (
    Libp2pNode, APP_PROTOCOL, IDENTIFY_PROTOCOL,
)
from warpgate.traversal.plugins.libp2p_native.pipe_adapter import LibP2PPipeAdapter


class TestIdentifyEncoding(unittest.TestCase):
    def test_round_trip(self):
        ident = peer_id.Identity.from_seed(b"\xee" * 32)
        listen_ma1 = multiaddr.encode_ip_tcp("127.0.0.1", 4001)
        listen_ma2 = multiaddr.encode_ip_tcp("10.0.0.5", 4002)
        protos = ["/warpgate/relay/1.0.0", "/ipfs/id/1.0.0"]
        blob = identify_mod.encode_identify(
            public_key_marshalled=ident.pubkey_marshalled,
            listen_addrs_bytes=[listen_ma1, listen_ma2],
            protocols=protos,
            observed_addr_bytes=multiaddr.encode_ip_tcp("203.0.113.5", 50001),
        )
        result = identify_mod.decode_identify(blob)
        self.assertEqual(result.public_key, ident.pubkey_marshalled)
        self.assertEqual(result.listen_addrs, [listen_ma1, listen_ma2])
        self.assertEqual(set(result.protocols), set(protos))
        self.assertTrue(result.protocol_version.startswith("warpgate-libp2p"))
        self.assertTrue(result.agent_version.startswith("warpgate-libp2p-native"))

    def test_empty_optionals_tolerated(self):
        blob = identify_mod.encode_identify(
            public_key_marshalled=b"",
            listen_addrs_bytes=[],
            protocols=[],
            observed_addr_bytes=b"",
        )
        result = identify_mod.decode_identify(blob)
        self.assertEqual(result.public_key, b"")
        self.assertEqual(result.listen_addrs, [])
        self.assertEqual(result.protocols, [])
        self.assertEqual(result.observed_addr, b"")


class TestIdentifyEndToEnd(AsyncTestCase):
    """Real-TCP Identify exchange between two Libp2pNode instances."""

    async def asyncSetUp(self):
        self.id_a = peer_id.Identity.generate()
        self.id_b = peer_id.Identity.generate()
        self.node_a = Libp2pNode(self.id_a)
        self.node_b = Libp2pNode(self.id_b)
        self.iface = await Interface("default")

    async def asyncTearDown(self):
        await self.node_a.close()
        await self.node_b.close()

    async def test_dialer_queries_listener_identify(self):
        bound_ip, bound_port = await self.node_a.listen(
            self.iface, IP4, ips="127.0.0.1", port=0,
        )
        route = await self.iface.route(IP4).bind(ips="127.0.0.1", port=0)
        dial_task = asyncio.ensure_future(self.node_b.dial(
            bound_ip, bound_port, route,
            expected_peer_id=self.id_a.peer_id, timeout=10.0,
        ))
        inbound_task = asyncio.ensure_future(asyncio.wait_for(
            self.node_a.inbound_streams.get(), timeout=10.0,
        ))
        b_stream, b_remote, b_session = await dial_task
        a_stream, a_remote, a_session = await inbound_task

        # Run identify against the listener (node_a).
        result = await asyncio.wait_for(
            self.node_b.query_identify(b_session), timeout=10.0,
        )
        self.assertEqual(result.public_key, self.id_a.pubkey_marshalled)
        self.assertIn(APP_PROTOCOL, result.protocols)
        self.assertIn(IDENTIFY_PROTOCOL, result.protocols)
        # Listener advertised its 127.0.0.1:bound_port multiaddr.
        expected_ma = multiaddr.encode_ip_tcp("127.0.0.1", bound_port)
        self.assertIn(expected_ma, result.listen_addrs)
        # And it should be cached on the session for subsequent reads.
        self.assertIs(b_session.last_identify, result)

        # Drop adapters cleanly.
        ad_a = LibP2PPipeAdapter(a_stream, a_session, a_remote)
        ad_b = LibP2PPipeAdapter(b_stream, b_session, b_remote)
        await ad_a.close()
        await ad_b.close()


if __name__ == "__main__":
    unittest.main()
