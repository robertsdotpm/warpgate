"""AutoNAT + AutoRelay + Bootstrap tests.

Unit coverage:
    * AutoNAT Message protobuf round-trips (DIAL, DIAL_RESPONSE)
    * AutoRelay multiaddr composition (relay_addr -> circuit form)
    * Bootstrap parses multiaddr strings + skips invalid ones

Integration:
    * Two Libp2pNode instances: A is a HOP-capable relay, B
      dials A and AutoRelay's ``consider()`` discovers A as a
      relay candidate via Identify, runs a HOP RESERVE, and
      appends a /p2p-circuit multiaddr to B's listen list.
    * AutoNAT round-trip: B asks A to dial-back, A's dialer is
      a synthetic stub that returns True for the announced addr;
      B receives STATUS_OK + the successful addr.
"""
import asyncio
import unittest

from aionetiface import IP4, Interface
from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.libp2p_native import (
    autonat as autonat_mod,
    autorelay as autorelay_mod,
    bootstrap as bootstrap_mod,
    multiaddr as ma,
    peer_id,
)
from warpgate.traversal.plugins.libp2p_native.node_core import Libp2pNode


class TestAutoNATEncoding(unittest.TestCase):
    def test_dial_request_round_trip(self):
        pid = b"\x00" * 32 + b"\x01"
        addrs = [ma.encode_ip_tcp("127.0.0.1", 4001)]
        blob = autonat_mod.encode_dial_request(pid, addrs)
        msg = autonat_mod.decode_message(blob)
        self.assertEqual(msg["type"], autonat_mod.TYPE_DIAL)
        out_pid, out_addrs = msg["dial_peer"]
        self.assertEqual(out_pid, pid)
        self.assertEqual(out_addrs, addrs)

    def test_response_ok(self):
        addr = ma.encode_ip_tcp("203.0.113.7", 50001)
        blob = autonat_mod.encode_dial_response(
            autonat_mod.STATUS_OK, "", addr,
        )
        msg = autonat_mod.decode_message(blob)
        self.assertEqual(msg["type"], autonat_mod.TYPE_DIAL_RESPONSE)
        self.assertEqual(msg["response"]["status"], autonat_mod.STATUS_OK)
        self.assertEqual(msg["response"]["addr"], addr)

    def test_response_error_with_text(self):
        blob = autonat_mod.encode_dial_response(
            autonat_mod.STATUS_DIAL_ERROR, "connection refused",
        )
        msg = autonat_mod.decode_message(blob)
        self.assertEqual(msg["response"]["status"], autonat_mod.STATUS_DIAL_ERROR)
        self.assertEqual(msg["response"]["status_text"], "connection refused")


class TestAutoRelayMultiaddr(AsyncTestCase):
    """Libp2pNode's __init__ allocates an asyncio.Queue, which on
    Python 3.8+ requires a running event loop; these tests run
    under AsyncTestCase so the loop is established for us."""

    async def test_build_relayed_addr(self):
        ident = peer_id.Identity.from_seed(b"\x42" * 32)
        node = Libp2pNode(ident)
        ar = autorelay_mod.AutoRelay(node)
        relay_pid = peer_id.Identity.from_seed(b"\x99" * 32).peer_id
        relay_addr = (
            ma.encode_ip_tcp("198.51.100.5", 4001)
            + ma.encode_p2p(relay_pid)
        )
        relayed = ar.build_relayed_addr(relay_addr)
        self.assertIsNotNone(relayed)
        parts = ma.decode(relayed)
        # Expect: ip4, tcp, p2p(relay), p2p-circuit, p2p(our).
        codes = [c for c, _ in parts]
        self.assertEqual(codes, [
            ma.CODE_IP4, ma.CODE_TCP, ma.CODE_P2P,
            ma.CODE_P2P_CIRCUIT, ma.CODE_P2P,
        ])
        self.assertTrue(ma.contains_circuit(parts))

    async def test_build_appends_relay_peer_id_when_missing(self):
        ident = peer_id.Identity.from_seed(b"\x42" * 32)
        node = Libp2pNode(ident)
        ar = autorelay_mod.AutoRelay(node)
        relay_pid = peer_id.Identity.from_seed(b"\x88" * 32).peer_id
        addr_without_pid = ma.encode_ip_tcp("198.51.100.5", 4001)
        # Without relay_peer_id supplied: can't compose.
        self.assertIsNone(ar.build_relayed_addr(addr_without_pid))
        # With relay_peer_id supplied: the helper splices it in.
        relayed = ar.build_relayed_addr(addr_without_pid, relay_peer_id=relay_pid)
        self.assertIsNotNone(relayed)
        parts = ma.decode(relayed)
        codes = [c for c, _ in parts]
        self.assertEqual(codes, [
            ma.CODE_IP4, ma.CODE_TCP, ma.CODE_P2P,
            ma.CODE_P2P_CIRCUIT, ma.CODE_P2P,
        ])


class TestBootstrapParsing(unittest.TestCase):
    def test_get_addrs_returns_defaults_by_default(self):
        import os
        env = os.environ.pop("WARPGATE_LIBP2P_BOOTSTRAP", None)
        try:
            addrs = bootstrap_mod.get_bootstrap_addrs()
            self.assertGreater(len(addrs), 0)
        finally:
            if env is not None:
                os.environ["WARPGATE_LIBP2P_BOOTSTRAP"] = env

    def test_env_override(self):
        import os
        env_before = os.environ.get("WARPGATE_LIBP2P_BOOTSTRAP")
        try:
            os.environ["WARPGATE_LIBP2P_BOOTSTRAP"] = (
                "/ip4/1.2.3.4/tcp/4001 /ip6/::1/tcp/9001"
            )
            addrs = bootstrap_mod.get_bootstrap_addrs()
            self.assertEqual(addrs, [
                "/ip4/1.2.3.4/tcp/4001",
                "/ip6/::1/tcp/9001",
            ])
        finally:
            if env_before is None:
                os.environ.pop("WARPGATE_LIBP2P_BOOTSTRAP", None)
            else:
                os.environ["WARPGATE_LIBP2P_BOOTSTRAP"] = env_before


class TestAutoNATEndToEnd(AsyncTestCase):
    """Real-TCP AutoNAT exchange between two Libp2pNode instances."""

    async def asyncSetUp(self):
        self.iface = await Interface("default")
        self.id_a = peer_id.Identity.generate()
        self.id_b = peer_id.Identity.generate()
        self.a = Libp2pNode(self.id_a)
        self.b = Libp2pNode(self.id_b)

        # A is the AutoNAT server: install a synthetic dialer that
        # claims success for any addr whose decoded multiaddr
        # matches the announced (127.0.0.x, port) pair from B.
        async def stub_dialer(addr_bytes, expected_peer_id):
            try:
                parts = ma.decode(addr_bytes)
            except Exception:
                return False
            ip, port = ma.extract_first_ip_tcp(parts)
            # Accept anything in 127.0.0.0/8 for the test (real
            # AutoNAT would refuse private IPs to avoid being used
            # as a port-scanner, but for the smoke test of the
            # wire protocol that's the point under test).
            return bool(ip and ip.startswith("127.") and port)

        self.a.set_autonat_dialer(stub_dialer)

    async def asyncTearDown(self):
        await self.a.close()
        await self.b.close()

    async def test_autonat_request_succeeds_for_reachable_addr(self):
        from warpgate.traversal.plugins.libp2p_native.multistream import negotiate_initiator
        a_ip, a_port = await self.a.listen(
            self.iface, IP4, ips="127.0.0.1", port=0,
        )
        route_b = await self.iface.route(IP4).bind(ips="127.0.0.2", port=0)
        _, _, session_b = await self.b.dial(
            a_ip, a_port, route_b,
            expected_peer_id=self.id_a.peer_id, timeout=10.0,
        )
        # B opens a fresh stream to A + multistream-selects /autonat
        # + requests a dial-back.
        stream = await session_b.mux_session.open_stream()
        chosen = await negotiate_initiator(
            stream, stream, [autonat_mod.AUTONAT_PROTOCOL],
        )
        self.assertEqual(chosen, autonat_mod.AUTONAT_PROTOCOL)
        b_announce_addr = ma.encode_ip_tcp("127.0.0.99", 9999)
        response = await autonat_mod.client_request_dial(
            stream, self.id_b.peer_id, [b_announce_addr], timeout=10.0,
        )
        await stream.close()
        self.assertEqual(response["status"], autonat_mod.STATUS_OK)
        self.assertEqual(response["addr"], b_announce_addr)


class TestAutoRelayEndToEnd(AsyncTestCase):
    """B's AutoRelay finds A as a HOP-capable relay and reserves a slot."""

    async def asyncSetUp(self):
        self.iface = await Interface("default")
        self.id_a = peer_id.Identity.generate()
        self.id_b = peer_id.Identity.generate()
        self.a = Libp2pNode(self.id_a)
        self.b = Libp2pNode(self.id_b)
        self.a.enable_relay_service()
        self.b.enable_autorelay(max_relays=1)

    async def asyncTearDown(self):
        await self.a.close()
        await self.b.close()

    async def test_autorelay_picks_up_hop_capable_peer(self):
        a_ip, a_port = await self.a.listen(
            self.iface, IP4, ips="127.0.0.1", port=0,
        )
        route_b = await self.iface.route(IP4).bind(ips="127.0.0.2", port=0)
        _, _, session = await self.b.dial(
            a_ip, a_port, route_b,
            expected_peer_id=self.id_a.peer_id, timeout=10.0,
        )
        # Wait for AutoRelay's consider() task that was kicked off
        # by on_session_established to complete.
        for t in list(self.b.autorelay.tasks):
            try:
                await asyncio.wait_for(t, timeout=10.0)
            except (asyncio.TimeoutError, Exception):
                pass
        self.assertIn(
            self.id_a.peer_id,
            self.b.autorelay.active_reservations,
            "AutoRelay didn't reserve on the HOP-capable peer",
        )
        # B should now advertise a /p2p-circuit multiaddr for itself
        # through A.
        any_circuit = False
        for la in self.b.listen_multiaddrs:
            try:
                if ma.contains_circuit(ma.decode(la)):
                    any_circuit = True
                    break
            except Exception:
                continue
        self.assertTrue(
            any_circuit,
            "B's listen_multiaddrs missing a /p2p-circuit entry",
        )


if __name__ == "__main__":
    unittest.main()
