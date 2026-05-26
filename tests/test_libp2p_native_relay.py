"""Circuit Relay v2 tests.

Unit coverage:
    * HopMessage RESERVE/CONNECT/STATUS round-trips
    * StopMessage CONNECT/STATUS round-trips
    * Reservation encode/decode

Integration coverage (the headline three-party flow):
    * Three Libp2pNode instances on real TCP loopback:
      RELAY in the middle, CLIENT-A and CLIENT-B as edge peers.
    * CLIENT-A dials RELAY and runs HOP RESERVE -- reserves a slot
      so CLIENT-B can reach A through the relay later.
    * CLIENT-B dials RELAY and runs HOP CONNECT(target=A_peer_id) --
      the relay opens a /stop stream to A, A accepts, the relay
      splices.  CLIENT-B now has a transparent stream to CLIENT-A.
    * CLIENT-B sends bytes through the spliced stream; A's
      relayed_inbound_streams queue surfaces them.
"""
import asyncio
import unittest

from aionetiface import IP4, Interface
from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.libp2p_native import circuit_relay as cr
from warpgate.traversal.plugins.libp2p_native import peer_id
from warpgate.traversal.plugins.libp2p_native.node_core import Libp2pNode


class TestHopMessageEncoding(unittest.TestCase):
    def test_reserve_round_trip(self):
        blob = cr.encode_hop_reserve()
        decoded = cr.decode_hop_message(blob)
        self.assertEqual(decoded["type"], cr.TYPE_RESERVE)

    def test_connect_round_trip(self):
        blob = cr.encode_hop_connect(b"\x00\x24\x08\x01\x12\x20" + b"\xaa" * 32)
        decoded = cr.decode_hop_message(blob)
        self.assertEqual(decoded["type"], cr.TYPE_CONNECT)
        pid, addrs = decoded["peer"]
        self.assertEqual(pid, b"\x00\x24\x08\x01\x12\x20" + b"\xaa" * 32)
        self.assertEqual(addrs, [])

    def test_status_with_reservation(self):
        reservation_blob = cr.encode_reservation(1700000000, [b"/maddr"], b"")
        limit_blob = cr.encode_limit(1800, 256 * 1024)
        blob = cr.encode_hop_status(cr.STATUS_OK, reservation_blob, limit_blob)
        decoded = cr.decode_hop_message(blob)
        self.assertEqual(decoded["type"], cr.TYPE_STATUS)
        self.assertEqual(decoded["status"], cr.STATUS_OK)
        expire, addrs, voucher = decoded["reservation"]
        self.assertEqual(expire, 1700000000)
        self.assertEqual(addrs, [b"/maddr"])
        self.assertEqual(voucher, b"")
        duration, data = decoded["limit"]
        self.assertEqual(duration, 1800)
        self.assertEqual(data, 256 * 1024)


class TestStopMessageEncoding(unittest.TestCase):
    def test_connect_round_trip(self):
        src_pid = b"\x00\x24\x08\x01\x12\x20" + b"\xcc" * 32
        blob = cr.encode_stop_connect(src_pid)
        decoded = cr.decode_stop_message(blob)
        self.assertEqual(decoded["type"], cr.STOP_TYPE_CONNECT)
        pid, addrs = decoded["peer"]
        self.assertEqual(pid, src_pid)

    def test_status_ok(self):
        blob = cr.encode_stop_status(cr.STATUS_OK)
        decoded = cr.decode_stop_message(blob)
        self.assertEqual(decoded["type"], cr.STOP_TYPE_STATUS)
        self.assertEqual(decoded["status"], cr.STATUS_OK)


class TestThreePartyRelay(AsyncTestCase):
    """Real-TCP three-party relay: A reserves on RELAY, B dials A via RELAY.

    Layout (all on 127/8 loopback, distinct IPs):

        127.0.0.1  RELAY (acts as Circuit Relay v2 service)
        127.0.0.2  CLIENT-A (reserves a slot on RELAY)
        127.0.0.3  CLIENT-B (dials A through RELAY)
    """

    async def asyncSetUp(self):
        self.iface = await Interface("default")
        self.id_relay = peer_id.Identity.generate()
        self.id_a = peer_id.Identity.generate()
        self.id_b = peer_id.Identity.generate()
        self.relay = Libp2pNode(self.id_relay)
        self.a = Libp2pNode(self.id_a)
        self.b = Libp2pNode(self.id_b)
        self.relay.enable_relay_service()

    async def asyncTearDown(self):
        await self.relay.close()
        await self.a.close()
        await self.b.close()

    async def open_session(self, dialer, target_node, target_ip, src_ip):
        """Helper: open a libp2p session from dialer to target_node."""
        bound_ip, bound_port = target_node.listen_multiaddrs and None, None
        # Already-running listener? Reuse.  Else start one.
        if not target_node.listen_pipes_started():
            bound_ip, bound_port = await target_node.listen(
                self.iface, IP4, ips=target_ip, port=0,
            )
        # NOTE: helper expects the target listener is set up by caller.
        raise NotImplementedError

    async def test_three_party_relayed_byte_exchange(self):
        # 1. RELAY listens on 127.0.0.1
        relay_ip, relay_port = await self.relay.listen(
            self.iface, IP4, ips="127.0.0.1", port=0,
        )

        # 2. CLIENT-A also listens (so RELAY can open /stop back to it
        # over A's outbound session -- we use A's existing session
        # to RELAY for that, no separate listen needed in practice,
        # but having one doesn't hurt).
        #
        # CLIENT-A dials RELAY from 127.0.0.2 source.
        route_a = await self.iface.route(IP4).bind(ips="127.0.0.2", port=0)
        a_to_relay_stream, _, a_to_relay_session = await self.a.dial(
            relay_ip, relay_port, route_a,
            expected_peer_id=self.id_relay.peer_id, timeout=10.0,
        )

        # 3. A asks RELAY to RESERVE a slot.
        reservation = await self.a.reserve_via_relay(
            a_to_relay_session, timeout=10.0,
        )
        self.assertTrue(reservation.expire > 0)
        # The relay should now have A in its reservation table.
        self.assertIn(
            self.id_a.peer_id, self.relay.relay_service.reservations,
        )

        # 4. CLIENT-B dials RELAY from 127.0.0.3.
        route_b = await self.iface.route(IP4).bind(ips="127.0.0.3", port=0)
        b_to_relay_stream, _, b_to_relay_session = await self.b.dial(
            relay_ip, relay_port, route_b,
            expected_peer_id=self.id_relay.peer_id, timeout=10.0,
        )

        # 5. B asks RELAY to CONNECT to A's peer_id.  We get back a
        # transparent stream that should forward bytes to A.
        relayed_to_a = await self.b.dial_via_relay(
            b_to_relay_session, self.id_a.peer_id, timeout=10.0,
        )

        # 6. On A's side, the RELAY opened a /stop stream.  A's
        # dispatcher accepts the /stop CONNECT and pushes the
        # resulting forwarded stream onto relayed_inbound_streams.
        a_relayed_stream, a_relayed_src, _ = await asyncio.wait_for(
            self.a.relayed_inbound_streams.get(), timeout=10.0,
        )
        self.assertEqual(a_relayed_src, self.id_b.peer_id)

        # 7. Byte exchange over the spliced path: B writes, A reads.
        await relayed_to_a.write(b"hello-via-relay")
        got_a = await asyncio.wait_for(a_relayed_stream.read(64), timeout=5.0)
        self.assertEqual(got_a, b"hello-via-relay")

        # And the reverse direction.
        await a_relayed_stream.write(b"reply-via-relay")
        got_b = await asyncio.wait_for(relayed_to_a.read(64), timeout=5.0)
        self.assertEqual(got_b, b"reply-via-relay")

        # Cleanup.
        await a_to_relay_stream.close()
        await b_to_relay_stream.close()
        await relayed_to_a.close()
        await a_relayed_stream.close()


if __name__ == "__main__":
    unittest.main()
