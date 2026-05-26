"""End-to-end test: two Libp2pNode instances on real TCP loopback
complete the full libp2p handshake and exchange application bytes.

Exercises every layer of the plugin together over a real aionetiface
Pipe (no in-memory shim): TCP listen + accept + connect -> PipeStream
-> multistream-select -> /plaintext/2.0.0 -> multistream-select ->
/yamux/1.0.0 -> yamux stream -> multistream-select ->
/warpgate/relay/1.0.0 -> application bytes through LibP2PPipeAdapter.

This is the test that proves the plugin is wireable to a real socket
on the same machine.  Cross-NIC validation happens against the Win10
VM (test_libp2p_native_two_nic.py).
"""
import asyncio
import unittest

from aionetiface import IP4, Interface
from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.libp2p_native.node_core import Libp2pNode
from warpgate.traversal.plugins.libp2p_native.peer_id import Identity
from warpgate.traversal.plugins.libp2p_native.pipe_adapter import LibP2PPipeAdapter


class TestLibp2pNativeLoopback(AsyncTestCase):
    """Two Libp2pNodes on the default loopback Interface complete the
    handshake; the dialer pumps bytes through and the listener echoes."""

    async def asyncSetUp(self):
        self.id_a = Identity.generate()
        self.id_b = Identity.generate()
        self.node_a = Libp2pNode(self.id_a)
        self.node_b = Libp2pNode(self.id_b)
        # Use the loopback Interface so both nodes share an address
        # family + can reach each other via 127.0.0.1 without
        # depending on the test environment having external NICs.
        self.iface = await Interface("default")

    async def asyncTearDown(self):
        await self.node_a.close()
        await self.node_b.close()

    async def test_handshake_and_byte_exchange(self):
        # A listens on loopback.
        bound_ip, bound_port = await self.node_a.listen(
            self.iface, IP4, ips="127.0.0.1", port=0,
        )
        self.assertEqual(bound_ip, "127.0.0.1")
        self.assertNotEqual(bound_port, 0)

        # B dials A.
        route = await self.iface.route(IP4).bind(ips="127.0.0.1", port=0)
        dial_task = asyncio.ensure_future(self.node_b.dial(
            bound_ip, bound_port, route,
            expected_peer_id=self.id_a.peer_id,
            timeout=10.0,
        ))
        # A waits for the inbound handshake to land.
        inbound_task = asyncio.ensure_future(asyncio.wait_for(
            self.node_a.inbound_streams.get(), timeout=10.0,
        ))

        b_stream, b_remote, b_session = await dial_task
        a_stream, a_remote, a_session = await inbound_task

        # PeerID handshake correctness.
        self.assertEqual(b_remote, self.id_a.peer_id)
        self.assertEqual(a_remote, self.id_b.peer_id)

        # Wrap each side in the Pipe adapter the cascade would return.
        adapter_b = LibP2PPipeAdapter(b_stream, b_session, b_remote)
        adapter_a = LibP2PPipeAdapter(a_stream, a_session, a_remote)

        # Byte exchange: B sends, A reads, A sends back, B reads.
        await adapter_b.send(b"hello-libp2p-from-B")
        msg_at_a = await asyncio.wait_for(adapter_a.recv(), timeout=5.0)
        self.assertEqual(msg_at_a, b"hello-libp2p-from-B")
        await adapter_a.send(b"reply-from-A")
        msg_at_b = await asyncio.wait_for(adapter_b.recv(), timeout=5.0)
        self.assertEqual(msg_at_b, b"reply-from-A")

        await adapter_b.close()
        await adapter_a.close()

    async def test_two_concurrent_dials_each_get_own_session(self):
        """Two separate dialers against one listener each complete their
        own handshake.  Catches accept-loop ordering bugs and proves
        the per-session sequence (multistream -> plaintext -> yamux
        -> app) is properly serialised per-connection."""
        bound_ip, bound_port = await self.node_a.listen(
            self.iface, IP4, ips="127.0.0.1", port=0,
        )

        id_c = Identity.generate()
        node_c = Libp2pNode(id_c)
        try:
            route_b = await self.iface.route(IP4).bind(ips="127.0.0.1", port=0)
            route_c = await self.iface.route(IP4).bind(ips="127.0.0.1", port=0)
            dial_b = asyncio.ensure_future(self.node_b.dial(
                bound_ip, bound_port, route_b,
                expected_peer_id=self.id_a.peer_id, timeout=10.0,
            ))
            dial_c = asyncio.ensure_future(node_c.dial(
                bound_ip, bound_port, route_c,
                expected_peer_id=self.id_a.peer_id, timeout=10.0,
            ))
            b_stream, b_remote, b_session = await dial_b
            c_stream, c_remote, c_session = await dial_c

            in1 = await asyncio.wait_for(self.node_a.inbound_streams.get(), timeout=5.0)
            in2 = await asyncio.wait_for(self.node_a.inbound_streams.get(), timeout=5.0)
            remote_pids_seen = {in1[1], in2[1]}
            self.assertEqual(
                remote_pids_seen, {self.id_b.peer_id, id_c.peer_id},
                "expected listener to see both B and C peer_ids",
            )
            await b_session.close()
            await c_session.close()
        finally:
            await node_c.close()


if __name__ == "__main__":
    unittest.main()
