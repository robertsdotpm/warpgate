"""End-to-end peer link tests.

Spins up two aionetiface Pipes connected over IPv6 loopback (``::1``),
runs the Yggdrasil handshake from both sides concurrently, then
exchanges WIRE_KEEP_ALIVE + WIRE_TRAFFIC packets and verifies
byte-for-byte that what one side sends is what the other side
receives.

These tests are "heavy" by the warpgate convention -- each test
spins up real sockets -- so the class lives in its own
``test_yggdrasil_peer_link.py`` file per
``aionetiface/CLAUDE.md`` heavy-tests-live-in-their-own-file rule.
"""
import asyncio
import os
import unittest

from aionetiface import IP6, TCP, Pipe, Interface
from aionetiface.testing import AsyncTestCase
from ecdsa import SigningKey, Ed25519

from warpgate.overlay.yggdrasil.address import addr_for_key, ipv6_str_from_bytes
from warpgate.overlay.yggdrasil.peer_link import (
    HANDSHAKE_DEADLINE_SECONDS,
    LinkToSelf,
    PeerLink,
    handshake_over_pipe,
    open_inbound,
    open_outbound,
)
from warpgate.overlay.yggdrasil.version import HandshakeError
from warpgate.overlay.yggdrasil.wire import (
    WIRE_KEEP_ALIVE,
    WIRE_TRAFFIC,
    WIRE_PROTO_ANNOUNCE,
)


def fresh_keypair():
    """Return a fresh (seed, pubkey) tuple."""
    seed = os.urandom(32)
    sk = SigningKey.from_string(seed, curve=Ed25519)
    pub = sk.verifying_key.to_string()
    return seed, pub


async def make_loopback_pair():
    """Spin up a TCP listener on ::1, dial it, return (client_pipe, server_pipe).

    Both pipes are fully connected; ready for handshake_over_pipe.
    Uses the default Interface so socket_factory binds locally with
    no NIC pinning -- matches what most simple loopback tests do.
    """
    iface = Interface("default")
    route = await iface.route(IP6).bind(ips="::1", port=0)
    listener = Pipe(TCP, dest=None, route=route)
    await listener.connect()
    bound_port = listener.sock.getsockname()[1]

    # Accept-side future fires when the first inbound TCP client lands.
    accept_task = asyncio.ensure_future(listener.accept())

    client_route = await iface.route(IP6).bind(ips="::1", port=0)
    client = Pipe(TCP, dest=("::1", bound_port), route=client_route)
    await client.connect()

    server_pipe = await asyncio.wait_for(accept_task, timeout=5)
    return client, server_pipe, listener


class TestPeerLinkHandshake(AsyncTestCase):
    """Both sides drive the handshake; verify peer pubkey + version."""

    async def test_concurrent_handshake_succeeds(self):
        seed_a, pub_a = fresh_keypair()
        seed_b, pub_b = fresh_keypair()
        client, server, listener = await make_loopback_pair()
        try:
            # Both sides run handshake_over_pipe concurrently --
            # mirroring how real peers behave (both write first,
            # then read; deadline applies symmetrically).
            a_task = asyncio.ensure_future(handshake_over_pipe(
                client, seed_a, pub_a, password=b"",
            ))
            b_task = asyncio.ensure_future(handshake_over_pipe(
                server, seed_b, pub_b, password=b"",
            ))
            (remote_meta_a, leftover_a), (remote_meta_b, leftover_b) = \
                await asyncio.gather(a_task, b_task)
            self.assertEqual(remote_meta_a.public_key, pub_b)
            self.assertEqual(remote_meta_b.public_key, pub_a)
            self.assertEqual(remote_meta_a.major_ver, 0)
            self.assertEqual(remote_meta_a.minor_ver, 5)
        finally:
            await client.close()
            await server.close()
            await listener.close()

    async def test_handshake_with_password(self):
        seed_a, pub_a = fresh_keypair()
        seed_b, pub_b = fresh_keypair()
        client, server, listener = await make_loopback_pair()
        try:
            a_task = asyncio.ensure_future(handshake_over_pipe(
                client, seed_a, pub_a, password=b"shared_password",
            ))
            b_task = asyncio.ensure_future(handshake_over_pipe(
                server, seed_b, pub_b, password=b"shared_password",
            ))
            await asyncio.gather(a_task, b_task)
        finally:
            await client.close()
            await server.close()
            await listener.close()

    async def test_handshake_with_mismatched_password_fails(self):
        seed_a, pub_a = fresh_keypair()
        seed_b, pub_b = fresh_keypair()
        client, server, listener = await make_loopback_pair()
        try:
            a_task = asyncio.ensure_future(handshake_over_pipe(
                client, seed_a, pub_a, password=b"correct",
            ))
            b_task = asyncio.ensure_future(handshake_over_pipe(
                server, seed_b, pub_b, password=b"wrong",
            ))
            with self.assertRaises(HandshakeError):
                await asyncio.gather(a_task, b_task)
        finally:
            await client.close()
            await server.close()
            await listener.close()

    async def test_handshake_self_connect_rejects(self):
        seed_a, pub_a = fresh_keypair()
        client, server, listener = await make_loopback_pair()
        try:
            # Both sides use the SAME keypair -- self-connect case.
            a_task = asyncio.ensure_future(handshake_over_pipe(
                client, seed_a, pub_a,
            ))
            b_task = asyncio.ensure_future(handshake_over_pipe(
                server, seed_a, pub_a,
            ))
            with self.assertRaises(LinkToSelf):
                await asyncio.gather(a_task, b_task)
        finally:
            await client.close()
            await server.close()
            await listener.close()


class TestPeerLinkPackets(AsyncTestCase):
    """After handshake, verify packet send/recv roundtrips for the wire types."""

    async def asyncSetUp(self):
        self.seed_a, self.pub_a = fresh_keypair()
        self.seed_b, self.pub_b = fresh_keypair()
        self.client, self.server, self.listener = await make_loopback_pair()
        a_task = asyncio.ensure_future(handshake_over_pipe(
            self.client, self.seed_a, self.pub_a,
        ))
        b_task = asyncio.ensure_future(handshake_over_pipe(
            self.server, self.seed_b, self.pub_b,
        ))
        (meta_remote_to_a, leftover_a), (meta_remote_to_b, leftover_b) = \
            await asyncio.gather(a_task, b_task)
        self.link_a = PeerLink(self.client, meta_remote_to_a,
                               self.pub_a, "outbound")
        self.link_b = PeerLink(self.server, meta_remote_to_b,
                               self.pub_b, "inbound")
        if leftover_a:
            self.link_a.parser.feed(leftover_a)
        if leftover_b:
            self.link_b.parser.feed(leftover_b)
        self.link_a.install_msg_cb()
        self.link_b.install_msg_cb()

    async def asyncTearDown(self):
        await self.link_a.close()
        await self.link_b.close()
        await self.listener.close()

    async def test_remote_addr_is_derived_from_pubkey(self):
        expected_a_on_b = ipv6_str_from_bytes(addr_for_key(self.pub_a))
        expected_b_on_a = ipv6_str_from_bytes(addr_for_key(self.pub_b))
        self.assertEqual(self.link_b.remote_addr, expected_a_on_b)
        self.assertEqual(self.link_a.remote_addr, expected_b_on_a)

    async def test_send_and_recv_keepalive(self):
        await self.link_a.send_packet(WIRE_KEEP_ALIVE, b"")
        ptype, payload = await self.link_b.recv_packet()
        self.assertEqual(ptype, WIRE_KEEP_ALIVE)
        self.assertEqual(payload, b"")

    async def test_send_and_recv_traffic_payload(self):
        body = b"\xde\xad\xbe\xef" * 16
        await self.link_a.send_packet(WIRE_TRAFFIC, body)
        ptype, payload = await self.link_b.recv_packet()
        self.assertEqual(ptype, WIRE_TRAFFIC)
        self.assertEqual(payload, body)

    async def test_send_multiple_back_to_back(self):
        payloads = [bytes([i]) * (i + 1) for i in range(5)]
        for body in payloads:
            await self.link_a.send_packet(WIRE_PROTO_ANNOUNCE, body)
        for body in payloads:
            ptype, payload = await self.link_b.recv_packet()
            self.assertEqual(ptype, WIRE_PROTO_ANNOUNCE)
            self.assertEqual(payload, body)

    async def test_send_oversize_rejected(self):
        with self.assertRaises(ValueError):
            await self.link_a.send_packet(
                WIRE_TRAFFIC, b"\x00" * (1 << 21),  # 2 MiB > 1 MiB cap
            )

    async def test_bytecounter_advances_on_send(self):
        before = self.link_a.tx_bytes
        await self.link_a.send_packet(WIRE_KEEP_ALIVE, b"")
        self.assertGreater(self.link_a.tx_bytes, before)

    async def test_close_is_idempotent(self):
        await self.link_a.close()
        await self.link_a.close()  # must not raise


if __name__ == "__main__":
    unittest.main()
