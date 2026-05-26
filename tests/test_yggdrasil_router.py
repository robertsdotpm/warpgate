"""End-to-end test: NodeCore + Router actually decode + count Yggdrasil-shaped traffic."""
import asyncio
import os
import unittest

from aionetiface import IP6
from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.node_core import NodeCore
from warpgate.overlay.yggdrasil.router import Router
from warpgate.overlay.yggdrasil.routing_msgs import (
    BLOOM_FILTER_U,
    Bloom,
    PathBroken,
    RouterAnnounce,
    RouterSigReq,
    RouterSigRes,
    Traffic,
)
from warpgate.overlay.yggdrasil.wire import (
    WIRE_PROTO_ANNOUNCE,
    WIRE_PROTO_BLOOM_FILTER,
    WIRE_PROTO_PATH_BROKEN,
    WIRE_PROTO_SIG_REQ,
    WIRE_TRAFFIC,
)


class TestRouterDispatch(AsyncTestCase):

    async def asyncSetUp(self):
        self.node_a = NodeCore(seed=os.urandom(32))
        self.node_b = NodeCore(seed=os.urandom(32))
        self.router_b = Router(self.node_b)
        self.node_b.packet_handler = self.router_b.on_packet
        await self.node_a.start_listener(bind_addr="::1", port=0, af=IP6)
        await self.node_b.start_listener(bind_addr="::1", port=0, af=IP6)

    async def asyncTearDown(self):
        await self.node_a.close()
        await self.node_b.close()

    async def wait_for_peering(self):
        uri = "tcp://[::1]:{0}".format(self.node_b.listen_port)
        await self.node_a.add_peer_uri(uri)
        for _ in range(50):
            entry = self.node_a.peers.get_peer(self.node_b.public_key)
            if entry is not None:
                return entry
            await asyncio.sleep(0.1)
        self.fail("peering never came up")

    async def test_router_counts_sig_req(self):
        entry = await self.wait_for_peering()
        req = RouterSigReq(seq=10, nonce=11)
        await entry.link.send_packet(WIRE_PROTO_SIG_REQ, req.encode())
        for _ in range(20):
            if self.router_b.counters[WIRE_PROTO_SIG_REQ] > 0:
                break
            await asyncio.sleep(0.05)
        self.assertGreaterEqual(self.router_b.counters[WIRE_PROTO_SIG_REQ], 1)
        st = self.router_b.peer_state[self.node_a.public_key]
        self.assertIsNotNone(st["sig_req"])
        self.assertEqual(st["sig_req"].seq, 10)
        self.assertEqual(st["sig_req"].nonce, 11)

    async def test_router_counts_announce(self):
        entry = await self.wait_for_peering()
        ann = RouterAnnounce(
            key=self.node_a.public_key,
            parent=self.node_a.public_key,
            sig_res=RouterSigRes(seq=1, nonce=2, port=3, psig=b"\x00" * 64),
            sig=b"\x00" * 64,
        )
        await entry.link.send_packet(WIRE_PROTO_ANNOUNCE, ann.encode())
        for _ in range(20):
            if self.router_b.counters[WIRE_PROTO_ANNOUNCE] > 0:
                break
            await asyncio.sleep(0.05)
        self.assertGreaterEqual(self.router_b.counters[WIRE_PROTO_ANNOUNCE], 1)
        st = self.router_b.peer_state[self.node_a.public_key]
        self.assertIsNotNone(st["announce"])

    async def test_router_counts_bloom(self):
        entry = await self.wait_for_peering()
        b = Bloom(slots=[0] * BLOOM_FILTER_U)
        await entry.link.send_packet(WIRE_PROTO_BLOOM_FILTER, b.encode())
        for _ in range(20):
            if self.router_b.counters[WIRE_PROTO_BLOOM_FILTER] > 0:
                break
            await asyncio.sleep(0.05)
        self.assertGreaterEqual(self.router_b.counters[WIRE_PROTO_BLOOM_FILTER], 1)
        st = self.router_b.peer_state[self.node_a.public_key]
        self.assertIsNotNone(st["bloom"])

    async def test_router_counts_path_broken(self):
        entry = await self.wait_for_peering()
        msg = PathBroken(path=[1, 2], watermark=99,
                         source=self.node_a.public_key,
                         dest=self.node_b.public_key)
        await entry.link.send_packet(WIRE_PROTO_PATH_BROKEN, msg.encode())
        for _ in range(20):
            if self.router_b.counters[WIRE_PROTO_PATH_BROKEN] > 0:
                break
            await asyncio.sleep(0.05)
        self.assertGreaterEqual(self.router_b.counters[WIRE_PROTO_PATH_BROKEN], 1)

    async def test_router_counts_traffic(self):
        entry = await self.wait_for_peering()
        tr = Traffic(path=[], from_path=[], source=self.node_a.public_key,
                     dest=self.node_b.public_key, watermark=0,
                     payload=b"hello router")
        await entry.link.send_packet(WIRE_TRAFFIC, tr.encode())
        for _ in range(20):
            if self.router_b.counters[WIRE_TRAFFIC] > 0:
                break
            await asyncio.sleep(0.05)
        self.assertGreaterEqual(self.router_b.counters[WIRE_TRAFFIC], 1)
        self.assertEqual(self.router_b.last_traffic_source, self.node_a.public_key)
        self.assertEqual(self.router_b.last_traffic_dest, self.node_b.public_key)

    async def test_router_handles_bad_payload_gracefully(self):
        entry = await self.wait_for_peering()
        # Send a malformed announce (too short).  Router should
        # log and continue -- the link must stay open.
        await entry.link.send_packet(WIRE_PROTO_ANNOUNCE, b"\x00\x01")
        await asyncio.sleep(0.2)
        # The link is still up; we can send something valid next.
        await entry.link.send_packet(
            WIRE_PROTO_SIG_REQ, RouterSigReq(seq=1, nonce=1).encode(),
        )
        for _ in range(20):
            if self.router_b.counters[WIRE_PROTO_SIG_REQ] > 0:
                break
            await asyncio.sleep(0.05)
        self.assertGreaterEqual(self.router_b.counters[WIRE_PROTO_SIG_REQ], 1)


if __name__ == "__main__":
    unittest.main()
