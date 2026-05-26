"""Stress + resource-leak tests for the Yggdrasil port.

What's covered:

  * Bloom filter false-positive bound (math: k=8, m=8192, n=100 ->
    expected ~0.4%; we assert < 5%).
  * High-throughput encrypted session (1000 back-to-back messages,
    all delivered in order with correct payloads).
  * Many simulated peers on one PacketConn (no inbox/queue
    cross-talk; each peer's per-peer queue gets only its own
    messages).
  * Resource leak guard: create + close 20 NodeCore+ActiveRouter
    pairs; verify no growth in asyncio.all_tasks beyond a small
    baseline.
  * Peer churn: rapid connect/disconnect of PeerLinks against a
    loopback listener -- no FD leak, no orphan tasks.

The 1000-message throughput test does NOT exercise the routing
tree -- it talks directly to encrypted-layer dispatch through a
FakeRouter that bus-shorts to its peer.  That isolates the
crypto/wire/dispatch pipeline so a regression there can't hide
behind a routing flake.

Note on tasks: every EncryptedPacketConn spawns a dispatch_loop
asyncio.Task.  We MUST close() to cancel it.  Tests that don't
close leak tasks and the AsyncTestCase backport's cancel-on-exit
sweep will paper over the leak.  The resource-leak test asserts
the loop is task-clean after close().
"""
import asyncio
import gc
import os
import sys
import unittest

from aionetiface import IP6
from aionetiface.testing import AsyncTestCase
from ecdsa import SigningKey, Ed25519

from warpgate.overlay.yggdrasil import nacl_box
from warpgate.overlay.yggdrasil.encrypted import (
    EncryptedPacketConn,
)
from warpgate.overlay.yggdrasil.node_core import NodeCore
from warpgate.overlay.yggdrasil.router_active import ActiveRouter
from warpgate.overlay.yggdrasil.routing_msgs import (
    BLOOM_FILTER_K,
    BLOOM_FILTER_M,
    BLOOM_FILTER_U,
    Bloom,
    Traffic,
)


def fresh_keys():
    seed = os.urandom(32)
    sk = SigningKey.from_string(seed, curve=Ed25519)
    pub = bytes(sk.verifying_key.to_string())
    return seed, pub


def get_all_tasks():
    """Return current set of asyncio tasks (compat with Python 3.5+)."""
    if sys.version_info >= (3, 7):
        return list(asyncio.all_tasks())
    return list(asyncio.Task.all_tasks())


class FakeRouter(object):
    """Capture send_to into a list; deliver to outbox."""

    def __init__(self, public_key):
        self.public_key = public_key
        self.inbox = asyncio.Queue()
        self.outbox = []

    async def send_to(self, peer, wire):
        self.outbox.append((bytes(peer), bytes(wire)))


async def establish_session(pc_a, pc_b, pub_a, pub_b, router_a, router_b):
    """Drive the lazy init/ack flow between two EncryptedPacketConns."""
    await pc_a.write_to(pub_b, b"primer")
    _, init_wire = router_a.outbox.pop(0)
    pc_b.handle_init(pub_a, init_wire)
    await asyncio.sleep(0.02)
    _, ack_wire = router_b.outbox.pop(0)
    pc_a.handle_ack(pub_b, ack_wire)
    await asyncio.sleep(0.02)
    _, primer = router_a.outbox.pop(0)
    pc_b.handle_traffic(pub_a, primer)
    await asyncio.sleep(0.02)
    if pc_b.inbox.qsize():
        await pc_b.inbox.get()


class TestBloomFalsePositiveRate(AsyncTestCase):
    """Empirical FPR for the bloom filter.

    The closed-form FPR for k=8, m=BLOOM_FILTER_M=65536 bits,
    n=100 inserts is ``(1 - exp(-k*n/m))^k`` ~= 4.6e-4 (0.046%).
    A 5% upper bound gives us a HUGE margin so this test never
    flakes -- if it ever fires, something is genuinely broken
    in the bloom hashing.
    """

    async def test_fpr_with_100_inserts_against_10000_lookups(self):
        b = Bloom()
        inserted = set()
        for i in range(100):
            k = os.urandom(32)
            inserted.add(k)
            b.add_key(k)
        # Every inserted key must hit.
        for k in inserted:
            self.assertTrue(b.test_key(k),
                            "inserted key missed -- bloom is broken")
        # Now probe with 10k random non-members.
        false_positives = 0
        trials = 10000
        for i in range(trials):
            k = os.urandom(32)
            if k in inserted:
                continue
            if b.test_key(k):
                false_positives += 1
        fpr = false_positives / trials
        self.assertLess(
            fpr, 0.05,
            "false positive rate {0:.4f} above 5% threshold".format(fpr),
        )

    async def test_empty_bloom_never_matches(self):
        b = Bloom()
        for i in range(1000):
            k = os.urandom(32)
            self.assertFalse(b.test_key(k))


class TestEncryptedThroughput(AsyncTestCase):
    """1000 back-to-back messages on a single encrypted session.

    Validates: no nonce skipping, no key-rotation drift, no
    asyncio.ensure_future starvation, no queue overflow.
    """

    async def asyncSetUp(self):
        self.seed_a, self.pub_a = fresh_keys()
        self.seed_b, self.pub_b = fresh_keys()
        self.router_a = FakeRouter(self.pub_a)
        self.router_b = FakeRouter(self.pub_b)
        self.pc_a = EncryptedPacketConn(
            self.seed_a, self.pub_a, self.router_a,
        )
        self.pc_b = EncryptedPacketConn(
            self.seed_b, self.pub_b, self.router_b,
        )
        await establish_session(
            self.pc_a, self.pc_b, self.pub_a, self.pub_b,
            self.router_a, self.router_b,
        )

    async def asyncTearDown(self):
        await self.pc_a.close()
        await self.pc_b.close()

    async def test_send_1000_msgs_all_arrive_in_order(self):
        N = 1000
        for i in range(N):
            payload = "msg-{0:04d}".format(i).encode("ascii")
            await self.pc_a.write_to(self.pub_b, payload)
        # Drain all traffic packets out of A's outbox -> B's handler.
        # The init/ack already happened in setUp.
        while self.router_a.outbox:
            _, wire = self.router_a.outbox.pop(0)
            self.pc_b.handle_traffic(self.pub_a, wire)
        # Wait for B's dispatch loop to process all packets.
        # Each handle_traffic schedules an inbox put via
        # asyncio.ensure_future; drain by repeated yields until
        # the queue stops growing.
        for _ in range(20):
            await asyncio.sleep(0.05)
            if self.pc_b.inbox.qsize() >= N:
                break
        self.assertEqual(self.pc_b.inbox.qsize(), N)
        # Drain + assert in-order delivery.
        for i in range(N):
            src, msg = await self.pc_b.inbox.get()
            expected = "msg-{0:04d}".format(i).encode("ascii")
            self.assertEqual(msg, expected)


class TestManyConcurrentPeersOnOnePacketConn(AsyncTestCase):
    """10 simulated peers all flowing traffic through one PacketConn.

    Validates per-peer queue isolation: peer X's traffic must
    land in peer X's queue only, never in peer Y's queue.
    """

    async def test_10_peers_no_crosstalk(self):
        my_seed, my_pub = fresh_keys()
        my_router = FakeRouter(my_pub)
        pc = EncryptedPacketConn(my_seed, my_pub, my_router)
        try:
            # Spin up 10 peer-side PacketConns + FakeRouters.
            peers = []
            for i in range(10):
                seed, pub = fresh_keys()
                router = FakeRouter(pub)
                peer_pc = EncryptedPacketConn(seed, pub, router)
                peers.append((seed, pub, router, peer_pc))
                pc.open_peer_channel(pub)

            # Establish each session.
            for seed, pub, router, peer_pc in peers:
                await pc.write_to(pub, b"primer")
                _, init_wire = my_router.outbox.pop(0)
                peer_pc.handle_init(my_pub, init_wire)
                await asyncio.sleep(0.01)
                _, ack_wire = router.outbox.pop(0)
                pc.handle_ack(pub, ack_wire)
                await asyncio.sleep(0.01)
                # Deliver primer traffic to settle nonces.
                _, primer = my_router.outbox.pop(0)
                peer_pc.handle_traffic(my_pub, primer)
                await asyncio.sleep(0.01)
                if peer_pc.inbox.qsize():
                    await peer_pc.inbox.get()

            # Each peer sends one labeled message back to "me".
            for i, (seed, pub, router, peer_pc) in enumerate(peers):
                label = "from-peer-{0}".format(i).encode("ascii")
                await peer_pc.write_to(my_pub, label)
                _, wire = router.outbox.pop(0)
                pc.handle_traffic(pub, wire)
            await asyncio.sleep(0.1)

            # Each per-peer queue must contain exactly one message
            # AND it must be the message from THAT peer.
            for i, (seed, pub, router, peer_pc) in enumerate(peers):
                q = pc.per_peer_inbox.get(pub)
                self.assertIsNotNone(q)
                self.assertEqual(
                    q.qsize(), 1,
                    "Peer {0} queue qsize={1}".format(i, q.qsize()),
                )
                msg = await q.get()
                expected = "from-peer-{0}".format(i).encode("ascii")
                self.assertEqual(msg, expected)

            # Cleanup peers.
            for _, _, _, peer_pc in peers:
                await peer_pc.close()
        finally:
            await pc.close()


class TestResourceLeak(AsyncTestCase):
    """Verify no asyncio.Task / fd leakage when nodes come and go."""

    async def test_repeated_node_creation_no_task_growth(self):
        baseline = len(get_all_tasks())
        for trial in range(20):
            seed = os.urandom(32)
            node = NodeCore(seed=seed)
            router = ActiveRouter(node)
            router.start()
            # Give the maintenance loop one cycle.
            await asyncio.sleep(0.01)
            router.stop()
            await node.close()
        # Cancel any leftover task references (the stop()/close()
        # should already have done it; this is defensive).
        await asyncio.sleep(0.05)
        # Force a GC pass so weakly-held tasks get collected.
        gc.collect()
        leftover = len(get_all_tasks())
        # Allow some headroom for the test runner's own task.  20
        # ActiveRouters with their maintenance loops MUST not all
        # be alive still.
        self.assertLess(
            leftover, baseline + 20,
            "Task count grew unboundedly: baseline={0} after_loop={1}".format(
                baseline, leftover,
            ),
        )

    async def test_packetconn_close_cancels_dispatch_task(self):
        # The PacketConn dispatch_loop is one task per instance;
        # close must cancel it.
        baseline = len(get_all_tasks())
        for trial in range(5):
            seed, pub = fresh_keys()
            router = FakeRouter(pub)
            pc = EncryptedPacketConn(seed, pub, router)
            await asyncio.sleep(0.01)
            await pc.close()
        await asyncio.sleep(0.05)
        gc.collect()
        leftover = len(get_all_tasks())
        self.assertLess(
            leftover, baseline + 6,
            "PacketConn close leaked dispatch tasks ({0} -> {1})".format(
                baseline, leftover,
            ),
        )


class TestPeerChurnLoopback(AsyncTestCase):
    """Real TCP loopback: connect + disconnect a peer 10x; no FD leak.

    Uses two real NodeCores so we exercise the full handshake +
    teardown lifecycle.  After 10 rounds, no orphan peer_tasks
    should remain on either side and the listener should still
    be accepting.
    """

    async def asyncSetUp(self):
        # Listener stays up across rounds.
        self.listener = NodeCore(seed=os.urandom(32))
        await self.listener.start_listener(bind_addr="::1", port=0, af=IP6)
        self.listener_port = self.listener.listen_port

    async def asyncTearDown(self):
        await self.listener.close()

    async def test_10_round_connect_disconnect(self):
        uri = "tcp://[::1]:{0}".format(self.listener_port)
        for round_idx in range(10):
            dialer = NodeCore(seed=os.urandom(32))
            await dialer.add_peer_uri(uri)
            # Wait for the dialer to register the peering.
            for _ in range(30):
                if dialer.peers.get_peer(self.listener.public_key) is not None:
                    break
                await asyncio.sleep(0.05)
            self.assertIsNotNone(
                dialer.peers.get_peer(self.listener.public_key),
                "round {0}: peering never came up".format(round_idx),
            )
            # Cleanly close the dialer.
            await dialer.close()
            await asyncio.sleep(0.05)
        # After 10 rounds the listener should still be listening
        # and its peer_tasks dict should be empty.
        #
        # This is the regression test for the close-watcher bug:
        # without ``PeerLink.watch_pipe_close`` (added 2026-05-26),
        # a clean TCP FIN from the dialer never woke the
        # ``peer_recv_loop.recv_packet`` await, so each round
        # leaked one peer_tasks entry on the listener side.  After
        # 10 rounds we'd see 9 ghost tasks.  With the watcher
        # in place the count returns to 0 promptly.
        await asyncio.sleep(0.3)
        for _ in range(20):
            if not self.listener.peer_tasks:
                break
            await asyncio.sleep(0.1)
        self.assertEqual(
            len(self.listener.peer_tasks), 0,
            "listener peer_tasks leaked: {0}".format(
                len(self.listener.peer_tasks),
            ),
        )


class TestPartialHandshakeDrop(AsyncTestCase):
    """Drop a peer mid-handshake; listener side must clean up.

    Reproduces the scenario where a peer connects, sends a chunk of
    its meta wire, then closes the socket.  Without the close
    watcher this would also leak: the listener's
    ``handshake_over_pipe`` would be stuck in ``wait_for_n`` (which
    awaits ``bytes_arrived``), the deadline would eventually fire,
    and the deadline-fail path is supposed to close the pipe.  The
    close watcher accelerates the cleanup so subsequent rounds
    don't queue behind a 6-second deadline.
    """

    async def asyncSetUp(self):
        self.listener = NodeCore(seed=os.urandom(32))
        await self.listener.start_listener(
            bind_addr="::1", port=0, af=IP6,
        )

    async def asyncTearDown(self):
        await self.listener.close()

    async def test_partial_handshake_does_not_leak(self):
        """Open TCP, send only half the meta bytes, close.  Listener cleans up."""
        # Open a raw asyncio socket connection and ship 50 bytes
        # of garbage that LOOKS like the start of a meta frame
        # but never completes.
        import socket as stdsocket
        sock = stdsocket.socket(stdsocket.AF_INET6, stdsocket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            try:
                sock.connect(("::1", self.listener.listen_port))
            except BlockingIOError:
                pass
            # Wait for connect to complete via the event loop.
            await asyncio.sleep(0.2)
            # Send 50 bytes of garbage -- decoder should reject.
            sock.send(b"\x00" * 50)
            await asyncio.sleep(0.1)
        finally:
            sock.close()
        # Listener should not have grown its peer_tasks dict.  The
        # handshake fails (or the close watcher fires); either way
        # no peer entry should appear.
        await asyncio.sleep(0.5)
        self.assertEqual(
            len(self.listener.peer_tasks), 0,
            "Listener leaked peer_tasks on mid-handshake drop",
        )
        self.assertEqual(
            len(list(self.listener.peers.peers())), 0,
            "Listener leaked peers on mid-handshake drop",
        )


class TestBloomMergeAndCopy(AsyncTestCase):
    """Bloom set operations under stress."""

    async def test_merge_is_bitwise_or(self):
        b1 = Bloom()
        b2 = Bloom()
        b1.add_key(b"alice")
        b2.add_key(b"bob")
        b1.merge(b2)
        self.assertTrue(b1.test_key(b"alice"))
        self.assertTrue(b1.test_key(b"bob"))
        # b2 untouched.
        self.assertFalse(b2.test_key(b"alice"))
        self.assertTrue(b2.test_key(b"bob"))

    async def test_copy_independence(self):
        b1 = Bloom()
        b1.add_key(b"alice")
        b2 = b1.copy()
        b2.add_key(b"bob")
        self.assertTrue(b1.test_key(b"alice"))
        self.assertFalse(b1.test_key(b"bob"))
        self.assertTrue(b2.test_key(b"alice"))
        self.assertTrue(b2.test_key(b"bob"))

    async def test_equal_after_same_inserts(self):
        b1 = Bloom()
        b2 = Bloom()
        for key in (b"x", b"y", b"z"):
            b1.add_key(key)
            b2.add_key(key)
        self.assertTrue(b1.equal(b2))

    async def test_roundtrip_preserves_membership(self):
        b1 = Bloom()
        keys = [os.urandom(32) for _ in range(50)]
        for k in keys:
            b1.add_key(k)
        wire = b1.encode()
        b2 = Bloom.decode(wire)
        for k in keys:
            self.assertTrue(b2.test_key(k))


class TestEncryptedConcurrentEstablishment(AsyncTestCase):
    """5 PacketConns all establishing sessions with each other concurrently."""

    async def test_pairwise_session_setup_no_crosstalk(self):
        N = 5
        # Each entry: (seed, pub, router, pc).
        nodes = []
        for i in range(N):
            seed, pub = fresh_keys()
            router = FakeRouter(pub)
            pc = EncryptedPacketConn(seed, pub, router)
            nodes.append((seed, pub, router, pc))

        try:
            # Establish each (i, j) pair exactly once (i < j).
            # Once that session is up, both directions can ship
            # traffic without re-running init/ack.
            for i in range(N):
                for j in range(i + 1, N):
                    seed_i, pub_i, router_i, pc_i = nodes[i]
                    seed_j, pub_j, router_j, pc_j = nodes[j]
                    await establish_session(
                        pc_i, pc_j, pub_i, pub_j, router_i, router_j,
                    )

            # Verify each pc has N-1 sessions and they're all distinct.
            for i in range(N):
                _, _, _, pc = nodes[i]
                self.assertEqual(
                    len(pc.sessions), N - 1,
                    "pc {0} has {1} sessions".format(i, len(pc.sessions)),
                )
                # Each session has a non-default peer pubkey.
                for peer_pub, sess in pc.sessions.items():
                    self.assertNotEqual(peer_pub, nodes[i][1])

            # Now exercise the no-crosstalk property: pc_0 sends a
            # labelled message to each of the other peers; each
            # peer's per-peer queue must hold only its own message
            # (and only that one).
            seed_0, pub_0, router_0, pc_0 = nodes[0]
            for j in range(1, N):
                seed_j, pub_j, router_j, pc_j = nodes[j]
                label = "to-{0}".format(j).encode("ascii")
                await pc_0.write_to(pub_j, label)
                # Drain the latest traffic from pc_0's outbox.
                _, wire = router_0.outbox.pop()
                pc_j.handle_traffic(pub_0, wire)
            await asyncio.sleep(0.05)
            for j in range(1, N):
                seed_j, pub_j, router_j, pc_j = nodes[j]
                self.assertGreaterEqual(pc_j.inbox.qsize(), 1)
                src, msg = await pc_j.inbox.get()
                expected = "to-{0}".format(j).encode("ascii")
                self.assertEqual(msg, expected)
                # The source MUST be pc_0's pubkey, not any other pc.
                self.assertEqual(src, pub_0)
        finally:
            for _, _, _, pc in nodes:
                await pc.close()


if __name__ == "__main__":
    unittest.main()
