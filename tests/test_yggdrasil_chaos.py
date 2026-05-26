"""Chaos / robustness tests for the Yggdrasil port.

Mostly bench-style tests built against a fake router that captures
sent bytes into a list -- lets us deliver packets out-of-order,
re-deliver replays, tamper with bytes, drop them on the floor, etc.
None of these tests do real networking.

What's covered:

  * Replay protection on encrypted session (same nonce twice rejected,
    out-of-order older nonce rejected, future nonce accepted)
  * Malformed encrypted packets (wrong type byte, truncated body,
    tampered ciphertext -- all silent drops, never crashes)
  * Pathfinder edge cases (rumor throttle, bad signature, unknown dest)
  * Encrypted layer state isolation between sessions

These were the kind of bugs that bit the live test: the Traffic
watermark default, the missing ratchet branches.  Test what would
have caught them if we'd thought to look.
"""
import asyncio
import os
import time
import unittest

from aionetiface.testing import AsyncTestCase
from ecdsa import SigningKey, Ed25519

from warpgate.overlay.yggdrasil import nacl_box
from warpgate.overlay.yggdrasil.encrypted import (
    BOX_PUB_SIZE,
    EncryptedPacketConn,
    SESSION_TYPE_TRAFFIC,
    SESSION_INIT_SIZE,
    SessionInit,
    SessionInfo,
)
from warpgate.overlay.yggdrasil.node_core import NodeCore
from warpgate.overlay.yggdrasil.pathfinder import PATH_THROTTLE_SECONDS
from warpgate.overlay.yggdrasil.router_active import ActiveRouter, sign
from warpgate.overlay.yggdrasil.routing_msgs import (
    PathBroken,
    PathNotify,
    PathNotifyInfo,
    Traffic,
)
from warpgate.overlay.yggdrasil.wire import encode_uvarint


def fresh_keys():
    """Return (seed, pubkey) for a fresh ed25519 identity."""
    seed = os.urandom(32)
    sk = SigningKey.from_string(seed, curve=Ed25519)
    pub = bytes(sk.verifying_key.to_string())
    return seed, pub


class FakeRouter(object):
    """Stand-in for ActiveRouter sufficient for encrypted-layer tests.

    Exposes the four pieces EncryptedPacketConn touches:
      ``public_key``  -- bytes
      ``inbox``       -- asyncio.Queue that the dispatch_loop drains
      ``send_to``     -- async callable that captures (peer, wire) into ``outbox``

    Tests inject packets by calling ``await router.inbox.put(...)``;
    they snapshot outbound by reading ``router.outbox``.
    """

    def __init__(self, public_key):
        self.public_key = public_key
        self.inbox = asyncio.Queue()
        self.outbox = []

    async def send_to(self, peer, wire):
        self.outbox.append((bytes(peer), bytes(wire)))


async def establish_session(pc_a, pc_b, pub_a, pub_b, router_a, router_b):
    """Drive the lazy init/ack flow between two EncryptedPacketConns.

    Returns once both sides have a fully populated SessionInfo.
    Uses an empty primer message; caller can then call write_to
    with real data.
    """
    await pc_a.write_to(pub_b, b"primer")
    # A's outbox now holds the init.
    _, init_wire = router_a.outbox.pop(0)
    pc_b.handle_init(pub_a, init_wire)
    await asyncio.sleep(0.02)
    # B sent its ack.
    _, ack_wire = router_b.outbox.pop(0)
    pc_a.handle_ack(pub_b, ack_wire)
    await asyncio.sleep(0.02)
    # A's outbox now contains the buffered "primer" traffic; deliver
    # it so B's session_for is properly aligned (recv_nonce moves up).
    _, primer_wire = router_a.outbox.pop(0)
    pc_b.handle_traffic(pub_a, primer_wire)
    await asyncio.sleep(0.02)
    # Drain B's inbox so the primer doesn't pollute later asserts.
    if pc_b.inbox.qsize():
        await pc_b.inbox.get()


class TestEncryptedReplayProtection(AsyncTestCase):
    """Replay attack should be silently dropped (nonce <= recv_nonce)."""

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

    async def test_duplicate_packet_dropped(self):
        await self.pc_a.write_to(self.pub_b, b"unique-msg")
        _, t1 = self.router_a.outbox.pop(0)
        # Deliver first time.
        self.pc_b.handle_traffic(self.pub_a, t1)
        await asyncio.sleep(0.02)
        self.assertEqual(self.pc_b.inbox.qsize(), 1)
        src, msg = await self.pc_b.inbox.get()
        self.assertEqual(msg, b"unique-msg")
        # Replay the exact same bytes.
        self.pc_b.handle_traffic(self.pub_a, t1)
        await asyncio.sleep(0.02)
        # Inbox should still be empty.
        self.assertEqual(
            self.pc_b.inbox.qsize(), 0,
            "Replayed packet leaked into inbox -- nonce check broken",
        )

    async def test_out_of_order_older_dropped(self):
        # Build packets 1..5; deliver 1, 2, 4 (skip 3), then try 3.
        traffics = []
        for label in (b"one", b"two", b"three", b"four", b"five"):
            await self.pc_a.write_to(self.pub_b, label)
            traffics.append(self.router_a.outbox.pop(0)[1])
        # Deliver in order: 1, 2.
        for t in traffics[:2]:
            self.pc_b.handle_traffic(self.pub_a, t)
        await asyncio.sleep(0.02)
        # Skip 3, deliver 4 -- accepted (future-nonce path).
        self.pc_b.handle_traffic(self.pub_a, traffics[3])
        await asyncio.sleep(0.02)
        # Now try 3 -- older than current recv_nonce, must reject.
        before_count = self.pc_b.inbox.qsize()
        self.pc_b.handle_traffic(self.pub_a, traffics[2])
        await asyncio.sleep(0.02)
        self.assertEqual(
            self.pc_b.inbox.qsize(), before_count,
            "Older out-of-order packet leaked -- recv_nonce monotone check broken",
        )

    async def test_future_nonce_accepted_no_gap_check(self):
        # Skip several nonces and ensure the future one is accepted.
        traffics = []
        for label in (b"a", b"b", b"c", b"d", b"e"):
            await self.pc_a.write_to(self.pub_b, label)
            traffics.append(self.router_a.outbox.pop(0)[1])
        # Deliver only the last one -- big jump in nonce.
        self.pc_b.handle_traffic(self.pub_a, traffics[-1])
        await asyncio.sleep(0.02)
        self.assertEqual(self.pc_b.inbox.qsize(), 1)
        src, msg = await self.pc_b.inbox.get()
        self.assertEqual(
            msg, b"e",
            "Future nonce should be accepted (no gap enforcement)",
        )


class TestEncryptedMalformedPackets(AsyncTestCase):
    """Malformed encrypted packets must silently drop, never crash."""

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

    async def test_unknown_type_byte_dropped(self):
        # Type byte 99 is not init/ack/traffic -- dispatch loop
        # should silently ignore.
        bogus = bytes([99]) + b"garbage payload"
        await self.router_b.inbox.put((self.pub_a, bogus))
        await asyncio.sleep(0.05)
        # No crash; no inbox put.
        self.assertEqual(self.pc_b.inbox.qsize(), 0)

    async def test_empty_payload_dropped(self):
        # Empty bytes -- dispatch_loop has a `if not payload: continue` guard.
        await self.router_b.inbox.put((self.pub_a, b""))
        await asyncio.sleep(0.05)
        self.assertEqual(self.pc_b.inbox.qsize(), 0)

    async def test_truncated_traffic_silent_drop(self):
        # Build a real traffic packet then cut bytes off the end.
        await self.pc_a.write_to(self.pub_b, b"hello")
        _, full = self.router_a.outbox.pop(0)
        # Try various truncations.
        for cut in (1, 5, len(full) // 2, len(full) - 1):
            truncated = full[:cut]
            self.pc_b.handle_traffic(self.pub_a, truncated)
            await asyncio.sleep(0.02)
        # No crash; the legitimate packet was never delivered so
        # inbox stays empty.  (truncations either fail varint
        # decode -- ValueError caught inside handle_traffic -- or
        # fail MAC verify -- triggers a session_init resend, which
        # we don't assert about here.)

    async def test_tampered_ciphertext_recovers(self):
        # Build a real traffic packet, then flip the last byte.
        await self.pc_a.write_to(self.pub_b, b"hello")
        _, full = self.router_a.outbox.pop(0)
        tampered = full[:-1] + bytes([full[-1] ^ 0xFF])
        # Drain any pending writes already in B's outbox.
        self.router_b.outbox = []
        self.pc_b.handle_traffic(self.pub_a, tampered)
        await asyncio.sleep(0.05)
        # MAC failure must produce no inbox put.
        self.assertEqual(self.pc_b.inbox.qsize(), 0)
        # And it should have triggered an init resend (recovery).
        sent = [w for _, w in self.router_b.outbox if w and w[0] == 1]
        self.assertGreaterEqual(
            len(sent), 1,
            "MAC failure should trigger send_init for recovery",
        )

    async def test_traffic_packet_for_unknown_session_dropped(self):
        # Construct a bogus traffic packet from a peer the session
        # map has never seen.  handle_traffic looks up sessions
        # first; missing session -> silent return.
        unknown_pub = b"\xAB" * 32
        bogus = bytes([SESSION_TYPE_TRAFFIC]) + b"\x00" * 50
        self.pc_b.handle_traffic(unknown_pub, bogus)
        await asyncio.sleep(0.02)
        self.assertEqual(self.pc_b.inbox.qsize(), 0)


class TestPathfinderEdgeCases(AsyncTestCase):
    """Pathfinder corner cases that aren't covered by the happy-path tests."""

    async def asyncSetUp(self):
        self.seed, self.pub = fresh_keys()
        self.node = NodeCore(seed=self.seed)
        self.router = ActiveRouter(self.node)

    async def asyncTearDown(self):
        self.router.stop()
        await self.node.close()

    async def test_rapid_same_dest_throttles_to_one_rumor(self):
        """10 outbound packets to the same dest -> rumor map has exactly 1 entry."""
        dest = b"\x77" * 32
        for i in range(10):
            tr = Traffic(
                source=self.router.public_key, dest=dest,
                watermark=(1 << 64) - 1, payload=bytes([i]),
            )
            await self.router.pathfinder.handle_outbound_traffic(tr)
        self.assertEqual(
            len(self.router.pathfinder.rumors), 1,
            "Rumor throttle failed: {0} rumors for one dest".format(
                len(self.router.pathfinder.rumors),
            ),
        )

    async def test_path_notify_with_bad_signature_rejected(self):
        """A signed PathNotifyInfo with a bad sig must NOT be cached."""
        # Build a PathNotify for "us" with a bogus signature.
        source_seed, source_pub = fresh_keys()
        info = PathNotifyInfo(
            seq=42, path=[1, 2, 3],
            sig=b"\x00" * 64,  # invalid signature
        )
        notify = PathNotify(
            path=[], watermark=(1 << 64) - 1,
            source=source_pub, dest=self.router.public_key, info=info,
        )
        # Prime the rumor map so the solicitation gate doesn't
        # drop the packet before the signature check runs.
        await self.router.pathfinder.send_rumor_lookup(source_pub)
        before = dict(self.router.pathfinder.paths)
        await self.router.pathfinder.handle_notify(source_pub, notify)
        self.assertEqual(
            self.router.pathfinder.paths, before,
            "Path cache mutated despite invalid signature",
        )

    async def test_path_notify_for_wrong_dest_dropped(self):
        # Notify targeted at someone else (dest != our pubkey),
        # AND we have no next-hop for it (empty path) -- pathfinder
        # should return without changing state.
        source_seed, source_pub = fresh_keys()
        other_dest = b"\x99" * 32
        # Sign the info properly so the only reason to reject is
        # the dest mismatch.
        info = PathNotifyInfo(seq=1, path=[], sig=b"\x00" * 64)
        info.sig = sign(source_seed, info.bytes_for_sig())
        notify = PathNotify(
            path=[],  # no forwarding path -> we're the candidate
            watermark=(1 << 64) - 1,
            source=source_pub, dest=other_dest, info=info,
        )
        before_paths = dict(self.router.pathfinder.paths)
        await self.router.pathfinder.handle_notify(source_pub, notify)
        self.assertEqual(self.router.pathfinder.paths, before_paths)

    async def test_path_broken_for_unknown_dest_no_crash(self):
        # PathBroken for a destination we never had a path to --
        # must not crash, must not create spurious state.
        unknown_dest = b"\xee" * 32
        broken = PathBroken(
            path=[],  # no forwarding path
            watermark=(1 << 64) - 1,
            source=self.router.public_key, dest=unknown_dest,
        )
        before = dict(self.router.pathfinder.paths)
        # Should not raise.
        await self.router.pathfinder.handle_broken(self.router.public_key, broken)
        # The unknown dest gets a rumor placeholder for the retry
        # path -- that's normal -- but paths map shouldn't gain
        # an entry.
        self.assertEqual(
            self.router.pathfinder.paths, before,
            "PathBroken for unknown dest mutated paths cache",
        )

    async def test_pathnotify_lower_seq_does_not_overwrite(self):
        """Stale PathNotify (lower seq) must not replace a fresh one."""
        source_seed, source_pub = fresh_keys()

        def make_notify(seq, path):
            info = PathNotifyInfo(seq=seq, path=path, sig=b"\x00" * 64)
            info.sig = sign(source_seed, info.bytes_for_sig())
            return PathNotify(
                path=[], watermark=(1 << 64) - 1,
                source=source_pub, dest=self.router.public_key, info=info,
            )

        # Prime the rumor map -- handle_notify has a solicitation
        # gate that drops notifies for keys we never asked about
        # (defense against drive-by path-cache pollution).
        await self.router.pathfinder.send_rumor_lookup(source_pub)
        # Fresh notify with a high seq.
        await self.router.pathfinder.handle_notify(
            source_pub, make_notify(100, [9, 9]),
        )
        existing = self.router.pathfinder.paths.get(source_pub)
        self.assertIsNotNone(existing)
        self.assertEqual(existing.seq, 100)
        self.assertEqual(existing.path, [9, 9])
        # Stale notify with lower seq.
        await self.router.pathfinder.handle_notify(
            source_pub, make_notify(50, [1]),
        )
        # Path must NOT have been replaced.
        still = self.router.pathfinder.paths.get(source_pub)
        self.assertEqual(still.seq, 100)
        self.assertEqual(still.path, [9, 9])


class TestSessionStateIsolation(AsyncTestCase):
    """Two sessions on one PacketConn must NOT cross-pollute keys."""

    async def test_distinct_peers_get_distinct_session_state(self):
        seed_a, pub_a = fresh_keys()
        seed_b, pub_b = fresh_keys()
        seed_c, pub_c = fresh_keys()
        router_a = FakeRouter(pub_a)
        pc_a = EncryptedPacketConn(seed_a, pub_a, router_a)
        try:
            sess_b = pc_a.session_for(pub_b)
            sess_c = pc_a.session_for(pub_c)
            self.assertIsNot(sess_b, sess_c)
            # Mutating one must not affect the other.
            sess_b.recv_nonce = 999
            self.assertEqual(sess_c.recv_nonce, 0)
            sess_c.send_nonce = 888
            self.assertEqual(sess_b.send_nonce, 0)
        finally:
            await pc_a.close()

    async def test_session_for_idempotent(self):
        # Repeated session_for(same_peer) returns the SAME object.
        seed_a, pub_a = fresh_keys()
        seed_b, pub_b = fresh_keys()
        router_a = FakeRouter(pub_a)
        pc_a = EncryptedPacketConn(seed_a, pub_a, router_a)
        try:
            s1 = pc_a.session_for(pub_b)
            s2 = pc_a.session_for(pub_b)
            self.assertIs(s1, s2)
        finally:
            await pc_a.close()


class TestEncryptedSessionHardening(AsyncTestCase):
    """Hardening: weird wire conditions that must not corrupt state."""

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

    async def asyncTearDown(self):
        await self.pc_a.close()
        await self.pc_b.close()

    async def test_init_with_wrong_size_returns_none(self):
        # Wire-shape failure on init/ack is a silent drop.
        sess = self.pc_b.session_for(self.pub_a)
        result = SessionInit.decode(
            b"\x01" * 50, self.pc_b.box_priv, self.pub_a,
        )
        self.assertIsNone(result)

    async def test_init_with_tampered_payload_returns_none(self):
        # Encode a valid init, flip a byte in the sealed payload.
        sess = SessionInit(
            current=b"\x01" * 32, next_pub=b"\x02" * 32,
            key_seq=0, seq=int(time.time()),
        )
        wire = sess.encode(self.seed_a, self.pub_b)
        tampered = wire[:50] + bytes([wire[50] ^ 0xFF]) + wire[51:]
        result = SessionInit.decode(tampered, self.pc_b.box_priv, self.pub_a)
        self.assertIsNone(result)

    async def test_handle_traffic_for_missing_session_silent(self):
        # No session in pc_b for an unknown peer -- handle_traffic
        # short-circuits before any decode.
        self.pc_b.handle_traffic(
            b"\xaa" * 32,
            bytes([SESSION_TYPE_TRAFFIC]) + b"\x01\x01\x01" + b"\x00" * 32,
        )
        # No crash; no inbox put.
        self.assertEqual(self.pc_b.inbox.qsize(), 0)


if __name__ == "__main__":
    unittest.main()
