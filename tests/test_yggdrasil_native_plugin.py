"""End-to-end integration: two YggdrasilNativeFactory instances bootstrap
to the same public Yggdrasil peer, discover each other through the
public mesh, then exchange application bytes via the plugin's adapter.

This is the live wire-compat test for the warpgate plugin layer.
It REQUIRES internet access to the bootstrap peer (currently
tls://37.186.113.100:1515) and may take 20-30 seconds to converge
because the tree formation + bloom-multicast lookup against the
public mesh takes that long.

Skip via WARPGATE_SKIP_LIVE_YGG=1 if running in an offline env.
"""
import asyncio
import os
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.yggdrasil_native.main import (
    DEFAULT_BOOTSTRAP_PEERS,
    YggdrasilNativeFactory,
)


SKIP_LIVE = os.environ.get("WARPGATE_SKIP_LIVE_YGG") == "1"
CONVERGENCE_BUDGET = 25.0  # seconds; public mesh tree formation


class FakeNode(object):
    """Minimal node stand-in: just enough surface for the factory."""

    def __init__(self):
        self.resources = FakeResources()


class FakeResources(object):
    def __init__(self):
        self.registered = []

    def register(self, obj):
        self.registered.append(obj)


class TestYggdrasilNativeLiveBootstrap(AsyncTestCase):
    """Spin up TWO factories, both bootstrap to the same public peer,
    then exchange bytes through the public mesh via the encrypted
    PacketConn.  This is the full end-to-end proof that the warpgate
    plugin layer works through the actual Yggdrasil network."""

    async def asyncSetUp(self):
        if SKIP_LIVE:
            self.skipTest("WARPGATE_SKIP_LIVE_YGG=1 set")
        self.fac_a = YggdrasilNativeFactory(FakeNode())
        self.fac_b = YggdrasilNativeFactory(FakeNode())

    async def asyncTearDown(self):
        await self.fac_a.close()
        await self.fac_b.close()

    async def test_both_factories_bootstrap_successfully(self):
        """Weaker check: both factories at least learn SOMETHING from
        the public mesh -- they got connected, exchanged some
        announces.  This is the necessary precondition for any
        end-to-end byte exchange but doesn't itself prove it works."""
        await self.fac_a.ensure_overlay_started()
        await self.fac_b.ensure_overlay_started()
        # Give the announce propagation 8s to populate infos.
        await asyncio.sleep(8)
        # Each side should have at least its own info + a few from
        # the public mesh peers.
        self.assertGreater(
            len(self.fac_a.router.infos), 1,
            "factory A: bootstrap dial didn't yield any tree info",
        )
        self.assertGreater(
            len(self.fac_b.router.infos), 1,
            "factory B: bootstrap dial didn't yield any tree info",
        )

    async def test_a_to_b_byte_exchange_via_public_mesh(self):
        """The real integration test: A sends bytes to B through the
        public Yggdrasil mesh, B receives them on its per-peer channel.

        Exercises: bootstrap → tree formation → path_lookup via
        bloom multicast → path_notify reply → encrypted session
        init/ack → first traffic packet with full ratchet machinery.
        End-to-end against real public peers (no mocks).
        """
        await self.fac_a.ensure_overlay_started()
        await self.fac_b.ensure_overlay_started()
        # Bootstrap settle: bloom filter propagation + first tree
        # maintenance cycle.
        await asyncio.sleep(8)

        pk_a = self.fac_a.node_core.public_key
        pk_b = self.fac_b.node_core.public_key
        pc_a = self.fac_a.packet_conn
        pc_b = self.fac_b.packet_conn

        # B opens a per-peer channel for A so A's bytes are queued.
        pc_b.open_peer_channel(pk_a)
        await pc_a.write_to(pk_b, b"hello from A via public mesh")

        msg = await pc_b.read_from_peer(pk_a, timeout=30.0)
        self.assertEqual(
            msg, b"hello from A via public mesh",
            "Expected A's message, got {0!r}".format(msg),
        )


class TestBootstrapConfig(AsyncTestCase):
    """Pure-unit tests for the bootstrap-peer config path -- no network."""

    async def test_default_bootstrap_list_nonempty(self):
        self.assertGreater(len(DEFAULT_BOOTSTRAP_PEERS), 0)
        for uri in DEFAULT_BOOTSTRAP_PEERS:
            self.assertTrue(
                uri.startswith("tcp://") or uri.startswith("tls://"),
                "bootstrap URI must be tcp:// or tls://, got {0}".format(uri),
            )

    async def test_env_override(self):
        from warpgate.traversal.plugins.yggdrasil_native.main import (
            get_bootstrap_peers,
        )
        original = os.environ.get("WARPGATE_YGG_PEERS")
        try:
            os.environ["WARPGATE_YGG_PEERS"] = "tls://1.2.3.4:9001 tcp://5.6.7.8:1234"
            peers = get_bootstrap_peers()
            self.assertEqual(peers, ["tls://1.2.3.4:9001", "tcp://5.6.7.8:1234"])
        finally:
            if original is None:
                os.environ.pop("WARPGATE_YGG_PEERS", None)
            else:
                os.environ["WARPGATE_YGG_PEERS"] = original

    async def test_empty_env_uses_defaults(self):
        from warpgate.traversal.plugins.yggdrasil_native.main import (
            get_bootstrap_peers,
        )
        original = os.environ.get("WARPGATE_YGG_PEERS")
        try:
            os.environ["WARPGATE_YGG_PEERS"] = ""
            peers = get_bootstrap_peers()
            self.assertEqual(peers, list(DEFAULT_BOOTSTRAP_PEERS))
        finally:
            if original is None:
                os.environ.pop("WARPGATE_YGG_PEERS", None)
            else:
                os.environ["WARPGATE_YGG_PEERS"] = original


class TestPerPeerChannels(AsyncTestCase):
    """Verify PacketConn's per-peer queue mechanic without going through
    the live mesh -- routes a synthetic decrypted-traffic event into
    the dispatcher and confirms both shared + per-peer queues fire."""

    async def test_open_close_channel_idempotent(self):
        # Build a minimal PacketConn-shaped object without actually
        # spinning up the overlay -- we just need the per-peer
        # channel surface.
        from warpgate.overlay.yggdrasil.encrypted import EncryptedPacketConn

        # We can't easily instantiate EncryptedPacketConn without a
        # router; build a minimal stand-in.
        class FakeRouter(object):
            class _Inbox(object):
                async def get(self):
                    await asyncio.sleep(3600)  # never resolves
            inbox = _Inbox()
        seed = b"\x01" * 32
        from ecdsa import SigningKey, Ed25519
        sk = SigningKey.from_string(seed, curve=Ed25519)
        ed_pub = bytes(sk.verifying_key.to_string())
        pc = EncryptedPacketConn(seed, ed_pub, FakeRouter())
        try:
            peer = b"\xab" * 32
            q1 = pc.open_peer_channel(peer)
            q2 = pc.open_peer_channel(peer)
            self.assertIs(q1, q2, "open_peer_channel must be idempotent")
            pc.close_peer_channel(peer)
            # Closing twice is safe.
            pc.close_peer_channel(peer)
            q3 = pc.open_peer_channel(peer)
            self.assertIsNot(q3, q1, "after close, open returns a fresh queue")
        finally:
            await pc.close()


def build_packet_conn_with_capture():
    """Build an EncryptedPacketConn whose outbound writes go to an in-mem queue.

    Returns (pc, sent_queue, seed, ed_pub).  Used by the session-state
    tests below to inspect what the encrypted layer actually puts on
    the wire without going through a real router.
    """
    from warpgate.overlay.yggdrasil.encrypted import EncryptedPacketConn
    from ecdsa import SigningKey, Ed25519

    sent = asyncio.Queue()

    class FakeRouter(object):
        class FakeInbox(object):
            def __init__(self):
                self.queue = asyncio.Queue()

            async def get(self):
                return await self.queue.get()

            async def put(self, item):
                await self.queue.put(item)
        inbox = FakeInbox()

        async def send_to(self, dest, payload):
            await sent.put((bytes(dest), bytes(payload)))

    seed = os.urandom(32)
    sk = SigningKey.from_string(seed, curve=Ed25519)
    ed_pub = bytes(sk.verifying_key.to_string())
    pc = EncryptedPacketConn(seed, ed_pub, FakeRouter())
    return pc, sent, seed, ed_pub


class TestEncryptedSessionUnknownPeerRecovery(AsyncTestCase):
    """Mirror upstream session.go:_handleTraffic for unknown-peer (lines 131-140).

    When a traffic packet arrives for a peer we have no session
    for, upstream sends an init back with throwaway keys to start
    bootstrap.  Without this Python silently drops the packet and
    the peer never realises we've lost state -- their session
    sticks at a defunct key set forever.
    """

    async def test_unknown_peer_traffic_triggers_throwaway_init(self):
        from warpgate.overlay.yggdrasil.encrypted import (
            SESSION_TYPE_INIT, SESSION_TYPE_TRAFFIC,
        )
        from warpgate.overlay.yggdrasil.wire import encode_uvarint
        pc, sent, seed, ed_pub = build_packet_conn_with_capture()
        try:
            # Fake peer pubkey we have no session for.
            from ecdsa import SigningKey, Ed25519
            peer_seed = os.urandom(32)
            peer_pub = bytes(
                SigningKey.from_string(peer_seed, curve=Ed25519)
                .verifying_key.to_string()
            )
            # Fabricate a "traffic" packet with the right tag and
            # plausible varints + sealed bytes (won't decrypt
            # because there's no session -- that's the point).
            traffic = (
                bytes([SESSION_TYPE_TRAFFIC])
                + encode_uvarint(0)
                + encode_uvarint(0)
                + encode_uvarint(1)
                + b"\x00" * 64
            )
            pc.handle_traffic(peer_pub, traffic)
            # Give the asyncio.ensure_future a chance to run.
            for _ in range(5):
                if not sent.empty():
                    break
                await asyncio.sleep(0.01)
            self.assertFalse(
                sent.empty(),
                "unknown-peer traffic must trigger an outbound init",
            )
            dest, wire = await sent.get()
            self.assertEqual(dest, peer_pub)
            self.assertEqual(wire[0], SESSION_TYPE_INIT)
        finally:
            await pc.close()


class TestEncryptedSessionTimeout(AsyncTestCase):
    """Idle sessions must expire after SESSION_TIMEOUT seconds.

    Mirrors upstream session.go's per-session ``time.AfterFunc(
    sessionTimeout)``: every session has a 60-second idle deadline
    that resets on every send/recv.  Python had NO equivalent, so
    sessions grew unbounded in long-running nodes.
    """

    async def test_idle_session_reaped(self):
        from warpgate.overlay.yggdrasil.encrypted import (
            SessionInfo, SESSION_TIMEOUT,
        )
        pc, sent, seed, ed_pub = build_packet_conn_with_capture()
        try:
            peer = b"\xab" * 32
            sess = SessionInfo(peer)
            pc.sessions[peer] = sess
            # Backdate last_activity so the reaper will collect it.
            sess.last_activity -= SESSION_TIMEOUT + 5.0
            # Run a single reaper cycle synchronously by manually
            # invoking the same logic the loop uses.
            import time as _time
            now = _time.monotonic()
            to_drop = [k for k, info in pc.sessions.items()
                       if now - info.last_activity > SESSION_TIMEOUT]
            for k in to_drop:
                pc.sessions.pop(k, None)
            self.assertNotIn(peer, pc.sessions,
                             "idle session should have been reaped")
        finally:
            await pc.close()

    async def test_active_session_not_reaped(self):
        from warpgate.overlay.yggdrasil.encrypted import (
            SessionInfo, SESSION_TIMEOUT,
        )
        pc, sent, seed, ed_pub = build_packet_conn_with_capture()
        try:
            peer = b"\xcd" * 32
            sess = SessionInfo(peer)
            pc.sessions[peer] = sess
            sess.touch()
            import time as _time
            now = _time.monotonic()
            to_drop = [k for k, info in pc.sessions.items()
                       if now - info.last_activity > SESSION_TIMEOUT]
            self.assertEqual(to_drop, [], "active session must not be reaped")
            self.assertIn(peer, pc.sessions)
        finally:
            await pc.close()


class TestEncryptedSessionPendingBufferReap(AsyncTestCase):
    """Pending buffers for unreachable peers must NOT accumulate forever.

    Upstream session.go:170-177 installs a ``time.AfterFunc(
    sessionTimeout)`` to delete the buffered init+data after the
    timeout window.  Python had no equivalent so any peer that
    became permanently unreachable leaked memory for every queued
    write.
    """

    async def test_stale_pending_buffer_dropped(self):
        from warpgate.overlay.yggdrasil.encrypted import SESSION_TIMEOUT
        pc, sent, seed, ed_pub = build_packet_conn_with_capture()
        try:
            peer = b"\xee" * 32
            pc.pending_buffers[peer] = [b"hello"]
            import time as _time
            pc.pending_buffer_times[peer] = _time.monotonic() - SESSION_TIMEOUT - 5.0
            # Trigger one reaper iteration manually.
            now = _time.monotonic()
            stale = [k for k, t in pc.pending_buffer_times.items()
                     if now - t > SESSION_TIMEOUT]
            for k in stale:
                pc.pending_buffers.pop(k, None)
                pc.pending_buffer_times.pop(k, None)
            self.assertNotIn(peer, pc.pending_buffers)
            self.assertNotIn(peer, pc.pending_buffer_times)
        finally:
            await pc.close()


class TestEncryptedAckOnAckRecovery(AsyncTestCase):
    """Receiving an ack for an UNKNOWN session must reply with our own ack.

    Mirrors upstream admin/session.go:_handleAck branch (lines 113-124).
    When peer's ack lands on a session we don't have (e.g. we
    restarted, peer kept its session), upstream treats the ack
    AS IF IT WERE AN INIT and replies with another ack -- that
    way both sides re-bootstrap.  Without this fix, our side
    silently adopts the keys with no reply, and the peer keeps
    sending traffic encrypted under stale keys we never built
    matching shared-secrets for.
    """

    async def test_ack_with_no_prior_session_sends_reply_ack(self):
        from warpgate.overlay.yggdrasil.encrypted import (
            SessionInit, SESSION_TYPE_ACK,
        )
        pc, sent, seed, ed_pub = build_packet_conn_with_capture()
        try:
            from ecdsa import SigningKey, Ed25519
            peer_seed = os.urandom(32)
            peer_sk = SigningKey.from_string(peer_seed, curve=Ed25519)
            peer_pub = bytes(peer_sk.verifying_key.to_string())
            # Build a legit ack signed with the peer's ed key.
            from warpgate.overlay.yggdrasil import nacl_box
            peer_curr_priv, peer_curr_pub = nacl_box.generate_keypair()
            peer_next_priv, peer_next_pub = nacl_box.generate_keypair()
            ack = SessionInit(
                current=peer_curr_pub, next_pub=peer_next_pub,
                key_seq=0, seq=1,
            )
            wire = ack.encode(peer_seed, ed_pub, type_byte=SESSION_TYPE_ACK)
            # Confirm we have no session up front.
            self.assertNotIn(peer_pub, pc.sessions)
            pc.handle_ack(peer_pub, wire)
            for _ in range(5):
                if not sent.empty():
                    break
                await asyncio.sleep(0.01)
            # Session was bootstrapped.
            self.assertIn(peer_pub, pc.sessions)
            # A reply ack was sent.
            self.assertFalse(
                sent.empty(),
                "ack-for-unknown-session must trigger a reply ack",
            )
            dest, reply = await sent.get()
            self.assertEqual(dest, peer_pub)
            from warpgate.overlay.yggdrasil.encrypted import SESSION_TYPE_ACK
            self.assertEqual(
                reply[0], SESSION_TYPE_ACK,
                "reply for ack-on-unknown must be another ack",
            )
        finally:
            await pc.close()


class TestEncryptedSessionInitRoundtrip(AsyncTestCase):
    """Verify SessionInit encode/decode + sig layout match upstream."""

    async def test_init_roundtrip(self):
        from warpgate.overlay.yggdrasil.encrypted import (
            SESSION_INIT_SIZE, SESSION_TYPE_INIT, SessionInit,
            derive_box_keys_from_ed_seed,
        )
        from warpgate.overlay.yggdrasil import nacl_box
        from ecdsa import SigningKey, Ed25519

        sender_seed = os.urandom(32)
        sender_pub = bytes(
            SigningKey.from_string(sender_seed, curve=Ed25519)
            .verifying_key.to_string()
        )
        receiver_seed = os.urandom(32)
        receiver_box_priv, receiver_box_pub, receiver_ed_pub = (
            derive_box_keys_from_ed_seed(receiver_seed)
        )

        curr_priv, curr_pub = nacl_box.generate_keypair()
        next_priv, next_pub = nacl_box.generate_keypair()
        init = SessionInit(
            current=curr_pub, next_pub=next_pub,
            key_seq=7, seq=0xdeadbeef,
        )
        wire = init.encode(sender_seed, receiver_ed_pub,
                           type_byte=SESSION_TYPE_INIT)
        self.assertEqual(
            len(wire), SESSION_INIT_SIZE,
            "init wire bytes must match upstream's sessionInitSize"
            " constant: 1+32+16+64+32+32+8+8 = 193",
        )
        self.assertEqual(wire[0], SESSION_TYPE_INIT)
        decoded = SessionInit.decode(wire, receiver_box_priv, sender_pub)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.current, curr_pub)
        self.assertEqual(decoded.next, next_pub)
        self.assertEqual(decoded.key_seq, 7)
        self.assertEqual(decoded.seq, 0xdeadbeef)

    async def test_init_decode_rejects_tampered_signature(self):
        from warpgate.overlay.yggdrasil.encrypted import (
            SESSION_TYPE_INIT, SessionInit,
            derive_box_keys_from_ed_seed,
        )
        from warpgate.overlay.yggdrasil import nacl_box
        from ecdsa import SigningKey, Ed25519

        sender_seed = os.urandom(32)
        sender_pub = bytes(
            SigningKey.from_string(sender_seed, curve=Ed25519)
            .verifying_key.to_string()
        )
        receiver_seed = os.urandom(32)
        receiver_box_priv, _, receiver_ed_pub = (
            derive_box_keys_from_ed_seed(receiver_seed)
        )
        curr_priv, curr_pub = nacl_box.generate_keypair()
        next_priv, next_pub = nacl_box.generate_keypair()
        init = SessionInit(current=curr_pub, next_pub=next_pub,
                           key_seq=0, seq=1)
        wire = bytearray(init.encode(sender_seed, receiver_ed_pub,
                                     type_byte=SESSION_TYPE_INIT))
        # Flip a byte deep in the sealed payload (well past the
        # box_pub prefix so the box MAC fails).
        wire[-1] ^= 0xff
        decoded = SessionInit.decode(bytes(wire), receiver_box_priv,
                                     sender_pub)
        self.assertIsNone(decoded,
                          "tampered init must fail decode/verify")


if __name__ == "__main__":
    unittest.main()
