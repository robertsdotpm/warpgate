"""Noise XX correctness + integration tests.

Unit coverage:
    * RFC 8439 ChaCha20-Poly1305 AEAD vector
    * Noise XX handshake round-trip in-memory
    * NoiseHandshakePayload signed-static-key verification
    * Tampered signature rejected
    * Wrong static_pubkey in signature payload rejected

Integration coverage:
    * Two Libp2pNode instances dial each other -- the dialer prefers
      /noise so we observe the encrypted path end-to-end on real TCP
      loopback through aionetiface Pipes.
"""
import asyncio
import unittest

from aionetiface import IP4, Interface
from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.libp2p_native import (
    aead,
    noise,
    pb_lite,
    peer_id,
)
from warpgate.traversal.plugins.libp2p_native.node_core import Libp2pNode
from warpgate.traversal.plugins.libp2p_native.pipe_adapter import LibP2PPipeAdapter


class TestChaCha20Poly1305AEAD(unittest.TestCase):
    """RFC 8439 §2.8.2 byte-exact vector + tag tamper detection."""

    def test_rfc_vector(self):
        key = bytes.fromhex(
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
        )
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = bytes.fromhex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
            "637265656e20776f756c642062652069742e"
        )
        expected = bytes.fromhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116"
            "1ae10b594f09e26a7e902ecbd0600691"
        )
        self.assertEqual(aead.aead_encrypt(key, nonce, aad, plaintext), expected)
        self.assertEqual(
            aead.aead_decrypt(key, nonce, aad, expected), plaintext
        )

    def test_tampered_tag_rejected(self):
        key = b"\x42" * 32
        nonce = b"\x07" * 12
        aad = b"x"
        pt = b"hello"
        ct = aead.aead_encrypt(key, nonce, aad, pt)
        tampered = ct[:-1] + bytes([ct[-1] ^ 0x01])
        with self.assertRaises(ValueError):
            aead.aead_decrypt(key, nonce, aad, tampered)

    def test_aad_mismatch_rejected(self):
        key = b"\x42" * 32
        nonce = b"\x07" * 12
        ct = aead.aead_encrypt(key, nonce, b"aad1", b"hello")
        with self.assertRaises(ValueError):
            aead.aead_decrypt(key, nonce, b"aad2", ct)


class TestNoisePayload(unittest.TestCase):
    def test_signed_payload_round_trips(self):
        ident = peer_id.Identity.from_seed(b"\xaa" * 32)
        static_priv, static_pub = noise.generate_x25519_keypair(b"\x11" * 32)
        payload = noise.encode_noise_payload(ident, static_pub)
        pid, ed_pub = noise.decode_and_verify_noise_payload(payload, static_pub)
        self.assertEqual(pid, ident.peer_id)
        self.assertEqual(ed_pub, ident.pub)

    def test_wrong_static_pubkey_rejected(self):
        ident = peer_id.Identity.from_seed(b"\xaa" * 32)
        _, static_pub = noise.generate_x25519_keypair(b"\x11" * 32)
        payload = noise.encode_noise_payload(ident, static_pub)
        wrong_static = b"\x00" * 32
        with self.assertRaises(ConnectionError):
            noise.decode_and_verify_noise_payload(payload, wrong_static)

    def test_tampered_signature_rejected(self):
        ident = peer_id.Identity.from_seed(b"\xaa" * 32)
        _, static_pub = noise.generate_x25519_keypair(b"\x11" * 32)
        payload = noise.encode_noise_payload(ident, static_pub)
        # Find the identity_sig field and flip one bit.
        fields = pb_lite.parse_message(payload)
        sig = bytearray(fields[2][-1])
        sig[0] ^= 0x01
        # Rebuild a tampered payload.
        tampered = (
            pb_lite.encode_bytes_field(1, fields[1][-1])
            + pb_lite.encode_bytes_field(2, bytes(sig))
        )
        with self.assertRaises(ConnectionError):
            noise.decode_and_verify_noise_payload(tampered, static_pub)


class InMemDuplex(object):
    """Minimal in-memory reader/writer; mirrors what the unit test fixture
    in test_libp2p_native_unit.py uses but kept local here to avoid
    test-file cross-imports."""

    def __init__(self):
        self.buf = bytearray()
        self.event = asyncio.Event()
        self.peer = None

    async def write(self, data):
        self.peer.buf.extend(data)
        self.peer.event.set()

    async def read(self, n):
        while not self.buf:
            self.event.clear()
            await self.event.wait()
        if n >= len(self.buf):
            out = bytes(self.buf)
            self.buf = bytearray()
            self.event.clear()
            return out
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out


def make_duplex_pair():
    a = InMemDuplex()
    b = InMemDuplex()
    a.peer = b
    b.peer = a
    return a, b


class TestNoiseHandshakeInMemory(AsyncTestCase):
    async def test_xx_round_trip(self):
        a, b = make_duplex_pair()
        ida = peer_id.Identity.from_seed(b"\xaa" * 32)
        idb = peer_id.Identity.from_seed(b"\xbb" * 32)

        async def init_side():
            return await noise.perform_initiator_handshake(
                a, a, ida, expected_peer_id=idb.peer_id,
            )

        async def resp_side():
            return await noise.perform_responder_handshake(b, b, idb)

        ti = asyncio.ensure_future(init_side())
        tr = asyncio.ensure_future(resp_side())
        sess_i, sess_r = await asyncio.gather(ti, tr)
        self.assertEqual(sess_i.remote_peer_id, idb.peer_id)
        self.assertEqual(sess_r.remote_peer_id, ida.peer_id)

        # Bidirectional encrypted application bytes.
        await sess_i.write(b"hello-noise")
        got_r = await sess_r.read(64)
        self.assertEqual(got_r, b"hello-noise")
        await sess_r.write(b"pong-" + got_r)
        got_i = await sess_i.read(64)
        self.assertEqual(got_i, b"pong-hello-noise")

    async def test_xx_rejects_wrong_expected_peer_id(self):
        a, b = make_duplex_pair()
        ida = peer_id.Identity.from_seed(b"\xaa" * 32)
        idb = peer_id.Identity.from_seed(b"\xbb" * 32)
        idc = peer_id.Identity.from_seed(b"\xcc" * 32)

        async def init_side():
            return await noise.perform_initiator_handshake(
                a, a, ida, expected_peer_id=idc.peer_id,
            )

        async def resp_side():
            return await noise.perform_responder_handshake(b, b, idb)

        ti = asyncio.ensure_future(init_side())
        tr = asyncio.ensure_future(resp_side())
        with self.assertRaises(ConnectionError):
            await ti
        # Initiator raised AFTER msg2 and BEFORE msg3, leaving the
        # responder blocked on read_noise_frame for msg3 indefinitely.
        # Cancel it so the test cleans up.
        tr.cancel()
        try:
            await tr
        except (ConnectionError, ValueError, OSError, asyncio.CancelledError):
            pass


class TestNoiseEndToEndTcp(AsyncTestCase):
    """Real TCP loopback: two Libp2pNode instances complete the full
    Noise-protected handshake and exchange application bytes through
    the LibP2PPipeAdapter."""

    async def asyncSetUp(self):
        self.id_a = peer_id.Identity.generate()
        self.id_b = peer_id.Identity.generate()
        self.node_a = Libp2pNode(self.id_a)
        self.node_b = Libp2pNode(self.id_b)
        self.iface = await Interface("default")

    async def asyncTearDown(self):
        await self.node_a.close()
        await self.node_b.close()

    async def test_noise_handshake_and_byte_exchange(self):
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

        self.assertEqual(b_remote, self.id_a.peer_id)
        self.assertEqual(a_remote, self.id_b.peer_id)

        adapter_b = LibP2PPipeAdapter(b_stream, b_session, b_remote)
        adapter_a = LibP2PPipeAdapter(a_stream, a_session, a_remote)

        await adapter_b.send(b"hello-via-noise")
        got_a = await asyncio.wait_for(adapter_a.recv(), timeout=5.0)
        self.assertEqual(got_a, b"hello-via-noise")
        await adapter_a.send(b"echo:" + got_a)
        got_b = await asyncio.wait_for(adapter_b.recv(), timeout=5.0)
        self.assertEqual(got_b, b"echo:hello-via-noise")

        await adapter_b.close()
        await adapter_a.close()


if __name__ == "__main__":
    unittest.main()
