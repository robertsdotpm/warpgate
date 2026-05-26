"""Unit tests for the libp2p_native plugin: varint + protobuf
encode/decode + multistream-select + peer_id derivation + yamux
framing.  All offline, no socket / network use -- runs in <1 s
on Python 3.5.10.
"""
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.libp2p_native import (
    multistream,
    pb_lite,
    peer_id,
    varint,
    yamux,
)


class TestVarint(unittest.TestCase):
    def test_round_trip_small(self):
        for n in (0, 1, 127, 128, 129, 255, 256, 16384, 65535, 1 << 30):
            self.assertEqual(varint.decode_from(varint.encode(n))[0], n)

    def test_truncated_raises(self):
        # 0x80 indicates "more bytes follow" but the buffer ends.
        with self.assertRaises(ValueError):
            varint.decode_from(b"\x80")

    def test_negative_rejected(self):
        with self.assertRaises(ValueError):
            varint.encode(-1)


class TestPbLite(unittest.TestCase):
    def test_public_key_round_trip(self):
        marshalled = pb_lite.encode_public_key(pb_lite.KEY_TYPE_ED25519, b"A" * 32)
        kt, kb = pb_lite.decode_public_key(marshalled)
        self.assertEqual(kt, pb_lite.KEY_TYPE_ED25519)
        self.assertEqual(kb, b"A" * 32)

    def test_exchange_round_trip(self):
        pubkey_marshalled = pb_lite.encode_public_key(pb_lite.KEY_TYPE_ED25519, b"B" * 32)
        exchange = pb_lite.encode_exchange(b"pid-bytes", pubkey_marshalled)
        pid_back, pubkey_back = pb_lite.decode_exchange(exchange)
        self.assertEqual(pid_back, b"pid-bytes")
        self.assertEqual(pubkey_back, pubkey_marshalled)


class TestPeerId(unittest.TestCase):
    def test_identity_deterministic_from_seed(self):
        a = peer_id.Identity.from_seed(b"\x07" * 32)
        b = peer_id.Identity.from_seed(b"\x07" * 32)
        self.assertEqual(a.peer_id, b.peer_id)
        self.assertEqual(a.pub, b.pub)
        # Different seed -> different identity.
        c = peer_id.Identity.from_seed(b"\x08" * 32)
        self.assertNotEqual(a.peer_id, c.peer_id)

    def test_peer_id_has_libp2p_ed25519_prefix(self):
        # Identity-multihash + Ed25519 PublicKey marshalled = 38 bytes
        # total starting "00 24 08 01 12 20 ..." (hash=0x00, length=0x24,
        # tag-for-field-1=0x08, value=0x01 (Ed25519), tag-for-field-2=0x12,
        # length=0x20).  Render via base58 the result MUST start "12D".
        ident = peer_id.Identity.from_seed(b"\x07" * 32)
        b58 = peer_id.peer_id_to_b58(ident.peer_id)
        self.assertTrue(b58.startswith("12D3KooW"),
                        "peer_id b58 didn't start 12D3KooW: {0}".format(b58))

    def test_pubkey_marshalled_contains_ed25519_type(self):
        ident = peer_id.Identity.from_seed(b"\x07" * 32)
        kt, kb = pb_lite.decode_public_key(ident.pubkey_marshalled)
        self.assertEqual(kt, pb_lite.KEY_TYPE_ED25519)
        self.assertEqual(len(kb), 32)


class TestYamuxHeader(unittest.TestCase):
    def test_pack_unpack_round_trip(self):
        h = yamux.pack_header(yamux.TYPE_DATA, yamux.FLAG_SYN, 3, 17)
        typ, flags, sid, length = yamux.unpack_header(h)
        self.assertEqual(typ, yamux.TYPE_DATA)
        self.assertEqual(flags, yamux.FLAG_SYN)
        self.assertEqual(sid, 3)
        self.assertEqual(length, 17)

    def test_header_length(self):
        h = yamux.pack_header(yamux.TYPE_PING, yamux.FLAG_ACK, 0, 0xCAFE)
        self.assertEqual(len(h), yamux.HEADER_LEN)


class InMemoryDuplex(object):
    """Bidirectional in-memory reader/writer pair for multistream tests.

    Two of these wired together (a.peer = b, b.peer = a) form a
    full-duplex pipe with no event loop required.  Each exposes the
    async read(n) / sync write(data) / async drain() surface."""

    def __init__(self):
        import asyncio as _asyncio
        self.buf = bytearray()
        self.event = _asyncio.Event()
        self.peer = None
        self.closed = False

    async def write(self, data):
        if self.peer is None:
            raise ConnectionError("InMemoryDuplex.write: not connected")
        self.peer.buf.extend(data)
        self.peer.event.set()

    async def drain(self):
        return

    async def read(self, n):
        while not self.buf and not self.closed:
            self.event.clear()
            await self.event.wait()
        if not self.buf:
            return b""
        if n >= len(self.buf):
            out = bytes(self.buf)
            self.buf = bytearray()
            return out
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def close(self):
        self.closed = True
        self.event.set()


def make_duplex_pair():
    a = InMemoryDuplex()
    b = InMemoryDuplex()
    a.peer = b
    b.peer = a
    return a, b


class TestMultistream(AsyncTestCase):
    async def test_negotiate_first_protocol_accepted(self):
        import asyncio
        a, b = make_duplex_pair()

        async def responder():
            return await multistream.negotiate_responder(b, b, ("/plaintext/2.0.0",))

        async def initiator():
            return await multistream.negotiate_initiator(a, a, ["/plaintext/2.0.0"])

        r_task = asyncio.ensure_future(responder())
        i_task = asyncio.ensure_future(initiator())
        r_result = await r_task
        i_result = await i_task
        self.assertEqual(r_result, "/plaintext/2.0.0")
        self.assertEqual(i_result, "/plaintext/2.0.0")

    async def test_negotiate_falls_back_through_na(self):
        import asyncio
        a, b = make_duplex_pair()

        async def responder():
            return await multistream.negotiate_responder(b, b, ("/yamux/1.0.0",))

        async def initiator():
            return await multistream.negotiate_initiator(
                a, a, ["/noise", "/tls", "/yamux/1.0.0"],
            )

        r_task = asyncio.ensure_future(responder())
        i_task = asyncio.ensure_future(initiator())
        self.assertEqual(await r_task, "/yamux/1.0.0")
        self.assertEqual(await i_task, "/yamux/1.0.0")


class TestPlaintextHandshake(AsyncTestCase):
    async def test_round_trip_succeeds_and_returns_peer_id(self):
        import asyncio
        from warpgate.traversal.plugins.libp2p_native import plaintext

        a, b = make_duplex_pair()
        id_a = peer_id.Identity.from_seed(b"\xaa" * 32)
        id_b = peer_id.Identity.from_seed(b"\xbb" * 32)

        async def side_a():
            return await plaintext.perform_handshake(a, a, id_a)

        async def side_b():
            return await plaintext.perform_handshake(b, b, id_b)

        ta = asyncio.ensure_future(side_a())
        tb = asyncio.ensure_future(side_b())
        a_remote, a_pub = await ta
        b_remote, b_pub = await tb
        self.assertEqual(a_remote, id_b.peer_id)
        self.assertEqual(b_remote, id_a.peer_id)
        self.assertEqual(a_pub, id_b.pub)
        self.assertEqual(b_pub, id_a.pub)

    async def test_mismatched_expected_peer_id_rejected(self):
        import asyncio
        from warpgate.traversal.plugins.libp2p_native import plaintext

        a, b = make_duplex_pair()
        id_a = peer_id.Identity.from_seed(b"\xaa" * 32)
        id_b = peer_id.Identity.from_seed(b"\xbb" * 32)
        id_c = peer_id.Identity.from_seed(b"\xcc" * 32)

        async def side_a():
            # A insists peer must be C, but peer is actually B.
            return await plaintext.perform_handshake(
                a, a, id_a, expected_peer_id=id_c.peer_id,
            )

        async def side_b():
            return await plaintext.perform_handshake(b, b, id_b)

        ta = asyncio.ensure_future(side_a())
        tb = asyncio.ensure_future(side_b())
        with self.assertRaises(ConnectionError):
            await ta
        # B's side might not raise (it doesn't know A failed verification),
        # but ConnectionError on A is enough -- if reached.  Drain ta's
        # cancellation and let tb settle.
        try:
            await tb
        except (ConnectionError, OSError):
            pass


class TestYamuxSession(AsyncTestCase):
    async def test_one_stream_byte_exchange(self):
        import asyncio
        a, b = make_duplex_pair()

        s_client = yamux.Session(a, a, is_client=True).start()
        s_server = yamux.Session(b, b, is_client=False).start()

        async def server_side():
            stream = await s_server.accept_stream()
            data = await stream.read(-1)
            # Echo back.
            await stream.write(b"pong:" + data)
            return data

        async def client_side():
            stream = await s_client.open_stream()
            await stream.write(b"hello")
            return await stream.read(-1)

        st = asyncio.ensure_future(server_side())
        ct = asyncio.ensure_future(client_side())
        server_saw = await asyncio.wait_for(st, timeout=5)
        client_saw = await asyncio.wait_for(ct, timeout=5)
        self.assertEqual(server_saw, b"hello")
        self.assertEqual(client_saw, b"pong:hello")

        await s_client.close()
        await s_server.close()


if __name__ == "__main__":
    unittest.main()
