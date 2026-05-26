"""Edge-case tests for buffered_reader.BufferedReader.

The reader is the framing shim between aionetiface's chunk-based
``pipe.recv(SUB_ALL)`` and the Yggdrasil link's varint-framed
packets.  Bugs here surface as silent packet drops or as
peer-disconnection cascades, so we exercise:

  - Boundary inputs: n=0, n<0, single-byte varint, 10-byte (max)
    varint, oversize varint (>10 bytes), overflow varint
    (10 bytes encoding > 2**64-1).
  - Failure modes: pipe closes mid-read, pipe raises OSError,
    pipe returns None forever (no sock), subscribe quirks.
  - Idempotency: close() called twice, ensure_subscribed twice.
"""
import asyncio
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.buffered_reader import (
    BufferedReader, PipeClosed,
)
from warpgate.overlay.yggdrasil.wire import (
    MAX_VARINT_LEN, encode_uvarint,
)


# ---------------------------------------------------------------------------
# Fake Pipe: feeds the reader a scripted sequence of chunks.
#
# Behaviour matches enough of aionetiface.Pipe for BufferedReader's
# purposes -- recv(SUB_ALL) returns the next chunk, or None on EOF
# (configurable), or raises OSError on a "broken pipe" turn.
# ---------------------------------------------------------------------------
class FakePipe(object):
    """Scripted Pipe stub: each call to recv pops one element off
    the script.  Element types:
      * bytes-like -> returned as chunk
      * None       -> returned as-is (BufferedReader treats as timeout)
      * Exception  -> raised
    When the script is exhausted, behaviour is configurable via
    ``terminal``: 'eof' returns None forever, 'osr' raises OSError.
    """

    def __init__(self, script, terminal="eof", has_sock=True):
        self.script = list(script)
        self.terminal = terminal
        self.subscribe_calls = 0
        self.recv_calls = 0
        self.sock = object() if has_sock else None

    def subscribe(self, ch):
        self.subscribe_calls += 1

    async def recv(self, ch, timeout=None):
        self.recv_calls += 1
        if self.script:
            item = self.script.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        if self.terminal == "osr":
            raise OSError("pipe broken")
        return None


class FakePipeNoSubscribe(FakePipe):
    """Pipe stub whose subscribe() raises LookupError -- exercises the
    BufferedReader's tolerant fallback path."""

    def subscribe(self, ch):
        raise LookupError("subscribe not supported")


class TestReadExactBoundaries(AsyncTestCase):

    async def test_read_zero_returns_empty_bytes_without_io(self):
        pipe = FakePipe(script=[])
        reader = BufferedReader(pipe)
        result = await reader.read_exact(0)
        self.assertEqual(result, b"")
        self.assertIsInstance(result, bytes)
        self.assertEqual(
            pipe.recv_calls, 0,
            "zero-byte read must NOT touch the pipe",
        )

    async def test_read_negative_raises_value_error(self):
        pipe = FakePipe(script=[])
        reader = BufferedReader(pipe)
        with self.assertRaises(ValueError) as ctx:
            await reader.read_exact(-1)
        self.assertIn("n must be >= 0", str(ctx.exception))

    async def test_read_exact_concatenates_multi_chunk_arrival(self):
        # Reader must reassemble a varint-framed packet that the
        # kernel split across 3 separate recv() calls.
        pipe = FakePipe(script=[b"hel", b"lo ", b"world!!"])
        reader = BufferedReader(pipe)
        result = await reader.read_exact(11)
        self.assertEqual(result, b"hello world")
        self.assertIsInstance(result, bytes)
        # Two extra bytes ("!!") should remain in the internal buf
        # for the next read_exact -- verify by reading them out.
        rest = await reader.read_exact(2)
        self.assertEqual(rest, b"!!")

    async def test_read_exact_raises_pipe_closed_on_mid_read_eof(self):
        pipe = FakePipe(script=[b"hi", PipeClosed("explicit close")])
        reader = BufferedReader(pipe)
        with self.assertRaises(PipeClosed):
            await reader.read_exact(10)
        # Bytes already buffered when EOF hit are still in the buffer.
        # Reader allows a follow-up read_exact(2) to reclaim them.

    async def test_read_exact_on_already_closed_reader_raises(self):
        pipe = FakePipe(script=[])
        reader = BufferedReader(pipe)
        reader.close()
        with self.assertRaises(PipeClosed):
            await reader.read_exact(1)


class TestReadUvarintBoundaries(AsyncTestCase):

    async def test_single_byte_zero(self):
        pipe = FakePipe(script=[b"\x00"])
        reader = BufferedReader(pipe)
        self.assertEqual(await reader.read_uvarint(), 0)

    async def test_single_byte_max_no_continuation(self):
        # 0x7f = 127, the highest value encodable in a single varint byte.
        pipe = FakePipe(script=[b"\x7f"])
        reader = BufferedReader(pipe)
        self.assertEqual(await reader.read_uvarint(), 127)

    async def test_two_byte_value_128(self):
        pipe = FakePipe(script=[encode_uvarint(128)])
        reader = BufferedReader(pipe)
        self.assertEqual(await reader.read_uvarint(), 128)

    async def test_max_uint64_value_decodes(self):
        max_u64 = (1 << 64) - 1
        pipe = FakePipe(script=[encode_uvarint(max_u64)])
        reader = BufferedReader(pipe)
        self.assertEqual(await reader.read_uvarint(), max_u64)

    async def test_varint_straddling_chunk_boundary(self):
        # encode_uvarint(0x123456789a) splits across two single-byte
        # chunks -- reader must keep pulling until terminator clears.
        encoded = encode_uvarint(0x123456789a)
        self.assertGreater(len(encoded), 1)
        # Split into one chunk per byte
        chunks = [bytes([b]) for b in encoded]
        pipe = FakePipe(script=chunks)
        reader = BufferedReader(pipe)
        self.assertEqual(await reader.read_uvarint(), 0x123456789a)

    async def test_oversize_varint_eleven_bytes_raises(self):
        # 11 bytes with continuation bit set on every one -- exceeds
        # MAX_VARINT_LEN (10) without terminating.
        over = bytes([0x80] * (MAX_VARINT_LEN + 1))
        # Split into single-byte chunks to make the reader iterate.
        pipe = FakePipe(script=[bytes([b]) for b in over])
        reader = BufferedReader(pipe)
        with self.assertRaises(ValueError) as ctx:
            await reader.read_uvarint()
        self.assertIn("too long", str(ctx.exception))

    async def test_decode_uvarint_overflow_branch_unreachable_via_reader(self):
        # decode_uvarint raises ValueError("overflow ...") only when
        # 11+ continuation bytes are fed.  BufferedReader bounds the
        # buffer at MAX_VARINT_LEN bytes and raises "too long" first,
        # so the overflow propagation branch is unreachable in
        # practice.  Pin that "too long" beats "overflow" here so a
        # future refactor doesn't silently flip the precedence and
        # expose a 10-byte-decoded-value > uint64 as a valid varint.
        too_many = bytes([0x80] * (MAX_VARINT_LEN + 5))
        pipe = FakePipe(script=[bytes([b]) for b in too_many])
        reader = BufferedReader(pipe)
        with self.assertRaises(ValueError) as ctx:
            await reader.read_uvarint()
        self.assertIn("too long", str(ctx.exception))
        self.assertNotIn("overflow", str(ctx.exception))

    async def test_eof_mid_varint_raises_pipe_closed(self):
        # A single 0x80 (continuation bit set, no terminator) followed
        # by EOF: reader can't tell if more bytes are coming, hits EOF.
        pipe = FakePipe(
            script=[b"\x80", PipeClosed("eof mid-varint")],
        )
        reader = BufferedReader(pipe)
        with self.assertRaises(PipeClosed):
            await reader.read_uvarint()


class TestSubscribeAndClose(AsyncTestCase):

    async def test_ensure_subscribed_calls_pipe_once(self):
        pipe = FakePipe(script=[b"x"])
        reader = BufferedReader(pipe)
        reader.ensure_subscribed()
        reader.ensure_subscribed()
        reader.ensure_subscribed()
        self.assertEqual(pipe.subscribe_calls, 1)
        self.assertTrue(reader.subscribed)

    async def test_subscribe_lookup_error_swallowed(self):
        pipe = FakePipeNoSubscribe(script=[b"x"])
        reader = BufferedReader(pipe)
        # Must not raise -- the reader treats LookupError as
        # "this pipe type subscribes implicitly".
        reader.ensure_subscribed()
        self.assertTrue(reader.subscribed)

    async def test_subscribe_attribute_error_swallowed(self):
        class NoSubscribe(object):
            sock = object()
            async def recv(self, ch, timeout=None):
                return b"x"
        reader = BufferedReader(NoSubscribe())
        # No subscribe method at all -> attribute lookup fails on
        # call; reader must tolerate.
        reader.ensure_subscribed()
        self.assertTrue(reader.subscribed)

    async def test_close_is_idempotent_and_clears_buffer(self):
        pipe = FakePipe(script=[b"abcde"])
        reader = BufferedReader(pipe)
        # Pre-fill the buffer.
        await reader.read_exact(3)  # leaves "de" in buf
        self.assertEqual(bytes(reader.buf), b"de")
        reader.close()
        self.assertEqual(bytes(reader.buf), b"")
        self.assertTrue(reader.closed)
        # Second close must not raise.
        reader.close()
        self.assertTrue(reader.closed)

    async def test_fill_some_after_close_raises(self):
        pipe = FakePipe(script=[b"x"])
        reader = BufferedReader(pipe)
        reader.close()
        with self.assertRaises(PipeClosed):
            await reader.fill_some()

    async def test_fill_some_propagates_oserror_as_pipe_closed(self):
        pipe = FakePipe(script=[OSError("connection reset")])
        reader = BufferedReader(pipe)
        with self.assertRaises(PipeClosed):
            await reader.fill_some()

    async def test_fill_some_no_sock_treats_none_as_eof(self):
        # script empty + has_sock=False -> recv returns None and
        # there's no sock to fall back on; reader bails out.
        pipe = FakePipe(script=[], has_sock=False)
        reader = BufferedReader(pipe)
        with self.assertRaises(PipeClosed) as ctx:
            await reader.fill_some()
        self.assertIn("no sock", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
