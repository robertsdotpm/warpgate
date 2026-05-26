"""Async stream IO helpers + a passive Pipe-to-StreamReader/Writer adapter.

The libp2p stack (multistream-select, plaintext, yamux) talks to a
``reader/writer`` pair shaped like asyncio.StreamReader/Writer:

    reader.read(n)         -> bytes (UP TO n, may be short)
    writer.write(b)        -> async, fully flushed

aionetiface Pipes deliver inbound bytes via the ``msg_cb`` callback
contract: a registered cb is called with ``(data, client_tup, pipe)``
on every received chunk -- including, for TCP servers, ONE shared
cb that fires per-client with the client-side ``pipe`` as the third
arg.  We lean on that natively rather than spinning a separate
accept loop: the plugin's listener registers ONE demuxing cb on
the server Pipe that creates a PipeStream the first time it sees
a new ``id(pipe)``, and routes subsequent bytes for that pipe into
the same PipeStream.

So PipeStream itself is PASSIVE -- it doesn't know about msg_cbs at
all.  The caller (node_core) wires up whichever cb topology makes
sense for that side and pushes data in via ``feed_data(bytes)``.
The dialer path uses ``pipe.handoff_to_cb`` with a single-stream
lambda; the listener path uses one shared demuxer over many streams.
"""
import asyncio


async def read_exactly(reader, n):
    """Read exactly ``n`` bytes from a reader, accumulating short reads.

    asyncio.StreamReader has readexactly() but our PipeStream may not,
    so this helper is the portable variant the rest of the libp2p
    stack relies on.
    """
    if n == 0:
        return b""
    out = bytearray()
    while len(out) < n:
        chunk = await reader.read(n - len(out))
        if not chunk:
            raise ConnectionError("stream_io.read_exactly: peer closed early")
        out.extend(chunk)
    return bytes(out)


class PipeStream(object):
    """StreamReader/StreamWriter-shaped surface on top of an aionetiface Pipe.

    Two-sided:
        - Reader side is passive: ``feed_data(data)`` pushes bytes
          into the internal buffer + wakes any ``read()`` waiter.
          ``feed_eof()`` flips the closed flag.  The CALLER is
          responsible for arranging the msg_cb wiring that calls
          feed_data.
        - Writer side forwards to ``pipe.send`` so back-pressure is
          honoured naturally (Pipe.send is fully awaited).

    Keeping the cb wiring out of PipeStream lets one msg_cb on a
    server pipe demux across many PipeStreams (one per client) and
    avoids paying for the SUB_ALL-queue handoff + per-stream cb
    registration we'd need otherwise.
    """

    def __init__(self, pipe):
        self.pipe = pipe
        self.buf = bytearray()
        self.event = asyncio.Event()
        self.closed = False

    def feed_data(self, data):
        """Push received bytes into the buffer and wake any reader."""
        if not data or self.closed:
            return
        self.buf.extend(data)
        self.event.set()

    def feed_eof(self):
        """Mark the stream closed; pending + future reads return b''."""
        self.closed = True
        self.event.set()

    async def read(self, n):
        """Read UP TO ``n`` bytes; returns immediately if buffer has any."""
        if n == 0:
            return b""
        while not self.buf and not self.closed:
            self.event.clear()
            await self.event.wait()
        if not self.buf and self.closed:
            return b""
        if n >= len(self.buf):
            out = bytes(self.buf)
            self.buf = bytearray()
            self.event.clear()
            return out
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    async def write(self, data):
        """Send ``data`` over the underlying Pipe.

        Async (not the asyncio.StreamWriter sync+drain split) so the
        protocol layers above can treat PipeStream and yamux.Stream
        interchangeably -- both expose ``await write(data)``.
        """
        if self.closed:
            raise ConnectionError("PipeStream.write: closed")
        await self.pipe.send(bytes(data))

    async def drain(self):
        """No-op flush: write() is already fully awaited."""
        return

    def close(self):
        """Mark the stream closed and wake any pending read."""
        self.feed_eof()
