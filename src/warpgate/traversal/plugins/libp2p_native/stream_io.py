"""Async stream IO helpers + a Pipe-to-StreamReader/Writer adapter.

The whole libp2p stack (multistream-select, plaintext, yamux) talks
to a ``reader/writer`` pair shaped like asyncio.StreamReader/Writer:

    reader.read(n)         -> bytes (UP TO n, may be short)
    writer.write(b)        -> sync queue
    writer.drain()         -> async flush

aionetiface Pipes give us send/recv on top of raw TCP; to plug them
into a libp2p stack we wrap each Pipe in a PipeStream that exposes
the asyncio.StreamReader interface backed by Pipe's msg_cb pump.
This is the natural mapping the user asked for: "ensure your
networking version works well with aionetifaces pipes, routes, and
nics" -- the wrapping lives here and nowhere else.
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
    """Adapter exposing the asyncio StreamReader/StreamWriter surface
    on top of an aionetiface Pipe.

    Construction:
        ps = PipeStream(pipe)
        await ps.start()    # subscribes msg_cb to Pipe.pipe_events.msg_cbs

    Then use ps.read(n), ps.write(b), ps.drain(), ps.close().

    Internally:
        - inbound bytes arrive via msg_cb(data, client_tup, pipe)
          which appends to a bytearray buffer + signals an Event
        - read() awaits the event, drains buffer up to n bytes
        - write() forwards to Pipe.send() (synchronously enqueued;
          drain() awaits the resulting send-future for back-pressure)
    """

    def __init__(self, pipe):
        self.pipe = pipe
        self.buf = bytearray()
        self.event = asyncio.Event()
        self.closed = False
        self.bound_cb = None
        self.pending_send = None

    async def start(self):
        """Register the msg_cb that pumps inbound bytes into our buffer.

        Works against either:
          * A Pipe instance -- has ``.pipe_events`` + proxies
            ``handoff_to_cb`` / ``add_msg_cb`` via __getattr__.
          * A bare PipeEvents instance (the kind ``Pipe.accept()``
            returns) -- exposes the same methods directly.

        Critically: aionetiface's server-side accept sets
        ``client_events.msg_cbs = pipe_events.msg_cbs`` (see
        ``pipe_tcp_events.connection_made``) so every accepted
        client INHERITS the parent server's shared msg_cbs set.
        Our cb therefore filters on the ``pipe`` arg -- only data
        whose dispatching pipe matches OUR pipe object gets pushed
        into THIS stream's buffer.  Without that filter, two
        concurrent inbound connections would see each other's bytes
        and the multistream-select handshake of conn 1 would race
        conn 2's bytes.
        """
        ps = self
        # Resolve the PipeEvents-shaped object regardless of whether
        # we were handed a Pipe or a raw PipeEvents.
        pe = getattr(self.pipe, "pipe_events", None)
        if pe is None:
            pe = self.pipe  # bare PipeEvents from Pipe.accept()
        our_pe_id = id(pe)

        async def msg_cb(data, client_tup, pipe):
            # Filter: only deliver bytes whose dispatching pipe is
            # OUR pipe.  The shared-msg_cbs design on server-side
            # accepted clients makes this filter load-bearing.
            if id(pipe) != our_pe_id:
                return
            if not data:
                return
            ps.buf.extend(data)
            ps.event.set()

        self.bound_cb = msg_cb
        self.bound_pe = pe
        # Atomic handoff if supported; falls back to direct msg_cbs
        # add for legacy / minimal stubs.
        handoff = getattr(pe, "handoff_to_cb", None)
        if handoff is not None:
            handoff(msg_cb)
        else:
            msg_cbs = getattr(pe, "msg_cbs", None)
            if msg_cbs is None:
                raise ValueError("PipeStream.start: pipe lacks msg_cbs / handoff_to_cb")
            msg_cbs.add(msg_cb)
        return self

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
        self.closed = True
        self.event.set()
        cb = self.bound_cb
        if cb is not None:
            pe = getattr(self.pipe, "pipe_events", None) or self.pipe
            try:
                pe.msg_cbs.discard(cb)
            except (KeyError, AttributeError):
                pass
            self.bound_cb = None
