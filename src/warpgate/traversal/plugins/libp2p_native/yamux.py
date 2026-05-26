"""yamux 1.0.0 stream multiplexer -- minimal byte-compatible subset.

Frame layout (12 bytes header, network byte order = big-endian):
    Version (uint8)      | 0
    Type    (uint8)      | 0=Data, 1=WindowUpdate, 2=Ping, 3=GoAway
    Flags   (uint16)     | SYN=1, ACK=2, FIN=4, RST=8
    StreamID (uint32)    | client streams = odd, server streams = even
    Length   (uint32)    | Data=byte count, WindowUpdate=delta, Ping=opaque

Initial window size per stream is 256 KiB.  We send/honour
WindowUpdate frames so back-pressure works across the wire; for the
warpgate relay use case we never push enough bytes per stream to
hit the limit but the framing has to be byte-correct anyway.

Stream IDs: per yamux spec the *initiator* of the muxer (the side
that wrote the multistream "/yamux/1.0.0" first) opens odd IDs (1,
3, 5, ...) and accepts even from the responder.  We track this as
``is_client`` on Session.

This implementation supports exactly what the warpgate plugin
needs: open_stream(), accept_stream(), Stream.write(), Stream.read(),
close, plus passive WindowUpdate / Ping echo so the peer doesn't
choke.  No keepalives -- the cascade times each plugin out so a
dead muxer is reaped by the outer plugin timeout.
"""
import asyncio
import struct

from .stream_io import read_exactly


TYPE_DATA = 0
TYPE_WINDOW_UPDATE = 1
TYPE_PING = 2
TYPE_GO_AWAY = 3

FLAG_SYN = 0x1
FLAG_ACK = 0x2
FLAG_FIN = 0x4
FLAG_RST = 0x8

VERSION = 0
INITIAL_WINDOW = 256 * 1024
HEADER_FMT = ">BBHII"
HEADER_LEN = 12


def pack_header(typ, flags, stream_id, length):
    """Pack the 12-byte yamux header."""
    return struct.pack(HEADER_FMT, VERSION, typ, flags, stream_id, length)


def unpack_header(buf):
    """Unpack the 12-byte header; returns (typ, flags, stream_id, length)."""
    if len(buf) != HEADER_LEN:
        raise ValueError("yamux.unpack_header: bad header length {0}".format(len(buf)))
    version, typ, flags, stream_id, length = struct.unpack(HEADER_FMT, bytes(buf))
    if version != VERSION:
        raise ValueError("yamux.unpack_header: bad version {0}".format(version))
    return typ, flags, stream_id, length


class Stream(object):
    """One yamux stream -- read/write surface used by the warpgate plugin."""

    def __init__(self, session, stream_id, is_initiator):
        self.session = session
        self.stream_id = stream_id
        self.is_initiator = is_initiator
        self.inbox = asyncio.Queue()
        self.inbox_eof = False
        self.send_window = INITIAL_WINDOW
        self.recv_window = INITIAL_WINDOW
        self.window_event = asyncio.Event()
        self.window_event.set()
        self.closed = False
        # Did we already mark the local side as having sent SYN/ACK?
        # The first outbound frame on an initiator-opened stream
        # carries SYN; on a responder-accepted stream it carries ACK.
        self.syn_sent = not is_initiator  # initiator must send SYN; responder is implicit
        self.ack_sent = is_initiator      # responder must send ACK back; initiator is implicit
        self.partial_read = b""

    async def write(self, data):
        """Send ``data`` as one or more Data frames, respecting send_window."""
        if self.closed:
            raise ConnectionError("yamux.Stream.write: closed")
        view = memoryview(data)
        offset = 0
        max_chunk = 16 * 1024  # cap per-frame so big writes don't starve the muxer
        while offset < len(view):
            # Wait for send credit if we've hit the window.
            while self.send_window <= 0:
                self.window_event.clear()
                await self.window_event.wait()
                if self.closed:
                    raise ConnectionError("yamux.Stream.write: closed while waiting for window")
            chunk_len = min(len(view) - offset, max_chunk, self.send_window)
            chunk = bytes(view[offset:offset + chunk_len])
            flags = 0
            if not self.syn_sent:
                flags |= FLAG_SYN
                self.syn_sent = True
            if not self.ack_sent:
                flags |= FLAG_ACK
                self.ack_sent = True
            header = pack_header(TYPE_DATA, flags, self.stream_id, len(chunk))
            await self.session.send_frame(header + chunk)
            self.send_window -= chunk_len
            offset += chunk_len

    async def read(self, n=-1):
        """Read UP TO ``n`` bytes (or all available if n=-1).

        Mirrors asyncio.StreamReader.read semantics for the framed
        muxer case.  Returns b"" on clean EOF (peer FIN).
        """
        if self.partial_read:
            if n < 0 or n >= len(self.partial_read):
                out = self.partial_read
                self.partial_read = b""
                return out
            out = self.partial_read[:n]
            self.partial_read = self.partial_read[n:]
            return out
        if self.closed:
            return b""
        try:
            chunk = await self.inbox.get()
        except asyncio.CancelledError:
            raise
        if chunk is None:
            # EOF sentinel.
            return b""
        # Update recv window: as bytes are pulled out of the inbox
        # we can credit the peer with more send budget.
        await self.maybe_send_window_update(len(chunk))
        if n < 0 or n >= len(chunk):
            return chunk
        self.partial_read = chunk[n:]
        return chunk[:n]

    async def maybe_send_window_update(self, consumed):
        """If the consumed delta is significant, send WindowUpdate to peer."""
        self.recv_window -= consumed
        if self.recv_window < INITIAL_WINDOW // 2:
            delta = INITIAL_WINDOW - self.recv_window
            self.recv_window += delta
            header = pack_header(TYPE_WINDOW_UPDATE, 0, self.stream_id, delta)
            await self.session.send_frame(header)

    async def close(self):
        """Send FIN on this stream and mark locally closed."""
        if self.closed:
            return
        self.closed = True
        try:
            header = pack_header(TYPE_DATA, FLAG_FIN, self.stream_id, 0)
            await self.session.send_frame(header)
        except (OSError, ConnectionError):
            pass
        # Wake any pending readers / writers.
        self.window_event.set()
        try:
            self.inbox.put_nowait(None)
        except asyncio.QueueFull:
            pass

    def deliver_data(self, data):
        """Internal: called by the Session reader loop when a Data frame arrives."""
        if not data:
            return
        self.inbox.put_nowait(bytes(data))

    def deliver_fin(self):
        """Internal: peer sent FIN; surface EOF to read()."""
        self.inbox_eof = True
        try:
            self.inbox.put_nowait(None)
        except asyncio.QueueFull:
            pass

    def deliver_window_update(self, delta):
        """Internal: peer extended our send window."""
        self.send_window += delta
        if self.send_window > 0:
            self.window_event.set()


class Session(object):
    """One end of a yamux multiplexed connection.

    Constructed with a stream_io.PipeStream-like reader/writer pair
    and an ``is_client`` bool that determines the StreamID parity
    rule.  Call session.start() to spawn the reader loop; then use
    open_stream() / accept_stream() to get Stream objects.
    """

    def __init__(self, reader, writer, is_client):
        self.reader = reader
        self.writer = writer
        self.is_client = is_client
        self.streams = {}  # stream_id -> Stream
        self.next_stream_id = 1 if is_client else 2
        self.send_lock = asyncio.Lock()
        self.read_task = None
        self.accept_queue = asyncio.Queue()
        self.closed = False
        self.go_away = False

    def start(self):
        """Spawn the background reader loop that demuxes inbound frames."""
        if self.read_task is None:
            self.read_task = asyncio.ensure_future(self.read_loop())
        return self

    async def send_frame(self, frame_bytes):
        """Serialise frame writes so headers + bodies don't interleave on the wire."""
        if self.closed:
            raise ConnectionError("yamux.Session.send_frame: session closed")
        async with self.send_lock:
            await self.writer.write(frame_bytes)

    async def open_stream(self):
        """Open a new stream from our side; returns the Stream object.

        We assign the next odd/even ID per is_client and register the
        stream locally.  No SYN is sent here -- it goes out with the
        first Data frame written via stream.write(), per yamux spec.
        That deferral matches go-yamux's behaviour and lets us send
        zero-byte SYN+FIN to test the muxer without payload.
        """
        if self.closed:
            raise ConnectionError("yamux.Session.open_stream: session closed")
        sid = self.next_stream_id
        self.next_stream_id += 2
        s = Stream(self, sid, is_initiator=True)
        self.streams[sid] = s
        return s

    async def accept_stream(self):
        """Wait for the peer to open a stream against us; return the Stream."""
        if self.closed:
            raise ConnectionError("yamux.Session.accept_stream: session closed")
        return await self.accept_queue.get()

    async def read_loop(self):
        """Pull frames off the wire forever and dispatch to streams."""
        try:
            while not self.closed:
                header_buf = await read_exactly(self.reader, HEADER_LEN)
                typ, flags, stream_id, length = unpack_header(header_buf)
                if typ == TYPE_DATA:
                    payload = await read_exactly(self.reader, length) if length else b""
                    await self.handle_data(stream_id, flags, payload)
                elif typ == TYPE_WINDOW_UPDATE:
                    await self.handle_window_update(stream_id, flags, length)
                elif typ == TYPE_PING:
                    await self.handle_ping(flags, length)
                elif typ == TYPE_GO_AWAY:
                    self.go_away = True
                    break
                else:
                    # Unknown frame type -- per spec close the session.
                    break
        except (ConnectionError, asyncio.CancelledError, OSError, ValueError):
            pass
        finally:
            await self.close()

    async def handle_data(self, stream_id, flags, payload):
        """Dispatch a Data frame to the matching Stream, opening one if needed (SYN)."""
        s = self.streams.get(stream_id)
        if s is None and (flags & FLAG_SYN):
            # Peer opening a new stream against us.  Its parity must
            # match the "other half" of the ID space.  We accept it
            # regardless of parity -- some clients reuse IDs across
            # restarts -- but we record that ACK is owed.
            s = Stream(self, stream_id, is_initiator=False)
            s.syn_sent = True   # peer already SYN'd
            # We'll send ACK on the first Data frame we emit.
            self.streams[stream_id] = s
            await self.accept_queue.put(s)
        if s is None:
            # Stray frame for an unknown stream and no SYN -- ignore.
            return
        if payload:
            s.deliver_data(payload)
        if flags & FLAG_FIN:
            s.deliver_fin()
        if flags & FLAG_RST:
            s.deliver_fin()
            s.closed = True

    async def handle_window_update(self, stream_id, flags, delta):
        """Credit a stream's send window."""
        s = self.streams.get(stream_id)
        if s is None and (flags & FLAG_SYN):
            s = Stream(self, stream_id, is_initiator=False)
            s.syn_sent = True
            self.streams[stream_id] = s
            await self.accept_queue.put(s)
        if s is None:
            return
        s.deliver_window_update(delta)

    async def handle_ping(self, flags, opaque):
        """Echo pings (ACK them) so the peer's keepalive succeeds."""
        if flags & FLAG_SYN:
            # Reply with ACK + same opaque.
            header = pack_header(TYPE_PING, FLAG_ACK, 0, opaque)
            try:
                await self.send_frame(header)
            except (OSError, ConnectionError):
                pass

    async def close(self):
        """Send GoAway, then tear down all streams + the reader task."""
        if self.closed:
            return
        self.closed = True
        try:
            header = pack_header(TYPE_GO_AWAY, 0, 0, 0)
            await self.send_frame(header)
        except (OSError, ConnectionError):
            pass
        for s in list(self.streams.values()):
            s.closed = True
            s.window_event.set()
            try:
                s.inbox.put_nowait(None)
            except asyncio.QueueFull:
                pass
        if self.read_task is not None and not self.read_task.done():
            self.read_task.cancel()
