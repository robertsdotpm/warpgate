"""Yggdrasil peer link layer -- handshake + framed packet exchange.

Port of the post-connect bits of ``src/core/link.go`` (the
``handler`` function) and the post-handshake packet framing from
``ironwood/network/peers.go``.

Wire flow on a freshly-connected TCP socket:

  1. Both sides send their ``version_metadata`` block concurrently
     with a 6-second deadline.
  2. After the handshake, every packet is varint-length-prefixed:
        ``[uvarint usize][type_byte][payload of (usize-1) bytes]``
  3. Keepalive logic:
        * Sender: after writing non-keepalive traffic, set a 3 s
          read deadline (peerTimeout).  Cleared on any inbound.
        * Receiver: after receiving non-keepalive traffic, schedule
          a 1 s timer (peerKeepAliveDelay) to send a keepalive
          unless we send something else first.
  4. Self-connect detection: peer pubkey == ours -> ErrLinkToSelf.

Receive side uses aionetiface's ``msg_cb`` push pattern (per
``Pipe.handoff_to_cb``): the Pipe's TCP layer hands raw bytes to
our msg_cb on each ``data_received`` tick, we feed them into an
internal varint parser, and emit parsed ``(type, payload)``
tuples to an asyncio queue that ``recv_packet()`` awaits.  This
avoids the ``pipe.recv()`` busy-await loop and gives a single
arrival path (matches how the TURN plugin's msg_cb refactor
landed in [[session-2026-05-24]]).

Send side stays write-on-demand (``send_packet`` builds + writes
the framed bytes synchronously).  That's symmetric with how the
ironwood writer side works (writes are scheduled by an actor and
hit the bufio.Writer immediately; framing happens on the way out,
not on the way in).
"""
import asyncio

from aionetiface import TCP, Pipe, SUB_ALL, fstr, log, log_exception

from .buffered_reader import BufferedReader, PipeClosed
from .wire import (
    MAX_VARINT_LEN,
    WIRE_DUMMY,
    WIRE_KEEP_ALIVE,
    decode_uvarint,
    encode_uvarint,
)
from .version import (
    VersionMetadata,
    HandshakeError,
    HEADER_LEN,
    PREAMBLE,
    PROTOCOL_VERSION_MAJOR,
    PROTOCOL_VERSION_MINOR,
    ERR_INVALID_PREAMBLE,
    ERR_INVALID_LENGTH,
)
from .address import addr_for_key, ipv6_str_from_bytes


# Timing constants -- match upstream defaults in core/link.go and
# ironwood/network/config.go.  Bumping these breaks wire compat with
# real Yggdrasil peers, so don't tune them lightly.
HANDSHAKE_DEADLINE_SECONDS = 6.0
PEER_KEEP_ALIVE_DELAY = 1.0
PEER_TIMEOUT = 3.0
PEER_MAX_MESSAGE_SIZE = 1 << 20  # 1 MiB


class LinkToSelf(Exception):
    """Raised when the peer's pubkey matches our own (self-connect)."""


class FrameParser(object):
    """Stateful varint-length-prefix parser fed by msg_cb chunks.

    The TCP layer hands us arbitrary-sized byte chunks via msg_cb;
    we accumulate them and emit one (packet_type, payload) tuple
    per fully-buffered Yggdrasil frame.  Internal state is a single
    bytearray + a parsing position; safe to call ``feed`` multiple
    times in quick succession.

    Frames that exceed ``PEER_MAX_MESSAGE_SIZE`` cause the parser
    to raise the next time ``next_frame`` is called -- the link
    layer treats this as a fatal protocol error.
    """

    def __init__(self):
        self.buf = bytearray()

    def feed(self, chunk):
        """Push bytes into the parser's buffer."""
        if chunk:
            self.buf.extend(chunk)

    def next_frame(self):
        """Try to extract one complete frame from the buffer.

        Returns ``(packet_type, payload_bytes)`` or ``None`` if the
        buffer doesn't yet hold a full frame.  Raises ``ValueError``
        on oversize / empty frames.
        """
        if not self.buf:
            return None
        # Try to decode the varint size.  May fail (truncated) --
        # treat that as "not yet" and return None.
        try:
            usize, consumed = decode_uvarint(bytes(self.buf), 0)
        except ValueError as exc:
            # If we've already accumulated > MAX_VARINT_LEN bytes
            # without a valid varint, that's a real protocol error.
            if len(self.buf) > MAX_VARINT_LEN and "overflow" in str(exc):
                raise
            if len(self.buf) > MAX_VARINT_LEN:
                raise ValueError("FrameParser: malformed varint header")
            return None
        if usize > PEER_MAX_MESSAGE_SIZE:
            raise ValueError(fstr(
                "FrameParser: oversize frame {0} > max {1}",
                (usize, PEER_MAX_MESSAGE_SIZE),
            ))
        if usize < 1:
            raise ValueError("FrameParser: empty frame")
        # Do we have the whole body yet?
        if len(self.buf) < consumed + usize:
            return None
        # Consume the frame.
        body = bytes(self.buf[consumed : consumed + usize])
        del self.buf[: consumed + usize]
        packet_type = body[0]
        payload = body[1:]
        return packet_type, payload


class PeerLink(object):
    """A single live Yggdrasil peer link.

    Wraps an aionetiface Pipe with the post-handshake framing layer.
    Recv path uses ``Pipe.handoff_to_cb`` so the TCP layer pushes
    bytes through our parser into ``inbound_queue``; ``recv_packet()``
    is a thin queue-await.

    Constructed via ``open_outbound`` / ``open_inbound`` -- never
    directly.
    """

    def __init__(self, transport, remote_meta, local_pubkey, link_type):
        # v2: transport is a yggdrasil.transport.Transport (PipeTransport
        # in production; LoopbackTransport / ReplayTransport in tests).
        # The Transport interface gives us send/recv/close/msg_cb +
        # closed_event uniformly across real and simulated I/O, so
        # this code no longer has any pipe-specific knowledge.
        #
        # Backwards-compat: if a caller still passes a raw Pipe
        # (older tests or warpgate plugin code that hasn't been
        # ported), auto-wrap in PipeTransport so the upgrade is
        # incremental.
        from .transport import Transport, PipeTransport
        if not isinstance(transport, Transport):
            transport = PipeTransport(transport)
        self.transport = transport
        self.remote_meta = remote_meta
        self.remote_pubkey = remote_meta.public_key
        self.remote_priority = remote_meta.priority
        self.local_pubkey = local_pubkey
        self.link_type = link_type  # "outbound" or "inbound"
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.closed = False

        # Inbound parser + queue.  The msg_cb feeds bytes into
        # ``parser`` and drains complete frames into ``inbound_queue``;
        # recv_packet() awaits on the queue.
        self.parser = FrameParser()
        # Note: maxsize=0 (unbounded) keeps the msg_cb non-blocking;
        # the Pipe's own TCP backpressure naturally bounds memory
        # use because data_received only fires when the kernel has
        # buffered bytes, and we drain via recv_packet.
        self.inbound_queue = asyncio.Queue()
        # Sentinel pushed to wake any pending recv_packet on close.
        self.recv_closed_sentinel = object()

        # Lock around outbound writes so concurrent send_packet calls
        # serialise on the same Pipe (varint+type+payload bytes must
        # land contiguously).
        self.send_lock = asyncio.Lock()

        # Keepalive timer handle.
        self.pending_keepalive_handle = None

        # Close-watcher task -- spawned by install_msg_cb to wake
        # the recv loop on a graceful peer disconnect.  None until
        # install_msg_cb runs.
        self.close_watcher = None

    @property
    def remote_addr(self):
        """Derived 200::/7 IPv6 address string for the remote peer."""
        return ipv6_str_from_bytes(addr_for_key(self.remote_pubkey))

    def install_msg_cb(self):
        """Register our byte-parser cb on the transport.

        Called by ``open_outbound`` / ``open_inbound`` AFTER the
        handshake completes.  The handshake function uses an
        ad-hoc cb that drives wait-for-N-bytes; this method
        installs the long-running parser cb that decodes
        varint-framed packets.

        Also wires the transport's ``closed_event`` to our
        ``fatal_close`` so a graceful peer disconnect wakes any
        pending ``recv_packet()`` awaiter promptly (without
        this, a clean FIN leaves recv_packet blocked forever --
        the peer-task-leak bug caught by
        ``test_yggdrasil_stress.TestPeerChurnLoopback``).
        """

        def on_bytes(data, transport):
            """msg_cb: feed bytes into the parser, drain complete frames."""
            if self.closed:
                return
            try:
                self.parser.feed(data)
                while True:
                    frame = self.parser.next_frame()
                    if frame is None:
                        break
                    packet_type, payload = frame
                    self.rx_bytes += 1 + len(payload)
                    # Receiver-side keepalive logic.
                    if packet_type not in (WIRE_DUMMY, WIRE_KEEP_ALIVE):
                        self.schedule_keepalive()
                    # Hand the frame to whoever's awaiting recv_packet.
                    try:
                        self.inbound_queue.put_nowait((packet_type, payload))
                    except asyncio.QueueFull:
                        log("peer_link: inbound_queue full, dropping frame")
            except ValueError:
                # Protocol error -- tear down the link.  Cleanup runs
                # via the next recv_packet caller seeing the sentinel.
                log_exception()
                self.fatal_close()

        self.transport.add_msg_cb(on_bytes)

        # Arm the close-watcher on the transport's unified close
        # event.  Transport.closed_event fires on any underlying
        # close source (Pipe FIN, LoopbackTransport peer-close,
        # ReplayTransport stage_eof) so this works uniformly.
        try:
            self.close_watcher = asyncio.ensure_future(self.watch_transport_close())
        except RuntimeError:
            # No running event loop (sync tests); skip the watcher.
            self.close_watcher = None

    async def watch_transport_close(self):
        """Wait for the transport's close event then mark the link closed.

        Drives the recv_packet sentinel so the NodeCore.peer_recv_loop
        wakes promptly when the remote peer disconnects.  Without
        this, a graceful FIN from the peer leaves recv_packet
        blocked on the inbound queue forever, and NodeCore leaks
        the peer_tasks + PeerEntry slot.

        Eats CancelledError silently: cancellation is the normal
        path when ``close()`` runs before the peer ever
        disconnects, and the parent task has no recovery action
        to take in that case.
        """
        event = self.transport.closed_event
        try:
            await event.wait()
        except asyncio.CancelledError:
            return
        self.fatal_close()

    def fatal_close(self):
        """Mark the link closed and wake any recv_packet caller.  Sync, callable from msg_cb."""
        if self.closed:
            return
        self.closed = True
        if self.close_watcher is not None:
            try:
                self.close_watcher.cancel()
            except Exception:
                pass
            self.close_watcher = None
        try:
            self.inbound_queue.put_nowait((None, self.recv_closed_sentinel))
        except asyncio.QueueFull:
            pass

    async def send_packet(self, packet_type, payload=b""):
        """Send one varint-prefixed packet to the peer.

        ``packet_type`` is one of the ``WIRE_*`` constants.
        Raises ``PipeClosed`` if the link is torn down.
        """
        if self.closed:
            raise PipeClosed("send_packet: link is closed")
        if not isinstance(payload, (bytes, bytearray)):
            raise ValueError("send_packet: payload must be bytes")
        body_size = len(payload) + 1
        if body_size > PEER_MAX_MESSAGE_SIZE:
            raise ValueError(fstr(
                "send_packet: body {0} > max {1}",
                (body_size, PEER_MAX_MESSAGE_SIZE),
            ))
        wire = encode_uvarint(body_size) + bytes([packet_type]) + bytes(payload)
        async with self.send_lock:
            try:
                sent = await self.transport.send(wire)
            except Exception as exc:
                raise PipeClosed(
                    "send_packet: transport send raised: {0}".format(repr(exc))
                )
            if sent in (None, 0):
                raise PipeClosed("send_packet: transport send returned 0")
            self.tx_bytes += len(wire)
            # Sender-side keepalive logic: clear pending keepalive
            # if we just sent non-keepalive traffic (no need to chase).
            if packet_type not in (WIRE_DUMMY, WIRE_KEEP_ALIVE):
                self.cancel_pending_keepalive()

    async def recv_packet(self):
        """Await one inbound packet.  Returns ``(packet_type, payload)``.

        Raises ``PipeClosed`` if the link is closed (either by us
        or by the peer); the close path pushes a sentinel into the
        queue so a pending caller wakes promptly.
        """
        if self.closed:
            raise PipeClosed("recv_packet: link is closed")
        item = await self.inbound_queue.get()
        if item[1] is self.recv_closed_sentinel:
            raise PipeClosed("recv_packet: link closed during recv")
        return item

    def schedule_keepalive(self):
        """Arm the keepalive timer.  Idempotent."""
        if self.closed:
            return
        self.cancel_pending_keepalive()
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            return
        self.pending_keepalive_handle = loop.call_later(
            PEER_KEEP_ALIVE_DELAY, self.fire_keepalive
        )

    def cancel_pending_keepalive(self):
        """Cancel the pending keepalive (no-op if none)."""
        h = self.pending_keepalive_handle
        if h is not None:
            try:
                h.cancel()
            except Exception:
                pass
            self.pending_keepalive_handle = None

    def fire_keepalive(self):
        """Loop callback: schedule the keepalive send.  Internal."""
        self.pending_keepalive_handle = None
        if self.closed:
            return
        asyncio.ensure_future(self.send_keepalive_safe())

    async def send_keepalive_safe(self):
        """Send a keepalive, swallowing transport errors."""
        try:
            await self.send_packet(WIRE_KEEP_ALIVE, b"")
        except (PipeClosed, OSError, ConnectionError):
            pass

    async def close(self):
        """Tear down the link.  Idempotent."""
        if self.closed:
            return
        self.closed = True
        self.cancel_pending_keepalive()
        watcher = self.close_watcher
        self.close_watcher = None
        if watcher is not None:
            try:
                watcher.cancel()
            except Exception:
                pass
            # Briefly await the watcher so the cancellation
            # propagates through the asyncio internals and the
            # task transitions to "done" before we exit close().
            # Without this, Python 3.5 occasionally reports
            # "Task exception was never retrieved" for the
            # cancelled watcher because the GC sees the task
            # still in the not-yet-run-cancelled state.
            try:
                await watcher
            except (asyncio.CancelledError, Exception):
                pass
        try:
            self.inbound_queue.put_nowait((None, self.recv_closed_sentinel))
        except asyncio.QueueFull:
            pass
        try:
            await self.transport.close()
        except asyncio.CancelledError:
            raise
        except Exception:
            log_exception()


async def handshake_over_transport(transport, private_seed, public_key,
                                   password=b"", priority=0,
                                   deadline=HANDSHAKE_DEADLINE_SECONDS):
    """Drive a Yggdrasil version_metadata handshake on a Transport.

    Returns ``(remote_meta, leftover_bytes)`` on success.  Raises
    ``HandshakeError`` on protocol-level failure, ``LinkToSelf``
    on self-connect, ``asyncio.TimeoutError`` on deadline expiry.

    v2: takes a Transport (not a raw Pipe) so the same code runs
    against real TCP, in-memory loopback, or replay-from-bytes.

    The receive side uses ``transport.add_msg_cb`` from the moment
    we start, so any bytes the transport already delivered land
    in our buffer.  AFTER this function returns, the caller is
    expected to install the PeerLink steady-state msg_cb; the
    handshake cb is removed via ``del_msg_cb`` before we return.
    """
    if not isinstance(public_key, (bytes, bytearray)):
        raise ValueError("public_key must be bytes")

    meta = VersionMetadata(
        major_ver=PROTOCOL_VERSION_MAJOR,
        minor_ver=PROTOCOL_VERSION_MINOR,
        public_key=bytes(public_key),
        priority=priority,
    )
    wire = meta.encode(bytes(private_seed), password=bytes(password))

    incoming = bytearray()
    bytes_arrived = asyncio.Event()

    def on_bytes(data, transport_arg):
        if not data:
            return
        incoming.extend(data)
        bytes_arrived.set()

    transport.add_msg_cb(on_bytes)

    async def wait_for_n(n):
        while len(incoming) < n:
            bytes_arrived.clear()
            if transport.is_closed():
                raise HandshakeError(
                    "handshake: transport closed during read"
                )
            await bytes_arrived.wait()
        head = bytes(incoming[:n])
        del incoming[:n]
        return head

    async def do_handshake():
        try:
            sent = await transport.send(wire)
        except Exception as exc:
            raise HandshakeError(
                "handshake: send raised: {0}".format(repr(exc))
            )
        if sent in (None, 0):
            raise HandshakeError("handshake: transport send returned 0")

        head = await wait_for_n(HEADER_LEN)
        if head[:4] != PREAMBLE:
            raise HandshakeError(ERR_INVALID_PREAMBLE)
        import struct
        body_len = struct.unpack(">H", head[4:6])[0]
        if body_len < 64:
            raise HandshakeError(ERR_INVALID_LENGTH)
        body = await wait_for_n(body_len)
        remote_meta = VersionMetadata.decode(
            head + body, password=bytes(password),
        )
        if not remote_meta.check():
            raise HandshakeError(fstr(
                "handshake: version mismatch (local {0}.{1}, remote {2}.{3})",
                (
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    remote_meta.major_ver, remote_meta.minor_ver,
                ),
            ))
        if remote_meta.public_key == bytes(public_key):
            raise LinkToSelf("handshake: remote pubkey equals local")
        return remote_meta, bytes(incoming)

    try:
        result = await asyncio.wait_for(do_handshake(), timeout=deadline)
    finally:
        try:
            transport.del_msg_cb(on_bytes)
        except Exception:
            pass
    return result


async def handshake_over_pipe(pipe_or_transport, private_seed, public_key,
                              password=b"", priority=0,
                              deadline=HANDSHAKE_DEADLINE_SECONDS):
    """Backwards-compat shim.  Auto-wraps a raw Pipe in PipeTransport.

    Existing tests and the warpgate plugin layer call this with
    raw aionetiface Pipe objects.  Detect that by absence of
    ``is_closed`` (a Transport method) and wrap before delegating.
    """
    from .transport import PipeTransport, Transport
    if isinstance(pipe_or_transport, Transport):
        transport = pipe_or_transport
    else:
        transport = PipeTransport(pipe_or_transport)
    return await handshake_over_transport(
        transport, private_seed, public_key,
        password=password, priority=priority,
        deadline=deadline,
    )


async def open_outbound(dest_addr, dest_port, route,
                        private_seed, public_key,
                        password=b"", priority=0,
                        link_proto="tcp",
                        deadline=HANDSHAKE_DEADLINE_SECONDS):
    """Dial a Yggdrasil peer over TCP or TLS and complete the handshake.

    ``link_proto`` is "tcp" or "tls".  TLS uses aionetiface Pipe's
    ``use_ssl`` conf flag (which sets up a TLS context with
    cert-verify disabled -- Yggdrasil peers use self-signed certs
    and the link-layer identity proof is the ed25519 handshake,
    not the TLS cert).  Returns a fully-open PeerLink in msg_cb
    push mode.
    """
    if link_proto not in ("tcp", "tls"):
        raise ValueError(fstr(
            "open_outbound: only 'tcp' or 'tls' supported, got {0}",
            (link_proto,),
        ))
    from aionetiface import NET_CONF
    conf = dict(NET_CONF)
    conf["use_ssl"] = (link_proto == "tls")
    pipe = Pipe(TCP, dest=(dest_addr, int(dest_port)), route=route, conf=conf)
    await pipe.connect()
    if pipe.sock is None:
        raise OSError("open_outbound: pipe failed to connect")
    log(fstr(
        "yggdrasil: outbound dial dest={0}:{1}",
        (dest_addr, dest_port),
    ))
    from .transport import PipeTransport
    transport = PipeTransport(pipe)
    try:
        remote_meta, leftover = await handshake_over_transport(
            transport, private_seed, public_key,
            password=password, priority=priority,
            deadline=deadline,
        )
    except Exception:
        try:
            await transport.close()
        except Exception:
            pass
        raise
    link = PeerLink(transport, remote_meta, public_key, "outbound")
    if leftover:
        link.parser.feed(leftover)
    link.install_msg_cb()
    return link


async def open_inbound(pipe, private_seed, public_key,
                       password=b"", priority=0,
                       deadline=HANDSHAKE_DEADLINE_SECONDS):
    """Accept-side handshake on an already-connected Pipe.

    Returns a fully-open PeerLink in msg_cb push mode.
    """
    from .transport import PipeTransport
    transport = PipeTransport(pipe)
    remote_meta, leftover = await handshake_over_transport(
        transport, private_seed, public_key,
        password=password, priority=priority,
        deadline=deadline,
    )
    link = PeerLink(transport, remote_meta, public_key, "inbound")
    if leftover:
        link.parser.feed(leftover)
    link.install_msg_cb()
    return link


# Transport-native variants for v2 callers (loopback / replay)
# that already have a Transport in hand and don't want the Pipe
# wrapping dance.  These exist alongside open_outbound /
# open_inbound for the warpgate-plugin use case which still
# operates on Pipe objects from aionetiface.

async def open_inbound_transport(transport, private_seed, public_key,
                                 password=b"", priority=0,
                                 deadline=HANDSHAKE_DEADLINE_SECONDS):
    """Accept-side handshake driven directly on a Transport.

    No Pipe wrapping -- use this when the caller built a
    LoopbackTransport / ReplayTransport for testing or already
    has a non-Pipe transport (a future TLS-wrapped variant, a
    WebSocket transport, etc.).
    """
    remote_meta, leftover = await handshake_over_transport(
        transport, private_seed, public_key,
        password=password, priority=priority,
        deadline=deadline,
    )
    link = PeerLink(transport, remote_meta, public_key, "inbound")
    if leftover:
        link.parser.feed(leftover)
    link.install_msg_cb()
    return link


async def open_outbound_transport(transport, private_seed, public_key,
                                  password=b"", priority=0,
                                  deadline=HANDSHAKE_DEADLINE_SECONDS):
    """Outbound-side handshake driven directly on a Transport.

    Symmetric with ``open_inbound_transport``; the protocol is
    initiator-agnostic so the distinction is just bookkeeping
    (and the ``link_type`` field set on the returned PeerLink).
    """
    remote_meta, leftover = await handshake_over_transport(
        transport, private_seed, public_key,
        password=password, priority=priority,
        deadline=deadline,
    )
    link = PeerLink(transport, remote_meta, public_key, "outbound")
    if leftover:
        link.parser.feed(leftover)
    link.install_msg_cb()
    return link
