"""Transport abstraction for the Yggdrasil port -- v2 simulation-compatible.

The original (v1) code assumed an ``aionetiface.Pipe`` everywhere
bytes crossed the network boundary.  That made the codebase
impossible to unit-test without a real socket pair: every test
either span up loopback Pipes or skipped the network bits.

v2 separates the WIRE (bytes in/out) from the ALGORITHM (state
machines that decide what to write or expect).  Anything that
exchanges bytes with a peer takes a ``Transport`` instead of a
Pipe directly.  Three concrete transports:

  * ``PipeTransport``     -- wraps an aionetiface.Pipe (production)
  * ``LoopbackTransport`` -- pair of in-memory byte queues
                              (deterministic two-side tests)
  * ``ReplayTransport``   -- bytes to ``recv`` come from a pre-
                              recorded list; bytes from ``send``
                              are captured for assertions
                              (replay tests + scenario catalog)

Refactoring rule (per the user's directive): do NOT shim around
the old Pipe API.  Anywhere we used to take a Pipe, take a
Transport instead.  PipeTransport adapts the Pipe to the
Transport API; no shim hidden the other way.

Transport contract
==================
Every Transport exposes the same minimal surface:

  ``async def send(data: bytes) -> int``
      Write all bytes.  Returns count.  Raises OSError /
      ConnectionError on transport failure; raises ``TransportClosed``
      if close() has run.

  ``def add_msg_cb(cb)``
      Register ``cb(data: bytes, transport: Transport)`` which
      fires whenever bytes arrive.  Multiple cbs allowed.  Matches
      aionetiface's push-mode msg_cb semantics.

  ``def del_msg_cb(cb)``
      Remove a previously-registered cb.

  ``async def recv(timeout=None) -> bytes | None``
      Pull-mode: wait for the next chunk.  ``None`` on close.
      Mainly used for handshake bytes during version_metadata
      exchange where we want a deterministic deadline.

  ``async def close()``
      Tear down + fire close handlers + reject future sends.

  ``def is_closed() -> bool``
"""
import asyncio

from aionetiface import SUB_ALL, fstr, log, log_exception


class TransportClosed(Exception):
    """Raised on send / recv after close()."""


class Transport(object):
    """Abstract base.  Subclasses MUST override send / recv / close.

    The common cb dispatching + close-event plumbing lives here so
    every concrete transport behaves identically from the
    consumer's POV.
    """

    def __init__(self):
        self.msg_cbs = set()
        self.close_cbs = set()
        self.closed_event = asyncio.Event()
        # Per-transport monotonic byte counter, exposed for tests
        # and the admin API; not part of the wire protocol.
        self.tx_bytes = 0
        self.rx_bytes = 0

    def add_msg_cb(self, cb):
        self.msg_cbs.add(cb)

    def del_msg_cb(self, cb):
        self.msg_cbs.discard(cb)

    def add_close_cb(self, cb):
        self.close_cbs.add(cb)

    def deliver(self, data):
        """Subclass-internal: route ``data`` to every registered msg_cb.

        Tracks rx_bytes and gracefully swallows cb exceptions
        (a single bad cb should NOT poison the rest of the chain).
        """
        if not data:
            return
        self.rx_bytes += len(data)
        for cb in list(self.msg_cbs):
            try:
                cb(data, self)
            except Exception:
                log_exception()

    def fire_close(self):
        """Subclass-internal: mark closed + fire close_cbs."""
        self.closed_event.set()
        for cb in list(self.close_cbs):
            try:
                cb(self)
            except Exception:
                log_exception()

    def is_closed(self):
        return self.closed_event.is_set()

    async def send(self, data):
        raise NotImplementedError

    async def recv(self, timeout=None):
        raise NotImplementedError

    async def close(self):
        raise NotImplementedError


class PipeTransport(Transport):
    """Production transport: wraps an aionetiface.Pipe.

    Two race windows to handle:

    1. Bytes already in the pipe's SUB_ALL queue at wrap time
       (Pipe.connect auto-subscribed and bytes arrived before
       we wrapped).  Resolved by calling ``handoff_to_cb`` --
       atomically drains the queue through our forwarding cb
       and switches the pipe to push mode.

    2. The drained / inbound bytes arrive on ``on_pipe_bytes``
       BEFORE any consumer has registered an add_msg_cb on us.
       Those bytes would fan out to the empty msg_cbs set and
       vanish.  Resolved by buffering: anything we receive
       while msg_cbs is empty goes into ``predelivery_buffer``,
       and on the first add_msg_cb the buffer is flushed into
       that cb.
    """

    def __init__(self, pipe):
        super().__init__()
        self.pipe = pipe
        # Buffer for bytes that arrive before any consumer
        # registers.  Replayed into the first add_msg_cb in
        # arrival order, then dropped.
        self.predelivery_buffer = []
        # Wire the pipe's close event to fire OUR close callback
        # so consumers see a unified transport-level close signal
        # (Transport's closed_event) regardless of which underlying
        # layer noticed the disconnect first.  Watcher armed BEFORE
        # handoff to avoid an even-smaller race where the pipe
        # closes between our wrap and the watcher arming.
        on_close = getattr(pipe, "on_close", None)
        if on_close is not None:
            try:
                self.close_watcher = asyncio.ensure_future(
                    self.watch_pipe_close(on_close),
                )
            except RuntimeError:
                self.close_watcher = None
        else:
            self.close_watcher = None
        # handoff_to_cb is the atomic "drain SUB_ALL queue +
        # switch to push-mode + register this cb" primitive
        # aionetiface exposes.  Falls back to add_msg_cb on test
        # stubs that don't implement handoff.
        try:
            pipe.handoff_to_cb(self.on_pipe_bytes)
        except AttributeError:
            pipe.add_msg_cb(self.on_pipe_bytes)

    def add_msg_cb(self, cb):
        """Register a consumer + flush any buffered bytes into it.

        Overrides Transport.add_msg_cb because predelivery_buffer
        only matters for PipeTransport (LoopbackTransport and
        ReplayTransport handle buffering differently or not at
        all).  The flush happens BEFORE the cb is added to the
        set so the first delivery the new cb sees IS the first
        buffered chunk -- no out-of-order surprises.
        """
        if self.predelivery_buffer:
            buffered = list(self.predelivery_buffer)
            self.predelivery_buffer = []
            for data in buffered:
                try:
                    cb(data, self)
                except Exception:
                    log_exception()
        super().add_msg_cb(cb)

    async def watch_pipe_close(self, event):
        try:
            await event.wait()
        except asyncio.CancelledError:
            return
        if not self.is_closed():
            self.fire_close()

    def on_pipe_bytes(self, data, client_tup, pipe_arg):
        # aionetiface msg_cb signature is (data, client_tup, pipe);
        # we translate to Transport's (data, transport) shape.
        if self.is_closed():
            return
        if not self.msg_cbs:
            # No consumer subscribed yet -- buffer for replay on
            # the first add_msg_cb so the bytes that arrived
            # immediately after pipe wrap don't vanish.
            self.predelivery_buffer.append(bytes(data))
            self.rx_bytes += len(data)
            return
        self.deliver(data)

    async def send(self, data):
        if self.is_closed():
            raise TransportClosed("PipeTransport: send on closed pipe")
        sent = await self.pipe.send(data)
        if sent in (None, 0):
            raise TransportClosed("PipeTransport: pipe.send returned 0")
        self.tx_bytes += len(data)
        return len(data)

    async def recv(self, timeout=None):
        if self.is_closed():
            return None
        if timeout is None:
            chunk = await self.pipe.recv(SUB_ALL)
        else:
            chunk = await self.pipe.recv(SUB_ALL, timeout=timeout)
        if chunk is None:
            return None
        self.rx_bytes += len(chunk)
        return chunk

    async def close(self):
        if self.is_closed():
            return
        try:
            self.pipe.del_msg_cb(self.on_pipe_bytes)
        except Exception:
            pass
        self.fire_close()
        watcher = self.close_watcher
        self.close_watcher = None
        if watcher is not None:
            try:
                watcher.cancel()
                await watcher
            except (asyncio.CancelledError, Exception):
                pass
        try:
            await self.pipe.close()
        except Exception:
            log_exception()


class LoopbackTransport(Transport):
    """Pair of in-memory queues -- both sides see each other's writes.

    Constructed via the ``loopback_pair()`` factory which returns
    two LoopbackTransport instances cross-wired.  Used for
    deterministic two-side scenario tests with zero real I/O.
    """

    def __init__(self):
        super().__init__()
        self.inbound = asyncio.Queue()
        # Set by loopback_pair to point at the OTHER side.
        self.peer = None

    async def send(self, data):
        if self.is_closed():
            raise TransportClosed("LoopbackTransport: send on closed")
        if self.peer is None:
            raise TransportClosed("LoopbackTransport: no peer wired")
        if self.peer.is_closed():
            raise TransportClosed("LoopbackTransport: peer closed")
        self.tx_bytes += len(data)
        # Push to peer's inbound queue AND fire their msg_cbs.
        await self.peer.inbound.put(bytes(data))
        self.peer.deliver(bytes(data))
        return len(data)

    async def recv(self, timeout=None):
        if self.is_closed():
            return None
        try:
            if timeout is None:
                return await self.inbound.get()
            return await asyncio.wait_for(self.inbound.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def close(self):
        if self.is_closed():
            return
        self.fire_close()
        # Wake any pending recv on our side.
        try:
            self.inbound.put_nowait(None)
        except Exception:
            pass
        # Propagate to peer so they see EOF too.
        if self.peer is not None and not self.peer.is_closed():
            await self.peer.close()


def loopback_pair():
    """Return ``(a, b)`` -- two LoopbackTransports cross-wired.

    Bytes sent on ``a`` arrive on ``b``'s recv / msg_cbs, and
    vice versa.  Closing either side closes the other.
    """
    a = LoopbackTransport()
    b = LoopbackTransport()
    a.peer = b
    b.peer = a
    return a, b


class ReplayTransport(Transport):
    """Transport whose recv stream is a pre-recorded list of bytes
    chunks; send captures bytes for later assertion.

    Used by the v2 scenario tests to replay a captured packet
    stream against the algorithm code without any real I/O.

    Usage:

        rt = ReplayTransport(inbound_chunks=[b"meta...", b"announce..."])
        link = PeerLink(rt, ...)         # algorithm under test
        await link.do_handshake()
        # rt.sent_chunks now contains everything the link tried
        # to write, ready to assert on.
    """

    def __init__(self, inbound_chunks=None):
        super().__init__()
        self.inbound = asyncio.Queue()
        if inbound_chunks:
            for chunk in inbound_chunks:
                self.inbound.put_nowait(bytes(chunk))
        self.sent_chunks = []
        # When True, deliver inbound chunks to msg_cbs as soon
        # as they're staged AND recv() also drains the same queue.
        # This matches what a real pipe does (push + pull both
        # work).  Subscribers see every chunk.
        self.push_on_stage = True

    def stage_inbound(self, *chunks):
        """Add more bytes to the recv-stream + fire msg_cbs.

        Mirrors what a peer would do mid-conversation -- staged
        chunks are visible to BOTH ``recv()`` and any registered
        ``msg_cb``.  Returns the count staged for the caller's
        convenience.
        """
        for chunk in chunks:
            self.inbound.put_nowait(bytes(chunk))
            if self.push_on_stage:
                self.deliver(bytes(chunk))
        return len(chunks)

    def stage_eof(self):
        """Signal end-of-stream so any pending recv() returns None."""
        self.inbound.put_nowait(None)

    async def send(self, data):
        if self.is_closed():
            raise TransportClosed("ReplayTransport: send on closed")
        self.tx_bytes += len(data)
        self.sent_chunks.append(bytes(data))
        return len(data)

    async def recv(self, timeout=None):
        if self.is_closed():
            return None
        try:
            if timeout is None:
                item = await self.inbound.get()
            else:
                item = await asyncio.wait_for(
                    self.inbound.get(), timeout=timeout,
                )
        except asyncio.TimeoutError:
            return None
        if item is None:
            # EOF sentinel; close ourselves.
            self.fire_close()
            return None
        return item

    async def close(self):
        if self.is_closed():
            return
        self.fire_close()

    def all_sent_bytes(self):
        """Concatenate every chunk send() ever wrote, for byte-level
        assertions (e.g. 'the wire output equals this golden hex')."""
        return b"".join(self.sent_chunks)
