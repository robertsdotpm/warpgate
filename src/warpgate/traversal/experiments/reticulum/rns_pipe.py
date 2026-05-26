"""Pipe-compatible adapter wrapping a Reticulum (RNS) Link.

Reticulum's transport is application-layer, not socket-layer: there
is no kernel file descriptor backing an RNS Link the way a socket
backs an aionetiface Pipe.  So we cannot return a real
``aionetiface.Pipe`` from the Reticulum plugin -- the higher layers
of warpgate use ``pipe.send`` / ``pipe.recv`` / ``pipe.close`` and a
truthy ``pipe.sock`` to test "did the plugin produce a working
pipe", and that's the contract this adapter implements.

The adapter is bidirectional and buffers inbound bytes through an
``asyncio.Queue`` so the warpgate-side ``recv()`` shape (an
awaitable that returns bytes or None) lines up with the RNS-side
callback model (a synchronous "packet_callback" that fires from
the RNS dispatch thread).
"""
import asyncio
from aionetiface import log, log_exception, fstr


# Sentinel placed on the inbound queue to signal a clean close so
# any pending recv() can resolve to None instead of hanging.
QUEUE_CLOSE_SENTINEL = object()


class RNSStubStream:
    """Minimal stand-in for aionetiface PipeEvents.stream.subs surface.

    Gate.listen flips ``pipe.pipe_events.stream.subs = {}`` to disable
    subscription multiplexing when a managed listener owns the
    pipe.  Reticulum has no subscription model -- inbound bytes
    flow through one queue -- so we expose a writable dict and let
    the assignment succeed without doing anything with it.
    """

    def __init__(self):
        self.subs = {}


class RNSStubPipeEvents:
    """Minimal stand-in for aionetiface Pipe.pipe_events surface."""

    def __init__(self):
        self.stream = RNSStubStream()


class RNSPipe:
    """Bidirectional Pipe-like adapter over a single RNS Link."""

    def __init__(self, link, loop=None):
        """Build an RNSPipe around an already-established RNS Link.

        ``link`` is whatever the underlying RNS client returns from
        its session setup -- the adapter only uses three methods on
        it: ``send_buffer(bytes)`` / ``set_packet_callback(cb)`` /
        ``teardown()``.  Real RNS Link objects expose those names;
        tests can substitute a mock that does the same.  ``loop`` is
        the asyncio event loop the inbound callback should hand work
        off to (RNS callbacks fire from its own threads).
        """
        self.link = link
        self.loop = loop
        self.sock = link  # Non-None sentinel for warpgate's pipe-validity check.
        self.dest = None
        self.proto = None
        self.pipe_events = RNSStubPipeEvents()
        # Queue of inbound bytes (or QUEUE_CLOSE_SENTINEL).
        self.inbound = asyncio.Queue()
        self.closed = False
        self.winner_plugin = "reticulum"
        # Wire the link's inbound callback.  If the underlying object
        # doesn't support it we still expose recv() but no bytes will
        # ever arrive -- this lets a half-built mock fail loudly at
        # send-time rather than crashing the constructor.
        try:
            link.set_packet_callback(self.on_packet)
        except AttributeError:
            log("RNSPipe: link has no set_packet_callback -- inbound will hang")

    def on_packet(self, data, packet=None):
        """RNS-side callback: push ``data`` bytes into the asyncio queue.

        Called from the RNS dispatch thread, NOT the asyncio loop.
        We schedule a thread-safe queue put via ``call_soon_threadsafe``
        so the loop sees the new item and any awaiting recv()
        unblocks.  ``packet`` is the RNS Packet object -- discarded;
        only the bytes matter to the warpgate layer.
        """
        if self.closed:
            return
        loop = self.loop
        if loop is None:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                return
        try:
            loop.call_soon_threadsafe(self.inbound.put_nowait, data)
        except RuntimeError:
            # Loop closed mid-callback; drop silently.
            return

    async def send(self, msg, client_tup=None):
        """Push ``msg`` (bytes) across the RNS Link.

        ``client_tup`` is accepted for surface parity with the
        TCP-server Pipe API but ignored: an RNS Link is a one-to-one
        session, not a multi-client server.
        """
        if self.closed:
            raise OSError("RNSPipe: send on closed pipe")
        try:
            self.link.send_buffer(msg)
        except AttributeError as exc:
            raise OSError(fstr(
                "RNSPipe: link has no send_buffer ({0})",
                (repr(exc),),
            ))

    async def recv(self, sub=None):
        """Await the next inbound bytes; return None on clean close.

        ``sub`` is the aionetiface subscription tag and is ignored --
        RNS has no subscription model.
        """
        if self.closed:
            return None
        try:
            item = await self.inbound.get()
        except asyncio.CancelledError:
            raise
        if item is QUEUE_CLOSE_SENTINEL:
            return None
        return item

    def subscribe(self, sub):
        """No-op: RNS has no subscription tagging, every recv gets every byte."""
        return None

    async def close(self):
        """Tear down the underlying RNS Link.  Idempotent."""
        if self.closed:
            return
        self.closed = True
        # Unblock any pending recv().
        try:
            self.inbound.put_nowait(QUEUE_CLOSE_SENTINEL)
        except asyncio.QueueFull:
            pass
        try:
            self.link.teardown()
        except (AttributeError, OSError):
            log_exception()
