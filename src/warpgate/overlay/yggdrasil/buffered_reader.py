"""Byte-buffered reader for aionetiface Pipes (used by the Yggdrasil link).

aionetiface Pipes deliver bytes the way the underlying TCP stack
hands them up -- whatever the kernel had ready at the moment
``data_received`` fired.  That's not a message boundary in the
Yggdrasil sense (varint-prefixed packets), so we need a buffering
shim that:

  1. Accumulates whatever ``pipe.recv(SUB_ALL)`` returns into an
     internal bytearray.
  2. Exposes ``read_exact(n)`` and ``read_uvarint()`` -- the two
     primitives the link layer needs to parse handshake bytes and
     post-handshake packet frames.

There's no fixed buffer cap; oversize incoming bytes are caught at
a higher layer (the ``peerMaxMessageSize=1MB`` check in the link's
packet read loop).

Returning to small reads is cheap because we only call back into
the pipe when our buffer doesn't have enough bytes.
"""
import asyncio

from aionetiface import SUB_ALL, fstr

from .wire import decode_uvarint, MAX_VARINT_LEN


class PipeClosed(Exception):
    """Raised when the underlying Pipe returns None (peer disconnected)."""


class BufferedReader(object):
    """Stream-style reader over an aionetiface Pipe.

    ``pipe`` is an already-connected ``aionetiface.Pipe``.  The
    reader subscribes ``SUB_ALL`` on first use so any bytes
    delivered after subscribe arrive in our queue.  Callers do NOT
    need to subscribe themselves -- the Pipe's subscription model
    is hidden behind ``read_exact`` / ``read_uvarint``.
    """

    def __init__(self, pipe, default_timeout=None):
        self.pipe = pipe
        self.buf = bytearray()
        self.default_timeout = default_timeout
        self.subscribed = False
        self.closed = False

    def ensure_subscribed(self):
        """Subscribe to all bytes the Pipe delivers; no-op if already done."""
        if not self.subscribed and self.pipe is not None:
            try:
                self.pipe.subscribe(SUB_ALL)
            except (LookupError, AttributeError):
                # Some Pipe types subscribe implicitly; ignore.
                pass
            self.subscribed = True

    async def fill_some(self, timeout=None):
        """Pull one chunk of bytes from the Pipe into the buffer.

        Returns the number of bytes added.  Raises ``PipeClosed``
        if the underlying pipe has gone away or signalled close.

        ``aionetiface.Pipe.recv`` returns ``None`` on both timeout
        AND on close, so a None alone isn't enough to distinguish
        the two.  We treat None as "still alive, no bytes yet"
        and keep waiting -- our callers wrap us in
        ``asyncio.wait_for(...)`` for the overall deadline.  The
        only way to bail out is the Pipe raising an OSError /
        ConnectionError or the caller's outer wait_for tripping
        and cancelling us.
        """
        if self.closed:
            raise PipeClosed("BufferedReader: pipe already closed")
        self.ensure_subscribed()
        use_timeout = timeout if timeout is not None else self.default_timeout
        while True:
            try:
                if use_timeout is None:
                    chunk = await self.pipe.recv(SUB_ALL)
                else:
                    chunk = await self.pipe.recv(SUB_ALL, timeout=use_timeout)
            except asyncio.CancelledError:
                raise
            except (OSError, ConnectionError):
                raise PipeClosed("BufferedReader: pipe raised")
            if chunk is None:
                # Could be timeout (more bytes still coming) OR true
                # close.  Sniff by checking sock state if the Pipe
                # exposes one; otherwise loop and let the outer
                # wait_for cap our wait.
                sock = getattr(self.pipe, "sock", None)
                if sock is None:
                    raise PipeClosed("BufferedReader: pipe has no sock")
                # No chunk yet; yield + retry.  Don't hot-spin --
                # recv's own timeout means we slept at least a bit.
                continue
            self.buf.extend(chunk)
            return len(chunk)

    async def read_exact(self, n, timeout=None):
        """Read exactly ``n`` bytes.  Raises ``PipeClosed`` on EOF.

        ``timeout`` here is per-fill, not total -- a slow peer that
        feeds bytes one-at-a-time within timeout windows can keep
        the call alive for longer than ``timeout``.  This matches
        upstream's bufio behaviour where ``ReadFull`` keeps reading
        until N is reached or EOF.
        """
        if n < 0:
            raise ValueError("read_exact: n must be >= 0")
        if n == 0:
            return b""
        while len(self.buf) < n:
            added = await self.fill_some(timeout=timeout)
            if added == 0:
                raise PipeClosed(fstr(
                    "read_exact: pipe closed after {0} of {1} bytes",
                    (len(self.buf), n),
                ))
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    async def read_uvarint(self, timeout=None):
        """Read one Go-style unsigned varint.  Buffers as needed.

        Mirrors Go's ``binary.ReadUvarint(bufio.Reader)``: keeps
        pulling one byte at a time until the high bit clears OR
        we've consumed ``MAX_VARINT_LEN`` bytes (10) without
        terminating, which signals an oversized varint -- raise
        ValueError in that case so the link can drop the peer.
        """
        # Accumulate one byte at a time using the existing buffer
        # plus pipe fills so a varint that straddles a TCP chunk
        # boundary still parses cleanly.
        while True:
            try:
                value, consumed = decode_uvarint(bytes(self.buf), 0)
                del self.buf[:consumed]
                return value
            except ValueError as exc:
                if "overflow" in str(exc):
                    raise
                # Truncated; pull more bytes and retry.
                if len(self.buf) >= MAX_VARINT_LEN:
                    raise ValueError(
                        "read_uvarint: malformed varint (too long)"
                    )
                added = await self.fill_some(timeout=timeout)
                if added == 0:
                    raise PipeClosed("read_uvarint: pipe closed mid-varint")

    def close(self):
        """Mark the reader as closed.  Idempotent.  Does NOT close the Pipe --
        the link layer owns the Pipe's lifetime and decides when to
        tear it down.
        """
        self.closed = True
        self.buf.clear()
