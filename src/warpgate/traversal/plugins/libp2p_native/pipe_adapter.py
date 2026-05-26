"""Pipe-shape adapter around a yamux Stream.

The warpgate cascade hands the winning plugin's pipe back to the
caller, which calls ``pipe.send`` / ``pipe.recv`` for application
traffic.  Our yamux Stream has the right shape but with different
method names (read/write); this adapter wraps it.

We mirror the YggdrasilPipeAdapter pattern from
plugins/yggdrasil_native/main.py so the rest of warpgate doesn't
care which overlay won the race.
"""
import asyncio

from aionetiface import TCP


class StubStream(object):
    """Minimal stand-in for Pipe.stream so subscribe/unsubscribe calls
    from the gate layer don't crash.  No actual subscription model
    is needed -- our recv() pulls straight from the yamux Stream."""

    def __init__(self):
        self.subs = {}


class StubPipeEvents(object):
    def __init__(self):
        self.stream = StubStream()


class LibP2PPipeAdapter(object):
    """Pipe-surface wrapper exposing send/recv/close around a yamux.Stream.

    Constructed by the plugin once the handshake is complete.  Holds
    a reference to the underlying LibP2PSession so close() can tear
    down the whole muxer + TCP pipe in one call -- matches what
    YggdrasilPipeAdapter does for the overlay case.
    """

    def __init__(self, stream, session, remote_peer_id):
        self.stream = stream
        self.session = session
        self.remote_peer_id = remote_peer_id
        # Sentinel attrs the gate layer pokes at.
        self.sock = stream  # non-None placeholder
        self.dest = None
        self.proto = TCP
        self.closed = False
        self.winner_plugin = "libp2p_native"
        self.pipe_events = StubPipeEvents()

    async def send(self, msg, client_tup=None):
        if self.closed:
            raise OSError("LibP2PPipeAdapter.send: closed pipe")
        await self.stream.write(msg)

    async def recv(self, sub=None):
        """Pull the next chunk of bytes from the yamux Stream."""
        if self.closed:
            return None
        return await self.stream.read(-1)

    def subscribe(self, sub):
        """No-op; recv() is the only read surface we expose."""
        return None

    async def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            await self.stream.close()
        except (OSError, ConnectionError):
            pass
        try:
            await self.session.close()
        except (OSError, ConnectionError):
            pass
