"""Libp2pNode: TCP listener + dialer + handshake pipeline.

One Libp2pNode per warpgate Node; the traversal plugin asks it to
listen on a NIC/route and to dial a peer Pipe with full libp2p
stack negotiation.  The application-layer protocol opened on top
of yamux is /warpgate/relay/1.0.0 -- a private name so we don't
collide with anything else in the libp2p ecosystem.

Flow on a fresh inbound TCP pipe (responder side):
    1. Wrap Pipe in PipeStream
    2. multistream-select header + accept /plaintext/2.0.0
    3. plaintext.perform_handshake -> remote PeerID + pubkey
    4. multistream-select accept /yamux/1.0.0
    5. start yamux.Session(is_client=False)
    6. session.accept_stream() -> Stream
    7. multistream-select inside stream: accept /warpgate/relay/1.0.0
    8. Yield (Stream, remote_peer_id) to the plugin

Flow on dial (initiator):
    1. Pipe(TCP, dest, route).connect()
    2. Wrap in PipeStream
    3. multistream-select propose /plaintext/2.0.0
    4. plaintext.perform_handshake -> remote PeerID + pubkey
    5. multistream-select propose /yamux/1.0.0
    6. start yamux.Session(is_client=True)
    7. open_stream() -> Stream
    8. multistream-select inside stream: propose /warpgate/relay/1.0.0
    9. Yield (Stream, remote_peer_id) to the plugin
"""
import asyncio

from aionetiface import TCP, Pipe, fstr, log, log_exception

from .multistream import (
    negotiate_initiator, negotiate_responder,
)
from . import plaintext
from . import yamux
from .stream_io import PipeStream


SECURITY_PROTOCOL = "/plaintext/2.0.0"
MUXER_PROTOCOL = "/yamux/1.0.0"
APP_PROTOCOL = "/warpgate/relay/1.0.0"


class LibP2PSession(object):
    """Bundle of (Pipe, PipeStream, yamux.Session, remote_peer_id)
    for one active libp2p connection.  Held by Libp2pNode so we can
    tear everything down together on close."""

    def __init__(self, pipe, pipe_stream, mux_session, remote_peer_id):
        self.pipe = pipe
        self.pipe_stream = pipe_stream
        self.mux_session = mux_session
        self.remote_peer_id = remote_peer_id

    async def close(self):
        try:
            await self.mux_session.close()
        except (OSError, ConnectionError):
            pass
        try:
            self.pipe_stream.close()
        except (OSError, ConnectionError):
            pass
        try:
            await self.pipe.close()
        except (OSError, ConnectionError, asyncio.TimeoutError):
            pass


class Libp2pNode(object):
    """Per-warpgate-node libp2p host.  Owns the Identity (Ed25519
    keypair derived once at startup), the optional TCP listener, and
    the active LibP2PSession registry keyed by remote_peer_id.

    The plugin asks node.listen(nic, af, port=0) to start a server
    (returns the bound (addr, port) so the plugin can advertise it
    in the signal), and node.dial(addr, port, nic, af) to connect
    out.

    Both listen() and dial() complete the full handshake before
    returning a Stream, so the plugin's call site is a one-liner.
    """

    def __init__(self, identity):
        self.identity = identity
        self.listener_pipes = {}  # (af, nic_name) -> Pipe
        self.listener_tasks = []
        self.inbound_streams = asyncio.Queue()  # (stream, remote_peer_id) tuples
        self.sessions = []
        self.closed = False

    async def listen(self, nic, af, ips, port=0):
        """Start a TCP listener on ``ips`` of ``nic`` for ``af``.

        Returns (bound_ip_string, bound_port).  Multiple calls add
        more listeners (e.g. v4 + v6 + LAN + ext).  The accept loop
        per listener handles each inbound pipe through the full
        handshake pipeline and pushes the resulting yamux Stream
        into ``self.inbound_streams``.

        ips is the address string to bind on (e.g. "0.0.0.0", "::").
        Use the resolved NIC IP (self.src["ip"]) when called from a
        plugin so the bind matches the advertised IP.
        """
        if self.closed:
            raise OSError("Libp2pNode.listen: node is closed")
        route = await nic.route(af).bind(ips=ips, port=port)
        pipe = Pipe(TCP, dest=None, route=route)
        await pipe.connect()
        if pipe.sock is None:
            raise OSError("Libp2pNode.listen: TCP server failed to open")
        try:
            bound = pipe.sock.getsockname()
            bound_ip = bound[0]
            bound_port = bound[1]
        except (AttributeError, IndexError, OSError):
            bound_ip = ips
            bound_port = port
        self.listener_pipes[(af, getattr(nic, "name", "?"))] = pipe
        t = asyncio.ensure_future(self.accept_loop(pipe))
        self.listener_tasks.append(t)
        log(fstr(
            "libp2p_native: listener up on {0}:{1} af={2} nic={3}",
            (bound_ip, bound_port, af, getattr(nic, "name", "?")),
        ))
        return bound_ip, bound_port

    async def accept_loop(self, listener):
        """Per-listener accept loop: handshake each inbound pipe."""
        while not self.closed:
            try:
                inbound = await listener.accept()
            except asyncio.CancelledError:
                raise
            except (OSError, ConnectionError):
                log_exception()
                return
            if inbound is None:
                return
            asyncio.ensure_future(self.handle_inbound(inbound))

    async def handle_inbound(self, pipe):
        """Run the responder side of the libp2p handshake on a fresh pipe."""
        ps = PipeStream(pipe)
        try:
            await ps.start()
            # 1) outer multistream + security
            chosen_sec = await negotiate_responder(ps, ps, (SECURITY_PROTOCOL,))
            if chosen_sec != SECURITY_PROTOCOL:
                raise ConnectionError(
                    "libp2p_native: peer wanted {0}".format(chosen_sec)
                )
            remote_peer_id, _remote_pub = await plaintext.perform_handshake(
                ps, ps, self.identity,
            )
            # 2) inner multistream + muxer
            chosen_mux = await negotiate_responder(ps, ps, (MUXER_PROTOCOL,))
            if chosen_mux != MUXER_PROTOCOL:
                raise ConnectionError(
                    "libp2p_native: peer wanted muxer {0}".format(chosen_mux)
                )
            mux = yamux.Session(ps, ps, is_client=False).start()
            session = LibP2PSession(pipe, ps, mux, remote_peer_id)
            self.sessions.append(session)
            # 3) accept the first stream + negotiate app protocol
            stream = await asyncio.wait_for(mux.accept_stream(), timeout=30)
            chosen_app = await negotiate_responder(stream, stream, (APP_PROTOCOL,))
            if chosen_app != APP_PROTOCOL:
                raise ConnectionError(
                    "libp2p_native: peer wanted app {0}".format(chosen_app)
                )
            log(fstr(
                "libp2p_native: inbound handshake complete from peer_id={0}",
                (remote_peer_id.hex()[:16],),
            ))
            await self.inbound_streams.put((stream, remote_peer_id, session))
        except (ConnectionError, asyncio.TimeoutError, OSError, ValueError):
            log_exception()
            try:
                ps.close()
            except (OSError, ConnectionError):
                pass
            try:
                await pipe.close()
            except (OSError, ConnectionError, asyncio.TimeoutError):
                pass

    async def dial(self, dest_ip, dest_port, route, expected_peer_id=None, timeout=15.0):
        """Open a libp2p connection to (dest_ip, dest_port) over ``route``.

        Returns (stream, remote_peer_id, session) on success, raises
        on failure.  ``expected_peer_id`` is the multihash PeerID
        bytes we expect the peer to announce -- the plaintext
        handshake verifies it.
        """
        if self.closed:
            raise OSError("Libp2pNode.dial: node is closed")
        pipe = await asyncio.wait_for(
            Pipe(TCP, dest=(dest_ip, dest_port), route=route).connect(),
            timeout=timeout,
        )
        if pipe is None or pipe.sock is None:
            raise OSError("Libp2pNode.dial: TCP connect produced no socket")
        ps = PipeStream(pipe)
        try:
            await ps.start()
            chosen_sec = await negotiate_initiator(ps, ps, [SECURITY_PROTOCOL])
            if chosen_sec != SECURITY_PROTOCOL:
                raise ConnectionError("libp2p_native: dial sec mismatch")
            remote_peer_id, _ = await plaintext.perform_handshake(
                ps, ps, self.identity, expected_peer_id=expected_peer_id,
            )
            chosen_mux = await negotiate_initiator(ps, ps, [MUXER_PROTOCOL])
            if chosen_mux != MUXER_PROTOCOL:
                raise ConnectionError("libp2p_native: dial mux mismatch")
            mux = yamux.Session(ps, ps, is_client=True).start()
            session = LibP2PSession(pipe, ps, mux, remote_peer_id)
            self.sessions.append(session)
            stream = await mux.open_stream()
            chosen_app = await negotiate_initiator(stream, stream, [APP_PROTOCOL])
            if chosen_app != APP_PROTOCOL:
                raise ConnectionError("libp2p_native: dial app mismatch")
            log(fstr(
                "libp2p_native: dial handshake complete to peer_id={0} at {1}:{2}",
                (remote_peer_id.hex()[:16], dest_ip, dest_port),
            ))
            return stream, remote_peer_id, session
        except (ConnectionError, asyncio.TimeoutError, OSError, ValueError):
            try:
                ps.close()
            except (OSError, ConnectionError):
                pass
            try:
                await pipe.close()
            except (OSError, ConnectionError, asyncio.TimeoutError):
                pass
            raise

    async def close(self):
        """Tear down all listeners + active sessions."""
        if self.closed:
            return
        self.closed = True
        for t in self.listener_tasks:
            if not t.done():
                t.cancel()
        for pipe in list(self.listener_pipes.values()):
            try:
                await pipe.close()
            except (OSError, ConnectionError, asyncio.TimeoutError):
                pass
        for sess in list(self.sessions):
            try:
                await sess.close()
            except (OSError, ConnectionError):
                pass
        self.sessions = []
        self.listener_pipes = {}
        self.listener_tasks = []
