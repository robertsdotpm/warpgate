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
from . import noise
from . import yamux
from . import identify as identify_mod
from . import multiaddr as ma
from . import circuit_relay as cr
from . import kad as kad_mod
from . import autonat as autonat_mod
from . import autorelay as autorelay_mod
from ....kademlia.routing import RoutingTable, PeerInfo
from .stream_io import PipeStream


NOISE_PROTOCOL = "/noise"
PLAINTEXT_PROTOCOL = "/plaintext/2.0.0"
# Dial-side preference order: noise first (real-world libp2p
# default), plaintext second (fallback for warpgate-to-warpgate
# during smoke tests or when the peer hasn't been upgraded yet).
DIAL_SECURITY_PREFERENCE = (NOISE_PROTOCOL, PLAINTEXT_PROTOCOL)
# Listener accepts either -- the initiator's first matching offer wins.
LISTEN_SECURITY_OFFERS = (NOISE_PROTOCOL, PLAINTEXT_PROTOCOL)
MUXER_PROTOCOL = "/yamux/1.0.0"
APP_PROTOCOL = "/warpgate/relay/1.0.0"
IDENTIFY_PROTOCOL = identify_mod.IDENTIFY_PROTOCOL  # "/ipfs/id/1.0.0"
HOP_PROTOCOL = cr.HOP_PROTOCOL    # "/libp2p/circuit/relay/0.2.0/hop"
STOP_PROTOCOL = cr.STOP_PROTOCOL  # "/libp2p/circuit/relay/0.2.0/stop"
KAD_PROTOCOL = kad_mod.KAD_PROTOCOL          # "/ipfs/kad/1.0.0"
AUTONAT_PROTOCOL = autonat_mod.AUTONAT_PROTOCOL  # "/libp2p/autonat/1.0.0"

# Protocols we'll advertise via Identify.  Order is informational
# only -- libp2p Identify lists are unordered + a peer may filter.
ADVERTISED_PROTOCOLS = (
    APP_PROTOCOL,
    IDENTIFY_PROTOCOL,
    HOP_PROTOCOL,
    STOP_PROTOCOL,
    KAD_PROTOCOL,
    AUTONAT_PROTOCOL,
)


class LibP2PSession(object):
    """Bundle of (Pipe, PipeStream, yamux.Session, remote_peer_id)
    for one active libp2p connection.  Held by Libp2pNode so we can
    tear everything down together on close.

    Also holds the side-stream dispatcher task -- the responder
    side spawns one per session, accepting fresh yamux streams the
    peer opens and routing them by their multistream-selected
    protocol id.  This is how /ipfs/id/1.0.0 (Identify) gets
    handled out-of-band from the main /warpgate/relay/1.0.0 stream.
    """

    def __init__(self, pipe, pipe_stream, mux_session, remote_peer_id):
        self.pipe = pipe
        self.pipe_stream = pipe_stream
        self.mux_session = mux_session
        self.remote_peer_id = remote_peer_id
        self.side_dispatcher_task = None
        # Last Identify result we learned from the peer (None until
        # Identify runs at least once).
        self.last_identify = None

    async def close(self):
        if self.side_dispatcher_task is not None and not self.side_dispatcher_task.done():
            self.side_dispatcher_task.cancel()
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
        self.inbound_streams = asyncio.Queue()  # (stream, remote_peer_id, session) tuples
        self.sessions = []
        # Per-listener demuxer state: id(client_pipe_events) -> PipeStream.
        # Populated lazily on first byte from a new client; the cb spawns
        # the handshake task at that moment and routes subsequent bytes
        # into the existing PipeStream.
        self.inbound_pipestreams = {}
        self.handshake_tasks = []
        # Listen-side advertised addresses (multiaddr bytes) -- used in
        # Identify responses.  Each successful listen() call appends
        # an entry.  Multiaddrs follow the libp2p wire format
        # /ip4/<v4>/tcp/<port>; for v6: /ip6/<v6>/tcp/<port>.
        self.listen_multiaddrs = []
        # Optional RelayService: when this node should act as a relay
        # for other peers (i.e. accept /hop streams + forward), set
        # ``self.relay_service`` to a circuit_relay.RelayService.
        # ``None`` means we DECLINE /hop streams ("we're not a relay").
        self.relay_service = None
        # Active outbound reservation we hold against a remote relay
        # (so we can be reached via /p2p-circuit).  Map session ->
        # Reservation.  Updated by ``reserve_via_relay``.
        self.reservations = {}
        # Handler invoked when an inbound /stop CONNECT lands -- the
        # relay punched a stream to us on behalf of a source peer.
        # Default: hand the spliced stream back up to the caller via
        # ``relayed_inbound_streams`` so plugin code can run the
        # libp2p stack on top of it.
        self.relayed_inbound_streams = asyncio.Queue()
        # Kademlia DHT routing table.  We store libp2p PeerIDs as
        # the transport-meaningful peer identifier; the routing
        # table's ``key_fn=key_for_peer_id`` derives the SHA-256
        # kad-keyspace key on demand.  This way the transport can
        # look up sessions by their libp2p PeerID (the natural
        # session-keying field) without an extra hash->id table.
        self.kad_routing_table = RoutingTable(
            local_peer_id=identity.peer_id,
            k=20, key_bits=256,
            key_fn=kad_mod.key_for_peer_id,
        )
        # Kad transport adapter (lazy-built on first use so plugin
        # imports don't pay the cost when DHT isn't used).
        self.kad_transport = None
        # AutoRelay client -- opportunistically reserves on peers
        # that advertise /hop in their Identify.  Off by default;
        # caller flips it on with ``enable_autorelay()``.
        self.autorelay = None
        # AutoNAT dialer -- the callback the server-side AutoNAT
        # handler invokes to attempt a dial-back.  Default: None,
        # meaning we refuse AutoNAT requests.  Caller can plug in
        # a dialer via ``set_autonat_dialer``.
        self.autonat_dialer = None
        self.closed = False

    def enable_autorelay(self, max_relays=2):
        """Turn AutoRelay on -- opportunistically reserve on relay-capable peers."""
        if self.autorelay is None:
            self.autorelay = autorelay_mod.AutoRelay(self, max_relays=max_relays)
        return self.autorelay

    def set_autonat_dialer(self, dialer):
        """Plug in the dial-back function for AutoNAT server handling.

        ``dialer(multiaddr_bytes, expected_peer_id) -> bool`` -- if
        a dial back to the requester at the given multiaddr
        succeeds, returns True.  Setting this enables AutoNAT
        server responses; leaving it None refuses them.
        """
        self.autonat_dialer = dialer

    def get_kad_transport(self):
        """Return (lazily-built) the libp2p Kad transport adapter."""
        if self.kad_transport is None:
            self.kad_transport = kad_mod.Libp2pKadTransport(self)
        return self.kad_transport

    def enable_relay_service(self):
        """Turn this node into a libp2p Circuit Relay v2 relay.

        After this, peers can run /hop RESERVE against us; their
        sessions get tracked in our reservations table.  We then
        accept incoming /hop CONNECT requests and forward via /stop
        to the reserved peer.

        Idempotent -- calling twice is harmless.
        """
        if self.relay_service is None:
            self.relay_service = cr.RelayService(self)

    async def listen(self, nic, af, ips, port=0):
        """Start a TCP listener on ``ips`` of ``nic`` for ``af``.

        Returns (bound_ip_string, bound_port).  Multiple calls add
        more listeners (e.g. v4 + v6 + LAN + ext).

        The listener is a normal aionetiface TCP server Pipe (one
        ``Pipe(TCP, dest=None, route=route).connect()``) -- we hook
        into it the canonical way, by registering a single ``msg_cb``
        on the server's pipe_events.  aionetiface inherits that cb
        set onto every accepted client's pipe_events
        (``pipe_tcp_events.connection_made`` deliberately sets
        ``client_events.msg_cbs = pipe_events.msg_cbs``), so our one
        cb fires per-client with the third arg ``pipe`` being the
        per-client PipeEvents.  We demux by ``id(pipe)`` -- first
        time we see an unseen pipe id, spin a PipeStream + spawn the
        handshake; subsequent chunks feed the existing PipeStream.

        Avoids the ``await listener.accept()`` codepath entirely --
        ``accept`` is a legacy surface that suffers from a double-
        dispatch on Windows Py3.8 (the ``create_server(sock=...)``
        accept loop AND the ``server.serve_forever()`` task both
        push the same client_events onto the accept queue) and we
        simply don't need it: msg_cb already gives us everything.
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

        node = self

        async def demux_cb(data, client_tup, client_pipe):
            """Per-server-pipe demuxer: route data to the right PipeStream
            and spin up a handshake task on first sight of a new client.
            """
            if node.closed:
                return
            cpid = id(client_pipe)
            ps = node.inbound_pipestreams.get(cpid)
            if ps is None:
                # First byte from a new client -- create its PipeStream
                # + spawn the handshake task.  The data we just
                # received is fed AFTER the spawn so the task's first
                # read() sees it.
                ps = PipeStream(client_pipe)
                node.inbound_pipestreams[cpid] = ps
                t = asyncio.ensure_future(node.handle_inbound_stream(ps, cpid))
                node.handshake_tasks.append(t)
            ps.feed_data(data)

        pipe.add_msg_cb(demux_cb)
        # Record the multiaddr form so Identify can advertise it.
        try:
            self.listen_multiaddrs.append(ma.encode_ip_tcp(bound_ip, bound_port))
        except ValueError:
            # Some bind targets (e.g. an unresolvable name, "::%zone")
            # won't pack into a multiaddr; skip rather than fail listen.
            log_exception()
        log(fstr(
            "libp2p_native: listener up on {0}:{1} af={2} nic={3}",
            (bound_ip, bound_port, af, getattr(nic, "name", "?")),
        ))
        return bound_ip, bound_port

    async def session_stream_dispatcher(self, session):
        """Accept new yamux streams on ``session`` forever, multistream-
        select each one, then dispatch by protocol.

        ``/warpgate/relay/1.0.0`` -> push the Stream onto
        ``self.inbound_streams`` so plugin code can hand it back to
        the cascade as a winning pipe.

        ``/ipfs/id/1.0.0`` -> write our Identify protobuf and close
        the stream (no further bytes flow on an Identify stream).

        Anything else -> the multistream-select responder already
        sent "na" while iterating the offer list, so by the time we
        get here we've negotiated a known protocol; drop the stream
        if it somehow slipped through.
        """
        try:
            while True:
                try:
                    stream = await session.mux_session.accept_stream()
                except (ConnectionError, asyncio.CancelledError):
                    raise
                except Exception:
                    log_exception()
                    return
                if stream is None:
                    return
                asyncio.ensure_future(self.handle_inbound_substream(stream, session))
        except asyncio.CancelledError:
            return

    async def handle_inbound_substream(self, stream, session):
        """Multistream-select one fresh yamux stream then route by protocol.

        Dispatch table:
          /warpgate/relay/1.0.0  -- app stream, push to inbound_streams
          /ipfs/id/1.0.0         -- reply with our Identify protobuf
          /libp2p/.../hop        -- handled by RelayService (if enabled)
          /libp2p/.../stop       -- handled as inbound relayed dial
        """
        # The set we OFFER depends on which optional services are
        # turned on -- without enable_relay_service we don't
        # advertise /hop, without set_autonat_dialer we don't
        # advertise /libp2p/autonat/1.0.0.
        offers = [APP_PROTOCOL, IDENTIFY_PROTOCOL, STOP_PROTOCOL, KAD_PROTOCOL]
        if self.relay_service is not None:
            offers.append(HOP_PROTOCOL)
        if self.autonat_dialer is not None:
            offers.append(AUTONAT_PROTOCOL)
        try:
            chosen = await negotiate_responder(stream, stream, tuple(offers))
        except (ConnectionError, asyncio.TimeoutError, OSError, ValueError):
            log_exception()
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass
            return

        if chosen == APP_PROTOCOL:
            await self.inbound_streams.put(
                (stream, session.remote_peer_id, session)
            )
            return

        if chosen == IDENTIFY_PROTOCOL:
            try:
                await identify_mod.send_identify(
                    stream,
                    public_key_marshalled=self.identity.pubkey_marshalled,
                    listen_addrs_bytes=list(self.listen_multiaddrs),
                    protocols=list(ADVERTISED_PROTOCOLS),
                )
            except (OSError, ConnectionError):
                log_exception()
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass
            return

        if chosen == HOP_PROTOCOL and self.relay_service is not None:
            await self.relay_service.handle_hop(stream, session)
            return

        if chosen == STOP_PROTOCOL:
            # A relay is forwarding bytes to us on behalf of a source.
            try:
                src_peer_id, src_addrs, _limit = await cr.destination_handle_stop(stream)
            except (ConnectionError, OSError, ValueError):
                log_exception()
                try:
                    await stream.close()
                except (OSError, ConnectionError):
                    pass
                return
            log(fstr(
                "libp2p_native: inbound relayed /stop from peer_id={0}",
                (src_peer_id.hex()[:16],),
            ))
            await self.relayed_inbound_streams.put(
                (stream, src_peer_id, session)
            )
            return

        if chosen == KAD_PROTOCOL:
            await kad_mod.handle_kad_stream(stream, self)
            return

        if chosen == AUTONAT_PROTOCOL and self.autonat_dialer is not None:
            try:
                await autonat_mod.server_handle(stream, session, self.autonat_dialer)
            except (ConnectionError, OSError, ValueError):
                log_exception()
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass
            return

        # Unknown protocol -- shouldn't happen since multistream-select
        # narrowed to our offer set.  Drop defensively.
        try:
            await stream.close()
        except (OSError, ConnectionError):
            pass

    def on_session_established(self, session):
        """Hook: each new completed session goes through here.

        Currently:
          - Add the remote peer (BY PeerID, not by kad-key) to our
            Kad routing table so iterative_find_node can route to
            them via the existing session.  The table's key_fn
            derives the SHA-256 kad-key on demand for distance
            calc.
          - If AutoRelay is on, kick off a consider() task.
        """
        self.kad_routing_table.add_peer(
            PeerInfo(session.remote_peer_id, addrs=[], last_seen=0)
        )
        if self.autorelay is not None:
            t = asyncio.ensure_future(
                self.autorelay.consider(session),
            )
            self.autorelay.tasks.append(t)

    async def find_peer(self, target_peer_id, timeout=30.0):
        """Run an iterative Kad-DHT FIND_NODE walk for ``target_peer_id``.

        Returns a list of ``PeerInfo`` ordered by XOR distance to
        the target.  The list might be empty if the local routing
        table is empty (no bootstrap was performed).

        ``target_peer_id`` is the libp2p PeerID multihash bytes;
        we hash it through SHA-256 to land in the Kad keyspace.
        """
        from ....kademlia.lookup import iterative_find_node
        target_key = kad_mod.key_for_peer_id(target_peer_id)
        transport = self.get_kad_transport()
        return await asyncio.wait_for(
            iterative_find_node(
                self.kad_routing_table, target_key, transport,
            ),
            timeout=timeout,
        )

    async def reserve_via_relay(self, session, timeout=10.0):
        """Use ``session`` (a Libp2pSession to a relay) to RESERVE a slot.

        After this returns, peers that look us up via the relay's
        /hop CONNECT can reach us through ``self.relayed_inbound_streams``.
        Returns a circuit_relay.Reservation -- the caller can advertise
        the reservation's addrs as relayed multiaddrs for our peer.
        """
        stream = await session.mux_session.open_stream()
        try:
            chosen = await asyncio.wait_for(
                negotiate_initiator(stream, stream, [HOP_PROTOCOL]),
                timeout=timeout,
            )
            if chosen != HOP_PROTOCOL:
                raise ConnectionError("libp2p_native: relay refused /hop negotiation")
            reservation = await asyncio.wait_for(
                cr.client_reserve(stream), timeout=timeout,
            )
            self.reservations[session.remote_peer_id] = reservation
            return reservation
        finally:
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass

    async def dial_via_relay(self, session, target_peer_id, timeout=10.0):
        """Use ``session`` (a Libp2pSession to a relay) to /hop CONNECT
        to ``target_peer_id`` (which must have a live reservation on
        that relay).

        On success, returns a ``yamux.Stream``-shaped object that is
        a transparent conduit to the target peer; the caller can run
        a fresh libp2p stack (multistream + security + muxer + app)
        on TOP of it.
        """
        stream = await session.mux_session.open_stream()
        try:
            chosen = await asyncio.wait_for(
                negotiate_initiator(stream, stream, [HOP_PROTOCOL]),
                timeout=timeout,
            )
            if chosen != HOP_PROTOCOL:
                raise ConnectionError("libp2p_native: relay refused /hop negotiation")
            await asyncio.wait_for(
                cr.client_connect_to(stream, target_peer_id),
                timeout=timeout,
            )
            return stream
        except Exception:
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass
            raise

    async def query_identify(self, session, timeout=10.0):
        """Open a fresh yamux stream on ``session`` and run /ipfs/id/1.0.0.

        Returns an ``identify.IdentifyResult`` populated from the
        peer's response.  Caches the latest result on
        ``session.last_identify`` so callers can re-use without
        re-querying.
        """
        stream = await session.mux_session.open_stream()
        try:
            chosen = await asyncio.wait_for(
                negotiate_initiator(stream, stream, [IDENTIFY_PROTOCOL]),
                timeout=timeout,
            )
            if chosen != IDENTIFY_PROTOCOL:
                raise ConnectionError("libp2p_native: peer rejected Identify")
            result = await asyncio.wait_for(
                identify_mod.recv_identify(stream), timeout=timeout,
            )
            session.last_identify = result
            return result
        finally:
            try:
                await stream.close()
            except (OSError, ConnectionError):
                pass

    async def handle_inbound_stream(self, ps, cpid):
        """Run the responder side of the libp2p handshake on a new PipeStream.

        Called by the listener's demuxer the first time a client
        sends a byte.  Drives the full multistream + security
        upgrade (noise OR plaintext, whichever the peer picks) +
        yamux + app handshake; on success pushes the result onto
        ``inbound_streams`` for plugin code to await.
        """
        pipe = ps.pipe
        try:
            chosen_sec = await negotiate_responder(ps, ps, LISTEN_SECURITY_OFFERS)
            if chosen_sec == NOISE_PROTOCOL:
                noise_sess = await noise.perform_responder_handshake(
                    ps, ps, self.identity,
                )
                remote_peer_id = noise_sess.remote_peer_id
                secure_io = noise_sess
            elif chosen_sec == PLAINTEXT_PROTOCOL:
                remote_peer_id, _remote_pub = await plaintext.perform_handshake(
                    ps, ps, self.identity,
                )
                secure_io = ps
            else:
                raise ConnectionError(
                    "libp2p_native: peer wanted unsupported sec {0}".format(chosen_sec)
                )

            chosen_mux = await negotiate_responder(secure_io, secure_io, (MUXER_PROTOCOL,))
            if chosen_mux != MUXER_PROTOCOL:
                raise ConnectionError(
                    "libp2p_native: peer wanted muxer {0}".format(chosen_mux)
                )
            mux = yamux.Session(secure_io, secure_io, is_client=False).start()
            session = LibP2PSession(pipe, ps, mux, remote_peer_id)
            self.sessions.append(session)
            # Spawn the side-stream dispatcher BEFORE awaiting the
            # first app-stream -- the peer might send Identify or
            # another protocol first, and we don't want those frames
            # to languish in accept_queue while we block on a
            # specific app stream.
            session.side_dispatcher_task = asyncio.ensure_future(
                self.session_stream_dispatcher(session),
            )
            self.on_session_established(session)
            log(fstr(
                "libp2p_native: inbound session complete from peer_id={0} sec={1}",
                (remote_peer_id.hex()[:16], chosen_sec),
            ))
        except (ConnectionError, asyncio.TimeoutError, OSError, ValueError):
            log_exception()
            try:
                ps.close()
            except (OSError, ConnectionError):
                pass
            self.inbound_pipestreams.pop(cpid, None)

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
        # Wire bytes from this Pipe into the PipeStream via handoff_to_cb.
        # The pipe was opened with dest+no-msg_cb so it's currently
        # subscribed to SUB_ALL; handoff atomically drains the
        # buffered queue + installs our feed cb.

        def dial_cb(data, client_tup, pipe_arg):
            ps.feed_data(data)

        pipe.handoff_to_cb(dial_cb)
        try:
            chosen_sec = await negotiate_initiator(ps, ps, list(DIAL_SECURITY_PREFERENCE))
            if chosen_sec == NOISE_PROTOCOL:
                noise_sess = await noise.perform_initiator_handshake(
                    ps, ps, self.identity, expected_peer_id=expected_peer_id,
                )
                remote_peer_id = noise_sess.remote_peer_id
                secure_io = noise_sess
            elif chosen_sec == PLAINTEXT_PROTOCOL:
                remote_peer_id, _ = await plaintext.perform_handshake(
                    ps, ps, self.identity, expected_peer_id=expected_peer_id,
                )
                secure_io = ps
            else:
                raise ConnectionError("libp2p_native: dial security mismatch")

            chosen_mux = await negotiate_initiator(secure_io, secure_io, [MUXER_PROTOCOL])
            if chosen_mux != MUXER_PROTOCOL:
                raise ConnectionError("libp2p_native: dial mux mismatch")
            mux = yamux.Session(secure_io, secure_io, is_client=True).start()
            session = LibP2PSession(pipe, ps, mux, remote_peer_id)
            self.sessions.append(session)
            # Side dispatcher so the peer can open Identify (or
            # future control) streams back to us on this session.
            session.side_dispatcher_task = asyncio.ensure_future(
                self.session_stream_dispatcher(session),
            )
            self.on_session_established(session)
            # Open the application stream + negotiate /warpgate/relay/1.0.0.
            stream = await mux.open_stream()
            chosen_app = await negotiate_initiator(stream, stream, [APP_PROTOCOL])
            if chosen_app != APP_PROTOCOL:
                raise ConnectionError("libp2p_native: dial app mismatch")
            log(fstr(
                "libp2p_native: dial handshake complete to peer_id={0} at {1}:{2} sec={3}",
                (remote_peer_id.hex()[:16], dest_ip, dest_port, chosen_sec),
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
        """Tear down all listeners + handshake tasks + active sessions."""
        if self.closed:
            return
        self.closed = True
        for t in self.handshake_tasks:
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
        self.handshake_tasks = []
        self.inbound_pipestreams = {}
