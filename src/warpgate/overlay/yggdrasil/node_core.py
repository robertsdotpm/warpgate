"""Yggdrasil node core -- identity + peer table + listener + dialer.

Port of the orchestration bits of yggdrasil-go's ``core/core.go``
+ ``core/link.go``.  Not 1:1 wire-compatible above the peer link
layer yet -- the routing protocol that sits on top of the peer
links (ironwood) is Phase 5.  For Phase 4 the goal is just:

  * Maintain an ed25519 identity + derived 200::/7 address.
  * Listen on a TCP port and accept inbound peer connections.
  * Dial a configured set of outbound peer URIs with exponential
    backoff.
  * Keep a PeerTable of live peer links.
  * Hand each new peer link to a per-peer "packet reader" task
    that pumps recv_packet() into a placeholder handler (in
    Phase 5 this becomes the ironwood router; for now it just
    counts inbound packets so the test can verify the loop ran).

URIs follow upstream's format: ``tcp://host:port``.  TLS / QUIC /
WS / UNIX are listed in upstream but TCP is the only one strictly
required for connecting to public Yggdrasil peers (yggstack and
most public-peer admin pages list TCP endpoints).

NIC pinning + socket creation is delegated to aionetiface (no
hand-rolled socket code in this module).  Pass an Interface or
Route to ``listen`` / ``add_peer_uri`` if you need to pin to a
specific NIC; default uses ``Interface("default")``.
"""
import asyncio

from aionetiface import IP4, IP6, TCP, Interface, Pipe, fstr, log, log_exception
from ecdsa import SigningKey, Ed25519

from .address import addr_for_key, ipv6_str_from_bytes
from .peer_table import BackoffCounter, DuplicatePeerError, PeerTable
from .peer_link import (
    LinkToSelf,
    open_inbound,
    open_outbound,
)
from .buffered_reader import PipeClosed
from .version import HandshakeError
from .wire import WIRE_TYPE_NAMES


def derive_pubkey(seed):
    """Return the 32-byte ed25519 public key for the given 32-byte seed.

    ``ecdsa.VerifyingKey.to_string()`` returns a ``bytearray`` in
    0.19; coerce to ``bytes`` so callers can use the pubkey as a
    dict key without surprise hashability errors.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("derive_pubkey: seed must be 32 bytes")
    sk = SigningKey.from_string(bytes(seed), curve=Ed25519)
    return bytes(sk.verifying_key.to_string())


def parse_peer_uri(uri):
    """Parse a ``tcp://`` or ``tls://`` URI into ``(scheme, host, port)``.

    Raises ``ValueError`` on any other scheme or malformed URI.
    """
    try:
        from urllib.parse import urlparse
    except ImportError:
        # Python 2 fallback; warpgate is 3.5+ so this shouldn't fire.
        from urlparse import urlparse
    parsed = urlparse(str(uri))
    if parsed.scheme not in ("tcp", "tls"):
        raise ValueError(fstr(
            "parse_peer_uri: only tcp:// or tls:// supported, got {0}",
            (parsed.scheme,),
        ))
    host = parsed.hostname
    port = parsed.port
    if not host or not port:
        raise ValueError(fstr(
            "parse_peer_uri: missing host/port in {0}", (uri,),
        ))
    return parsed.scheme, host, int(port)


class NodeCore(object):
    """A single Yggdrasil node instance.

    Constructed with an ed25519 32-byte seed (random if None).
    Call ``start_listener(bind_addr, port, af)`` to accept inbound;
    ``add_peer_uri(uri)`` for each outbound to maintain; ``close()``
    to tear everything down.

    ``packet_handler`` (optional) is an async callable
    ``packet_handler(peer_link, packet_type, payload)`` invoked for
    every inbound packet on every peer.  Defaults to a no-op (the
    routing layer in Phase 5 will plug in here).
    """

    def __init__(self, seed=None, password=b"", priority=0,
                 packet_handler=None):
        if seed is None:
            import os
            seed = os.urandom(32)
        if len(seed) != 32:
            raise ValueError("NodeCore: seed must be 32 bytes")
        self.seed = bytes(seed)
        self.public_key = derive_pubkey(self.seed)
        self.address = ipv6_str_from_bytes(addr_for_key(self.public_key))
        self.password = bytes(password)
        self.priority = int(priority) & 0xFF
        self.packet_handler = packet_handler

        self.peers = PeerTable()
        # Per-peer recv-loop tasks.  Removed on link teardown so
        # we don't leak coroutines when peers come and go.
        self.peer_tasks = {}  # pubkey -> asyncio.Task

        # Listener state.
        self.listener_pipe = None
        self.listener_task = None
        self.listen_port = None
        self.listen_addr = None

        # Outbound dialer state: uri -> (cancel_event, task).
        self.dialer_tasks = {}

        self.closed = False

    async def start_listener(self, bind_addr="::", port=0, af=IP6,
                             nic=None):
        """Begin accepting inbound Yggdrasil peers on ``(bind_addr, port)``.

        ``bind_addr`` is an IP string -- ``"::"`` for all v6 IPs,
        ``"0.0.0.0"`` for all v4, or a specific NIC IP for pinning.
        ``port=0`` asks the kernel for an ephemeral port; the
        actual bound port is exposed as ``self.listen_port``.
        Returns ``(bind_addr, listen_port)``.
        """
        if self.closed:
            raise RuntimeError("start_listener: node is closed")
        if self.listener_pipe is not None:
            raise RuntimeError("start_listener: already listening")
        iface = nic if nic is not None else Interface("default")
        route = await iface.route(af).bind(ips=bind_addr, port=port)
        pipe = Pipe(TCP, dest=None, route=route)
        await pipe.connect()
        if pipe.sock is None:
            raise OSError("start_listener: TCP server failed to open")
        bound_port = pipe.sock.getsockname()[1]
        self.listener_pipe = pipe
        self.listen_addr = bind_addr
        self.listen_port = bound_port
        self.listener_task = asyncio.ensure_future(self.accept_loop(pipe))
        log(fstr(
            "yggdrasil[node {0}]: listening on {1} port {2}",
            (self.address, bind_addr, bound_port),
        ))
        return bind_addr, bound_port

    async def accept_loop(self, listener):
        """Per-listener accept loop: handshake each inbound + register."""
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
            asyncio.ensure_future(self.handle_inbound_pipe(inbound))

    async def handle_inbound_pipe(self, pipe):
        """Drive the handshake on a freshly-accepted Pipe + register."""
        try:
            link = await open_inbound(
                pipe, self.seed, self.public_key,
                password=self.password, priority=self.priority,
            )
        except LinkToSelf:
            # Self-connect; close quietly.  Upstream emits a debug
            # log and drops; we do the same.
            try:
                await pipe.close()
            except Exception:
                pass
            return
        except (HandshakeError, asyncio.TimeoutError, OSError,
                ConnectionError, PipeClosed):
            log_exception()
            try:
                await pipe.close()
            except Exception:
                pass
            return
        await self.register_link(link)

    async def register_link(self, link):
        """Insert a successful PeerLink into the table + start its recv loop."""
        try:
            self.peers.add_peer(link)
        except DuplicatePeerError:
            # Already have a link for this peer; close the new one.
            log(fstr(
                "yggdrasil[node {0}]: duplicate peer {1}, closing new link",
                (self.address, link.remote_addr),
            ))
            await link.close()
            return
        log(fstr(
            "yggdrasil[node {0}]: peer {1} connected ({2})",
            (self.address, link.remote_addr, link.link_type),
        ))
        task = asyncio.ensure_future(self.peer_recv_loop(link))
        self.peer_tasks[link.remote_pubkey] = task

    async def peer_recv_loop(self, link):
        """Pump recv_packet() into ``self.packet_handler`` until the link closes."""
        try:
            while not link.closed:
                try:
                    packet_type, payload = await link.recv_packet()
                except PipeClosed:
                    break
                except (OSError, ConnectionError):
                    log_exception()
                    break
                if self.packet_handler is not None:
                    try:
                        await self.packet_handler(link, packet_type, payload)
                    except Exception:
                        # Handler errors must not kill the peer link;
                        # log + continue so the routing protocol can
                        # recover from a single malformed packet.
                        log_exception()
        finally:
            self.peer_tasks.pop(link.remote_pubkey, None)
            self.peers.remove_peer(link.remote_pubkey)
            await link.close()
            log(fstr(
                "yggdrasil[node {0}]: peer {1} disconnected",
                (self.address, link.remote_addr),
            ))

    async def add_peer_uri(self, uri, nic=None):
        """Configure an outbound peer to dial with backoff.

        ``uri`` is a ``tcp://host:port`` string.  The dialer task
        runs until ``remove_peer_uri(uri)`` or ``close()`` is
        called.  Idempotent: re-adding an existing URI is a no-op.
        """
        if self.closed:
            raise RuntimeError("add_peer_uri: node is closed")
        if uri in self.dialer_tasks:
            return
        # Parse early so a malformed URI fails fast (raises
        # ValueError before any background task is spawned).
        parse_peer_uri(uri)
        cancel_event = asyncio.Event()
        task = asyncio.ensure_future(self.dialer_loop(uri, cancel_event, nic))
        self.dialer_tasks[uri] = (cancel_event, task)

    def remove_peer_uri(self, uri):
        """Stop the dialer loop for ``uri``.  Open links are NOT closed."""
        entry = self.dialer_tasks.pop(uri, None)
        if entry is None:
            return
        cancel_event, task = entry
        cancel_event.set()
        try:
            task.cancel()
        except Exception:
            pass

    async def dialer_loop(self, uri, cancel_event, nic):
        """Outbound dialer with exponential backoff.  One loop per URI."""
        scheme, host, port = parse_peer_uri(uri)
        backoff = BackoffCounter()
        af = self.guess_af_for_host(host)
        if nic is None:
            nic = Interface("default")
        while not self.closed and not cancel_event.is_set():
            try:
                # Bind to the "any" address for this AF so the kernel
                # picks a source IP whose routing table entry matches
                # ``host`` -- crucially this lets dest=::1 use ::1 as
                # the source.  A literal nic.route(af).bind() pins to
                # the NIC's primary GUA, which can't loop back to a
                # listener bound to ::1.
                bind_ip = "::" if af == IP6 else "0.0.0.0"
                route = await nic.route(af).bind(ips=bind_ip, port=0)
            except (OSError, ValueError, LookupError):
                log_exception()
                # NIC not ready / no route -- wait and retry.
                if await self.wait_or_cancel(backoff.next_delay(), cancel_event):
                    return
                continue
            link = None
            try:
                link = await open_outbound(
                    host, port, route,
                    self.seed, self.public_key,
                    password=self.password, priority=self.priority,
                    link_proto=scheme,
                )
            except LinkToSelf:
                log(fstr(
                    "yggdrasil[node {0}]: peer {1} is ourselves, skipping",
                    (self.address, uri),
                ))
                return
            except (HandshakeError, asyncio.TimeoutError, OSError,
                    ConnectionError, PipeClosed):
                log(fstr(
                    "yggdrasil[node {0}]: outbound dial to {1} failed; "
                    "backing off",
                    (self.address, uri),
                ))
                if await self.wait_or_cancel(backoff.next_delay(),
                                             cancel_event):
                    return
                continue
            backoff.reset()
            try:
                await self.register_link(link)
            except Exception:
                log_exception()
                try:
                    await link.close()
                except Exception:
                    pass
                continue
            # Wait for the link to close (the recv loop owns the
            # link's lifetime) then loop and re-dial.  We watch
            # both the peer_tasks entry and the cancel_event.
            recv_task = self.peer_tasks.get(link.remote_pubkey)
            if recv_task is not None:
                done, pending = await asyncio.wait(
                    {recv_task, asyncio.ensure_future(cancel_event.wait())},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if cancel_event.is_set():
                    for t in pending:
                        t.cancel()
                    return
            if cancel_event.is_set():
                return

    @staticmethod
    def guess_af_for_host(host):
        """Best-effort AF selection: an IPv6 literal returns IP6, else IP4.

        For host names we conservatively try IP4 first; aionetiface's
        resolution chain will translate from there.  Upstream
        ``net.LookupIP`` returns both families; this could grow into
        a happy-eyeballs path in a later session.
        """
        if ":" in host:
            return IP6
        return IP4

    @staticmethod
    async def wait_or_cancel(delay, cancel_event):
        """Sleep ``delay`` seconds OR until ``cancel_event`` fires.  Returns True if cancelled."""
        try:
            await asyncio.wait_for(cancel_event.wait(), timeout=delay)
            return True
        except asyncio.TimeoutError:
            return False

    async def close(self):
        """Tear down the node: cancel dialers, close peers, stop listener."""
        if self.closed:
            return
        self.closed = True
        # Cancel all dialer loops first so they don't reconnect mid-shutdown.
        for uri, (cancel_event, task) in list(self.dialer_tasks.items()):
            cancel_event.set()
            try:
                task.cancel()
            except Exception:
                pass
        self.dialer_tasks.clear()
        # Close all live peer links.
        for entry in list(self.peers.peers()):
            try:
                await entry.link.close()
            except Exception:
                log_exception()
        # Cancel + drain per-peer recv loops.
        for pubkey, task in list(self.peer_tasks.items()):
            try:
                task.cancel()
            except Exception:
                pass
        self.peer_tasks.clear()
        # Close the listener.
        if self.listener_task is not None:
            try:
                self.listener_task.cancel()
            except Exception:
                pass
            self.listener_task = None
        if self.listener_pipe is not None:
            try:
                await self.listener_pipe.close()
            except Exception:
                log_exception()
            self.listener_pipe = None
