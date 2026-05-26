"""Warpgate traversal plugin: warpgate-native Yggdrasil overlay.

Bridges warpgate's plugin cascade to the pure-Python Yggdrasil
port living in ``warpgate.overlay.yggdrasil``.  Unlike the
deferred ``experiments/yggdrasil`` plugin (which required the
user to install the Yggdrasil Go daemon out-of-band), this one
runs the entire overlay in-process -- NodeCore + ActiveRouter +
pathfinder + encrypted PacketConn -- so warpgate ships a working
Yggdrasil-class relay with NO external binaries.

Plugin shape: register as ``phase="relay"``,
``route_types=(EXT_BIND,)``, exchange the local ed25519 pubkey
via signaling, and dial back through the in-process overlay to
``send_to`` the peer's pubkey.  Returns a YggdrasilPipeAdapter
exposing the standard Pipe send/recv surface.

Bootstrap: on first plugin run, the factory dials a list of
known-good public Yggdrasil peers (default: a hardcoded set
verified working) so both warpgate nodes converge on the same
public mesh and can find each other.  Override via
``WARPGATE_YGG_PEERS`` env var (space-separated tcp:// or tls://
URIs) or by passing ``bootstrap_uris=[]`` at factory time.

Convergence: plugin waits up to ``timeout-2s`` for the routing
table to contain the peer's pubkey before declaring the dial
ready.  Without this the responder can fire ``write_to`` before
the tree has formed and the packet ends up at no peer.

Resource model: one NodeCore + ActiveRouter + PacketConn per
warpgate node (shared across all plugin instances) -- created
lazily on first run(); guarded against same-WAN-IP combos so it
doesn't waste cycles when a better path exists locally.
"""
import asyncio
import os

from aionetiface import EXT_BIND, TCP, fstr, log, log_exception
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ....protocol.proto_defs import P2P_OVERLAY
from .proto import YggdrasilNativeMsg


# Default bootstrap peer list -- one public Yggdrasil node that's
# been live-verified (handshake completed, announces flowing) at
# port time.  We dial ALL of these (best-effort) so failure of
# any single one doesn't sink the plugin.  Override via the
# WARPGATE_YGG_PEERS env var (space-separated URIs) for
# air-gapped / private-mesh setups.
DEFAULT_BOOTSTRAP_PEERS = (
    "tls://37.186.113.100:1515",
    "tls://95.217.35.92:1337",
)


def get_bootstrap_peers():
    """Read bootstrap URIs from env or fall back to defaults."""
    env = os.environ.get("WARPGATE_YGG_PEERS", "").strip()
    if env:
        return [s for s in env.split() if s]
    return list(DEFAULT_BOOTSTRAP_PEERS)


# Lazy import the overlay module: it has nontrivial setup cost
# (Curve25519 pure-Python primitives) so we don't import unless
# the plugin actually fires.
def lazy_import_overlay():
    from warpgate.overlay.yggdrasil.node_core import NodeCore
    from warpgate.overlay.yggdrasil.router_active import ActiveRouter
    from warpgate.overlay.yggdrasil.encrypted import EncryptedPacketConn
    return NodeCore, ActiveRouter, EncryptedPacketConn


class YggdrasilPipeAdapter(object):
    """Thin Pipe-shape wrapper around EncryptedPacketConn for a single peer.

    Uses the PacketConn's per-peer channel (opened at construction
    time) so multiple adapters can coexist on one PacketConn
    without dropping each other's traffic.
    """

    def __init__(self, packet_conn, peer_pubkey):
        self.packet_conn = packet_conn
        self.peer_pubkey = bytes(peer_pubkey)
        self.sock = packet_conn  # non-None sentinel
        self.dest = None
        self.proto = TCP
        self.closed = False
        self.winner_plugin = "yggdrasil_native"
        self.pipe_events = _StubPipeEvents()
        # Open the per-peer queue immediately so the very first
        # inbound packet from this peer is captured (vs the shared
        # inbox where it'd be raced against other adapters).
        self.packet_conn.open_peer_channel(self.peer_pubkey)

    async def send(self, msg, client_tup=None):
        if self.closed:
            raise OSError("YggdrasilPipeAdapter: send on closed pipe")
        await self.packet_conn.write_to(self.peer_pubkey, msg)

    async def recv(self, sub=None):
        if self.closed:
            return None
        return await self.packet_conn.read_from_peer(self.peer_pubkey)

    def subscribe(self, sub):
        return None

    async def close(self):
        if self.closed:
            return
        self.closed = True
        # Release the per-peer queue so the PacketConn doesn't
        # leak buffered packets after we're gone.
        try:
            self.packet_conn.close_peer_channel(self.peer_pubkey)
        except Exception:
            pass


class _StubPipeEvents(object):
    def __init__(self):
        self.stream = _StubStream()


class _StubStream(object):
    def __init__(self):
        self.subs = {}


@register(phase="relay")
class YggdrasilNativePlugin(Plugin):
    """Warpgate relay via the in-process Yggdrasil overlay."""

    name = "yggdrasil_native"
    transport = TCP
    route_types = (EXT_BIND,)
    conf = {"timeout": 30}
    proto_messages = (
        (YggdrasilNativeMsg, P2P_OVERLAY, 10),
    )

    @classmethod
    async def setup(cls, node):
        """Construct + register the shared overlay state."""
        factory = YggdrasilNativeFactory(node)
        node.resources.register(factory)
        return factory

    def __init__(self):
        super().__init__()
        self.factory = None
        self.adapter = None

    async def run(self, reply=None):
        """Initiator advertises pubkey + waits; responder dials."""
        # TURN-style guard: if both peers share the same WAN IP
        # (e.g. same-machine or same-NAT pairs) the overlay
        # is the WRONG path -- something local will be faster
        # and the cascade should fall through.  Mirror what TURN
        # does (see warpgate/traversal/plugins/turn/main.py).
        src_ext = self.src.get("ext") if self.src else None
        dest_ext = self.dest.get("ext") if self.dest else None
        if src_ext and dest_ext and str(src_ext) == str(dest_ext):
            log(fstr(
                "yggdrasil_native[{0}]: src ext == dest ext ({1}); aborting",
                (self.plugin_id, src_ext),
            ))
            if not self.result.done():
                self.result.set_result(None)
            return

        try:
            await self.factory.ensure_overlay_started()
        except Exception:
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
            return
        pc = self.factory.packet_conn
        our_hex = self.factory.node_core.public_key.hex()

        if reply is None:
            # Initiator: advertise our pubkey, then wait for an
            # inbound packet from the responder on the per-peer
            # channel.  We don't yet know the responder's pubkey
            # so we drain the SHARED inbox here; once we see a
            # source we promote it to a per-peer channel.
            msg = YggdrasilNativeMsg({
                "payload": {"pubkey_hex": our_hex},
            })
            msg.meta.plugin_name = self.name
            try:
                await self.send_signal(msg)
            except Exception:
                log_exception()
                if not self.result.done():
                    self.result.set_result(None)
                return
            log(fstr(
                "yggdrasil_native[{0}]: advertised pubkey {1}",
                (self.plugin_id, our_hex[:16]),
            ))
            cap = max(1.0, (self.timeout or 30) - 2.0)
            try:
                source, _first = await asyncio.wait_for(
                    pc.read_from(), timeout=cap,
                )
            except asyncio.TimeoutError:
                log(fstr(
                    "yggdrasil_native[{0}]: no inbound after {1}s",
                    (self.plugin_id, cap),
                ))
                if not self.result.done():
                    self.result.set_result(None)
                return
            adapter = YggdrasilPipeAdapter(pc, source)
            self.adapter = adapter
            if not self.result.done():
                self.result.set_result(adapter)
        else:
            # Responder: dial via the overlay using the initiator's
            # pubkey from the signal.  Wait for routing convergence
            # before sending so the first packet has somewhere to go.
            peer_hex = reply.payload.pubkey_hex
            try:
                peer_pubkey = bytes.fromhex(peer_hex)
            except (ValueError, AttributeError):
                if not self.result.done():
                    self.result.set_result(None)
                return
            convergence_cap = max(1.0, (self.timeout or 30) - 4.0)
            converged = await self.factory.wait_for_route(
                peer_pubkey, timeout=convergence_cap,
            )
            if not converged:
                log(fstr(
                    "yggdrasil_native[{0}]: no route to {1} after {2}s",
                    (self.plugin_id, peer_hex[:16], convergence_cap),
                ))
                if not self.result.done():
                    self.result.set_result(None)
                return
            adapter = YggdrasilPipeAdapter(pc, peer_pubkey)
            self.adapter = adapter
            # Kick the encrypted session by sending one byte (the
            # handshake is lazy; this triggers init/ack).
            try:
                await adapter.send(b"\x00")
            except Exception:
                log_exception()
                if not self.result.done():
                    self.result.set_result(None)
                return
            log(fstr(
                "yggdrasil_native[{0}]: dialed peer {1}",
                (self.plugin_id, peer_hex[:16]),
            ))
            if not self.result.done():
                self.result.set_result(adapter)


class YggdrasilNativeFactory(object):
    """Shared overlay state: one NodeCore + Router + PacketConn per node.

    On first plugin run, the factory:
      1. Spins up a fresh ed25519 identity + NodeCore + ActiveRouter
      2. Starts the encrypted PacketConn dispatcher
      3. Opens a TCP listener for inbound Yggdrasil peers
      4. Dials each bootstrap peer URI -- both warpgate nodes must
         converge on at least one common public peer for their
         routing tables to overlap

    ``bootstrap_uris`` controls the dial list; ``None`` (default)
    means consult ``get_bootstrap_peers()`` which reads the
    ``WARPGATE_YGG_PEERS`` env var with hardcoded fallback.
    """

    def __init__(self, node, bootstrap_uris=None):
        self.node = node
        self.bootstrap_uris = (
            list(bootstrap_uris) if bootstrap_uris is not None
            else get_bootstrap_peers()
        )
        self.node_core = None
        self.router = None
        self.packet_conn = None
        self.started = False
        self.start_lock = asyncio.Lock()

    async def ensure_overlay_started(self):
        async with self.start_lock:
            if self.started:
                return
            NodeCore, ActiveRouter, EncryptedPacketConn = lazy_import_overlay()
            seed = os.urandom(32)
            self.node_core = NodeCore(seed=seed)
            self.router = ActiveRouter(self.node_core)
            self.node_core.packet_handler = self.router.on_packet
            self.router.start()
            self.packet_conn = EncryptedPacketConn(
                seed, self.node_core.public_key, self.router,
            )
            # Inbound TCP listener -- best-effort, bind on any v6.
            try:
                from aionetiface import IP6
                await self.node_core.start_listener(
                    bind_addr="::", port=0, af=IP6,
                )
            except Exception:
                log_exception()
            # Bootstrap dial: ask the NodeCore dialer to maintain
            # outbound connections to each configured public peer.
            for uri in self.bootstrap_uris:
                try:
                    await self.node_core.add_peer_uri(uri)
                    log(fstr(
                        "yggdrasil_native: bootstrap dial {0}",
                        (uri,),
                    ))
                except (ValueError, OSError):
                    log_exception()
            self.started = True

    async def wait_for_route(self, peer_pubkey, timeout=15.0):
        """Poll the routing table until we have a route to ``peer_pubkey``.

        Returns True if convergence achieved within ``timeout``,
        False otherwise.  ``ActiveRouter.infos[peer_pubkey]``
        being populated proves the peer's tree announce has
        reached us; their pathfinder can then look us up + the
        encrypted session can establish.
        """
        if self.router is None:
            return False
        peer_pubkey = bytes(peer_pubkey)
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            if peer_pubkey in self.router.infos:
                return True
            await asyncio.sleep(0.25)
        return peer_pubkey in self.router.infos

    def build_plugin(self):
        plugin = YggdrasilNativePlugin()
        plugin.factory = self
        return plugin

    async def close(self):
        if self.packet_conn is not None:
            await self.packet_conn.close()
            self.packet_conn = None
        if self.router is not None:
            self.router.stop()
            self.router = None
        if self.node_core is not None:
            await self.node_core.close()
            self.node_core = None
