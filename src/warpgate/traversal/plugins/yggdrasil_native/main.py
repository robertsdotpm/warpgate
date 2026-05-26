"""Warpgate traversal plugin: warpgate-native Yggdrasil overlay.

Bridges warpgate's plugin cascade to the pure-Python Yggdrasil
port living in ``warpgate.overlay.yggdrasil``.  Unlike the
deferred ``experiments/yggdrasil`` plugin (which required the
user to install the Yggdrasil Go daemon out-of-band), this one
runs the entire overlay in-process -- NodeCore + ActiveRouter +
pathfinder + encrypted PacketConn -- so warpgate ships a working
Yggdrasil-class relay with NO external binaries.

Plugin shape mirrors the deferred experiments version: register
as ``phase="relay"``, ``route_types=(EXT_BIND,)``, exchange
the local ed25519 pubkey via signaling, and on the responder
side dial back through the in-process overlay to ``send_to``
the initiator's pubkey.  The returned "pipe" is a thin adapter
wrapping the EncryptedPacketConn's read_from / write_to surface
so warpgate's downstream code can use it like any other Pipe.

Resource model: one NodeCore + ActiveRouter + PacketConn per
warpgate node (shared across all plugin instances) -- created
lazily on first run().  Tear-down happens at node shutdown.
"""
import asyncio
import os

from aionetiface import EXT_BIND, TCP, fstr, log, log_exception
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ....protocol.proto_defs import P2P_OVERLAY
from .proto import YggdrasilNativeMsg


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

    Exposes the subset of aionetiface.Pipe that warpgate's
    downstream code uses: ``send``, ``recv``, ``close``, and a
    truthy ``sock`` attribute so the standard "did this pipe
    open" check passes.  Uses the underlying PacketConn for
    actual byte transport.
    """

    def __init__(self, packet_conn, peer_pubkey):
        self.packet_conn = packet_conn
        self.peer_pubkey = bytes(peer_pubkey)
        self.sock = packet_conn  # non-None sentinel
        self.dest = None
        self.proto = TCP
        self.closed = False
        self.winner_plugin = "yggdrasil_native"
        # Stub pipe_events.stream.subs surface for Gate.listen compat.
        self.pipe_events = _StubPipeEvents()

    async def send(self, msg, client_tup=None):
        if self.closed:
            raise OSError("YggdrasilPipeAdapter: send on closed pipe")
        await self.packet_conn.write_to(self.peer_pubkey, msg)

    async def recv(self, sub=None):
        if self.closed:
            return None
        # Note: PacketConn.read_from() returns (source_pubkey, msg)
        # for ANY peer, not just ours.  Loop until we get one from
        # our peer.  Production code would maintain per-peer queues;
        # for the MVP this is fine since each plugin run is one peer.
        while True:
            source, msg = await self.packet_conn.read_from()
            if source == self.peer_pubkey:
                return msg
            # Different peer -- requeue (lossy: ok for MVP)

    def subscribe(self, sub):
        return None

    async def close(self):
        self.closed = True


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
            # Initiator path: advertise our pubkey, wait for peer to
            # write_to us (their first packet will arrive on our
            # PacketConn.inbox).
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
            # Wait for the peer's first packet to arrive (the
            # routing tree must be up; in real deployment the
            # initial discovery may take seconds).  Cap at the
            # plugin timeout to keep the cascade moving.
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
            # Responder path: dial via the overlay using the
            # initiator's pubkey from the signal.
            peer_hex = reply.payload.pubkey_hex
            try:
                peer_pubkey = bytes.fromhex(peer_hex)
            except (ValueError, AttributeError):
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
    """Shared overlay state: one NodeCore + Router + PacketConn per node."""

    def __init__(self, node):
        self.node = node
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
            # Use a fresh ed25519 seed for the overlay identity --
            # not the warpgate node identity (different keyspace,
            # different lifetime).  In a follow-up we could derive
            # both from a shared root.
            seed = os.urandom(32)
            self.node_core = NodeCore(seed=seed)
            self.router = ActiveRouter(self.node_core)
            self.node_core.packet_handler = self.router.on_packet
            self.router.start()
            self.packet_conn = EncryptedPacketConn(
                seed, self.node_core.public_key, self.router,
            )
            # Start the overlay's own TCP listener for inbound
            # Yggdrasil peers.  Best-effort; if the bind fails
            # we still work as an outbound-only node.
            try:
                from aionetiface import IP6
                await self.node_core.start_listener(
                    bind_addr="::", port=0, af=IP6,
                )
            except Exception:
                log_exception()
            self.started = True

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
