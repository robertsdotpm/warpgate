"""Traversal plugin: byte-compatible libp2p TCP relay.

Two-role pattern, like yggdrasil_native:

  * Initiator (no reply yet) -- opens a libp2p TCP listener on the
    NIC the cascade picked, advertises (ip, port, peer_id_hex, af)
    over the warpgate signalling channel, waits on inbound_streams
    for the responder's handshake to complete.
  * Responder (reply set) -- dials (ip, port) via Libp2pNode.dial,
    runs the full libp2p handshake, then immediately closes the
    cascade with the resulting LibP2PPipeAdapter.

This deliberately mirrors the yggdrasil_native plugin shape so the
auto_connect cascade slots it in as just another relay-phase
candidate.  No edits outside this directory are required: the
plugin loader picks us up via @register, registers Libp2pNativeMsg
via proto_messages, and create_plugin instantiates us.
"""
import asyncio

from aionetiface import EXT_BIND, NIC_BIND, LOOPBACK_BIND, TCP, fstr, log, log_exception
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ....protocol.proto_defs import P2P_OVERLAY
from .node_core import Libp2pNode
from .peer_id import Identity
from .pipe_adapter import LibP2PPipeAdapter
from .proto import Libp2pNativeMsg


@register(phase="relay")
class Libp2pNativePlugin(Plugin):
    """libp2p TCP transport as a warpgate traversal cascade plugin."""

    name = "libp2p_native"
    transport = TCP
    # Allow every route_type -- libp2p's TCP transport works anywhere
    # plain TCP works, so loopback/LAN/external dial all apply.  The
    # cascade's combo generator already filters out structurally
    # impossible pairs (same_machine via EXT, etc).
    route_types = (EXT_BIND, NIC_BIND, LOOPBACK_BIND)
    # 20 s budget: TCP connect (~1 s) + multistream + plaintext +
    # multistream + yamux SYN + multistream + app proto ~5 round
    # trips.  Local LAN ~200 ms total, cross-WAN with high RTT could
    # easily blow past 5 s.  Use 20 s for headroom.
    conf = {"timeout": 20}
    proto_messages = (
        (Libp2pNativeMsg, P2P_OVERLAY, 15),
    )

    @classmethod
    async def setup(cls, node):
        """One Libp2pNode per warpgate Node (shared identity + listeners)."""
        factory = Libp2pNativeFactory(node)
        node.resources.register(factory)
        return factory

    def __init__(self):
        super().__init__()
        self.factory = None
        self.session = None
        self.our_listener = None  # (ip, port) tuple after we listen

    async def run(self, reply=None):
        try:
            await self.factory.ensure_started()
        except Exception:
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
            return

        if reply is None:
            await self.run_initiator()
        else:
            await self.run_responder(reply)

    async def run_initiator(self):
        """Open a listener on the bound src IP, signal it, wait for inbound."""
        try:
            bound_ip, bound_port = await self.factory.node.listen(
                self.nic, self.af, ips=self.src["ip"], port=0,
            )
        except (OSError, ValueError):
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
            return
        self.our_listener = (bound_ip, bound_port)

        msg = Libp2pNativeMsg({
            "payload": {
                "ip": bound_ip,
                "port": bound_port,
                "peer_id_hex": self.factory.identity.peer_id.hex(),
                "af": int(self.af),
            },
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
            "libp2p_native[{0}]: initiator listening on {1}:{2}, "
            "advertised peer_id={3}",
            (
                self.plugin_id, bound_ip, bound_port,
                self.factory.identity.peer_id.hex()[:16],
            ),
        ))

        cap = max(1.0, (self.timeout or 20) - 2.0)
        try:
            stream, remote_peer_id, session = await asyncio.wait_for(
                self.factory.node.inbound_streams.get(), timeout=cap,
            )
        except asyncio.TimeoutError:
            log(fstr(
                "libp2p_native[{0}]: initiator timed out waiting for inbound after {1}s",
                (self.plugin_id, cap),
            ))
            if not self.result.done():
                self.result.set_result(None)
            return

        adapter = LibP2PPipeAdapter(stream, session, remote_peer_id)
        self.session = session
        if not self.result.done():
            self.result.set_result(adapter)

    async def run_responder(self, reply):
        """Dial the initiator's libp2p listener; resolve with the adapter."""
        peer_ip = getattr(reply.payload, "ip", "")
        peer_port = getattr(reply.payload, "port", 0)
        peer_id_hex = getattr(reply.payload, "peer_id_hex", "")
        if not peer_ip or not peer_port or not peer_id_hex:
            log(fstr(
                "libp2p_native[{0}]: incomplete reply payload ip={1} port={2} pid={3}",
                (self.plugin_id, peer_ip, peer_port, peer_id_hex),
            ))
            if not self.result.done():
                self.result.set_result(None)
            return
        try:
            expected_peer_id = bytes.fromhex(peer_id_hex)
        except (ValueError, TypeError):
            if not self.result.done():
                self.result.set_result(None)
            return

        try:
            route = await self.bind()
        except (OSError, ValueError):
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
            return

        cap = max(1.0, (self.timeout or 20) - 1.0)
        try:
            stream, remote_peer_id, session = await self.factory.node.dial(
                peer_ip, peer_port, route,
                expected_peer_id=expected_peer_id, timeout=cap,
            )
        except (OSError, ConnectionError, asyncio.TimeoutError, ValueError):
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
            return

        adapter = LibP2PPipeAdapter(stream, session, remote_peer_id)
        self.session = session
        log(fstr(
            "libp2p_native[{0}]: responder handshake complete to {1}:{2}",
            (self.plugin_id, peer_ip, peer_port),
        ))
        if not self.result.done():
            self.result.set_result(adapter)


class Libp2pNativeFactory(object):
    """Shared Libp2pNode (identity + listener registry) for one warpgate Node.

    Constructed lazily in @classmethod setup() so we don't pay the
    Ed25519 keygen + cold-import cost on nodes that never run a
    libp2p plugin attempt.  ``ensure_started`` is the actual hot
    construction path; the first plugin run() to fire wins the
    start_lock and the others reuse the already-built node.
    """

    def __init__(self, node):
        self.node = None  # Libp2pNode instance (built on first ensure_started)
        self.warpgate_node = node
        self.identity = None
        self.started = False
        self.start_lock = asyncio.Lock()

    async def ensure_started(self):
        async with self.start_lock:
            if self.started:
                return
            self.identity = Identity.generate()
            self.node = Libp2pNode(self.identity)
            self.started = True
            log(fstr(
                "libp2p_native: factory started peer_id={0}",
                (self.identity.peer_id.hex()[:16],),
            ))

    def build_plugin(self):
        """TraversalManager calls this to construct per-attempt plugin instances."""
        plugin = Libp2pNativePlugin()
        plugin.factory = self
        return plugin

    @property
    def node_safe(self):
        """Convenience accessor that the @property on Plugin.run uses
        once ensure_started has resolved.  Plugin code always touches
        ``self.factory.node`` after awaiting ensure_started, but this
        guards against accidental pre-init access in tests."""
        if not self.started:
            raise OSError("Libp2pNativeFactory.node_safe: not started")
        return self.node

    async def close(self):
        """Tear down the Libp2pNode (called by warpgate's resource manager)."""
        if self.node is not None:
            await self.node.close()
        self.node = None
        self.identity = None
        self.started = False
