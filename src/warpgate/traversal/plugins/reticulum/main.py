"""Reticulum (RNS) overlay relay plugin.

Reticulum is a cryptographic networking stack: each node is identified
by a 16-byte destination hash derived from its public keys, and the
RNS daemon (``rnsd``) handles routing across whatever lower-layer
transports are configured (TCP interfaces, LoRa radios, packet
radio, serial, ...).  From a warpgate point of view it's the same
shape as Yggdrasil -- a side-channel that gets bytes from A to B
regardless of NAT or routing path -- but the addressing model is
hash-based rather than IP-based.

The plugin defers all NIC/transport concerns to the underlying RNS
daemon.  No aionetiface socket pinning happens here -- we cannot
pin RNS Link traffic to a specific NIC even if we wanted to,
because the bytes leave the host via whatever interface ``rnsd``
is configured for and the kernel makes the egress decision under
the daemon.  We honour the user's "use my socket.py function"
constraint by simply NOT writing socket code: the RNSPipe adapter
in this directory is a Pipe-shape adapter around an RNS Link, not
a custom socket wrapper.

The RNS package is an optional runtime dep.  If the import fails,
the plugin still registers (so plugin_loader doesn't crash) but
``ensure_transport_up`` raises immediately -- the cascade falls
through to whatever the next strategy is.
"""
import asyncio
from aionetiface import TCP, fstr, log, log_exception
from ...strategy_registry import register
from ....protocol.proto_defs import P2P_OVERLAY
from ..overlay.base import OverlayPlugin
from .proto import ReticulumMsg
from .rns_pipe import RNSPipe


try:
    import RNS  # noqa: F401 -- imported solely to test availability.
    RNS_AVAILABLE = True
except ImportError:
    RNS = None
    RNS_AVAILABLE = False


# How long to wait for an inbound RNS Link to establish on the
# initiator side, in seconds.  RNS path resolution can take a few
# seconds the first time a peer's hash is touched; after that it's
# cached.  Caps the listener half of OverlayPlugin.run_as_initiator.
LINK_ACCEPT_SECONDS = 20.0


# RNS application name namespace.  Two destinations with the same
# app_name + aspects can address each other -- think of it as a port
# label for the hash routing layer.  Keep this stable across releases
# so existing peers keep matching.
RNS_APP_NAME = "warpgate"
RNS_ASPECTS = ("relay",)


@register(phase="relay")
class ReticulumPlugin(OverlayPlugin):
    """Bridge a Pipe over the Reticulum encrypted overlay."""

    name = "reticulum"
    transport = TCP  # nominal; RNS chooses the actual lower-layer transport.
    proto_messages = (
        (ReticulumMsg, P2P_OVERLAY, 10),
    )

    @classmethod
    async def setup(cls, node):
        """Lazy-initialise a shared Reticulum stack and stash it on the factory."""
        factory = ReticulumPluginFactory(node)
        if RNS_AVAILABLE:
            try:
                factory.ensure_reticulum_started()
            except (OSError, RuntimeError, ValueError):
                log_exception()
        node.resources.register(factory)
        return factory

    def __init__(self):
        super().__init__()
        # Filled in by the factory's build_plugin hook.
        self.factory = None
        self.node = None
        # Initiator-side state.
        self.local_destination = None
        self.pending_link_future = None
        # Adapter wrapping the established Link (set after accept/dial).
        self.rns_pipe = None

    async def ensure_transport_up(self):
        """Confirm RNS is importable and the shared Reticulum stack is up."""
        if not RNS_AVAILABLE:
            raise RuntimeError(
                "reticulum: RNS package not installed -- pip install rns"
            )
        if self.factory is None or self.factory.reticulum is None:
            raise RuntimeError(
                "reticulum: shared Reticulum stack failed to start "
                "(check rnsd config / dependencies)"
            )

    async def get_local_address(self):
        """Return our local destination hash as a 32-character hex string.

        Created lazily because the same destination object is reused
        by start_listener (the responder dials it).  We don't allocate
        it in __init__ to keep failure modes localised to ensure_*.
        """
        if self.local_destination is None:
            self.local_destination = self.factory.build_destination(
                self.plugin_id,
            )
        # RNS Destination exposes .hash (16 raw bytes); hexlify for the wire.
        hash_bytes = self.local_destination.hash
        try:
            return hash_bytes.hex()
        except AttributeError:
            # Python 3.5 bytes have no .hex(); fall back to binascii.
            import binascii
            return binascii.hexlify(hash_bytes).decode("ascii")

    async def start_listener(self):
        """Register an RNS link-established callback and return (port=0, accept_coro).

        ``port`` is a sentinel 0 because Reticulum doesn't use ports
        -- the destination hash is the full address.  OverlayPlugin's
        run_as_initiator advertises both the address and the port,
        but the responder's connect_to_peer ignores the port (see
        proto.py).
        """
        # Future resolved by on_link_established below when the
        # responder's incoming RNS Link finishes its handshake.
        loop = asyncio.get_event_loop()
        link_future = loop.create_future()
        self.pending_link_future = link_future

        def on_link_established(link):
            """RNS-thread callback; hand the established Link to asyncio."""
            try:
                loop.call_soon_threadsafe(self.complete_pending_link, link)
            except RuntimeError:
                log_exception()

        try:
            self.local_destination.set_link_established_callback(on_link_established)
        except AttributeError as exc:
            raise RuntimeError(fstr(
                "reticulum: destination object missing "
                "set_link_established_callback ({0})",
                (repr(exc),),
            ))

        async def accept_inbound():
            """Wait for the first inbound Link, wrap it in an RNSPipe."""
            try:
                link = await asyncio.wait_for(
                    asyncio.shield(link_future),
                    timeout=LINK_ACCEPT_SECONDS,
                )
            except asyncio.TimeoutError:
                return None
            pipe = RNSPipe(link, loop=loop)
            self.rns_pipe = pipe
            return pipe

        return 0, accept_inbound()

    def complete_pending_link(self, link):
        """Resolve the pending Future from the asyncio side; safe under races."""
        fut = self.pending_link_future
        if fut is not None and not fut.done():
            fut.set_result(link)

    async def connect_to_peer(self, peer_address, peer_port):
        """Resolve the peer's destination hash, open an RNS Link, return an RNSPipe.

        ``peer_address`` is the hex destination hash; ``peer_port`` is
        ignored.  RNS handles path discovery and may block while it
        learns the route, so we run the link setup in a thread
        executor to avoid stalling the event loop.
        """
        loop = asyncio.get_event_loop()
        try:
            peer_hash = bytes.fromhex(peer_address)
        except (ValueError, TypeError):
            log(fstr(
                "reticulum[{0}]: malformed peer hash {1}",
                (self.plugin_id, repr(peer_address)),
            ))
            return None

        try:
            link = await asyncio.wait_for(
                loop.run_in_executor(
                    None, self.factory.dial_destination, peer_hash,
                ),
                timeout=LINK_ACCEPT_SECONDS,
            )
        except (asyncio.TimeoutError, OSError, RuntimeError):
            log_exception()
            return None
        if link is None:
            return None

        pipe = RNSPipe(link, loop=loop)
        self.rns_pipe = pipe
        return pipe

    async def close(self):
        """Release the inbound-link Future if it's still pending.

        The RNSPipe (and the wrapped Link) is owned by whoever
        consumes the result Pipe; we don't tear it down here.
        """
        fut = self.pending_link_future
        if fut is not None and not fut.done():
            fut.cancel()


class ReticulumPluginFactory:
    """Owns a single shared Reticulum stack across all plugin instances.

    Reticulum is designed to run ONE ``Reticulum`` instance per
    process: every Destination / Link / Identity created in this
    process flows through that singleton's transport.  Spawning a
    fresh ``Reticulum`` per plugin attempt would crash on the second
    instantiation, so the factory caches the first one.
    """

    def __init__(self, node):
        self.node = node
        self.reticulum = None
        self.identity = None
        # destination_cache: plugin_id -> RNS Destination.  Keeps
        # responder-side Destinations alive for the lifetime of the
        # plugin attempt; close() in the plugin doesn't drop them.
        self.destination_cache = {}

    def ensure_reticulum_started(self):
        """Spin up Reticulum and a node Identity once; cache both.

        Synchronous because RNS internals are not asyncio-aware and
        the cost of touching them under run_in_executor for a one-
        shot setup isn't worth the complexity.
        """
        if not RNS_AVAILABLE:
            raise RuntimeError("reticulum: RNS package not installed")
        if self.reticulum is None:
            self.reticulum = RNS.Reticulum()
        if self.identity is None:
            self.identity = RNS.Identity()

    def build_destination(self, plugin_id):
        """Return (and cache) a Destination this plugin instance listens on.

        Reticulum Destinations are addressed by hashing their
        Identity + app_name + aspects.  We pass plugin_id as an
        additional aspect so two simultaneous plugin attempts get
        distinct destinations without sharing inbound callbacks.
        """
        cached = self.destination_cache.get(plugin_id)
        if cached is not None:
            return cached
        dest = RNS.Destination(
            self.identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            RNS_APP_NAME,
            *RNS_ASPECTS,
            plugin_id,
        )
        # Accept inbound links (RNS calls this "single accept policy").
        try:
            dest.set_accepts_links(True)
        except AttributeError:
            # Older RNS versions name it differently; ignore -- default
            # accept policy is permissive for SINGLE destinations.
            pass
        self.destination_cache[plugin_id] = dest
        return dest

    def dial_destination(self, peer_hash):
        """Open an RNS Link to ``peer_hash`` (16 bytes); return the Link or None.

        Runs synchronously in a thread executor.  RNS internally
        blocks on path resolution and then returns a Link object
        that the caller wraps in RNSPipe for async consumption.
        """
        try:
            # Build an OUT-direction Destination for the peer's
            # identity hash.  RNS.Destination's recall() function
            # turns a known hash into an addressable destination
            # without needing the peer's public key on file.
            peer_identity = RNS.Identity.recall(peer_hash)
            if peer_identity is None:
                # Force a path request and try once more.
                RNS.Transport.request_path(peer_hash)
                peer_identity = RNS.Identity.recall(peer_hash)
            if peer_identity is None:
                return None
            peer_dest = RNS.Destination(
                peer_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                RNS_APP_NAME,
                *RNS_ASPECTS,
            )
            link = RNS.Link(peer_dest)
            return link
        except (OSError, RuntimeError, ValueError, AttributeError):
            log_exception()
            return None

    def build_plugin(self):
        """Create a new ReticulumPlugin wired to this factory."""
        plugin = ReticulumPlugin()
        plugin.factory = self
        plugin.node = self.node
        return plugin

    async def close(self):
        """Tear down the shared Reticulum stack at process shutdown."""
        for dest in list(self.destination_cache.values()):
            try:
                if hasattr(dest, "deregister"):
                    dest.deregister()
            except (OSError, RuntimeError):
                log_exception()
        self.destination_cache.clear()
        if self.reticulum is not None:
            try:
                if hasattr(self.reticulum, "exit_handler"):
                    self.reticulum.exit_handler()
            except (OSError, RuntimeError):
                log_exception()
            self.reticulum = None
        self.identity = None
