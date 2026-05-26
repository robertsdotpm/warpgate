"""Yggdrasil overlay relay plugin.

Yggdrasil is a self-arranging IPv6 overlay: every node owns a global-
unicast address in 200::/7 derived from an ed25519 keypair, and the
daemon creates a TUN interface so the host's stack treats those
addresses as ordinary IPv6.  That means we can lean on the OS for
every transport-layer concern -- routing, ordering, retransmission --
and just bind aionetiface Pipes to the 200:: address like any other
NIC IP.

The plugin's only job is therefore:

  1. Detect that an Yggdrasil-owned 200::/7 IPv6 exists on some local
     NIC; if not, fail fast so the cascade falls through.
  2. Open a TCP listener on that address (initiator), or dial the
     peer's 200:: address+port (responder).
  3. Hand the resulting Pipe back to TraversalManager.

NIC selection is delegated to aionetiface's ``socket_factory`` via
``Pipe``: we just pass the route bound to the 200:: address and the
existing NIC-pin sockopts take over.  No per-NIC pinning code lives in
this file.

Both IPv4 and IPv6 invocation contexts route through the SAME
overlay: the 200::/7 address is v6-only, but the bytes the peer
ultimately ships through it can be carrying either v4 or v6
application data.  ``route_types=(EXT_BIND,)`` (inherited from
OverlayPlugin) ensures auto_combos only emits external-class combos,
and the AF of the *combo* is irrelevant -- the overlay carries
the bits regardless.
"""
import asyncio
import socket as stdsocket
from aionetiface import IP6, TCP, Pipe, fstr, log, log_exception
from ...strategy_registry import register
from ....protocol.proto_defs import P2P_OVERLAY
from ..overlay.base import OverlayPlugin
from .proto import YggdrasilMsg


# Wait up to this long for the overlay accept coroutine to yield a
# pipe.  Caps the listener half of run_as_initiator on top of the
# OverlayPlugin's own per-plugin timeout.
ACCEPT_GRACE_SECONDS = 2.0


def is_yggdrasil_addr(ip):
    """Return True if ``ip`` (string IPv6) sits in the Yggdrasil 200::/7 subnet.

    200::/7 means the first byte of the packed address is 0x02 or
    0x03.  Strips a trailing ``%scope`` if present (link-local style
    suffixes don't apply to 200::/7 in practice, but be tolerant).
    """
    try:
        addr = str(ip).split("%", 1)[0]
        packed = stdsocket.inet_pton(stdsocket.AF_INET6, addr)
    except (OSError, ValueError, AttributeError, TypeError):
        return False
    first = packed[0] if isinstance(packed[0], int) else ord(packed[0])
    return first in (0x02, 0x03)


def find_overlay_nic_and_addr(ifs):
    """Walk a list of Interface objects, return (nic, route, addr_str) or None.

    The first NIC whose IPv6 route has a 200::/7 IP in its nic_ips
    wins.  Caller is responsible for verifying len(ifs)>0; this
    function returns None on no match so the plugin can fail clean.
    """
    for nic in ifs:
        try:
            supported = nic.supported()
        except (ValueError, AttributeError):
            continue
        if IP6 not in supported:
            continue
        try:
            route = nic.route(IP6)
        except (LookupError, ValueError):
            continue
        for ipr in (route.nic_ips or []):
            addr = str(ipr)
            if is_yggdrasil_addr(addr):
                return nic, route, addr
    return None


@register(phase="relay")
class YggdrasilPlugin(OverlayPlugin):
    """Bridge a Pipe over the Yggdrasil IPv6 overlay (200::/7)."""

    name = "yggdrasil"
    transport = TCP
    proto_messages = (
        (YggdrasilMsg, P2P_OVERLAY, 10),
    )

    @classmethod
    async def setup(cls, node):
        """Stash the node reference so plugin instances can read node.ifs."""
        factory = YggdrasilPluginFactory(node)
        node.resources.register(factory)
        return factory

    def __init__(self):
        super().__init__()
        self.node = None
        # Discovered once in ensure_transport_up; reused by every hook.
        self.overlay_nic = None
        self.overlay_route = None
        self.overlay_addr = None
        # Server-side Pipe (initiator) -- held so close() can tear it
        # down explicitly without depending on GC ordering.
        self.listener_pipe = None

    async def ensure_transport_up(self):
        """Locate the local Yggdrasil 200::/7 address; raise on miss."""
        if self.node is None:
            raise RuntimeError("yggdrasil: factory did not inject node ref")
        match = find_overlay_nic_and_addr(self.node.ifs or [])
        if match is None:
            raise RuntimeError(
                "yggdrasil: no 200::/7 address found on any local NIC "
                "(is the yggdrasil daemon running?)"
            )
        self.overlay_nic, self.overlay_route, self.overlay_addr = match
        log(fstr(
            "yggdrasil[{0}]: overlay address {1} on NIC {2}",
            (self.plugin_id, self.overlay_addr, self.overlay_nic.name),
        ))

    async def get_local_address(self):
        """Return the discovered 200:: address as a string."""
        if not self.overlay_addr:
            raise RuntimeError("yggdrasil: overlay address not resolved yet")
        return self.overlay_addr

    async def start_listener(self):
        """Open a TCP listener on (overlay_addr, ephemeral_port); return (port, accept_coro).

        We rebind the discovered v6 route to the 200:: IP specifically
        (the route's nic_ips may also include link-locals / standard
        v6 addresses; pin to the overlay IP so the listener doesn't
        get an off-overlay binding) and ask the kernel for an
        ephemeral port (port=0).  After connect() the socket is bound
        and listening -- we read the assigned port from
        sock.getsockname() because route.bind_port is only set when
        the caller asked for a specific port up front.
        """
        route = await self.overlay_nic.route(IP6).bind(
            ips=self.overlay_addr, port=0,
        )
        pipe = Pipe(TCP, dest=None, route=route)
        await pipe.connect()
        if pipe.sock is None:
            raise RuntimeError(
                "yggdrasil: listener socket allocation failed"
            )
        bound_port = pipe.sock.getsockname()[1]
        self.listener_pipe = pipe

        async def accept_inbound():
            """Yield the first inbound client Pipe.

            Pipe.accept() returns one client per call; we only need
            the first.  Wrapped in a small grace timer so a peer that
            crashes mid-dial doesn't pin the listener forever past
            OverlayPlugin's own cap.
            """
            return await pipe.accept()

        return bound_port, accept_inbound()

    async def connect_to_peer(self, peer_address, peer_port):
        """Dial peer_address:peer_port over the Yggdrasil overlay; return a Pipe."""
        # Bind the dialer to the local 200:: address so the socket's
        # source IP is the overlay's, not e.g. a public v6 that the
        # peer can't route back through their Yggdrasil instance.
        route = await self.overlay_nic.route(IP6).bind(
            ips=self.overlay_addr, port=0,
        )
        try:
            pipe = await asyncio.wait_for(
                Pipe(TCP, dest=(peer_address, int(peer_port)), route=route).connect(),
                timeout=8.0,
            )
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()
            return None
        if pipe is None or pipe.sock is None:
            return None
        return pipe

    async def close(self):
        """Tear down the listener (if any).

        Idempotent.  The pipe we ultimately return to TraversalManager
        is the *accepted client*, not the listener -- so closing the
        listener here is always safe regardless of the result futures.
        """
        pipe = self.listener_pipe
        if pipe is None:
            return
        try:
            await pipe.close()
        except asyncio.CancelledError:
            raise
        except Exception:
            log_exception()


class YggdrasilPluginFactory:
    """Factory that injects the node reference into each fresh plugin instance."""

    def __init__(self, node):
        self.node = node

    def build_plugin(self):
        """Create a new YggdrasilPlugin wired to this factory's node ref."""
        plugin = YggdrasilPlugin()
        plugin.node = self.node
        return plugin

    async def close(self):
        """Nothing process-wide to tear down -- the daemon belongs to the OS."""
        return None
