"""Shared base for overlay-network traversal plugins.

Overlay plugins (Yggdrasil, Reticulum, ...) all share the same shape:

  1. Bring up an overlay transport (a daemon, an RNS instance, ...).
  2. Discover the local overlay address (the IPv6 of a TUN, a destination
     hash, ...).
  3. Initiator publishes its address + port via signaling, then waits for
     an inbound overlay connection from the peer.
  4. Responder reads the address+port from the signal, dials the
     initiator over the overlay, and returns the resulting pipe.

This base class implements the warpgate-side glue (signaling, run()
shape, result futures, cancellation hygiene).  Concrete subclasses
implement four async hooks that bind to the specific overlay:

  ``async ensure_transport_up()``      -- daemon/lib ready, raise on fail
  ``async get_local_address()``        -- return string overlay address
  ``async start_listener()``           -- return (port, accept-coroutine)
  ``async connect_to_peer(addr, port)``-- return a Pipe-like object

The "Pipe-like" object only needs ``send``, ``recv``, and ``close``
methods; concrete subclasses either return a real aionetiface.Pipe (the
Yggdrasil case, since the TUN gives us real sockets) or a thin adapter
that wraps the overlay's own API (the Reticulum case).
"""
import asyncio
from aionetiface import EXT_BIND, log, log_exception, fstr
from ...traversal_plugin import Plugin


class OverlayPlugin(Plugin):
    """Abstract base for overlay-network relay plugins.

    Concrete subclasses must set ``name`` and ``transport``, and
    implement the four hooks listed in the module docstring.  Every
    overlay is by definition an EXT_BIND-class strategy -- the overlay
    *is* the external transport, regardless of which physical NIC the
    underlying daemon happens to use.
    """

    # All overlays are external-by-nature.  NIC_BIND / LOOPBACK_BIND
    # combos make no sense -- the overlay carries the bits, not the
    # NIC.  auto_combos won't emit non-EXT_BIND combos for us.
    route_types = (EXT_BIND,)
    conf = {"timeout": 30}

    # Subclasses populate this with an OverlayMsg subclass (one per
    # overlay protocol) so plugin_loader registers the wire name.
    proto_messages = ()

    def __init__(self):
        super().__init__()
        # Resolved by a second run() call when the peer's reply arrives.
        # Pattern matches TURN plugin (turn/main.py:run).
        self.ready = asyncio.Future()
        # Concrete subclasses stash their overlay-specific state here.
        self.listener_state = None

    # ------------------------------------------------------------------
    # Subclass hooks -- override in YggdrasilPlugin / ReticulumPlugin.
    # ------------------------------------------------------------------

    async def ensure_transport_up(self):
        """Bring the overlay transport online; raise if unavailable."""
        raise NotImplementedError

    async def get_local_address(self):
        """Return the local overlay address as a string."""
        raise NotImplementedError

    async def start_listener(self):
        """Start an overlay-side listener.  Return (port, await_inbound).

        ``port`` is what we advertise to the peer.  ``await_inbound`` is
        a coroutine that returns a Pipe-like object when the peer dials
        in (or None / raises on timeout).  Subclasses are free to
        ignore ``port`` if their overlay uses destination hashes rather
        than (addr, port) tuples -- they just return the hash via
        ``get_local_address`` and pass any sentinel as ``port``.
        """
        raise NotImplementedError

    async def connect_to_peer(self, peer_address, peer_port):
        """Dial the peer over the overlay; return a Pipe-like object."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Shared run() logic.
    # ------------------------------------------------------------------

    async def run(self, reply=None):
        """Initiator (reply=None) listens; responder (reply=msg) dials.

        Mirrors the TURN plugin's two-call pattern: TraversalManager
        invokes run() once with reply=None on the initiator side, then
        a second time with reply=<peer's OverlayMsg> on either side
        when the signaling reply arrives.
        """
        try:
            await self.ensure_transport_up()
        except Exception:
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
            return

        try:
            local_address = await self.get_local_address()
        except Exception:
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
            return

        if reply is None:
            # Initiator path: start listener, advertise, wait for dial.
            await self.run_as_initiator(local_address)
        else:
            # Responder path: dial peer at the address they signaled.
            await self.run_as_responder(local_address, reply)

    async def run_as_initiator(self, local_address):
        """Listener half: open an overlay port and wait for the peer."""
        msg_class = self.overlay_msg_class()
        try:
            listener_port, accept_coro = await self.start_listener()
        except Exception:
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
            return

        msg = msg_class(
            {
                "payload": {
                    "address": local_address,
                    "port": listener_port,
                },
            }
        )
        msg.meta.plugin_name = self.name
        try:
            await self.send_signal(msg)
        except Exception:
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
            return

        log(fstr(
            "{0}[{1}]: listening on overlay {2}:{3}",
            (self.name, self.plugin_id, local_address, listener_port),
        ))

        # Wait for the peer's inbound connection, capped at the plugin
        # timeout minus a small grace so the outer race_combos has room
        # to consume the result before its own timeout fires.
        cap = max(1.0, (self.timeout or 30) - 2.0)
        try:
            pipe = await asyncio.wait_for(accept_coro, timeout=cap)
        except asyncio.TimeoutError:
            log(fstr(
                "{0}[{1}]: timed out waiting for overlay inbound",
                (self.name, self.plugin_id),
            ))
            if not self.result.done():
                self.result.set_result(None)
            return
        except Exception:
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
            return

        if pipe is None:
            if not self.result.done():
                self.result.set_result(None)
            return

        log(fstr(
            "{0}[{1}]: peer connected over overlay",
            (self.name, self.plugin_id),
        ))
        if not self.result.done():
            self.result.set_result(pipe)

    async def run_as_responder(self, local_address, reply):
        """Dialer half: connect to the address the initiator signaled."""
        peer_address = reply.payload.address
        peer_port = reply.payload.port
        try:
            pipe = await self.connect_to_peer(peer_address, peer_port)
        except Exception:
            log_exception()
            if not self.result.done():
                self.result.set_result(None)
            return

        if pipe is None:
            if not self.result.done():
                self.result.set_result(None)
            return

        log(fstr(
            "{0}[{1}]: connected to peer overlay {2}:{3}",
            (self.name, self.plugin_id, peer_address, peer_port),
        ))
        if not self.result.done():
            self.result.set_result(pipe)

    # ------------------------------------------------------------------
    # Helpers.
    # ------------------------------------------------------------------

    def overlay_msg_class(self):
        """Return the proto class registered in proto_messages.

        Single source of truth: the first (and only) entry in
        ``proto_messages`` is the overlay's signaling message class.
        """
        if not self.proto_messages:
            raise RuntimeError(
                "{0}: no proto_messages registered".format(self.name)
            )
        return self.proto_messages[0][0]
