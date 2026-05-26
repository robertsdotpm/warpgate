"""AutoRelay client logic.

When a libp2p host can't be reached directly (NAT, no UPnP, etc),
the canonical libp2p fallback is to reserve slots on public Circuit
Relay v2 relays and advertise the resulting ``/p2p-circuit``
multiaddrs so peers know they can reach us through those relays.

AutoRelay is the client-side machinery for that:

  1. For each active libp2p session, check if the peer advertises
     ``/libp2p/circuit/relay/0.2.0/hop`` in their Identify response.
  2. If yes -- and we want a relay -- call
     ``Libp2pNode.reserve_via_relay(session)`` to hold a slot.
  3. Track active reservations; advertise the corresponding
     ``/p2p-circuit`` multiaddrs in our own Identify response.

For Phase 1 we keep this simple: opportunistic reservations on
every peer that advertises HOP, capped at ``max_relays`` to bound
overhead.  Real go-libp2p AutoRelay does fancier reachability
detection (via AutoNAT) before deciding to engage a relay; we
let the caller pass a ``should_use_relay()`` callback to mirror
that policy hook.
"""
import asyncio

from . import multiaddr as ma


HOP_PROTOCOL = "/libp2p/circuit/relay/0.2.0/hop"


class AutoRelay(object):
    """Per-Libp2pNode helper that opportunistically reserves on HOP-capable peers.

    Construct with the owning node; call ``run(session)`` from the
    session dispatcher's post-handshake hook to consider that
    session as a relay candidate.
    """

    def __init__(self, node, max_relays=2, query_timeout=10.0):
        self.node = node
        self.max_relays = max_relays
        self.query_timeout = query_timeout
        # session.remote_peer_id -> Reservation
        self.active_reservations = {}
        # Tasks we've spawned for AutoRelay work.
        self.tasks = []

    async def consider(self, session):
        """Decide whether to reserve on ``session.remote_peer_id``.

        Run Identify against the session; if the peer lists
        ``/libp2p/.../hop`` in its protocols list AND we have <
        max_relays active reservations, call ``reserve_via_relay``.

        Idempotent / safe to call multiple times -- if a
        reservation already exists for this peer we skip; if our
        slots are full we skip.
        """
        if session.remote_peer_id in self.active_reservations:
            return
        if len(self.active_reservations) >= self.max_relays:
            return
        try:
            ident = await asyncio.wait_for(
                self.node.query_identify(session),
                timeout=self.query_timeout,
            )
        except (ConnectionError, asyncio.TimeoutError, OSError, ValueError):
            return
        if HOP_PROTOCOL not in ident.protocols:
            return
        try:
            reservation = await asyncio.wait_for(
                self.node.reserve_via_relay(session),
                timeout=self.query_timeout,
            )
        except (ConnectionError, asyncio.TimeoutError, OSError, ValueError):
            return
        self.active_reservations[session.remote_peer_id] = reservation
        # Add a /p2p-circuit/p2p/<our_id> multiaddr per relay-advertised
        # addr to our published listen list so a future Identify
        # response surfaces "you can reach me through these relays".
        for relay_addr_bytes in reservation.addrs:
            relayed = self.build_relayed_addr(
                relay_addr_bytes,
                relay_peer_id=session.remote_peer_id,
            )
            if relayed and relayed not in self.node.listen_multiaddrs:
                self.node.listen_multiaddrs.append(relayed)

    def build_relayed_addr(self, relay_addr_bytes, relay_peer_id=None):
        """Compose ``<relay_addr>/p2p-circuit/p2p/<our_peer_id>``.

        ``relay_addr_bytes`` is the relay's own listenable multiaddr.
        If it already contains a ``/p2p/<relay_pid>`` segment, use
        it as-is.  Otherwise, append ``/p2p/<relay_peer_id>`` from
        the optional argument -- real libp2p relays often advertise
        bare ip/tcp multiaddrs in their HOP reservation reply, so
        we splice the peer_id we already know from the session.
        """
        try:
            parts = ma.decode(relay_addr_bytes)
        except (ValueError, OSError):
            return None
        has_relay_peer_id = any(c == ma.CODE_P2P for c, _ in parts)
        out = bytes(relay_addr_bytes)
        if not has_relay_peer_id:
            if relay_peer_id is None:
                return None
            out += ma.encode_p2p(relay_peer_id)
        return out + ma.encode_p2p_circuit() + ma.encode_p2p(self.node.identity.peer_id)

    async def close(self):
        for t in self.tasks:
            if not t.done():
                t.cancel()
        self.tasks = []
        self.active_reservations.clear()
