"""Lightweight router: decode protocol packets, track peers, count traffic.

This is the Phase 5a port of ``ironwood/network/router.go`` --
just enough state to recognise every routing-protocol packet a
real Yggdrasil peer sends us without crashing, plus the
peer-bookkeeping needed to source-route a reply.  The Phase 5b
follow-up will add:

  * spanning-tree maintenance (announce / sig_req / sig_res handling)
  * bloom-filter multicast for path lookups
  * traffic forwarding along source-routed paths

For Phase 5a a node attached to a real Yggdrasil network behaves
as a STUB leaf: it acknowledges peer protocol traffic (so the
peer doesn't drop the link as unresponsive), reports its own
identity, but does NOT forward traffic on behalf of others and
does NOT participate in tree formation.  That's enough to be a
non-disruptive presence on the overlay -- existing traffic
flows around us -- while the routing protocol stays under test.

Plug into NodeCore via ``packet_handler``: NodeCore calls
``Router.on_packet(link, packet_type, payload)`` for every inbound
packet, and Router decodes + counts + (eventually) acts.
"""
import asyncio

from aionetiface import fstr, log, log_exception

from .routing_msgs import (
    DECODER_FOR_TYPE,
    DecodeError,
    PathBroken,
    PathLookup,
    PathNotify,
    RouterAnnounce,
    RouterSigReq,
    RouterSigRes,
    Traffic,
    Bloom,
)
from .wire import (
    WIRE_TYPE_NAMES,
    WIRE_DUMMY,
    WIRE_KEEP_ALIVE,
    WIRE_PROTO_SIG_REQ,
    WIRE_PROTO_SIG_RES,
    WIRE_PROTO_ANNOUNCE,
    WIRE_PROTO_BLOOM_FILTER,
    WIRE_PROTO_PATH_LOOKUP,
    WIRE_PROTO_PATH_NOTIFY,
    WIRE_PROTO_PATH_BROKEN,
    WIRE_TRAFFIC,
)


class Router(object):
    """Stub router with full decode + per-type counters + peer info.

    Hand the router a NodeCore reference + the node's pubkey at
    construction.  Then the NodeCore packet_handler can be set to
    ``router.on_packet`` and every inbound packet flows through.

    The router does NOT spawn its own asyncio task -- it lives
    inside the per-peer recv loops NodeCore already runs.  All
    state mutation is in the on_*_packet methods which the
    asyncio loop serialises by virtue of single-threaded coro
    dispatch.
    """

    def __init__(self, node_core):
        self.node_core = node_core
        # Per-wire-type packet counters.  Used in tests + diagnostics.
        self.counters = {wt: 0 for wt in WIRE_TYPE_NAMES}
        # Per-peer protocol state.  Keyed by remote pubkey, holds:
        #   - last_sig_req / last_sig_res seen
        #   - last_announce seen
        #   - last_bloom seen
        # These let the Phase 5b router pick up where we left off
        # without having to walk the wire again.
        self.peer_state = {}
        # Most recent traffic source/dest seen, for sanity logging.
        self.last_traffic_source = None
        self.last_traffic_dest = None

    @property
    def public_key(self):
        return self.node_core.public_key

    def ensure_peer_state(self, link):
        st = self.peer_state.get(link.remote_pubkey)
        if st is None:
            st = {
                "sig_req": None,
                "sig_res": None,
                "announce": None,
                "bloom": None,
            }
            self.peer_state[link.remote_pubkey] = st
        return st

    async def on_packet(self, link, packet_type, payload):
        """NodeCore packet_handler entry point.  Dispatch by wire type."""
        self.counters[packet_type] = self.counters.get(packet_type, 0) + 1

        # Fast paths -- no decode needed.
        if packet_type in (WIRE_DUMMY, WIRE_KEEP_ALIVE):
            return

        decoder = DECODER_FOR_TYPE.get(packet_type)
        if decoder is None:
            log(fstr(
                "router[{0}]: unknown wire type {1} from peer {2}",
                (self.public_key[:4].hex(), packet_type, link.remote_addr),
            ))
            return

        try:
            msg = decoder.decode(payload)
        except (DecodeError, ValueError):
            log_exception()
            return

        if packet_type == WIRE_PROTO_SIG_REQ:
            await self.on_sig_req(link, msg)
        elif packet_type == WIRE_PROTO_SIG_RES:
            await self.on_sig_res(link, msg)
        elif packet_type == WIRE_PROTO_ANNOUNCE:
            await self.on_announce(link, msg)
        elif packet_type == WIRE_PROTO_BLOOM_FILTER:
            await self.on_bloom(link, msg)
        elif packet_type == WIRE_PROTO_PATH_LOOKUP:
            await self.on_path_lookup(link, msg)
        elif packet_type == WIRE_PROTO_PATH_NOTIFY:
            await self.on_path_notify(link, msg)
        elif packet_type == WIRE_PROTO_PATH_BROKEN:
            await self.on_path_broken(link, msg)
        elif packet_type == WIRE_TRAFFIC:
            await self.on_traffic(link, msg)

    async def on_sig_req(self, link, req):
        """Tree-signing request from a peer wanting us to be its parent.

        Phase 5a: stash the request without responding.  The peer
        will fall back to a different parent on its own (after the
        per-peer sigreq timeout).  Phase 5b will sign + reply.
        """
        st = self.ensure_peer_state(link)
        st["sig_req"] = req

    async def on_sig_res(self, link, res):
        """Tree-signing response from a peer we chose as parent.

        Phase 5a: stash; we never SENT a sig_req (no tree
        participation) so this shouldn't fire in practice.
        """
        st = self.ensure_peer_state(link)
        st["sig_res"] = res

    async def on_announce(self, link, ann):
        """Tree announcement: peer broadcasting its (node, parent) coords.

        Phase 5a: cache + count.  Real router would update the
        per-key infos map + propagate to other peers.
        """
        st = self.ensure_peer_state(link)
        st["announce"] = ann

    async def on_bloom(self, link, b):
        """Bloom-filter update for path-lookup multicasting.

        Phase 5a: cache.  Real router would use this to decide
        which peers a future path_lookup should be forwarded to.
        """
        st = self.ensure_peer_state(link)
        st["bloom"] = b

    async def on_path_lookup(self, link, lookup):
        """Multicast path-discovery request.

        Phase 5a: if the lookup is FOR US (dest matches our pubkey
        modulo the bloom transform that's not yet implemented),
        we'd reply with a PathNotify.  Otherwise we'd multicast
        forward.  For now: just count + drop.
        """
        # No-op; Phase 5b adds the multicast forward + self-match reply.
        pass

    async def on_path_notify(self, link, notify):
        """Reply to a PathLookup we (or someone we forwarded for) issued.

        Phase 5a: count + drop.  Phase 5b would resolve the
        corresponding outstanding lookup.
        """
        pass

    async def on_path_broken(self, link, broken):
        """Notification that a previously-known path no longer works."""
        pass

    async def on_traffic(self, link, tr):
        """User data packet.  Forward if it's a transit, deliver if dest=us."""
        self.last_traffic_source = tr.source
        self.last_traffic_dest = tr.dest
        # If we're the destination, hand to the application.  We
        # don't yet have an application-side packet API (Phase 6+
        # would expose this via something analogous to
        # iwe.PacketConn); for now just count + log.
        if tr.dest == self.public_key:
            log(fstr(
                "router[{0}]: received {1}-byte traffic from {2}",
                (
                    self.public_key[:4].hex(),
                    len(tr.payload),
                    tr.source[:4].hex(),
                ),
            ))
        # Otherwise: this is transit.  Phase 5b would look up the
        # next hop from the source-routed path and forward.

    def summary(self):
        """Return a dict summarising current state (test/diagnostic use)."""
        return {
            "counters": dict(self.counters),
            "peer_count": len(self.peer_state),
            "last_traffic_source": self.last_traffic_source,
            "last_traffic_dest": self.last_traffic_dest,
        }
