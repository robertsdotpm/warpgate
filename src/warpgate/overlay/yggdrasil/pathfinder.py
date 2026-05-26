"""Pathfinder -- multicast path lookup + per-dest source-route cache.

Port of ``ironwood/network/pathfinder.go``.  Once the tree is up,
greedy tree-routing forwards traffic correctly but inefficiently
(hop count = tree distance).  The pathfinder adds shortcuts:

  1. When app sends to a new dest, we issue a PathLookup multicast
     (forwarded via Bloom filter -- only peers whose filter
     "knows" the dest receive it).
  2. The dest's node receives the lookup, signs a PathNotifyInfo,
     replies with a PathNotify carrying its current source-route.
  3. We cache the dest's path in ``self.paths[dest]``; future
     Traffic packets to that dest use the cached path instead
     of greedy tree-route hops.
  4. When a hop along the cached path fails to find a next peer
     (greedy lookup returns None mid-flight), we emit PathBroken
     back to the source so they re-discover.

Bloom filter is the multicast forwarding optimisation: each peer
sends us a Bloom of "keys reachable through me" (transformed via
``bloom_transform`` -- subnet-aware so a whole /64 collapses into
one bit set).  When forwarding a PathLookup we only send it to
peers whose filter Test() matches the dest -- no flood, just the
relevant arm of the tree.
"""
import asyncio
import time

from aionetiface import fstr, log, log_exception

from .address import get_key_from_subnet, subnet_for_key
from .routing_msgs import (
    Bloom,
    PathBroken,
    PathLookup,
    PathNotify,
    PathNotifyInfo,
    Traffic,
)
from .wire import WIRE_PROTO_PATH_BROKEN, WIRE_PROTO_PATH_LOOKUP, WIRE_PROTO_PATH_NOTIFY


# Upstream defaults from ironwood/network/config.go.
PATH_TIMEOUT_SECONDS = 60.0
PATH_THROTTLE_SECONDS = 1.0
# Extra delay after a path_broken before re-lookup, on top of the
# normal throttle.  Gives the public mesh time to refresh its
# tree-port-allocation view before we re-discover the path --
# without this we'd retry the same stale path in a tight loop.
PATH_BROKEN_BACKOFF_SECONDS = 5.0


def bloom_transform(key):
    """Map a 32-byte ed25519 pubkey to its /64-subnet equivalent.

    Matches yggdrasil-go's ``keyXform`` (``SubnetForKey(key).GetKey()``):
    takes a node key, derives the /64 subnet it lives in, and
    converts back to a partial key with the per-node bits zeroed.
    Two keys in the same /64 hash identically here -- the point
    of the transform is to collapse a whole subnet into one bloom
    bit set so multicast forwarding is subnet-granular.
    """
    return get_key_from_subnet(subnet_for_key(key))


class PathInfo(object):
    """Cached source-route to a known destination."""

    def __init__(self, path, seq=0):
        self.path = list(path)
        self.seq = int(seq)
        self.req_time = time.monotonic()
        self.broken = False
        # Optional pending Traffic awaiting confirmation -- the
        # upstream traffic-cache feature; we keep it for parity
        # but the in-flight Traffic isn't strictly necessary on
        # the warpgate side (we drop on no-route).
        self.traffic = None


class PathRumor(object):
    """In-flight path lookup -- key is the transformed dest pubkey."""

    def __init__(self):
        self.send_time = time.monotonic()
        self.traffic = None  # buffered traffic awaiting PathNotify


class Pathfinder(object):
    """Per-router pathfinder state.

    Constructed against an ActiveRouter.  The router calls into
    ``handle_lookup`` / ``handle_notify`` / ``handle_broken`` for
    incoming packets, and ``handle_outbound_traffic`` for app
    traffic that needs a route lookup.
    """

    def __init__(self, router):
        self.router = router
        self.paths = {}   # dest_key -> PathInfo
        self.rumors = {}  # xformed dest_key -> PathRumor

    @property
    def public_key(self):
        return self.router.public_key

    @property
    def seed(self):
        return self.router.seed

    # -------- traffic-side -----------------------------------------------

    async def handle_outbound_traffic(self, tr):
        """App-issued Traffic.  Fast path if path known; else fire a lookup."""
        info = self.paths.get(bytes(tr.dest))
        if info is not None and not info.broken:
            tr.path = list(info.path)
            _, from_path = self.router.get_root_and_path(self.public_key)
            tr.from_path = list(from_path or [])
            # Cache the latest traffic for retransmit-on-recovery
            # (mirrors upstream pathfinderTrafficCache).
            info.traffic = tr
            # Hand to the router's normal forward path.
            await self.router.forward_outbound_traffic(tr)
            return
        # No cached path -- issue a lookup + buffer the traffic.
        await self.send_rumor_lookup(tr.dest, buffered_traffic=tr)

    async def send_rumor_lookup(self, dest, buffered_traffic=None):
        """Throttled PathLookup -- one in-flight per xformed dest at a time."""
        xform = bloom_transform(bytes(dest))
        rumor = self.rumors.get(xform)
        now = time.monotonic()
        if rumor is not None:
            if now - rumor.send_time < PATH_THROTTLE_SECONDS:
                # Already requested recently; just buffer the traffic.
                if buffered_traffic is not None:
                    rumor.traffic = buffered_traffic
                return
            rumor.send_time = now
        else:
            rumor = PathRumor()
            self.rumors[xform] = rumor
        if buffered_traffic is not None:
            rumor.traffic = buffered_traffic
        await self.issue_path_lookup(dest)

    async def issue_path_lookup(self, dest):
        """Build + multicast a PathLookup to bloom-matching peers."""
        _, from_path = self.router.get_root_and_path(self.public_key)
        lookup = PathLookup(
            source=self.public_key,
            dest=bytes(dest),
            from_path=list(from_path or []),
        )
        await self.handle_lookup(self.public_key, lookup)

    # -------- protocol-side ----------------------------------------------

    async def handle_lookup(self, from_key, lookup):
        """Multicast forward + self-match check.

        Per upstream pathfinder.go:46-48, only on-tree peers may
        inject lookups -- otherwise an arbitrary connected node
        could trigger bloom-multicast fan-out toward every
        on-tree peer (amplification DoS).  Self-issued lookups
        skip the gate (we route our own queries unconditionally).
        """
        if bytes(from_key) != bytes(self.public_key):
            if not self.router.is_peer_on_tree(from_key):
                return
        # Forward via bloom multicast: any peer whose recv-bloom
        # matches the transformed dest gets the lookup.
        await self.router.bloom_multicast(
            WIRE_PROTO_PATH_LOOKUP, lookup.encode(),
            from_key=from_key, dest_key=lookup.dest,
        )
        # Self-match check: am I (or a /64 sibling of mine) the dest?
        if bloom_transform(self.public_key) != bloom_transform(lookup.dest):
            return
        # Yes -- sign + send back a PathNotify with our current path.
        _, path = self.router.get_root_and_path(self.public_key)
        info = PathNotifyInfo(
            seq=int(time.time()), path=list(path or []), sig=b"\x00" * 64,
        )
        from .router_active import sign
        info.sig = sign(self.seed, info.bytes_for_sig())
        notify = PathNotify(
            path=list(lookup.from_path),
            watermark=(1 << 64) - 1,
            source=self.public_key,
            dest=lookup.source,
            info=info,
        )
        await self.handle_notify(self.public_key, notify)

    async def handle_notify(self, from_key, notify):
        """Either forward (we're a transit hop) or accept (dest is us)."""
        # The watermark mechanism in upstream is for loop avoidance
        # on the forward path; for our compact port we just check
        # whether we have a closer next-hop and forward if so.
        watermark = [notify.watermark]
        next_link = self.router.lookup_next_hop_with_watermark(
            notify.path, watermark,
        )
        if next_link is not None:
            notify.watermark = watermark[0]
            await self.router.send_packet_safe(
                next_link, WIRE_PROTO_PATH_NOTIFY, notify.encode(),
            )
            return
        # We're the destination of the notify -- accept it.
        if bytes(notify.dest) != bytes(self.public_key):
            return
        src = bytes(notify.source)
        existing = self.paths.get(src)
        # Solicitation gate: upstream pathfinder._handleNotify (Go
        # lines 104-124) drops notifies that don't correspond to an
        # outstanding rumor OR an existing path entry.  Without this
        # check, any peer can pollute our path cache by sending
        # valid-looking notifies for keys we never asked about.
        if existing is None:
            xform = bloom_transform(src)
            if xform not in self.rumors:
                return
        # Existing-path seq check first, so the cheap reject happens
        # before the expensive signature verify.
        if existing is not None and notify.info.seq <= existing.seq:
            return
        # Verify the signed PathNotifyInfo (proves the source
        # really sent this path).
        from .router_active import verify
        if not verify(notify.source, notify.info.bytes_for_sig(),
                      notify.info.sig):
            return
        info = PathInfo(path=list(notify.info.path), seq=notify.info.seq)
        # If there's a rumor with buffered traffic for this dest,
        # promote the traffic so we can resend it.
        xform = bloom_transform(src)
        rumor = self.rumors.get(xform)
        if rumor is not None and rumor.traffic is not None:
            info.traffic = rumor.traffic
            rumor.traffic = None
        self.paths[src] = info
        # Resend the buffered traffic, now that we have a path.
        if info.traffic is not None:
            tr = info.traffic
            info.traffic = None
            await self.handle_outbound_traffic(tr)

    async def handle_broken(self, from_key, broken):
        """A path we used has broken -- forward to source, or invalidate cache.

        On source-side: mark the cached path broken AND push the
        rumor's send_time forward by ``PATH_BROKEN_BACKOFF_SECONDS``
        so the next ``send_rumor_lookup`` for this dest is delayed.
        This gives the public mesh time to converge between
        re-lookups -- without backoff, we'd keep getting the
        same stale path advertised by the dest (whose own tree
        view hasn't refreshed yet).  See
        [[yggdrasil-tree-convergence-bug]] for the live trace
        that motivated this delay.
        """
        watermark = [broken.watermark]
        next_link = self.router.lookup_next_hop_with_watermark(
            broken.path, watermark,
        )
        if next_link is not None:
            broken.watermark = watermark[0]
            await self.router.send_packet_safe(
                next_link, WIRE_PROTO_PATH_BROKEN, broken.encode(),
            )
            return
        # We are the source of the broken path -- invalidate + retry
        # with a forced back-off so the mesh has time to converge.
        if bytes(broken.source) != bytes(self.public_key):
            return
        info = self.paths.get(bytes(broken.dest))
        if info is not None:
            info.broken = True
        # Push the rumor's send_time forward so the next lookup waits.
        xform = bloom_transform(bytes(broken.dest))
        rumor = self.rumors.get(xform)
        if rumor is not None:
            rumor.send_time = time.monotonic() + PATH_BROKEN_BACKOFF_SECONDS
        # Issue the lookup -- it will throttle itself based on the
        # send_time we just pushed forward, so this is effectively
        # a "schedule for later" call.
        await self.send_rumor_lookup(broken.dest)

    async def emit_path_broken(self, tr):
        """Build + send a PathBroken back along the from-path of ``tr``."""
        broken = PathBroken(
            path=list(tr.from_path),
            watermark=(1 << 64) - 1,
            source=tr.source,
            dest=tr.dest,
        )
        await self.handle_broken(self.public_key, broken)
