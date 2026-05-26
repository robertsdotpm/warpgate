"""Active routing layer -- tree formation + greedy traffic forwarding.

Phase 5b port of ``ironwood/network/router.go``'s state-machine
core.  This replaces the Phase 5a stub with a router that
actually participates in spanning-tree formation and forwards
source-routed traffic.

What's in:

  * sig_req signing (we reply when a peer asks us to be its parent)
  * sig_res caching + verification (when our chosen parent replies)
  * announce processing (update infos[key] table per the
    upstream age/parent/nonce comparator)
  * parent selection (``_fix``) -- pick the peer that leads to
    the lowest-pubkey root with the lowest cost
  * become-root fallback (sign our own announce with parent=self)
  * traffic forwarding via greedy tree lookup (``_lookup``)
  * periodic ``_do_maintenance`` (1s tick) that fixes parent and
    sends pending announcements

What's deferred to Phase 5c:

  * Bloom filter multicast for path lookups (currently no-ops
    on bloom packets but tracks them)
  * Pathfinder (path_lookup → path_notify → cached source route)
  * Per-peer latency-weighted cost (uses uniform cost=1 for now)

Even without 5c, the tree alone gives loop-free greedy routing
that works on small overlays.  Real Yggdrasil performance comes
from path caching, but correctness comes from the tree.
"""
import asyncio
import os
import struct
import time

from aionetiface import fstr, log, log_exception
from ecdsa import SigningKey, VerifyingKey, Ed25519
from ecdsa.keys import BadSignatureError

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


# Upstream defaults from ironwood/network/config.go.  routerRefresh
# is how often a root re-signs its own info; routerTimeout is how
# long peer info lives before being expired.
ROUTER_REFRESH_SECONDS = 4 * 60          # 4 min
ROUTER_TIMEOUT_SECONDS = 60 * 60         # 1 hr
MAINTENANCE_INTERVAL_SECONDS = 1.0


def sign(seed, msg):
    """Return a 64-byte ed25519 signature over ``msg`` with the seed key."""
    sk = SigningKey.from_string(bytes(seed), curve=Ed25519)
    return bytes(sk.sign(bytes(msg)))


def verify(public_key, msg, sig):
    """Return True if ``sig`` is a valid ed25519 signature on ``msg`` by ``public_key``."""
    try:
        vk = VerifyingKey.from_string(bytes(public_key), curve=Ed25519)
        vk.verify(bytes(sig), bytes(msg))
        return True
    except (BadSignatureError, ValueError):
        return False


def key_less(a, b):
    """Lexicographic less-than on raw key bytes -- mirrors upstream ``publicKey.less``."""
    return bytes(a) < bytes(b)


class RouterInfo(object):
    """Per-key entry in the routing table.

    Mirrors upstream's ``routerInfo`` -- the canonical tuple
    that's compared between announces to decide whether a new
    one is better than what we have.
    """

    def __init__(self, parent, sig_res, sig):
        self.parent = bytes(parent)
        self.sig_res = sig_res  # RouterSigRes
        self.sig = bytes(sig)

    @property
    def seq(self):
        return self.sig_res.seq

    @property
    def nonce(self):
        return self.sig_res.nonce

    @property
    def port(self):
        return self.sig_res.port

    def get_announce(self, key):
        """Build the broadcastable ``RouterAnnounce`` for this info under ``key``."""
        return RouterAnnounce(
            key=key, parent=self.parent,
            sig_res=self.sig_res, sig=self.sig,
        )


class ActiveRouter(object):
    """Spanning-tree router + greedy traffic forwarding.

    Constructed against a NodeCore.  Set
    ``node_core.packet_handler = router.on_packet`` to wire it
    in.  ``router.start()`` launches the 1 s maintenance timer;
    ``router.stop()`` cancels it.

    State maps:
      ``self.infos[key]`` -- RouterInfo for each known node
      ``self.requests[peer_key]`` -- last sig_req we sent the peer
      ``self.responses[peer_key]`` -- last sig_res we received from peer
      ``self.sent[peer_key]`` -- set of node keys whose info we've
                                 already sent to this peer (announce dedup)
    """

    def __init__(self, node_core):
        self.node_core = node_core
        self.counters = {wt: 0 for wt in WIRE_TYPE_NAMES}
        # Per-key routing table.
        self.infos = {}
        # Per-peer protocol state.
        self.requests = {}
        self.responses = {}
        self.sent = {}
        # Latest bloom from each peer (Phase 5c will act on these).
        self.peer_bloom = {}
        # Local sequence number -- monotonic per (re)become-root.
        self.local_seq = 0
        # Maintenance timer state.
        self.maintenance_task = None
        self.do_root2 = True   # first maintenance cycle: become root
        self.running = False
        # Traffic delivered to us (dest == our pubkey) -- delivered
        # to the application layer in Phase 6+.  For now just
        # collect them in a queue the test can pull from.
        self.inbox = asyncio.Queue()
        # Become root immediately so we have a usable self.infos entry.
        self.become_root()

    @property
    def public_key(self):
        return self.node_core.public_key

    @property
    def seed(self):
        return self.node_core.seed

    # -------- lifecycle --------------------------------------------------

    def start(self):
        if self.running:
            return
        self.running = True
        loop = asyncio.get_event_loop()
        self.maintenance_task = loop.create_task(self.maintenance_loop())

    async def maintenance_loop(self):
        try:
            while self.running:
                await asyncio.sleep(MAINTENANCE_INTERVAL_SECONDS)
                try:
                    self.do_maintenance()
                except Exception:
                    log_exception()
        except asyncio.CancelledError:
            pass

    def stop(self):
        self.running = False
        if self.maintenance_task is not None:
            try:
                self.maintenance_task.cancel()
            except Exception:
                pass
            self.maintenance_task = None

    # -------- spanning-tree core -----------------------------------------

    def become_root(self):
        """Sign + install an announce naming OURSELVES as our own parent.

        Used at startup and as the fallback when no peer leads to a
        lower-pubkey root.  The signed payload is the same shape
        the rest of the protocol uses; root nodes just have
        parent==self.
        """
        self.local_seq += 1
        req = RouterSigReq(seq=self.local_seq, nonce=int.from_bytes(os.urandom(8), "big"))
        res = RouterSigRes(
            seq=req.seq, nonce=req.nonce, port=0,
            psig=b"\x00" * 64,  # filled below
        )
        # We sign as both child and parent (we are our own parent).
        bs = res.bytes_for_sig(self.public_key, self.public_key)
        psig = sign(self.seed, bs)
        res.psig = psig
        ann = RouterAnnounce(
            key=self.public_key, parent=self.public_key,
            sig_res=res, sig=psig,  # same sig serves both
        )
        self.update_info(ann)

    def handle_sig_req(self, link, req):
        """Peer asked us to be their parent.  Sign + reply."""
        res = RouterSigRes(
            seq=req.seq, nonce=req.nonce,
            port=self.node_core.peers.get_peer(link.remote_pubkey).port,
            psig=b"\x00" * 64,
        )
        bs = res.bytes_for_sig(link.remote_pubkey, self.public_key)
        res.psig = sign(self.seed, bs)
        return res

    def handle_sig_res(self, link, res):
        """Peer (our potential parent) signed our sig_req.

        Verify the signature; if valid, cache and let the next
        ``_fix`` cycle decide whether to adopt them as parent.
        """
        req = self.requests.get(link.remote_pubkey)
        if req is None:
            return
        # Verify peer's signature on (us, peer, req+port).
        bs = res.bytes_for_sig(self.public_key, link.remote_pubkey)
        if not verify(link.remote_pubkey, bs, res.psig):
            log(fstr(
                "router[{0}]: sig_res signature verify FAILED from {1}",
                (self.public_key[:4].hex(), link.remote_addr),
            ))
            return
        self.responses[link.remote_pubkey] = res

    def handle_announce(self, link, ann):
        """Apply upstream's announce-comparison rules and propagate."""
        # Verify both signatures: child signed (key,parent,sig_res)
        # and parent signed (key,parent,req+port).
        bs = ann.sig_res.bytes_for_sig(ann.key, ann.parent)
        if not verify(ann.key, bs, ann.sig):
            return
        if not verify(ann.parent, bs, ann.sig_res.psig):
            return
        # Special-case: a non-root must have a non-zero port.
        if ann.sig_res.port == 0 and ann.key != ann.parent:
            return
        accepted = self.update_info(ann)
        if accepted:
            self.sent.setdefault(link.remote_pubkey, set()).add(ann.key)

    def update_info(self, ann):
        """Insert/replace info[key] if ``ann`` is strictly better.

        Comparison rules ARE MANDATORY for protocol convergence
        and must match upstream byte-for-byte:
          1) higher seq wins
          2) ties: lower parent key wins
          3) ties: lower nonce wins
          4) otherwise reject
        """
        existing = self.infos.get(ann.key)
        if existing is not None:
            if existing.seq > ann.sig_res.seq:
                return False
            if existing.seq == ann.sig_res.seq:
                if key_less(existing.parent, ann.parent):
                    return False
                if existing.parent == ann.parent:
                    if ann.sig_res.nonce >= existing.nonce:
                        return False
        # Accept.  Reset the sent-dedup map so this gets re-broadcast.
        for sent in self.sent.values():
            sent.discard(ann.key)
        self.infos[ann.key] = RouterInfo(
            parent=ann.parent,
            sig_res=ann.sig_res,
            sig=ann.sig,
        )
        return True

    def fix(self):
        """Pick the best parent from known responses.

        Best = leads to lowest-pubkey root.  Cost is ignored for
        now (uniform peer cost); Phase 5c will fold in latency.
        """
        self_pub = self.public_key
        best_root = self_pub
        best_parent = self_pub
        # Walk current responses.
        for peer_key, res in self.responses.items():
            if peer_key not in self.infos:
                continue
            p_root, p_dists = self.get_root_and_dists(peer_key)
            if self_pub in p_dists:
                # Would loop through us.
                continue
            if key_less(p_root, best_root):
                best_root, best_parent = p_root, peer_key
        # If our current self.info's parent isn't best_parent, switch.
        self_info = self.infos.get(self_pub)
        if self_info is None or self_info.parent != best_parent:
            if best_parent != self_pub and best_parent in self.responses:
                # Use the response from best_parent to update self.
                self.use_response(best_parent, self.responses[best_parent])
            elif self.do_root2:
                # No better option; become root.
                self.become_root()
                self.do_root2 = False

    def use_response(self, peer_key, res):
        """Adopt ``peer_key`` as our parent using their res.

        Build a new self-info with parent=peer_key, our own sig
        over (us, peer_key, req+port).  Then re-broadcast.
        """
        bs = res.bytes_for_sig(self.public_key, peer_key)
        self_sig = sign(self.seed, bs)
        # Wrap with our self-key.
        info = RouterInfo(parent=peer_key, sig_res=res, sig=self_sig)
        ann = RouterAnnounce(
            key=self.public_key, parent=peer_key,
            sig_res=res, sig=self_sig,
        )
        self.update_info(ann)

    def get_root_and_dists(self, dest):
        """Walk parent chain from ``dest`` to compute (root_key, dist_map).

        ``dist_map`` maps each key on the chain to its hop distance
        from ``dest``.  Used by ``fix`` for loop detection + cost
        comparison.
        """
        dists = {}
        next_key = bytes(dest)
        root = next_key
        dist = 0
        while next_key not in dists:
            info = self.infos.get(next_key)
            if info is None:
                break
            root = next_key
            dists[next_key] = dist
            dist += 1
            if info.parent == next_key:
                break
            next_key = info.parent
        return root, dists

    def get_root_and_path(self, dest):
        """Compute the source-route path from root → dest.

        Returns ``(root_key, [peer_port, ...])`` -- the ports
        listed in root-to-dest order.  Used when injecting our
        own traffic to figure out the path to advertise.
        """
        ports = []
        visited = set()
        next_key = bytes(dest)
        root = next_key
        while next_key not in visited:
            info = self.infos.get(next_key)
            if info is None:
                return dest, None
            root = next_key
            visited.add(next_key)
            if info.parent == next_key:
                break
            ports.append(info.port)
            next_key = info.parent
        ports.reverse()
        return root, ports

    def do_maintenance(self):
        """Periodic tick: sync new peers, fix parent selection, send pending announces."""
        self.sync_peers()
        self.fix()
        self.send_pending_announces()

    def sync_peers(self):
        """Initialize routing state for any newly-connected peers.

        NodeCore.peers is the source of truth for live peer links;
        this scans for any pubkey we don't yet have a ``sent[]``
        entry for, primes it, and kicks off a sig_req so the peer
        starts replying with sig_res messages (which feed into
        parent selection).
        """
        for entry in self.node_core.peers.peers():
            pk = entry.link.remote_pubkey
            if pk not in self.sent:
                self.sent[pk] = set()
                # Send a fresh sig_req so this peer becomes a
                # candidate parent.
                req = RouterSigReq(
                    seq=self.local_seq + 1,
                    nonce=int.from_bytes(os.urandom(8), "big"),
                )
                self.requests[pk] = req
                asyncio.ensure_future(self.send_packet_safe(
                    entry.link, WIRE_PROTO_SIG_REQ, req.encode(),
                ))

    def send_pending_announces(self):
        """For each peer, send announces for keys we haven't yet sent them."""
        for peer_key, sent in self.sent.items():
            entry = self.node_core.peers.get_peer(peer_key)
            if entry is None:
                continue
            for key, info in list(self.infos.items()):
                if key in sent:
                    continue
                sent.add(key)
                ann = info.get_announce(key)
                asyncio.ensure_future(self.send_packet_safe(
                    entry.link, WIRE_PROTO_ANNOUNCE, ann.encode(),
                ))

    async def send_packet_safe(self, link, packet_type, payload):
        """Send + swallow OSError so a single peer dying doesn't kill maintenance."""
        try:
            await link.send_packet(packet_type, payload)
        except Exception:
            log_exception()

    # -------- traffic forwarding -----------------------------------------

    def lookup_next_hop(self, dest_path):
        """Find the peer that's closest to ``dest_path`` in tree-space.

        Greedy: of our peers (including self), pick the one with
        minimum tree distance to dest_path.  Returns the peer's
        link, or None if we ARE the closest (deliver locally).
        """
        self_dist = self.get_dist(dest_path, self.public_key)
        best_link = None
        best_dist = self_dist
        for peer_key in self.infos:
            entry = self.node_core.peers.get_peer(peer_key)
            if entry is None:
                continue
            dist = self.get_dist(dest_path, peer_key)
            if dist < best_dist:
                best_dist = dist
                best_link = entry.link
        return best_link

    def get_dist(self, dest_path, key):
        """Tree distance between key's path and ``dest_path``."""
        _, key_path = self.get_root_and_path(key)
        if key_path is None:
            return float("inf")
        end = min(len(dest_path), len(key_path))
        dist = len(key_path) + len(dest_path)
        for i in range(end):
            if dest_path[i] == key_path[i]:
                dist -= 2
            else:
                break
        return dist

    async def forward_traffic(self, link, tr):
        """Either deliver locally (if dest is us) or forward to next hop."""
        if bytes(tr.dest) == bytes(self.public_key):
            await self.inbox.put((tr.source, tr.payload))
            return
        next_link = self.lookup_next_hop(tr.path)
        if next_link is None:
            # We're the best hop but not the dest -- packet is
            # mis-routed.  Drop (or send path_broken).  Upstream
            # would emit a path_broken; we do nothing here.
            return
        if next_link is link:
            # Don't bounce back to sender.
            return
        await self.send_packet_safe(next_link, WIRE_TRAFFIC, tr.encode())

    # -------- top-level packet dispatch ----------------------------------

    async def on_packet(self, link, packet_type, payload):
        """NodeCore packet_handler entry point."""
        self.counters[packet_type] = self.counters.get(packet_type, 0) + 1
        if packet_type in (WIRE_DUMMY, WIRE_KEEP_ALIVE):
            return
        decoder = DECODER_FOR_TYPE.get(packet_type)
        if decoder is None:
            return
        try:
            msg = decoder.decode(payload)
        except (DecodeError, ValueError):
            log_exception()
            return
        if packet_type == WIRE_PROTO_SIG_REQ:
            res = self.handle_sig_req(link, msg)
            await self.send_packet_safe(link, WIRE_PROTO_SIG_RES, res.encode())
        elif packet_type == WIRE_PROTO_SIG_RES:
            self.handle_sig_res(link, msg)
        elif packet_type == WIRE_PROTO_ANNOUNCE:
            self.handle_announce(link, msg)
        elif packet_type == WIRE_PROTO_BLOOM_FILTER:
            self.peer_bloom[link.remote_pubkey] = msg
        elif packet_type == WIRE_TRAFFIC:
            await self.forward_traffic(link, msg)
        # path_lookup / path_notify / path_broken: stored but no-op
        # in Phase 5b -- handled by Phase 5c pathfinder.

    # -------- outbound traffic helper ------------------------------------

    async def send_to(self, dest_pubkey, payload):
        """Send application-level payload to ``dest_pubkey`` via the tree.

        Looks up the path from root → dest, builds a Traffic
        packet, hands to the next-hop peer (or delivers
        locally if dest is us).
        """
        if bytes(dest_pubkey) == bytes(self.public_key):
            # Loopback.
            await self.inbox.put((self.public_key, bytes(payload)))
            return
        _, path = self.get_root_and_path(dest_pubkey)
        if path is None:
            # Don't know how to reach dest yet.
            raise OSError("router.send_to: no route to dest")
        tr = Traffic(
            path=path, from_path=[],
            source=self.public_key, dest=bytes(dest_pubkey),
            watermark=0, payload=bytes(payload),
        )
        next_link = self.lookup_next_hop(path)
        if next_link is None:
            raise OSError("router.send_to: no next hop")
        await next_link.send_packet(WIRE_TRAFFIC, tr.encode())

    # -------- diagnostic helper ------------------------------------------

    def summary(self):
        return {
            "counters": dict(self.counters),
            "infos": len(self.infos),
            "responses": len(self.responses),
            "peer_blooms": len(self.peer_bloom),
        }
