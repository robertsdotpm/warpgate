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
        # Per-peer bloom filters: we maintain a "send" filter
        # (the latest we sent that peer) and a "recv" filter
        # (the latest we received from that peer).  recv is what
        # we test against when deciding whether to multicast a
        # path_lookup through them.
        self.peer_send_bloom = {}
        self.peer_recv_bloom = {}
        # Per-peer measured RTT from sig_req → sig_res.  Used in
        # _fix / lookup_next_hop as the cost weight.  Stored as
        # seconds (float).  Missing entry = unknown latency.
        self.peer_lags = {}
        # Per-peer sig_req send timestamp for RTT measurement.
        self.peer_req_sent_at = {}
        # Local sequence number -- monotonic per (re)become-root.
        self.local_seq = 0
        # Per-info insertion timestamps for lazy TTL expiry.  Keys
        # not in info_timestamps are treated as "fresh forever"
        # (e.g. self_info which we always want around).  Upstream
        # uses per-key time.AfterFunc Timer objects; we use a
        # cheaper batch-sweep on the maintenance tick to avoid
        # the scheduler churn at the cost of <1s expiry precision.
        self.info_timestamps = {}
        # Refresh flag -- set on self-info update from a peer
        # (mirrors upstream router._handleAnnounce: when a peer
        # echoes back our own info, that means our seq reset and
        # we need a fresh announce out).
        self.refresh = False
        # Maintenance timer state.
        self.maintenance_task = None
        self.do_root2 = True   # first maintenance cycle: become root
        self.running = False
        # Traffic delivered to us (dest == our pubkey) -- delivered
        # to the application layer in Phase 6+.  For now just
        # collect them in a queue the test can pull from.
        self.inbox = asyncio.Queue()
        # Pathfinder for source-route discovery + caching.  Created
        # here so handle_path_* methods can dispatch into it.
        # Lazy import: pathfinder.py imports back from us.
        from .pathfinder import Pathfinder
        self.pathfinder = Pathfinder(self)
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

        Verify the signature; if valid, cache + measure RTT and
        let the next ``_fix`` cycle decide whether to adopt them
        as parent.
        """
        req = self.requests.get(link.remote_pubkey)
        if req is None:
            return
        # Upstream router._handleResponse (router.go:425) gates the
        # accept on ``r.requests[p.key] == res.routerSigReq`` -- i.e.
        # the seq+nonce of the response must match the seq+nonce of
        # our currently-outstanding request.  Without this gate, a
        # stale response from a previous (already-overwritten)
        # request can race ahead of the current one and corrupt our
        # state.  Even though the signature check below covers
        # forgery, it does NOT detect "old but still-valid" responses.
        if req.seq != res.seq or req.nonce != res.nonce:
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
        # RTT measurement: exponentially-weighted average of the
        # round-trip between when we sent the sig_req and when
        # the matching sig_res arrived.  Used as link cost.
        sent_at = self.peer_req_sent_at.pop(link.remote_pubkey, None)
        if sent_at is not None:
            import time as _time
            rtt = max(0.001, _time.monotonic() - sent_at)
            prev = self.peer_lags.get(link.remote_pubkey)
            if prev is None:
                # First measurement -- penalize fresh links slightly
                # to discourage churning to brand-new peers.
                self.peer_lags[link.remote_pubkey] = rtt * 2
            else:
                # 7/8 old + 1/8 new (capped so a single spike can't
                # double the value).  Matches upstream's EWMA.
                capped = min(rtt, prev * 2)
                self.peer_lags[link.remote_pubkey] = prev * 7 / 8 + capped / 8

    def handle_announce(self, link, ann):
        """Apply upstream's announce-comparison rules and propagate.

        Two upstream behaviours we now match (router.go:544-573):
        - If a peer ECHOES BACK our own info, that means our seq
          probably reset (e.g. process restart) and we should set
          ``refresh = True`` so the next maintenance tick re-mints
          our own announce with a bumped seq.
        - If we REJECT an inbound announce (theirs is worse than
          what we have), send THEM what we have so they update.
          Otherwise we'd spam each other with stale data until
          one side capitulates.
        """
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
            # Self-info echo recovery: peer just told us about our
            # own key, our seq probably reset, flag for refresh.
            if bytes(ann.key) == bytes(self.public_key):
                self.refresh = True
        else:
            # Rejected as worse-than-known.  Tell the peer what
            # we have so they update.
            existing = self.infos.get(bytes(ann.key))
            if existing is not None:
                self.sent.setdefault(link.remote_pubkey, set()).add(ann.key)
                better = existing.get_announce(ann.key)
                asyncio.ensure_future(self.send_packet_safe(
                    link, WIRE_PROTO_ANNOUNCE, better.encode(),
                ))

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
        # Stamp the insertion time for the TTL sweep.  Self-info
        # is exempt -- we always want our own entry around.
        if bytes(ann.key) != bytes(self.public_key):
            import time as _time
            self.info_timestamps[bytes(ann.key)] = _time.monotonic()
        return True

    def sweep_expired_infos(self):
        """Drop infos older than ROUTER_TIMEOUT_SECONDS.

        Upstream uses per-key time.AfterFunc timers (router.go:521);
        we sweep on the 1 s maintenance tick instead.  Same end
        result -- stale peer infos eventually disappear from the
        table -- with a fraction of the scheduler load.  Self-info
        is never expired.

        Also handles the refresh-on-self-update flag: every
        ROUTER_REFRESH_SECONDS, our own info is re-signed (matches
        upstream's _doMaintenance refresh schedule).
        """
        import time as _time
        now = _time.monotonic()
        # TTL sweep: remove any info older than ROUTER_TIMEOUT_SECONDS.
        expired = []
        for key, ts in self.info_timestamps.items():
            if now - ts > ROUTER_TIMEOUT_SECONDS:
                expired.append(key)
        for key in expired:
            self.infos.pop(key, None)
            self.info_timestamps.pop(key, None)
            # Drop sent-dedup entries too so we don't keep advertising
            # a key we've forgotten.
            for sent in self.sent.values():
                sent.discard(key)
        # Refresh self-info on the upstream cadence so we don't
        # appear stale to long-running peers' TTL sweeps.
        self_age_attr = "_self_info_signed_at"
        signed_at = getattr(self, self_age_attr, None)
        if signed_at is None:
            setattr(self, self_age_attr, now)
        elif now - signed_at > ROUTER_REFRESH_SECONDS:
            self.refresh = True
            setattr(self, self_age_attr, now)

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

        Also sync local_seq forward to ``res.seq`` -- upstream's
        ``_newReq`` (router.go:386) computes the next req from
        ``r.infos[selfKey].seq + 1``; if our local_seq lags behind
        the seq we just adopted, the next sig_req we send carries a
        stale seq, peers respond with a stale seq, and update_info
        rejects everything because existing.seq > ann.seq.
        """
        bs = res.bytes_for_sig(self.public_key, peer_key)
        self_sig = sign(self.seed, bs)
        # Wrap with our self-key.
        info = RouterInfo(parent=peer_key, sig_res=res, sig=self_sig)
        ann = RouterAnnounce(
            key=self.public_key, parent=peer_key,
            sig_res=res, sig=self_sig,
        )
        if self.update_info(ann):
            if res.seq > self.local_seq:
                self.local_seq = res.seq

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
        """Periodic tick: sweep stale infos, fix parent, send announces,
        resend blooms if they changed.

        Sweep order matters: expire BEFORE fix so a freshly-stale
        peer doesn't get picked as parent.  Sweep BEFORE sync_peers
        so a peer that timed out but reconnects gets a fresh sig_req.
        Refresh self-info from a peer's echo BEFORE sync, in case
        the new sig_req would otherwise carry a stale local_seq.
        """
        self.sweep_expired_infos()
        if self.refresh:
            self.become_root()
            self.refresh = False
        self.sync_peers()
        self.fix()
        self.send_pending_announces()
        self.resend_changed_blooms()

    def resend_changed_blooms(self):
        """F9 fix: re-send our outbound bloom to each peer if it changed.

        Without periodic resend, the bloom we sent at peer-attach
        time is stuck even as our ``peer_recv_bloom`` map updates
        (other peers learning about new keys).  With F8's merge
        semantics, that means transitive reachability info never
        propagates -- multi-hop chains can't discover paths to
        nodes that appear AFTER initial bootstrap.

        Mirrors upstream bloomfilter.go:269-290 ``_sendAllBlooms``,
        minus the "force-resend every 3600 ticks" anti-quiet-link
        clause (deferred -- not yet seen to matter).
        """
        for entry in self.node_core.peers.peers():
            pk = entry.link.remote_pubkey
            if pk not in self.sent:
                # Hasn't gone through sync_peers yet -- skip.
                continue
            new_bloom = self.build_bloom_for_peer(pk)
            old_bloom = self.peer_send_bloom.get(pk)
            if old_bloom is not None and old_bloom.equal(new_bloom):
                continue   # nothing changed; no resend needed
            self.peer_send_bloom[pk] = new_bloom
            asyncio.ensure_future(self.send_packet_safe(
                entry.link, WIRE_PROTO_BLOOM_FILTER, new_bloom.encode(),
            ))

    def sync_peers(self):
        """Initialize routing state for any newly-connected peers.

        NodeCore.peers is the source of truth for live peer links;
        this scans for any pubkey we don't yet have a ``sent[]``
        entry for, primes it, sends a sig_req (which feeds into
        parent selection AND RTT measurement) and sends our
        current bloom filter (which the peer uses for path-lookup
        multicast forwarding).
        """
        import time as _time
        for entry in self.node_core.peers.peers():
            pk = entry.link.remote_pubkey
            if pk not in self.sent:
                self.sent[pk] = set()
                # Send a fresh sig_req so this peer becomes a
                # candidate parent.  Record the send time so the
                # matching sig_res can compute RTT.
                req = RouterSigReq(
                    seq=self.local_seq + 1,
                    nonce=int.from_bytes(os.urandom(8), "big"),
                )
                self.requests[pk] = req
                self.peer_req_sent_at[pk] = _time.monotonic()
                asyncio.ensure_future(self.send_packet_safe(
                    entry.link, WIRE_PROTO_SIG_REQ, req.encode(),
                ))
                # Send our current bloom (all our known keys
                # transformed via bloom_transform) so the peer
                # can forward path_lookups to us appropriately.
                self.peer_send_bloom[pk] = self.build_bloom_for_peer(pk)
                asyncio.ensure_future(self.send_packet_safe(
                    entry.link, WIRE_PROTO_BLOOM_FILTER,
                    self.peer_send_bloom[pk].encode(),
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

    def get_cost(self, peer_key):
        """Latency-weighted cost for a peer link (uniform 1 if unknown)."""
        lag = self.peer_lags.get(peer_key)
        if lag is None or lag <= 0:
            return 1
        # Cost in ms-ish units -- multiplied by tree distance in
        # lookup_next_hop to compute the joint cost*dist score.
        return max(1, int(lag * 1000))

    def lookup_next_hop(self, dest_path):
        """Find the peer that's closest to ``dest_path`` in tree-space.

        Greedy: of our peers (including self), pick the one with
        minimum (cost * tree-distance) to dest_path.  Returns the
        peer's link, or None if we ARE the closest (deliver
        locally).  Mirrors upstream router._lookup's two-stage
        selection: first filter peers strictly closer than us by
        distance alone, then pick among those by cost*dist.
        """
        self_dist = self.get_dist(dest_path, self.public_key)
        # Stage 1: distance filter -- candidate must be strictly
        # closer than us by tree distance to guarantee loop-free
        # progress.
        candidates = []
        for peer_key in self.infos:
            entry = self.node_core.peers.get_peer(peer_key)
            if entry is None:
                continue
            dist = self.get_dist(dest_path, peer_key)
            if dist < self_dist:
                candidates.append((peer_key, entry, dist))
        if not candidates:
            return None
        # Stage 2: pick min (cost * dist), ties broken by smaller dist
        # then smaller cost.
        best = None
        best_score = None
        for peer_key, entry, dist in candidates:
            cost = self.get_cost(peer_key)
            score = (cost * dist, dist, cost)
            if best_score is None or score < best_score:
                best_score = score
                best = entry.link
        return best

    def lookup_next_hop_with_watermark(self, dest_path, watermark_ref):
        """Watermark variant: only forward if we're STRICTLY closer than ``watermark``.

        ``watermark_ref`` is a single-element list (Python pass-by-
        reference trick) so the caller can read the updated
        watermark back.  Mirrors upstream's pointer semantics.
        """
        self_dist = self.get_dist(dest_path, self.public_key)
        if self_dist >= watermark_ref[0]:
            # We're not closer than the previous hop -- drop.
            return None
        watermark_ref[0] = self_dist
        return self.lookup_next_hop(dest_path)

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
        """Either deliver locally (if dest is us) or forward to next hop.

        Uses watermark-routing (loop-avoidance) per upstream
        router.handleTraffic.  Watermark MUST monotonically
        decrease along the forwarding chain -- if we're not
        STRICTLY closer to the dest than the prior hop was,
        drop the packet (path_broken back to source).
        """
        if bytes(tr.dest) == bytes(self.public_key):
            await self.inbox.put((bytes(tr.source), bytes(tr.payload)))
            return
        watermark_ref = [tr.watermark]
        next_link = self.lookup_next_hop_with_watermark(
            tr.path, watermark_ref,
        )
        if next_link is None:
            # Either watermark says we're not closer than the prior
            # hop (loop guard fired) OR no peer can move closer.
            # Tell the source so it can re-discover.
            await self.pathfinder.emit_path_broken(tr)
            return
        if next_link is link:
            return
        tr.watermark = watermark_ref[0]
        await self.send_packet_safe(next_link, WIRE_TRAFFIC, tr.encode())

    async def forward_outbound_traffic(self, tr):
        """Pathfinder calls this after it's filled in tr.path / tr.from_path."""
        if bytes(tr.dest) == bytes(self.public_key):
            await self.inbox.put((bytes(tr.source), bytes(tr.payload)))
            return
        next_link = self.lookup_next_hop(tr.path)
        if next_link is None:
            # No next hop -- buffer-and-retry would belong here, but
            # the pathfinder already buffers in its rumor map, so
            # silently drop and let the next path_notify drive a retry.
            return
        await self.send_packet_safe(next_link, WIRE_TRAFFIC, tr.encode())

    # -------- bloom filter helpers ---------------------------------------

    def is_peer_on_tree(self, peer_key):
        """Return True iff ``peer_key`` is a direct link OR shares a tree edge.

        Upstream gates path_lookup forwarding on this to prevent
        amplification (any client could trigger fan-out otherwise).
        Definition: peer is our parent, our direct child, OR a
        currently-live direct peer (link present in NodeCore.peers).

        Adding the direct-peer fallback is slightly more permissive
        than upstream's strict ``_fixOnTree`` -- it eliminates the
        race window where a freshly-connected peer's sig_res hasn't
        landed yet but they're already exchanging traffic with us.
        Cost: a peer with which we share a link but no tree edge
        could trigger lookup forwarding.  Bound: limited by the
        physical peering set, not the open internet.
        """
        peer_bytes = bytes(peer_key)
        self_info = self.infos.get(bytes(self.public_key))
        if self_info is not None and self_info.parent == peer_bytes:
            return True
        peer_info = self.infos.get(peer_bytes)
        if peer_info is not None and peer_info.parent == bytes(self.public_key):
            return True
        # Permissive fallback: any node we have an active link to
        # counts as on-tree.  Closes the post-connect race without
        # opening the gate to arbitrary off-internet senders.
        if self.node_core.peers.get_peer(peer_bytes) is not None:
            return True
        return False

    def build_bloom_for_peer(self, peer_key):
        """Build the outbound bloom filter we should send to ``peer_key``.

        Two contributions, per upstream bloomfilter.go:223-234
        ``_getBloomFor``:

        1. ``bloom_transform(self.public_key)`` -- our own key,
           so peers know they can reach us through this link.
        2. The bitwise UNION of every other peer's RECV bloom
           filter -- so the merged filter advertises everyone
           reachable transitively through us.  Without the
           merge, a path_lookup to a node 2+ hops away never
           gets multicast-forwarded because no direct peer's
           bloom matches it.  This was a silent-drop on
           multi-hop networks.

        Filters out ``peer_key`` itself -- no point telling them
        about themselves.
        """
        from .pathfinder import bloom_transform
        b = Bloom()
        b.add_key(bloom_transform(self.public_key))
        # Merge every other peer's RECV bloom -- this is the
        # transitive-reachability bit, recovers multi-hop
        # forwarding capability.
        for other_peer_key, other_bloom in self.peer_recv_bloom.items():
            if bytes(other_peer_key) == bytes(peer_key):
                continue
            b.merge(other_bloom)
        return b

    async def bloom_multicast(self, packet_type, payload, from_key, dest_key):
        """Forward ``payload`` to every peer whose recv-bloom matches ``dest_key``.

        Skips the sender (``from_key``) so multicasts don't
        bounce back to whoever forwarded the lookup to us.
        Bloom Test() may yield false positives (which only costs
        bandwidth), never false negatives (which would lose the
        packet).
        """
        from .pathfinder import bloom_transform
        target = bloom_transform(dest_key)
        for entry in self.node_core.peers.peers():
            peer_key = entry.link.remote_pubkey
            if peer_key == from_key:
                continue
            recv_bloom = self.peer_recv_bloom.get(peer_key)
            if recv_bloom is None:
                # We haven't received their bloom yet -- conservative
                # forward so we don't black-hole during ramp-up.
                pass
            elif not recv_bloom.test_key(target):
                # Definitely not interested.
                continue
            await self.send_packet_safe(entry.link, packet_type, payload)

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
            self.peer_recv_bloom[link.remote_pubkey] = msg
        elif packet_type == WIRE_PROTO_PATH_LOOKUP:
            await self.pathfinder.handle_lookup(link.remote_pubkey, msg)
        elif packet_type == WIRE_PROTO_PATH_NOTIFY:
            await self.pathfinder.handle_notify(link.remote_pubkey, msg)
        elif packet_type == WIRE_PROTO_PATH_BROKEN:
            await self.pathfinder.handle_broken(link.remote_pubkey, msg)
        elif packet_type == WIRE_TRAFFIC:
            await self.forward_traffic(link, msg)

    # -------- outbound traffic helper ------------------------------------

    async def send_to(self, dest_pubkey, payload):
        """Send application-level payload to ``dest_pubkey`` via the overlay.

        Delegates to the pathfinder which handles both cached-path
        fast path AND cold-start (issue path_lookup via bloom
        multicast + buffer the traffic until path_notify lands).
        Loopback short-circuit for self-addressed packets.

        Watermark MUST be initialized to MAX (^uint64(0) in upstream's
        terms): the first hop's watermark check is
        ``if self_dist >= watermark: drop``, so any non-max starting
        value causes the very first router to refuse to forward.
        This was the bug that broke every live A->B byte exchange
        until 2026-05-27 -- without it path_broken loops on the
        first hop instead of the traffic actually moving.
        """
        if bytes(dest_pubkey) == bytes(self.public_key):
            await self.inbox.put((self.public_key, bytes(payload)))
            return
        tr = Traffic(
            path=[],          # filled by pathfinder if cached
            from_path=[],     # filled by pathfinder
            source=self.public_key, dest=bytes(dest_pubkey),
            watermark=(1 << 64) - 1, payload=bytes(payload),
        )
        await self.pathfinder.handle_outbound_traffic(tr)

    # -------- diagnostic helper ------------------------------------------

    def summary(self):
        return {
            "counters": dict(self.counters),
            "infos": len(self.infos),
            "responses": len(self.responses),
            "peer_blooms": len(self.peer_bloom),
        }
