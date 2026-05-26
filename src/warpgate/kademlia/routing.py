"""Kademlia routing table: bucket-of-K-per-CPL ordered by last-seen.

Each bucket holds up to K peer records, ordered most-recently-seen
first.  When a new peer is added:

  - Already in bucket? Move to head.
  - Bucket has room? Insert at head.
  - Bucket full? Optionally ping the LRU; if it doesn't respond,
    evict it and insert the new entry.  This module reports the
    eviction candidate via the ``pending`` return value; the
    transport layer decides whether to ping.

K and KEY_BITS are configurable per-instance.  libp2p Kad-DHT uses
K=20 + 256-bit keys (SHA-256 namespace).  BitTorrent DHT uses K=8
+ 160-bit keys.  This module supports both.
"""
from .distance import common_prefix_length, xor_distance


class PeerInfo(object):
    """Triple of (peer_id_bytes, addrs, last_seen_unix_seconds).

    ``addrs`` is a list of opaque address blobs -- the transport
    layer's notion of how to reach the peer.  For libp2p that's
    multiaddr bytes; for a future warpgate-native DHT it could be
    a list of (ip, port) tuples.  The kademlia core treats them as
    opaque.
    """

    __slots__ = ("peer_id", "addrs", "last_seen")

    def __init__(self, peer_id, addrs=(), last_seen=0):
        self.peer_id = bytes(peer_id)
        self.addrs = list(addrs)
        self.last_seen = last_seen

    def __repr__(self):
        return "PeerInfo({0}..., {1} addrs, last_seen={2})".format(
            self.peer_id.hex()[:16], len(self.addrs), self.last_seen,
        )


class KBucket(object):
    """One Kademlia bucket -- up to K peers, ordered most-recently-seen first."""

    def __init__(self, capacity):
        self.capacity = capacity
        # entries[0] is most recently seen, entries[-1] is LRU.
        self.entries = []

    def __len__(self):
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    def find(self, peer_id):
        """Return the matching PeerInfo or None."""
        for p in self.entries:
            if p.peer_id == peer_id:
                return p
        return None

    def add(self, peer):
        """Insert/refresh ``peer`` in the bucket.

        Returns one of:
            ("added", None)     -- new entry, room available
            ("refreshed", None) -- already known, moved to head
            ("full", evict_candidate)  -- bucket full; LRU is the
                                          candidate to ping/evict
        """
        existing = self.find(peer.peer_id)
        if existing is not None:
            self.entries.remove(existing)
            # Merge addrs (union) and bump last_seen.
            merged_addrs = list(existing.addrs)
            for a in peer.addrs:
                if a not in merged_addrs:
                    merged_addrs.append(a)
            existing.addrs = merged_addrs
            existing.last_seen = max(existing.last_seen, peer.last_seen)
            self.entries.insert(0, existing)
            return ("refreshed", None)
        if len(self.entries) < self.capacity:
            self.entries.insert(0, peer)
            return ("added", None)
        return ("full", self.entries[-1])

    def evict(self, peer_id):
        existing = self.find(peer_id)
        if existing is not None:
            self.entries.remove(existing)
            return True
        return False


def identity_key(peer_id):
    """Default ``key_fn``: the peer_id IS the kad-keyspace key."""
    return peer_id


class RoutingTable(object):
    """Kademlia routing table indexed by common-prefix-length with our local key.

    The library separates a peer's **transport identifier**
    (``peer_id`` -- what the transport uses to dial them) from its
    **kad-keyspace key** (the bit-string used for XOR distance).
    For libp2p Kad-DHT they DIFFER: peer_id is the libp2p multihash,
    kad-key is SHA-256(peer_id).  For raw Kademlia (e.g. mainline
    BitTorrent DHT) they coincide.

    Configure via ``key_fn(peer_id) -> bytes``; defaults to
    identity (peer_id == kad-key).  Distance + bucket placement
    use the derived kad-keys; ``find_closest`` takes a kad-key
    (not a peer_id) since lookup targets may be arbitrary
    keyspace keys, not peers.
    """

    DEFAULT_K = 20
    DEFAULT_KEY_BITS = 256

    def __init__(self, local_peer_id, k=DEFAULT_K, key_bits=DEFAULT_KEY_BITS,
                 key_fn=identity_key):
        local_key = key_fn(local_peer_id)
        if len(local_key) * 8 != key_bits:
            raise ValueError(
                "RoutingTable: local key length {0} bits != configured key_bits {1}".format(
                    len(local_key) * 8, key_bits,
                )
            )
        self.local_peer_id = bytes(local_peer_id)
        self.local_key = bytes(local_key)
        self.k = k
        self.key_bits = key_bits
        self.key_fn = key_fn
        # buckets[i] holds peers with CPL(key, local_key) == i.  Lazy.
        self.buckets = {}

    def bucket_for(self, peer_id):
        cpl = common_prefix_length(self.local_key, self.key_fn(peer_id))
        if cpl >= self.key_bits:
            return None
        bucket = self.buckets.get(cpl)
        if bucket is None:
            bucket = KBucket(self.k)
            self.buckets[cpl] = bucket
        return bucket

    def add_peer(self, peer):
        if peer.peer_id == self.local_peer_id:
            return ("skipped", None)
        bucket = self.bucket_for(peer.peer_id)
        if bucket is None:
            return ("skipped", None)
        return bucket.add(peer)

    def evict(self, peer_id):
        bucket = self.bucket_for(peer_id)
        if bucket is None:
            return False
        return bucket.evict(peer_id)

    def find_closest(self, target_key, n):
        """Return up to ``n`` PeerInfo ordered by XOR distance to ``target_key``.

        ``target_key`` is a kad-keyspace key (already in the
        post-key_fn form -- e.g. for libp2p Kad-DHT the caller
        passes ``SHA-256(target_peer_id)``).
        """
        if len(target_key) * 8 != self.key_bits:
            raise ValueError("find_closest: target_key wrong key bits")
        all_peers = []
        for bucket in self.buckets.values():
            all_peers.extend(bucket.entries)
        all_peers.sort(key=lambda p: xor_distance(self.key_fn(p.peer_id), target_key))
        return all_peers[:n]

    def total_peers(self):
        return sum(len(b) for b in self.buckets.values())

    def __repr__(self):
        return "RoutingTable(local={0}..., k={1}, peers={2}, buckets={3})".format(
            self.local_key.hex()[:16], self.k, self.total_peers(),
            sorted(self.buckets.keys()),
        )
