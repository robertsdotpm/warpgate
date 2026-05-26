"""Iterative Kademlia FIND_NODE lookup with alpha-concurrency.

Algorithm (Kademlia paper §2.3, adjusted for libp2p Kad-DHT
section 1.2):

  1. Seed the candidate set with K closest known peers from the
     local routing table.
  2. Track a "closest_so_far" sorted set of <= K candidates.
  3. Repeatedly: pick the alpha closest candidates not yet queried,
     issue FIND_NODE(target) on each in parallel.  Wait for any
     response.
  4. For each response: add the returned peers to candidate set
     (deduplicated, sorted by XOR distance to target).  Mark the
     responder as queried-and-OK.
  5. Stop when either (a) all K closest_so_far have been queried,
     or (b) max iterations exceeded, or (c) no progress for one
     full round.

This module is transport-agnostic -- it calls into a
``KadTransport`` adapter that the caller supplies, with one async
method:

    transport.find_node(peer, target_key) -> [PeerInfo, ...]

The transport is responsible for opening a stream, encoding
FIND_NODE, parsing the response.  libp2p Kad-DHT supplies a
``Libp2pKadTransport`` in libp2p_native/kad.py; alternate
implementations can hook this same algorithm onto any other wire
format.
"""
import asyncio

from .distance import xor_distance


DEFAULT_ALPHA = 3   # concurrent in-flight FIND_NODE queries
DEFAULT_K = 20      # closest peers retained


class KadTransport(object):
    """Protocol-stub for what ``iterative_find_node`` calls.

    Implementations override ``find_node``.  The kademlia algorithm
    doesn't know anything else about the transport.
    """

    async def find_node(self, peer_info, target_key):
        """Ask ``peer_info`` for the K closest peers it knows to ``target_key``.

        Returns a list of ``PeerInfo`` objects.  Raises any
        exception to indicate the query failed (caller marks the
        peer as down and moves on).
        """
        raise NotImplementedError


async def iterative_find_node(routing_table, target_key, transport,
                              alpha=DEFAULT_ALPHA, k=DEFAULT_K,
                              query_timeout=10.0, max_rounds=10):
    """Perform an iterative FIND_NODE walk and return the K closest peers.

    ``routing_table`` -- our local RoutingTable; seeded into the
    candidate set + updated with newly-learned peers.
    ``target_key`` -- the key we're searching for (e.g. a peer ID
    SHA-256 image, in libp2p Kad).
    ``transport`` -- the KadTransport adapter.
    ``alpha`` -- concurrent in-flight queries (Kademlia paper recs 3).
    ``k`` -- desired result set size.

    Returns a list of up to k PeerInfo, sorted by XOR distance to
    target.  The list may include peers we couldn't successfully
    query (their FIND_NODE call failed) -- the caller distinguishes
    by whether ``queried_ok`` is set on each.
    """
    # Seed candidates with K closest known.
    candidates = list(routing_table.find_closest(target_key, k))
    queried = set()    # peer_id bytes -> we've sent FIND_NODE to it
    failed = set()     # peer_id bytes -> FIND_NODE failed
    rounds_without_progress = 0

    def closest_distance():
        if not candidates:
            return None
        return xor_distance(routing_table.key_fn(candidates[0].peer_id), target_key)

    for round_idx in range(max_rounds):
        # Pick the alpha closest candidates we haven't queried yet.
        next_batch = []
        for p in candidates:
            if p.peer_id in queried or p.peer_id in failed:
                continue
            next_batch.append(p)
            if len(next_batch) >= alpha:
                break
        if not next_batch:
            return candidates[:k]

        before_distance = closest_distance()

        for p in next_batch:
            queried.add(p.peer_id)

        tasks = [
            asyncio.ensure_future(
                run_query(transport, p, target_key, query_timeout)
            )
            for p in next_batch
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        any_new_closer = False
        for peer, result in zip(next_batch, results):
            if isinstance(result, Exception):
                failed.add(peer.peer_id)
                continue
            for fresh in result:
                if fresh.peer_id == routing_table.local_peer_id:
                    continue
                if any(c.peer_id == fresh.peer_id for c in candidates):
                    continue
                candidates.append(fresh)
                # Opportunistically populate the routing table too --
                # cheap and improves future lookups.
                routing_table.add_peer(fresh)
        # Re-sort by distance (in kad-key space) + cap to K.
        candidates.sort(
            key=lambda c: xor_distance(routing_table.key_fn(c.peer_id), target_key)
        )
        if len(candidates) > k:
            candidates = candidates[:k]

        after_distance = closest_distance()
        if after_distance is not None and (
            before_distance is None or after_distance < before_distance
        ):
            any_new_closer = True
        if not any_new_closer:
            rounds_without_progress += 1
        else:
            rounds_without_progress = 0
        if rounds_without_progress >= 2:
            # No closer peer found in two consecutive rounds -- the
            # closest-K is stable, exit.
            break

    return candidates[:k]


async def run_query(transport, peer_info, target_key, timeout):
    """Wrap one FIND_NODE call with a per-query timeout.

    Returns the list of fresh PeerInfo on success; raises on any
    error (caller treats it as a failed peer).
    """
    return await asyncio.wait_for(
        transport.find_node(peer_info, target_key), timeout=timeout,
    )
