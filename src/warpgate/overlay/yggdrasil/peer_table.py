"""Peer table -- tracks active Yggdrasil peer links by remote pubkey.

Port of the relevant bits of ironwood's ``network/peers.go`` peer
membership logic + yggdrasil-go's ``core/link.go`` link-state map.

Responsibilities split:

  * ``PeerTable`` -- pure data structure, keyed by remote pubkey.
    Tracks per-peer ``peer_port`` allocations (ironwood-style: a
    small uint64 unique per peer at this node, NOT a TCP port --
    routing uses these as source-route hops in Phase 5).  No
    asyncio state here; called from NodeCore.

  * Listener / dialer code lives in ``node_core.py``; this module
    is intentionally small so it can be unit-tested without
    real sockets.

Port allocation matches upstream: walk integers from 1 upward,
skipping any already in use.  ``0`` is reserved as the source-route
terminator (see ``wire.encode_path``), so peer_port starts at 1.
"""
import asyncio

from aionetiface import fstr


class DuplicatePeerError(Exception):
    """Raised when add_peer() is called twice for the same pubkey."""


class PeerEntry(object):
    """Per-peer state held by the PeerTable.

    ``link`` is the live PeerLink object; ``port`` is the ironwood
    peer_port (uint64 source-route hop ID).  ``added_at`` is a
    monotonic timestamp used for stable ordering when reporting
    via the admin API (Phase 7).
    """

    def __init__(self, link, port, added_at):
        self.link = link
        self.port = port
        self.added_at = added_at


class PeerTable(object):
    """Maps remote pubkey -> PeerEntry, allocates peer_ports.

    Allocation is monotonic-best-effort: when a peer disconnects
    its port frees up and the next new peer can reuse it.  Mirrors
    the upstream ``ports`` set bookkeeping.
    """

    def __init__(self):
        self.by_pubkey = {}  # pubkey bytes -> PeerEntry
        self.used_ports = set()
        self.next_clock = 0

    def add_peer(self, link):
        """Insert a new peer link; allocate a peer_port; return PeerEntry.

        ``link`` is a fully-open PeerLink (handshake complete).
        Raises ``DuplicatePeerError`` if a peer with the same
        pubkey is already in the table -- upstream allows multiple
        links per pubkey (load balancing), but we'll defer that
        until the routing layer actually needs it.  The earlier
        link should be closed before re-adding.
        """
        pubkey = bytes(link.remote_pubkey)
        if pubkey in self.by_pubkey:
            raise DuplicatePeerError(fstr(
                "add_peer: pubkey {0} already has a live link",
                (pubkey.hex(),),
            ))
        # Walk integers from 1 upward to find the first unused port.
        # Tiny brute-force search; the peer count stays small for
        # warpgate's use case (single-digit peers per node).
        port = 1
        while port in self.used_ports:
            port += 1
        self.used_ports.add(port)
        self.next_clock += 1
        entry = PeerEntry(link=link, port=port, added_at=self.next_clock)
        self.by_pubkey[pubkey] = entry
        return entry

    def remove_peer(self, pubkey):
        """Remove a peer by pubkey; return True if removed, False if absent."""
        entry = self.by_pubkey.pop(bytes(pubkey), None)
        if entry is None:
            return False
        self.used_ports.discard(entry.port)
        return True

    def get_peer(self, pubkey):
        """Return the PeerEntry for ``pubkey``, or None."""
        return self.by_pubkey.get(bytes(pubkey))

    def peers(self):
        """Iterate live PeerEntries.  Order is insertion (added_at)."""
        return sorted(self.by_pubkey.values(), key=lambda e: e.added_at)

    def __len__(self):
        return len(self.by_pubkey)


class BackoffCounter(object):
    """Exponential backoff schedule for outbound dial retries.

    Upstream uses ``time.Second << attempt`` clamped to
    ``defaultBackoffLimit = time.Second << 12`` (~68 minutes) with
    a ``minimumBackoffLimit = 5 seconds`` floor on the maximum
    backoff a single user-configured peer can request.
    """

    INITIAL_SECONDS = 1.0
    MAX_SECONDS = 1.0 * (1 << 12)  # 4096s ~= 68min, upstream defaultBackoffLimit

    def __init__(self, max_seconds=None):
        self.attempt = 0
        self.max_seconds = max_seconds if max_seconds is not None else self.MAX_SECONDS

    def next_delay(self):
        """Return seconds to wait before the next dial attempt, then advance."""
        delay = self.INITIAL_SECONDS * (2 ** self.attempt)
        if delay > self.max_seconds:
            delay = self.max_seconds
        self.attempt += 1
        return delay

    def reset(self):
        """Call after a successful dial so the next failure starts at INITIAL_SECONDS."""
        self.attempt = 0
