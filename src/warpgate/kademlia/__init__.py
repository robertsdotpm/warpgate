"""Generic Kademlia algorithm -- transport-agnostic.

This package contains the Kademlia algorithm in its pure form: XOR-
distance metric, k-bucket routing table, iterative FIND_NODE
lookup with alpha-concurrency, and provider-record storage
machinery.  Nothing in here knows about TCP, UDP, libp2p,
bittorrent, or any wire format -- the transport is plugged in by
the caller via a small adapter interface.

The libp2p Kad-DHT wire protocol implementation lives in the
libp2p_native plugin at
``warpgate/traversal/plugins/libp2p_native/kad.py``; it adapts
this generic core onto the ``/ipfs/kad/1.0.0`` stream protocol.
A future warpgate-native DHT (peer-served PNP / signalling /
STUN per the project_decentralization_direction roadmap) can
reuse the same core with a different transport adapter.

Public surface:

  - ``warpgate.kademlia.distance.xor_distance(a, b)``
  - ``warpgate.kademlia.distance.common_prefix_length(a, b)``
  - ``warpgate.kademlia.routing.RoutingTable``
  - ``warpgate.kademlia.routing.KBucket``
  - ``warpgate.kademlia.lookup.iterative_find_node(...)``
"""

from .distance import xor_distance, common_prefix_length
from .routing import RoutingTable, KBucket, PeerInfo
from .lookup import iterative_find_node, KadTransport
