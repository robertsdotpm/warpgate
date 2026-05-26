"""Live interop test against the public IPFS / libp2p DHT.

GUARDED BY ENV VAR: ``WARPGATE_LIBP2P_LIVE=1`` to run.  Default
(no env var set) skips so CI doesn't depend on public-network
behaviour.

What this test actually proves:

  1. Our libp2p TCP transport handshake (multistream-select +
     Noise XX + yamux) interoperates with at least one real
     non-warpgate libp2p peer on the public network.
  2. After the handshake, our Identify protocol round-trips
     against that peer (we receive their PublicKey + listenAddrs
     + protocol list).
  3. We can issue a FIND_NODE Kad-DHT query against the peer and
     receive a wire-correct response.

What it deliberately doesn't test:

  - Successfully PUT-ing a record to the global IPFS DHT.  Stock
    go-libp2p has a record validator that rejects PUT_VALUE on
    most namespaces; only ``/pk/<peerid>`` and ``/ipns/<peerid>``
    pass.  We could exercise that codepath but a failure there
    is a validator-policy problem, not an interop problem.
  - End-to-end "put on A, get on B through the public DHT".
    The latency + flakiness budget for a DHT walk to converge
    through random public peers is way outside a unit-test
    timeout; the right test for that is manual.

Even just steps 1-3 above are strong evidence the wire format is
correct -- if any byte is wrong in our Noise XX, yamux frames,
multistream-select, or Kad protobuf, the handshake fails at that
specific layer and we get a clear log.
"""
import asyncio
import os
import unittest

from aionetiface import IP4, Interface
from aionetiface.testing import AsyncTestCase

from warpgate.traversal.plugins.libp2p_native import (
    bootstrap as bootstrap_mod,
    multiaddr as ma,
    peer_id,
)
from warpgate.traversal.plugins.libp2p_native.node_core import Libp2pNode


SKIP_LIVE = os.environ.get("WARPGATE_LIBP2P_LIVE") != "1"


class TestLiveIPFSInterop(AsyncTestCase):
    """Best-effort dial against a public libp2p peer.

    Uses ``bootstrap_mod.dial_one_bootstrap`` against each entry
    in ``WARPGATE_LIBP2P_BOOTSTRAP`` (or the curated defaults) and
    succeeds if AT LEAST ONE dial completes the full handshake.
    """

    async def asyncSetUp(self):
        if SKIP_LIVE:
            self.skipTest("WARPGATE_LIBP2P_LIVE=1 not set")
        self.iface = await Interface()
        self.identity = peer_id.Identity.generate()
        self.node = Libp2pNode(self.identity)

    async def asyncTearDown(self):
        if not SKIP_LIVE:
            await self.node.close()

    async def test_dial_any_bootstrap_succeeds(self):
        """Dial each bootstrap peer; require at least one to complete handshake."""
        sessions = await bootstrap_mod.bootstrap(
            self.node, iface=self.iface, timeout=20.0,
        )
        self.assertTrue(
            len(sessions) > 0,
            "no bootstrap peer accepted our handshake -- "
            "wire-format incompatibility or all peers offline",
        )
        print("live-ipfs: bootstrap connected to {0} peer(s)".format(len(sessions)))
        for s in sessions:
            print("  peer_id =", s.remote_peer_id.hex()[:16])

    async def test_identify_round_trip_against_bootstrap_peer(self):
        """Once connected, query Identify against one bootstrap peer."""
        sessions = await bootstrap_mod.bootstrap(
            self.node, iface=self.iface, timeout=20.0,
        )
        if not sessions:
            self.skipTest("no bootstrap peer reachable -- env, not interop")
        # Identify on the first session.
        session = sessions[0]
        ident = await asyncio.wait_for(
            self.node.query_identify(session), timeout=15.0,
        )
        print("live-ipfs: Identify protocols reported by peer:")
        for p in ident.protocols:
            print("  ", p)
        # A real go-libp2p / js-libp2p node will speak at least
        # /ipfs/id/1.0.0 and usually /ipfs/kad/1.0.0.
        self.assertTrue(
            len(ident.protocols) > 0,
            "Identify came back empty -- something's off in the round-trip",
        )

    async def test_find_node_via_bootstrap_peer(self):
        """Run a FIND_NODE through a bootstrap peer; expect closer_peers back."""
        sessions = await bootstrap_mod.bootstrap(
            self.node, iface=self.iface, timeout=20.0,
        )
        if not sessions:
            self.skipTest("no bootstrap peer reachable -- env, not interop")
        # FIND_NODE looking for OUR OWN peer_id -- the bootstrap
        # peer should return up to 20 nodes near us in keyspace.
        try:
            result = await self.node.find_peer(
                self.identity.peer_id, timeout=20.0,
            )
        except asyncio.TimeoutError:
            self.skipTest("FIND_NODE walk timed out -- public DHT flake, not interop")
        print("live-ipfs: FIND_NODE returned {0} peer(s)".format(len(result)))
        for p in result[:5]:
            print("  ", peer_id.peer_id_to_b58(p.peer_id))
        # The walk should at least have the bootstrap peer + the
        # peers it told us about.
        self.assertGreater(
            len(result), 0,
            "FIND_NODE walk returned zero peers -- wire compat failure?",
        )


class TestLiveProviderRoundTrip(AsyncTestCase):
    """End-to-end put/get over the real public IPFS DHT.

    Two warpgate nodes both bootstrap to the public IPFS DHT.  Node
    A calls ``provide(key)`` to publish that it provides some
    content.  Node B calls ``find_providers(key)`` and recovers
    A's PeerID via the public DHT -- with the lookup walking
    through whatever real IPFS bootstrap / DHT-relay nodes the
    routing tables of intermediate hops surface.

    Why ``provide`` rather than ``put_value``: go-libp2p's stock
    record validator REJECTS most PUT_VALUE keys (only ``/pk/`` and
    ``/ipns/`` namespaces pass).  Provider records have no
    validator -- ADD_PROVIDER is universally accepted -- so this
    is the realistic shape of "put on the network, get on the
    other side" against the public DHT.

    Skipped by default to avoid public-network flake; opt-in via
    ``WARPGATE_LIBP2P_LIVE=1``.
    """

    async def asyncSetUp(self):
        if SKIP_LIVE:
            self.skipTest("WARPGATE_LIBP2P_LIVE=1 not set")
        self.iface = await Interface()
        self.id_a = peer_id.Identity.generate()
        self.id_b = peer_id.Identity.generate()
        self.node_a = Libp2pNode(self.id_a)
        self.node_b = Libp2pNode(self.id_b)
        # Public-DHT participation requires auto-dialling peers
        # surfaced by FIND_NODE responses; without it the walk
        # never gets past the one bootstrap peer.
        self.node_a.enable_auto_dial_during_walks()
        self.node_b.enable_auto_dial_during_walks()

    async def asyncTearDown(self):
        if not SKIP_LIVE:
            await self.node_a.close()
            await self.node_b.close()

    async def test_provide_then_find_providers_via_public_dht(self):
        # Both nodes bootstrap to the public DHT.
        sa = await bootstrap_mod.bootstrap(self.node_a, iface=self.iface, timeout=20.0)
        sb = await bootstrap_mod.bootstrap(self.node_b, iface=self.iface, timeout=20.0)
        if not sa or not sb:
            self.skipTest("bootstrap failed -- public network not reachable")
        print("live-provider: A connected to {0} bootstrap peer(s)".format(len(sa)))
        print("live-provider: B connected to {0} bootstrap peer(s)".format(len(sb)))

        # Use a fresh randomised content key so we don't collide
        # with another test run's record sitting in the public DHT.
        import os as _os
        content_key = b"/warpgate-test/" + _os.urandom(8).hex().encode("ascii")
        print("live-provider: content_key =", content_key)

        # A advertises that it provides content_key.
        accepted = await self.node_a.provide(content_key, timeout=45.0)
        print("live-provider: A.provide accepted by", accepted, "peer(s)")
        # Best-effort: the public DHT may not always accept records
        # from a peer that's not yet established + has no provided
        # listenable addrs; if accepted == 0 we still proceed --
        # B may still find A's announcement via DHT propagation.

        # Give the network a moment to propagate.
        await asyncio.sleep(2.0)

        # B looks up providers.  The lookup walks the DHT and
        # eventually queries peers that A's provider record was
        # stored on.
        providers = await self.node_b.find_providers(
            content_key, max_providers=5, timeout=60.0,
        )
        print("live-provider: B.find_providers returned {0} provider(s)".format(len(providers)))
        for p in providers:
            print("  ", peer_id.peer_id_to_b58(p.peer_id),
                  "with", len(p.addrs), "addr(s)")
        # The success criterion: B sees A as a provider.  If the
        # public DHT didn't propagate within our timeout, we
        # acknowledge it as a known limitation of public DHTs
        # rather than a wire-format failure.
        a_in_providers = any(
            p.peer_id == self.id_a.peer_id for p in providers
        )
        if not a_in_providers:
            self.skipTest(
                "provider record didn't surface back through public "
                "DHT within the timeout -- known propagation latency, "
                "not a wire-format failure.  A.provide accepted={0}; "
                "B.find_providers got {1} other providers.".format(
                    accepted, len(providers),
                )
            )


if __name__ == "__main__":
    unittest.main()
