"""Shared helpers for multi-node yggdrasil topology tests.

Used by ``test_yggdrasil_line_network.py`` and
``test_yggdrasil_random_tree.py``.  Mirrors upstream
``ironwood/network/core_test.go`` helpers (newDummyConn +
waitForRoot + per-pair traffic delivery) using real TCP loopback
listeners instead of an in-memory pipe -- this gives us the same
correctness signal AND exercises the real socket path.

We use real loopback rather than the v2 LoopbackTransport because
the active router + pathfinder rely on send_packet_safe scheduling
that's only fully wired through NodeCore (real listener/dialer +
register_link).  A future refactor could push this through
LoopbackTransport so the multi-node tests run with zero kernel I/O.
"""
import asyncio
import os
import time

from aionetiface import IP6

from warpgate.overlay.yggdrasil.node_core import NodeCore
from warpgate.overlay.yggdrasil.router_active import ActiveRouter


class TopologyNode(object):
    """One node + router pair, wired together."""

    def __init__(self, seed=None):
        self.seed = seed if seed is not None else os.urandom(32)
        self.node = NodeCore(seed=self.seed)
        self.router = ActiveRouter(self.node)
        self.node.packet_handler = self.router.on_packet

    async def start(self):
        await self.node.start_listener(bind_addr="::1", port=0, af=IP6)
        self.router.start()

    async def stop(self):
        self.router.stop()
        await self.node.close()

    @property
    def public_key(self):
        return self.node.public_key

    @property
    def listen_port(self):
        return self.node.listen_port

    def uri(self):
        return "tcp://[::1]:{0}".format(self.listen_port)


class Topology(object):
    """N-node setup + tear-down + convergence/traffic helpers.

    Subclasses populate ``self.nodes`` and override ``wire_edges`` to
    decide which (i, j) pairs get a direct peer link.
    """

    def __init__(self, n):
        self.n = int(n)
        self.nodes = []

    async def start(self):
        for _ in range(self.n):
            tn = TopologyNode()
            await tn.start()
            self.nodes.append(tn)
        # Stagger the dial requests so simultaneous inbound
        # handshakes against the same listener don't race for the
        # accept loop's processing slot.  A 100 ms gap is enough
        # for one handshake's TLV exchange to settle.
        for i, j in self.edges():
            here = self.nodes[j]
            prev = self.nodes[i]
            await here.node.add_peer_uri(prev.uri())
            await asyncio.sleep(0.1)

    async def stop(self):
        for tn in self.nodes:
            try:
                await tn.stop()
            except Exception:
                pass

    def edges(self):
        raise NotImplementedError("Topology.edges must return iterable of (i,j)")

    async def wait_for_edges(self, timeout=15.0):
        """Wait until every wired edge has a live peer link both ways."""
        deadline = time.monotonic() + timeout
        wanted = list(self.edges())
        while time.monotonic() < deadline:
            ok = True
            for i, j in wanted:
                a_node = self.nodes[i].node
                b_node = self.nodes[j].node
                if a_node.peers.get_peer(b_node.public_key) is None:
                    ok = False
                    break
                if b_node.peers.get_peer(a_node.public_key) is None:
                    ok = False
                    break
            if ok:
                return True
            await asyncio.sleep(0.2)
        return False

    async def wait_for_root_convergence(self, timeout=40.0):
        """Wait until every router agrees on the same root pubkey.

        Mirrors upstream's ``waitForRoot`` helper -- the tree has
        settled iff all participants compute the same root key for
        themselves.  Returns True on convergence, False on timeout.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            roots = set()
            for tn in self.nodes:
                root, _ = tn.router.get_root_and_path(tn.public_key)
                roots.add(bytes(root))
            if len(roots) == 1:
                return True
            await asyncio.sleep(0.3)
        return False

    def diagnostic_state(self):
        """Dump per-node {root, parent, infos, peers, responses} for failure diagnosis."""
        lines = []
        for idx, tn in enumerate(self.nodes):
            r = tn.router
            self_info = r.infos.get(tn.public_key)
            parent = self_info.parent if self_info else None
            root, _ = r.get_root_and_path(tn.public_key)
            peers = [bytes(e.link.remote_pubkey)[:4].hex()
                     for e in tn.node.peers.peers()]
            infos = [k[:4].hex() for k in r.infos]
            responses = [k[:4].hex() for k in r.responses]
            requests = [(k[:4].hex(), r.requests[k].seq)
                        for k in r.requests]
            lines.append("  node[{0}] self={1} parent={2} root={3}\n"
                "    peers={4}\n"
                "    infos={5}\n"
                "    responses={6}\n"
                "    requests={7}".format(
                idx,
                bytes(tn.public_key)[:4].hex(),
                bytes(parent)[:4].hex() if parent else "(none)",
                bytes(root)[:4].hex(),
                peers, infos, responses, requests,
            ))
        return "\n".join(lines)

    async def send_and_receive(self, src_idx, dst_idx, msg, timeout=12.0):
        """Send ``msg`` from src to dst over the overlay; await arrival.

        Returns True if dst's inbox produced (src_pub, msg) within
        timeout, False otherwise.  Mirrors upstream's send-loop with
        retry-until-receive pattern.
        """
        src = self.nodes[src_idx]
        dst = self.nodes[dst_idx]
        dst_pub = dst.public_key
        src_pub = src.public_key
        msg_bytes = bytes(msg)
        deadline = time.monotonic() + timeout
        # Drain any stale entries from dst.router.inbox before we send.
        while not dst.router.inbox.empty():
            try:
                dst.router.inbox.get_nowait()
            except asyncio.QueueEmpty:
                break
        # Send repeatedly: cold-start may path_broken the first few
        # tries until the pathfinder has a route cached.  Upstream
        # uses a 1s tick + lifelong retry until the receiver echoes
        # success.  We cap retries at the deadline.
        retry = 0
        while time.monotonic() < deadline:
            await src.router.send_to(dst_pub, msg_bytes)
            try:
                wait = max(0.05, min(0.5, deadline - time.monotonic()))
                source_key, payload = await asyncio.wait_for(
                    dst.router.inbox.get(), timeout=wait,
                )
                if bytes(source_key) == bytes(src_pub) \
                        and bytes(payload) == msg_bytes:
                    return True
                # Mismatched delivery: put back to the inbox not strictly
                # necessary (we drain at start); just keep retrying.
            except asyncio.TimeoutError:
                retry += 1
                continue
        return False


class LineTopology(Topology):
    """Chain: 0 <-> 1 <-> 2 <-> ... <-> n-1."""

    def edges(self):
        return [(i, i + 1) for i in range(self.n - 1)]


class RandomTreeTopology(Topology):
    """Random tree: each new node attaches to a randomly-chosen earlier one.

    Determined at construction via a pinned seed so the topology is
    reproducible across runs.  Upstream uses time.Now().UnixNano() as
    its randIdx source; we use random.Random(seed) so the test
    output is stable -- a flaky tree test is harder to debug than a
    deterministic one.
    """

    def __init__(self, n, seed=0xC0FFEE):
        super(RandomTreeTopology, self).__init__(n)
        import random
        self.rng = random.Random(seed)
        self.attachments = []
        for new_idx in range(1, n):
            parent_idx = self.rng.randrange(0, new_idx)
            self.attachments.append((parent_idx, new_idx))

    def edges(self):
        return list(self.attachments)
