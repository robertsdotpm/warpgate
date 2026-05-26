"""Bootstrap dial: connect to public libp2p network entry points.

A libp2p host can't participate in the global mesh from a cold
start without knowing at least one already-connected peer.  The
canonical entry points are the IPFS bootstrap peers -- public
nodes the IPFS project runs that always accept inbound + are
addressable in the global DHT.

We keep the list editable via the ``WARPGATE_LIBP2P_BOOTSTRAP``
env var (whitespace-separated multiaddr strings) for air-gapped /
test-mesh deployments.  Default: a small, conservative set known
to accept Noise XX + yamux.

Bootstrap is best-effort -- dialing any single one is allowed to
fail.  The dial machinery itself goes through ``Libp2pNode.dial``
which means it picks up Noise XX + identify + everything else
already wired.  Successfully-bootstrapped peers populate the
Kad-DHT routing table automatically (each new session triggers an
``add_peer`` on ``node.kad_routing_table``).
"""
import asyncio
import os

from aionetiface import IP4, IP6, Interface, fstr, log, log_exception

from . import multiaddr as ma


# A short curated list of public IPFS bootstrap multiaddrs.  These
# are deliberately the TCP ones (we don't yet speak QUIC), and they
# are the canonical IPFS bootstrappers as of 2026; subject to drift
# but each one accepts /noise + /yamux.
DEFAULT_BOOTSTRAP = (
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    # The dnsaddr resolution step requires an extra DNS hop we don't
    # implement; for offline-safe default, also include concrete v4
    # multiaddrs that historically backed the same peer IDs:
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
)


def get_bootstrap_addrs():
    """Read bootstrap multiaddr strings from env or fall back to defaults."""
    env = os.environ.get("WARPGATE_LIBP2P_BOOTSTRAP", "").strip()
    if env:
        return [s for s in env.split() if s]
    return list(DEFAULT_BOOTSTRAP)


async def bootstrap(node, addrs=None, iface=None, timeout=15.0):
    """Dial every bootstrap multiaddr in parallel, best-effort.

    Returns the list of successfully-established LibP2PSession
    objects.  Failure of any single dial is logged but doesn't
    affect the others.

    Multiaddrs are expected to embed ``/p2p/<peer_id>`` so we can
    verify the expected_peer_id during dial.  Multiaddrs without
    a peer_id segment are skipped (we'd have no way to authenticate
    the responder).
    """
    if addrs is None:
        addrs = get_bootstrap_addrs()
    if iface is None:
        try:
            iface = await Interface()
        except Exception:
            log_exception()
            return []

    tasks = []
    for ma_text in addrs:
        tasks.append(
            asyncio.ensure_future(
                dial_one_bootstrap(node, ma_text, iface, timeout),
            )
        )
    if not tasks:
        return []
    results = await asyncio.gather(*tasks, return_exceptions=True)
    sessions = []
    for ma_text, result in zip(addrs, results):
        if isinstance(result, Exception):
            log(fstr(
                "libp2p_native bootstrap: dial {0} failed: {1}",
                (ma_text, repr(result)[:80]),
            ))
            continue
        if result is None:
            continue
        sessions.append(result)
        log(fstr(
            "libp2p_native bootstrap: dial {0} OK", (ma_text,),
        ))
    return sessions


async def dial_one_bootstrap(node, ma_text, iface, timeout):
    """Parse ``ma_text`` to (ip, port, peer_id), then dial via Libp2pNode."""
    try:
        ma_bytes = ma.parse_text(ma_text)
    except ValueError:
        log_exception()
        return None
    parts = ma.decode(ma_bytes)
    ip, port = ma.extract_first_ip_tcp(parts)
    peer_id = ma.extract_peer_id(parts)
    if ip is None or port is None:
        # No /ip4/...//tcp/... pair -- DNS multiaddrs / circuit-only
        # multiaddrs we can't resolve in this pass.
        return None
    if peer_id is None:
        # Without a peer_id we can't authenticate via Noise XX -- skip.
        return None
    try:
        from aionetiface import IP4 as af4, IP6 as af6
    except ImportError:
        af4, af6 = IP4, IP6
    # Choose the AF that matches the parsed IP.
    af = af4 if ":" not in ip else af6
    try:
        route = await iface.route(af).bind(ips=None, port=0)
    except (OSError, ValueError):
        log_exception()
        return None
    try:
        _stream, _remote_pid, session = await node.dial(
            ip, port, route,
            expected_peer_id=peer_id, timeout=timeout,
        )
    except (OSError, ConnectionError, asyncio.TimeoutError, ValueError):
        return None
    return session
