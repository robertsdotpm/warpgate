"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""
import asyncio
import time
from aionetiface import (
    fstr, log, log_exception, log_p2p, async_wrap_errors,
    IP4, IP6, OPEN_INTERNET, AFGroup, Interface, SysClock,
    list_interfaces, load_interfaces, parse_node_addr, make_node_addr,
    field_wrap, dhash, create_task, Signing, os_id, os_net_timeouts,
    ErrorCantLoadNATInfo, aionetiface_setup_netifaces,
)
from aionetiface.nic.nat.nat_utils import nat_info
from aionetiface.utility.hashing import sha256_hex_short
from aionetiface.nic.nat.nat_cache import (
    network_fingerprint, nat_cache_get, nat_cache_put, nat_cache_invalidate,
)
from sidewire import Router
from .node_utils import (
    load_machine_id,
    resolve_install_path,
    load_signing_key,
    load_stun_clients,
    close_idle_pipes,
    listen_on_ifs,
    forward,
    remote_reachability_cb,
    enrich_addr_map_with_loopback,
)
from .nickname import Nickname
from ..traversal.traversal_manager import TraversalManager
from ..traversal.plugin_loader import load_plugins, register_plugin_wire_names
from ..install_check import verify_sibling_installs


# Per-OS network-load timeouts come from aionetiface.os_net_timeouts()
# -- one table (NET_TIMEOUTS) shared by node startup, STUN, and the
# MQTT broker walk so XP/Vista get coherent budgets everywhere. Node
# startup uses the interface_load and nat_load entries.


# ==========================================
# Orchestrates the startup sequence for a P2P node.
# ==========================================
async def node_start(node, sys_clock=None, out=False, cout=print):
    """Execute the full ordered startup sequence for a P2P node and return it when ready.

    WARNING -- propagation race after node_start returns
    ====================================================

    On return, the node has put its PNP record on the configured PNP
    servers and subscribed to its MQTT signaling topic. Those operations
    may not yet be visible to every server in the pool. A peer that
    resolves this node's nickname, or routes signaling via its MQTT
    topic, in the immediate window after node_start returns can race a
    server that hasn't yet seen the put / accepted the subscribe, and
    will silently hang in the resolve or dispatch step.

    This affects EVERY caller whose flow is listener-then-connector --
    which is every cross-node test in the matrix. The connector side
    MUST allow a settling window before it starts resolving the
    listener's nickname; ~8 seconds is sufficient in practice. The
    demo entry point enforces this with `await asyncio.sleep(8)` after
    Nickname.put completes (see demo/__main__.py:setup_node). Tests
    or callers that bypass setup_node must insert an equivalent sleep
    themselves before any cross-node lookup.
    """
    # Print where each sibling repo's package resolved from. Cheap
    # (4 imports, ms-scale) and gives every node log a header that
    # makes stale-install bugs (e.g. aionetiface imported from a
    # checkout outside ~/projects/) instantly diagnosable. Non-strict
    # so library / PyPI users aren't forced into the dev layout.
    verify_sibling_installs(strict=False)

    # Startup timeline instrumentation. node_start is a flat sequence
    # of awaits, each a wall-clock-bound step (network round trips,
    # timeouts) -- one [NODE-START] line per step with a monotonic
    # delta gives the whole startup breakdown from a single launch.
    start_t = time.monotonic()

    def mark(step):
        log(fstr(
            "[NODE-START] t={0}ms step={1}",
            (int((time.monotonic() - start_t) * 1000), step),
        ))

    # Hardware & Network Setup
    await load_network_interfaces(node)
    mark("interfaces")

    # Validate --ip / listen_ips against the now-loaded NIC set.
    # Deferred from Node.__init__ because the Gate path doesn't
    # pre-populate node.ifs there.
    if node.listen_ips:
        from .node_connect import apply_listen_ips
        apply_listen_ips(node)

    # Identity & Security
    await load_machine_identity(node)
    kp = load_cryptography_and_auth(node)
    mark("identity")

    # Time & Synchronization
    # Must complete BEFORE the Router (and its MQTTClient instances) is
    # constructed: each MQTTClient takes get_time at __init__ and uses
    # it to stamp app-packet timestamps. Patching get_time on the
    # Router post-hoc doesn't propagate to already-constructed
    # MQTTClients, which silently kept using time.time -- the silent
    # fallback that hid a multi-hour clock-skew bug between
    # XP/Vista (BIOS clock drift) and modern VMs (NTP-synced).
    await initialize_system_clock(node, sys_clock, out, cout)
    mark("sys_clock")

    # STUN clients + Router can run concurrently now that sys_clock
    # is established and can be passed into Router at construction.
    # Each is wrapped so it marks when its own coroutine finishes --
    # they still run concurrently, but the timeline shows which of the
    # two dominates the parallel window.
    async def timed_step(coro, label):
        await coro
        mark(label)

    await asyncio.gather(
        timed_step(load_p2p_stun_clients(node, out, cout), "stun"),
        timed_step(setup_router_and_signal(node, kp, out, cout), "router"),
    )

    await initialize_punch_coordination(node, out, cout)
    mark("punch_coord")

    # Start Servers
    start_maintenance_tasks(node)
    await listen_on_ifs(node)
    mark("listen")

    # Finalize Connectivity — start UPnP only after the node is listening and
    # the listen port is known; await it after high-level setup so UPnP runs
    # concurrently with nickname and plugin initialisation.
    build_node_address(node, out)
    upnp_task = start_background_port_forwarding(node)

    # Real NAT classification runs here, off the startup path. The
    # address was just built with cached-or-placeholder NAT; this task
    # probes the real values, caches them, and republishes if they
    # differ. node.nat_classify_task is exposed so callers can await
    # it if they need a definitely-classified NAT.
    node.nat_classify_task = create_task(
        async_wrap_errors(classify_nat_background(node, out))
    )
    node.resources.add_task(node.nat_classify_task)

    # High-Level Services
    await setup_nickname_service(node)
    mark("nickname")
    await setup_traversal_plugins(node)
    mark("plugins")

    await finalize_port_forwarding(node, upnp_task, out, cout)
    mark("port_forward")

    return node


# ==========================================
# Phase: Hardware & Network Setup
# ==========================================
async def load_network_interfaces(node):
    """Discover and sort all available network interfaces, raising if none are found.

    Respects node.nic_names (list of str): when non-empty, only interfaces
    whose name appears in that list are loaded.  Pass an empty list or omit
    nic_names to discover all available interfaces.

    Idempotent: skips discovery when node.ifs is already populated.
    NAT validation for manually-passed NICs is the caller's responsibility
    (Gate.__aenter__ checks this before invoking node.start).
    """
    if not node.ifs:
        nic_names = getattr(node, "nic_names", [])
        try:
            if_names = await list_interfaces()
            if nic_names:
                # Each wanted name is either a canonical (description
                # on Windows; device path elsewhere) or an alias the
                # netifaces backend recognises (friendly name on
                # Windows).  Resolve each through by_name_index to
                # its canonical, then filter against the discovered
                # list.  Backends without by_name_index (POSIX) fall
                # through to canonical-only matching.
                aliases = {}
                try:
                    netifaces = await aionetiface_setup_netifaces()
                    aliases = getattr(netifaces, "by_name_index", {}) or {}
                except Exception:  # pylint: disable=broad-except
                    pass

                def to_canonical(name):
                    if name in if_names:
                        return name
                    info = aliases.get(name)
                    return info.get("name") if info else None

                filtered = [c for c in (to_canonical(n) for n in nic_names)
                            if c in if_names]
                if not filtered:
                    raise ValueError(
                        "nic_names {0!r} matched no available interfaces {1!r}".format(
                            nic_names, if_names
                        )
                    )
                if_names = filtered
            # skip_nat=True: NAT classification (~2s of STUN probing)
            # is deferred off the startup path. apply_cached_or_
            # placeholder_nat seeds nic.nat below; classify_nat_
            # background does the real probe after the node is up.
            # timeout scales up on XP/Vista (slow interface enum).
            node.ifs = await load_interfaces(
                if_names, Interface, skip_nat=True,
                timeout=os_net_timeouts()["interface_load"],
            )
        except asyncio.CancelledError:
            raise
        except ValueError:
            raise
        except (OSError, asyncio.TimeoutError):
            log_exception()
            node.ifs = []

    node.ifs = sorted(node.ifs, key=lambda x: x.name)

    if not node.ifs:
        raise RuntimeError("p2p node could not load ifs.")

    # Seed nic.nat from the network-fingerprint cache (or an optimistic
    # placeholder) so the address can be built and published without
    # waiting on NAT classification. Idempotent via the nat_fingerprint
    # guard -- whichever of Gate pre-start / node_start runs first does
    # the work, the other is a no-op.
    if not getattr(node, "nat_fingerprint", None):
        apply_cached_or_placeholder_nat(node)

def apply_cached_or_placeholder_nat(node):
    """Seed every nic.nat from the NAT cache, or an optimistic placeholder.

    NAT classification proper is deferred to classify_nat_background;
    this just makes nic.nat non-None so node_start can build and
    publish the address straight away. A network-fingerprint cache hit
    seeds the real previously-measured values (rebuilt via nat_info to
    avoid trusting the raw JSON blob); a miss seeds nat_info()'s
    optimistic default.

    Stores whether the cache hit was FRESH on the node
    (node.nat_cache_is_fresh) so classify_nat_background can decide
    whether to skip the BG classification entirely (fresh) or refresh
    in the background (stale / miss).
    """
    fingerprint = network_fingerprint(node.ifs)
    node.nat_fingerprint = fingerprint
    cached_nics, is_fresh = nat_cache_get(fingerprint)
    node.nat_cache_is_fresh = bool(is_fresh)
    cached = cached_nics or {}
    for nic in node.ifs:
        name = getattr(nic, "name", None)
        entry = cached.get(name)
        if entry and "type" in entry and "delta" in entry:
            try:
                nic.set_nat(nat_info(entry["type"], entry["delta"]))
                continue
            except (ValueError, KeyError, TypeError):
                log_exception()
        if getattr(nic, "nat", None) is None:
            nic.set_nat(nat_info())


async def classify_nat_background(node, out):
    """Run real NAT classification off the startup path, then cache + republish.

    node_start publishes the node address seeded with cached-or-
    placeholder NAT so startup never blocks on the ~2s STUN
    classification probe. This task does the real probe, stores the
    result in the network-fingerprint cache, and -- only if the
    measured NAT differs from what was published -- rebuilds and
    re-publishes the address. Re-publishing the same PNP name is an
    UPDATE and does not consume nickname quota.

    The ~2s classify + republish completes well inside the ~8s
    connector settling window, so a peer never resolves the
    placeholder addr in practice.

    Trust-first short-circuit: when the NAT cache hit was fresh
    (node.nat_cache_is_fresh set by apply_cached_or_placeholder_nat),
    skip the real classification entirely.  The cached values are
    already seeded into nic.nat and the published address reflects
    them; running another classification round just burns STUN load
    and risks overwriting confident cached data with a transient bad
    measurement.  The cache is re-classified on:
      - cache miss (no entry at all)  -> classify normally
      - stale hit (entry past TTL)    -> classify in background
      - cache invalidation by a punch-attempt failure (separately wired)
    """
    if getattr(node, "nat_cache_is_fresh", False):
        log("[NAT-CLASSIFY] cache fresh; skipping background classify")
        return

    classify_t0 = time.monotonic()
    before = {}
    for nic in node.ifs:
        before[getattr(nic, "name", None)] = getattr(nic, "nat", None)

    # Determine per-NIC cold-start status BEFORE classification runs.
    # A NIC is "cold-start" when no usable cached entry was seeded
    # earlier (apply_cached_or_placeholder_nat fell back to the
    # nat_info() placeholder default rather than a previous measurement).
    # The placeholder default produced by nat_info() with no args is
    # (RESTRICT_PORT_NAT, EQUAL_DELTA) -- so any NIC whose seeded nat
    # matches that exactly is cold; anything else carried a prior
    # measurement from cache.  This lets delta_test apply its
    # optimistic-default-on-cold-start behaviour only where it's
    # actually warranted, never on a NIC we've already classified
    # before and stored.
    is_cold_for_nic = {}
    placeholder = nat_info()
    for nic in node.ifs:
        cur = getattr(nic, "nat", None) or {}
        is_cold = (
            cur.get("type") == placeholder.get("type")
            and isinstance(cur.get("delta"), dict)
            and cur["delta"].get("type") == placeholder["delta"]["type"]
        )
        is_cold_for_nic[getattr(nic, "name", None)] = is_cold

    # NAT classification timeout scales up on XP/Vista (slow stacks).
    nat_timeout = os_net_timeouts()["nat_load"]
    nat_by_nic = {}
    for nic in node.ifs:
        try:
            await asyncio.wait_for(
                nic.load_nat(
                    timeout=nat_timeout,
                    is_cold_start=is_cold_for_nic.get(getattr(nic, "name", None), False),
                ),
                timeout=nat_timeout + 5,
            )
        except asyncio.CancelledError:
            raise
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()
        except ErrorCantLoadNATInfo:
            log_exception()
        except Exception:  # pylint: disable=broad-except
            log_exception()

        nat = getattr(nic, "nat", None)
        if nat is not None:
            nat_by_nic[getattr(nic, "name", None)] = nat

    log(fstr(
        "[NAT-CLASSIFY] t={0}ms done nics={1}",
        (int((time.monotonic() - classify_t0) * 1000), len(nat_by_nic)),
    ))

    fingerprint = getattr(node, "nat_fingerprint", None)
    if fingerprint:
        nat_cache_put(fingerprint, nat_by_nic)

    # Republish only if the measured NAT differs from what the address
    # was built with.
    changed = any(
        before.get(getattr(nic, "name", None)) != getattr(nic, "nat", None)
        for nic in node.ifs
    )
    if not changed:
        log("[NAT-CLASSIFY] measured NAT matches published addr; no republish")
        return

    log("[NAT-CLASSIFY] measured NAT differs; rebuilding + republishing addr")
    build_node_address(node, out)
    register_name = getattr(node, "pnp_name", None) or node.node_id
    try:
        await register_and_persist(node, register_name)
    except asyncio.CancelledError:
        raise
    except Exception:  # pylint: disable=broad-except
        log_exception()


def start_background_port_forwarding(node):
    """Launch a background UPnP port-forwarding task if the node is behind NAT and UPnP is enabled."""
    # Check if all NICs are already open. A NIC whose load_nat did not
    # complete (nic.nat is None) cannot be assumed open; conservatively
    # treat it as closed so UPnP forwarding still runs.
    all_open_internet = True
    for nic in node.ifs:
        if nic.nat is None or nic.nat["type"] != OPEN_INTERNET:
            all_open_internet = False
            break

    # If UPnP is enabled and we are behind NAT, start the task
    if node.conf["enable_upnp"] and not all_open_internet:
        reachability = {IP4: {}, IP6: {}}

        async def reachability_cb(msg, client_tup, pipe):
            """Forward inbound messages to the shared reachability checker."""
            await remote_reachability_cb(reachability, msg, client_tup, pipe)

        node.add_msg_cb(reachability_cb)

        return asyncio.create_task(
            async_wrap_errors(forward(node, node.listen_port, reachability))
        )
    return None


# ==========================================
# Phase: Identity & Security
# ==========================================
async def load_machine_identity(node):
    """Load or derive a stable machine ID and set the node's listen port deterministically."""
    node.machine_id = await load_machine_id("warpgate", node.ifs[0].netifaces)

    if node.machine_id in (None, ""):
        raise AssertionError("Could not load machine id.")

    # The listen port is set deterministically to avoid conflicts
    # with port forwarding with multiple nodes in the LAN.
    if node.listen_port is None:
        node.listen_port = field_wrap(dhash(node.machine_id), [10000, 60000])


def load_cryptography_and_auth(node):
    """Load or generate the node's ECDSA signing key, derive the node ID, and return the keypair.

    If ``node.pnp_name`` is set (Gate-driven path), the priv key comes
    from the JSON keystore at ``~/aionetiface/<pnp_name>.json`` --
    fresh entries are created on first call.  Otherwise we fall back
    to the legacy ``load_signing_key`` hex-file path keyed by
    ``node.node_name``.
    """
    pnp_name = getattr(node, "pnp_name", None)
    if pnp_name:
        from aionetiface import keystore
        node.sk = keystore.load_or_create(pnp_name)
    else:
        install_path = resolve_install_path(node.conf)
        node.sk, _ = load_signing_key(
            node.ifs, node.listen_ips, node.listen_port, install_path,
            node_name=getattr(node, "node_name", None),
        )
    node.vk = node.sk.verifying_key

    node.node_id = sha256_hex_short(node.vk.to_string("compressed"), 25)

    # Table of authenticated users
    node.auth = {
        node.node_id: {
            "sk": node.sk,
            "vk": node.vk.to_string("compressed"),
        }
    }

    node.kp = Signing(node.sk)
    return node.kp


# ==========================================
# Phase: Time & Synchronization (concurrent)
# ==========================================
async def initialize_system_clock(node, sys_clock, out, cout):
    """Create or reuse the system clock, optionally synchronising it against NTP."""
    if sys_clock is None:
        if node.conf["init_clock_skew"]:
            sys_clock = SysClock(interface=node.ifs[0])
            await sys_clock.start()
        else:
            sys_clock = SysClock(node.ifs[0], ntp=time.time())
            node.sys_clock = sys_clock

    # Store reference if passed in or created
    if not hasattr(node, "sys_clock") or node.sys_clock is None:
        node.sys_clock = sys_clock


async def load_p2p_stun_clients(node, out, cout):
    """Load TCP STUN clients for each interface and AF if hole-punching is enabled."""
    if node.conf.get("enable_punching", True):
        if out:
            cout("\tLoading STUN clients...")
        # Returns TCP STUN clients using PUNCH_CONF.
        node.stun_clients = await load_stun_clients(node.ifs)

        if out:
            buf = ""
            for if_index in range(0, len(node.ifs)):
                nic = node.ifs[if_index]
                buf += "\t\t" + nic.name + " "
                for af in nic.supported():
                    af_txt = "V4" if af is IP4 else "V6"
                    buf += fstr(
                        "({0}={1})",
                        (
                            af_txt,
                            str(len(node.stun_clients[af][if_index])),
                        ),
                    )
            cout(buf)


async def setup_router_and_signal(node, kp, out, cout):
    """Instantiate the MQTT router, install default traversal plugins, and start the signal channel."""
    # node.sys_clock is established by initialize_system_clock which
    # runs before this in node_start. Threading get_time at Router
    # construction means every MQTTClient stamps app-packet timestamps
    # off the same NTP-synced clock, instead of falling back to
    # wall-clock time.time (which on XP/Vista can be hours off).
    router = Router(
        kp,
        nic=AFGroup.from_interfaces(node.ifs),
        get_time=node.sys_clock.time,
    )
    node.traversal = TraversalManager(
        router, node.stop_reader, node.inbound_pipes, node.ifs,
        # Pass node.msg_cb so any pipe created inside a plugin
        # (e.g. tcp_punch's reverse_server) can pre-populate
        # pipe_events.msg_cbs before the first inbound byte arrives.
        node_msg_cb=node.msg_cb,
    )
    router.add_msg_handler(node.traversal.recv_signal_msg)

    node.traversal.kp = node.kp

    # Wire-names MUST be in node.traversal.sig_proto BEFORE the MQTT
    # subscription goes live in setup_signal_router below.  Otherwise the
    # window between 'subscribed' and 'setup_traversal_plugins finished'
    # (~600ms during which load_p2p_stun_clients, punch_coord, listen and
    # nickname all run) drops any PunchMsg / signal that arrives at the
    # listener with "ValueError: unknown wire_name 'tcp_punch.PunchMsg'".
    # That window is sub-second on a healthy LAN but trivially exposed by
    # a connector whose own startup finishes faster -- the listener never
    # sees the punch and sidewire's republish loses the race if the
    # connector exits inside its punch budget.
    #
    # register_plugin_wire_names is the pure-sync subset of load_plugins
    # (import classes + populate sig_proto + proto_handlers) with no
    # cls.setup() awaits, so it's safe to run before stun_clients /
    # sys_clock have been wired up.  load_plugins below re-runs the same
    # registration during full setup; the collision check makes the
    # double-write a no-op.
    register_plugin_wire_names(node)

    await setup_signal_router(node, router, out, cout)


async def setup_signal_router(node, router, out, cout):
    """Attach the router to the node and start MQTT subscriptions for inbound signalling."""
    node.router = router

    # Subscribe to our own MQTT topic so we can receive incoming signals.
    if out:
        cout("\tLoading MQTT router...")
    # XP's TCP/TLS-less MQTT handshake measurably slower than newer
    # Windows; observed ~8-12s on a fresh socket. 15s gives headroom
    # without dragging healthy hosts (which complete in <1s) into a
    # noticeably slower startup. router.start internally connects to
    # multiple MQTT brokers and racing the slower of them past 15s
    # is genuinely unhealthy.
    try:
        clients = await asyncio.wait_for(router.start(), timeout=15)
    except asyncio.TimeoutError as exc:
        raise OSError("Router MQTT start timed out - signaling may be degraded") from exc


# ==========================================
# Phase: Connectivity Clients
# ==========================================
async def initialize_punch_coordination(node, out, cout):
    """Log the NTP clock skew value used to coordinate hole-punch timing across peers."""
    if out:
        cout("\tLoading NTP clock skew...")
    if node.conf["init_clock_skew"]:
        ntp = str(node.sys_clock.ntp)
        if out:
            cout(fstr("\t\tClock ntp = {0}", (ntp,)))


# ==========================================
# Phase: Start Servers
# ==========================================
def start_maintenance_tasks(node):
    """Launch the background idle-pipe-closer loop and register it for cancellation on shutdown."""
    # Simple loop to close idle tasks.
    node.resources.set_idle_closer(create_task(close_idle_pipes(node)))


# ==========================================
# Phase: Finalize Connectivity
# ==========================================
def build_node_address(node, out):
    """Serialise the node's public key and interface info into addr_bytes and parse it into addr_map."""
    if node.node_id is None:
        raise AssertionError("node_id was not set before building node address.")

    # Collect MQTT broker hints from router.protected_clients --
    # the brokers we successfully connected to at startup. Remote
    # peers resolving our addr will prefer publishing via these
    # before falling back to their own rendezvous-derived
    # candidate set, sidestepping the broker-set non-convergence
    # bug.
    #
    # MAX_BROKER_HINTS caps the count to keep the addr under
    # namebump's NB_VAL_LEN ceiling. Each hint is ~30-50 bytes
    # encoded; 3 hints with 4 base sections fits comfortably
    # under 500B. Two hints would give some redundancy but only
    # one mutually-reachable broker is needed for delivery, so
    # 3 is plenty in practice.
    MAX_BROKER_HINTS = 3
    mqtt_brokers = []
    try:
        for client in getattr(node.router, "protected_clients", set()) or []:
            af = getattr(client, "af", None)
            host, port = getattr(client, "dest", (None, None))
            if af is not None and host and port:
                mqtt_brokers.append({"af": int(af), "host": host, "port": int(port)})
            if len(mqtt_brokers) >= MAX_BROKER_HINTS:
                break
    except (AttributeError, TypeError):
        # If the router didn't finish setting up protected_clients
        # we just emit no hints; legacy 4-part addr behaviour.
        mqtt_brokers = []

    log_p2p(fstr(
        "[NODE-ADDR] packing {0}/{1} broker hints: {2}",
        (len(mqtt_brokers), MAX_BROKER_HINTS, mqtt_brokers),
    ), node.node_id[:8])

    node.addr_bytes = make_node_addr(
        node.kp.public_key_hex,
        node.machine_id,
        node.ifs,
        port=node.listen_port,
        mqtt_brokers=mqtt_brokers,
        if_ports=getattr(node, "if_ports", None),
        os=os_id(),
    )
    node.traversal.addr_bytes = node.addr_bytes

    # Log address.
    msg = fstr("Starting node = '{0}'", (node.addr_bytes,))
    if not out:
        log_p2p(msg, node.node_id[:8])

    # Save a dict version of the address fields.
    try:
        node.addr_map = parse_node_addr(node.addr_bytes)
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (ValueError, TypeError) as exc:
        log_exception()
        raise ValueError("Can't parse nodes p2p addr.") from exc

    # Attach the per-node loopback alias to every if_info. select_dest_ipr
    # uses dest["loopback"] when same_pc=True so cross-subnet
    # same-machine peers route via 127.0.0.0/8 instead of NIC IPs.
    enrich_addr_map_with_loopback(node.addr_map)


async def finalize_port_forwarding(node, upnp_task, out, cout):
    """Hand the UPnP/PCP task off to background tracking; do not block startup on it.

    Port forwarding only benefits the direct / reverse-connect path,
    and its failure degrades gracefully -- reverse_connect still works
    without a forwarded port. Awaiting it here used to add ~2-8s to
    node startup: a router with no IGD/PCP just burns the SSDP/PCP
    discovery timeout while the rest of the node sits idle waiting.

    Instead, register the task with node.resources so it is cancelled
    on shutdown, and return immediately. The mapping installs in the
    background whenever discovery completes. The task uses a static
    mapping description ("warpgate" -- see forward()), so a background
    run never accumulates duplicate-named entries on the IGD.
    """
    if upnp_task:
        if out:
            cout("\tUPnP/PCP forwarding running in background...")
        node.resources.add_task(upnp_task)


# ==========================================
# Phase: High-Level Services
# ==========================================
async def setup_nickname_service(node):
    """Initialise the PNP nickname client and optionally register this node's ID.

    Skips the entire client construction when enable_nickname=False --
    Nickname's __await__ runs start() which tries to reach every PNP
    server and raises StartNodeNicknameFailed if none come up. On
    hosts whose TLS / network stack can't talk to those servers (e.g.
    Windows XP), that fail kills node startup outright even when the
    caller never intended to use nicknames. Tests that opt out via
    enable_nickname=False shouldn't pay that cost. nick_client is
    left None so put/get crash loudly if accidentally called.
    """
    if not node.conf.get("enable_nickname", True):
        node.nick_client = None
        return

    node.nick_client = await Nickname(
        node.sk,
        node.ifs,
        node.sys_clock,
    )

    register_name = getattr(node, "pnp_name", None) or node.node_id
    task = asyncio.create_task(async_wrap_errors(
        register_and_persist(node, register_name),
    ))
    node.resources.add_task(task)
    node.nickname_register_task = task


async def register_and_persist(node, name):
    """Register name in PNP and stash the full name (with TLD) on node.full_name.

    On failure, captures the exception on ``node.nickname_error`` so
    callers can surface a typed message instead of a generic
    "didn't load" string.
    """
    node.nickname_error = None
    node.full_name = None
    register_t0 = time.monotonic()
    log("[REGISTER-TIME] t=0ms step=put_start")
    try:
        node.full_name = await node.nickname(name)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pylint: disable=broad-except
        node.nickname_error = exc
        log(fstr(
            "[REGISTER-TIME] t={0}ms step=put_failed {1}",
            (int((time.monotonic() - register_t0) * 1000), repr(exc)),
        ))
        raise
    log(fstr(
        "[REGISTER-TIME] t={0}ms step=put_done",
        (int((time.monotonic() - register_t0) * 1000),),
    ))


async def setup_traversal_plugins(node):
    """Discover and install all traversal plugins found under the plugins/ directory."""
    await load_plugins(node)
    log("traversal plugin_loaders: " + str(node.traversal.plugin_loaders))
