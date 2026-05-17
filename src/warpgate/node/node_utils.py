"""Miscellaneous helpers for node startup and operation."""
import asyncio
import hashlib
import os
import socket
import signal
import time
from ecdsa import SigningKey, SECP256k1
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import pathlib
from aionetiface import (
    fstr, log, log_exception, ip_norm, get_aionetiface_install_root,
    get_n_stun_clients, TCP, RFC5389, IP4, IP6, IPR,
    async_wrap_errors, strip_none, sock_has_data, hash160, to_h, to_b, to_s,
    h_to_b, WebCurl, get_default_iface, USE_MAP_NO,
)
from aionetiface.nic.netifaces.netiface_extra import get_mac_address
from ..traversal.plugins.tcp_punch.punch_defs import PUNCH_CONF
from ..vendor.machine_id import hashed_machine_id


def resolve_install_path(conf):
    """Return the configured install path, falling back to the library root."""
    return conf["install_path"] or get_aionetiface_install_root()


def loopback_candidates_for(pub_key_hex, listen_port):
    """Ordered list of (af, ip, port) loopback candidates for same-machine traversal.

    Listener tries each on bind (best-effort, ignores collisions); peer
    tries each on connect until one accepts. Order is "most-likely-to-
    work-without-collisions" first, "most-portable" second:

      1. (IP4, 127.X.Y.Z, listen_port)
         The per-node alias derived from pub_key. Unique address per node
         so two same-machine peers never collide on the same loopback IP.
         Doesn't work on platforms whose stack only routes 127.0.0.1
         (Windows XP has been observed to silently drop traffic here).

      2. (IP4, 127.0.0.1, listen_port)
         The universally-routable IPv4 loopback. listen_port is unique
         per node, so two same-machine peers don't collide on this
         tuple either. Used as the XP-safe primary fallback.

      3. (IP6, ::1, listen_port)
         IPv6 loopback. Works when the host has IPv6 enabled and the
         IPv4 stack is jammed (firewall, weird filter driver, etc.).

      4. (IP4, 127.0.0.1, pub_key_derived_port)
         Last-resort: pub_key-derived port in [30000, 60000) so two
         peers competing for the same listen_port still don't collide
         on this tuple. More likely to clash with unrelated services
         on the host but kept as a safety net.
    """
    primary_v4 = loopback_ip_for_node(pub_key_hex)
    val = int(pub_key_hex, 16)
    fallback_port = 30000 + (val % 30000)
    return [
        (IP4, primary_v4, listen_port),
        (IP4, "127.0.0.1", listen_port),
        (IP6, "::1", listen_port),
        (IP4, "127.0.0.1", fallback_port),
    ]


def enrich_addr_map_with_loopback(addr_map):
    """Attach the per-node loopback alias + candidate fallbacks to every if_info.

    parse_node_addr (in aionetiface) is intentionally unaware of the warpgate
    loopback convention; we add the field on the warpgate side after parse so
    select_dest_ipr can reach it as dest["loopback"] and the plugins
    can iterate dest["loopback_candidates"] on connect failure.
    Mutates and returns addr_map for the convenience of callers that
    want to chain.

    Only attaches when the addr_map advertises at least one IPv4
    interface -- the loopback fallbacks include IPv6 ::1, but for the
    same-machine path to make sense we still need at least one IP4
    if_info to anchor the loopback field on.
    """
    pub = addr_map.get("pub_key_hex")
    if not pub:
        return addr_map
    if not addr_map.get(IP4):
        return addr_map
    try:
        lo_str = loopback_ip_for_node(pub)
    except (ValueError, TypeError):
        return addr_map
    lo_ipr = IPR(lo_str)
    # The candidates list uses the if_info's own listen port (per_iface).
    # Different if_indexes on the same node may bind different ports, so
    # build the list per-info rather than once.
    for af in (IP4, IP6):
        af_dict = addr_map.get(af) or {}
        for info in af_dict.values():
            info["loopback"] = lo_ipr
            info_port = info.get("port")
            if info_port:
                try:
                    info["loopback_candidates"] = loopback_candidates_for(
                        pub, int(info_port)
                    )
                except (ValueError, TypeError):
                    info["loopback_candidates"] = []
            else:
                info["loopback_candidates"] = []
    return addr_map


def loopback_ip_for_node(pub_key_hex):
    """Deterministic 127.X.Y.Z loopback address keyed on a node's pub_key.

    Same-machine peers can't reliably TCP-connect between two of their own
    NIC IPs across different subnets on Windows — the kernel doesn't
    loopback-shortcut cross-subnet traffic. Both nodes instead bind a
    127.X.Y.Z address derived from their pub_key; the peer reads the same
    pub_key out of the addr_map and connects via the loopback interface,
    which always works.

    pub_key_hex is a node's compressed secp256k1 public key (66 hex chars),
    globally unique per node. Mapping it modulo the usable 127.0.0.0/8
    range keeps cross-node collisions effectively zero — and within one
    machine the two nodes guaranteed to differ since their key pairs do.

    Reserved corners are avoided:
      - First octet is always 127 (loopback).
      - Second octet (A) ∈ [1, 254] so 127.0.* / 127.255.* are skipped.
      - Last octet (C) ∈ [2, 254] so 127.A.B.0 / 127.A.B.1 / 127.A.B.255
        are skipped.

    The resulting address is bind-able and reachable on every supported
    platform: 127.0.0.0/8 is implicitly routed to the loopback iface by
    Linux and Windows alike, no admin-side route table change needed.
    """
    val = int(pub_key_hex, 16)
    # Available host addresses inside the 127.0.0.0/8 block after corner
    # exclusions: A∈[1,254] (254), B∈[0,255] (256), C∈[2,254] (253).
    c = 2 + (val % 253)
    val //= 253
    b = val % 256
    val //= 256
    a = 1 + (val % 254)
    return "127.{0}.{1}.{2}".format(a, b, c)


def make_stop_pair(existing=None):
    """Create a non-blocking/blocking socket pair used to signal shutdown, or return existing."""
    if existing:
        return existing
    stop_rw = socket.socketpair()
    stop_rw[0].setblocking(False)
    stop_rw[1].setblocking(True)
    return stop_rw


def pipe_future(inbound_pipes, pipe_id):
    """Return the Future for pipe_id, creating it if it does not yet exist."""
    if pipe_id not in inbound_pipes:
        inbound_pipes[pipe_id] = asyncio.Future()
    return inbound_pipes[pipe_id]


def pipe_ready(inbound_pipes, pipe_id, pipe):
    """Resolve the Future for pipe_id with the given pipe object."""
    if pipe_id not in inbound_pipes:
        pipe_future(inbound_pipes, pipe_id)
    if not inbound_pipes[pipe_id].done():
        inbound_pipes[pipe_id].set_result(pipe)
    return pipe


def norm_listen_ips(listen_ips):
    """Deduplicate and sort a list of listen IPs, normalising each address."""
    # Skip if empty.
    if not listen_ips:
        return listen_ips

    # Norm the IPs.
    listen_ips = [ip_norm(ip) for ip in listen_ips]

    # Remove duplicates.
    listen_ips = list(set(listen_ips))

    # Sort it deterministically.
    listen_ips = sorted(listen_ips)

    return listen_ips


def load_signing_key(nics, listen_ips, listen_port, install_path, node_name=None):
    """Load the node's ECDSA signing key from disk, generating and persisting a new one if absent.

    Returns (signing_key, is_fresh).  is_fresh=True means the key was
    generated this call (no prior file existed); is_fresh=False means
    it was loaded from disk.  Callers use this to distinguish first-
    time PNP registration (must check name is free) from re-registering
    a name we already own (skip the collision check).

    Identity is keyed by node_name. When node_name is None the file
    falls back to the single shared "default" path at install_path --
    suitable for single-node hosts and the common no-flag case. Two
    nodes that pass the same node_name share a private key: that's the
    contract, the caller is responsible for not booting two such nodes
    on the same box.

    nics / listen_ips / listen_port are kept in the function signature
    for backwards compatibility; they are no longer hashed into the path.
    Earlier schemes derived the path from (NIC names + listen_port) which
    churned every time the host's interfaces or DHCP-assigned addresses
    moved -- explicit node_name gives the caller stable, predictable
    identity instead.
    """
    # Make install dir if needed.
    pathlib.Path(install_path).mkdir(parents=True, exist_ok=True)

    name_tag = node_name if node_name else "default"
    # v3_ prefix distinguishes the explicit-node-name scheme from the
    # earlier (NIC, port)-hash and listen_ips-namespaced files.
    sk_path = os.path.realpath(
        os.path.join(install_path, fstr("PRIV_KEY_DONT_SHARE_v3_{0}.hex", (name_tag,)))
    )

    # Read existing key or generate fresh. We do NOT migrate forward
    # from old listen_ips-namespaced files: such migration can't tell
    # which (NIC, port) config a legacy file originated from, so two
    # nodes loading from the same install_path with distinct (NIC,
    # port) tuples would both adopt the same legacy key and end up
    # with identical pubkeys -- the exact regression the IPv6 churn
    # fix was meant to avoid in spirit. Users upgrading from the
    # legacy scheme get one fresh identity per (NIC, port); the old
    # files stay on disk untouched (the user can delete them once
    # the new identity is registered).
    if os.path.exists(sk_path):
        with open(sk_path, mode="r", encoding="utf-8") as fp:
            sk_hex = fp.read()
        is_fresh = False
    else:
        sk = SigningKey.generate(curve=SECP256k1)
        sk_buf = sk.to_string()
        sk_hex = to_h(sk_buf)
        with open(sk_path, "w", encoding="utf-8") as file:
            file.write(sk_hex)
        is_fresh = True

    # Convert secret key to a singing key.
    sk_buf = h_to_b(sk_hex)
    sk = SigningKey.from_string(sk_buf, curve=SECP256k1)
    return sk, is_fresh


async def fallback_machine_id(netifaces, app_id="warpgate"):
    """Derive a stable machine ID from hostname, default interface name, and MAC address."""
    host = socket.gethostname()
    if_name = get_default_iface(netifaces)
    mac = await get_mac_address(if_name, netifaces)
    buf = fstr(
        "{0} {1} {2} {3}",
        (
            app_id,
            host,
            if_name,
            mac,
        ),
    )
    return to_s(hashlib.sha256(to_b(buf)).hexdigest())


async def close_idle_pipes(node):
    """
    As the number of free processes in the process pool
    decreases and the pool approaches full the need to
    check for idle connections to free up processes becomes
    more urgent. The math below allocates an interval to use
    for the idle count down based on urgency (remaining
    processes) in reference to a min and max idle interval.
    """
    punch = getattr(node.resources, "punch_factory", None)
    if punch is None or punch.max_workers <= 0:
        return

    floor_check = 300
    ceil_check = 7200
    while not sock_has_data(node.stop_reader):
        alloc_pcent = punch.active_punchers / punch.max_workers
        num_space = ceil_check - floor_check
        abs_placement = ceil_check - (num_space * alloc_pcent)

        close_list = []
        cur_time = time.time()
        next_sleep = 5  # default max sleep

        # Sort recv queue oldest → newest
        node.resources.last_recv_queue.sort(
            key=lambda pipe: node.resources.last_recv_table.get(pipe.sock, 0)
        )

        # Loop over the queue
        for pipe in node.resources.last_recv_queue:
            last_recv = node.resources.last_recv_table.get(pipe.sock)
            if last_recv is None:
                continue

            elapsed = max(0, cur_time - last_recv)
            if elapsed >= abs_placement:
                close_list.append(pipe)
            else:
                # Compute time until this pipe reaches abs_placement
                time_until_expire = abs_placement - elapsed
                next_sleep = min(next_sleep, time_until_expire)
                # Queue is sorted, so no need to check further
                break

        # Close idle pipes
        for pipe in close_list:
            node.resources.last_recv_queue.remove(pipe)
            node.resources.last_recv_table.pop(pipe.sock, None)
            try:
                await asyncio.wait_for(pipe.close(), timeout=2)
            except asyncio.TimeoutError:
                log("close idle pipe close timeout")
            except (OSError, ConnectionError):
                log_exception()
                log("unknown exception for close pipe in close_idle_pipes.")

        # Sleep until the next pipe is due, capped at 5 seconds
        await asyncio.sleep(min(next_sleep, 5))


# Cap on STUN probe sockets open at once across the whole interface
# load.  Each (af, interface) job fires `pool` concurrent TCP probes;
# with many dual-stack interfaces the naive all-at-once gather could
# blow past the platform socket ceiling (the Windows selector event
# loop tops out around 64, shared with broker + listen sockets).
STUN_SOCKET_BUDGET = 32
# Per-job pool ceiling -- candidates probed concurrently per (af,
# interface) job when the socket budget comfortably covers them.
# 6 is 3x the needed count (USE_MAP_NO=2): enough to shrug off ~4 dead
# servers in a run, without burning sockets a healthy node won't use.
STUN_POOL_MAX = 6


async def load_stun_clients(ifs, limit=USE_MAP_NO):
    """Load `limit` TCP STUN clients per AF per interface, indexed, within a socket budget.

    Each (af, interface) job probes a pool of candidate STUN servers
    concurrently.  To keep total concurrent sockets under
    STUN_SOCKET_BUDGET: the per-job pool is divided down by the job
    count (never below `limit`, since NAT-delta needs that many), and
    the jobs themselves run in batches so concurrent pools never
    exceed the budget.
    """
    stun_clients = {IP4: {}, IP6: {}}
    stun_t0 = time.monotonic()

    # Enumerate every (af, interface) job up front.
    jobs = []
    for if_index in range(len(ifs)):
        interface = ifs[if_index]
        for af in interface.supported():
            jobs.append((af, if_index, interface))
    if not jobs:
        return stun_clients

    # Conservative per-job pool: split the budget across jobs, clamp to
    # [limit, STUN_POOL_MAX].  Then size the job batch so concurrent
    # sockets (jobs_per_batch * per_job_pool) stay within budget.
    per_job_pool = min(STUN_POOL_MAX, max(limit, STUN_SOCKET_BUDGET // len(jobs)))
    jobs_per_batch = max(1, STUN_SOCKET_BUDGET // per_job_pool)

    async def run_job(af, if_index, interface):
        """Fetch STUN clients for one (af, interface) pair and return them with their index."""
        clients = await get_n_stun_clients(
            af=af,
            n=limit,
            mode=RFC5389,
            interface=interface,
            proto=TCP,
            conf=PUNCH_CONF,
            pool=per_job_pool,
        )
        log(fstr(
            "[STUN-TIME] af={0} if={1} t={2}ms pool={3} found={4}",
            (af, if_index,
             int((time.monotonic() - stun_t0) * 1000),
             per_job_pool, len(clients)),
        ))
        return (af, if_index, clients)

    for i in range(0, len(jobs), jobs_per_batch):
        batch = jobs[i:i + jobs_per_batch]
        results = await asyncio.gather(
            *[run_job(af, ix, iface) for af, ix, iface in batch],
            return_exceptions=False,
        )
        for af, if_index, clients in results:
            stun_clients[af][if_index] = clients

    return stun_clients


def worker_init():
    """
    This runs when each worker process starts.
    We tell the worker to ignore SIGINT.
    """
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    except (OSError, AttributeError):
        # Fallback for edge cases or embedded environments
        pass


async def get_pp_executors(workers=None):
    """Create a ThreadPoolExecutor for tcp_punch's burst-send worker.

    Was ProcessPoolExecutor for "more accurate timing and isolating
    busy connection spam from main app." In practice the precision
    benefit was marginal -- punch's sub-second timing precision
    comes from socket-call latency, not from process isolation,
    and the GIL releases on every socket op anyway. The cost was
    real though: on Python 3.8 + Windows, ProcessPoolExecutor's
    queue-management thread routinely crashes with
    OSError [WinError 6] ("invalid handle") and BrokenPipeError
    [WinError 109] mid-poll, killing the punch task even though
    the worker subprocess is fine. Documented CPython bug
    (issue 39104, 41588). Switching to ThreadPoolExecutor
    sidesteps that entire mess. Same Executor interface so callers
    don't change.

    Future: if punch precision in production turns out to need
    process isolation after all, replace with one-shot
    multiprocessing.Process per call (no pool, no queue manager).
    """
    workers = workers or min(32, os.cpu_count() + 4)
    pp_executor = None
    try:
        # ThreadPoolExecutor doesn't need worker_init's SIGINT handler:
        # signals are delivered to the main thread only, so worker
        # threads don't see them. Skip the initializer entirely.
        pp_executor = ThreadPoolExecutor(max_workers=workers)
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (OSError, RuntimeError):
        log_exception()

    log("get_pp_executors: type={0} workers={1} executor={2}".format(
        type(pp_executor).__name__ if pp_executor else "None",
        workers,
        "OK" if pp_executor is not None else "FAILED",
    ))
    return workers, pp_executor


async def load_machine_id(app_id, netifaces):
    """Return a hashed machine ID for app_id, falling back to a network-derived value on failure."""
    try:
        return hashed_machine_id(app_id)
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (OSError, ValueError):
        return await fallback_machine_id(netifaces, app_id)


async def soft_bind_and_listen(node, route, label):
    """Bind and add_listener for one route; log on failure, never raise.

    Returns the actual bound port on success, 0 on failure.
    When node.listen_port is non-zero (user-specified), a bind failure is
    a hard miss — no silent port=0 fallback — so the caller's nic_successes
    counter stays at zero and listen_on_ifs can raise loudly.
    """
    try:
        await route.bind(port=node.listen_port)
    except (OSError, ValueError, AssertionError) as exc:
        log(fstr("listen_on_ifs: bind failed for {0}: {1}", (label, exc)))
        return 0
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise

    try:
        result = await node.add_listener(TCP, route)
    except (OSError, ValueError, AssertionError) as exc:
        log(fstr("listen_on_ifs: add_listener failed for {0}: {1}", (label, exc)))
        return 0
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise

    if result is None:
        return 0
    return result[0]


async def bind_nic_v4(node, nic_i, nic):
    """Bind v4 listen_local on one NIC.  Returns bound port (0 = fail).

    Critical: a zero return contributes to the "every NIC bind failed"
    runtime error in listen_on_ifs.
    """
    try:
        listed = await node.listen_local(TCP, node.listen_port, nic) or []
    except (OSError, ValueError, AssertionError) as exc:
        log(fstr("listen_on_ifs: listen_local nic={0} failed: {1}", (nic.id, exc)))
        return 0

    if not listed:
        return 0

    first = next((x for x in listed if isinstance(x, tuple) and x[0]), None)
    if not first:
        return 0
    nic_port = first[0]

    if not any(x is not None for x in listed):
        return 0

    node.if_ports[(IP4, nic_i)] = {"ext": nic_port, "nic": nic_port}
    return nic_port


async def bind_nic_v6_ext(node, nic_i, nic, label):
    """Bind v6 ext (global) on one NIC.  Returns bound port (0 = fail)."""
    v6_route = nic.route(IP6)
    port = await soft_bind_and_listen(node, v6_route, label)
    if port > 0:
        node.if_ports.setdefault((IP6, nic_i), {})["ext"] = port
    return port


def fe80_iprs(nic):
    """Return the NIC's IPv6 fe80 link-local IPRs (may be 0, 1, or more)."""
    out = []
    for ipr in nic:
        if getattr(ipr, "af", None) == IP6 and str(ipr).lower().startswith("fe80"):
            out.append(ipr)
    return out


async def bind_nic_v6_fe80(node, nic_i, fe80_ipr, label):
    """Bind a v6 fe80 link-local listener on one NIC.  Returns port (0 = fail).

    Part of the NIC's "nic" path -- the v6 NIC-local listener, mirror of
    the v4 NIC IP. Sets if_ports[(IP6, nic_i)]["nic"] from the real bind
    (it used to be faked from the v4 port).
    """
    port = await soft_bind_and_listen(node, fe80_ipr.route, label)
    if port > 0:
        node.if_ports.setdefault((IP6, nic_i), {})["nic"] = port
    return port


async def bind_loopback(node, cand_af, cand_ip, cand_port, label):
    """Bind a per-node loopback alias.  Returns port (0 = fail).  Non-critical.

    Deepcopies the route because add_listener retains the reference; without
    a copy the next iteration's bind(ips=...) would mutate the previous
    listener's route in place.
    """
    import copy as copy_mod
    try:
        # Use Interface("default") rather than node.ifs[0] so the
        # listen socket isn't SO_BINDTODEVICE-pinned to a physical
        # NIC.  apply_nic_pin_sockopts pins to route.interface.name;
        # Interface("default")'s name is "default" which the kernel
        # rejects with ENODEV, leaving the socket unpinned -- which
        # is exactly what we want for a 127.x bind, since the kernel
        # routes loopback traffic via `lo` and a NIC-pinned listen
        # socket can't accept SYNs that arrive on lo.
        from aionetiface import Interface
        default_nic = await Interface("default")
        cand_route = default_nic.route(cand_af)
        await cand_route.bind(ips=cand_ip, port=cand_port)
        await node.add_listener(TCP, cand_route)
        log(fstr("listen_on_ifs: {0} bound af={1}", (label, cand_af)))
        return cand_port
    except (OSError, ValueError, AssertionError) as exc:
        log(fstr("listen_on_ifs: {0} bind failed: {1}", (label, exc)))
        return 0


async def listen_on_ifs(node):
    """Bind TCP listeners for every NIC, plus the per-node loopback aliases.

    Each NIC has two bind paths:
      - "nic": the NIC-local listeners -- the v4 NIC IP and the v6 fe80
        link-local(s).
      - "ext": the v6 global listener.
    A path counts as bound when at least one of its listeners came up.

    Failure semantics:
      - General NIC -> OSError only if BOTH paths fail (no inbound path).
      - NIC named in --nic (node.nic_names) -> OSError if ANY applicable
        path fails; an explicitly-requested NIC must come up fully.
      - Every NIC failing both paths -> OSError regardless.
      - --ip (node.listen_ips): every listed address must bind, else OSError.
      - Loopback aliases: log + continue (convenience only).

    When node.listen_port is 0, a probe socket pre-resolves an OS-assigned
    ephemeral port so every concurrent bind targets the same number. All
    binds run concurrently via asyncio.gather(return_exceptions=True); one
    slow / hung NIC never blocks any other. No retries.
    """
    node.if_ports = {}

    if node.listen_port == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("", 0))
            node.listen_port = probe.getsockname()[1]

    # --- strict --ip path: every listed address must bind ----------------
    if node.listen_ips:
        listen_iprs = [IPR(ip) for ip in node.listen_ips]
        ip_tasks = []  # (label, coro)
        for nic in node.ifs:
            for nic_ipr in nic:
                if nic_ipr in listen_iprs:
                    label = fstr("listen_ip {0}", (nic_ipr,))
                    ip_tasks.append((label, soft_bind_and_listen(node, nic_ipr.route, label)))
        results = await asyncio.gather(
            *(c for _, c in ip_tasks), return_exceptions=True,
        )
        failed = []
        for (label, _), r in zip(ip_tasks, results):
            if not (isinstance(r, int) and r > 0):
                failed.append(label)
                if isinstance(r, BaseException) and not isinstance(r, asyncio.CancelledError):
                    log(fstr("listen_on_ifs: {0} raised: {1}", (label, r)))
        if failed or not ip_tasks:
            msg = fstr(
                "listen_on_ifs: --ip address(es) failed to bind: {0}",
                ("; ".join(failed) or "(no --ip address matched any NIC)",),
            )
            log(msg)
            raise OSError(msg)
        return

    # --- default path: per-NIC "nic" + "ext" binds -----------------------
    explicit = set(node.nic_names or [])
    plan = []  # (nic_i, nic, path, label, coro)
    for nic_i, nic in enumerate(node.ifs):
        plan.append((
            nic_i, nic, "nic", fstr("v4 nic={0}", (nic.id,)),
            bind_nic_v4(node, nic_i, nic),
        ))
        if IP6 in nic.supported():
            for fe80_ipr in fe80_iprs(nic):
                lbl = fstr("v6 fe80 {0} nic={1}", (fe80_ipr, nic.id))
                plan.append((nic_i, nic, "nic", lbl,
                             bind_nic_v6_fe80(node, nic_i, fe80_ipr, lbl)))
            elbl = fstr("v6 ext nic={0}", (nic.id,))
            plan.append((nic_i, nic, "ext", elbl,
                         bind_nic_v6_ext(node, nic_i, nic, elbl)))

    try:
        candidates = loopback_candidates_for(node.kp.public_key_hex, node.listen_port)
    except Exception as exc:  # pylint: disable=broad-except
        candidates = []
        log(fstr("listen_on_ifs: loopback candidates compute failed: {0}", (exc,)))
    aux = []  # (label, coro) -- non-critical
    for cand_af, cand_ip, cand_port in candidates:
        cand_label = fstr("loopback {0}:{1}", (cand_ip, cand_port))
        aux.append((cand_label, bind_loopback(node, cand_af, cand_ip, cand_port, cand_label)))

    results = await asyncio.gather(
        *([c for _, _, _, _, c in plan] + [c for _, c in aux]),
        return_exceptions=True,
    )
    plan_results = results[: len(plan)]
    aux_results = results[len(plan):]

    for (label, _), r in zip(aux, aux_results):
        if isinstance(r, BaseException) and not isinstance(r, asyncio.CancelledError):
            log(fstr("listen_on_ifs: aux {0} raised: {1}", (label, r)))

    # Per-NIC path accounting: a path is bound if >=1 of its listeners came up.
    acct = {}  # nic_i -> {"nic": bool, "ext": bool, "ext_applies": bool, "obj": nic}
    for (nic_i, nic, path, label, _), r in zip(plan, plan_results):
        a = acct.setdefault(nic_i, {
            "nic": False, "ext": False,
            "ext_applies": IP6 in nic.supported(), "obj": nic,
        })
        if isinstance(r, int) and r > 0:
            a[path] = True
        elif isinstance(r, BaseException) and not isinstance(r, asyncio.CancelledError):
            log(fstr("listen_on_ifs: {0} raised: {1}", (label, r)))

    failed_nics = []
    for nic_i, a in acct.items():
        nic = a["obj"]
        nic_ok, ext_ok, ext_applies = a["nic"], a["ext"], a["ext_applies"]

        if getattr(nic, "name", None) in explicit:
            # --nic NIC: every applicable path must bind.
            missing = []
            if not nic_ok:
                missing.append("nic")
            if ext_applies and not ext_ok:
                missing.append("ext")
            if missing:
                msg = fstr(
                    "listen_on_ifs: --nic '{0}' failed to bind path(s): {1}",
                    (nic.name, ", ".join(missing)),
                )
                log(msg)
                raise OSError(msg)

        if not (nic_ok or ext_ok):
            failed_nics.append(getattr(nic, "id", nic_i))

    if acct and len(failed_nics) == len(acct):
        msg = fstr(
            "listen_on_ifs: every NIC failed both bind paths ({0} NIC(s)); "
            "node has no inbound path. Failed: {1}",
            (len(acct), failed_nics),
        )
        log(msg)
        raise OSError(msg)


async def remote_reachability_cb(reachability, _msg, client_tup, pipe):
    """Mark the NIC as reachable when an inbound connection arrives from the known warpgate probe server."""
    try:
        warpgate_ips = (
            IPR("2607:5300:60:80b0::1", af=IP6),
            IPR("158.69.27.176", af=IP4),
        )
        client_ip = IPR(client_tup[0], af=pipe.route.af)
        if client_ip not in warpgate_ips:
            return
        nic = pipe.route.interface
        af = pipe.route.af
        if nic.id in reachability[af]:
            future = reachability[af][nic.id]
            if not future.done():
                future.set_result(True)
    except (OSError, ValueError, KeyError, AttributeError):
        log("unknown exception in reachability cb")
        log_exception()


async def forward(node, port, reachability):
    """Run UPnP+PCP port forwarding for every NIC/AF and probe reachability, returning (forwarded, reachable) lists."""
    from ..traversal.plugins.upnp.main import port_forward as upnp_port_forward
    from .pcp_client import pcp_try_anycast_and_gateway, PROTOCOL_TCP

    # Stage timeline for the port_forward breakdown: the UPnP/PCP
    # mapping race vs the reachability probe vs the fixed connect-back
    # wait.
    fwd_t0 = time.monotonic()

    def fwd_stage(name):
        log(fstr(
            "[FORWARD-TIME] t={0}ms stage={1}",
            (int((time.monotonic() - fwd_t0) * 1000), name),
        ))

    fwd_stage("forward_enter")
    tasks = []
    for nic in node.ifs:
        for af in nic.supported():

            async def do_forward(af=af, nic=nic):
                """Forward the listen port for one (af, nic) pair and return [af, nic.id] on success.

                Races UPnP and PCP: the first to install a mapping wins.
                UPnP-IGD is the old standard most consumer home routers
                implement; PCP (RFC 6887) is the modern replacement
                that several carriers and prosumer CPEs run instead --
                some of them explicitly disable UPnP-IGD.  Running both
                in parallel covers both populations without doubling
                the cold-start budget.
                """
                reachability[af][nic.id] = asyncio.Future()
                route = await nic.route(af).bind()
                src_ip = route.nic() if af == IP4 else route.ext()
                src_tup = (src_ip, port)

                # Per-method timing so the UPnP/PCP race breaks down
                # into the individual cost of each path.
                race_t0 = time.monotonic()

                def race_mark(method, result):
                    log(fstr(
                        "[FORWARD-RACE] af={0} method={1} t={2}ms result={3}",
                        (af, method,
                         int((time.monotonic() - race_t0) * 1000), result),
                    ))

                async def via_upnp():
                    out = await upnp_port_forward(af, nic, port, src_tup, "warpgate")
                    race_mark("upnp", out)
                    return out

                async def via_pcp():
                    gws = nic.netifaces.gateways()
                    gw = None
                    if af in gws:
                        # netifaces returns [(addr, ifname), ...]; take first.
                        glist = gws[af]
                        if glist:
                            gw = glist[0][0]
                    sock_af = socket.AF_INET6 if af == IP6 else socket.AF_INET
                    parsed = await pcp_try_anycast_and_gateway(
                        sock_af, src_ip, gw, port, proto=PROTOCOL_TCP,
                        suggested_ext_port=port,
                    )
                    out = 1 if parsed and parsed.get("result_code") == 0 else 0
                    race_mark("pcp", out)
                    return out

                upnp_task = asyncio.ensure_future(via_upnp())
                pcp_task = asyncio.ensure_future(via_pcp())
                race = [upnp_task, pcp_task]
                winner = 0
                try:
                    for done in asyncio.as_completed(race):
                        result = await done
                        if result:
                            winner = 1
                            break
                finally:
                    for t in race:
                        if not t.done():
                            t.cancel()
                    await asyncio.gather(*race, return_exceptions=True)
                if winner:
                    return [af, nic.id]

            tasks.append(do_forward())

    forward_success = strip_none(await asyncio.gather(*tasks, return_exceptions=True))
    fwd_stage("forwards_done")

    # Reachability probe: curl a remote server to trigger a connect-
    # back, then wait for it to land.  This is diagnostic only --
    # `reachable` is logged by finalize_port_forwarding, nothing
    # functional gates on it -- and it costs a remote round trip plus
    # a fixed 2s connect-back wait.  Gated off by default; set
    # enable_reachability_test in node.conf to re-enable it.
    reachable = []
    if node.conf.get("enable_reachability_test", False):
        test_addr = {IP4: "158.69.27.176", IP6: "2607:5300:60:80b0::1"}

        async def reachability_test(af, nic):
            """Trigger the remote warpgate probe server to connect back to us on the forwarded port."""
            route = nic.route(af)
            curl = WebCurl((test_addr[af], 80), route, do_close=0)
            try:
                await curl.vars({"action": "hello", "proto": "tcp", "port": str(port)}).get(
                    "/warpgate/net_debug.php"
                )
            except asyncio.TimeoutError:
                return None

        await asyncio.gather(
            *[reachability_test(af, nic) for nic in node.ifs for af in nic.supported()],
            return_exceptions=True,
        )
        fwd_stage("reachability_done")

        await asyncio.sleep(2)
        fwd_stage("sleep_done")

        reachable = [
            (af, nic_id)
            for af in (IP4, IP6)
            for nic_id in reachability[af]
            if reachability[af][nic_id].done()
        ]
    return forward_success, reachable
