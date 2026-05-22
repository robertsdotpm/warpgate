"""NAT port-prediction algorithms used by hole-punching."""
import asyncio
import random
from aionetiface import (
    fstr, log, log_exception, TCP, STUN_PORT, MAX_PORT,
    get_high_port_socket, socket_factory, from_range,
    OPEN_INTERNET, delta_info, NA_DELTA, nat_info, RESTRICT_PORT_NAT,
    nats_can_predict, nats_intersect, field_wrap, in_range, port_wrap,
    n_dist, strip_none,
    EQUAL_DELTA, PRESERV_DELTA, INDEPENDENT_DELTA, DEPENDENT_DELTA,
    RANDOM_DELTA, PREDICTABLE_NATS,
)

MAX_PREDICT_NO = 100

# Duplicate defs
# TODO: should this module be moved into nat lib? probably.
TCP_PUNCH_LAN = 1
TCP_PUNCH_REMOTE = 2
TCP_PUNCH_SELF = 3


class NATMapping:
    """Represents a single NAT port mapping with local, reply, and remote ports."""

    def __init__(self, mapping, sock=None):
        self.local = mapping[0]
        self.reply = mapping[1]
        self.remote = mapping[2]
        self.sock = sock

    def __str__(self):
        buf = fstr(
            "{0} {1} ",
            (
                self.local,
                self.reply,
            ),
        )
        buf += fstr(
            "{0} {1}",
            (
                self.remote,
                self.sock,
            ),
        )
        return buf

    def to_json(self):
        """Return the mapping as a JSON-serialisable [local, reply, remote] list."""
        return [self.local, self.reply, self.remote]

    def to_dict(self):
        """Serialise this mapping to a dictionary with local, reply, remote, and sock fields."""
        return {
            "local": self.local,
            "reply": self.reply,
            "remote": self.remote,
            "sock": self.sock,
        }

    @staticmethod
    def from_dict(d):
        """Reconstruct a NATMapping from a serialised dictionary."""
        return NATMapping([d["local"], d["reply"], d["remote"]], d["sock"])


def mappings_dicts_to_objs(mappings):
    """Convert a list of mapping dicts to NATMapping objects."""
    ret = []
    for d in mappings:
        ret.append(NATMapping.from_dict(d))

    return ret


def mappings_objs_to_dicts(mappings):
    """Convert a list of NATMapping objects to serialisable dicts."""
    ret = []
    for m in mappings:
        ret.append(m.to_dict())

    return ret


async def get_high_port_mapping(stun_client):
    """Bind to a high-numbered port via STUN and return the resulting NAT mapping."""
    assert stun_client.conf["reuse_addr"]
    nic = stun_client.interface
    af = stun_client.af
    for _ in range(0, 5):
        try:
            # Reserve a sock for use.
            _, high_port = await get_high_port_socket(
                nic.route(af),
                socket_factory,
                sock_type=TCP,
            )

            # Bind to a sock with that port.
            route = nic.route(af)
            await route.bind(port=high_port)

            # Determine associated remote port.
            ret = await stun_client.get_mapping(
                # Upgraded to a pipe.
                pipe=route
            )

            return NATMapping([ret[0], 0, ret[1]], ret[2])
        except (OSError, asyncio.TimeoutError):
            log_exception()
            continue

    raise ConnectionError("high port sock fail.")


def get_mapping_templates(use_stun_port=False, use_range=[2000, MAX_PORT], test_no=8):
    """Build placeholder NATMapping templates used when no peer mappings are yet available."""
    mappings = []
    for _ in range(0, test_no):
        # Default port for when there is a
        # [port restrict, rand delta] NAT.
        if use_stun_port:
            mappings.append(NATMapping([0, 0, STUN_PORT]))
            break
        else:
            mappings.append(NATMapping([0, 0, from_range(use_range)]))

    return mappings


def init_predictions(mode, src_nat, dest_nat, recv_mappings=None, test_no=8):
    """Normalise NAT info and produce initial mapping templates for the prediction algorithm."""
    # Set test_no based on recipients test no.
    # [[remote port, required reply port], ...]
    if recv_mappings is not None:
        test_no = len(recv_mappings)

    # Patch NAT if it's not remote.
    if mode in [TCP_PUNCH_LAN, TCP_PUNCH_SELF]:
        src_nat = nat_info(OPEN_INTERNET, delta_info(NA_DELTA, 0))

        dest_nat = nat_info(OPEN_INTERNET, delta_info(NA_DELTA, 0))

    # Attempt to make chosen local ports compatible
    # with any reply port restrictions.
    use_stun_port = nats_can_predict(src_nat, dest_nat)
    use_range = nats_intersect(src_nat, dest_nat, test_no)
    if use_stun_port:
        test_no = 1

    # Pretend we have a list of mappings from a peer
    # even if we don't -- used to simplify code.
    if recv_mappings is None:
        recv_mappings = get_mapping_templates(
            use_stun_port,
            use_range,
            test_no,
        )

    return use_range, src_nat, dest_nat, recv_mappings


async def preload_mappings(no, stuns):
    """Concurrently fetch no high-port STUN mappings from the given STUN clients.

    Samples STUN servers WITHOUT replacement when possible.  random.choice
    can pick the same server twice for a 3-sample preload, which costs us
    real diversity -- two samples through the same anchor IP can land on
    the same NAT-mapping family even when the next allocation slot has
    moved on, so the predictor sees less drift than is actually present.
    Fall back to with-replacement only when there are fewer stuns than
    samples requested.
    """
    if len(stuns) >= no:
        chosen = random.sample(list(stuns), no)
    else:
        chosen = list(stuns)
        while len(chosen) < no:
            chosen.append(random.choice(stuns))

    tasks = [get_high_port_mapping(s) for s in chosen]
    mappings = await asyncio.gather(*tasks)
    mappings = strip_none(mappings)
    return mappings


def filter_preload_outliers(mappings):
    """Drop preloaded samples whose remote port deviates wildly from the median.

    Real NAT allocation patterns cluster -- EQUAL puts mapped == local,
    PRESERV keeps successive mapped within a small window, INDEPENDENT/
    DEPENDENT advance by a fixed step.  A stray sample from a different
    NAT family (e.g. an IPv6 sample mixed with v4, or a STUN reflection
    through a secondary CGNAT path) shows up as a remote port hundreds
    of thousands of bins away from the others.

    Median-Absolute-Deviation gate with a floor of 1000 ports -- generous
    enough that legitimate sequential allocation (delta < 1000) never
    trips it, tight enough to catch the cross-family case.  Never strip
    below 2 samples (the drift-rate estimator needs >=2).
    """
    if len(mappings) < 3:
        return mappings
    remotes = sorted(m.remote for m in mappings)
    median = remotes[len(remotes) // 2]
    deviations = sorted(abs(m.remote - median) for m in mappings)
    mad = deviations[len(deviations) // 2]
    threshold = max(mad * 6, 1000)
    kept = [m for m in mappings if abs(m.remote - median) <= threshold]
    return kept if len(kept) >= 2 else mappings


def get_single_mapping(
mode,
    rmap,
    last_mapped,
    use_range,
    our_nat,
    preloaded_mapping,
    step=1000,
    index=0,
):
    """Predict a single outbound NAT mapping that coordinates with the peer's rmap."""
    # Allow last mapped to be modified from inside func.
    last_local = last_mapped.local
    last_remote = last_mapped.remote

    # Need to bind to a specific port.
    remote_port = rmap.remote
    reply_port = rmap.reply
    bind_port = reply_port or remote_port
    assert bind_port
    assert remote_port

    # Normally the code tries to use the same port as the recipient to simplify
    # coordination. But when punching yourself, the same local port is already
    # in use, so we must choose a non-conflicting port instead.
    if mode == TCP_PUNCH_SELF:
        remote = field_wrap(remote_port + step, [2001, MAX_PORT])

        return NATMapping(
            [
                remote,
                0,
                remote,
            ]
        )

    # If we're port restricted specify we're happy to use their mapping.
    # This may not be possible if our delta is random though.
    our_reply = bind_port if our_nat["type"] == RESTRICT_PORT_NAT else 0

    # Use their mapping as-is.
    if our_nat["is_open"]:
        return NATMapping([bind_port, 0, bind_port])

    # If preserving try use their mapping.
    if our_nat["delta"]["type"] == EQUAL_DELTA:
        if not in_range(bind_port, our_nat["range"]):
            bind_port = from_range(use_range)

        return NATMapping([bind_port, 0, bind_port])

    # NAT preserves distance between local ports in remote ports.
    if our_nat["delta"]["type"] == PRESERV_DELTA:
        # PRESERV branch used to chase the peer's bind_port: compute the
        # signed distance from our last STUN-observed mapping to that
        # bind_port and add the same distance to our last_local.  That
        # only works when the NAT applies a CONSTANT (local - mapped)
        # offset across every socket -- which is what EQUAL_DELTA does,
        # not PRESERV.  Real PRESERV NATs (and the burst-sequential
        # CGNATs the classifier surfaces as PRESERV when round 2 sees
        # mapped_dist == local_dist == 1) preserve port distance only
        # for sockets allocated close in time to the STUN observation;
        # a socket whose local port is tens of thousands away from
        # last_local lands in a different allocation family with an
        # unrelated offset.  Three preloaded mappings on a real carrier
        # NAT bear this out: (42662->1446), (48808->1448), (3352->1304)
        # -- three different (local-mapped) shifts, not one.
        #
        # Match the WE-DICTATE pattern the other non-trivial deltas
        # already use (INDEPENDENT / DEPENDENT / PREDICTABLE-fallback):
        # bind sequentially after the last STUN observation
        # (last_local + 1 + index) and tell the peer to target the
        # adjacent mapped port (last_remote + 1 + index).  The peer
        # reads our .remote and lands there regardless of what they
        # initially templated.  The per-mapping index spreads the N
        # punch sockets across N adjacent NAT slots so multiple SYNs
        # racing through the allocator have non-colliding predictions.
        offset = 1 + index
        next_local = port_wrap(last_local + offset)
        next_remote = port_wrap(last_remote + offset)
        # We intentionally do NOT check next_remote against use_range:
        # nats_intersect() bumps use_range[0] to 2000 to keep BIND-PORT
        # selection out of privileged territory, but next_remote isn't a
        # bind port -- it's what the carrier NAT will actually map us to,
        # and real CGNATs commonly allocate from sub-2000 pools (the
        # observed last_remote=1319 is the canonical case).  Falling back
        # to from_range(use_range) here was randomising the predicted
        # mapping back to 30k+ ports the NAT never assigns, defeating
        # the whole WE-DICTATE prediction.  port_wrap() above guards
        # arithmetic overflow; that's the only invariant we need.

        # We're dictating the mapped port now, not chasing the peer's
        # choice -- so the reply-port hint for our RESTRICT_PORT NAT
        # must point at the port we'll actually arrive on, not the
        # peer's original ask.
        if our_nat["type"] == RESTRICT_PORT_NAT:
            our_reply = next_remote

        log("[NAT-PREDICT] PRESERV: last=({0}->{1}) idx={2} "
            "next_local={3} next_remote={4} our_reply={5}".format(
                last_local, last_remote, index, next_local, next_remote, our_reply,
            ))

        return NATMapping([next_local, our_reply, next_remote])

    # Independent and dependent NATs allocate mappings from a known range
    # (measured via a large number of STUN tests) and wrap around when they
    # reach the end. Imprecise ranges cause wrong wrap-around predictions and
    # failed hole punching. Ranges must be exact for these delta types;
    # increasing test_no and rounding to powers of two improves accuracy.

    # INDEPENDENT: NAT advances mapped port by a constant delta per
    # allocation regardless of local port.  Spread N candidates across
    # N adjacent allocation slots so the SYN spray covers the pointer
    # advancing during the punch fire, not just the slot we observed
    # at preload time.  Was: next_remote = last_remote + delta for
    # every i (effective spray width 1).
    if our_nat["delta"]["type"] == INDEPENDENT_DELTA:
        delta_val = our_nat["delta"]["value"]
        next_local = from_range([2000, MAX_PORT])
        next_remote = field_wrap(
            last_remote + (1 + index) * delta_val, use_range,
        )
        return NATMapping([next_local, our_reply, next_remote])

    # DEPENDENT: mapped advances by delta per local-port advance.  Bind
    # locals at last_local+1+i so the NAT walks delta*i in lockstep.
    # Was: next_local = last_local+1 for every i (EADDRINUSE on 7/8
    # sockets) and next_remote constant.
    if our_nat["delta"]["type"] == DEPENDENT_DELTA:
        delta_val = our_nat["delta"]["value"]
        next_local = port_wrap(last_local + 1 + index)
        if delta_val == 0:
            return NATMapping([next_local, our_reply, last_remote])
        next_remote = field_wrap(
            last_remote + (1 + index) * delta_val, use_range,
        )
        return NATMapping([next_local, our_reply, next_remote])

    # Delta type is random -- get a mapping from STUN to reuse.
    # If we're port restricted then set our reply port to the STUN port.
    if our_nat["type"] in PREDICTABLE_NATS:
        # Calculate reply port.
        our_reply = 3478 if our_nat["type"] == RESTRICT_PORT_NAT else 0
        # TODO: Could connect to STUN port in their range.

        # Return results.
        return NATMapping(
            [preloaded_mapping.local, our_reply, preloaded_mapping.remote]
        )

    # Symmetric NATs only allow mappings per (src_ip, src_port, dest_ip,
    # dest_port). The only way to support them is if they also have a
    # non-random delta. Reaching this point means a random-delta symmetric
    # NAT — unpredictable and unsupported.
    raise AssertionError("Can't predict this NAT type.")


async def nat_prediction(mode, src_nat, dest_nat, stuns, recv_mappings=None, test_no=8):
    # Wider spray for the predictor path to absorb carrier-NAT
    # allocation-pointer drift between the STUN preload and the punch
    # fire. At test_no=2 the wire-level mappings only had to drift by 2
    # slots to miss both candidates; with test_no=8 (and the
    # last_local+1..N WE-DICTATE pattern in get_single_mapping) the
    # spray covers a contiguous 8-port window adjacent to the last STUN
    # observation, tolerating up to 8 slots of pointer advance.
    # XP's half-open SYN cap is 10, so 8 stays safely under (matching
    # boundary_alloc's NUM_PORTS=8 chosen for the same reason).
    """Compute predicted send and preloaded mappings for a hole-punch session."""
    log("[NAT-PREDICT] mode={0} src_nat_type={1} dest_nat_type={2} "
        "stuns={3} recv_mappings={4}".format(
            mode, src_nat.get("type"), dest_nat.get("type"),
            len(stuns), len(recv_mappings) if recv_mappings else 0,
        ))
    # Setup nats and initial mapping templates.
    # The mappings will be filled in with details.
    use_range, src_nat, dest_nat, recv_mappings = init_predictions(
        mode, src_nat, dest_nat, recv_mappings, test_no
    )

    # Preload NAT predictions: STUN samples to anchor the predictor.
    # This path carries the punch only when boundary_alloc was skipped
    # -- at least one side has a non-deterministic delta (INDEPENDENT /
    # DEPENDENT / RANDOM / PRESERV), where the external port has to be
    # measured rather than derived from a time bucket.
    #
    # Default 3 samples are enough to fit a linear drift model for
    # EQUAL / PRESERV / INDEPENDENT / DEPENDENT.  For RANDOM_DELTA on a
    # PREDICTABLE_NAT, get_single_mapping returns preloaded[i] directly,
    # so the spray width is exactly len(preloaded) -- 3 collapses test_no=8
    # into 3 effective candidates.  Preload test_no in that case so each
    # spray slot gets a fresh STUN sample (still cheap; STUN burst).
    src_delta_info = src_nat.get("delta") or {}
    is_random_predictable = (
        src_delta_info.get("type") == RANDOM_DELTA
        and src_nat.get("type") in PREDICTABLE_NATS
    )
    preload_no = test_no if is_random_predictable else 3

    # In-process preload cache.  Carrier NATs allocate slowly enough that
    # back-to-back punch attempts (failure + retry, or multi-peer fan-out
    # from one node) see the allocation pointer barely moved between
    # preloads.  Stash the last successful burst on the first STUN client's
    # NIC and reuse if recent.  Strictly best-effort: any miss falls back
    # to a fresh STUN burst, so a stale cache costs at most one bad
    # prediction (which spray + drift candidates absorb).
    nic_obj = stuns[0].interface if stuns else None
    cache_key = ("preload", src_nat.get("type"), (src_nat.get("delta") or {}).get("type"))
    PRELOAD_CACHE_TTL = 30.0  # seconds
    now_t = asyncio.get_event_loop().time() if hasattr(asyncio, "get_event_loop") else None

    cached = None
    if nic_obj is not None and now_t is not None:
        cache_dict = getattr(nic_obj, "preload_cache", None)
        if isinstance(cache_dict, dict):
            entry = cache_dict.get(cache_key)
            if entry is not None:
                cached_mappings, cached_t_start, cached_t_end = entry
                if (now_t - cached_t_end) < PRELOAD_CACHE_TTL and len(cached_mappings) >= preload_no:
                    cached = (cached_mappings[:preload_no], cached_t_start, cached_t_end)
                    log("[NAT-PREDICT] preload cache HIT age={0:.1f}s".format(
                        now_t - cached_t_end,
                    ))

    if cached is not None:
        preloaded_mappings, t_preload_start, t_preload_end = cached
    else:
        # Capture wall-clock around the STUN burst so we can estimate the
        # NAT's allocation-pointer drift (ports/sec) and extrapolate forward
        # to the actual punch fire time.
        t_preload_start = now_t
        preloaded_mappings = await preload_mappings(preload_no, stuns)
        t_preload_end = asyncio.get_event_loop().time() if hasattr(
            asyncio, "get_event_loop"
        ) else None
        # Store on the NIC for the next call within TTL.
        if nic_obj is not None and t_preload_start is not None:
            cache_dict = getattr(nic_obj, "preload_cache", None)
            if not isinstance(cache_dict, dict):
                cache_dict = {}
                try:
                    nic_obj.preload_cache = cache_dict
                except (AttributeError, TypeError):
                    cache_dict = None
            if cache_dict is not None:
                cache_dict[cache_key] = (
                    preloaded_mappings, t_preload_start, t_preload_end,
                )

    assert len(preloaded_mappings)
    # Outlier filter -- drop cross-family STUN samples that would corrupt
    # last_remote (the WE-DICTATE anchor).  Done before downstream usage.
    preloaded_mappings = filter_preload_outliers(preloaded_mappings)

    # Use default ports for client if unknown
    # or try use their ports if known.
    results = []
    for i in range(0, len(recv_mappings)):
        # Default to using first mapped.
        try:
            preloaded_mapping = preloaded_mappings[i]
        except IndexError:
            preloaded_mapping = preloaded_mappings[0]

        # Predict our mappings.
        # Try to match our ports to any provided mappings.
        result = get_single_mapping(
            # Punching mode.
            mode,
            # Try match this mapping.
            recv_mappings[i],
            # A mapping fetch from STUN.
            # Only set depending on certain NATs.
            preloaded_mappings[-1],
            # Uses a range compatible with both NATs
            # Otherwise uses our range.
            use_range,
            # Info on our NAT type and delta.
            src_nat,
            # Get a result instantly.
            preloaded_mapping,
            # Per-mapping index so WE-DICTATE branches (PRESERV) can
            # spread N punch sockets across N adjacent NAT-slots.
            index=i,
        )

        # Save prediction.
        results.append(result)

    # Diagnostic: log the full input + output of this prediction round so
    # punch failures can be reconstructed from the log without needing to
    # rerun the demo.  Previously only mode/types/counts were logged,
    # which made it impossible to tell whether a failed punch came from
    # a bad NAT classification (wrong delta type), a wrong preloaded STUN
    # measurement, a bad bind_port template, or a bug in get_single_mapping.
    log("[NAT-PREDICT] preloaded={0}".format(
        [(m.local, m.remote) for m in preloaded_mappings],
    ))
    log("[NAT-PREDICT] recv_template={0}".format(
        [(m.local, m.reply, m.remote) for m in recv_mappings],
    ))
    log("[NAT-PREDICT] send_mappings={0}".format(
        [(m.local, m.reply, m.remote) for m in results],
    ))

    # R8-6: sequential-allocator one-step-ahead candidate.
    # ~40-60% of SOHO routers allocate ports sequentially (Guha2005 §3.2).
    # The STUN measurement captures the external port at measurement time;
    # by the time the real punch socket connects, the NAT may have advanced
    # by one delta increment. Adding `last_remote + delta` as an extra
    # candidate covers this "off-by-one" without any extra round trips.
    # Only applied for INDEPENDENT_DELTA / DEPENDENT_DELTA with abs(delta)<=10
    # to avoid inflating the candidate list for high-variance deltas.
    src_delta = src_nat.get("delta") or {}
    src_delta_type = src_delta.get("type")
    src_delta_val = src_delta.get("value", 0)
    if (
        src_delta_type in (INDEPENDENT_DELTA, DEPENDENT_DELTA)
        and abs(src_delta_val) <= 10
        and preloaded_mappings
    ):
        ahead_remote = field_wrap(
            preloaded_mappings[-1].remote + src_delta_val, use_range
        )
        results.append(NATMapping([from_range([2000, MAX_PORT]), 0, ahead_remote]))
        log("[NAT-PREDICT] R8-6: added one-ahead candidate remote={0} "
            "(delta={1})".format(ahead_remote, src_delta_val))

    # Drift-rate candidate: estimate ports/sec from the preload burst and
    # extrapolate forward to the punch fire (assume ~2s gap; conservative
    # since signal_rtt is usually ~1s and we add one for spread).  R8-6
    # adds a SINGLE one-delta-ahead slot; this adds a RATE-based slot
    # that scales with however long it actually takes to fire.  Only
    # meaningful for non-trivial allocation rates and reasonable preload
    # spans (no extrapolation from a single sample, no extrapolation
    # when t_preload_end - t_preload_start collapses to zero).
    if (
        src_delta_type in (INDEPENDENT_DELTA, DEPENDENT_DELTA, PRESERV_DELTA)
        and len(preloaded_mappings) >= 2
        and t_preload_start is not None
        and t_preload_end is not None
    ):
        dt = t_preload_end - t_preload_start
        if dt > 0.05:
            r_first = preloaded_mappings[0].remote
            r_last = preloaded_mappings[-1].remote
            drift_per_s = (r_last - r_first) / dt
            # Project forward by the typical inter-stage gap (~2s).
            drift_ahead = int(drift_per_s * 2.0)
            # Sanity-clamp to avoid extrapolating into nonsense for
            # noisy single-burst estimates: don't predict more than
            # +/- use_range/4 from last_remote.
            cap = max(2000, (use_range[1] - use_range[0]) // 4)
            if abs(drift_ahead) <= cap:
                drift_remote = field_wrap(r_last + drift_ahead, use_range)
                results.append(NATMapping(
                    [from_range([2000, MAX_PORT]), 0, drift_remote],
                ))
                log("[NAT-PREDICT] drift: rate={0:.0f}ports/s ahead={1} "
                    "remote={2}".format(drift_per_s, drift_ahead, drift_remote))

    # R11-3: ±1 jitter candidates for small-delta NATs (Wang2011 §3.3
    # found ~18% of consumer NATs add ±1-3 random jitter on top of a
    # dominant fixed delta; mode-delta is stable but individual allocation
    # can drift by one). Only when abs(delta) <= 2 to avoid over-expanding
    # the list for large-step allocators where ±1 is noise.
    if (
        src_delta_type == INDEPENDENT_DELTA
        and abs(src_delta_val) <= 2
        and results
    ):
        base_remote = results[0].remote
        results.append(NATMapping([from_range([2000, MAX_PORT]), 0,
                                   port_wrap(base_remote - 1)]))
        results.append(NATMapping([from_range([2000, MAX_PORT]), 0,
                                   port_wrap(base_remote + 1)]))
        log("[NAT-PREDICT] R11-3: added jitter candidates remote={0}+-1 "
            "(delta={1})".format(base_remote, src_delta_val))

    return results, preloaded_mappings


def self_punch_patch(mode, mappings, step=1000):
    """Offset local ports by step when punching to ourself to avoid port collisions."""
    if mode != TCP_PUNCH_SELF:
        return

    log("[NAT-PREDICT] self_punch_patch: shifting {0} mappings by step={1} "
        "(TCP_PUNCH_SELF same-machine port-collision avoidance)".format(
            len(mappings), step,
        ))
    for m in mappings:
        m.local = port_wrap(m.local + step)
        m.remote = m.local


def update_for_reply_ports(
mode,
    src_nat,
    dest_nat,
    preloaded_mappings,
    send_mappings,
    recv_mappings,
):
    """Adjust our local port predictions to satisfy the peer's reply port restrictions."""
    test_no = min(len(send_mappings), len(recv_mappings))
    use_range = nats_intersect(src_nat, dest_nat, test_no)
    # PRESERV joins the we-dictate set: its predictor branch no longer
    # follows the peer's bind_port, so re-running it here against the
    # peer's reply port would just produce another mapping in our own
    # adjacent-to-STUN-sample range -- not actually satisfying their
    # reply-port constraint.  Same for INDEPENDENT/DEPENDENT/RANDOM.
    bad_delta = [PRESERV_DELTA, INDEPENDENT_DELTA, DEPENDENT_DELTA, RANDOM_DELTA]

    # Update our local ports for port restricted NATs.
    log("[NAT-PREDICT] update_for_reply_ports enter src_delta={0} bad={1} "
        "test_no={2} send_before={3} recv={4}".format(
            (src_nat.get("delta") or {}).get("type"),
            (src_nat.get("delta") or {}).get("type") in bad_delta,
            test_no,
            [(m.local, m.reply, m.remote) for m in send_mappings],
            [(m.local, m.reply, m.remote) for m in recv_mappings],
        ))
    for i in range(0, test_no):
        # No NAT so reply ports don't apply.
        if mode == TCP_PUNCH_SELF:
            break

        # The update is to satisfy a port restricted NAT.
        # These NATs require a specific reply port.
        if not recv_mappings[i].reply:
            log("[NAT-PREDICT] update i={0} skip: recv reply=0".format(i))
            continue

        # We can satisfy their requirements.
        if src_nat["delta"]["type"] in bad_delta:
            log("[NAT-PREDICT] update i={0} skip: src delta in bad_delta".format(i))
            continue

        # preloaded_mappings has 3 entries from preload_mappings(3, ...)
        # but test_no can be up to 8 (the spray width).  nat_prediction's
        # main loop guards this with try/except IndexError; mirror that
        # here so update_for_reply_ports doesn't IndexError for i >= 3.
        try:
            per_iter_preload = preloaded_mappings[i]
        except IndexError:
            per_iter_preload = preloaded_mappings[0]

        # local, remote, reply, sock.
        mapping = get_single_mapping(
            mode,
            recv_mappings[i],
            preloaded_mappings[-1],
            use_range,
            src_nat,
            per_iter_preload,
            index=i,
        )

        # Update our local port.
        send_mappings[i].local = mapping.local
        send_mappings[i].remote = recv_mappings[i].reply
        log("[NAT-PREDICT] update i={0} -> local={1} remote={2} (from recv.reply)".format(
            i, send_mappings[i].local, send_mappings[i].remote,
        ))

    log("[NAT-PREDICT] update_for_reply_ports exit send_after={0}".format(
        [(m.local, m.reply, m.remote) for m in send_mappings],
    ))
    return send_mappings
