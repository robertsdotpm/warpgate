"""Sliding-window boundary analysis for port prediction."""
import time
import random
from aionetiface.utility.utils import log

from .punch_defs import CONNECT_TIMEOUT, RETRY_INTERVAL

# --- Time Rendezvous Constants ---
# WINDOW must be > 2 * MAX_CLOCK_ERROR (2 * 20 = 40) to guarantee both hosts
# select the same time bucket/boundary despite the clock offset.
WINDOW = 42
MAX_CLOCK_ERROR = 20  # The known max clock difference (1-20s)
MIN_RUN_WINDOW = 10  # Minimum time required to run setup before the rendezvous
# NUM_PORTS = number of source-port SYNs each side fires at the peer's
# single predicted dest port. Higher N = more chances to converge when
# port prediction has any error (e.g. XP's non-monotonic ephemeral
# allocator producing wider mapping spread). 16 was the historical
# value before db0c676 (which dropped to 2 nominally but kept punch_client
# pinned at hardcoded n=16 -- so the live spray was 16 the whole time).
# When 2a36880 removed the hardcode, NUM_PORTS=2 actually took effect
# and broke XP tcp_punch. Bumping back to 16 restores what was
# empirically working before. XP's 10-half-open cap (Tcpip Event 4226)
# matters per *instant*, but with the 5 ms spray cadence the SYNs are
# staggered over ~75 ms; combined with sub-second SYN turnaround on
# LAN-routed traffic, the kernel keeps the in-flight half-open count
# bounded well below 16 at any single moment.
NUM_PORTS = 16
BASE_PORT = 2024

# Plugin path NTP-pin offset: when tcp_punch runs as a traversal plugin
# (auto_connect cascade), the connector picks an absolute punch moment
# `now + PLUGIN_PIN_OFFSET` and ships it inside the outgoing PunchMsg.
# The listener reads the value back out of `payload.ntp` and uses it
# verbatim, so both peers fire on the same wall-clock instant without
# any bucket math. The floor is bounded by signal RTT through MQTT
# (~300-600 ms on healthy paths) plus listener setup (socket binds +
# NAT predict, ~200 ms). 1.0 s leaves slack; reduce toward ~0.5 s
# once measured variance allows.
#
# This constant has NO effect on the CLI standalone path
# (`punch_client.py` __main__): that path keeps the compute_rendezvous
# bucket math because there's no PunchMsg exchange to communicate a
# pinned time -- both sides must derive it independently from NTP.
PLUGIN_PIN_OFFSET = 1.0

# Predictor-path NTP-pin offset.  PLUGIN_PIN_OFFSET above is sized for
# the boundary-allocator fast path, where the listener does ZERO STUN
# between receiving the PunchMsg and firing -- just build the
# PunchClient and bind sockets (~few hundred ms).  When either NAT has
# a non-deterministic delta (INDEPENDENT / DEPENDENT / RANDOM /
# PRESERV) boundary_port_alloc is skipped and the punch relies on the
# STUN NAT predictor: the listener must run preload_mappings (3 STUN
# round trips) plus get_single_mapping before it can fire.  That work
# does not fit inside PLUGIN_PIN_OFFSET, so the predictor path uses a
# larger offset.  3.0 s covers signal RTT + 3 concurrent STUN RTTs +
# prediction compute + socket binds with margin; tune from measured
# [PUNCH-STAGE] run_enter -> run_engine_enter spans on real
# predictor-path punches rather than guessing further.
PLUGIN_PIN_OFFSET_PREDICT = 3.0
# Wider sample space than the original 20000 -- combined with the lower
# BASE_PORT this gives the allocator the full user-port range (~2k-52k),
# which makes collisions across back-to-back runs in the same NTP bucket
# significantly less likely.
PORT_RANGE = 50000
# Slack added on top of worst-case rendezvous wait (window +
# max_clock_error) to produce the max_sleep cap.  max_sleep is the
# upper bound on sleep_until()'s blocking wait -- it must sit above
# the worst-case legitimate rendezvous wait, otherwise sleep_until
# returns early and the punch fires before the peer is ready (see
# punch_client.py for the "may fire before peer is ready" warning).
# The 2 s slack covers OS scheduler jitter on top of the worst case.
MAX_SLEEP_SLACK = 2
LARGE_PRIME = 2654435761


def derive_max_sleep(window, max_clock_error, slack=MAX_SLEEP_SLACK):
    """Return the max_sleep cap derived from a profile's bucket params.

    Keeping max_sleep tied to (window, max_clock_error) instead of a
    free parameter prevents the silent class of bug where a profile
    shrinks its bucket size without updating max_sleep -- the result
    is a cap below the worst-case rendezvous wait, sleep_until fires
    early, and punches misfire with the only visible signal being the
    cap-fired log line.
    """
    return window + max_clock_error + slack

# Ports that SIP-ALG and RTP helper modules on SOHO routers (Asus,
# Linksys, MikroTik) may silently inspect, mangle, or redirect.
# stable_ports() re-samples when the bucket RNG lands on one of
# these so they never appear in the spray set.
SIP_ALG_BLACKLIST = frozenset(
    [5060, 5061] + list(range(10000, 20001))
)
# --------------------------

# --------------------------
# --- Punch Parameter Presets ---
#
# DEFAULT_PUNCH_PARAMS: Robust conservative values for CLI / standalone usage.
#   - Large WINDOW (42 s) and MAX_CLOCK_ERROR (20 s) tolerate poor NTP sync.
#   - Rendezvous wait: 10–52 seconds worst-case.
#
# FAST_PUNCH_PARAMS: Tight values for network-protocol usage where punch_time
#   is communicated between peers so both sides use the exact same value.
#   Constraint: window > 2 * max_clock_error.
#   - max_sleep is derived from derive_max_sleep(window, max_clock_error)
#     post dict-build, so any profile that shrinks the bucket params
#     automatically gets the correct cap (sleep_until needs max_sleep
#     above the worst-case rendezvous wait or it returns early before
#     the bucket boundary and the punch misfires).
# --------------------------

DEFAULT_PUNCH_PARAMS = {
    # Time rendezvous
    "window": WINDOW,  # 42 s
    "max_clock_error": MAX_CLOCK_ERROR,  # 20 s
    "min_run_window": MIN_RUN_WINDOW,  # 10 s
    # Engine timing
    "connect_timeout": CONNECT_TIMEOUT,  # 5.0 s spray window
    "monitor_timeout": CONNECT_TIMEOUT,  # 5.0 s monitor window
    "retry_interval": RETRY_INTERVAL,  # 0.05 s selector poll interval
    # PunchClient / plugin timing -- max_sleep is filled in below from
    # derive_max_sleep(window, max_clock_error) so a profile change to
    # the bucket params can't leave the cap behind.
    # Timeout (seconds) the plugin will wait for the peer's mapping
    # reply future to resolve before spawning the punch worker anyway.
    # Replaces an unconditional sleep -- the plugin now sets the future
    # the moment the peer's mappings arrive and advance_punching_protocol
    # has folded them into puncher.port_allocs, so the worker normally
    # starts the instant the mappings land.  reply_delay is the fallback
    # ceiling for the pathological case where the peer's signal is
    # dropped or delayed past this many seconds; the worker proceeds
    # with whatever port_allocs are already in the puncher.
    "reply_delay": 2.0,
}
DEFAULT_PUNCH_PARAMS["max_sleep"] = derive_max_sleep(
    DEFAULT_PUNCH_PARAMS["window"], DEFAULT_PUNCH_PARAMS["max_clock_error"],
)

FAST_PUNCH_PARAMS = {
    # Time rendezvous — sized for SysClock-quorum'd peers.  Both sides
    # compute punch_time through SysClock (NTP-quorum-backed) so peer-
    # to-peer skew is the residual error in the quorum result --
    # typically sub-second on modern OSes.  XP cross-NAT tcp_punch is
    # routed away (see XP RST CLAUDE note), so only intra-LAN XP-
    # punch passes through these params, where peer clocks usually
    # share an upstream and fall well inside max_clock_error=4.
    # Constraint: window > 2 * max_clock_error  →  4 > 2 ✓; tight
    # profile sized for SysClock-quorum'd peers where peer-to-peer
    # skew is sub-second.  Worst-case rendezvous wait =
    # window + max_clock_error = 5 s (down from 14 s).  Previously
    # reverted to 10/4 when sub-2s pre-bucket bailouts were
    # appearing -- those turned out to be a NameError in the
    # re-entry guard (fstr not imported, fixed in edde6f3), not a
    # genuine bailout firing, so this profile is safe again.
    # Tightest profile: window=3 is the minimum given max_clock_error=1
    # (constraint window > 2 * max_clock_error -> 3 > 2 ✓).  Worst-case
    # rendezvous wait = window + max_clock_error = 4s, average wait
    # ~2.5s (with min_run_window=1 below).
    "window": 3,
    "max_clock_error": 1,
    # min_run_window=10 was inherited from DEFAULT_PUNCH_PARAMS, which
    # sized it for *manual CLI* usage where a human types ssh commands
    # on two machines and needs ~10s of slack to start both sides.
    # Network-protocol invocation completes setup in <1s after PunchMsg
    # arrives -- 10s is wildly conservative and was the actual cause of
    # the bucket-fork failures we saw (~5% sweep flake): two peers with
    # NTP-correct clocks 0.79s apart straddled the 10s "skip to next
    # bucket" threshold, one bumped, the other didn't, and they ended
    # up firing 42s apart on different ports.  Dropping to 3 s shrinks
    # the fork window from 10/42=24% of every bucket transition to
    # 3/42=7%; together with the small absolute setup cost (~100 ms
    # for socket binds) this is comfortably enough headroom.
    # Back to 3 s now that NUM_PORTS=8 restores XP convergence margin.
    # The 3 -> 10 revert earlier was a guess at fixing XP; the real
    # cause was NUM_PORTS dropping from 16 to 2 (db0c676 + 2a36880).
    # 3 s wins back the original sweep-flake reduction (bucket-fork
    # window 3/42 = 7% vs 10/42 = 24% per bucket transition).
    # Drop to 1 s with the smaller window=4 profile: skip path adds
    # exactly window=4s every fire, and at min_run_window=3 the skip
    # rate is 75% (3/4) -> avg rendezvous wait ~5.4s.  At
    # min_run_window=1 skip rate drops to 25% (1/4) -> avg rendezvous
    # wait drops by ~2.25s.  Safe given SysClock-NTP-quorum'd peers
    # have sub-second skew well below 1s.
    "min_run_window": 1,
    # Engine timing — bumped from 2.0 to 3.0 each after the matrix sweep
    # showed udp_punch flaking on busy hosts. With 18 sockets each spraying
    # at 50 Hz the connector saw only 1/18 of expected PROBEs back -- the
    # asyncio executor thread couldn't keep up with the 2 s window under
    # MQTT broker churn + plugin coordination chatter. 3 s gives ~50%
    # headroom on both directions, still well below DEFAULT_PUNCH_PARAMS's
    # 5.0 s and well within plugin's 30/40 s timeout.
    # Tightest profile: spray runs full window, monitor early-exits at
    # 50ms grace on first ESTABLISHED so monitor_timeout is the
    # fail-fast ceiling on a non-converging punch.  1.5s spray gives
    # both peers a tight overlap window for simul-open SYN exchange;
    # may flake on slow stacks (older Windows, BSD with high jitter)
    # where convergence trails into the second half-second.  If sweep
    # regressions appear, bump connect_timeout back to 3.0 first.
    "connect_timeout": 1.5,  # 1.5 s spray window (tightened from 3.0)
    "monitor_timeout": 1.5,  # 1.5 s fail-fast ceiling (was 3.0)
    "retry_interval": 0.05,  # 0.05 s selector poll interval (unchanged)
    # PunchClient / plugin timing -- max_sleep is filled in below from
    # derive_max_sleep(window, max_clock_error).
    # See DEFAULT_PUNCH_PARAMS above for the role of reply_delay; this
    # is the fast-profile fallback ceiling.  Mostly a guard against a
    # signal that never arrives -- on a healthy run the mapping-reply
    # future resolves well below this and the worker spawns immediately.
    #
    # Bumped from 2 to 2.8 because mapping_reply is now only resolved
    # AFTER recv_mappings has been folded (see main.py
    # advance_punching_protocol).  Observed signal_rtt on the
    # mobile<->LAN predictor path is 1.4-2.0s; the 2.0s ceiling
    # cut into legitimate late replies and made the worker spawn
    # with un-updated port_allocs.  2.8s gives ~0.8s of slack on a
    # 2.0s rtt while staying safely under PLUGIN_PIN_OFFSET_PREDICT
    # (3.0s) so the worker still spawns BEFORE punch_time.
    "reply_delay": 2.8,
}
FAST_PUNCH_PARAMS["max_sleep"] = derive_max_sleep(
    FAST_PUNCH_PARAMS["window"], FAST_PUNCH_PARAMS["max_clock_error"],
)


def now_from_network(network_timer, network_time):
    """Returns the current Unix timestamp aligned to the NTP reference."""
    elapsed = time.monotonic() - network_timer
    return network_time + int(elapsed)


def quantized_bucket(now, window=WINDOW, max_error=MAX_CLOCK_ERROR):
    """
    Calculates the time bucket number, robust against clock offsets.
    By subtracting the max error, we shift the timeline so that both hosts,
    regardless of their actual time offset, fall into the same integer bucket.
    """
    return int((now - max_error) // window)


def stable_boundary(bucket):
    """
    Deterministic boundary stable against small clock offsets, used as PRNG seed.
    """
    return (bucket * LARGE_PRIME) % 0xFFFFFFFF


def stable_ports(
boundary,
    num_ports=NUM_PORTS,
    base_port=BASE_PORT,
    port_range=PORT_RANGE,
):
    """
    Deterministic, smooth port selection using PRNG seeded by boundary.
    """
    rng = random.Random(boundary)
    ports = set()
    while len(ports) < num_ports:
        port = base_port + rng.randint(0, port_range - 1)
        if port not in SIP_ALG_BLACKLIST:
            ports.add(port)

    return sorted(ports, reverse=True)


# Per-OS port pool for the bucket allocator. The os_token is whatever
# the platform module emitted on the peer (e.g. "Windows-XP",
# "Windows-10", "Linux-5.10.0", "Darwin-22.1.0"). Match by substring so
# we don't have to enumerate every possible release string.
#
# The motivating case is Windows XP. XP's NAT classification is run from
# its normal ephemeral allocator (1025-5000); the FULL_CONE+EQUAL_DELTA
# reading we get back is only valid for sources in that range. The
# default bucket pool (BASE_PORT=2024, PORT_RANGE=50000) picks ports up
# to 52023, well outside XP's classified range -- the router NAT then
# behaves differently than the classifier observed (different mapping
# strategy, sometimes silently rewrites the source port), so the
# external port the peer is told to connect to is wrong and tcp_punch's
# simultaneous-open never converges. Pinning XP's allocator to its
# 1025-5000 pool keeps the bind ports in the range the classifier
# actually validated.
DEFAULT_PORT_POOL = (BASE_PORT, PORT_RANGE)
WINXP_PORT_POOL = (1025, 5000 - 1025 + 1)  # 1025..5000


def port_pool_for_os(os_token):
    """Return (base_port, port_range) for the bucket allocator for os_token.

    os_token is the platform.system()+'-'+platform.release() string the
    peer advertised (or None if the peer didn't ship one). Match by
    substring so unknown future releases of the same OS family route
    to the right pool. Returns DEFAULT_PORT_POOL on unknown OS or None.
    """
    if not os_token:
        return DEFAULT_PORT_POOL
    if "XP" in os_token:
        return WINXP_PORT_POOL
    if "2000" in os_token and "Windows" in os_token:
        return WINXP_PORT_POOL
    return DEFAULT_PORT_POOL


def compute_rendezvous(
now,
    window=WINDOW,
    min_run_window=MIN_RUN_WINDOW,
    max_error=MAX_CLOCK_ERROR,
):
    """
    Computes the current time bucket and the rendezvous time (start of the NEXT bucket).
    """
    # 1. Determine the current, shared bucket
    bucket = quantized_bucket(now, window, max_error)

    # 2. Calculate the start of the *next* bucket's valid time window.
    # The rendezvous time is the start of the (bucket + 1) window.
    rendezvous_time = (bucket + 1) * window + max_error

    # 3. Check if there's enough time left for setup.
    # If not, skip to the following bucket.
    if (rendezvous_time - now) < min_run_window:
        bucket += 1
        rendezvous_time = (bucket + 1) * window + max_error
        log("min run window being applied -- next bucket window")

    return bucket, rendezvous_time
