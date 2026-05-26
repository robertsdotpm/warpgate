"""Real-world Gate connector for the gate_sweep matrix runner.

Spins up a default Gate (no --nic, --ip, or --port pinning), calls
``gate.connect(peer.find(target), test_all_phases=True)`` so every
auto_connect phase runs serially regardless of which one wins first,
sends a PING and reads back the PONG.

Per-phase outcomes are picked up from the [AC-PHASE] log lines auto_connect
prints to stdout in test_all_phases mode. We additionally print:

    OUTCOME winner_plugin=<name|none>
    OUTCOME echo_ok=<true|false>
    OUTCOME echo_msg=<bytes-repr>

so the orchestrator can grep a single stable shape per iteration.
"""
import asyncio
import os
import sys
import time

from aionetiface import aionetiface_setup_event_loop, IP4, IP6
aionetiface_setup_event_loop()

sys.argv = [sys.argv[0]]

from warpgate.gate import Gate, peer
from warpgate.tools.sweep_utils import parse_afs as parse_afs_ints, first_msg


def parse_afs(env_value):
    """Parse WG_AFS to (IP4|IP6, ...) -- aionetiface constants, not ints."""
    ints = parse_afs_ints(env_value)
    if ints is None:
        return None
    return tuple((IP4 if v == 4 else IP6) for v in ints)


async def main():
    target = os.environ["WG_TARGET"]
    name = os.environ.get("WG_CONNECT_NAME") or None
    # Default 900s: test_all_phases runs every phase serially -- tcp_punch
    # plugin timeout is 180s, udp/spray 150s, turn 60s. With the phase loop
    # iterating route_types and AFs per phase, the worst-case serial budget
    # is multiples of those. 300s used to fire mid-cascade, dropping a
    # winner pipe phase1 had already produced. 900s is generous but covers
    # every realistic cumulative path.
    timeout = float(os.environ.get("WG_TIMEOUT", "900"))

    afs = parse_afs(os.environ.get("WG_AFS"))
    plugins_env = os.environ.get("WG_PLUGINS", "").strip()
    plugins = None
    if plugins_env:
        plugins = [p.strip() for p in plugins_env.split(",") if p.strip()]
    # WG_ROUTE_TYPES restricts the auto_connect cascade to a subset of
    # binding strategies -- comma-separated names from
    # {NIC_BIND, EXT_BIND, LOOPBACK_BIND}.  Gate.connect maps the names
    # to aionetiface constants and raises ValueError on typos.  Used by
    # the matrix harness to force EXT_BIND-only cross-WAN paths in
    # intra-VM 2-NIC iterations (the same_machine NIC_BIND combos
    # otherwise burn ~3-5s on Windows before falling through).
    route_types_env = os.environ.get("WG_ROUTE_TYPES", "").strip()
    route_types = None
    if route_types_env:
        route_types = [
            rt.strip() for rt in route_types_env.split(",") if rt.strip()
        ]
    # WG_NIC pins the connector to a single interface (see gate_listen).
    nic = os.environ.get("WG_NIC") or None
    nic_names = [nic] if nic else None
    async with (Gate(name=name, nic_names=nic_names) if name
                else Gate(nic_names=nic_names)) as gate:
        print("WG_CONNECTOR_READY: {0} afs={1} plugins={2} route_types={3}".format(
            gate.full_name or "?", afs, plugins, route_types,
        ), flush=True)
        link = await gate.connect(
            peer.find(target),
            test_all_phases=True,
            timeout=timeout,
            afs=afs,
            plugins=plugins,
            route_types=route_types,
        )
        if link is None:
            print("OUTCOME winner_plugin=none", flush=True)
            print("OUTCOME echo_ok=false", flush=True)
            return
        winner = type(link.pipe).__name__
        # The plugin name is informational here -- auto_connect's
        # [AC-PHASE] lines already disclose which plugin won. We
        # echo the underlying pipe class instead so the orchestrator
        # can sanity-check transport.
        print("OUTCOME winner_pipe={0}".format(winner), flush=True)
        ok = False
        msg = None
        # WG_HOLD_SECONDS: after the first echo, keep ping/ponging over
        # the same pipe for this many seconds and report exactly when
        # (if) it dies.  A one-shot echo cannot tell a durable pipe
        # from one that RSTs ~1s later -- this does.  Used to check
        # whether XP's tcpip.sys delayed RST kills the pipe after the
        # quick echo squeaks through.
        hold_s = float(os.environ.get("WG_HOLD_SECONDS", "0") or "0")
        try:
            async with link:
                await link.send(b"PING:gate_sweep")

                msg = await first_msg(link, timeout=10.0)
                ok = msg is not None and msg.startswith(b"PONG:")

                if ok and hold_s > 0:
                    t0 = time.monotonic()
                    rnd = 0
                    last_ok = 0.0
                    hold_err = None
                    while time.monotonic() - t0 < hold_s:
                        rnd += 1
                        try:
                            await link.send(
                                b"PING:hold-" + str(rnd).encode("ascii")
                            )
                            hm = await asyncio.wait_for(one(), timeout=10.0)
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:  # pylint: disable=broad-except
                            hold_err = repr(exc)
                            break
                        if hm is None or not hm.startswith(b"PONG:"):
                            hold_err = "bad-reply:{0}".format(hm)
                            break
                        last_ok = time.monotonic() - t0
                        await asyncio.sleep(1.0)
                    print(
                        "OUTCOME hold_target={0}s hold_rounds={1} "
                        "hold_last_ok={2:.1f}s hold_err={3}".format(
                            hold_s, rnd, last_ok, hold_err,
                        ),
                        flush=True,
                    )
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pylint: disable=broad-except
            print("OUTCOME echo_exc={0}".format(repr(exc)), flush=True)
        print("OUTCOME echo_ok={0}".format("true" if ok else "false"), flush=True)
        if msg is not None:
            print("OUTCOME echo_msg={0!r}".format(msg[:80]), flush=True)


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
