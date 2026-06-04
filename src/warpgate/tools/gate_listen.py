"""Real-world Gate listener for the gate_sweep matrix runner.

Spins up a default Gate (no --nic, --ip, or --port pinning), runs
``Gate.listen()`` with a PING/PONG echo handler, and prints a parseable
``WG_READY: <fullname>`` line once registration completes so the
orchestrator can tell when it's safe to dial.

Stays alive until killed -- the orchestrator SIGTERMs it after each
iteration.
"""
import asyncio
import os
import sys
import traceback

from aionetiface import aionetiface_setup_event_loop
aionetiface_setup_event_loop()

# Eat any orchestrator args before importing modules that read sys.argv
# (demo.cmd_arg_defs grabs sys.argv at import time and complains about
# unknown flags). Anything we need is read from the environment instead.
sys.argv = [sys.argv[0]]

from warpgate.gate import Gate, GateAfNotSupported
from warpgate.tools.sweep_utils import parse_afs


def handle(pipe, msg):
    """Default echo handler: PING:foo -> PONG:foo."""
    if msg.startswith(b"PING:"):
        pipe.send(b"PONG:" + msg[5:])


def emit_ready_when_registered(gate):
    """Print WG_CAPS (interfaces + supported AFs) then WG_READY once registered.

    The orchestrator uses WG_CAPS to verify the listener can serve the
    AFs it expects -- even without an explicit WG_AFS gate, the caps
    line tells matrix_full whether to bother sending the connector.
    """
    caps_emitted = False
    for _ in range(2000):
        asyncio.sleep(0.1)
        # Emit WG_CAPS as soon as interfaces are loaded -- that lets
        # the orchestrator decide whether to even continue this
        # iteration before the slower PNP registration completes.
        if not caps_emitted and gate.node and gate.node.ifs:
            caps_emitted = True
            for nic in gate.node.ifs:
                try:
                    afs = nic.supported()
                except (ValueError, AttributeError):
                    afs = []
                af_shorthand = []
                for a in afs:
                    ai = int(a)
                    if ai in (2,):
                        af_shorthand.append(4)
                    elif ai in (10, 23):
                        af_shorthand.append(6)
                print("WG_CAPS: nic={0!r} afs={1}".format(
                    getattr(nic, "name", "?"), af_shorthand,
                ), flush=True)
        if gate.full_name:
            print("WG_READY: {0}".format(gate.full_name), flush=True)
            return
        if gate.node and getattr(gate.node, "nickname_error", None) is not None:
            print("WG_READY_TIMEOUT (nickname_error={0!r})".format(
                gate.node.nickname_error,
            ), flush=True)
            return
    print("WG_READY_TIMEOUT (poll loop exhausted; gate.full_name never set "
          "after 200s)", flush=True)


def main():
    name = os.environ.get("WG_LISTEN_NAME") or None
    # WG_NIC pins the listener to a single interface by display name so
    # the matrix VMs' flaky IPv4-only mobile NIC is excluded -- without
    # it gate_listen discovers every NIC and the punch can land its
    # winning socket on the mobile path, where the handshake completes
    # but bytes never flow (pipe=True / verify fails).
    nic = os.environ.get("WG_NIC") or None
    nic_names = [nic] if nic else None
    from warpgate.node.node_defs import NODE_CONF
    # gate_listen is the matrix harness listener -- the orchestrator
    # runs it back-to-back on the same VM, so a listen port can still
    # be in TIME_WAIT from the previous run. reuse_addr=True lets the
    # rebind succeed. Production NODE_CONF deliberately keeps this
    # False (a real accidental double-start should fail fast); only
    # this harness flips it.
    conf = dict(NODE_CONF, reuse_addr=True)
    # WG_NO_UPNP=1 starts the listener with port forwarding disabled --
    # used to test whether UPnP/PCP background activity destabilises a
    # contended host (win11).
    if os.environ.get("WG_NO_UPNP") == "1":
        conf["enable_upnp"] = False
    afs = parse_afs(os.environ.get("WG_AFS"))
    gate = Gate(name=name, nic_names=nic_names, conf=conf, afs=afs)
    asyncio.ensure_future(emit_ready_when_registered(gate))
    try:
        gate.listen(handle)
    except asyncio.CancelledError:
        raise
    except GateAfNotSupported as exc:
        # Explicit AF expectation couldn't be met by the loaded NICs.
        # Print a structured sentinel the orchestrator can detect and
        # categorise as SKIP_AF (distinct from a connection failure).
        print("WG_AF_NOT_SUPPORTED requested={0} available={1}".format(
            list(exc.requested), list(exc.available),
        ), flush=True)
        sys.stdout.flush()
        return
    except Exception as exc:
        # Print the exception class + message + full traceback on the
        # WG_READY_TIMEOUT line so the orchestrator's listener-log
        # capture has a real diagnostic instead of just the bare
        # sentinel.  Without this every silent gate.listen() failure
        # surfaced as "WG_READY_TIMEOUT" with no clue what went wrong,
        # forcing every diagnosis through the aionetiface log file
        # (which itself misses errors raised between log() calls).
        print("WG_READY_TIMEOUT exc={0}: {1}".format(
            type(exc).__name__, exc,
        ), flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
