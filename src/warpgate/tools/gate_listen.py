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

from warpgate.gate import Gate


async def handle(pipe, msg):
    """Default echo handler: PING:foo -> PONG:foo."""
    if msg.startswith(b"PING:"):
        await pipe.send(b"PONG:" + msg[5:])


async def emit_ready_when_registered(gate):
    """Print the WG_READY sentinel once gate.full_name is populated."""
    for _ in range(2000):
        await asyncio.sleep(0.1)
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


async def main():
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
    gate = Gate(name=name, nic_names=nic_names, conf=conf)
    asyncio.ensure_future(emit_ready_when_registered(gate))
    try:
        await gate.listen(handle)
    except asyncio.CancelledError:
        raise
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
