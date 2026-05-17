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
            print("WG_READY_TIMEOUT", flush=True)
            return
    print("WG_READY_TIMEOUT", flush=True)


async def main():
    name = os.environ.get("WG_LISTEN_NAME") or None
    # WG_NIC pins the listener to a single interface by display name so
    # the matrix VMs' flaky IPv4-only mobile NIC is excluded -- without
    # it gate_listen discovers every NIC and the punch can land its
    # winning socket on the mobile path, where the handshake completes
    # but bytes never flow (pipe=True / verify fails).
    nic = os.environ.get("WG_NIC") or None
    nic_names = [nic] if nic else None
    gate_kwargs = {"name": name, "nic_names": nic_names}
    # WG_NO_UPNP=1 starts the listener with port forwarding disabled --
    # used to test whether UPnP/PCP background activity destabilises a
    # contended host (win11).
    if os.environ.get("WG_NO_UPNP") == "1":
        from warpgate.node.node_defs import NODE_CONF
        gate_kwargs["conf"] = dict(NODE_CONF, enable_upnp=False)
    gate = Gate(**gate_kwargs)
    asyncio.ensure_future(emit_ready_when_registered(gate))
    try:
        await gate.listen(handle)
    except asyncio.CancelledError:
        raise
    except Exception:
        print("WG_READY_TIMEOUT", flush=True)


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
