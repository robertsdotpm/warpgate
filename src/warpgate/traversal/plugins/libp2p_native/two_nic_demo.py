"""Two-NIC demonstration: prove that two Libp2pNode instances bound
to DIFFERENT NICs on the same machine can complete the full libp2p
handshake and exchange application bytes through the plugin's
stack.

This is the Windows 10 cross-NIC validation the user asked for --
it doesn't go through the warpgate traversal cascade (no MQTT
signaling), it just exercises the libp2p TCP transport directly:

   NIC-A:  Libp2pNode listening on listen_ip:port
   NIC-B:  Libp2pNode dialing (listen_ip, port) via NIC-B's route

Run from a checkout root:

    python -m warpgate.traversal.plugins.libp2p_native.two_nic_demo \\
        --listen-ip 10.0.1.199 --dial-ip 20.0.0.26

If both NICs are dual-stack the same script works for v6 too:

    python -m warpgate.traversal.plugins.libp2p_native.two_nic_demo \\
        --listen-ip fe80::1%Ethernet0 --dial-ip fe80::2%Ethernet1 --af 6

On exit the script prints PASS / FAIL + the message contents to
stdout so a one-liner SSH harness can grep "PASS".
"""
import argparse
import asyncio
import sys
import traceback

from aionetiface import IP4, IP6, Interface
from aionetiface.entrypoint import aionetiface_setup_event_loop

from .node_core import Libp2pNode
from .peer_id import Identity
from .pipe_adapter import LibP2PPipeAdapter


PASS_MSG = b"libp2p-two-nic-ok"
ECHO_PREFIX = b"echo:"


async def run_demo(listen_ip, dial_ip, af, listen_iface_name, dial_iface_name,
                   port=0, timeout=15.0):
    """Run the full cross-NIC demo; return True iff the round-trip succeeds."""
    print("two_nic_demo: starting", flush=True)

    listen_iface = await Interface(listen_iface_name) if listen_iface_name else await Interface()
    dial_iface = await Interface(dial_iface_name) if dial_iface_name else listen_iface
    print("two_nic_demo: listener iface =", listen_iface.name, flush=True)
    print("two_nic_demo: dialer iface   =", dial_iface.name, flush=True)

    id_listen = Identity.generate()
    id_dial = Identity.generate()
    node_listen = Libp2pNode(id_listen)
    node_dial = Libp2pNode(id_dial)

    success = False
    try:
        bound_ip, bound_port = await node_listen.listen(
            listen_iface, af, ips=listen_ip, port=port,
        )
        print("two_nic_demo: listener bound on", bound_ip, "port", bound_port, flush=True)

        # Dialer binds locally on its own NIC IP so the source
        # address of the SYN actually leaves dial_iface.  Without
        # this the kernel picks whatever route the host's default
        # routing table maps to bound_ip -- which on dual-NIC
        # hosts can be the WRONG NIC and the cross-NIC validity
        # claim falls flat.
        route = await dial_iface.route(af).bind(ips=dial_ip, port=0)
        print("two_nic_demo: dialer route bound on", dial_ip, flush=True)

        dial_task = asyncio.ensure_future(node_dial.dial(
            bound_ip, bound_port, route,
            expected_peer_id=id_listen.peer_id,
            timeout=timeout,
        ))
        inbound_task = asyncio.ensure_future(asyncio.wait_for(
            node_listen.inbound_streams.get(), timeout=timeout,
        ))
        d_stream, d_remote, d_session = await dial_task
        l_stream, l_remote, l_session = await inbound_task
        print("two_nic_demo: handshakes complete", flush=True)
        print("two_nic_demo: dialer sees peer_id  =", d_remote.hex()[:16], flush=True)
        print("two_nic_demo: listener sees peer_id =", l_remote.hex()[:16], flush=True)

        # Verify mutual peer-id matches.
        if d_remote != id_listen.peer_id:
            print("two_nic_demo: dialer's view of listener peer_id MISMATCH", flush=True)
            return False
        if l_remote != id_dial.peer_id:
            print("two_nic_demo: listener's view of dialer peer_id MISMATCH", flush=True)
            return False

        # Exchange a known message through the LibP2PPipeAdapter so
        # we also exercise the Pipe-shape surface, which is what the
        # warpgate cascade hands to user code.
        dial_adapter = LibP2PPipeAdapter(d_stream, d_session, d_remote)
        listen_adapter = LibP2PPipeAdapter(l_stream, l_session, l_remote)

        await dial_adapter.send(PASS_MSG)
        msg_at_listener = await asyncio.wait_for(listen_adapter.recv(), timeout=5)
        print("two_nic_demo: listener received:", msg_at_listener, flush=True)
        if msg_at_listener != PASS_MSG:
            print("two_nic_demo: payload mismatch on listener side", flush=True)
            return False

        await listen_adapter.send(ECHO_PREFIX + PASS_MSG)
        msg_at_dialer = await asyncio.wait_for(dial_adapter.recv(), timeout=5)
        print("two_nic_demo: dialer received:", msg_at_dialer, flush=True)
        if msg_at_dialer != ECHO_PREFIX + PASS_MSG:
            print("two_nic_demo: payload mismatch on dialer side", flush=True)
            return False

        success = True
        await dial_adapter.close()
        await listen_adapter.close()
    finally:
        await node_dial.close()
        await node_listen.close()

    return success


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--listen-ip", required=True,
                   help="local IP to bind the listener on (e.g. 10.0.1.199)")
    p.add_argument("--dial-ip", required=True,
                   help="local IP to bind the dialer's source on (e.g. 20.0.0.26)")
    p.add_argument("--listen-iface", default=None,
                   help='Interface name for the listener (e.g. "Ethernet0"); '
                        'omit for the default')
    p.add_argument("--dial-iface", default=None,
                   help='Interface name for the dialer (e.g. "Ethernet1"); '
                        'omit for the default')
    p.add_argument("--af", type=int, default=4, choices=(4, 6),
                   help="address family: 4 or 6 (default 4)")
    p.add_argument("--port", type=int, default=0,
                   help="listener port (default 0 = ephemeral)")
    p.add_argument("--timeout", type=float, default=15.0)
    args = p.parse_args(argv)

    af = IP4 if args.af == 4 else IP6

    aionetiface_setup_event_loop()
    loop = asyncio.get_event_loop()
    try:
        ok = loop.run_until_complete(run_demo(
            args.listen_ip, args.dial_ip, af,
            args.listen_iface, args.dial_iface,
            port=args.port, timeout=args.timeout,
        ))
    except Exception:
        traceback.print_exc()
        print("two_nic_demo: FAIL (exception)", flush=True)
        return 2
    print("two_nic_demo: " + ("PASS" if ok else "FAIL"), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
