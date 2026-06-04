"""
Validate warpgate's TURN client handshake as pure sync code on runloom.

A *full relay* test (peer -> relay -> peer) is not possible from one host:
you can't circuit a TURN relay back to yourself (coturn rejects same-WAN-IP
relay) and it needs a second peer anyway.  What IS testable -- and is the
protocol-critical part of "does the TURN client work" -- is the **handshake**
against a real TURN server: connect, send Allocate, receive the 401
long-term-credential challenge, parse REALM + NONCE, and compute the
credential key.  The final authed Allocate (relay address) needs valid
server credentials.

Uses the live public TURN server relay1.expressturn.com:3478 with throwaway
credentials, so it confirms the handshake up to the credential challenge.
Run: PYTHON_GIL=0 PYTHONPATH=<all repos' src> python3.13t this.py [hubs]
"""
import sys
import time
import traceback

import runloom_boot
runloom_boot.install()

from aionetiface import Interface, IP4  # noqa: E402
from warpgate.traversal.plugins.turn.turn_client import TURNClient  # noqa: E402
from warpgate.traversal.plugins.turn.turn_defs import TURN_ERROR_STOPPED  # noqa: E402
import runloom  # noqa: E402

TURN_SERVER = ("relay1.expressturn.com", 3478)
RESULTS = []


def check(name, fn):
    """Run one check, recording (name, ok, detail)."""
    t0 = time.time()
    try:
        RESULTS.append((name, True, fn(), round(time.time() - t0, 2)))
    except BaseException:
        RESULTS.append((name, False, traceback.format_exc(), round(time.time() - t0, 2)))


def check_turn_handshake():
    """TURN Allocate handshake against a real server (connect -> 401 -> creds)."""
    nic = Interface("default")
    c = TURNClient(IP4, TURN_SERVER, nic, auth=("runloom-probe", "runloom-probe"))
    try:
        c.start()
        # Protocol-critical client logic, exercised over the real network:
        assert c.turn_pipe is not None, "did not connect to the TURN server"
        assert c.realm is not None, "no REALM in the 401 challenge"
        assert c.nonce is not None and len(c.nonce) > 0, "no NONCE in the 401 challenge"
        assert c.key is not None, "long-term credential key not computed"
        relay = "yes" if c.relay_event.is_set() else "no (needs valid creds; no self-relay)"
        return "connect+Allocate+401(realm=%s)+nonce(%dB)+key ok; relay=%s" % (
            bytes(c.realm).decode("latin-1"), len(c.nonce), relay)
    finally:
        # Stop the allocation refresher goroutine so run() can return.
        c.set_state(TURN_ERROR_STOPPED)
        try:
            c.close()
        except Exception:
            pass


def report_and_exit():
    """Print results and exit.

    The TURN pipe's reader goroutine doesn't drain on close in the sync model
    (super_init shadows the pipe, so close() doesn't reach that reader), which
    would otherwise hold runloom.run() open.  The handshake we're validating is
    already complete by here, so we report and os._exit cleanly rather than
    wait on a teardown wrinkle that's orthogonal to "does the client work".
    """
    import os
    failed = 0
    for nm, ok, detail, secs in RESULTS:
        if ok:
            print("  PASS  %-18s %5.2fs  %s" % (nm, secs, detail))
        else:
            failed += 1
            print("  FAIL  %-18s %5.2fs" % (nm, secs))
            print("        " + detail.replace("\n", "\n        "))
    print("=== %d passed, %d failed ===" % (len(RESULTS) - failed, failed))
    sys.stdout.flush()
    os._exit(1 if failed else 0)


def main():
    """Run the TURN handshake check as plain sync code on the scheduler."""
    check("turn_handshake", check_turn_handshake)
    report_and_exit()


if __name__ == "__main__":
    hubs = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    print("=== warpgate TURN handshake: runloom_boot.run(main, hubs=%d) ===" % hubs)
    runloom_boot.run(main, hubs=hubs)
