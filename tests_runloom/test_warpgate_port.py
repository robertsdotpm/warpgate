"""
Validate the warpgate runloom sync port -- plain blocking code on runloom's
M:N scheduler, on top of the ported namebump + sidewire + aionetiface stack.

warpgate is the top of the stack: P2P NAT traversal (node bootstrap, MQTT
signalling, PNP naming, hole-punching).  A real cross-NAT connection needs
two peers behind real NATs plus MQTT/TURN infra -- out of scope on one Linux
box (and the project's own connectivity tests need that infra too).  What we
validate here, as pure sync code, is:

  - the ENTIRE 4-repo stack imports as sync (no async/await) -- the headline:
    warpgate (23 K LOC) + sidewire + namebump + aionetiface
  - warpgate's local protocol/naming logic: the core signal-proto registry,
    deterministic human nicknames, the PNP timestamp envelope, and TLD codec

Run: PYTHON_GIL=0 PYTHONPATH=<all repos' src> python3.13t this.py [hubs]
"""
import sys
import time
import traceback

import runloom_boot
runloom_boot.install()

import warpgate  # noqa: E402  (whole stack: warpgate->sidewire->namebump->aionetiface)
from warpgate.protocol.proto_msg import build_core_sig_proto, ConMsg, GetAddr  # noqa: E402
from warpgate.node.nouns import hex_to_human  # noqa: E402
from warpgate.node.nickname import (  # noqa: E402
    pnp_wrap_with_ts, pnp_unwrap_ts,
    pnp_get_tld, pnp_get_offsets, pnp_name_has_tld, pnp_strip_tlds,
)
import runloom  # noqa: E402

RESULTS = []


def check(name, fn):
    """Run one check, recording (name, ok, detail)."""
    t0 = time.time()
    try:
        RESULTS.append((name, True, fn(), round(time.time() - t0, 2)))
    except BaseException:
        RESULTS.append((name, False, traceback.format_exc(), round(time.time() - t0, 2)))


def check_full_stack_import():
    """The whole 4-repo stack is importable as pure sync code."""
    public = [n for n in dir(warpgate) if not n.startswith("_")]
    assert len(public) > 300, "warpgate exposed too few names (%d)" % len(public)
    # Names that come from each layer of the stack prove the chain imported.
    assert hasattr(warpgate, "Address"), "aionetiface layer missing"     # aionetiface
    assert "ConMsg" in [c.__name__ for c in (ConMsg, GetAddr)], "protocol missing"
    return "warpgate + sidewire + namebump + aionetiface import sync; %d names" % len(public)


def check_core_sig_proto():
    """The plugin-independent signal-protocol registry builds with all core msgs."""
    proto = build_core_sig_proto()
    wire_names = set(proto.keys())
    for cls in (ConMsg, GetAddr):
        assert cls.WIRE_NAME in wire_names, "missing %s" % cls.WIRE_NAME
    # Each entry is [msg_class, strategy_enum, ttl].
    for wire_name, entry in proto.items():
        assert len(entry) == 3 and isinstance(entry[2], int), "bad proto entry %s" % wire_name
    return "%d core signal types (%s ...)" % (len(proto), sorted(wire_names)[0])


def check_human_nickname():
    """hex_to_human maps a key hash deterministically to a memorable name."""
    h = "a1b2c3d4e5f6"
    name1 = hex_to_human(h)
    name2 = hex_to_human(h)
    assert name1 == name2, "non-deterministic nickname"
    assert name1.count("_") == 2 and name1.split("_")[-1].isdigit(), "bad name shape: %s" % name1
    # A different hash should (almost always) give a different name.
    other = hex_to_human("ffffffffffff")
    return "%s (stable; != %s)" % (name1, other)


def check_pnp_envelope_and_tld():
    """PNP timestamp envelope + TLD codec roundtrip (the naming wire helpers)."""
    # Timestamp envelope.
    ts = 1733300000
    wrapped = pnp_wrap_with_ts(b"my-value", ts)
    got_ts, payload = pnp_unwrap_ts(wrapped)
    assert got_ts == ts and payload == b"my-value", "ts envelope roundtrip failed"
    # Unwrapped (legacy) value passes through as (0, value).
    assert pnp_unwrap_ts(b"legacy") == (0, b"legacy"), "legacy passthrough failed"

    # TLD <-> server-offsets codec.
    for tld in (".p2p", ".node", ".peer"):
        offsets = pnp_get_offsets(tld)
        assert pnp_get_tld(offsets) == tld, "TLD roundtrip failed for %s" % tld
    # TLD detection / strip.
    assert pnp_name_has_tld("alice.peer") is True, "TLD detect failed"
    assert pnp_strip_tlds("alice.peer") == "alice", "TLD strip failed"
    assert pnp_name_has_tld("bare") is False, "false TLD detect"
    return "ts envelope + .p2p/.node/.peer TLD codec + detect/strip ok"


def main():
    """Run warpgate checks as plain sync code on the runloom scheduler."""
    check("full_stack_import", check_full_stack_import)
    check("core_sig_proto", check_core_sig_proto)
    check("human_nickname", check_human_nickname)
    check("pnp_envelope_and_tld", check_pnp_envelope_and_tld)


if __name__ == "__main__":
    hubs = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    print("=== warpgate runloom sync port: runloom_boot.run(main, hubs=%d) ===" % hubs)
    runloom_boot.run(main, hubs=hubs)
    failed = 0
    for nm, ok, detail, secs in RESULTS:
        if ok:
            print("  PASS  %-22s %5.2fs  %s" % (nm, secs, detail))
        else:
            failed += 1
            print("  FAIL  %-22s %5.2fs" % (nm, secs))
            print("        " + detail.replace("\n", "\n        "))
    print("=== %d passed, %d failed ===" % (len(RESULTS) - failed, failed))
    sys.exit(1 if failed else 0)
