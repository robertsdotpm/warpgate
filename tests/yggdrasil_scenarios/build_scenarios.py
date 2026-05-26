"""Record canonical yggdrasil packet flows into JSON scenarios.

Run once with deterministic seeds to generate every
``scenario_*.json`` in this directory.  The scenarios are then
committed and used by ``test_yggdrasil_scenarios.py`` to drive
replay tests that exercise the protocol without any real I/O.

The seeds are PINNED so the resulting wire bytes are exactly
reproducible run-to-run.  If you change a seed, every scenario
file regenerates with new bytes.  If you change the protocol's
on-wire format, regenerate the scenarios (this script is the
single source of truth -- delete + re-run, don't hand-edit
the JSON).

Run::

    cd /home/x/projects/warpgate
    ~/.pyenv/versions/3.5.10/bin/python tests/yggdrasil_scenarios/build_scenarios.py

Scenarios produced:
  - 01_version_metadata_handshake.json
  - 02_handshake_then_keepalive.json
  - 03_handshake_then_sig_req.json
  - 04_handshake_then_announce.json
  - 05_handshake_then_traffic.json
  - 06_handshake_then_bloom.json
  - 07_handshake_then_path_lookup.json
  - 08_handshake_then_path_notify.json
  - 09_handshake_then_path_broken.json
  - 10_full_session_init_exchange.json
  - 11_session_init_then_traffic.json
  - 12_multicast_beacon.json
"""
import asyncio
import binascii
import json
import os
import sys
import time

sys.path.insert(0, "/home/x/projects/aionetiface/src")
sys.path.insert(0, "/home/x/projects/warpgate/src")
sys.path.insert(0, "/home/x/projects/namebump/src")
sys.path.insert(0, "/home/x/projects/sidewire/src")

from aionetiface.testing import aionetiface_setup_event_loop
aionetiface_setup_event_loop()

from warpgate.overlay.yggdrasil.address import addr_for_key, ipv6_str_from_bytes
from warpgate.overlay.yggdrasil.encrypted import (
    SESSION_TYPE_INIT, SESSION_TYPE_ACK, SESSION_TYPE_TRAFFIC,
    SessionInit, derive_box_keys_from_ed_seed,
)
from warpgate.overlay.yggdrasil.multicast import MulticastAdvertisement
from warpgate.overlay.yggdrasil.node_core import derive_pubkey
from warpgate.overlay.yggdrasil.peer_link import (
    handshake_over_transport,
    open_outbound_transport,
    open_inbound_transport,
    PeerLink,
)
from warpgate.overlay.yggdrasil.routing_msgs import (
    BLOOM_FILTER_U, Bloom, PathBroken, PathLookup, PathNotify,
    PathNotifyInfo, RouterAnnounce, RouterSigReq, RouterSigRes,
    Traffic,
)
from warpgate.overlay.yggdrasil.router_active import sign
from warpgate.overlay.yggdrasil.simulation import ScenarioRecorder
from warpgate.overlay.yggdrasil.transport import loopback_pair
from warpgate.overlay.yggdrasil.version import (
    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR, VersionMetadata,
)
from warpgate.overlay.yggdrasil.wire import (
    WIRE_KEEP_ALIVE, WIRE_PROTO_ANNOUNCE, WIRE_PROTO_BLOOM_FILTER,
    WIRE_PROTO_PATH_BROKEN, WIRE_PROTO_PATH_LOOKUP,
    WIRE_PROTO_PATH_NOTIFY, WIRE_PROTO_SIG_REQ, WIRE_PROTO_SIG_RES,
    WIRE_TRAFFIC, encode_uvarint,
)


# Pinned seeds for reproducibility -- A and B are distinct
# 32-byte identities used across every scenario in this directory.
SEED_A_HEX = "11" * 32
SEED_B_HEX = "22" * 32
SEED_A = binascii.unhexlify(SEED_A_HEX)
SEED_B = binascii.unhexlify(SEED_B_HEX)
PUB_A = derive_pubkey(SEED_A)
PUB_B = derive_pubkey(SEED_B)


SCENARIOS_DIR = os.path.dirname(os.path.abspath(__file__))


def frame_metadata(actor_seed, password=b"", priority=0):
    """Build a deterministic handshake wire payload for an actor.

    Unlike a real handshake which embeds a timestamp / nonce, we
    pin both to 0 for byte-stable scenario files.  The signature
    over blake2b-keyed(password)(pubkey) is deterministic given
    the same inputs.
    """
    meta = VersionMetadata(
        major_ver=PROTOCOL_VERSION_MAJOR,
        minor_ver=PROTOCOL_VERSION_MINOR,
        public_key=derive_pubkey(actor_seed),
        priority=priority,
    )
    return meta.encode(actor_seed, password=password)


def framed_packet(packet_type, payload):
    """Wrap a payload in the post-handshake [varint usize][type][payload] frame."""
    body = bytes([packet_type]) + bytes(payload)
    return encode_uvarint(len(body)) + body


def write_scenario(filename, scenario):
    """Write the scenario dict as pretty-printed JSON for human review."""
    path = os.path.join(SCENARIOS_DIR, filename)
    with open(path, "w") as fh:
        json.dump(scenario, fh, indent=2, sort_keys=True)
    print("wrote {0}  ({1} frames)".format(filename, len(scenario.get("frames", []))))


def base_actors():
    return {
        "A": {"seed_hex": SEED_A_HEX},
        "B": {"seed_hex": SEED_B_HEX},
    }


# ---------------------------------------------------------------------------
# Individual scenario builders
# ---------------------------------------------------------------------------

def build_01_handshake():
    """A sends meta to B, B replies with meta to A.  Both sides parse + verify."""
    return {
        "name": "version_metadata_handshake",
        "description": (
            "Two-peer version_metadata exchange.  Each side sends its "
            "'meta' preamble + signed handshake body, the other side "
            "verifies the ed25519 signature over blake2b-keyed(password)"
            "(pubkey), and both end up with peer pubkeys.  This is the "
            "first frame any peer link exchanges."
        ),
        "actors": base_actors(),
        "frames": [
            {
                "from": "A", "to": "B",
                "kind": "version_metadata",
                "wire_hex": binascii.hexlify(frame_metadata(SEED_A)).decode(),
                "comment": (
                    "A's handshake meta.  Layout: 4-byte 'meta' preamble + "
                    "uint16 BE body length + TLV body (major+minor+pubkey+"
                    "priority) + 64-byte ed25519 signature.  Signature is "
                    "over blake2b-keyed(empty_password)(A_pubkey)."
                ),
            },
            {
                "from": "B", "to": "A",
                "kind": "version_metadata",
                "wire_hex": binascii.hexlify(frame_metadata(SEED_B)).decode(),
                "comment": (
                    "B's handshake reply -- same layout, B's pubkey, "
                    "B's ed25519 signature.  Both sides may send "
                    "concurrently; the order in this scenario is "
                    "canonical-A-first but the protocol doesn't care."
                ),
            },
        ],
        "asserts": [],
    }


def build_02_keepalive():
    """After handshake, post-handshake keepalive frame [0x01][0x01]."""
    sc = build_01_handshake()
    sc["name"] = "handshake_then_keepalive"
    sc["description"] += (
        "  Then A sends a single keepalive packet -- the smallest "
        "possible post-handshake frame (2 bytes: varint 1 + type 1)."
    )
    sc["frames"].append({
        "from": "A", "to": "B",
        "kind": "keepalive",
        "wire_hex": binascii.hexlify(framed_packet(WIRE_KEEP_ALIVE, b"")).decode(),
        "comment": (
            "Keepalive frame: varint length=1, type byte=WIRE_KEEP_ALIVE=1, "
            "zero payload.  Total wire = 2 bytes (0x01 0x01).  Cancels the "
            "sender's pending keepalive timer + extends the receiver's "
            "read deadline."
        ),
    })
    return sc


def build_03_sig_req():
    sc = build_01_handshake()
    sc["name"] = "handshake_then_sig_req"
    sc["description"] += (
        "  Then A sends a router sig_req -- A wants B to sign A's tree "
        "position so A can adopt B as parent."
    )
    req = RouterSigReq(seq=1, nonce=0x12345678)
    sc["frames"].append({
        "from": "A", "to": "B",
        "kind": "sig_req",
        "wire_hex": binascii.hexlify(framed_packet(WIRE_PROTO_SIG_REQ, req.encode())).decode(),
        "comment": (
            "RouterSigReq(seq=1, nonce=0x12345678).  Body is varint(seq) + "
            "varint(nonce).  Type byte = WIRE_PROTO_SIG_REQ = 2.  Triggers "
            "B's handle_sig_req which constructs + signs a sig_res with "
            "port=A's port at B."
        ),
    })
    return sc


def build_04_announce():
    sc = build_01_handshake()
    sc["name"] = "handshake_then_announce"
    sc["description"] += (
        "  Then A sends a root announce -- A as its own parent, "
        "self-signed.  This is what a newly-self-rooting node broadcasts."
    )
    # Build a deterministic root announce for A
    res = RouterSigRes(seq=1, nonce=42, port=0, psig=b"\x00" * 64)
    bs = res.bytes_for_sig(PUB_A, PUB_A)
    psig = sign(SEED_A, bs)
    res.psig = psig
    ann = RouterAnnounce(key=PUB_A, parent=PUB_A, sig_res=res, sig=psig)
    sc["frames"].append({
        "from": "A", "to": "B",
        "kind": "announce",
        "wire_hex": binascii.hexlify(framed_packet(WIRE_PROTO_ANNOUNCE, ann.encode())).decode(),
        "comment": (
            "RouterAnnounce(key=A, parent=A, ...)  -- A as its own root.  "
            "Body: 32-byte key + 32-byte parent + sig_res(seq, nonce, "
            "port=0, psig) + 64-byte ed25519 signature.  B's "
            "handle_announce verifies both signatures (key signs + parent "
            "signs, same since A==parent) then update_info accepts."
        ),
    })
    return sc


def build_05_traffic():
    sc = build_01_handshake()
    sc["name"] = "handshake_then_traffic"
    sc["description"] += (
        "  Then A sends a Traffic packet addressed to a hypothetical dest C "
        "via empty source-route (B would forward via its tree)."
    )
    tr = Traffic(
        path=[], from_path=[],
        source=PUB_A, dest=b"\xcc" * 32,
        watermark=(1 << 64) - 1, payload=b"hello via overlay",
    )
    sc["frames"].append({
        "from": "A", "to": "B",
        "kind": "traffic",
        "wire_hex": binascii.hexlify(framed_packet(WIRE_TRAFFIC, tr.encode())).decode(),
        "comment": (
            "Traffic packet from A to dest 0xcc...cc.  watermark MUST be "
            "max-uint64 on initial send -- the receiver's lookup_next_hop "
            "compares self_dist < watermark and drops if not strictly "
            "less.  Initialising at 0 would cause every first-hop "
            "to path_broken the packet.  Caught live, fixed in "
            "commit 8a41d04."
        ),
    })
    return sc


def build_06_bloom():
    sc = build_01_handshake()
    sc["name"] = "handshake_then_bloom"
    sc["description"] += (
        "  Then A sends an empty Bloom filter packet (32 bytes -- "
        "16-byte all-zero flag + 16-byte all-zero flag, no body slots).  "
        "Used during peer-attach + every maintenance tick (F9) if the "
        "bloom changed."
    )
    b = Bloom(slots=[0] * BLOOM_FILTER_U)
    sc["frames"].append({
        "from": "A", "to": "B",
        "kind": "bloom_filter",
        "wire_hex": binascii.hexlify(framed_packet(WIRE_PROTO_BLOOM_FILTER, b.encode())).decode(),
        "comment": (
            "Empty bloom filter.  All 128 slots are zero, so flags0 (16 "
            "bytes) is all-0xff and flags1 (16 bytes) is all-0x00; "
            "no body bytes.  Real blooms grow as nodes learn about more "
            "peers; this is the 'I just joined and know nothing' state."
        ),
    })
    return sc


def build_07_path_lookup():
    sc = build_01_handshake()
    sc["name"] = "handshake_then_path_lookup"
    sc["description"] += (
        "  Then A sends a path_lookup for a third pubkey C.  "
        "Multicast-forwarded through the tree via bloom matching; "
        "any node matching bloom_transform(C) replies with a "
        "signed path_notify."
    )
    lookup = PathLookup(
        source=PUB_A, dest=b"\x42" * 32,
        from_path=[1, 2, 3],
    )
    sc["frames"].append({
        "from": "A", "to": "B",
        "kind": "path_lookup",
        "wire_hex": binascii.hexlify(framed_packet(WIRE_PROTO_PATH_LOOKUP, lookup.encode())).decode(),
        "comment": (
            "PathLookup(source=A_pub, dest=0x42*32, from_path=[1,2,3]).  "
            "from_path is the route from root to A as A knows it -- the "
            "reply travels back via this path with watermark routing."
        ),
    })
    return sc


def build_08_path_notify():
    sc = build_01_handshake()
    sc["name"] = "handshake_then_path_notify"
    sc["description"] += (
        "  Then A sends a path_notify (reply to a previous lookup).  "
        "Contains A's signed PathNotifyInfo describing its current "
        "route from root."
    )
    info = PathNotifyInfo(seq=12345, path=[7, 8, 9], sig=b"\x00" * 64)
    info.sig = sign(SEED_A, info.bytes_for_sig())
    notify = PathNotify(
        path=[1, 2, 3], watermark=(1 << 64) - 1,
        source=PUB_A, dest=PUB_B, info=info,
    )
    sc["frames"].append({
        "from": "A", "to": "B",
        "kind": "path_notify",
        "wire_hex": binascii.hexlify(framed_packet(WIRE_PROTO_PATH_NOTIFY, notify.encode())).decode(),
        "comment": (
            "PathNotify.  notify.path is the return route (from B back "
            "via the tree to lookup-source).  notify.info.path is the "
            "advertised route from root to A.  notify.info.sig is "
            "ed25519 over (info.seq, info.path) -- B verifies it before "
            "caching."
        ),
    })
    return sc


def build_09_path_broken():
    sc = build_01_handshake()
    sc["name"] = "handshake_then_path_broken"
    sc["description"] += (
        "  Then A sends a path_broken -- a previously-cached route "
        "is dead and the source should re-discover."
    )
    broken = PathBroken(
        path=[5, 6, 7], watermark=(1 << 64) - 1,
        source=PUB_A, dest=PUB_B,
    )
    sc["frames"].append({
        "from": "A", "to": "B",
        "kind": "path_broken",
        "wire_hex": binascii.hexlify(framed_packet(WIRE_PROTO_PATH_BROKEN, broken.encode())).decode(),
        "comment": (
            "PathBroken.  path is the dead route; A is signalling the "
            "actual source (further down the chain) that their cached "
            "path no longer works.  Triggers the source's pathfinder "
            "to invalidate + re-lookup with the 5s backoff (added in "
            "commit c66fd69)."
        ),
    })
    return sc


def build_10_session_init():
    """Just the encrypted-session init packet (after handshake).

    SessionInit is non-deterministic in production because it embeds
    a random ephemeral box keypair + wall-clock timestamp.  We pin
    both via the test-only kwarg + a fixed seq for byte stability.
    """
    sc = build_01_handshake()
    sc["name"] = "handshake_then_session_init"
    sc["description"] += (
        "  Then A sends a SessionInit -- the first packet of an "
        "encrypted session.  Carries A's box pubkey + signed metadata, "
        "all sealed under ECDH(A's_ephemeral, B's_box_pub_from_ed_pub)."
    )
    # Pinned ephemeral keypair for byte stability.  The pub MUST be
    # scalarmult_base(priv) -- the recipient does ECDH against this
    # wire-embedded pub, so a bogus pub makes the seal undecryptable.
    from warpgate.overlay.yggdrasil import curve25519
    pinned_ephemeral_priv = b"\xee" * 32
    pinned_ephemeral_pub = curve25519.scalarmult_base(pinned_ephemeral_priv)
    # current / next box pubs are derived from A's identity.
    _, a_box_pub, _ = derive_box_keys_from_ed_seed(SEED_A)
    init = SessionInit(
        current=a_box_pub, next_pub=a_box_pub,
        key_seq=0, seq=1,
    )
    # encode internally generates a fresh ephemeral; we pin via kwarg.
    wire = init.encode(
        SEED_A, PUB_B,
        type_byte=SESSION_TYPE_INIT,
        test_ephemeral_box_keypair=(pinned_ephemeral_priv, pinned_ephemeral_pub),
    )
    sc["frames"].append({
        "from": "A", "to": "B",
        "kind": "session_init",
        "wire_hex": binascii.hexlify(wire).decode(),
        "comment": (
            "SessionInit byte structure: [type=1][32-byte ephemeral box "
            "pub][nacl-box-sealed(64-byte ed sig || 32-byte current box "
            "pub || 32-byte next box pub || 8-byte BE key_seq || 8-byte "
            "BE seq)].  Sealed under ECDH(ephemeral_priv, "
            "ed25519_pk_to_curve25519(B_pub)).  Pinned ephemeral keypair "
            "for test reproducibility."
        ),
    })
    return sc


def build_12_multicast_beacon():
    """A multicast beacon advertisement.  NOT post-handshake -- this is
    the LAN discovery flow, completely separate from peer links."""
    # Note: multicast hash bug (fixed in commit cad64b6) was: hash
    # was blake2b(password) but upstream uses blake2b-keyed(password)
    # (pubkey).  Our recorded bytes use the fixed (correct) form.
    from warpgate.overlay.yggdrasil.blake2b import blake2b_hash
    hash_bytes = blake2b_hash(PUB_A, key=b"", digest_size=64)
    adv = MulticastAdvertisement(
        major_ver=PROTOCOL_VERSION_MAJOR,
        minor_ver=PROTOCOL_VERSION_MINOR,
        public_key=PUB_A, port=9001,
        hash_bytes=hash_bytes,
    )
    return {
        "name": "multicast_beacon",
        "description": (
            "Standalone scenario: a single multicast beacon "
            "advertisement on ff02::114:9001.  Layout: 2-byte major + "
            "2-byte minor + 32-byte pubkey + 2-byte port + 2-byte "
            "hash_len + hash_len bytes hash.  Hash is "
            "blake2b-keyed(password)(pubkey) -- the keyed form was "
            "wrong in early versions (commit cad64b6 fixed it)."
        ),
        "actors": base_actors(),
        "frames": [
            {
                "from": "A", "to": "B",
                "kind": "multicast_beacon",
                "wire_hex": binascii.hexlify(adv.encode()).decode(),
                "comment": (
                    "Multicast beacon advertising A's identity + listen "
                    "port + password hash.  B's listener decodes this, "
                    "checks the hash matches its own password derivation, "
                    "and if so dials A's port + pubkey."
                ),
            },
        ],
        "asserts": [],
    }


def main():
    write_scenario("01_version_metadata_handshake.json", build_01_handshake())
    write_scenario("02_handshake_then_keepalive.json", build_02_keepalive())
    write_scenario("03_handshake_then_sig_req.json", build_03_sig_req())
    write_scenario("04_handshake_then_announce.json", build_04_announce())
    write_scenario("05_handshake_then_traffic.json", build_05_traffic())
    write_scenario("06_handshake_then_bloom.json", build_06_bloom())
    write_scenario("07_handshake_then_path_lookup.json", build_07_path_lookup())
    write_scenario("08_handshake_then_path_notify.json", build_08_path_notify())
    write_scenario("09_handshake_then_path_broken.json", build_09_path_broken())
    write_scenario("10_handshake_then_session_init.json", build_10_session_init())
    write_scenario("12_multicast_beacon.json", build_12_multicast_beacon())
    print("Done.")


if __name__ == "__main__":
    main()
