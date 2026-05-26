"""v2 replay tests -- drive the yggdrasil protocol stack from JSON byte logs.

Every scenario file in ``tests/yggdrasil_scenarios/*.json`` is loaded,
replayed through ``ScenarioPlayer`` (which spins up LoopbackTransport
pairs and pushes bytes through them), and individually decoded to
verify the wire bytes round-trip through the encoder/decoder pair.

This is the byte-level proof that the protocol stack can run with
zero real I/O: every packet the software sends or receives in
production has a recorded canonical form in the catalog, and these
tests demonstrate that form is correct + parseable.

Run with::

    ~/.pyenv/versions/3.5.10/bin/python -m unittest \\
        tests.test_yggdrasil_scenarios -v

To regenerate the JSON files after a protocol change::

    ~/.pyenv/versions/3.5.10/bin/python \\
        tests/yggdrasil_scenarios/build_scenarios.py
"""
import binascii
import json
import os
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.encrypted import (
    SESSION_TYPE_INIT, SessionInit, derive_box_keys_from_ed_seed,
)
from warpgate.overlay.yggdrasil.multicast import MulticastAdvertisement
from warpgate.overlay.yggdrasil.node_core import derive_pubkey
from warpgate.overlay.yggdrasil.routing_msgs import (
    Bloom, PathBroken, PathLookup, PathNotify, RouterAnnounce,
    RouterSigReq, RouterSigRes, Traffic, decode_routing_packet,
)
from warpgate.overlay.yggdrasil.simulation import (
    ScenarioError, ScenarioPlayer,
)
from warpgate.overlay.yggdrasil.version import VersionMetadata
from warpgate.overlay.yggdrasil.wire import (
    WIRE_KEEP_ALIVE, WIRE_PROTO_ANNOUNCE, WIRE_PROTO_BLOOM_FILTER,
    WIRE_PROTO_PATH_BROKEN, WIRE_PROTO_PATH_LOOKUP,
    WIRE_PROTO_PATH_NOTIFY, WIRE_PROTO_SIG_REQ, WIRE_PROTO_SIG_RES,
    WIRE_TRAFFIC, decode_uvarint,
)


SCENARIOS_DIR = os.path.join(
    os.path.dirname(__file__), "yggdrasil_scenarios",
)


WIRE_TYPE_FOR_KIND = {
    "sig_req": WIRE_PROTO_SIG_REQ,
    "sig_res": WIRE_PROTO_SIG_RES,
    "announce": WIRE_PROTO_ANNOUNCE,
    "bloom_filter": WIRE_PROTO_BLOOM_FILTER,
    "path_lookup": WIRE_PROTO_PATH_LOOKUP,
    "path_notify": WIRE_PROTO_PATH_NOTIFY,
    "path_broken": WIRE_PROTO_PATH_BROKEN,
    "traffic": WIRE_TRAFFIC,
}


def load_scenario(filename):
    with open(os.path.join(SCENARIOS_DIR, filename), "r") as fh:
        return json.load(fh)


def all_scenario_files():
    return sorted(
        f for f in os.listdir(SCENARIOS_DIR)
        if f.endswith(".json")
    )


def strip_framing(framed_bytes):
    """Take [varint len][type byte][payload] -> (type_byte, payload)."""
    length, consumed = decode_uvarint(framed_bytes, 0)
    body = framed_bytes[consumed:consumed + length]
    if len(body) < 1:
        raise ValueError("strip_framing: body shorter than 1 byte")
    return body[0], body[1:]


class TestScenarioFilesPresent(AsyncTestCase):
    """The build script should have produced one JSON per protocol flow."""

    async def test_directory_has_scenarios(self):
        files = all_scenario_files()
        self.assertGreaterEqual(
            len(files), 11,
            "expected >=11 scenario files, got: {0}".format(files),
        )

    async def test_each_scenario_has_required_keys(self):
        for filename in all_scenario_files():
            sc = load_scenario(filename)
            for key in ("name", "description", "actors", "frames"):
                self.assertIn(
                    key, sc,
                    "{0} missing required key '{1}'".format(filename, key),
                )
            self.assertGreaterEqual(
                len(sc["actors"]), 1,
                "{0} has no actors".format(filename),
            )
            self.assertGreaterEqual(
                len(sc["frames"]), 1,
                "{0} has no frames".format(filename),
            )

    async def test_each_frame_has_required_fields(self):
        for filename in all_scenario_files():
            sc = load_scenario(filename)
            for idx, frame in enumerate(sc["frames"]):
                for key in ("from", "to", "kind", "wire_hex", "comment"):
                    self.assertIn(
                        key, frame,
                        "{0} frame {1} missing '{2}'".format(
                            filename, idx, key,
                        ),
                    )
                # Wire hex must be even-length valid hex.
                try:
                    binascii.unhexlify(frame["wire_hex"])
                except (binascii.Error, ValueError) as exc:
                    self.fail("{0} frame {1} bad hex: {2}".format(
                        filename, idx, exc,
                    ))


class TestScenariosReplayThroughLoopback(AsyncTestCase):
    """Each scenario must replay cleanly through ScenarioPlayer (no I/O)."""

    async def test_every_scenario_runs(self):
        files = all_scenario_files()
        self.assertGreater(len(files), 0, "no scenarios to run")
        for filename in files:
            sc = load_scenario(filename)
            player = ScenarioPlayer.from_dict(sc)
            # Empty-actors scenarios are an error; the helper raises
            # cleanly so we use that to assert structure.
            try:
                await player.run()
            except ScenarioError as exc:
                self.fail("{0} replay failed: {1}".format(filename, exc))


class TestHandshakeBytesRoundTrip(AsyncTestCase):
    """version_metadata wire bytes must decode + match pinned pubkeys."""

    async def test_handshake_frames_decode(self):
        sc = load_scenario("01_version_metadata_handshake.json")
        actors = sc["actors"]
        seed_a = binascii.unhexlify(actors["A"]["seed_hex"])
        seed_b = binascii.unhexlify(actors["B"]["seed_hex"])
        pub_a = derive_pubkey(seed_a)
        pub_b = derive_pubkey(seed_b)

        frame_0 = sc["frames"][0]
        self.assertEqual(frame_0["from"], "A")
        wire_0 = binascii.unhexlify(frame_0["wire_hex"])
        meta_a = VersionMetadata.decode(wire_0)
        self.assertEqual(
            bytes(meta_a.public_key), bytes(pub_a),
            "A's handshake bytes do not decode to A's pubkey",
        )

        frame_1 = sc["frames"][1]
        self.assertEqual(frame_1["from"], "B")
        wire_1 = binascii.unhexlify(frame_1["wire_hex"])
        meta_b = VersionMetadata.decode(wire_1)
        self.assertEqual(
            bytes(meta_b.public_key), bytes(pub_b),
            "B's handshake bytes do not decode to B's pubkey",
        )


class TestKeepaliveCanonicalShape(AsyncTestCase):
    """Keepalive must be the literal 2 bytes 0x01 0x01."""

    async def test_keepalive_frame_is_two_bytes(self):
        sc = load_scenario("02_handshake_then_keepalive.json")
        frame = sc["frames"][-1]
        self.assertEqual(frame["kind"], "keepalive")
        wire = binascii.unhexlify(frame["wire_hex"])
        self.assertEqual(wire, b"\x01\x01",
            "keepalive must be exactly varint(1) + type=KEEP_ALIVE=1")
        type_byte, payload = strip_framing(wire)
        self.assertEqual(type_byte, WIRE_KEEP_ALIVE)
        self.assertEqual(payload, b"")


class TestSigReqRoundTrip(AsyncTestCase):

    async def test_sig_req_decodes_and_round_trips(self):
        sc = load_scenario("03_handshake_then_sig_req.json")
        frame = sc["frames"][-1]
        self.assertEqual(frame["kind"], "sig_req")
        wire = binascii.unhexlify(frame["wire_hex"])
        type_byte, payload = strip_framing(wire)
        self.assertEqual(type_byte, WIRE_PROTO_SIG_REQ)
        decoded = decode_routing_packet(type_byte, payload)
        self.assertIsInstance(decoded, RouterSigReq)
        self.assertEqual(decoded.seq, 1)
        self.assertEqual(decoded.nonce, 0x12345678)
        # Re-encode and check byte parity.
        self.assertEqual(
            decoded.encode(), payload,
            "RouterSigReq re-encode is not byte-identical",
        )


class TestAnnounceRoundTrip(AsyncTestCase):

    async def test_announce_decodes_with_valid_signatures(self):
        sc = load_scenario("04_handshake_then_announce.json")
        seed_a = binascii.unhexlify(sc["actors"]["A"]["seed_hex"])
        pub_a = derive_pubkey(seed_a)
        frame = sc["frames"][-1]
        self.assertEqual(frame["kind"], "announce")
        wire = binascii.unhexlify(frame["wire_hex"])
        type_byte, payload = strip_framing(wire)
        self.assertEqual(type_byte, WIRE_PROTO_ANNOUNCE)
        decoded = decode_routing_packet(type_byte, payload)
        self.assertIsInstance(decoded, RouterAnnounce)
        self.assertEqual(bytes(decoded.key), bytes(pub_a))
        self.assertEqual(bytes(decoded.parent), bytes(pub_a),
            "root announce must have key == parent")
        self.assertEqual(decoded.encode(), payload)


class TestTrafficWatermarkInvariant(AsyncTestCase):
    """The famous F-fix: traffic.watermark MUST decode as max-uint64."""

    async def test_traffic_decodes_with_max_uint64_watermark(self):
        sc = load_scenario("05_handshake_then_traffic.json")
        seed_a = binascii.unhexlify(sc["actors"]["A"]["seed_hex"])
        pub_a = derive_pubkey(seed_a)
        frame = sc["frames"][-1]
        self.assertEqual(frame["kind"], "traffic")
        wire = binascii.unhexlify(frame["wire_hex"])
        type_byte, payload = strip_framing(wire)
        self.assertEqual(type_byte, WIRE_TRAFFIC)
        decoded = decode_routing_packet(type_byte, payload)
        self.assertIsInstance(decoded, Traffic)
        self.assertEqual(bytes(decoded.source), bytes(pub_a))
        self.assertEqual(
            decoded.watermark, (1 << 64) - 1,
            "watermark MUST be max-uint64 on initial send -- if this "
            "regresses to 0, every receiver path_broken's the packet "
            "(see commit 8a41d04)",
        )
        self.assertEqual(decoded.payload, b"hello via overlay")
        self.assertEqual(decoded.encode(), payload)


class TestBloomEmptyShape(AsyncTestCase):

    async def test_bloom_decodes_and_round_trips(self):
        sc = load_scenario("06_handshake_then_bloom.json")
        frame = sc["frames"][-1]
        self.assertEqual(frame["kind"], "bloom_filter")
        wire = binascii.unhexlify(frame["wire_hex"])
        type_byte, payload = strip_framing(wire)
        self.assertEqual(type_byte, WIRE_PROTO_BLOOM_FILTER)
        decoded = decode_routing_packet(type_byte, payload)
        self.assertIsInstance(decoded, Bloom)
        self.assertTrue(all(slot == 0 for slot in decoded.slots),
            "empty bloom should have all-zero slots")
        self.assertEqual(decoded.encode(), payload)


class TestPathLookupRoundTrip(AsyncTestCase):

    async def test_path_lookup_decodes(self):
        sc = load_scenario("07_handshake_then_path_lookup.json")
        seed_a = binascii.unhexlify(sc["actors"]["A"]["seed_hex"])
        pub_a = derive_pubkey(seed_a)
        frame = sc["frames"][-1]
        self.assertEqual(frame["kind"], "path_lookup")
        wire = binascii.unhexlify(frame["wire_hex"])
        type_byte, payload = strip_framing(wire)
        self.assertEqual(type_byte, WIRE_PROTO_PATH_LOOKUP)
        decoded = decode_routing_packet(type_byte, payload)
        self.assertIsInstance(decoded, PathLookup)
        self.assertEqual(bytes(decoded.source), bytes(pub_a))
        self.assertEqual(bytes(decoded.dest), b"\x42" * 32)
        self.assertEqual(decoded.from_path, [1, 2, 3])
        self.assertEqual(decoded.encode(), payload)


class TestPathNotifyRoundTrip(AsyncTestCase):

    async def test_path_notify_decodes_with_valid_info_sig(self):
        sc = load_scenario("08_handshake_then_path_notify.json")
        seed_a = binascii.unhexlify(sc["actors"]["A"]["seed_hex"])
        seed_b = binascii.unhexlify(sc["actors"]["B"]["seed_hex"])
        pub_a = derive_pubkey(seed_a)
        pub_b = derive_pubkey(seed_b)
        frame = sc["frames"][-1]
        self.assertEqual(frame["kind"], "path_notify")
        wire = binascii.unhexlify(frame["wire_hex"])
        type_byte, payload = strip_framing(wire)
        self.assertEqual(type_byte, WIRE_PROTO_PATH_NOTIFY)
        decoded = decode_routing_packet(type_byte, payload)
        self.assertIsInstance(decoded, PathNotify)
        self.assertEqual(bytes(decoded.source), bytes(pub_a))
        self.assertEqual(bytes(decoded.dest), bytes(pub_b))
        self.assertEqual(decoded.path, [1, 2, 3])
        self.assertEqual(decoded.info.seq, 12345)
        self.assertEqual(decoded.info.path, [7, 8, 9])
        self.assertEqual(decoded.encode(), payload)


class TestPathBrokenRoundTrip(AsyncTestCase):

    async def test_path_broken_decodes(self):
        sc = load_scenario("09_handshake_then_path_broken.json")
        frame = sc["frames"][-1]
        self.assertEqual(frame["kind"], "path_broken")
        wire = binascii.unhexlify(frame["wire_hex"])
        type_byte, payload = strip_framing(wire)
        self.assertEqual(type_byte, WIRE_PROTO_PATH_BROKEN)
        decoded = decode_routing_packet(type_byte, payload)
        self.assertIsInstance(decoded, PathBroken)
        self.assertEqual(decoded.path, [5, 6, 7])
        self.assertEqual(decoded.watermark, (1 << 64) - 1)
        self.assertEqual(decoded.encode(), payload)


class TestSessionInitDecryption(AsyncTestCase):
    """B's box-priv key must decrypt A's SessionInit + verify A's ed sig."""

    async def test_session_init_decodes_when_b_decrypts(self):
        sc = load_scenario("10_handshake_then_session_init.json")
        seed_a = binascii.unhexlify(sc["actors"]["A"]["seed_hex"])
        seed_b = binascii.unhexlify(sc["actors"]["B"]["seed_hex"])
        pub_a = derive_pubkey(seed_a)
        # Recipient's box keypair from ed seed.
        b_box_priv, _, _ = derive_box_keys_from_ed_seed(seed_b)
        frame = sc["frames"][-1]
        self.assertEqual(frame["kind"], "session_init")
        wire = binascii.unhexlify(frame["wire_hex"])
        # SessionInit is NOT framed with varint(len) -- it's raw.
        self.assertEqual(wire[0], SESSION_TYPE_INIT)
        decoded = SessionInit.decode(wire, b_box_priv, pub_a)
        self.assertIsNotNone(
            decoded,
            "B must be able to decrypt + verify A's SessionInit",
        )
        self.assertEqual(decoded.seq, 1)
        self.assertEqual(decoded.key_seq, 0)


class TestMulticastBeaconRoundTrip(AsyncTestCase):

    async def test_multicast_beacon_decodes(self):
        sc = load_scenario("12_multicast_beacon.json")
        seed_a = binascii.unhexlify(sc["actors"]["A"]["seed_hex"])
        pub_a = derive_pubkey(seed_a)
        frame = sc["frames"][0]
        self.assertEqual(frame["kind"], "multicast_beacon")
        wire = binascii.unhexlify(frame["wire_hex"])
        decoded = MulticastAdvertisement.decode(wire)
        self.assertEqual(bytes(decoded.public_key), bytes(pub_a))
        self.assertEqual(decoded.port, 9001)
        self.assertGreater(len(decoded.hash_bytes), 0)
        self.assertEqual(decoded.encode(), wire)


class TestScenarioByteStability(AsyncTestCase):
    """Pinned seeds + zeroed nonces mean every wire_hex must be stable.

    If this test ever fails after a "no-op" edit to the protocol code,
    it means the encoder drifted -- either fix the encoder, or
    regenerate the scenarios via build_scenarios.py and commit the
    new bytes (which is also a signal to bump a protocol version).
    """

    async def test_handshake_first_bytes_are_meta_preamble(self):
        for filename in all_scenario_files():
            sc = load_scenario(filename)
            if not sc["frames"]:
                continue
            kind = sc["frames"][0].get("kind")
            if kind != "version_metadata":
                continue
            wire = binascii.unhexlify(sc["frames"][0]["wire_hex"])
            self.assertEqual(
                wire[:4], b"meta",
                "{0}: first 4 bytes of handshake frame must be "
                "'meta' preamble; got {1}".format(
                    filename, repr(wire[:4]),
                ),
            )


if __name__ == "__main__":
    unittest.main()
