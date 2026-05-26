"""Byte-parity tests for routing-protocol message codecs.

Compares Python encode() output against bytes produced by a Go
program that inlines the upstream ironwood/network encoders.
Each line in ``yggdrasil_routing_vectors.txt`` is a pipe-separated
record naming the message type, its field values, and the expected
hex wire form.
"""
import binascii
import os
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.routing_msgs import (
    BLOOM_FILTER_U,
    Bloom,
    DecodeError,
    PathBroken,
    PathLookup,
    PathNotify,
    PathNotifyInfo,
    RouterAnnounce,
    RouterSigReq,
    RouterSigRes,
    Traffic,
    decode_routing_packet,
)
from warpgate.overlay.yggdrasil.wire import (
    WIRE_PROTO_ANNOUNCE,
    WIRE_PROTO_BLOOM_FILTER,
    WIRE_PROTO_PATH_BROKEN,
    WIRE_PROTO_PATH_LOOKUP,
    WIRE_PROTO_PATH_NOTIFY,
    WIRE_PROTO_SIG_REQ,
    WIRE_PROTO_SIG_RES,
    WIRE_TRAFFIC,
)


VECTOR_PATH = os.path.join(
    os.path.dirname(__file__), "yggdrasil_routing_vectors.txt"
)


def load_vectors():
    """Return list of (kind, fields) tuples."""
    out = []
    with open(VECTOR_PATH, "r") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("|")
            kind = parts[0]
            fields = parts[1:]
            out.append((kind, fields))
    return out


def parse_path(s):
    return [int(x) for x in s.split(",")] if s else []


def hx(s):
    return binascii.unhexlify(s)


class TestSigReqVectors(AsyncTestCase):

    async def test_sigreq_matches_go(self):
        for kind, fields in load_vectors():
            if kind != "SigReq":
                continue
            seq, nonce, expected_hex = fields
            msg = RouterSigReq(seq=int(seq), nonce=int(nonce))
            self.assertEqual(msg.encode(), hx(expected_hex))

    async def test_sigreq_decode_matches(self):
        for kind, fields in load_vectors():
            if kind != "SigReq":
                continue
            seq, nonce, expected_hex = fields
            decoded = RouterSigReq.decode(hx(expected_hex))
            self.assertEqual(decoded.seq, int(seq))
            self.assertEqual(decoded.nonce, int(nonce))


class TestSigResVectors(AsyncTestCase):

    async def test_sigres_matches_go(self):
        for kind, fields in load_vectors():
            if kind != "SigRes":
                continue
            seq, nonce, port, psig_hex, expected_hex = fields
            msg = RouterSigRes(
                seq=int(seq), nonce=int(nonce),
                port=int(port), psig=hx(psig_hex),
            )
            self.assertEqual(msg.encode(), hx(expected_hex))


class TestAnnounceVectors(AsyncTestCase):

    async def test_announce_matches_go(self):
        for kind, fields in load_vectors():
            if kind != "Announce":
                continue
            key, parent, seq, nonce, port, psig, sig, expected = fields
            msg = RouterAnnounce(
                key=hx(key), parent=hx(parent),
                sig_res=RouterSigRes(seq=int(seq), nonce=int(nonce),
                                     port=int(port), psig=hx(psig)),
                sig=hx(sig),
            )
            self.assertEqual(msg.encode(), hx(expected))


class TestBloomVectors(AsyncTestCase):

    async def test_bloom_empty_matches_go(self):
        for kind, fields in load_vectors():
            if kind != "BloomEmpty":
                continue
            expected = hx(fields[0])
            msg = Bloom(slots=[0] * BLOOM_FILTER_U)
            self.assertEqual(msg.encode(), expected)
            self.assertEqual(Bloom.decode(expected).slots, [0] * BLOOM_FILTER_U)

    async def test_bloom_all_ones_matches_go(self):
        for kind, fields in load_vectors():
            if kind != "BloomAllOnes":
                continue
            expected = hx(fields[0])
            all_ones = (1 << 64) - 1
            msg = Bloom(slots=[all_ones] * BLOOM_FILTER_U)
            self.assertEqual(msg.encode(), expected)

    async def test_bloom_sequence_matches_go(self):
        for kind, fields in load_vectors():
            if kind != "BloomSeq":
                continue
            expected = hx(fields[0])
            msg = Bloom(slots=[i for i in range(BLOOM_FILTER_U)])
            self.assertEqual(msg.encode(), expected)
            decoded = Bloom.decode(expected)
            self.assertEqual(decoded.slots, [i for i in range(BLOOM_FILTER_U)])


class TestPathLookupVectors(AsyncTestCase):

    async def test_pathlookup_matches_go(self):
        for kind, fields in load_vectors():
            if kind != "PathLookup":
                continue
            source, dest, path_str, expected = fields
            msg = PathLookup(source=hx(source), dest=hx(dest),
                             from_path=parse_path(path_str))
            self.assertEqual(msg.encode(), hx(expected))


class TestPathNotifyVectors(AsyncTestCase):

    async def test_pathnotify_matches_go(self):
        for kind, fields in load_vectors():
            if kind != "PathNotify":
                continue
            (path_s, watermark, source, dest,
             info_seq, info_path_s, info_sig, expected) = fields
            info = PathNotifyInfo(
                seq=int(info_seq), path=parse_path(info_path_s),
                sig=hx(info_sig),
            )
            msg = PathNotify(
                path=parse_path(path_s), watermark=int(watermark),
                source=hx(source), dest=hx(dest), info=info,
            )
            self.assertEqual(msg.encode(), hx(expected))


class TestPathBrokenVectors(AsyncTestCase):

    async def test_pathbroken_matches_go(self):
        for kind, fields in load_vectors():
            if kind != "PathBroken":
                continue
            path_s, watermark, source, dest, expected = fields
            msg = PathBroken(path=parse_path(path_s),
                             watermark=int(watermark),
                             source=hx(source), dest=hx(dest))
            self.assertEqual(msg.encode(), hx(expected))


class TestTrafficVectors(AsyncTestCase):

    async def test_traffic_matches_go(self):
        for kind, fields in load_vectors():
            if kind != "Traffic":
                continue
            path_s, from_s, source, dest, watermark, payload, expected = fields
            msg = Traffic(
                path=parse_path(path_s), from_path=parse_path(from_s),
                source=hx(source), dest=hx(dest),
                watermark=int(watermark), payload=payload.encode("utf-8"),
            )
            self.assertEqual(msg.encode(), hx(expected))


class TestDispatchTable(AsyncTestCase):

    async def test_decode_routing_packet_dispatches_by_type(self):
        cases = [
            (WIRE_PROTO_SIG_REQ, RouterSigReq(seq=1, nonce=2)),
            (WIRE_PROTO_SIG_RES, RouterSigRes(seq=1, nonce=2, port=3, psig=b"\x01" * 64)),
            (WIRE_PROTO_PATH_LOOKUP, PathLookup(source=b"\x11"*32, dest=b"\x22"*32, from_path=[1])),
            (WIRE_PROTO_PATH_BROKEN, PathBroken(path=[1], watermark=5, source=b"\x11"*32, dest=b"\x22"*32)),
            (WIRE_TRAFFIC, Traffic(source=b"\x11"*32, dest=b"\x22"*32, payload=b"x")),
        ]
        for wire_type, msg in cases:
            decoded = decode_routing_packet(wire_type, msg.encode())
            self.assertEqual(decoded.encode(), msg.encode())

    async def test_decode_unknown_type_raises(self):
        with self.assertRaises(DecodeError):
            decode_routing_packet(99, b"\x00")


if __name__ == "__main__":
    unittest.main()
