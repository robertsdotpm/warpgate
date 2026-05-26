"""Tests for the wire helpers.

These are pure-format tests -- varint round-trip + path encoding +
cursor reads -- with edge cases at every boundary the upstream
``encoding/binary`` Uvarint implementation cares about (boundary
values: 0, 0x7F, 0x80, 0x3FFF, 0x4000, 0xFFFF_FFFF_FFFF_FFFF, etc).
"""
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.wire import (
    WIRE_DUMMY,
    WIRE_KEEP_ALIVE,
    WIRE_TRAFFIC,
    encode_uvarint,
    decode_uvarint,
    varint_size,
    encode_path,
    encode_packet_type,
    WireCursor,
)


# Spot-check varint encodings against the LEB128 reference values.
# These bytes are what Go's binary.AppendUvarint emits -- verified
# by running:
#   package main; import "encoding/binary"; func main() {
#       for _, v := range []uint64{0, 1, 127, 128, 16383, 16384, 1<<32}{
#           buf := make([]byte, 10); n := binary.PutUvarint(buf, v);
#           fmt.Printf("%d -> %x\n", v, buf[:n])
#       }
#   }
KNOWN_VARINTS = [
    (0, b"\x00"),
    (1, b"\x01"),
    (127, b"\x7f"),
    (128, b"\x80\x01"),
    (255, b"\xff\x01"),
    (16383, b"\xff\x7f"),
    (16384, b"\x80\x80\x01"),
    (1 << 32, b"\x80\x80\x80\x80\x10"),
    (0xFFFFFFFFFFFFFFFF, b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"),
]


class TestVarint(AsyncTestCase):

    async def test_encode_known_values(self):
        for value, expected in KNOWN_VARINTS:
            self.assertEqual(
                encode_uvarint(value), expected,
                "encode({0}) -> {1}, expected {2}".format(
                    value, encode_uvarint(value).hex(), expected.hex()))

    async def test_decode_known_values(self):
        for value, encoded in KNOWN_VARINTS:
            got, consumed = decode_uvarint(encoded)
            self.assertEqual(got, value)
            self.assertEqual(consumed, len(encoded))

    async def test_decode_with_offset(self):
        buf = b"\xff" + encode_uvarint(12345)
        got, consumed = decode_uvarint(buf, offset=1)
        self.assertEqual(got, 12345)
        self.assertEqual(consumed, len(buf) - 1)

    async def test_decode_truncated_raises(self):
        # missing terminator byte
        with self.assertRaises(ValueError):
            decode_uvarint(b"\x80\x80")

    async def test_decode_overflow_raises(self):
        # 11-byte stream with continuation bits forever -- exceeds 64-bit width
        with self.assertRaises(ValueError):
            decode_uvarint(b"\xff" * 10 + b"\x01")

    async def test_encode_negative_raises(self):
        with self.assertRaises(ValueError):
            encode_uvarint(-1)

    async def test_size_matches_encode_length(self):
        for value, _ in KNOWN_VARINTS:
            self.assertEqual(varint_size(value), len(encode_uvarint(value)))


class TestPath(AsyncTestCase):

    async def test_encode_decode_roundtrip(self):
        for ports in ([1], [1, 2, 3], [255, 16384, 65535], [12345]):
            wire = encode_path(ports)
            cursor = WireCursor(wire)
            got = cursor.chop_path()
            self.assertEqual(got, ports)
            self.assertEqual(cursor.remaining(), 0)

    async def test_empty_path_is_just_terminator(self):
        wire = encode_path([])
        self.assertEqual(wire, b"\x00")
        cursor = WireCursor(wire)
        got = cursor.chop_path()
        self.assertEqual(got, [])

    async def test_encode_rejects_zero_port(self):
        # Port 0 is reserved as the terminator
        with self.assertRaises(ValueError):
            encode_path([1, 0, 3])

    async def test_chop_path_refuses_oversize(self):
        # > 128 hops with no terminator should refuse
        cursor = WireCursor(b"\x01" * 200)  # 200 single-byte varints, all "1"
        with self.assertRaises(ValueError):
            cursor.chop_path()


class TestWireCursor(AsyncTestCase):

    async def test_chop_byte(self):
        cursor = WireCursor(b"\xaa\xbb\xcc")
        self.assertEqual(cursor.chop_byte(), 0xAA)
        self.assertEqual(cursor.chop_byte(), 0xBB)
        self.assertEqual(cursor.chop_byte(), 0xCC)
        self.assertEqual(cursor.remaining(), 0)

    async def test_chop_byte_empty_raises(self):
        cursor = WireCursor(b"")
        with self.assertRaises(ValueError):
            cursor.chop_byte()

    async def test_chop_slice(self):
        cursor = WireCursor(b"helloworld")
        self.assertEqual(cursor.chop_slice(5), b"hello")
        self.assertEqual(cursor.chop_slice(5), b"world")
        self.assertEqual(cursor.remaining(), 0)

    async def test_chop_slice_too_short_raises(self):
        cursor = WireCursor(b"abc")
        with self.assertRaises(ValueError):
            cursor.chop_slice(10)

    async def test_chop_uvarint(self):
        for value, encoded in KNOWN_VARINTS:
            cursor = WireCursor(encoded + b"trailing")
            self.assertEqual(cursor.chop_uvarint(), value)
            self.assertEqual(cursor.chop_slice(8), b"trailing")


class TestEncodePacketType(AsyncTestCase):

    async def test_prepends_single_byte(self):
        out = encode_packet_type(WIRE_TRAFFIC, b"payload")
        self.assertEqual(out[0], WIRE_TRAFFIC)
        self.assertEqual(out[1:], b"payload")

    async def test_traffic_constant_matches_upstream(self):
        # ironwood/network/wire.go: wireTraffic = 9
        self.assertEqual(WIRE_TRAFFIC, 9)
        self.assertEqual(WIRE_KEEP_ALIVE, 1)
        self.assertEqual(WIRE_DUMMY, 0)

    async def test_rejects_out_of_range_type(self):
        with self.assertRaises(ValueError):
            encode_packet_type(256, b"x")
        with self.assertRaises(ValueError):
            encode_packet_type(-1, b"x")


if __name__ == "__main__":
    unittest.main()
