"""murmur3-128 sum256 byte-parity tests against bits-and-blooms reference."""
import binascii
import os
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.murmur128 import sum128, sum256


VECTOR_PATH = os.path.join(
    os.path.dirname(__file__), "yggdrasil_murmur_vectors.txt"
)


def load_vectors():
    out = []
    with open(VECTOR_PATH, "r") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("|")
            if len(parts) != 5:
                continue
            data_hex, h1, h2, h3, h4 = parts
            out.append((
                binascii.unhexlify(data_hex),
                int(h1, 16), int(h2, 16),
                int(h3, 16), int(h4, 16),
            ))
    return out


class TestMurmurSum256(AsyncTestCase):

    async def test_vectors_present(self):
        vectors = load_vectors()
        self.assertGreaterEqual(len(vectors), 15)

    async def test_sum256_matches_go(self):
        for data, h1, h2, h3, h4 in load_vectors():
            got = sum256(data)
            self.assertEqual(
                got, (h1, h2, h3, h4),
                "data={0}: got={1} expected={2}".format(
                    binascii.hexlify(data).decode(),
                    [hex(v) for v in got],
                    [hex(v) for v in (h1, h2, h3, h4)],
                ),
            )

    async def test_sum128_returns_first_two_of_sum256(self):
        for data, h1, h2, _h3, _h4 in load_vectors():
            self.assertEqual(sum128(data), (h1, h2))


if __name__ == "__main__":
    unittest.main()
