"""Phase 8 crypto stack: Curve25519 + Salsa20 + Poly1305 + NaCl box.

Verified against RFC 7748 vectors (Curve25519) and the canonical
libsodium ``box`` test vector (NaCl box end-to-end).  HSalsa20 +
Salsa20 + Poly1305 are verified implicitly by the NaCl box vector
since any drift in those primitives breaks the box output.
"""
import binascii
import os
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil import nacl_box
from warpgate.overlay.yggdrasil.curve25519 import (
    ed25519_priv_seed_to_curve25519,
    edwards_y_to_montgomery_u,
    scalarmult,
    scalarmult_base,
)
from warpgate.overlay.yggdrasil.poly1305 import poly1305_mac, poly1305_verify
from warpgate.overlay.yggdrasil.salsa20 import hsalsa20, salsa20_block, xsalsa20_stream


# RFC 7748 §6.1 vectors.
ALICE_PRIV = binascii.unhexlify(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUB = binascii.unhexlify(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_PRIV = binascii.unhexlify(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PUB = binascii.unhexlify(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
SHARED = binascii.unhexlify(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")


class TestCurve25519RFC(AsyncTestCase):

    async def test_alice_pub_matches_rfc(self):
        self.assertEqual(scalarmult_base(ALICE_PRIV), ALICE_PUB)

    async def test_bob_pub_matches_rfc(self):
        self.assertEqual(scalarmult_base(BOB_PRIV), BOB_PUB)

    async def test_shared_secret_matches_rfc_both_directions(self):
        self.assertEqual(scalarmult(ALICE_PRIV, BOB_PUB), SHARED)
        self.assertEqual(scalarmult(BOB_PRIV, ALICE_PUB), SHARED)


class TestNaClBoxVector(AsyncTestCase):
    """The canonical libsodium box test vector -- proves the full
    Curve25519 + HSalsa20 + Salsa20 + Poly1305 pipeline."""

    async def test_libsodium_box_vector(self):
        nonce = binascii.unhexlify(
            "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"
        )
        msg = binascii.unhexlify(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5e"
            "cbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8"
            "250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb4"
            "8f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705"
        )
        expected = binascii.unhexlify(
            "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce483"
            "32ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c2"
            "0f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368"
            "517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a4"
            "3d14a6599b1f654cb45a74e355a5"
        )
        ct = nacl_box.seal(msg, nonce, BOB_PUB, ALICE_PRIV)
        self.assertEqual(ct, expected)
        dec = nacl_box.open_box(ct, nonce, ALICE_PUB, BOB_PRIV)
        self.assertEqual(dec, msg)

    async def test_box_open_rejects_tampered(self):
        nonce = b"\x00" * 24
        ct = nacl_box.seal(b"hello", nonce, BOB_PUB, ALICE_PRIV)
        # Flip one byte in the ciphertext -- MAC verify must fail.
        tampered = ct[:-1] + bytes([ct[-1] ^ 0x01])
        self.assertIsNone(
            nacl_box.open_box(tampered, nonce, ALICE_PUB, BOB_PRIV),
        )

    async def test_keypair_roundtrip(self):
        priv1, pub1 = nacl_box.generate_keypair()
        priv2, pub2 = nacl_box.generate_keypair()
        ct = nacl_box.seal(b"hello", b"\x00" * 24, pub2, priv1)
        dec = nacl_box.open_box(ct, b"\x00" * 24, pub1, priv2)
        self.assertEqual(dec, b"hello")


class TestPoly1305(AsyncTestCase):

    async def test_rfc_7539_vector(self):
        """RFC 7539 §2.5.2 reference vector."""
        key = binascii.unhexlify(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        )
        msg = b"Cryptographic Forum Research Group"
        expected = binascii.unhexlify("a8061dc1305136c6c22b8baf0c0127a9")
        self.assertEqual(poly1305_mac(key, msg), expected)

    async def test_verify_consistent(self):
        key = os.urandom(32)
        msg = b"hello world"
        tag = poly1305_mac(key, msg)
        self.assertTrue(poly1305_verify(key, msg, tag))
        self.assertFalse(poly1305_verify(key, msg + b"x", tag))


class TestEd25519ToCurve25519(AsyncTestCase):

    async def test_priv_pub_derivation_consistent(self):
        """Conversion of ed_priv and ed_pub must yield matching curve pair."""
        from ecdsa import SigningKey, Ed25519
        for _ in range(3):
            seed = os.urandom(32)
            sk = SigningKey.from_string(seed, curve=Ed25519)
            ed_pub = bytes(sk.verifying_key.to_string())
            curve_priv = ed25519_priv_seed_to_curve25519(seed)
            curve_pub_a = edwards_y_to_montgomery_u(ed_pub)
            curve_pub_b = scalarmult_base(curve_priv)
            self.assertEqual(curve_pub_a, curve_pub_b)

    async def test_box_works_with_converted_keys(self):
        """A box session keyed via ed-derived curve keys round-trips."""
        from ecdsa import SigningKey, Ed25519
        seed_a = os.urandom(32)
        seed_b = os.urandom(32)
        priv_a = ed25519_priv_seed_to_curve25519(seed_a)
        priv_b = ed25519_priv_seed_to_curve25519(seed_b)
        pub_a = edwards_y_to_montgomery_u(
            bytes(SigningKey.from_string(seed_a, curve=Ed25519).verifying_key.to_string())
        )
        pub_b = edwards_y_to_montgomery_u(
            bytes(SigningKey.from_string(seed_b, curve=Ed25519).verifying_key.to_string())
        )
        ct = nacl_box.seal(b"hi", b"\x00" * 24, pub_b, priv_a)
        dec = nacl_box.open_box(ct, b"\x00" * 24, pub_a, priv_b)
        self.assertEqual(dec, b"hi")


if __name__ == "__main__":
    unittest.main()
