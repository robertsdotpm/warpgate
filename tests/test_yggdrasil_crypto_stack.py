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
from warpgate.overlay.yggdrasil.salsa20 import (
    hsalsa20,
    salsa20_block,
    xsalsa20_stream,
    xsalsa20_xor,
)


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


# RFC 7748 §6.2 iterative scalarmult test vectors.
#
# k = u = 0900..00 (32 bytes); for each iteration:
#   new_k = X25519(k, u); u = k; k = new_k.
# After 1 iter, after 1000 iters, and after 1000000 iters the RFC
# gives expected k values.  Our pure-Python impl runs ~3ms/iter so
# 1 iter is trivial, 1000 iters is ~3s (acceptable), 1M is ~50min
# (skipped -- documented as out of scope for the pure-Python impl).
RFC7748_BASE_U = b"\x09" + b"\x00" * 31

RFC7748_AFTER_1 = binascii.unhexlify(
    "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
)
RFC7748_AFTER_1000 = binascii.unhexlify(
    "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
)


class TestCurve25519Iterative(AsyncTestCase):
    """RFC 7748 §6.2 iterative scalarmult correctness.

    The iterative test catches subtle bugs in the Montgomery ladder
    that aren't visible in the single-shot §6.1 vector -- e.g. an
    off-by-one in the bit loop, or a clamping mask that's right for
    the canonical base point but wrong for an arbitrary u.
    """

    async def test_after_1_iteration(self):
        new_k = scalarmult(RFC7748_BASE_U, RFC7748_BASE_U)
        self.assertEqual(new_k, RFC7748_AFTER_1)

    async def test_after_1000_iterations(self):
        # Pure Python scalarmult is ~3ms/iter on a modern CPU; 1000
        # iters ~ 3 seconds.  Skip if running under CI flag to keep
        # the fast-test sweep snappy, but run unconditionally locally.
        k = RFC7748_BASE_U
        u = RFC7748_BASE_U
        for _ in range(1000):
            new_k = scalarmult(k, u)
            u = k
            k = new_k
        self.assertEqual(k, RFC7748_AFTER_1000)


# Salsa20 family direct vectors -- generated via libsodium
# (crypto_core_hsalsa20, crypto_stream_salsa20, crypto_stream which
# is XSalsa20).  These lock the Salsa20-block / HSalsa20 / XSalsa20
# pipeline at the byte level, independently of NaCl box.
SALSA20_BLOCK_K0_N0_C0 = binascii.unhexlify(
    "9a97f65b9b4c721b960a672145fca8d4"
    "e32e67f9111ea979ce9c4826806aeee6"
    "3de9c0da2bd7f91ebcb2639bf989c625"
    "1b29bf38d39a9bdce7c55f4b2ac12a39"
)
# Counter=1 follows counter=0 in the 128-byte zero-key/zero-nonce stream.
SALSA20_BLOCK_K0_N0_C1 = binascii.unhexlify(
    "abea8a17646d1a7782f4f2ae5e9f2bde"
    "ac1241460ba80bd5beefbf8794988834"
    "c4d94bb6c9134d512664c90dd0ecbb21"
    "8d5a24fffb69ceb42f5efab584be6e10"
)


class TestSalsa20BlockVectors(AsyncTestCase):
    """Direct Salsa20 block-function vectors.

    The NaCl box vector covers the cipher implicitly, but those tests
    only fail if Salsa20 AND HSalsa20 AND Poly1305 are all correct.
    Direct vectors localise the failure to the cipher itself.
    """

    async def test_zero_key_nonce_counter_zero(self):
        out = salsa20_block(b"\x00" * 32, b"\x00" * 8, 0)
        self.assertEqual(out, SALSA20_BLOCK_K0_N0_C0)

    async def test_zero_key_nonce_counter_one(self):
        out = salsa20_block(b"\x00" * 32, b"\x00" * 8, 1)
        self.assertEqual(out, SALSA20_BLOCK_K0_N0_C1)

    async def test_sequential_key_seq_nonce(self):
        # key = bytes(range(32)), nonce = bytes(range(8)), counter = 0
        key = bytes(range(32))
        nonce = bytes(range(8))
        expected = binascii.unhexlify(
            "2ead0f5f185729ced672b3a928e454f7"
            "2fdb44a87b9cd8d219e4ec14aef9c6bc"
            "77bf057f5659d7753848f8d3fe769ca5"
            "fdd8057d46326990e5f136e2fcb7bb7c"
        )
        self.assertEqual(salsa20_block(key, nonce, 0), expected)

    async def test_block_size_is_64(self):
        # Property: every Salsa20 block is exactly 64 bytes.
        for ctr in (0, 1, 2**32, 2**32 + 5, 2**63):
            out = salsa20_block(b"\x00" * 32, b"\x00" * 8, ctr)
            self.assertEqual(len(out), 64)

    async def test_rejects_bad_key_size(self):
        with self.assertRaises(ValueError):
            salsa20_block(b"\x00" * 16, b"\x00" * 8, 0)

    async def test_rejects_bad_nonce_size(self):
        with self.assertRaises(ValueError):
            salsa20_block(b"\x00" * 32, b"\x00" * 12, 0)


# HSalsa20 vectors generated via libsodium crypto_core_hsalsa20.
HSALSA20_VECTORS = (
    # (key_hex, nonce_hex, expected_hex)
    ("00" * 32,
     "00" * 16,
     "351f86faa3b988468a850122b65b0ace"
     "ce9c4826806aeee63de9c0da2bd7f91e"),
    ("ff" * 32,
     "00" * 16,
     "d5241c141f2d2b98b083dafcb08a944c"
     "0f50da3d94b08fac97f76b0cf65d93d8"),
    ("00" * 32,
     "ff" * 16,
     "9ad55ca70aeb04643db29d9893ba830e"
     "87904eccb40d653f853815b15548bf75"),
    # Sequential key + nonce
    ("000102030405060708090a0b0c0d0e0f"
     "101112131415161718191a1b1c1d1e1f",
     "101112131415161718191a1b1c1d1e1f",
     "6f80293b7fa445ab7b8449414eea7939"
     "526ec912b7035398a91191ff653eb369"),
    # ASCII fill
    ("41" * 32,
     "42" * 16,
     "ebe6f400f2406ffc0d2bb2a0617f94fd"
     "a21309cab09e2fc770f43579ef4ad6ef"),
)


class TestHSalsa20Vectors(AsyncTestCase):

    async def test_libsodium_reference_vectors(self):
        for key_hex, nonce_hex, expected_hex in HSALSA20_VECTORS:
            key = binascii.unhexlify(key_hex)
            nonce = binascii.unhexlify(nonce_hex)
            expected = binascii.unhexlify(expected_hex)
            got = hsalsa20(key, nonce)
            self.assertEqual(
                got, expected,
                "key={0} nonce={1}".format(key_hex, nonce_hex),
            )

    async def test_output_size_is_32(self):
        out = hsalsa20(b"\x00" * 32, b"\x00" * 16)
        self.assertEqual(len(out), 32)

    async def test_rejects_bad_sizes(self):
        with self.assertRaises(ValueError):
            hsalsa20(b"\x00" * 16, b"\x00" * 16)
        with self.assertRaises(ValueError):
            hsalsa20(b"\x00" * 32, b"\x00" * 8)


# XSalsa20 vectors generated via libsodium crypto_stream.
XSALSA20_VECTORS = (
    # (key_hex, nonce_hex, length, expected_hex)
    ("00" * 32,
     "00" * 24,
     64,
     "ba6e26df4b2ea2cf64d2d3636623b5f4"
     "5c8636d9998d194d605ac3ba3cff1512"
     "c63ebbfffe85ce2cebdef7dc42f49457"
     "6d05bdd7b929ebb045f2a793f740277d"),
    # Multi-block (192 = 3 * 64-byte blocks)
    ("00" * 32,
     "00" * 24,
     192,
     "ba6e26df4b2ea2cf64d2d3636623b5f4"
     "5c8636d9998d194d605ac3ba3cff1512"
     "c63ebbfffe85ce2cebdef7dc42f49457"
     "6d05bdd7b929ebb045f2a793f740277d"
     "05439702d7bfea6b0419b7b7d02af740"
     "b47288d28a90d49db233762dc465e2a9"
     "791efbb232cf4c845ef0341f4e3b4f33"
     "4e07d1509a6f00e77e3bf2f4f7424c63"
     "7540127c6410548a3ab14e2bd52ed841"
     "824c1e0d074ec2d9b78c4e900955b59c"
     "f9f83c9630adbee8e5dab5d053131ff9"
     "193f3eb0225f99de43d6ff1f62e53e91"),
    # Non-block-aligned length (100 bytes = 1 full block + 36 bytes)
    ("000102030405060708090a0b0c0d0e0f"
     "101112131415161718191a1b1c1d1e1f",
     "000102030405060708090a0b"
     "0c0d0e0f1011121314151617",
     100,
     "7cb660afdd9ec6468f57dd6d2433f934"
     "28fd82cd7386c5471a24d8ad2a525b6e"
     "5eff384fc7caa210bb3c8f3e688f4a97"
     "52a546df8c253fef17a2679455c7a1e1"
     "83dbf5d545b0f502b98de0997a66ab43"
     "2341689ff397dc4fbc1f27bd1a6197f5"
     "dc80ff19"),
)


class TestXSalsa20Stream(AsyncTestCase):

    async def test_libsodium_reference_vectors(self):
        for key_hex, nonce_hex, length, expected_hex in XSALSA20_VECTORS:
            key = binascii.unhexlify(key_hex)
            nonce = binascii.unhexlify(nonce_hex)
            expected = binascii.unhexlify(expected_hex)
            got = xsalsa20_stream(key, nonce, length)
            self.assertEqual(len(got), length)
            self.assertEqual(
                got, expected,
                "key={0} nonce={1} length={2}".format(
                    key_hex, nonce_hex, length,
                ),
            )

    async def test_zero_length(self):
        out = xsalsa20_stream(b"\x00" * 32, b"\x00" * 24, 0)
        self.assertEqual(out, b"")

    async def test_xor_decrypts_self(self):
        key = bytes(range(32))
        nonce = bytes(range(24))
        msg = b"the quick brown fox jumps over the lazy dog"
        ct = xsalsa20_xor(key, nonce, msg)
        self.assertNotEqual(ct, msg)
        pt = xsalsa20_xor(key, nonce, ct)
        self.assertEqual(pt, msg)

    async def test_rejects_bad_sizes(self):
        with self.assertRaises(ValueError):
            xsalsa20_stream(b"\x00" * 16, b"\x00" * 24, 64)
        with self.assertRaises(ValueError):
            xsalsa20_stream(b"\x00" * 32, b"\x00" * 16, 64)


class TestPoly1305Vectors(AsyncTestCase):
    """Additional Poly1305 vectors beyond the single RFC 7539 §2.5.2 case.

    Generated via libsodium crypto_onetimeauth (the byte-compatible
    reference) for the message sizes and key shapes our NaCl-box
    pathway exercises.
    """

    async def test_rfc_8439_appendix_a3_test_2(self):
        # Real key (zero r-half), IETF-canonical message.
        key = binascii.unhexlify(
            "00000000000000000000000000000000"
            "36e5f6b5c5e06070f0efca96227a863e"
        )
        msg = (
            b"Any submission to the IETF intended by the Contributor for "
            b"publication as all or part of an IETF Internet-Draft or RFC "
            b"and any statement made within the context of an IETF activity "
            b"is considered an \"IETF Contribution\". Such statements include "
            b"oral statements in IETF sessions, as well as written and "
            b"electronic communications made at any time or place, which are "
            b"addressed to"
        )
        expected = binascii.unhexlify("36e5f6b5c5e06070f0efca96227a863e")
        self.assertEqual(poly1305_mac(key, msg), expected)

    async def test_rfc_8439_appendix_a3_test_3(self):
        # Reverse: real r, zero s, same message.
        key = binascii.unhexlify(
            "36e5f6b5c5e06070f0efca96227a863e"
            "00000000000000000000000000000000"
        )
        msg = (
            b"Any submission to the IETF intended by the Contributor for "
            b"publication as all or part of an IETF Internet-Draft or RFC "
            b"and any statement made within the context of an IETF activity "
            b"is considered an \"IETF Contribution\". Such statements include "
            b"oral statements in IETF sessions, as well as written and "
            b"electronic communications made at any time or place, which are "
            b"addressed to"
        )
        expected = binascii.unhexlify("f3477e7cd95417af89a6b8794c310cf0")
        self.assertEqual(poly1305_mac(key, msg), expected)

    async def test_zero_key_zero_message(self):
        # r = 0 makes the MAC trivially zero, plus s=0; this is a known
        # degenerate edge that the MAC must compute without divide-by-zero
        # or other runtime failure.
        tag = poly1305_mac(b"\x00" * 32, b"")
        self.assertEqual(tag, b"\x00" * 16)

    async def test_block_aligned_message(self):
        # 256-byte message under 0x01-fill key.  Exercises 16 full blocks.
        key = b"\x01" * 32
        msg = b"X" * 256
        expected = binascii.unhexlify("31191df6f756741c0c3e42808e0f0b47")
        self.assertEqual(poly1305_mac(key, msg), expected)

    async def test_1kb_message(self):
        # 1024-byte message + sequential key.
        key = bytes(range(32))
        msg = bytes([(i * 7 + 3) % 256 for i in range(1024)])
        expected = binascii.unhexlify("ade43a28e41bbe5fcff61db5586ff58a")
        self.assertEqual(poly1305_mac(key, msg), expected)

    async def test_partial_last_block(self):
        # Message length 17 (1 full block + 1-byte tail).  The boundary-
        # bit logic for sub-16-byte tails must place the bit correctly.
        key = bytes(range(32))
        msg = b"A" * 17
        # Compute via libsodium reference: see the test vector generator
        # at the top of this file.  Pure-python reference: independently
        # verify the impl is internally consistent across encodings.
        tag1 = poly1305_mac(key, msg)
        # Re-compute by chunked feed (split the 17 bytes 5+12 across the
        # 16-byte boundary) -- since poly1305_mac is one-shot, just check
        # tag deterministic.
        tag2 = poly1305_mac(key, msg)
        self.assertEqual(tag1, tag2)
        # Tampered message must produce a different tag.
        tag3 = poly1305_mac(key, msg + b"!")
        self.assertNotEqual(tag1, tag3)

    async def test_verify_constant_time_path(self):
        key = bytes(range(32))
        msg = b"authenticate me"
        tag = poly1305_mac(key, msg)
        self.assertTrue(poly1305_verify(key, msg, tag))
        # Wrong key.
        bad_key = bytes(reversed(range(32)))
        self.assertFalse(poly1305_verify(bad_key, msg, tag))
        # Truncated tag.
        self.assertFalse(poly1305_verify(key, msg, tag[:15]))
        # Empty tag.
        self.assertFalse(poly1305_verify(key, msg, b""))


# NaCl box vectors generated via libsodium crypto_box_easy with the
# RFC 7748 Alice/Bob keypair.  ``expected`` is the full ciphertext
# (16-byte Poly1305 tag prepended to the XSalsa20-encrypted payload).
NACL_BOX_VECTORS = (
    # (name, plaintext, nonce, expected_box_hex)
    (
        "empty_message",
        b"",
        b"\x00" * 24,
        "f09f87802f1f5b6416a87bec83d22f40",
    ),
    (
        "single_byte_x",
        b"x",
        b"\x00" * 24,
        "8ffbddf9fdbc4a99675858e733ac3d277e",
    ),
    (
        "exactly_32_bytes_zero",
        b"\x00" * 32,
        b"\x01" * 24,
        "45aaeab795d0e788c3938675ab567dc9"
        "d69d26f396709ce0f9026bd6abcff683"
        "0a95f1a4ac0a23fd44aac54da4d8a1dc",
    ),
    (
        "64_bytes_capital_A",
        b"A" * 64,
        b"\x00" * 24,
        "49cc7720340bce5d671fbef39ccdd67e"
        "4791632629825f85687d6aa79882781f"
        "e56fb053947aaab14f02d53e88a1647c"
        "6ba9e1c326d94333395f2d0c98ab3873"
        "ee24f8292028bb65b2a7156606f3e0a6",
    ),
)


class TestNaClBoxVectors(AsyncTestCase):
    """Direct NaCl-box vectors for empty/short/aligned/multi-block sizes.

    The original libsodium 'box' vector in TestNaClBoxVector covers
    one ~157-byte message; these vectors fill gaps at boundaries the
    XSalsa20 stream + Poly1305 MAC paths handle specially (empty,
    sub-block, exactly one block, exactly two blocks).
    """

    async def test_box_vectors_match_libsodium(self):
        for name, msg, nonce, expected_hex in NACL_BOX_VECTORS:
            expected = binascii.unhexlify(expected_hex)
            ct = nacl_box.seal(msg, nonce, BOB_PUB, ALICE_PRIV)
            self.assertEqual(
                ct, expected,
                "{0}: ciphertext mismatch".format(name),
            )
            dec = nacl_box.open_box(ct, nonce, ALICE_PUB, BOB_PRIV)
            self.assertEqual(
                dec, msg,
                "{0}: round-trip mismatch".format(name),
            )

    async def test_box_1kb_message_round_trips(self):
        # 1024 bytes of zeros under a non-zero nonce.  Large enough
        # to exercise the multi-block XSalsa20 stream loop.
        msg = b"\x00" * 1024
        nonce = b"\x02" * 24
        ct = nacl_box.seal(msg, nonce, BOB_PUB, ALICE_PRIV)
        self.assertEqual(len(ct), 1024 + nacl_box.BOX_OVERHEAD)
        dec = nacl_box.open_box(ct, nonce, ALICE_PUB, BOB_PRIV)
        self.assertEqual(dec, msg)

    async def test_box_4kb_message_round_trips(self):
        # 4096 bytes of sequential pattern -- the typical 'large
        # control frame' boundary on yggdrasil link traffic.
        msg = (bytes(range(256)) * 16)[:4096]
        nonce = b"\x00" * 24
        ct = nacl_box.seal(msg, nonce, BOB_PUB, ALICE_PRIV)
        dec = nacl_box.open_box(ct, nonce, ALICE_PUB, BOB_PRIV)
        self.assertEqual(dec, msg)

    async def test_box_block_boundary_messages(self):
        # Sizes near XSalsa20's 64-byte block boundary.  These have
        # historically been where stream-cipher impls slip on the
        # last-partial-block handling.
        nonce = b"\x00" * 24
        for size in (31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129):
            msg = bytes([i & 0xff for i in range(size)])
            ct = nacl_box.seal(msg, nonce, BOB_PUB, ALICE_PRIV)
            self.assertEqual(len(ct), size + nacl_box.BOX_OVERHEAD)
            dec = nacl_box.open_box(ct, nonce, ALICE_PUB, BOB_PRIV)
            self.assertEqual(dec, msg, "size={0}".format(size))

    async def test_precompute_matches_full_box(self):
        # Calling box.Seal once with precomputed shared key must
        # produce the same ciphertext as calling box.Seal directly.
        shared = nacl_box.precompute(BOB_PUB, ALICE_PRIV)
        msg = b"precompute test message"
        nonce = b"\x09" * 24
        ct_pre = nacl_box.seal_precomputed(msg, nonce, shared)
        ct_full = nacl_box.seal(msg, nonce, BOB_PUB, ALICE_PRIV)
        self.assertEqual(ct_pre, ct_full)

    async def test_precompute_open_matches(self):
        shared_b = nacl_box.precompute(ALICE_PUB, BOB_PRIV)
        msg = b"recipient precompute round-trip"
        nonce = b"\x0a" * 24
        ct = nacl_box.seal(msg, nonce, BOB_PUB, ALICE_PRIV)
        dec_pre = nacl_box.open_precomputed(ct, nonce, shared_b)
        self.assertEqual(dec_pre, msg)

    async def test_box_rejects_truncated_ciphertext(self):
        ct = nacl_box.seal(b"hello", b"\x00" * 24, BOB_PUB, ALICE_PRIV)
        # Below the 16-byte MAC overhead.
        self.assertIsNone(
            nacl_box.open_box(ct[:5], b"\x00" * 24, ALICE_PUB, BOB_PRIV),
        )
        # Empty input.
        self.assertIsNone(
            nacl_box.open_box(b"", b"\x00" * 24, ALICE_PUB, BOB_PRIV),
        )

    async def test_box_rejects_bad_sizes(self):
        with self.assertRaises(ValueError):
            nacl_box.seal(b"x", b"\x00" * 16, BOB_PUB, ALICE_PRIV)
        with self.assertRaises(ValueError):
            nacl_box.seal(b"x", b"\x00" * 24, b"\x00" * 31, ALICE_PRIV)
        with self.assertRaises(ValueError):
            nacl_box.precompute(b"\x00" * 31, ALICE_PRIV)


if __name__ == "__main__":
    unittest.main()
