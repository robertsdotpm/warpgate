"""Pure-Python Salsa20 / HSalsa20 / XSalsa20.

Yggdrasil's encrypted layer wraps NaCl's ``box``, which is
XSalsa20-Poly1305 over X25519 ECDH.  This module provides the
three Salsa20-family stream ciphers NaCl needs:

  * ``salsa20_block(key, nonce, counter)`` -- one 64-byte block of
    the Salsa20/20 stream
  * ``hsalsa20(key, nonce_16)`` -- the 32-byte HSalsa20 derivative
    used to derive a sub-key from a (key, nonce-prefix) pair
  * ``xsalsa20_stream(key, nonce_24, length)`` -- XSalsa20 stream
    of ``length`` bytes built on top of HSalsa20 + Salsa20

The XSalsa20 construction: split the 24-byte nonce into a 16-byte
prefix and an 8-byte tail.  Derive a subkey via HSalsa20(key,
prefix), then run Salsa20 with (subkey, tail) to produce the
stream.  Encryption is XOR of stream with plaintext; decryption
is the same operation.
"""
import struct


# Salsa20 constants (the "expand 32-byte k" tau-128 / sigma-256
# tags).  The implementation only uses sigma (32-byte key).
SIGMA = b"expand 32-byte k"


def rotl32(x, n):
    """32-bit left rotate."""
    x &= 0xFFFFFFFF
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def quarter_round(state, a, b, c, d):
    """Salsa20 quarter-round on a 16-word state, in-place."""
    state[b] ^= rotl32(state[a] + state[d], 7)
    state[c] ^= rotl32(state[b] + state[a], 9)
    state[d] ^= rotl32(state[c] + state[b], 13)
    state[a] ^= rotl32(state[d] + state[c], 18)


def salsa20_core(input_words, rounds=20):
    """20-round Salsa20 core: takes 16 LE uint32 words, returns 16."""
    x = list(input_words)
    for _ in range(rounds // 2):
        # Column round.
        quarter_round(x, 0, 4, 8, 12)
        quarter_round(x, 5, 9, 13, 1)
        quarter_round(x, 10, 14, 2, 6)
        quarter_round(x, 15, 3, 7, 11)
        # Row round.
        quarter_round(x, 0, 1, 2, 3)
        quarter_round(x, 5, 6, 7, 4)
        quarter_round(x, 10, 11, 8, 9)
        quarter_round(x, 15, 12, 13, 14)
    return [(x[i] + input_words[i]) & 0xFFFFFFFF for i in range(16)]


def salsa20_block(key, nonce, counter):
    """One 64-byte Salsa20/20 block.

    ``key`` is 32 bytes, ``nonce`` is 8 bytes, ``counter`` is a
    uint64.  Returns 64 bytes of stream.
    """
    if len(key) != 32:
        raise ValueError("salsa20_block: key must be 32 bytes")
    if len(nonce) != 8:
        raise ValueError("salsa20_block: nonce must be 8 bytes")
    # Salsa20 state layout per the spec:
    # [c0  k0  k1  k2  k3  c1  n0  n1
    #  i0  i1  c2  k4  k5  k6  k7  c3]
    # where c0..c3 = sigma in LE uint32; k0..k7 = key in LE uint32;
    # n0..n1 = nonce in LE uint32; i0..i1 = block-counter LE uint32.
    c0, c1, c2, c3 = struct.unpack("<4I", SIGMA)
    k = struct.unpack("<8I", key)
    n = struct.unpack("<2I", nonce)
    counter_lo = counter & 0xFFFFFFFF
    counter_hi = (counter >> 32) & 0xFFFFFFFF
    state = [
        c0,    k[0], k[1], k[2],
        k[3],  c1,   n[0], n[1],
        counter_lo, counter_hi, c2, k[4],
        k[5],  k[6], k[7], c3,
    ]
    out_words = salsa20_core(state)
    return struct.pack("<16I", *out_words)


def hsalsa20(key, nonce_16):
    """HSalsa20: keyed compression returning a 32-byte sub-key.

    Used by XSalsa20 to derive a subkey from (32-byte key, 16-byte
    nonce-prefix).  NaCl box uses it similarly during the shared-
    secret precomputation step.  Output is 8 of the 16 state
    words after the rounds (specifically the "constant" + "input"
    positions, NOT including the key/nonce slots).
    """
    if len(key) != 32:
        raise ValueError("hsalsa20: key must be 32 bytes")
    if len(nonce_16) != 16:
        raise ValueError("hsalsa20: nonce must be 16 bytes")
    c0, c1, c2, c3 = struct.unpack("<4I", SIGMA)
    k = struct.unpack("<8I", key)
    n = struct.unpack("<4I", nonce_16)
    state = [
        c0,   k[0], k[1], k[2],
        k[3], c1,   n[0], n[1],
        n[2], n[3], c2,   k[4],
        k[5], k[6], k[7], c3,
    ]
    # HSalsa20 does NOT add the input back -- it's just the rounds.
    x = list(state)
    for _ in range(10):
        quarter_round(x, 0, 4, 8, 12)
        quarter_round(x, 5, 9, 13, 1)
        quarter_round(x, 10, 14, 2, 6)
        quarter_round(x, 15, 3, 7, 11)
        quarter_round(x, 0, 1, 2, 3)
        quarter_round(x, 5, 6, 7, 4)
        quarter_round(x, 10, 11, 8, 9)
        quarter_round(x, 15, 12, 13, 14)
    # Output positions: 0, 5, 10, 15, 6, 7, 8, 9.  See the HSalsa20
    # spec; these are the four "constants" + the four "nonce"
    # positions in the original state.
    out_words = [x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9]]
    return struct.pack("<8I", *out_words)


def xsalsa20_stream(key, nonce_24, length):
    """Generate ``length`` bytes of XSalsa20 stream.

    ``key`` is 32 bytes, ``nonce_24`` is 24 bytes.  Returns
    exactly ``length`` bytes.  Use XOR with plaintext to encrypt
    or with ciphertext to decrypt.
    """
    if len(key) != 32:
        raise ValueError("xsalsa20_stream: key must be 32 bytes")
    if len(nonce_24) != 24:
        raise ValueError("xsalsa20_stream: nonce must be 24 bytes")
    sub_key = hsalsa20(key, nonce_24[:16])
    sub_nonce = nonce_24[16:24]
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(salsa20_block(sub_key, sub_nonce, counter))
        counter += 1
    return bytes(out[:length])


def xsalsa20_xor(key, nonce_24, data):
    """XOR ``data`` with the XSalsa20 stream -- encrypt or decrypt."""
    stream = xsalsa20_stream(key, nonce_24, len(data))
    return bytes(s ^ d for s, d in zip(stream, data))
