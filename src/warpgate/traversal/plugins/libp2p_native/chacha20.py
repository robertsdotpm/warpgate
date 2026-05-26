"""ChaCha20 stream cipher (RFC 8439).

Pure-Python, dependency-free, ~70 LOC of actual cipher.  Slow vs
optimised C (~3-5 MB/s on a modern CPU) but plenty fast for the
Noise XX handshake (3 messages, each <500 bytes) and ordinary
warpgate-relay-grade application traffic.

The cipher operates on 64-byte blocks generated from
(key=32B, counter=u32, nonce=12B); the per-block output is XORed
into the plaintext stream.  No keystream caching across calls --
each ``chacha20_encrypt`` call regenerates from the supplied
counter, matching the way Noise / RFC 8439 AEAD use the cipher.
"""
import struct


def rotl32(v, c):
    """Left-rotate a 32-bit word by c bits, wrapping."""
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF


def quarter_round(state, a, b, c, d):
    """RFC 8439 section 2.1 quarter-round, in place on a list of u32s."""
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotl32(state[b] ^ state[c], 7)


# "expand 32-byte k" -- the four constants that pad the start of the
# initial state for the 256-bit-key variant of ChaCha20.
CONSTANTS = struct.unpack("<4I", b"expand 32-byte k")


def chacha20_block(key, counter, nonce):
    """Compute one 64-byte ChaCha20 keystream block.

    ``key`` is 32 bytes, ``counter`` is a uint32, ``nonce`` is 12 bytes.
    Returns 64 bytes.
    """
    if len(key) != 32:
        raise ValueError("chacha20: key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("chacha20: nonce must be 12 bytes")
    state = list(CONSTANTS) \
        + list(struct.unpack("<8I", key)) \
        + [counter & 0xFFFFFFFF] \
        + list(struct.unpack("<3I", nonce))
    working = list(state)
    for _ in range(10):
        # Column rounds.
        quarter_round(working, 0, 4,  8, 12)
        quarter_round(working, 1, 5,  9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        # Diagonal rounds.
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7,  8, 13)
        quarter_round(working, 3, 4,  9, 14)
    out = [(w + s) & 0xFFFFFFFF for w, s in zip(working, state)]
    return struct.pack("<16I", *out)


def chacha20_encrypt(key, counter, nonce, data):
    """Encrypt or decrypt ``data`` under (key, counter, nonce).

    ChaCha20 is a stream cipher, so encrypt and decrypt are the same
    operation -- XOR with the generated keystream.  ``counter`` is
    the starting block counter (RFC 8439 starts at 1 for AEAD
    payloads; 0 is reserved for the Poly1305 one-time key).
    """
    out = bytearray()
    pos = 0
    total = len(data)
    while pos < total:
        block = chacha20_block(key, counter, nonce)
        counter = (counter + 1) & 0xFFFFFFFF
        end = pos + 64
        if end > total:
            end = total
        chunk = data[pos:end]
        out.extend(bytes(a ^ b for a, b in zip(chunk, block)))
        pos = end
    return bytes(out)
