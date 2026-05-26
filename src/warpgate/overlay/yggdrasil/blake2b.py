"""Pure-Python Blake2b implementation, RFC 7693 reference algorithm.

We need Blake2b because the Yggdrasil handshake (``src/core/version.go``
in yggdrasil-go) signs a ``blake2b-512-keyed(password)(public_key)``
hash, and the keyed-hash form isn't in Python 3.5's stdlib
``hashlib`` (Python 3.6+ ships it, but warpgate's floor is 3.5).
C-backed alternatives (``pyblake2``, ``pynacl``) fall over on the
3.5 install path on Windows because their wheels don't span the
old toolchain.  Pure Python avoids the entire compile-on-Windows
trap at the cost of being slower than the C version -- not a
problem for handshake hashes (one per peer link, ~tens of microseconds
of CPU).

The implementation is a direct port of the RFC 7693 reference and
matches the upstream Go ``golang.org/x/crypto/blake2b`` byte-for-byte
on:

  * the empty / short / 64-byte / 32-byte / large inputs in the RFC
    test vector list
  * keyed hashes with empty + short + 64-byte keys
  * 64-byte output size (the only one Yggdrasil uses)

Test vectors live in ``tests/test_yggdrasil_blake2b.py`` and include
the RFC 7693 Appendix-A vector ("abc" → 64-byte digest) plus
Go-generated vectors that exercise the keyed-mode path Yggdrasil
specifically uses.
"""
import struct


# Blake2b IV constants (the first 8 SHA-512 IVs, lifted unchanged).
# Source: RFC 7693 Section 2.6.  Used as the initial state h[0..7].
IV = (
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
)

# Message word permutation table.  RFC 7693 Section 2.7.
# 12 rounds, each round selects 16 words from the 16-word message
# block in a round-specific order.  Blake2b uses the first 12 of
# the 10 permutations cyclically (rows 11 and 12 reuse rows 1 and 2).
SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
)

# 64-bit mask -- Python ints are unbounded so we mask after every op
# that should wrap.  Keeps the implementation matching the spec's
# fixed-width semantics without per-line `% (1 << 64)`.
MASK64 = 0xFFFFFFFFFFFFFFFF


def rotr64(x, n):
    """Right-rotate a 64-bit value by ``n`` bits.  Mask before AND-OR'ing
    so a Python int that's grown larger than 2**64 still produces the
    correct width-bounded rotation."""
    x &= MASK64
    return ((x >> n) | (x << (64 - n))) & MASK64


def mix(v, a, b, c, d, x, y):
    """RFC 7693 G function in-place on v[0..15].

    Updates four words of ``v`` (indexed by ``a, b, c, d``) using the
    two message words ``x`` and ``y``.  This is the core mixing
    primitive called 8 times per round (4x column + 4x diagonal).
    """
    v[a] = (v[a] + v[b] + x) & MASK64
    v[d] = rotr64(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & MASK64
    v[b] = rotr64(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + y) & MASK64
    v[d] = rotr64(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & MASK64
    v[b] = rotr64(v[b] ^ v[c], 63)


def compress(h, block, t, final):
    """Compress one 128-byte block into the 8-word state ``h``.

    ``block`` is exactly 128 bytes (the BLAKE2b block size).  ``t`` is
    the 128-bit byte counter as a Python int (we split into two
    64-bit halves inside).  ``final`` is True only on the very last
    block of the message; it flips the f[0] flag that distinguishes
    finalisation from a mid-stream compression.
    """
    # Parse the 128-byte block as 16 little-endian uint64s.
    m = struct.unpack("<16Q", block)

    # Init working vector v[0..15]: v[0..7] = h, v[8..15] = IV with
    # IV[12] XORed against the low 64 bits of t, IV[13] against the
    # high 64 bits, and IV[14] flipped on finalisation.
    v = [
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
        IV[0], IV[1], IV[2], IV[3],
        IV[4] ^ (t & MASK64),
        IV[5] ^ ((t >> 64) & MASK64),
        IV[6] ^ (MASK64 if final else 0),
        IV[7],
    ]

    # 12 rounds of column + diagonal mixing.  Each round picks message
    # words via SIGMA[round_index].
    for r in range(12):
        s = SIGMA[r]
        # Column step.
        mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        # Diagonal step.
        mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])

    # XOR v[0..7] and v[8..15] back into h.
    for i in range(8):
        h[i] = (h[i] ^ v[i] ^ v[i + 8]) & MASK64


class Blake2b(object):
    """Streaming Blake2b hasher.

    Constructor matches the keyword shape used by Python 3.6+'s
    ``hashlib.blake2b`` for the subset of options Yggdrasil needs
    (``key`` and ``digest_size``).  Other Blake2 features (salt,
    person, tree mode) are not implemented because no upstream
    handshake path uses them; calling with unsupported kwargs is a
    ValueError so silent silent-different-hash bugs can't sneak in.
    """

    BLOCK_SIZE = 128
    MAX_DIGEST_SIZE = 64
    MAX_KEY_SIZE = 64

    def __init__(self, data=b"", key=b"", digest_size=64):
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("data must be bytes")
        if not isinstance(key, (bytes, bytearray)):
            raise ValueError("key must be bytes")
        if not (1 <= digest_size <= self.MAX_DIGEST_SIZE):
            raise ValueError("digest_size out of range")
        if len(key) > self.MAX_KEY_SIZE:
            raise ValueError("key too long")
        self.digest_size = digest_size
        self.buffer = bytearray()
        self.t = 0
        self.finalized = False
        # h[0] is XORed with the parameter block as a tiny header:
        # byte 0 = digest_size, byte 1 = key length, byte 2 = fanout
        # (=1, sequential mode), byte 3 = depth (=1, sequential mode).
        # All other parameter-block bytes are zero for our use case.
        self.h = list(IV)
        self.h[0] ^= 0x01010000 | (len(key) << 8) | digest_size
        # Keyed mode: prepend the key padded to one full block.
        if key:
            padded = bytes(key) + b"\x00" * (self.BLOCK_SIZE - len(key))
            self.update(padded)
        if data:
            self.update(data)

    def update(self, data):
        """Feed ``data`` into the hash.  Handles arbitrary chunking."""
        if self.finalized:
            raise ValueError("update after finalize")
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("data must be bytes")
        self.buffer.extend(data)
        # Process every full block EXCEPT the last one in the buffer --
        # we hold onto the trailing block in case it's the final one
        # (the final-block flag is set differently inside compress()).
        while len(self.buffer) > self.BLOCK_SIZE:
            block = bytes(self.buffer[: self.BLOCK_SIZE])
            self.t += self.BLOCK_SIZE
            compress(self.h, block, self.t, False)
            del self.buffer[: self.BLOCK_SIZE]
        return self

    def digest(self):
        """Return the digest bytes.  Idempotent."""
        if not self.finalized:
            # Finalise: pad the last partial block with zeros to a
            # full 128 bytes, advance t by the *real* unpadded length,
            # then compress with the final flag set.
            last = bytes(self.buffer) + b"\x00" * (
                self.BLOCK_SIZE - len(self.buffer)
            )
            self.t += len(self.buffer)
            compress(self.h, last, self.t, True)
            self.finalized = True
            self.final_digest = b"".join(
                struct.pack("<Q", w) for w in self.h
            )[: self.digest_size]
        return self.final_digest

    def hexdigest(self):
        """Return the hex-encoded digest as a str."""
        return self.digest().hex() if hasattr(bytes, "hex") else \
            "".join("%02x" % b for b in self.digest())


def blake2b_hash(data, key=b"", digest_size=64):
    """One-shot helper: ``blake2b(data, key=..., digest_size=...).digest()``.

    Matches the surface of ``hashlib.blake2b(data, key=...).digest()``
    so call sites that may run on either Python 3.5 (our impl) or
    3.6+ (stdlib) can share a code path through a small adapter.
    """
    return Blake2b(data, key=key, digest_size=digest_size).digest()
