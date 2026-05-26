"""Pure-Python murmur3-128 + sum256 -- byte-compat with bits-and-blooms.

Port of ``github.com/bits-and-blooms/bloom/murmur.go``.  The bloom
filter library used by ironwood derives K hash positions from a
``sum256`` that calls murmur3-128 twice -- once on the raw data,
once on the data with a 0x01 byte virtually appended -- producing
four 64-bit hash values that are linearly combined into K
locations.

We mirror that exact pipeline because the on-wire bloom filter
shares its bit positions across peers; two implementations that
hash differently would produce silently-incompatible filters.

This is a pure-Python implementation -- no C extension, no
optional deps -- so it runs everywhere the rest of the warpgate
stack runs (Python 3.5+ floor, every platform).  Performance is
roughly ~20µs per 32-byte key on a modern CPU; bloom usage in
the routing layer is ~1 add per peer per second, so the cost is
trivial.
"""
import struct


# Spec constants from the murmur3-128 reference.
C1 = 0x87C37B91114253D5
C2 = 0x4CF5AD432745937F
MASK64 = (1 << 64) - 1


def rotl64(x, n):
    """64-bit left-rotate of ``x`` by ``n`` bits.

    Python ints are unbounded; mask explicitly so the shift stays
    inside 64 bits before the rotation completes.
    """
    x &= MASK64
    n &= 63
    return ((x << n) | (x >> (64 - n))) & MASK64


def fmix64(k):
    """The fmix64 finalizer used by murmur3-128 to mix output bits."""
    k &= MASK64
    k ^= k >> 33
    k = (k * 0xFF51AFD7ED558CCD) & MASK64
    k ^= k >> 33
    k = (k * 0xC4CEB9FE1A85EC53) & MASK64
    k ^= k >> 33
    return k


def bmix_words(h1, h2, k1, k2):
    """Mix two 8-byte words into the running hash state.

    Direct port of upstream's ``bmix_words``: rotate / multiply /
    accumulate dance.  Returns the updated ``(h1, h2)``.
    """
    k1 = (k1 * C1) & MASK64
    k1 = rotl64(k1, 31)
    k1 = (k1 * C2) & MASK64
    h1 ^= k1
    h1 &= MASK64

    h1 = rotl64(h1, 27)
    h1 = (h1 + h2) & MASK64
    h1 = ((h1 * 5) + 0x52DCE729) & MASK64

    k2 = (k2 * C2) & MASK64
    k2 = rotl64(k2, 33)
    k2 = (k2 * C1) & MASK64
    h2 ^= k2
    h2 &= MASK64

    h2 = rotl64(h2, 31)
    h2 = (h2 + h1) & MASK64
    h2 = ((h2 * 5) + 0x38495AB5) & MASK64
    return h1, h2


def bmix(h1, h2, data):
    """Process ``data`` in 16-byte blocks; return updated ``(h1, h2)``."""
    nblocks = len(data) // 16
    for i in range(nblocks):
        chunk = data[i * 16 : (i + 1) * 16]
        k1, k2 = struct.unpack("<QQ", chunk)
        h1, h2 = bmix_words(h1, h2, k1, k2)
    return h1, h2


def finalize_tail(h1, h2, pad_tail, length, tail):
    """Mix in the (up to 15-byte) tail + finalize.

    ``pad_tail=True`` virtually appends a 0x01 byte to the tail
    before mixing -- this is how ``sum256`` produces its second
    pair of hash values without a real allocation.
    """
    k1 = 0
    k2 = 0

    if pad_tail:
        slot = (len(tail) + 1) & 15
        # Place the appended 0x01 byte at the right slot index.
        if slot == 15:
            k2 ^= 1 << 48
        elif slot == 14:
            k2 ^= 1 << 40
        elif slot == 13:
            k2 ^= 1 << 32
        elif slot == 12:
            k2 ^= 1 << 24
        elif slot == 11:
            k2 ^= 1 << 16
        elif slot == 10:
            k2 ^= 1 << 8
        elif slot == 9:
            k2 ^= 1 << 0
            k2 = (k2 * C2) & MASK64
            k2 = rotl64(k2, 33)
            k2 = (k2 * C1) & MASK64
            h2 ^= k2
            h2 &= MASK64
        elif slot == 8:
            k1 ^= 1 << 56
        elif slot == 7:
            k1 ^= 1 << 48
        elif slot == 6:
            k1 ^= 1 << 40
        elif slot == 5:
            k1 ^= 1 << 32
        elif slot == 4:
            k1 ^= 1 << 24
        elif slot == 3:
            k1 ^= 1 << 16
        elif slot == 2:
            k1 ^= 1 << 8
        elif slot == 1:
            k1 ^= 1 << 0
            k1 = (k1 * C1) & MASK64
            k1 = rotl64(k1, 31)
            k1 = (k1 * C2) & MASK64
            h1 ^= k1
            h1 &= MASK64
        # slot == 0 falls through with k1/k2 still zero

    # Now the real tail bytes -- they layer on TOP of any pad_tail bits.
    tlen = len(tail) & 15
    if tlen >= 15:
        k2 ^= tail[14] << 48
    if tlen >= 14:
        k2 ^= tail[13] << 40
    if tlen >= 13:
        k2 ^= tail[12] << 32
    if tlen >= 12:
        k2 ^= tail[11] << 24
    if tlen >= 11:
        k2 ^= tail[10] << 16
    if tlen >= 10:
        k2 ^= tail[9] << 8
    if tlen >= 9:
        k2 ^= tail[8] << 0
    if tlen >= 9:
        k2 = (k2 * C2) & MASK64
        k2 = rotl64(k2, 33)
        k2 = (k2 * C1) & MASK64
        h2 ^= k2
        h2 &= MASK64
    if tlen >= 8:
        k1 ^= tail[7] << 56
    if tlen >= 7:
        k1 ^= tail[6] << 48
    if tlen >= 6:
        k1 ^= tail[5] << 40
    if tlen >= 5:
        k1 ^= tail[4] << 32
    if tlen >= 4:
        k1 ^= tail[3] << 24
    if tlen >= 3:
        k1 ^= tail[2] << 16
    if tlen >= 2:
        k1 ^= tail[1] << 8
    if tlen >= 1:
        k1 ^= tail[0] << 0
    if tlen >= 1:
        k1 = (k1 * C1) & MASK64
        k1 = rotl64(k1, 31)
        k1 = (k1 * C2) & MASK64
        h1 ^= k1
        h1 &= MASK64

    # Length mix-in + final fmix dance.
    h1 ^= length & MASK64
    h2 ^= length & MASK64

    h1 = (h1 + h2) & MASK64
    h2 = (h2 + h1) & MASK64

    h1 = fmix64(h1)
    h2 = fmix64(h2)

    h1 = (h1 + h2) & MASK64
    h2 = (h2 + h1) & MASK64

    return h1, h2


def sum128(data):
    """Compute the murmur3-128 hash of ``data``; return ``(h1, h2)``."""
    h1 = 0
    h2 = 0
    h1, h2 = bmix(h1, h2, data)
    length = len(data)
    tail_len = length % 16
    tail = data[length - tail_len:]
    return finalize_tail(h1, h2, False, length, tail)


def sum256(data):
    """Compute the four-uint64 hash used by bits-and-blooms.

    Equivalent to: ``murmur3-128(data) || murmur3-128(data || 0x01)``
    but without actually allocating ``data || 0x01`` -- we virtually
    append the byte during the tail-mixing step of the second
    hash, exactly like upstream.

    Returns ``(h1, h2, h3, h4)``.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("sum256: data must be bytes")
    data = bytes(data)

    # First hash: vanilla murmur3-128 over the input.
    h1 = h2 = 0
    h1, h2 = bmix(h1, h2, data)
    length = len(data)
    tail_len = length % 16
    tail = data[length - tail_len:]
    hash1, hash2 = finalize_tail(h1, h2, False, length, tail)

    # Second hash: virtually appends a 0x01 byte to ``data``.  If
    # that pushes the tail to a full 16 bytes we process the
    # synthesized block via bmix_words and finalize with an empty
    # tail; otherwise we feed the existing tail to finalize_tail
    # with pad_tail=True so the 0x01 lands in the right slot.
    if tail_len + 1 == 16:
        # Full extra block: synthesize the 16-byte block from tail + 0x01.
        word1 = struct.unpack("<Q", tail[:8])[0]
        word2 = (struct.unpack("<I", tail[8:12])[0]
                 | (tail[12] << 32)
                 | (tail[13] << 40)
                 | (tail[14] << 48)
                 | (1 << 56))
        h1n, h2n = bmix_words(h1, h2, word1, word2)
        hash3, hash4 = finalize_tail(h1n, h2n, False, length + 1, b"")
    else:
        hash3, hash4 = finalize_tail(h1, h2, True, length + 1, tail)

    return hash1, hash2, hash3, hash4
