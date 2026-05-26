"""Pure-Python Poly1305 one-time authenticator.

Implements RFC 7539 Poly1305: a 16-byte MAC over arbitrary-length
messages using a 32-byte one-time key.  Used in NaCl's
``secretbox`` / ``box`` to authenticate XSalsa20 ciphertexts.

The 32-byte key is split into two halves:
  * the first 16 bytes are clamped + interpreted as the
    polynomial coefficient ``r`` modulo 2^130 - 5
  * the second 16 bytes are added as the additive constant ``s``

The message is processed in 16-byte blocks, each interpreted as a
130-bit integer (the high bit set to mark the block boundary).
The MAC is ``(((r*m1 + r^2*m0 + ...) + s) mod 2^130 - 5)`` mod 2^128.
"""

P130 = (1 << 130) - 5
MASK128 = (1 << 128) - 1
R_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def poly1305_mac(key, message):
    """Return the 16-byte Poly1305 MAC of ``message`` under ``key``.

    ``key`` is 32 bytes (the first 16 bytes are the polynomial r,
    clamped; the second 16 are the additive constant s).
    ``message`` is arbitrary-length bytes.
    """
    if len(key) != 32:
        raise ValueError("poly1305_mac: key must be 32 bytes")
    # Parse r (first 16 bytes LE) with clamping per RFC.
    r = int.from_bytes(key[:16], "little") & R_CLAMP
    s = int.from_bytes(key[16:32], "little")

    acc = 0
    msg = memoryview(message)
    offset = 0
    while offset < len(msg):
        chunk = bytes(msg[offset:offset + 16])
        offset += 16
        # Append the boundary bit: 0x01 byte after the chunk.
        # Block value = LE(chunk + 0x01) -- pad chunk with zeros
        # up to 16 bytes before adding the boundary bit at the
        # corresponding bit position.
        chunk_int = int.from_bytes(chunk, "little") | (1 << (8 * len(chunk)))
        acc = (acc + chunk_int) % P130
        acc = (acc * r) % P130

    acc = (acc + s) & MASK128
    return acc.to_bytes(16, "little")


def poly1305_verify(key, message, expected_tag):
    """Constant-time verification of ``expected_tag`` against the computed MAC."""
    if len(expected_tag) != 16:
        return False
    computed = poly1305_mac(key, message)
    # Constant-time compare via XOR-OR fold.
    diff = 0
    for a, b in zip(computed, expected_tag):
        diff |= a ^ b
    return diff == 0
