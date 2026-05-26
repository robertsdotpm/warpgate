"""Pure-Python Poly1305 one-time authenticator (RFC 8439 section 2.5).

Same algorithm as the Poly1305 in ``warpgate.overlay.yggdrasil`` --
copied here intentionally so the libp2p plugin stays self-contained
in its own directory (per the plugin-scope constraint).  The two
implementations are independent; either could be optimised without
touching the other.

32-byte one-time key:
  * first 16 bytes -> polynomial coefficient r (clamped per RFC)
  * second 16 bytes -> additive constant s

Message processed in 16-byte blocks each interpreted as a 130-bit
integer (high bit set as block-boundary marker).  MAC is
``(((r*m1 + r^2*m0 + ...) + s) mod 2^130 - 5)`` truncated to 128
bits.
"""

P130 = (1 << 130) - 5
MASK128 = (1 << 128) - 1
R_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def poly1305_mac(key, message):
    """Return the 16-byte Poly1305 MAC of ``message`` under ``key``."""
    if len(key) != 32:
        raise ValueError("poly1305_mac: key must be 32 bytes")
    r = int.from_bytes(key[:16], "little") & R_CLAMP
    s = int.from_bytes(key[16:32], "little")

    acc = 0
    msg = memoryview(message)
    offset = 0
    total = len(msg)
    while offset < total:
        end = offset + 16
        if end > total:
            end = total
        chunk = bytes(msg[offset:end])
        offset = end
        chunk_int = int.from_bytes(chunk, "little") | (1 << (8 * len(chunk)))
        acc = (acc + chunk_int) % P130
        acc = (acc * r) % P130

    acc = (acc + s) & MASK128
    return acc.to_bytes(16, "little")


def poly1305_verify(key, message, expected_tag):
    """Constant-time verification of ``expected_tag`` against the MAC."""
    if len(expected_tag) != 16:
        return False
    computed = poly1305_mac(key, message)
    diff = 0
    for a, b in zip(computed, expected_tag):
        diff |= a ^ b
    return diff == 0
