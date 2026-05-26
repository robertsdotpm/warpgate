"""Pure-Python Curve25519 (X25519) scalar multiplication.

Implements RFC 7748 X25519 -- the bilinear map used by NaCl's
``box`` (and therefore by Yggdrasil's encrypted layer) for ECDH
shared-secret derivation.  This module exposes two functions:

  * ``scalarmult(scalar, point)`` -- generic X25519 scalarmult
  * ``scalarmult_base(scalar)`` -- scalarmult with the standard
    base point ``9`` (i.e. derive public key from private key)

And one helper used by NaCl box for the Ed25519→Curve25519
conversion path:

  * ``edwards_y_to_montgomery_u(y)`` -- the (1+y)/(1-y) bilinear
    map that takes an Ed25519 y-coordinate to a Curve25519 u.

Performance: pure Python, ~30-50ms per scalarmult on a modern
CPU.  Slow vs C nacl, fast enough for one-shot session setup.

The implementation follows the RFC 7748 reference structure
(constant-time conditional swap in the Montgomery ladder)
because timing-dependent secrets leak more easily in Python
than in C anyway; this is "as constant-time as Python permits."
"""

# Curve25519 field prime (2^255 - 19).
P = (1 << 255) - 19

# Curve constant a24 = (486662 - 2) / 4 = 121665.
A24 = 121665

# Base point u-coordinate (per RFC 7748).
U_BASE = 9


def cswap(swap, x_2, x_3):
    """Constant-time swap of two ints if ``swap`` is 1."""
    # Python-style branchless swap via mask arithmetic.
    dummy = swap * (x_2 ^ x_3)
    return x_2 ^ dummy, x_3 ^ dummy


def clamp_scalar(scalar_bytes):
    """Apply RFC 7748 scalar clamping to a 32-byte scalar.

    Forces the low 3 bits to 0, the high bit of byte 31 to 0,
    and the second-high bit of byte 31 to 1.  This eliminates
    small-subgroup attacks + ensures the result is a multiple
    of the cofactor.
    """
    if len(scalar_bytes) != 32:
        raise ValueError("clamp_scalar: scalar must be 32 bytes")
    s = bytearray(scalar_bytes)
    s[0] &= 248
    s[31] &= 127
    s[31] |= 64
    # Decode little-endian to int.
    return int.from_bytes(bytes(s), "little")


def decode_u(u_bytes):
    """Decode a 32-byte u-coordinate.  Per RFC, top bit is masked off."""
    if len(u_bytes) != 32:
        raise ValueError("decode_u: u must be 32 bytes")
    u = bytearray(u_bytes)
    u[31] &= 0x7F  # Mask the top bit.
    return int.from_bytes(bytes(u), "little") % P


def encode_u(u_int):
    """Encode an int u-coordinate as 32 little-endian bytes."""
    u_int = u_int % P
    return u_int.to_bytes(32, "little")


def scalarmult(scalar_bytes, u_bytes):
    """X25519 scalar multiplication.

    ``scalar_bytes`` and ``u_bytes`` are both 32-byte little-endian.
    Returns the 32-byte little-endian product.
    """
    k = clamp_scalar(scalar_bytes)
    u = decode_u(u_bytes)

    # Montgomery ladder, RFC 7748 section 5.  255 iterations because
    # the clamping fixes bit 254 as the top significant bit.
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t

        a = (x_2 + z_2) % P
        aa = (a * a) % P
        b = (x_2 - z_2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x_3 + z_3) % P
        d = (x_3 - z_3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x_3 = pow((da + cb) % P, 2, P)
        z_3 = (x_1 * pow((da - cb) % P, 2, P)) % P
        x_2 = (aa * bb) % P
        z_2 = (e * ((aa + A24 * e) % P)) % P

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)

    result = (x_2 * pow(z_2, P - 2, P)) % P
    return encode_u(result)


def scalarmult_base(scalar_bytes):
    """X25519 with the standard base point u=9.  Derives a public key."""
    return scalarmult(scalar_bytes, encode_u(U_BASE))


def edwards_y_to_montgomery_u(y_bytes):
    """Convert an Ed25519 public-key y-coordinate to Curve25519 u.

    Per Filippo Valsorda's writeup (and the e2c code in ironwood):

      u = (1 + y) / (1 - y)  mod p

    Where ``y`` is the little-endian Ed25519 public key with the
    sign bit (msb of byte 31) cleared.  Used by NaCl box's
    ``crypto_sign_ed25519_pk_to_curve25519`` codepath, which
    yggdrasil-go uses to derive box keys from ed25519 keys.
    """
    if len(y_bytes) != 32:
        raise ValueError("edwards_y_to_montgomery_u: y must be 32 bytes")
    # ed25519 stores the y-coordinate little-endian with the sign
    # bit of x stored in the top bit of byte 31.  Mask it out.
    y_le = bytearray(y_bytes)
    y_le[31] &= 0x7F
    y = int.from_bytes(bytes(y_le), "little") % P
    # u = (1 + y) / (1 - y) mod p
    one_plus_y = (1 + y) % P
    one_minus_y = (1 - y) % P
    if one_minus_y == 0:
        raise ValueError("edwards_y_to_montgomery_u: y == 1")
    inv = pow(one_minus_y, P - 2, P)
    u = (one_plus_y * inv) % P
    return encode_u(u)


def ed25519_priv_seed_to_curve25519(seed):
    """Derive a Curve25519 scalar from an Ed25519 32-byte seed.

    NaCl's ``crypto_sign_ed25519_sk_to_curve25519`` strategy:
    take SHA-512(seed), then clamp the first 32 bytes.

    Returns the 32-byte little-endian Curve25519 private scalar.
    """
    if len(seed) != 32:
        raise ValueError("ed25519_priv_seed_to_curve25519: seed must be 32 bytes")
    import hashlib
    h = hashlib.sha512(bytes(seed)).digest()
    out = bytearray(h[:32])
    # Clamping is applied by scalarmult itself, but the canonical
    # ``ed25519_sk_to_curve25519`` returns the unclamped 32 bytes;
    # clamping happens at use time.  Match that.
    return bytes(out)
