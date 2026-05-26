"""HKDF-SHA256 (RFC 5869) + the Noise-flavoured variant.

RFC 5869 defines:
    HKDF-Extract(salt, IKM) -> PRK   (HMAC-Hash(salt, IKM))
    HKDF-Expand(PRK, info, L) -> OKM (counter-mode HMAC chain)

Noise (Noise specification revision 34, §4.3) uses a slightly
different shape: HKDF takes (chaining_key, input_keying_material,
num_outputs) and returns ``num_outputs`` 32-byte keys.  Internally
it's HKDF-Extract followed by repeated HMACs with constants
0x01, 0x02, 0x03 chained through the previous output -- functionally
HKDF-Expand with the info field set to an empty byte string but the
counter-prefix-vs-suffix conventions are swapped vs RFC 5869.  This
module provides BOTH so callers can pick the right one for the
spec they're implementing.

Both functions use HMAC-SHA256.  Hash output is 32 bytes; PRK is
always 32 bytes; output keys here are also 32 bytes.
"""
import hashlib
import hmac


HASH_LEN = 32


def hkdf_extract(salt, ikm):
    """RFC 5869 HKDF-Extract: HMAC-Hash(salt, IKM)."""
    if not salt:
        salt = b"\x00" * HASH_LEN
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    """RFC 5869 HKDF-Expand: counter-mode HMAC chain."""
    if length > 255 * HASH_LEN:
        raise ValueError("hkdf_expand: length too large")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def noise_hkdf(chaining_key, input_keying_material, num_outputs):
    """Noise-spec HKDF: returns a tuple of up to 3 32-byte keys.

    Equivalent to HKDF-Extract(chaining_key, IKM) followed by an
    Expand-like chain with constant single-byte counters:

        temp_key = HMAC-Hash(chaining_key, IKM)
        output1  = HMAC-Hash(temp_key, 0x01)
        output2  = HMAC-Hash(temp_key, output1 || 0x02)
        output3  = HMAC-Hash(temp_key, output2 || 0x03)
    """
    if num_outputs < 1 or num_outputs > 3:
        raise ValueError("noise_hkdf: num_outputs must be 1, 2, or 3")
    temp_key = hmac.new(chaining_key, input_keying_material, hashlib.sha256).digest()
    output1 = hmac.new(temp_key, b"\x01", hashlib.sha256).digest()
    if num_outputs == 1:
        return (output1,)
    output2 = hmac.new(temp_key, output1 + b"\x02", hashlib.sha256).digest()
    if num_outputs == 2:
        return (output1, output2)
    output3 = hmac.new(temp_key, output2 + b"\x03", hashlib.sha256).digest()
    return (output1, output2, output3)
