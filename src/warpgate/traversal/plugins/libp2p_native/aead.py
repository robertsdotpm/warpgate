"""ChaCha20-Poly1305 AEAD construction per RFC 8439 section 2.8.

Encrypt:
    poly_key = ChaCha20(key, counter=0, nonce)[0:32]   # one-time MAC key
    ciphertext = ChaCha20(key, counter=1, nonce, plaintext)
    tag = Poly1305(poly_key, AAD || pad16(AAD)
                            || ct || pad16(ct)
                            || u64_le(|AAD|) || u64_le(|ct|))
    output = ciphertext || tag

Decrypt verifies tag (constant-time) before returning the recovered
plaintext.  We use a 16-byte tag and a 12-byte nonce, matching the
Noise spec's IETF variant.

This is the AEAD primitive Noise XX over libp2p relies on; using a
deterministic AEAD wrapper instead of speaking RFC 8439 directly
also keeps the higher-level state machine readable.
"""
import struct

from .chacha20 import chacha20_block, chacha20_encrypt
from .poly1305 import poly1305_mac, poly1305_verify


TAG_LEN = 16


def pad16(data):
    """Zero-pad ``data`` up to the next multiple of 16 bytes."""
    rem = len(data) % 16
    if rem == 0:
        return b""
    return b"\x00" * (16 - rem)


def poly_key_for_nonce(key, nonce):
    """Derive the one-time Poly1305 MAC key from ChaCha20 block 0."""
    return chacha20_block(key, 0, nonce)[:32]


def mac_payload(aad, ciphertext):
    """Build the bytes Poly1305 computes its MAC over, per RFC 8439."""
    return (
        aad + pad16(aad)
        + ciphertext + pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


def aead_encrypt(key, nonce, aad, plaintext):
    """Encrypt + authenticate; return ``ciphertext || tag`` bytes."""
    if len(key) != 32:
        raise ValueError("aead_encrypt: key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("aead_encrypt: nonce must be 12 bytes")
    ct = chacha20_encrypt(key, 1, nonce, plaintext)
    pk = poly_key_for_nonce(key, nonce)
    tag = poly1305_mac(pk, mac_payload(aad, ct))
    return ct + tag


def aead_decrypt(key, nonce, aad, ciphertext_with_tag):
    """Verify tag (constant-time) and return recovered plaintext.

    Raises ValueError on tag mismatch, length mismatch, or any
    parameter problem.  The cipher.encrypt-then-mac order means a
    failed MAC must be the only reason the caller learns anything --
    don't leak partial plaintext on mismatch.
    """
    if len(key) != 32:
        raise ValueError("aead_decrypt: key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("aead_decrypt: nonce must be 12 bytes")
    if len(ciphertext_with_tag) < TAG_LEN:
        raise ValueError("aead_decrypt: ciphertext shorter than tag")
    ct = ciphertext_with_tag[:-TAG_LEN]
    tag = ciphertext_with_tag[-TAG_LEN:]
    pk = poly_key_for_nonce(key, nonce)
    if not poly1305_verify(pk, mac_payload(aad, ct), tag):
        raise ValueError("aead_decrypt: tag verification failed")
    return chacha20_encrypt(key, 1, nonce, ct)
