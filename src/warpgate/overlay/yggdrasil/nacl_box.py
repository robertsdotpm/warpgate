"""NaCl ``box`` / ``secretbox`` -- pure-Python, byte-compat with libsodium.

Implements the authenticated public-key encryption primitive
yggdrasil-go's encrypted layer uses via
``golang.org/x/crypto/nacl/box``.  Built on three pure-Python
components in this directory:

  * curve25519.scalarmult / scalarmult_base -- ECDH
  * salsa20.hsalsa20 / xsalsa20_stream      -- stream cipher
  * poly1305.poly1305_mac                   -- authenticator

Wire-compatible with NaCl box:

  * ``box.GenerateKey`` -> ``generate_keypair()``  (returns
    (priv_32, pub_32) -- pub is scalarmult_base(priv))
  * ``box.Precompute(out, pub, priv)`` -> ``precompute(pub, priv)``
    -- returns a 32-byte shared key via HSalsa20(ECDH, zero-nonce)
  * ``box.SealAfterPrecomputation`` -> ``seal_precomputed(msg, nonce, shared)``
  * ``box.OpenAfterPrecomputation`` -> ``open_precomputed(boxed, nonce, shared)``

Box overhead is 16 bytes (the Poly1305 MAC); nonces are 24 bytes
(XSalsa20).  Empty messages are legal (just the 16-byte MAC).
"""
import os

from . import curve25519
from .poly1305 import poly1305_mac, poly1305_verify
from .salsa20 import hsalsa20, xsalsa20_stream


# NaCl box constants.
BOX_PUB_SIZE = 32
BOX_PRIV_SIZE = 32
BOX_SHARED_SIZE = 32
BOX_NONCE_SIZE = 24
BOX_OVERHEAD = 16   # Poly1305 MAC length


def generate_keypair():
    """Return ``(priv, pub)`` -- both 32 bytes.

    ``priv`` is 32 random bytes (NaCl does NOT clamp at generation
    time; clamping happens in scalarmult).  ``pub`` is the
    Curve25519 public key derived via the base-point scalarmult.
    """
    priv = os.urandom(BOX_PRIV_SIZE)
    pub = curve25519.scalarmult_base(priv)
    return priv, pub


def precompute(pub, priv):
    """Derive the 32-byte shared key from a peer pubkey + our privkey.

    Internally: shared_secret = X25519(priv, pub); then
    HSalsa20(shared_secret, nonce=0x00 * 16).  Matches NaCl's
    ``box.Precompute`` byte-for-byte.
    """
    if len(pub) != BOX_PUB_SIZE:
        raise ValueError("precompute: pub must be 32 bytes")
    if len(priv) != BOX_PRIV_SIZE:
        raise ValueError("precompute: priv must be 32 bytes")
    shared_point = curve25519.scalarmult(priv, pub)
    return hsalsa20(shared_point, b"\x00" * 16)


def seal_precomputed(message, nonce, shared_key):
    """Encrypt + authenticate ``message`` under a precomputed shared key.

    Returns ``ciphertext + tag`` (16 bytes longer than ``message``).
    """
    if len(nonce) != BOX_NONCE_SIZE:
        raise ValueError("seal_precomputed: nonce must be 24 bytes")
    if len(shared_key) != BOX_SHARED_SIZE:
        raise ValueError("seal_precomputed: shared_key must be 32 bytes")
    # NaCl's secretbox layout: the first 32 bytes of the XSalsa20
    # stream are used as the one-time Poly1305 key; the rest XORs
    # the message.  Equivalently: generate (32 + len(msg)) bytes
    # of stream, use the first 32 as poly_key, XOR the rest with
    # message to get ciphertext, then compute MAC over ciphertext.
    stream = xsalsa20_stream(shared_key, nonce, 32 + len(message))
    poly_key = stream[:32]
    ct = bytes(s ^ m for s, m in zip(stream[32:], message))
    tag = poly1305_mac(poly_key, ct)
    return tag + ct


def open_precomputed(boxed, nonce, shared_key):
    """Verify + decrypt under a precomputed shared key.

    Returns the plaintext bytes on success, ``None`` on MAC
    failure (so callers can branch without leaking timing).
    """
    if len(nonce) != BOX_NONCE_SIZE:
        raise ValueError("open_precomputed: nonce must be 24 bytes")
    if len(shared_key) != BOX_SHARED_SIZE:
        raise ValueError("open_precomputed: shared_key must be 32 bytes")
    if len(boxed) < BOX_OVERHEAD:
        return None
    tag = boxed[:BOX_OVERHEAD]
    ct = boxed[BOX_OVERHEAD:]
    stream = xsalsa20_stream(shared_key, nonce, 32 + len(ct))
    poly_key = stream[:32]
    if not poly1305_verify(poly_key, ct, tag):
        return None
    return bytes(s ^ c for s, c in zip(stream[32:], ct))


def seal(message, nonce, pub, priv):
    """One-shot ``box.Seal`` -- derives shared key from (pub, priv)."""
    shared = precompute(pub, priv)
    return seal_precomputed(message, nonce, shared)


def open_box(boxed, nonce, pub, priv):
    """One-shot ``box.Open`` -- derives shared key from (pub, priv)."""
    shared = precompute(pub, priv)
    return open_precomputed(boxed, nonce, shared)
