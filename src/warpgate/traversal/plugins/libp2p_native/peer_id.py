"""libp2p PeerID derivation from an Ed25519 keypair.

A libp2p PeerID is the multihash of the marshalled-protobuf
PublicKey for the node's identity key.  For Ed25519 keys (32 bytes
public), the marshalled PublicKey is so short that libp2p uses the
"identity" multihash codec -- the digest IS the message.  Older
libp2p code used sha256-multihash; both forms remain valid wire
representations and any modern client accepts both.

We use the identity multihash form because it's deterministic, has
no preimage hashing, and is the one go-libp2p, js-libp2p, and
rust-libp2p emit today for Ed25519 keys.

Multihash framing:
    [hash_function: varint][digest_length: varint][digest...]

Identity hash function is 0x00; digest is the raw message.
"""
import os
import hashlib

from . import pb_lite
from . import varint


# Multihash codec for the "identity" no-op hash function.
MULTIHASH_IDENTITY = 0x00
# Multihash codec for sha2-256.
MULTIHASH_SHA256 = 0x12


def encode_multihash(codec, digest):
    """Wrap a digest in the multihash header [codec, length, bytes...]."""
    return varint.encode(codec) + varint.encode(len(digest)) + bytes(digest)


def peer_id_from_pubkey(pubkey_marshalled):
    """Compute the canonical PeerID multihash for a marshalled PublicKey.

    Per https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
    the rule is: if the marshalled PublicKey is <= 42 bytes, use the
    identity multihash; otherwise use sha2-256.  Our Ed25519 case is
    36 bytes (tag + length + 32-byte key + nested field framing),
    safely under 42, so we always use identity here -- but we honour
    the rule generally so the helper can be used for other key types
    later.
    """
    if len(pubkey_marshalled) <= 42:
        return encode_multihash(MULTIHASH_IDENTITY, pubkey_marshalled)
    digest = hashlib.sha256(pubkey_marshalled).digest()
    return encode_multihash(MULTIHASH_SHA256, digest)


class Identity(object):
    """Ed25519 host identity + derived libp2p PeerID.

    Created via Identity.generate() for a fresh keypair, or via
    Identity.from_seed(seed_bytes) if we want determinism (test
    fixtures, reproducible bootstrap).  Holds:

      * priv_seed: 32 bytes (Ed25519 seed, RFC 8032)
      * pub: 32 bytes (Ed25519 public key)
      * pubkey_marshalled: bytes (protobuf PublicKey marshalled)
      * peer_id: bytes (multihash PeerID; canonical wire form)
    """

    def __init__(self, priv_seed, pub, pubkey_marshalled, peer_id):
        self.priv_seed = priv_seed
        self.pub = pub
        self.pubkey_marshalled = pubkey_marshalled
        self.peer_id = peer_id

    @classmethod
    def from_seed(cls, priv_seed):
        if not isinstance(priv_seed, (bytes, bytearray)) or len(priv_seed) != 32:
            raise ValueError("Identity.from_seed: priv_seed must be 32 bytes")
        priv_seed = bytes(priv_seed)
        # Derive Ed25519 public key from the seed.  Use the ecdsa
        # library which is already a warpgate dep.
        from ecdsa import Ed25519, SigningKey
        sk = SigningKey.from_string(priv_seed, curve=Ed25519)
        pub = sk.verifying_key.to_string()
        pubkey_marshalled = pb_lite.encode_public_key(pb_lite.KEY_TYPE_ED25519, pub)
        peer_id = peer_id_from_pubkey(pubkey_marshalled)
        return cls(priv_seed, pub, pubkey_marshalled, peer_id)

    @classmethod
    def generate(cls):
        return cls.from_seed(os.urandom(32))

    def sign(self, msg):
        """Ed25519-sign a message and return the 64-byte signature."""
        from ecdsa import Ed25519, SigningKey
        sk = SigningKey.from_string(self.priv_seed, curve=Ed25519)
        return sk.sign(msg)


def verify_signature(pub_ed25519, msg, sig):
    """Verify an Ed25519 signature; return True/False without raising."""
    try:
        from ecdsa import Ed25519, VerifyingKey, BadSignatureError
        vk = VerifyingKey.from_string(pub_ed25519, curve=Ed25519)
        try:
            vk.verify(sig, msg)
            return True
        except BadSignatureError:
            return False
    except (ValueError, AttributeError, ImportError):
        return False


def b58encode(b):
    """Encode bytes as base58btc -- only used for log-friendly PeerID
    rendering.  Implemented inline to avoid an extra runtime dep."""
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    pad = 0
    for ch in b:
        if ch == 0:
            pad += 1
        else:
            break
    n = int.from_bytes(b, "big") if b else 0
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(alphabet[r])
    out.extend(b"1" * pad)
    out.reverse()
    return bytes(out)


def peer_id_to_b58(peer_id_bytes):
    """Pretty-print a binary PeerID multihash as a base58btc Qm/12D string."""
    return b58encode(peer_id_bytes).decode("ascii")


def b58decode(s):
    """Decode base58btc text/bytes to raw bytes.

    Inverse of ``b58encode`` -- used by the multiaddr text parser to
    convert a ``/p2p/<peer_id_b58>`` segment back to the binary
    multihash.  Raises ValueError on any non-alphabet character.
    """
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    table = {c: i for i, c in enumerate(alphabet)}
    if isinstance(s, str):
        s = s.encode("ascii")
    pad = 0
    for ch in s:
        if ch == ord(b"1"):
            pad += 1
        else:
            break
    n = 0
    for ch in s:
        if ch not in table:
            raise ValueError("b58decode: bad char {0!r}".format(bytes([ch])))
        n = n * 58 + table[ch]
    if n == 0:
        return b"\x00" * pad
    # int -> bytes (big-endian, no leading zeros).
    body = bytearray()
    while n > 0:
        n, r = divmod(n, 256)
        body.append(r)
    body.reverse()
    return b"\x00" * pad + bytes(body)
