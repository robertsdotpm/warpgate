"""Noise XX state machine + libp2p-specific payload framing.

Wire protocol: ``Noise_XX_25519_ChaChaPoly_SHA256``.  Implemented
from the Noise spec revision 34 (https://noiseprotocol.org/noise.html).
The three-message handshake pattern:

    -> e
    <- e, ee, s, es
    -> s, se

Once the third message is processed, ``Split()`` returns two
``CipherState`` instances -- one for sending, one for receiving.
After that, every application frame is independently AEAD-protected
under its own monotonically-increasing nonce.

libp2p-specific wire framing on top of Noise:

    [2-byte big-endian length][noise message bytes]

The length field counts the encrypted payload + any AEAD tag.  Each
handshake message is one length-prefixed frame; each post-handshake
data frame is also one length-prefixed frame.

libp2p's NoiseHandshakePayload protobuf (sent encrypted as the
plaintext of handshake msg 2 and msg 3) carries:

    bytes identity_key  = 1  // marshalled libp2p PublicKey (Ed25519)
    bytes identity_sig  = 2  // Ed25519 sig over
                             //   b"noise-libp2p-static-key:" || s_pub
    bytes early_data    = 3  // optional, unused

This binds the X25519 static key used in the Noise handshake to the
Ed25519 libp2p host identity -- a peer that forwards / replays
someone else's static can't forge the identity_sig without the
identity-key holder's signature.
"""
import hashlib
import os
import struct

from . import pb_lite
from .aead import aead_encrypt, aead_decrypt, TAG_LEN
from .hkdf import noise_hkdf
from .peer_id import verify_signature
from .stream_io import read_exactly


# Protocol name as used to seed the SymmetricState handshake hash.
PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"

# Static-key signature payload prefix per libp2p Noise spec:
# https://github.com/libp2p/specs/blob/master/noise/README.md
SIG_PREFIX = b"noise-libp2p-static-key:"

# Curve25519 -- the Diffie-Hellman primitive used in this Noise
# suite.  Pure-Python implementation lives in the plugin folder
# itself (curve25519.py) so the libp2p plugin stays self-contained
# without depending on any sibling warpgate package.
from .curve25519 import scalarmult, scalarmult_base


def x25519(scalar_bytes, point_bytes):
    """Pure-Python X25519 scalar-multiplication."""
    return scalarmult(scalar_bytes, point_bytes)


def x25519_base(scalar_bytes):
    """Derive an X25519 public key from a private scalar."""
    return scalarmult_base(scalar_bytes)


def generate_x25519_keypair(seed=None):
    """Return (priv32, pub32) -- a fresh X25519 keypair or one from a seed."""
    if seed is None:
        seed = os.urandom(32)
    if len(seed) != 32:
        raise ValueError("generate_x25519_keypair: seed must be 32 bytes")
    return seed, x25519_base(seed)


class CipherState(object):
    """One direction of post-handshake AEAD.

    Noise rule: nonces start at 0, increment by 1 after every
    encrypt/decrypt.  We track the counter as an int and pack it
    into the IETF-variant 12-byte ChaChaPoly nonce as
    (4 zero bytes || 8 LE-counter bytes).
    """

    def __init__(self, key=None):
        self.k = key
        self.n = 0

    def has_key(self):
        return self.k is not None

    def nonce(self):
        return b"\x00\x00\x00\x00" + struct.pack("<Q", self.n)

    def encrypt_with_ad(self, ad, plaintext):
        if self.k is None:
            return plaintext
        out = aead_encrypt(self.k, self.nonce(), ad, plaintext)
        self.n += 1
        return out

    def decrypt_with_ad(self, ad, ciphertext):
        if self.k is None:
            return ciphertext
        out = aead_decrypt(self.k, self.nonce(), ad, ciphertext)
        self.n += 1
        return out


class SymmetricState(object):
    """Tracks the chaining key + handshake hash during the XX exchange."""

    def __init__(self, protocol_name):
        if len(protocol_name) <= 32:
            self.h = protocol_name + b"\x00" * (32 - len(protocol_name))
        else:
            self.h = hashlib.sha256(protocol_name).digest()
        self.ck = self.h
        self.cipher = CipherState()

    def mix_key(self, input_keying_material):
        new_ck, temp_k = noise_hkdf(self.ck, input_keying_material, 2)
        self.ck = new_ck
        self.cipher = CipherState(temp_k)

    def mix_hash(self, data):
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key_and_hash(self, input_keying_material):
        new_ck, temp_h, temp_k = noise_hkdf(self.ck, input_keying_material, 3)
        self.ck = new_ck
        self.mix_hash(temp_h)
        self.cipher = CipherState(temp_k)

    def encrypt_and_hash(self, plaintext):
        ct = self.cipher.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext):
        pt = self.cipher.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return pt

    def split(self):
        temp_k1, temp_k2 = noise_hkdf(self.ck, b"", 2)
        return CipherState(temp_k1), CipherState(temp_k2)


class HandshakeState(object):
    """Noise XX state machine.

    Initiator side calls ``write_message_1`` -> sends bytes ->
    ``read_message_2`` -> ``write_message_3`` -> done, ``split()``
    returns (send_cipher, recv_cipher).

    Responder side calls ``read_message_1`` -> ``write_message_2``
    -> ``read_message_3`` -> done, ``split()`` returns
    (recv_cipher, send_cipher) (note inverse order -- the spec's
    perspective is the local side, so initiator's "send" is the
    first returned cipher, responder's "send" is the second).

    ``s`` is the local static keypair, an (priv32, pub32) tuple.
    ``prologue`` is mixed into the handshake hash up front so any
    info both peers know (e.g. signed multistream-select prefix)
    can't be replayed across sessions.
    """

    def __init__(self, initiator, s_keypair, prologue=b""):
        self.sym = SymmetricState(PROTOCOL_NAME)
        self.sym.mix_hash(prologue)
        self.s = s_keypair      # (priv32, pub32)
        self.e = None           # local ephemeral keypair (filled on write)
        self.rs = None          # remote static pub32 (filled on read)
        self.re = None          # remote ephemeral pub32 (filled on read)
        self.initiator = initiator
        self.done = False

    # ---- initiator path -------------------------------------------------

    def write_message_1(self, payload=b""):
        # -> e
        self.e = generate_x25519_keypair()
        out = self.e[1]
        self.sym.mix_hash(self.e[1])
        out += self.sym.encrypt_and_hash(payload)
        return out

    def read_message_2(self, msg):
        # <- e, ee, s, es
        if len(msg) < 32 + 32 + TAG_LEN:
            raise ValueError("noise: message 2 too short")
        self.re = msg[0:32]
        self.sym.mix_hash(self.re)
        self.sym.mix_key(x25519(self.e[0], self.re))
        # s: 32 bytes static pub + 16 byte tag = 48 bytes
        encrypted_rs = msg[32:32 + 32 + TAG_LEN]
        self.rs = self.sym.decrypt_and_hash(encrypted_rs)
        self.sym.mix_key(x25519(self.e[0], self.rs))
        encrypted_payload = msg[32 + 32 + TAG_LEN:]
        payload = self.sym.decrypt_and_hash(encrypted_payload)
        return payload

    def write_message_3(self, payload=b""):
        # -> s, se
        encrypted_s = self.sym.encrypt_and_hash(self.s[1])
        out = encrypted_s
        self.sym.mix_key(x25519(self.s[0], self.re))
        out += self.sym.encrypt_and_hash(payload)
        self.done = True
        return out

    # ---- responder path -------------------------------------------------

    def read_message_1(self, msg):
        # -> e
        if len(msg) < 32:
            raise ValueError("noise: message 1 too short")
        self.re = msg[0:32]
        self.sym.mix_hash(self.re)
        payload = self.sym.decrypt_and_hash(msg[32:])
        return payload

    def write_message_2(self, payload=b""):
        # <- e, ee, s, es
        self.e = generate_x25519_keypair()
        out = self.e[1]
        self.sym.mix_hash(self.e[1])
        self.sym.mix_key(x25519(self.e[0], self.re))
        encrypted_s = self.sym.encrypt_and_hash(self.s[1])
        out += encrypted_s
        self.sym.mix_key(x25519(self.s[0], self.re))
        out += self.sym.encrypt_and_hash(payload)
        return out

    def read_message_3(self, msg):
        # -> s, se
        if len(msg) < 32 + TAG_LEN:
            raise ValueError("noise: message 3 too short")
        encrypted_rs = msg[:32 + TAG_LEN]
        self.rs = self.sym.decrypt_and_hash(encrypted_rs)
        self.sym.mix_key(x25519(self.e[0], self.rs))
        encrypted_payload = msg[32 + TAG_LEN:]
        payload = self.sym.decrypt_and_hash(encrypted_payload)
        self.done = True
        return payload

    def split(self):
        """Return (send_cipher, recv_cipher) post-handshake.

        For the initiator: (i_to_r, r_to_i) -- send first, recv second.
        For the responder: (i_to_r, r_to_i) too -- so the responder
        uses the SECOND for sending.  Caller decides which one to use
        for which direction based on its role.
        """
        return self.sym.split()


# ---- libp2p NoiseHandshakePayload encode/decode -------------------------


def encode_noise_payload(identity, static_pubkey, early_data=b""):
    """Marshal a NoiseHandshakePayload signed under the libp2p identity.

    ``identity`` is a ``peer_id.Identity`` -- gives us the marshalled
    PublicKey (field 1) and the Ed25519 priv seed for signing.
    ``static_pubkey`` is the 32-byte X25519 static key whose ownership
    we're proving belongs to this libp2p identity.
    """
    sig_payload = SIG_PREFIX + static_pubkey
    sig = identity.sign(sig_payload)
    parts = [
        pb_lite.encode_bytes_field(1, identity.pubkey_marshalled),
        pb_lite.encode_bytes_field(2, sig),
    ]
    if early_data:
        parts.append(pb_lite.encode_bytes_field(3, early_data))
    return b"".join(parts)


def decode_and_verify_noise_payload(payload_bytes, static_pubkey):
    """Decode a peer's NoiseHandshakePayload and verify the signed-static-key.

    Returns ``(peer_id_bytes, ed25519_pubkey_bytes)`` -- the peer's
    canonical libp2p PeerID + their raw Ed25519 public key.  Raises
    ConnectionError on any verification failure.  ``static_pubkey`` is
    the peer's X25519 static key as observed during the Noise
    handshake (the ``rs`` field of HandshakeState).
    """
    fields = pb_lite.parse_message(payload_bytes)
    if 1 not in fields or 2 not in fields:
        raise ConnectionError("noise payload missing identity_key or identity_sig")
    pubkey_marshalled = fields[1][-1]
    identity_sig = fields[2][-1]
    key_type, key_bytes = pb_lite.decode_public_key(pubkey_marshalled)
    if key_type != pb_lite.KEY_TYPE_ED25519:
        raise ConnectionError("noise payload key type not Ed25519")
    if len(key_bytes) != 32:
        raise ConnectionError("noise payload Ed25519 key wrong length")
    sig_payload = SIG_PREFIX + static_pubkey
    if not verify_signature(key_bytes, sig_payload, identity_sig):
        raise ConnectionError("noise payload identity_sig verification failed")
    # Derive PeerID multihash from the marshalled PublicKey (same
    # codepath as ``peer_id.peer_id_from_pubkey``, repeated here so
    # noise.py doesn't drag in peer_id.* private helpers).
    from .peer_id import peer_id_from_pubkey
    return peer_id_from_pubkey(pubkey_marshalled), key_bytes


# ---- Stream-framing helpers --------------------------------------------


async def write_noise_frame(writer, data):
    """Write one length-prefixed Noise frame (2-byte BE length + data)."""
    if len(data) > 0xFFFF:
        raise ValueError("noise frame too large for 16-bit length prefix")
    await writer.write(struct.pack(">H", len(data)) + data)


async def read_noise_frame(reader):
    """Read one length-prefixed Noise frame from ``reader``."""
    header = await read_exactly(reader, 2)
    length = struct.unpack(">H", header)[0]
    if length == 0:
        return b""
    return await read_exactly(reader, length)


# ---- High-level handshake driver ---------------------------------------


class NoiseSession(object):
    """Wraps a fully-completed XX handshake -- exposes the same
    ``async read(n)`` / ``async write(data)`` surface as
    PipeStream and yamux.Stream so the layers above (multistream-
    select + yamux) keep their plumbing unchanged.

    libp2p Noise framing: every post-handshake AEAD record is
    written as a 2-byte big-endian length prefix followed by
    ``ciphertext || tag``.  The internal ``recv_buf`` accumulates
    decrypted plaintext across frames so ``read(n)`` can return
    arbitrary byte counts.
    """

    NOISE_MAX_PLAINTEXT = 0xFFFF - TAG_LEN

    def __init__(self, reader, writer, send_cipher, recv_cipher, remote_peer_id, remote_ed25519):
        self.reader = reader
        self.writer = writer
        self.send_cipher = send_cipher
        self.recv_cipher = recv_cipher
        self.remote_peer_id = remote_peer_id
        self.remote_ed25519 = remote_ed25519
        # Byte-stream buffer of decrypted plaintext.
        self.recv_buf = bytearray()
        self.closed = False

    async def send_app(self, data):
        """Send one application chunk; splits across multiple Noise frames if needed."""
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + self.NOISE_MAX_PLAINTEXT]
            ct = self.send_cipher.encrypt_with_ad(b"", chunk)
            await write_noise_frame(self.writer, ct)
            offset += len(chunk)

    async def recv_app(self):
        """Read + decrypt one Noise frame.  Returns plaintext bytes."""
        frame = await read_noise_frame(self.reader)
        return self.recv_cipher.decrypt_with_ad(b"", frame)

    # ---- StreamReader/Writer-shaped surface ----

    async def read(self, n):
        """Read UP TO n bytes from the decrypted stream, pulling new Noise
        frames from the underlying reader as needed."""
        if n == 0:
            return b""
        while not self.recv_buf:
            if self.closed:
                return b""
            try:
                frame = await read_noise_frame(self.reader)
            except ConnectionError:
                self.closed = True
                return b""
            if not frame:
                continue
            pt = self.recv_cipher.decrypt_with_ad(b"", frame)
            self.recv_buf.extend(pt)
        if n >= len(self.recv_buf):
            out = bytes(self.recv_buf)
            self.recv_buf = bytearray()
            return out
        out = bytes(self.recv_buf[:n])
        del self.recv_buf[:n]
        return out

    async def write(self, data):
        await self.send_app(data)

    async def drain(self):
        return

    def close(self):
        self.closed = True


async def perform_initiator_handshake(reader, writer, identity, expected_peer_id=None):
    """Run the initiator side of Noise XX over a length-prefixed framing.

    Returns a NoiseSession ready for post-handshake encrypted I/O.
    """
    static_keypair = generate_x25519_keypair()
    hs = HandshakeState(initiator=True, s_keypair=static_keypair)

    # -> e (no payload from initiator on message 1 -- libp2p convention)
    msg1 = hs.write_message_1(b"")
    await write_noise_frame(writer, msg1)

    # <- e, ee, s, es
    msg2 = await read_noise_frame(reader)
    payload2 = hs.read_message_2(msg2)
    remote_peer_id, remote_ed25519 = decode_and_verify_noise_payload(
        payload2, hs.rs,
    )
    if expected_peer_id is not None and remote_peer_id != expected_peer_id:
        raise ConnectionError("noise: remote peer_id != expected")

    # -> s, se with our signed payload
    our_payload = encode_noise_payload(identity, static_keypair[1])
    msg3 = hs.write_message_3(our_payload)
    await write_noise_frame(writer, msg3)

    i_to_r, r_to_i = hs.split()
    return NoiseSession(reader, writer, i_to_r, r_to_i, remote_peer_id, remote_ed25519)


async def perform_responder_handshake(reader, writer, identity):
    """Run the responder side of Noise XX over a length-prefixed framing."""
    static_keypair = generate_x25519_keypair()
    hs = HandshakeState(initiator=False, s_keypair=static_keypair)

    # -> e
    msg1 = await read_noise_frame(reader)
    hs.read_message_1(msg1)

    # <- e, ee, s, es with our signed payload
    our_payload = encode_noise_payload(identity, static_keypair[1])
    msg2 = hs.write_message_2(our_payload)
    await write_noise_frame(writer, msg2)

    # -> s, se with remote's signed payload
    msg3 = await read_noise_frame(reader)
    payload3 = hs.read_message_3(msg3)
    remote_peer_id, remote_ed25519 = decode_and_verify_noise_payload(
        payload3, hs.rs,
    )

    i_to_r, r_to_i = hs.split()
    # Responder: i_to_r is the cipher for INBOUND, r_to_i is OUTBOUND.
    return NoiseSession(reader, writer, r_to_i, i_to_r, remote_peer_id, remote_ed25519)
