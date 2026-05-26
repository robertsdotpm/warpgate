"""libp2p /plaintext/2.0.0 "security" upgrade.

After multistream-select agrees on /plaintext/2.0.0, each side emits
a single length-prefixed protobuf Exchange message containing its
PeerID + marshalled PublicKey.  The receiver verifies that the
declared PeerID matches the multihash of the marshalled PublicKey
and (if it knew an expected PeerID up front) that the announced
identity matches.

There's no encryption here -- the upgrade exists so the rest of the
libp2p stack has a known peer identity for both ends.  Real
deployments should layer Noise XX on top; this module is the
minimal demoable form.

Wire layout (per peer, after multistream-select agreed):
    [varint(length)][Exchange protobuf bytes]
"""
from . import pb_lite
from . import peer_id
from . import varint
from .stream_io import read_exactly


async def perform_handshake(reader, writer, our_identity, expected_peer_id=None):
    """Perform the /plaintext/2.0.0 exchange and return the remote PeerID.

    ``our_identity`` is a peer_id.Identity instance (Ed25519 + cached
    pubkey marshalled + peer_id).

    If ``expected_peer_id`` is given, raise ConnectionError when the
    peer announces a different PeerID -- this lets dialers verify
    they reached the node they meant to.

    Returns (remote_peer_id_bytes, remote_pub_ed25519_bytes).
    """
    # --- Send our Exchange ---
    exchange = pb_lite.encode_exchange(
        our_identity.peer_id, our_identity.pubkey_marshalled,
    )
    await writer.write(varint.encode(len(exchange)) + exchange)

    # --- Receive peer Exchange ---
    length = await varint.read_varint(reader)
    if length > 4096:
        raise ConnectionError("plaintext.perform_handshake: oversize Exchange ({0} bytes)".format(length))
    exchange_bytes = await read_exactly(reader, length)
    remote_peer_id, remote_pubkey_marshalled = pb_lite.decode_exchange(exchange_bytes)
    expected_remote_pid = peer_id.peer_id_from_pubkey(remote_pubkey_marshalled)
    if remote_peer_id != expected_remote_pid:
        raise ConnectionError(
            "plaintext.perform_handshake: peer ID mismatch (declared vs derived-from-pubkey)"
        )
    if expected_peer_id is not None and remote_peer_id != expected_peer_id:
        raise ConnectionError(
            "plaintext.perform_handshake: peer ID is not the expected target"
        )

    key_type, key_bytes = pb_lite.decode_public_key(remote_pubkey_marshalled)
    if key_type != pb_lite.KEY_TYPE_ED25519:
        raise ConnectionError(
            "plaintext.perform_handshake: unsupported key type {0}".format(key_type)
        )
    return remote_peer_id, key_bytes
