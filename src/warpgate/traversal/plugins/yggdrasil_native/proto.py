"""yggdrasil_native protocol message -- carries the local Yggdrasil pubkey.

The signaling-side payload is just the local node's 32-byte ed25519
public key (hex-encoded for JSON friendliness).  The peer derives
the same warpgate-overlay node id from that key and dials into the
shared overlay -- they then route bytes to us through the Yggdrasil
mesh.  No (addr, port) tuple needed: routing is hash-based, address
is derived from the key.
"""
from ....protocol.proto_msg import ProtoMsg


class YggdrasilNativeMsg(ProtoMsg):
    """Carries the initiator's 32-byte ed25519 pubkey (hex)."""

    class Payload:
        def __init__(self, pubkey_hex=""):
            self.pubkey_hex = str(pubkey_hex or "")

        def to_dict(self):
            return {"pubkey_hex": self.pubkey_hex}

        @staticmethod
        def from_dict(d):
            return YggdrasilNativeMsg.Payload(
                pubkey_hex=d.get("pubkey_hex", ""),
            )
