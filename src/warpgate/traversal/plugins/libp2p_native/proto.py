"""libp2p_native signal message.

Initiator publishes its listening (ip, port) + PeerID hex so the
responder can dial back through plain libp2p TCP transport.  No
DHT lookup yet -- the warpgate signalling channel substitutes for
peer discovery; the libp2p stack only runs on the dial side.

The payload also carries the dial address family so the responder
knows whether to open a v4 or v6 TCP connection.
"""
from ....protocol.proto_msg import ProtoMsg


class Libp2pNativeMsg(ProtoMsg):
    """Carries the initiator's libp2p listen (ip, port, peer_id_hex, af)."""

    class Payload:
        def __init__(self, ip="", port=0, peer_id_hex="", af=0):
            self.ip = str(ip or "")
            self.port = int(port or 0)
            self.peer_id_hex = str(peer_id_hex or "")
            self.af = int(af or 0)

        def to_dict(self):
            return {
                "ip": self.ip,
                "port": self.port,
                "peer_id_hex": self.peer_id_hex,
                "af": self.af,
            }

        @staticmethod
        def from_dict(d):
            return Libp2pNativeMsg.Payload(
                ip=d.get("ip", ""),
                port=d.get("port", 0),
                peer_id_hex=d.get("peer_id_hex", ""),
                af=d.get("af", 0),
            )
