"""yggdrasil overlay signalling message.

Plugin-owned.  plugin_loader registers YggdrasilMsg under wire name
"yggdrasil.YggdrasilMsg" via PROTO_MESSAGES.

The payload is dirt simple: the initiator advertises its Yggdrasil
address (a 200::/7 IPv6) and the TCP port its overlay listener is
bound on.  The responder reads those and dials.
"""

from ....protocol.proto_msg import ProtoMsg


class YggdrasilMsg(ProtoMsg):
    """Carries the initiator's overlay (address, port) to the responder."""

    class Payload:
        """Initiator-side overlay listener tuple.

        ``address`` is an Yggdrasil 200::/7 IPv6 as a string.
        ``port`` is the TCP port advertised on that address.
        """

        def __init__(self, address="", port=0):
            self.address = address
            self.port = int(port)

        def to_dict(self):
            return {
                "address": self.address,
                "port": self.port,
            }

        @staticmethod
        def from_dict(d):
            return YggdrasilMsg.Payload(
                d.get("address", ""),
                int(d.get("port", 0)),
            )
