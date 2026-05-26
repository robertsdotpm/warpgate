"""Reticulum overlay signalling message.

Plugin-owned.  plugin_loader registers ReticulumMsg under wire name
"reticulum.ReticulumMsg" via PROTO_MESSAGES.

Reticulum doesn't address peers by (IP, port) -- it uses 16-byte
destination hashes (32-char hex when stringified).  The OverlayPlugin
shape expects address + port, so we use ``address`` for the hex hash
and leave ``port`` as a sentinel ``0``.  This keeps the wire schema
uniform across overlay plugins; the Reticulum dialer ignores
``port`` entirely.
"""

from ....protocol.proto_msg import ProtoMsg


class ReticulumMsg(ProtoMsg):
    """Carries the initiator's RNS destination hash to the responder."""

    class Payload:
        """Initiator-side RNS listener identity.

        ``address`` is the destination hash as a 32-character hex
        string (16 bytes encoded).  ``port`` is unused and reserved
        at 0 -- kept for schema parity with overlays that DO use
        (addr, port) tuples.
        """

        def __init__(self, address="", port=0):
            self.address = str(address or "")
            self.port = int(port or 0)

        def to_dict(self):
            return {
                "address": self.address,
                "port": self.port,
            }

        @staticmethod
        def from_dict(d):
            return ReticulumMsg.Payload(
                d.get("address", ""),
                int(d.get("port", 0)),
            )
