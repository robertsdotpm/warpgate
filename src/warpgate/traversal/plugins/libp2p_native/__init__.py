"""warpgate-native libp2p TCP traversal plugin.

A minimal byte-compatible libp2p TCP transport implementation,
shaped as a warpgate traversal plugin so the cascade can fall
back to it when the punch / direct / reverse paths fail.

Wire stack (matches the default go-libp2p / js-libp2p TCP listener):

  TCP
   |- multistream-select 1.0.0
   |   |- /plaintext/2.0.0   (security upgrade -- exchange PeerID +
   |   |                      Ed25519 public key as protobuf)
   |   |- multistream-select 1.0.0
   |       |- /yamux/1.0.0   (stream multiplexer)
   |           |- (yamux stream) multistream-select 1.0.0
   |               |- /warpgate/relay/1.0.0  (application channel)

The /plaintext/2.0.0 security upgrade is intentionally chosen over
Noise XX so the whole stack ships in pure Python without pulling in
ChaCha20-Poly1305.  Noise XX is a follow-on; the wire layout above
already segments cleanly so swapping security in is local to
plaintext.py.

Everything in this plugin folder stays in this plugin folder -- no
edits to the rest of warpgate are required other than the standard
proto_messages registration via the plugin loader.
"""
