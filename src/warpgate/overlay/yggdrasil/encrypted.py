"""Encrypted PacketConn -- port of ironwood/encrypted/session.go.

Wraps the routing-layer Traffic packets with NaCl box encryption
so app-level bytes are end-to-end confidential + authenticated.
This is what makes the python port wire-compatible with real
Yggdrasil peers (whose user traffic is always encrypted).

Wire shape on top of WIRE_TRAFFIC:

  ``[type_byte][session-specific fields]``

Three traffic types (encrypted layer's own enum, distinct from
the routing wire types):

  ``0x01 sessionTypeInit``
        ``[1: type][32: from_box_pub][rest: box-sealed payload]``
        Payload = ``[64 sig][32 current][32 next][8 keySeq BE][8 seq BE]``
        Sealed under ECDH(from_box_priv, to_ed_box_pub) with nonce=0.
        Signature is over ``from_box_pub || current || next || keySeq || seq``,
        signed with the SENDER'S ED25519 PRIVATE key.

  ``0x02 sessionTypeAck`` -- exact same wire layout as Init, just
        a different type tag (signals "we got your init, here's
        ours back").

  ``0x03 sessionTypeTraffic``
        ``[1: type][varint local_key_seq][varint remote_key_seq]
         [varint nonce][box-sealed (next_pub || msg)]``
        Sealed under the precomputed shared key for this session.

For Phase 8 we implement the static-key variant: each session
holds (current, next) boxKey pairs but we don't rotate keys on
nonce overflow (impossible in practice -- 2^64 packets).  The
init/ack ratchet IS implemented because peers may rotate at any
time and we'd lose them if we ignored their updates.
"""
import os
import time

from aionetiface import fstr, log, log_exception
from ecdsa import SigningKey, VerifyingKey, Ed25519
from ecdsa.keys import BadSignatureError

from . import nacl_box
from .curve25519 import edwards_y_to_montgomery_u, ed25519_priv_seed_to_curve25519
from .wire import decode_uvarint, encode_uvarint


# Wire constants -- mirror upstream.
SESSION_TYPE_DUMMY = 0
SESSION_TYPE_INIT = 1
SESSION_TYPE_ACK = 2
SESSION_TYPE_TRAFFIC = 3

BOX_PUB_SIZE = nacl_box.BOX_PUB_SIZE
BOX_PRIV_SIZE = nacl_box.BOX_PRIV_SIZE
BOX_OVERHEAD = nacl_box.BOX_OVERHEAD
ED_SIG_SIZE = 64

# sessionInitSize from upstream: 1 + boxPub + boxOverhead + edSig + boxPub*2 + 8 + 8
SESSION_INIT_SIZE = 1 + BOX_PUB_SIZE + BOX_OVERHEAD + ED_SIG_SIZE + BOX_PUB_SIZE * 2 + 8 + 8


def derive_box_keys_from_ed_seed(ed_seed):
    """Derive a (curve_priv, curve_pub) pair from an Ed25519 seed.

    NaCl uses ``ed25519_sk_to_curve25519`` for the private side
    (sha512(seed)[:32]) and ``ed25519_pk_to_curve25519`` for the
    public side ((1+y)/(1-y) on the y-coord).  The two derivations
    are consistent: scalarmult_base(curve_priv) == curve_pub.
    """
    sk = SigningKey.from_string(bytes(ed_seed), curve=Ed25519)
    ed_pub = bytes(sk.verifying_key.to_string())
    curve_priv = ed25519_priv_seed_to_curve25519(ed_seed)
    curve_pub = edwards_y_to_montgomery_u(ed_pub)
    return curve_priv, curve_pub, ed_pub


def sign_ed25519(ed_seed, message):
    sk = SigningKey.from_string(bytes(ed_seed), curve=Ed25519)
    return bytes(sk.sign(bytes(message)))


def verify_ed25519(ed_pub, message, sig):
    try:
        vk = VerifyingKey.from_string(bytes(ed_pub), curve=Ed25519)
        vk.verify(bytes(sig), bytes(message))
        return True
    except (BadSignatureError, ValueError):
        return False


class SessionInit(object):
    """The (current, next) handshake message exchanged via init/ack.

    Carries the sender's two box public keys + a key-sequence
    counter + a wall-clock seq (timestamp) used as a freshness
    nonce.  Signed by the sender's ed25519 key.
    """

    def __init__(self, current=b"\x00" * BOX_PUB_SIZE,
                 next_pub=b"\x00" * BOX_PUB_SIZE,
                 key_seq=0, seq=0):
        self.current = bytes(current)
        self.next = bytes(next_pub)
        self.key_seq = int(key_seq)
        self.seq = int(seq)

    def encode(self, from_ed_seed, to_ed_pub, type_byte=SESSION_TYPE_INIT):
        """Sign + encrypt the init/ack for transmission to ``to_ed_pub``."""
        # Fresh box keypair for this init transmission.
        from_box_priv, from_box_pub = nacl_box.generate_keypair()
        # Build the sig payload: from_box_pub || current || next ||
        # key_seq (8 BE) || seq (8 BE).
        sig_bytes = (from_box_pub + self.current + self.next
                     + self.key_seq.to_bytes(8, "big")
                     + self.seq.to_bytes(8, "big"))
        sig = sign_ed25519(from_ed_seed, sig_bytes)
        # Payload (encrypted under ECDH): sig || rest_of_sig_bytes
        # where rest_of_sig_bytes is everything AFTER from_box_pub.
        payload = sig + sig_bytes[BOX_PUB_SIZE:]
        # ECDH partner: convert peer's ed25519 pubkey to box pub.
        to_box_pub = edwards_y_to_montgomery_u(to_ed_pub)
        sealed = nacl_box.seal(payload, b"\x00" * 24,
                               to_box_pub, from_box_priv)
        # Final message: [type][from_box_pub][sealed]
        out = bytes([type_byte]) + from_box_pub + sealed
        if len(out) != SESSION_INIT_SIZE:
            raise ValueError(fstr(
                "SessionInit.encode: wire size {0}, expected {1}",
                (len(out), SESSION_INIT_SIZE),
            ))
        return out

    @classmethod
    def decode(cls, data, my_box_priv, from_ed_pub):
        """Verify + decrypt a wire-form init/ack from ``from_ed_pub``."""
        if len(data) != SESSION_INIT_SIZE:
            return None
        from_box_pub = data[1:1 + BOX_PUB_SIZE]
        sealed = data[1 + BOX_PUB_SIZE:]
        payload = nacl_box.open_box(sealed, b"\x00" * 24,
                                    from_box_pub, my_box_priv)
        if payload is None:
            return None
        sig = payload[:ED_SIG_SIZE]
        rest = payload[ED_SIG_SIZE:]
        if len(rest) != BOX_PUB_SIZE * 2 + 16:
            return None
        current = rest[:BOX_PUB_SIZE]
        next_pub = rest[BOX_PUB_SIZE:BOX_PUB_SIZE * 2]
        key_seq = int.from_bytes(rest[BOX_PUB_SIZE * 2:BOX_PUB_SIZE * 2 + 8], "big")
        seq = int.from_bytes(rest[BOX_PUB_SIZE * 2 + 8:], "big")
        # Recompute the sig-bytes (from_box_pub || current || ... ||
        # key_seq || seq) and verify against the sender's ed25519
        # key.  This proves the sender owns the ed key AND chose
        # these box keys (defeats key-substitution attacks).
        sig_bytes = (from_box_pub + current + next_pub
                     + key_seq.to_bytes(8, "big")
                     + seq.to_bytes(8, "big"))
        if not verify_ed25519(from_ed_pub, sig_bytes, sig):
            return None
        return cls(current=current, next_pub=next_pub,
                   key_seq=key_seq, seq=seq)


class SessionInfo(object):
    """Per-peer encrypted-session state.

    Tracks the active AND "next" box keypairs on both sides + the
    nonce counters AND the four precomputed shared keys upstream
    uses (recv, send, nextSend, nextRecv).  Implements the three
    decrypt cases from upstream session.go's doRecv:

      * fromCurrent && toRecv  - boring case (recv_shared)
      * fromNext    && toSend  - remote ratcheted (nextSend_shared)
      * fromNext    && toRecv  - remote ratcheted early (nextRecv_shared)

    The two ratchet branches also rotate keys when triggered, so
    receiving traffic alone is sufficient to keep both sides
    in lockstep.
    """

    def __init__(self, peer_ed_pub):
        self.peer_ed_pub = bytes(peer_ed_pub)
        # Peer's box keys (filled by init/ack handler).
        self.current = b"\x00" * BOX_PUB_SIZE
        self.next = b"\x00" * BOX_PUB_SIZE
        # Our own three keypairs (current recv / current send / next).
        self.recv_priv, self.recv_pub = nacl_box.generate_keypair()
        self.send_priv, self.send_pub = nacl_box.generate_keypair()
        self.next_priv, self.next_pub = nacl_box.generate_keypair()
        self.recv_nonce = 0
        self.send_nonce = 0
        self.next_send_nonce = 0
        self.next_recv_nonce = 0
        self.remote_key_seq = 0
        self.local_key_seq = 0
        self.seq = 0   # peer's seq (anti-replay for init)
        self.rotated_at = 0.0   # monotonic ts of last key rotation
        # Precomputed shared keys -- regenerated on fix_shared.
        self.recv_shared = None
        self.send_shared = None
        self.next_send_shared = None
        self.next_recv_shared = None
        self.fix_shared()

    def fix_shared(self):
        """Recompute the four precomputed shared keys after a key change.

        Layout matches upstream _fixShared exactly:
          recv_shared      = precompute(peer.current, our.recv_priv)
          send_shared      = precompute(peer.current, our.send_priv)
          next_send_shared = precompute(peer.next,    our.send_priv)
          next_recv_shared = precompute(peer.next,    our.recv_priv)
        Plus reset of the next-side nonces.  Caller already
        manages recv_nonce / send_nonce.
        """
        zero32 = b"\x00" * BOX_PUB_SIZE
        if self.current and self.current != zero32:
            self.recv_shared = nacl_box.precompute(self.current, self.recv_priv)
            self.send_shared = nacl_box.precompute(self.current, self.send_priv)
        if self.next and self.next != zero32:
            self.next_send_shared = nacl_box.precompute(self.next, self.send_priv)
            self.next_recv_shared = nacl_box.precompute(self.next, self.recv_priv)
        self.next_send_nonce = 0
        self.next_recv_nonce = 0

    def handle_update(self, init):
        """Apply an incoming Init/Ack -- ratchet our own keys forward."""
        if init.seq <= self.seq:
            return False
        self.current = init.current
        self.next = init.next
        self.seq = init.seq
        self.remote_key_seq = init.key_seq
        # Ratchet: recv <- old send, send <- old next, next <- fresh.
        self.recv_priv, self.recv_pub = self.send_priv, self.send_pub
        self.send_priv, self.send_pub = self.next_priv, self.next_pub
        self.next_priv, self.next_pub = nacl_box.generate_keypair()
        self.local_key_seq += 1
        self.recv_nonce = 0
        self.fix_shared()
        return True

    def ratchet_on_traffic(self, new_peer_next_pub, new_recv_nonce):
        """Rotate keys when traffic arrives that proves remote ratcheted.

        Mirrors upstream's onSuccess closure for the fromNext cases:
        peer's NEXT becomes our CURRENT, peer's new NEXT is the
        innerKey carried in the decrypted payload, we ratchet our
        own keys forward by one step, and fix_shared rederives the
        four shared keys.

        Rate-limited to once per minute (matches upstream's
        ``time.Since(info.rotated) > time.Minute`` guard) so we
        don't churn keys on every traffic packet in a steady-state
        session.
        """
        import time as _time
        now = _time.monotonic()
        if self.rotated_at != 0.0 and now - self.rotated_at < 60.0:
            return
        self.current = self.next
        self.next = bytes(new_peer_next_pub)
        self.remote_key_seq += 1
        self.recv_priv, self.recv_pub = self.send_priv, self.send_pub
        self.send_priv, self.send_pub = self.next_priv, self.next_pub
        self.next_priv, self.next_pub = nacl_box.generate_keypair()
        self.local_key_seq += 1
        self.recv_nonce = new_recv_nonce
        self.fix_shared()
        self.rotated_at = now


class EncryptedPacketConn(object):
    """Application-layer encrypted packet API on top of an ActiveRouter.

    Construct with an ActiveRouter; the router's inbox feeds this
    layer's session.handleData; the router's send_to consumes
    bytes this layer produces.  Apps interact via:

      ``await pc.write_to(peer_ed_pub, message)`` -- send (encrypts + routes)
      ``await pc.read_from()`` -> ``(peer_ed_pub, message)`` -- recv

    Init/ack are issued lazily on first write to a new peer (or
    on receiving an unsolicited init from one).
    """

    def __init__(self, ed_seed, ed_pub, router):
        self.ed_seed = bytes(ed_seed)
        self.ed_pub = bytes(ed_pub)
        # Our own box keys derived from the ed25519 identity --
        # used to OPEN incoming init/ack messages.  Persistent.
        self.box_priv = ed25519_priv_seed_to_curve25519(self.ed_seed)
        self.box_pub = edwards_y_to_montgomery_u(self.ed_pub)
        self.router = router
        self.sessions = {}     # peer_ed_pub -> SessionInfo
        # Pending app sends to peers we haven't yet established a
        # session with -- buffered until the ack arrives.
        self.pending_buffers = {}  # peer_ed_pub -> list[message]
        # Per-peer inbound queues.  ``read_from()`` drains the
        # shared catch-all queue (any peer); ``read_from_peer(pk)``
        # drains a peer-specific queue.  This eliminates the
        # earlier "shared inbox loses other peer's traffic" race
        # when multiple plugin instances share one PacketConn.
        import asyncio
        self.inbox = asyncio.Queue()
        self.per_peer_inbox = {}  # peer_ed_pub -> asyncio.Queue
        # Wire ourselves into the router's traffic inbox.
        self.dispatch_task = asyncio.ensure_future(self.dispatch_loop())

    async def dispatch_loop(self):
        """Pull each routing-layer traffic packet, dispatch by session type."""
        try:
            while True:
                source, payload = await self.router.inbox.get()
                if not payload:
                    continue
                tag = payload[0]
                if tag == SESSION_TYPE_INIT:
                    self.handle_init(source, payload)
                elif tag == SESSION_TYPE_ACK:
                    self.handle_ack(source, payload)
                elif tag == SESSION_TYPE_TRAFFIC:
                    self.handle_traffic(source, payload)
        except Exception:
            log_exception()

    def session_for(self, peer_ed_pub):
        info = self.sessions.get(bytes(peer_ed_pub))
        if info is None:
            info = SessionInfo(peer_ed_pub)
            self.sessions[bytes(peer_ed_pub)] = info
        return info

    def handle_init(self, source, data):
        info = self.session_for(source)
        init = SessionInit.decode(data, self.box_priv, source)
        if init is None:
            return
        if info.handle_update(init):
            # Reply with our own ack so the sender's session locks on.
            ack_init = SessionInit(
                current=info.send_pub, next_pub=info.next_pub,
                key_seq=info.local_key_seq,
                seq=int(time.time()),
            )
            wire = ack_init.encode(self.ed_seed, source,
                                   type_byte=SESSION_TYPE_ACK)
            import asyncio
            asyncio.ensure_future(self.send_raw(source, wire))
            # Flush any pending buffers for this peer.
            asyncio.ensure_future(self.flush_pending(source))

    def handle_ack(self, source, data):
        info = self.session_for(source)
        ack = SessionInit.decode(data, self.box_priv, source)
        if ack is None:
            return
        if info.handle_update(ack):
            import asyncio
            asyncio.ensure_future(self.flush_pending(source))

    def handle_traffic(self, source, data):
        """Decode + decrypt one traffic packet from ``source``.

        Implements the full 3-case switch from upstream session.go
        doRecv.  The wire layout from sender's POV:
          ``[tag][sender.local_key_seq][sender.remote_key_seq][nonce][sealed]``
        From OUR perspective, sender.local_key_seq is what we'd
        call remote_key_seq, and sender.remote_key_seq is what we'd
        call local_key_seq.

        Three accept cases:
          1) ``fromCurrent && toRecv`` -- both sides aligned on
             current keys.  Decrypt with recv_shared, advance recv_nonce.
          2) ``fromNext && toSend`` -- remote ratcheted to its next
             AHEAD of us.  Decrypt with next_send_shared; on
             success, rotate our own keys to match.
          3) ``fromNext && toRecv`` -- both ratcheted early.
             Decrypt with next_recv_shared; rotate.

        Anything else: send a fresh init to re-sync (upstream's
        default branch).
        """
        info = self.sessions.get(bytes(source))
        if info is None:
            return
        try:
            offset = 1
            remote_key_seq, consumed = decode_uvarint(data, offset)
            offset += consumed
            local_key_seq, consumed = decode_uvarint(data, offset)
            offset += consumed
            nonce, consumed = decode_uvarint(data, offset)
            offset += consumed
        except ValueError:
            return
        sealed = data[offset:]

        from_current = remote_key_seq == info.remote_key_seq
        from_next = remote_key_seq == info.remote_key_seq + 1
        to_recv = local_key_seq + 1 == info.local_key_seq
        to_send = local_key_seq == info.local_key_seq

        shared = None
        post_action = None   # set by case branches to mutate state on success

        if from_current and to_recv:
            if nonce <= info.recv_nonce:
                return
            shared = info.recv_shared
            def on_success(_inner_key):
                info.recv_nonce = nonce
            post_action = on_success
        elif from_next and to_send:
            if nonce <= info.next_send_nonce:
                return
            shared = info.next_send_shared
            def on_success(inner_key):
                info.next_send_nonce = nonce
                info.ratchet_on_traffic(inner_key, nonce)
            post_action = on_success
        elif from_next and to_recv:
            if nonce <= info.next_recv_nonce:
                return
            shared = info.next_recv_shared
            def on_success(inner_key):
                info.next_recv_nonce = nonce
                info.ratchet_on_traffic(inner_key, nonce)
            post_action = on_success
        else:
            # Out of sync -- send a fresh init to recover.
            import asyncio
            asyncio.ensure_future(self.send_init(source))
            return

        if shared is None:
            return
        nonce_bytes = (b"\x00" * 16) + nonce.to_bytes(8, "big")
        opened = nacl_box.open_precomputed(sealed, nonce_bytes, shared)
        if opened is None:
            # MAC failed -- session keys probably drifted.  Try a
            # fresh init to re-sync.  Matches upstream's "Keys
            # somehow became out-of-sync" recovery branch.
            import asyncio
            asyncio.ensure_future(self.send_init(source))
            return
        if len(opened) < BOX_PUB_SIZE:
            return
        inner_key = opened[:BOX_PUB_SIZE]
        msg = opened[BOX_PUB_SIZE:]
        post_action(inner_key)
        import asyncio
        asyncio.ensure_future(self.inbox.put((bytes(source), msg)))
        peer_q = self.per_peer_inbox.get(bytes(source))
        if peer_q is not None:
            asyncio.ensure_future(peer_q.put(msg))

    async def write_to(self, peer_ed_pub, message):
        """Encrypt + send ``message`` to ``peer_ed_pub`` (routes via the tree)."""
        info = self.session_for(peer_ed_pub)
        if info.send_shared is None or info.current == b"\x00" * BOX_PUB_SIZE:
            # No session yet -- buffer + send an init.
            self.pending_buffers.setdefault(
                bytes(peer_ed_pub), []
            ).append(bytes(message))
            await self.send_init(peer_ed_pub)
            return
        await self.send_traffic(info, peer_ed_pub, message)

    async def send_init(self, peer_ed_pub):
        info = self.session_for(peer_ed_pub)
        init = SessionInit(
            current=info.send_pub, next_pub=info.next_pub,
            key_seq=info.local_key_seq, seq=int(time.time()),
        )
        wire = init.encode(self.ed_seed, peer_ed_pub,
                           type_byte=SESSION_TYPE_INIT)
        await self.send_raw(peer_ed_pub, wire)

    async def flush_pending(self, peer_ed_pub):
        info = self.session_for(peer_ed_pub)
        if info.send_shared is None:
            return
        for msg in self.pending_buffers.pop(bytes(peer_ed_pub), []):
            await self.send_traffic(info, peer_ed_pub, msg)

    async def send_traffic(self, info, peer_ed_pub, message):
        info.send_nonce += 1
        nonce = info.send_nonce
        nonce_bytes = (b"\x00" * 16) + nonce.to_bytes(8, "big")
        # Inner payload: our next_pub + the app message (lets the
        # peer learn our next box pub for ratchet).
        inner = info.next_pub + bytes(message)
        sealed = nacl_box.seal_precomputed(inner, nonce_bytes, info.send_shared)
        # Wire layout: [tag][varint local_key_seq (= peer's remote)]
        # [varint remote_key_seq (= peer's local)][varint nonce][sealed].
        wire = (bytes([SESSION_TYPE_TRAFFIC])
                + encode_uvarint(info.local_key_seq)
                + encode_uvarint(info.remote_key_seq)
                + encode_uvarint(nonce)
                + sealed)
        await self.send_raw(peer_ed_pub, wire)

    async def send_raw(self, peer_ed_pub, wire):
        """Route ``wire`` through the active router to ``peer_ed_pub``."""
        try:
            await self.router.send_to(peer_ed_pub, wire)
        except (OSError, ConnectionError):
            log_exception()

    async def read_from(self):
        """Await one decrypted (peer_ed_pub, message) pair from ANY peer."""
        return await self.inbox.get()

    def open_peer_channel(self, peer_ed_pub):
        """Open a per-peer inbound queue + return the Queue object.

        Once a peer channel is open, every inbound packet from
        ``peer_ed_pub`` lands in BOTH the shared inbox AND the
        peer-specific queue.  Plugin instances should use the
        peer-specific queue so they don't drop each other's
        traffic on a shared PacketConn.  Idempotent: re-opening
        for the same peer returns the existing queue.
        """
        import asyncio
        key = bytes(peer_ed_pub)
        q = self.per_peer_inbox.get(key)
        if q is None:
            q = asyncio.Queue()
            self.per_peer_inbox[key] = q
        return q

    def close_peer_channel(self, peer_ed_pub):
        """Drop the per-peer inbound queue for ``peer_ed_pub``."""
        self.per_peer_inbox.pop(bytes(peer_ed_pub), None)

    async def read_from_peer(self, peer_ed_pub, timeout=None):
        """Await the next decrypted message from a SPECIFIC peer.

        Caller must have called ``open_peer_channel`` first.
        Returns None on timeout.
        """
        import asyncio
        key = bytes(peer_ed_pub)
        q = self.per_peer_inbox.get(key)
        if q is None:
            raise RuntimeError(
                "read_from_peer: no channel open for this peer"
            )
        try:
            if timeout is None:
                return await q.get()
            return await asyncio.wait_for(q.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def close(self):
        if self.dispatch_task is not None:
            try:
                self.dispatch_task.cancel()
            except Exception:
                pass
            self.dispatch_task = None
