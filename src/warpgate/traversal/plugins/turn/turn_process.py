"""TURN message parsing and state-machine processing."""
import asyncio
import io
import struct
from struct import unpack
from hashlib import md5
from aionetiface import (
    STUNMsg, RFC5389, STUNAttrs, STUNAddrTup, STUNMsgTypes, STUNMsgCodes,
    b_and, fstr, log, log_exception, to_s, to_h,
    rm_done_tasks, async_retry, async_wrap_errors, STATUS_RETRY, STATUS_SUCCESS,
    stun_proc_attrs, norm_client_tup,
)
from .turn_defs import (
    TURN_TRY_ALLOCATE,
    TURN_ERROR_STOPPED,
)

# IS_DEBUG is referenced below but not exported by aionetiface.
try:
    IS_DEBUG  # noqa: F821 — may be injected by test/demo harness
except NameError:
    IS_DEBUG = False


# Parse a TURN message.
# Use bitwise OPs to get valid method and status codes.
def turn_parse_msg(buf):
    """Parse raw bytes into (turn_msg, method, status) or (None, None, None) on failure."""
    try:
        turn_msg, _ = STUNMsg.unpack(buf, mode=RFC5389)
        turn_method = b_and(turn_msg.msg_type, b"\x00\x0f")
        turn_status = b_and(turn_msg.msg_type, b"\x01\x10")
        return turn_msg, turn_method, turn_status
    except (ValueError, struct.error):
        return None, None, None


# Messages sent to a relay address get returned by the TURN
# server to the client as a message with a:
# A) DATA attribute (the message)
# B) Peer Address attribute (the sender)
#
# Return this information to the caller.


def turn_get_data_attr(msg, af, client):
    """Extract the DATA payload and XorPeerAddress from a TURN relay message."""
    # Step through all attributes.
    data = peer_tup = None
    while not msg.eof():
        attr_code, _, attr_data = msg.read_attr()

        # The message segment.
        if attr_code == STUNAttrs.Data:
            if isinstance(attr_data, memoryview):
                data = attr_data.tobytes()
            else:
                data = attr_data

        # The sender of the message.
        if attr_code == STUNAttrs.XorPeerAddress:
            stun_addr = STUNAddrTup(
                af=af,
                txid=msg.txn_id,
                magic_cookie=msg.magic_cookie,
            )
            stun_addr.decode(attr_code, attr_data)
            peer_tup = stun_addr.tup

            # Validate the peer addr.
            ext = client.turn_pipe.route.ext()
            if peer_tup[0] == ext:
                error = fstr(
                    """
                We received a TURN message from ourselves
                this might indicate bad logic
                msg peer_tup 0 == {0}
                """,
                    (ext,),
                )
                log(error)

    # Reset attribute pointer to start.
    msg.attr_cursor = 0

    # Return results (if any.)
    return data, peer_tup


# True when all the fields in the client needed for auth are set.
def is_auth_ready(self):
    """Return True when key, realm, and nonce are all set on the client."""
    key_con = self.key is not None
    realm_con = self.realm is not None
    nonce_con = self.nonce is not None
    return bool(key_con and realm_con and nonce_con)


def turn_proc_attrs(af, attr_code, attr_data, msg, self):
    """Process a single TURN attribute and update client state, returning [error_code, error_msg]."""
    error_code = 0
    error_msg = b""

    # Server address given back for relaying messages.
    if attr_code == STUNAttrs.XorRelayedAddress:
        if self.relay_tup is None:
            # Extract the relay address info to a tup.
            stun_addr = STUNAddrTup(
                af=af,
                txid=msg.txn_id,
                magic_cookie=msg.magic_cookie,
            )
            stun_addr.decode(attr_code, attr_data)
            self.relay_tup = stun_addr.tup

            # Indicate the tup has been set.
            if not self.relay_tup_future.done():
                self.relay_tup_future.set_result(self.relay_tup)
            log(fstr("> Turn setting relay addr = {0}", (self.relay_tup,)))
            self.relay_event.set()

            # Validate relay tup IP.
            if self.relay_tup[0] != self.dest[0]:
                error = fstr(
                    """
                Our XOR relay tup IP was decoded as
                {0} which is different
                from the address of the TURN server
                {1} which may
                indicate a XOR decoding error.
                """,
                    (
                        self.relay_tup[0],
                        self.dest[0],
                    ),
                )
                log(error)

    # Handle authentication.
    if attr_code == STUNAttrs.Realm:
        self.realm = attr_data
        if self.turn_user is not None and self.turn_pw is not None:
            self.key = md5(
                self.turn_user + b":" + self.realm + b":" + self.turn_pw
            ).digest()
            log(fstr("> Turn setting key = {0}", (to_s(to_h(self.key)),)))

    # Nonce is used for reply protection.
    # As our client uses a state-machine the impact of this is minimal.
    elif attr_code == STUNAttrs.Nonce:
        self.nonce = attr_data
        if IS_DEBUG:
            log(fstr("> Turn setting nonce = {0}", (to_s(to_h(self.nonce.tobytes())),)))

    elif attr_code == STUNAttrs.Lifetime:
        (self.lifetime,) = unpack("!I", attr_data)
        if IS_DEBUG:
            log(fstr("> Turn setting lifetime = {0}", (self.lifetime,)))

    # Return any error codes.
    elif attr_code == STUNAttrs.ErrorCode:
        b2 = io.BytesIO(attr_data)
        d = b2.read(4)
        error_code = (d[2] & 0x7) * 100 + d[3]
        error_msg = b2.read()

    return [error_code, error_msg]


# Processes attributes from a TURN message.
def process_attributes(af, self, msg):
    """Walk all attributes in a TURN message, updating client state and returning any error info."""
    # Unpack attributes from message.
    error_code = 0
    error_msg = b""
    while not msg.eof():
        attr_code, _, attr_data = msg.read_attr()
        attr_result = turn_proc_attrs(af, attr_code, attr_data, msg, self)
        if attr_result[0]:
            error_code = attr_result[0]
            error_msg = attr_result[1]
        stun_proc_attrs(af, attr_code, attr_data, msg)
        if hasattr(msg, "rtup"):
            if not self.client_tup_future.done():
                self.mapped = msg.rtup
                self.client_tup_future.set_result(self.mapped)

    # Trigger auth ready event.
    if is_auth_ready(self):
        if not self.auth_event.is_set():
            self.auth_event.set()

    # Reset attribute pointer to start.
    msg.attr_cursor = 0

    # Return any errors info.
    return [error_code, error_msg]


# Process any replies from the TURN server.
# This function is run concurrently and doesn't block the main program.
def turn_msg_handler(client, data, client_tup, pipe):
    """msg_cb-style handler for TURN server messages on the signaling
    pipe.  Replaces the old process_replies polling loop -- registered
    via turn_pipe.add_msg_cb(...) in TURNClient.start() so each inbound
    frame dispatches immediately (no 1s poll latency).

    Wrapped per-message in an exception guard: a single malformed frame
    must not kill subsequent dispatch.
    """
    try:
        dispatch_one(client, data)
    except asyncio.CancelledError:
        raise
    except Exception:  # pylint: disable=broad-except
        log_exception()


def dispatch_one(self, out):
    """Dispatch one inbound frame from the TURN server's signaling
    pipe.  Recognises three classes:
      1. ChannelData (first byte 0x40-0x7F) — strip channel header,
         route via channel_to_peer.
      2. STUN message with a Data attribute + XorPeerAddress —
         relay-forwarded peer data, route via handle_data.
      3. STUN message matching a previously-recorded transaction TXID
         — Allocate / CreatePermission / Refresh / ChannelBind reply,
         resolve the waiting future.
    """
    # Prune old tasks at each iteration (was in the old loop).
    self.tasks = rm_done_tasks(self.tasks)

    # 1) ChannelData dispatch.  Non-STUN, [channel:2][len:2][data][pad].
    out_bytes = bytes(out) if not isinstance(out, bytes) else out
    if len(out_bytes) >= 4 and 0x40 <= out_bytes[0] <= 0x7F:
        channel_num = (out_bytes[0] << 8) | out_bytes[1]
        data_len = (out_bytes[2] << 8) | out_bytes[3]
        if len(out_bytes) >= 4 + data_len:
            channel_peer = self.channel_to_peer.get(channel_num)
            if channel_peer is not None:
                payload = out_bytes[4:4 + data_len]
                # ACK reply MUST go via raw self.stream.send so the
                # 9-byte ACK frame is sent unwrapped to the peer's
                # relay.  Using TURNClient.send would re-wrap via
                # ack_send -> [new_seq:8][0x00][ack:9] = 18 bytes;
                # the peer's dispatch would then unwrap the outer
                # frame and route the inner 9-byte ACK to its app
                # via handle_data (TURNClient.is_ack is None for the
                # UDP-typed TURN pipe so the inner ACK isn't filtered),
                # surfacing as a stray 9-byte buffer to user code.
                peer_relay_tup = self.peers.get(channel_peer)
                if peer_relay_tup is not None:
                    f_send = (
                        lambda buf, prt=peer_relay_tup:
                        self.stream.send(buf, prt)
                    )
                else:
                    f_send = lambda buf: None
                _, app_payload = self.stream.handle_ack(
                    payload,
                    self.stream.is_ack,
                    self.stream.is_ackable,
                    f_send,
                )
                if app_payload is not None:
                    self.handle_data(app_payload, channel_peer)
            else:
                log(fstr(
                    "ChannelData on unbound channel {0}",
                    (channel_num,),
                ))
        return

    # 2) STUN message parse.  Malformed frames return None; skip.
    turn_msg, turn_method, turn_status = turn_parse_msg(memoryview(out))
    if turn_msg is None:
        return

    # Data attribute path — server forwarded a peer's data to us.
    msg_data, peer_tup = turn_get_data_attr(turn_msg, self.turn_pipe.route.af, self)
    if msg_data is not None and peer_tup is not None:
        peer_tup = norm_client_tup(peer_tup)
        if peer_tup not in self.peers:
            log(fstr(
                "Got a TURN data message from an unknown peer = {0} "
                "which may indicate a decoding error.",
                (peer_tup,),
            ))
            return
        peer_relay_tup = self.peers[peer_tup]
        _, payload = self.stream.handle_ack(
            msg_data,
            self.stream.is_ack,
            self.stream.is_ackable,
            lambda buf: self.stream.send(buf, peer_relay_tup),
        )
        if payload is None:
            log(fstr("Payload from turn was None but msg data = {0}", (msg_data,)))
            if self.blank_rudp_headers:
                self.handle_data(msg_data, peer_tup)
            return
        self.handle_data(payload, peer_tup)
        return

    # 3) Response to one of our outstanding requests, matched by TXID.
    txid = turn_msg.txn_id
    if txid not in self.msgs:
        log("Got turn message with unknown TXID.")
        return
    if self.msgs[txid]["status"].done():
        return

    try:
        error_code, error_msg = process_attributes(
            self.turn_pipe.route.af, self, turn_msg
        )
    except (OSError, ValueError):
        log_exception()
        return

    if turn_status == STUNMsgCodes.ErrorResp:
        log("Turn error {}: {}".format(error_code, error_msg))
        log(fstr("turn hex msg: {0}", (to_h(turn_msg.pack()),)))
        if error_code == 438:
            log(fstr("stale nonce. retransmit for {0}", (txid,)))
            if not self.msgs[txid]["status"].done():
                self.msgs[txid]["status"].set_result(STATUS_RETRY)
            return

    if turn_method == STUNMsgTypes.Allocate:
        log("got alloc")
        if not self.msgs[txid]["status"].done():
            self.msgs[txid]["status"].set_result(STATUS_SUCCESS)
        if turn_status == STUNMsgCodes.SuccessResp:
            if self.state != TURN_TRY_ALLOCATE:
                self.auth_event.set()
        else:
            log("Error in TURN allocate")
        # First Allocate is intentionally unsigned -> 401, then signed
        # via the retry task below.
        if turn_status == STUNMsgCodes.ErrorResp:
            if self.state != TURN_TRY_ALLOCATE:
                self.set_state(TURN_TRY_ALLOCATE)
                task = asyncio.create_task(async_wrap_errors(
                    async_retry(lambda: self.allocate_relay(sign=True), count=5)
                ))
                self.tasks.append(task)
        self.msgs.pop(txid, None)
        return

    if turn_method == STUNMsgTypes.CreatePermission:
        if turn_status == STUNMsgCodes.SuccessResp:
            if not self.msgs[txid]["status"].done():
                self.msgs[txid]["status"].set_result(STATUS_SUCCESS)
        else:
            log(fstr(
                "Error in TURN create permission = {0}",
                (to_h(turn_msg.pack()),),
            ))
        self.msgs.pop(txid, None)
        return

    if turn_method == STUNMsgTypes.Refresh:
        if not self.msgs[txid]["status"].done():
            self.msgs[txid]["status"].set_result(STATUS_SUCCESS)
        self.msgs.pop(txid, None)
        return

    if turn_method == STUNMsgTypes.ChannelBind:
        if not self.msgs[txid]["status"].done():
            if turn_status == STUNMsgCodes.SuccessResp:
                self.msgs[txid]["status"].set_result(STATUS_SUCCESS)
            else:
                self.msgs[txid]["status"].set_result(STATUS_RETRY)
                log(fstr(
                    "ChannelBind rejected: {0}",
                    (to_h(turn_msg.pack()),),
                ))
        self.msgs.pop(txid, None)
        return
