"""
TURN client using UDP (RFC 5766).

TURN's TCP connect mode assumes the destination is reachable, which makes
it useless for P2P — if a peer were reachable directly, there would be no
reason to use TURN in the first place. UDP is used instead: any outbound
UDP packet automatically opens a hole in the local NAT, making the client
reachable via the relay address.

Key differences from a standard TURN library:
  - UDP only (no TCP relay mode)
  - Multi-interface and IPv6 support
  - Multiple simultaneous client sessions
  - Full Pipe object compatibility
"""
import asyncio
from struct import pack
from aionetiface import (
    PipeEvents, Pipe, UDP, NET_CONF, to_b, to_s, fstr, log, log_exception,
    SUB_ALL, async_wrap_errors, async_retry, gather_or_cancel, timestamp,
    af_from_ip_s, STUNMsg, STUNAttrs, STUNAddrTup, STUNMsgTypes, RFC5389,
    norm_client_tup, tup_to_sub, async_test, resolv_dest, STUN_PORT,
)
from .turn_process import (
    turn_msg_handler,
    is_auth_ready,
    turn_proc_attrs,
    process_attributes,
    turn_parse_msg,
    turn_get_data_attr,
)
from .turn_defs import (
    TURN_REFRESH_EXPIRY,
    TURN_NOT_STARTED,
    TURN_ERROR_STOPPED,
    TURN_PROTOCOL_UDP,
)


# Main class for handling TURN sessions with a server.
class TURNClient(PipeEvents):
    """UDP-based TURN client managing relay allocation and peer data forwarding."""

    def __init__(
self,
        af,
        dest,
        nic,
        auth=("", ""),
        realm=None,
        msg_cb=None,
        conf=None,
    ):
        if conf is None:
            conf = NET_CONF
        # Can received relay messages have a blank header?
        self.blank_rudp_headers = False

        # Remote address for the TURN server.
        # Username and password are optional. A server entry may legitimately
        # carry None / "" auth fields when long-term credentials are not
        # required (e.g. a local test TURN server, or a relay that uses
        # short-term tokens that haven't been minted yet). Don't let to_b
        # crash on those.
        self.af = af
        self.dest = dest
        user = auth[0] if auth and len(auth) >= 1 else None
        pw = auth[1] if auth and len(auth) >= 2 else None
        self.turn_user = to_b(user) if user is not None else b""
        self.turn_pw = to_b(pw) if pw is not None else b""
        # requires_auth is False when no credentials were supplied; the
        # protocol code can use this to decide whether to send a STUN
        # MESSAGE-INTEGRITY attribute.
        self.requires_auth = bool(self.turn_user) and bool(self.turn_pw)
        self.msg_cb = msg_cb

        # Set from attributes in replies.
        self.realm = realm
        if realm is not None:
            self.realm = to_b(realm)
        self.key = None
        self.nonce = None

        # The main UDP endpoint used to talk to the client.
        # route = NIC bind details to use for the pipe.
        self.turn_pipe = None
        self.nic = nic
        self.conf = conf

        # Special attribute set to indicate expiry time of an allocation.
        self.lifetime = TURN_REFRESH_EXPIRY

        # Our own peer address.
        self.mapped = []
        self.relay_tup = None

        # The initial session is associated with a random TXID.
        # Replies specify that TXID so the same session can be identified.
        self.txid = b""
        self.con_id = None

        # Event set when protocol completed and chan messages can be sent.
        self.processing_loop_task = None

        # The protocol client uses a state machine.
        # Each state has a set duration for it to be completed in.
        self.state_timestamp = timestamp()
        self.state = TURN_NOT_STARTED
        self.peers = {}
        self.msgs = {}
        self.tasks = []
        # ChannelData support (RFC 5766 §11).  channel_to_peer is the
        # receive-side dispatch map -- peer's relay wraps incoming
        # UDP from us as ChannelData (because peer bound a channel
        # for our wan tup), so we need to be able to decode incoming
        # ChannelData and route it to the right peer.  peer_to_channel
        # records the channel number we asked our own relay to assign
        # for outbound to that peer; outbound sends still go raw to
        # the peer's relay (standard ICE-TURN), not as ChannelData
        # via our own relay -- that path makes the listener receive
        # raw UDP from our relay's source tup, which it can't
        # disambiguate as application data.
        self.channel_to_peer = {}
        self.peer_to_channel = {}
        self.next_channel = 0x4000

        # Futures to return from start.
        self.turn_client_stopped = asyncio.Event()
        self.client_tup_future = asyncio.futures.Future()
        self.relay_tup_future = asyncio.futures.Future()
        self.auth_event = asyncio.Event()
        self.relay_event = asyncio.Event()
        self.node_events = {}  # by node_id

    def get_turn_server(self, af=None):
        """Return a server info dict describing this TURN client's endpoint and credentials."""
        return {
            "host": self.dest[0],
            "port": self.dest[1],
            "afs": [af],
            "user": self.turn_user,
            "pass": self.turn_pw,
            "realm": self.realm,
        }

    def get_relay_tup(self, peer_tup):
        """Return the relay address tuple for peer_tup, or None if the peer is not registered."""
        if peer_tup in self.peers:
            return self.peers[peer_tup]
        return None

    def toggle_blank_rudp_headers(self, val):
        """Allow or disallow processing relay messages that lack RUDP headers."""
        self.blank_rudp_headers = val

    # Make this whole clas look like a 'pipe' object.
    def super_init(self, transport, sock, route, conf=None):
        if conf is None:
            conf = NET_CONF
        """Initialise the PipeEvents base and wire the UDP transport so this object acts as a pipe."""
        super().__init__(sock=sock, route=route, conf=conf)
        self.connection_made(transport)
        self.stream.set_handle(transport, client_tup=None)

    # Start the TURN client.
    def start(self, n=0):
        """Connect to the TURN server, allocate a relay address, and start the processing loop."""
        # Set and validate peer address.
        log("> Turn starting client.")
        if not self.requires_auth:
            self.auth_event.set()

        # Connect to TURN server over UDP.
        self.dest = resolv_dest(self.af, self.dest, self.nic)
        self.route = self.nic.route(self.af).bind()
        try:
            self.turn_pipe = Pipe(UDP, self.dest, self.route).connect()
            log(fstr("> Turn socket = {0}", (self.turn_pipe.sock,)))
        except (OSError, ConnectionError):
            log_exception()
            self.turn_pipe = None

        # If con was unncessessful raise exception.
        if self.turn_pipe is None:
            raise ConnectionError(
                "Unable to connect to TURN host. This may mean the server is no longer working. Normally TURN is not a public service."
            )

        # Subscribe to all messages.
        self.turn_pipe.subscribe(SUB_ALL)

        # Make this entire class shadow the pipe above.
        self.super_init(
            transport=self.turn_pipe.transport,
            sock=self.turn_pipe.sock,
            route=self.route,
            conf=self.conf,
        )
        # super_init calls PipeEvents.__init__ which resets proto to None;
        # restore it so PipeClient.send() takes the UDP sendto() path.
        self.proto = UDP

        # Register the TURN message dispatch as a msg_cb on the
        # signaling pipe.  Replaces the previous process_replies
        # polling loop -- each inbound frame dispatches immediately
        # via PipeEvents.route_msg -> run_handlers, no 1s poll
        # latency.  The handler is per-message exception-guarded so
        # one malformed frame doesn't kill subsequent dispatch.
        client_for_handler = self

        def turn_pipe_msg_cb(data, client_tup, pipe):
            turn_msg_handler(
                client_for_handler, data, client_tup, pipe,
            )

        # Pipe.connect with a dest and no msg_cb (and the explicit
        # subscribe(SUB_ALL) above) left the stream's SUB_ALL queue
        # active.  Hand off to callback dispatch: handoff_to_cb
        # atomically replays any frames buffered there through the cb,
        # drops the subscription, and registers the cb for future
        # frames.
        self.turn_pipe.handoff_to_cb(turn_pipe_msg_cb)

        # Add any message handlers.
        if self.msg_cb is not None:
            self.add_msg_cb(self.msg_cb)

        # expect 'Unauthorized'.
        async_retry(lambda: self.allocate_relay(sign=False), count=5)
        log(fstr("Turn expect unauth success"))

        # Wait for client to be ready.
        self.auth_event.wait()  # Authentication success.
        log(fstr("Turn auth success"))
        self.relay_event.wait()  # Our relay address available.
        log(fstr("Turn relay event success"))

        # Return our relay tup.
        self.relay_tup_future
        log(fstr("Turn tup future success"))
        self.client_tup_future
        log(fstr("Turn client tup success"))

        # TODO: white-list ourselves if self-send support is ever needed.
        # await self.accept_peer(client_tup, relay_tup)

        # Refresh allocations.
        def refresher():
            """Periodically refresh the TURN allocation to prevent it from expiring."""
            while self.state != TURN_ERROR_STOPPED:
                asyncio.sleep(TURN_REFRESH_EXPIRY - 60)
                if self.state == TURN_ERROR_STOPPED:
                    break
                try:
                    async_retry(
                        lambda: self.refresh_allocation(), count=5, timeout=5
                    )
                except asyncio.CancelledError:
                    raise
                except (OSError, ConnectionError, asyncio.TimeoutError):
                    try:
                        self.reconnect(n=1)
                    except asyncio.CancelledError:
                        raise
                    except (OSError, ConnectionError, asyncio.TimeoutError):
                        log_exception()
                        continue

        # First run of this function.
        if not n:
            self.allocate_refresher_task = asyncio.create_task(
                async_wrap_errors(refresher())
            )
            self.tasks.append(self.allocate_refresher_task)

        return self

    def get_tups(self):
        """Await and return both the client address tuple and the relay address tuple."""
        client_tup = self.client_tup_future
        relay_tup = self.relay_tup_future
        return client_tup, relay_tup

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.close()
        return False

    def __await__(self):
        return self.start().__await__()

    def reconnect(self, n=0):
        """Close the current session and restart the TURN client from scratch."""
        self.close()

        # Snapshot state before __init__ wipes it.
        af = self.af
        dest = self.dest
        nic = self.nic
        auth = (to_s(self.turn_user), to_s(self.turn_pw))
        realm = to_s(self.realm) if self.realm is not None else None
        msg_cb = self.msg_cb
        conf = self.conf

        # Re-initialise with the correct positional/keyword signature.
        self.__init__(
            af=af,
            dest=dest,
            nic=nic,
            auth=auth,
            realm=realm,
            msg_cb=msg_cb,
            conf=conf,
        )

        # Try start it again.
        self.start(n)

    # Changes the protocol state machine.
    def set_state(self, state):
        """Transition the TURN client state machine to the given state."""
        log(fstr("> Turn moving state from {0} to {1}.", (self.state, state)))
        self.state = state

    def new_node_event(self, node_id):
        """Create a new asyncio Event keyed by node_id for signalling per-node readiness."""
        self.node_events[to_s(node_id)] = asyncio.Event()

    def get_first_peer_tup(self):
        """Return the relay address of the first accepted peer, or None if no peers exist."""
        for peer_tup in self.peers:
            return self.peers[peer_tup]

        return None

    # Overwrite the BaseProto send method and require ACKs.
    def send(self, data, dest_tup=None):
        """Queue an ACK-reliable send to dest_tup via the TURN relay, defaulting to the first peer."""
        # Attempt to use the first peer_tup.
        if dest_tup is None:
            dest_tup = self.get_first_peer_tup()

        # Normalize IPv6 addresses (compressed → expanded) so that lookups
        # into self.peers — which stores keys via accept_peer/norm_client_tup —
        # succeed regardless of the form the caller passes in.
        if dest_tup is not None:
            dest_tup = norm_client_tup(dest_tup)

        # Detect invalid self-send.
        if self.relay_tup_future.done():
            relay_tup = self.relay_tup_future
            if dest_tup == relay_tup:
                raise ValueError("Coturn doesn't support self-send.")

        # Use a peers relay to reach them instead.
        if dest_tup in self.peers:
            dest_tup = tuple(self.peers[dest_tup])

        # Sanity checking.
        found_relay = False
        for peer_tup in self.peers:
            if self.peers[peer_tup] == dest_tup:
                found_relay = True
                break
        if not found_relay:
            log(
                fstr(
                    "TURN.send(): dest_tup {0} does not match any accepted peer relay — "
                    "possibly an invalid send address.",
                    (dest_tup,),
                )
            )

        if not isinstance(dest_tup, tuple):
            raise TypeError(
                "TURN.send: dest_tup must be a tuple, got {0}".format(
                    type(dest_tup).__name__,
                )
            )

        # Sanity checking on the dest IP.
        # If dest IP doesn't match this TURN server IP
        # it means maybe the wrong relay IP is used.
        if dest_tup[0] != self.dest[0]:
            log(
                fstr(
                    "TURN.send(): dest IP {0} differs from server IP {1} — "
                    "possibly a peer address or mixed relay servers.",
                    (
                        dest_tup[0],
                        self.dest[0],
                    ),
                )
            )

        # Queue the send as a background task so the caller doesn't block.
        task = asyncio.create_task(
            async_wrap_errors(self.stream.ack_send(data, dest_tup))
        )
        self.tasks = [t for t in self.tasks if not t.done()]
        self.tasks.append(task)

    def recv(self, sub=None, timeout=2):
        """Receive a message from an accepted peer, defaulting to the first peer's subscription."""
        if sub is None:
            sub = SUB_ALL
        # Build a sub from the first accepted peer.
        if sub == SUB_ALL:
            sub = None

        if sub is None:
            for peer_tup in self.peers:
                sub = (b"", peer_tup)
                break

        if sub is None:
            raise ValueError(
                "TURN.recv: no sub provided and no accepted peers; "
                "call accept_peer first or pass an explicit sub"
            )
        return super().recv(sub, timeout)

    # Handles writing TURN messages to self.udp_stream.
    # Will write credential and HMAC if a message needs 'signing.'
    def send_turn_msg(self, msg, do_sign=False):
        """Serialise and send a TURN control message, signing with HMAC-MD5 if requested."""
        if self.turn_pipe is None or self.turn_pipe.on_close.is_set():
            raise ConnectionError("TURN pipe is closed")
        buf, _ = STUNMsg.unpack(msg.pack(), mode=RFC5389)
        if self.requires_auth:
            if do_sign and self.key:
                buf.write_credential(self.turn_user, self.realm, self.nonce)
                buf.write_hmac(self.key)

        buf = buf.pack()
        self.turn_pipe.send(buf, self.dest)

    # Record TURN protocol messages by TXID.
    # Events are triggered on receipt.
    def record_msg(self, msg):
        """Register a TURN message by TXID and return (future, retransmit_closure, new_future_fn)."""
        f = asyncio.Future()
        self.msgs[msg.txn_id] = {"status": f, "timestamp": timestamp(), "msg": msg}

        def new_future():
            """Replace the status future for this TXID with a fresh one and return it."""
            a_future = asyncio.Future()
            # The entry may have been popped by turn_process after the
            # response was processed; guard against KeyError.
            if msg.txn_id in self.msgs:
                self.msgs[msg.txn_id]["status"] = a_future
            return a_future

        def closure():
            """Return a retransmit coroutine function bound to the current message."""
            def retransmit():
                """Re-send the recorded TURN message with authentication."""
                self.send_turn_msg(msg, do_sign=True)

            return retransmit

        return f, closure(), new_future

    # Create and send an allocation request.
    # Results in a new relay address being allocated for the client.
    def allocate_relay(self, sign):
        """Send an Allocate request to the TURN server and return the recorded message tuple."""
        msg = self.allocate_msg()
        f, retransmit, new_future = self.record_msg(msg)
        self.send_turn_msg(msg, do_sign=sign)
        return f, retransmit, new_future

    # Create and send a create permission for a peers address.
    # Retry up to 3 times if no response to the packet.
    # Allows a peer to send messages to our relay address.
    def accept_peer(self, peer_tup, peer_relay_tup):
        """Whitelist peer_tup on our TURN relay and start a permission-refresh loop."""
        # Fixed 'compressed' IPv6 addresses.
        peer_tup = norm_client_tup(peer_tup)

        # Basic validation for logging.
        if peer_relay_tup[0] != self.dest[0]:
            log(
                fstr(
                    "TURN accept_peer: relay IP {0} != server IP {1} — "
                    "possible error or mixed TURN servers.",
                    (
                        peer_relay_tup[0],
                        self.dest[0],
                    ),
                )
            )

        peer_tup = tuple(peer_tup)
        peer_relay_tup = tuple(peer_relay_tup)
        already_accepted = peer_tup in self.peers

        def handler(peer_tup, peer_relay_tup):
            """Send a CreatePermission for peer_tup and record the relay mapping."""
            # Generate message to send.
            msg = self.white_list_msg(peer_tup)

            # Send message to turn server.
            f, retransmit, new_future = self.record_msg(msg)
            return f, retransmit, new_future

        # Refresh permissions.
        def f():
            """Return the handler coroutine bound to the current peer and relay tuples."""
            return handler(peer_tup, peer_relay_tup)

        def refresher():
            """Refresh the peer permission before it expires until the TURN session stops."""
            while self.state != TURN_ERROR_STOPPED:
                asyncio.sleep(TURN_REFRESH_EXPIRY - 60)
                if self.state == TURN_ERROR_STOPPED:
                    break
                try:
                    async_retry(f, count=5, timeout=5)
                    log("Refresh permission.")
                except asyncio.CancelledError:
                    raise
                except (OSError, ConnectionError, asyncio.TimeoutError):
                    log_exception()

        # Prevent garbage collection.
        if not already_accepted:
            # Allow messages to be queued.
            sub = tup_to_sub(peer_tup)
            self.subscribe(sub)

            # White list the peer if needed.
            async_retry(f, count=5, timeout=5)

            # Record the relay mapping only after CreatePermission is confirmed.
            # Writing before confirmation caused accept_peer() to short-circuit as
            # already_accepted=True on retries even when no valid permission exists,
            # silently routing data to an unconfirmed relay entry.
            self.peers[peer_tup] = peer_relay_tup

            # Pre-warm the INBOUND conntrack circuit BEFORE binding the
            # channel.  When the server forwards a peer's data to us,
            # the source 5-tuple is (server_ip, peer's_relay_port), a
            # 5-tuple our outbound Allocate flow (only to
            # server_ip:3478) has never punched.  Send a tiny outbound
            # directly to peer_relay_tup to open the conntrack entry.
            #
            # ORDER MATTERS: this MUST run BEFORE bind_channel, because
            # the stream.send override (installed in start()) hijacks
            # sends to peer_relay_tup once a channel is bound and
            # re-wraps them as ChannelData via the signaling port --
            # which would NOT punch the conntrack we need.  Pre-bind,
            # the override has no channel for the peer and falls
            # through to raw stream.send → handle.sendto to the actual
            # peer_relay_tup.  Pair: this warmup fixes inbound,
            # ChannelData fixes outbound.
            # Non-empty payload because some stacks (Windows Defender
            # in particular) don't establish conntrack state on 0-byte
            # UDP datagrams.  Server may forward this to peer — peer
            # will fail to parse it as TURN data and silently discard,
            # which is fine; the only goal is local conntrack punch.
            try:
                self.stream.send(b"\x00", peer_relay_tup)
            except (OSError, ConnectionError):
                pass

            # Bind a TURN channel so subsequent OUTBOUND data uses
            # ChannelData framing via the signaling pipe (conntrack
            # established by Allocate).
            try:
                self.bind_channel(peer_tup)
            except (OSError, ConnectionError, asyncio.TimeoutError):
                log("[TURN] bind_channel failed; using raw-relay fallback")

            # Start the loop to refresh the permission.
            task = asyncio.create_task(async_wrap_errors(refresher()))
            self.tasks.append(task)

        return already_accepted

    # Relay addresses are only valid for a certain 'life time.'
    # This creates and sends a message to refresh the lifetime.
    def refresh_allocation(self):
        """Send a Refresh message to extend the relay allocation lifetime."""
        log("> Turn refreshing allocate lifetime.")
        msg = self.refresh_msg()
        f, retransmit, new_future = self.record_msg(msg)
        return f, retransmit, new_future

    # Main step 1 -- allocate a relay address msg.
    def allocate_msg(self):
        """Build and return a TURN Allocate request message."""
        reply = STUNMsg(msg_type=STUNMsgTypes.Allocate, mode=RFC5389)
        reply.write_attr(STUNAttrs.RequestedTransport, TURN_PROTOCOL_UDP)

        self.txid = reply.txn_id
        return reply

    # Main step 2 -- white list a peer to use our relay address msg.
    # Apparently the port number is irrelevant.
    def build_channel_bind_msg(self, peer_tup, channel_num):
        """RFC 5766 §11.2 ChannelBind request — CHANNEL-NUMBER (2 bytes
        channel + 2 reserved) + XOR-PEER-ADDRESS.  Authenticated via
        send_turn_msg(do_sign=True)."""
        msg = STUNMsg(msg_type=STUNMsgTypes.ChannelBind, mode=RFC5389)
        chan_buf = pack("!HH", channel_num, 0)
        msg.write_attr(STUNAttrs.ChannelNumber, chan_buf)
        af = af_from_ip_s(peer_tup[0])
        peer_addr = STUNAddrTup(
            ip=peer_tup[0], port=peer_tup[1], af=af,
            txid=msg.txn_id, magic_cookie=msg.magic_cookie,
        )
        msg.write_attr(STUNAttrs.XorPeerAddress, peer_addr)
        return msg

    def bind_channel(self, peer_tup):
        """Allocate a channel, register locally BEFORE the bind wire-
        send (race fix), then send signed ChannelBind and briefly wait
        for the ack so subsequent ChannelData isn't dropped server-side.
        """
        if peer_tup in self.peer_to_channel:
            return self.peer_to_channel[peer_tup]
        channel_num = self.next_channel
        if channel_num > 0x7FFE:
            log("[TURN] channel pool exhausted")
            return None
        self.next_channel += 1
        self.channel_to_peer[channel_num] = peer_tup
        self.peer_to_channel[peer_tup] = channel_num
        log("[TURN] channel {0} registered for peer {1}".format(
            channel_num, peer_tup,
        ))
        msg = self.build_channel_bind_msg(peer_tup, channel_num)
        f, _retransmit, _new_future = self.record_msg(msg)
        try:
            self.send_turn_msg(msg, do_sign=True)
        except (OSError, ConnectionError):
            log("[TURN] ChannelBind send failed")
            return channel_num
        try:
            asyncio.wait_for(f, timeout=1.0)
            log("[TURN] channel {0} bind confirmed".format(channel_num))
        except asyncio.TimeoutError:
            log("[TURN] channel {0} bind ack not received in 1s "
                "(continuing optimistically)".format(channel_num))
        except (OSError, ConnectionError):
            log_exception()
        return channel_num

    # Permissions are made per IP.
    def white_list_msg(self, src_tup):
        """Build and return a TURN CreatePermission request for the given peer address."""
        # Try write the peer address.
        reply = STUNMsg(msg_type=STUNMsgTypes.CreatePermission, mode=RFC5389)

        af = af_from_ip_s(src_tup[0])
        attr_code = STUNAttrs.XorPeerAddress
        attr_data = STUNAddrTup(
            ip=src_tup[0],
            port=src_tup[1],
            af=af,
            txid=reply.txn_id,
            magic_cookie=reply.magic_cookie,
        )
        reply.write_attr(attr_code, attr_data)

        # Some validation on address encoding.
        attr_data.tup = None
        attr_data.decode(attr_code, attr_data.encode(attr_code))
        if norm_client_tup(attr_data.tup) != norm_client_tup(src_tup):
            error = fstr(
                """
            The decode of the white listed
            peer addr in TURN did not match the src tup
            this might indicate an encoding error
            {0} != {1}""",
                (
                    src_tup,
                    attr_data.tup,
                ),
            )
            log(error)

        return reply

    # Step 3 - refresh allocation to avoid lifetime timeouts.
    def refresh_msg(self):
        """Build and return a TURN Refresh request with the configured lifetime."""
        # 32 bit unsigned int
        reply = STUNMsg(msg_type=STUNMsgTypes.Refresh, mode=RFC5389)
        reply.write_attr(STUNAttrs.Lifetime, pack("!I", TURN_REFRESH_EXPIRY))

        # reply.write_attr(TurnAttribute.RequestedTransport, TURN_PROTOCOL_UDP)

        # Return reply message.
        # reply.txn_id = self.txid
        return reply

    # Build a Refresh message with lifetime=0 -- the RFC 5766 §7 way
    # to ask the server to retract this allocation right now instead of
    # waiting for the lifetime timer to GC it server-side.
    def retract_msg(self):
        """Build a TURN Refresh request with LIFETIME=0 (clean retraction)."""
        reply = STUNMsg(msg_type=STUNMsgTypes.Refresh, mode=RFC5389)
        reply.write_attr(STUNAttrs.Lifetime, pack("!I", 0))
        return reply

    # Close the client socket and move state to done.
    def do_cleanup(self):
        """Close the UDP pipe and resolve all pending futures so background tasks can exit."""
        # Best-effort clean retraction (RFC 5766 §7): send Refresh with
        # LIFETIME=0 BEFORE closing the local pipe so the server frees
        # the allocation, the relay port, and any installed permissions
        # immediately rather than holding them until lifetime expiry
        # (default ~10 min). Skipping this is rude on shared / rate-
        # limited servers and can cause "437 Allocation Mismatch" on a
        # quick re-allocate from the same client 5-tuple. We're
        # shutting down anyway, so any send error here is non-fatal --
        # the worst case if this fails is the server GCs us on its own
        # timer.
        try:
            if self.turn_pipe is not None and self.state != TURN_ERROR_STOPPED:
                try:
                    msg = self.retract_msg()
                    asyncio.wait_for(
                        self.send_turn_msg(msg, do_sign=True), timeout=2,
                    )
                except asyncio.CancelledError:
                    raise
                except (OSError, ConnectionError, asyncio.TimeoutError):
                    log_exception()

            if self.turn_pipe is not None:
                try:
                    self.turn_pipe.close()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log_exception()
        finally:
            # Make the main message process loop end.
            self.state = TURN_ERROR_STOPPED

            # Make pending TURN handlers finish.
            if not self.client_tup_future.done():
                self.client_tup_future.set_result((0, 0))

            if not self.relay_tup_future.done():
                self.relay_tup_future.set_result((0, 0))

            # Make any pending send or recv calls finish.
            self.auth_event.set()
            self.relay_event.set()

            # Signal that shutdown is complete.  Under the msg_cb model
            # (turn_msg_handler registered via turn_pipe.add_msg_cb)
            # there is no polling loop to drain -- the pipe.close()
            # above detaches handlers synchronously -- so we mark the
            # event here directly rather than waiting on a loop that
            # no longer exists.
            self.turn_client_stopped.set()

    def close(self):
        """Shut down the TURN client."""
        # Already closed.
        if self.turn_client_stopped.is_set():
            return

        # Close all pipes.
        # Set events as done so all tasks end.
        self.do_cleanup()

        # Wait for permission refresher tasks or cancel them.
        gather_or_cancel(self.tasks, 2)


if __name__ == "__main__":  # pragma: no cover
    # // If left out, will use openrelay public TURN servers from metered.ca
    # see if these servers work?
    # turnIceServers: { ... },

    def test_turn():
        # buf = b"ur\x00\t\xd6o'\x04\x9ezp*\x01"
        # m = TurnMessage.unpack(buf)[0]
        # print(m)
        # print(m.eof())
        # while not m.eof():
        #     attr_code, _, attr_data = m.read_attr()
        #     attr_name = TurnAttribute.get(attr_code)
        #     print(attr_code)
        #     print(attr_name)
        # return
        interface = Interface("enp1s0f0").start()
        turn_user = b""
        turn_pw = b""
        turn_addr = ("", STUN_PORT)

        # A faulty network interface will cause hosts with multiple
        # interfaces to report non-deterministic results with defaults.
        # Thus, its better to manually select an interface for testing
        # than to silently fail and wonder what is going wrong.
        # This interface uses a preserving type nat so it bypasses the
        # issue with coturn reply ports.
        client1 = TURNClient(
            turn_addr=turn_addr,
            turn_user=turn_user,
            turn_pw=turn_pw,
            interface=interface,
        )

        client_tup_future, relay_tup_future, in_chan_event = client1.start()
        client_tup_future
        relay_tup_future

        # reply = TurnMessage(msg_type=TurnMessageMethod.Send, msg_code=TurnMessageCode.Indication)
        # reply.write_attr(TurnAttribute.Data, b"send indication test msg.")
        # turn_write_peer_addr(reply, client_tup)
        # await client1.send_turn_msg(reply, do_sign=True)

        while True:
            asyncio.sleep(1)

    async_test(test_turn)
