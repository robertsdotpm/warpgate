"""Traversal plugin that relays connections through a TURN server."""
import asyncio
from aionetiface import EXT_BIND, UDP, get_infra, fstr, log, log_p2p
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ....protocol.proto_defs import P2P_RELAY
from .proto import TURNMsg
from .turn_utils import get_first_working_turn_client, rendezvous_rank


@register(phase="relay")
class TURNPlugin(Plugin):
    """Traversal plugin that establishes a P2P connection via a TURN relay server."""

    name = "turn"
    transport = UDP
    # TURN is a public-relay mechanism only; only EXT_BIND combos make
    # sense. auto_combos won't generate NIC_BIND / LOOPBACK_BIND combos
    # for us. The historical "if route_type == NIC_BIND: return"
    # guard at the top of run() is no longer needed.
    route_types = (EXT_BIND,)
    # 10 s budget (per phase4_turn attempt; phase4 retries up to
    # TURN_TOTAL_CAP times). Unlike the punch plugins -- one NTP-pinned
    # shot, ~3 s -- turn is a two-round-trip cross-node protocol:
    # initiator allocates, signals the peer, the responder allocates +
    # accepts, signals back, the initiator's self.ready resolves.
    # Critical path = initiator_alloc + signal_RTT + responder_alloc +
    # accept + signal_RTT. Matrix best-case is ~2.6 s (fast local MQTT);
    # structural worst legit case ~8 s. 10 s nests the internal caps:
    # 10 (outer) > 8 (self.ready) > 4 (PER_SERVER_TIMEOUT / start() /
    # accept_peer()) -- every inner timeout strictly inside its
    # encloser so none is dead behind the outer cap.
    conf = {"timeout": 10}
    proto_messages = (
        (TURNMsg, P2P_RELAY, 10),
    )

    @classmethod
    def setup(cls, node):
        factory = TURNPluginFactory(node.msg_cb, node.node_id)
        node.resources.register(factory)
        return factory

    # Maximum number of server-renegotiation round trips before giving up.
    # Each round trip is one (initiator picks server, responder fails to
    # reach it, signals back) cycle. With a typical INFRA TURN list of 10
    # candidates this is generous -- 5 cycles can exclude up to 5 servers.
    MAX_RENEGOTIATIONS = 5

    def __init__(self):
        super().__init__()

        # Resolved by a second run() call on this same instance when the peer's
        # reply arrives, unblocking the first run() call that is awaiting it.
        self.ready = asyncio.Future()
        self.turn_clients = None
        self.msg_cb = None
        self.node_id = ""

        # Set of (host, port) tuples that have been attempted and failed
        # (or that the peer has excluded) for this plugin instance.
        # Renegotiation excludes these from candidate pools so we never
        # reattempt a known-bad server.
        self.tried_servers = set()
        self.renego_count = 0

    def run(self, reply=None):
        """Allocate a TURN relay, exchange addresses with the peer, and establish the channel.

        Server selection is initiator-decides with renegotiation. Mirrors
        reverse_connect's "I tell you what to do" pattern but adds a back
        channel so the responder can refuse a server and ask the initiator
        to pick again.

          * Initiator (reply is None): walks rendezvous-ranked TURN
            servers via get_first_working_turn_client, allocates, then
            sends TURNMsg with server_host/server_port embedded so the
            responder allocates on the SAME server. tried_servers
            carries every server the initiator has already attempted
            (just the one chosen, on the first round).
          * Responder receives TURNMsg with a server_host: tries to
            allocate on that server. If reachable -> normal flow. If
            unreachable -> sends back a TURNMsg with reject_reason set
            and tried_servers including the rejected server. relay_tup
            in the rejection is None.
          * Initiator receives a rejection: merges tried_servers into
            its local set, drops the cached client, picks the next
            best server from rendezvous excluding the tried set,
            allocates fresh, and sends a new TURNMsg.

        The renegotiation is bounded by MAX_RENEGOTIATIONS to keep a
        broken pair from looping forever; after that budget is spent the
        session aborts cleanly. The previous behaviour -- one server
        choice, no recourse -- meant any case where the initiator's
        chosen server was reachable to it but not to the responder
        (e.g. initiator on a mobile carrier reaching a Chinese coturn
        the responder's home ISP can't) silently NO_ECHO'd.
        """
        # TURN requires the two peers to be reachable from the relay
        # server as DISTINCT addresses.  When src["ext"] == dest["ext"]
        # (both peers behind the same NAT / colocated WAN IP), Coturn's
        # anti-loopback check rejects the relay forward, and even if it
        # didn't, the server's outbound to (ext, port) would loopback
        # via the local NAT to the wrong side.  Reject combos that
        # share an ext IP up front so the cascade falls through to
        # something that can work (NIC_BIND / LOOPBACK_BIND for same-
        # machine pairs).  Skipped for empty ext IPs (combo generator
        # guard handles that case).
        src_ext = self.src.get("ext")
        dest_ext = self.dest.get("ext")
        if src_ext and dest_ext and str(src_ext) == str(dest_ext):
            log(fstr(
                "turn[{0}]: src ext == dest ext ({1}); aborting "
                "(Coturn will reject same-WAN-IP relay)",
                (self.plugin_id, src_ext),
            ))
            if not self.result.done():
                self.result.set_result(None)
            return

        is_initial_initiator = reply is None
        is_responder = reply is not None and not (
            getattr(reply.payload, "reject_reason", None)
        )
        is_renegotiating_initiator = (
            reply is not None and getattr(reply.payload, "reject_reason", None) is not None
        )
        role_label = (
            "responder" if is_responder
            else ("renego-initiator" if is_renegotiating_initiator else "initiator")
        )
        log(fstr(
            "turn[{0}]: run af={1} reply={2} role={3} renego_count={4}",
            (
                self.plugin_id, self.af, reply is not None,
                role_label, self.renego_count,
            ),
        ))

        # Merge any peer-supplied tried_servers into our local set so
        # neither side reattempts a server the other has already failed
        # on. Both rejection messages and normal TURNMsgs may carry
        # tried_servers; absorb either.
        if reply is not None:
            for s in (getattr(reply.payload, "tried_servers", None) or []):
                try:
                    self.tried_servers.add((s[0], int(s[1])))
                except (IndexError, TypeError, ValueError):
                    continue

        # --- Renegotiation initiator path ----------------------------------
        # The peer rejected our last server choice. Drop our cached client
        # (it was good for us but useless for them) and reallocate on a
        # different server. After MAX_RENEGOTIATIONS we give up.
        if is_renegotiating_initiator:
            self.renego_count += 1
            if self.renego_count > self.MAX_RENEGOTIATIONS:
                log(fstr(
                    "turn[{0}]: exceeded MAX_RENEGOTIATIONS ({1}); aborting",
                    (self.plugin_id, self.MAX_RENEGOTIATIONS),
                ))
                if not self.result.done():
                    self.result.set_result(None)
                return
            log(fstr(
                "turn[{0}]: peer rejected our server with reason={1}; "
                "renegotiating (round {2}/{3}, tried_servers={4})",
                (
                    self.plugin_id,
                    repr(getattr(reply.payload, "reject_reason", None)),
                    self.renego_count, self.MAX_RENEGOTIATIONS,
                    sorted(self.tried_servers),
                ),
            ))
            # The previous pick is now known-bad (peer couldn't reach it),
            # so add it to the failed set BEFORE re-picking. This is the
            # only place a successful-allocation server gets marked tried,
            # so the on-wire tried_servers list always means "rejected by
            # at least one peer", not "currently in use".
            existing = self.turn_clients.get(self.plugin_id)
            if existing is not None:
                try:
                    self.tried_servers.add((existing.dest[0], int(existing.dest[1])))
                except (IndexError, TypeError, ValueError):
                    pass
                try:
                    existing.close()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log_p2p("turn[{0}]: error closing rejected client".format(self.plugin_id),
                            self.node_id[:8])
                del self.turn_clients[self.plugin_id]
            # From here on this branch behaves as a fresh initiator.
            reply = None

        # --- Allocate a TURN relay for this session ---
        client = self.turn_clients.get(self.plugin_id)
        if client is None:
            groups = get_infra(self.af, UDP, "TURN", no=100)
            all_servers = [g[0] for g in groups]
            # Filter out any server already in the joint tried set.
            all_servers = [
                s for s in all_servers
                if (s.get("ip"), int(s.get("port", 0))) not in self.tried_servers
            ]

            # Responder path: if the incoming TURNMsg specified a server
            # the initiator already allocated on, use it directly so we
            # land on the SAME server. If we cannot reach it, send a
            # rejection back instead of silently failing.
            chosen_servers = None
            initiator_choice = None
            if reply is not None and getattr(reply.payload, "server_host", None):
                target_host = reply.payload.server_host
                target_port = int(reply.payload.server_port or 0)
                initiator_choice = (target_host, target_port)
                for s in all_servers:
                    if s.get("ip") == target_host and int(s.get("port", 0)) == target_port:
                        chosen_servers = [s]
                        break
                # If we don't have it in INFRA, treat as unreachable too --
                # send rejection so the initiator picks something we share.
                if chosen_servers is None:
                    log(fstr(
                        "turn[{0}]: initiator chose {1}:{2} but it's not in our "
                        "INFRA / already-tried; rejecting",
                        (self.plugin_id, target_host, target_port),
                    ))
                    self.tried_servers.add(initiator_choice)
                    self.send_rejection("not_in_infra")
                    if not self.result.done():
                        self.result.set_result(None)
                    return

            if chosen_servers is None:
                chosen_servers = rendezvous_rank(self.plugin_id, all_servers)

            log(fstr(
                "turn[{0}]: trying {1} candidate server(s)",
                (self.plugin_id, len(chosen_servers)),
            ))
            client = get_first_working_turn_client(
                self.af,
                chosen_servers,
                self.nic,
                self.msg_cb,
            )

            if client is None:
                # If we are the responder and the initiator picked a
                # specific server, send a rejection so they retry. If
                # we're the initiator (or renego-initiator) and have no
                # working server left, abort.
                if initiator_choice is not None:
                    log(fstr(
                        "turn[{0}]: failed to allocate on initiator's server "
                        "{1}:{2}; sending rejection",
                        (self.plugin_id, initiator_choice[0], initiator_choice[1]),
                    ))
                    self.tried_servers.add(initiator_choice)
                    self.send_rejection("unreachable")
                    if not self.result.done():
                        self.result.set_result(None)
                    return
                log(fstr(
                    "turn[{0}]: no working TURN server -- aborting",
                    (self.plugin_id,),
                ))
                if not self.result.done():
                    self.result.set_result(None)
                return
            log(fstr(
                "turn[{0}]: allocated relay on {1}",
                (self.plugin_id, getattr(client, "dest", "?")),
            ))
            # NB: do NOT add the freshly-allocated server to self.tried_servers.
            # tried_servers means "rejected by at least one peer" -- it is shipped
            # to the peer so the peer's candidate filter excludes those entries.
            # Adding our successful pick here would cause the responder to
            # filter it out and reply "not_in_infra", looping until both
            # sides exhaust the list. The renego-initiator branch above is
            # the only place a successful pick gets marked tried, and only
            # AFTER we know the peer actually rejected it.

            # A concurrent run() may have raced through the await above and
            # already stored a client — reuse it and discard ours.
            existing = self.turn_clients.get(self.plugin_id)
            if existing is not None:
                client.close()
                client = existing
            else:
                self.turn_clients[self.plugin_id] = client

        if client is None:
            if not self.result.done():
                self.result.set_result(None)
            return

        # --- Accept the peer's relay (reply path only) ---
        # When the peer's TURNMsg arrives, whitelist their relay address so
        # the TURN server will forward their traffic to us.
        if reply is not None:
            dest_peer = reply.payload.peer_tup
            dest_relay = reply.payload.relay_tup
            try:
                already_accepted = asyncio.wait_for(
                    client.accept_peer(dest_peer, dest_relay), 4,
                )
            except asyncio.TimeoutError:
                self.send_rejection("accept_peer_timeout")
                self.close()
                if not self.result.done():
                    self.result.set_result(None)
                return

            # Unblock any initiating run() that is waiting for the peer's info.
            if not self.ready.done():
                self.ready.set_result(client)

            # If both sides have already whitelisted each other we still
            # need to send the follow-up TURNMsg so the other side's
            # run() gets triggered and can resolve its self.ready Future.
            # (Without the message the initiator times out after 40s.)
            if already_accepted:
                if not self.result.done():
                    self.result.set_result(client)

            our_relay = client.relay_tup_future
            log_p2p(
                fstr(
                    "Whitelist {0} -> {1} to '{2}'",
                    (dest_peer, our_relay, self.nic.name),
                ),
                self.node_id[:8],
            )

        # --- Advertise our relay address (and server choice) to the peer ---
        # Embed the chosen server's host/port so the peer allocates on the
        # SAME server. tried_servers carries our local exclusion set so
        # the peer (whether responder, or initiator receiving our own
        # rejection-driven rechoice) never picks something we've already
        # ruled out. On the responder path (reply is not None) we pass
        # the same server back through, which is harmless -- the initiator
        # already used it. On the initiator path (reply is None) this is
        # how the responder learns which server to use.
        server_host, server_port = client.dest
        msg = TURNMsg(
            {
                "payload": {
                    "peer_tup": client.client_tup_future,
                    "relay_tup": client.relay_tup_future,
                    "server_host": server_host,
                    "server_port": server_port,
                    "tried_servers": [list(t) for t in sorted(self.tried_servers)],
                },
            }
        )
        msg.meta.plugin_name = "turn"
        self.send_signal(msg)

        # --- Wait for the peer to whitelist our relay ---
        # self.ready is resolved by a second run() call when the peer's
        # reply arrives. Cap at 8s: it covers the peer's full round-trip
        # -- responder alloc (<=4s) + accept_peer (<=4s) + two signaling
        # hops -- and sits inside the 10s plugin conf timeout with room
        # for the initiator's own pre-work (its alloc + outgoing signal).
        # Without this cap a non-responding peer would burn the whole
        # plugin timeout at the initiator side.
        try:
            pipe = asyncio.wait_for(self.ready, 8)
        except asyncio.TimeoutError:
            if not self.result.done():
                self.result.set_result(None)
            return
        if not self.result.done():
            self.result.set_result(pipe)

    def send_rejection(self, reason):
        """Tell the peer we cannot allocate on the server they just asked us
        to use. Carries our full tried_servers set so the peer's next pick
        excludes everything we've ruled out, not just the one server we
        rejected this round. relay_tup / peer_tup are filled with sentinel
        empty tuples because the on-wire schema requires them but the
        receiver ignores them when reject_reason is set."""
        msg = TURNMsg(
            {
                "payload": {
                    "peer_tup": ("", 0),
                    "relay_tup": ("", 0),
                    "tried_servers": [list(t) for t in sorted(self.tried_servers)],
                    "reject_reason": reason,
                },
            }
        )
        msg.meta.plugin_name = "turn"
        log(fstr(
            "turn[{0}]: sending rejection reason={1} tried={2}",
            (self.plugin_id, reason, sorted(self.tried_servers)),
        ))
        self.send_signal(msg)

    def close(self):
        """Clean up after a TURN connection attempt.

        On failure (timeout, cancellation, error) the TURNClient is closed
        immediately to free the UDP socket, the relay allocation, and all
        background tasks.  On success the TURNClient *is* the pipe returned
        to the caller — the caller owns it and will close it — so we leave
        it open and let TURNPluginFactory.close() handle final shutdown.

        Safe to call multiple times: the dict pop is a no-op on a missing key
        and all futures are checked with .done() before acting.
        """
        connection_succeeded = False
        try:
            # raises if pending, cancelled, or exception
            self.result.result()
            connection_succeeded = True
        except BaseException:
            pass

        if not connection_succeeded:
            # Per-run cleanup intentionally does NOT pop turn_clients
            # here. Cleanup semantics across plugins will be revisited
            # in a dedicated session; for now leave the entry so a
            # peer's follow-up signal doesn't trigger a duplicate
            # allocation while the original is still tearing down.
            turn_client = self.turn_clients.get(self.plugin_id)
            if turn_client is not None:
                turn_client.close()

        if not self.ready.done():
            self.ready.cancel()


class TURNPluginFactory:
    """Creates and configures TURNPlugin instances sharing TURN client sessions."""

    def __init__(self, msg_cb=None, node_id=""):
        self.turn_clients = {}
        self.msg_cb = msg_cb
        self.node_id = node_id

    def build_plugin(self):
        """Create a new TURNPlugin instance wired to this factory's shared client pool."""
        plugin = TURNPlugin()
        plugin.turn_clients = self.turn_clients
        plugin.msg_cb = self.msg_cb
        plugin.node_id = self.node_id
        return plugin

    def close(self):
        """Close all shared TURN clients and clear the pool."""
        for client in list(self.turn_clients.values()):
            try:
                client.close()
            except (OSError, asyncio.TimeoutError):
                pass

        self.turn_clients.clear()


