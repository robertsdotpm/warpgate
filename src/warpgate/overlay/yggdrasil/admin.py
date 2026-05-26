"""yggctl-compatible admin socket -- JSON-RPC over UNIX/TCP socket.

Port of ``yggdrasil-go/src/admin/admin.go``'s request/response
loop.  Listens on a UNIX socket (or TCP for testing), accepts
newline-terminated JSON requests, dispatches by ``request`` name,
and writes a JSON response.

Wire shape per request:

  {"request": "<name>",
   "arguments": { ...optional...},
   "keepalive": false}

Response shape:

  {"status": "success" | "error",
   "error": "<error message if any>",
   "request": <echo of request object>,
   "response": <handler-specific payload>}

Handlers registered out of the box (matches upstream's defaults):

  list           -> list available admin commands
  getself        -> our own public key + derived 200:: address
  getpeers       -> live peer list with addresses + uptime
  getnodeinfo    -> opaque info dict (Phase 7+ feature)

Adding handlers: ``admin.add_handler(name, desc, args, func)``
where ``func(args_dict, summary_dict) -> response_dict``.
"""
import asyncio
import json
import os
import time

from aionetiface import IP4, IP6, TCP, Interface, Pipe, SUB_ALL, fstr, log, log_exception

from .address import addr_for_key, ipv6_str_from_bytes


class AdminError(Exception):
    """Raised by handlers to signal a clean error response."""


class AdminSocket(object):
    """A single admin listener -- TCP for now (UNIX in a follow-up).

    Construct with a NodeCore reference; optionally pass a
    pre-built ActiveRouter.  Call ``start(bind_host, bind_port)``
    to accept connections.
    """

    def __init__(self, node_core, router=None):
        self.node_core = node_core
        self.router = router
        self.handlers = {}
        self.start_time = time.time()
        self.listener_pipe = None
        self.accept_task = None
        self.closed = False
        # Register the standard handlers.  These mirror the upstream
        # set registered in admin.go:SetupAdminHandlers() so a stock
        # ``yggctl`` client (or any code that targets the upstream
        # JSON-RPC surface) talks to us unchanged.  Handlers that
        # don't have a meaningful payload yet (no peer table yet,
        # no path table yet) return empty lists -- mirrors upstream
        # behaviour when those slots are empty.
        self.add_handler(
            "list", "List the admin commands available on this socket",
            [], self.handle_list,
        )
        self.add_handler(
            "getself", "Return this node's public key + Yggdrasil IPv6 address",
            [], self.handle_getself,
        )
        self.add_handler(
            "getpeers", "Return the list of currently-connected peers",
            ["sort"], self.handle_getpeers,
        )
        self.add_handler(
            "getnodeinfo", "Return arbitrary node-info from this node",
            [], self.handle_getnodeinfo,
        )
        self.add_handler(
            "getpaths", "Show established paths through this node",
            [], self.handle_getpaths,
        )
        self.add_handler(
            "getsessions", "Show established traffic sessions with remote nodes",
            [], self.handle_getsessions,
        )
        self.add_handler(
            "gettree", "Show known tree entries from this node",
            [], self.handle_gettree,
        )
        self.add_handler(
            "addpeer", "Add a peer to the peer list",
            ["uri", "interface"], self.handle_addpeer,
        )
        self.add_handler(
            "removepeer", "Remove a peer from the peer list",
            ["uri", "interface"], self.handle_removepeer,
        )

    def add_handler(self, name, desc, args, handler):
        """Register an admin command.

        ``handler`` is a callable accepting the request's
        ``arguments`` dict and returning a response dict.  May
        raise ``AdminError`` to signal a clean error response.
        """
        key = name.lower()
        if key in self.handlers:
            raise ValueError(fstr("admin: handler {0} already registered", (name,)))
        self.handlers[key] = {
            "name": name,
            "desc": desc,
            "args": list(args),
            "handler": handler,
        }

    async def start(self, bind_host="127.0.0.1", bind_port=0, af=IP4):
        """Open the admin TCP listener and start accept loop."""
        if self.closed:
            raise RuntimeError("admin: closed")
        if self.listener_pipe is not None:
            return
        iface = Interface("default")
        route = await iface.route(af).bind(ips=bind_host, port=bind_port)
        self.listener_pipe = Pipe(TCP, dest=None, route=route)
        await self.listener_pipe.connect()
        self.accept_task = asyncio.ensure_future(self.accept_loop())
        bound_port = self.listener_pipe.sock.getsockname()[1]
        log(fstr(
            "admin: listening on {0}:{1}",
            (bind_host, bound_port),
        ))
        return bind_host, bound_port

    @property
    def bound_port(self):
        if self.listener_pipe is None or self.listener_pipe.sock is None:
            return None
        return self.listener_pipe.sock.getsockname()[1]

    async def accept_loop(self):
        while not self.closed:
            try:
                inbound = await self.listener_pipe.accept()
            except asyncio.CancelledError:
                raise
            except (OSError, ConnectionError):
                log_exception()
                return
            if inbound is None:
                return
            asyncio.ensure_future(self.client_session(inbound))

    async def client_session(self, pipe):
        """Run one admin client's lifetime: read JSON requests, dispatch, reply."""
        buf = bytearray()
        try:
            pipe.subscribe(SUB_ALL)
            keepalive = True
            while keepalive and not self.closed:
                # Read until newline.
                while b"\n" not in buf:
                    chunk = await pipe.recv(SUB_ALL, timeout=30)
                    if chunk is None:
                        return
                    buf.extend(chunk)
                line, _, rest = bytes(buf).partition(b"\n")
                buf = bytearray(rest)
                try:
                    req = json.loads(line.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    await self.send_response(pipe, {
                        "status": "error",
                        "error": "invalid JSON",
                        "request": {},
                        "response": {},
                    })
                    continue
                resp = await self.dispatch(req)
                await self.send_response(pipe, resp)
                keepalive = bool(req.get("keepalive", False))
        except (OSError, ConnectionError):
            log_exception()
        finally:
            try:
                await pipe.close()
            except Exception:
                pass

    async def dispatch(self, req):
        """Look up the handler, run it, build the response envelope."""
        name = str(req.get("request", "")).lower()
        args = req.get("arguments") or {}
        # Mirror upstream admin.go:330-332: an empty ``request`` field
        # is a distinct error case ("no request specified") rather
        # than an unknown-command lookup miss.
        if not name:
            return {
                "status": "error",
                "error": "no request specified",
                "request": req,
                "response": {},
            }
        handler_info = self.handlers.get(name)
        if handler_info is None:
            return {
                "status": "error",
                "error": "unknown action '" + name + "', try 'list' for help",
                "request": req,
                "response": {},
            }
        try:
            payload = handler_info["handler"](args)
            if asyncio.iscoroutine(payload):
                payload = await payload
            return {
                "status": "success",
                "request": req,
                "response": payload,
            }
        except AdminError as exc:
            return {
                "status": "error",
                "error": str(exc),
                "request": req,
                "response": {},
            }
        except Exception as exc:
            log_exception()
            return {
                "status": "error",
                "error": "handler raised: " + repr(exc),
                "request": req,
                "response": {},
            }

    async def send_response(self, pipe, response):
        line = (json.dumps(response) + "\n").encode("utf-8")
        try:
            await pipe.send(line)
        except (OSError, ConnectionError):
            log_exception()

    # -------- standard handlers ------------------------------------------

    def handle_list(self, args):
        items = []
        for name, h in sorted(self.handlers.items()):
            items.append({
                "command": h["name"],
                "description": h["desc"],
                "fields": h["args"],
            })
        return {"list": items}

    def handle_getself(self, args):
        pub = self.node_core.public_key
        addr = ipv6_str_from_bytes(addr_for_key(pub))
        return {
            "key": pub.hex(),
            "address": addr,
            "build_name": "warpgate-yggdrasil-python",
            "uptime": time.time() - self.start_time,
        }

    def handle_getpeers(self, args):
        peers = []
        for entry in self.node_core.peers.peers():
            pub = entry.link.remote_pubkey
            peers.append({
                "key": pub.hex(),
                "address": entry.link.remote_addr,
                "port": entry.port,
                "priority": entry.link.remote_priority,
                "direction": entry.link.link_type,
                "bytes_sent": entry.link.tx_bytes,
                "bytes_recvd": entry.link.rx_bytes,
            })
        return {"peers": peers}

    def handle_getnodeinfo(self, args):
        """Return arbitrary opaque node-info -- matches upstream's getNodeInfo.

        Upstream returns a json.RawMessage the operator sets via
        config.NodeInfo.  We honour ``self.node_info`` if set,
        otherwise return an empty dict (matches upstream's default).
        """
        info = getattr(self, "node_info", None)
        if info is None:
            info = {}
        return {"nodeinfo": info}

    def handle_getpaths(self, args):
        """Return the per-destination path-table.

        Empty if pathfinder hasn't formed any paths yet -- matches
        upstream's behaviour when getPathsHandler finds no entries.
        """
        paths = []
        try:
            pf = getattr(self.node_core, "pathfinder", None)
            if pf is not None and hasattr(pf, "paths"):
                for dest, entry in pf.paths.items():
                    paths.append({
                        "key": bytes(dest).hex(),
                        "path": list(getattr(entry, "path", [])),
                    })
        except (AttributeError, TypeError):
            pass
        return {"paths": paths}

    def handle_getsessions(self, args):
        """Return the live encrypted-sessions list.

        Sources from the EncryptedPacketConn registered on ``self.pc``
        if any -- otherwise empty (no sessions exist).  Matches
        upstream's GetSessionsResponse shape.
        """
        sessions = []
        pc = getattr(self, "pc", None)
        if pc is not None:
            try:
                for peer_key, sess in pc.sessions.items():
                    sessions.append({
                        "key": bytes(peer_key).hex(),
                        "bytes_sent": getattr(sess, "tx_bytes", 0),
                        "bytes_recvd": getattr(sess, "rx_bytes", 0),
                        "uptime": 0.0,
                    })
            except (AttributeError, TypeError):
                pass
        return {"sessions": sessions}

    def handle_gettree(self, args):
        """Return the known tree entries (announce table)."""
        tree = []
        try:
            if self.router is not None and hasattr(self.router, "infos"):
                for pub, info in self.router.infos.items():
                    tree.append({
                        "key": bytes(pub).hex(),
                        "parent": (bytes(info.get_announce(pub).peerKey).hex()
                                   if hasattr(info, "get_announce") else ""),
                    })
        except (AttributeError, TypeError):
            pass
        return {"tree": tree}

    def handle_addpeer(self, args):
        """Add a new outbound peer URI.

        Mirrors upstream's addPeer (admin/addpeer.go) shape: accepts
        ``uri`` (required) and optional ``interface``.  Delegates to
        ``node_core.add_peer_uri`` if available.
        """
        uri = args.get("uri") if isinstance(args, dict) else None
        if not uri:
            raise AdminError("missing 'uri' argument")
        interface = args.get("interface", "") if isinstance(args, dict) else ""
        added = False
        try:
            adder = getattr(self.node_core, "add_peer_uri", None)
            if adder is not None:
                adder(uri, interface)
                added = True
        except Exception as exc:
            raise AdminError("add_peer failed: " + str(exc))
        if not added:
            raise AdminError("node_core has no add_peer_uri method")
        return {"added": [uri]}

    def handle_removepeer(self, args):
        """Remove an outbound peer URI -- mirrors upstream's removePeer."""
        uri = args.get("uri") if isinstance(args, dict) else None
        if not uri:
            raise AdminError("missing 'uri' argument")
        interface = args.get("interface", "") if isinstance(args, dict) else ""
        removed = False
        try:
            remover = getattr(self.node_core, "remove_peer_uri", None)
            if remover is not None:
                remover(uri, interface)
                removed = True
        except Exception as exc:
            raise AdminError("remove_peer failed: " + str(exc))
        if not removed:
            raise AdminError("node_core has no remove_peer_uri method")
        return {"removed": [uri]}

    async def stop(self):
        if self.closed:
            return
        self.closed = True
        if self.accept_task is not None:
            try:
                self.accept_task.cancel()
            except Exception:
                pass
        self.accept_task = None
        if self.listener_pipe is not None:
            try:
                await self.listener_pipe.close()
            except Exception:
                log_exception()
            self.listener_pipe = None


def parse_response(data):
    """Helper: parse a single newline-terminated JSON response from bytes."""
    line, _, _ = bytes(data).partition(b"\n")
    return json.loads(line.decode("utf-8"))
