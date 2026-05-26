"""Admin socket tests: TCP client → admin handlers → JSON response."""
import asyncio
import json
import os
import unittest

from aionetiface import IP4, TCP, Interface, Pipe, SUB_ALL
from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.admin import AdminError, AdminSocket
from warpgate.overlay.yggdrasil.node_core import NodeCore


async def send_admin_request(host, port, request):
    """Open a TCP connection, send one JSON request + newline, read one response."""
    iface = Interface("default")
    route = await iface.route(IP4).bind(ips="0.0.0.0", port=0)
    pipe = Pipe(TCP, dest=(host, port), route=route)
    await pipe.connect()
    pipe.subscribe(SUB_ALL)
    line = (json.dumps(request) + "\n").encode("utf-8")
    await pipe.send(line)
    buf = bytearray()
    for _ in range(20):
        chunk = await pipe.recv(SUB_ALL, timeout=2)
        if chunk is None:
            break
        buf.extend(chunk)
        if b"\n" in buf:
            break
    await pipe.close()
    line, _, _ = bytes(buf).partition(b"\n")
    return json.loads(line.decode("utf-8")) if line else None


class TestAdminListCommand(AsyncTestCase):

    async def asyncSetUp(self):
        from aionetiface import IP6
        self.node = NodeCore(seed=os.urandom(32))
        await self.node.start_listener(bind_addr="::1", port=0, af=IP6)
        self.admin = AdminSocket(self.node)
        host, port = await self.admin.start(bind_host="127.0.0.1", bind_port=0, af=IP4)
        self.admin_host = host
        self.admin_port = port

    async def asyncTearDown(self):
        await self.admin.stop()
        await self.node.close()

    async def test_list_command_returns_known_handlers(self):
        resp = await send_admin_request(
            self.admin_host, self.admin_port, {"request": "list"},
        )
        self.assertEqual(resp["status"], "success")
        commands = [item["command"] for item in resp["response"]["list"]]
        for required in ("list", "getself", "getpeers"):
            self.assertIn(required, commands)

    async def test_getself_returns_pubkey_and_address(self):
        resp = await send_admin_request(
            self.admin_host, self.admin_port, {"request": "getself"},
        )
        self.assertEqual(resp["status"], "success")
        body = resp["response"]
        self.assertEqual(body["key"], self.node.public_key.hex())
        # Address starts with "2" -- 200::/7 derived.
        self.assertTrue(body["address"].startswith("2"))
        self.assertGreater(body["uptime"], 0)

    async def test_getpeers_returns_empty_list_when_no_peers(self):
        resp = await send_admin_request(
            self.admin_host, self.admin_port, {"request": "getpeers"},
        )
        self.assertEqual(resp["status"], "success")
        self.assertEqual(resp["response"]["peers"], [])

    async def test_unknown_command_returns_error(self):
        resp = await send_admin_request(
            self.admin_host, self.admin_port, {"request": "no_such_command"},
        )
        self.assertEqual(resp["status"], "error")
        self.assertIn("unknown", resp["error"].lower())

    async def test_handler_admin_error_returns_clean_response(self):
        def raises(args):
            raise AdminError("custom error message")
        self.admin.add_handler("brokenhandler", "raises", [], raises)
        resp = await send_admin_request(
            self.admin_host, self.admin_port, {"request": "brokenhandler"},
        )
        self.assertEqual(resp["status"], "error")
        self.assertEqual(resp["error"], "custom error message")

    async def test_empty_request_name_returns_specific_error(self):
        """Upstream admin.go:330-332 returns 'no request specified' when
        the request field is empty -- distinct from 'unknown action'.
        Verify we propagate that distinction so tooling that branches
        on the error string gets the same answer.
        """
        resp = await send_admin_request(
            self.admin_host, self.admin_port, {"request": ""},
        )
        self.assertEqual(resp["status"], "error")
        self.assertIn("no request", resp["error"].lower())

    async def test_standard_upstream_handlers_registered(self):
        """All ~8 standard yggctl commands upstream registers in
        admin.go:SetupAdminHandlers() must be present.  Earlier
        revisions only had 3 (list/getself/getpeers); the missing
        5 (getNodeInfo / getPaths / getSessions / getTree / addPeer
        / removePeer) made ``yggctl`` against this socket error
        out on common commands.
        """
        resp = await send_admin_request(
            self.admin_host, self.admin_port, {"request": "list"},
        )
        self.assertEqual(resp["status"], "success")
        commands = set(item["command"] for item in resp["response"]["list"])
        for cmd in (
            "list", "getself", "getpeers",
            "getnodeinfo", "getpaths", "getsessions", "gettree",
            "addpeer", "removepeer",
        ):
            self.assertIn(cmd, commands,
                          "missing standard handler: " + cmd)

    async def test_getnodeinfo_returns_dict(self):
        resp = await send_admin_request(
            self.admin_host, self.admin_port, {"request": "getnodeinfo"},
        )
        self.assertEqual(resp["status"], "success")
        self.assertIn("nodeinfo", resp["response"])

    async def test_getpaths_returns_paths_list(self):
        resp = await send_admin_request(
            self.admin_host, self.admin_port, {"request": "getpaths"},
        )
        self.assertEqual(resp["status"], "success")
        self.assertIn("paths", resp["response"])
        self.assertIsInstance(resp["response"]["paths"], list)

    async def test_getsessions_returns_sessions_list(self):
        resp = await send_admin_request(
            self.admin_host, self.admin_port, {"request": "getsessions"},
        )
        self.assertEqual(resp["status"], "success")
        self.assertIn("sessions", resp["response"])
        self.assertIsInstance(resp["response"]["sessions"], list)

    async def test_gettree_returns_tree_list(self):
        resp = await send_admin_request(
            self.admin_host, self.admin_port, {"request": "gettree"},
        )
        self.assertEqual(resp["status"], "success")
        self.assertIn("tree", resp["response"])
        self.assertIsInstance(resp["response"]["tree"], list)

    async def test_addpeer_without_uri_returns_clean_error(self):
        resp = await send_admin_request(
            self.admin_host, self.admin_port,
            {"request": "addpeer", "arguments": {}},
        )
        self.assertEqual(resp["status"], "error")
        self.assertIn("uri", resp["error"].lower())

    async def test_removepeer_without_uri_returns_clean_error(self):
        resp = await send_admin_request(
            self.admin_host, self.admin_port,
            {"request": "removepeer", "arguments": {}},
        )
        self.assertEqual(resp["status"], "error")
        self.assertIn("uri", resp["error"].lower())

    async def test_keepalive_allows_multiple_requests_on_single_conn(self):
        """Upstream admin.go:354-358: ``if !req.KeepAlive break else continue``
        keeps the connection open for repeated requests when the client
        sets ``keepalive: true``.  Validate that two consecutive list
        requests on the same TCP socket both succeed.
        """
        iface = Interface("default")
        route = await iface.route(IP4).bind(ips="0.0.0.0", port=0)
        pipe = Pipe(TCP, dest=(self.admin_host, self.admin_port), route=route)
        await pipe.connect()
        try:
            pipe.subscribe(SUB_ALL)
            buf = bytearray()
            # Send TWO requests over the same connection.  Both must
            # respond with a success line.
            for i in range(2):
                req = {"request": "list", "keepalive": True}
                line = (json.dumps(req) + "\n").encode("utf-8")
                await pipe.send(line)
                while b"\n" not in buf:
                    chunk = await pipe.recv(SUB_ALL, timeout=5)
                    if chunk is None:
                        self.fail(
                            "keepalive: connection closed before request "
                            + str(i),
                        )
                    buf.extend(chunk)
                line_bytes, _, rest = bytes(buf).partition(b"\n")
                buf = bytearray(rest)
                resp = json.loads(line_bytes.decode("utf-8"))
                self.assertEqual(
                    resp["status"], "success",
                    "keepalive: request " + str(i) + " failed",
                )
        finally:
            await pipe.close()


if __name__ == "__main__":
    unittest.main()
