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


if __name__ == "__main__":
    unittest.main()
