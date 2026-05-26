"""Edge-case tests for the v2 Transport family.

Covers:
  - ``Transport`` ABC contract (NotImplementedError on stubs)
  - cb dispatch invariants (set semantics, exception isolation,
    empty-data short-circuit, rx_bytes accounting)
  - ``LoopbackTransport``: cross-wired send/recv, close
    propagation, TransportClosed on every invalid post-close
    operation, peer=None safety
  - ``ReplayTransport``: preloaded inbound, stage_inbound +
    stage_eof, sent_chunks capture, push_on_stage semantics
  - ``loopback_pair()`` returns two distinct instances with peer
    pointers wired both ways
"""
import asyncio
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.transport import (
    LoopbackTransport, ReplayTransport, Transport, TransportClosed,
    loopback_pair,
)


# ---------------------------------------------------------------------------
# Transport ABC -- the bare class must raise NotImplementedError so
# subclassers can't accidentally inherit a working stub that swallows
# bytes.
# ---------------------------------------------------------------------------
class TestTransportABCContract(AsyncTestCase):

    async def test_send_on_bare_transport_raises(self):
        t = Transport()
        with self.assertRaises(NotImplementedError):
            await t.send(b"x")

    async def test_recv_on_bare_transport_raises(self):
        t = Transport()
        with self.assertRaises(NotImplementedError):
            await t.recv()

    async def test_close_on_bare_transport_raises(self):
        t = Transport()
        with self.assertRaises(NotImplementedError):
            await t.close()

    async def test_is_closed_initially_false(self):
        t = Transport()
        self.assertEqual(t.is_closed(), False)
        self.assertFalse(t.closed_event.is_set())

    async def test_counters_start_at_zero(self):
        t = Transport()
        self.assertEqual(t.tx_bytes, 0)
        self.assertEqual(t.rx_bytes, 0)


class TestTransportCallbackPlumbing(AsyncTestCase):
    """deliver() / add_msg_cb / del_msg_cb / fire_close behaviour
    -- shared across every concrete transport, tested via Transport
    directly + a no-op subclass."""

    async def test_add_then_del_msg_cb(self):
        t = Transport()
        captured = []
        def cb(data, transport):
            captured.append(data)
        t.add_msg_cb(cb)
        self.assertIn(cb, t.msg_cbs)
        t.del_msg_cb(cb)
        self.assertNotIn(cb, t.msg_cbs)

    async def test_del_msg_cb_unknown_is_noop(self):
        t = Transport()
        def cb(data, transport): pass
        # discard semantics -- no KeyError.
        t.del_msg_cb(cb)
        self.assertEqual(len(t.msg_cbs), 0)

    async def test_add_msg_cb_set_semantics_no_duplicates(self):
        t = Transport()
        def cb(data, transport): pass
        t.add_msg_cb(cb)
        t.add_msg_cb(cb)
        t.add_msg_cb(cb)
        self.assertEqual(len(t.msg_cbs), 1)

    async def test_deliver_empty_data_is_noop(self):
        t = Transport()
        captured = []
        t.add_msg_cb(lambda d, tr: captured.append(d))
        t.deliver(b"")
        self.assertEqual(captured, [])
        # rx_bytes must NOT advance on empty deliver.
        self.assertEqual(t.rx_bytes, 0)

    async def test_deliver_increments_rx_bytes(self):
        t = Transport()
        t.deliver(b"hello")
        self.assertEqual(t.rx_bytes, 5)
        t.deliver(b"world!")
        self.assertEqual(t.rx_bytes, 11)

    async def test_deliver_fans_out_to_every_cb(self):
        t = Transport()
        seen_a = []
        seen_b = []
        t.add_msg_cb(lambda d, tr: seen_a.append(d))
        t.add_msg_cb(lambda d, tr: seen_b.append(d))
        t.deliver(b"data")
        self.assertEqual(seen_a, [b"data"])
        self.assertEqual(seen_b, [b"data"])

    async def test_deliver_passes_self_as_transport_arg(self):
        t = Transport()
        received = []
        def cb(data, transport):
            received.append(transport)
        t.add_msg_cb(cb)
        t.deliver(b"x")
        self.assertIs(received[0], t)

    async def test_cb_exception_does_not_poison_others(self):
        t = Transport()
        survived = []
        def bad_cb(data, transport):
            raise RuntimeError("simulated bad cb")
        def good_cb(data, transport):
            survived.append(data)
        t.add_msg_cb(bad_cb)
        t.add_msg_cb(good_cb)
        # Must not raise -- the bad cb's exception is logged + swallowed.
        t.deliver(b"x")
        self.assertEqual(survived, [b"x"])

    async def test_fire_close_sets_event_and_calls_close_cbs(self):
        t = Transport()
        close_seen = []
        t.add_close_cb(lambda tr: close_seen.append(tr))
        t.fire_close()
        self.assertTrue(t.is_closed())
        self.assertEqual(close_seen, [t])

    async def test_fire_close_close_cb_exception_does_not_poison(self):
        t = Transport()
        seen = []
        def bad(tr): raise RuntimeError("bad close cb")
        def good(tr): seen.append(tr)
        t.add_close_cb(bad)
        t.add_close_cb(good)
        t.fire_close()
        self.assertEqual(seen, [t])


class TestLoopbackTransport(AsyncTestCase):

    async def test_loopback_pair_returns_two_cross_wired_instances(self):
        a, b = loopback_pair()
        self.assertIsNot(a, b)
        self.assertIs(a.peer, b)
        self.assertIs(b.peer, a)

    async def test_send_arrives_on_peer_recv(self):
        a, b = loopback_pair()
        n = await a.send(b"ping")
        self.assertEqual(n, 4)
        received = await b.recv(timeout=1.0)
        self.assertEqual(received, b"ping")
        self.assertIsInstance(received, bytes)

    async def test_send_fires_peer_msg_cbs(self):
        a, b = loopback_pair()
        captured = []
        b.add_msg_cb(lambda d, tr: captured.append(d))
        await a.send(b"pong")
        # cb is sync; the deliver happens inside send() so no yield needed.
        self.assertEqual(captured, [b"pong"])

    async def test_recv_returns_bytes_not_bytearray(self):
        a, b = loopback_pair()
        await a.send(bytearray(b"raw"))
        chunk = await b.recv(timeout=1.0)
        # Even when input was bytearray, the API promises bytes.
        self.assertEqual(type(chunk), bytes)
        self.assertEqual(chunk, b"raw")

    async def test_tx_rx_byte_counters(self):
        a, b = loopback_pair()
        await a.send(b"hello")
        await a.send(b"!!")
        self.assertEqual(a.tx_bytes, 7)
        # b.rx_bytes is incremented via deliver(), which fires inside send().
        self.assertEqual(b.rx_bytes, 7)

    async def test_send_after_self_close_raises(self):
        a, b = loopback_pair()
        await a.close()
        with self.assertRaises(TransportClosed) as ctx:
            await a.send(b"x")
        self.assertIn("closed", str(ctx.exception))

    async def test_send_after_peer_close_raises(self):
        a, b = loopback_pair()
        await b.close()
        # b closing also closes a (propagation); both branches raise.
        with self.assertRaises(TransportClosed):
            await a.send(b"x")

    async def test_send_with_no_peer_raises(self):
        # Construct a bare LoopbackTransport with no peer wired.
        t = LoopbackTransport()
        with self.assertRaises(TransportClosed) as ctx:
            await t.send(b"x")
        self.assertIn("no peer", str(ctx.exception))

    async def test_recv_returns_none_on_close(self):
        a, b = loopback_pair()
        await a.close()
        result = await a.recv(timeout=0.5)
        self.assertIsNone(result)

    async def test_recv_timeout_returns_none(self):
        a, b = loopback_pair()
        # Nothing sent -- recv must time out cleanly + return None.
        result = await a.recv(timeout=0.05)
        self.assertIsNone(result)

    async def test_close_is_idempotent(self):
        a, b = loopback_pair()
        await a.close()
        await a.close()
        await a.close()
        self.assertTrue(a.is_closed())

    async def test_close_propagates_to_peer(self):
        a, b = loopback_pair()
        self.assertFalse(b.is_closed())
        await a.close()
        self.assertTrue(b.is_closed())

    async def test_send_empty_bytes_succeeds_and_returns_zero(self):
        a, b = loopback_pair()
        n = await a.send(b"")
        self.assertEqual(n, 0)
        # b.deliver(b"") is a no-op -- no msg_cb fires.
        captured = []
        b.add_msg_cb(lambda d, tr: captured.append(d))
        await a.send(b"")
        self.assertEqual(captured, [])


class TestReplayTransport(AsyncTestCase):

    async def test_init_with_no_inbound_starts_empty(self):
        rt = ReplayTransport()
        self.assertEqual(rt.sent_chunks, [])
        # recv with short timeout must yield None (queue empty).
        self.assertIsNone(await rt.recv(timeout=0.05))

    async def test_init_with_inbound_chunks_queues_them(self):
        rt = ReplayTransport(inbound_chunks=[b"first", b"second", b"third"])
        self.assertEqual(await rt.recv(timeout=1.0), b"first")
        self.assertEqual(await rt.recv(timeout=1.0), b"second")
        self.assertEqual(await rt.recv(timeout=1.0), b"third")

    async def test_init_inbound_chunks_coerced_to_bytes(self):
        rt = ReplayTransport(inbound_chunks=[bytearray(b"ba")])
        chunk = await rt.recv(timeout=1.0)
        self.assertEqual(type(chunk), bytes)
        self.assertEqual(chunk, b"ba")

    async def test_stage_inbound_delivers_to_msg_cbs(self):
        rt = ReplayTransport()
        captured = []
        rt.add_msg_cb(lambda d, tr: captured.append(d))
        rt.stage_inbound(b"alpha", b"beta")
        self.assertEqual(captured, [b"alpha", b"beta"])

    async def test_stage_inbound_also_appears_on_recv(self):
        # push_on_stage=True (default) means staged chunks go to BOTH
        # the msg_cbs AND the recv queue.
        rt = ReplayTransport()
        rt.stage_inbound(b"pulled")
        result = await rt.recv(timeout=1.0)
        self.assertEqual(result, b"pulled")

    async def test_stage_inbound_returns_count(self):
        rt = ReplayTransport()
        n = rt.stage_inbound(b"a", b"b", b"c", b"d")
        self.assertEqual(n, 4)

    async def test_stage_eof_causes_recv_to_return_none(self):
        rt = ReplayTransport(inbound_chunks=[b"only"])
        first = await rt.recv(timeout=1.0)
        self.assertEqual(first, b"only")
        rt.stage_eof()
        # The EOF sentinel was None in the queue; recv returns None
        # AND auto-closes the transport.
        eof = await rt.recv(timeout=1.0)
        self.assertIsNone(eof)
        self.assertTrue(rt.is_closed())

    async def test_recv_on_closed_returns_none(self):
        rt = ReplayTransport()
        await rt.close()
        result = await rt.recv(timeout=0.1)
        self.assertIsNone(result)

    async def test_send_captures_into_sent_chunks(self):
        rt = ReplayTransport()
        n1 = await rt.send(b"first send")
        n2 = await rt.send(b"second")
        self.assertEqual(n1, 10)
        self.assertEqual(n2, 6)
        self.assertEqual(rt.sent_chunks, [b"first send", b"second"])

    async def test_send_after_close_raises(self):
        rt = ReplayTransport()
        await rt.close()
        with self.assertRaises(TransportClosed):
            await rt.send(b"x")

    async def test_send_tracks_tx_bytes(self):
        rt = ReplayTransport()
        await rt.send(b"abc")
        await rt.send(b"de")
        self.assertEqual(rt.tx_bytes, 5)

    async def test_all_sent_bytes_concatenates(self):
        rt = ReplayTransport()
        await rt.send(b"part1")
        await rt.send(b"part2")
        await rt.send(b"part3")
        self.assertEqual(rt.all_sent_bytes(), b"part1part2part3")

    async def test_all_sent_bytes_empty_when_no_sends(self):
        rt = ReplayTransport()
        self.assertEqual(rt.all_sent_bytes(), b"")

    async def test_close_is_idempotent(self):
        rt = ReplayTransport()
        await rt.close()
        await rt.close()
        self.assertTrue(rt.is_closed())

    async def test_recv_timeout_does_not_close_transport(self):
        rt = ReplayTransport()
        # Empty queue + short timeout returns None but transport
        # stays open (unlike EOF which auto-closes).
        result = await rt.recv(timeout=0.05)
        self.assertIsNone(result)
        self.assertFalse(rt.is_closed())


if __name__ == "__main__":
    unittest.main()
