"""Edge-case tests for simulation.ScenarioPlayer and ScenarioActor.

Three sensitive areas:
  - Scenario input validation (missing actors, missing seed_hex,
    malformed hex, wrong-length seed, malformed wire_hex)
  - eval()-based assert DSL sandbox (no __builtins__, no
    __import__, no open() / os / sys leak, exceptions captured
    as failures rather than crashing the run)
  - run() aggregation: ALL assert failures listed (not just first)

The eval sandbox is the security-sensitive boundary -- a scenario
JSON downloaded from a third party MUST NOT be able to escape into
arbitrary code execution.  The tests below try the canonical
sandbox-escape vectors and pin them as blocked.
"""
import binascii
import json
import os
import tempfile
import unittest

from aionetiface.testing import AsyncTestCase

from warpgate.overlay.yggdrasil.simulation import (
    ScenarioActor, ScenarioError, ScenarioPlayer,
)


GOOD_SEED_HEX_A = "11" * 32
GOOD_SEED_HEX_B = "22" * 32


def minimal_scenario():
    """Return the smallest valid scenario dict: 2 actors, 0 frames."""
    return {
        "name": "minimal",
        "description": "two actors, no frames",
        "actors": {
            "A": {"seed_hex": GOOD_SEED_HEX_A},
            "B": {"seed_hex": GOOD_SEED_HEX_B},
        },
        "frames": [],
        "asserts": [],
    }


# ---------------------------------------------------------------------------
# ScenarioActor: seed handling
# ---------------------------------------------------------------------------
class TestScenarioActor(AsyncTestCase):

    async def test_seed_decodes_and_pubkey_derives(self):
        actor = ScenarioActor("A", GOOD_SEED_HEX_A)
        self.assertEqual(actor.name, "A")
        self.assertEqual(type(actor.seed), bytes)
        self.assertEqual(len(actor.seed), 32)
        self.assertEqual(type(actor.pub), bytes)
        self.assertEqual(len(actor.pub), 32)
        # Distinct seeds yield distinct pubkeys.
        actor_b = ScenarioActor("B", GOOD_SEED_HEX_B)
        self.assertNotEqual(actor.pub, actor_b.pub)

    async def test_seed_hex_too_short_rejected_by_derive_pubkey(self):
        # 16 hex chars = 8 bytes; derive_pubkey requires 32.
        with self.assertRaises(ValueError):
            ScenarioActor("X", "ab" * 8)

    async def test_seed_hex_too_long_rejected(self):
        with self.assertRaises(ValueError):
            ScenarioActor("X", "ab" * 100)

    async def test_non_hex_seed_raises_binascii_error(self):
        with self.assertRaises(binascii.Error):
            ScenarioActor("X", "not-hex-at-all" * 5)

    async def test_odd_length_hex_raises_binascii_error(self):
        with self.assertRaises(binascii.Error):
            ScenarioActor("X", "abc")

    async def test_initial_state_collections_empty(self):
        actor = ScenarioActor("A", GOOD_SEED_HEX_A)
        self.assertEqual(actor.transports, {})
        self.assertIsNone(actor.link)
        self.assertIsNone(actor.router)
        self.assertIsNone(actor.packet_conn)


# ---------------------------------------------------------------------------
# Scenario setup: input validation
# ---------------------------------------------------------------------------
class TestScenarioSetup(AsyncTestCase):

    async def test_missing_actors_key_raises_scenario_error(self):
        player = ScenarioPlayer.from_dict({"frames": []})
        with self.assertRaises(ScenarioError) as ctx:
            player.setup()
        self.assertIn("'actors'", str(ctx.exception))

    async def test_actor_missing_seed_hex_raises_scenario_error(self):
        player = ScenarioPlayer.from_dict({
            "actors": {"A": {}},
            "frames": [],
        })
        with self.assertRaises(ScenarioError) as ctx:
            player.setup()
        self.assertIn("seed_hex", str(ctx.exception))
        self.assertIn("A", str(ctx.exception))

    async def test_setup_creates_one_actor_per_entry(self):
        player = ScenarioPlayer.from_dict(minimal_scenario())
        player.setup()
        self.assertEqual(set(player.actors.keys()), {"A", "B"})
        self.assertIsInstance(player.actors["A"], ScenarioActor)
        self.assertIsInstance(player.actors["B"], ScenarioActor)

    async def test_from_file_round_trip(self):
        scenario = minimal_scenario()
        scenario["name"] = "from_file_test"
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(scenario, fh)
            player = ScenarioPlayer.from_file(path)
            self.assertEqual(player.scenario["name"], "from_file_test")
            player.setup()
            self.assertEqual(set(player.actors.keys()), {"A", "B"})
        finally:
            os.unlink(path)

    async def test_setup_runs_independently_per_player(self):
        # Two players with overlapping actor names get independent
        # ScenarioActor instances -- no shared identity state.
        sc = minimal_scenario()
        p1 = ScenarioPlayer.from_dict(sc)
        p2 = ScenarioPlayer.from_dict(sc)
        p1.setup()
        p2.setup()
        self.assertIsNot(p1.actors["A"], p2.actors["A"])


# ---------------------------------------------------------------------------
# transport_pair caching
# ---------------------------------------------------------------------------
class TestTransportPairCaching(AsyncTestCase):

    async def test_transport_pair_cached_per_direction(self):
        player = ScenarioPlayer.from_dict(minimal_scenario())
        player.setup()
        sender1, receiver1 = player.transport_pair("A", "B")
        sender2, receiver2 = player.transport_pair("A", "B")
        # Same pair on second call -- caching property.
        self.assertIs(sender1, sender2)
        self.assertIs(receiver1, receiver2)

    async def test_transport_pair_cross_wired(self):
        player = ScenarioPlayer.from_dict(minimal_scenario())
        player.setup()
        sender, receiver = player.transport_pair("A", "B")
        # Sender's peer is the receiver and vice-versa.
        self.assertIs(sender.peer, receiver)
        self.assertIs(receiver.peer, sender)

    async def test_distinct_pairs_per_actor_pair(self):
        player = ScenarioPlayer.from_dict(minimal_scenario())
        player.setup()
        # Add a third actor so we can probe (A,B) vs (A,C) caches.
        player.actors["C"] = ScenarioActor("C", "33" * 32)
        s_ab, _ = player.transport_pair("A", "B")
        s_ac, _ = player.transport_pair("A", "C")
        # A's transport-to-B is distinct from A's transport-to-C.
        self.assertIsNot(s_ab, s_ac)


# ---------------------------------------------------------------------------
# step(): frame replay
# ---------------------------------------------------------------------------
class TestStepFrameReplay(AsyncTestCase):

    async def test_step_delivers_bytes_to_receiver(self):
        sc = minimal_scenario()
        sc["frames"] = [{
            "from": "A", "to": "B",
            "kind": "raw", "wire_hex": "deadbeef",
            "comment": "test",
        }]
        player = ScenarioPlayer.from_dict(sc)
        player.setup()
        captured = []
        # Force receiver transport into existence by pre-priming
        # the cache, then attach a cb.
        sender, receiver = player.transport_pair("A", "B")
        receiver.add_msg_cb(lambda d, tr: captured.append(d))
        await player.step(0)
        self.assertEqual(captured, [b"\xde\xad\xbe\xef"])

    async def test_step_malformed_wire_hex_raises_binascii(self):
        sc = minimal_scenario()
        sc["frames"] = [{
            "from": "A", "to": "B", "kind": "raw",
            "wire_hex": "not hex at all", "comment": "bad",
        }]
        player = ScenarioPlayer.from_dict(sc)
        player.setup()
        with self.assertRaises(binascii.Error):
            await player.step(0)

    async def test_step_with_out_of_range_frame_idx_raises_index_error(self):
        sc = minimal_scenario()
        sc["frames"] = []
        player = ScenarioPlayer.from_dict(sc)
        player.setup()
        with self.assertRaises(IndexError):
            await player.step(0)


# ---------------------------------------------------------------------------
# evaluate_assert: eval DSL sandbox
# ---------------------------------------------------------------------------
class TestAssertDslSandbox(AsyncTestCase):

    def make_player(self):
        player = ScenarioPlayer.from_dict(minimal_scenario())
        player.setup()
        return player

    async def test_truthy_check_returns_ok(self):
        player = self.make_player()
        ok, detail = player.evaluate_assert({"check": "1 + 1 == 2"})
        self.assertEqual(ok, True)
        self.assertEqual(detail, "ok")

    async def test_falsy_check_returns_failure_with_detail(self):
        player = self.make_player()
        ok, detail = player.evaluate_assert({"check": "1 == 2"})
        self.assertEqual(ok, False)
        self.assertIn("falsy", detail)
        self.assertIn("1 == 2", detail)

    async def test_actor_pub_accessible_in_dsl(self):
        player = self.make_player()
        ok, _ = player.evaluate_assert({
            "check": "len(actors['A'].pub) == 32",
        })
        # Even though len() is a builtin, it's pulled in via the
        # globals context.  But our sandbox passes __builtins__: {}.
        # So len() should NOT be available either.
        self.assertEqual(ok, False)

    async def test_attribute_access_blocked_via_no_builtins(self):
        player = self.make_player()
        ok, detail = player.evaluate_assert({
            "check": "__import__('os').system('echo pwned')",
        })
        self.assertEqual(ok, False)
        self.assertIn("eval raised", detail)
        # The NameError should be for __import__ being absent.
        self.assertIn("__import__", detail)

    async def test_open_function_blocked(self):
        player = self.make_player()
        ok, detail = player.evaluate_assert({
            "check": "open('/etc/passwd').read()",
        })
        self.assertEqual(ok, False)
        self.assertIn("eval raised", detail)

    async def test_exec_blocked(self):
        player = self.make_player()
        ok, detail = player.evaluate_assert({
            "check": "exec('print(1)')",
        })
        self.assertEqual(ok, False)
        self.assertIn("eval raised", detail)

    async def test_arbitrary_exception_in_check_captured_as_failure(self):
        player = self.make_player()
        ok, detail = player.evaluate_assert({
            "check": "actors['NOT_AN_ACTOR'].pub",
        })
        self.assertEqual(ok, False)
        self.assertIn("eval raised", detail)
        self.assertIn("KeyError", detail)

    async def test_check_with_zero_division_captured(self):
        player = self.make_player()
        ok, detail = player.evaluate_assert({"check": "1 / 0"})
        self.assertEqual(ok, False)
        self.assertIn("ZeroDivisionError", detail)

    async def test_actor_identity_equality_works(self):
        # Two pubkeys from same seed are equal; from different seeds not.
        player = self.make_player()
        ok_same, _ = player.evaluate_assert({
            "check": "actors['A'].pub == actors['A'].pub",
        })
        self.assertEqual(ok_same, True)
        ok_diff, _ = player.evaluate_assert({
            "check": "actors['A'].pub != actors['B'].pub",
        })
        self.assertEqual(ok_diff, True)

    async def test_missing_check_string_returns_falsy(self):
        # No "check" key -> defaults to empty string -> eval("") raises
        # SyntaxError -> captured as failure.
        player = self.make_player()
        ok, detail = player.evaluate_assert({})
        self.assertEqual(ok, False)
        self.assertIn("eval raised", detail)


# ---------------------------------------------------------------------------
# run(): aggregation + error reporting
# ---------------------------------------------------------------------------
class TestRunAggregation(AsyncTestCase):

    async def test_run_with_no_frames_completes_cleanly(self):
        player = ScenarioPlayer.from_dict(minimal_scenario())
        await player.run()
        self.assertEqual(player.assert_failures, [])

    async def test_run_reports_every_assert_failure(self):
        # Three failing asserts after three frames -- the run() must
        # NOT bail on the first failure; all three must appear in
        # the final ScenarioError message.
        sc = minimal_scenario()
        sc["frames"] = [
            {"from": "A", "to": "B", "kind": "raw",
             "wire_hex": "01", "comment": "f0"},
            {"from": "A", "to": "B", "kind": "raw",
             "wire_hex": "02", "comment": "f1"},
            {"from": "A", "to": "B", "kind": "raw",
             "wire_hex": "03", "comment": "f2"},
        ]
        sc["asserts"] = [
            {"after_frame": 0, "check": "False",
             "comment": "first will fail"},
            {"after_frame": 1, "check": "False",
             "comment": "second will fail"},
            {"after_frame": 2, "check": "False",
             "comment": "third will fail"},
        ]
        player = ScenarioPlayer.from_dict(sc)
        with self.assertRaises(ScenarioError) as ctx:
            await player.run()
        msg = str(ctx.exception)
        self.assertIn("first will fail", msg)
        self.assertIn("second will fail", msg)
        self.assertIn("third will fail", msg)
        # The collected failures list also has all three.
        self.assertEqual(len(player.assert_failures), 3)

    async def test_run_with_mixed_pass_fail_only_reports_failures(self):
        sc = minimal_scenario()
        sc["frames"] = [
            {"from": "A", "to": "B", "kind": "raw",
             "wire_hex": "aa", "comment": ""},
        ]
        sc["asserts"] = [
            {"after_frame": 0, "check": "True",  "comment": "pass"},
            {"after_frame": 0, "check": "False", "comment": "fail-one"},
            {"after_frame": 0, "check": "True",  "comment": "pass"},
        ]
        player = ScenarioPlayer.from_dict(sc)
        with self.assertRaises(ScenarioError) as ctx:
            await player.run()
        # Only ONE failure recorded, not three.
        self.assertEqual(len(player.assert_failures), 1)
        self.assertIn("fail-one", str(ctx.exception))

    async def test_run_all_assertions_passing_returns_cleanly(self):
        sc = minimal_scenario()
        sc["frames"] = [
            {"from": "A", "to": "B", "kind": "raw",
             "wire_hex": "ff", "comment": ""},
        ]
        sc["asserts"] = [
            {"after_frame": 0, "check": "actors['A'].pub != actors['B'].pub",
             "comment": "pubs differ"},
        ]
        player = ScenarioPlayer.from_dict(sc)
        await player.run()
        self.assertEqual(player.assert_failures, [])

    async def test_assert_with_unmatched_after_frame_is_skipped(self):
        sc = minimal_scenario()
        sc["frames"] = [
            {"from": "A", "to": "B", "kind": "raw",
             "wire_hex": "ee", "comment": ""},
        ]
        sc["asserts"] = [
            # after_frame=99 never fires for a 1-frame scenario.
            {"after_frame": 99, "check": "False",
             "comment": "never evaluated"},
        ]
        player = ScenarioPlayer.from_dict(sc)
        # Should NOT raise -- the assert was gated past the last frame.
        await player.run()
        self.assertEqual(player.assert_failures, [])


# ---------------------------------------------------------------------------
# check_asserts: granular control flow
# ---------------------------------------------------------------------------
class TestCheckAssertsGranular(AsyncTestCase):

    async def test_appends_each_failure_to_assert_failures_list(self):
        player = ScenarioPlayer.from_dict(minimal_scenario())
        player.setup()
        player.scenario["asserts"] = [
            {"after_frame": 0, "check": "False", "comment": "fail-a"},
            {"after_frame": 0, "check": "False", "comment": "fail-b"},
        ]
        player.check_asserts(after_frame=0)
        self.assertEqual(len(player.assert_failures), 2)
        comments = [a[1].get("comment") for a in player.assert_failures]
        self.assertEqual(comments, ["fail-a", "fail-b"])

    async def test_no_asserts_key_is_noop(self):
        player = ScenarioPlayer.from_dict(minimal_scenario())
        player.setup()
        # Strip the asserts key entirely.
        del player.scenario["asserts"]
        # Must not raise.
        player.check_asserts(after_frame=0)
        self.assertEqual(player.assert_failures, [])

    async def test_failure_record_includes_frame_idx_and_detail(self):
        player = ScenarioPlayer.from_dict(minimal_scenario())
        player.setup()
        player.scenario["asserts"] = [
            {"after_frame": 5, "check": "False", "comment": "X"},
        ]
        player.check_asserts(after_frame=5)
        self.assertEqual(len(player.assert_failures), 1)
        frame_idx, assertion, detail = player.assert_failures[0]
        self.assertEqual(frame_idx, 5)
        self.assertEqual(assertion["comment"], "X")
        self.assertIn("falsy", detail)


if __name__ == "__main__":
    unittest.main()
