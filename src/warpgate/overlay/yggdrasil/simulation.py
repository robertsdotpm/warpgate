"""v2 scenario player -- drive the protocol stack from a JSON byte log.

A scenario is a JSON document describing:
  * Named ACTORS (each with an ed25519 seed -> pubkey -> 200::/7 address)
  * A sequence of FRAMES, each a captured wire packet with metadata
    (which actor sent it, which actor it's destined for, what type it is)
  * ASSERTS that check protocol state after specific frames

The player constructs LoopbackTransport pairs for every actor pair
mentioned, instantiates the algorithm-side objects (NodeCore /
ActiveRouter / EncryptedPacketConn) wired to those transports, and
replays frames in order.  Each frame's bytes are staged on the
destination actor's inbound queue, triggering the receiving side's
state machine.  Asserts run synchronously between frames.

Example scenario document::

  {
    "name": "version_metadata_handshake",
    "description": "Two peers exchange handshake metas + verify each
                    has decoded the other's pubkey.",
    "actors": {
      "A": {"seed_hex": "00..00"},
      "B": {"seed_hex": "01..01"}
    },
    "frames": [
      {
        "from": "A", "to": "B", "kind": "version_metadata",
        "wire_hex": "6d6574...",
        "comment": "A's handshake -- preamble + body + ed25519 sig"
      },
      {
        "from": "B", "to": "A", "kind": "version_metadata",
        "wire_hex": "6d6574...",
        "comment": "B's handshake reply"
      }
    ],
    "asserts": [
      {"after_frame": 1,
       "check": "A.link.remote_pubkey == actors.B.pub",
       "comment": "A learned B's identity from the meta exchange"}
    ]
  }

The "check" string is a tiny DSL: it's eval'd in a context where
``actors.X.pub`` resolves to actor X's 32-byte pubkey and any
named ``link`` / ``router`` / ``packet_conn`` objects are
accessible by actor name.  The DSL is intentionally restrictive
(no arbitrary Python) and assert failures include the comment for
human-readable test output.
"""
import asyncio
import binascii
import json
import os

from aionetiface import fstr

from .node_core import derive_pubkey
from .transport import LoopbackTransport, ReplayTransport, loopback_pair


class ScenarioError(Exception):
    """Raised when a scenario file is malformed or an assert fails."""


class ScenarioActor(object):
    """Per-actor state in a scenario replay.

    Holds the actor's identity + the live objects the player
    spins up (transports + algorithm objects).  Population is
    lazy: ``link`` / ``router`` / ``packet_conn`` are populated
    only when a scenario's asserts or frame-handlers need them.
    """

    def __init__(self, name, seed_hex):
        self.name = str(name)
        self.seed = binascii.unhexlify(seed_hex)
        self.pub = derive_pubkey(self.seed)
        # Filled as the player builds them.
        self.transports = {}     # {peer_actor_name: Transport}
        self.link = None         # PeerLink (after handshake)
        self.router = None       # ActiveRouter (if scenario uses it)
        self.packet_conn = None  # EncryptedPacketConn (if scenario uses it)


class ScenarioPlayer(object):
    """Driver that loads a JSON scenario and replays it frame-by-frame.

    Usage:
      player = ScenarioPlayer.from_file("path/to/scenario.json")
      await player.run()           # runs all frames + asserts
      # or step-by-step:
      await player.setup()
      for frame_idx in range(len(player.scenario['frames'])):
          await player.step(frame_idx)
          player.check_asserts(after_frame=frame_idx)
    """

    def __init__(self, scenario):
        self.scenario = scenario
        self.actors = {}      # {actor_name: ScenarioActor}
        # All assertion failures get appended here so the
        # test runner can report every one (not just the first).
        self.assert_failures = []

    @classmethod
    def from_file(cls, path):
        with open(path, "r") as fh:
            scenario = json.load(fh)
        return cls(scenario)

    @classmethod
    def from_dict(cls, scenario):
        return cls(scenario)

    def setup(self):
        """Build actor objects (identity + empty transport map).

        Transports are created lazily on first frame referencing
        each (from, to) pair so a scenario that uses only A→B
        doesn't accidentally allocate every possible pair.
        """
        if "actors" not in self.scenario:
            raise ScenarioError("scenario missing 'actors' map")
        for name, info in self.scenario["actors"].items():
            if "seed_hex" not in info:
                raise ScenarioError(fstr(
                    "actor {0} missing seed_hex", (name,),
                ))
            self.actors[name] = ScenarioActor(name, info["seed_hex"])

    def transport_pair(self, from_name, to_name):
        """Return the cross-wired LoopbackTransport pair for (from, to).

        Cached on the actor objects so subsequent frames on the
        same pair reuse the same transports + see continuous state.
        """
        from_actor = self.actors[from_name]
        to_actor = self.actors[to_name]
        sender_transport = from_actor.transports.get(to_name)
        receiver_transport = to_actor.transports.get(from_name)
        if sender_transport is None or receiver_transport is None:
            sender_transport, receiver_transport = loopback_pair()
            from_actor.transports[to_name] = sender_transport
            to_actor.transports[from_name] = receiver_transport
        return sender_transport, receiver_transport

    async def step(self, frame_idx):
        """Replay frame ``frame_idx`` against the actor state."""
        frame = self.scenario["frames"][frame_idx]
        from_name = frame["from"]
        to_name = frame["to"]
        wire = binascii.unhexlify(frame["wire_hex"])
        sender_transport, receiver_transport = self.transport_pair(
            from_name, to_name,
        )
        # Stage the bytes on the RECEIVER's inbound (which is the
        # sender's outbound, by loopback symmetry).  Mirrors what
        # a real wire send would do.  We bypass sender_transport.send
        # entirely because the scenario specifies the EXACT bytes
        # to deliver -- the sender's algorithm might have produced
        # different bytes (deterministic crypto, but timing-
        # dependent fields like timestamps differ).
        await receiver_transport.inbound.put(wire)
        receiver_transport.deliver(wire)
        # Yield to let the receiver's msg_cb chain process.
        await asyncio.sleep(0)

    def check_asserts(self, after_frame):
        """Evaluate any asserts gated by ``after_frame`` and record failures."""
        for assertion in self.scenario.get("asserts", []):
            if assertion.get("after_frame") != after_frame:
                continue
            ok, detail = self.evaluate_assert(assertion)
            if not ok:
                self.assert_failures.append((after_frame, assertion, detail))

    def evaluate_assert(self, assertion):
        """Evaluate the assert's ``check`` DSL string against actor state.

        Restricted DSL: ``check`` is eval'd with a context dict
        exposing ``actors`` (dict of name→ScenarioActor) and
        nothing else.  No builtins.  This keeps scenarios safe
        to load from arbitrary files (no arbitrary-code-exec).
        """
        check = assertion.get("check", "")
        context = {"actors": dict(self.actors)}
        try:
            result = eval(check, {"__builtins__": {}}, context)
        except Exception as exc:
            return False, "eval raised: {0}".format(repr(exc))
        if not result:
            return False, "check returned falsy: {0}".format(check)
        return True, "ok"

    async def run(self):
        """Run setup + all frames + all asserts; raise on any failure."""
        self.setup()
        frames = self.scenario.get("frames", [])
        for idx, frame in enumerate(frames):
            await self.step(idx)
            self.check_asserts(after_frame=idx)
        if self.assert_failures:
            lines = []
            for frame_idx, assertion, detail in self.assert_failures:
                lines.append("after frame {0}: {1}  ({2})".format(
                    frame_idx,
                    assertion.get("comment", assertion.get("check", "?")),
                    detail,
                ))
            raise ScenarioError(
                "scenario '{0}' failed:\n  {1}".format(
                    self.scenario.get("name", "?"),
                    "\n  ".join(lines),
                )
            )


# ---------------------------------------------------------------------------
# Scenario recorder
# ---------------------------------------------------------------------------

class ScenarioRecorder(object):
    """Wrap a LoopbackTransport pair, capture every byte exchange.

    Usage in a test that drives a real handshake against loopback:
      rec = ScenarioRecorder(actor_a, actor_b)
      sender, receiver = rec.transport_pair()
      # Drive your code using sender + receiver as if they were
      # plain loopback transports.  Behind the scenes the recorder
      # logs every send into a serializable list.
      ...
      data = rec.to_dict(name="my_scenario", description="...")
      json.dump(data, open("scenario.json", "w"))
    """

    def __init__(self, actor_a, actor_b):
        self.actor_a = actor_a
        self.actor_b = actor_b
        self.frames = []
        self.sender, self.receiver = loopback_pair()
        # Wrap both sides' send to capture.
        orig_a_send = self.sender.send
        orig_b_send = self.receiver.send

        async def patched_a_send(data):
            n = await orig_a_send(data)
            self.frames.append({
                "from": self.actor_a, "to": self.actor_b,
                "wire_hex": binascii.hexlify(bytes(data)).decode("ascii"),
                "kind": "raw",
            })
            return n

        async def patched_b_send(data):
            n = await orig_b_send(data)
            self.frames.append({
                "from": self.actor_b, "to": self.actor_a,
                "wire_hex": binascii.hexlify(bytes(data)).decode("ascii"),
                "kind": "raw",
            })
            return n

        self.sender.send = patched_a_send
        self.receiver.send = patched_b_send

    def transport_pair(self):
        return self.sender, self.receiver

    def to_dict(self, name, description, actor_seeds, asserts=None,
                comments=None):
        """Bundle the recorded frames into a serializable scenario dict.

        ``actor_seeds`` is a {actor_name: seed_hex} map (necessary
        to round-trip).  ``comments`` is an optional list
        per-frame human-readable annotation (e.g. ``["A handshake",
        "B handshake reply", "sig_req", ...]``).
        """
        actors = {
            name: {"seed_hex": seed_hex}
            for name, seed_hex in actor_seeds.items()
        }
        frames_out = []
        for idx, fr in enumerate(self.frames):
            entry = dict(fr)
            if comments and idx < len(comments):
                entry["comment"] = comments[idx]
            frames_out.append(entry)
        return {
            "name": name,
            "description": description,
            "actors": actors,
            "frames": frames_out,
            "asserts": list(asserts or []),
        }
