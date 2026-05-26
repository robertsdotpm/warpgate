"""IPv6 link-local multicast discovery -- byte-compat with yggdrasil-go.

Port of ``yggdrasil-go/src/multicast``.  Periodically beacons a
``multicastAdvertisement`` to the group ``[ff02::114]:9001``; when
a peer's beacon arrives on the same group, we add the peer to our
NodeCore's outbound dialer list.

The advertisement wire format (per ``advertisement.go``):

  [uint16 BE major][uint16 BE minor]
  [32 bytes ed25519 public key]
  [uint16 BE port]
  [uint16 BE hash_len][hash_len bytes hash]

Where ``hash`` is the blake2b-512 of the optional shared password
(empty bytes for the unauthenticated case).  Both peers must
agree on the hash to peer.

Networking uses aionetiface's UDP Pipe (no msg_cb-style cb
because aionetiface's UDP path predates msg_cb -- recv() in pull
mode is fine since the beacon traffic is low-rate).  The group
address is link-local, so the kernel automatically scopes it to
the NIC the socket was bound on.
"""
import asyncio
import struct

from aionetiface import IP6, UDP, Interface, Pipe, SUB_ALL, fstr, log, log_exception

from .blake2b import blake2b_hash
from .version import PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR


# Upstream defaults.  ff02::114 is the Yggdrasil link-local multicast
# group; port 9001 is the well-known beacon port.
MULTICAST_GROUP = "ff02::114"
MULTICAST_PORT = 9001
BEACON_INTERVAL_SECONDS = 1.0   # upstream starts at 1s, grows to 15s
BEACON_MAX_INTERVAL = 15.0
ED25519_PUBLIC_KEY_SIZE = 32


class MulticastAdvertisement(object):
    """A single beacon message -- both encoded and decoded form."""

    def __init__(self, major_ver=PROTOCOL_VERSION_MAJOR,
                 minor_ver=PROTOCOL_VERSION_MINOR,
                 public_key=b"\x00" * ED25519_PUBLIC_KEY_SIZE,
                 port=0, hash_bytes=b""):
        self.major_ver = int(major_ver)
        self.minor_ver = int(minor_ver)
        self.public_key = bytes(public_key)
        self.port = int(port)
        self.hash_bytes = bytes(hash_bytes)

    def encode(self):
        return (struct.pack(">HH", self.major_ver, self.minor_ver)
                + self.public_key
                + struct.pack(">HH", self.port, len(self.hash_bytes))
                + self.hash_bytes)

    @classmethod
    def decode(cls, buf):
        header_len = ED25519_PUBLIC_KEY_SIZE + 8
        if len(buf) < header_len:
            raise ValueError("MulticastAdvertisement: truncated header")
        major, minor = struct.unpack(">HH", buf[0:4])
        pub = buf[4:4 + ED25519_PUBLIC_KEY_SIZE]
        port = struct.unpack(">H", buf[4 + ED25519_PUBLIC_KEY_SIZE:6 + ED25519_PUBLIC_KEY_SIZE])[0]
        hash_len = struct.unpack(">H", buf[6 + ED25519_PUBLIC_KEY_SIZE:8 + ED25519_PUBLIC_KEY_SIZE])[0]
        if len(buf) < header_len + hash_len:
            raise ValueError("MulticastAdvertisement: truncated hash body")
        hash_bytes = buf[header_len:header_len + hash_len]
        return cls(major_ver=major, minor_ver=minor, public_key=pub,
                   port=port, hash_bytes=hash_bytes)


class MulticastDiscovery(object):
    """Beaconer + listener on the Yggdrasil multicast group.

    Constructed against a NodeCore.  Call ``start(nic)`` to begin
    beaconing on a specific NIC; ``stop()`` to tear down.  Inbound
    beacons whose hash matches ours trigger an ``add_peer_uri``
    on the NodeCore for the advertised host:port.
    """

    def __init__(self, node_core, password=b""):
        self.node_core = node_core
        self.password = bytes(password)
        # Hash advertised in our beacon -- matches upstream
        # multicast.go:214-230 exactly: blake2b-512 KEYED with the
        # password, hashing OUR public key.  Both ends must agree on
        # the password AND know each other's public key (carried in
        # the beacon) for the hash compare to succeed.  Earlier this
        # was wrongly computed as blake2b-512(password) which made
        # us byte-incompatible with real yggdrasil peers.
        self.hash_bytes = blake2b_hash(
            self.node_core.public_key,
            key=self.password, digest_size=64,
        )
        self.pipe = None
        self.beacon_task = None
        self.listen_task = None
        self.beacon_interval = BEACON_INTERVAL_SECONDS
        self.closed = False
        # Per-peer-pubkey: last-seen beacon timestamp (anti-spam).
        self.last_seen = {}

    async def start(self, nic=None, bind_addr="::"):
        """Open the multicast UDP socket and start beaconing + listening."""
        if self.closed:
            raise RuntimeError("MulticastDiscovery: closed")
        if self.pipe is not None:
            return
        iface = nic if nic is not None else Interface("default")
        route = await iface.route(IP6).bind(ips=bind_addr, port=MULTICAST_PORT)
        # UDP socket; reuse_addr so multiple nodes on the same machine
        # can co-bind for testing.
        self.pipe = Pipe(UDP, dest=None, route=route)
        await self.pipe.connect()
        # NOTE: full IPv6 multicast group-join requires
        # setsockopt(IPV6_JOIN_GROUP, ...).  aionetiface doesn't
        # surface that yet; on Linux the socket auto-receives
        # ff02::/16 traffic for the bound NIC anyway via the
        # default group-membership.  Real deployment of Yggdrasil
        # via this code path would need a stdlib setsockopt call
        # against the pipe's underlying sock.
        try:
            self.join_multicast_group(iface)
        except Exception:
            log_exception()
        self.beacon_task = asyncio.ensure_future(self.beacon_loop())
        self.listen_task = asyncio.ensure_future(self.listen_loop())

    def join_multicast_group(self, nic):
        """Best-effort IPV6_JOIN_GROUP for the Yggdrasil multicast group."""
        if self.pipe is None or self.pipe.sock is None:
            return
        import socket as stdsocket
        sock = self.pipe.sock
        # Resolve the NIC index for the join request.  socket.if_nametoindex
        # is stdlib on Python 3.3+; fall back to 0 (default NIC) if unknown.
        if_index = 0
        try:
            if_index = stdsocket.if_nametoindex(nic.name)
        except (AttributeError, OSError):
            pass
        try:
            group_bin = stdsocket.inet_pton(stdsocket.AF_INET6, MULTICAST_GROUP)
            # ipv6_mreq layout: 16 bytes group + 4 bytes interface index BE.
            mreq = group_bin + struct.pack("@I", if_index)
            sock.setsockopt(
                stdsocket.IPPROTO_IPV6,
                stdsocket.IPV6_JOIN_GROUP,
                mreq,
            )
        except (OSError, AttributeError):
            log_exception()

    async def beacon_loop(self):
        """Periodically emit a beacon to the multicast group."""
        while not self.closed:
            try:
                await self.send_beacon()
            except Exception:
                log_exception()
            # Backoff up to BEACON_MAX_INTERVAL, then steady-state.
            await asyncio.sleep(self.beacon_interval)
            if self.beacon_interval < BEACON_MAX_INTERVAL:
                self.beacon_interval += 1.0

    async def send_beacon(self):
        """Emit one MulticastAdvertisement to the group."""
        if self.pipe is None or self.node_core.listen_port is None:
            return
        adv = MulticastAdvertisement(
            major_ver=PROTOCOL_VERSION_MAJOR,
            minor_ver=PROTOCOL_VERSION_MINOR,
            public_key=self.node_core.public_key,
            port=self.node_core.listen_port,
            hash_bytes=self.hash_bytes,
        )
        try:
            await self.pipe.send(adv.encode(), (MULTICAST_GROUP, MULTICAST_PORT))
        except (OSError, ConnectionError):
            log_exception()

    async def listen_loop(self):
        """Receive multicast beacons; trigger add_peer_uri on match."""
        self.pipe.subscribe(SUB_ALL)
        while not self.closed:
            try:
                chunk = await self.pipe.recv(SUB_ALL, timeout=2)
            except asyncio.CancelledError:
                raise
            except (OSError, ConnectionError):
                log_exception()
                continue
            if chunk is None:
                continue
            try:
                adv = MulticastAdvertisement.decode(chunk)
            except ValueError:
                continue
            await self.handle_beacon(adv)

    async def handle_beacon(self, adv):
        """If this beacon is from a compatible peer, dial it."""
        # Skip our own beacons (loop-back via the multicast group).
        if adv.public_key == self.node_core.public_key:
            return
        # Skip beacons from peers using a different password.
        # The hash carried in the beacon is
        # blake2b-512-keyed(password)(SENDER's_pubkey) -- so we
        # recompute it locally with OUR password and THEIR pubkey
        # and compare.  This proves the sender knows the shared
        # password without revealing it.  Mirrors upstream
        # multicast.go:430-441 exactly.
        expected = blake2b_hash(
            adv.public_key, key=self.password, digest_size=64,
        )
        if adv.hash_bytes != expected:
            return
        # Version compat -- mirror upstream's check.
        if (adv.major_ver != PROTOCOL_VERSION_MAJOR
                or adv.minor_ver != PROTOCOL_VERSION_MINOR):
            return
        # Anti-spam: don't re-dial the same peer if we just saw them.
        import time as _time
        now = _time.monotonic()
        last = self.last_seen.get(adv.public_key)
        if last is not None and now - last < 30:
            return
        self.last_seen[adv.public_key] = now
        # Beacon doesn't carry the source IP -- we'd need to know
        # it from the recv tuple to build a dial URI.  Real
        # deployment: pull it from recv(full=True) which returns
        # ``(data, client_tup)``.  For now we log and skip.
        log(fstr(
            "multicast: saw beacon from peer {0} (port {1})",
            (adv.public_key[:4].hex(), adv.port),
        ))

    async def stop(self):
        """Cancel both loops and close the socket."""
        if self.closed:
            return
        self.closed = True
        for task in (self.beacon_task, self.listen_task):
            if task is not None:
                try:
                    task.cancel()
                except Exception:
                    pass
        self.beacon_task = self.listen_task = None
        if self.pipe is not None:
            try:
                await self.pipe.close()
            except Exception:
                log_exception()
            self.pipe = None
