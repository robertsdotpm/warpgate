"""Utility functions shared across traversal strategies."""
import asyncio
from aionetiface import (
    IP4, IP6, IPRange, af_bitlen,
    NIC_BIND, EXT_BIND, LOOPBACK_BIND,
    to_s, to_b, to_h, h_to_b, rand_plain,
    fstr, log, log_p2p, log_exception,
    async_wrap_errors, decrypt, encrypt,
    cancel_task, cancel_tasks,
)
from ..protocol.proto_msg import ProtoMsg

__all__ = ["cancel_task", "cancel_tasks"]


def f_path_txt(x):
    """Return 'local' for NIC_BIND paths, 'external' otherwise."""
    return "local" if x == NIC_BIND else "external"


# Routing-decision keys that resolve_pair strips off the per-side dicts
# before plugins see them.  After resolution the only addressing fields
# that remain are "ip" + "port" -- the resolved local-bind / peer-dial
# pair for the chosen route_type.  Peer metadata (if_index, nat,
# netiface_index, machine_id, pub_key_hex, …) stays.
# Routing-decision keys that get stripped from the per-side dict
# resolve_pair hands to plugins.  Plugins should read the resolved
# (ip, port) and let the route layer make the binding decisions.
#
# NOTE: "ext" deliberately stays IN the resolved dict (i.e. not in
# this drop set) -- the punch family's master/slave election uses
# src["ext"] as the peer-observable identifier for the comparison.
# It is NOT a routing decision; it is a symmetric peer ID.  Stripping
# it caused every election to silently fall back to bind_ip and
# could land both peers on the same role.
RESOLVE_DROP_KEYS = (
    "nic", "loopback",
    "nic_port", "ext_port",
    "loopback_candidates",
)


def select_local_bind(af, route_type, src, dest):
    """Pick the local (ip, port) pair to bind for this route_type."""
    if route_type == LOOPBACK_BIND:
        ip = src.get("loopback")
        port = src.get("nic_port", src.get("port"))
    elif route_type == NIC_BIND:
        ip = src["nic"]
        port = src.get("nic_port", src.get("port"))
    elif route_type == EXT_BIND:
        # v4: NAT box rewrites src; kernel binds to the local LAN
        # address (src["nic"]) and the peer sees src["ext"].
        # v6: no NAT in the path -- bind == advertise == ext (global).
        # make_node_addr serialises v6's nic as fe80 link-local when
        # any link-local exists on the route (topology.py:428-430),
        # so binding to src["nic"] for v6 EXT_BIND would put us on a
        # link-local source addr that can't reach a global remote.
        if af == IP6:
            ip = src.get("ext") or src["nic"]
        else:
            ip = src["nic"]
        port = src.get("ext_port", src.get("port"))
    else:
        raise ValueError(fstr("resolve_pair: unknown route_type {0}", (route_type,)))
    return ip, port


def select_remote_dial(af, route_type, src, dest):
    """Pick the (ip, port) pair to dial on the peer for this route_type."""
    if route_type == LOOPBACK_BIND:
        ip = dest.get("loopback")
        port = dest.get("nic_port", dest.get("port"))
    elif route_type == NIC_BIND:
        # Dial the peer's nic IP directly -- the mirror of
        # select_local_bind's src["nic"]. NIC_BIND is only ever paired
        # for same-machine / same-LAN peers (auto_connect's viable()
        # gates it on same_machine or same_lan), so the peer's nic IP
        # is always L2-reachable, including a v6 fe80 link-local: its
        # scope is the interface the punch socket binds to.
        #
        # Do NOT swap a v6 fe80 dest for dest["ext"] (global): src
        # binds the link-local nic IP, so a global dest is a scope
        # mismatch and the connection cannot form. Cross-link peers
        # never reach NIC_BIND -- they use EXT_BIND.
        ip = dest["nic"]
        port = dest.get("nic_port", dest.get("port"))
    elif route_type == EXT_BIND:
        ip = dest["ext"]
        port = dest.get("ext_port", dest.get("port"))
    else:
        raise ValueError(fstr("resolve_pair: unknown route_type {0}", (route_type,)))
    return ip, port


def resolve_pair(af, route_type, src, dest, nic, same_machine=False):
    """Resolve a (src, dest) pair into the bind / dial values
    a plugin will actually use.

    Returns ``(src_resolved, dest_resolved)`` -- shallow copies of the
    inputs with two changes:

      1.  ``ip`` / ``port`` set to the chosen local bind / peer dial
          values for *route_type*.  v6 link-local destinations get the
          paired link-local source plus ``%scope`` patched into both
          sides so Windows connect_ex works.
      2.  Routing-decision keys (nic / ext / loopback / nic_port /
          ext_port / loopback_candidates) are removed.  Plugins that
          need additional info beyond (ip, port) read it from the
          local NIC object directly, not from the per-side dict.

    Peer metadata (if_index, nat, netiface_index, machine_id,
    pub_key_hex, …) is preserved -- plugins legitimately need NAT
    shape, if_index, etc.
    """
    src_ip, src_port = select_local_bind(af, route_type, src, dest)
    dest_ip, dest_port = select_remote_dial(af, route_type, src, dest)

    # v6 link-local fix-up: paired source must also be link-local, and
    # both sides need %scope_id appended for the Windows TCP stack to
    # route the SYN out the right interface.  Linux's getaddrinfo
    # tolerates a bare fe80::, but baking the scope is harmless there
    # and removes the cross-platform branch from every plugin.
    if af == IP6 and dest_ip is not None and str(dest_ip).lower().startswith("fe80"):
        if nic is not None:
            try:
                local_link = nic.route(af).link_locals[0]
                src_ip = str(local_link)
            except (IndexError, AttributeError, ValueError):
                pass
            try:
                from aionetiface.net.bind.bind_utils import ip6_patch_bind_ip
                scope = nic.get_nic_id(af)
                if scope is not None:
                    dest_ip = ip6_patch_bind_ip(str(dest_ip).split("%", 1)[0], scope)
                    src_ip = ip6_patch_bind_ip(str(src_ip).split("%", 1)[0], scope)
            except (ImportError, AttributeError, ValueError):
                pass

    # Strict mode: per-side dict carries only the resolved (ip, port)
    # plus peer metadata (if_index, nat, netiface_index, machine_id,
    # pub_key_hex, bytes, ...).  Raw routing-decision keys (nic / ext
    # / loopback / nic_port / ext_port / loopback_candidates) are
    # filtered out so plugins can't accidentally do per-route-type
    # selection inside their run().
    def strip(info):
        return {k: v for k, v in info.items() if k not in RESOLVE_DROP_KEYS}
    src_resolved = strip(src)
    src_resolved["ip"] = str(src_ip) if src_ip is not None else None
    src_resolved["port"] = src_port
    dest_resolved = strip(dest)
    dest_resolved["ip"] = str(dest_ip) if dest_ip is not None else None
    dest_resolved["port"] = dest_port
    _ = same_machine  # accepted for future fixups (multi-NIC same-pc edge case)
    return src_resolved, dest_resolved


def select_dest_ipr(af, same_pc, src, dest, addr_types, has_set_bind=True):
    """Select the best destination IPRange for a traversal attempt.

    Nodes behind the same router share an external address; in that case the
    private NIC address is used instead so the connection does not loop back
    through the router.
    """
    # Shorten these for expressions.
    src_nid = src["netiface_index"]
    dest_nid = dest["netiface_index"]

    # Same-LAN detection. The right question for the NIC_BIND path is
    # "is dest reachable via my directly-connected interface, with no
    # router hop?" -- i.e. is dest's IP within MY nic's directly-
    # connected subnet. When the wire format ships our peer's NIC
    # subnet (9-field addr), use it; otherwise fall back to the v4
    # ext-equality heuristic.
    same_lan = False
    src_nic_subnet = getattr(src["nic"], "subnet", None)
    if src_nic_subnet is not None and src_nic_subnet > 0:
        host_bits = af_bitlen(af) - src_nic_subnet
        if af == IP6 and str(src["nic"]).lower().startswith("fe80:"):
            try:
                src_net = IPRange(str(src["ext"]), bitlen=host_bits)
                same_lan = dest["ext"] in src_net
            except (ValueError, TypeError):
                same_lan = False
        else:
            try:
                src_net = IPRange(str(src["nic"]), bitlen=host_bits)
                same_lan = (
                    dest["nic"] in src_net or dest["ext"] in src_net
                )
            except (ValueError, TypeError):
                same_lan = False
    else:
        same_lan = src["ext"] == dest["ext"]

    # Makes long conditions slightly more readable.
    same_if = src_nid == dest_nid
    same_if_on_host = same_pc and same_if

    # There may be multiple compatible addresses per info.
    # Caller controls priority via the order of addr_types.
    for addr_type in addr_types:
        # Per-node 127.X.Y.Z (or ::1) loopback alias. Only meaningful
        # for same-machine peers and only when both sides have a
        # loopback IP attached (set by enrich_addr_map_with_loopback).
        if addr_type == LOOPBACK_BIND:
            if not same_pc:
                continue
            lo = dest.get("loopback")
            if lo is None:
                continue
            return lo

        # Public WAN address. Skip when both nodes share the same
        # external address (same NAT / same machine with the same
        # global IP) -- the connection would loop back through the
        # router or fail. When ext IPs differ (different ISPs etc.)
        # it's the natural cross-machine path.
        if addr_type == EXT_BIND:
            if src["ext"] == dest["ext"]:
                continue
            return dest["ext"]

        # Local NIC address.
        #
        # v6 global NIC addresses are publicly routable (no NAT for v6),
        # so they are valid for any pairing -- skip the same_lan gate.
        #
        # v6 link-local (fe80::/10) addresses are only valid on the same
        # L2 segment; skip them when the peers are not on the same LAN.
        #
        # v4 private NIC addresses are only reachable within the same LAN
        # (same NAT router = same external IP); skip otherwise.
        if addr_type == NIC_BIND:
            if not has_set_bind:
                pass
            if af == IP6:
                nic_str = str(dest["nic"]).lower().split("%")[0]
                if not nic_str.startswith("fe80:"):
                    return dest["nic"]
            if not (same_pc or same_lan):
                continue
            return dest["nic"]

    # No compatible addresses.
    return None


def sort_pairs_by_overlap(srcs, dests):
    """Partition (src, dest) pairs into overlapping and non-overlapping external IPs.

    Pairs where either side has a missing/empty ``ext`` are placed in
    the unique bucket so they get filtered upstream in
    ``get_if_infos_order`` (the EXT_BIND filter drops them; the
    NIC_BIND / LOOPBACK_BIND paths don't rely on ext anyway).
    """
    overlap = []
    unique = []
    for src in srcs:
        for dest in dests:
            pair = [src, dest]
            s_ext = src.get("ext")
            d_ext = dest.get("ext")
            if s_ext and d_ext and s_ext == d_ext:
                overlap.append(pair)
            else:
                unique.append(pair)

    return overlap, unique



def get_if_infos_order(af, route_type, src_map, dest_map):
    """
    Given a list of interface details
    for an address family indexed by interface
    offset return a list of them directly.

    EXT_BIND filter: pairs where either side lacks an ``ext`` IP or where
    both sides share the same ``ext`` (same router / same machine WAN)
    are dropped entirely.  Such pairs cannot produce a working external
    path -- traffic loops back at the router with no NAT mapping -- and
    they used to be returned at low priority, where plugins had to
    defensively detect them.  The role-election in plugins like
    random_probe also depends on the two sides having distinct ext IPs
    to break the NAT-type tie symmetrically; an equal-ext combo races
    both peers into the same role.
    """
    srcs = list(src_map[af].values())
    dests = list(dest_map[af].values())

    # Given two lists of interface details, break them into
    # two lists of (src, dest) pairs. The first
    # contains pairs for which both interface details have the
    # same ext (external address). The other is non-overlapping,
    # where both have different addresses.
    overlap, unique = sort_pairs_by_overlap(srcs, dests)

    # If the route type is external then using the same external
    # address for overlapping pairs is likely not to lead to
    # a connection since both are behind the same router.  Also drop
    # pairs where either side has no ext IP at all -- without ext we
    # have nothing for the peer to aim at, and downstream plugins'
    # election math (own_ext_ip vs peer_ext_ip) would have to special-
    # case the empty value.
    if route_type in (EXT_BIND, None):
        unique = [
            pair for pair in unique
            if pair[0].get("ext") and pair[1].get("ext")
        ]
        pair_order = unique

    # For local addresses you want to do the opposite.
    # So you're on the same LAN or NIC if on the same machine.
    if route_type == NIC_BIND:
        pair_order = overlap + unique

    # LOOPBACK_BIND is a same-machine path (both sides have a
    # loopback alias attached). Same priority as NIC_BIND --
    # overlap first since same-machine pairs typically share the
    # ext too.
    if route_type == LOOPBACK_BIND:
        pair_order = overlap + unique

    return pair_order


def try_unpack_msg(buf, sk, sig_proto_map):
    """Decrypt (if needed) and deserialise an incoming signal buffer into a protocol message.

    Wire layout (after stripping the encryption framing):

        [name_len: 1 byte][wire_name: ASCII][JSON payload]

    The wire_name is looked up against sig_proto_map (keys are the
    same strings plugins register via PROTO_MESSAGES) to find the
    receiver-side msg_class. Replaces the old single-byte enum so
    plugins never have to coordinate enum allocation.
    """
    buf = h_to_b(buf)

    if len(buf) < 1:
        raise ValueError("try_unpack_msg: empty payload")

    # Try to decrypt message if its encrypted.
    is_enc = buf[0]
    if is_enc:
        # Ensure a SK is set for decryption.
        if not sk:
            raise ValueError("No sk set for decryption.")

        # Will raise if it can't decrypt.
        buf = decrypt(sk, buf[1:])
        log(fstr("Recv decrypted {0}", (buf,)))

    # Otherwise buffer is not encrypted -- use as is.
    if not is_enc:
        buf = buf[1:]

    # Read length-prefixed wire_name + look up the class.
    if len(buf) < 1:
        raise ValueError("try_unpack_msg: empty payload")
    name_len = buf[0]
    if len(buf) < 1 + name_len:
        raise ValueError(
            "try_unpack_msg: truncated wire_name (len={0}, buf={1})".format(
                name_len, len(buf),
            )
        )
    wire_name = bytes(buf[1:1 + name_len]).decode("ascii", errors="replace")
    msg_info = sig_proto_map.get(wire_name)
    if msg_info is None:
        raise ValueError(
            "try_unpack_msg: unknown wire_name {0!r}".format(wire_name)
        )
    msg_class = msg_info[0]
    msg = msg_class.unpack(buf[1 + name_len:])
    return msg


def sig_msg_to_buf(msg, dest_pk):
    """Serialise a signal message, optionally encrypting it with the destination's public key."""
    if dest_pk:
        buf = b"\1" + encrypt(dest_pk, msg.pack())
    else:
        buf = b"\0" + msg.pack()

    # UTF-8 messes up binary data in MQTT.
    buf = to_h(buf)
    return to_b(buf)


def close_plugin(plugin, plugins, inbound_pipes):
    """Release plugin resources and remove it from registries.

    Safe to call multiple times (pop is a no-op when the key is absent).
    Registry pop is intentionally deferred until here (not at result.done()
    time) to avoid the race where a follow-up PunchMsg signal arrives
    between the done() check and the pop and finds an empty registry slot,
    spawning a duplicate engine that collides on the same predicted ports.
    By the time close_plugin is called the result is already resolved so no
    further signals for this plugin_id are in-flight.
    """
    plugin_id = getattr(plugin, "plugin_id", None)
    log("[CLOSE-PLUGIN] enter plugin_id={0} result_done={1}".format(
        plugin_id, plugin.result.done(),
    ))
    plugins.pop(plugin_id, None)

    fut = inbound_pipes.pop(plugin_id, None)
    if fut is not None and not fut.done():
        fut.cancel()

    if not plugin.result.done():
        log("[CLOSE-PLUGIN] cancelling plugin.result plugin_id={0}".format(plugin_id))
        plugin.result.cancel()

    close_fn = getattr(plugin, "close", None)
    if close_fn is not None:
        try:
            asyncio.wait_for(close_fn(), timeout=5.0)
        except (asyncio.TimeoutError, OSError):
            log_exception()
        except asyncio.CancelledError:
            raise
