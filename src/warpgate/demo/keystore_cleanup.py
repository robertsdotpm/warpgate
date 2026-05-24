"""Prompt the user to delete stale keystore entries when the PNP
server's per-IP quota is exhausted.

When ``setup_node`` catches ``PnpServerResourceLimit``, it calls
``prompt_keystore_cleanup`` from here.  We list every ``*.json`` file
under ``~/aionetiface/`` that looks like a keystore (i.e. has the
expected ``{pnp_name, priv_key_hex}`` shape), let the user pick one /
all / cancel, and for each chosen entry:

  1. Sign a DELETE request with the file's keypair so the PNP server
     actually frees that quota slot (otherwise the names just age out
     on the 30-day clock).
  2. Unlink the local keystore file.

We deliberately use a fresh ``namebump.Client`` rather than the
node's ``nick_client`` because the node failed to start when the
quota tripped, so its client isn't fully wired up.
"""
from __future__ import print_function
import json
import os

from aionetiface import IP4, PNP_SERVERS
from aionetiface.keystore import KEYSTORE_DIR
from ecdsa import SECP256k1, SigningKey

from .utils import ainput, cout


# Files in ~/aionetiface/ that aren't keystores and must be skipped.
KEYSTORE_DIR_BLACKLIST = {
    "servers.json",
    "servers.json.dealer_state",
    "servers.json.tmp",
    "logs",
}


def discover_keystore_entries():
    """Return [(pnp_name, priv_key_hex, path), ...] for every valid
    keystore JSON under KEYSTORE_DIR.  Silently skips files that
    don't parse or don't look like keystores."""
    if not os.path.isdir(KEYSTORE_DIR):
        return []
    out = []
    for fn in sorted(os.listdir(KEYSTORE_DIR)):
        if fn in KEYSTORE_DIR_BLACKLIST:
            continue
        if not fn.endswith(".json"):
            continue
        path = os.path.join(KEYSTORE_DIR, fn)
        try:
            with open(path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        pnp_name = data.get("pnp_name")
        priv_hex = data.get("priv_key_hex")
        if not pnp_name or not priv_hex:
            continue
        out.append((pnp_name, priv_hex, path))
    return out


async def delete_from_pnp(nic, sys_clock, pnp_name, priv_hex):
    """Sign a DELETE for pnp_name against the configured PNP server
    using the keypair from priv_hex.  Returns True on success."""
    # Local imports keep this module cheap to import even when
    # cleanup never gets called.
    from namebump.client import Client
    from namebump.keypair import Keypair

    pnp_info = PNP_SERVERS[IP4][0]
    pnp_dest = (pnp_info["ip"], pnp_info["port"])
    pnp_pk = bytes.fromhex(pnp_info["pk"])
    sk = SigningKey.from_string(bytes.fromhex(priv_hex), curve=SECP256k1)
    kp = Keypair(priv=sk)

    client = await Client(pnp_dest, pnp_pk, sys_clock, nic)
    # Single-PNP-server deployment uses ".p2p" as the TLD.  If we
    # ever go multi-server we'll need to thread the active TLD
    # through; for now this matches what derive_default_pnp_name +
    # registration use.
    full_name = pnp_name + ".p2p"
    await client.delete(full_name, kp)


async def prompt_keystore_cleanup(nic, sys_clock):
    """Interactive cleanup flow.  Returns True if anything was
    deleted (caller can re-attempt setup), False otherwise."""
    entries = discover_keystore_entries()
    if not entries:
        cout()
        cout("PNP server quota looks exhausted, but no local keystore "
             "files were found under {0} -- nothing to clean up.".format(
                 KEYSTORE_DIR,
             ))
        cout("The names are likely held by another machine sharing your "
             "WAN IP.  They will age out automatically on the 30-day "
             "expiry clock.")
        return False

    cout()
    cout("PNP server quota exhausted for your source IP.")
    cout("Found {0} local keystore file(s); each one corresponds to a "
         "previously-registered nickname:".format(len(entries)))
    for i, (name, _, _) in enumerate(entries, 1):
        cout("  [{0}] {1}".format(i, name))
    cout()
    cout("Type a number to delete one entry, 'all' to delete all,")
    cout("or anything else to cancel.")

    try:
        response = (await ainput("Choice: ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False

    to_delete = []
    if response == "all":
        to_delete = list(entries)
    elif response.isdigit():
        idx = int(response) - 1
        if 0 <= idx < len(entries):
            to_delete = [entries[idx]]
    if not to_delete:
        cout("Cancelled.")
        return False

    cleaned = 0
    for pnp_name, priv_hex, path in to_delete:
        # PNP-side delete: best-effort.  If it fails (network, already
        # gone, signature mismatch) we still want to nuke the local
        # keystore file so the user isn't blocked.
        try:
            await delete_from_pnp(nic, sys_clock, pnp_name, priv_hex)
            cout("Deleted '{0}' from PNP server.".format(pnp_name))
            cleaned += 1
        except Exception as exc:  # pylint: disable=broad-except
            cout("Could not delete '{0}' from PNP server: {1}".format(
                pnp_name, type(exc).__name__,
            ))
        try:
            os.unlink(path)
            cout("Removed keystore file: {0}".format(path))
        except OSError as exc:
            cout("Could not remove {0}: {1}".format(path, exc))

    cout()
    cout("Done.  Restart warpgate.demo to retry registration.")
    return cleaned > 0
