"""Interactive menu system for the warpgate demo."""
import asyncio
from aionetiface import (
    SUB_ALL,
    async_wrap_errors, fstr, log, log_exception, sock_has_data,
)
from ..traversal.traversal_utils import close_plugin
from ..node.auto_connect import auto_connect
from ..node.nickname import (
    FullNameFailure, PnpServerResourceLimit, PnpServerUnreachable,
)
from . import stop_rw
from .utils import (
    ainput, choose_address_families, choose_connection_methods,
    choose_pathways, cout, echo_client, get_dest_addr,
)


# Open a tunnel to a remote destination.
# Accepts a PNP address or a full node address.
async def connect_option(node, con_opts):
    """Open a P2P tunnel to a remote address and run an interactive echo session."""
    # Some variables set by command line flags or other parts.
    last_addr, echo_data, cmd_opts = con_opts
    con_method = pathway = addr_type = None
    if cmd_opts:
        _, con_method, pathway, addr_type = cmd_opts

    # Dest addr is already set from command line.
    if isinstance(last_addr, str):
        dest_addr = last_addr
    else:
        dest_addr = await get_dest_addr(node, last_addr)

    # Self-connect guard. The cascade has no native "same machine,
    # same NIC, same identity" path -- punching to yourself fails in
    # confusing ways (your own STUN reflection becomes the dest, NAT
    # mappings collide on the kernel) and the symptoms look like
    # generic plugin failures rather than "you can't punch to
    # yourself". Catch the common shapes up front and tell the user
    # what to do instead.
    self_names = set()
    full = getattr(node, "full_name", None)
    if full:
        self_names.add(full)
        # Allow comparing without the TLD too.
        if "." in full:
            self_names.add(full.split(".", 1)[0])
    pnp = getattr(node, "pnp_name", None)
    if pnp:
        self_names.add(pnp)
    dest_str = dest_addr if isinstance(dest_addr, str) else None
    own_bytes = getattr(node, "addr_bytes", None)
    is_self = False
    if dest_str and dest_str.strip() in self_names:
        is_self = True
    if own_bytes is not None and dest_addr == own_bytes:
        is_self = True
    if is_self:
        cout()
        cout("That's this node's own address -- warpgate can't")
        cout("punch a hole to itself (your STUN reflection becomes")
        cout("the destination and the kernel's NAT mapping collides")
        cout("with itself).")
        cout()
        cout("To test locally, open a SECOND terminal on this machine")
        cout("with a DIFFERENT --nic (or a different --ip alias on the")
        cout("same NIC), e.g.:")
        cout()
        cout("    python3 -m warpgate.demo --nic <other-nic-name>")
        cout()
        cout("then connect this node to the other's nickname.")
        return "menu"

    # Get connect cmd segments manually if not set.
    plugin_name = await choose_connection_methods(con_method)
    if plugin_name == "menu":
        return "menu"

    # auto_connect skips the AF/pathway prompts entirely.
    if plugin_name == "auto_connect":
        cout()
        cout("Auto-connecting... Please wait...")
        try:
            pipe, plugin = await auto_connect(node, dest_addr, protocol=None)
        except (OSError, ConnectionError, asyncio.TimeoutError) as e:
            cout("Auto-connect error: " + str(e))
            return "menu"

        if pipe is None:
            cout("Auto-connect failed: all strategies exhausted.")
            return "menu"

        cout("plugin result = " + str(pipe))
        cout(pipe.sock)
        pipe.subscribe(SUB_ALL)
        try:
            return await echo_client(pipe, echo_data)
        finally:
            await pipe.close()

    route_type = await choose_pathways(pathway)
    af = await choose_address_families(addr_type)
    if "menu" in (route_type, af):
        return "menu"

    # Data structure to control a tunnel to the remote host.
    cout()
    cout("Connection in progress... Please wait...")

    # Attempt to make the tunnel connection to the remote host.
    # Capture the plugin in the outer scope so we can cancel its punch task
    # if the attempt times out or fails, preventing stale subprocesses from
    # holding ports and poisoning the next attempt.
    # node.connect() runs outside async_wrap_errors so that validation
    # errors (e.g. same-IP sanity checks) surface immediately to the user
    # rather than being swallowed.  Only the actual network work
    # (plugin.result) is wrapped so connection timeouts and failures are
    # handled gracefully.
    try:
        plugin = await node.connect(af, route_type, dest_addr, plugin_name)
    except (OSError, ConnectionError, asyncio.TimeoutError) as e:
        cout("Connection error: " + str(e))
        return "menu"
    except FullNameFailure as e:
        # PNP lookup couldn't find the destination nickname on any
        # configured server. Either the name was never registered,
        # has expired, or was deleted.
        cout("Nickname not found: " + str(e))
        cout("Make sure the other peer is running and has registered "
             "this name.")
        return "menu"
    except PnpServerUnreachable as e:
        cout("PNP server unreachable: " + str(e))
        cout("Check your network connection and try again.")
        return "menu"
    except PnpServerResourceLimit as e:
        cout("PNP server reported a resource limit: " + str(e))
        return "menu"
    except LookupError as e:
        # resolve_pnp_addr raises LookupError when the PNP record is
        # missing on the server but the round-trip itself succeeded.
        cout("Nickname not found: " + str(e))
        return "menu"
    except ValueError as e:
        # node.connect raises ValueError for predictable user-input
        # mistakes -- e.g. picking NIC_BIND with a peer whose addr_map
        # claims our own NIC IP, or asking for an AF the peer doesn't
        # advertise. The validation message is the useful signal; the
        # full traceback is just noise in interactive use.
        cout("Cannot establish connection: " + str(e))
        return "menu"

    plugin_holder = [plugin]
    # Use the plugin's own configured timeout (set by TraversalManager
    # from the per-plugin PLUGIN_CONF["timeout"]) plus a small margin
    # for run_plugin's finally-block to resolve plugin.result.  With
    # the TM's finally guarantee, any failure -- caught, raised, or
    # silent early-return -- resolves the future immediately, so this
    # outer wait only hits its ceiling on a legitimate long success.
    pipe = await async_wrap_errors(plugin.result, timeout=plugin.timeout + 10)

    # Unconditional cleanup: cancels any still-running punch task and removes
    # the plugin from the traversal manager's registry.  On success the punch
    # task is already done so this is a fast no-op; on failure it terminates
    # the background subprocess and frees the ports for the next attempt.
    if plugin_holder[0] is not None:
        await close_plugin(
            plugin_holder[0],
            node.traversal.plugins,
            node.traversal.inbound_pipes,
        )

    try:
        if pipe is None:
            cout("Connection failed.")
            return "menu"

        cout("plugin result = ", pipe)
        cout(pipe.sock)
        # Message queuing isn't enabled by default when callbacks
        # are setup for pipe methods so this says to queue
        # all messages received so they can be awaited.
        pipe.subscribe(SUB_ALL)
        return await echo_client(pipe, echo_data)
    finally:
        if pipe:
            await pipe.close()

    # Return to menu for unexpected code paths.
    return "menu"


async def accept_option(nick, node=None):
    """Wait in an accept loop, printing the node's PNP nickname, until a stop signal arrives.

    Awaits node.nat_classify_task (if present) BEFORE printing "Listen on
    PNP" so callers / scripted matrix runners that key off the
    nickname-printed marker don't race the background NAT classifier.
    classify_nat_background republishes the node addr if the measured
    NAT differs from the cached placeholder; a connector that resolves
    our nickname during that window picks up the stale addr and runs
    the punch with wrong NAT info -- predictions miss the wire, punch
    fails for non-obvious reasons.  Blocking the listener-side wait
    here gives every PNP-resolve a node addr that already reflects the
    real measured NAT.  No-op if node was not passed or the task is
    already done.
    """
    if node is not None:
        nct = getattr(node, "nat_classify_task", None)
        if nct is not None and not nct.done():
            print("\tWaiting for NAT classification to complete...", flush=True)
            try:
                await nct
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                # NAT classify is best-effort; surface failure but don't
                # block the listener if classification errored.  The cached
                # placeholder remains; punch may misfire but the listener
                # is still reachable.
                log_exception()

    print("\tListen on PNP: ", nick, flush=True)
    while not sock_has_data(stop_rw[0]):
        await asyncio.sleep(1)

    return "menu"


async def nickname_option(node):
    """Prompt for a nickname string and register it on the PNP network."""
    choice = await ainput("Enter nickname: ")
    try:
        ret = await node.nickname(choice)
        cout(fstr("Nickname registered = {0}", (str(ret),)))
    except (OSError, ConnectionError, asyncio.TimeoutError):
        cout("Nickname taken.")

    return "menu"


async def stop_nodes_option(nodes):
    """Gracefully shut down all provided nodes."""
    cout("")
    cout("Stopping nodes...")
    for n in nodes:
        try:
            await n.close()
        except (OSError, asyncio.TimeoutError):
            log("exception in stop nodes")
            log_exception()

    return ""


async def run_menu_program(
    nick,
    ifs,
    nodes,
    con_opts=None,
    menu_option=None,
):
    """Display the interactive menu and dispatch to the chosen option handler."""
    # Select menu program.
    menu_option = menu_option or (await ainput("Select menu option: "))
    menu_option = menu_option.lower().strip()

    # Connect to a remote host using PNP or full node address.
    if "connect:" and menu_option == "0":
        assert con_opts
        return await connect_option(nodes[0], con_opts)

    # Just run the event loop so cons can be accepted.
    # Just an asyncio sleep loop.
    if "accept:" and menu_option == "1":
        # NOTE: Blocking loop so won't return.
        # Pass node so accept_option can await its background NAT
        # classification before advertising the nickname; otherwise
        # scripted callers (--cmd 1 matrix runs) race the classifier
        # and any connector that resolves the nickname during that
        # window picks up a stale-NAT addr.
        return await accept_option(nick, node=nodes[0])

    # Set a new nickname for the primary node.
    if "nickname:" and menu_option == "2":
        return await nickname_option(nodes[0])

    # Close all nodes and exit the program.
    if "exit:" and menu_option in ("3", "exit", "quit"):
        return "exit"

    # Try again.
    return "menu"
