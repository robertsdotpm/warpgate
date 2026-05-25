"""Graceful shutdown logic for a warpgate node."""
import asyncio
import glob
import os
from contextlib import suppress
from aionetiface import log, log_exception, Daemon, AlreadyClosedError


def cleanup_stale_pidfiles(install_path):
    """Delete *_pid.txt files in install_path whose locks aren't held.

    The daemon writes one pidfile per (af, proto, port, ip) listener
    and uses InterProcessLock to detect zombie servers on restart.
    On a clean shutdown the lock is released but the file persists,
    accumulating stale entries over many runs.  This sweep tries to
    reacquire each lock non-blockingly: success means no live process
    holds it, so the file is safe to remove; failure means another
    warpgate instance still owns it and we leave it alone.
    """
    try:
        from aionetiface.vendor.fasteners import InterProcessLock
    except ImportError:
        return

    try:
        candidates = glob.glob(os.path.join(install_path, "*_pid.txt"))
    except OSError:
        log_exception()
        return

    for path in candidates:
        try:
            lock = InterProcessLock(path)
            if lock.acquire(blocking=False):
                try:
                    lock.release()
                except OSError:
                    log_exception()
                try:
                    os.unlink(path)
                except OSError:
                    log_exception()
        except OSError:
            log_exception()


# Canonical home of close_helper / close_with_timeout is
# aionetiface.utility.cleanup; re-exported here so existing
# `from .node_stop import close_helper` callers keep working.
from aionetiface.utility.cleanup import (  # noqa: F401, E402
    close_helper, close_with_timeout,
)


# Shutdown the node server and do cleanup.
async def node_stop(node):
    """Shut down the node, closing traversal plugins, resources, the daemon, and the stop socket pair."""
    import time as time_mod
    log("[NODE-STOP] mono={0:.4f} node_stop entered".format(
        time_mod.monotonic()
    ))
    # Send stop signal (any amount of data.)
    try:
        node.stop_writer.send(b"Meow")
    except OSError:
        pass

    # Stop error logging thread.
    log(None)

    # Close all pipes stored in plugins.
    traversal_plugins = (
        node.traversal.plugins
        if getattr(node, "traversal", None) is not None
        else {}
    )
    for pipe_id in traversal_plugins:
        plugin = traversal_plugins[pipe_id]
        result = plugin.result
        if isinstance(result, asyncio.Future):
            if result.cancelled():
                continue

            if result.done():
                try:
                    pipe = result.result()
                except BaseException:
                    # Plugin future completed with an exception; nothing to close.
                    continue
                if hasattr(pipe, "close"):
                    try:
                        await close_with_timeout(pipe)
                    except (OSError, asyncio.TimeoutError):
                        pass
            else:
                result.cancel()

    if getattr(node, "resources", None):
        await node.resources.close()

    # Close the traversal manager's background signal-handler tasks.
    traversal = getattr(node, "traversal", None)
    if traversal is not None and hasattr(traversal, "close"):
        await traversal.close()

    # Close the MQTT router and its background dispatcher tasks. Without this,
    # dispatcher coroutines from each MQTTClient stay pending after node_stop
    # and hang the test runner's final asyncio.gather on cancelled tasks.
    router = getattr(node, "router", None)
    if router is not None and hasattr(router, "close"):
        try:
            await asyncio.wait_for(router.close(), timeout=4)
        except asyncio.TimeoutError:
            log("Timeout closing node.router")

    # Stop node server (Daemon.close closes all listener pipes).
    # Using Daemon.close(node) directly rather than super(node.__class__, node).close()
    # because the super() pattern breaks if Node is ever subclassed: super(SubClass, node)
    # would resolve to Node, calling node_stop() again and looping infinitely.
    await Daemon.close(node)

    # Close the stop-signal socket pair.
    for sock in (
        getattr(node, "stop_reader", None),
        getattr(node, "stop_writer", None),
    ):
        if sock is not None:
            with suppress(Exception):
                sock.close()
    node.stop_reader = None
    node.stop_writer = None

    install_path = getattr(node, "install_path", None)
    if install_path:
        cleanup_stale_pidfiles(install_path)

    log("stop node () ending")
