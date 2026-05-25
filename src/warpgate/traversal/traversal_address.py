"""Address resolution helpers used during NAT traversal."""
import asyncio
from aionetiface import log


async def get_updated_addr_from_mqtt(node, dest_bytes):
    """Ask the peer for its freshest address bytes via the get_addr plugin over MQTT."""
    af = None  # AF selection is handled inside connect().
    route_type = None
    plugin = await node.connect(af, route_type, dest_bytes, "get_addr")
    try:
        updated_bytes = await asyncio.wait_for(plugin.result, timeout=10)
    except asyncio.TimeoutError:
        log("get_updated_addr_from_mqtt timed out waiting for reply")
        return None
    except asyncio.CancelledError:
        # Same lifecycle distinction as auto_connect.attempt_one_combo:
        # only propagate if the OUTER task is being cancelled.  If the
        # cleanup loop cancelled plugin.result internally, treat as a
        # failed-but-recoverable fetch and return None so the caller
        # (typically node-startup address refresh) carries on.
        try:
            cancelled_internally = plugin.result.cancelled()
        except AttributeError:
            cancelled_internally = False
        if not cancelled_internally:
            raise
        log("get_updated_addr_from_mqtt: plugin.result cancelled internally")
        return None
    finally:
        try:
            await plugin.close()
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
    return updated_bytes
