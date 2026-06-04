"""Shared helpers for the gate_* / *_sweep CLI tools.

Both gate_listen.py and gate_connect.py parsed the WG_AFS env var
with near-identical bodies (return-type drift: ints vs IP4/IP6).
Both gate_connect.py and gate_connect_pinned.py defined the same
"first message" closure inside their echo logic.  Centralised here
so future divergence is visible at one site.
"""
import asyncio


def parse_afs(env_value):
    """Parse WG_AFS env: '4' / '6' / '4,6' / unset -> None (no expectation).

    Returns a tuple of plain ints (4, 6) or None.  Callers that need
    aionetiface's IP4 / IP6 constants instead can map after this call.
    """
    if not env_value:
        return None
    out = []
    for tok in env_value.replace(" ", "").split(","):
        if tok == "4":
            out.append(4)
        elif tok == "6":
            out.append(6)
    return tuple(out) if out else None


def first_msg(link, timeout):
    """Await one message from *link* (any async-iterable), bounded by *timeout*.

    Centralises the tiny ``async for m in link: return m`` closure that
    gate_connect.py and gate_connect_pinned.py both inlined.
    """
    def inner():
        for m in link:
            return m

    return asyncio.wait_for(inner(), timeout=timeout)
