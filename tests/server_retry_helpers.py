"""Shim — canonical home is aionetiface.testing.

`with_server_retry` / `try_servers` / `TRANSIENT_SERVER_ERRORS` were
previously duplicated near-byte-for-byte in this file AND in
namebump/tests/server_retry_helpers.py.  Lifted to aionetiface.testing
so both downstreams import from one place.
"""
from aionetiface.testing import (  # noqa: F401
    TRANSIENT_SERVER_ERRORS,
    with_server_retry,
    try_servers,
)

# Backwards-compat alias for the older constant name.
TRANSIENT_ERRORS = TRANSIENT_SERVER_ERRORS
