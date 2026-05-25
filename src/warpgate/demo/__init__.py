"""Interactive demo application sub-package."""
from ..node.node_utils import make_stop_pair

# A single shutdown socketpair shared across the demo's cooperating modules
# (__main__, utils, menu). Created once at package import time so every demo
# helper can read the same stop signal the signal handler writes to.
stop_rw = make_stop_pair()
