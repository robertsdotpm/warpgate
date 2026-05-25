"""Constants, data-structures, and defaults for a warpgate node."""

NODE_PORT = 10001

# No more than n signal pipes to send signals to nodes.
SIGNAL_PIPE_NO = 1


NODE_CONF = {
    "reuse_addr": False,
    "enable_upnp": True,
    "sig_pipe_no": SIGNAL_PIPE_NO,
    "install_path": None,
    "init_clock_skew": True,
    "enable_punching": True,
    "enable_nickname": True,
    "enable_stun_clients": True,
}

NODE_TEST_CONF = {
    # SO_REUSEADDR=True for tests so back-to-back runs can rebind the
    # same listen port even when the previous run's socket is still
    # in TIME_WAIT (Linux holds it ~60s, longer than the gap between
    # two consecutive test subprocesses). Production NODE_CONF keeps
    # this False so an accidentally double-started node fails fast
    # instead of silently shadowing an existing one.
    "reuse_addr": True,
    "enable_upnp": False,
    "sig_pipe_no": 0,
    "install_path": None,
    "init_clock_skew": False,
    "enable_punching": True,
    "enable_nickname": False,
    "enable_stun_clients": False,
}
