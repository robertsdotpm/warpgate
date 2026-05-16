"""Wire-format constants for the UDP punch CONFIRM probe.

The UDP punch engine fires datagrams at every predicted (peer_ext_ip,
peer_ext_port) tuple and listens on every locally-bound src_port for
inbound. To distinguish a real peer-from-NAT-mapping arrival from
random internet scanner traffic / NAT misroute, every probe carries a
fixed magic prefix + a session nonce both sides agreed on via the
PunchMsg exchange. CONFIRM is the second-leg ack: the receiver sees a
probe, fires CONFIRM back on the same 4-tuple, and the originator
locks the socket as the winner.

Frame layout (all big-endian):

    [0:4]   MAGIC = b"P2UP"
    [4]     KIND  -- 0x01 PROBE, 0x02 CONFIRM
    [5:21]  16-byte session nonce (must equal PunchMsg.nonce)

Total length: 21 bytes. The validator drops any datagram that doesn't
exactly match length + magic + matching nonce so application traffic
sharing the post-punch socket is not interfered with.
"""

UDP_PUNCH_MAGIC = b"P2UP"
UDP_PUNCH_KIND_PROBE = 0x01
UDP_PUNCH_KIND_CONFIRM = 0x02
UDP_PUNCH_NONCE_LEN = 16
UDP_PUNCH_FRAME_LEN = 4 + 1 + UDP_PUNCH_NONCE_LEN  # 21


# udp_punch's own punch-timing params, independent of tcp_punch's
# FAST_PUNCH_PARAMS.  udp_punch used to import FAST_PUNCH_PARAMS
# directly -- but PunchClient stores `self.params = params` by
# reference, so a single module-level dict shared between the two
# plugins means either plugin's PunchClient can mutate timing the
# other reads, and any retune of FAST_PUNCH_PARAMS for tcp_punch
# silently changes udp_punch too.  A separate dict decouples them.
#
# Values are the PRE-tightening profile -- the timings udp_punch ran
# the matrix on historically (full_sweep_v4 9/9):
#   window=10 / max_clock_error=4 / min_run_window=3 -- the bucket
#     rendezvous udp_punch's compute_rendezvous path was designed for;
#     worst-case wait = window + max_clock_error = 14 s.
#   connect_timeout / monitor_timeout = 3.0 -- udp_punch's 18-socket
#     50 Hz spray flaked at 2.0 s on busy hosts (executor thread
#     couldn't keep up under MQTT churn); 3.0 s was the fix.  The
#     1.5 s tcp_punch tightened to is a tcp_punch-only profile.
# tcp_punch's FAST_PUNCH_PARAMS stays tight; udp_punch stays on the
# proven profile until its own optimisation pass is redone.
from ..tcp_punch.boundary_lib import derive_max_sleep  # noqa: E402

UDP_PUNCH_PARAMS = {
    "window": 10,
    "max_clock_error": 4,
    "min_run_window": 3,
    "connect_timeout": 3.0,
    "monitor_timeout": 3.0,
    "retry_interval": 0.05,
    "reply_delay": 2,
}
# derive_max_sleep(10, 4) = 10 + 4 + 2 slack = 16, matching the old
# hard-coded max_sleep=16 in the pre-session FAST_PUNCH_PARAMS.
UDP_PUNCH_PARAMS["max_sleep"] = derive_max_sleep(
    UDP_PUNCH_PARAMS["window"], UDP_PUNCH_PARAMS["max_clock_error"],
)


def build_frame(kind, nonce):
    """Build a 21-byte UDP punch frame for the given kind + nonce."""
    if len(nonce) != UDP_PUNCH_NONCE_LEN:
        raise ValueError("nonce must be {0} bytes".format(UDP_PUNCH_NONCE_LEN))
    return UDP_PUNCH_MAGIC + bytes([kind]) + nonce


def parse_frame(buf):
    """Parse a UDP punch frame; returns (kind, nonce) or (None, None) on mismatch.

    Used by the engine to filter inbound datagrams: anything that
    doesn't match length+magic is application traffic that should
    pass through to the wrapping Pipe untouched.
    """
    if len(buf) != UDP_PUNCH_FRAME_LEN:
        return (None, None)
    if buf[:4] != UDP_PUNCH_MAGIC:
        return (None, None)
    return (buf[4], buf[5:5 + UDP_PUNCH_NONCE_LEN])
