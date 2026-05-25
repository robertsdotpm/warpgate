"""Constants and data structures for the punch engine."""
from aionetiface import dict_child, NET_CONF

# Punch modes.
TCP_PUNCH_LAN = 1
TCP_PUNCH_REMOTE = 2
TCP_PUNCH_SELF = 3

# Connection timing.  Shared by boundary_lib (FAST_PUNCH_PARAMS),
# tcp_punch_engine (spray + monitor windows), and udp_punch_engine
# (UDP RETRY_INTERVAL).
CONNECT_TIMEOUT = 5.0
RETRY_INTERVAL = 0.05

# NTP rendezvous.  Used by punch_utils.fetch_ntp_time to bound the
# pool.ntp.org round-trip and convert the response to a Unix epoch.
NTP_SERVER = "pool.ntp.org"
NTP_PORT = 123
NTP_DELTA = 2208988800  # 70-year offset between NTP epoch (1900) and Unix epoch (1970)
NTP_PACKET_SIZE = 48
MAX_NTP_RETRIES = 5
NTP_TIMEOUT = 1.0

PUNCH_ALIVE = b"234o2jdjf\n"
PUNCH_END = b"qwekl2k343ok\n"
INITIATED_PREDICTIONS = 1
RECEIVED_PREDICTIONS = 2
UPDATED_PREDICTIONS = 3
INITIATOR = 1
RECIPIENT = 2

# Number of seconds in the future from an NTP time
# for hole punching to occur.
PUNCH_MAX_SLEEP = 3
NTP_MEET_STEP = 6

# Fine tune various network settings.
PUNCH_CONF = dict_child(
    {
        # Reuse address tuple for bind() socket call.
        "reuse_addr": True,
        # Return the sock instead of the base proto.
        # "sock_only": True,
        # Disable closing sock on error
        # Applies to the pipe_open only (may not be needed.)
        "do_close": False,
    },
    NET_CONF,
)


class PortAlloc:
    """Holds a source/destination port pair for a single TCP hole-punch attempt."""

    def __init__(self, src_port, dest_port):
        self.src_port = src_port
        self.dest_port = dest_port

    def __iter__(self):
        yield self.src_port
        yield self.dest_port
