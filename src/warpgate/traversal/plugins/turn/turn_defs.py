"""Constants and helper functions for the TURN protocol."""

# Config variables -------------------------------------

TURN_MAX_RETRANSMITS = 5
TURN_MAIN_REPLY_TIMEOUT = 5

# secs - Turn recommends 1 minute before expiry.
TURN_REFRESH_EXPIRY = 600
TURN_MAX_DICT_LEN = 1000
TURN_MAX_RECV_PACKETS = 100

#########################################################
# RFC 5389 magic cookie + XOR template live in aionetiface
# (STUN_MAGIC_COOKIE / STUN_MAGIC_XOR in stun_defs.py).  Local
# redefinitions were dead code; import from stun_defs if needed.
TURN_CHANNEL = b"\x40\x02\x00\x00"
TURN_PROTOCOL_TCP = b"\x06\x00\x00\x00"
TURN_PROTOCOL_UDP = b"\x11\x00\x00\x00"
TURN_CHAN_RANGE = [16384, 32766]

# Protocol state machine.
# With convenient lookup values.
TURN_NOT_STARTED = 1
TURN_TRY_ALLOCATE = 2
TURN_ALLOCATE_FAILED = 3
TURN_TRY_REQ_TRANSPORT = 4
TURN_REQ_TRANSPORT_FAILED = 5
TURN_TRY_REFRESH = 6
TURN_REFRESH_DONE = 7
TURN_REFRESH_FAIL = 8
TURN_ERROR_STOPPED = 9


