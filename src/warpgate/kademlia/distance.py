"""XOR distance + leading-zero / common-prefix helpers.

Kademlia keys are fixed-length byte strings (for libp2p Kad: 32
bytes = SHA-256 of the marshalled PublicKey).  The XOR metric:

    d(a, b) = int(a) XOR int(b)

induces a total ordering on the keyspace such that
``d(a, b) <= d(a, c)`` iff ``a XOR b <= a XOR c`` as 256-bit ints.

The routing table indexes buckets by the *common prefix length*
(CPL) of two keys -- how many leading bits they share.  Bucket i
holds peers whose XOR-distance from us falls in
``[2^(L-i-1), 2^(L-i))`` where L is the key bit-length.

This module is keyspace-agnostic: it works for any equal-length
byte keys.  Callers normalise their keys (libp2p: SHA-256 of
PeerID multihash) before passing them in.
"""


def xor_distance(a, b):
    """Return XOR distance between two equal-length byte strings as an int.

    Raises ValueError if lengths differ -- mixing keyspaces is a
    programming error, not a runtime condition.
    """
    if len(a) != len(b):
        raise ValueError("xor_distance: key lengths differ ({0} vs {1})".format(len(a), len(b)))
    return int.from_bytes(bytes(x ^ y for x, y in zip(a, b)), "big")


def common_prefix_length(a, b):
    """Return the number of leading BITS that ``a`` and ``b`` share."""
    if len(a) != len(b):
        raise ValueError("common_prefix_length: key lengths differ")
    cpl = 0
    for x, y in zip(a, b):
        if x == y:
            cpl += 8
            continue
        # Differ in this byte -- count leading equal bits of (x XOR y).
        diff = x ^ y
        # Most significant bit of diff is where they first differ.
        bit = 7
        while bit >= 0 and not (diff & (1 << bit)):
            cpl += 1
            bit -= 1
        break
    return cpl
