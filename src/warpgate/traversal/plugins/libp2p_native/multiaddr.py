"""Minimal libp2p multiaddr encoder/decoder.

We need just enough multiaddr to emit and parse:

    /ip4/<v4>/tcp/<port>
    /ip6/<v6>/tcp/<port>
    /ip4/<v4>/tcp/<port>/p2p/<peer_id_b58>
    /ip4/<v4>/tcp/<port>/p2p/<relay_id>/p2p-circuit/p2p/<dst_id>

Multiaddr wire format: a sequence of (protocol_code: varint,
addr_bytes...) tuples, where some protocols (ip4, ip6, tcp, p2p)
have known fixed or length-prefixed sizes.

Protocol codes from the multicodec table:
    4    = ip4    (4 bytes)
    41   = ip6    (16 bytes)
    6    = tcp    (2 bytes BE)
    421  = p2p    (length-prefixed multihash bytes)
    290  = p2p-circuit (no addr)

This module deliberately implements ONLY the subset above -- enough
for the Identify listenAddrs field and the Circuit Relay v2
multiaddr forms.
"""
import ipaddress
import socket
import struct

from . import varint


CODE_IP4 = 4
CODE_TCP = 6
CODE_IP6 = 41
CODE_P2P_CIRCUIT = 290
CODE_P2P = 421


def encode_ip_tcp(ip_str, port):
    """Encode /ip4/<v4>/tcp/<port> or /ip6/<v6>/tcp/<port> as bytes."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError as e:
        raise ValueError("encode_ip_tcp: bad IP {0}: {1}".format(ip_str, e))
    if addr.version == 4:
        out = varint.encode(CODE_IP4) + socket.inet_pton(socket.AF_INET, ip_str)
    else:
        # Drop any %zone suffix (zone IDs are not part of multiaddr).
        clean = ip_str.split("%", 1)[0]
        out = varint.encode(CODE_IP6) + socket.inet_pton(socket.AF_INET6, clean)
    out += varint.encode(CODE_TCP) + struct.pack(">H", port)
    return out


def encode_p2p(peer_id_bytes):
    """Encode a /p2p/<peer_id> segment.

    The wire form is varint(421) followed by length-prefixed
    peer_id multihash bytes.  Caller passes the binary multihash
    (NOT base58-encoded).
    """
    return (
        varint.encode(CODE_P2P)
        + varint.encode(len(peer_id_bytes))
        + bytes(peer_id_bytes)
    )


def encode_p2p_circuit():
    """Encode the bare /p2p-circuit marker segment."""
    return varint.encode(CODE_P2P_CIRCUIT)


def decode(buf):
    """Decode a multiaddr to a list of (code, value) tuples.

    Lengths for ip4/ip6/tcp are fixed; p2p is varint-length-prefixed;
    p2p-circuit has no payload.  Unknown protocol codes raise so we
    don't silently misinterpret addresses we haven't agreed to
    support.
    """
    out = []
    pos = 0
    end = len(buf)
    while pos < end:
        code, pos = varint.decode_from(buf, pos)
        if code == CODE_IP4:
            if pos + 4 > end:
                raise ValueError("multiaddr: truncated ip4")
            out.append((CODE_IP4, socket.inet_ntop(socket.AF_INET, buf[pos:pos + 4])))
            pos += 4
        elif code == CODE_IP6:
            if pos + 16 > end:
                raise ValueError("multiaddr: truncated ip6")
            out.append((CODE_IP6, socket.inet_ntop(socket.AF_INET6, buf[pos:pos + 16])))
            pos += 16
        elif code == CODE_TCP:
            if pos + 2 > end:
                raise ValueError("multiaddr: truncated tcp")
            out.append((CODE_TCP, struct.unpack(">H", buf[pos:pos + 2])[0]))
            pos += 2
        elif code == CODE_P2P:
            length, pos = varint.decode_from(buf, pos)
            if pos + length > end:
                raise ValueError("multiaddr: truncated p2p")
            out.append((CODE_P2P, bytes(buf[pos:pos + length])))
            pos += length
        elif code == CODE_P2P_CIRCUIT:
            out.append((CODE_P2P_CIRCUIT, None))
        else:
            raise ValueError("multiaddr: unsupported code {0}".format(code))
    return out


def to_text(parts):
    """Render a decoded multiaddr (list of tuples) as the canonical text form.

    Used for logging.  ``parts`` is the output of ``decode``.
    """
    from .peer_id import peer_id_to_b58
    out = []
    for code, value in parts:
        if code == CODE_IP4:
            out.append("/ip4/" + value)
        elif code == CODE_IP6:
            out.append("/ip6/" + value)
        elif code == CODE_TCP:
            out.append("/tcp/" + str(value))
        elif code == CODE_P2P:
            out.append("/p2p/" + peer_id_to_b58(value))
        elif code == CODE_P2P_CIRCUIT:
            out.append("/p2p-circuit")
    return "".join(out)
