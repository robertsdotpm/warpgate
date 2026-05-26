"""Minimal hand-rolled protobuf encoder/decoder.

libp2p needs exactly two protobuf message shapes for /plaintext/2.0.0
+ /ipfs/id/1.0.0:

    PublicKey {
        KeyType Type = 1;  // enum: 0=RSA, 1=Ed25519, 2=Secp256k1, 3=ECDSA
        bytes Data = 2;
    }

    Exchange {
        bytes id = 1;       // PeerID, the multihash of the marshalled PublicKey
        PublicKey pubkey = 2;
    }

    Identify {
        string protocolVersion = 5;
        string agentVersion = 6;
        bytes publicKey = 1;
        repeated bytes listenAddrs = 2;
        repeated string protocols = 3;
    }

Rather than pulling in google.protobuf (Py3.5-incompatible) we encode
these shapes by hand.  The wire format is documented at
https://protobuf.dev/programming-guides/encoding/ -- this module
implements just the bits we need: varint, length-delimited, and
enums-as-varint.
"""
from . import varint


WIRE_VARINT = 0
WIRE_LEN = 2


def encode_tag(field_number, wire_type):
    """Return the encoded protobuf tag byte for (field_number, wire_type)."""
    return varint.encode((field_number << 3) | wire_type)


def encode_varint_field(field_number, value):
    """Encode a varint-typed field as tag + value."""
    return encode_tag(field_number, WIRE_VARINT) + varint.encode(value)


def encode_bytes_field(field_number, data):
    """Encode a length-delimited field as tag + length + data."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("pb_lite.encode_bytes_field: data must be bytes")
    return encode_tag(field_number, WIRE_LEN) + varint.encode(len(data)) + bytes(data)


def encode_string_field(field_number, s):
    """Encode a UTF-8 string field."""
    return encode_bytes_field(field_number, s.encode("utf-8"))


def encode_message_field(field_number, nested_bytes):
    """Encode a nested message field (length-delimited, contents are pre-marshalled)."""
    return encode_bytes_field(field_number, nested_bytes)


def parse_message(buf):
    """Parse a protobuf message into a dict of {field_number: [values...]}.

    Each value is either an int (WIRE_VARINT) or bytes (WIRE_LEN).
    Unknown wire types raise ValueError.  Repeated fields land as a
    list with multiple entries -- callers take the last for "scalar"
    or the whole list for repeated.

    We support only WIRE_VARINT and WIRE_LEN because every libp2p
    protobuf we care about uses only those.
    """
    out = {}
    pos = 0
    end = len(buf)
    while pos < end:
        tag, pos = varint.decode_from(buf, pos)
        field_number = tag >> 3
        wire_type = tag & 0x7
        if wire_type == WIRE_VARINT:
            val, pos = varint.decode_from(buf, pos)
            out.setdefault(field_number, []).append(val)
        elif wire_type == WIRE_LEN:
            length, pos = varint.decode_from(buf, pos)
            if pos + length > end:
                raise ValueError("pb_lite.parse_message: length-delimited field overruns buffer")
            out.setdefault(field_number, []).append(bytes(buf[pos:pos + length]))
            pos += length
        else:
            raise ValueError("pb_lite.parse_message: unsupported wire type {0}".format(wire_type))
    return out


# --- libp2p-specific helpers ---

KEY_TYPE_RSA = 0
KEY_TYPE_ED25519 = 1
KEY_TYPE_SECP256K1 = 2
KEY_TYPE_ECDSA = 3


def encode_public_key(key_type, key_bytes):
    """Marshal a libp2p PublicKey {Type, Data}."""
    return (
        encode_varint_field(1, key_type)
        + encode_bytes_field(2, key_bytes)
    )


def decode_public_key(buf):
    """Return (key_type, key_bytes) parsed from a marshalled PublicKey."""
    fields = parse_message(buf)
    if 1 not in fields or 2 not in fields:
        raise ValueError("pb_lite.decode_public_key: missing required fields")
    return fields[1][-1], fields[2][-1]


def encode_exchange(peer_id_bytes, pubkey_marshalled):
    """Marshal an Exchange {id, pubkey} for /plaintext/2.0.0."""
    return (
        encode_bytes_field(1, peer_id_bytes)
        + encode_message_field(2, pubkey_marshalled)
    )


def decode_exchange(buf):
    """Return (peer_id_bytes, pubkey_marshalled) parsed from an Exchange."""
    fields = parse_message(buf)
    if 1 not in fields or 2 not in fields:
        raise ValueError("pb_lite.decode_exchange: missing required fields")
    return fields[1][-1], fields[2][-1]
