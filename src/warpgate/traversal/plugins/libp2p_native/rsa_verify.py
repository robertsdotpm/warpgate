"""Pure-Python RSA signature verify (PKCS#1 v1.5 with SHA-256).

libp2p historically defaults to RSA host keys -- every IPFS public
bootstrap peer with a ``Qm...`` PeerID is RSA-2048.  To interoperate
with them, we need to:

  1. Parse the marshalled libp2p PublicKey blob for an RSA key
     (which wraps a DER-encoded PKIX SubjectPublicKeyInfo).
  2. Extract the modulus ``n`` and public exponent ``e`` from the
     SPKI.
  3. Verify the Noise-payload signature (a PKCS#1 v1.5 signature
     over SHA-256 of ``b"noise-libp2p-static-key:" || s_pub``).

This module implements EXACTLY that -- not a general RSA library.
Limitations relative to a full ASN.1/DER parser:

  - Only INTEGER, SEQUENCE, BIT STRING, OBJECT IDENTIFIER, NULL,
    and OCTET STRING tags are recognised.  All others raise.
  - Lengths up to 4 GiB (4-byte length) are accepted; the libp2p
    RSA-2048 keys fit in ~270 bytes total, so this is plenty.
  - We don't validate the algorithm OID against rsaEncryption; we
    assume the libp2p Marshalled PublicKey type=RSA preamble has
    already filtered that.

Pure Python, no external deps.  Verify-only -- we never need to
sign RSA records ourselves (warpgate identities are Ed25519).
"""
import hashlib


# ---- DER parsing (minimum needed for SubjectPublicKeyInfo) -------------


class DERParseError(Exception):
    pass


def parse_der_tlv(buf, pos):
    """Parse one DER TLV starting at ``pos``.  Returns (tag, body_bytes, new_pos)."""
    if pos + 2 > len(buf):
        raise DERParseError("truncated TLV header")
    tag = buf[pos]
    length_byte = buf[pos + 1]
    pos += 2
    if length_byte < 0x80:
        body_len = length_byte
    else:
        n_octets = length_byte & 0x7F
        if n_octets == 0 or n_octets > 4:
            raise DERParseError("unsupported length-of-length {0}".format(n_octets))
        if pos + n_octets > len(buf):
            raise DERParseError("truncated length octets")
        body_len = 0
        for i in range(n_octets):
            body_len = (body_len << 8) | buf[pos + i]
        pos += n_octets
    if pos + body_len > len(buf):
        raise DERParseError(
            "TLV body length {0} overruns buffer".format(body_len)
        )
    return tag, bytes(buf[pos:pos + body_len]), pos + body_len


def parse_der_integer(buf):
    """Parse a DER INTEGER body to a Python int (big-endian, two's-complement).

    libp2p RSA keys are positive integers so we strip the leading
    sign-padding byte if present (DER requires INTEGERs to be
    sign-extended).
    """
    if not buf:
        raise DERParseError("empty INTEGER")
    val = int.from_bytes(buf, "big", signed=False)
    return val


def parse_rsa_spki(spki_bytes):
    """Extract (n, e) from a DER-encoded PKIX SubjectPublicKeyInfo.

    Layout:
        SEQUENCE {
            SEQUENCE {                    -- AlgorithmIdentifier
                OBJECT IDENTIFIER (oid)
                NULL or other params
            }
            BIT STRING {                  -- subjectPublicKey
                SEQUENCE {                -- RSAPublicKey
                    INTEGER n
                    INTEGER e
                }
            }
        }
    """
    tag, body, _ = parse_der_tlv(spki_bytes, 0)
    if tag != 0x30:
        raise DERParseError("SPKI: outer not SEQUENCE")
    pos = 0
    # AlgorithmIdentifier -- skip whole thing.
    alg_tag, _alg_body, pos = parse_der_tlv(body, pos)
    if alg_tag != 0x30:
        raise DERParseError("SPKI: AlgorithmIdentifier not SEQUENCE")
    # subjectPublicKey BIT STRING.
    bs_tag, bs_body, pos = parse_der_tlv(body, pos)
    if bs_tag != 0x03:
        raise DERParseError("SPKI: subjectPublicKey not BIT STRING")
    # BIT STRING has a leading "unused bits" byte; expect 0.
    if not bs_body or bs_body[0] != 0:
        raise DERParseError("SPKI: unsupported unused-bits != 0")
    rsa_pub_bytes = bs_body[1:]
    # Inner SEQUENCE { INTEGER n, INTEGER e }.
    seq_tag, seq_body, _ = parse_der_tlv(rsa_pub_bytes, 0)
    if seq_tag != 0x30:
        raise DERParseError("RSAPublicKey: not SEQUENCE")
    p2 = 0
    n_tag, n_body, p2 = parse_der_tlv(seq_body, p2)
    if n_tag != 0x02:
        raise DERParseError("RSAPublicKey: n not INTEGER")
    e_tag, e_body, _ = parse_der_tlv(seq_body, p2)
    if e_tag != 0x02:
        raise DERParseError("RSAPublicKey: e not INTEGER")
    return parse_der_integer(n_body), parse_der_integer(e_body)


# ---- PKCS#1 v1.5 signature verify (SHA-256) ----------------------------


# DigestInfo prefix for SHA-256 per RFC 8017 Appendix A.2.4:
# SEQUENCE { SEQUENCE { OID id-sha256, NULL }, OCTET STRING (32) }
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


def rsa_verify_pkcs1_v15_sha256(n, e, message, signature):
    """Verify a PKCS#1 v1.5 RSA-SHA-256 signature.

    Returns True on valid signature, False on any mismatch.  Does
    NOT raise (this is hot-path code for our Noise responder
    handshake -- a bad sig should yield ``False`` so the caller
    decides the policy response).
    """
    try:
        n_bytes = (n.bit_length() + 7) // 8
        s = int.from_bytes(signature, "big")
        if s >= n:
            return False
        m = pow(s, e, n)
        em = m.to_bytes(n_bytes, "big")
        # EM layout: 0x00 || 0x01 || PS (>= 8 bytes of 0xFF) || 0x00 || T
        # T = DigestInfo || H (32 bytes for SHA-256).
        if len(em) < 11 or em[0] != 0x00 or em[1] != 0x01:
            return False
        # Find the 0x00 separator.
        ps_end = 2
        while ps_end < len(em) and em[ps_end] == 0xFF:
            ps_end += 1
        if ps_end - 2 < 8 or ps_end >= len(em) or em[ps_end] != 0x00:
            return False
        t = em[ps_end + 1:]
        expected = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
        return t == expected
    except (OverflowError, ValueError, TypeError):
        return False


def verify_libp2p_rsa_signature(key_bytes, message, signature):
    """High-level: ``key_bytes`` is the SPKI DER blob from a libp2p
    PublicKey{type=RSA, Data=...}.  Verify the signature over
    ``message`` and return True/False.
    """
    try:
        n, e = parse_rsa_spki(key_bytes)
    except DERParseError:
        return False
    return rsa_verify_pkcs1_v15_sha256(n, e, message, signature)
