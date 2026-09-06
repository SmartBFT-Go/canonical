#!/usr/bin/env python3
"""Conformance checker for WIRE-SPEC.md, implemented from that document alone.

Usage: verify_vectors.py <path-to-vectors.json>

Standard library only. A dependency would make "a non-Go client can implement
this" a claim about a package rather than about the document, and it would put a
supply-chain surface inside a conformance check.
"""

import hashlib
import json
import sys

# --------------------------------------------------------------- 2. the type profile

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_SEQUENCE = 0x30

TAG_NAMES = {
    TAG_BOOLEAN: "BOOLEAN",
    TAG_INTEGER: "INTEGER",
    TAG_OCTET_STRING: "OCTET STRING",
    TAG_SEQUENCE: "SEQUENCE",
}

# 2.4 documents lengths up to 0x82 and does not bound the form. Four octets is
# this reader's cap: past it a length is rejected rather than allocated against.
MAX_LENGTH_OCTETS = 4


class SpecError(Exception):
    """A rejection this specification requires."""


def _tag_name(tag):
    return TAG_NAMES.get(tag, "tag 0x%02x" % tag)


def _read_length(data, off, limit):
    """2.4: definite, DER-minimal length. Indefinite and non-minimal are rejected."""
    if off >= limit:
        raise SpecError("truncated: length octet missing")
    first = data[off]
    off += 1
    if first == 0x80:
        raise SpecError("indefinite length is not permitted (2.4)")
    if first == 0xFF:
        raise SpecError("reserved length octet 0xff (2.4)")
    if first < 0x80:
        return first, off
    count = first & 0x7F
    if count > MAX_LENGTH_OCTETS:
        raise SpecError("length of %d octets is beyond this reader's cap of %d (2.4)"
                        % (count, MAX_LENGTH_OCTETS))
    if off + count > limit:
        raise SpecError("truncated: long-form length runs past the buffer")
    raw = data[off:off + count]
    off += count
    if raw[0] == 0x00:
        raise SpecError("non-minimal length: leading zero octet (2.4)")
    length = int.from_bytes(raw, "big")
    if length < 0x80:
        raise SpecError("non-minimal length: %d fits the short form (2.4)" % length)
    return length, off


def _read_integer(content):
    """2.5: signed, minimal two's-complement big-endian, at least one octet."""
    if not content:
        raise SpecError("INTEGER with no content octet (2.5)")
    if len(content) > 1:
        if content[0] == 0x00 and content[1] < 0x80:
            raise SpecError("non-minimal INTEGER: redundant leading 00 (2.5)")
        if content[0] == 0xFF and content[1] >= 0x80:
            raise SpecError("non-minimal INTEGER: redundant leading ff (2.5)")
    return int.from_bytes(content, "big", signed=True)


def _read_value(data, off, limit):
    if off >= limit:
        raise SpecError("truncated: tag octet missing")
    tag = data[off]
    off += 1
    length, off = _read_length(data, off, limit)
    end = off + length
    if end > limit:
        raise SpecError("%s content runs past its container (4.2.1)" % _tag_name(tag))
    content = data[off:end]
    if tag == TAG_SEQUENCE:
        items = []
        inner = off
        while inner < end:
            item, inner = _read_value(data, inner, end)
            items.append(item)
        return ("seq", items), end
    if tag == TAG_INTEGER:
        return ("int", _read_integer(content)), end
    if tag == TAG_OCTET_STRING:
        return ("bytes", content), end
    if tag == TAG_BOOLEAN:
        if content == b"\x00":
            return ("bool", False), end
        if content == b"\xff":
            return ("bool", True), end
        raise SpecError("BOOLEAN content must be 00 or ff (2.2)")
    raise SpecError("%s is outside the type profile (2.2, 2.3)" % _tag_name(tag))


def parse_der(data):
    """Parse one complete DER value. R-RULE (4.2): no byte may remain after it."""
    value, off = _read_value(data, 0, len(data))
    if off != len(data):
        raise SpecError("%d trailing byte(s) after the outer value (4.2)" % (len(data) - off))
    return value


# --------------------------------------------------------------- the encoder

def _encode_length(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _minimal_signed(v):
    width = 1
    while True:
        try:
            return v.to_bytes(width, "big", signed=True)
        except OverflowError:
            width += 1


def encode_value(value):
    kind, v = value
    if kind == "int":
        tag, body = TAG_INTEGER, _minimal_signed(v)
    elif kind == "bytes":
        tag, body = TAG_OCTET_STRING, v
    elif kind == "seq":
        tag, body = TAG_SEQUENCE, b"".join(encode_value(x) for x in v)
    elif kind == "bool":
        tag, body = TAG_BOOLEAN, (b"\xff" if v else b"\x00")
    else:
        raise SpecError("cannot encode %r" % (kind,))
    return bytes([tag]) + _encode_length(len(body)) + body


# --------------------------------------------------------------- 3. the structures

INT = "int"
OCT = "oct"


def SEQOF(element):
    return ("seqof", element)


SCHEMAS = {
    "Header": [("Version", INT), ("PrevStateRoot", OCT), ("PrevSeq", INT),
               ("ConsensusTime", INT)],
    "ProposalV0": [("Payload", OCT), ("Header", OCT), ("Metadata", OCT),
                   ("VerificationSequence", INT)],
    "GenesisV1": [("Version", INT), ("TrustDomain", OCT), ("CARoot", OCT), ("MaxNodes", INT),
                  ("Members", SEQOF("GenesisMemberV1"))],
    "GenesisMemberV1": [("NodeID", INT), ("SpiffeID", OCT), ("LeafPubKey", OCT)],
    "SignatureSetV0": [("Sigs", SEQOF("SignerSigV0"))],
    "SignerSigV0": [("Signer", INT), ("Value", OCT), ("Msg", OCT)],
    "SignedV1": [("Version", INT), ("Purpose", INT), ("GenesisDigest", OCT), ("Payload", OCT)],
    "SignedBlobV1": [("Version", INT), ("Purpose", INT), ("Payload", OCT), ("Value", OCT)],
    "CommitPayloadV1": [("Version", INT), ("ProposalDigest", OCT), ("Aux", OCT)],
    "ClientRequestV1": [("Version", INT), ("ClientCert", OCT),
                        ("Intermediates", SEQOF("CertificateV1")), ("RequestID", OCT),
                        ("Expiry", INT), ("Payload", OCT)],
    "CertificateV1": [("DER", OCT)],
    "ReadIndexV1": [("Version", INT), ("SignerID", INT), ("View", INT), ("Seq", INT),
                    ("Nonce", OCT)],
    "CommitCertificateV1": [("Version", INT), ("ProposalDigest", OCT), ("View", INT),
                            ("Seq", INT), ("Sigs", SEQOF("SignerSigV0"))],
}

# 4.1's exception table, plus CertificateV1 which 3.11.7 allowlists.
VERSION_EXEMPT = frozenset(
    ["ProposalV0", "SignatureSetV0", "SignerSigV0", "GenesisMemberV1", "CertificateV1"])

# 3.9.1: the verifier supplies these, so a blob vector carries them beside the
# structure's own fields rather than inside them.
VERIFIER_INPUTS = {"SignedBlobV1": ("GenesisDigest", "PubKey")}

# 3.8.1 and 3.8.5. Purpose 2 relays its caller's argument and has no structure.
PURPOSES = (1, 2, 3, 4)
PURPOSE_PAYLOAD = {1: "CommitPayloadV1", 3: "ClientRequestV1", 4: "ReadIndexV1"}

GENESIS_DIGEST_LEN = 32
SIGNATURE_LEN = 64
DIGEST_LEN = 32
REQUEST_ID_LEN = 16
NONCE_LEN = 16
PUBKEY_LEN = 32


def decode_struct(name, value):
    fields = SCHEMAS[name]
    if value[0] != "seq":
        raise SpecError("%s: expected a SEQUENCE, found %s" % (name, value[0]))
    items = value[1]
    if len(items) != len(fields):
        raise SpecError("%s: SEQUENCE has %d element(s), the structure has %d field(s) (4.2.1)"
                        % (name, len(items), len(fields)))
    out = {}
    for (fname, kind), item in zip(fields, items):
        if kind is INT:
            if item[0] != "int":
                raise SpecError("%s.%s: expected INTEGER, found %s" % (name, fname, item[0]))
            out[fname] = item[1]
        elif kind is OCT:
            if item[0] != "bytes":
                raise SpecError("%s.%s: expected OCTET STRING, found %s" % (name, fname, item[0]))
            out[fname] = item[1].hex()
        else:
            if item[0] != "seq":
                raise SpecError("%s.%s: expected SEQUENCE OF, found %s" % (name, fname, item[0]))
            out[fname] = [decode_struct(kind[1], e) for e in item[1]]
    return out


def struct_value(name, obj):
    items = []
    for fname, kind in SCHEMAS[name]:
        v = obj[fname]
        if kind is INT:
            items.append(("int", v))
        elif kind is OCT:
            items.append(("bytes", bytes.fromhex(v)))
        else:
            items.append(("seq", [struct_value(kind[1], e) for e in v]))
    return ("seq", items)


def encode_struct(name, obj):
    return encode_value(struct_value(name, obj))


# --------------------------------------------------------------- the constraints

def _octets(obj, name, field, want, section):
    got = len(obj[field]) // 2
    if got != want:
        raise SpecError("%s.%s MUST be exactly %d bytes, found %d (%s)"
                        % (name, field, want, got, section))


def _nonempty(obj, name, field, section):
    if not obj[field]:
        raise SpecError("%s.%s MUST be non-empty (%s)" % (name, field, section))


def _at_least(obj, name, field, floor, section):
    if obj[field] < floor:
        raise SpecError("%s.%s is %d, must be >= %d (%s)"
                        % (name, field, obj[field], floor, section))


def _strictly_ascending(items, key, where, section):
    ids = [x[key] for x in items]
    for a, b in zip(ids, ids[1:]):
        if a >= b:
            raise SpecError("%s MUST be strictly ascending by %s; found %d then %d (%s)"
                            % (where, key, a, b, section))


def _check_header(o):
    _octets(o, "Header", "PrevStateRoot", 32, "3.1.1")


def _check_genesis(o):
    _nonempty(o, "GenesisV1", "TrustDomain", "3.6")
    _at_least(o, "GenesisV1", "MaxNodes", 0, "3.6")
    if o["MaxNodes"] < len(o["Members"]):
        raise SpecError("GenesisV1.MaxNodes is %d, below the %d member(s) it bounds (3.6)"
                        % (o["MaxNodes"], len(o["Members"])))
    _strictly_ascending(o["Members"], "NodeID", "GenesisV1.Members", "3.6.2")
    domain = bytes.fromhex(o["TrustDomain"])
    for i, m in enumerate(o["Members"]):
        _at_least(m, "GenesisMemberV1", "NodeID", 0, "3.6")
        _octets(m, "GenesisMemberV1", "LeafPubKey", 32, "3.6")
        want = b"spiffe://" + domain + b"/node/" + str(m["NodeID"]).encode("ascii")
        if bytes.fromhex(m["SpiffeID"]) != want:
            raise SpecError("GenesisV1.Members[%d].SpiffeID is not the derived value %r (3.6.6)"
                            % (i, want.decode("ascii", "replace")))


def _check_signed(o):
    if o["Purpose"] not in PURPOSES:
        raise SpecError("SignedV1.Purpose %d is not one of %s (3.8, 3.8.1)"
                        % (o["Purpose"], list(PURPOSES)))
    _octets(o, "SignedV1", "GenesisDigest", GENESIS_DIGEST_LEN, "3.8")


def _check_blob(o):
    if o["Purpose"] not in PURPOSES:
        raise SpecError("SignedBlobV1.Purpose %d is not one of %s (3.9, 3.8.1)"
                        % (o["Purpose"], list(PURPOSES)))
    _nonempty(o, "SignedBlobV1", "Payload", "3.9.4")
    _octets(o, "SignedBlobV1", "Value", SIGNATURE_LEN, "3.9")


def _check_commit_payload(o):
    _octets(o, "CommitPayloadV1", "ProposalDigest", DIGEST_LEN, "3.10")


def _check_client_request(o):
    _nonempty(o, "ClientRequestV1", "ClientCert", "3.11")
    for i, c in enumerate(o["Intermediates"]):
        if not c["DER"]:
            raise SpecError("ClientRequestV1.Intermediates[%d].DER MUST be non-empty (3.11)" % i)
    _octets(o, "ClientRequestV1", "RequestID", REQUEST_ID_LEN, "3.11.1")
    if o["Expiry"] <= 0:
        raise SpecError("ClientRequestV1.Expiry is %d, must be strictly positive (3.11.5)"
                        % o["Expiry"])


def _check_read_index(o):
    if o["SignerID"] <= 0:
        raise SpecError("ReadIndexV1.SignerID is %d, must be strictly positive (3.12.3)"
                        % o["SignerID"])
    _at_least(o, "ReadIndexV1", "View", 0, "3.12.3")
    _at_least(o, "ReadIndexV1", "Seq", 0, "3.12.3")
    _octets(o, "ReadIndexV1", "Nonce", NONCE_LEN, "3.12.2")


def _check_commit_cert(o):
    _octets(o, "CommitCertificateV1", "ProposalDigest", DIGEST_LEN, "3.13")
    _at_least(o, "CommitCertificateV1", "View", 0, "3.13")
    _at_least(o, "CommitCertificateV1", "Seq", 0, "3.13")
    _nonempty(o, "CommitCertificateV1", "Sigs", "3.13")
    _strictly_ascending(o["Sigs"], "Signer", "CommitCertificateV1.Sigs", "3.13.2")
    for i, s in enumerate(o["Sigs"]):
        _octets(s, "CommitCertificateV1.Sigs[%d]" % i, "Value", SIGNATURE_LEN, "3.13")
        if not s["Msg"]:
            raise SpecError("CommitCertificateV1.Sigs[%d].Msg MUST be non-empty (3.13.5)" % i)
        _check_cert_msg(o, s, i)


# 3.13.1's cross-check is only reachable where Msg is a CommitPayloadV1; the
# encoding layer leaves SignerSigV0.Msg opaque (3.7). CHECKED counts the hits.
CHECKED = {"3.13.1": 0}


def _check_cert_msg(cert, entry, i):
    try:
        payload = decode_struct("CommitPayloadV1", parse_der(bytes.fromhex(entry["Msg"])))
        validate("CommitPayloadV1", payload)
    except SpecError:
        return
    CHECKED["3.13.1"] += 1
    if payload["ProposalDigest"] != cert["ProposalDigest"]:
        raise SpecError("CommitCertificateV1.Sigs[%d].Msg names proposal %s, the certificate "
                        "names %s (3.13.1)" % (i, payload["ProposalDigest"][:16],
                                               cert["ProposalDigest"][:16]))


CHECKS = {
    "Header": _check_header,
    "GenesisV1": _check_genesis,
    "SignedV1": _check_signed,
    "SignedBlobV1": _check_blob,
    "CommitPayloadV1": _check_commit_payload,
    "ClientRequestV1": _check_client_request,
    "ReadIndexV1": _check_read_index,
    "CommitCertificateV1": _check_commit_cert,
}


def validate(name, obj):
    """4.1's V-RULE plus 3.x's own constraints, checked on decode as 3.6.3 requires."""
    if name not in VERSION_EXEMPT:
        first = SCHEMAS[name][0][0]
        if first != "Version":
            raise SpecError("%s: first field is %s, not Version (4.1)" % (name, first))
        if obj["Version"] != 1:
            raise SpecError("%s.Version is %d, this decoder knows 1 (4.1)" % (name, obj["Version"]))
    check = CHECKS.get(name)
    if check is not None:
        check(obj)


# --------------------------------------------------------------- 5. Merkle node hashing

def merkle_hash(entry):
    """5.2: fixed-width domain-separated concatenation, not DER."""
    tree_id = entry["treeID"].to_bytes(8, "big")
    depth = entry["depth"]
    if not 0 <= depth <= 255:
        raise SpecError("depth %d does not fit the one-byte field (5.1)" % depth)
    fn = entry["fn"]
    if fn == "leaf":
        key = bytes.fromhex(entry["key"])
        val = bytes.fromhex(entry["val"])
        pre = (b"\x00" + tree_id + bytes([depth])
               + len(key).to_bytes(8, "big") + key
               + len(val).to_bytes(8, "big") + val)
    elif fn == "internal":
        left = bytes.fromhex(entry["left"])
        right = bytes.fromhex(entry["right"])
        if len(left) != 32 or len(right) != 32:
            raise SpecError("child digests are 32 bytes each (5.1)")
        pre = b"\x01" + tree_id + bytes([depth]) + left + right
    elif fn == "empty":
        pre = b"\x02" + tree_id + bytes([depth])
    else:
        raise SpecError("unknown node form %r (5.2)" % fn)
    return hashlib.sha256(pre).hexdigest()


# --------------------------------------------------------------- Ed25519, RFC 8032 section 5.1

P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    """RFC 8032 5.1.3: the curve point whose y is given, with x's low bit fixed."""
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if x & 1 != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
BASE = (_GX, _GY, 1, _GX * _GY % P)
IDENTITY = (0, 1, 1, 0)


def _point_add(a, b):
    """RFC 8032 5.1.4, extended homogeneous coordinates."""
    a1 = (a[1] - a[0]) * (b[1] - b[0]) % P
    a2 = (a[1] + a[0]) * (b[1] + b[0]) % P
    c = 2 * a[3] * b[3] * D % P
    d = 2 * a[2] * b[2] % P
    e, f, g, h = a2 - a1, d - c, d + c, a2 + a1
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_mul(scalar, point):
    acc = IDENTITY
    while scalar > 0:
        if scalar & 1:
            acc = _point_add(acc, point)
        point = _point_add(point, point)
        scalar >>= 1
    return acc


def _point_equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def _point_decompress(raw):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def ed25519_verify(public, message, signature):
    """RFC 8032 5.1.7: accept iff [s]B equals R + [SHA-512(R||A||M) mod L]A."""
    if len(public) != PUBKEY_LEN or len(signature) != SIGNATURE_LEN:
        return False
    point_a = _point_decompress(public)
    if point_a is None:
        return False
    r_raw = signature[:32]
    point_r = _point_decompress(r_raw)
    if point_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= Q:
        return False
    k = int.from_bytes(hashlib.sha512(r_raw + public + message).digest(), "little") % Q
    return _point_equal(_point_mul(s, BASE), _point_add(point_r, _point_mul(k, point_a)))


# --------------------------------------------------------------- the vector checks

def compare_fields(name, got, want, path=""):
    """The decoded value against the annex's `fields`, element by element."""
    for fname, kind in SCHEMAS[name]:
        where = path + fname
        if fname not in want:
            raise SpecError("field %s is absent from the vector's fields object" % where)
        mine, theirs = got[fname], want[fname]
        if isinstance(kind, tuple):
            if not isinstance(theirs, list):
                raise SpecError("field %s: vector gives %r, expected a list" % (where, theirs))
            if len(mine) != len(theirs):
                raise SpecError("field %s: der decodes to %d element(s), vector says %d"
                                % (where, len(mine), len(theirs)))
            for i, (a, b) in enumerate(zip(mine, theirs)):
                compare_fields(kind[1], a, b, "%s[%d]." % (where, i))
        elif mine != theirs:
            raise SpecError("field %s: der decodes to %r, vector says %r" % (where, mine, theirs))
    known = {f for f, _ in SCHEMAS[name]} | set(VERIFIER_INPUTS.get(name, ()))
    extra = sorted(set(want) - known)
    if extra:
        raise SpecError("%s: fields object carries unknown key(s) %s" % (name, extra))


def _seq_paths(value, path=()):
    if value[0] == "seq":
        yield path
        for i, child in enumerate(value[1]):
            for deeper in _seq_paths(child, path + (i,)):
                yield deeper


def _splice(value, path):
    if not path:
        return ("seq", list(value[1]) + [("int", 0x63)])
    kids = list(value[1])
    kids[path[0]] = _splice(kids[path[0]], path[1:])
    return ("seq", kids)


def derived_forgeries(name, tree, der):
    """4.3: every forgery derivable from the vector itself MUST be rejected."""
    count = 0
    for path in _seq_paths(tree):
        forged = encode_value(_splice(tree, path))
        try:
            validate(name, decode_struct(name, parse_der(forged)))
        except SpecError:
            count += 1
            continue
        raise SpecError("a 02 01 63 spliced into SEQUENCE %s was accepted (4.2.1, 4.3)"
                        % (list(path) or "outer",))
    try:
        parse_der(der + b"\xff")
    except SpecError:
        count += 1
    else:
        raise SpecError("a trailing 0xff was accepted (4.2)")
    if name not in VERSION_EXEMPT:
        fields = dict(decode_struct(name, tree), Version=2)
        try:
            validate(name, decode_struct(name, parse_der(encode_struct(name, fields))))
        except SpecError:
            count += 1
        else:
            raise SpecError("Version 2 was accepted by a v1 decoder (4.1)")
    return count


def purpose_payload(purpose, payload_hex, required):
    """3.8.5's mapping. Required where 3.9's table demands the purpose's own structure."""
    want = PURPOSE_PAYLOAD.get(purpose)
    if want is None:
        return "payload opaque under purpose 2"
    try:
        inner = decode_struct(want, parse_der(bytes.fromhex(payload_hex)))
        validate(want, inner)
    except SpecError as err:
        if required:
            raise SpecError("Payload is not the %s that purpose %d names: %s"
                            % (want, purpose, err))
        return "payload not a %s (3.8.5)" % want
    return "payload is a %s" % want


def check_blob_signature(fields, obj):
    """3.9.1: rebuild the envelope from the verifier's own genesis digest and verify Value."""
    digest = fields.get("GenesisDigest")
    pub = fields.get("PubKey")
    if not digest or not pub:
        return None
    key = bytes.fromhex(pub)
    if len(key) != PUBKEY_LEN:
        raise SpecError("PubKey MUST be 32 bytes, found %d" % len(key))
    sig = bytes.fromhex(obj["Value"])
    envelope = encode_struct("SignedV1", {
        "Version": 1, "Purpose": obj["Purpose"],
        "GenesisDigest": digest, "Payload": obj["Payload"],
    })
    if not ed25519_verify(key, envelope, sig):
        raise SpecError("Ed25519 signature does not verify over the reconstructed "
                        "SignedV1 envelope (3.9.1)")
    foreign = bytearray(bytes.fromhex(digest))
    foreign[0] ^= 0x01
    other = encode_struct("SignedV1", {
        "Version": 1, "Purpose": obj["Purpose"],
        "GenesisDigest": bytes(foreign).hex(), "Payload": obj["Payload"],
    })
    if ed25519_verify(key, other, sig):
        raise SpecError("the signature verified under a foreign genesis digest, so 3.8.4's "
                        "binding is not in the signed bytes")
    return len(envelope)


def _msg_is_commit_payload(msg_hex):
    try:
        decode_struct("CommitPayloadV1", parse_der(bytes.fromhex(msg_hex)))
    except SpecError:
        return False
    return True


def check_vector(vec):
    name = vec["name"]
    structure = vec["structure"]
    if structure not in SCHEMAS:
        raise SpecError("no schema for structure %s" % structure)
    der = bytes.fromhex(vec["der"])
    tree = parse_der(der)
    obj = decode_struct(structure, tree)
    validate(structure, obj)
    compare_fields(structure, obj, vec["fields"])
    again = encode_struct(structure, obj)
    if again != der:
        raise SpecError("re-encoding the decoded value gives %d byte(s) that differ from der "
                        "(2, 4.2.1)" % sum(1 for a, b in zip(again, der) if a != b))
    got = hashlib.sha256(der).hexdigest()
    if got != vec["sha256"]:
        raise SpecError("sha256 of der is %s, vector says %s (1.4, 3.4)" % (got, vec["sha256"]))
    notes = []
    if structure == "CommitCertificateV1":
        bound = sum(1 for e in obj["Sigs"] if _msg_is_commit_payload(e["Msg"]))
        notes.append("%d/%d Msg bound to the proposal digest" % (bound, len(obj["Sigs"])))
    if structure == "SignedV1":
        notes.append(purpose_payload(obj["Purpose"], obj["Payload"], required=False))
    elif structure == "SignedBlobV1":
        notes.append(purpose_payload(obj["Purpose"], obj["Payload"], required=True))
        size = check_blob_signature(vec["fields"], obj)
        if size is not None:
            notes.append("Ed25519 verified over %d envelope bytes" % size)
    forgeries = derived_forgeries(structure, tree, der)
    return len(der), forgeries, "; ".join(notes)


def main(argv):
    if len(argv) != 2:
        print("usage: verify_vectors.py <path-to-vectors.json>", file=sys.stderr)
        return 2
    with open(argv[1], "r") as handle:
        annex = json.load(handle)

    vectors = annex.get("vectors", [])
    merkle = annex.get("merkle", [])
    if not vectors:
        print("FAIL: the annex holds no vectors; there is nothing to be conformant with",
              file=sys.stderr)
        return 1

    total_forgeries = 0
    structures = set()
    for vec in vectors:
        try:
            size, forgeries, notes = check_vector(vec)
        except SpecError as err:
            print("FAIL %s: %s" % (vec.get("name", "<unnamed>"), err), file=sys.stderr)
            return 1
        total_forgeries += forgeries
        structures.add(vec["structure"])
        print("ok  %-38s %-21s %5d B  %2d forgeries rejected  %s"
              % (vec["name"], vec["structure"], size, forgeries, notes))

    for entry in merkle:
        try:
            got = merkle_hash(entry)
        except SpecError as err:
            print("FAIL %s: %s" % (entry.get("name", "<unnamed>"), err), file=sys.stderr)
            return 1
        if got != entry["hash"]:
            print("FAIL %s: hash is %s, vector says %s (5.2)" % (entry["name"], got,
                                                                 entry["hash"]), file=sys.stderr)
            return 1
        print("ok  %-38s %-21s        %s" % (entry["name"], "merkle/" + entry["fn"], got[:16]))

    missing = sorted(set(SCHEMAS) - structures - {"GenesisMemberV1", "SignerSigV0",
                                                  "CertificateV1"})
    if missing:
        print("FAIL: no vector for %s (3.3)" % ", ".join(missing), file=sys.stderr)
        return 1

    if CHECKED["3.13.1"] == 0:
        print("FAIL: no certificate entry exercised 3.13.1's Msg-to-ProposalDigest binding",
              file=sys.stderr)
        return 1

    print("\n%d vectors over %d structures, %d Merkle nodes, %d derived forgeries rejected"
          % (len(vectors), len(structures), len(merkle), total_forgeries))
    print("%d certificate entries bound to their proposal digest (3.13.1)" % CHECKED["3.13.1"])
    print("SignatureSetV0.Sigs and ClientRequestV1.Intermediates carry no order constraint "
          "(3.7.4, 3.11.3)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
