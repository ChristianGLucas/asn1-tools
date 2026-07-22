"""Shared decode/encode/lookup helpers for every node in this package.

Wraps asn1crypto (MIT, https://github.com/wbond/asn1crypto) — specifically its
low-level TLV framing primitives (`_parse` / `_dump_header`, the same engine the
library uses internally to read and write every value, including multi-byte tag
numbers and long-form/indefinite BER lengths) and its per-universal-type semantic
decoders (OID, INTEGER, TIME, string variants) reached via `core.load`. This
module supplies only the generic recursive walk, the input-size/depth/node
budget guards, and hex/base64/RFC3339 formatting glue — none of the actual
ASN.1 framing or value-semantics logic is reimplemented here.
"""
import base64
import re
from datetime import timezone

from asn1crypto import algos, cms, core, keys, pem as asn1_pem
from asn1crypto.core import _dump_header, _parse

from gen.messages_pb2 import Asn1Node

# --- Bounds (input -> cost) -------------------------------------------------
# A caller-controlled ASN.1 blob drives parse cost (allocation, recursion) in
# direct proportion to these three dimensions. Each is bounded BEFORE the bytes
# are touched by the parser, not after.
MAX_INPUT_BYTES = 2 * 1024 * 1024      # raw decoded-input size cap (2 MiB)
MAX_TREE_DEPTH = 64                    # nested constructed-value recursion cap
MAX_TREE_NODES = 50_000                # total tree-node cap (adversarially wide trees)
MAX_PEM_TEXT_BYTES = 8 * 1024 * 1024   # raw PEM text size cap (8 MiB; base64 text, so larger than the DER cap)
MAX_PEM_BLOCKS = 1000                  # cap on the number of concatenated PEM blocks in one input

CLASS_NAMES = {0: "universal", 1: "application", 2: "context", 3: "private"}
CLASS_NUMS = {v: k for k, v in CLASS_NAMES.items()}

UNIVERSAL_TAG_NAMES = {
    0: "END-OF-CONTENTS", 1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING",
    4: "OCTET STRING", 5: "NULL", 6: "OBJECT IDENTIFIER", 7: "ObjectDescriptor",
    8: "EXTERNAL", 9: "REAL", 10: "ENUMERATED", 11: "EMBEDDED PDV",
    12: "UTF8String", 13: "RELATIVE-OID", 14: "TIME", 16: "SEQUENCE", 17: "SET",
    18: "NumericString", 19: "PrintableString", 20: "T61String",
    21: "VideotexString", 22: "IA5String", 23: "UTCTime", 24: "GeneralizedTime",
    25: "GraphicString", 26: "VisibleString", 27: "GeneralString",
    28: "UniversalString", 29: "CHARACTER STRING", 30: "BMPString",
}
STRING_TAGS = {12, 18, 19, 20, 21, 22, 25, 26, 27, 28, 29, 30}
TIME_TAGS = {23, 24}

# Known OID -> friendly-name registries, as maintained by asn1crypto itself.
# Checked in this fixed order; first match wins.
_OID_REGISTRIES = [
    ("public_key_algorithm", keys.PublicKeyAlgorithmId._map),
    ("signed_digest_algorithm", algos.SignedDigestAlgorithmId._map),
    ("digest_algorithm", algos.DigestAlgorithmId._map),
    ("content_type", cms.ContentType._map),
]

_WHITESPACE_RE = re.compile(r"\s+")


class Asn1Error(Exception):
    """Raised on malformed input or a bound being exceeded. Every node catches
    this and returns a structured {ok: false, error: str} result — never lets
    it propagate as a crash."""


def lookup_oid_info(oid: str):
    """Return (category, name) for a dotted OID string, or ("", "") when none
    of the known registries recognize it."""
    for category, mapping in _OID_REGISTRIES:
        name = mapping.get(oid)
        if name:
            return category, name
    return "", ""


def bytes_from_hex(hex_str: str) -> bytes:
    cleaned = _WHITESPACE_RE.sub("", hex_str)
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise Asn1Error(f"invalid hex: {e}") from e


def bytes_from_base64(b64_str: str) -> bytes:
    cleaned = _WHITESPACE_RE.sub("", b64_str)
    try:
        return base64.b64decode(cleaned, validate=True)
    except Exception as e:
        raise Asn1Error(f"invalid base64: {e}") from e


def bytes_from_hex_or_base64(data_hex: str, data_base64: str) -> bytes:
    if data_hex:
        return bytes_from_hex(data_hex)
    if data_base64:
        return bytes_from_base64(data_base64)
    raise Asn1Error("one of data_hex or data_base64 is required")


def resolve_input_bytes(input_msg) -> bytes:
    """Resolve an Asn1Input-shaped message (pem / data_base64 / data_hex) to raw
    bytes, honoring that documented priority order, and enforce the size bound."""
    pem_text = getattr(input_msg, "pem", "") or ""
    b64 = getattr(input_msg, "data_base64", "") or ""
    hex_str = getattr(input_msg, "data_hex", "") or ""

    if pem_text:
        if len(pem_text.encode("utf-8", "surrogateescape")) > MAX_INPUT_BYTES:
            raise Asn1Error("pem input exceeds maximum size")
        try:
            _label, _headers, der_bytes = asn1_pem.unarmor(pem_text.encode("utf-8"))
        except Exception as e:
            raise Asn1Error(f"invalid PEM: {e}") from e
    elif b64:
        if len(b64) > MAX_INPUT_BYTES * 2:
            raise Asn1Error("data_base64 input exceeds maximum size")
        der_bytes = bytes_from_base64(b64)
    elif hex_str:
        if len(hex_str) > MAX_INPUT_BYTES * 2:
            raise Asn1Error("data_hex input exceeds maximum size")
        der_bytes = bytes_from_hex(hex_str)
    else:
        raise Asn1Error("one of pem, data_base64, or data_hex is required")

    if len(der_bytes) > MAX_INPUT_BYTES:
        raise Asn1Error("decoded input exceeds maximum size")
    if len(der_bytes) == 0:
        raise Asn1Error("decoded input is empty")
    return der_bytes


def iter_pem_blocks(pem_text: str):
    """Yield (label, headers_dict, der_bytes) for every armored block in a
    (possibly multi-block) PEM text, bounding both the input text size and the
    number of blocks. Raises Asn1Error on empty/malformed input."""
    if not pem_text:
        raise Asn1Error("pem is required")
    encoded = pem_text.encode("utf-8", "surrogateescape")
    if len(encoded) > MAX_PEM_TEXT_BYTES:
        raise Asn1Error("pem input exceeds maximum size")
    try:
        blocks = list(asn1_pem.unarmor(encoded, multiple=True))
    except Exception as e:
        raise Asn1Error(f"invalid PEM: {e}") from e
    if not blocks:
        raise Asn1Error("no PEM blocks found")
    if len(blocks) > MAX_PEM_BLOCKS:
        raise Asn1Error(f"PEM input exceeds the maximum block count ({MAX_PEM_BLOCKS})")
    return blocks


def _parse_tlv(buf: bytes, pointer: int):
    """One TLV step at `pointer` within `buf`. Returns
    (class_num, method, tag_num, header_bytes, contents_bytes, new_pointer)."""
    try:
        info, new_pointer = _parse(buf, len(buf), pointer)
    except Exception as e:
        raise Asn1Error(f"malformed ASN.1 encoding: {e}") from e
    class_num, method, tag_num, header, contents, _trailer = info
    return class_num, method, tag_num, header, contents, new_pointer


def _format_rfc3339(dt) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _populate_typed_value(node: Asn1Node, tag_num: int, header: bytes, contents: bytes) -> None:
    """Best-effort typed interpretation of a universal primitive value, via
    asn1crypto's own per-type decoder. Never raises — an interpretation failure
    just leaves value_kind empty; value_hex/value_base64 remain the ground truth."""
    try:
        if tag_num == 1:
            typed = core.load(header + contents)
            node.value_kind = "boolean"
            node.value_boolean = bool(typed.native)
        elif tag_num in (2, 10):
            typed = core.load(header + contents)
            node.value_kind = "integer"
            node.value_integer = str(typed.native)
        elif tag_num == 6:
            typed = core.load(header + contents)
            node.value_kind = "oid"
            node.value_oid = typed.dotted
            _cat, name = lookup_oid_info(typed.dotted)
            node.value_oid_name = name
        elif tag_num == 5:
            node.value_kind = "null"
        elif tag_num == 3:
            node.value_kind = "bit_string"
            node.unused_bits = contents[0] if contents else 0
        elif tag_num in TIME_TAGS:
            typed = core.load(header + contents)
            node.value_kind = "time"
            node.value_time = _format_rfc3339(typed.native)
        elif tag_num in STRING_TAGS:
            typed = core.load(header + contents)
            if isinstance(typed.native, str):
                node.value_kind = "string"
                node.value_string = typed.native
    except Exception:
        pass


def _build_node(class_num: int, method: int, tag_num: int, header: bytes,
                 contents: bytes, depth: int, budget: dict) -> Asn1Node:
    budget["count"] += 1
    if budget["count"] > MAX_TREE_NODES:
        raise Asn1Error(f"ASN.1 structure exceeds the maximum node count ({MAX_TREE_NODES})")

    node = Asn1Node(
        tag_class=CLASS_NAMES.get(class_num, "unknown"),
        tag_number=tag_num,
        constructed=bool(method),
        content_length=len(contents),
    )
    if class_num == 0:
        node.universal_type = UNIVERSAL_TAG_NAMES.get(tag_num, "")

    if method:  # constructed: recurse into sibling TLVs held in `contents`
        if depth + 1 > MAX_TREE_DEPTH:
            raise Asn1Error(f"ASN.1 structure exceeds the maximum nesting depth ({MAX_TREE_DEPTH})")
        offset = 0
        children = []
        while offset < len(contents):
            c_class, c_method, c_tag, c_header, c_contents, new_offset = _parse_tlv(contents, offset)
            if new_offset <= offset:
                raise Asn1Error("malformed ASN.1 encoding: non-advancing child parse")
            children.append(_build_node(c_class, c_method, c_tag, c_header, c_contents, depth + 1, budget))
            offset = new_offset
        node.children.extend(children)
    else:
        node.value_hex = contents.hex()
        node.value_base64 = base64.b64encode(contents).decode("ascii")
        if class_num == 0:
            _populate_typed_value(node, tag_num, header, contents)

    return node


def decode_tree(data: bytes) -> Asn1Node:
    """Decode exactly one ASN.1 TLV (and everything nested within it) from
    `data` into a generic Asn1Node tree. Rejects trailing bytes after the
    outer value rather than silently ignoring them."""
    class_num, method, tag_num, header, contents, consumed = _parse_tlv(data, 0)
    if consumed != len(data):
        raise Asn1Error("trailing bytes after the top-level ASN.1 value")
    return _build_node(class_num, method, tag_num, header, contents, depth=0, budget={"count": 0})


def encode_tree(node: Asn1Node, depth: int = 0) -> bytes:
    """Encode a generic Asn1Node tree back to DER bytes — the inverse of
    decode_tree. Uses only value_hex/value_base64 (raw bytes) and children;
    the typed convenience fields (value_oid, value_integer, ...) are decode-only
    and are not consulted here, so this is a byte-exact structural round trip."""
    if depth > MAX_TREE_DEPTH:
        raise Asn1Error(f"ASN.1 structure exceeds the maximum nesting depth ({MAX_TREE_DEPTH})")
    class_num = CLASS_NUMS.get(node.tag_class)
    if class_num is None:
        raise Asn1Error(f"unknown tag_class '{node.tag_class}' (expected one of: universal, application, context, private)")
    if node.tag_number < 0:
        raise Asn1Error("tag_number must be non-negative")

    method = 1 if node.constructed else 0
    if node.constructed:
        content = b"".join(encode_tree(child, depth + 1) for child in node.children)
    else:
        if node.value_hex:
            content = bytes_from_hex(node.value_hex)
        elif node.value_base64:
            content = bytes_from_base64(node.value_base64)
        else:
            content = b""

    try:
        header = _dump_header(class_num, method, node.tag_number, content)
    except Exception as e:
        raise Asn1Error(f"failed to encode ASN.1 header: {e}") from e
    return header + content
