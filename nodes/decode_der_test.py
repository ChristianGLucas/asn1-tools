from gen.messages_pb2 import Asn1Input, DecodeDerResult
from nodes.decode_der import decode_der
from gen.axiom_context import SecretStatus


class _TestContext:
    """Minimal AxiomContext implementation for unit tests."""

    class _Logger:
        def debug(self, msg: str, **attrs) -> None: pass
        def info(self, msg: str, **attrs) -> None: pass
        def warn(self, msg: str, **attrs) -> None: pass
        def error(self, msg: str, **attrs) -> None: pass

    class _Secrets:
        def __init__(self, m: dict, revoked: set) -> None:
            self._m = m or {}
            self._revoked = revoked or set()
        def get(self, name: str):
            v = self._m.get(name)
            return (v, True) if v is not None else ("", False)
        def status(self, name: str) -> SecretStatus:
            if name in self._m:
                return SecretStatus.AVAILABLE
            if name in self._revoked:
                return SecretStatus.REVOKED
            return SecretStatus.UNSET

    def __init__(self, secrets_map: dict | None = None, revoked_names: set | None = None) -> None:
        self.log = self._Logger()
        self.secrets = self._Secrets(secrets_map or {}, revoked_names)
        self.execution_id = "test-execution-id"
        self.flow_id = "test-flow-id"
        self.tenant_id = "test-tenant-id"


# Hand-computed per X.690: SEQUENCE { INTEGER 74 (0x4A), UTF8String "Hi" }
#   30 07                 SEQUENCE, length 7
#      02 01 4A           INTEGER, length 1, value 0x4A = 74
#      0C 02 48 69        UTF8String, length 2, "Hi" (0x48='H', 0x69='i')
HAND_COMPUTED_SEQUENCE_HEX = "300702014a0c024869"


def test_decode_der_sequence_matches_hand_computed_structure():
    ax = _TestContext()
    result = decode_der(ax, Asn1Input(data_hex=HAND_COMPUTED_SEQUENCE_HEX))
    assert result.ok is True
    assert result.error == ""
    root = result.root
    assert root.tag_class == "universal"
    assert root.tag_number == 16
    assert root.constructed is True
    assert root.universal_type == "SEQUENCE"
    assert root.content_length == 7
    assert len(root.children) == 2

    integer_node = root.children[0]
    assert integer_node.tag_class == "universal"
    assert integer_node.tag_number == 2
    assert integer_node.constructed is False
    assert integer_node.universal_type == "INTEGER"
    assert integer_node.value_hex == "4a"
    assert integer_node.value_kind == "integer"
    assert integer_node.value_integer == "74"

    string_node = root.children[1]
    assert string_node.tag_class == "universal"
    assert string_node.tag_number == 12
    assert string_node.constructed is False
    assert string_node.universal_type == "UTF8String"
    assert string_node.value_hex == "4869"
    assert string_node.value_kind == "string"
    assert string_node.value_string == "Hi"


def test_decode_der_accepts_base64_and_pem_equivalently():
    ax = _TestContext()
    raw = bytes.fromhex(HAND_COMPUTED_SEQUENCE_HEX)
    import base64
    b64_result = decode_der(ax, Asn1Input(data_base64=base64.b64encode(raw).decode()))
    pem_text = "-----BEGIN TEST-----\n" + base64.b64encode(raw).decode() + "\n-----END TEST-----\n"
    pem_result = decode_der(ax, Asn1Input(pem=pem_text))
    assert b64_result.ok is True
    assert pem_result.ok is True
    assert b64_result.root.tag_number == pem_result.root.tag_number == 16


def test_decode_der_context_tag_recurses_generically():
    # [0] EXPLICIT INTEGER 5 -> A0 03 02 01 05 (hand-computed: context class,
    # constructed, tag 0, length 3, containing INTEGER 5)
    ax = _TestContext()
    result = decode_der(ax, Asn1Input(data_hex="a0030201" + "05"))
    assert result.ok is True
    root = result.root
    assert root.tag_class == "context"
    assert root.tag_number == 0
    assert root.constructed is True
    assert root.universal_type == ""  # not a universal tag; no typed name
    assert len(root.children) == 1
    inner = root.children[0]
    assert inner.tag_class == "universal"
    assert inner.tag_number == 2
    assert inner.value_kind == "integer"
    assert inner.value_integer == "5"


def test_decode_der_indefinite_length_ber():
    # Indefinite-length constructed OCTET STRING containing two OCTET STRING
    # primitives "A" and "B", terminated by the EOC marker (00 00) — valid BER,
    # forbidden in strict DER. Hand-computed per X.690 section 8.1.3.6.
    ax = _TestContext()
    data_hex = "2480" + "040141" + "040142" + "0000"
    result = decode_der(ax, Asn1Input(data_hex=data_hex))
    assert result.ok is True
    root = result.root
    assert root.tag_class == "universal"
    assert root.tag_number == 4  # OCTET STRING
    assert root.constructed is True
    assert len(root.children) == 2
    assert root.children[0].value_hex == "41"
    assert root.children[1].value_hex == "42"


def test_decode_der_rejects_empty_input():
    ax = _TestContext()
    result = decode_der(ax, Asn1Input(data_hex=""))
    assert result.ok is False
    assert result.error != ""


def test_decode_der_rejects_malformed_input():
    ax = _TestContext()
    # Length byte claims 10 bytes of content but none follow.
    result = decode_der(ax, Asn1Input(data_hex="300a"))
    assert result.ok is False
    assert result.error != ""


def test_decode_der_rejects_trailing_garbage():
    ax = _TestContext()
    # A valid NULL (05 00) followed by trailing junk byte.
    result = decode_der(ax, Asn1Input(data_hex="0500ff"))
    assert result.ok is False
    assert result.error != ""


def _der_len(n: int) -> bytes:
    """Standalone, from-scratch DER length-octet encoder (X.690 8.1.3) used
    only to build adversarial test fixtures — independent of the encode/decode
    logic under test."""
    if n < 0x80:
        return bytes([n])
    length_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def _nested_sequences(depth: int) -> bytes:
    inner = bytes.fromhex("0500")  # NULL
    for _ in range(depth):
        inner = b"\x30" + _der_len(len(inner)) + inner
    return inner


def test_decode_der_rejects_excessive_nesting_depth():
    ax = _TestContext()
    data = _nested_sequences(100)  # exceeds MAX_TREE_DEPTH (64)
    result = decode_der(ax, Asn1Input(data_hex=data.hex()))
    assert result.ok is False
    assert "depth" in result.error.lower() or "nest" in result.error.lower()


def test_decode_der_accepts_nesting_within_bound():
    ax = _TestContext()
    data = _nested_sequences(10)
    result = decode_der(ax, Asn1Input(data_hex=data.hex()))
    assert result.ok is True


def test_decode_der_rejects_excessive_node_count():
    ax = _TestContext()
    # One SEQUENCE containing 60,001 empty NULL siblings (2 bytes each) —
    # exceeds MAX_TREE_NODES (50,000).
    null_count = 60_001
    content = b"\x05\x00" * null_count
    data = b"\x30" + _der_len(len(content)) + content
    result = decode_der(ax, Asn1Input(data_hex=data.hex()))
    assert result.ok is False
    assert "node" in result.error.lower() or "count" in result.error.lower()


def test_decode_der_rejects_oversized_input():
    ax = _TestContext()
    from asn1crypto.core import OctetString
    from nodes._asn1_common import MAX_INPUT_BYTES
    big = OctetString(b"A" * (MAX_INPUT_BYTES + 100)).dump()
    result = decode_der(ax, Asn1Input(data_hex=big.hex()))
    assert result.ok is False
    assert "size" in result.error.lower()


def test_decode_der_boolean_and_null_and_oid():
    ax = _TestContext()
    # BOOLEAN TRUE: 01 01 FF
    bool_result = decode_der(ax, Asn1Input(data_hex="0101ff"))
    assert bool_result.ok is True
    assert bool_result.root.value_kind == "boolean"
    assert bool_result.root.value_boolean is True

    # NULL: 05 00
    null_result = decode_der(ax, Asn1Input(data_hex="0500"))
    assert null_result.ok is True
    assert null_result.root.value_kind == "null"

    # OBJECT IDENTIFIER 1.2.840.113549.1.1.1 (rsaEncryption)
    oid_result = decode_der(ax, Asn1Input(data_hex="06092a864886f70d010101"))
    assert oid_result.ok is True
    assert oid_result.root.value_kind == "oid"
    assert oid_result.root.value_oid == "1.2.840.113549.1.1.1"
    assert oid_result.root.value_oid_name == "rsa"


def test_decode_der_returns_isinstance_result():
    ax = _TestContext()
    result = decode_der(ax, Asn1Input(data_hex="0500"))
    assert isinstance(result, DecodeDerResult)
