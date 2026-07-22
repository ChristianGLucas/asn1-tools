from gen.messages_pb2 import Asn1Input, ContentInfoResult
from nodes.parse_content_info import parse_content_info
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


def test_parse_content_info_with_content_matches_hand_computed_bytes():
    # Hand-computed: ContentInfo { contentType: id-data (1.2.840.113549.1.7.1),
    # content: [0] EXPLICIT OCTET STRING "hello world" }
    #   30 1a                                    SEQUENCE, length 26
    #      06 09 2a864886f70d010701              OID (9 bytes), id-data
    #      a0 0d                                  [0] EXPLICIT, length 13
    #         04 0b 68656c6c6f20776f726c64        OCTET STRING "hello world"
    #                                             (h=68 e=65 l=6c l=6c o=6f
    #                                              sp=20 w=77 o=6f r=72 l=6c d=64)
    ax = _TestContext()
    data_hex = "301a" + "06092a864886f70d010701" + "a00d" + "040b68656c6c6f20776f726c64"
    result = parse_content_info(ax, Asn1Input(data_hex=data_hex))
    assert result.ok is True
    assert result.content_type_oid == "1.2.840.113549.1.7.1"
    assert result.content_type_name == "data"
    assert result.content_present is True
    assert result.content_hex == "a00d040b68656c6c6f20776f726c64"

    tree = result.content_tree
    assert tree.tag_class == "context"
    assert tree.tag_number == 0
    assert tree.constructed is True
    assert len(tree.children) == 1
    inner = tree.children[0]
    assert inner.tag_class == "universal"
    assert inner.tag_number == 4  # OCTET STRING
    assert bytes.fromhex(inner.value_hex) == b"hello world"


def test_parse_content_info_without_content():
    # Hand-computed: ContentInfo { contentType: id-data }, content OMITTED.
    #   30 0b                          SEQUENCE, length 11
    #      06 09 2a864886f70d010701    OID (9 bytes), id-data
    ax = _TestContext()
    data_hex = "300b" + "06092a864886f70d010701"
    result = parse_content_info(ax, Asn1Input(data_hex=data_hex))
    assert result.ok is True
    assert result.content_type_oid == "1.2.840.113549.1.7.1"
    assert result.content_type_name == "data"
    assert result.content_present is False
    assert result.content_hex == ""


def test_parse_content_info_rejects_malformed_input():
    ax = _TestContext()
    result = parse_content_info(ax, Asn1Input(data_hex="0500"))
    assert result.ok is False
    assert result.error != ""


def test_parse_content_info_rejects_outer_valid_inner_corrupt_input():
    """Regression: a ContentInfo SEQUENCE that loads fine at the top level but
    carries a truncated contentType OID must not crash — asn1crypto only
    raises when that lazily-parsed field is actually touched, after .load()
    has already succeeded."""
    ax = _TestContext()
    # 30 04  SEQUENCE, length 4
    #    06 05 2a 86   contentType OID declares length 5, only 2 bytes follow
    result = parse_content_info(ax, Asn1Input(data_hex="300406052a86"))
    assert result.ok is False
    assert result.error != ""


def test_parse_content_info_returns_isinstance_result():
    ax = _TestContext()
    data_hex = "300b" + "06092a864886f70d010701"
    result = parse_content_info(ax, Asn1Input(data_hex=data_hex))
    assert isinstance(result, ContentInfoResult)
