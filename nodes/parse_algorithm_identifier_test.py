from gen.messages_pb2 import Asn1Input, AlgorithmIdentifierResult
from nodes.parse_algorithm_identifier import parse_algorithm_identifier
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


def test_parse_algorithm_identifier_sha256_no_parameters():
    # Hand-computed: SEQUENCE { OID 2.16.840.1.101.3.4.2.1 (sha256) }, no
    # parameters field at all.
    #   30 0b                        SEQUENCE, length 11
    #      06 09 60 86 48 01 65 03 04 02 01   OID (9 bytes), sha256
    ax = _TestContext()
    result = parse_algorithm_identifier(ax, Asn1Input(data_hex="300b0609608648016503040201"))
    assert result.ok is True
    assert result.oid == "2.16.840.1.101.3.4.2.1"
    assert result.name == "sha256"
    assert result.parameters_present is False
    assert result.parameters_hex == ""


def test_parse_algorithm_identifier_rsa_with_null_parameters():
    # Hand-computed: SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL }
    #   30 0d                                   SEQUENCE, length 13
    #      06 09 2a 86 48 86 f7 0d 01 01 01      OID (9 bytes), rsaEncryption
    #      05 00                                 NULL parameters
    ax = _TestContext()
    result = parse_algorithm_identifier(ax, Asn1Input(data_hex="300d06092a864886f70d0101010500"))
    assert result.ok is True
    assert result.oid == "1.2.840.113549.1.1.1"
    assert result.name == "rsa"
    assert result.parameters_present is True
    assert result.parameters_hex == "0500"
    assert result.parameters_tree.tag_class == "universal"
    assert result.parameters_tree.tag_number == 5
    assert result.parameters_tree.value_kind == "null"


def test_parse_algorithm_identifier_ec_with_curve_oid_parameters():
    from nodes._test_fixtures import EC_P256_PARAMS_HEX
    # SEQUENCE { OID ecPublicKey, OID prime256v1 } — EC's AlgorithmIdentifier
    # parameters are themselves an OID naming the curve.
    #   30 13
    #      06 07 2a8648ce3d0201            OID ecPublicKey (1.2.840.10045.2.1)
    #      06 08 2a8648ce3d030107          OID prime256v1  (1.2.840.10045.3.1.7)
    data_hex = "3013" + "06072a8648ce3d0201" + EC_P256_PARAMS_HEX
    ax = _TestContext()
    result = parse_algorithm_identifier(ax, Asn1Input(data_hex=data_hex))
    assert result.ok is True
    assert result.oid == "1.2.840.10045.2.1"
    assert result.name == "ec"
    assert result.parameters_present is True
    assert result.parameters_hex == EC_P256_PARAMS_HEX
    assert result.parameters_tree.value_kind == "oid"
    assert result.parameters_tree.value_oid == "1.2.840.10045.3.1.7"


def test_parse_algorithm_identifier_rejects_malformed_input():
    ax = _TestContext()
    result = parse_algorithm_identifier(ax, Asn1Input(data_hex="0500"))  # a NULL, not a SEQUENCE
    assert result.ok is False
    assert result.error != ""


def test_parse_algorithm_identifier_returns_isinstance_result():
    ax = _TestContext()
    result = parse_algorithm_identifier(ax, Asn1Input(data_hex="300b0609608648016503040201"))
    assert isinstance(result, AlgorithmIdentifierResult)
