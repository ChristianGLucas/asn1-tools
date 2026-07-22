from gen.messages_pb2 import Asn1Input, PrivateKeyInfoResult
from nodes.parse_private_key_info import parse_private_key_info
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


def test_parse_private_key_info_rsa_matches_openssl_modulus():
    from nodes._test_fixtures import RSA_PKCS8_PEM, RSA_MODULUS_HEX
    ax = _TestContext()
    result = parse_private_key_info(ax, Asn1Input(pem=RSA_PKCS8_PEM))
    assert result.ok is True
    assert result.version == 0
    assert result.algorithm_oid == "1.2.840.113549.1.1.1"
    assert result.algorithm_name == "rsa"
    assert result.algorithm_parameters_hex == "0500"  # RSA's conventional NULL params
    # Independent oracle: the openssl-computed modulus must appear inside the
    # still-encoded RSAPrivateKey bytes carried in privateKey.
    assert RSA_MODULUS_HEX.lower() in result.private_key_hex.lower()


def test_parse_private_key_info_ec_p256():
    from nodes._test_fixtures import EC_PKCS8_PEM, EC_P256_PARAMS_HEX
    ax = _TestContext()
    result = parse_private_key_info(ax, Asn1Input(pem=EC_PKCS8_PEM))
    assert result.ok is True
    assert result.version == 0
    assert result.algorithm_oid == "1.2.840.10045.2.1"
    assert result.algorithm_name == "ec"
    # The EC AlgorithmIdentifier's parameters are the named-curve OID
    # (prime256v1) — independently hand-verified in parse_algorithm_identifier_test.py.
    assert result.algorithm_parameters_hex == EC_P256_PARAMS_HEX


def test_parse_private_key_info_ed25519_matches_openssl_asn1parse():
    from nodes._test_fixtures import ED25519_PKCS8_PEM, ED25519_OID, ED25519_PRIVATE_KEY_FIELD_HEX
    ax = _TestContext()
    result = parse_private_key_info(ax, Asn1Input(pem=ED25519_PKCS8_PEM))
    assert result.ok is True
    assert result.version == 0
    assert result.algorithm_oid == ED25519_OID
    assert result.algorithm_name == "ed25519"
    assert result.algorithm_parameters_hex == ""  # Ed25519 carries no algorithm parameters
    # Independent oracle: `openssl asn1parse` printed this exact hex dump for
    # the privateKey OCTET STRING's raw content.
    assert result.private_key_hex == ED25519_PRIVATE_KEY_FIELD_HEX


def test_parse_private_key_info_rejects_malformed_input():
    ax = _TestContext()
    result = parse_private_key_info(ax, Asn1Input(data_hex="0500"))
    assert result.ok is False
    assert result.error != ""


def test_parse_private_key_info_rejects_outer_valid_inner_corrupt_input():
    """Regression: a PrivateKeyInfo SEQUENCE that loads fine at the top level
    but carries a truncated privateKeyAlgorithm (an OID declaring 5 content
    bytes, only 2 supplied) must not crash — asn1crypto only raises when that
    lazily-parsed field is actually touched, after .load() has already
    succeeded."""
    ax = _TestContext()
    # 30 0d  SEQUENCE, length 13
    #    02 01 00                    version 0
    #    30 04 06 05 2a 86           privateKeyAlgorithm: truncated OID (as above)
    #    02 00 01                    (padding/garbage to fill the declared outer length)
    result = parse_private_key_info(ax, Asn1Input(data_hex="300d020100300406052a8604020001"))
    assert result.ok is False
    assert result.error != ""


def test_parse_private_key_info_returns_isinstance_result():
    from nodes._test_fixtures import RSA_PKCS8_PEM
    ax = _TestContext()
    result = parse_private_key_info(ax, Asn1Input(pem=RSA_PKCS8_PEM))
    assert isinstance(result, PrivateKeyInfoResult)
