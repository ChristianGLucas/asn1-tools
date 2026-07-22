from gen.messages_pb2 import Asn1Input, PublicKeyInfoResult
from nodes.parse_subject_public_key_info import parse_subject_public_key_info
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


def test_parse_subject_public_key_info_rsa_embeds_openssl_modulus():
    from nodes._test_fixtures import RSA_PUB_PEM, RSA_MODULUS_HEX
    ax = _TestContext()
    result = parse_subject_public_key_info(ax, Asn1Input(pem=RSA_PUB_PEM))
    assert result.ok is True
    assert result.algorithm_oid == "1.2.840.113549.1.1.1"
    assert result.algorithm_name == "rsa"
    assert result.algorithm_parameters_hex == "0500"
    # Independent oracle: the openssl-computed modulus is embedded (as the
    # nested RSAPublicKey DER) inside the BIT STRING content.
    assert RSA_MODULUS_HEX.lower() in result.public_key_hex.lower()
    # 271 raw bytes (including the 1 leading unused-bits byte) -> 270*8 bits.
    assert result.public_key_bits == 2160


def test_parse_subject_public_key_info_ec_matches_captured_bytes():
    ax = _TestContext()
    from nodes._test_fixtures import EC_PUB_PEM, EC_P256_PARAMS_HEX
    result = parse_subject_public_key_info(ax, Asn1Input(pem=EC_PUB_PEM))
    assert result.ok is True
    assert result.algorithm_oid == "1.2.840.10045.2.1"
    assert result.algorithm_name == "ec"
    assert result.algorithm_parameters_hex == EC_P256_PARAMS_HEX
    # Independently captured via direct asn1crypto introspection during
    # development (see package retrospective); cross-checked here structurally:
    # an uncompressed P-256 point is 0x04 + 32-byte X + 32-byte Y = 65 bytes,
    # plus 1 leading unused-bits byte = 66 raw bytes -> 65*8 = 520 bits.
    assert result.public_key_bits == 520
    pk = bytes.fromhex(result.public_key_hex)
    assert len(pk) == 66
    assert pk[0] == 0  # zero unused bits
    assert pk[1] == 0x04  # uncompressed EC point marker


def test_parse_subject_public_key_info_ed25519():
    from nodes._test_fixtures import ED25519_PUB_PEM, ED25519_OID
    ax = _TestContext()
    result = parse_subject_public_key_info(ax, Asn1Input(pem=ED25519_PUB_PEM))
    assert result.ok is True
    assert result.algorithm_oid == ED25519_OID
    assert result.algorithm_name == "ed25519"
    assert result.algorithm_parameters_hex == ""
    # A raw Ed25519 public key is exactly 32 bytes -> 256 bits.
    assert result.public_key_bits == 256
    pk = bytes.fromhex(result.public_key_hex)
    assert len(pk) == 33  # 1 unused-bits byte + 32 key bytes
    assert pk[0] == 0


def test_parse_subject_public_key_info_rejects_malformed_input():
    ax = _TestContext()
    result = parse_subject_public_key_info(ax, Asn1Input(data_hex="0500"))
    assert result.ok is False
    assert result.error != ""


def test_parse_subject_public_key_info_returns_isinstance_result():
    from nodes._test_fixtures import RSA_PUB_PEM
    ax = _TestContext()
    result = parse_subject_public_key_info(ax, Asn1Input(pem=RSA_PUB_PEM))
    assert isinstance(result, PublicKeyInfoResult)
