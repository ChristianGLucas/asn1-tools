from gen.messages_pb2 import OidInput, OidResult
from nodes.lookup_oid import lookup_oid
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


def test_lookup_oid_rsa_encryption():
    # 1.2.840.113549.1.1.1 (rsaEncryption) is a publicly documented, fixed
    # OID (RFC 8017 Appendix A.1) — independent of asn1crypto's own map.
    ax = _TestContext()
    result = lookup_oid(ax, OidInput(oid="1.2.840.113549.1.1.1"))
    assert result.ok is True
    assert result.known is True
    assert result.name == "rsa"
    assert result.category == "public_key_algorithm"


def test_lookup_oid_sha256_digest():
    # 2.16.840.1.101.3.4.2.1 (id-sha256) is the published NIST OID (FIPS 180-4
    # / RFC 5754), independent of this codebase.
    ax = _TestContext()
    result = lookup_oid(ax, OidInput(oid="2.16.840.1.101.3.4.2.1"))
    assert result.ok is True
    assert result.known is True
    assert result.name == "sha256"
    assert result.category == "digest_algorithm"


def test_lookup_oid_ec_public_key():
    # 1.2.840.10045.2.1 (id-ecPublicKey), published in RFC 5480.
    ax = _TestContext()
    result = lookup_oid(ax, OidInput(oid="1.2.840.10045.2.1"))
    assert result.ok is True
    assert result.known is True
    assert result.name == "ec"
    assert result.category == "public_key_algorithm"


def test_lookup_oid_pkcs7_data_content_type():
    # 1.2.840.113549.1.7.1 (id-data), published in RFC 5652.
    ax = _TestContext()
    result = lookup_oid(ax, OidInput(oid="1.2.840.113549.1.7.1"))
    assert result.ok is True
    assert result.known is True
    assert result.name == "data"
    assert result.category == "content_type"


def test_lookup_oid_unknown_but_well_formed():
    ax = _TestContext()
    result = lookup_oid(ax, OidInput(oid="1.2.3.4.5.6.7.8.9"))
    assert result.ok is True
    assert result.known is False
    assert result.name == ""
    assert result.category == ""


def test_lookup_oid_rejects_invalid_format():
    ax = _TestContext()
    result = lookup_oid(ax, OidInput(oid="not-an-oid"))
    assert result.ok is False
    assert result.error != ""


def test_lookup_oid_returns_isinstance_result():
    ax = _TestContext()
    result = lookup_oid(ax, OidInput(oid="1.2.3"))
    assert isinstance(result, OidResult)
