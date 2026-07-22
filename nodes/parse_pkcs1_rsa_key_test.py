from gen.messages_pb2 import Asn1Input, RsaPrivateKeyResult
from nodes.parse_pkcs1_rsa_key import parse_pkcs1_rsa_key
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


def test_parse_pkcs1_rsa_key_matches_openssl_modulus_and_exponent():
    from nodes._test_fixtures import RSA_PKCS1_PEM, RSA_MODULUS_HEX, RSA_PUBLIC_EXPONENT_HEX
    ax = _TestContext()
    result = parse_pkcs1_rsa_key(ax, Asn1Input(pem=RSA_PKCS1_PEM))
    assert result.ok is True
    assert result.version == 0
    assert result.modulus_bits == 2048
    # Independent oracle: `openssl rsa -noout -modulus` on the SAME key.
    assert result.modulus_hex.upper() == RSA_MODULUS_HEX
    # Independent oracle: `openssl rsa -noout -text` printed
    # "publicExponent: 65537 (0x10001)".
    assert result.public_exponent_hex == RSA_PUBLIC_EXPONENT_HEX
    # Structural sanity: p*q must reconstruct n (a from-scratch arithmetic
    # check independent of asn1crypto's own decoding).
    p = int(result.prime1_hex, 16)
    q = int(result.prime2_hex, 16)
    n = int(result.modulus_hex, 16)
    assert p * q == n
    # CRT coefficient/exponent identities (RFC 8017 section 3.2), checked
    # from scratch:
    d = int(result.private_exponent_hex, 16)
    e = int(result.public_exponent_hex, 16)
    assert (d * e) % (p - 1) == 1  # d*e == 1 (mod lcm(p-1,q-1)), which implies mod (p-1) too
    dp = int(result.exponent1_hex, 16)
    dq = int(result.exponent2_hex, 16)
    assert dp == d % (p - 1)
    assert dq == d % (q - 1)
    q_inv = int(result.coefficient_hex, 16)
    assert (q_inv * q) % p == 1


def test_parse_pkcs1_rsa_key_rejects_malformed_input():
    ax = _TestContext()
    result = parse_pkcs1_rsa_key(ax, Asn1Input(data_hex="0500"))
    assert result.ok is False
    assert result.error != ""


def test_parse_pkcs1_rsa_key_rejects_outer_valid_inner_corrupt_input():
    """Regression: a RSAPrivateKey SEQUENCE that loads fine at the top level
    but carries a truncated inner INTEGER field must not crash — asn1crypto
    only raises when that lazily-parsed field is actually touched, after
    .load() has already succeeded."""
    ax = _TestContext()
    # 30 07  SEQUENCE, length 7
    #    02 01 00        version 0
    #    02 05 00 01     modulus INTEGER declares length 5, only 2 bytes follow
    result = parse_pkcs1_rsa_key(ax, Asn1Input(data_hex="300702010002050001"))
    assert result.ok is False
    assert result.error != ""


def test_parse_pkcs1_rsa_key_rejects_multi_prime_version():
    """Patch the real key's version field from 0 (two-prime) to 1 (multi) —
    a minimal, surgical byte edit independent of any encoding logic under
    test — and confirm the node rejects it rather than silently truncating
    otherPrimeInfos."""
    import base64
    from nodes._test_fixtures import RSA_PKCS1_PEM
    lines = [l for l in RSA_PKCS1_PEM.strip().splitlines() if "-----" not in l]
    der = bytearray(base64.b64decode("".join(lines)))
    # The very first INTEGER in an RSAPrivateKey is its version; its DER
    # encoding for value 0 is the 3 bytes 02 01 00, appearing immediately
    # after the outer SEQUENCE header.
    patched = bytes(der).replace(b"\x02\x01\x00", b"\x02\x01\x01", 1)
    assert patched != bytes(der)  # sanity: the replacement actually happened

    ax = _TestContext()
    result = parse_pkcs1_rsa_key(ax, Asn1Input(data_hex=patched.hex()))
    assert result.ok is False
    assert "multi" in result.error.lower()


def test_parse_pkcs1_rsa_key_returns_isinstance_result():
    from nodes._test_fixtures import RSA_PKCS1_PEM
    ax = _TestContext()
    result = parse_pkcs1_rsa_key(ax, Asn1Input(pem=RSA_PKCS1_PEM))
    assert isinstance(result, RsaPrivateKeyResult)
