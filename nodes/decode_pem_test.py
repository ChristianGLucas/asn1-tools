import base64

from gen.messages_pb2 import PemInput, PemDecodeResult
from nodes.decode_pem import decode_pem
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


def test_decode_pem_single_block_matches_independent_base64_decode():
    from nodes._test_fixtures import ED25519_PKCS8_PEM
    ax = _TestContext()
    result = decode_pem(ax, PemInput(pem=ED25519_PKCS8_PEM))
    assert result.ok is True
    assert len(result.blocks) == 1
    block = result.blocks[0]
    assert block.label == "PRIVATE KEY"

    # Independent oracle: decode the base64 payload with the plain stdlib
    # base64 module directly off the PEM text, bypassing asn1crypto.pem
    # entirely, and confirm it matches what DecodePem produced.
    lines = [l for l in ED25519_PKCS8_PEM.strip().splitlines() if "-----" not in l]
    expected_der = base64.b64decode("".join(lines))
    assert block.der_hex == expected_der.hex()
    assert block.der_base64 == base64.b64encode(expected_der).decode()


def test_decode_pem_multi_block_concatenated_text():
    ax = _TestContext()
    block_a = "-----BEGIN A-----\n" + base64.b64encode(b"hello").decode() + "\n-----END A-----\n"
    block_b = "-----BEGIN B-----\n" + base64.b64encode(b"world!").decode() + "\n-----END B-----\n"
    result = decode_pem(ax, PemInput(pem=block_a + block_b))
    assert result.ok is True
    assert len(result.blocks) == 2
    assert result.blocks[0].label == "A"
    assert result.blocks[0].der_hex == b"hello".hex()
    assert result.blocks[1].label == "B"
    assert result.blocks[1].der_hex == b"world!".hex()


def test_decode_pem_rejects_non_pem_text():
    ax = _TestContext()
    result = decode_pem(ax, PemInput(pem="this is not PEM data at all"))
    assert result.ok is False
    assert result.error != ""


def test_decode_pem_rejects_empty_input():
    ax = _TestContext()
    result = decode_pem(ax, PemInput(pem=""))
    assert result.ok is False
    assert result.error != ""


def test_decode_pem_returns_isinstance_result():
    ax = _TestContext()
    result = decode_pem(ax, PemInput(pem="not pem"))
    assert isinstance(result, PemDecodeResult)
