import base64

from gen.messages_pb2 import PemEncodeInput, PemEncodeResult, PemInput
from nodes.encode_pem import encode_pem
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


def test_encode_pem_matches_hand_built_armor():
    ax = _TestContext()
    data = b"hello world"
    result = encode_pem(ax, PemEncodeInput(label="TEST", data_hex=data.hex()))
    assert result.ok is True
    # Hand-built expected PEM (independent of asn1crypto.pem.armor): standard
    # base64 of the bytes, wrapped at 64 chars, under BEGIN/END TEST markers.
    b64 = base64.b64encode(data).decode()
    expected = "-----BEGIN TEST-----\n" + b64 + "\n-----END TEST-----\n"
    assert result.pem == expected


def test_encode_pem_round_trips_through_decode_pem():
    ax = _TestContext()
    data = bytes(range(256))  # exercise every byte value
    encoded = encode_pem(ax, PemEncodeInput(label="CERTIFICATE", data_base64=base64.b64encode(data).decode()))
    assert encoded.ok is True
    decoded = decode_pem(ax, PemInput(pem=encoded.pem))
    assert decoded.ok is True
    assert len(decoded.blocks) == 1
    assert decoded.blocks[0].label == "CERTIFICATE"
    assert bytes.fromhex(decoded.blocks[0].der_hex) == data


def test_encode_pem_with_headers_round_trips():
    ax = _TestContext()
    encoded = encode_pem(ax, PemEncodeInput(
        label="RSA PRIVATE KEY",
        data_hex=b"secret".hex(),
        headers={"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,0123456789ABCDEF"},
    ))
    assert encoded.ok is True
    assert "Proc-Type: 4,ENCRYPTED" in encoded.pem
    assert "DEK-Info: AES-128-CBC,0123456789ABCDEF" in encoded.pem
    decoded = decode_pem(ax, PemInput(pem=encoded.pem))
    assert decoded.ok is True
    assert dict(decoded.blocks[0].headers) == {"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,0123456789ABCDEF"}


def test_encode_pem_rejects_blank_label():
    ax = _TestContext()
    result = encode_pem(ax, PemEncodeInput(label="  ", data_hex="ff"))
    assert result.ok is False
    assert result.error != ""


def test_encode_pem_rejects_missing_data():
    ax = _TestContext()
    result = encode_pem(ax, PemEncodeInput(label="TEST"))
    assert result.ok is False
    assert result.error != ""


def test_encode_pem_returns_isinstance_result():
    ax = _TestContext()
    result = encode_pem(ax, PemEncodeInput(label="TEST", data_hex="00"))
    assert isinstance(result, PemEncodeResult)
