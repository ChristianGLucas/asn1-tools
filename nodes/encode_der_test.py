import base64

from gen.messages_pb2 import Asn1Input, Asn1Node, EncodeDerResult
from nodes.decode_der import decode_der
from nodes.encode_der import encode_der
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


# Same hand-computed DER as decode_der_test.py:
# SEQUENCE { INTEGER 74 (0x4A), UTF8String "Hi" }
HAND_COMPUTED_SEQUENCE_HEX = "300702014a0c024869"


def test_encode_der_matches_hand_computed_bytes():
    ax = _TestContext()
    tree = Asn1Node(
        tag_class="universal",
        tag_number=16,
        constructed=True,
        children=[
            Asn1Node(tag_class="universal", tag_number=2, constructed=False, value_hex="4a"),
            Asn1Node(tag_class="universal", tag_number=12, constructed=False, value_hex="4869"),
        ],
    )
    result = encode_der(ax, tree)
    assert result.ok is True
    assert result.data_hex == HAND_COMPUTED_SEQUENCE_HEX
    assert result.data_base64 == base64.b64encode(bytes.fromhex(HAND_COMPUTED_SEQUENCE_HEX)).decode()


def test_encode_der_accepts_value_base64_too():
    ax = _TestContext()
    tree = Asn1Node(tag_class="universal", tag_number=2, constructed=False, value_base64="Sg==")  # 0x4A
    result = encode_der(ax, tree)
    assert result.ok is True
    assert result.data_hex == "02014a"


def test_encode_der_round_trips_decode_der_output_byte_exact():
    """DecodeDer -> EncodeDer must reproduce the original bytes exactly for a
    real-world structure, not just the trivial hand-built one above."""
    ax = _TestContext()
    original_hex = HAND_COMPUTED_SEQUENCE_HEX
    decoded = decode_der(ax, Asn1Input(data_hex=original_hex))
    assert decoded.ok is True
    reencoded = encode_der(ax, decoded.root)
    assert reencoded.ok is True
    assert reencoded.data_hex == original_hex


def test_encode_der_round_trips_a_real_ec_private_key():
    from nodes._test_fixtures import EC_PKCS8_PEM
    ax = _TestContext()
    decoded = decode_der(ax, Asn1Input(pem=EC_PKCS8_PEM))
    assert decoded.ok is True
    reencoded = encode_der(ax, decoded.root)
    assert reencoded.ok is True

    # Independently recover the expected DER bytes via base64, not via any
    # code path shared with DecodeDer/EncodeDer.
    lines = [l for l in EC_PKCS8_PEM.strip().splitlines() if "-----" not in l]
    expected_der = base64.b64decode("".join(lines))
    assert reencoded.data_hex == expected_der.hex()


def test_encode_der_rejects_unknown_tag_class():
    ax = _TestContext()
    tree = Asn1Node(tag_class="bogus", tag_number=1, constructed=False, value_hex="ff")
    result = encode_der(ax, tree)
    assert result.ok is False
    assert result.error != ""


def test_encode_der_rejects_invalid_value_hex():
    ax = _TestContext()
    tree = Asn1Node(tag_class="universal", tag_number=2, constructed=False, value_hex="zz")
    result = encode_der(ax, tree)
    assert result.ok is False
    assert result.error != ""


def test_encode_der_returns_isinstance_result():
    ax = _TestContext()
    result = encode_der(ax, Asn1Node(tag_class="universal", tag_number=5, constructed=False))
    assert isinstance(result, EncodeDerResult)
