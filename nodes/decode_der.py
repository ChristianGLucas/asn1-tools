from gen.messages_pb2 import Asn1Input, DecodeDerResult
from gen.axiom_context import AxiomContext
from nodes._asn1_common import Asn1Error, decode_tree, resolve_input_bytes


def decode_der(ax: AxiomContext, input: Asn1Input) -> DecodeDerResult:
    """Decode a caller-supplied ASN.1 BER/CER/DER blob (as pem, data_base64, or
    data_hex — see Asn1Input) into a generic, recursively-structured tree: every
    TLV's tag class/number, constructed flag, content length, nested children,
    raw content bytes (hex + base64), and — for recognized universal primitive
    types (BOOLEAN, INTEGER/ENUMERATED, OBJECT IDENTIFIER, NULL, BIT STRING,
    UTCTime/GeneralizedTime, and the text-string variants) — a best-effort typed
    interpretation. This is a schema-free structural decode: it makes no
    assumption about what the bytes represent (a certificate, a key, a protocol
    message, or an arbitrary ASN.1 structure), unlike the schema-specific
    Parse* nodes in this package. Malformed input, a truncated encoding, or an
    over-nested/over-sized structure returns a structured error, never a crash.
    """
    try:
        data = resolve_input_bytes(input)
        root = decode_tree(data)
        return DecodeDerResult(ok=True, root=root)
    except Asn1Error as e:
        return DecodeDerResult(ok=False, error=str(e))
