from asn1crypto import pem as asn1_pem

from gen.messages_pb2 import PemEncodeInput, PemEncodeResult
from gen.axiom_context import AxiomContext
from nodes._asn1_common import Asn1Error, MAX_INPUT_BYTES, bytes_from_hex_or_base64


def encode_pem(ax: AxiomContext, input: PemEncodeInput) -> PemEncodeResult:
    """Armor raw DER/BER bytes (as data_hex or data_base64 — exactly one) into
    PEM text under the given label (e.g. "CERTIFICATE", "PRIVATE KEY"), with
    optional legacy "Name: Value" headers written after the BEGIN line. The
    inverse of DecodePem for a single block. A blank label, or input bytes
    exceeding the size bound, returns a structured error rather than a crash.
    """
    try:
        if not input.label.strip():
            raise Asn1Error("label is required")
        data = bytes_from_hex_or_base64(input.data_hex, input.data_base64)
        if len(data) > MAX_INPUT_BYTES:
            raise Asn1Error("decoded input exceeds maximum size")
        pem_bytes = asn1_pem.armor(input.label, data, dict(input.headers) if input.headers else None)
        return PemEncodeResult(ok=True, pem=pem_bytes.decode("ascii"))
    except Asn1Error as e:
        return PemEncodeResult(ok=False, error=str(e))
