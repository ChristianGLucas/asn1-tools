import base64

from gen.messages_pb2 import PemInput, PemDecodeResult, PemBlock
from gen.axiom_context import AxiomContext
from nodes._asn1_common import Asn1Error, iter_pem_blocks


def decode_pem(ax: AxiomContext, input: PemInput) -> PemDecodeResult:
    """Split a PEM text — one or more concatenated "-----BEGIN X-----" /
    "-----END X-----" armored blocks, of any label (CERTIFICATE, PRIVATE KEY,
    RSA PRIVATE KEY, PUBLIC KEY, CERTIFICATE REQUEST, ...) — into its
    individual blocks, each de-armored to raw DER bytes (hex + base64) plus
    its label and any legacy "Name: Value" headers (e.g. the old
    Proc-Type/DEK-Info pair on an encrypted PEM key). A pure PEM-envelope
    operation — the DER payload of each block is returned as bytes only, not
    further decoded; feed it to DecodeDer or one of this package's Parse*
    nodes for structural decoding. Malformed or non-PEM input returns a
    structured error, never a crash.
    """
    try:
        blocks = iter_pem_blocks(input.pem)
        result = PemDecodeResult(ok=True)
        for label, headers, der_bytes in blocks:
            result.blocks.append(PemBlock(
                label=label,
                headers=dict(headers or {}),
                der_hex=der_bytes.hex(),
                der_base64=base64.b64encode(der_bytes).decode("ascii"),
            ))
        return result
    except Asn1Error as e:
        return PemDecodeResult(ok=False, error=str(e))
