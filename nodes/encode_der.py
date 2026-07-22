import base64

from gen.messages_pb2 import Asn1Node, EncodeDerResult
from gen.axiom_context import AxiomContext
from nodes._asn1_common import Asn1Error, encode_tree


def encode_der(ax: AxiomContext, input: Asn1Node) -> EncodeDerResult:
    """Encode a generic Asn1Node tree (of the same shape DecodeDer produces)
    back into DER bytes — the structural inverse of DecodeDer. Recurses
    depth-first: a constructed node's encoded content is its children's
    encoded bytes concatenated in order; a primitive node's content is its
    value_hex (or value_base64) raw bytes taken as-is. The typed convenience
    fields (value_oid, value_integer, value_string, ...) are decode-only and
    are NOT consulted here — only tag_class/tag_number/constructed/value_hex/
    value_base64/children — so DecodeDer -> EncodeDer round-trips any
    well-formed input byte-for-byte. An unknown tag_class, a negative
    tag_number, or unparsable value_hex/value_base64 returns a structured
    error rather than a crash.
    """
    try:
        data = encode_tree(input)
        return EncodeDerResult(ok=True, data_hex=data.hex(), data_base64=base64.b64encode(data).decode("ascii"))
    except Asn1Error as e:
        return EncodeDerResult(ok=False, error=str(e))
