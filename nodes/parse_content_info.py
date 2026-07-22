from asn1crypto import cms

from gen.messages_pb2 import Asn1Input, ContentInfoResult
from gen.axiom_context import AxiomContext
from nodes._asn1_common import Asn1Error, decode_tree, lookup_oid_info, resolve_input_bytes


def parse_content_info(ax: AxiomContext, input: Asn1Input) -> ContentInfoResult:
    """Decode a CMS/PKCS#7 ContentInfo envelope (the outermost `SEQUENCE {
    contentType OBJECT IDENTIFIER, content [0] EXPLICIT ANY OPTIONAL }`
    wrapper around every CMS message — SignedData, EnvelopedData,
    DigestedData, EncryptedData, AuthenticatedData, ...) into its
    content-type OID + recognized name, and the inner content, both as raw
    DER (content_hex, including its `[0]` EXPLICIT tag) and — since it is
    itself a well-formed ASN.1 value — a generic decoded tree via the same
    structure DecodeDer produces. This is a purely STRUCTURAL unwrap: it does
    NOT decrypt EnvelopedData/EncryptedData, verify SignedData's signatures,
    or interpret the content-type-specific schema beyond the generic tree —
    pair it with DecodeDer to walk further into a specific content type's
    fields. content_present=false (not an error) when the OPTIONAL content
    field was omitted. Malformed input, or input that isn't a ContentInfo,
    returns a structured error, never a crash.
    """
    try:
        data = resolve_input_bytes(input)
        ci = cms.ContentInfo.load(data)

        # asn1crypto parses fields LAZILY: a structurally well-formed outer
        # SEQUENCE can still carry a corrupt/truncated inner field, which only
        # raises when that field is actually touched (below), not at .load().
        # Every access is inside this same try block so that case is caught
        # too, not just a bad outer shape.
        content_type_oid = ci["content_type"].dotted
        _category, content_type_name = lookup_oid_info(content_type_oid)
        content_der = ci["content"].dump()

        result = ContentInfoResult(
            ok=True,
            content_type_oid=content_type_oid,
            content_type_name=content_type_name,
            content_present=len(content_der) > 0,
            content_hex=content_der.hex(),
        )
        if content_der:
            try:
                result.content_tree.CopyFrom(decode_tree(content_der))
            except Asn1Error:
                pass  # raw bytes are still returned; tree is best-effort
        return result
    except Asn1Error as e:
        return ContentInfoResult(ok=False, error=str(e))
    except Exception as e:
        return ContentInfoResult(ok=False, error=f"not a valid ContentInfo: {e}")
