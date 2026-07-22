from asn1crypto import algos

from gen.messages_pb2 import Asn1Input, AlgorithmIdentifierResult
from gen.axiom_context import AxiomContext
from nodes._asn1_common import Asn1Error, decode_tree, lookup_oid_info, resolve_input_bytes


def parse_algorithm_identifier(ax: AxiomContext, input: Asn1Input) -> AlgorithmIdentifierResult:
    """Decode a standalone AlgorithmIdentifier — the `SEQUENCE { algorithm
    OBJECT IDENTIFIER, parameters ANY OPTIONAL }` structure that appears
    throughout PKCS/X.509/CMS wherever an algorithm and its tuning parameters
    are named (a certificate's signatureAlgorithm, a PrivateKeyInfo's
    privateKeyAlgorithm, a DigestInfo's digestAlgorithm, ...) — into its OID,
    a recognized friendly name (checked against public-key/signed-digest/
    digest-algorithm OID registries), and its parameters, both as raw DER
    (parameters_hex) and — when the parameters are themselves a well-formed
    ASN.1 value — a generic decoded tree via the same structure DecodeDer
    produces. parameters_present=false (not an error) when the OPTIONAL
    parameters field was omitted entirely (distinct from parameters being
    present but NULL, e.g. plain RSA's conventional `NULL` parameters).
    Malformed input returns a structured error, never a crash.
    """
    try:
        data = resolve_input_bytes(input)
        ai = algos.AlgorithmIdentifier.load(data)

        # asn1crypto parses fields LAZILY: a structurally well-formed outer
        # SEQUENCE can still carry a corrupt/truncated inner field, which only
        # raises when that field is actually touched (below), not at .load().
        # Every access is inside this same try block so that case is caught
        # too, not just a bad outer shape.
        oid = ai["algorithm"].dotted
        _category, name = lookup_oid_info(oid)
        params_der = ai["parameters"].dump()

        result = AlgorithmIdentifierResult(
            ok=True,
            oid=oid,
            name=name,
            parameters_present=len(params_der) > 0,
            parameters_hex=params_der.hex(),
        )
        if params_der:
            try:
                result.parameters_tree.CopyFrom(decode_tree(params_der))
            except Asn1Error:
                pass  # parameters raw bytes are still returned; tree is best-effort
        return result
    except Asn1Error as e:
        return AlgorithmIdentifierResult(ok=False, error=str(e))
    except Exception as e:
        return AlgorithmIdentifierResult(ok=False, error=f"not a valid AlgorithmIdentifier: {e}")
