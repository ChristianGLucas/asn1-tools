import base64

from asn1crypto import keys

from gen.messages_pb2 import Asn1Input, PublicKeyInfoResult
from gen.axiom_context import AxiomContext
from nodes._asn1_common import Asn1Error, lookup_oid_info, resolve_input_bytes


def parse_subject_public_key_info(ax: AxiomContext, input: Asn1Input) -> PublicKeyInfoResult:
    """Decode a SubjectPublicKeyInfo structure (the standard, algorithm-
    agnostic `SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT
    STRING }` wrapper used by "-----BEGIN PUBLIC KEY-----" for RSA, EC,
    Ed25519, Ed448, X25519, X448, and DSA keys alike — the same wrapper a
    certificate's own public key field uses) into its algorithm OID +
    recognized name, the algorithm's own parameters (e.g. a named curve OID
    for EC), and the raw subjectPublicKey BIT STRING content (its full raw
    octets, including the leading unused-bits-count byte per X.690 — see
    public_key_bits for the actual bit length) — still an algorithm-specific
    encoding (a nested RSAPublicKey DER structure for RSA, a raw EC point for
    EC, a raw scalar for Ed25519/X25519), returned as-is rather than further
    decoded. Standalone key-structure parsing, independent of any certificate
    wrapper (see christiangeorgelucas/certificate-tools' ExtractPublicKey for
    a certificate-specific equivalent). Malformed input, or input that isn't
    a SubjectPublicKeyInfo, returns a structured error, never a crash.
    """
    try:
        data = resolve_input_bytes(input)
        try:
            spki = keys.PublicKeyInfo.load(data)
        except Exception as e:
            raise Asn1Error(f"not a valid SubjectPublicKeyInfo: {e}") from e

        algo = spki["algorithm"]
        algo_oid = algo["algorithm"].dotted
        _category, algo_name = lookup_oid_info(algo_oid)
        algo_params = algo["parameters"].dump()
        pk_bytes = spki["public_key"].contents
        unused_bits = pk_bytes[0] if pk_bytes else 0
        bit_length = max((len(pk_bytes) - 1) * 8 - unused_bits, 0) if pk_bytes else 0

        return PublicKeyInfoResult(
            ok=True,
            algorithm_oid=algo_oid,
            algorithm_name=algo_name,
            algorithm_parameters_hex=algo_params.hex(),
            public_key_bits=bit_length,
            public_key_hex=pk_bytes.hex(),
            public_key_base64=base64.b64encode(pk_bytes).decode("ascii"),
        )
    except Asn1Error as e:
        return PublicKeyInfoResult(ok=False, error=str(e))
