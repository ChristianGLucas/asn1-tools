import base64

from asn1crypto import keys

from gen.messages_pb2 import Asn1Input, PrivateKeyInfoResult
from gen.axiom_context import AxiomContext
from nodes._asn1_common import Asn1Error, lookup_oid_info, resolve_input_bytes


def parse_private_key_info(ax: AxiomContext, input: Asn1Input) -> PrivateKeyInfoResult:
    """Decode a PKCS#8 PrivateKeyInfo structure (the standard, algorithm-
    agnostic `SEQUENCE { version, privateKeyAlgorithm, privateKey OCTET
    STRING, attributes OPTIONAL }` wrapper used by "-----BEGIN PRIVATE
    KEY-----" for RSA, EC, Ed25519, Ed448, X25519, X448, and DSA keys alike)
    into its version, algorithm OID + recognized name, the algorithm's own
    parameters (e.g. a named curve OID for EC, NULL for RSA, absent for
    Ed25519/X25519), and the raw privateKey OCTET STRING content — which is
    itself still an algorithm-specific encoding (an RSAPrivateKey DER
    structure for RSA — see ParsePkcs1RsaKey — or a raw scalar for the
    Montgomery/Edwards curves), returned as-is rather than further decoded.
    Standalone key-structure parsing, independent of any certificate wrapper.
    Malformed input, or input that isn't a PrivateKeyInfo, returns a
    structured error, never a crash.
    """
    try:
        data = resolve_input_bytes(input)
        try:
            pki = keys.PrivateKeyInfo.load(data)
        except Exception as e:
            raise Asn1Error(f"not a valid PrivateKeyInfo: {e}") from e

        version = int.from_bytes(pki["version"].contents, "big", signed=False) if pki["version"].contents else 0
        algo = pki["private_key_algorithm"]
        algo_oid = algo["algorithm"].dotted
        _category, algo_name = lookup_oid_info(algo_oid)
        algo_params = algo["parameters"].dump()
        private_key_bytes = pki["private_key"].contents

        return PrivateKeyInfoResult(
            ok=True,
            version=version,
            algorithm_oid=algo_oid,
            algorithm_name=algo_name,
            algorithm_parameters_hex=algo_params.hex(),
            private_key_hex=private_key_bytes.hex(),
            private_key_base64=base64.b64encode(private_key_bytes).decode("ascii"),
        )
    except Asn1Error as e:
        return PrivateKeyInfoResult(ok=False, error=str(e))
