from asn1crypto import keys

from gen.messages_pb2 import Asn1Input, RsaPrivateKeyResult
from gen.axiom_context import AxiomContext
from nodes._asn1_common import Asn1Error, resolve_input_bytes


def _hex(field) -> str:
    n = field.native
    if n < 0:
        raise Asn1Error("unexpected negative RSA field value")
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, "big").hex()


def parse_pkcs1_rsa_key(ax: AxiomContext, input: Asn1Input) -> RsaPrivateKeyResult:
    """Decode a PKCS#1 RSAPrivateKey structure (RFC 8017 — the
    "-----BEGIN RSA PRIVATE KEY-----" traditional format, or the payload
    inside a PKCS#8 PrivateKeyInfo's privateKey field for an RSA key) into
    its full CRT key material: modulus (n), public exponent (e), private
    exponent (d), the two primes (p, q), the two CRT exponents (dP, dQ), and
    the CRT coefficient (qInv) — each as unsigned big-endian hex, plus the
    modulus bit length. Multi-prime keys (RFC 8017's otherPrimeInfos) are not
    supported (two-prime is the overwhelmingly common case; this returns a
    structured error for a multi-prime key rather than silently truncating
    it). Malformed input, or input that isn't an RSAPrivateKey, returns a
    structured error, never a crash.
    """
    try:
        data = resolve_input_bytes(input)
        try:
            rsa = keys.RSAPrivateKey.load(data)
        except Exception as e:
            raise Asn1Error(f"not a valid RSAPrivateKey: {e}") from e

        version_bytes = rsa["version"].contents
        version = int.from_bytes(version_bytes, "big", signed=False) if version_bytes else 0
        if version != 0:
            raise Asn1Error("multi-prime RSA keys (otherPrimeInfos) are not supported")

        modulus = rsa["modulus"].native
        return RsaPrivateKeyResult(
            ok=True,
            version=version,
            modulus_bits=modulus.bit_length(),
            modulus_hex=_hex(rsa["modulus"]),
            public_exponent_hex=_hex(rsa["public_exponent"]),
            private_exponent_hex=_hex(rsa["private_exponent"]),
            prime1_hex=_hex(rsa["prime1"]),
            prime2_hex=_hex(rsa["prime2"]),
            exponent1_hex=_hex(rsa["exponent1"]),
            exponent2_hex=_hex(rsa["exponent2"]),
            coefficient_hex=_hex(rsa["coefficient"]),
        )
    except Asn1Error as e:
        return RsaPrivateKeyResult(ok=False, error=str(e))
