import re

from gen.messages_pb2 import OidInput, OidResult
from gen.axiom_context import AxiomContext
from nodes._asn1_common import lookup_oid_info

_OID_RE = re.compile(r"^\d+(\.\d+)+$")


def lookup_oid(ax: AxiomContext, input: OidInput) -> OidResult:
    """Resolve a dotted-decimal OID (e.g. "1.2.840.113549.1.1.1") to a
    recognized friendly name, checked against asn1crypto's own algorithm/
    content-type OID registries — public-key algorithms (rsa, ec, ed25519,
    ...), signed-digest algorithms (sha256_rsa, sha256_ecdsa, ...), digest
    algorithms (sha256, sha3_256, ...), and CMS/PKCS#7 content types (data,
    signed_data, enveloped_data, ...). known=false (not an error) for a
    well-formed OID this package doesn't recognize. A string that isn't valid
    dotted-decimal notation returns a structured error.
    """
    oid = input.oid.strip()
    if not _OID_RE.match(oid):
        return OidResult(ok=False, error="invalid OID: expected dotted-decimal notation, e.g. '1.2.840.113549.1.1.1'")
    category, name = lookup_oid_info(oid)
    return OidResult(ok=True, oid=oid, known=bool(name), name=name, category=category)
