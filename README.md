# asn1-tools

Deterministic, offline generic ASN.1 (X.690) structure parsing and encoding —
built for the [Axiom](https://axiom.dev) marketplace, handle `christiangeorgelucas`.

Decode any BER/CER/DER blob into a recursively-structured, schema-free tree
(tag class/number, constructed flag, nested children, raw bytes, and
best-effort typed values for OIDs/integers/strings/times/booleans/bit
strings), encode that tree back to DER, armor/dearmor PEM (any label,
multi-block, legacy headers), resolve algorithm/content-type OIDs to friendly
names, and decode the common algorithm-agnostic PKI wrapper structures
(AlgorithmIdentifier, PKCS#8 PrivateKeyInfo, PKCS#1 RSAPrivateKey,
SubjectPublicKeyInfo, CMS/PKCS#7 ContentInfo).

Wraps [asn1crypto](https://github.com/wbond/asn1crypto) (MIT, zero runtime
dependencies), reusing its own low-level BER/DER framing primitives and
per-universal-type semantic decoders rather than reimplementing X.690.

Distinct from `christiangeorgelucas/certificate-tools` (X.509-certificate-
specific semantics — SANs, key usage, chain linkage): this package is the
generic ASN.1 structure layer beneath it, for any DER/BER blob, not just
certificates.

## Nodes

| Node | What it does |
|---|---|
| `DecodeDer` | Decode a BER/CER/DER blob into a generic, recursive tree |
| `EncodeDer` | Encode a generic tree back into DER bytes (inverse of DecodeDer) |
| `DecodePem` | Split PEM text into its de-armored blocks (label, headers, DER) |
| `EncodePem` | Armor raw DER/BER bytes into PEM text |
| `LookupOid` | Resolve a dotted OID to a recognized friendly name |
| `ParseAlgorithmIdentifier` | Decode a standalone AlgorithmIdentifier structure |
| `ParsePrivateKeyInfo` | Decode a PKCS#8 PrivateKeyInfo (any algorithm) |
| `ParsePkcs1RsaKey` | Decode a PKCS#1 RSAPrivateKey's full CRT key material |
| `ParseSubjectPublicKeyInfo` | Decode a SubjectPublicKeyInfo (any algorithm) |
| `ParseContentInfo` | Decode a CMS/PKCS#7 ContentInfo envelope |

Every node is a pure, bounded (input size / tree depth / node count all
capped), single-input to single-output transform. Malformed input returns a
structured error, never a crash. Offline — no network access, no external
service.

## License

MIT — see [LICENSE](LICENSE).
