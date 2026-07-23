# asn1-tools

Deterministic, offline generic ASN.1 (X.690) structure parsing and encoding —
built for the [Axiom](https://axiomide.com) marketplace, handle `christiangeorgelucas`.

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

## Use it from your agent or app

Every node in this package is a **live, auto-scaling API endpoint** on the
[Axiom](https://axiomide.com) marketplace — call it from an AI agent or your own
code, with nothing to self-host.

**📦 See it on the marketplace:**
https://dev.axiomide.com/marketplace/christiangeorgelucas/asn1-tools@0.1.0

**Hook it up to an AI agent (MCP).** Add Axiom's hosted MCP server to any MCP
client and every node becomes a typed tool your agent can call — search the
catalog, inspect a schema, and invoke it directly.

```bash
# Claude Code
claude mcp add --transport http axiom https://api.axiomide.com/mcp \
  --header "Authorization: Bearer $AXIOM_API_KEY"
```

Claude Desktop, Cursor, or any config-based client:

```json
{
  "mcpServers": {
    "axiom": {
      "type": "http",
      "url": "https://api.axiomide.com/mcp",
      "headers": { "Authorization": "Bearer YOUR_AXIOM_API_KEY" }
    }
  }
}
```

**Call it from the CLI.**

```bash
axiom invoke christiangeorgelucas/asn1-tools/DecodeDer --input '{ ... }'
```

**Call it over HTTP.**

```bash
curl -X POST https://api.axiomide.com/invocations/v1/nodes/christiangeorgelucas/asn1-tools/0.1.0/DecodeDer \
  -H "Authorization: Bearer $AXIOM_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{ ... }'
```

> Input/output schema for each node is on the marketplace page above, or via
> `axiom inspect node christiangeorgelucas/asn1-tools/DecodeDer`.

### Get started free

Install the CLI:

```bash
# macOS / Linux — Homebrew
brew install axiomide/tap/axiom

# macOS / Linux — install script
curl -fsSL https://raw.githubusercontent.com/AxiomIDE/axiom-releases/main/install.sh | sh
```

**Windows:** download the `windows/amd64` `.zip` from the
[releases page](https://github.com/AxiomIDE/axiom-releases/releases), unzip it,
and put `axiom.exe` on your `PATH`.

Then `axiom version` to verify, `axiom login` (GitHub or Google) to authenticate,
and create an API key under **Console → API Keys**. Docs and sign-up at
**[axiomide.com](https://axiomide.com)**.

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
