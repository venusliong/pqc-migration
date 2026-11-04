# Assessment: CodeQL's `experimental/quantum` crypto model

Status as of 2026-11-04. Written after discovering, while planning the Ruby
stage, that `codeql/cpp-all` carries `codeql/quantum` as a dependency.

**Verdict in one line:** GitHub's `experimental/quantum` is a crypto
*identification and inventory* framework. It does not assess quantum exposure
and never names a PQC replacement — which is exactly the layer this project
provides. The two are complementary, not competing.

## 1. What it is

A shared, language-parameterized CodeQL library plus per-language
instantiations.

| Component | Location |
|---|---|
| Shared library pack | `shared/quantum` in `github/codeql` |
| → the two library files | `shared/quantum/codeql/quantum/experimental/{Model.qll,Standardization.qll}` |
| C/C++ instantiation | `cpp/ql/lib/experimental/quantum/` (`Language.qll` + `OpenSSL/`) |
| C/C++ queries | `cpp/ql/src/experimental/quantum/` — **one file**, `PrintCBOMGraph.ql` |
| Java queries | `java/ql/src/experimental/quantum/` — `PrintCBOMGraph.ql`, `Examples/` (23 files), `InventorySlices/` (14 files) |
| Local copy on this machine | `~/.codeql/packages/codeql/quantum/0.0.30/` |

The pack declares `library: true`, `groups: [shared]`, and depends only on
`codeql/util`. It arrives transitively — `codeql/cpp-all` 11.0.0 pins
`codeql/quantum: 0.0.30` — not as something you install directly.

`Model.qll` (2402 lines) describes itself as *"a language-independent library
for reasoning about cryptography."* It is a parameterized module:

```ql
signature module InputSig<LocationSig Location> { ... }
module CryptographyBase<LocationSig Location, InputSig<Location> Input> { ... }
```

Each language pack instantiates it, which is why support is per-language rather
than universal.

## 2. It is not the 2023 research artifact

The [2023 GitHub Security Lab post](https://github.blog/security/vulnerability-research/addressing-post-quantum-cryptography-with-codeql/)
is the origin story, but the code is live work that postdates it:

| Path | Commit evidence |
|---|---|
| `shared/quantum` | newest **2026-10-30** ("Post-release preparation for codeql-cli-2.27.4"); the 100th most recent commit is 2025-06-27 |
| `cpp/ql/lib/experimental/quantum` | newest 2025-10-08 ("Crypto: Standardize naming where use of 'family' and 'type'..."); 100th most recent 2025-05-08 |
| `java/ql/src/experimental/quantum` | newest **2026-10-16** ("Java/Ruby: Replace recursive algorithm string builders"); fewer than 100 commits total |

Published references beyond the 2023 post are thin: `advanced-security/cbom-action`
(a CodeQL-based CBOM GitHub Action) is cited in
[Towards Cryptography Bill of Materials Compliance](https://link.springer.com/chapter/10.1007/978-3-032-19567-8_10).
No release announcement or changelog entry after 2023 was found; every release
note in the pack's `CHANGELOG.md` reads "No user-facing changes." **Commit
history is better evidence of its status than anything published.**

## 3. Language coverage

Checked by looking for a `codeql/quantum` dependency in each
`<lang>/ql/lib/qlpack.yml`:

| Language | Quantum model |
|---|---|
| cpp | yes |
| java | yes |
| python, go, javascript, csharp, rust, swift | no |
| **ruby** | **no** |

`codeql/ruby-all` depends on `concepts`, `controlflow`, `dataflow`, `mad`,
`regex`, `ssa`, `tutorial`, `util`, `namebinding` — no quantum. There is no
`ruby/ql/{lib,src}/experimental/quantum` directory.

## 4. The three layers — it ships two

### Layer 1: identify and normalize (strong)

For C/C++, `cpp/ql/lib/experimental/quantum/OpenSSL/` contains
`LibraryDetector.qll`, `AvcFlow.qll`, `KeyFlow.qll`, `Random.qll`,
`ArtifactPassthrough.qll` and an `AlgorithmInstances/` directory.

Library attribution is deliberately blunt:

```ql
predicate isPossibleOpenSslLocation(Location l) {
  l.toString().toLowerCase().matches("%openssl%")
}
```

A function is "OpenSSL" if its declaration location path contains `openssl` —
i.e. it came from OpenSSL headers. Note this is *consumer* analysis, the same
philosophy as this project's "scan consumers, not implementations" rule.

`AlgorithmInstances/KnownAlgorithmConstants.qll` is the valuable asset: a
~1000-row normalization table covering function names, OpenSSL NIDs and
aliases.

```
"EVP_RSA_gen", "RSA_generate_key_ex", "RSA_generate_key",
"RSA_new", "RSA_sign", "RSA_verify"          → normalized = "RSA"

name = "rsa"      nid = 19   normalized = "RSA"   algType = "ASYMMETRIC_ENCRYPTION"
name = "sha1"     nid = 64   normalized = "SHA1"  algType = "HASH"
name = "md5"      nid = 4    normalized = "MD5"   algType = "HASH"
name = "hmac-md5" nid = 780  normalized = "MD5"   algType = "HASH"
alias = "ssl3-sha1" → target = "sha1"
```

`Standardization.qll` (484 lines) supplies the taxonomy: asymmetric ciphers
(`RSA`), signatures (`DSA`, `ECDSA`, `EDDSA`, `HSS_LMS`), KEMs (`KYBER`,
`FRODO_KEM`), MACs (`HMAC`, `CMAC`), hashes (`MD2`, `MD4`, `MD5`, `MDC2`,
`SHA1`, `SHA2`, `SHA3`, `SHAKE`, `BLAKE2B/S`, `RIPEMD160`, `WHIRLPOOL`,
`GOST_HASH`, `SM3`, `POLY1305`), block modes, padding schemes
(`PKCS1_V1_5`, `OAEP`, `PKCS7`), key agreement (incl. `ECDH`) and curve
families (`NIST`, `SEC`, `BRAINPOOL`, `CURVE25519`, `CURVE448`, `SM2`, ...).

`Model.qll` supplies the graph vocabulary: `OperationInstance`,
`AlgorithmInstance`, `AlgorithmValueConsumer`, `ArtifactInstance`,
`KeyOperationInstance`, `RandomNumberGenerationInstance`,
`PaddingAlgorithmInstance` and friends — dataflow-aware, so an algorithm value
can be traced to the operation that consumes it.

### Layer 2: inventory (present)

```ql
// cpp/ql/src/experimental/quantum/PrintCBOMGraph.ql
// @kind graph — "This query only supports DGML output, as CodeQL DOT output
//                omits properties."
query predicate nodes(Crypto::NodeBase node, string key, string value) { ... }
query predicate edges(Crypto::NodeBase source, Crypto::NodeBase target, ...) { ... }
```

That is the entire user-facing C/C++ surface: a DGML graph to post-process into
a CBOM. No alerts, no file/line list, no severity.

Java goes further with 14 `InventorySlices/` table queries —
`KnownAsymmetricAlgorithm.ql`, `KnownHashingAlgorithm.ql`,
`KnownEllipticCurveAlgorithm.ql`, `KnownKeyDerivationAlgorithm.ql`,
`UnknownOperationAlgorithm.ql`, `LikelyCryptoAPIFunction.ql` and so on. They
answer inventory questions, not risk questions:

```ql
// InventorySlices/KnownAsymmetricAlgorithm.ql   @kind table
from Crypto::AsymmetricAlgorithmNode a
select a, a.asAlgorithmNode().getAlgorithmName()
```

### Layer 3: judge quantum exposure (absent)

Java ships 23 `Examples/` files that *are* alert queries — `BrokenCrypto.ql`,
`WeakHash.ql`, `WeakSymmetricCipher.ql`, `WeakBlockModes.ql`,
`WeakAsymmetricKeyGenSize.ql`, `WeakKDFIterationCount.ql`, `ReusedNonce.ql`,
`BadMacOrderDecryptThenMac.ql`, `InsecureIVorNonceSource.ql`,
`NonAESGCMCipher.ql`, ... But what they flag is **conventional** weakness:

```ql
// Examples/BrokenCrypto.ql
// @kind problem  @security-severity 7.5  @tags security external/cwe/cwe-327 external/cwe/cwe-328
// "THIS QUERY IS A REPLICA OF: .../CWE-327/BrokenCryptoAlgorithm.ql
//  but uses the **NEW MODELING**"
string getAnInsecureAlgorithmName() {
  result = ["DES", "RC2", "RC4", "RC5", "ARCFOUR", "ECB", "AES/CBC/PKCS[57]Padding"]
}
```

RSA, DH, ECDH, ECDSA are **not** in that list. And the one asymmetric query
checks classical key strength, not quantum exposure:

> `WeakAsymmetricKeyGenSize.ql` — *"An asymmetric key of known size is less than
> 2048 bits for any non-elliptic curve key operation."*

So RSA-2048 passes. RSA-4096 passes. Both are fully quantum-broken.

Evidence that the quantum judgment is simply not there:

- Grepping `Model.qll` and `Standardization.qll` for
  `vulnerab|insecure|weak|broken|deprecat|unsafe|migrat` returns **one** hit, a
  code comment: `CBC() or // Vulnerable to padding oracle attacks`.
- Grepping the Java example and slice queries for `quantum|ML-KEM|ML-DSA|Kyber|
  Dilithium|post-quantum|FIPS|migrate` returns only the literal `@tags quantum`
  line and the `import experimental.quantum.Language` path.
- PQC naming is pre-standard: `KYBER` and `FRODO_KEM` exist; **`ML-KEM`,
  `ML-DSA` and `SLH-DSA` — the FIPS 203/204/205 names this project's reports
  use — do not appear anywhere**, nor do Dilithium or SPHINCS+. Among
  signatures only `HSS_LMS` (RFC 8554, hash-based) is quantum-resistant.

The directory name describes the *purpose* — quantum readiness — not the
analysis.

## 5. Where this project stands

| Layer | `experimental/quantum` | This project |
|---|---|---|
| Identify & normalize crypto usage | ~1000 NID/name rows, dataflow-aware | regex rules (Semgrep) / name + macro regex (CodeQL) |
| Inventory | CBOM graph (cpp, java) + 14 slices (java) | — (roadmap item) |
| Judge quantum exposure, name replacement | **none** | **P1–P3 + ML-KEM-768 / ML-DSA-65 / SLH-DSA per FIPS 203/204/205** |

The hand-rolled queries are not redundant with the official model. They occupy
the layer it omits. The honest framing for `EVALUATION.md` is that the official
pack has deeper *identification* while this project supplies the *assessment*.

## 6. What this project can reuse

Ordered by value, none of it blocking current work:

1. **The NID/name normalization table → the C macro-resolution rule.**
   `codeql/ext/openssl.model.yml` currently resolves macro-fed algorithm IDs
   with a single hand-written regex:
   `EVP_PKEY_(RSA(_PSS)?|EC|DSA|DH|ED25519|ED448|X25519|X448)|NID_X9_62_id_ecPublicKey`.
   `KnownAlgorithmConstants.qll` does the same job across ~1000 NIDs with
   normalized names and algorithm types. This is the detection class that
   produced all 4 of our CodeQL-exclusive openssh findings, so broader coverage
   there is likely to find more sites. **Caveat:** adopting it would change
   verified C output, so it must not land in the same change that has to prove
   no C regression.

2. **`PrintCBOMGraph.ql` → the CycloneDX CBOM roadmap item.** It already emits a
   crypto graph with the node/edge vocabulary a CBOM needs. Our task would be
   DGML → CycloneDX conversion plus the risk annotations the graph lacks,
   rather than building an inventory from scratch.

3. **`WeakAsymmetricKeyGenSize.ql` → the key-size dataflow we don't have.** It
   taint-tracks key sizes into key-generation sinks:

   ```ql
   predicate isSink(DataFlow::Node sink) {
     exists(Crypto::KeyCreationOperationNode kgen |
       sink = kgen.getKeySizeConsumer().getConsumer().getInputNode())
   }
   ```

   That is structurally identical to postal's
   `OpenSSL::PKey::RSA.new(Postal::Config.dns.dkim_key_size)` — a config value
   flowing into keygen. A ready-made model for the deferred Ruby dataflow pass.

4. **Java stage on an official model.** The roadmap's Java/JCA stage scored
   against CryptoAPI-Bench could build on `experimental/quantum`'s Java
   instantiation instead of hand-rolled JCA rules — the one language where the
   official model is most developed.

5. **Ruby: `codeql/ruby/security/OpenSSL.qll`** (617 lines, in `ruby-all`,
   *outside* the quantum framework). Models `OpenSslCipher`, `CipherOperation`
   and a `Digest` module whose calls implement
   `Cryptography::CryptographicOperation` with MD5/SHA1 weakness resolution
   built in. Usable for the Ruby **P3** tier. It models **no** asymmetric
   crypto — zero mentions of PKey, RSA, DSA, EC or DH — so Ruby P1/P2 must be
   hand-rolled on `API::Node`.

## 7. What it cannot give us

- Any quantum-vulnerability verdict, priority scale, or migration target.
- FIPS 203/204/205 algorithm names.
- Any Ruby support at all, and specifically no Ruby asymmetric modeling in any
  CodeQL library, quantum or otherwise.

## 8. Risks of depending on it

- `experimental/` and version **0.0.30** — no stability guarantee.
- Every `CHANGELOG.md` entry reads "No user-facing changes," so the changelog
  cannot be used to track breaking changes.
- Observed API churn: the 2025-10-08 C++ commit standardized naming "where use
  of 'family' and 'type'" was inconsistent — a rename across the model.
- The OpenSSL library detector is a path substring match (`%openssl%`), which
  will misattribute any file whose path happens to contain "openssl".
- Java's judgment queries live under `Examples/`, which signals illustrative
  rather than supported.

## 9. How this was verified

```sh
# local pack
cat ~/.codeql/packages/codeql/quantum/0.0.30/qlpack.yml
wc -l ~/.codeql/packages/codeql/quantum/0.0.30/codeql/quantum/experimental/*.qll
grep -niE "vulnerab|insecure|weak|broken|deprecat|unsafe|migrat" \
  ~/.codeql/packages/codeql/quantum/0.0.30/codeql/quantum/experimental/*.qll

# cpp instantiation
ls ~/.codeql/packages/codeql/cpp-all/11.0.0/experimental/quantum/OpenSSL/

# upstream layout, per-language coverage, commit dates (GitHub API)
curl -s https://api.github.com/repos/github/codeql/contents/<path>
curl -s "https://api.github.com/repos/github/codeql/commits?path=<path>&per_page=1"
curl -s https://api.github.com/repos/github/codeql/contents/<lang>/ql/lib/qlpack.yml
```

Claims about query contents were read from
`raw.githubusercontent.com/github/codeql/main/...`. Nothing here was run
against our databases — no CBOM graph or Java query has been executed on
`dbs/openssh-portable` yet. Doing so is an open option, not a finding.
