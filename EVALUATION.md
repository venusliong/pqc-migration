# Evaluation: Semgrep vs CodeQL (via MCP)

Two targets, one per language: **openssh-portable** (C, below) and
**postal** (Ruby/Rails, [second section](#postal-ruby-2026-11-04)).

## openssh-portable (C)

Date: 2026-07-13. Target: openssh-portable (shallow clone, `targets/`).
Semgrep pass: `semgrep/rules/c-legacy-crypto.yaml` via `semgrep/scan.py`.
CodeQL pass: `codeql/cpp/` pack (`pqc/cpp-crypto-queries`) against a database
built by tracing `make`.

Related: `docs/codeql-quantum-assessment.md` assesses GitHub's official
`experimental/quantum` crypto model (shipped with `codeql/cpp-all`) against
this project's hand-rolled queries — what it can be reused for, and the
quantum-exposure judgment it deliberately omits.

### Findings comparison

| | Semgrep | CodeQL |
|---|---|---|
| Total sites | 33 | 30 |
| Shared sites | 26 | 26 |
| Exclusive sites | 7 | 4 |

**Semgrep-only (7):** all in `regress/` (test code: `sk-dummy.c`,
`ssh-verify-attestation.c`, `test_sshbuf_getput_*.c`). These files are not
compiled by the default `make` target, so they do not exist in the CodeQL
database at all — a structural blind spot of build-traced analysis, not a
rule gap.

**CodeQL-only (4):** Ed25519 raw-key EVP calls where the algorithm arrives
as a macro-expanded ID, invisible to per-line pattern matching:

- `ed25519-openssl.c:106` `EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, ...)`
- `ed25519-openssl.c:141` `EVP_PKEY_new_raw_private_key(...)`
- `ed25519-openssl.c:212` `EVP_PKEY_new_raw_public_key(...)`
- `sshkey.c:3346` `EVP_PKEY_new_raw_private_key(...)`

#### By priority

Both reports carry the same priority scale (P1 kex/RSA exposure, P2
signatures / EC key material, P3 weak hash); as of 2026-07-14 the CodeQL
queries embed it in their messages, so the two reports are directly
comparable:

| Priority | Semgrep | CodeQL | Shared | Semgrep-only | CodeQL-only |
|---|---|---|---|---|---|
| P1 | 13 | 17 | 13 | 0 | 4 |
| P2 | 17 | 10 | 10 | 7 | 0 |
| P3 | 3 | 3 | 3 | 0 | 0 |

The totals reconcile exactly and both deltas concentrate in one priority
each: every Semgrep-only site is P2 (all seven are `regress/` EC-key/ECDSA
test-code sites), and every CodeQL-only site is P1 (the four macro-fed
Ed25519 raw-key EVP calls). On the 26 shared sites the tools assign
identical priorities — expected, since both use the same primitive→priority
mapping, but it confirms neither pipeline mislabels a site. Notably, the
highest-severity tier is where pattern matching under-reports: all four
sites it misses are P1.
The passes are complementary: Semgrep covers the full tree (including
never-built code) in seconds with no build; CodeQL adds semantic resolution
of macro/ID indirection and cross-function dataflow, at the cost of needing
a working build.

Iteration notes: weak-hash detection in QL must match `FunctionAccess` as
well as `FunctionCall` (openssh stores `EVP_md5`/`EVP_sha1` as pointers in a
digest dispatch table). `AlgorithmNameFlow.ql` returns zero on openssh — a
true negative (openssh does not use by-name EVP factories), verified by a
synthetic test where "RSA" flows literal → variable → helper parameter →
`EVP_PKEY_CTX_new_from_name`.


## postal (Ruby) <a id="postal-ruby-2026-11-04"></a>

Date: 2026-11-04. Target: `postalserver/postal` @ `d96eddb` (3.5 MB Rails
mail server; shallow clone in `targets/postal`). Semgrep pass:
`semgrep/rules/ruby-legacy-crypto.yaml` via the same `semgrep/scan.py`.
CodeQL pass: `codeql/ruby/` pack (`pqc/ruby-crypto-queries`) against a
database built with `--language=ruby` — **no build step**, so both tools see
the same file set, including `spec/`.

### Findings comparison

| | Semgrep | CodeQL |
|---|---|---|
| Findings | 30 | 21 |
| Distinct sites | 27 | 21 |
| Shared sites | 21 | 21 |
| Exclusive sites | 6 | 0 |

Semgrep reports 30 findings across 27 sites because three lines carry two
findings each — a `key.sign(OpenSSL::Digest.new("SHA1"), data)` line is both a
P2 signature and a P3 weak hash.

| Priority | Semgrep | CodeQL | Shared | Semgrep-only | CodeQL-only |
|---|---|---|---|---|---|
| P1 | 11 | 11 | 11 | 0 | 0 |
| P2 | 9 | 0 | 0 | 9 | 0 |
| P3 | 10 | 10 | 10 | 0 | 0 |

**The relationship inverts versus C.** On openssh CodeQL was a strict
superset on compiled code; on postal CodeQL is a strict *subset*. Both
reasons are structural, not rule gaps:

- **No build-mode blind spot to exploit.** Ruby extraction reads source
  directly, so the `regress/`-style asymmetry that gave Semgrep its 7
  exclusives on openssh cannot occur. Every Semgrep-only site here is a real
  rule-coverage difference.
- **No preprocessor to resolve.** All four CodeQL-exclusive openssh findings
  came from macro-fed EVP algorithm IDs
  (`EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, …)`). Ruby has no
  equivalent, so CodeQL's one decisive advantage on C simply does not apply.

**Semgrep-only (6 sites / 9 findings):** every one is the P2 signature tier,
where the receiver is a typed value rather than a constant path —
`private_key.sign(…)` (`lib/postal/signer.rb:32,55`), `@dkim_key.sign(…)`
(`app/lib/dkim_header.rb:127`), `cert.sign …`
(`script/generate_tls_certificate.rb:23`), and four `.sign`/`.verify` sites
in `spec/lib/postal/signer_spec.rb`. Semgrep matches `$K.sign(...)`
syntactically; CodeQL's API-graph walk starts from a constant path
(`OpenSSL::PKey::RSA`) and cannot reach a local variable without dataflow.
This is the deferred dataflow query's exact job — a known gap, not a defect.

**CodeQL-only: none.** Expected, per the two structural reasons above.

**Priorities agree everywhere both tools assign one.** On all 21 shared
sites the priorities match; the only rows where the per-site sets differ are
the three dual-finding lines, where Semgrep adds its P2 signature finding to
the P3 both tools report.

### Precision notes

- **One false positive, in Semgrep:** `spec/lib/postal/signer_spec.rb:26`
  `signer.sign(data)` — the receiver is a `Postal::Signer` wrapper, not a
  key. Inherent to matching `$K.sign(...)` by shape; the dataflow query that
  would close the P2 gap would also eliminate this.
- **The SHA-256 control holds in both tools.** `Digest::SHA256.digest`
  (`app/lib/dkim_header.rb:104`) and `OpenSSL::Digest.new("SHA256")`
  (`lib/postal/signer.rb:32`) are never flagged as weak hashes — the same
  built-in false-positive check openssh's hybrid PQC kex provided for C.
- **Two misses recorded in advance, both confirmed.**
  `OpenSSL::HMAC.hexdigest(CRAM_MD5_DIGEST, …)`
  (`app/lib/smtp_server/client.rb:263`) is missed by both tools: the digest
  arrives as a constant, and dropping the name constraint would flag
  HMAC-SHA256 too. At `signer.rb:55` CodeQL flags only the inner
  `OpenSSL::Digest.new("SHA1")`, not the enclosing `sign` call.
- **The DH / EC / DSA rules fire nowhere, in either tool.** postal uses only
  RSA, so those rules (7 Semgrep patterns, 3 CodeQL rows) are unexercised
  here rather than validated. Rule scope deliberately mirrors the C side so
  the two targets stay comparable; a second Ruby target would be needed to
  exercise them.
- **12 of 27 Semgrep sites and 9 of 21 CodeQL sites are in `spec/`.** Ruby
  test code is indistinguishable to both tools since neither needs a build.
  Tagging or excluding test directories (roadmap) would affect both passes
  equally here — unlike C, where it only ever affected Semgrep.

### Reuse of official CodeQL modeling

`codeql/ruby-all` models **no** asymmetric crypto (zero mentions of
PKey/RSA/DSA/EC/DH), so P1/P2 are hand-rolled on `API::Node` over the
`rubyLegacyApiCall` data extension. P3 instead consumes the official modeling
in `security/OpenSSL.qll` and `frameworks/core/Digest.qll` through the public
`Cryptography::CryptographicOperation` concept, restricted to
`HashingAlgorithm` so that conventionally-weak ciphers (DES, RC4) stay out of
a scale that means *quantum*-broken.

On postal the official model contributed **no site our own rows did not
already find**, and disagreed on none — so it currently acts as a
corroborating cross-check rather than added coverage. It does cover a shape
our rows do not describe (a digest operation whose algorithm it resolves
independently), which is why it stays in the query as the safety net; our
rows take precedence where both match, because they report the qualified call
(`Digest::SHA1.hexdigest`) rather than just the algorithm name.

### Verdict

For Ruby, Semgrep alone is close to sufficient at this rule maturity: it
found every CodeQL site plus the entire signature tier, in seconds, with no
database. CodeQL's value on Ruby is not breadth but what it enables next —
dataflow for `key.sign(…)` receivers and for digests passed as constants,
which is precisely the set both tools miss or over-match today.

## MCP server evaluation (advanced-security/codeql-development-mcp-server)

Evaluated as a replacement for a hand-rolled CodeQL wrapper; adopted.

- **Sufficient for our requirement.** `codeql_query_run` (+`codeql_bqrs_decode`)
  runs our custom pack queries and returns rows with file/line; message text
  carries the crypto function and PQC suggestion. `codeql_database_analyze`
  runs the whole pack to SARIF. 43 tools total, including query
  compile/validate, QL LSP, and profiling we would not have built.
- **Runs in this environment.** npm package v2.25.2 works on Node v24.14.1
  despite `engines` declaring >= 25.6 (advisory only). Verified by stdio
  JSON-RPC handshake and an end-to-end `codeql_query_run` call against the
  openssh database (`isError: false`).
- **Configuration.** Locates the CLI via `CODEQL_PATH`, databases via
  `CODEQL_DATABASES_BASE_DIRS`; registered project-scoped in `.mcp.json`
  (`npx -y codeql-development-mcp-server`). Tool arguments are `query`
  (absolute) and `database` (absolute, or relative to the project root). Both env paths avoid machine-specific
  absolute paths (`${HOME}`-relative CLI path, relative `dbs`).
- **Caveats.** First tool call pays npx cold-start; query runs take tens of
  seconds to minutes. `CODEQL_PATH` must be absolute (validated, fails
  loudly), while a non-existent database base dir is skipped silently.

## Reproducing

```sh
# C
python3 semgrep/scan.py targets/openssh-portable --out report/openssh-semgrep-report.md --json report/openssh-semgrep-findings.json
codeql database analyze dbs/openssh-portable codeql/cpp --format=sarif-latest --output=report/openssh-codeql.sarif
python3 codeql/report.py report/openssh-codeql.sarif   # -> report/openssh-codeql-report.md

# Ruby (database needs no build: codeql database create dbs/postal --language=ruby --source-root targets/postal)
python3 semgrep/scan.py targets/postal --json report/postal-semgrep-findings.json
codeql database analyze dbs/postal codeql/ruby --format=sarif-latest --output=report/postal-codeql.sarif
python3 codeql/report.py report/postal-codeql.sarif    # -> report/postal-codeql-report.md
```

Pass the per-language pack directory (`codeql/cpp`, `codeql/ruby`), never the
`codeql/` parent — it would try to compile every language's queries against
one database.
