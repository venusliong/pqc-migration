# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A prototype scanner that finds quantum-vulnerable crypto API usage in target
codebases and reports file, line, crypto function name, and a suggested PQC
replacement (ML-KEM-768 / ML-DSA-65 / SLH-DSA per FIPS 203/204/205). It is a
Semgrep rule pack plus a Python runner — there is no build step and no test
suite yet. Two languages are covered: C (OpenSSL API, target
`openssh-portable`) and Ruby (OpenSSL stdlib + `Digest`, target `postal`).

## Commands

```sh
# run a scan (semgrep lives in ~/.local/bin — ensure it's on PATH)
python3 semgrep/scan.py targets/openssh-portable --json report/openssh-semgrep-findings.json
python3 semgrep/scan.py targets/postal --json report/postal-semgrep-findings.json

# debug a single rule against one file
semgrep scan --config semgrep/rules/c-legacy-crypto.yaml --metrics off <file.c>

# add a new scan target (shallow clone; targets/ holds third-party code, never edit it)
git clone --depth 1 <repo-url> targets/<name>
```

`scan.py` is language-neutral: `--rules` defaults to the whole
`semgrep/rules/` directory and Semgrep applies each rule only to its declared
language, so one invocation covers any target.

Reports in `report/` are committed deliverables named per target
(`openssh-semgrep-report.md`, `openssh-codeql.sarif`,
`openssh-codeql-report.md`); regenerate rather than hand-edit. Both report
scripts default their output into `report/` with per-target names when
`--out` is omitted.

## Architecture

The contract between the two halves lives in rule **metadata**: every rule in
`semgrep/rules/*.yaml` must carry `category`, `primitive`, `priority` (P1
kex/RSA → P3 weak hash), and `pqc_replacement`. `semgrep/scan.py` reads those fields
from Semgrep's JSON to build the report — a rule without them shows up as
`?` in every column. The suggestion text lives only in rules, never in the
script.

`semgrep/rules/*-legacy-crypto.yaml` are generated, not hand-edited: the
function-name/call-pattern lists for each rule live in
`semgrep/crypto-functions.yaml` (edit this to add/remove/rename a matched
function), while each rule's fixed message/severity/metadata/**language**
stays as Python literals in `semgrep/gen_rules.py` (edit this only when a
rule's meaning changes, or to add a new rule). Run
`python3 semgrep/gen_rules.py` after editing `crypto-functions.yaml`, then
re-scan. One run writes one file per language found in the specs
(`c-legacy-crypto.yaml`, `ruby-legacy-crypto.yaml`); a spec without a
`language=` key defaults to `c`. This is a deliberately
simpler, flatter analog of the CodeQL per-library data-extension mechanism
below — Semgrep has no runtime data-extension mechanism to mirror, so the
split is just "data file" vs. "generator script," not per-library tables.

`scan.py` post-processes Semgrep output in three ways that matter when editing
either side:

- It dedupes findings by (file, line, rule-id), because overlapping patterns
  in one `pattern-either` can match the same call site twice. Prefer a single
  bare-call pattern (`RSA_new()` matches even inside `if ((rsa = RSA_new())`)
  over adding assignment variants.
- It re-reads the matched line from the source file to extract the crypto
  function name, because this Semgrep version redacts `extra.lines`
  ("requires login") in JSON output when not logged in. Don't rely on
  `extra.lines`.
- Function-name extraction dispatches on file suffix. The C regexes require
  `identifier(` and prefer names containing `_`, so they degrade to a bare
  primitive or a truncated line on Ruby's qualified constants; `.rb` files go
  through `ruby_crypto_function()` instead, which reports `RSA.new` /
  `Digest::SHA1.hexdigest`. It takes the rule id, because a signature rule
  should name the receiver (`private_key.sign`) while the same line's digest
  rule should name the digest (`Digest.new`).

## Rule-writing lessons already paid for

- Match function-pointer references, not just calls: `EVP_md5` appears bare
  in digest tables (see openssh `digest-openssl.c`).
- Ed25519/X25519/Ed448/X448 are quantum-vulnerable — keep `EVP_PKEY_ED25519`
  etc. in the EVP algorithm-ID rule; they're easy to forget.
- Grep-style validation against the rules produces false positives on error
  strings like `error("RSA_new failed")` — compare by call sites, not raw
  grep counts.
- Scan crypto *consumers*, not implementations (never point the scanner at
  OpenSSL/mbedTLS themselves — every match would be the library implementing,
  not depending on, an algorithm).
- Semgrep aborts the whole scan if any non-rule YAML file sits inside the
  `--config` directory (`scan.py` defaults `--rules` to all of
  `semgrep/rules/`) — a stray file there fails with
  `InvalidRuleSchemaError: missing 'rules' as top-level key` and returns
  zero findings, not a loud crash. This is why `crypto-functions.yaml` and
  `gen_rules.py` live beside `semgrep/rules/`, not inside it.

## CodeQL stage

`codeql/` holds **one sibling query pack per language**, run against
databases in `dbs/` (gitignored; rebuild per README):
`codeql/cpp/` = `pqc/cpp-crypto-queries` (depends on `codeql/cpp-all`),
`codeql/ruby/` = `pqc/ruby-crypto-queries` (depends on `codeql/ruby-all`),
with `codeql/report.py` shared between them (it reads only
`runs[].results[]`, so it is language-neutral). Extensible predicates are
pack-scoped, so every `addsTo.pack` names its owning pack and one pack
cannot hold two languages' queries against a single-language database.
**Always pass the language pack directory** to `database analyze`
(`codeql/cpp`, never `codeql/`): `codeql resolve queries codeql/` recurses
with no language filter and would try to compile the Ruby queries against a
C database. There is deliberately no third shared pack yet — of the seven
extensible predicates only `algoNameSource` is genuinely language-neutral,
and it is consumed only by the deferred dataflow query; create the shared
pack when the Ruby dataflow query needs it. The CLI lives at
`~/tools/codeql/codeql` — not on default PATH. `.mcp.json` registers GitHub's
`codeql-development-mcp-server` (via npx, works on Node 24 despite its
engines field saying 25.6+); its `codeql_query_run` tool takes `query` and
`database` as arguments. `query` is used as an absolute path; `database`
accepts a path relative to the project root (verified 2026-11-04:
`database: dbs/openssh-portable` works, because the server's cwd is the
project root), so the paths `list_codeql_databases` returns can be passed
straight through. Note `codeql_bqrs_info`/`codeql_bqrs_decode` take the BQRS
path as `file`, not `bqrsPath`. The server's two env paths in
`.mcp.json` carry no hardcoded username: `CODEQL_PATH` is `${HOME}/tools/codeql/codeql`
and `CODEQL_DATABASES_BASE_DIRS` is `${CODEQL_DATABASES_BASE_DIRS:-dbs}`
(relative, resolved against the project root).

Three landmines paid for here:

- **Claude Code's `${VAR:-default}` expansion in `.mcp.json` is not
  recursive** — it ends the expression at the first `}`, so a nested default
  like `${CODEQL_PATH:-${HOME}/tools/codeql/codeql}` resolves to the literal
  `${HOME/tools/codeql/codeql}` and the server dies with
  `CONNECTION_CLOSED`. Never nest `${...}` inside a default. This is why
  `CODEQL_PATH` uses a plain `${HOME}` with no override default.
- The server *validates* `CODEQL_PATH` is absolute and fails loudly, but
  silently skips a database base dir that doesn't exist, so a broken `dbs`
  path reports "no databases found" rather than an error.
- **CLI 2.26.0 cannot install `codeql/ruby-all` 6.x/7.x.** Those versions
  were published by CLI 2.27.4 and their OCI manifests carry a
  `config.digest` field this CLI's manifest parser rejects:
  `Could not get manifest for codeql/ruby-all@7.1.1 ... UnrecognizedPropertyException
  "Unrecognized field \"digest\""`. `codeql/ruby/qlpack.yml` therefore pins
  `codeql/ruby-all: "5.*"` (resolves to 5.2.2, installs cleanly). Bumping it
  means upgrading the CodeQL CLI first — which would also invalidate the
  verified C baseline, so do the two together and re-run the regression gate.

A failed MCP launch is diagnosable: Claude Code writes the server's stderr to
`~/.cache/claude-cli-nodejs/<project-slug>/mcp-logs-ql-mcp/*.jsonl`.

Hard-won specifics:

- The CodeQL database only contains files the traced `make` compiled —
  openssh's `regress/` never appears, so Semgrep-vs-CodeQL finding counts
  differ by exactly those files. Compare per-site, not by totals.
- Weak-hash detection must match `FunctionAccess` as well as `FunctionCall`
  (digest dispatch tables hold `EVP_md5` as a pointer).
- `AlgorithmNameFlow.ql` legitimately returns zero on openssh (no by-name
  EVP factories there); its dataflow is verified by a synthetic test —
  string literal → variable → helper parameter → `EVP_PKEY_CTX_new_from_name`.
- CodeQL resolves macro-fed algorithm IDs (`EVP_PKEY_ED25519` into
  `EVP_PKEY_new_raw_private_key`) that the Semgrep rules missed; keep the
  two rule sets in sync when adding primitives.
- Ruby needs no build: `codeql database create --language=ruby` extracts
  source directly, so Ruby has none of the `regress/` build-mode blind spot
  and Semgrep and CodeQL see the same file set (including `spec/`).
- Ruby constants are not flat function names, so the C `pattern` column
  splits into `receiverPath` (an exact `::` path walked through
  `API::getTopLevelMember(...).getMember(...)`) plus `methodPattern`, with an
  optional `argPattern` on a string argument to tell
  `OpenSSL::Digest.new("SHA1")` from `"SHA256"`. The path walk is guarded by
  `rubyLegacyApiCall(_, _, path, ...)` so it never enumerates the API graph.
- `evpLegacyIdSinkFunction`/`evpLegacyIdMacroPattern` are C-only (Ruby has no
  preprocessor) — that macro branch produced all four CodeQL-exclusive
  openssh findings, which is why CodeQL's edge over Semgrep is *smaller* on
  Ruby, not larger.
- P3 on Ruby reuses the official `codeql/ruby-all` crypto modeling
  (`security/OpenSSL.qll`, `frameworks/core/Digest.qll`) via the public
  `Cryptography::CryptographicOperation` concept, restricted to
  `HashingAlgorithm` so conventionally-weak ciphers (DES/RC4) stay out of a
  quantum-exposure scale. Our own rows take precedence where both match, for
  the qualified name; without that precedence CodeQL merges the two results
  at one location into a single newline-joined message.
- `codeql/ruby-all` models no asymmetric crypto at all (zero mentions of
  PKey/RSA/DSA/EC/DH), so P1/P2 must stay hand-rolled on `API::Node`.
- Query messages carry the priority as a `[P1]`/`[P2]`/`[P3]` prefix (same
  scale as the Semgrep rules); `codeql/report.py` parses it into the report's
  Priority column — note SARIF markdown-escapes it to `\[P1\]`. When one call
  site matches nested macros (`EVP_PKEY_EC` expands to
  `NID_X9_62_id_ecPublicKey`), only the outermost is reported.

## Roadmap context

Candidates: CycloneDX CBOM output, tagging/excluding test dirs (`regress/`
in openssh), Java rules to score against CryptoAPI-Bench, merging
Semgrep+CodeQL findings into one report.
