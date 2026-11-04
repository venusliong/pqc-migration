# Handoff — PQC legacy-crypto scanner prototype

Status as of 2026-11-04. Everything through `f475626` (the Semgrep
crypto-function externalization) is committed **and pushed** — `main` and
`origin/main` both at `f475626`, confirmed. The 2026-11-04 work below is
**uncommitted in the working tree**; the user commits and pushes (SSH origin
with a passphrase-protected key that agent sessions can't unlock).

## Goal

Prototype a scanner that finds quantum-vulnerable crypto API usage and
reports **file, line, crypto function name, and a suggested PQC
replacement** (ML-KEM-768 / ML-DSA-65 / SLH-DSA per FIPS 203/204/205).
First real target: OpenSSH-portable (chosen over synthetic benchmarks like
NIST Juliet because it's production code that mixes legacy RSA/ECDSA/DH
with hybrid PQC kex — a built-in false-positive test).

## What's built (all working; the 2026-11-04 Ruby stage is uncommitted)

| Piece | Where | State |
|---|---|---|
| Semgrep rule pack (OpenSSL C API) | `semgrep/rules/c-legacy-crypto.yaml` (generated) | 33 findings on openssh (13 P1 / 17 P2 / 3 P3) |
| Semgrep rule pack (Ruby OpenSSL stdlib) | `semgrep/rules/ruby-legacy-crypto.yaml` (generated) | 30 findings / 27 sites on postal (11 P1 / 9 P2 / 10 P3) |
| Semgrep crypto-function config + generator | `semgrep/crypto-functions.yaml`, `semgrep/gen_rules.py` | working — function/pattern lists live in YAML, generator rebuilds the rules file; verified behavior-identical to the old hardcoded version |
| Semgrep runner → Markdown/JSON report | `semgrep/scan.py` | working |
| CodeQL query pack `pqc/cpp-crypto-queries` | `codeql/cpp/` | 30 findings on openssh (17 P1 / 10 P2 / 3 P3) |
| CodeQL query pack `pqc/ruby-crypto-queries` | `codeql/ruby/` | 21 findings on postal (11 P1 / 0 P2 / 10 P3) |
| CodeQL crypto-name config (per-library, data extensions) | `codeql/cpp/lib/CryptoConfig.qll`, `codeql/cpp/ext/openssl.model.yml`, `codeql/ruby/lib/RubyCryptoConfig.qll`, `codeql/ruby/ext/openssl-ruby.model.yml` | working — function names/regexes/priorities live in YAML, `.ql` files read them via `extensible predicate`; verified behavior-identical to the old hardcoded version |
| CodeQL SARIF → Markdown report | `codeql/report.py` | working |
| CodeQL MCP server registration | `.mcp.json` | verified end-to-end |
| Evaluation: Semgrep vs CodeQL + MCP server assessment | `EVALUATION.md` | committed; postal (Ruby) section added 2026-11-04 |
| Per-target reports (deliverables, tracked in git) | `report/openssh-*` and `report/postal-*` (semgrep report + JSON, CodeQL SARIF + report) | openssh committed; postal uncommitted (2026-11-04) |

Git history: `6fb7c2b` Semgrep prototype → `298bf2a` CodeQL stage + MCP →
`faa65a5` evaluation doc + CodeQL report → `bc5bae8` per-target report names
→ `02b39ad` handoff → `026ce6d` restructure into `semgrep/`/`codeql/`/`report/`
→ `d9992dd` priorities in CodeQL findings + priority summaries in both reports
→ `3439c0c` document `--rerun` flag → `2cd7be7` handoff for 2026-07-14
→ `056be0c` externalize CodeQL crypto function names into per-library data
extensions → `a2843a4` handoff for 2026-08-12 → *(this session)* externalize
Semgrep crypto function names into `crypto-functions.yaml` + `gen_rules.py`.

Layout since `026ce6d`: each approach's tools live under its own directory
(`semgrep/` = rules + runner, `codeql/` = query packs + SARIF renderer),
committed deliverables under `report/` (both scripts default output there).
Since 2026-11-04 the CodeQL side is one sibling pack per language
(`codeql/cpp/`, `codeql/ruby/`) with `codeql/report.py` shared; always pass
the language directory to `database analyze`, never the `codeql/` parent.

## Key results

- **Semgrep 33 vs CodeQL 30 findings; 26 shared.** Semgrep's 7 exclusives
  are all in `regress/` (never compiled, so absent from the CodeQL
  database). CodeQL's 4 exclusives are Ed25519 raw-key EVP calls whose
  algorithm ID arrives via macro expansion — invisible to pattern matching.
  On compiled code, CodeQL found a strict superset. Details in
  `EVALUATION.md`.
- **`AlgorithmNameFlow.ql` returns zero on openssh** — a verified true
  negative (openssh doesn't use by-name EVP factories); the dataflow was
  proven with a synthetic test (literal → variable → helper param →
  `EVP_PKEY_CTX_new_from_name`).
- **MCP server verdict: use GitHub's official one** (user preference:
  established tools over hand-rolled). `codeql_query_run` verified
  end-to-end against the openssh database. Approved and loaded in the
  2026-07-14 session.
- **Priorities agree per-site across tools.** CodeQL query messages carry
  the same P1–P3 scale as the Semgrep rules (`[Px]` prefix, parsed by
  `codeql/report.py`); on all 26 shared sites the tools assign identical
  priorities. Every Semgrep-only site is P2 (`regress/` EC test code),
  every CodeQL-only site is P1 (macro-fed Ed25519) — the top severity tier
  is exactly where pattern matching under-reports. Table in `EVALUATION.md`.
- **CodeQL crypto names externalized to per-library config (2026-08-12).**
  All function-name lists/regexes that used to be QL string literals in
  `LegacyCryptoAPIs.ql`/`AlgorithmNameFlow.ql` now live in
  `codeql/ext/openssl.model.yml`, read via `extensible predicate`s declared
  in `codeql/lib/CryptoConfig.qll` and wired up through `qlpack.yml`'s
  `dataExtensions:` field — CodeQL's standard data-extension mechanism (same
  one `codeql/cpp-all` uses for its own library models), not a custom
  parser. A future library (mbedtls, wolfssl, JCA) is a new
  `ext/<library>.model.yml` file with zero `.ql` changes, since every query
  predicate binds the `library` column with `_`. No wildcard/prefix
  matching was added — this pass only moved the two matching mechanisms
  that already existed (`regexpMatch` and exact-name `=`). Verified
  behavior-identical: re-running against the existing `dbs/openssh-portable`
  database gave byte-identical SARIF results (30/30 findings, same rule
  IDs/locations/priorities/messages — the only diff was the pack's embedded
  git-commit fingerprint); the `AlgorithmNameFlow.ql` source/sink migration
  (openssh itself yields zero findings for that query) was separately
  re-verified with a throwaway synthetic database. Scope was deliberately
  CodeQL-only — Semgrep's rules still embed names inline in
  `pattern-either` blocks (see Open to-dos).

## Environment specifics a fresh session needs

- CodeQL CLI 2.26.0 at `~/tools/codeql/codeql` — **not on default PATH**.
- Semgrep 1.169.0 via `pip3 install --user` — in `~/.local/bin`.
- CodeQL databases at `dbs/openssh-portable` and `dbs/postal` (gitignored;
  rebuild per README: C needs `autoreconf -i && ./configure` then
  `codeql database create ... --command=make`; Ruby needs no build at all —
  `codeql database create dbs/postal --language=ruby --source-root targets/postal`,
  ~20 s, 7.3 MB).
- `targets/openssh-portable` and `targets/postal` are gitignored shallow
  clones (postal pinned at `d96eddb`).
- `codeql/ruby/qlpack.yml` pins `codeql/ruby-all: "5.*"` (→ 5.2.2). 6.x/7.x
  cannot be installed by CLI 2.26.0: their OCI manifests were written by CLI
  2.27.4 and carry a `config.digest` field this CLI's parser rejects
  (`UnrecognizedPropertyException "Unrecognized field \"digest\""`).
  Unpinning means upgrading the CLI, which also invalidates the verified C
  baseline — do both together and re-run the regression gate.
- `.mcp.json` registers `ql-mcp` (`npx -y codeql-development-mcp-server`,
  env `CODEQL_PATH` = `${HOME}/tools/codeql/codeql`,
  `CODEQL_DATABASES_BASE_DIRS` = `${CODEQL_DATABASES_BASE_DIRS:-dbs}` — no
  machine-specific paths as of 2026-11-04). First
  session using it will prompt for approval. Works on Node 24 despite the
  package's engines saying >= 25.6. Tool args: `query` (absolute) and
  `database` (absolute, or relative to the project root).
- Node v24.14.1, WSL2 Ubuntu.
- `codeql` is now on PATH permanently via `~/.bashrc:121`, so the
  `export PATH=...` line in the reproduce block is no longer needed on this
  machine (keep it documented for a fresh checkout).

## Reproduce the scans

```sh
export PATH="$HOME/.local/bin:$HOME/tools/codeql:$PATH"

# C
python3 semgrep/scan.py targets/openssh-portable --json report/openssh-semgrep-findings.json
codeql database analyze dbs/openssh-portable codeql/cpp --format=sarif-latest --output=report/openssh-codeql.sarif
python3 codeql/report.py report/openssh-codeql.sarif   # -> report/openssh-codeql-report.md

# Ruby
python3 semgrep/scan.py targets/postal --json report/postal-semgrep-findings.json
codeql database analyze dbs/postal codeql/ruby --format=sarif-latest --output=report/postal-codeql.sarif
python3 codeql/report.py report/postal-codeql.sarif    # -> report/postal-codeql-report.md
```

## Conventions the user has set

- Scan reports/SARIF are **deliverables**: commit them, named per target
  (`openssh-codeql.sarif`, not `codeql.sarif`). Only gitignore reproducible
  bulk (databases, cloned targets).
- Prefer established/official tooling over writing our own (the MCP server
  decision).
- Scan crypto *consumers*, not implementations.

## 2026-11-04 session (uncommitted)

- **`.mcp.json` parameterized** — closes to-do #1; see the env note above.
  First attempt used `${CODEQL_PATH:-${HOME}/tools/codeql/codeql}` and broke
  the server (`CONNECTION_CLOSED`): Claude Code's `${VAR:-default}` expansion
  ends at the first `}`, so the nested default resolved to the literal
  `${HOME/tools/codeql/codeql}`. Fixed by using a plain `${HOME}` with no
  override default — see the landmine note in `CLAUDE.md`. **Verified green
  2026-11-04** after reconnect: `list_codeql_databases` finds
  `dbs/openssh-portable` via the relative base dir, and `codeql_query_run` on
  `LegacyCryptoAPIs.ql` returns 30 rows — the unchanged C baseline.
- **`docs/codeql-quantum-assessment.md` (new)** — assessment of GitHub's
  official `experimental/quantum` crypto model, found as a transitive
  dependency of `codeql/cpp-all`. Conclusion: it identifies and inventories
  crypto (CBOM) but makes **no** quantum-exposure judgment and never names a
  PQC replacement, so this project's P1–P3 + FIPS 203/204/205 layer is
  complementary, not redundant. Lists five concrete reuse opportunities —
  notably its ~1000-row NID table as an upgrade to our one-regex macro rule,
  and `WeakAsymmetricKeyGenSize.ql` as a model for key-size dataflow.
  Cross-referenced from `EVALUATION.md`.
- **Ruby/Rails stage built** (plan at
  `~/.claude/plans/i-want-to-extend-tender-conway.md`, followed end to end;
  target `postalserver/postal` @ `d96eddb`). Landed:
  - Semgrep: `gen_rules.py` gained a `language` dimension — one data file,
    one generator, one rules file per language. 7 Ruby rules in
    `rules/ruby-legacy-crypto.yaml`. **30 findings / 27 sites** on postal
    (11 P1 / 9 P2 / 10 P3).
  - `scan.py`: Ruby function-name branch (suffix dispatch), so the report
    shows `RSA.new` / `Digest::SHA1.hexdigest` / `private_key.sign` instead
    of a bare primitive or a truncated line. It takes the rule id, so a
    signature finding names the receiver while the same line's digest
    finding names the digest.
  - CodeQL: restructured into sibling per-language packs
    (`codeql/cpp/` = `pqc/cpp-crypto-queries`, `codeql/ruby/` =
    `pqc/ruby-crypto-queries`), `report.py` shared and unchanged.
    `RubyLegacyCryptoAPIs.ql` + `rubyLegacyApiCall` data extension:
    **21 findings** on postal (11 P1 / 0 P2 / 10 P3).
  - P3 on Ruby reuses the official `codeql/ruby-all` modeling via
    `Cryptography::CryptographicOperation` (hashing only, so DES/RC4 stay out
    of a quantum scale); our rows take precedence where both match, else
    CodeQL merges the two results at one site into one message.
  - **Result inverts the C finding:** CodeQL's 21 sites are a strict
    *subset* of Semgrep's 27 — no build-mode blind spot and no preprocessor,
    so CodeQL's two C advantages don't apply. All 6 Semgrep-only sites are
    the P2 `key.sign(…)` tier (receiver is a typed value → needs the
    deferred dataflow query). Zero CodeQL-only. Priorities agree on all 21
    shared sites. One FP, in Semgrep: `signer_spec.rb:26` `signer.sign(data)`
    (receiver is a wrapper, not a key). Full per-site table in
    `EVALUATION.md`.
  - **C regression gate green throughout**: openssh Semgrep 33 findings
    byte-identical (report + JSON), CodeQL 30 rows normalized-identical,
    rendered report byte-identical below the `Source:` line, extension row
    counts unchanged at 6/4/1/6/10/3. `report/openssh-codeql.sarif` was
    regenerated from the moved pack (its embedded pack path changed; the
    rendered report did not).
  - Docs updated: `README.md` gained a **Language prerequisites** section
    (Semgrep needs nothing per language; CodeQL needs one `pack install` per
    pack; Ruby parsing needs no Ruby runtime, no `bundle install` and no
    `--command`, because the extractor is a self-contained binary — verified:
    `bundle` is not installed on this machine and the database built fine),
    plus per-language commands labelled one-time / per-target / each-scan.
    `CLAUDE.md` and `EVALUATION.md` cover the architecture and the per-site
    comparison.
  - Deferred as designed: the Ruby dataflow query (and with it the shared
    third pack for `algoNameSource`), and X.509 `Certificate.new` as its own
    finding — it is a container, flagged through its `.sign`.

## Open to-dos (none blocking, in suggested order)

1. ~~Consider parameterizing the machine-specific paths in `.mcp.json`~~ —
   **done (2026-11-04)**: `CODEQL_PATH` is a plain `${HOME}/tools/codeql/codeql`
   with **no** `${VAR:-default}` wrapper (a nested default breaks the server,
   see the landmine in `CLAUDE.md`), and `CODEQL_DATABASES_BASE_DIRS` is
   `${CODEQL_DATABASES_BASE_DIRS:-dbs}` (relative, resolved against the
   project root). That variable is not set in the user's environment, so the
   default is the live configuration; the override exists for other
   checkouts. A CLI installed elsewhere needs the `CODEQL_PATH` line edited.
2. Ruby dataflow query (the stage deliberately deferred on 2026-11-04).
   Closes the whole P2 gap — `key.sign(digest, data)` where the receiver is
   a typed value, the only tier CodeQL misses on postal — and the
   `OpenSSL::HMAC.hexdigest(CRAM_MD5_DIGEST, …)` miss both tools share.
   Also eliminates Semgrep's one FP (`signer.sign(data)` on a wrapper
   object). This is the trigger for creating the shared third pack:
   `algoNameSource` is the one genuinely language-neutral predicate and only
   the dataflow query consumes it.
3. Merge Semgrep + CodeQL findings into one per-site report; emit
   CycloneDX CBOM. (The scratch comparator used for the postal evaluation is
   a starting point: match on `(file, line)`, keep both tools' priorities.)
4. Java stage: JCA rules scored against CryptoAPI-Bench (labeled, gives
   precision/recall). Note Java *does* have an official `codeql/quantum`
   instantiation — worth building on rather than hand-rolling.
5. Second real C target (OpenVPN or nginx) for config-string-driven
   algorithm selection.
6. ~~Mirror the CodeQL per-library config approach into the Semgrep
   side~~ — **done (2026-10-22)**, but deliberately *not* a literal mirror:
   the user asked for something simpler and more human-readable rather than
   architectural parity with CodeQL's per-library extensible-predicate
   mechanism (which Semgrep has no runtime equivalent for anyway). Landed
   as `semgrep/crypto-functions.yaml` (flat per-rule-id function/pattern
   lists, hand-edited) + `semgrep/gen_rules.py` (fixed message/severity/
   metadata per rule, generates `semgrep/rules/c-legacy-crypto.yaml`, now a
   generated-not-hand-edited file like `report/`). Verified finding- and
   byte-identical against the committed openssh report/JSON before and
   after (33 findings, 13 P1/17 P2/3 P3, zero diff). One landmine found and
   documented in CLAUDE.md: Semgrep aborts the whole scan if any non-rule
   YAML sits inside the `--config` directory, so both new files live beside
   `semgrep/rules/`, not inside it. The two rule sets (Semgrep patterns vs.
   CodeQL regexes) still aren't unified into one shared data source — that
   would be a further step, not attempted here.
