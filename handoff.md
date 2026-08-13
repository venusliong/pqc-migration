# Handoff — PQC legacy-crypto scanner prototype

Status as of 2026-08-12. All work committed on `main`; **not yet pushed** —
`main` is 2 commits ahead of `origin/main` as of this session (SSH origin;
the user pushes — agent sessions can't unlock the passphrase-protected key).

## Goal

Prototype a scanner that finds quantum-vulnerable crypto API usage and
reports **file, line, crypto function name, and a suggested PQC
replacement** (ML-KEM-768 / ML-DSA-65 / SLH-DSA per FIPS 203/204/205).
First real target: OpenSSH-portable (chosen over synthetic benchmarks like
NIST Juliet because it's production code that mixes legacy RSA/ECDSA/DH
with hybrid PQC kex — a built-in false-positive test).

## What's built (all working, all committed)

| Piece | Where | State |
|---|---|---|
| Semgrep rule pack (OpenSSL C API) | `semgrep/rules/c-legacy-crypto.yaml` | 33 findings on openssh (13 P1 / 17 P2 / 3 P3) |
| Semgrep runner → Markdown/JSON report | `semgrep/scan.py` | working |
| CodeQL query pack `pqc/crypto-queries` | `codeql/` | 30 findings on openssh (17 P1 / 10 P2 / 3 P3) |
| CodeQL crypto-name config (per-library, data extensions) | `codeql/lib/CryptoConfig.qll`, `codeql/ext/openssl.model.yml` | working — function names/regexes/priorities live in YAML, `.ql` files read them via `extensible predicate`; verified behavior-identical to the old hardcoded version |
| CodeQL SARIF → Markdown report | `codeql/report.py` | working |
| CodeQL MCP server registration | `.mcp.json` | verified end-to-end |
| Evaluation: Semgrep vs CodeQL + MCP server assessment | `EVALUATION.md` | committed |
| Per-target reports (deliverables, tracked in git) | `report/openssh-semgrep-report.md`, `report/openssh-semgrep-findings.json`, `report/openssh-codeql.sarif`, `report/openssh-codeql-report.md` | committed |

Git history: `6fb7c2b` Semgrep prototype → `298bf2a` CodeQL stage + MCP →
`faa65a5` evaluation doc + CodeQL report → `bc5bae8` per-target report names
→ `02b39ad` handoff → `026ce6d` restructure into `semgrep/`/`codeql/`/`report/`
→ `d9992dd` priorities in CodeQL findings + priority summaries in both reports
→ `3439c0c` document `--rerun` flag → `2cd7be7` handoff for 2026-07-14
→ `056be0c` externalize CodeQL crypto function names into per-library data
extensions.

Layout since `026ce6d`: each approach's tools live under its own directory
(`semgrep/` = rules + runner, `codeql/` = query pack + SARIF renderer),
committed deliverables under `report/` (both scripts default output there).

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
- CodeQL database at `dbs/openssh-portable` (gitignored; rebuild per README:
  `autoreconf -i && ./configure`, then `codeql database create ... --command=make`).
- `targets/openssh-portable` is a gitignored shallow clone.
- `.mcp.json` registers `ql-mcp` (`npx -y codeql-development-mcp-server`,
  env `CODEQL_PATH`, `CODEQL_DATABASES_BASE_DIRS` — absolute, machine-specific
  paths). First session using it will prompt for approval. Works on Node 24
  despite the package's engines saying >= 25.6. Tool args: `query` and
  `database`, absolute paths.
- Node v24.14.1, WSL2 Ubuntu.

## Reproduce the scans

```sh
export PATH="$HOME/.local/bin:$HOME/tools/codeql:$PATH"
python3 semgrep/scan.py targets/openssh-portable --json report/openssh-semgrep-findings.json
codeql database analyze dbs/openssh-portable codeql/ --format=sarif-latest --output=report/openssh-codeql.sarif
python3 codeql/report.py report/openssh-codeql.sarif   # -> report/openssh-codeql-report.md
```

## Conventions the user has set

- Scan reports/SARIF are **deliverables**: commit them, named per target
  (`openssh-codeql.sarif`, not `codeql.sarif`). Only gitignore reproducible
  bulk (databases, cloned targets).
- Prefer established/official tooling over writing our own (the MCP server
  decision).
- Scan crypto *consumers*, not implementations.

## Open to-dos (none blocking, in suggested order)

1. Consider parameterizing the machine-specific paths in `.mcp.json`
   (server itself is approved and working as of 2026-07-14).
2. Merge Semgrep + CodeQL findings into one per-site report; emit
   CycloneDX CBOM.
3. Java stage: JCA rules scored against CryptoAPI-Bench (labeled, gives
   precision/recall).
4. Close the `regress/` blind spot by building openssh test binaries into
   the CodeQL database.
5. Second real C target (OpenVPN or nginx) for config-string-driven
   algorithm selection.
6. Consider mirroring the CodeQL per-library config approach
   (`codeql/ext/*.model.yml`) into the Semgrep side — `c-legacy-crypto.yaml`
   still embeds function names inline per-rule, so the two rule sets still
   require the manual sync CLAUDE.md flags. Deliberately deferred out of
   the 2026-08-12 CodeQL refactor at the user's request (kept that change
   small and reviewable) — not started.
