# Handoff — PQC legacy-crypto scanner prototype

Status as of 2026-07-13. All work committed on `main` (no remote configured).

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
| Semgrep rule pack (OpenSSL C API) | `rules/c-legacy-crypto.yaml` | 33 findings on openssh |
| Semgrep runner → Markdown/JSON report | `scripts/scan.py` | working |
| CodeQL query pack `pqc/crypto-queries` | `codeql/` | 30 findings on openssh |
| CodeQL SARIF → Markdown report | `scripts/codeql_report.py` | working |
| CodeQL MCP server registration | `.mcp.json` | verified end-to-end |
| Evaluation: Semgrep vs CodeQL + MCP server assessment | `EVALUATION.md` | committed |
| Per-target reports (deliverables, tracked in git) | `openssh-semgrep-report.md`, `openssh-semgrep-findings.json`, `openssh-codeql.sarif`, `openssh-codeql-report.md` | committed |

Git history: `6fb7c2b` Semgrep prototype → `298bf2a` CodeQL stage + MCP →
`faa65a5` evaluation doc + CodeQL report → `bc5bae8` per-target report names.

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
  end-to-end against the openssh database.

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
python3 scripts/scan.py targets/openssh-portable --json openssh-semgrep-findings.json
codeql database analyze dbs/openssh-portable codeql/ --format=sarif-latest --output=openssh-codeql.sarif
python3 scripts/codeql_report.py openssh-codeql.sarif   # -> openssh-codeql-report.md
```

## Conventions the user has set

- Scan reports/SARIF are **deliverables**: commit them, named per target
  (`openssh-codeql.sarif`, not `codeql.sarif`). Only gitignore reproducible
  bulk (databases, cloned targets).
- Prefer established/official tooling over writing our own (the MCP server
  decision).
- Scan crypto *consumers*, not implementations.

## Open to-dos (none blocking, in suggested order)

1. Approve/load the `ql-mcp` MCP server in the next session; consider
   parameterizing the machine-specific paths in `.mcp.json`.
2. Merge Semgrep + CodeQL findings into one per-site report; emit
   CycloneDX CBOM.
3. Java stage: JCA rules scored against CryptoAPI-Bench (labeled, gives
   precision/recall).
4. Close the `regress/` blind spot by building openssh test binaries into
   the CodeQL database.
5. Second real C target (OpenVPN or nginx) for config-string-driven
   algorithm selection.
