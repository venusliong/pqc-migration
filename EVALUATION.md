# Evaluation: Semgrep vs CodeQL (via MCP) on openssh-portable

Date: 2026-07-13. Target: openssh-portable (shallow clone, `targets/`).
Semgrep pass: `rules/c-legacy-crypto.yaml` via `scripts/scan.py`.
CodeQL pass: `codeql/` pack against a database built by tracing `make`.

## Findings comparison

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

**Conclusion:** on compiled code CodeQL found a strict superset of Semgrep.
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
  (`npx -y codeql-development-mcp-server`). Tool arguments are `query` and
  `database` (absolute paths).
- **Caveats.** Env paths in `.mcp.json` are machine-specific; first tool
  call pays npx cold-start; query runs take tens of seconds to minutes.

## Reproducing

```sh
python3 scripts/scan.py targets/openssh-portable --out openssh-semgrep-report.md --json openssh-semgrep-findings.json
codeql database analyze dbs/openssh-portable codeql/ --format=sarif-latest --output=openssh-codeql.sarif
python3 scripts/codeql_report.py openssh-codeql.sarif   # -> openssh-codeql-report.md
```
