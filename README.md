# pqc-migration

Prototype scanner that finds quantum-vulnerable crypto API usage and reports
file, line, the crypto function used, and a suggested PQC replacement
(ML-KEM / ML-DSA / SLH-DSA per FIPS 203/204/205).

## Layout

- `semgrep/` — the Semgrep stage. `rules/c-legacy-crypto.yaml` covers the
  OpenSSL C API: low-level `RSA_*`/`DSA_*`/`EC_KEY_*`/`ECDSA_*`/`ECDH_*`/`DH_*`,
  EVP contexts bound to legacy algorithm IDs or name strings, and weak hashes
  (MD5/SHA-1, including function-pointer usage). `scan.py` is the runner:
  executes Semgrep, dedupes overlapping matches, and writes a Markdown report
  plus optional JSON.
- `codeql/` — the CodeQL stage: query pack plus `report.py` (SARIF →
  Markdown). Details below.
- `report/` — committed scan deliverables, named per target
  (`openssh-semgrep-report.md`, `openssh-codeql.sarif`, …). Regenerate,
  don't hand-edit; both scripts default their output here.
- `targets/` — codebases under scan (not ours; shallow clones). Currently
  OpenSSH-portable.
- `dbs/` — CodeQL databases (gitignored; rebuild per below).

## One-time setup

```sh
# tools
pip3 install --user semgrep   # installs to ~/.local/bin

# scan target (targets/ is gitignored; clones are read-only)
git clone --depth 1 https://github.com/openssh/openssh-portable targets/openssh-portable
```

The CodeQL stage needs additional one-time setup — see below.

## Usage

```sh
python3 semgrep/scan.py targets/openssh-portable --json report/openssh-semgrep-findings.json
```

Priorities in the report: P1 = key exchange / RSA (harvest-now-decrypt-later
exposure), P2 = signatures / EC key material, P3 = weak hashes.

## CodeQL stage (dataflow-precise)

- `codeql/` — query pack `pqc/crypto-queries`: `LegacyCryptoAPIs.ql` (direct
  legacy calls, EVP contexts bound to legacy algorithm IDs via macros, weak
  hashes incl. function-pointer references) and `AlgorithmNameFlow.ql`
  (path-problem: algorithm name strings flowing across functions into EVP
  by-name factories).
- `.mcp.json` — registers GitHub's `codeql-development-mcp-server` (npx) so
  agent sessions can run queries interactively; it locates the CLI via
  `CODEQL_PATH` and databases via `CODEQL_DATABASES_BASE_DIRS`.

```sh
# one-time setup: unzip the CodeQL CLI into ~/tools/codeql (add to PATH), then
cd codeql && codeql pack install

# one-time per target: build a database (requires the target to build;
# openssh needs autoconf, make, and OpenSSL/zlib dev headers)
cd targets/openssh-portable && autoreconf -i && ./configure
codeql database create ../../dbs/openssh-portable --language=cpp --command="make -j$(nproc)"

# each scan: run the pack and render the report
# (add --rerun to force re-evaluation; by default cached results are reused
#  when the queries are unchanged)
codeql database analyze dbs/openssh-portable codeql/ --format=sarif-latest --output=report/openssh-codeql.sarif
python3 codeql/report.py report/openssh-codeql.sarif
```

On openssh-portable: CodeQL finds a strict superset of the Semgrep findings
outside uncompiled test dirs (`regress/` is invisible to CodeQL since `make`
doesn't build it), and additionally catches Ed25519 raw-key EVP calls that
pattern matching missed.

## Notes

- Scan crypto *consumers*, not crypto *implementations* (don't point this at
  OpenSSL itself).
- Semgrep matches per call site with per-rule PQC suggestions in metadata;
  a CodeQL pass (dataflow-precise, needs a build) is the planned second stage
  for algorithm strings that travel across files.
- Semgrep's JSON redacts `extra.lines` when not logged in; `scan.py` reads
  the source file for the matched line instead.
