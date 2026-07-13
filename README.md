# pqc-migration

Prototype scanner that finds quantum-vulnerable crypto API usage and reports
file, line, the crypto function used, and a suggested PQC replacement
(ML-KEM / ML-DSA / SLH-DSA per FIPS 203/204/205).

## Layout

- `rules/` — Semgrep rules. `c-legacy-crypto.yaml` covers the OpenSSL C API:
  low-level `RSA_*`/`DSA_*`/`EC_KEY_*`/`ECDSA_*`/`ECDH_*`/`DH_*`, EVP contexts
  bound to legacy algorithm IDs or name strings, and weak hashes (MD5/SHA-1,
  including function-pointer usage).
- `scripts/scan.py` — runner: executes Semgrep, dedupes overlapping matches,
  and writes a Markdown report plus optional JSON.
- `targets/` — codebases under scan (not ours; shallow clones). Currently
  OpenSSH-portable.

## Usage

```sh
pip3 install --user semgrep   # once
python3 scripts/scan.py targets/openssh-portable --out report.md --json findings.json
```

Priorities in the report: P1 = key exchange / RSA (harvest-now-decrypt-later
exposure), P2 = signatures / EC key material, P3 = weak hashes.

## Notes

- Scan crypto *consumers*, not crypto *implementations* (don't point this at
  OpenSSL itself).
- Semgrep matches per call site with per-rule PQC suggestions in metadata;
  a CodeQL pass (dataflow-precise, needs a build) is the planned second stage
  for algorithm strings that travel across files.
- Semgrep's JSON redacts `extra.lines` when not logged in; `scan.py` reads
  the source file for the matched line instead.
