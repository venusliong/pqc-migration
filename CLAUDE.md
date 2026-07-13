# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A prototype scanner that finds quantum-vulnerable crypto API usage in target
codebases and reports file, line, crypto function name, and a suggested PQC
replacement (ML-KEM-768 / ML-DSA-65 / SLH-DSA per FIPS 203/204/205). It is a
Semgrep rule pack plus a Python runner — there is no build step and no test
suite yet.

## Commands

```sh
# run a scan (semgrep lives in ~/.local/bin — ensure it's on PATH)
python3 scripts/scan.py targets/openssh-portable --out report.md --json findings.json

# debug a single rule against one file
semgrep scan --config rules/c-legacy-crypto.yaml --metrics off <file.c>

# add a new scan target (shallow clone; targets/ holds third-party code, never edit it)
git clone --depth 1 <repo-url> targets/<name>
```

`report.md` and `findings.json` at the repo root are generated output —
regenerate rather than hand-edit.

## Architecture

The contract between the two halves lives in rule **metadata**: every rule in
`rules/*.yaml` must carry `category`, `primitive`, `priority` (P1 kex/RSA →
P3 weak hash), and `pqc_replacement`. `scripts/scan.py` reads those fields
from Semgrep's JSON to build the report — a rule without them shows up as
`?` in every column. The suggestion text lives only in rules, never in the
script.

`scan.py` post-processes Semgrep output in two ways that matter when editing
either side:

- It dedupes findings by (file, line, rule-id), because overlapping patterns
  in one `pattern-either` can match the same call site twice. Prefer a single
  bare-call pattern (`RSA_new()` matches even inside `if ((rsa = RSA_new())`)
  over adding assignment variants.
- It re-reads the matched line from the source file to extract the crypto
  function name, because this Semgrep version redacts `extra.lines`
  ("requires login") in JSON output when not logged in. Don't rely on
  `extra.lines`.

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

## Roadmap context

Planned second stage is a CodeQL pass (dataflow-precise, requires building
the target) for algorithm strings that travel across files; other candidates:
CycloneDX CBOM output, tagging/excluding test dirs (`regress/` in openssh),
and Java rules to score against CryptoAPI-Bench.
