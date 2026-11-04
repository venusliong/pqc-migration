# pqc-migration

Prototype scanner that finds quantum-vulnerable crypto API usage and reports
file, line, the crypto function used, and a suggested PQC replacement
(ML-KEM / ML-DSA / SLH-DSA per FIPS 203/204/205).

## Layout

- `semgrep/` — the Semgrep stage, one rules file per language.
  `rules/c-legacy-crypto.yaml` covers the OpenSSL C API: low-level
  `RSA_*`/`DSA_*`/`EC_KEY_*`/`ECDSA_*`/`ECDH_*`/`DH_*`, EVP contexts bound to
  legacy algorithm IDs or name strings, and weak hashes (MD5/SHA-1, including
  function-pointer usage). `rules/ruby-legacy-crypto.yaml` covers the Ruby
  OpenSSL stdlib: `OpenSSL::PKey::{RSA,DH,EC,DSA}`, `.sign`/`.verify` on keys
  and X.509 certificates, and weak hashes named by constant
  (`Digest::SHA1`) or by string (`OpenSSL::Digest.new("md5")`). Both are
  generated from `crypto-functions.yaml` (the editable function/pattern
  lists) by `gen_rules.py` — regenerate, don't hand-edit. `scan.py` is the
  runner: executes Semgrep, dedupes overlapping matches, and writes a
  Markdown report plus optional JSON. It is language-neutral — `--rules`
  defaults to the whole `rules/` directory and Semgrep applies each rule only
  to its declared language.
- `codeql/` — the CodeQL stage: one sibling query pack per language
  (`codeql/cpp/`, `codeql/ruby/`) plus the shared `report.py` (SARIF →
  Markdown). Details below.
- `report/` — committed scan deliverables, named per target
  (`openssh-semgrep-report.md`, `openssh-codeql.sarif`, …). Regenerate,
  don't hand-edit; both scripts default their output here.
- `targets/` — codebases under scan (not ours; shallow clones). Currently
  OpenSSH-portable (C) and postal (Ruby/Rails).
- `dbs/` — CodeQL databases (gitignored; rebuild per below).

## One-time setup

```sh
# tools (once per machine)
pip3 install --user semgrep   # installs to ~/.local/bin

# scan targets (once per target; targets/ is gitignored, clones are read-only)
git clone --depth 1 https://github.com/openssh/openssh-portable targets/openssh-portable
git clone --depth 1 https://github.com/postalserver/postal targets/postal
```

The CodeQL stage needs additional one-time setup — see below.

### PATH

Only the CodeQL CLI needs a shell-init change; Semgrep normally does not.

- **Semgrep:** `pip3 install --user` puts it in `~/.local/bin`, which
  Debian/Ubuntu's default `~/.profile` already prepends — but only *if the
  directory exists at login*. Right after a first install the current session
  will not see it, so either log out and back in, `source ~/.profile`, or
  export it once. `semgrep/scan.py` shells out to a bare `semgrep`, so it has
  to be resolvable; `codeql/report.py` needs nothing on PATH.
- **CodeQL:** nothing puts it on PATH — the CLI is a manual unzip into
  `~/tools/codeql`. Add it to a shell-init file, or use the per-shell export
  that the command blocks below assume:

```sh
export PATH="$HOME/.local/bin:$HOME/tools/codeql:$PATH"
```

  If you add it permanently, prefer `~/.profile` over `~/.bashrc`:
  `~/.bashrc` is only sourced for *interactive* shells, so a `codeql` line
  there is invisible to scripts, `bash -lc`, Makefiles and CI. (That is the
  state on this machine — `~/.bashrc:121` — which is why the reproduce
  commands still carry the explicit `export`.)
- **The MCP server needs no PATH at all.** `.mcp.json` resolves the CLI
  through `CODEQL_PATH` as an absolute path, so agent sessions work whether
  or not your shell can find `codeql`.

### Language prerequisites

**Semgrep needs nothing per language.** Both the C and Ruby parsers are built
into the `semgrep` wheel (verified on 1.169.0), so a Ruby scan works straight
after `pip3 install --user semgrep` — no Ruby runtime, no `--lang` flag, and
no change to `scan.py` (it applies every file in `semgrep/rules/`, and
Semgrep runs each rule only against its declared language).

**CodeQL needs one `pack install` per query pack, once each:**

```sh
cd codeql/cpp  && codeql pack install   # pulls codeql/cpp-all
cd codeql/ruby && codeql pack install   # pulls codeql/ruby-all (pinned 5.*)
```

The CLI distribution ships each language's *extractor* but **not** its QL
libraries, so this step needs network access. `codeql resolve languages`
should list `ruby` — if it does not, the CLI download was a language-specific
bundle rather than the full one.

**Ruby parsing needs no Ruby toolchain at all.** Unlike the C stage — which
needs the target to actually build (`autoconf`, `make`, OpenSSL and zlib dev
headers) because the database only contains what the compiler saw — the Ruby
extractor is a self-contained binary that parses source directly. It never
invokes `ruby`, `gem` or `bundle`, so:

- no Ruby runtime or specific Ruby version is required;
- `bundle install` is *not* needed and the target's gems need not be present;
- there is no `--command` argument to `codeql database create`, and no
  uncompiled-code blind spot: every `.rb` file in the tree is extracted,
  `spec/` included.

Building `dbs/postal` this way takes ~20 s and produces ~7 MB.

Two version constraints to know about:

- `codeql/ruby/qlpack.yml` pins `codeql/ruby-all: "5.*"` (resolves to 5.2.2).
  Versions 6.x/7.x were published by CodeQL CLI 2.27.4 and their OCI
  manifests carry a `config.digest` field that CLI 2.26.0's parser rejects
  (`Could not get manifest … UnrecognizedPropertyException "Unrecognized
  field \"digest\""`). Lifting the pin means upgrading the CLI first.
- `codeql/cpp/codeql-pack.lock.yml` is pinned deliberately — don't
  regenerate it, or the verified openssh baseline moves under you.

## Usage

```sh
# after editing semgrep/crypto-functions.yaml (not each scan)
python3 semgrep/gen_rules.py

python3 semgrep/scan.py targets/openssh-portable --json report/openssh-semgrep-findings.json
python3 semgrep/scan.py targets/postal --json report/postal-semgrep-findings.json
```

Priorities in the report: P1 = key exchange / RSA (harvest-now-decrypt-later
exposure), P2 = signatures / EC key material, P3 = weak hashes.

## CodeQL stage (dataflow-precise)

- `codeql/cpp/` — query pack `pqc/cpp-crypto-queries`: `LegacyCryptoAPIs.ql`
  (direct legacy calls, EVP contexts bound to legacy algorithm IDs via
  macros, weak hashes incl. function-pointer references) and
  `AlgorithmNameFlow.ql` (path-problem: algorithm name strings flowing across
  functions into EVP by-name factories).
- `codeql/ruby/` — query pack `pqc/ruby-crypto-queries`:
  `RubyLegacyCryptoAPIs.ql` (asymmetric keygen/load on `OpenSSL::PKey::*`
  constant paths, plus weak hashes taken from the official `codeql/ruby-all`
  crypto modeling). Packs are per language because extensible predicates are
  pack-scoped — **always pass the language directory** to `database analyze`,
  never the `codeql/` parent, which would try to compile every language's
  queries against one database.
- `.mcp.json` — registers GitHub's `codeql-development-mcp-server` (npx) so
  agent sessions can run queries interactively; it locates the CLI via
  `CODEQL_PATH` and databases via `CODEQL_DATABASES_BASE_DIRS`. Both resolve
  to this checkout's layout with no setup: `${HOME}/tools/codeql/codeql` and
  the relative `dbs`. Export `CODEQL_DATABASES_BASE_DIRS` to override it (a
  colon-separated list, resolved against the project root); a CodeQL CLI
  installed somewhere other than `~/tools/codeql` needs the `CODEQL_PATH`
  line in `.mcp.json` edited, because Claude Code's `${VAR:-default}`
  expansion cannot nest `${HOME}` inside a default.

```sh
# one-time setup: unzip the CodeQL CLI into ~/tools/codeql (add to PATH), then
# run the per-pack `codeql pack install` from "Language prerequisites" above

# one-time per C target: build a database (requires the target to build;
# openssh needs autoconf, make, and OpenSSL/zlib dev headers)
cd targets/openssh-portable && autoreconf -i && ./configure
codeql database create ../../dbs/openssh-portable --language=cpp --command="make -j$(nproc)"

# one-time per Ruby target: no build, no --command -- the extractor reads source
codeql database create dbs/postal --language=ruby --source-root targets/postal

# each scan: run the pack for that language and render the report
# (add --rerun to force re-evaluation; by default cached results are reused
#  when the queries are unchanged)
codeql database analyze dbs/openssh-portable codeql/cpp --format=sarif-latest --output=report/openssh-codeql.sarif
python3 codeql/report.py report/openssh-codeql.sarif

codeql database analyze dbs/postal codeql/ruby --format=sarif-latest --output=report/postal-codeql.sarif
python3 codeql/report.py report/postal-codeql.sarif
```

Note `codeql/ruby/qlpack.yml` pins `codeql/ruby-all: "5.*"`: 6.x/7.x were
published by a newer CLI whose OCI manifests CodeQL 2.26.0 cannot parse.

## Notes

- Scan crypto *consumers*, not crypto *implementations* (don't point this at
  OpenSSL itself).
- Semgrep matches per call site with per-rule PQC suggestions in metadata;
  the CodeQL pass adds semantic resolution (macro-fed algorithm IDs in C) and
  is where cross-function dataflow for algorithm strings lives. It needs a
  database — built by tracing the compiler for C, extracted straight from
  source for Ruby.
- Priorities are per primitive, not per language: both stages and both
  languages use one P1–P3 scale, so reports are directly comparable.
- Semgrep's JSON redacts `extra.lines` when not logged in; `scan.py` reads
  the source file for the matched line instead.
