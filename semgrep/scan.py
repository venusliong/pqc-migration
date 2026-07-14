#!/usr/bin/env python3
"""Scan a codebase for quantum-vulnerable crypto API usage and report
file:line, the crypto function used, and a suggested PQC replacement.

Usage: scan.py <target-dir> [--rules DIR] [--out report.md] [--json out.json]
"""
import argparse
import collections
import json
import re
import subprocess
import sys
from pathlib import Path

CRYPTO_CALL_RE = re.compile(
    r"\b((?:RSA|DSA|ECDSA|ECDH|DH|EC_KEY|EC_GROUP|EVP|MD5|SHA1)[A-Za-z0-9_]*)\s*\("
)


def run_semgrep(rules: Path, target: Path) -> dict:
    cmd = [
        "semgrep", "scan",
        "--config", str(rules),
        "--json",
        "--metrics", "off",
        "--quiet",
        str(target),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):  # 1 = findings present
        sys.stderr.write(proc.stderr)
        sys.exit(f"semgrep failed with exit code {proc.returncode}")
    return json.loads(proc.stdout)


CRYPTO_IDENT_RE = re.compile(
    r"\b((?:RSA|DSA|ECDSA|ECDH|DH|EC_KEY|EC_GROUP|EVP|MD5|SHA1)[A-Za-z0-9_]*)\b"
)


def crypto_function(path: Path, line: int) -> str:
    # semgrep may redact extra.lines when not logged in; read the source
    try:
        text = path.read_text(errors="replace").splitlines()[line - 1]
    except (OSError, IndexError):
        return "?"
    m = CRYPTO_CALL_RE.search(text)
    if m:
        return m.group(1)
    idents = [i.group(1) for i in CRYPTO_IDENT_RE.finditer(text)]
    if idents:
        # prefer API identifiers (contain '_') over bare words in strings
        return next((i for i in idents if "_" in i), idents[0])
    return text.strip()[:40]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", type=Path)
    ap.add_argument("--rules", type=Path,
                    default=Path(__file__).resolve().parent / "rules")
    ap.add_argument("--out", type=Path, default=None,
                    help="default: report/<target>-semgrep-report.md")
    ap.add_argument("--json", type=Path, default=None,
                    help="also write raw findings as JSON")
    args = ap.parse_args()
    if args.out is None:
        report_dir = Path(__file__).resolve().parent.parent / "report"
        args.out = report_dir / f"{args.target.name}-semgrep-report.md"

    data = run_semgrep(args.rules, args.target)
    findings = []
    for r in data.get("results", []):
        meta = r["extra"].get("metadata", {})
        findings.append({
            "file": str(Path(r["path"]).relative_to(args.target)),
            "line": r["start"]["line"],
            "function": crypto_function(Path(r["path"]), r["start"]["line"]),
            "primitive": meta.get("primitive", "?"),
            "category": meta.get("category", "?"),
            "priority": meta.get("priority", "?"),
            "suggestion": meta.get("pqc_replacement", "?"),
            "rule": r["check_id"].rsplit(".", 1)[-1],
        })
    # dedupe overlapping pattern matches on the same call site
    seen = set()
    findings = [f for f in findings
                if (k := (f["file"], f["line"], f["rule"])) not in seen
                and not seen.add(k)]
    findings.sort(key=lambda f: (f["priority"], f["file"], f["line"]))

    by_priority = collections.Counter(f["priority"] for f in findings)
    by_primitive = collections.Counter(f["primitive"] for f in findings)
    by_file = collections.Counter(f["file"] for f in findings)

    lines = ["# PQC migration scan report", "",
             f"Target: `{args.target}`  |  Findings: **{len(findings)}**", "",
             "## Summary by priority", "",
             "| Priority | Findings |", "|---|---|"]
    lines += [f"| {p} | {n} |" for p, n in sorted(by_priority.items())]
    lines += ["", "## Summary by primitive", "",
              "| Primitive | Findings |", "|---|---|"]
    lines += [f"| {p} | {n} |" for p, n in by_primitive.most_common()]
    lines += ["", "## Top files", "", "| File | Findings |", "|---|---|"]
    lines += [f"| {f} | {n} |" for f, n in by_file.most_common(15)]
    lines += ["", "## Findings", "",
              "| Priority | File:Line | Crypto function | Suggested replacement |",
              "|---|---|---|---|"]
    lines += [
        f"| {f['priority']} | `{f['file']}:{f['line']}` | `{f['function']}` "
        f"| {f['suggestion']} |"
        for f in findings
    ]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(findings, indent=2) + "\n")

    print(f"{len(findings)} findings across {len(by_file)} files")
    for p, n in by_primitive.most_common():
        print(f"  {p:10} {n}")
    print(f"report: {args.out}")


if __name__ == "__main__":
    main()
