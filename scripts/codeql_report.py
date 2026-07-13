#!/usr/bin/env python3
"""Render a CodeQL SARIF file into the same Markdown report format as the
Semgrep pass: file:line, crypto function, suggested PQC replacement.

Usage: codeql_report.py <sarif-file> [--out codeql-report.md]
"""
import argparse
import collections
import json
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("sarif", type=Path)
    ap.add_argument("--out", type=Path, default=Path("codeql-report.md"))
    args = ap.parse_args()

    doc = json.loads(args.sarif.read_text())
    findings = []
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            loc = res.get("locations", [{}])[0].get("physicalLocation", {})
            msg = res.get("message", {}).get("text", "")
            # LegacyCryptoAPIs.ql messages are "<function>: <explanation>"
            func, _, detail = msg.partition(": ")
            findings.append({
                "rule": res.get("ruleId", "?"),
                "file": loc.get("artifactLocation", {}).get("uri", "?"),
                "line": loc.get("region", {}).get("startLine", 0),
                "function": func,
                "detail": detail or msg,
            })
    findings.sort(key=lambda f: (f["file"], f["line"]))

    by_rule = collections.Counter(f["rule"] for f in findings)
    lines = ["# CodeQL PQC scan report", "",
             f"Source: `{args.sarif}`  |  Findings: **{len(findings)}**", "",
             "## Summary by rule", "", "| Rule | Findings |", "|---|---|"]
    lines += [f"| {r} | {n} |" for r, n in by_rule.most_common()]
    lines += ["", "## Findings", "",
              "| File:Line | Crypto function | Migration guidance |",
              "|---|---|---|"]
    lines += [f"| `{f['file']}:{f['line']}` | `{f['function']}` | {f['detail']} |"
              for f in findings]
    args.out.write_text("\n".join(lines) + "\n")
    print(f"{len(findings)} findings -> {args.out}")


if __name__ == "__main__":
    main()
