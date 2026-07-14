#!/usr/bin/env python3
"""Render a CodeQL SARIF file into the same Markdown report format as the
Semgrep pass: file:line, crypto function, suggested PQC replacement.

Usage: report.py <sarif-file> [--out report/<name>-codeql-report.md]
"""
import argparse
import collections
import json
import re
from pathlib import Path

# CodeQL markdown-escapes brackets in SARIF messages: "[P1]" arrives as "\[P1\]"
PRIORITY_RE = re.compile(r"^\\?\[(P\d)\\?\]\s*")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("sarif", type=Path)
    ap.add_argument("--out", type=Path, default=None,
                    help="default: report/<sarif-stem>-report.md")
    args = ap.parse_args()
    if args.out is None:
        report_dir = Path(__file__).resolve().parent.parent / "report"
        args.out = report_dir / f"{args.sarif.stem}-report.md"

    doc = json.loads(args.sarif.read_text())
    findings = []
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            loc = res.get("locations", [{}])[0].get("physicalLocation", {})
            # CodeQL merges duplicate results at one site into a single
            # newline-joined message; keep table cells single-line
            msg = " / ".join(res.get("message", {}).get("text", "").splitlines())
            # LegacyCryptoAPIs.ql messages are "[<priority>] <function>: <explanation>"
            pm = PRIORITY_RE.match(msg)
            priority = pm.group(1) if pm else "?"
            func, _, detail = msg[pm.end():].partition(": ") if pm else msg.partition(": ")
            findings.append({
                "rule": res.get("ruleId", "?"),
                "file": loc.get("artifactLocation", {}).get("uri", "?"),
                "line": loc.get("region", {}).get("startLine", 0),
                "priority": priority,
                "function": func,
                "detail": detail or msg,
            })
    findings.sort(key=lambda f: (f["priority"], f["file"], f["line"]))

    by_priority = collections.Counter(f["priority"] for f in findings)
    by_rule = collections.Counter(f["rule"] for f in findings)
    lines = ["# CodeQL PQC scan report", "",
             f"Source: `{args.sarif}`  |  Findings: **{len(findings)}**", "",
             "## Summary by priority", "",
             "| Priority | Findings |", "|---|---|"]
    lines += [f"| {p} | {n} |" for p, n in sorted(by_priority.items())]
    lines += ["", "## Summary by rule", "", "| Rule | Findings |", "|---|---|"]
    lines += [f"| {r} | {n} |" for r, n in by_rule.most_common()]
    lines += ["", "## Findings", "",
              "| Priority | File:Line | Crypto function | Migration guidance |",
              "|---|---|---|---|"]
    lines += [f"| {f['priority']} | `{f['file']}:{f['line']}` | `{f['function']}` "
              f"| {f['detail']} |"
              for f in findings]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n")
    print(f"{len(findings)} findings -> {args.out}")


if __name__ == "__main__":
    main()
