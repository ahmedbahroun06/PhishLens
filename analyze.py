#!/usr/bin/env python3
"""The CLI door. Same brain as the website.

Usage:
    python analyze.py path/to/email.eml
    python analyze.py -                 # read raw email from stdin
    python analyze.py email.eml --json  # print only the JSON report

Exit code is the score bucket: 0 clean, 1 suspicious, 2 phishing — handy in scripts.
"""
from __future__ import annotations

import argparse
import json
import sys

from app.core.analyzer import analyze

# Windows consoles default to cp1252 and choke on ✓/✕ glyphs; force UTF-8 if we can.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

_UNICODE_OK = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "") == "utf8"
_MARKS = ({"fail": "✕", "warn": "!", "pass": "✓", "other": "?"}
          if _UNICODE_OK else {"fail": "x", "warn": "!", "pass": "+", "other": "?"})

_COLORS = {
    "phishing": "\033[91m", "suspicious": "\033[93m", "clean": "\033[92m",
    "reset": "\033[0m", "dim": "\033[90m", "bold": "\033[1m",
}


def _c(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


def main() -> int:
    ap = argparse.ArgumentParser(description="PhishLens — analyze one email from the terminal.")
    ap.add_argument("email", help="Path to an .eml file, or - for stdin.")
    ap.add_argument("--json", action="store_true", help="Print only the JSON report.")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    args = ap.parse_args()

    if args.email == "-":
        raw = sys.stdin.buffer.read()
    else:
        with open(args.email, "rb") as fh:
            raw = fh.read()

    report = analyze(raw)

    if args.json:
        print(json.dumps(report, indent=2))
        return _exit_code(report)

    use_color = sys.stdout.isatty() and not args.no_color
    _print_human(report, use_color)
    return _exit_code(report)


def _exit_code(report: dict) -> int:
    return {"clean": 0, "suspicious": 1, "phishing": 2}.get(report["verdict"], 0)


def _print_human(report: dict, use_color: bool) -> None:
    v = report["verdict"]
    meta = report.get("meta", {})
    print()
    print(_c(f"  {v.upper()}  ", v, use_color) + _c(f"  score {report['score']}/100", "bold", use_color))
    print(_c(f"  From: {meta.get('from_display','')} <{meta.get('from','')}>", "dim", use_color))
    if meta.get("subject"):
        print(_c(f"  Subject: {meta['subject']}", "dim", use_color))
    print()
    print(_c("  Signals", "bold", use_color))
    for s in report["signals"]:
        key = s["status"] if s["status"] in ("fail", "warn", "pass") else "other"
        mark = _MARKS[key]
        pts = f"+{s['points']}" if s["points"] else "  0"
        line = f"    {mark} {s['name']:<22} {s['status']:<9} {pts} pts"
        detail = f"   {s['detail']}" if s.get("detail") else ""
        color = "clean" if s["status"] == "pass" else "phishing" if s["status"] == "fail" else "suspicious"
        print(_c(line, color, use_color) + _c(detail, "dim", use_color))

    urls = report.get("urls", [])
    if urls:
        print()
        print(_c("  URLs", "bold", use_color))
        for u in urls:
            print(f"    [{u['source']}] {u['url']}  →  {u.get('status','?')} "
                  f"(mal {u.get('malicious',0)}, susp {u.get('suspicious',0)})")

    llm = report.get("llm", {})
    print()
    print(_c("  AI analysis", "bold", use_color)
          + _c(f"  (source: {llm.get('source','n/a')})", "dim", use_color))
    print(f"    BEC likelihood:      {llm.get('bec_likelihood','?')}")
    print(f"    AI-generated text:   {llm.get('ai_generated_likelihood','?')}")
    if llm.get("explanation"):
        print()
        print(f"    {llm['explanation']}")
    if meta.get("notes"):
        print()
        print(_c(f"  notes: {'; '.join(meta['notes'])}", "dim", use_color))
    print()


if __name__ == "__main__":
    sys.exit(main())
