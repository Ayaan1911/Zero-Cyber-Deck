#!/usr/bin/env python3
"""Build a Markdown session report from results/ (file inventory with SHA-256 + recent audit log)."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence import sha256_file  # noqa: E402

AUDIT_TAIL = 50


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def build_report(results: Path, scope: Path | None, title: str, operator: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    scope_hash = hashlib.sha256(scope.read_bytes()).hexdigest()[:16] if scope and scope.is_file() else "n/a"
    out = [f"# {_cell(title)}", "", f"- Generated: {now}", f"- Operator: {_cell(operator)}", f"- Scope file SHA-256 (first 16): `{scope_hash}`",
           "", "> Contains raw tool output stored UNENCRYPTED. Treat as sensitive; encrypt or move off the USB.", "",
           "## Artifacts", "", "| File | Bytes | Modified (UTC) | SHA-256 |", "|---|---:|---|---|"]
    files = sorted(f for f in results.rglob("*") if f.is_file() and f.name != "README.md" and not f.name.startswith("report_"))
    for f in files:
        st = f.stat()
        mtime = datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        out.append(f"| {_cell(f.relative_to(results).as_posix())} | {st.st_size} | {mtime} | `{sha256_file(f)}` |")
    if not files:
        out.append("| _(none)_ | | | |")
    audit = results / "audit.log"
    out += ["", f"## Audit log (last {AUDIT_TAIL} entries)", "", "Columns: time, user, action, kind, target, verdict, scope-hash, detail", "", "```"]
    out += audit.read_text(encoding="utf-8", errors="replace").splitlines()[-AUDIT_TAIL:] if audit.is_file() else ["(no audit log)"]
    out += ["```", "", "## Findings / notes", "", "_Add analyst notes here._", ""]
    return "\n".join(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--scope", type=Path)
    parser.add_argument("--title", default="ZERO Deck session report")
    parser.add_argument("--operator", default="unspecified")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if not args.results.is_dir():
        print(f"ERROR: results directory not found: {args.results}", file=sys.stderr)
        return 2
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.out or args.results / f"report_{stamp}.md"
    out.write_text(build_report(args.results, args.scope, args.title, args.operator), encoding="utf-8", newline="\n")
    print(f"Report written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
