#!/usr/bin/env python3
"""Build a Markdown session report from results/ (file inventory with SHA-256 + recent audit log).
Links/junctions are listed but never followed or hashed. Existing reports are never overwritten.
The audit log is a plain file: it records what happened but is not tamper-proof."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence import sha256_file  # noqa: E402
from pathsafe import assert_no_links_in_chain, create_new_file, is_link  # noqa: E402

AUDIT_TAIL = 50


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def collect(results: Path):
    """Return (regular files, skipped links) without following any link."""
    files, skipped = [], []
    for dirpath, dirnames, filenames in os.walk(results, followlinks=False):
        dirnames.sort()
        keep = []
        for name in dirnames:
            full = Path(dirpath) / name
            if is_link(full):
                skipped.append(full)
            else:
                keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if is_link(full):
                skipped.append(full)
            elif name != "README.md" and not name.startswith("report_"):
                files.append(full)
    return files, skipped


def build_report(results: Path, scope: Path | None, title: str, operator: str) -> str:
    results = assert_no_links_in_chain(results)  # ancestors too: `alias/results` where alias is a link is refused
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    scope_hash = hashlib.sha256(scope.read_bytes()).hexdigest()[:16] if scope and scope.is_file() and not is_link(scope) else "n/a"
    out = [f"# {_cell(title)}", "", f"- Generated: {now}", f"- Operator: {_cell(operator)}", f"- Scope file SHA-256 (first 16): `{scope_hash}`",
           "", "> Contains raw tool output stored UNENCRYPTED. Treat as sensitive; encrypt or move off the USB.", "",
           "## Artifacts", "", "| File | Bytes | Modified (UTC) | SHA-256 |", "|---|---:|---|---|"]
    files, skipped = collect(results)
    for f in files:
        st = f.stat()
        mtime = datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        out.append(f"| {_cell(f.relative_to(results).as_posix())} | {st.st_size} | {mtime} | `{sha256_file(f)}` |")
    if not files:
        out.append("| _(none)_ | | | |")
    if skipped:
        out += ["", "## Skipped links (not followed, not hashed)", ""] + [f"- {_cell(p.relative_to(results).as_posix())}" for p in skipped]
    audit = results / "audit.log"
    out += ["", f"## Audit log (last {AUDIT_TAIL} entries)", "",
            "Columns: time, user, action, kind, target, verdict, scope-hash, detail. Plain text: not tamper-proof.", "", "```"]
    if audit.is_file() and not is_link(audit):
        out += audit.read_text(encoding="utf-8", errors="replace").splitlines()[-AUDIT_TAIL:]
    else:
        out += ["(no audit log)"]
    out += ["```", "", "## Findings / notes", "", "_Add analyst notes here._", ""]
    return "\n".join(out)


def _create_exclusive(out: Path, explicit: bool, text: str) -> Path:
    for n in range(1000):
        candidate = out if n == 0 else out.with_name(f"{out.stem}_{n}{out.suffix}")
        try:
            with create_new_file(candidate) as fh:  # exclusive create; every ancestor validated; no write-through
                fh.write(text.encode("utf-8"))
            return candidate
        except FileExistsError:
            if explicit:
                raise ValueError(f"Refusing to overwrite existing file: {out}") from None
    raise ValueError("Could not find an unused report name")


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
    try:
        text = build_report(args.results, args.scope, args.title, args.operator)
        written = _create_exclusive(args.out or args.results / f"report_{stamp}.md", args.out is not None, text)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Report written: {written}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
