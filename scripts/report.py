#!/usr/bin/env python3
"""Build a Markdown session report from the results folder (file inventory with SHA-256 + recent audit log).

The results folder is opened through safefs (whole path walked without following links, held open): links/junctions
are listed but never followed or hashed, nothing is read through a name that was validated earlier, and the report is
created exclusively - an existing report is never overwritten.
The audit log is a plain file: it records what happened but is not tamper-proof."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fscaps  # noqa: E402
import safefs  # noqa: E402

AUDIT_TAIL = 50


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _inventory(root):
    """(files with hash/size/mtime, skipped links) from a HELD results directory."""
    files, skipped = [], []
    for rel, parent, name, kind in safefs.walk_files(root, links="include"):
        if kind != "file":
            skipped.append(rel)
        elif name != "README.md" and not name.startswith("report_"):
            with parent.open_read(name) as fh:
                mtime = getattr(parent, "last_mtime_ns", 0) / 1e9
                size, digest = 0, hashlib.sha256()
                for block in iter(lambda: fh.read(safefs.CHUNK), b""):
                    size += len(block)
                    digest.update(block)
            files.append((rel, size, mtime, digest.hexdigest()))
    return files, skipped


def build_report(results, scope: Optional[Path], title: str, operator: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    scope_hash = "n/a"
    if scope:
        try:
            scope_hash = hashlib.sha256(Path(scope).read_bytes()).hexdigest()[:16]
        except OSError:
            pass
    out = [f"# {_cell(title)}", "", f"- Generated: {now}", f"- Operator: {_cell(operator)}", f"- Scope file SHA-256 (first 16): `{scope_hash}`",
           "", "> Contains raw tool output stored UNENCRYPTED. Treat as sensitive; encrypt or move off the USB.", "",
           "## Artifacts", "", "| File | Bytes | Modified (UTC) | SHA-256 |", "|---|---:|---|---|"]
    with safefs.open_dir(results) as root:
        files, skipped = _inventory(root)
        for rel, size, mtime, digest in files:
            stamp = datetime.datetime.fromtimestamp(mtime, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            out.append(f"| {_cell(rel)} | {size} | {stamp} | `{digest}` |")
        if not files:
            out.append("| _(none)_ | | | |")
        if skipped:
            out += ["", "## Skipped links (not followed, not hashed)", ""] + [f"- {_cell(rel)}" for rel in skipped]
        out += ["", f"## Audit log (last {AUDIT_TAIL} entries)", "",
                "Columns: time, user, action, kind, target, verdict, scope-hash, detail. Plain text: not tamper-proof.", "", "```"]
        try:
            with root.open_read("audit.log") as fh:
                out += fh.read().decode("utf-8", errors="replace").splitlines()[-AUDIT_TAIL:]
        except (FileNotFoundError, safefs.UnsafePathError):
            out += ["(no audit log)"]
    out += ["```", "", "## Findings / notes", "", "_Add analyst notes here._", ""]
    return "\n".join(out)


def _create_report(directory, name: str, explicit: bool, text: str) -> str:
    stem, dot, ext = name.rpartition(".")
    for n in range(1000):
        candidate = name if n == 0 else f"{stem}_{n}{dot}{ext}"
        try:
            with directory.create_file(candidate) as nf:
                nf.write(text.encode("utf-8"))
                nf.commit(0o600)
            directory.verify_bound()
            return candidate
        except FileExistsError:
            if explicit:
                raise ValueError(f"Refusing to overwrite existing file: {name}") from None
    raise ValueError("Could not find an unused report name")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--scope", type=Path)
    parser.add_argument("--title", default="ZERO Deck session report")
    parser.add_argument("--operator", default="unspecified")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        fscaps.require_publish_at(safefs.abs_path(args.out).parent if args.out else args.results)  # refuse before reading anything
        text = build_report(args.results, args.scope, args.title, args.operator)
        if args.out:
            out_abs = safefs.abs_path(args.out)
            with safefs.open_dir(out_abs.parent) as d:
                written = out_abs.parent / _create_report(d, out_abs.name, True, text)
        else:
            with safefs.open_dir(args.results) as d:
                written = safefs.abs_path(args.results) / _create_report(d, f"report_{stamp}.md", False, text)
    except FileNotFoundError as exc:
        print(f"ERROR: results directory not found: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Report written: {written}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
