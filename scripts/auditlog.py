#!/usr/bin/env python3
"""The ONE audit-log writer (bash, PowerShell and the scope guard all call this; stdlib only, Python 3.8+).

The log is opened through safefs: the whole path is walked without following links, the directory is held open while
we append, and the entry is written through that held directory (no check-then-write by name). Fail closed: any problem
-> non-zero exit and the caller must refuse the action.

The log is a PLAIN TEXT file. It records activity; it does NOT prevent or reliably reveal tampering by anyone who can
write to the data folder, and the scope hash only identifies which scope file version was in use.

  auditlog.py append --results DIR --action A --kind K --target T --verdict V [--detail D] [--scope FILE]
"""
from __future__ import annotations

import argparse
import datetime
import getpass
import hashlib
import re
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safefs  # noqa: E402
from redaction import redact  # noqa: E402

LOG_NAME = "audit.log"
_race_hook = None  # test seam (None in production): called after the folder is opened, before the append


def _clean(text: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", "?", text)[:300]


def format_row(action: str, kind: str, target: str, verdict: str, detail: str = "", scope_file: Optional[Path] = None) -> str:
    digest = "-"
    if scope_file is not None:
        try:
            digest = hashlib.sha256(Path(scope_file).read_bytes()).hexdigest()[:16]
        except OSError:
            digest = "unreadable"
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser can raise many things on odd systems
        user = "unknown"
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # every logged target/detail is redacted, whatever its kind: a mistyped host like "10.0.0.5?secret" must not leak either
    return "\t".join([now, _clean(user), _clean(action), _clean(kind), _clean(redact(target)), _clean(verdict), digest, _clean(redact(detail))])


def append_row(results_dir, row: str, name: str = LOG_NAME) -> None:
    """Append one row. The results folder must already exist (initialize the data folder first)."""
    with safefs.open_dir(results_dir) as directory:
        if _race_hook is not None:
            _race_hook(directory)
        with directory.open_append(name) as fh:
            fh.write((row + "\n").encode("utf-8"))
            fh.flush()
        directory.verify_bound()  # the folder we wrote into is still the one at that path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("append")
    p.add_argument("--results", type=Path, required=True)
    p.add_argument("--action", required=True)
    p.add_argument("--kind", required=True)
    p.add_argument("--target", default="")
    p.add_argument("--verdict", required=True)
    p.add_argument("--detail", default="")
    p.add_argument("--scope", type=Path)
    args = parser.parse_args(argv)
    try:
        append_row(args.results, format_row(args.action, args.kind, args.target, args.verdict, args.detail, args.scope))
    except (OSError, ValueError) as exc:
        print(f"AUDIT WRITE FAILED: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
