#!/usr/bin/env python3
"""The user-data folder (ZERO-DATA), kept completely separate from the application folder (ZERO-Deck).

  ZERO-Deck/   application code. Replaceable. Matches SHA256SUMS.txt exactly. NEVER holds results, evidence, notes or scope.
  ZERO-DATA/   everything that belongs to the operator: results/ notes/ config/ evidence/ migrations/ + a marker file.

The updater never reads, moves, copies, deletes or replaces ZERO-DATA. Compatibility is a single integer: the application
requires DATA_FORMAT (file in the app folder); the data folder records the format it was created with in `.zerodeck-data`.
The data folder is NEVER created implicitly: an operator (or the installer, when it is absent) runs `init` explicitly.

  datadir.py default --app APP        print the default data folder (sibling of the app folder)
  datadir.py check --data DIR [--app APP]   exit 0 ok | 3 missing | 4 not a ZERO data folder | 5 newer than this app | 6 invalid
  datadir.py init --data DIR [--app APP]    create it (the parent must exist; refuses a non-empty unmarked folder)
"""
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path
from typing import Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safefs  # noqa: E402

MARKER = ".zerodeck-data"
SUBDIRS = ("results", "notes", "config", "evidence", "archives", "migrations")
DEFAULT_NAME = "ZERO-DATA"


def default_app_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_data_dir(app_root: Path) -> Path:
    return safefs.abs_path(app_root).parent / DEFAULT_NAME


def required_format(app_root: Path) -> int:
    try:
        with safefs.open_dir(app_root) as d, d.open_read("DATA_FORMAT") as fh:
            return int(fh.read().decode("ascii").strip())
    except (OSError, ValueError):
        raise ValueError(f"The application folder has no valid DATA_FORMAT file: {app_root}") from None


def _read_marker(data) -> Optional[int]:
    with safefs.open_dir(data) as d:
        if d.stat_kind(MARKER) == "missing":
            return None
        with d.open_read(MARKER) as fh:
            for line in fh.read().decode("utf-8", errors="replace").splitlines():
                if line.startswith("format="):
                    return int(line.split("=", 1)[1].strip())
    raise ValueError("marker file has no format= line")


def check(data, app_root: Optional[Path] = None) -> Tuple[str, str]:
    """Return (state, message). state: ok | missing | unmarked | newer | invalid."""
    app_root = app_root or default_app_root()
    try:
        need = required_format(app_root)
    except ValueError as exc:
        return "invalid", str(exc)
    data = safefs.abs_path(data)
    try:
        have = _read_marker(data)
    except FileNotFoundError:
        return "missing", f"Data folder does not exist: {data}. Initialize it explicitly: datadir.py init --data \"{data}\""
    except (OSError, ValueError) as exc:  # includes UnsafePathError / UnsupportedConfigurationError
        return "invalid", f"Data folder cannot be used safely: {exc}"
    if have is None:
        return "unmarked", f"{data} exists but is not a ZERO data folder (no {MARKER}). Nothing will be written to it."
    if have > need:
        return "newer", f"{data} uses data format {have}; this application understands up to {need}. Update the application; do not downgrade."
    return "ok", f"{data} (data format {have}, application needs {need})"


def init(data, app_root: Optional[Path] = None) -> str:
    app_root = app_root or default_app_root()
    need = required_format(app_root)
    data = safefs.abs_path(data)
    with safefs.open_dir(data.parent) as parent:
        with parent.child_dir(data.name, create=True) as d:
            names = [e.name for e in d.listdir()]
            if names and MARKER not in names:
                raise ValueError(f"{data} already exists and is not empty but has no {MARKER}: refusing to adopt it")
            for sub in SUBDIRS:
                with d.child_dir(sub, create=True):
                    pass
            try:
                with d.create_file(MARKER) as nf:
                    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    nf.write(f"format={need}\ncreated={stamp}\n".encode("ascii"))
                    nf.commit(0o644)
            except FileExistsError:
                pass  # already initialised: idempotent
            d.verify_bound()
    state, msg = check(data, app_root)
    if state != "ok":
        raise ValueError(msg)
    return msg


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("default", "check", "init"):
        p = sub.add_parser(name)
        p.add_argument("--app", type=Path, default=None)
        if name != "default":
            p.add_argument("--data", type=Path, required=True)
    args = parser.parse_args(argv)
    app = args.app or default_app_root()
    try:
        if args.cmd == "default":
            print(default_data_dir(app))
            return 0
        if args.cmd == "init":
            print("OK:", init(args.data, app))
            return 0
        state, msg = check(args.data, app)
        print(f"{state.upper()}: {msg}", file=sys.stdout if state == "ok" else sys.stderr)
        return {"ok": 0, "missing": 3, "unmarked": 4, "newer": 5, "invalid": 6}[state]
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
