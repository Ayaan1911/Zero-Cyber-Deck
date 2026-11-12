#!/usr/bin/env python3
"""The user-data folder (ZERO-DATA), kept completely separate from the application folder (ZERO-Deck).

  ZERO-Deck/   application code. Replaceable. Matches SHA256SUMS.txt exactly. NEVER holds results, evidence, notes or scope.
  ZERO-DATA/   everything that belongs to the operator: results/ notes/ config/ evidence/ archives/ migrations/ + a marker file.

The updater never reads, moves, copies, deletes or replaces ZERO-DATA. Compatibility is a single integer: the application
requires DATA_FORMAT (file in the app folder); the data folder records the format it was created with in `.zerodeck-data`.
The data folder is NEVER created implicitly: an operator (or the installer, when it is absent) runs `init` explicitly.

INITIALISATION IS SAFE TO INTERRUPT AND SAFE TO REPEAT
  1. the filesystem is probed first (scripts/fscaps.py, inside a throw-away sub-folder of the data folder): if the safe-file
     guarantees cannot be established the folder is NOT initialised, a folder this call created is removed again (only if empty),
     and nothing a user put there is touched
  2. the standard sub-folders are created, 3. the marker file is written LAST - it means "complete"
  An interrupted init leaves only ZERO's own empty folders and no marker: `check` reports it as `partial` and `init` completes
  it, deleting nothing. A folder that contains anything else without a marker is never adopted.

  datadir.py default --app APP        print the default data folder (sibling of the app folder)
  datadir.py check --data DIR [--app APP]   exit 0 ok | 3 missing | 4 not a ZERO data folder | 5 newer than this app | 6 invalid
                                            | 7 partial (interrupted init: run init) | 8 incomplete (folders missing: run init)
  datadir.py init --data DIR [--app APP]    create / complete it (the parent must exist)
"""
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fscaps  # noqa: E402
import safefs  # noqa: E402

MARKER = ".zerodeck-data"
SUBDIRS = ("results", "notes", "config", "evidence", "archives", "migrations")
DEFAULT_NAME = "ZERO-DATA"
_after_subdirs_hook = None  # test seam (None in production): called after the sub-folders exist, before the marker is written


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


def _read_marker(d) -> Optional[int]:
    if d.stat_kind(MARKER) == "missing":
        return None
    with d.open_read(MARKER) as fh:
        for line in fh.read().decode("utf-8", errors="replace").splitlines():
            if line.startswith("format="):
                return int(line.split("=", 1)[1].strip())
    raise ValueError("marker file has no format= line")


def _is_interrupted_init(d, entries) -> bool:
    """True if the folder holds ONLY ZERO's own standard sub-folders (all empty) and its own empty probe leftovers."""
    if not entries:
        return False
    for e in entries:
        if e.kind != "dir" or not (e.name in SUBDIRS or e.name.startswith(fscaps.PROBE_PREFIX)):
            return False
        with d.child_dir(e.name) as sub:
            if sub.listdir():
                return False
    return True


def check(data, app_root: Optional[Path] = None) -> Tuple[str, str]:
    """Return (state, message). state: ok | missing | unmarked | partial | incomplete | newer | invalid."""
    app_root = app_root or default_app_root()
    try:
        need = required_format(app_root)
    except ValueError as exc:
        return "invalid", str(exc)
    data = safefs.abs_path(data)
    try:
        with safefs.open_dir(data) as d:
            have = _read_marker(d)
            entries = d.listdir()
            if have is None:
                if entries and _is_interrupted_init(d, entries):
                    return "partial", (f"{data} looks like an interrupted initialization (it contains only ZERO's own empty folders and no marker). "
                                       "Run: bash zero-deck.sh --init-data  - it completes the setup and deletes nothing.")
                return "unmarked", f"{data} exists but is not a ZERO data folder (no {MARKER}). Nothing will be written to it."
            if have > need:
                return "newer", f"{data} uses data format {have}; this application understands up to {need}. Update the application; do not downgrade."
            present = {e.name: e.kind for e in entries}
            missing = [s for s in SUBDIRS if present.get(s) != "dir"]
            if missing:
                return "incomplete", f"{data} is missing folders: {', '.join(missing)}. Run: bash zero-deck.sh --init-data  - it creates them; existing files are untouched."
            return "ok", f"{data} (data format {have}, application needs {need})"
    except FileNotFoundError:
        return "missing", f"Data folder does not exist: {data}. Initialize it explicitly: datadir.py init --data \"{data}\""
    except (OSError, ValueError) as exc:  # includes UnsafePathError / UnsupportedConfigurationError
        return "invalid", f"Data folder cannot be used safely: {exc}"


def _initialise(d, need: int, fresh: bool) -> Optional[Exception]:
    """Complete the setup inside the HELD folder. Returns an exception to raise AFTER cleanup, or None. Other errors propagate untouched."""
    have = _read_marker(d)
    if have is not None and have > need:
        raise ValueError(f"{d.path} uses data format {have}; this application understands up to {need}. Update the application; do not downgrade.")
    if have is None:
        report = fscaps.probe_in(d, approved=True)  # the init command IS the operator's approval of this folder for the probe
        if report.verdict != fscaps.SUPPORTED:
            return safefs.UnsupportedConfigurationError(
                f"{d.path} cannot be initialised: the filesystem does not provide the guarantees the safe-file layer needs.\n{report.text()}\n"
                + ("The folder this command created was removed again (it was empty)." if fresh else "The existing folder was left exactly as it was."))
    for sub in SUBDIRS:
        with d.child_dir(sub, create=True):
            pass
    if _after_subdirs_hook is not None:
        _after_subdirs_hook()
    if have is None:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            with d.create_file(MARKER) as nf:  # written LAST: the marker means "complete"
                nf.write(f"format={need}\ncreated={stamp}\nprobe=supported\n".encode("ascii"))
                nf.commit(0o644)
        except FileExistsError:
            pass  # another initialiser finished first: idempotent
    d.verify_bound()
    return None


def init(data, app_root: Optional[Path] = None) -> str:
    app_root = app_root or default_app_root()
    need = required_format(app_root)
    data = safefs.abs_path(data)
    failure: Optional[Exception] = None
    with safefs.open_dir(data.parent) as parent:
        kind = parent.stat_kind(data.name)
        if kind not in ("missing", "dir"):
            raise ValueError(f"{data} exists and is not a folder")
        fresh = kind == "missing"
        d = parent.child_dir(data.name, create=True)  # created only if absent; an existing folder is opened, never replaced
        try:
            entries = d.listdir()
            if _read_marker(d) is None and entries and not _is_interrupted_init(d, entries):
                raise ValueError(f"{data} already exists and is not empty but has no {MARKER}: refusing to adopt it (nothing was changed)")
            failure = _initialise(d, need, fresh)
        finally:
            d.close()
        if failure is not None:
            if fresh:
                try:
                    parent.remove_dir(data.name)  # succeeds ONLY if empty: a folder we just created and never filled
                except OSError:
                    pass
            raise failure
    state, msg = check(data, app_root)
    if state != "ok":
        raise ValueError(msg)
    return msg


_EXIT = {"ok": 0, "missing": 3, "unmarked": 4, "newer": 5, "invalid": 6, "partial": 7, "incomplete": 8}


def main(argv: Optional[List[str]] = None) -> int:
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
        return _EXIT[state]
    except safefs.UnsupportedConfigurationError as exc:
        print(f"UNSUPPORTED FILESYSTEM: {exc}", file=sys.stderr)
        return 9
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
