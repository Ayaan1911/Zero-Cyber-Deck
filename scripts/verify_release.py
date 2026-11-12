#!/usr/bin/env python3
"""Verify an application folder against its UNMODIFIED release manifest (SHA256SUMS.txt), exactly.

The release manifest describes the release only. It deliberately knows nothing about operator data, scope files or
results (those live in ZERO-DATA and have their own inventories), so a correct installation always verifies.

  verify_release.py [--app DIR] [--allow-extra]    exit 0 verified | 1 differences | 2 error
Files are opened through safefs (no link is followed). Extra files fail verification unless --allow-extra
(a developer checkout has .git/ and caches; an installed deployment must have none).
Checksums prove CONSISTENCY with the list, not AUTHENTICITY: whoever can change a file can regenerate the list."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safefs  # noqa: E402

MANIFEST = "SHA256SUMS.txt"
LINE = re.compile(r"([0-9a-f]{64}) [ *](.+)")


def parse_manifest(text: str):
    entries = {}
    for num, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        m = LINE.fullmatch(raw)
        if not m:
            raise ValueError(f"{MANIFEST} line {num} is malformed")
        digest, rel = m.group(1), m.group(2)
        safefs.split_relative(rel, portable=True)  # a release must install on Windows too: strictest rules on every OS
        if rel in entries:
            raise ValueError(f"{MANIFEST} lists {rel} twice")
        entries[rel] = digest
    return entries


def verify(app_root, allow_extra: bool = False):
    """Return (failed, missing, extra)."""
    with safefs.open_dir(app_root) as root:
        with root.open_read(MANIFEST) as fh:
            entries = parse_manifest(fh.read().decode("utf-8-sig"))
        failed, missing = [], []
        for rel, digest in sorted(entries.items()):
            try:
                with safefs.open_relative_file(root, rel) as fh:
                    if safefs.hash_stream(fh) != digest:
                        failed.append(rel)
            except (FileNotFoundError, NotADirectoryError):
                missing.append(rel)
        extra = [] if allow_extra else [rel for rel, _p, _n, _k in safefs.walk_files(root, links="include") if rel not in entries and rel != MANIFEST]
        return failed, missing, extra


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--app", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--allow-extra", action="store_true")
    args = parser.parse_args(argv)
    try:
        failed, missing, extra = verify(args.app, args.allow_extra)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    for label, items in (("CHANGED", failed), ("MISSING", missing), ("UNLISTED", extra)):
        for item in items:
            print(f"{label}: {item}")
    bad = bool(failed or missing or extra)
    print("RELEASE DIFFERS FROM MANIFEST" if bad else "RELEASE VERIFIED (consistent with SHA256SUMS.txt; not an authenticity proof)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
