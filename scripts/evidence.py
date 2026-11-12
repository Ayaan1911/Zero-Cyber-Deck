#!/usr/bin/env python3
"""Hashing, manifests and chain-of-custody copies (stdlib only, Windows + Linux).

  evidence.py hash FILE...
  evidence.py verify-file FILE EXPECTED_SHA256
  evidence.py manifest DIR OUT          sha256sum-compatible manifest
  evidence.py verify MANIFEST           re-hash files listed relative to the manifest
  evidence.py acquire SRC DESTDIR --case ID --examiner NAME   verified read-only copy + custody log
Sources are only ever read.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

CHUNK = 1024 * 1024
HEX = set("0123456789abcdef")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            yield Path(dirpath) / name


def write_manifest(directory: Path, out: Path) -> int:
    if not directory.is_dir():
        raise ValueError(f"Not a directory: {directory}")
    out_abs = out.resolve()
    lines = []
    for file in iter_files(directory):
        if file.resolve() == out_abs or file.is_symlink():
            continue
        lines.append(f"{sha256_file(file)}  {file.relative_to(directory).as_posix()}")
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8", newline="\n")
    return len(lines)


def verify_manifest(manifest: Path) -> tuple[list, list, list]:
    """Return (failed, missing, extra) relative paths. Manifest paths are confined to its directory."""
    base = manifest.parent.resolve()
    listed, failed, missing = set(), [], []
    for num, raw in enumerate(manifest.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not raw.strip():
            continue
        digest, sep, rel = raw.partition("  ")
        if not sep or len(digest) != 64 or set(digest.lower()) - HEX:
            raise ValueError(f"Malformed manifest line {num}")
        target = (base / rel).resolve()
        if base not in target.parents:
            raise ValueError(f"Manifest line {num} escapes the manifest directory: {rel!r}")
        listed.add(rel)
        if not target.is_file():
            missing.append(rel)
        elif sha256_file(target) != digest.lower():
            failed.append(rel)
    extra = [f.relative_to(base).as_posix() for f in iter_files(base)
             if f.resolve() != manifest.resolve() and f.relative_to(base).as_posix() not in listed]
    return failed, missing, extra


def acquire(src: Path, dest_dir: Path, case: str, examiner: str) -> int:
    """Copy src (file or tree) into dest_dir, verifying hashes; append JSONL custody records."""
    if not src.exists():
        raise ValueError(f"Source not found: {src}")
    src, dest_dir = src.resolve(), dest_dir.resolve()
    if dest_dir == src or src in dest_dir.parents:
        raise ValueError("Destination must not be inside the source")
    dest_dir.mkdir(parents=True, exist_ok=True)
    files = [(src, Path(src.name))] if src.is_file() else [(f, Path(src.name) / f.relative_to(src)) for f in iter_files(src)]
    log = dest_dir / "custody.jsonl"
    count = 0
    for file, rel in files:
        target = dest_dir / rel
        if target.exists():
            raise ValueError(f"Refusing to overwrite existing evidence: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        before = sha256_file(file)
        shutil.copy2(file, target)
        after = sha256_file(target)
        if before != after:
            target.unlink()
            raise ValueError(f"Hash mismatch copying {file}")
        target.chmod(0o444)
        record = {"time": _now(), "case": case, "examiner": examiner, "source": str(file), "copy": str(target),
                  "sha256": after, "size": target.stat().st_size, "action": "acquire"}
        with log.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        count += 1
    return count


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hash").add_argument("files", nargs="+", type=Path)
    p = sub.add_parser("verify-file")
    p.add_argument("file", type=Path)
    p.add_argument("expected")
    p = sub.add_parser("manifest")
    p.add_argument("directory", type=Path)
    p.add_argument("out", type=Path)
    sub.add_parser("verify").add_argument("manifest", type=Path)
    p = sub.add_parser("acquire")
    p.add_argument("src", type=Path)
    p.add_argument("dest", type=Path)
    p.add_argument("--case", required=True)
    p.add_argument("--examiner", required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "hash":
            for f in args.files:
                print(f"{sha256_file(f)}  {f}")
        elif args.cmd == "verify-file":
            expected = args.expected.strip().lower()
            if len(expected) != 64 or set(expected) - HEX:
                raise ValueError("Expected value must be 64 hex characters (SHA-256)")
            actual = sha256_file(args.file)
            print(f"{'MATCH' if actual == expected else 'MISMATCH'}  {actual}  {args.file}")
            return 0 if actual == expected else 1
        elif args.cmd == "manifest":
            print(f"Wrote {write_manifest(args.directory, args.out)} entries to {args.out}")
        elif args.cmd == "verify":
            failed, missing, extra = verify_manifest(args.manifest)
            for label, items in (("FAILED", failed), ("MISSING", missing), ("EXTRA", extra)):
                for item in items:
                    print(f"{label}: {item}")
            print("VERIFIED" if not (failed or missing) else "VERIFICATION FAILED")
            return 0 if not (failed or missing) else 1
        elif args.cmd == "acquire":
            print(f"Acquired {acquire(args.src, args.dest, args.case, args.examiner)} file(s); custody log: {args.dest / 'custody.jsonl'}")
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
