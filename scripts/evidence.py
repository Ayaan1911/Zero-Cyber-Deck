#!/usr/bin/env python3
"""Hashing, manifests and chain-of-custody copies (stdlib only, Windows + Linux, Python 3.8+).

  evidence.py hash FILE...
  evidence.py verify-file FILE EXPECTED_SHA256
  evidence.py manifest DIR OUT          sha256sum-compatible; refuses to overwrite OUT; refuses links/junctions
  evidence.py verify MANIFEST [--allow-extra]   fails on changed, missing AND unlisted files
  evidence.py acquire SRC DESTDIR --case ID --examiner NAME   verified read-only copy + custody log
Sources are only read. A link, junction or reparse point ANYWHERE in an input or output path (including ancestor
folders) is rejected, never followed. Outputs are created exclusively and never overwritten.
The custody log and manifests are plain files: they document, but do not prevent, tampering.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pathsafe import (  # noqa: E402
    abs_path, append_text, assert_no_links_in_chain, create_new_file, is_link, make_dirs, reject_links_under,
)

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


def iter_files(root: Path, links: str = "error"):
    """Yield files under root, never following links. links='error' raises on any link/junction;
    links='include' yields the link itself (not descended) so callers can report it."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        keep = []
        for name in dirnames:
            full = Path(dirpath) / name
            if is_link(full):
                if links == "error":
                    raise ValueError(f"Refusing link/junction inside the tree: {full}")
                yield full
            else:
                keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if links == "error" and is_link(full):
                raise ValueError(f"Refusing link inside the tree: {full}")
            yield full


def write_manifest(directory: Path, out: Path) -> int:
    directory = assert_no_links_in_chain(directory)
    if not directory.is_dir():
        raise ValueError(f"Not a plain directory: {directory}")
    if os.path.lexists(out):
        raise ValueError(f"Manifest already exists, not overwriting: {out}")
    lines = [f"{sha256_file(f)}  {f.relative_to(directory).as_posix()}" for f in iter_files(directory)]
    with create_new_file(out) as fh:  # exclusive create, ancestors validated, no write-through
        fh.write(("\n".join(lines) + ("\n" if lines else "")).encode("utf-8"))
    return len(lines)


def verify_manifest(manifest: Path):
    """Return (failed, missing, extra) relative paths. Entries are confined to the manifest directory and
    may not pass through links; anything on disk that the manifest does not list is reported as extra."""
    manifest = assert_no_links_in_chain(manifest)
    if is_link(manifest):
        raise ValueError(f"Manifest is a link: {manifest}")
    base = manifest.parent
    listed, failed, missing = set(), [], []
    for num, raw in enumerate(manifest.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not raw.strip():
            continue
        digest, sep, rel = raw.partition("  ")
        if not sep or len(digest) != 64 or set(digest.lower()) - HEX:
            raise ValueError(f"Malformed manifest line {num}")
        target = abs_path(base / rel)
        if base not in target.parents:
            raise ValueError(f"Manifest line {num} escapes the manifest directory: {rel!r}")
        reject_links_under(base, rel)
        listed.add(rel)
        if not target.is_file():
            missing.append(rel)
        elif sha256_file(target) != digest.lower():
            failed.append(rel)
    extra = [f.relative_to(base).as_posix() for f in iter_files(base, links="include")
             if f != manifest and f.relative_to(base).as_posix() not in listed]
    return failed, missing, extra


def acquire(src: Path, dest_dir: Path, case: str, examiner: str) -> int:
    """Copy src (file or tree) into dest_dir, verifying hashes; append JSONL custody records.
    Rejects links anywhere in the source path/tree and anywhere in the destination path; never overwrites."""
    if not os.path.lexists(src):
        raise ValueError(f"Source not found: {src}")
    src = assert_no_links_in_chain(src)          # includes ANCESTOR folders, not only the leaf
    dest_dir = assert_no_links_in_chain(dest_dir)  # lexical absolute path; nothing is resolved through links
    if dest_dir == src or src in dest_dir.parents:
        raise ValueError("Destination must not be inside the source")
    files = [(src, Path(src.name))] if src.is_file() else [(f, Path(src.name) / f.relative_to(src)) for f in iter_files(src)]
    make_dirs(dest_dir)
    log = dest_dir / "custody.jsonl"
    if is_link(log):
        raise ValueError(f"Custody log is a link, refusing: {log}")
    count = 0
    for file, rel in files:
        target = dest_dir / rel
        if os.path.lexists(target):
            raise ValueError(f"Refusing to overwrite existing evidence: {target}")
        digest = hashlib.sha256()
        created = False
        try:
            with file.open("rb") as reader, create_new_file(target) as writer:  # exclusive; every ancestor validated
                created = True
                for block in iter(lambda: reader.read(CHUNK), b""):
                    digest.update(block)
                    writer.write(block)
            shutil.copystat(file, target)
            after = sha256_file(target)
            if digest.hexdigest() != after:
                raise ValueError(f"Hash mismatch copying {file}")
        except Exception:
            if created and os.path.lexists(target) and not is_link(target):
                target.unlink()  # only the partial copy WE just created
            raise
        target.chmod(0o444)
        record = {"time": _now(), "case": case, "examiner": examiner, "source": str(file), "copy": str(target),
                  "sha256": after, "size": target.stat().st_size, "action": "acquire"}
        append_text(log, json.dumps(record, sort_keys=True) + "\n")
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
    p = sub.add_parser("verify")
    p.add_argument("manifest", type=Path)
    p.add_argument("--allow-extra", action="store_true", help="do not fail on files the manifest does not list")
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
            for label, items in (("FAILED", failed), ("MISSING", missing), ("UNLISTED", extra)):
                for item in items:
                    print(f"{label}: {item}")
            bad = bool(failed or missing or (extra and not args.allow_extra))
            print("VERIFICATION FAILED" if bad else "VERIFIED")
            return 1 if bad else 0
        elif args.cmd == "acquire":
            print(f"Acquired {acquire(args.src, args.dest, args.case, args.examiner)} file(s); custody log: {args.dest / 'custody.jsonl'}")
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
