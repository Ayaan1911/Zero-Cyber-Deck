#!/usr/bin/env python3
"""Hashing, manifests and chain-of-custody copies (stdlib only, Windows + Linux, Python 3.8+).

  evidence.py hash FILE...
  evidence.py verify-file FILE EXPECTED_SHA256
  evidence.py manifest DIR OUT          sha256sum-compatible; refuses to overwrite OUT; refuses links/junctions
  evidence.py verify MANIFEST [--allow-extra]   fails on changed, missing AND unlisted files
  evidence.py acquire SRC DESTDIR --case ID --examiner NAME   verified read-only copy + custody log

SAFETY MODEL (see scripts/safefs.py): every source and destination directory is opened ONCE by walking its whole path
without following links, and held open; every later operation (list, read, create, append) is relative to those held
directories. Nothing is validated by name and then re-opened by name, so a link/junction/rename introduced after
validation cannot redirect a read or a write. New evidence files are created exclusively, verified by re-reading through
the same open file, and never replace an existing name. Cleanup of a failed copy removes only the object we created.
Where the platform/volume cannot provide this (UNC/remote paths, non-canonical paths, macOS) the command REFUSES.
Manifests, custody logs and reports are plain files: they document, but do not prevent, tampering.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safefs  # noqa: E402
from safefs import abs_path, sha256_file  # noqa: E402,F401  (sha256_file re-exported for callers/tests)

HEX = set("0123456789abcdef")

# Test seam (None in production): called as _race_hook(stage, **context) at the points where a race could be attempted.
_race_hook = None


def _race(stage: str, **context) -> None:
    if _race_hook is not None:
        _race_hook(stage, **context)


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _not_found(exc: Exception, what: str) -> ValueError:
    return ValueError(f"{what} not found: {exc}")


def write_manifest(directory, out) -> int:
    """Hash every file under `directory` (links are refused) and write a NEW manifest at `out` (never overwrites)."""
    directory, out = abs_path(directory), abs_path(out)
    lines = []
    try:
        with safefs.open_dir(directory) as root:
            for rel, parent, name, _kind in safefs.walk_files(root, links="error"):
                with parent.open_read(name) as fh:
                    lines.append(f"{safefs.hash_stream(fh)}  {rel}")
    except FileNotFoundError as exc:
        raise ValueError(f"Not a plain directory: {directory} ({exc})") from None
    try:
        with safefs.open_dir(out.parent) as odir:
            try:
                with odir.create_file(out.name) as nf:  # exclusive: an existing name (file OR link) is refused
                    nf.write(("\n".join(lines) + ("\n" if lines else "")).encode("utf-8"))
                    nf.commit(0o644)
            except FileExistsError:
                raise ValueError(f"Manifest already exists, not overwriting: {out}") from None
            odir.verify_bound()
    except FileNotFoundError as exc:
        raise ValueError(f"Output folder not found: {exc}") from None
    return len(lines)


def verify_manifest(manifest):
    """Return (failed, missing, extra) relative paths. Entries are confined to the manifest directory, are opened
    through held directories (so no link on the way is followed), and anything on disk that the manifest does not
    list - including links - is reported as extra."""
    manifest = abs_path(manifest)
    try:
        base_cm = safefs.open_dir(manifest.parent)
    except FileNotFoundError as exc:
        raise _not_found(exc, "Manifest folder") from None
    with base_cm as base:
        try:
            with base.open_read(manifest.name) as fh:
                text = fh.read().decode("utf-8-sig")
        except FileNotFoundError as exc:
            raise _not_found(exc, "Manifest") from None
        listed, failed, missing = set(), [], []
        for num, raw in enumerate(text.splitlines(), 1):
            if not raw.strip():
                continue
            digest, sep, rel = raw.partition("  ")
            if not sep or len(digest) != 64 or set(digest.lower()) - HEX:
                raise ValueError(f"Malformed manifest line {num}")
            try:
                safefs.split_relative(rel)  # rejects '..', absolute paths, ':' / device names on Windows
            except safefs.UnsafePathError as exc:
                raise ValueError(f"Manifest line {num} is not a safe relative path: {exc}") from None
            listed.add(rel)
            try:
                with safefs.open_relative_file(base, rel) as fh:
                    if safefs.hash_stream(fh) != digest.lower():
                        failed.append(rel)
            except (FileNotFoundError, NotADirectoryError):
                missing.append(rel)
        extra = [rel for rel, _p, _n, _k in safefs.walk_files(base, links="include") if rel != manifest.name and rel not in listed]
        return failed, missing, extra


class _Counter:
    def __init__(self):
        self.n = 0


def _copy_one(src_dir, name: str, dst_dir, log_dir, src_text: str, dst_text: str, case: str, examiner: str, counter: _Counter) -> None:
    with src_dir.open_read(name) as reader:
        mtime_ns = getattr(src_dir, "last_mtime_ns", None)
        _race("after-open-source", src_dir=src_dir, name=name)
        try:
            nf = dst_dir.create_file(name)  # exclusive; an existing name (even a link) -> FileExistsError
        except FileExistsError:
            raise ValueError(f"Refusing to overwrite existing evidence: {dst_text}") from None
        with nf:
            _race("after-create-dest", dst_dir=dst_dir, new_file=nf, name=name)
            digest = hashlib.sha256()
            size = 0
            for block in iter(lambda: reader.read(safefs.CHUNK), b""):
                digest.update(block)
                nf.write(block)
                size += len(block)
            if nf.hash_back() != digest.hexdigest():  # read back through the SAME open file, never by name
                raise ValueError(f"Hash mismatch while copying {src_text}")
            if mtime_ns is not None:
                nf.set_mtime_ns(mtime_ns)
            _race("before-commit", dst_dir=dst_dir, new_file=nf, name=name)
            try:
                nf.commit(0o444)  # POSIX detects a name collision here (link() never replaces); Windows already did at create time
            except FileExistsError:
                raise ValueError(f"Refusing to overwrite existing evidence: {dst_text}") from None
    record = {"time": _now(), "case": case, "examiner": examiner, "source": src_text, "copy": dst_text,
              "sha256": digest.hexdigest(), "size": size, "action": "acquire"}
    with log_dir.open_append("custody.jsonl") as log:
        log.write((json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
    counter.n += 1


def _copy_tree(sdir, ddir, log_dir, src_prefix: str, dst_prefix: str, case: str, examiner: str, counter: _Counter) -> None:
    for entry in sdir.listdir():
        if entry.kind in ("link", "other"):
            raise safefs.UnsafePathError(f"Refusing a link/special file inside the evidence tree: {src_prefix}/{entry.name}")
        if entry.kind == "dir":
            with sdir.child_dir(entry.name) as s2, ddir.child_dir(entry.name, create=True) as d2:
                _copy_tree(s2, d2, log_dir, f"{src_prefix}/{entry.name}", f"{dst_prefix}/{entry.name}", case, examiner, counter)
        else:
            _copy_one(sdir, entry.name, ddir, log_dir, f"{src_prefix}/{entry.name}", f"{dst_prefix}/{entry.name}", case, examiner, counter)


def acquire(src, dest_dir, case: str, examiner: str) -> int:
    """Copy `src` (file or tree) into `dest_dir`, verifying hashes; append JSONL custody records.

    Pass 1 only validates (early, cheap refusal). Pass 2 is the authoritative copy and runs entirely on held
    directories, so a link or rename introduced between the passes cannot redirect anything. Sources are only read.
    Existing evidence is never overwritten; completed copies are kept if a later file fails."""
    src_abs, dest_abs = abs_path(src), abs_path(dest_dir)
    if dest_abs == src_abs or src_abs in dest_abs.parents:
        raise ValueError("Destination must not be inside the source")
    try:
        sp = safefs.open_dir(src_abs.parent)
    except FileNotFoundError as exc:
        raise _not_found(exc, "Source") from None
    with sp:
        kind = sp.stat_kind(src_abs.name)
        if kind == "missing":
            raise ValueError(f"Source not found: {src_abs}")
        if kind in ("link", "other"):
            raise safefs.UnsafePathError(f"Source is a link/junction or special file, refusing: {src_abs}")
        if kind == "dir":  # pass 1: advisory, nothing is copied
            with sp.child_dir(src_abs.name) as probe:
                for _ in safefs.walk_files(probe, links="error"):
                    pass
        _race("between-passes", src_parent=sp, src_abs=src_abs)  # pass 1 handles are released here; pass 2 must not trust pass 1
        counter = _Counter()
        with safefs.open_dir(dest_abs, create=True) as droot:
            if kind == "file":
                _copy_one(sp, src_abs.name, droot, droot, str(src_abs), str(dest_abs / src_abs.name), case, examiner, counter)
            else:
                with sp.child_dir(src_abs.name) as s_top, droot.child_dir(src_abs.name, create=True) as d_top:
                    _copy_tree(s_top, d_top, droot, str(src_abs), str(dest_abs / src_abs.name), case, examiner, counter)
            droot.verify_bound()  # fail loudly if the destination was swapped while we worked
    return counter.n


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
            print(f"Acquired {acquire(args.src, args.dest, args.case, args.examiner)} file(s); custody log: {abs_path(args.dest) / 'custody.jsonl'}")
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
