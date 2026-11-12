#!/usr/bin/env python3
"""Copy operator data out of a LEGACY in-tree installation (results/, notes/, config scope files inside the application
folder) into the separate data folder. COPY ONLY: the original is never modified, moved or deleted.

  migrate_data.py --from OLD_APP_FOLDER --to DATA_FOLDER [--dry-run]

Safety: the legacy folder and the data folder are opened through safefs (whole path walked without following links, held
open), so a junction/symlink anywhere - including a parent such as `config` pointing elsewhere - is refused, not read. Every
file is read through a held directory and written exclusively, then verified by re-reading the copy through the same
open file. Existing destination files are never overwritten: identical content is skipped (re-running is safe), different
content is a CONFLICT and aborts BEFORE anything is written. Afterwards the source is re-hashed; if it changed meanwhile
(the deck was still running) the command says so and exits 3 - the copies are then valid snapshots of the earlier
state and you should re-run it. A receipt is written to <data>/migrations/.

Back up first (see SETUP.md "Back up your data before migrating"). Close the deck before migrating.
Exit codes: 0 done | 2 error/unsafe/refused | 3 source changed during migration | 4 conflicts"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import datadir  # noqa: E402
import fscaps  # noqa: E402
import safefs  # noqa: E402

_after_copy_hook = None  # test seam: called after copying, before the source is re-verified. None in production.


def _active_scope(text: str) -> bool:
    return any(line.partition("#")[0].strip() for line in text.splitlines())


def _read_all(parent, name: str) -> bytes:
    with parent.open_read(name) as fh:
        return fh.read()


def plan(old_root):
    """List (dest_relative, source_parts, sha256, size) from a HELD legacy app folder. Raises on links anywhere."""
    items = []
    for top in ("results", "notes"):
        kind = old_root.stat_kind(top)
        if kind == "missing":
            continue
        if kind != "dir":
            raise safefs.UnsafePathError(f"{top} is a {kind}, not a plain folder: refusing to migrate")
        with old_root.child_dir(top) as d:
            for rel, parent, name, _k in safefs.walk_files(d, links="error"):
                if rel == "README.md":
                    continue  # release placeholder, not user data
                data = _read_all(parent, name)
                items.append((f"{top}/{rel}", [top] + rel.split("/"), hashlib.sha256(data).hexdigest(), len(data)))
    kind = old_root.stat_kind("config")
    if kind not in ("missing", "dir"):
        raise safefs.UnsafePathError(f"config is a {kind}, not a plain folder: refusing to migrate")
    if kind == "dir":
        with old_root.child_dir("config") as cfg:  # a junction named `config` is refused HERE, not read
            for name, dest in (("scope.local.txt", "config/scope.local.txt"), ("scope.txt", "config/legacy-scope.txt")):
                k = cfg.stat_kind(name)
                if k == "missing":
                    continue
                if k != "file":
                    raise safefs.UnsafePathError(f"config/{name} is a {k}: refusing to migrate")
                data = _read_all(cfg, name)
                if name == "scope.txt" and not _active_scope(data.decode("utf-8", errors="replace")):
                    continue  # the untouched release template: nothing of the operator's
                items.append((dest, ["config", name], hashlib.sha256(data).hexdigest(), len(data)))
    return items


def _open_source_file(old_root, parts):
    return safefs.open_relative_file(old_root, "/".join(parts))


def _dest_hash(data_root, dest_rel: str):
    """sha256 of an existing destination file, or None if absent. Refuses links."""
    try:
        with safefs.open_relative_file(data_root, dest_rel) as fh:
            return safefs.hash_stream(fh)
    except (FileNotFoundError, NotADirectoryError):
        return None


def migrate(old_app, data_dir, dry_run: bool = False, app_root=None):
    old_app, data_dir = safefs.abs_path(old_app), safefs.abs_path(data_dir)
    state, msg = datadir.check(data_dir, app_root)
    dry_missing = False  # a dry run against a data folder that does not exist yet creates nothing
    if state == "missing":
        if dry_run:
            dry_missing = True
        else:
            datadir.init(data_dir, app_root)
    elif state != "ok":
        raise ValueError(msg)
    summary = {"copied": [], "skipped": [], "conflicts": []}
    if not dry_run and not dry_missing:
        fscaps.require_publish_at(data_dir)  # refuse before reading the legacy folder if the data folder's filesystem cannot publish safely
    with safefs.open_dir(old_app) as old_root:
        items = plan(old_root)
        if dry_missing:  # everything would be copied
            summary["copied"] = [i[0] for i in items]
            return summary, 0
        with safefs.open_dir(data_dir) as data_root:
            for dest, _parts, digest, _size in items:
                existing = _dest_hash(data_root, dest)
                if existing is None:
                    continue
                (summary["skipped"] if existing == digest else summary["conflicts"]).append(dest)
            if summary["conflicts"]:
                return summary, 4
            if dry_run:
                summary["copied"] = [i[0] for i in items if i[0] not in summary["skipped"]]
                return summary, 0
            for dest, parts, digest, _size in items:
                if dest in summary["skipped"]:
                    continue
                dest_parts = dest.split("/")
                stack, cur = [], data_root
                try:
                    for p in dest_parts[:-1]:
                        cur = cur.child_dir(p, create=True)
                        stack.append(cur)
                    with _open_source_file(old_root, parts) as reader:
                        with cur.create_file(dest_parts[-1]) as nf:
                            for block in iter(lambda: reader.read(safefs.CHUNK), b""):
                                nf.write(block)
                            if nf.hash_back() != digest:
                                raise ValueError(f"The source changed while copying {dest}; re-run after closing the deck")
                            nf.commit(0o600)
                finally:
                    for d in reversed(stack):
                        d.close()
                summary["copied"].append(dest)
            if _after_copy_hook:
                _after_copy_hook()
            changed = []
            now = {i[0]: i[2] for i in plan(old_root)}
            for dest, _p, digest, _s in items:
                if now.get(dest) != digest:
                    changed.append(dest)
            changed += [d for d in now if d not in {i[0] for i in items}]
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            receipt = {"time": stamp, "from": str(old_app), "to": str(data_dir), "copied": summary["copied"], "skipped_identical": summary["skipped"],
                       "files": {i[0]: {"sha256": i[2], "size": i[3]} for i in items}, "source_changed_during_migration": changed}
            with data_root.child_dir("migrations", create=True) as md:
                for n in range(1000):
                    name = f"{stamp}-{re.sub(r'[^A-Za-z0-9._-]', '_', old_app.name)}{'' if n == 0 else '_' + str(n)}.json"
                    try:
                        with md.create_file(name) as nf:
                            nf.write(json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8"))
                            nf.commit(0o600)
                        break
                    except FileExistsError:
                        continue
            data_root.verify_bound()
            summary["changed"] = changed
            return summary, (3 if changed else 0)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--from", dest="old", type=Path, required=True)
    parser.add_argument("--to", dest="data", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        summary, code = migrate(args.old, args.data, args.dry_run)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    verb = "would copy" if args.dry_run else "copied"
    print(f"{verb} {len(summary['copied'])} file(s); {len(summary['skipped'])} already present and identical; {len(summary['conflicts'])} conflict(s)")
    for name in summary["conflicts"]:
        print(f"CONFLICT (different content already in the data folder, nothing was written): {name}", file=sys.stderr)
    for name in summary.get("changed", []):
        print(f"SOURCE CHANGED DURING MIGRATION: {name}  (re-run after closing the deck)", file=sys.stderr)
    print("The original folder was not modified. Verify, then keep it as your backup.")
    return code


if __name__ == "__main__":
    sys.exit(main())
