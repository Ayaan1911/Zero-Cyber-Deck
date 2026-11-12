#!/usr/bin/env python3
"""Filesystem capability checks for the safe-file layer (scripts/safefs.py). Stdlib only, Python 3.8+.

The safe-file design depends on filesystem behaviour that not every filesystem provides (exFAT/FAT32 have no hard
links, no permissions, unstable inode numbers ...). Filesystem NAMES are never trusted: every property is exercised.

  fscaps.py probe    --dir DIR --approve-disposable-dir [--json]   full probe inside a throw-away sub-folder of DIR
  fscaps.py rehearse --dir DIR                                    the exact publish sequence on one zero-byte file

Each check reports one of
  supported    the guarantee was demonstrated here
  unsupported  the guarantee is demonstrably missing here
  unverified   it could not be established (read-only mount, I/O error, ...) and is therefore NOT assumed
and every check is either REQUIRED by the safe-file implementation or INFORMATIONAL (a warning for the operator).
Verdict: SUPPORTED only if every required check is supported; otherwise the location is refused (fail closed).

PROBE SAFETY: the probe writes and removes files, so it runs only when the caller passes approved=True / --approve-disposable-dir for a
folder the operator declared disposable. It works exclusively inside one sub-folder it creates itself (.zdprobe-<random>),
through the held-directory primitives (nothing is followed or opened by name), and removes ONLY the entries it created.
Anything else it finds there is left in place and reported - unknown data is never deleted. A rehearsal is not a probe: it is the
publish step the real operation is about to perform, with a zero-byte file, in the folder the operator already chose for it.

Exit codes: 0 supported | 3 unsupported | 4 unverified | 2 error / not approved
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Callable, List, NamedTuple, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safefs  # noqa: E402

SUPPORTED, UNSUPPORTED, UNVERIFIED = "supported", "unsupported", "unverified"
WIN = sys.platform == "win32"
PROBE_PREFIX = ".zdprobe-"
REHEARSE_PREFIX = ".zdrehearse-"

# Test seams (None in production).
_after_probe_hook = None      # called as hook(probe_dir, report) after the checks, before cleanup
_ident_name_override = None   # replaces "identity by name" to simulate filesystems with unstable inode numbers


class Check(NamedTuple):
    name: str
    required: bool
    status: str
    detail: str


class Report:
    def __init__(self, location: str):
        self.location = location
        self.checks: List[Check] = []
        self.notes: List[str] = []

    def add(self, name: str, required: bool, status: str, detail: str) -> None:
        self.checks.append(Check(name, required, status, detail))

    @property
    def verdict(self) -> str:
        required = [c.status for c in self.checks if c.required]
        if not required or UNSUPPORTED in required:
            return UNSUPPORTED if UNSUPPORTED in required else UNVERIFIED
        return UNVERIFIED if UNVERIFIED in required else SUPPORTED

    def text(self) -> str:
        lines = [f"Filesystem capability probe: {self.location}"]
        for c in self.checks:
            lines.append(f"  [{c.status:<11}] {'REQUIRED     ' if c.required else 'informational'} {c.name}: {c.detail}")
        for n in self.notes:
            lines.append(f"  note: {n}")
        v = self.verdict
        lines.append(f"VERDICT: {v.upper()}")
        if v == UNSUPPORTED:
            lines.append("Fail closed: evidence, manifests, reports and migration must not be placed here. Use ext4, XFS, btrfs or NTFS (SETUP.md 'Storage layout').")
        elif v == UNVERIFIED:
            lines.append("The required guarantees could not be established here, so they are not assumed: treated as unsupported (see the 'unverified' lines).")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {"location": self.location, "verdict": self.verdict, "notes": self.notes,
                "checks": [c._asdict() for c in self.checks]}


# ---------------------------------------------------------------------------------------------------------------------
# POSIX checks: each exercises the real *at() primitive the safe-file layer uses, relative to the held probe folder
# ---------------------------------------------------------------------------------------------------------------------
_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)) if not WIN else 0
_NO_SYMLINK_ERRNOS = {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS} if not WIN else set()


def _errname(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno, str(exc.errno))


def _ident_name(fd: int, name: str) -> Tuple[int, int]:
    if _ident_name_override is not None:
        return _ident_name_override(fd, name)
    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    return (st.st_dev, st.st_ino)


def _p_dir_relative(pd, created) -> Tuple[str, str]:
    fd = pd.fd
    os.mkdir("sub", 0o700, dir_fd=fd)
    created.append(("dir", "sub"))
    sfd = os.open("sub", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        inner = os.open("inner", _CREATE, 0o600, dir_fd=sfd)
        os.close(inner)
        os.unlink("inner", dir_fd=sfd)
    finally:
        os.close(sfd)
    os.rmdir("sub", dir_fd=fd)
    created.remove(("dir", "sub"))
    return SUPPORTED, "mkdirat / openat(O_NOFOLLOW|O_DIRECTORY) / unlinkat / rmdir work relative to a held directory"


def _p_exclusive(pd, created) -> Tuple[str, str]:
    fd = pd.fd
    os.close(os.open("excl", _CREATE, 0o600, dir_fd=fd))
    created.append(("file", "excl"))
    try:
        os.close(os.open("excl", _CREATE, 0o600, dir_fd=fd))
    except FileExistsError:
        return SUPPORTED, "a second exclusive create of an existing name is refused (O_EXCL)"
    return UNSUPPORTED, "exclusive create did NOT refuse an existing name"


def _p_hardlink(pd, created) -> Tuple[str, str]:
    fd = pd.fd
    a = os.open("src", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    created.append(("file", "src"))
    try:
        os.write(a, b"zd-probe")
        try:
            os.link("src", "pub", src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            created.append(("file", "pub"))
        except FileExistsError:
            raise
        except OSError as exc:
            if exc.errno in safefs.NO_HARDLINK_ERRNOS:
                return UNSUPPORTED, f"link() is refused ({_errname(exc)}): this filesystem has no hard links, which atomic publication requires"
            raise
        st_a, st_p = os.fstat(a), os.stat("pub", dir_fd=fd, follow_symlinks=False)
        if (st_a.st_dev, st_a.st_ino) != (st_p.st_dev, st_p.st_ino) or st_a.st_nlink < 2:
            return UNSUPPORTED, "link() reported success but did not create a second name for the same file"
        os.close(os.open("other", _CREATE, 0o600, dir_fd=fd))
        created.append(("file", "other"))
        with os.fdopen(os.open("other", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=fd), "wb") as fh:
            fh.write(b"KEEP")
        try:
            os.link("src", "other", src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        except FileExistsError:
            pass
        else:
            return UNSUPPORTED, "link() REPLACED an existing name (publication could overwrite evidence)"
        rd = os.open("other", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            if os.read(rd, 16) != b"KEEP":
                return UNSUPPORTED, "an existing file changed during a refused link()"
        finally:
            os.close(rd)
        return SUPPORTED, "link() makes a second name for the same file and never replaces an existing name"
    finally:
        os.close(a)


def _p_nofollow(pd, created) -> Tuple[str, str]:
    fd = pd.fd
    try:
        os.symlink("zd-nonexistent-target", "lnk", dir_fd=fd)
        created.append(("file", "lnk"))
    except OSError as exc:
        if exc.errno in _NO_SYMLINK_ERRNOS:
            return SUPPORTED, f"this filesystem cannot contain symbolic links ({_errname(exc)}): there is nothing to follow"
        raise
    try:
        os.close(os.open("lnk", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd))
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return SUPPORTED, "O_NOFOLLOW refuses a symbolic link (ELOOP)"
        raise
    return UNSUPPORTED, "O_NOFOLLOW opened a symbolic link"


def _p_identity(pd, created) -> Tuple[str, str]:
    fd = pd.fd
    a = os.open("ident", _CREATE, 0o600, dir_fd=fd)
    created.append(("file", "ident"))
    try:
        st = os.fstat(a)
        by_fd, by_name = (st.st_dev, st.st_ino), _ident_name(fd, "ident")
        pd.verify_bound()
    finally:
        os.close(a)
    if by_fd != by_name:
        return UNSUPPORTED, "while a file is open, its identity through the descriptor and through its name differ: identity checks cannot be trusted"
    return SUPPORTED, "descriptor and name agree on identity while the file is held; the held directory is still the one at its path"


def _p_ident_after_close(pd, created) -> Tuple[str, str]:
    fd = pd.fd
    a = os.open("ident2", _CREATE, 0o600, dir_fd=fd)
    created.append(("file", "ident2"))
    st = os.fstat(a)
    before = (st.st_dev, st.st_ino)
    os.close(a)
    if _ident_name(fd, "ident2") != before:
        return UNSUPPORTED, "the inode number changed after the file was closed (typical for exFAT): this implementation unlinks BEFORE closing for that reason"
    return UNVERIFIED, "unchanged after close, but cache eviction cannot be forced non-destructively; this implementation does not rely on it"


def _p_case(pd, created) -> Tuple[str, str]:
    fd = pd.fd
    os.close(os.open("ZdCase", _CREATE, 0o600, dir_fd=fd))
    created.append(("file", "ZdCase"))
    if pd.stat_kind("zdcase") != "missing":
        return UNSUPPORTED, "case-INsensitive: names that differ only by case collide (an evidence tree with such names aborts the copy)"
    return SUPPORTED, "case-sensitive names"


def _p_permissions(pd, created) -> Tuple[str, str]:
    fd = pd.fd
    a = os.open("perm", _CREATE, 0o600, dir_fd=fd)
    created.append(("file", "perm"))
    try:
        try:
            os.fchmod(a, 0o444)
        except OSError as exc:
            return UNSUPPORTED, f"chmod is rejected ({_errname(exc)}): read-only marking is not available"
        if os.fstat(a).st_mode & 0o222:
            return UNSUPPORTED, "permission bits are not enforced (typical for exFAT/FAT and NTFS mounts without permissions): a 0o444 evidence copy is NOT protected and every local user can read and change everything here"
    finally:
        os.close(a)
    return SUPPORTED, "permission bits are honoured"


# ---------------------------------------------------------------------------------------------------------------------
# Windows checks: the same properties expressed through the handle-based implementation
# ---------------------------------------------------------------------------------------------------------------------
def _w_held_dir(pd, created) -> Tuple[str, str]:
    moved = pd.path + "_zdrn"
    try:
        os.rename(pd.path, moved)
    except OSError as exc:
        if isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in (5, 32):
            return SUPPORTED, "a held directory cannot be renamed or replaced by another party (sharing violation): swaps are blocked on this volume"
        raise
    try:
        os.rename(moved, pd.path)  # protection absent: put it back immediately
    except OSError:
        pass
    return UNSUPPORTED, "a held directory WAS renamed while held: link-swap protection does not work on this volume"


def _w_exclusive(pd, created) -> Tuple[str, str]:
    nf = pd.create_file("excl")
    nf.write(b"x")
    nf.commit(0o600)
    created.append(("file", "excl"))
    try:
        again = pd.create_file("excl")
    except FileExistsError:
        return SUPPORTED, "CREATE_NEW refuses an existing name"
    again.discard()
    return UNSUPPORTED, "exclusive create did NOT refuse an existing name"


def _w_discard(pd, created) -> Tuple[str, str]:
    nf = pd.create_file("tmp")
    nf.write(b"x")
    nf.discard()
    if pd.stat_kind("tmp") == "missing":
        return SUPPORTED, "delete-on-close removes exactly the file we created when it is discarded"
    created.append(("file", "tmp"))
    return UNSUPPORTED, "a discarded file was NOT removed"


def _w_commit(pd, created) -> Tuple[str, str]:
    nf = pd.create_file("ok")
    nf.write(b"hello")
    digest = nf.hash_back()
    nf.commit(0o600)
    created.append(("file", "ok"))
    with pd.open_read("ok") as fh:
        if safefs.hash_stream(fh) != digest:
            return UNSUPPORTED, "a committed file does not read back identically"
    return SUPPORTED, "a committed file persists and reads back identically through a held directory"


def _w_identity(pd, created) -> Tuple[str, str]:
    pd.verify_bound()
    return SUPPORTED, "the held directory's real path equals the requested path"


def _w_case(pd, created) -> Tuple[str, str]:
    nf = pd.create_file("ZdCase")
    nf.commit(0o600)
    created.append(("file", "ZdCase"))
    if pd.stat_kind("zdcase") != "missing":
        return UNSUPPORTED, "case-INsensitive: names that differ only by case collide (an evidence tree with such names aborts the copy)"
    return SUPPORTED, "case-sensitive names"


def _w_readonly(pd, created) -> Tuple[str, str]:
    nf = pd.create_file("ro")
    nf.commit(0o444)
    created.append(("file", "ro"))
    import stat as stat_mod
    if os.stat(os.path.join(pd.path, "ro")).st_mode & stat_mod.S_IWRITE:
        return UNSUPPORTED, "the read-only attribute could not be set"
    # the read-only attribute must be cleared before the probe can remove its own file
    os.chmod(os.path.join(pd.path, "ro"), 0o600)
    return SUPPORTED, "the read-only attribute is honoured"


def _durability(pd, created) -> Tuple[str, str]:
    return UNVERIFIED, "power-loss durability cannot be verified without destroying data; exFAT/FAT have no journal, so a pulled stick can leave partial files"


def _na(msg: str) -> Callable:
    return lambda pd, created: (SUPPORTED, msg)


def _checks() -> List[Tuple[str, bool, Callable]]:
    if WIN:
        return [("held_directory_blocks_swap", True, _w_held_dir), ("exclusive_create", True, _w_exclusive),
                ("discard_removes_only_our_file", True, _w_discard), ("commit_persists", True, _w_commit),
                ("path_identity", True, _w_identity),
                ("hardlink_publish", False, _na("not used on Windows: files are created with CREATE_NEW and published in place")),
                ("case_sensitivity", False, _w_case), ("read_only_marking", False, _w_readonly), ("power_loss_durability", False, _durability)]
    return [("dir_relative_operations", True, _p_dir_relative), ("exclusive_create", True, _p_exclusive),
            ("hardlink_publish", True, _p_hardlink), ("nofollow", True, _p_nofollow), ("path_identity", True, _p_identity),
            ("identity_after_close", False, _p_ident_after_close), ("case_sensitivity", False, _p_case),
            ("permission_bits", False, _p_permissions), ("power_loss_durability", False, _durability)]


def _cleanup(parent, pd, name: str, created: list, report: Report) -> None:
    """Remove ONLY what the probe created (flat entries inside its own exclusive folder). Never follows, never descends."""
    for kind, entry in reversed(created):
        try:
            if pd.stat_kind(entry) != "missing":
                (pd.remove_dir if kind == "dir" else pd.remove_file)(entry)
        except OSError as exc:
            report.notes.append(f"could not remove probe entry {entry!r}: {exc}")
    leftovers = [e.name for e in pd.listdir()]
    pd.close()
    if leftovers:
        report.notes.append(f"left in place (not created by the probe; unknown data is never deleted automatically): {leftovers} - probe folder {name!r} kept for you to inspect")
        return
    try:
        parent.remove_dir(name)
    except OSError as exc:
        report.notes.append(f"could not remove the (empty) probe folder {name!r}: {exc}")


def probe_in(parent, *, approved: bool = False) -> Report:
    """Probe the filesystem of the HELD directory `parent` inside a sub-folder this call creates and removes."""
    if approved is not True:
        raise PermissionError("capability probing creates and removes temporary files: it only runs in a folder the operator explicitly approved as disposable "
                              "(pass approved=True / --approve-disposable-dir)")
    report = Report(parent.path)
    name = PROBE_PREFIX + secrets.token_hex(8)
    if parent.stat_kind(name) != "missing":
        raise ValueError("probe folder name collision (astronomically unlikely); run it again")
    pd = parent.child_dir(name, create=True)
    created: list = []
    try:
        for check_name, required, fn in _checks():
            try:
                status, detail = fn(pd, created)
            except safefs.UnsafePathError as exc:
                status, detail = UNSUPPORTED, f"path safety failed: {exc}"
            except OSError as exc:
                status, detail = UNVERIFIED, f"could not be determined ({_errname(exc) if exc.errno else 'OS error'}: {exc})"
            except Exception as exc:  # noqa: BLE001 - a probe must never crash the caller; unknown means unverified
                status, detail = UNVERIFIED, f"could not be determined ({type(exc).__name__}: {exc})"
            report.add(check_name, required, status, detail)
        if _after_probe_hook is not None:
            _after_probe_hook(pd, report)
    finally:
        _cleanup(parent, pd, name, created, report)
    return report


def probe_path(directory, *, approved: bool = False) -> Report:
    if approved is not True:
        raise PermissionError("capability probing creates and removes temporary files: it only runs in a folder the operator explicitly approved as disposable "
                              "(pass approved=True / --approve-disposable-dir)")
    with safefs.open_dir(directory) as parent:  # must already exist; never created here
        return probe_in(parent, approved=True)


def require_publish(held) -> None:
    """Rehearse the exact publish sequence on a zero-byte file in the HELD directory; raise UnsupportedConfigurationError if it cannot work.
    Called before an operation creates anything, so a refusal leaves nothing behind."""
    name = REHEARSE_PREFIX + secrets.token_hex(8)
    try:
        with held.create_file(name) as nf:
            nf.commit(0o600)
        held.remove_file(name)
    except safefs.UnsupportedConfigurationError:
        raise
    except FileExistsError:
        raise ValueError("rehearsal name collision (astronomically unlikely); run it again") from None
    except OSError as exc:
        raise safefs.UnsupportedConfigurationError(
            f"The folder {held.path} cannot be used for publishing files safely ({exc}). Nothing was written. Check that it is writable and on a filesystem "
            "with hard links (ext4, XFS, btrfs, NTFS).") from None


def require_publish_at(path) -> Path:
    """Rehearse in `path`, or - if it does not exist yet - in its nearest existing ancestor (same filesystem), without creating anything.
    Returns the folder the rehearsal actually ran in."""
    p = safefs.abs_path(path)
    while True:
        try:
            with safefs.open_dir(p) as held:
                require_publish(held)
                return p
        except FileNotFoundError:
            if p.parent == p:
                raise
            p = p.parent


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--dir", type=Path, required=True)
    p.add_argument("--approve-disposable-dir", action="store_true", help="confirm that --dir may be written to and cleaned (a probe sub-folder is created and removed)")
    p.add_argument("--json", action="store_true")
    r = sub.add_parser("rehearse")
    r.add_argument("--dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "rehearse":
            where = require_publish_at(args.dir)
            print(f"publish rehearsal OK: {where} supports the safe publish sequence")
            return 0
        report = probe_path(args.dir, approved=args.approve_disposable_dir)
    except PermissionError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except safefs.UnsupportedConfigurationError as exc:
        print(f"UNSUPPORTED: {exc}", file=sys.stderr)
        return 3
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report.to_dict(), indent=2) if args.json else report.text())
    return {SUPPORTED: 0, UNSUPPORTED: 3, UNVERIFIED: 4}[report.verdict]


if __name__ == "__main__":
    sys.exit(main())
