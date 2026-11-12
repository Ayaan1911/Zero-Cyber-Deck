"""Link-safe path handling shared by evidence.py, report.py and scope_guard.py (stdlib, Python 3.8+).

Threat: a symlink, junction or other reparse point anywhere in a path (including ANCESTOR components such as
`alias -> /elsewhere` in `alias/evidence`) silently redirects reads/writes. Policy: fail closed.

* assert_no_links_in_chain(): every existing component from the filesystem root down must be a plain directory/file.
  Paths are normalized lexically (os.path.abspath), never resolved through links.
* create_new_file()/append_text()/make_dirs():
    - POSIX: the path is walked component by component with O_NOFOLLOW and directory file descriptors, so a link
      anywhere (even one swapped in during the operation) makes the OS refuse: no check-then-use race.
    - Windows: no equivalent primitive is used here, so each step is "validate chain -> exclusive create -> re-validate
      that the created object really lives where we meant". A swap that lands in the tiny window between validation
      and creation is detected afterwards and the file we just created is removed; the content briefly existed at the
      redirected location. This residual race is documented in SETUP.md and cannot be closed without Win32 handle APIs.
* Legitimate paths that traverse a link (e.g. macOS /var -> /private/var) are refused: resolve them yourself and pass
  the real path.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path

_REPARSE_POINT = 0x400  # Windows FILE_ATTRIBUTE_REPARSE_POINT: symlinks, junctions, mount points, cloud placeholders
_POSIX_WALK = (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
               and os.open in getattr(os, "supports_dir_fd", set()))

# Test-only seam: called between "chain validated" and "object created" to simulate a replacement race. None in production.
_after_check_hook = None


def is_link(path) -> bool:
    """True for symlinks AND Windows junctions/reparse points. Never follows the link."""
    p = Path(path)
    try:
        if p.is_symlink():
            return True
        return bool(getattr(os.lstat(p), "st_file_attributes", 0) & _REPARSE_POINT)
    except OSError:
        return False


def abs_path(path) -> Path:
    """Absolute, lexically normalized path. Does NOT resolve links."""
    return Path(os.path.abspath(os.fspath(path)))


def assert_no_links_in_chain(path) -> Path:
    """Return the absolute path after proving that no existing component, root to leaf, is a link/junction."""
    p = abs_path(path)
    current = Path(p.anchor)
    for part in p.parts[1:]:
        current = current / part
        if not os.path.lexists(current):
            break  # the remaining components do not exist yet; creation below re-validates each step
        if is_link(current):
            raise ValueError(f"Refusing a path that passes through a link/junction: {current} (in {p})")
    return p


def reject_links_under(base, rel) -> None:
    """Raise ValueError if any existing component of base/rel is a link (base itself is not checked)."""
    current = Path(base)
    for part in Path(rel).parts:
        current = current / part
        if is_link(current):
            raise ValueError(f"Refusing to use a path through a link/junction: {current}")


def _same_place(path: Path) -> bool:
    """True if the object at `path` really lives at that path (no link anywhere on the way)."""
    return os.path.normcase(os.path.realpath(path)) == os.path.normcase(str(path))


def _wrap_link_error(exc: OSError, path) -> ValueError:
    return ValueError(f"Refusing to follow a link/junction while opening {path}: {exc}")


def _posix_open_parent(p: Path, create: bool) -> int:
    """Open p's parent directory fd by walking from '/' with O_NOFOLLOW; optionally creating missing directories."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(p.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in p.parts[1:-1]:
            try:
                nxt = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def make_dirs(path) -> Path:
    """Create `path` (and missing parents) without ever following a link."""
    p = assert_no_links_in_chain(path)
    if _POSIX_WALK:
        try:
            fd = _posix_open_parent(p / "x", create=True)  # opens p itself as the "parent" of a dummy leaf
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise _wrap_link_error(exc, p) from None
            raise
        os.close(fd)
        return p
    current = Path(p.anchor)
    for part in p.parts[1:]:
        current = current / part
        if not os.path.lexists(current):
            if _after_check_hook:
                _after_check_hook()
            os.mkdir(current)
        if is_link(current) or not _same_place(current):
            raise ValueError(f"Refusing: {current} is, or became, a link/junction")
    return p


def create_new_file(path):
    """Exclusively create a NEW file (parents are created safely) and return it open for binary writing.
    Fails if the path exists or if any component is, or becomes, a link."""
    p = assert_no_links_in_chain(path)
    if _POSIX_WALK:
        try:
            fd = _posix_open_parent(p, create=True)
            try:
                if _after_check_hook:
                    _after_check_hook()
                out = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            finally:
                os.close(fd)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise _wrap_link_error(exc, p) from None
            raise
        return os.fdopen(out, "wb")
    make_dirs(p.parent)
    if _after_check_hook:
        _after_check_hook()
    fh = open(p, "xb")
    try:
        if is_link(p.parent) or not _same_place(p.parent) or not _same_place(p):
            raise ValueError(f"Path was redirected through a link/junction during creation: {p}")
    except ValueError:
        fh.close()
        try:
            os.unlink(p)  # only the file we just created, wherever it landed
        except OSError:
            pass
        raise
    return fh


def append_text(path, text: str) -> None:
    """Append UTF-8 text to a log file, refusing links anywhere in the path. Creates the file (and parents) if needed."""
    p = assert_no_links_in_chain(path)
    if is_link(p):
        raise ValueError(f"Refusing to append to a link: {p}")
    data = text.encode("utf-8")
    if _POSIX_WALK:
        try:
            fd = _posix_open_parent(p, create=True)
            try:
                if _after_check_hook:
                    _after_check_hook()
                out = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            finally:
                os.close(fd)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise _wrap_link_error(exc, p) from None
            raise
        with os.fdopen(out, "ab") as fh:
            fh.write(data)
        return
    make_dirs(p.parent)
    if _after_check_hook:
        _after_check_hook()
    existed = os.path.lexists(p)
    fh = open(p, "ab")
    try:
        if is_link(p.parent) or not _same_place(p.parent) or not _same_place(p):
            raise ValueError(f"Path was redirected through a link/junction: {p}")
        fh.write(data)  # nothing is written until the final location has been verified
    except ValueError:
        fh.close()
        if not existed:
            try:
                os.unlink(p)  # remove only the empty file this call itself just created
            except OSError:
                pass
        raise
    finally:
        if not fh.closed:
            fh.close()


def _cli(argv=None) -> int:  # `pathsafe.py check PATH...`: used by shell/PowerShell wrappers
    import sys
    args = (argv if argv is not None else sys.argv[1:])
    if len(args) < 2 or args[0] != "check":
        print("usage: pathsafe.py check PATH...", file=sys.stderr)
        return 2
    try:
        for item in args[1:]:
            assert_no_links_in_chain(item)
    except ValueError as exc:
        print(f"UNSAFE PATH: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
