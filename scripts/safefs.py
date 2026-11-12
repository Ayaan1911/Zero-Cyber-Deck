"""safefs: link-safe, race-resistant file access (stdlib only, Python 3.8+).

THREAT: a symlink / junction / reparse point (or a renamed or replaced folder or file) introduced by another
process, user or a hostile source tree BEFORE or WHILE we work. Validating a path and then re-opening it by name is
unsafe: the name can mean something else by the time it is used. Policy: open once, keep the open handle/descriptor,
and do every following operation relative to it. Anything that cannot be secured is refused, never "mostly" done.

POSIX (Linux; macOS lacks the needed link flags and is refused):
  * the path is walked from the root with O_NOFOLLOW and directory file descriptors; every later operation is
    relative to a verified descriptor (openat/mkdirat/linkat/unlinkat semantics). A link at any level, even one
    swapped in mid-operation, makes the OS refuse (ELOOP) or leaves us bound to the original directory.
  * new files are created exclusively under a random temporary name, written, verified by re-reading through the SAME
    descriptor, then published with link() (never replaces an existing name). Cleanup unlinks only if the name still
    refers to the object we created (device+inode check). Residual: the check and the unlink are two syscalls; the
    name is 128 random bits created O_EXCL, so replacing it needs write access to the directory AND the name.
WINDOWS (NTFS/ReFS/exFAT, local volumes):
  * every component from the drive root down is opened with FILE_FLAG_OPEN_REPARSE_POINT and held open WITHOUT
    FILE_SHARE_DELETE. While held, no component can be renamed, deleted or replaced by a junction (verified by
    tests/probe: rmdir/rename of the directory and of its ancestors fail with a sharing violation). Reparse points are
    detected on the handle itself and refused. Files are created with CREATE_NEW, delete-on-close armed on OUR handle
    (so failure/crash removes exactly the object we created), verified through the same handle, then the flag is cleared.
  * refused with a diagnostic: UNC/remote paths, SUBST/short-name/non-canonical paths (the handle's final path must equal the
    requested path). Sharing semantics on exFAT USB media follow the I/O manager and were not tested on real exFAT.
Neither backend provides tamper-proof logs, protects against an attacker who already owns the directory, or defends against
a malicious kernel/driver. NTFS alternate data streams in names are rejected.
"""
from __future__ import annotations

import errno
import hashlib
import os
import secrets
import stat as stat_mod
import sys
from pathlib import Path
from typing import List, NamedTuple, Optional, Tuple

CHUNK = 1024 * 1024
_WIN = sys.platform == "win32"


class UnsafePathError(ValueError):
    """A link/junction/reparse point or a replaced object was found where none is allowed."""


class UnsupportedConfigurationError(ValueError):
    """This platform/volume cannot provide the guarantee, so the sensitive operation is refused."""


class Entry(NamedTuple):
    name: str
    kind: str  # 'file' | 'dir' | 'link' | 'other'


def abs_path(path) -> Path:
    """Absolute, lexically normalized path. Never resolves links."""
    return Path(os.path.abspath(os.fspath(path)))


_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def check_name(name: str, portable: bool = False) -> str:
    """A single path component. On Windows (or with portable=True, used for release manifests that must install on
    Windows too) the strict rules apply; on Linux ordinary names that merely look odd (':' or a backslash) are legal."""
    if not name or name in (".", "..") or "/" in name or "\0" in name:
        raise UnsafePathError(f"Unsafe file name: {name!r}")
    if _WIN or portable:  # Windows dangers: separators, NTFS alternate streams (name:stream), device names, trailing dot/space
        if "\\" in name or ":" in name or any(ord(c) < 32 for c in name) or any(c in '<>"|?*' for c in name):
            raise UnsafePathError(f"Unsafe file name on Windows: {name!r}")
        if name.endswith((".", " ")) or name.split(".")[0].upper() in _RESERVED:
            raise UnsafePathError(f"Unsafe file name on Windows: {name!r}")
    return name


def split_relative(rel: str, portable: bool = False) -> List[str]:
    """Validate an untrusted relative path (e.g. from a manifest) and return its components."""
    if not rel or rel.startswith(("/", "\\")) or (len(rel) > 1 and rel[1] == ":"):
        raise UnsafePathError(f"Absolute or empty path not allowed: {rel!r}")
    return [check_name(p, portable) for p in rel.split("/")]


def hash_stream(fh) -> str:
    digest = hashlib.sha256()
    for block in iter(lambda: fh.read(CHUNK), b""):
        digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------------------------------------------------------------
# shared behaviour
# ---------------------------------------------------------------------------------------------------------------------
class _NewFile:
    """A file being created. Use as a context manager; call commit() on success. Anything else discards it."""

    committed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self.committed:
            self.discard()
        return False

    def write(self, data: bytes) -> int:
        return self.fh.write(data)

    def hash_back(self) -> str:
        """SHA-256 of what is on disk, read back through the SAME open file (never by name)."""
        self.fh.flush()
        self.fh.seek(0)
        digest = hash_stream(self.fh)
        self.fh.seek(0, 2)
        return digest


class _DirBase:
    path: str

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


# ---------------------------------------------------------------------------------------------------------------------
# POSIX backend
# ---------------------------------------------------------------------------------------------------------------------
if not _WIN:
    _DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)

    # errno values that mean "this filesystem has no hard links" (the Linux VFS returns EPERM when a filesystem has no link op)
    NO_HARDLINK_ERRNOS = {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EMLINK, errno.ENOSYS}
    HARDLINK_HELP = ("This folder ({path}) is on a filesystem that does not support hard links (error {errno}). exFAT, FAT32 and some network "
                     "filesystems do not, and the safe publish step requires them. Evidence, manifests, reports and migration are refused here "
                     "so that nothing is written with weaker guarantees. Use a folder on ext4, XFS, btrfs or NTFS (see SETUP.md 'Storage layout').")

    def _posix_supported() -> Optional[str]:
        if not (hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")):
            return "this platform has no O_NOFOLLOW/O_DIRECTORY"
        if os.open not in os.supports_dir_fd or os.link not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd:
            return "dir_fd-relative open/link/mkdir are not available (Linux is required; macOS is not supported)"
        if os.link not in os.supports_follow_symlinks:
            return "link(follow_symlinks=False) is not available (Linux is required; macOS is not supported)"
        return None

    def _map_posix(exc: OSError, path) -> Exception:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return UnsafePathError(f"Refusing a link or non-directory in the path: {path}")
        return exc

    class _PosixNewFile(_NewFile):
        def __init__(self, parent: "_PosixDir", name: str):
            self._parent, self.name = parent, check_name(name)
            self._tmp = ".zdtmp-" + secrets.token_hex(16)
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            self._fd = os.open(self._tmp, flags, 0o600, dir_fd=parent._fd)
            st = os.fstat(self._fd)
            self._ident = (st.st_dev, st.st_ino)
            self.fh = os.fdopen(self._fd, "r+b")
            self._mtime_ns: Optional[int] = None

        def set_mtime_ns(self, ns: int) -> None:
            self._mtime_ns = ns

        def commit(self, mode: int = 0o600) -> None:
            self.fh.flush()
            os.fsync(self._fd)
            os.fchmod(self._fd, mode)
            if self._mtime_ns is not None:
                os.utime(self._fd, ns=(self._mtime_ns, self._mtime_ns))
            try:
                # atomic, never replaces an existing name; both names are relative to the verified directory fd
                os.link(self._tmp, self.name, src_dir_fd=self._parent._fd, dst_dir_fd=self._parent._fd, follow_symlinks=False)
            except FileExistsError:
                raise
            except OSError as exc:
                if exc.errno in NO_HARDLINK_ERRNOS:  # exFAT/FAT32/some network filesystems: a clear diagnostic, never a bare EPERM
                    raise UnsupportedConfigurationError(HARDLINK_HELP.format(path=self._parent.path, errno=errno.errorcode.get(exc.errno, exc.errno))) from None
                raise
            self._unlink_if_ours()
            self.fh.close()
            self.committed = True

        def _unlink_if_ours(self) -> None:
            try:
                cur = os.stat(self._tmp, dir_fd=self._parent._fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            if (cur.st_dev, cur.st_ino) == self._ident:
                os.unlink(self._tmp, dir_fd=self._parent._fd)
            # else: the name now refers to something that is NOT ours -> leave it untouched

        def discard(self) -> None:
            # Unlink BEFORE closing: while our descriptor is open the inode is pinned in memory, so the name->inode identity
            # check is reliable even on filesystems that give a file a NEW inode number when it is re-read from disk (exFAT
            # assigns i_ino from a runtime counter). Closing first could make our own temporary file look "not ours" and
            # leave it behind. Replacement protection is unchanged: a different object at the name never matches.
            try:
                self._unlink_if_ours()
            finally:
                self.fh.close()

    class _PosixDir(_DirBase):
        def __init__(self, fd: int, path: str):
            self._fd, self.path = fd, path

        @property
        def fd(self) -> int:
            """The held directory descriptor (for the capability probe, which must exercise the real *at() primitives)."""
            return self._fd

        def remove_file(self, name: str) -> None:
            """Remove a file, or a link ITSELF (never what it points to), relative to this held directory."""
            os.unlink(check_name(name), dir_fd=self._fd)

        def remove_dir(self, name: str) -> None:
            """Remove an EMPTY directory relative to this held directory (the OS refuses if it is not empty)."""
            os.rmdir(check_name(name), dir_fd=self._fd)

        def close(self) -> None:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

        def child_dir(self, name: str, create: bool = False) -> "_PosixDir":
            check_name(name)
            try:
                fd = os.open(name, _DIR_FLAGS, dir_fd=self._fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(name, 0o700, dir_fd=self._fd)
                except FileExistsError:
                    pass
                try:
                    fd = os.open(name, _DIR_FLAGS, dir_fd=self._fd)
                except OSError as exc:
                    raise _map_posix(exc, os.path.join(self.path, name)) from None
            except OSError as exc:
                raise _map_posix(exc, os.path.join(self.path, name)) from None
            return _PosixDir(fd, os.path.join(self.path, name))

        def listdir(self) -> List[Entry]:
            out = []
            with os.scandir(self._fd) as it:
                for e in it:
                    if e.name.startswith(".zdtmp-"):
                        continue  # our own in-flight temporary files are not user content
                    if e.is_symlink():
                        kind = "link"
                    elif e.is_dir(follow_symlinks=False):
                        kind = "dir"
                    elif e.is_file(follow_symlinks=False):
                        kind = "file"
                    else:
                        kind = "other"
                    out.append(Entry(e.name, kind))
            return sorted(out)

        def stat_kind(self, name: str) -> str:
            try:
                st = os.stat(check_name(name), dir_fd=self._fd, follow_symlinks=False)
            except FileNotFoundError:
                return "missing"
            m = st.st_mode
            return "link" if stat_mod.S_ISLNK(m) else "dir" if stat_mod.S_ISDIR(m) else "file" if stat_mod.S_ISREG(m) else "other"

        def open_read(self, name: str):
            try:
                fd = os.open(check_name(name), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=self._fd)
            except OSError as exc:
                raise _map_posix(exc, os.path.join(self.path, name)) from None
            st = os.fstat(fd)
            if not stat_mod.S_ISREG(st.st_mode):
                os.close(fd)
                raise UnsafePathError(f"Not a regular file: {os.path.join(self.path, name)}")
            self.last_mtime_ns = st.st_mtime_ns
            return os.fdopen(fd, "rb")

        def create_file(self, name: str) -> _PosixNewFile:
            return _PosixNewFile(self, name)

        def open_append(self, name: str):
            try:
                fd = os.open(check_name(name), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=self._fd)
            except OSError as exc:
                raise _map_posix(exc, os.path.join(self.path, name)) from None
            if not stat_mod.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise UnsafePathError(f"Not a regular file: {os.path.join(self.path, name)}")
            return os.fdopen(fd, "ab")

        def verify_bound(self) -> None:
            """The directory we hold must still be the one at its path (not replaced/renamed meanwhile)."""
            st = os.fstat(self._fd)
            try:
                cur = os.stat(self.path, follow_symlinks=False)
            except OSError:
                raise UnsafePathError(f"Directory no longer exists at {self.path}: it was removed or renamed while in use") from None
            if (cur.st_dev, cur.st_ino) != (st.st_dev, st.st_ino):
                raise UnsafePathError(f"Directory at {self.path} was replaced while in use: data written so far is in an orphaned directory")

    def _open_dir_posix(path: Path, create: bool) -> _PosixDir:
        reason = _posix_supported()
        if reason:
            raise UnsupportedConfigurationError(reason)
        try:
            fd = os.open(path.anchor or "/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        except OSError as exc:
            raise _map_posix(exc, path) from None
        cur = _PosixDir(fd, path.anchor or "/")
        try:
            for part in path.parts[1:]:
                nxt = cur.child_dir(part, create)
                cur.close()
                cur = nxt
        except BaseException:
            cur.close()
            raise
        return cur


# ---------------------------------------------------------------------------------------------------------------------
# Windows backend
# ---------------------------------------------------------------------------------------------------------------------
if _WIN:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    _k32.SetFileInformationByHandle.restype = wintypes.BOOL
    _k32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    _k32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _k32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    _k32.GetDriveTypeW.restype = wintypes.UINT
    _k32.SetFileTime.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID]
    _k32.SetFileTime.restype = wintypes.BOOL

    _INVALID = ctypes.c_void_p(-1).value
    _GENERIC_READ, _GENERIC_WRITE, _DELETE = 0x80000000, 0x40000000, 0x00010000
    _FILE_LIST_DIRECTORY, _FILE_READ_ATTRIBUTES, _FILE_WRITE_ATTRIBUTES, _FILE_APPEND_DATA = 0x1, 0x80, 0x100, 0x4
    _SHARE_READ, _SHARE_WRITE = 0x1, 0x2  # deliberately NO FILE_SHARE_DELETE anywhere
    _CREATE_NEW, _OPEN_EXISTING, _OPEN_ALWAYS = 1, 3, 4
    _FLAG_NORMAL, _FLAG_BACKUP, _FLAG_REPARSE = 0x80, 0x02000000, 0x00200000
    _ATTR_DIR, _ATTR_REPARSE = 0x10, 0x400

    class _BHFI(ctypes.Structure):
        _fields_ = [("attrs", wintypes.DWORD), ("ct", wintypes.DWORD * 2), ("at", wintypes.DWORD * 2), ("wt", wintypes.DWORD * 2),
                    ("vol", wintypes.DWORD), ("sh", wintypes.DWORD), ("sl", wintypes.DWORD), ("links", wintypes.DWORD),
                    ("ih", wintypes.DWORD), ("il", wintypes.DWORD)]

    _k32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_BHFI)]
    _k32.GetFileInformationByHandle.restype = wintypes.BOOL

    def _create(path: str, access: int, share: int, disposition: int, flags: int) -> int:
        h = _k32.CreateFileW(path, access, share, None, disposition, flags, None)
        if h is None or h == _INVALID:
            raise ctypes.WinError(ctypes.get_last_error())
        return h

    def _info(h) -> _BHFI:
        info = _BHFI()
        if not _k32.GetFileInformationByHandle(h, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        return info

    def _final_path(h) -> str:
        buf = ctypes.create_unicode_buffer(32768)
        n = _k32.GetFinalPathNameByHandleW(h, buf, len(buf), 0)
        if n == 0 or n >= len(buf):
            raise ctypes.WinError(ctypes.get_last_error())
        s = buf.value
        return s[4:] if s.startswith("\\\\?\\") and not s.startswith("\\\\?\\UNC\\") else s

    def _norm(p: str) -> str:
        return os.path.normcase(os.path.normpath(p))

    def _win_supported(path: Path) -> None:
        drive = path.drive
        if not drive or drive.startswith("\\\\") or path.anchor.startswith("\\\\"):
            raise UnsupportedConfigurationError(f"UNC/network paths are not supported for sensitive operations: {path}")
        if _k32.GetDriveTypeW(drive + "\\") not in (2, 3, 6):  # removable, fixed, ram disk
            raise UnsupportedConfigurationError(f"Only local fixed/removable volumes are supported (handle sharing is not reliable elsewhere): {drive}")

    def _set_delete_flag(h, on: bool) -> None:
        flag = ctypes.c_ubyte(1 if on else 0)  # FILE_DISPOSITION_INFO { BOOLEAN DeleteFile } = 1 byte
        if not _k32.SetFileInformationByHandle(h, 4, ctypes.byref(flag), 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def _filetime(ns: int):
        t = ns // 100 + 116444736000000000
        return (wintypes.DWORD * 2)(t & 0xFFFFFFFF, t >> 32)

    class _WinNewFile(_NewFile):
        def __init__(self, parent: "_WinDir", name: str):
            self._parent, self.name = parent, check_name(name)
            self._path = os.path.join(parent.path, name)
            try:
                # CREATE_NEW: fails if the name exists (including a link). No share-delete: nobody else can delete/replace it.
                h = _create(self._path, _GENERIC_READ | _GENERIC_WRITE | _DELETE | _FILE_WRITE_ATTRIBUTES, _SHARE_READ, _CREATE_NEW, _FLAG_NORMAL | _FLAG_REPARSE)
            except OSError as exc:
                if getattr(exc, "winerror", None) in (80, 183) or os.path.lexists(self._path):
                    raise FileExistsError(errno.EEXIST, "File exists", self._path) from None
                raise
            _set_delete_flag(h, True)  # until commit(): closing OR crashing deletes exactly THIS object
            self._h = h
            self._fd = msvcrt.open_osfhandle(h, os.O_RDWR | os.O_BINARY)
            self.fh = os.fdopen(self._fd, "r+b")
            self._mtime_ns: Optional[int] = None

        def set_mtime_ns(self, ns: int) -> None:
            self._mtime_ns = ns

        def commit(self, mode: int = 0o600) -> None:
            self.fh.flush()
            os.fsync(self._fd)
            if self._mtime_ns is not None:
                ft = _filetime(self._mtime_ns)
                _k32.SetFileTime(self._h, None, None, ft)
            _set_delete_flag(self._h, False)
            self.fh.close()
            self.committed = True
            if not (mode & 0o200):
                os.chmod(self._path, mode)  # read-only attribute (path-based, best effort; content is already final)

        def discard(self) -> None:
            self.fh.close()  # delete-on-close removes exactly the object we created, whatever the name now refers to

    class _WinDir(_DirBase):
        def __init__(self, handle, path: str, parent: Optional["_WinDir"] = None):
            self._h, self.path, self._parent, self._kids, self._closed = handle, path, parent, 0, False
            if parent is not None:
                parent._kids += 1

        def close(self) -> None:
            self._closed = True
            self._release()

        def _release(self) -> None:
            if self._closed and self._kids == 0 and self._h is not None:
                _k32.CloseHandle(self._h)
                self._h = None
                if self._parent is not None:
                    self._parent._kids -= 1
                    self._parent._release()

        def child_dir(self, name: str, create: bool = False) -> "_WinDir":
            check_name(name)
            path = os.path.join(self.path, name)
            flags = _FLAG_BACKUP | _FLAG_REPARSE
            access = _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES
            try:
                h = _create(path, access, _SHARE_READ | _SHARE_WRITE, _OPEN_EXISTING, flags)
            except OSError as exc:
                if not create or getattr(exc, "winerror", None) not in (2, 3):
                    raise
                try:
                    os.mkdir(path)
                except FileExistsError:
                    pass
                h = _create(path, access, _SHARE_READ | _SHARE_WRITE, _OPEN_EXISTING, flags)
            info = _info(h)
            if info.attrs & _ATTR_REPARSE:
                _k32.CloseHandle(h)
                raise UnsafePathError(f"Refusing a link/junction in the path: {path}")
            if not info.attrs & _ATTR_DIR:
                _k32.CloseHandle(h)
                raise UnsafePathError(f"Not a directory: {path}")
            return _WinDir(h, path, self)

        def listdir(self) -> List[Entry]:
            out = []
            with os.scandir(self.path) as it:
                for e in it:
                    attrs = e.stat(follow_symlinks=False).st_file_attributes
                    kind = "link" if attrs & _ATTR_REPARSE else "dir" if attrs & _ATTR_DIR else "file"
                    out.append(Entry(e.name, kind))
            return sorted(out)

        def stat_kind(self, name: str) -> str:
            try:
                attrs = os.stat(os.path.join(self.path, check_name(name)), follow_symlinks=False).st_file_attributes
            except FileNotFoundError:
                return "missing"
            return "link" if attrs & _ATTR_REPARSE else "dir" if attrs & _ATTR_DIR else "file"

        def remove_file(self, name: str) -> None:
            """Remove a file, or a link ITSELF, under this held directory (its ancestors cannot be swapped while we hold it)."""
            os.remove(os.path.join(self.path, check_name(name)))

        def remove_dir(self, name: str) -> None:
            """Remove an EMPTY directory (rmdir; a junction is removed itself, never its target). Close any handle on it first."""
            os.rmdir(os.path.join(self.path, check_name(name)))

        def open_read(self, name: str):
            path = os.path.join(self.path, check_name(name))
            h = _create(path, _GENERIC_READ, _SHARE_READ, _OPEN_EXISTING, _FLAG_NORMAL | _FLAG_REPARSE)
            info = _info(h)
            if info.attrs & (_ATTR_REPARSE | _ATTR_DIR):
                _k32.CloseHandle(h)
                raise UnsafePathError(f"Refusing a link or directory where a regular file is required: {path}")
            self.last_mtime_ns = ((info.wt[1] << 32 | info.wt[0]) - 116444736000000000) * 100
            return os.fdopen(msvcrt.open_osfhandle(h, os.O_RDONLY | os.O_BINARY), "rb")

        def create_file(self, name: str) -> _WinNewFile:
            return _WinNewFile(self, name)

        def open_append(self, name: str):
            path = os.path.join(self.path, check_name(name))
            h = _create(path, _FILE_APPEND_DATA | _FILE_READ_ATTRIBUTES, _SHARE_READ | _SHARE_WRITE, _OPEN_ALWAYS, _FLAG_NORMAL | _FLAG_REPARSE)
            info = _info(h)
            if info.attrs & (_ATTR_REPARSE | _ATTR_DIR):
                _k32.CloseHandle(h)
                raise UnsafePathError(f"Refusing a link or directory where a regular file is required: {path}")
            return os.fdopen(msvcrt.open_osfhandle(h, os.O_WRONLY | os.O_APPEND | os.O_BINARY), "ab")

        def verify_bound(self) -> None:
            if _norm(_final_path(self._h)) != _norm(self.path):
                raise UnsafePathError(f"Directory path changed while in use: {self.path}")

    def _open_dir_windows(path: Path, create: bool) -> _WinDir:
        _win_supported(path)
        root = path.anchor
        h = _create(root, _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES, _SHARE_READ | _SHARE_WRITE, _OPEN_EXISTING, _FLAG_BACKUP | _FLAG_REPARSE)
        cur = _WinDir(h, root)
        try:
            for part in path.parts[1:]:
                nxt = cur.child_dir(part, create)
                cur.close()
                cur = nxt
            if _norm(_final_path(cur._h)) != _norm(str(path)):
                raise UnsupportedConfigurationError(
                    f"Path is not canonical (links, SUBST drive or 8.3 short name?): requested {path}, real {_final_path(cur._h)}. "
                    "Use the full real path.")
        except BaseException:
            cur.close()
            raise
        return cur


# ---------------------------------------------------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------------------------------------------------
def open_dir(path, create: bool = False):
    """Open and HOLD a directory by walking its whole path without following links. Use as a context manager."""
    p = abs_path(path)
    return _open_dir_windows(p, create) if _WIN else _open_dir_posix(p, create)


def open_path_parent(path, create: bool = False) -> Tuple[object, str]:
    """(held parent directory, final component name) for a file path."""
    p = abs_path(path)
    return open_dir(p.parent, create), check_name(p.name)


def walk_files(root, links: str = "error", _prefix: str = ""):
    """Yield (relative posix path, parent_dir, name, kind) for every file under a HELD directory, depth first.
    parent_dir is only valid until the generator is advanced. links='error' raises UnsafePathError on any link/other;
    links='include' yields them with kind 'link'/'other' (never followed, never descended)."""
    for entry in root.listdir():
        rel = _prefix + entry.name
        if entry.kind in ("link", "other"):
            if links == "error":
                raise UnsafePathError(f"Refusing a link/special file inside the tree: {rel}")
            yield rel, root, entry.name, entry.kind
        elif entry.kind == "dir":
            with root.child_dir(entry.name) as sub:
                yield from walk_files(sub, links, rel + "/")
        else:
            yield rel, root, entry.name, "file"


def open_relative_file(base, rel: str):
    """Open a file at an UNTRUSTED relative path under a held directory, holding every intermediate directory
    until the returned file is closed. Raises FileNotFoundError / UnsafePathError."""
    parts = split_relative(rel)
    stack = []
    cur = base
    try:
        for part in parts[:-1]:
            cur = cur.child_dir(part)
            stack.append(cur)
        fh = cur.open_read(parts[-1])
    except BaseException:
        for d in reversed(stack):
            d.close()
        raise
    return _HeldFile(fh, stack)


class _HeldFile:
    """A file plus the directory handles that pin its path; closing it releases them."""

    def __init__(self, fh, dirs):
        self._fh, self._dirs = fh, dirs

    def read(self, *a):
        return self._fh.read(*a)

    def close(self):
        self._fh.close()
        for d in reversed(self._dirs):
            d.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def sha256_file(path) -> str:
    """SHA-256 of a file reached without following any link (whole path chain held open while reading)."""
    parent, name = open_path_parent(path)
    with parent:
        with parent.open_read(name) as fh:
            return hash_stream(fh)


def supported() -> Tuple[bool, str]:
    """(True, '') when this platform can provide the guarantees, else (False, reason)."""
    if _WIN:
        return True, ""
    reason = _posix_supported()
    return (reason is None), (reason or "")
