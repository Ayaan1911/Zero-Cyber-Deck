"""Filesystem capability probe + publish rehearsal. Offline, disposable temp folders only; no privileged operations.

Filesystems without hard links (exFAT/FAT32) are SIMULATED by making os.link() fail with EPERM, as the Linux VFS does for
a filesystem with no link operation (verified in the kernel source: fs/exfat has no .link inode operation). This models one
property; it is not a test on real exFAT (see docs/KALI-VM-CHECKLIST.md for the real-image step)."""
import _isolation  # noqa: F401
import errno
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from linkutil import make_dir_link

ROOT = Path(__file__).resolve().parents[1]
SUPPORT = ROOT / "tests" / "support"
sys.path.insert(0, str(ROOT / "scripts"))
import fscaps  # noqa: E402
import safefs  # noqa: E402

WIN = sys.platform == "win32"
OK, WHY = safefs.supported()


def listing(root):
    return sorted(p.name for p in Path(root).iterdir())


class no_hardlinks:
    """Context manager: os.link fails with EPERM like on exFAT, while safefs's API-level capability check still passes."""

    def __enter__(self):
        def failing(*_a, **_k):
            raise OSError(errno.EPERM, "Operation not permitted")
        self._fn = failing
        self._patch = mock.patch.object(os, "link", failing)
        self._patch.start()
        os.supports_dir_fd.add(failing)
        os.supports_follow_symlinks.add(failing)
        return self

    def __exit__(self, *exc):
        self._patch.stop()
        os.supports_dir_fd.discard(self._fn)
        os.supports_follow_symlinks.discard(self._fn)
        return False


@unittest.skipUnless(OK, WHY or "unsupported platform")
class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name).resolve()
        fscaps._after_probe_hook = None
        fscaps._ident_name_override = None

    def tearDown(self):
        fscaps._after_probe_hook = None
        fscaps._ident_name_override = None
        self._tmp.cleanup()

    def status(self, report, name):
        return next(c for c in report.checks if c.name == name)


class ProbeTests(Base):
    def test_probe_requires_explicit_approval_and_writes_nothing_without_it(self):
        with self.assertRaises(PermissionError):
            fscaps.probe_path(self.dir)
        with self.assertRaises(PermissionError):
            fscaps.probe_path(self.dir, approved=False)
        self.assertEqual(fscaps.main(["probe", "--dir", str(self.dir)]), 2)
        self.assertEqual(listing(self.dir), [])

    def test_supported_filesystem_is_demonstrated_check_by_check_and_leaves_nothing(self):
        report = fscaps.probe_path(self.dir, approved=True)
        self.assertEqual(report.verdict, fscaps.SUPPORTED, report.text())
        required = [c for c in report.checks if c.required]
        self.assertTrue(required and all(c.status == fscaps.SUPPORTED for c in required), report.text())
        names = {c.name for c in report.checks}
        expected = {"held_directory_blocks_swap", "exclusive_create", "path_identity"} if WIN else {"hardlink_publish", "exclusive_create", "nofollow", "path_identity", "dir_relative_operations"}
        self.assertTrue(expected <= names, names)
        self.assertEqual(listing(self.dir), [], "the probe left something behind")
        self.assertEqual(report.notes, [])

    def test_probe_never_creates_the_target_folder(self):
        with self.assertRaises(FileNotFoundError):
            fscaps.probe_path(self.dir / "missing", approved=True)
        self.assertEqual(fscaps.main(["probe", "--dir", str(self.dir / "missing"), "--approve-disposable-dir"]), 2)
        self.assertEqual(listing(self.dir), [])

    def test_ancestor_links_are_refused_by_the_probe_too(self):
        outside = self.dir / "outside"
        outside.mkdir()
        alias = self.dir / "alias"
        if not make_dir_link(alias, outside):
            self.skipTest("neither symlinks nor junctions can be created here")
        with self.assertRaises(safefs.UnsafePathError):
            fscaps.probe_path(alias, approved=True)
        self.assertEqual(listing(outside), [])

    def test_cleanup_removes_only_what_the_probe_created_and_never_follows_links(self):
        outside = self.dir / "outside"
        outside.mkdir()
        (outside / "sentinel.txt").write_text("PRECIOUS")
        planted = {}

        def hostile(probe_dir, report):  # someone drops a stranger file and a link into the probe folder before cleanup
            (Path(probe_dir.path) / "stranger.txt").write_text("not ours")
            planted["link"] = make_dir_link(Path(probe_dir.path) / "planted_link", outside)
        fscaps._after_probe_hook = hostile
        report = fscaps.probe_path(self.dir, approved=True)
        self.assertEqual(report.verdict, fscaps.SUPPORTED)
        self.assertEqual((outside / "sentinel.txt").read_text(), "PRECIOUS", "cleanup followed a link and deleted outside data")
        self.assertEqual(listing(outside), ["sentinel.txt"])
        kept = [p for p in self.dir.iterdir() if p.name.startswith(fscaps.PROBE_PREFIX)]
        self.assertEqual(len(kept), 1, "the probe folder must be KEPT when it contains entries it did not create")
        self.assertEqual((kept[0] / "stranger.txt").read_text(), "not ours")
        self.assertTrue(any("left in place" in n for n in report.notes), report.notes)

    def test_informational_findings_never_change_the_verdict(self):
        name = "_w_case" if WIN else "_p_case"
        with mock.patch.object(fscaps, name, lambda pd, created: (fscaps.UNSUPPORTED, "simulated: case-insensitive")):
            report = fscaps.probe_path(self.dir, approved=True)
        self.assertEqual(self.status(report, "case_sensitivity").status, fscaps.UNSUPPORTED)
        self.assertFalse(self.status(report, "case_sensitivity").required)
        self.assertEqual(report.verdict, fscaps.SUPPORTED)
        self.assertEqual(self.status(report, "power_loss_durability").status, fscaps.UNVERIFIED)  # honestly reported, never assumed

    def test_a_required_check_that_cannot_be_determined_is_unverified_and_fails_closed(self):
        name = "_w_exclusive" if WIN else "_p_exclusive"

        def broken(pd, created):
            raise OSError(errno.EIO, "simulated I/O error")
        with mock.patch.object(fscaps, name, broken):
            report = fscaps.probe_path(self.dir, approved=True)
        self.assertEqual(self.status(report, "exclusive_create").status, fscaps.UNVERIFIED)
        self.assertEqual(report.verdict, fscaps.UNVERIFIED)
        self.assertIn("not assumed", report.text())
        self.assertEqual(listing(self.dir), [], "cleanup must still happen after a failed check")
        with mock.patch.object(fscaps, name, broken):
            self.assertEqual(fscaps.main(["probe", "--dir", str(self.dir), "--approve-disposable-dir"]), 4)

    def test_unexpected_exceptions_in_a_check_become_unverified_not_a_crash(self):
        name = "_w_commit" if WIN else "_p_hardlink"
        with mock.patch.object(fscaps, name, lambda pd, created: 1 / 0):
            report = fscaps.probe_path(self.dir, approved=True)
        self.assertEqual(report.verdict, fscaps.UNVERIFIED)

    def test_json_output_is_machine_readable(self):
        out = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "fscaps.py"), "probe", "--dir", str(self.dir), "--approve-disposable-dir", "--json"],
                             capture_output=True, text=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(out.returncode, 0, out.stderr)
        data = json.loads(out.stdout)
        self.assertEqual(data["verdict"], "supported")
        self.assertTrue(all({"name", "required", "status", "detail"} <= set(c) for c in data["checks"]))


@unittest.skipIf(WIN, "hard-link semantics are a POSIX concern (the Windows backend publishes in place, without link())")
class NoHardLinkFilesystemTests(Base):
    def test_a_filesystem_without_hard_links_is_reported_unsupported_with_a_clear_reason(self):
        with no_hardlinks():
            report = fscaps.probe_path(self.dir, approved=True)
        self.assertEqual(report.verdict, fscaps.UNSUPPORTED, report.text())
        hl = self.status(report, "hardlink_publish")
        self.assertEqual(hl.status, fscaps.UNSUPPORTED)
        self.assertIn("no hard links", hl.detail)
        for other in ("exclusive_create", "nofollow", "path_identity", "dir_relative_operations"):
            self.assertEqual(self.status(report, other).status, fscaps.SUPPORTED, other)  # only the missing property is blamed
        self.assertIn("Fail closed", report.text())
        self.assertIn("ext4", report.text())
        self.assertEqual(listing(self.dir), [], "probe cleanup must be complete even when a check fails")

    def test_cli_exit_code_for_unsupported_is_3(self):
        with no_hardlinks():
            self.assertEqual(fscaps.main(["probe", "--dir", str(self.dir), "--approve-disposable-dir"]), 3)
        self.assertEqual(listing(self.dir), [])

    def test_unstable_inode_identity_is_unsupported(self):
        counter = iter(range(1, 1000))
        fscaps._ident_name_override = lambda fd, name: (1, next(counter))  # the name 'moves' to another inode every time it is read
        report = fscaps.probe_path(self.dir, approved=True)
        self.assertEqual(self.status(report, "path_identity").status, fscaps.UNSUPPORTED)
        self.assertEqual(report.verdict, fscaps.UNSUPPORTED)
        self.assertEqual(self.status(report, "identity_after_close").status, fscaps.UNSUPPORTED)  # informational
        self.assertEqual(listing(self.dir), [])

    def test_link_that_replaces_an_existing_name_would_be_detected(self):
        real_link = os.link

        def overwriting_link(src, dst, **kw):  # a broken filesystem that silently replaces the target
            if os.path.exists(os.path.join("/proc/self/fd", str(kw["dst_dir_fd"]), dst)) if False else False:
                pass
            try:
                os.unlink(dst, dir_fd=kw["dst_dir_fd"])
            except FileNotFoundError:
                pass
            return real_link(src, dst, **kw)
        os.supports_dir_fd.add(overwriting_link)
        os.supports_follow_symlinks.add(overwriting_link)
        try:
            with mock.patch.object(os, "link", overwriting_link):
                report = fscaps.probe_path(self.dir, approved=True)
        finally:
            os.supports_dir_fd.discard(overwriting_link)
            os.supports_follow_symlinks.discard(overwriting_link)
        self.assertEqual(self.status(report, "hardlink_publish").status, fscaps.UNSUPPORTED)
        self.assertIn("REPLACED", self.status(report, "hardlink_publish").detail)


class RehearsalTests(Base):
    def test_rehearsal_succeeds_where_publishing_works_and_leaves_nothing(self):
        where = fscaps.require_publish_at(self.dir)
        self.assertEqual(where, self.dir)
        self.assertEqual(listing(self.dir), [])
        self.assertEqual(fscaps.main(["rehearse", "--dir", str(self.dir)]), 0)

    def test_rehearsal_for_a_missing_folder_runs_in_the_nearest_existing_ancestor_and_creates_nothing(self):
        where = fscaps.require_publish_at(self.dir / "a" / "b" / "c")
        self.assertEqual(where, self.dir)
        self.assertEqual(listing(self.dir), [])

    @unittest.skipIf(WIN, "POSIX hard-link behaviour")
    def test_rehearsal_refuses_without_hard_links_with_a_diagnostic_and_leaves_no_temporary_file(self):
        with no_hardlinks():
            with self.assertRaises(safefs.UnsupportedConfigurationError) as ctx:
                fscaps.require_publish_at(self.dir)
            self.assertEqual(fscaps.main(["rehearse", "--dir", str(self.dir)]), 3)
        text = str(ctx.exception)
        for needle in ("does not support hard links", "exFAT", "ext4", "Storage layout"):
            self.assertIn(needle, text)
        self.assertEqual(listing(self.dir), [], "a .zdtmp-/.zdrehearse- file was left behind")

    def test_rehearsal_in_an_unwritable_place_is_a_diagnostic_not_a_traceback(self):
        f = self.dir / "a_file"
        f.write_text("x")
        with self.assertRaises((safefs.UnsupportedConfigurationError, safefs.UnsafePathError, OSError)):
            fscaps.require_publish_at(f)

    def test_ancestor_links_are_refused(self):
        outside = self.dir / "outside"
        outside.mkdir()
        alias = self.dir / "alias"
        if not make_dir_link(alias, outside):
            self.skipTest("neither symlinks nor junctions can be created here")
        with self.assertRaises(safefs.UnsafePathError):
            fscaps.require_publish_at(alias / "sub")
        self.assertEqual(listing(outside), [])


class StaticTests(unittest.TestCase):
    def test_only_the_probe_and_data_initialiser_remove_anything(self):
        """Removal primitives exist solely for probe cleanup and for removing an EMPTY folder that init itself created."""
        allowed = {"safefs.py", "fscaps.py", "datadir.py"}
        for f in (ROOT / "scripts").glob("*.py"):
            text = f.read_text(encoding="utf-8")
            if ".remove_file(" in text or ".remove_dir(" in text:
                self.assertIn(f.name, allowed, f"{f.name} must not delete anything")
        for f in (ROOT / "scripts").glob("*.py"):
            for forbidden in ("shutil.rmtree", "os.removedirs", "shutil.move", "os.remove(", "os.unlink(", "os.rmdir("):
                if f.name in ("safefs.py", "fscaps.py") and forbidden in ("os.unlink(", "os.rmdir("):
                    continue  # safefs: the primitives; fscaps: dir-fd-relative removal inside its own probe sub-folder
                if f.name == "safefs.py" and forbidden == "os.remove(":
                    continue
                self.assertNotIn(forbidden, f.read_text(encoding="utf-8"), f"{f.name}: {forbidden}")


if __name__ == "__main__":
    unittest.main()
