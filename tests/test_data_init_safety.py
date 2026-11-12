"""Safe, interruptible, repeatable ZERO-DATA initialisation; refusal where the filesystem cannot publish safely. Offline, temp folders only."""
import _isolation  # noqa: F401
import errno
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import datadir  # noqa: E402
import evidence  # noqa: E402
import fscaps  # noqa: E402
import migrate_data  # noqa: E402
import report  # noqa: E402
import safefs  # noqa: E402

WIN = sys.platform == "win32"
OK, WHY = safefs.supported()


def names(p):
    return sorted(x.name for x in Path(p).iterdir())


class no_hardlinks:
    def __enter__(self):
        def failing(*_a, **_k):
            raise OSError(errno.EPERM, "Operation not permitted")
        self._fn = failing
        self._p = mock.patch.object(os, "link", failing)
        self._p.start()
        os.supports_dir_fd.add(failing)
        os.supports_follow_symlinks.add(failing)

    def __exit__(self, *a):
        self._p.stop()
        os.supports_dir_fd.discard(self._fn)
        os.supports_follow_symlinks.discard(self._fn)


@unittest.skipUnless(OK, WHY or "unsupported platform")
class InitSafety(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.base = Path(self._t.name).resolve()
        self.data = self.base / "ZERO-DATA"
        datadir._after_subdirs_hook = None

    def tearDown(self):
        datadir._after_subdirs_hook = None
        self._t.cleanup()

    def state(self):
        return datadir.check(self.data)[0]

    def test_interrupted_init_is_partial_then_completed_without_deleting_anything(self):
        def boom():
            raise KeyboardInterrupt
        datadir._after_subdirs_hook = boom
        with self.assertRaises(KeyboardInterrupt):
            datadir.init(self.data)
        datadir._after_subdirs_hook = None
        self.assertEqual(self.state(), "partial")
        self.assertFalse((self.data / datadir.MARKER).exists())
        self.assertEqual(datadir.main(["check", "--data", str(self.data)]), 7)
        datadir.init(self.data)
        self.assertEqual(self.state(), "ok")

    def test_repeated_init_is_idempotent_and_preserves_user_files(self):
        datadir.init(self.data)
        (self.data / "notes" / "mine.txt").write_text("KEEP")
        (self.data / "config" / "scope.local.txt").write_text("10.0.0.0/24\n")
        marker = (self.data / datadir.MARKER).read_text()
        datadir.init(self.data)
        datadir.init(self.data)
        self.assertEqual((self.data / "notes" / "mine.txt").read_text(), "KEEP")
        self.assertEqual((self.data / "config" / "scope.local.txt").read_text(), "10.0.0.0/24\n")
        self.assertEqual((self.data / datadir.MARKER).read_text(), marker)

    def test_missing_subfolder_is_incomplete_and_repaired_in_place(self):
        datadir.init(self.data)
        (self.data / "archives").rmdir()
        self.assertEqual(self.state(), "incomplete")
        self.assertEqual(datadir.main(["check", "--data", str(self.data)]), 8)
        datadir.init(self.data)
        self.assertEqual(self.state(), "ok")

    def test_unknown_non_empty_folder_is_never_adopted_or_modified(self):
        self.data.mkdir()
        (self.data / "photos.jpg").write_text("not ours")
        with self.assertRaises(ValueError):
            datadir.init(self.data)
        self.assertEqual(names(self.data), ["photos.jpg"])
        self.assertEqual(self.state(), "unmarked")

    def test_zero_folders_holding_user_data_without_marker_are_not_adopted(self):
        (self.data / "results").mkdir(parents=True)
        (self.data / "results" / "scan.txt").write_text("x")
        self.assertEqual(self.state(), "unmarked")
        with self.assertRaises(ValueError):
            datadir.init(self.data)
        self.assertEqual((self.data / "results" / "scan.txt").read_text(), "x")

    def test_init_never_creates_missing_parents(self):
        with self.assertRaises(OSError):
            datadir.init(self.base / "nope" / "ZERO-DATA")
        self.assertEqual(names(self.base), [])

    @unittest.skipIf(WIN, "POSIX hard-link behaviour")
    def test_init_on_filesystem_without_hard_links_is_refused_and_leaves_nothing(self):
        with no_hardlinks():
            with self.assertRaises(safefs.UnsupportedConfigurationError) as ctx:
                datadir.init(self.data)
            self.assertEqual(datadir.main(["init", "--data", str(self.data)]), 9)
        self.assertIn("hard links", str(ctx.exception))
        self.assertEqual(names(self.base), [], "a half-initialised ZERO-DATA was left behind")

    @unittest.skipIf(WIN, "POSIX hard-link behaviour")
    def test_init_refused_on_existing_empty_folder_leaves_it_exactly_as_it_was(self):
        self.data.mkdir()
        with no_hardlinks():
            with self.assertRaises(safefs.UnsupportedConfigurationError):
                datadir.init(self.data)
        self.assertEqual(names(self.data), [])

    @unittest.skipIf(WIN, "POSIX hard-link behaviour")
    def test_evidence_manifest_report_and_migration_refuse_without_hard_links_and_write_nothing(self):
        datadir.init(self.data)
        src = self.base / "src"
        src.mkdir()
        (src / "a.txt").write_text("a")
        out = self.data / "evidence" / "case1"
        with no_hardlinks():
            with self.assertRaises(safefs.UnsupportedConfigurationError):
                evidence.acquire(src, out, "case1", "examiner")
            with self.assertRaises(safefs.UnsupportedConfigurationError):
                evidence.write_manifest(src, self.data / "evidence" / "m.sha256")
            with self.assertRaises(safefs.UnsupportedConfigurationError):
                fscaps.require_publish_at(self.data / "results")
        self.assertEqual(names(self.data / "evidence"), [])
        self.assertEqual(names(self.data / "results"), [])
        self.assertTrue(callable(report.main) and callable(migrate_data.migrate))

    def test_stale_probe_folder_from_a_crash_is_recognised_as_partial(self):
        (self.data / (fscaps.PROBE_PREFIX + "deadbeef")).mkdir(parents=True)
        self.assertEqual(self.state(), "partial")
        datadir.init(self.data)
        self.assertEqual(self.state(), "ok")
        self.assertTrue((self.data / (fscaps.PROBE_PREFIX + "deadbeef")).exists(), "an old probe folder must not be deleted automatically")


if __name__ == "__main__":
    unittest.main()
