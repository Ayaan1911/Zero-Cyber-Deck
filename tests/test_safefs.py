"""safefs: link safety, handle holding, exclusive creation, identity-aware cleanup, race behaviour.
Windows tests prove the handle-holding protection EMPIRICALLY (the attacker's rename/rmdir/replace actually fails);
POSIX tests prove the descriptor-relative behaviour. Disposable temp folders only."""
import _isolation  # noqa: F401
import os
import sys
import tempfile
import unittest
from pathlib import Path

from linkutil import make_dir_link

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import safefs  # noqa: E402

WIN = sys.platform == "win32"
OK, WHY = safefs.supported()


@unittest.skipUnless(OK, WHY or "unsupported platform")
class SafeFsCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name).resolve()
        self.outside = self.dir / "outside"
        self.outside.mkdir()
        (self.outside / "secret.txt").write_text("TOPSECRET")

    def tearDown(self):
        self._tmp.cleanup()

    def link_or_skip(self, link, target):
        if not make_dir_link(link, target):
            self.skipTest("neither symlinks nor junctions can be created here")


class BasicTests(SafeFsCase):
    def test_create_commit_and_read_back(self):
        with safefs.open_dir(self.dir / "a" / "b", create=True) as d:
            with d.create_file("f.bin") as nf:
                nf.write(b"hello")
                digest = nf.hash_back()
                nf.commit(0o444)
        self.assertEqual((self.dir / "a" / "b" / "f.bin").read_bytes(), b"hello")
        self.assertEqual(digest, safefs.sha256_file(self.dir / "a" / "b" / "f.bin"))

    def test_creation_is_exclusive_and_leaves_no_temporary_file(self):
        with safefs.open_dir(self.dir) as d:
            with d.create_file("f.bin") as nf:
                nf.write(b"first")
                nf.commit()
            with self.assertRaises(FileExistsError):
                with d.create_file("f.bin") as nf2:
                    nf2.write(b"second")
                    nf2.commit()
            self.assertEqual([e.name for e in d.listdir()], ["f.bin", "outside"])
        self.assertEqual((self.dir / "f.bin").read_bytes(), b"first")
        self.assertEqual([p.name for p in self.dir.iterdir() if p.name.startswith(".zdtmp")], [])

    def test_uncommitted_file_vanishes(self):
        with safefs.open_dir(self.dir) as d:
            with self.assertRaises(RuntimeError):
                with d.create_file("partial.bin") as nf:
                    nf.write(b"half")
                    raise RuntimeError("boom")
        self.assertFalse((self.dir / "partial.bin").exists())
        self.assertEqual([p.name for p in self.dir.iterdir() if p.name.startswith(".zdtmp")], [])

    def test_append_creates_and_appends(self):
        with safefs.open_dir(self.dir) as d:
            for text in (b"one\n", b"two\n"):
                with d.open_append("log.txt") as fh:
                    fh.write(text)
        self.assertEqual((self.dir / "log.txt").read_bytes(), b"one\ntwo\n")

    def test_names_are_validated(self):
        for bad in ("", ".", "..", "a/b", "a\0b"):
            with self.assertRaises(safefs.UnsafePathError, msg=repr(bad)):
                safefs.check_name(bad)
        for bad in ("../x", "/etc/passwd", "a//b", "a/./b", "a/../b"):
            with self.assertRaises(safefs.UnsafePathError, msg=bad):
                safefs.split_relative(bad)
        if WIN:
            for bad in ("a:b", "file.txt:stream", "CON", "nul.txt", "x.", "x ", "a|b"):
                with self.assertRaises(safefs.UnsafePathError, msg=bad):
                    safefs.check_name(bad)
        else:
            self.assertEqual(safefs.check_name("2026-01-01T12:00:00.log"), "2026-01-01T12:00:00.log")

    def test_walk_files_rejects_special_entries_and_can_report_them(self):
        (self.dir / "t" / "sub").mkdir(parents=True)
        (self.dir / "t" / "a.txt").write_text("a")
        (self.dir / "t" / "sub" / "b.txt").write_text("b")
        self.link_or_skip(self.dir / "t" / "jn", self.outside)
        with safefs.open_dir(self.dir / "t") as d:
            with self.assertRaises(safefs.UnsafePathError):
                list(safefs.walk_files(d))
            seen = [(rel, kind) for rel, _p, _n, kind in safefs.walk_files(d, links="include")]
        self.assertEqual(seen, [("a.txt", "file"), ("jn", "link"), ("sub/b.txt", "file")])


class LinkRefusalTests(SafeFsCase):
    def test_leaf_link_is_refused(self):
        self.link_or_skip(self.dir / "leaf", self.outside)
        with self.assertRaises(safefs.UnsafePathError):
            safefs.open_dir(self.dir / "leaf")

    def test_ancestor_link_is_refused_at_any_depth(self):
        self.link_or_skip(self.dir / "alias", self.outside)
        (self.outside / "x" / "y").mkdir(parents=True)
        for p in (self.dir / "alias" / "x", self.dir / "alias" / "x" / "y"):
            with self.assertRaises(safefs.UnsafePathError, msg=str(p)):
                safefs.open_dir(p)
        with self.assertRaises(safefs.UnsafePathError):
            safefs.open_dir(self.dir / "alias" / "new" / "dir", create=True)
        self.assertFalse((self.outside / "new").exists(), "a directory was created through the link")

    def test_create_never_writes_through_a_link_in_the_tree(self):
        with safefs.open_dir(self.dir) as d:
            self.link_or_skip(self.dir / "jn", self.outside)
            with self.assertRaises(safefs.UnsafePathError):
                d.child_dir("jn", create=True)
            self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ["secret.txt"])

    def test_open_read_refuses_directories(self):
        (self.dir / "adir").mkdir()
        with safefs.open_dir(self.dir) as d:
            with self.assertRaises((safefs.UnsafePathError, OSError)):
                d.open_read("adir")

    def test_open_relative_file_pins_intermediate_directories(self):
        (self.dir / "p" / "q").mkdir(parents=True)
        (self.dir / "p" / "q" / "f.txt").write_text("data")
        with safefs.open_dir(self.dir) as d:
            with safefs.open_relative_file(d, "p/q/f.txt") as fh:
                self.assertEqual(fh.read(), b"data")
            with self.assertRaises(FileNotFoundError):
                safefs.open_relative_file(d, "p/q/missing.txt")
            with self.assertRaises(safefs.UnsafePathError):
                safefs.open_relative_file(d, "p/../../etc/passwd")


@unittest.skipUnless(WIN and OK, "Windows handle-holding protection")
class WindowsHandleProtectionTests(SafeFsCase):
    """The protection itself: while we hold the directories, the ATTACKER's operations fail."""

    def test_held_chain_cannot_be_renamed_deleted_or_swapped_for_a_junction(self):
        (self.dir / "a" / "b").mkdir(parents=True)
        with safefs.open_dir(self.dir / "a" / "b"):
            for label, op in (("rmdir leaf", lambda: os.rmdir(self.dir / "a" / "b")),
                              ("rename leaf", lambda: os.rename(self.dir / "a" / "b", self.dir / "a" / "b2")),
                              ("rename ancestor", lambda: os.rename(self.dir / "a", self.dir / "a2"))):
                with self.assertRaises(PermissionError, msg=label):
                    op()
            self.assertTrue((self.dir / "a" / "b").is_dir())
        os.rename(self.dir / "a", self.dir / "a2")  # control: after release the same operation works

    def test_swap_for_junction_during_use_is_impossible_so_data_cannot_leave_the_tree(self):
        (self.dir / "ev").mkdir()
        with safefs.open_dir(self.dir / "ev") as d:
            with self.assertRaises(PermissionError):
                os.rmdir(self.dir / "ev")  # the first step of any swap
            with d.create_file("evidence.bin") as nf:
                nf.write(b"DATA")
                nf.commit()
        self.assertEqual((self.dir / "ev" / "evidence.bin").read_bytes(), b"DATA")
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ["secret.txt"])

    def test_open_file_cannot_be_deleted_or_replaced_by_name_while_we_hold_it(self):
        with safefs.open_dir(self.dir) as d:
            nf = d.create_file("evidence.bin")
            nf.write(b"DATA")
            with self.assertRaises(PermissionError):
                os.remove(self.dir / "evidence.bin")
            with self.assertRaises(OSError):
                os.replace(self.outside / "secret.txt", self.dir / "evidence.bin")
            nf.commit()
        self.assertEqual((self.dir / "evidence.bin").read_bytes(), b"DATA")
        self.assertEqual((self.outside / "secret.txt").read_text(), "TOPSECRET")

    def test_delete_on_close_removes_exactly_our_file_when_discarded(self):
        with safefs.open_dir(self.dir) as d:
            nf = d.create_file("temp.bin")
            nf.write(b"x")
            self.assertTrue((self.dir / "temp.bin").exists())
            nf.discard()
        self.assertFalse((self.dir / "temp.bin").exists())

    def test_unc_and_remote_paths_are_refused_without_any_network_access(self):
        with self.assertRaises(safefs.UnsupportedConfigurationError):
            safefs.open_dir(r"\\server\share\evidence")

    def test_noncanonical_path_is_refused(self):
        # a SUBST/short-name style alias: ask for the real directory through a different spelling of the SAME path
        (self.dir / "LongDirectoryName").mkdir()
        spelled = Path(str(self.dir / "LongDirectoryName").upper())
        with safefs.open_dir(spelled) as d:  # case differences are canonical on Windows and must be accepted
            self.assertTrue(d.path)


@unittest.skipUnless(not WIN and OK, "POSIX descriptor-relative behaviour")
class PosixRaceTests(SafeFsCase):
    def test_directory_swapped_for_a_symlink_while_held_cannot_redirect_writes(self):
        (self.dir / "ev").mkdir()
        with safefs.open_dir(self.dir / "ev") as d:
            os.rename(self.dir / "ev", self.dir / "ev_moved")        # attacker moves the real directory away ...
            os.symlink(str(self.outside), str(self.dir / "ev"))      # ... and puts a symlink in its place
            with d.create_file("evidence.bin") as nf:
                nf.write(b"DATA")
                nf.commit()
            self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ["secret.txt"], "data went through the swapped-in symlink")
            self.assertTrue((self.dir / "ev_moved" / "evidence.bin").exists())  # it went to the directory we actually opened
            with self.assertRaises(safefs.UnsafePathError):
                d.verify_bound()                                      # and the swap is detected, so the caller can invalidate the result

    def test_cleanup_never_unlinks_a_replacement_file(self):
        with safefs.open_dir(self.dir) as d:
            nf = d.create_file("final.bin")
            nf.write(b"ours")
            tmp = self.dir / nf._tmp
            tmp.unlink()                                  # attacker deletes our temporary file ...
            tmp.write_text("UNRELATED-FILE-OF-THE-OPERATOR")  # ... and plants an unrelated one under the same name
            nf.discard()
            self.assertEqual(tmp.read_text(), "UNRELATED-FILE-OF-THE-OPERATOR", "cleanup deleted a file that was not ours")

    def test_commit_never_replaces_an_existing_name(self):
        (self.dir / "final.bin").write_text("EXISTING")
        with safefs.open_dir(self.dir) as d:
            with self.assertRaises(FileExistsError):
                with d.create_file("final.bin") as nf:
                    nf.write(b"new")
                    nf.commit()
        self.assertEqual((self.dir / "final.bin").read_text(), "EXISTING")
        self.assertEqual([p.name for p in self.dir.iterdir() if p.name.startswith(".zdtmp")], [])

    def test_dangling_symlink_leaf_is_not_followed_on_create(self):
        os.symlink(str(self.dir / "nowhere"), str(self.dir / "final.bin"))
        with safefs.open_dir(self.dir) as d:
            with self.assertRaises(FileExistsError):
                with d.create_file("final.bin") as nf:
                    nf.write(b"x")
                    nf.commit()
        self.assertFalse((self.dir / "nowhere").exists())

    def test_symlinked_file_is_refused_for_read_and_append(self):
        os.symlink(str(self.outside / "secret.txt"), str(self.dir / "innocent.txt"))
        with safefs.open_dir(self.dir) as d:
            with self.assertRaises(safefs.UnsafePathError):
                d.open_read("innocent.txt")
            with self.assertRaises(safefs.UnsafePathError):
                d.open_append("innocent.txt")
        self.assertEqual((self.outside / "secret.txt").read_text(), "TOPSECRET")


if __name__ == "__main__":
    unittest.main()
