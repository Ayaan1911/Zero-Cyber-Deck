import _isolation  # noqa: F401  (blocks real DNS/network for this process)
import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from linkutil import make_dir_link, make_file_symlink

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import auditlog  # noqa: E402
import evidence  # noqa: E402
import report  # noqa: E402
import safefs  # noqa: E402

WIN = sys.platform == "win32"
OK, WHY = safefs.supported()


def attempt(fn):
    """Run an attacker's filesystem operation. Returns (succeeded, exception-or-None)."""
    try:
        fn()
        return True, None
    except OSError as exc:
        return False, exc


@unittest.skipUnless(OK, WHY or "unsupported platform")
class TmpCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name).resolve()  # a real path: the code under test refuses links anywhere above its inputs
        evidence._race_hook = None
        auditlog._race_hook = None

    def tearDown(self):
        evidence._race_hook = None
        auditlog._race_hook = None
        for f in self.dir.rglob("*"):
            if f.is_file() and not f.is_symlink():
                try:
                    f.chmod(0o666)
                except OSError:
                    pass
        self._tmp.cleanup()

    def outside(self):
        out = self.dir / "outside"
        out.mkdir()
        (out / "secret.txt").write_text("TOPSECRET")
        return out

    def link_or_skip(self, link, target):
        if not make_dir_link(link, target):
            self.skipTest("neither symlinks nor junctions can be created here")

    def only_secret(self, outside):
        return sorted(p.name for p in outside.iterdir()) == ["secret.txt"] and (outside / "secret.txt").read_text() == "TOPSECRET"


class HashTests(TmpCase):
    def test_hash_matches_hashlib(self):
        f = self.dir / "a.bin"
        f.write_bytes(b"abc" * 1000)
        self.assertEqual(evidence.sha256_file(f), hashlib.sha256(b"abc" * 1000).hexdigest())

    def test_verify_file_cli(self):
        f = self.dir / "a"
        f.write_bytes(b"x")
        good = hashlib.sha256(b"x").hexdigest()
        self.assertEqual(evidence.main(["verify-file", str(f), good.upper()]), 0)
        self.assertEqual(evidence.main(["verify-file", str(f), "0" * 64]), 1)
        self.assertEqual(evidence.main(["verify-file", str(f), "nothex"]), 2)

    def test_missing_file_is_error_not_crash(self):
        self.assertEqual(evidence.main(["hash", str(self.dir / "none")]), 2)

    def test_hash_refuses_a_link(self):
        self.link_or_skip(self.dir / "alias", self.outside())
        self.assertEqual(evidence.main(["hash", str(self.dir / "alias" / "secret.txt")]), 2)


class ManifestTests(TmpCase):
    def make(self):
        (self.dir / "sub").mkdir()
        (self.dir / "one.txt").write_text("1")
        (self.dir / "sub" / "two.txt").write_text("2")
        self.manifest = self.dir / "MANIFEST.sha256"
        return evidence.write_manifest(self.dir, self.manifest)

    def test_roundtrip_and_format(self):
        self.assertEqual(self.make(), 2)
        self.assertIn("  sub/two.txt", self.manifest.read_text())
        self.assertEqual(evidence.verify_manifest(self.manifest), ([], [], []))
        self.assertEqual(evidence.main(["verify", str(self.manifest)]), 0)

    def test_detects_tamper_missing_extra(self):
        self.make()
        (self.dir / "one.txt").write_text("changed")
        (self.dir / "sub" / "two.txt").unlink()
        (self.dir / "new.txt").write_text("n")
        self.assertEqual(evidence.verify_manifest(self.manifest), (["one.txt"], ["sub/two.txt"], ["new.txt"]))
        self.assertEqual(evidence.main(["verify", str(self.manifest)]), 1)

    def test_extra_file_alone_fails_verification(self):
        self.make()
        (self.dir / "planted.exe").write_text("evil")
        self.assertEqual(evidence.main(["verify", str(self.manifest)]), 1)
        self.assertEqual(evidence.main(["verify", str(self.manifest), "--allow-extra"]), 0)

    def test_manifest_never_overwrites(self):
        self.make()
        before = self.manifest.read_text()
        (self.dir / "later.txt").write_text("l")
        with self.assertRaises(ValueError):
            evidence.write_manifest(self.dir, self.manifest)
        self.assertEqual(self.manifest.read_text(), before)
        self.assertEqual(evidence.main(["manifest", str(self.dir), str(self.manifest)]), 2)

    def test_path_traversal_and_malformed_manifest(self):
        m = self.dir / "m.sha256"
        for bad in ("0" * 64 + "  ../outside.txt\n", "not a hash line\n", "0" * 64 + "  /etc/passwd\n", "0" * 64 + "  a/../../b\n"):
            m.write_text(bad)
            with self.assertRaises(ValueError, msg=bad):
                evidence.verify_manifest(m)

    def test_manifest_refuses_a_link_inside_the_tree(self):
        tree = self.dir / "tree"
        tree.mkdir()
        (tree / "a.txt").write_text("a")
        self.link_or_skip(tree / "jn", self.outside())
        with self.assertRaises(ValueError):
            evidence.write_manifest(tree, tree / "M.sha256")
        self.assertFalse((tree / "M.sha256").exists())

    def test_verify_rejects_manifest_entry_through_link(self):
        out = self.outside()
        tree = self.dir / "tree"
        tree.mkdir()
        self.link_or_skip(tree / "jn", out)
        m = tree / "M.sha256"
        m.write_text(f"{hashlib.sha256(b'TOPSECRET').hexdigest()}  jn/secret.txt\n")
        with self.assertRaises(ValueError):
            evidence.verify_manifest(m)

    def test_verify_flags_link_as_unlisted(self):
        tree = self.dir / "tree"
        tree.mkdir()
        (tree / "a.txt").write_text("a")
        m = tree / "M.sha256"
        evidence.write_manifest(tree, m)
        self.link_or_skip(tree / "jn", self.outside())
        self.assertEqual(evidence.verify_manifest(m)[2], ["jn"])
        self.assertEqual(evidence.main(["verify", str(m)]), 1)


class AcquireTests(TmpCase):
    def test_acquire_file_and_tree(self):
        src = self.dir / "case_src"
        (src / "d").mkdir(parents=True)
        (src / "a.txt").write_text("alpha")
        (src / "d" / "b.txt").write_text("beta")
        dest = self.dir / "evidence"
        self.assertEqual(evidence.acquire(src, dest, "C-1", "tester"), 2)
        self.assertEqual((dest / "case_src" / "d" / "b.txt").read_text(), "beta")
        lines = (dest / "custody.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn('"case": "C-1"', lines[0])
        self.assertEqual((src / "a.txt").read_text(), "alpha")  # source untouched
        self.assertEqual([p.name for p in dest.rglob("*") if p.name.startswith(".zdtmp")], [])
        self.assertEqual(evidence.acquire(src / "a.txt", self.dir / "ev_file", "C-2", "t"), 1)

    def test_copies_are_hash_verified_and_read_only(self):
        f = self.dir / "f.bin"
        f.write_bytes(os.urandom(300000))
        dest = self.dir / "ev"
        evidence.acquire(f, dest, "C", "e")
        self.assertEqual(hashlib.sha256((dest / "f.bin").read_bytes()).hexdigest(), hashlib.sha256(f.read_bytes()).hexdigest())
        with self.assertRaises(PermissionError):
            (dest / "f.bin").open("ab")

    def test_refuses_overwrite_and_nested_dest(self):
        f = self.dir / "f.txt"
        f.write_text("x")
        dest = self.dir / "ev"
        evidence.acquire(f, dest, "C", "e")
        with self.assertRaises(ValueError):
            evidence.acquire(f, dest, "C", "e")
        src = self.dir / "tree"
        src.mkdir()
        with self.assertRaises(ValueError):
            evidence.acquire(src, src / "inside", "C", "e")

    def test_missing_source(self):
        self.assertEqual(evidence.main(["acquire", str(self.dir / "no"), str(self.dir / "d"), "--case", "c", "--examiner", "e"]), 2)

    def test_refuses_link_inside_source_before_copying_anything(self):
        tree = self.dir / "case_tree"
        tree.mkdir()
        (tree / "ok.txt").write_text("ok")
        self.link_or_skip(tree / "jn", self.outside())
        with self.assertRaises(ValueError):
            evidence.acquire(tree, self.dir / "ev", "C", "e")
        self.assertEqual(list((self.dir / "ev").rglob("*.txt")) if (self.dir / "ev").exists() else [], [])

    def test_refuses_source_that_is_a_link(self):
        link = self.dir / "srclink"
        self.link_or_skip(link, self.outside())
        with self.assertRaises(ValueError):
            evidence.acquire(link, self.dir / "ev", "C", "e")

    def test_refuses_destination_component_link_and_link_destination(self):
        src = self.dir / "tree"
        src.mkdir()
        (src / "a.txt").write_text("a")
        dest, elsewhere = self.dir / "ev", self.dir / "elsewhere"
        dest.mkdir()
        elsewhere.mkdir()
        self.link_or_skip(dest / "tree", elsewhere)
        with self.assertRaises(ValueError):
            evidence.acquire(src, dest, "C", "e")
        real, link = self.dir / "real", self.dir / "evlink"
        real.mkdir()
        self.link_or_skip(link, real)
        with self.assertRaises(ValueError):
            evidence.acquire(src, link, "C", "e")
        self.assertEqual((list(elsewhere.rglob("*")), list(real.rglob("*"))), ([], []))

    def test_refuses_file_symlink_in_source(self):
        src = self.dir / "tree"
        src.mkdir()
        target = self.dir / "secret.txt"
        target.write_text("s")
        if not make_file_symlink(src / "ln.txt", target):
            self.skipTest("file symlinks not permitted on this machine")
        with self.assertRaises(ValueError):
            evidence.acquire(src, self.dir / "ev", "C", "e")


class AncestorLinkTests(TmpCase):
    """A link in an ANCESTOR component must never redirect reads or writes."""

    def alias(self):
        outside = self.outside()
        alias = self.dir / "alias"
        self.link_or_skip(alias, outside)
        return alias, outside

    def test_acquire_destination_behind_ancestor_link_is_refused(self):
        alias, outside = self.alias()
        src = self.dir / "ev_src.txt"
        src.write_text("evidence")
        for dest in (alias / "ev", alias / "a" / "b" / "ev"):
            with self.assertRaises(ValueError):
                evidence.acquire(src, dest, "C", "e")
        self.assertTrue(self.only_secret(outside), "evidence was written through the ancestor link")

    def test_acquire_source_behind_ancestor_link_is_refused(self):
        alias, outside = self.alias()
        (outside / "case").mkdir()
        (outside / "case" / "x.txt").write_text("x")
        with self.assertRaises(ValueError):
            evidence.acquire(alias / "case", self.dir / "ev", "C", "e")

    def test_manifest_verify_and_report_behind_ancestor_link_are_refused(self):
        alias, outside = self.alias()
        (outside / "case").mkdir()
        (outside / "case" / "x.txt").write_text("x")
        with self.assertRaises(ValueError):
            evidence.write_manifest(alias / "case", self.dir / "m.sha256")
        evidence.write_manifest(outside / "case", outside / "case" / "M.sha256")
        with self.assertRaises(ValueError):
            evidence.verify_manifest(alias / "case" / "M.sha256")
        with self.assertRaises(ValueError):
            evidence.write_manifest(self.dir, alias / "M2.sha256")
        self.assertFalse((outside / "M2.sha256").exists())
        self.assertEqual(report.main(["--results", str(alias / "case")]), 2)
        real = self.dir / "res"
        real.mkdir()
        self.assertEqual(report.main(["--results", str(real), "--out", str(alias / "out.md")]), 2)
        self.assertFalse((outside / "out.md").exists())

    def test_lexical_dotdot_cannot_hide_a_link(self):
        alias, outside = self.alias()
        with self.assertRaises(ValueError):
            evidence.acquire(self.dir / "f.txt", alias / ".." / "alias" / "ev", "C", "e")


class RaceTests(TmpCase):
    """The audited failures: a link introduced AFTER validation, and cleanup deleting a replacement file."""

    def test_source_link_introduced_between_validation_and_copy_is_not_followed(self):
        src = self.dir / "case"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "a.txt").write_text("LEGIT")
        outside = self.outside()
        (outside / "a.txt").write_text("FOREIGN-SECRET")

        def swap(stage, **ctx):
            if stage != "between-passes":
                return
            shutil.rmtree(src / "sub")
            if not make_dir_link(src / "sub", outside):
                raise unittest.SkipTest("neither symlinks nor junctions can be created here")
        evidence._race_hook = swap
        with self.assertRaises(ValueError):
            evidence.acquire(src, self.dir / "ev", "C", "e")
        copied = [p.read_text() for p in (self.dir / "ev").rglob("a.txt")] if (self.dir / "ev").exists() else []
        self.assertNotIn("FOREIGN-SECRET", copied)
        self.assertEqual((outside / "a.txt").read_text(), "FOREIGN-SECRET")

    def test_attack_while_the_source_is_open_cannot_change_what_is_copied(self):
        src = self.dir / "case"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "a.txt").write_text("LEGIT")
        outside = self.outside()
        (outside / "a.txt").write_text("FOREIGN-SECRET")
        outcome = {}

        def attack(stage, **ctx):
            if stage == "after-open-source" and not outcome:
                moved, e1 = attempt(lambda: os.rename(src / "sub", src / "sub_moved"))       # step 1 of any swap
                if moved:
                    attempt(lambda: make_dir_link(src / "sub", outside))                   # step 2: put a link in its place
                outcome["moved"] = moved
        evidence._race_hook = attack
        evidence.acquire(src, self.dir / "ev", "C", "e")
        copied = (self.dir / "ev" / "case" / "sub" / "a.txt").read_text()
        self.assertEqual(copied, "LEGIT", "the copy followed the attacker's replacement")
        if WIN:
            self.assertFalse(outcome["moved"], "Windows: the held source directory must not be renameable while we use it")
        self.assertEqual((outside / "a.txt").read_text(), "FOREIGN-SECRET")

    def test_failed_copy_cleanup_never_removes_a_replacement_file(self):
        f = self.dir / "one.bin"
        f.write_bytes(b"EVIDENCE")
        dest = self.dir / "ev"
        planted = {}

        def hostile(stage, new_file=None, dst_dir=None, name=None, **ctx):
            if stage != "before-commit":
                return
            if WIN:
                ok, exc = attempt(lambda: os.remove(dest / "one.bin"))
                planted["removed_by_attacker"] = ok  # must be blocked: we hold the file without share-delete
            else:
                tmp = dest / new_file._tmp
                tmp.unlink()
                tmp.write_text("UNRELATED-FILE-OF-THE-OPERATOR")
                planted["path"] = tmp
            raise RuntimeError("injected failure after the data was written")
        evidence._race_hook = hostile
        with self.assertRaises(RuntimeError):
            evidence.acquire(f, dest, "C", "e")
        if WIN:
            self.assertFalse(planted["removed_by_attacker"])
            self.assertFalse((dest / "one.bin").exists(), "our uncommitted file must be gone")
        else:
            self.assertEqual(planted["path"].read_text(), "UNRELATED-FILE-OF-THE-OPERATOR", "cleanup deleted a file that was not ours")
            self.assertFalse((dest / "one.bin").exists())
        self.assertEqual(f.read_bytes(), b"EVIDENCE")

    @unittest.skipIf(WIN, "on Windows the swap itself is impossible (see test_destination_cannot_be_swapped_on_windows)")
    def test_destination_swapped_during_acquisition_is_detected_and_nothing_leaks(self):
        f = self.dir / "one.bin"
        f.write_bytes(b"EVIDENCE")
        dest = self.dir / "ev"
        outside = self.outside()

        def swap(stage, **ctx):
            if stage == "after-create-dest":
                os.rename(dest, self.dir / "ev_moved")
                os.symlink(str(outside), str(dest))
        evidence._race_hook = swap
        with self.assertRaises(ValueError):
            evidence.acquire(f, dest, "C", "e")
        self.assertTrue(self.only_secret(outside), "evidence leaked through the swapped-in symlink")

    @unittest.skipUnless(WIN, "Windows handle-holding protection")
    def test_destination_cannot_be_swapped_on_windows(self):
        f = self.dir / "one.bin"
        f.write_bytes(b"EVIDENCE")
        dest = self.dir / "ev"
        result = {}

        def swap(stage, **ctx):
            if stage == "after-create-dest":
                result["rename"] = attempt(lambda: os.rename(dest, self.dir / "ev_moved"))[0]
                result["rmdir"] = attempt(lambda: os.rmdir(dest))[0]
        evidence._race_hook = swap
        evidence.acquire(f, dest, "C", "e")
        self.assertEqual(result, {"rename": False, "rmdir": False})
        self.assertEqual((dest / "one.bin").read_bytes(), b"EVIDENCE")


class AuditWriterRaceTests(TmpCase):
    def test_results_folder_swap_during_append_cannot_redirect_the_row(self):
        outside = self.outside()
        results = self.dir / "results"
        results.mkdir()
        result = {}

        def swap(directory):
            ok, _ = attempt(lambda: os.rename(results, self.dir / "results_moved"))
            result["renamed"] = ok
            if ok:
                try:
                    os.symlink(str(outside), str(results))
                except OSError:
                    make_dir_link(results, outside)
        auditlog._race_hook = swap
        row = auditlog.format_row("a", "host", "1.2.3.4", "ALLOW", "d")
        if WIN:
            auditlog.append_row(results, row)
            self.assertFalse(result["renamed"], "Windows: the held results folder must not be renameable")
            self.assertIn("ALLOW", (results / "audit.log").read_text())
        else:
            with self.assertRaises(ValueError):
                auditlog.append_row(results, row)  # detected: the folder at the path is no longer the one we wrote into
        self.assertTrue(self.only_secret(outside), "an audit row was written through the swapped-in link")

    def test_missing_results_folder_is_not_created_implicitly(self):
        with self.assertRaises(OSError):
            auditlog.append_row(self.dir / "does_not_exist", "row")
        self.assertFalse((self.dir / "does_not_exist").exists())

    def test_ancestor_link_in_results_path_is_refused(self):
        outside = self.outside()
        (outside / "results").mkdir()
        self.link_or_skip(self.dir / "alias", outside)
        with self.assertRaises(ValueError):
            auditlog.append_row(self.dir / "alias" / "results", "row")
        self.assertFalse((outside / "results" / "audit.log").exists())

    def test_cli_exit_codes(self):
        self.assertEqual(auditlog.main(["append", "--results", str(self.dir / "nope"), "--action=a", "--kind=k", "--verdict=V"]), 2)
        (self.dir / "res").mkdir()
        self.assertEqual(auditlog.main(["append", "--results", str(self.dir / "res"), "--action=a", "--kind=url", "--target=https://h/p?SECRETVALUE", "--verdict=V"]), 0)
        text = (self.dir / "res" / "audit.log").read_text()
        self.assertNotIn("SECRETVALUE", text)
        self.assertEqual(len(text.splitlines()), 1)


class ReportTests(TmpCase):
    def test_report_contents(self):
        res = self.dir / "results"
        res.mkdir()
        (res / "20250101T000000Z_dns.txt").write_text("a|b")
        (res / "audit.log").write_text("t\tu\ta\thost\t1.2.3.4\tALLOW\th\td\n")
        (res / "README.md").write_text("ignored")
        out = report.build_report(res, None, "T | x", "op\nerator")
        self.assertIn("20250101T000000Z_dns.txt", out)
        self.assertIn(hashlib.sha256(b"a|b").hexdigest(), out)
        self.assertIn("ALLOW", out)
        self.assertNotIn("ignored", out)
        self.assertIn("# T \\| x", out)
        self.assertIn("UNENCRYPTED", out)
        self.assertIn("not tamper-proof", out)

    def test_cli_writes_file_and_excludes_old_reports(self):
        res = self.dir / "results"
        res.mkdir()
        self.assertEqual(report.main(["--results", str(res)]), 0)
        first = next(res.glob("report_*.md"))
        self.assertNotIn("report_", first.read_text().split("## Audit")[0].split("## Artifacts")[1])
        self.assertEqual(report.main(["--results", str(self.dir / "missing")]), 2)

    def test_reports_in_the_same_second_never_collide(self):
        res = self.dir / "results"
        res.mkdir()
        for _ in range(4):
            self.assertEqual(report.main(["--results", str(res)]), 0)
        self.assertEqual(len(list(res.glob("report_*.md"))), 4)

    def test_explicit_out_is_never_overwritten(self):
        res = self.dir / "results"
        res.mkdir()
        out = self.dir / "mine.md"
        out.write_text("PRECIOUS")
        self.assertEqual(report.main(["--results", str(res), "--out", str(out)]), 2)
        self.assertEqual(out.read_text(), "PRECIOUS")

    def test_report_does_not_follow_links(self):
        res = self.dir / "results"
        res.mkdir()
        (res / "own.txt").write_text("own")
        self.link_or_skip(res / "jn", self.outside())
        text = report.build_report(res, None, "t", "o")
        self.assertIn("own.txt", text)
        self.assertNotIn("secret.txt", text)
        self.assertNotIn(hashlib.sha256(b"TOPSECRET").hexdigest(), text)
        self.assertIn("Skipped links", text)

    def test_report_does_not_read_or_hash_symlinked_files(self):
        res = self.dir / "results"
        res.mkdir()
        secret = self.dir / "secret.log"
        secret.write_text("TOPSECRET LINE")
        if not make_file_symlink(res / "audit.log", secret) or not make_file_symlink(res / "innocent.txt", secret):
            self.skipTest("file symlinks not permitted on this machine")
        text = report.build_report(res, None, "t", "o")
        self.assertNotIn("TOPSECRET", text)
        self.assertNotIn(hashlib.sha256(b"TOPSECRET LINE").hexdigest(), text)


if __name__ == "__main__":
    unittest.main()
