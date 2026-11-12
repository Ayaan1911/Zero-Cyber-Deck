import _isolation  # noqa: F401  (blocks real DNS/network for this process)
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

from linkutil import make_dir_link, make_file_symlink

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import evidence  # noqa: E402
import pathsafe  # noqa: E402
import report  # noqa: E402


class TmpCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        for f in self.dir.rglob("*"):
            if f.is_file() and not pathsafe.is_link(f):
                f.chmod(0o666)
        self._tmp.cleanup()

    def outside(self):
        out = self.dir / "outside"
        out.mkdir()
        (out / "secret.txt").write_text("TOPSECRET")
        return out

    def link_or_skip(self, link, target):
        if not make_dir_link(link, target):
            self.skipTest("neither symlinks nor junctions can be created here")


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

    def test_extra_file_alone_fails_verification(self):  # audit item 8
        self.make()
        (self.dir / "planted.exe").write_text("evil")
        self.assertEqual(evidence.main(["verify", str(self.manifest)]), 1)
        self.assertEqual(evidence.main(["verify", str(self.manifest), "--allow-extra"]), 0)

    def test_manifest_never_overwrites(self):  # audit item 9 (preserve existing evidence)
        self.make()
        before = self.manifest.read_text()
        (self.dir / "later.txt").write_text("l")
        with self.assertRaises(ValueError):
            evidence.write_manifest(self.dir, self.manifest)
        self.assertEqual(self.manifest.read_text(), before)
        self.assertEqual(evidence.main(["manifest", str(self.dir), str(self.manifest)]), 2)

    def test_path_traversal_and_malformed_manifest(self):
        m = self.dir / "m.sha256"
        for bad in ("0" * 64 + "  ../outside.txt\n", "not a hash line\n", "0" * 64 + "  /etc/passwd\n"):
            m.write_text(bad)
            with self.assertRaises(ValueError, msg=bad):
                evidence.verify_manifest(m)

    def test_manifest_refuses_junction_in_tree(self):  # audit item 2
        out = self.outside()
        tree = self.dir / "tree"
        tree.mkdir()
        (tree / "a.txt").write_text("a")
        self.link_or_skip(tree / "jn", out)
        with self.assertRaises(ValueError):
            evidence.write_manifest(tree, tree / "M.sha256")
        self.assertFalse((tree / "M.sha256").exists())

    def test_verify_rejects_manifest_entry_through_link(self):
        out = self.outside()
        tree = self.dir / "tree"
        tree.mkdir()
        self.link_or_skip(tree / "jn", out)
        digest = hashlib.sha256(b"TOPSECRET").hexdigest()
        m = tree / "M.sha256"
        m.write_text(f"{digest}  jn/secret.txt\n")
        with self.assertRaises(ValueError):
            evidence.verify_manifest(m)

    def test_verify_flags_link_as_unlisted(self):
        out = self.outside()
        tree = self.dir / "tree"
        tree.mkdir()
        (tree / "a.txt").write_text("a")
        m = tree / "M.sha256"
        evidence.write_manifest(tree, m)
        self.link_or_skip(tree / "jn", out)
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

    def test_refuses_junction_inside_source_and_copies_nothing(self):  # audit item 2 (source)
        out = self.outside()
        tree = self.dir / "case_tree"
        tree.mkdir()
        (tree / "ok.txt").write_text("ok")
        self.link_or_skip(tree / "jn", out)
        dest = self.dir / "ev"
        with self.assertRaises(ValueError):
            evidence.acquire(tree, dest, "C", "e")
        self.assertFalse(list(dest.rglob("*.txt")) if dest.exists() else [])

    def test_refuses_source_that_is_a_link(self):
        out = self.outside()
        link = self.dir / "srclink"
        self.link_or_skip(link, out)
        with self.assertRaises(ValueError):
            evidence.acquire(link, self.dir / "ev", "C", "e")

    def test_refuses_destination_component_junction(self):  # audit item 2 (destination)
        src = self.dir / "tree"
        src.mkdir()
        (src / "a.txt").write_text("a")
        dest = self.dir / "ev"
        dest.mkdir()
        elsewhere = self.dir / "elsewhere"
        elsewhere.mkdir()
        self.link_or_skip(dest / "tree", elsewhere)
        with self.assertRaises(ValueError):
            evidence.acquire(src, dest, "C", "e")
        self.assertEqual(list(elsewhere.rglob("*")), [])

    def test_refuses_destination_that_is_a_link(self):
        src = self.dir / "f.txt"
        src.write_text("x")
        real = self.dir / "real"
        real.mkdir()
        link = self.dir / "evlink"
        self.link_or_skip(link, real)
        with self.assertRaises(ValueError):
            evidence.acquire(src, link, "C", "e")
        self.assertEqual(list(real.rglob("*")), [])

    def test_refuses_file_symlink_in_source(self):
        src = self.dir / "tree"
        src.mkdir()
        target = self.dir / "secret.txt"
        target.write_text("s")
        if not make_file_symlink(src / "ln.txt", target):
            self.skipTest("file symlinks not permitted on this machine")
        with self.assertRaises(ValueError):
            evidence.acquire(src, self.dir / "ev", "C", "e")


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

    def test_reports_in_the_same_second_never_collide(self):  # audit item 9
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

    def test_report_does_not_follow_junctions(self):  # audit item 12
        res = self.dir / "results"
        res.mkdir()
        (res / "own.txt").write_text("own")
        self.link_or_skip(res / "jn", self.outside())
        text = report.build_report(res, None, "t", "o")
        self.assertIn("own.txt", text)
        self.assertNotIn("secret.txt", text)
        self.assertNotIn(hashlib.sha256(b"TOPSECRET").hexdigest(), text)
        self.assertIn("Skipped links", text)

    def test_report_does_not_read_symlinked_audit_log(self):
        res = self.dir / "results"
        res.mkdir()
        secret = self.dir / "secret.log"
        secret.write_text("TOPSECRET LINE")
        if not make_file_symlink(res / "audit.log", secret):
            self.skipTest("file symlinks not permitted on this machine")
        self.assertNotIn("TOPSECRET", report.build_report(res, None, "t", "o"))

    def test_report_does_not_hash_symlinked_file(self):
        res = self.dir / "results"
        res.mkdir()
        secret = self.dir / "secret.txt"
        secret.write_text("TOPSECRET")
        if not make_file_symlink(res / "innocent.txt", secret):
            self.skipTest("file symlinks not permitted on this machine")
        text = report.build_report(res, None, "t", "o")
        self.assertNotIn(hashlib.sha256(b"TOPSECRET").hexdigest(), text)


class PathSafeTests(TmpCase):
    def test_plain_paths_are_not_links(self):
        f = self.dir / "f"
        f.write_text("x")
        self.assertFalse(pathsafe.is_link(f))
        self.assertFalse(pathsafe.is_link(self.dir))
        self.assertFalse(pathsafe.is_link(self.dir / "missing"))

    def test_junction_detected(self):
        t = self.dir / "t"
        t.mkdir()
        self.link_or_skip(self.dir / "j", t)
        self.assertTrue(pathsafe.is_link(self.dir / "j"))
        with self.assertRaises(ValueError):
            pathsafe.reject_links_under(self.dir, "j/child")


if __name__ == "__main__":
    unittest.main()
