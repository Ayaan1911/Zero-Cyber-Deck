import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import evidence  # noqa: E402
import report  # noqa: E402


class TmpCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        for f in self.dir.rglob("*"):
            if f.is_file():
                f.chmod(0o666)
        self._tmp.cleanup()


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

    def test_detects_tamper_missing_extra(self):
        self.make()
        (self.dir / "one.txt").write_text("changed")
        (self.dir / "sub" / "two.txt").unlink()
        (self.dir / "new.txt").write_text("n")
        self.assertEqual(evidence.verify_manifest(self.manifest), (["one.txt"], ["sub/two.txt"], ["new.txt"]))
        self.assertEqual(evidence.main(["verify", str(self.manifest)]), 1)

    def test_path_traversal_and_malformed_manifest(self):
        m = self.dir / "m.sha256"
        m.write_text("0" * 64 + "  ../outside.txt\n")
        with self.assertRaises(ValueError):
            evidence.verify_manifest(m)
        m.write_text("not a hash line\n")
        with self.assertRaises(ValueError):
            evidence.verify_manifest(m)
        m.write_text("0" * 64 + "  /etc/passwd\n")
        with self.assertRaises(ValueError):
            evidence.verify_manifest(m)


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

    def test_cli_writes_file_and_excludes_old_reports(self):
        res = self.dir / "results"
        res.mkdir()
        self.assertEqual(report.main(["--results", str(res)]), 0)
        first = next(res.glob("report_*.md"))
        self.assertNotIn("report_", first.read_text().split("## Audit")[0].split("## Artifacts")[1])
        self.assertEqual(report.main(["--results", str(self.dir / "missing")]), 2)


if __name__ == "__main__":
    unittest.main()
