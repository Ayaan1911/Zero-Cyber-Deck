"""Windows PowerShell checks for the companion menu. Skipped where powershell.exe is unavailable.

SAFETY: no USB or physical disk is touched. python children get the offline DNS sandbox (tests/support/sitecustomize.py);
the menu is only driven through paths that stop before any network command (traceroute/Resolve-DnsName never run; denied,
cancelled or refused inputs only). The application folder is a disposable copy, the data folder a disposable sibling.
"""
import _isolation  # noqa: F401  (blocks real DNS/network for this process)
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from linkutil import make_dir_link

ROOT = Path(__file__).resolve().parents[1]
SUPPORT = ROOT / "tests" / "support"
PS = (shutil.which("powershell") or shutil.which("powershell.exe")) if sys.platform == "win32" else None  # WSL interop would run the Windows binary on Linux paths
SCRIPTS = [ROOT / "Start-ZeroDeck.ps1", ROOT / "Install-ZeroDeck.ps1"]
INSTALL = ROOT / "Install-ZeroDeck.ps1"


def ps(*args, stdin=None, env_extra=None, timeout=240):
    env = dict(os.environ, PYTHONPATH=str(SUPPORT), ZD_FAKE_DNS="", PYTHONDONTWRITEBYTECODE="1")
    env.pop("ZD_DATA", None)
    env.update(env_extra or {})
    return subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", *args], input=stdin, capture_output=True,
                          text=True, timeout=timeout, env=env)


@unittest.skipUnless(PS, "powershell.exe not available")
class WindowsCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.deck = self.tmp / "ZERO-Deck"       # application folder (disposable copy)
        self.data = self.tmp / "ZERO-DATA"       # sibling data folder (the default location)

    def tearDown(self):
        self._tmp.cleanup()

    def deck_copy(self, scope="192.168.56.0/24\n", init_data=True):
        shutil.copytree(ROOT / "scripts", self.deck / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        (self.deck / "config").mkdir()
        (self.deck / "config" / "scope.txt").write_text("# release template: empty\n")
        shutil.copy(ROOT / "Start-ZeroDeck.ps1", self.deck)
        shutil.copy(ROOT / "DATA_FORMAT", self.deck)
        if init_data:
            subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "datadir.py"), "init", "--data", str(self.data), "--app", str(self.deck)],
                           check=True, capture_output=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
            if scope is not None:
                (self.data / "config" / "scope.local.txt").write_text(scope)
        return self.deck

    def script(self, body):
        f = self.tmp / "case.ps1"
        f.write_text(body, encoding="ascii")
        return ps("-File", str(f))

    def link_or_skip(self, link, target):
        if not make_dir_link(link, target):
            self.skipTest("neither symlinks nor junctions can be created here")

    def run_menu(self, answers, **env):
        return ps("-File", str(self.deck / "Start-ZeroDeck.ps1"), stdin=answers, env_extra=dict(ZD_DNSLOG=str(self.tmp / "dns.log"), **env))

    def audit_verdicts(self):
        log = self.data / "results" / "audit.log"
        return [line.split("\t")[5] for line in log.read_text().splitlines()] if log.exists() else []


class SyntaxTests(WindowsCase):
    def test_scripts_parse_and_are_ascii(self):
        for s in SCRIPTS:
            s.read_bytes().decode("ascii")  # PS 5.1 misreads BOM-less UTF-8 non-ASCII
            cmd = (f"$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('{s}',[ref]$t,[ref]$e);"
                   "$e.Count")
            self.assertEqual(ps("-Command", cmd).stdout.strip(), "0", s.name)


class CheckModeTests(WindowsCase):
    def check(self):
        return ps("-File", str(self.deck / "Start-ZeroDeck.ps1"), "-Check")

    def test_check_ok(self):
        self.deck_copy()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("scope OK", r.stdout)
        self.assertIn("data folder", r.stdout)

    def test_check_fails_with_invalid_scope_file(self):
        self.deck_copy(scope="this is not a valid entry\n")
        r = self.check()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("invalid scope entry", r.stdout + r.stderr)

    def test_check_fails_when_the_data_folder_was_never_initialised_and_does_not_create_it(self):
        self.deck_copy(init_data=False)
        r = self.check()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("data folder not ready", r.stdout)
        self.assertIn("-InitData", r.stdout)
        self.assertFalse(self.data.exists(), "-Check must never create the data folder")

    def test_check_fails_for_a_newer_data_format(self):
        self.deck_copy()
        (self.data / ".zerodeck-data").write_text("format=9\n")
        r = self.check()
        self.assertEqual(r.returncode, 1)
        self.assertIn("do not downgrade", r.stdout)

    def test_check_fails_with_missing_template_when_no_operator_scope_exists(self):
        self.deck_copy(scope=None)
        (self.deck / "config" / "scope.txt").unlink()
        self.assertEqual(self.check().returncode, 1)

    def test_a_scope_file_inside_the_application_folder_is_ignored(self):
        self.deck_copy()
        (self.deck / "config" / "scope.local.txt").write_text("bad old-layout entry\n")  # old layout: must not be read
        self.assertEqual(self.check().returncode, 0)

    def test_operator_scope_in_the_data_folder_is_used(self):
        self.deck_copy(scope="bad operator entry\n")
        self.assertEqual(self.check().returncode, 1)


class InitDataTests(WindowsCase):
    def test_initdata_creates_the_folder_and_is_idempotent(self):
        self.deck_copy(init_data=False)
        r = ps("-File", str(self.deck / "Start-ZeroDeck.ps1"), "-InitData")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((self.data / ".zerodeck-data").is_file())
        (self.data / "results" / "keep.txt").write_text("mine")
        self.assertEqual(ps("-File", str(self.deck / "Start-ZeroDeck.ps1"), "-InitData").returncode, 0)
        self.assertEqual((self.data / "results" / "keep.txt").read_text(), "mine")

    def test_initdata_refuses_to_adopt_a_foreign_folder(self):
        self.deck_copy(init_data=False)
        self.data.mkdir()
        (self.data / "someone_elses.txt").write_text("x")
        r = ps("-File", str(self.deck / "Start-ZeroDeck.ps1"), "-InitData")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(sorted(p.name for p in self.data.iterdir()), ["someone_elses.txt"])


class MenuGateTests(WindowsCase):
    def test_gate_denies_and_cancels_without_running(self):
        self.deck_copy()
        r = self.run_menu("3\n8.8.8.8\n\n3\n192.168.56.5;calc\n\n3\n192.168.56.5\nno\n\n0\n")
        self.assertNotIn("Tracing route", r.stdout + r.stderr)
        self.assertEqual(self.audit_verdicts(), ["DENY", "ERROR", "PRECHECK", "CANCELLED"], r.stdout)

    def test_no_dns_lookup_before_confirmation(self):
        self.deck_copy(scope="192.168.56.0/24\nlab.example\n")
        self.run_menu("2\nlab.example\nno\n\n0\n", ZD_FAKE_DNS="lab.example=192.168.56.10")
        self.assertFalse((self.tmp / "dns.log").exists(), "a name was resolved before the operator confirmed")

    def test_unlisted_name_denied_without_lookup(self):
        self.deck_copy(scope="192.168.56.0/24\nlab.example\n")
        self.run_menu("2\nother.example\n\n0\n", ZD_FAKE_DNS="other.example=192.168.56.10")  # denied: no YES prompt appears
        self.assertFalse((self.tmp / "dns.log").exists())

    def test_audit_failure_stops_inventory(self):
        self.deck_copy()
        (self.data / "results" / "audit.log").mkdir()
        r = self.run_menu("1\n\n0\n")
        self.assertIn("AUDIT WRITE FAILED", r.stdout + r.stderr)
        self.assertEqual(list((self.data / "results").glob("*win_local_inventory*")), [])

    def test_audit_failure_stops_gate_before_any_network_command(self):
        self.deck_copy()
        (self.data / "results" / "audit.log").mkdir()
        r = self.run_menu("3\n192.168.56.5\n\n0\n")
        self.assertNotIn("Tracing route", r.stdout + r.stderr)
        self.assertNotIn("Verified target", r.stdout)

    def test_everything_refuses_when_the_data_folder_is_not_initialised(self):
        self.deck_copy(init_data=False)
        r = self.run_menu("1\n\n4\nC:\\nonexistent\n\n0\n")
        self.assertIn("Data folder not ready", r.stdout)
        self.assertIn("AUDIT UNAVAILABLE", r.stdout)
        self.assertFalse(self.data.exists(), "the data folder must never be created implicitly")

    def test_unique_output_names(self):
        self.deck_copy()
        f = self.tmp / "f.txt"
        f.write_text("x")
        self.run_menu("4\n{0}\n\n4\n{0}\n\n0\n".format(f))
        self.assertEqual(len(list((self.data / "results").glob("*win_sha256*"))), 2)

    def test_sha256_report_is_audited_before_it_is_written(self):  # post-remediation audit finding
        self.deck_copy()
        f = self.tmp / "f.txt"
        f.write_text("x")
        self.run_menu("4\n{0}\n\n0\n".format(f))
        log = (self.data / "results" / "audit.log").read_text().splitlines()
        self.assertTrue(any("\twin_sha256\t" in line and "\tRUN\t" in line for line in log))

    def test_audit_rows_are_written_by_the_shared_writer_and_stay_single_line(self):
        self.deck_copy()
        self.run_menu("1\n\n0\n")
        rows = [line.split("\t") for line in (self.data / "results" / "audit.log").read_text().splitlines()]
        self.assertTrue(rows and all(len(r) == 8 for r in rows), rows)

    def test_the_application_folder_is_never_written_by_a_session(self):
        self.deck_copy()
        before = sorted(str(p.relative_to(self.deck)) for p in self.deck.rglob("*"))
        self.run_menu("1\n\n6\n\n7\n\n8\n\n0\n")
        after = sorted(str(p.relative_to(self.deck)) for p in self.deck.rglob("*"))
        self.assertEqual(after, before)
        self.assertTrue(list((self.data / "results").glob("triage_*")))
        self.assertTrue(list((self.data / "results").glob("report_*.md")))


if __name__ == "__main__":
    unittest.main()
