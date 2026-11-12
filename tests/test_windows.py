"""Windows PowerShell checks. Skipped where powershell.exe is unavailable.

SAFETY: no USB or physical disk is touched. Disk/volume queries are replaced by a mocked Get-UsbTarget; deployment
logic runs only against temp folders; python children get the offline DNS sandbox (tests/support/sitecustomize.py);
the menu is only driven through paths that stop before any network command (traceroute/Resolve-DnsName never run).
"""
import _isolation  # noqa: F401  (blocks real DNS/network for this process)
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from linkutil import make_dir_link

ROOT = Path(__file__).resolve().parents[1]
SUPPORT = ROOT / "tests" / "support"
PS = shutil.which("powershell") or shutil.which("powershell.exe")
SCRIPTS = [ROOT / "Start-ZeroDeck.ps1", ROOT / "Install-ZeroDeck.ps1"]
INSTALL = ROOT / "Install-ZeroDeck.ps1"


def ps(*args, stdin=None, env_extra=None, timeout=240):
    env = dict(os.environ, PYTHONPATH=str(SUPPORT), ZD_FAKE_DNS="", PYTHONDONTWRITEBYTECODE="1")
    env.update(env_extra or {})
    return subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", *args], input=stdin, capture_output=True,
                          text=True, timeout=timeout, env=env)


@unittest.skipUnless(PS, "powershell.exe not available")
class WindowsCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def deck_copy(self, scope="192.168.56.0/24\n"):
        deck = self.tmp / "deck"
        shutil.copytree(ROOT / "scripts", deck / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        (deck / "config").mkdir()
        (deck / "config" / "scope.txt").write_text(scope)
        shutil.copy(ROOT / "Start-ZeroDeck.ps1", deck)
        return deck

    def script(self, body):
        """Run a throwaway .ps1 (ASCII) so quoting never depends on -Command parsing."""
        f = self.tmp / "case.ps1"
        f.write_text(body, encoding="ascii")
        return ps("-File", str(f))

    def link_or_skip(self, link, target):
        if not make_dir_link(link, target):
            self.skipTest("neither symlinks nor junctions can be created here")


class SyntaxTests(WindowsCase):
    def test_scripts_parse_and_are_ascii(self):
        for s in SCRIPTS:
            s.read_bytes().decode("ascii")  # PS 5.1 misreads BOM-less UTF-8 non-ASCII
            cmd = (f"$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('{s}',[ref]$t,[ref]$e);"
                   "$e.Count")
            self.assertEqual(ps("-Command", cmd).stdout.strip(), "0", s.name)


class CheckModeTests(WindowsCase):
    def test_check_ok(self):
        deck = self.deck_copy()
        r = ps("-File", str(deck / "Start-ZeroDeck.ps1"), "-Check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("scope OK", r.stdout)

    def test_check_fails_with_invalid_scope_file(self):  # audit item 11
        deck = self.deck_copy(scope="this is not a valid entry\n")
        r = ps("-File", str(deck / "Start-ZeroDeck.ps1"), "-Check")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("invalid scope entry", r.stdout + r.stderr)

    def test_check_fails_with_missing_scope_file(self):
        deck = self.deck_copy()
        (deck / "config" / "scope.txt").unlink()
        self.assertEqual(ps("-File", str(deck / "Start-ZeroDeck.ps1"), "-Check").returncode, 1)

    def test_check_prefers_untracked_local_scope(self):
        deck = self.deck_copy()
        (deck / "config" / "scope.local.txt").write_text("bad local entry\n")
        self.assertEqual(ps("-File", str(deck / "Start-ZeroDeck.ps1"), "-Check").returncode, 1)


class MenuGateTests(WindowsCase):
    def run_menu(self, deck, answers, **env):
        return ps("-File", str(deck / "Start-ZeroDeck.ps1"), stdin=answers, env_extra=dict(ZD_DNSLOG=str(self.tmp / "dns.log"), **env))

    def test_gate_denies_and_cancels_without_running(self):
        deck = self.deck_copy()
        answers = "3\n8.8.8.8\n\n3\n192.168.56.5;calc\n\n3\n192.168.56.5\nno\n\n0\n"
        r = self.run_menu(deck, answers)
        self.assertNotIn("Tracing route", r.stdout + r.stderr)
        verdicts = [line.split("\t")[5] for line in (deck / "results" / "audit.log").read_text().splitlines()]
        self.assertEqual(verdicts, ["DENY", "ERROR", "PRECHECK", "CANCELLED"], r.stdout)

    def test_no_dns_lookup_before_confirmation(self):  # audit item 3
        deck = self.deck_copy(scope="192.168.56.0/24\nlab.example\n")
        self.run_menu(deck, "2\nlab.example\nno\n\n0\n", ZD_FAKE_DNS="lab.example=192.168.56.10")
        self.assertFalse((self.tmp / "dns.log").exists(), "a name was resolved before the operator confirmed")

    def test_unlisted_name_denied_without_lookup(self):
        deck = self.deck_copy(scope="192.168.56.0/24\nlab.example\n")
        self.run_menu(deck, "2\nother.example\n\n0\n", ZD_FAKE_DNS="other.example=192.168.56.10")  # denied: no YES prompt appears
        self.assertFalse((self.tmp / "dns.log").exists())

    def test_audit_failure_stops_inventory(self):  # audit item 1
        deck = self.deck_copy()
        (deck / "results" / "audit.log").mkdir(parents=True)
        r = self.run_menu(deck, "1\n\n0\n")
        self.assertIn("AUDIT WRITE FAILED", r.stdout + r.stderr)
        self.assertEqual(list((deck / "results").glob("*win_local_inventory*")), [])

    def test_audit_failure_stops_gate_before_any_network_command(self):
        deck = self.deck_copy()
        (deck / "results" / "audit.log").mkdir(parents=True)
        r = self.run_menu(deck, "3\n192.168.56.5\n\n0\n")  # the audit failure stops the gate before any YES prompt
        self.assertNotIn("Tracing route", r.stdout + r.stderr)
        self.assertNotIn("Verified target", r.stdout)

    def test_unique_output_names(self):  # audit item 9
        deck = self.deck_copy()
        f = deck / "f.txt"
        f.write_text("x")
        self.run_menu(deck, "4\n{0}\n\n4\n{0}\n\n0\n".format(f))
        self.assertEqual(len(list((deck / "results").glob("*win_sha256*"))), 2)


class DeployTests(WindowsCase):
    def make_source(self):
        src = self.tmp / "src"
        for rel, text in (("keep.ps1", "k"), ("config/scope.txt", "# template\n"), ("docs/a.md", "a"), ("results/README.md", "r"),
                          ("results/secret.txt", "S"), (".git/config", "g"), ("big.iso", "i")):
            p = src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        return src

    def deploy(self, src, dest, extra="", staging=""):
        staging_arg = f" -StagingName '{staging}'" if staging else ""
        body = (f". '{INSTALL}'\ntry {{ $r = Deploy-DeckFiles -SourceRoot '{src}' -Destination '{dest}'{extra}{staging_arg}; "
                "Write-Host \"OK files=$($r.FileCount) backup=$($r.Backup)\" } catch { Write-Host \"ERR: $($_.Exception.Message)\" }\n")
        return self.script(body)

    def test_file_selection(self):
        src = self.make_source()
        r = self.script(f". '{INSTALL}'\nGet-DeckFiles '{src}' | ForEach-Object {{ $_.FullName.Substring('{src}'.Length).TrimStart('\\') }}\n")
        got = sorted(line.strip().replace("\\", "/") for line in r.stdout.splitlines() if line.strip())
        self.assertEqual(got, ["config/scope.txt", "docs/a.md", "keep.ps1", "results/README.md"], r.stdout + r.stderr)

    def test_fresh_install_is_staged_verified_and_leaves_no_staging(self):
        src, usb = self.make_source(), self.tmp / "usb"
        usb.mkdir()
        r = self.deploy(src, usb / "ZERO-Deck")
        self.assertIn("OK files=4", r.stdout, r.stdout + r.stderr)
        self.assertEqual(sorted(p.name for p in usb.iterdir()), ["ZERO-Deck"])
        self.assertEqual((usb / "ZERO-Deck" / "docs" / "a.md").read_text(), "a")
        self.assertFalse((usb / "ZERO-Deck" / "results" / "secret.txt").exists())

    def test_existing_destination_is_refused_and_untouched(self):  # overwrite behaviour
        src, usb = self.make_source(), self.tmp / "usb"
        (usb / "ZERO-Deck").mkdir(parents=True)
        (usb / "ZERO-Deck" / "mine.txt").write_text("PRECIOUS")
        r = self.deploy(src, usb / "ZERO-Deck")
        self.assertIn("ERR: Destination exists", r.stdout)
        self.assertEqual((usb / "ZERO-Deck" / "mine.txt").read_text(), "PRECIOUS")
        self.assertEqual(sorted(p.name for p in usb.iterdir()), ["ZERO-Deck"])

    def test_update_keeps_backup_and_carries_user_data_over(self):
        src, usb = self.make_source(), self.tmp / "usb"
        old = usb / "ZERO-Deck"
        for rel, text in (("results/old_case.txt", "EVIDENCE"), ("results/audit.log", "A"), ("notes/n.md", "NOTE"),
                          ("config/scope.txt", "192.168.56.0/24\n"), ("stale.txt", "gone")):
            p = old / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        r = self.deploy(src, old, extra=" -UpdateMode")
        self.assertIn("OK files=4", r.stdout, r.stdout + r.stderr)
        new = usb / "ZERO-Deck"
        self.assertEqual((new / "results" / "old_case.txt").read_text(), "EVIDENCE")
        self.assertEqual((new / "results" / "audit.log").read_text(), "A")
        self.assertEqual((new / "notes" / "n.md").read_text(), "NOTE")
        self.assertEqual((new / "config" / "scope.txt").read_text(), "192.168.56.0/24\n")  # operator's scope, not the template
        self.assertFalse((new / "stale.txt").exists())
        backups = [p for p in usb.iterdir() if p.name.startswith("ZERO-Deck.bak-")]
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / "stale.txt").read_text(), "gone")  # nothing was deleted
        self.assertFalse([p for p in usb.iterdir() if "staging" in p.name])

    def test_failure_during_staging_leaves_existing_install_intact(self):  # partial copy
        src, usb = self.make_source(), self.tmp / "usb"
        old = usb / "ZERO-Deck"
        old.mkdir(parents=True)
        (old / "mine.txt").write_text("PRECIOUS")
        (usb / "STAGE").mkdir()  # pre-existing staging path -> deployment must stop before touching anything
        r = self.deploy(src, old, extra=" -UpdateMode", staging="STAGE")
        self.assertIn("ERR: Staging path already exists", r.stdout, r.stdout + r.stderr)
        self.assertEqual((old / "mine.txt").read_text(), "PRECIOUS")
        self.assertEqual(sorted(p.name for p in usb.iterdir()), ["STAGE", "ZERO-Deck"])

    def test_destination_junction_is_refused(self):
        src, usb = self.make_source(), self.tmp / "usb"
        usb.mkdir()
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        self.link_or_skip(usb / "ZERO-Deck", elsewhere)
        for extra in ("", " -UpdateMode"):
            r = self.deploy(src, usb / "ZERO-Deck", extra=extra)
            self.assertIn("ERR: Destination is a link/junction", r.stdout, r.stdout + r.stderr)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_parent_junction_is_refused(self):
        src = self.make_source()
        real, usb = self.tmp / "real", self.tmp / "usbjunction"
        real.mkdir()
        self.link_or_skip(usb, real)
        r = self.deploy(src, usb / "ZERO-Deck")
        self.assertIn("Parent folder is a link/junction", r.stdout, r.stdout + r.stderr)
        self.assertEqual(list(real.iterdir()), [])

    def test_source_junction_is_never_followed(self):  # audit item 6
        src = self.make_source()
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("TOPSECRET")
        self.link_or_skip(src / "linked", outside)
        usb = self.tmp / "usb"
        usb.mkdir()
        r = self.deploy(src, usb / "ZERO-Deck")
        self.assertIn("OK files=4", r.stdout, r.stdout + r.stderr)
        self.assertFalse(list((usb / "ZERO-Deck").rglob("secret.txt")))

    def test_usb_checks_refuse_non_usb_disk_without_touching_real_disks(self):  # Get-UsbTarget is mocked
        body = (f". '{INSTALL}'\nfunction Get-UsbTarget {{ [pscustomobject]@{{ Volume = [pscustomobject]@{{ FileSystemLabel='Ventoy'; SizeRemaining=1TB; FileSystem='exFAT' }}; "
                "Disk = [pscustomobject]@{ BusType='NVMe'; FriendlyName='mock'; Size=1TB; Number=9 } } }\n"
                "$DriveLetter = 'Z'\ntry { Invoke-Deploy } catch { Write-Host \"ERR: $($_.Exception.Message)\" }\n")
        r = self.script(body)
        self.assertIn("not detected as USB", r.stdout, r.stdout + r.stderr)

    def test_usb_checks_refuse_foreign_label_and_dry_run_writes_nothing(self):
        mock = ("function Get-UsbTarget {{ [pscustomobject]@{{ Volume = [pscustomobject]@{{ FileSystemLabel='{label}'; SizeRemaining=1TB; FileSystem='exFAT' }}; "
                "Disk = [pscustomobject]@{{ BusType='USB'; FriendlyName='mock'; Size=64GB; Number=9 }} }} }}\n")
        body = f". '{INSTALL}'\n" + mock.format(label="DATA") + "$DriveLetter = 'Z'\ntry { Invoke-Deploy } catch { Write-Host \"ERR: $($_.Exception.Message)\" }\n"
        self.assertIn("not Ventoy's default", self.script(body).stdout)
        body = f". '{INSTALL}'\n" + mock.format(label="Ventoy") + "$DriveLetter = 'Z'\n$DryRun = [switch]$true\nInvoke-Deploy\n"
        r = self.script(body)
        self.assertIn("Dry run: nothing written.", r.stdout, r.stdout + r.stderr)
        self.assertIn("would copy", r.stdout)
        self.assertFalse(Path("Z:/ZERO-Deck").exists())


if __name__ == "__main__":
    unittest.main()
