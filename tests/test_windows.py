"""Windows PowerShell checks. Skipped where powershell.exe is unavailable. Never touches a USB drive."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PS = shutil.which("powershell") or shutil.which("powershell.exe")
SCRIPTS = [ROOT / "Start-ZeroDeck.ps1", ROOT / "Install-ZeroDeck.ps1"]


def ps(*args, stdin=None, cwd=None, timeout=180):
    r = subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", *args], input=stdin, capture_output=True,
                       text=True, cwd=cwd, timeout=timeout)
    return r


@unittest.skipUnless(PS, "powershell.exe not available")
class WindowsTests(unittest.TestCase):
    def test_scripts_parse_and_are_ascii(self):
        for s in SCRIPTS:
            s.read_bytes().decode("ascii")  # PS 5.1 misreads BOM-less UTF-8 non-ASCII
            cmd = (f"$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('{s}',[ref]$t,[ref]$e);"
                   "$e.Count")
            self.assertEqual(ps("-Command", cmd).stdout.strip(), "0", s.name)

    def test_check_mode(self):
        r = ps("-File", str(ROOT / "Start-ZeroDeck.ps1"), "-Check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("scope OK", r.stdout)

    def test_deploy_file_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for rel in ("keep.ps1", "config/scope.txt", "docs/a.md", "results/README.md", "results/secret.txt",
                        "results/triage_1/x.txt", ".git/config", "scripts/__pycache__/m.pyc", "big.iso", "capture.pcap", "run.log"):
                p = base / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x")
            cmd = f". '{ROOT / 'Install-ZeroDeck.ps1'}'; Get-DeckFiles '{base}' | ForEach-Object {{ $_.FullName.Substring('{base}'.Length).TrimStart('\\') }}"
            r = ps("-Command", cmd)
            got = sorted(line.strip().replace("\\", "/") for line in r.stdout.splitlines() if line.strip())
            self.assertEqual(got, ["config/scope.txt", "docs/a.md", "keep.ps1", "results/README.md"], r.stdout + r.stderr)

    def test_installer_refuses_non_usb_and_never_writes(self):
        r = ps("-File", str(ROOT / "Install-ZeroDeck.ps1"), "-DriveLetter", "C", "-DryRun")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("would copy", r.stdout)
        self.assertFalse(Path("C:/ZERO-Deck").exists())

    def test_menu_gate_denies_and_cancels_without_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            deck = Path(tmp) / "deck"
            shutil.copytree(ROOT / "scripts", deck / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
            (deck / "config").mkdir()
            (deck / "config" / "scope.txt").write_text("192.168.56.0/24\n")
            shutil.copy(ROOT / "Start-ZeroDeck.ps1", deck)
            # out of scope, injection-looking, then in scope but declined; finally exit
            answers = "3\n8.8.8.8\n\n3\n192.168.56.5;calc\n\n3\n192.168.56.5\nno\n\n0\n"
            r = ps("-File", str(deck / "Start-ZeroDeck.ps1"), stdin=answers)
            out = r.stdout + r.stderr
            self.assertNotIn("Tracing route", out)
            audit = (deck / "results" / "audit.log").read_text().splitlines()
            verdicts = [line.split("\t")[5] for line in audit]
            self.assertEqual(verdicts, ["DENY", "ERROR", "ALLOW", "CANCELLED"], out)


if __name__ == "__main__":
    unittest.main()
