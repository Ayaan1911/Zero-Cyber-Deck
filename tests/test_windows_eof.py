"""The Windows menu must terminate when stdin closes (it once spun forever). Runs in a temp copy; no network."""
import _isolation  # noqa: F401
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PS = shutil.which("powershell") or shutil.which("powershell.exe")


@unittest.skipUnless(PS, "powershell.exe not available")
class EofTests(unittest.TestCase):
    def test_menu_exits_on_closed_or_garbage_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            deck = Path(tmp) / "deck"
            shutil.copytree(ROOT / "scripts", deck / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
            (deck / "config").mkdir()
            (deck / "config" / "scope.txt").write_text("192.168.56.0/24\n")
            shutil.copy(ROOT / "Start-ZeroDeck.ps1", deck)
            for answers in ("", "x\n", "x\n\nx\n\nx\n"):
                r = subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(deck / "Start-ZeroDeck.ps1")],
                                   input=answers, capture_output=True, text=True, timeout=60,
                                   env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
                self.assertEqual(r.returncode, 0, (answers, r.stderr))


if __name__ == "__main__":
    unittest.main()
