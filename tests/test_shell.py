"""Shell integration tests: stubbed external tools, no network, no real scans."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def find_bash():
    candidates = [os.environ.get("ZD_BASH"), r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")]
    for c in filter(None, candidates):
        try:
            r = subprocess.run([c, "-c", "echo $BASH_VERSION"], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0 and r.stdout.strip():
            return c
    return None


BASH = find_bash()
STUB = "#!/bin/sh\nprintf '%s|' \"$@\" >> \"$STUBLOG\"; echo >> \"$STUBLOG\"\n"


@unittest.skipUnless(BASH, "bash not available")
class ShellCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.results = self.tmp / "results"
        self.notes = self.tmp / "notes"
        self.scope = self.tmp / "scope.txt"
        self.scope.write_text("192.168.56.0/24\n", encoding="utf-8")
        self.stubs = self.tmp / "stubs"
        self.stubs.mkdir()
        self.log = self.tmp / "stub.log"
        for name in ("nmap", "curl", "dig", "wireshark", "msfconsole"):
            self.stub(name)
        self.stub("timeout", '#!/bin/sh\nshift\nexec "$@"\n')

    def tearDown(self):
        self._tmp.cleanup()

    def stub(self, name, body=STUB):
        p = self.stubs / name
        p.write_text(body, newline="\n")
        p.chmod(0o755)

    def sh(self, script, stdin="", extra_env=None):
        env = dict(os.environ, ZD_ROOT=ROOT.as_posix(), ZD_SCOPE=self.scope.as_posix(), ZD_RESULTS=self.results.as_posix(),
                   ZD_NOTES=self.notes.as_posix(), STUBLOG=self.log.as_posix(), ZD_NO_PAUSE="1", ZD_PLAIN="1")
        env["STUBDIR"] = self.stubs.as_posix()
        env.update(extra_env or {})
        # Git Bash's startup puts /mingw64/bin ahead of the inherited PATH, so stubs must be prepended inside the shell
        # (otherwise a real curl/nmap could run). The assertion below guards against that ever regressing.
        pre = 'STUBDIR="$(cygpath -u "$STUBDIR" 2>/dev/null || printf %s "$STUBDIR")"; export PATH="$STUBDIR:$PATH"\n'
        pre += '[ "$(command -v curl)" = "$STUBDIR/curl" ] || { echo STUB_NOT_FIRST; exit 99; }\n'
        pre += 'cd "$ZD_ROOT"; source lib/common.sh; source lib/ui.sh; for m in modules/*.sh; do source "$m"; done\n'
        # bytes in/out: text mode would send CRLF on Windows and corrupt `read` answers
        r = subprocess.run([BASH, "-c", pre + script], input=stdin.encode(), capture_output=True, env=env, timeout=120)
        out, err = (b.decode("utf-8", "replace").replace("\r\n", "\n") for b in (r.stdout, r.stderr))
        return subprocess.CompletedProcess(r.args, r.returncode, out, err)

    def stub_calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def audit_verdicts(self):
        f = self.results / "audit.log"
        return [row.split("\t")[5] for row in f.read_text().splitlines()] if f.exists() else []


class SyntaxTests(unittest.TestCase):
    @unittest.skipUnless(BASH, "bash not available")
    def test_all_scripts_parse(self):
        scripts = [ROOT / "zero-deck.sh", ROOT / "setup-kali.sh", ROOT / "scripts" / "test-deck.sh",
                   *sorted((ROOT / "lib").glob("*.sh")), *sorted((ROOT / "modules").glob("*.sh"))]
        for s in scripts:
            r = subprocess.run([BASH, "-n", s.as_posix()], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{s}: {r.stderr}")

    def test_no_crlf_in_shell_or_python(self):
        for pattern in ("*.sh", "*.py"):
            for f in ROOT.rglob(pattern):
                if ".git" in f.parts:
                    continue
                self.assertNotIn(b"\r", f.read_bytes(), f"CRLF in {f}")


class DashboardTests(ShellCase):
    def test_check_reports_core_tools(self):
        r = self.sh("deps_report", extra_env={})
        self.assertIn("python3", r.stdout)
        self.assertIn("[ok]", r.stdout)

    def test_plain_menu_navigation_and_inventory(self):
        r = self.sh("ui_main", stdin="1\n1\n0\n0\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        for word in ("Main menu", "Network", "Web Security", "Forensics", "Incident Response", "CTF / Learning",
                     "System Recovery", "Utilities", "Local system + network inventory"):
            self.assertIn(word, r.stdout)
        self.assertTrue(list(self.results.glob("*_local_inventory.txt")))

    def test_raw_keyboard_mode_arrows_and_back(self):
        r = self.sh("ui_main", stdin="\x1b[B\n" + "q" + "q", extra_env={"ZD_FORCE_TTY": "1", "ZD_PLAIN": ""})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Web Security", r.stdout)
        self.assertIn("DNS A-record lookup", r.stdout)

    def test_missing_dependency_is_explained_and_not_run(self):
        r = self.sh('fake() { echo RAN_FAKE; }; run_item "Fake" fake "no_such_tool_xyz nmap_not_here"')
        self.assertNotIn("RAN_FAKE", r.stdout)
        self.assertIn("no_such_tool_xyz", r.stdout)
        self.assertIn("install", r.stdout)

    def test_all_categories_have_tools(self):
        r = self.sh('for c in "${ZD_CATS[@]}"; do n=0; for e in "${ZD_REG[@]}"; do [ "${e%%|*}" = "$c" ] && n=$((n+1)); done; echo "$c=$n"; done')
        for line in r.stdout.splitlines():
            self.assertGreater(int(line.split("=")[1]), 0, line)


class GateTests(ShellCase):
    def test_confirmed_target_passes_and_is_audited(self):
        r = self.sh('gate host 192.168.56.5 t_action && echo "G=$G_HOST/$G_ADDR"', stdin="YES\n")
        self.assertIn("G=192.168.56.5/192.168.56.5", r.stdout)
        self.assertEqual(self.audit_verdicts(), ["ALLOW", "CONFIRMED"])

    def test_declined_confirmation(self):
        r = self.sh("gate host 192.168.56.5 t_action; echo rc=$?", stdin="no\n")
        self.assertIn("rc=1", r.stdout)
        self.assertEqual(self.audit_verdicts()[-1], "CANCELLED")

    def test_out_of_scope_never_runs_nmap(self):
        r = self.sh("nmap_top_ports", stdin="8.8.8.8\nYES\n")
        self.assertIn("OUT OF SCOPE", r.stderr)
        self.assertEqual(self.stub_calls(), [])
        self.assertEqual(self.audit_verdicts(), ["DENY"])

    def test_empty_scope_blocks(self):
        self.scope.write_text("# empty\n")
        r = self.sh("nmap_top_ports", stdin="192.168.56.5\nYES\n")
        self.assertIn("Scope is empty", r.stderr)
        self.assertEqual(self.stub_calls(), [])

    def test_command_injection_attempts_do_nothing(self):
        marker = self.tmp / "PWNED"
        attempts = [f"192.168.56.5; touch {marker.as_posix()}", f"$(touch {marker.as_posix()})", f"`touch {marker.as_posix()}`",
                    f"192.168.56.5 && touch {marker.as_posix()}", "192.168.56.5 -oN /tmp/x", "--script=evil", "-sS"]
        for a in attempts:
            self.sh("nmap_top_ports", stdin=f"{a}\nYES\n")
            self.sh("dns_lookup", stdin=f"{a}\nYES\n")
        self.assertFalse(marker.exists())
        self.assertEqual(self.stub_calls(), [])

    def test_nmap_runs_against_pinned_address_with_timeouts(self):
        self.sh("nmap_top_ports", stdin="192.168.56.5\nYES\n")
        call = self.stub_calls()[0]
        self.assertIn("192.168.56.5|", call)
        for flag in ("--host-timeout|", "--top-ports|", "--open|"):
            self.assertIn(flag, call)

    def test_discovery_rejects_broad_network(self):
        self.sh("nmap_discovery", stdin="192.168.0.0/16\nYES\n")
        self.assertEqual(self.stub_calls(), [])
        self.sh("nmap_discovery", stdin="192.168.56.0/24\nYES\n")
        self.assertIn("-sn|", self.stub_calls()[0])

    def test_http_headers_blocks_globbing_and_pins_address(self):
        for bad in ("http://192.168.56.5/[1-9999]", "http://192.168.56.5/{a,b}", "http://192.168.56.5/a b"):
            self.sh("http_headers", stdin=f"{bad}\nYES\n")
        self.assertEqual(self.stub_calls(), [])
        self.sh("http_headers", stdin="http://192.168.56.5:8080/x?y=1\nYES\n")
        call = self.stub_calls()[0]
        for token in ("--globoff|", "--noproxy|*|", "--resolve|192.168.56.5:8080:192.168.56.5|", "--max-redirs|0|",
                      "http://192.168.56.5:8080/x?y=1|"):
            self.assertIn(token, call)

    def test_dns_uses_timeouts(self):
        self.sh("dns_lookup", stdin="192.168.56.5\nYES\n")
        self.assertIn("+time=5|+tries=1|", self.stub_calls()[0])


class PortTests(ShellCase):
    def test_valid_ports(self):
        good = ["22", "22,80,443", "1-1024", "1,5-9,65535"]
        bad = ["", "0", "65536", "22;id", "80-20", "1,,2", "-5", "a", "22 80", "1-2-3", "$(id)", "1" * 300]
        script = "".join(f'valid_ports "{p}" && echo "OK {p}" || echo "NO {p}"\n' for p in good + bad)
        out = self.sh(script).stdout.splitlines()
        for p, line in zip(good + bad, out):
            self.assertEqual(line.split()[0], "OK" if p in good else "NO", p)


class LauncherTests(ShellCase):
    def test_metasploit_requires_explicit_yes(self):
        self.sh("metasploit_launch", stdin="no\n")
        self.assertEqual(self.stub_calls(), [])
        self.sh("metasploit_launch", stdin="YES\n")
        self.assertEqual(self.stub_calls(), ["-q|"])  # interactive console only, no -x/-r automation

    def test_wireshark_requires_explicit_yes(self):
        self.sh("wireshark_launch", stdin="\n")
        self.assertEqual(self.stub_calls(), [])
        self.sh("wireshark_launch", stdin="YES\n")
        self.assertEqual(len(self.stub_calls()), 1)

    def test_launcher_missing_tool_message(self):
        r = self.sh("launch_manual not_installed_tool_xyz 'notice'", stdin="YES\n")
        self.assertIn("Missing tool", r.stdout)


class UtilityTests(ShellCase):
    def test_triage_creates_hashed_snapshot(self):
        self.sh("triage_linux")
        d = next(self.results.glob("triage_*"))
        self.assertTrue((d / "MANIFEST.sha256").is_file())
        self.assertTrue((d / "system.txt").is_file())
        r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "evidence.py"), "verify", str(d / "MANIFEST.sha256")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_forensic_helpers(self):
        f = self.tmp / "sample.bin"
        f.write_bytes(b"hello")
        r = self.sh("hash_file", stdin=f"{f.as_posix()}\n")
        self.assertIn("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", r.stdout)
        r = self.sh("verify_file_hash", stdin=f"{f.as_posix()}\n{'0' * 64}\n")
        self.assertIn("MISMATCH", r.stdout)
        r = self.sh("evidence_acquire", stdin=f"{f.as_posix()}\n{(self.tmp / 'ev').as_posix()}\nC1\ntester\n")
        self.assertTrue((self.tmp / "ev" / "custody.jsonl").is_file(), r.stdout + r.stderr)
        (self.tmp / "ev" / "sample.bin").chmod(0o666)

    def test_report_and_audit_view(self):
        self.sh("gate host 192.168.56.5 a", stdin="YES\n")
        r = self.sh("make_report", stdin="Title\nOp\n")
        self.assertTrue(list(self.results.glob("report_*.md")), r.stdout + r.stderr)
        self.assertIn("ALLOW", self.sh("view_audit").stdout)

    def test_notes_reject_traversal(self):
        self.sh("new_note", stdin="../escape\n")
        self.sh("new_note", stdin="good-note\n")
        self.assertEqual([p.name[9:] for p in self.notes.glob("*.md")], ["good-note.md"])
        self.assertFalse((self.tmp / "escape.md").exists())

    def test_show_scope(self):
        self.assertIn("scope OK", self.sh("show_scope").stdout)


if __name__ == "__main__":
    unittest.main()
