"""Shell integration tests. SAFETY MODEL (no real scans, disk access or network):

* every network-capable, disk-capable or host-inspecting external program is replaced by a stub that only logs its
  arguments to $STUBLOG; the stub directory is put FIRST on PATH *inside* the bash session (Git Bash's startup
  otherwise puts /mingw64/bin ahead) and the session aborts with exit 99 if any stub is shadowed;
* python children run with tests/support/sitecustomize.py: DNS answers come only from $ZD_FAKE_DNS, every lookup is
  logged to $ZD_DNSLOG and connects are blocked;
* only benign local commands stay real: date, uname, uptime, id, ls, tee, tar, grep, sed, mkdir, ...
"""
import _isolation  # noqa: F401  (blocks real DNS/network for this process)
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUPPORT = ROOT / "tests" / "support"

# Anything that could scan, connect, touch a disk, capture traffic or inspect the host.
STUBBED = ["nmap", "curl", "dig", "openssl", "tshark", "wireshark", "burpsuite", "msfconsole", "smartctl", "testdisk",
           "lsblk", "gpg", "file", "wget", "nc", "ncat", "ssh", "telnet", "ftp", "ping", "traceroute", "tracert", "whois",
           "ps", "ss", "ip", "who", "last", "getent", "crontab", "systemctl", "lsmod", "mount", "find", "timeout",
           "uname", "uptime", "id", "df", "ls", "hostname", "whoami", "dd", "fdisk", "parted", "mkfs", "wipefs"]
SAFE_REAL_DEPS = {"python3", "tar"}  # registry dependencies that are allowed to run for real
# The ONLY real programs a test may execute: pure text/file utilities working on the disposable temp dirs, the clock,
# and the interpreter. Everything else resolves to nothing and trips command_not_found_handle (-> test failure).
ALLOWED_REAL = ["python3", "python", "py", "date", "tee", "tar", "gzip", "grep", "sed", "tr", "tail", "head", "cat", "mkdir", "rm", "mv",
                "cp", "chmod", "touch", "dirname", "basename", "sort", "uniq", "wc", "cut", "cygpath"]


def find_bash():
    for c in filter(None, [os.environ.get("ZD_BASH"), r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")]):
        try:
            r = subprocess.run([c, "-c", "echo $BASH_VERSION"], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0 and r.stdout.strip():
            return c
    return None


BASH = find_bash()
LOGGING_STUB = '#!/bin/sh\nprintf \'%s\' "${0##*/}" >> "$STUBLOG"\nfor a in "$@"; do printf \'|%s\' "$a" >> "$STUBLOG"; done\necho >> "$STUBLOG"\n'
TIMEOUT_STUB = '#!/bin/sh\nshift\nexec "$@"\n'  # `timeout N cmd`: runs cmd, which is itself a stub in every test that uses it


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
        self.dnslog = self.tmp / "dns.log"
        for name in STUBBED:
            self.stub(name, TIMEOUT_STUB if name == "timeout" else LOGGING_STUB)

    def tearDown(self):
        for f in self.tmp.rglob("*"):
            if f.is_file():
                f.chmod(0o666)
        self._tmp.cleanup()

    def stub(self, name, body=LOGGING_STUB):
        p = self.stubs / name
        p.write_bytes(body.encode())
        p.chmod(0o755)

    def sh(self, script, stdin="", extra_env=None, fake_dns=""):
        env = dict(os.environ, ZD_ROOT=ROOT.as_posix(), ZD_SCOPE=self.scope.as_posix(), ZD_RESULTS=self.results.as_posix(),
                   ZD_NOTES=self.notes.as_posix(), STUBLOG=self.log.as_posix(), ZD_NO_PAUSE="1", ZD_PLAIN="1",
                   STUBDIR=self.stubs.as_posix(), PYTHONPATH=str(SUPPORT), ZD_FAKE_DNS=fake_dns,
                   ZD_DNSLOG=self.dnslog.as_posix(), PYTHONDONTWRITEBYTECODE="1")
        env.update(extra_env or {})
        env["SAFEBIN"] = (self.tmp / "safebin").as_posix()
        # 1) build wrappers for the allowlisted real tools using the ORIGINAL PATH, 2) then RESTRICT PATH to stubs + wrappers only.
        pre = 'STUBDIR="$(cygpath -u "$STUBDIR" 2>/dev/null || printf %s "$STUBDIR")"; SAFEBIN="$(cygpath -u "$SAFEBIN" 2>/dev/null || printf %s "$SAFEBIN")"\n'
        pre += 'if [ ! -e "$SAFEBIN/.ready" ]; then mkdir -p "$SAFEBIN"\nfor _c in ' + " ".join(ALLOWED_REAL) + '; do _p="$(command -v "$_c" 2>/dev/null)"; '
        pre += '[ -n "$_p" ] && { printf \'#!/bin/sh\\nexec "%s" "$@"\\n\' "$_p" > "$SAFEBIN/$_c"; chmod +x "$SAFEBIN/$_c"; }; done; : > "$SAFEBIN/.ready"; fi\n'
        pre += 'export PATH="$STUBDIR:$SAFEBIN"\n'
        pre += 'command_not_found_handle() { echo "UNEXPECTED_REAL_COMMAND:$1" >&2; echo "UNEXPECTED_REAL_COMMAND:$1"; return 127; }\n'
        # 3) verify precedence BEFORE anything runs: every stub resolves to the stub, every allowed tool to its wrapper
        pre += "for _t in " + " ".join(STUBBED) + '; do [ "$(command -v "$_t")" = "$STUBDIR/$_t" ] || { echo "STUB_NOT_FIRST:$_t"; exit 99; }; done\n'
        pre += "for _t in " + " ".join(ALLOWED_REAL) + '; do _r="$(command -v "$_t" 2>/dev/null)"; [ -z "$_r" ] || [ "$_r" = "$SAFEBIN/$_t" ] || { echo "ALLOWED_NOT_WRAPPED:$_t"; exit 99; }; done\n'
        pre += 'cd "$ZD_ROOT"; source lib/common.sh; source lib/ui.sh; for m in modules/*.sh; do source "$m"; done\n'
        # bytes in/out: text mode would send CRLF on Windows and corrupt `read` answers
        r = subprocess.run([BASH, "-c", pre + script], input=stdin.encode(), capture_output=True, env=env, timeout=180)
        out, err = (b.decode("utf-8", "replace").replace("\r\n", "\n") for b in (r.stdout, r.stderr))
        self.assertNotIn("STUB_NOT_FIRST", out, "a real tool could have shadowed its stub")
        self.assertNotIn("ALLOWED_NOT_WRAPPED", out, "an allowlisted tool resolved outside the sandbox bin")
        self.assertNotIn("UNEXPECTED_REAL_COMMAND", out + err, "the code under test tried to run a command that is neither stubbed nor allowlisted")
        return subprocess.CompletedProcess(r.args, r.returncode, out, err)

    def calls(self, name=None):
        """Recorded stub invocations as [name, arg, arg...] lists."""
        if not self.log.exists():
            return []
        rows = [line.split("|") for line in self.log.read_text().splitlines()]
        return [r for r in rows if name is None or r[0] == name]

    def dns_lookups(self):
        return self.dnslog.read_text().splitlines() if self.dnslog.exists() else []

    def audit_rows(self):
        f = self.results / "audit.log"
        return [row.split("\t") for row in f.read_text().splitlines()] if f.exists() and f.is_file() else []

    def verdicts(self):
        return [r[5] for r in self.audit_rows()]

    def reset_results(self):
        """Empty the disposable results folder between sub-scenarios."""
        if self.results.exists():
            shutil.rmtree(self.results)
        if self.log.exists():
            self.log.write_text("")

    def break_audit_log(self):
        """Make the audit log unusable (a directory), the way a full/readonly/hostile medium would."""
        self.results.mkdir(exist_ok=True)
        log = self.results / "audit.log"
        if log.exists():
            log.unlink()
        log.mkdir()


class SyntaxTests(unittest.TestCase):
    @unittest.skipUnless(BASH, "bash not available")
    def test_all_scripts_parse(self):
        scripts = [ROOT / "zero-deck.sh", ROOT / "setup-kali.sh", ROOT / "scripts" / "test-deck.sh", ROOT / "scripts" / "make-sums.sh",
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


class IsolationTests(ShellCase):
    def test_every_risky_tool_is_stubbed_and_registry_deps_are_covered(self):
        r = self.sh('for e in "${ZD_REG[@]}"; do IFS="|" read -r c l f d <<<"$e"; for t in $d; do echo "$t"; done; done')
        deps = set(r.stdout.split())
        self.assertEqual(deps - set(STUBBED) - SAFE_REAL_DEPS, set(), "a registry dependency could run for real in tests")

    def test_python_children_cannot_reach_real_dns(self):
        r = self.sh('"$PY" -c "import socket; socket.getaddrinfo(\'example.com\', 80)"')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("sandbox", r.stderr)
        self.assertEqual(self.dns_lookups(), ["lookup example.com"])

    def test_python_children_cannot_connect(self):
        r = self.sh('"$PY" -c "import socket; socket.create_connection((\'192.168.56.5\', 80), 1)"')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("blocked", r.stderr)

    def test_in_process_network_is_blocked(self):
        import socket
        with self.assertRaises(AssertionError):
            socket.getaddrinfo("example.com", 80)

    def test_unlisted_real_command_fails_the_test(self):  # audit item 6: unexpected real execution must not pass silently
        for cmd in ("perl -e 1", "nslookup example.invalid", "host example.invalid", "ruby -v", "python3_not_allowlisted"):
            with self.assertRaises(AssertionError, msg=cmd):
                self.sh(cmd)

    def test_host_inspection_commands_are_stubs_that_return_nothing(self):
        r = self.sh('uname -a; uptime; id; df -h; ls /; hostname; whoami; echo DONE')
        self.assertEqual(r.stdout.strip(), "DONE", "a host-inspection command produced real output")
        self.assertEqual({c[0] for c in self.calls()}, {"uname", "uptime", "id", "df", "ls", "hostname", "whoami"})

    def test_local_actions_never_touch_the_host(self):
        self.sh("local_inventory; triage_linux")
        ran = {c[0] for c in self.calls()}
        self.assertTrue(ran <= set(STUBBED), f"something other than a stub recorded activity: {ran - set(STUBBED)}")

    def test_allowed_real_tools_are_wrapped_and_nothing_else_is_on_path(self):
        r = self.sh('IFS=:; for d in $PATH; do echo "$d"; done')
        dirs = [d for d in r.stdout.split() if d]
        self.assertEqual(len(dirs), 2, dirs)  # stubs + wrappers; no system directory

    def test_tripwire_fires_if_a_stub_is_missing(self):
        # Remove one stub: the real curl (or nothing) would then be resolved, and the harness must refuse to run.
        (self.stubs / "curl").unlink()
        with self.assertRaises(AssertionError):
            self.sh("echo should-not-run")


class DashboardTests(ShellCase):
    def test_check_reports_core_tools(self):
        r = self.sh("deps_report")
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

    def test_registry_functions_exist_and_docs_present(self):
        r = self.sh('for e in "${ZD_REG[@]}"; do IFS="|" read -r c l f d <<<"$e"; declare -F "$f" >/dev/null || echo "NOFUNC $f"; '
                    'for t in $d; do hint "$t" | grep -q "^install \'" && echo "NOHINT $t"; done; done')
        self.assertEqual(r.stdout.strip(), "", r.stdout)
        for doc in ("LEARNING.md", "RECOVERY.md", "IR-CHECKLIST.md", "DEPENDENCIES.md"):
            self.assertTrue((ROOT / "docs" / doc).is_file(), doc)

    def test_every_module_category_is_known(self):
        r = self.sh('for e in "${ZD_REG[@]}"; do c="${e%%|*}"; ok=0; for k in "${ZD_CATS[@]}"; do [ "$k" = "$c" ] && ok=1; done; '
                    '[ $ok = 1 ] || echo "BADCAT $c"; done')
        self.assertEqual(r.stdout.strip(), "")

    def test_interactive_tools_are_labelled_manual_and_everything_else_is_not(self):  # audit item 5
        r = self.sh('for e in "${ZD_REG[@]}"; do IFS="|" read -r c l f d <<<"$e"; echo "$f|$l"; done')
        labels = dict(line.split("|", 1) for line in r.stdout.splitlines())
        manual = {f for f, label in labels.items() if label.startswith("[MANUAL] ")}
        self.assertEqual(manual, {"wireshark_launch", "metasploit_launch", "burp_launch", "testdisk_launch"})
        shown = self.sh("ui_category Network", stdin="0\n").stdout
        self.assertIn("[MANUAL] Wireshark", shown)
        self.assertIn("[MANUAL] Metasploit", shown)


class GateTests(ShellCase):
    def test_confirmed_target_passes_and_is_audited(self):
        r = self.sh('gate host 192.168.56.5 t_action && echo "G=$G_HOST/$G_ADDR"', stdin="YES\n")
        self.assertIn("G=192.168.56.5/192.168.56.5", r.stdout)
        self.assertEqual(self.verdicts(), ["PRECHECK", "CONFIRMED", "ALLOW"])

    def test_declined_confirmation(self):
        r = self.sh("gate host 192.168.56.5 t_action; echo rc=$?", stdin="no\n")
        self.assertIn("rc=1", r.stdout)
        self.assertEqual(self.verdicts(), ["PRECHECK", "CANCELLED"])

    def test_out_of_scope_never_runs_nmap(self):
        r = self.sh("nmap_top_ports", stdin="8.8.8.8\nYES\n")
        self.assertIn("OUT OF SCOPE", r.stderr)
        self.assertEqual(self.calls("nmap"), [])
        self.assertEqual(self.verdicts(), ["DENY"])

    def test_empty_scope_blocks(self):
        self.scope.write_text("# empty\n")
        r = self.sh("nmap_top_ports", stdin="192.168.56.5\nYES\n")
        self.assertIn("Scope is empty", r.stderr)
        self.assertEqual(self.calls("nmap"), [])

    def test_command_injection_attempts_do_nothing(self):
        marker = self.tmp / "PWNED"
        attempts = [f"192.168.56.5; touch {marker.as_posix()}", f"$(touch {marker.as_posix()})", f"`touch {marker.as_posix()}`",
                    f"192.168.56.5 && touch {marker.as_posix()}", "192.168.56.5 -oN /tmp/x", "--script=evil", "-sS"]
        for a in attempts:
            self.sh("nmap_top_ports", stdin=f"{a}\nYES\n")
            self.sh("dns_lookup", stdin=f"{a}\nYES\n")
        self.assertFalse(marker.exists())
        self.assertEqual(self.calls(), [])

    def test_nmap_runs_against_pinned_address_with_timeouts(self):
        self.sh("nmap_top_ports", stdin="192.168.56.5\nYES\n")
        args = self.calls("nmap")[0]
        self.assertEqual(args[-1], "192.168.56.5")
        for flag in ("--host-timeout", "--top-ports", "--open"):
            self.assertIn(flag, args)

    def test_nmap_exact_invocations_disable_reverse_dns(self):  # post-remediation audit finding: nmap without -n
        self.sh("nmap_discovery", stdin="192.168.56.0/24\nYES\n")
        self.sh("nmap_top_ports", stdin="192.168.56.5\nYES\n")
        self.sh("nmap_custom_ports", stdin="192.168.56.5\nYES\n22,80\n")
        discovery, top, custom = self.calls("nmap")
        self.assertEqual(discovery, ["nmap", "-n", "-sn", "--host-timeout", "30s", "192.168.56.0/24"])
        self.assertEqual(top, ["nmap", "-n", "-sT", "-sV", "--version-light", "--top-ports", "100", "--open",
                               "--host-timeout", "5m", "--max-retries", "2", "192.168.56.5"])
        self.assertEqual(custom, ["nmap", "-n", "-sT", "-sV", "--version-light", "-p", "22,80", "--open",
                                  "--host-timeout", "5m", "--max-retries", "2", "192.168.56.5"])

    def test_nmap_receives_only_the_pinned_ip_never_the_name(self):
        self.scope.write_text("192.168.56.0/24\nlab.example\n")
        for fn, extra in (("nmap_top_ports", ""), ("nmap_custom_ports", "443\n")):
            self.sh(fn, stdin=f"lab.example\nYES\n{extra}", fake_dns="lab.example=192.168.56.10")
        calls = self.calls("nmap")
        self.assertEqual(len(calls), 2)
        for args in calls:
            self.assertIn("-n", args)
            self.assertEqual(args[-1], "192.168.56.10")
            self.assertFalse([a for a in args if "lab.example" in a], "the hostname must never be passed to nmap")
        self.assertEqual(self.dns_lookups(), ["lookup lab.example", "lookup lab.example"])  # one guarded lookup per run, none by nmap's own args

    def test_every_nmap_invocation_in_the_code_has_dash_n(self):  # static guard against a future un-hardened addition
        import re
        for f in (ROOT / "modules").glob("*.sh"):
            for line in f.read_text(encoding="utf-8").splitlines():
                if re.search(r"\blogrun\b.*\bnmap\b", line):
                    self.assertRegex(line, r"\bnmap -n\b", f"{f.name}: {line.strip()}")

    def test_discovery_rejects_broad_network(self):
        self.sh("nmap_discovery", stdin="192.168.0.0/16\nYES\n")
        self.assertEqual(self.calls("nmap"), [])
        self.sh("nmap_discovery", stdin="192.168.56.0/24\nYES\n")
        self.assertIn("-sn", self.calls("nmap")[0])

    # --- DNS policy (audit item 3) -----------------------------------------------------------------------------
    DOMAIN_SCOPE = "192.168.56.0/24\nlab.example\n"

    def test_no_dns_lookup_before_the_operator_confirms(self):
        self.scope.write_text(self.DOMAIN_SCOPE)
        r = self.sh("gate host lab.example act; echo rc=$?", stdin="no\n", fake_dns="lab.example=192.168.56.10")
        self.assertIn("rc=1", r.stdout)
        self.assertEqual(self.dns_lookups(), [])

    def test_lookup_happens_once_after_confirmation_and_is_pinned(self):
        self.scope.write_text(self.DOMAIN_SCOPE)
        self.sh("nmap_top_ports", stdin="lab.example\nYES\n", fake_dns="lab.example=192.168.56.10")
        self.assertEqual(self.dns_lookups(), ["lookup lab.example"])
        self.assertEqual(self.calls("nmap")[0][-1], "192.168.56.10")  # the verified IP, never the name

    def test_unlisted_name_is_denied_without_any_lookup(self):
        self.scope.write_text(self.DOMAIN_SCOPE)
        self.sh("nmap_top_ports", stdin="other.example\nYES\n", fake_dns="other.example=192.168.56.10")
        self.assertEqual(self.dns_lookups(), [])
        self.assertEqual(self.calls("nmap"), [])

    def test_name_resolving_out_of_scope_is_denied_after_confirmation(self):
        self.scope.write_text(self.DOMAIN_SCOPE)
        r = self.sh("nmap_top_ports", stdin="lab.example\nYES\n", fake_dns="lab.example=8.8.8.8")
        self.assertIn("outside scope", r.stderr)
        self.assertEqual(self.calls("nmap"), [])
        self.assertEqual(self.verdicts(), ["PRECHECK", "CONFIRMED", "DENY"])

    def test_dns_drift_after_verification_is_flagged(self):
        self.scope.write_text(self.DOMAIN_SCOPE)
        self.stub("dig", "#!/bin/sh\necho 192.168.56.10\necho 8.8.8.8\n")
        r = self.sh("dns_lookup", stdin="lab.example\nYES\n", fake_dns="lab.example=192.168.56.10")
        self.assertIn("WARNING", r.stdout)
        self.assertIn("8.8.8.8", r.stdout)
        self.assertIn("DRIFT", self.verdicts())

    def test_unchanged_dns_has_no_warning(self):
        self.scope.write_text(self.DOMAIN_SCOPE)
        self.stub("dig", "#!/bin/sh\necho 192.168.56.10\n")
        r = self.sh("dns_lookup", stdin="lab.example\nYES\n", fake_dns="lab.example=192.168.56.10")
        self.assertNotIn("WARNING", r.stdout)
        self.assertNotIn("DRIFT", self.verdicts())

    # --- URLs: globbing + secrets (audit item 7) --------------------------------------------------------------------
    def test_http_headers_blocks_globbing_and_pins_address(self):
        for bad in ("http://192.168.56.5/[1-9999]", "http://192.168.56.5/{a,b}", "http://192.168.56.5/a b"):
            self.sh("http_headers", stdin=f"{bad}\nYES\n")
        self.assertEqual(self.calls("curl"), [])
        self.sh("http_headers", stdin="http://192.168.56.5:8080/x?y=1\nYES\n")
        args = self.calls("curl")[0]
        for token in ("--globoff", "--noproxy", "--max-redirs"):
            self.assertIn(token, args)
        self.assertIn("192.168.56.5:8080:192.168.56.5", args)
        self.assertEqual(args[-1], "http://192.168.56.5:8080/x?y=1")

    def test_url_secrets_never_reach_console_audit_or_results(self):
        url = "https://192.168.56.5/reset?token=SECRETVALUE&b=SECRETVALUE#SECRETVALUE"
        r = self.sh("http_headers", stdin=f"{url}\nYES\n")
        everything = r.stdout + r.stderr + "".join(p.read_text(errors="replace") for p in self.results.rglob("*") if p.is_file())
        self.assertNotIn("SECRETVALUE", everything)
        self.assertIn("https://192.168.56.5/reset?REDACTED", everything)  # the whole query is replaced, whatever its shape
        self.assertEqual(self.calls("curl")[0][-1], "https://192.168.56.5/reset?token=SECRETVALUE&b=SECRETVALUE")  # tool still gets the real URL

    def test_keyless_and_odd_query_strings_are_fully_redacted(self):  # audit finding: ?SECRETVALUE leaked
        for url in ("https://192.168.56.5/reset?SECRETVALUE", "https://192.168.56.5/p?a=1&SECRETVALUE&b", "https://192.168.56.5/p;jsessionid=SECRETVALUE",
                    "https://192.168.56.5/p?x=SECRETVALUE#SECRETVALUE", "https://192.168.56.5/a/SECRETVALUESECRETVALUESECRETVALUE/b"):
            with self.subTest(url=url):
                self.reset_results()
                r = self.sh("http_headers", stdin=f"{url}\nYES\n")
                everything = r.stdout + r.stderr + "".join(p.read_text(errors="replace") for p in self.results.rglob("*") if p.is_file())
                self.assertNotIn("SECRETVALUE", everything)
                self.assertEqual(self.calls("curl")[-1][-1], url.partition("#")[0])  # the authorised request still uses the real URL

    def test_dns_uses_timeouts(self):
        self.sh("dns_lookup", stdin="192.168.56.5\nYES\n")
        args = self.calls("dig")[0]
        self.assertIn("+time=5", args)
        self.assertIn("+tries=1", args)


class AuditFailClosedTests(ShellCase):  # audit item 1
    def test_gate_refuses_when_audit_log_unusable(self):
        self.break_audit_log()
        r = self.sh("nmap_top_ports", stdin="192.168.56.5\nYES\n")
        self.assertNotIn("Verified target", r.stdout)
        self.assertEqual(self.calls("nmap"), [])

    def test_logrun_refuses_when_audit_fails_after_authorization(self):
        r = self.sh('gate host 192.168.56.5 a && { rm -f "$RESULTS/audit.log"; mkdir "$RESULTS/audit.log"; '
                    'logrun probe echo COMMAND_EXECUTED_OK; echo "rc=$?"; }', stdin="YES\n")
        self.assertNotIn("COMMAND_EXECUTED_OK", r.stdout)
        self.assertIn("rc=1", r.stdout)
        self.assertEqual(list(self.results.glob("*_probe*")), [], "no result file may remain for a refused run")

    def test_confirmation_audit_failure_stops_the_gate(self):
        r = self.sh('audit() { return 1; }; gate host 192.168.56.5 a; echo "rc=$?"', stdin="YES\n")
        self.assertIn("rc=1", r.stdout)
        self.assertNotIn("Verified target", r.stdout)

    def test_manual_launch_refused_without_audit(self):
        self.break_audit_log()
        self.sh("metasploit_launch", stdin="MANUAL\n")
        self.assertEqual(self.calls("msfconsole"), [])

    def test_local_actions_refuse_without_audit(self):
        self.break_audit_log()
        self.sh("local_inventory")
        self.sh("triage_linux")
        self.sh("manifest_create", stdin=f"{self.tmp.as_posix()}\n")
        self.assertEqual(list(self.results.glob("*_local_inventory*")), [])
        self.assertEqual(list(self.results.glob("triage_*")), [])
        self.assertFalse((self.tmp / "MANIFEST.sha256").exists())
        self.assertEqual(self.calls(), [])

    def test_symlinked_audit_log_is_refused(self):
        from linkutil import make_file_symlink
        self.results.mkdir()
        real = self.tmp / "real.log"
        real.write_text("")
        if not make_file_symlink(self.results / "audit.log", real):
            self.skipTest("file symlinks not permitted on this machine")
        r = self.sh("audit a b c d e; echo rc=$?")
        self.assertIn("rc=1", r.stdout)
        self.assertEqual(real.read_text(), "")


class ManualToolTests(ShellCase):  # audit item 5
    def test_msf_requires_the_manual_word_not_yes(self):
        self.sh("metasploit_launch", stdin="YES\n")
        self.assertEqual(self.calls("msfconsole"), [])
        self.sh("metasploit_launch", stdin="MANUAL\n")
        self.assertEqual(self.calls("msfconsole"), [["msfconsole", "-q"]])  # interactive only: no -x / -r automation

    def test_banner_states_the_tool_is_outside_the_scope_gate_even_with_empty_scope(self):
        self.scope.write_text("# empty\n")
        r = self.sh("metasploit_launch", stdin="no\n")
        self.assertIn("OUTSIDE THE SCOPE GATE", r.stdout)
        self.assertIn("cannot restrict", r.stdout)

    def test_launch_is_audited_as_manual(self):
        self.sh("wireshark_launch", stdin="MANUAL\n")
        rows = self.audit_rows()
        self.assertEqual((rows[-1][3], rows[-1][5]), ("manual", "LAUNCH"))
        self.assertIn("outside scope gate", rows[-1][7])

    def test_all_launchers_need_manual_word(self):
        for fn, tool in (("wireshark_launch", "wireshark"), ("burp_launch", "burpsuite"), ("testdisk_launch", "testdisk"), ("metasploit_launch", "msfconsole")):
            self.sh(fn, stdin="YES\n")
            self.assertEqual(self.calls(tool), [], fn)
            self.sh(fn, stdin="MANUAL\n")
            self.assertEqual(len(self.calls(tool)), 1, fn)

    def test_launcher_missing_tool_message(self):
        r = self.sh("launch_manual not_installed_tool_xyz 'notice'", stdin="MANUAL\n")
        self.assertIn("Missing tool", r.stdout)


class UniqueOutputTests(ShellCase):  # audit item 9
    def test_same_second_runs_never_overwrite(self):
        r = self.sh('stamp() { echo FIXED; }; for i in 1 2 3 4 5; do logrun dup echo "RUN_$i" >/dev/null; done; n=0; for f in "$RESULTS"/FIXED_dup*; do n=$((n+1)); done; echo "$n"')
        self.assertEqual(r.stdout.strip().splitlines()[-1], "5")
        bodies = sorted(p.read_text().strip() for p in self.results.glob("FIXED_dup*"))
        self.assertEqual(bodies, [f"RUN_{i}" for i in range(1, 6)])

    def test_triage_folders_never_merge(self):
        self.sh("stamp() { echo FIXED; }; triage_linux >/dev/null; triage_linux >/dev/null")
        self.assertEqual(len(list(self.results.glob("triage_FIXED*"))), 2)

    def test_unique_file_does_not_touch_existing_files(self):
        self.results.mkdir()
        (self.results / "a.txt").write_text("PRECIOUS")
        r = self.sh('unique_file "$RESULTS" a .txt')
        self.assertNotEqual(Path(r.stdout.strip()).name, "a.txt")
        self.assertEqual((self.results / "a.txt").read_text(), "PRECIOUS")


class PortTests(ShellCase):
    def test_valid_ports(self):
        good = ["22", "22,80,443", "1-1024", "1,5-9,65535"]
        bad = ["", "0", "65536", "22;id", "80-20", "1,,2", "-5", "a", "22 80", "1-2-3", "$(id)", "1" * 300]
        script = "".join(f'valid_ports "{p}" && echo "OK {p}" || echo "NO {p}"\n' for p in good + bad)
        out = self.sh(script).stdout.splitlines()
        for p, line in zip(good + bad, out):
            self.assertEqual(line.split()[0], "OK" if p in good else "NO", p)


class UtilityTests(ShellCase):
    def test_triage_runs_only_stubs_and_creates_hashed_snapshot(self):
        self.sh("triage_linux")
        d = next(self.results.glob("triage_*"))
        self.assertTrue((d / "MANIFEST.sha256").is_file())
        self.assertTrue((d / "system.txt").is_file())
        ran = {c[0] for c in self.calls()}
        self.assertTrue({"ps", "ss", "ip", "uname", "uptime", "id"} <= ran, ran)  # proves host inspection hit stubs, not the host
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

    def test_manifest_is_never_overwritten_and_verify_fails_on_extra_file(self):  # audit items 8 + 9
        d = self.tmp / "case"
        d.mkdir()
        (d / "a.txt").write_text("a")
        self.sh("manifest_create", stdin=f"{d.as_posix()}\n")
        first = (d / "MANIFEST.sha256").read_text()
        (d / "b.txt").write_text("b")
        r = self.sh("manifest_create", stdin=f"{d.as_posix()}\n")
        self.assertIn("already exists", r.stdout + r.stderr)
        self.assertEqual((d / "MANIFEST.sha256").read_text(), first)
        r = self.sh("manifest_verify", stdin=f"{(d / 'MANIFEST.sha256').as_posix()}\n")
        self.assertIn("UNLISTED: b.txt", r.stdout)
        self.assertIn("VERIFICATION FAILED", r.stdout)

    def test_report_and_audit_view(self):
        self.sh("gate host 192.168.56.5 a", stdin="YES\n")
        r = self.sh("make_report", stdin="Title\nOp\n")
        self.assertTrue(list(self.results.glob("report_*.md")), r.stdout + r.stderr)
        self.assertIn("ALLOW", self.sh("view_audit").stdout)

    def test_note_creation_is_audited_before_the_file_exists(self):  # post-remediation audit finding
        self.sh("new_note", stdin="my-note\n")
        self.assertEqual(len(list(self.notes.glob("*-my-note.md"))), 1)
        rows = self.audit_rows()
        self.assertEqual((rows[-1][2], rows[-1][3], rows[-1][5]), ("new_note", "local", "RUN"))

    def test_note_creation_refused_when_audit_unavailable(self):
        self.break_audit_log()
        self.sh("new_note", stdin="my-note\n")
        self.assertEqual(list(self.notes.glob("*")) if self.notes.exists() else [], [], "a note was created without an audit entry")

    def test_existing_note_is_never_overwritten(self):
        self.sh("new_note", stdin="keep-me\n")
        note = next(self.notes.glob("*-keep-me.md"))
        note.write_text("MY WORK")
        r = self.sh("new_note", stdin="keep-me\n")
        self.assertEqual(note.read_text(), "MY WORK")
        self.assertIn("Not created", r.stdout)

    def test_linked_results_parent_makes_every_audit_refuse(self):
        from linkutil import make_dir_link
        real = self.tmp / "real_results"
        real.mkdir()
        link = self.tmp / "results_link"
        if not make_dir_link(link, real):
            self.skipTest("neither symlinks nor junctions can be created here")
        r = self.sh("audit a b c d e; echo rc=$?", extra_env={"ZD_RESULTS": link.as_posix()})
        self.assertIn("rc=1", r.stdout)
        self.assertEqual(list(real.iterdir()), [], "an audit row was written through the linked results folder")

    def test_notes_reject_traversal(self):
        self.sh("new_note", stdin="../escape\n")
        self.sh("new_note", stdin="good-note\n")
        self.assertEqual([p.name[9:] for p in self.notes.glob("*.md")], ["good-note.md"])
        self.assertFalse((self.tmp / "escape.md").exists())

    def test_show_scope(self):
        self.assertIn("scope OK", self.sh("show_scope").stdout)

    def test_local_scope_file_takes_precedence_and_is_untracked(self):
        fake_root = self.tmp / "root"
        (fake_root / "lib").mkdir(parents=True)
        (fake_root / "config").mkdir()
        shutil.copy(ROOT / "lib" / "common.sh", fake_root / "lib" / "common.sh")
        (fake_root / "config" / "scope.txt").write_text("10.0.0.1\n")
        (fake_root / "config" / "scope.local.txt").write_text("10.0.0.2\n")
        env = dict(os.environ, ZD_ROOT=fake_root.as_posix(), ZD_SCOPE="", ZD_RESULTS=(self.tmp / "r2").as_posix())
        r = subprocess.run([BASH, "-c", 'source "$ZD_ROOT/lib/common.sh"; echo "$SCOPE"'], capture_output=True, text=True, env=env)
        self.assertTrue(r.stdout.strip().endswith("scope.local.txt"), r.stdout)
        gi = (ROOT / ".gitignore").read_text()
        self.assertIn("config/scope.local.txt", gi)

    def test_encrypt_results_uses_stubbed_gpg_and_writes_outside_results(self):
        self.results.mkdir()
        (self.results / "x.txt").write_text("x")
        self.sh("encrypt_results", extra_env={"ZD_ARCHIVE_DIR": self.tmp.as_posix()})
        args = self.calls("gpg")[0]
        self.assertIn("--symmetric", args)
        self.assertIn("AES256", args)
        out = Path(args[args.index("-o") + 1])
        self.assertEqual(out.parent.as_posix(), self.tmp.as_posix())  # next to results/, never inside it
        self.assertNotEqual(out.parent.name, "results")


if __name__ == "__main__":
    unittest.main()
