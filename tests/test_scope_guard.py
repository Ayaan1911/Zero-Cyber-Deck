import _isolation  # noqa: F401  (blocks real DNS/network for this process)
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scope_guard import OutOfScope, approved, evaluate, parse_allowed, redact  # noqa: E402

GUARD = ROOT / "scripts" / "scope_guard.py"
SUPPORT = ROOT / "tests" / "support"
DNS = {"lab.example": ["192.168.56.10"], "multi.example": ["192.168.56.10", "8.8.8.8"],
       "evil.example": ["8.8.8.8"], "nowhere.example": []}


def fake_resolver(host):
    if host not in DNS:
        raise ValueError(f"Cannot resolve {host}")
    return DNS[host]


class Base(unittest.TestCase):
    SCOPE = "192.168.56.0/24\n10.0.0.2\nlab.example\nmulti.example\nevil.example\nnowhere.example\n"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "scope.txt"
        self.path.write_text(self.SCOPE, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def ok(self, target, kind="host"):
        return approved(self.path, target, kind, fake_resolver)


class HostTests(Base):
    def test_allowed(self):
        self.assertTrue(self.ok("192.168.56.42"))
        self.assertTrue(self.ok("10.0.0.2"))
        self.assertTrue(self.ok("LAB.example."))  # case + trailing dot normalised

    def test_not_allowed(self):
        for t in ("192.168.1.1", "10.0.0.3", "notlab.example", "evil.lab.example", "8.8.8.8"):
            self.assertFalse(self.ok(t), t)

    def test_malformed_targets(self):
        for t in ("", "   ", "-p80", "--script=x", "a b.example", "2001:db8::1", "::1", "lab.example:22",
                  "999.1.1.1", "300.1.1.1", "1.2.3", "127.1", "0x7f.1", "a..b.example", "-x.example",
                  "lab_example.com", "lab.example/../x", "http://lab.example"):
            with self.assertRaises(ValueError, msg=t):
                self.ok(t)

    def test_command_injection_strings_rejected(self):
        for t in ("192.168.56.1; touch /tmp/pwn", "192.168.56.1 && id", "$(id).lab.example", "`id`.lab.example",
                  "lab.example|id", "192.168.56.1\nid", "lab.example\x00.evil", "192.168.56.1 -oN /tmp/x"):
            with self.assertRaises(ValueError, msg=repr(t)):
                evaluate(self.path, t, "host", fake_resolver)

    def test_empty_scope(self):
        self.path.write_text("# nothing\n")
        with self.assertRaises(ValueError):
            self.ok("192.168.56.1")


class DnsTests(Base):
    def test_resolving_into_scope_is_pinned(self):
        d = evaluate(self.path, "lab.example", "host", fake_resolver)
        self.assertEqual((d.host, d.addrs), ("lab.example", ("192.168.56.10",)))

    def test_resolution_cannot_widen_scope(self):
        self.assertFalse(self.ok("evil.example"))  # listed name, public address
        self.assertFalse(self.ok("multi.example"))  # one address in scope, one not

    def test_empty_answer_errors(self):
        with self.assertRaises(ValueError):
            evaluate(self.path, "nowhere.example", "host", fake_resolver)

    def test_resolution_failure_errors(self):
        self.path.write_text("192.168.56.0/24\nghost.example\n")
        with self.assertRaises(ValueError):
            evaluate(self.path, "ghost.example", "host", fake_resolver)

    def test_unlisted_name_is_not_resolved(self):
        calls = []
        self.assertFalse(approved(self.path, "other.example", "host", lambda h: calls.append(h) or ["192.168.56.5"]))
        self.assertEqual(calls, [])


class NetworkTests(Base):
    def test_network(self):
        self.assertTrue(self.ok("192.168.56.0/24", "network"))
        self.assertTrue(self.ok("192.168.56.128/25", "network"))
        self.assertFalse(self.ok("192.168.55.0/24", "network"))

    def test_broad_ranges_rejected(self):
        for t in ("192.168.0.0/16", "10.0.0.0/8", "0.0.0.0/0", "::/0", "garbage"):
            with self.assertRaises(ValueError, msg=t):
                self.ok(t, "network")

    def test_host_bits_normalised(self):
        self.assertEqual(evaluate(self.path, "192.168.56.77/24", "network").host, "192.168.56.0/24")


class ScopeFileTests(Base):
    def test_bom_and_crlf(self):
        self.path.write_bytes(b"\xef\xbb\xbf192.168.56.0/24\r\nlab.example\r\n")
        nets, doms = parse_allowed(self.path)
        self.assertEqual((len(nets), doms), (1, {"lab.example"}))

    def test_invalid_encoding(self):
        self.path.write_bytes(b"\xff\xfe1\x002\x00")
        with self.assertRaises(ValueError):
            parse_allowed(self.path)

    def test_bad_entries(self):
        for line in ("0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/23", "300.1.1.1", "1.2.3", "10.0.0.1/33", "fe80::/10",
                     "*.lab.example", "localhost", "bad entry", "https://lab.example"):
            self.path.write_text(f"{line}\n")
            with self.assertRaises(ValueError, msg=line):
                parse_allowed(self.path)

    def test_comments_and_blanks(self):
        self.path.write_text("# c\n\n  10.0.0.1  # trailing\n")
        self.assertEqual(len(parse_allowed(self.path)[0]), 1)

    def test_missing_file(self):
        with self.assertRaises(ValueError):
            parse_allowed(self.path.with_name("nope.txt"))


class UrlTests(Base):
    def test_allowed_and_normalised(self):
        d = evaluate(self.path, "https://LAB.example:8443/health?q=x#frag", "url", fake_resolver)
        self.assertEqual((d.url, d.port, d.addrs), ("https://lab.example:8443/health?q=x", 8443, ("192.168.56.10",)))
        self.assertEqual(evaluate(self.path, "http://192.168.56.4", "url", fake_resolver).url, "http://192.168.56.4/")
        self.assertEqual(evaluate(self.path, "https://192.168.56.4/", "url", fake_resolver).port, 443)

    def test_out_of_scope(self):
        self.assertFalse(self.ok("https://google.com", "url"))
        self.assertFalse(self.ok("https://evil.example/", "url"))

    def test_rejected(self):
        bad = ["https://user:pass@lab.example", "file:///etc/passwd", "ftp://lab.example", "http://", "lab.example",
               "https://lab.example:0/", "https://lab.example:99999/", "https://lab.example:abc/",
               "http://lab.example\\@evil.com/", "http://lab.example@evil.com/", "http://[::1]/",
               "http://2130706433/", "https://lab.example/a b", "https://lab.example/\tx", "https://lab.example/\nx",
               "http://lab.example/%0d%0a" + "\x00"]
        for t in bad:
            with self.assertRaises(ValueError, msg=repr(t)):
                self.ok(t, "url")

    def test_curl_globbing_rejected(self):
        for t in ("http://lab.example/[1-9999]", "http://lab.example/{a,b}", "http://lab.example/x[1-2]",
                  "http://lab.[example]/", "http://{lab,evil}.example/"):
            with self.assertRaises(ValueError, msg=t):
                self.ok(t, "url")

    def test_quote_and_shell_chars(self):
        for t in ("http://lab.example/'x", 'http://lab.example/"x', "http://lab.example/`id`", "http://lab.example/a|b"):
            with self.assertRaises(ValueError, msg=t):
                self.ok(t, "url")


class CliTests(Base):
    def run_guard(self, *args, fake_dns=""):
        # Not `-I`: the offline sandbox (fake DNS, blocked connects) is injected through PYTHONPATH/sitecustomize.
        env = dict(os.environ, PYTHONPATH=str(SUPPORT), ZD_FAKE_DNS=fake_dns, PYTHONDONTWRITEBYTECODE="1",
                   ZD_DNSLOG=str(Path(self.tmp.name) / "dns.log"))
        return subprocess.run([sys.executable, str(GUARD), *map(str, args)], capture_output=True, text=True, env=env)

    def dns_log(self):
        f = Path(self.tmp.name) / "dns.log"
        return f.read_text().splitlines() if f.exists() else []

    def test_in_scope_output_and_audit(self):
        log = Path(self.tmp.name) / "audit.log"
        r = self.run_guard("--audit", log, "--action", "port_scan", self.path, "host", "--", "192.168.56.5")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("host=192.168.56.5", r.stdout)
        self.assertIn("addr=192.168.56.5", r.stdout)
        row = log.read_text().splitlines()[0].split("\t")
        self.assertEqual((row[2], row[3], row[4], row[5]), ("port_scan", "host", "192.168.56.5", "ALLOW"))

    def test_denied_and_error_are_logged_with_exit_2(self):
        log = Path(self.tmp.name) / "audit.log"
        self.assertEqual(self.run_guard("--audit", log, self.path, "host", "--", "1.1.1.1").returncode, 2)
        self.assertEqual(self.run_guard("--audit", log, self.path, "host", "--", "-p80;id").returncode, 2)
        verdicts = [line.split("\t")[5] for line in log.read_text().splitlines()]
        self.assertEqual(verdicts, ["DENY", "ERROR"])

    def test_option_like_target_cannot_inject_flags(self):
        r = self.run_guard(self.path, "host", "--", "--audit=/x")
        self.assertEqual(r.returncode, 2)
        self.assertIn("SCOPE ERROR", r.stderr)

    def test_audit_failure_fails_closed(self):
        blocker = Path(self.tmp.name) / "file"
        blocker.write_text("x")
        r = self.run_guard("--audit", blocker / "audit.log", self.path, "host", "--", "192.168.56.5")
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("IN SCOPE", r.stdout)

    def test_audit_row_is_single_line(self):
        log = Path(self.tmp.name) / "audit.log"
        self.run_guard("--audit", log, self.path, "host", "--", "a\nFAKE\tROW")
        self.assertEqual(len(log.read_text().splitlines()), 1)

    def test_validate(self):
        r = self.run_guard(self.path, "validate")
        self.assertEqual(r.returncode, 0)
        self.assertIn("scope OK", r.stdout)

    # --- audit fails closed (finding: audit writes failing open) ---------------------------------------------------
    def test_audit_path_is_a_directory_fails_closed_before_any_output(self):
        bad = Path(self.tmp.name) / "auditdir"
        bad.mkdir()
        for flags in ((), ("--no-resolve",)):
            r = self.run_guard("--audit", bad, *flags, self.path, "host", "--", "192.168.56.5")
            self.assertEqual(r.returncode, 2, flags)
            self.assertNotIn("IN SCOPE", r.stdout)
            self.assertIn("failing closed", r.stderr)

    def test_audit_symlink_is_refused(self):
        from linkutil import make_file_symlink
        real = Path(self.tmp.name) / "real.log"
        real.write_text("")
        link = Path(self.tmp.name) / "audit.log"
        if not make_file_symlink(link, real):
            self.skipTest("symlinks not permitted on this machine")
        r = self.run_guard("--audit", link, self.path, "host", "--", "192.168.56.5")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(real.read_text(), "")

    # --- DNS policy: nothing is resolved before the operator agrees ----------------------------------------------------
    def test_precheck_makes_no_dns_lookup_and_logs_precheck(self):
        log = Path(self.tmp.name) / "audit.log"
        r = self.run_guard("--no-resolve", "--audit", log, self.path, "host", "--", "lab.example", fake_dns="lab.example=192.168.56.10")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("host=lab.example", r.stdout)
        self.assertNotIn("addr=", r.stdout)
        self.assertEqual(self.dns_log(), [])
        self.assertEqual(log.read_text().split("\t")[5], "PRECHECK")

    def test_unlisted_name_denied_in_precheck_without_dns(self):
        r = self.run_guard("--no-resolve", self.path, "host", "--", "other.example", fake_dns="other.example=192.168.56.10")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(self.dns_log(), [])

    def test_full_check_resolves_once_and_prints_all_verified_addresses(self):
        r = self.run_guard(self.path, "host", "--", "lab.example", fake_dns="lab.example=192.168.56.10,192.168.56.11")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("addr=192.168.56.10", r.stdout)
        self.assertIn("addrs=192.168.56.10,192.168.56.11", r.stdout)
        self.assertEqual(self.dns_log(), ["lookup lab.example"])

    def test_resolution_change_to_out_of_scope_is_denied(self):
        r = self.run_guard(self.path, "host", "--", "lab.example", fake_dns="lab.example=8.8.8.8")
        self.assertEqual(r.returncode, 2)
        self.assertIn("outside scope", r.stderr)

    # --- secrets never reach the audit log -----------------------------------------------------------------------------
    def test_url_secrets_are_redacted_in_every_audit_row(self):
        log = Path(self.tmp.name) / "audit.log"
        urls = ["https://192.168.56.5/reset?token=SECRETVALUE&u=1#frag-SECRETVALUE",   # ALLOW
                "https://8.8.8.8/x?api_key=SECRETVALUE",                                 # DENY
                "https://user:SECRETVALUE@192.168.56.5/?k=SECRETVALUE",                  # ERROR (credentials)
                "https://192.168.56.5/a?b=SECRETVALUE c"]                                # ERROR (space)
        for u in urls:
            self.run_guard("--audit", log, self.path, "url", "--", u)
        text = log.read_text()
        self.assertEqual(len(text.splitlines()), 4)
        self.assertNotIn("SECRETVALUE", text)
        self.assertIn("token=REDACTED", text)

    def test_stdout_logurl_is_redacted_but_url_is_usable(self):
        r = self.run_guard(self.path, "url", "--", "https://192.168.56.5/p?token=SECRETVALUE")
        self.assertIn("url=https://192.168.56.5/p?token=SECRETVALUE", r.stdout)
        self.assertIn("logurl=https://192.168.56.5/p?token=REDACTED", r.stdout)


class RedactTests(unittest.TestCase):
    def test_redact(self):
        cases = {
            "https://h/p?token=abc&x=1": "https://h/p?token=REDACTED&x=REDACTED",
            "https://h/p?a=1;b=2": "https://h/p?a=REDACTED;b=REDACTED",
            "https://user:pw@h/p": "https://REDACTED@h/p",
            "https://h/p#access_token=zzz": "https://h/p#REDACTED",
            "https://h/api/v1/reset/ABCDEFGHIJKLMNOPQRSTUVWXYZ012345/confirm": "https://h/api/v1/reset/REDACTED/confirm",
            "https://h/short/path": "https://h/short/path",
        }
        for raw, expected in cases.items():
            self.assertEqual(redact(raw), expected, raw)

    def test_out_of_scope_exception_is_distinct(self):
        self.assertTrue(issubclass(OutOfScope, Exception) and not issubclass(OutOfScope, ValueError))


if __name__ == "__main__":
    unittest.main()
