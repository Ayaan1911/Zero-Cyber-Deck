"""Repository hygiene: what `git add -A` would commit must be free of sensitive/generated/oversized content.
Read-only git commands only. Skipped when git or a repository is unavailable."""
import _isolation  # noqa: F401
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GIT = shutil.which("git")

FORBIDDEN_SUFFIXES = {".iso", ".img", ".dat", ".pcap", ".pcapng", ".cap", ".gpg", ".pem", ".key", ".p12", ".pfx", ".kdbx", ".ovpn",
                      ".vhd", ".vhdx", ".vmdk", ".qcow2", ".ova", ".wim", ".log", ".pyc"}
FORBIDDEN_PARTS = {"__pycache__", ".venv", "venv", "env", "evidence", "cases", "persistence", "ISO", "ventoy", ".idea", ".vscode"}
SECRET_PATTERNS = [re.compile(p) for p in (
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{36,}",
    r"github_pat_[A-Za-z0-9_]{50,}", r"xox[baprs]-[A-Za-z0-9-]{10,}", r"AIza[0-9A-Za-z_\-]{35}", r"sk-[A-Za-z0-9]{32,}",
)]
MAX_BYTES = 1_000_000


def git(*args):
    return subprocess.run([GIT, "-C", str(ROOT), *args], capture_output=True, text=True, timeout=60)


@unittest.skipUnless(GIT and (ROOT / ".git").exists(), "git repository not available")
class HygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = git("ls-files", "--cached", "--others", "--exclude-standard")  # tracked + would-be-added
        cls.files = [Path(p) for p in out.stdout.splitlines() if p]

    def test_nothing_sensitive_or_generated_would_be_committed(self):
        bad = []
        for p in self.files:
            posix = p.as_posix()
            if p.suffix.lower() in FORBIDDEN_SUFFIXES or p.name.startswith(".env") or p.name.startswith(("id_rsa", "id_ed25519")):
                bad.append(posix)
            elif set(p.parts[:-1]) & FORBIDDEN_PARTS:
                bad.append(posix)
            elif posix.startswith(("results/", "notes/")) and p.name != "README.md":
                bad.append(posix)
            elif p.name.startswith(("triage_", "custody", "MANIFEST")) or posix == "config/scope.local.txt":
                bad.append(posix)
        self.assertEqual(bad, [])

    def test_no_large_files(self):
        big = [p.as_posix() for p in self.files if (ROOT / p).is_file() and (ROOT / p).stat().st_size > MAX_BYTES]
        self.assertEqual(big, [])

    def test_no_secret_patterns_in_working_tree(self):
        hits = []
        for p in self.files:
            if p.name == "test_repo_hygiene.py":
                continue
            try:
                text = (ROOT / p).read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for pat in SECRET_PATTERNS:
                if pat.search(text):
                    hits.append(f"{p.as_posix()}: {pat.pattern[:30]}")
        self.assertEqual(hits, [])

    def test_no_secret_patterns_in_history(self):
        log = git("log", "--all", "-p", "--no-color")
        self.assertEqual(log.returncode, 0, log.stderr)
        added = "\n".join(line for line in log.stdout.splitlines() if line.startswith("+") and "test_repo_hygiene" not in line)
        hits = [pat.pattern[:30] for pat in SECRET_PATTERNS if pat.search(added)]
        self.assertEqual(hits, [])

    def test_release_manifest_covers_exactly_the_tracked_files_and_matches(self):  # post-remediation audit finding (LICENSE was missing)
        import hashlib
        tracked = {p.as_posix() for p in self.files} - {"SHA256SUMS.txt"}
        listed = {}
        for line in (ROOT / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
            m = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
            self.assertIsNotNone(m, f"malformed manifest line: {line!r}")
            self.assertNotIn(m.group(2), listed, f"duplicate entry {m.group(2)}")
            listed[m.group(2)] = m.group(1)
        self.assertEqual(sorted(tracked - set(listed)), [], "tracked files missing from SHA256SUMS.txt")
        self.assertEqual(sorted(set(listed) - tracked), [], "SHA256SUMS.txt lists files that are not tracked")
        self.assertNotIn("SHA256SUMS.txt", listed, "a file cannot contain its own hash")
        stale = [name for name, digest in listed.items() if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest]
        self.assertEqual(stale, [], "SHA256SUMS.txt is stale: regenerate it after the final change")

    def test_working_tree_text_files_are_lf_so_checksums_match_on_every_platform(self):
        out = git("ls-files", "--eol").stdout.splitlines()
        crlf = [line for line in out if "w/crlf" in line or "w/mixed" in line]
        self.assertEqual(crlf, [], "normalize line endings (.gitattributes forces eol=lf)")

    def test_no_control_characters_in_tracked_text_files(self):
        # a scripted edit once turned "\\report" into a carriage return and "\\auditlog" into a BEL inside a path literal
        bad = []
        for p in self.files:
            if p.suffix.lower() in {".sh", ".py", ".ps1", ".md", ".txt", ".json"} or p.name in {"DATA_FORMAT", ".gitignore", ".gitattributes", "LICENSE"}:
                data = (ROOT / p).read_bytes()
                if any(b < 32 and b not in (9, 10, 13) for b in data):
                    bad.append(p.as_posix())
                if p.suffix == ".sh" and b"\r" in data:
                    bad.append(p.as_posix() + " (CR in shell script)")
        self.assertEqual(bad, [])

    def test_default_scope_file_is_an_empty_template(self):
        active = [ln for ln in (ROOT / "config" / "scope.txt").read_text(encoding="utf-8").splitlines() if ln.split("#")[0].strip()]
        self.assertEqual(active, [], "config/scope.txt must stay an empty template; real targets go in config/scope.local.txt")

    def test_gitignore_covers_sensitive_paths_and_keeps_placeholders(self):
        ignored = ["results/x.txt", "results/audit.log", "results/triage_1/system.txt", "config/scope.local.txt", "notes/n.md",
                   "kali.iso", "persistence/kali.dat", "a.img", "cap.pcapng", ".env", ".env.local", "k.pem", "id_rsa", "id_ed25519",
                   "case_1/x.txt", "evidence/x", "custody.jsonl", "MANIFEST.sha256", "ZERO-Deck.bak-20260101/x", "ZERO-Deck.staging-1/x", "ZERO-Deck.failed-1/x", "ZERO-DATA/results/audit.log", "ZERO-DATA/.zerodeck-data",
                   ".venv/lib/x.py", "results_20260101T000000Z.tar.gz.gpg", "scripts/__pycache__/m.pyc", "ISO/kali.iso", "ventoy/ventoy.json"]
        kept = ["results/README.md", "notes/README.md", "config/scope.txt", "config/ventoy.persistence.EXAMPLE.json"]
        not_ignored = [p for p in ignored if git("check-ignore", "-q", "--no-index", p).returncode != 0]
        wrongly_ignored = [p for p in kept if git("check-ignore", "-q", "--no-index", p).returncode == 0]
        self.assertEqual(not_ignored, [])
        self.assertEqual(wrongly_ignored, [])

    def test_no_remote_is_configured_by_the_tests_or_tools(self):
        # informational guard: this suite never adds remotes; pushing is a separate, manual, approved step
        self.assertEqual(git("config", "--get-regexp", r"^remote\..*\.pushurl$").stdout.strip(), "")


@unittest.skipUnless((ROOT / "docs" / "DEPENDENCIES.md").exists(), "docs missing")
class DocsTests(unittest.TestCase):  # audit item 13
    def test_dependency_doc_lists_every_tool_the_deck_checks(self):
        text = (ROOT / "docs" / "DEPENDENCIES.md").read_text(encoding="utf-8")
        mod = (ROOT / "modules" / "utilities.sh").read_text(encoding="utf-8")
        tools = re.search(r"for t in ([^;]+); do", mod).group(1).split()
        missing = [t for t in tools if t not in text]
        self.assertEqual(missing, [])
        for needle in ("3.8", "PowerShell", "setup-kali.sh"):
            self.assertIn(needle, text)

    def test_docs_describe_manual_tools_as_requiring_manual_not_yes(self):  # post-remediation audit finding (SETUP.md said YES)
        for name in ("SETUP.md", "README.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            for line in text.splitlines():
                if re.search(r"Metasploit|Wireshark|Burp|TestDisk", line) and re.search(r"(only launched by you|launch\w*|start\w*).{0,60}\bYES\b", line):
                    self.fail(f"{name} says a manual tool needs YES: {line.strip()}")
            self.assertIn("MANUAL", text)
        setup = (ROOT / "SETUP.md").read_text(encoding="utf-8")
        for needle in ("type `MANUAL`", "NOTHING CHANGED", "MANUAL RECOVERY REQUIRED", "not an atomic", "consistent"):
            self.assertIn(needle, setup, f"SETUP.md should document: {needle}")

    def test_readme_documents_path_safety_limits_and_log_limits(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for needle in ("Path safety", "O_NOFOLLOW", "not tamper-proof", "not** an authenticity proof", "-n"):
            self.assertIn(needle, readme, f"README should document: {needle}")

    def test_docs_describe_the_code_data_separation_and_its_limits(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        setup = (ROOT / "SETUP.md").read_text(encoding="utf-8")
        for needle in ("ZERO-DATA", "--init-data", "migrate_data.py", "verify_release.py", "never created implicitly", "Raw tool output is sensitive",
                       "not tested on real exFAT", "FILE_SHARE_DELETE", "O_NOFOLLOW"):
            self.assertIn(needle, readme, f"README should document: {needle}")
        for needle in ("ZERO-DATA", "Back up", "migrate_data.py --from", "-AcknowledgeLegacyData", "never touches"):
            self.assertIn(needle, setup, f"SETUP.md should document: {needle}")
        self.assertNotIn("carried over", setup.split("## 2.")[0].replace("never carried", ""), "the updater no longer carries user data over")

    def test_docs_describe_exfat_limits_storage_layout_and_the_vm_checklist(self):
        setup = (ROOT / "SETUP.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        checklist = (ROOT / "docs" / "KALI-VM-CHECKLIST.md").read_text(encoding="utf-8")
        for needle in ("Storage layout", "hard links", "ext4", "VTOYEFI", "Leave it exactly as Ventoy created it", "Windows cannot read ext4",
                       "verified copy", "not yet built or tested"):
            self.assertIn(needle, setup, f"SETUP.md should document: {needle}")
        for needle in ("exFAT/FAT32 cannot hold ZERO-DATA", "refused", "real exFAT is not tested"):
            self.assertIn(needle, readme, f"README should document: {needle}")
        for needle in ("python3 --version", "--init-data", "fscaps.py probe", "--approve-disposable-dir", "UNSUPPORTED filesystem", "clean", "Stop conditions"):
            self.assertIn(needle, checklist, f"KALI-VM-CHECKLIST.md should cover: {needle}")
        self.assertNotIn("Install Kali", checklist.replace("Nothing here installs Kali", ""))

    def test_readme_links_dependency_doc_and_states_python_floor(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/DEPENDENCIES.md", readme)
        self.assertIn("Python 3.8", readme)

    def test_registry_dependencies_are_documented(self):
        text = (ROOT / "docs" / "DEPENDENCIES.md").read_text(encoding="utf-8")
        deps = set()
        for f in (ROOT / "modules").glob("*.sh"):
            for m in re.finditer(r'^regm?\s+"[^"]+"\s+"[^"]+"\s+\w+\s+"([^"]*)"', f.read_text(encoding="utf-8"), re.M):
                deps.update(m.group(1).split())
        self.assertEqual([d for d in sorted(deps) if d not in text], [])


if __name__ == "__main__":
    unittest.main()
