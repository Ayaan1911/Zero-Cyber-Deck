"""Application/data separation: data folder lifecycle, migration from the legacy in-tree layout, release verification,
sanitized HTTP output. Disposable temp folders only."""
import _isolation  # noqa: F401
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from linkutil import make_dir_link

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import datadir  # noqa: E402
import httpsummary  # noqa: E402
import migrate_data  # noqa: E402
import safefs  # noqa: E402
import verify_release  # noqa: E402

OK, WHY = safefs.supported()


def snapshot(root):
    out = {}
    for dirpath, _dirs, files in os.walk(root, followlinks=False):
        for n in files:
            p = Path(dirpath) / n
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


@unittest.skipUnless(OK, WHY or "unsupported platform")
class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.app = self.tmp / "ZERO-Deck"
        self.app.mkdir()
        (self.app / "DATA_FORMAT").write_text("1\n")
        self.data = self.tmp / "ZERO-DATA"
        migrate_data._after_copy_hook = None

    def tearDown(self):
        migrate_data._after_copy_hook = None
        self._tmp.cleanup()

    def link_or_skip(self, link, target):
        if not make_dir_link(link, target):
            self.skipTest("neither symlinks nor junctions can be created here")


class DataDirTests(Base):
    def test_the_data_folder_is_never_created_implicitly(self):
        state, msg = datadir.check(self.data, self.app)
        self.assertEqual(state, "missing")
        self.assertFalse(self.data.exists())
        self.assertIn("init", msg)

    def test_init_creates_layout_and_marker_and_is_idempotent(self):
        datadir.init(self.data, self.app)
        self.assertEqual(sorted(p.name for p in self.data.iterdir()), sorted([*datadir.SUBDIRS, datadir.MARKER]))
        self.assertEqual(datadir.check(self.data, self.app)[0], "ok")
        (self.data / "results" / "keep.txt").write_text("mine")
        datadir.init(self.data, self.app)
        self.assertEqual((self.data / "results" / "keep.txt").read_text(), "mine")

    def test_init_refuses_to_adopt_a_non_empty_unmarked_folder(self):
        self.data.mkdir()
        (self.data / "someone_elses.txt").write_text("x")
        with self.assertRaises(ValueError):
            datadir.init(self.data, self.app)
        self.assertEqual(sorted(p.name for p in self.data.iterdir()), ["someone_elses.txt"])
        self.assertEqual(datadir.check(self.data, self.app)[0], "unmarked")

    def test_newer_format_is_refused_to_prevent_downgrades(self):
        datadir.init(self.data, self.app)
        (self.data / datadir.MARKER).write_text("format=2\n")
        state, msg = datadir.check(self.data, self.app)
        self.assertEqual(state, "newer")
        self.assertIn("do not downgrade", msg)

    def test_link_data_folder_is_invalid(self):
        real = self.tmp / "real"
        datadir.init(real, self.app)
        self.link_or_skip(self.data, real)
        self.assertEqual(datadir.check(self.data, self.app)[0], "invalid")

    def test_missing_data_format_in_the_app_is_invalid(self):
        (self.app / "DATA_FORMAT").unlink()
        self.assertEqual(datadir.check(self.data, self.app)[0], "invalid")

    def test_parent_must_exist_and_ancestors_are_not_created(self):
        with self.assertRaises(OSError):
            datadir.init(self.tmp / "no" / "such" / "ZERO-DATA", self.app)
        self.assertFalse((self.tmp / "no").exists())

    def test_cli_exit_codes(self):
        self.assertEqual(datadir.main(["check", "--data", str(self.data), "--app", str(self.app)]), 3)
        self.assertEqual(datadir.main(["init", "--data", str(self.data), "--app", str(self.app)]), 0)
        self.assertEqual(datadir.main(["check", "--data", str(self.data), "--app", str(self.app)]), 0)
        (self.data / datadir.MARKER).write_text("format=9\n")
        self.assertEqual(datadir.main(["check", "--data", str(self.data), "--app", str(self.app)]), 5)

    def test_default_data_folder_is_a_sibling_of_the_application(self):
        self.assertEqual(datadir.default_data_dir(self.app), self.tmp / "ZERO-DATA")

    def test_real_release_declares_a_data_format(self):
        self.assertEqual(datadir.required_format(ROOT), 1)


class MigrationTests(Base):
    def legacy(self):
        old = self.tmp / "OLD-Deck"
        for rel, text in (("results/a.txt", "EVIDENCE-A"), ("results/triage_1/system.txt", "TRIAGE"), ("results/audit.log", "AUDIT"),
                          ("results/README.md", "placeholder"), ("notes/n.md", "NOTE"), ("config/scope.local.txt", "10.0.0.5\n"),
                          ("config/scope.txt", "# template only\n"), ("keep.ps1", "code")):
            p = old / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        return old

    def test_copy_preserves_every_byte_and_never_touches_the_original(self):
        old = self.legacy()
        before = snapshot(old)
        summary, code = migrate_data.migrate(old, self.data, app_root=self.app)
        self.assertEqual(code, 0)
        self.assertEqual(snapshot(old), before, "the original was modified")
        migrated = snapshot(self.data)
        for rel in ("results/a.txt", "results/triage_1/system.txt", "results/audit.log", "notes/n.md", "config/scope.local.txt"):
            self.assertEqual(migrated[rel], before[rel], rel)
        self.assertNotIn("results/README.md", migrated)           # release placeholder is not user data
        self.assertNotIn("config/legacy-scope.txt", migrated)      # an untouched template has nothing of the operator's
        receipt = next((self.data / "migrations").glob("*.json"))
        self.assertEqual(json.loads(receipt.read_text())["files"]["results/a.txt"]["sha256"], before["results/a.txt"])

    def test_edited_legacy_scope_is_kept_as_a_separate_reviewable_file(self):
        old = self.legacy()
        (old / "config" / "scope.txt").write_text("192.168.56.0/24\n")
        migrate_data.migrate(old, self.data, app_root=self.app)
        self.assertEqual((self.data / "config" / "legacy-scope.txt").read_text(), "192.168.56.0/24\n")

    def test_rerun_is_idempotent_and_conflicts_abort_before_writing(self):
        old = self.legacy()
        migrate_data.migrate(old, self.data, app_root=self.app)
        summary, code = migrate_data.migrate(old, self.data, app_root=self.app)
        self.assertEqual((code, summary["copied"], len(summary["skipped"])), (0, [], 5))
        (self.data / "results" / "a.txt").write_text("OPERATOR EDITED THE COPY")
        (old / "notes" / "new_note.md").write_text("new")   # would be copied, but the conflict must stop everything first
        before = snapshot(self.data)
        summary, code = migrate_data.migrate(old, self.data, app_root=self.app)
        self.assertEqual(code, 4)
        self.assertEqual(summary["conflicts"], ["results/a.txt"])
        self.assertEqual(snapshot(self.data), before, "something was written despite a conflict")

    def test_dry_run_writes_nothing_even_the_data_folder(self):
        old = self.legacy()
        summary, code = migrate_data.migrate(old, self.data, dry_run=True, app_root=self.app)
        self.assertEqual(code, 0)
        self.assertGreater(len(summary["copied"]), 3)
        self.assertFalse(self.data.exists())

    def test_parent_junction_named_config_is_refused_not_read(self):  # audited failure 2 (the installer variant lives in the Windows suite)
        old = self.legacy()
        foreign = self.tmp / "foreign"
        foreign.mkdir()
        (foreign / "scope.txt").write_text("999.999.999.999 FOREIGN-SCOPE\n")
        (foreign / "scope.local.txt").write_text("FOREIGN-LOCAL\n")
        for f in (old / "config").iterdir():
            f.unlink()
        (old / "config").rmdir()
        self.link_or_skip(old / "config", foreign)
        with self.assertRaises(ValueError):
            migrate_data.migrate(old, self.data, app_root=self.app)
        self.assertEqual([p for p in self.data.rglob("*") if "FOREIGN" in (p.read_text(errors="ignore") if p.is_file() else "")], [])

    def test_linked_results_folder_and_inner_links_are_refused(self):
        old = self.legacy()
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("TOPSECRET")
        self.link_or_skip(old / "results" / "linked", outside)
        with self.assertRaises(ValueError):
            migrate_data.migrate(old, self.data, app_root=self.app)
        self.assertFalse(any("secret.txt" in str(p) for p in self.data.rglob("*")))

    def test_source_that_changes_during_migration_is_detected_and_reported(self):
        old = self.legacy()
        before_changed = (old / "results" / "a.txt")

        def mutate():
            before_changed.write_text("EVIDENCE-A, APPENDED WHILE MIGRATING")
        migrate_data._after_copy_hook = mutate
        summary, code = migrate_data.migrate(old, self.data, app_root=self.app)
        self.assertEqual(code, 3)
        self.assertIn("results/a.txt", summary["changed"])
        self.assertEqual(before_changed.read_text(), "EVIDENCE-A, APPENDED WHILE MIGRATING")  # the original keeps the newer data
        self.assertEqual((self.data / "results" / "a.txt").read_text(), "EVIDENCE-A")          # the copy is a valid snapshot of the earlier state
        receipt = json.loads(next((self.data / "migrations").glob("*.json")).read_text())
        self.assertIn("results/a.txt", receipt["source_changed_during_migration"])

    def test_cli_codes(self):
        old = self.legacy()
        self.assertEqual(migrate_data.main(["--from", str(old), "--to", str(self.data), "--dry-run"]), 0)
        self.assertFalse(self.data.exists())
        self.assertEqual(migrate_data.main(["--from", str(self.tmp / "nope"), "--to", str(self.data)]), 2)


class ReleaseVerificationTests(Base):
    def release(self):
        for rel, text in (("a.sh", "echo a\n"), ("docs/b.md", "b"), ("config/scope.txt", "# template\n")):
            p = self.app / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(self.app).as_posix()}"
                 for p in sorted(self.app.rglob("*")) if p.is_file()]
        (self.app / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n")

    def test_pristine_release_verifies(self):
        self.release()
        self.assertEqual(verify_release.verify(self.app), ([], [], []))
        self.assertEqual(verify_release.main(["--app", str(self.app)]), 0)

    def test_installed_tree_still_verifies_when_the_data_folder_is_full_of_operator_files(self):  # audited failure 6
        self.release()
        datadir.init(self.data, self.app)
        (self.data / "config" / "scope.local.txt").write_text("192.168.56.0/24\n")   # the operator's scope lives HERE now
        (self.data / "results" / "audit.log").write_text("rows\n")
        self.assertEqual(verify_release.main(["--app", str(self.app)]), 0)

    def test_detects_changed_missing_and_extra_files(self):
        self.release()
        (self.app / "a.sh").write_text("echo EVIL\n")
        (self.app / "docs" / "b.md").unlink()
        (self.app / "planted.exe").write_text("x")
        failed, missing, extra = verify_release.verify(self.app)
        self.assertEqual((failed, missing, extra), (["a.sh"], ["docs/b.md"], ["planted.exe"]))
        self.assertEqual(verify_release.main(["--app", str(self.app)]), 1)
        self.assertEqual(verify_release.main(["--app", str(self.app), "--allow-extra"]), 1)  # still fails: changed + missing

    def test_a_user_edited_scope_file_in_the_application_folder_is_detected(self):
        self.release()
        (self.app / "config" / "scope.txt").write_text("192.168.56.0/24\n")
        self.assertEqual(verify_release.verify(self.app)[0], ["config/scope.txt"])

    def test_pycache_written_into_the_app_folder_is_reported(self):
        self.release()
        (self.app / "__pycache__").mkdir()
        (self.app / "__pycache__" / "x.pyc").write_bytes(b"\0")
        self.assertEqual(verify_release.verify(self.app)[2], ["__pycache__/x.pyc"])

    def test_unsafe_manifest_entries_are_rejected(self):
        self.release()
        for bad in ("../x", "/etc/passwd", "a/../b", "a\\b", "C:/x"):
            (self.app / "SHA256SUMS.txt").write_text(f"{'0' * 64}  {bad}\n")
            with self.assertRaises(ValueError, msg=bad):
                verify_release.verify(self.app)

    def test_portable_rules_apply_to_release_manifests_on_every_platform(self):  # found by the Linux run
        for bad in ("a\\b", "a:b", "docs/file.md:stream", "CON", "docs/nul.txt", "x.", "docs/y "):
            (self.app / "SHA256SUMS.txt").write_text(f"{'0' * 64}  {bad}\n")
            with self.assertRaises(ValueError, msg=bad):
                verify_release.verify(self.app)
        with self.assertRaises(safefs.UnsafePathError):
            safefs.check_name("a:b", portable=True)
        if sys.platform != "win32":
            self.assertEqual(safefs.check_name("a:b"), "a:b")  # still legal as an ordinary Linux file name for evidence

    def test_link_inside_the_release_is_reported_not_followed(self):
        self.release()
        outside = self.tmp / "outside"
        outside.mkdir()
        self.link_or_skip(self.app / "jn", outside)
        self.assertEqual(verify_release.verify(self.app)[2], ["jn"])

    def test_the_real_release_manifest_is_wellformed(self):
        entries = verify_release.parse_manifest((ROOT / "SHA256SUMS.txt").read_text(encoding="utf-8"))
        self.assertIn("DATA_FORMAT", entries)
        self.assertIn("scripts/safefs.py", entries)
        self.assertNotIn("SHA256SUMS.txt", entries)


class HttpSummaryTests(unittest.TestCase):
    RAW = ("HTTP/1.1 302 Found\r\nServer: nginx\r\nContent-Type: text/html\r\n"
           "Location: https://192.168.56.5/callback?token=SECRETVALUE#frag\r\n"
           "Set-Cookie: sid=SECRETVALUE; Path=/; HttpOnly; Secure; SameSite=Lax\r\n"
           "Authorization: Bearer SECRETVALUE\r\nX-Api-Token: SECRETVALUE\r\nStrict-Transport-Security: max-age=31536000\r\n\r\n")

    def test_secrets_never_survive(self):
        out = httpsummary.summarize(self.RAW, "https://192.168.56.5/reset?token=SECRETVALUE")
        self.assertNotIn("SECRETVALUE", out)

    def test_useful_information_is_kept(self):
        out = httpsummary.summarize(self.RAW)
        for needle in ("HTTP/1.1 302 Found", "Server: nginx", "Content-Type: text/html", "Strict-Transport-Security: max-age=31536000",
                       "Location: https://192.168.56.5/callback?REDACTED", "Set-Cookie: sid=[REDACTED]; Path=/; HttpOnly; Secure; SameSite=Lax",
                       "Authorization: [REDACTED]", "X-Api-Token: [REDACTED]"):
            self.assertIn(needle, out)

    def test_curl_errors_that_echo_the_url_are_redacted(self):
        url = "https://192.168.56.5/x?key=SECRETVALUE"
        out = httpsummary.summarize(f"curl: (28) Connection timed out after 5001 ms for {url}\ncurl: (7) Failed to connect to https://192.168.56.5/y?k=SECRETVALUE", url)
        self.assertNotIn("SECRETVALUE", out)
        self.assertIn("curl: (28)", out)

    def test_unknown_headers_default_to_redacted(self):
        out = httpsummary.summarize("HTTP/1.1 200 OK\r\nX-Internal-Session: abc123\r\n")
        self.assertIn("X-Internal-Session: [REDACTED]", out)
        self.assertNotIn("abc123", out)

    def test_empty_and_garbage_input_do_not_crash(self):
        self.assertEqual(httpsummary.summarize(""), "")
        self.assertNotIn("SECRETVALUE", httpsummary.summarize("\x00\x01 SECRETVALUE?x\n"[:10] + "\n"))


if __name__ == "__main__":
    unittest.main()
