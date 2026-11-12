"""USB installer (Install-ZeroDeck.ps1): application-only, manifest-driven, never touches the data folder.
Disposable temp folders only; the real USB is never involved (disk queries are mocked).

ACCEPTANCE: no success, refusal or injected failure may make a file in ZERO-DATA disappear or change, and the
application folder is always either the old release (untouched, byte for byte) or the new release (verified against
its manifest) - or, if rollback itself fails, preserved under a named folder with recovery instructions. Nothing is deleted.
"""
import _isolation  # noqa: F401
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from linkutil import make_dir_link
import test_windows as tw  # module object only: its test classes must not be collected twice

INSTALL, PS, ps = tw.INSTALL, tw.PS, tw.ps
ROOT = Path(__file__).resolve().parents[1]
THROW = "throw 'INJECTED FAULT'"
NEW_FILES = {"DATA_FORMAT": "1\n", "config/scope.txt": "# release template: empty\n", "docs/a.md": "docs v2", "lib/x.sh": "echo v2\n",
             "keep.ps1": "keep v2", "scripts/s.py": "print('v2')\n"}
OLD_FILES = {"DATA_FORMAT": "1\n", "config/scope.txt": "# release template: empty\n", "docs/a.md": "docs v1", "lib/x.sh": "echo v1\n",
             "keep.ps1": "keep v1", "scripts/s.py": "print('v1')\n"}
PRECIOUS = {"results/a_precious.txt": b"EVIDENCE-A", "results/triage_1/system.txt": b"TRIAGE", "results/audit.log": b"AUDIT\n",
            "notes/n.md": b"NOTE", "config/scope.local.txt": b"192.168.56.0/24\n", "evidence/case1/e.bin": os.urandom(5000)}


def snapshot(root):
    """relative posix path -> sha256 of every regular file (links are not followed)."""
    out = {}
    root = Path(root)
    if not root.exists():
        return out
    for dirpath, _dirs, files in os.walk(root, followlinks=False):
        for name in files:
            p = Path(dirpath) / name
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def make_release(root: Path, files: dict, with_extra=False) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode())
    if with_extra:
        (root / "NOT_IN_MANIFEST.txt").write_text("a stray file next to the release")
    lines = [f"{hashlib.sha256((root / rel).read_bytes()).hexdigest()}  {rel}" for rel in sorted(files)]
    (root / "SHA256SUMS.txt").write_bytes(("\n".join(lines) + "\n").encode())


@unittest.skipUnless(PS, "powershell.exe not available")
class UpdateCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.src = self.tmp / "release"
        make_release(self.src, NEW_FILES)
        self.usb = self.tmp / "usb"
        self.app = self.usb / "ZERO-Deck"
        self.data = self.usb / "ZERO-DATA"
        self.usb.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def reset(self):
        self._tmp.cleanup()
        self.setUp()

    def install_old_app(self):
        make_release(self.app, OLD_FILES)
        self.before_app = snapshot(self.app)

    def init_data(self, precious=True):
        subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "datadir.py"), "init", "--data", str(self.data), "--app", str(self.src)],
                       check=True, capture_output=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        if precious:
            for rel, data in PRECIOUS.items():
                p = self.data / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
        self.before_data = snapshot(self.data)

    def run_deploy(self, hooks=None, update=True, ack=False, dest=None, data=None, src=None, overrides="", staging=""):
        table = "".join(f"  '{k}' = {{ {v} }}\n" for k, v in (hooks or {}).items())
        flags = (" -UpdateMode" if update else "") + (" -AcknowledgeLegacy" if ack else "") + (f" -StagingName '{staging}'" if staging else "")
        body = (f". '{INSTALL}'\n{overrides}\n$TestHooks = @{{\n{table}}}\n"
                f"try {{ $r = Deploy-DeckFiles -SourceRoot '{src or self.src}' -Destination '{dest or self.app}' -DataDir '{data or self.data}'{flags}; "
                "Write-Host \"OK backup=$($r.Backup) data=$($r.DataState) created=$($r.DataCreated)\" } catch { Write-Host \"ERR: $($_.Exception.Message)\" }\n")
        f = self.tmp / "case.ps1"
        f.write_text(body, encoding="ascii")
        r = ps("-File", str(f))
        return r.stdout + r.stderr

    def top(self, token):
        return sorted(p for p in self.usb.iterdir() if token in p.name)

    def verify_release(self, app=None):
        return subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "verify_release.py"), "--app", str(app or self.app)],
                              capture_output=True, text=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))

    def assert_data_untouched(self, out=""):
        self.assertEqual(snapshot(self.data), self.before_data, "ZERO-DATA changed\n" + out)

    def assert_old_app_untouched(self, out=""):
        self.assertEqual(snapshot(self.app), self.before_app, "the old application folder changed\n" + out)

    def link_or_skip(self, link, target):
        if not make_dir_link(link, target):
            self.skipTest("neither symlinks nor junctions can be created here")


class FreshInstallTests(UpdateCase):
    def test_fresh_install_is_exactly_the_manifest_and_creates_a_compatible_data_folder(self):
        out = self.run_deploy(update=False)
        self.assertIn("OK backup= data=missing created=True", out, out)
        self.assertEqual(self.verify_release().returncode, 0, self.verify_release().stdout)
        want = set(NEW_FILES) | {"SHA256SUMS.txt"}
        self.assertEqual(set(snapshot(self.app)), want)
        self.assertEqual(sorted(p.name for p in self.usb.iterdir()), ["ZERO-DATA", "ZERO-Deck"])  # no staging left behind
        check = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "datadir.py"), "check", "--data", str(self.data), "--app", str(self.src)],
                               capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        sys.path.insert(0, str(ROOT / "scripts"))
        import datadir
        self.assertEqual(sorted(p.name for p in self.data.iterdir()), sorted([*datadir.SUBDIRS, datadir.MARKER]), "PowerShell and Python must create the same layout")

    def test_stray_files_next_to_the_release_are_not_copied(self):
        make_release(self.src, NEW_FILES, with_extra=True)
        (self.src / "results").mkdir()
        (self.src / "results" / "someone_elses_result.txt").write_text("not mine")
        out = self.run_deploy(update=False)
        self.assertIn("OK", out, out)
        self.assertEqual(set(snapshot(self.app)), set(NEW_FILES) | {"SHA256SUMS.txt"})

    def test_existing_data_folder_is_never_modified(self):
        self.init_data()
        out = self.run_deploy(update=False)
        self.assertIn("data=ok created=False", out, out)
        self.assert_data_untouched(out)

    def test_unmarked_foreign_folder_is_left_untouched_and_the_install_proceeds(self):
        self.data.mkdir()
        (self.data / "someone_elses.txt").write_text("x")
        self.before_data = snapshot(self.data)
        out = self.run_deploy(update=False)
        self.assertIn("data=unmarked created=False", out, out)
        self.assert_data_untouched(out)
        self.assertFalse((self.data / ".zerodeck-data").exists())

    def test_newer_data_format_refuses_before_anything_is_written(self):
        self.init_data()
        (self.data / ".zerodeck-data").write_text("format=9\n")
        self.before_data = snapshot(self.data)
        out = self.run_deploy(update=False)
        self.assertIn("understands up to", out, out)
        self.assertEqual(sorted(p.name for p in self.usb.iterdir()), ["ZERO-DATA"], "nothing may be created when compatibility fails")
        self.assert_data_untouched(out)

    def test_data_folder_that_is_a_junction_is_refused(self):
        real = self.tmp / "real_data"
        real.mkdir()
        (real / "x.txt").write_text("x")
        self.link_or_skip(self.data, real)
        out = self.run_deploy(update=False)
        self.assertIn("link/junction", out, out)
        self.assertEqual([p.name for p in self.usb.iterdir()], ["ZERO-DATA"])
        self.assertEqual((real / "x.txt").read_text(), "x")


class UpdateTests(UpdateCase):
    def test_update_keeps_the_old_app_intact_and_never_touches_data(self):
        self.install_old_app()
        self.init_data()
        out = self.run_deploy()
        self.assertIn("OK backup=", out, out)
        self.assertEqual(self.verify_release().returncode, 0)
        (backup,) = self.top(".bak-")
        self.assertEqual(snapshot(backup), self.before_app, "the old release must be preserved byte for byte")
        self.assert_data_untouched(out)
        self.assertEqual(set(snapshot(self.app)), set(NEW_FILES) | {"SHA256SUMS.txt"})
        self.assertFalse([p for p in self.usb.iterdir() if "staging" in p.name])

    def test_no_user_data_is_carried_into_the_new_application_tree(self):  # audited failure 3 / architecture C
        self.install_old_app()
        self.init_data()
        self.run_deploy()
        installed = snapshot(self.app)
        for rel in PRECIOUS:
            self.assertNotIn(rel, installed)
        self.assertFalse(any(h in installed.values() for h in snapshot(self.data).values() if h not in {hashlib.sha256(v.encode()).hexdigest() for v in NEW_FILES.values()}))

    def test_installed_tree_verifies_against_the_release_manifest_even_with_operator_config(self):  # audited failure 6
        self.install_old_app()
        self.init_data()                 # the operator's scope.local.txt lives in ZERO-DATA/config
        self.run_deploy()
        self.assertEqual(self.verify_release().returncode, 0, self.verify_release().stdout)

    def test_update_without_the_flag_is_refused_and_changes_nothing(self):
        self.install_old_app()
        self.init_data()
        out = self.run_deploy(update=False)
        self.assertIn("Destination exists", out, out)
        self.assert_old_app_untouched(out)
        self.assert_data_untouched(out)
        self.assertEqual(sorted(p.name for p in self.usb.iterdir()), ["ZERO-DATA", "ZERO-Deck"])

    def test_evidence_written_during_the_update_is_never_stale(self):  # audited failure 3
        self.install_old_app()
        self.init_data()
        live = self.data / "results" / "live.txt"
        live.write_text("v1")
        self.before_data = snapshot(self.data)
        out = self.run_deploy(hooks={"before-backup-rename": f"Add-Content -LiteralPath '{live}' -Value 'WRITTEN-AFTER-THE-LAST-CHECK' -NoNewline"})
        self.assertIn("OK backup=", out, out)
        self.assertEqual(live.read_text(), "v1WRITTEN-AFTER-THE-LAST-CHECK")        # the one and only copy is the live one
        copies = [p for p in self.usb.rglob("live.txt")]
        self.assertEqual(copies, [live], "evidence must exist in exactly one place; a second copy could go stale")

    def test_a_second_update_to_the_same_release_is_clean(self):
        self.install_old_app()
        self.init_data()
        self.run_deploy()
        import time
        time.sleep(1.1)  # backup folder names carry a one-second timestamp
        out = self.run_deploy()
        self.assertIn("OK backup=", out, out)
        self.assertEqual(len(self.top(".bak-")), 2)
        self.assert_data_untouched(out)


class SourceIntegrityTests(UpdateCase):
    def test_modified_source_file_is_refused_before_anything_is_staged(self):
        (self.src / "docs" / "a.md").write_text("TAMPERED")
        out = self.run_deploy(update=False)
        self.assertIn("differs from the release manifest", out, out)
        self.assertEqual([p.name for p in self.usb.iterdir()], [])

    def test_missing_source_file_is_refused(self):
        (self.src / "lib" / "x.sh").unlink()
        self.assertIn("is missing", self.run_deploy(update=False))
        self.assertEqual([p.name for p in self.usb.iterdir()], [])

    def test_unsafe_manifest_paths_are_refused(self):
        for bad in ("../outside.txt", "/abs/path", "C:/x", "a\\b", "a:stream", "CON", "docs/../../x", "x."):
            self.reset()
            (self.src / "SHA256SUMS.txt").write_text(f"{'0' * 64}  {bad}\n")
            out = self.run_deploy(update=False)
            self.assertIn("unsafe path", out, f"{bad!r}: {out}")
            self.assertEqual([p.name for p in self.usb.iterdir()], [], bad)

    def test_malformed_and_duplicate_manifest_entries_are_refused(self):
        digest = hashlib.sha256(b"docs v2").hexdigest()
        for text in ("not a hash line\n", f"{digest}  docs/a.md\n{digest}  docs/a.md\n", ""):
            self.reset()
            (self.src / "SHA256SUMS.txt").write_text(text)
            out = self.run_deploy(update=False)
            self.assertRegex(out, "ERR: ", text)
            self.assertEqual([p.name for p in self.usb.iterdir()], [])

    def test_link_inside_the_source_is_refused_even_if_the_content_would_match(self):  # audited failure 2 (content addressing + link check)
        outside = self.tmp / "outside_docs"
        outside.mkdir()
        (outside / "a.md").write_text("docs v2")                    # byte-identical to the release file
        shutil.rmtree(self.src / "docs")
        self.link_or_skip(self.src / "docs", outside)
        out = self.run_deploy(update=False)
        self.assertIn("Link/junction in the path", out, out)
        self.assertEqual([p.name for p in self.usb.iterdir()], [])

    def test_destination_and_parent_links_are_refused(self):
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        self.link_or_skip(self.app, elsewhere)
        for extra in (False, True):
            out = self.run_deploy(update=extra)
            self.assertIn("link/junction", out, out)
        self.assertEqual(list(elsewhere.iterdir()), [])
        real, usbjunction = self.tmp / "real", self.tmp / "usbjunction"
        real.mkdir()
        self.link_or_skip(usbjunction, real)
        out = self.run_deploy(update=False, dest=usbjunction / "ZERO-Deck", data=usbjunction / "ZERO-DATA")
        self.assertIn("Parent folder is a link/junction", out, out)
        self.assertEqual(list(real.iterdir()), [])


class LegacyLayoutTests(UpdateCase):
    """Old installs kept operator data INSIDE the application folder. The updater never reads or carries it."""

    def legacy_app(self):
        self.install_old_app()
        for rel, text in (("results/old_case.txt", "EVIDENCE"), ("notes/n.md", "NOTE"), ("config/scope.local.txt", "10.0.0.5\n")):
            p = self.app / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        self.before_app = snapshot(self.app)

    def test_legacy_data_blocks_activation_with_instructions(self):
        self.legacy_app()
        self.init_data()
        out = self.run_deploy()
        self.assertIn("OLD layout", out, out)
        self.assertIn("migrate_data.py", out)
        self.assertIn("-AcknowledgeLegacyData", out)
        self.assert_old_app_untouched(out)
        self.assert_data_untouched(out)
        self.assertEqual(sorted(p.name for p in self.usb.iterdir()), ["ZERO-DATA", "ZERO-Deck"])

    def test_acknowledged_legacy_data_stays_in_the_backup_and_is_never_copied(self):
        self.legacy_app()
        self.init_data()
        out = self.run_deploy(ack=True)
        self.assertIn("OK backup=", out, out)
        (backup,) = self.top(".bak-")
        self.assertEqual(snapshot(backup), self.before_app)            # legacy files preserved byte for byte in the backup
        installed = snapshot(self.app)
        self.assertEqual(set(installed), set(NEW_FILES) | {"SHA256SUMS.txt"})
        self.assertNotIn("results/old_case.txt", installed)
        self.assert_data_untouched(out)
        self.assertEqual(self.verify_release().returncode, 0)

    def test_parent_junction_named_config_is_never_read_or_carried(self):  # audited failure 2
        self.install_old_app()
        self.init_data()
        foreign = self.tmp / "foreign_cfg"
        foreign.mkdir()
        (foreign / "scope.txt").write_text("999.999.999.999 FOREIGN-SCOPE\n")
        shutil.rmtree(self.app / "config")
        self.link_or_skip(self.app / "config", foreign)
        out = self.run_deploy()
        self.assertIn("config (is a link/junction)", out, out)
        self.assert_data_untouched(out)
        out = self.run_deploy(ack=True)
        self.assertIn("OK backup=", out, out)
        everything = "".join(p.read_text(errors="ignore") for p in self.app.rglob("*") if p.is_file())
        self.assertNotIn("FOREIGN-SCOPE", everything)
        self.assertEqual((self.app / "config" / "scope.txt").read_text(), NEW_FILES["config/scope.txt"])
        self.assertEqual((foreign / "scope.txt").read_text(), "999.999.999.999 FOREIGN-SCOPE\n")

    def test_scope_entries_in_the_old_template_are_detected_as_operator_data(self):
        self.install_old_app()
        self.init_data()
        (self.app / "config" / "scope.txt").write_text("192.168.56.0/24\n")
        self.before_app = snapshot(self.app)
        out = self.run_deploy()
        self.assertIn("OLD layout", out, out)
        self.assert_old_app_untouched(out)

    def test_operator_data_appearing_mid_update_aborts_without_change(self):
        self.install_old_app()
        self.init_data()
        late = self.app / "results"
        out = self.run_deploy(hooks={"pre-commit-verify": f"New-Item -ItemType Directory -Force -Path '{late}' | Out-Null; Set-Content -LiteralPath '{late}\\late.txt' -Value 'LATE'"})
        self.assertIn("appeared inside the old application folder", out, out)
        self.assertIn("NOTHING CHANGED", out)
        self.assertEqual((late / "late.txt").read_text().strip(), "LATE")
        self.assert_data_untouched(out)


class NothingChangedTests(UpdateCase):
    STEPS = ["stage-create", "stage-copy:1", "stage-copy:3", "stage-copy:7", "stage-verify", "pre-commit-verify", "before-backup-rename"]

    def test_every_pre_commit_fault_leaves_old_app_and_data_bit_identical(self):
        for step in self.STEPS:
            with self.subTest(step=step):
                self.reset()
                self.install_old_app()
                self.init_data()
                out = self.run_deploy(hooks={step: THROW})
                self.assertIn("NOTHING CHANGED", out, out)
                self.assertIn("INJECTED FAULT", out)
                self.assert_old_app_untouched(out)
                self.assert_data_untouched(out)
                self.assertEqual((self.top(".bak-"), self.top(".failed-")), ([], []))

    def test_data_folder_is_not_even_created_when_activation_never_happens(self):
        self.install_old_app()
        out = self.run_deploy(hooks={"before-backup-rename": THROW})
        self.assertIn("NOTHING CHANGED", out, out)
        self.assertFalse(self.data.exists())


class RollbackTests(UpdateCase):
    def test_post_rename_faults_roll_back_non_destructively(self):
        for step in ("after-backup-rename", "after-commit-rename", "post-verify"):
            with self.subTest(step=step):
                self.reset()
                self.install_old_app()
                self.init_data()
                out = self.run_deploy(hooks={step: THROW})
                self.assertIn("ROLLED BACK, NOTHING DELETED", out, out)
                self.assert_old_app_untouched(out)
                self.assert_data_untouched(out)
                self.assertEqual(self.top(".bak-"), [])
                kept = self.top(".failed-") if step != "after-backup-rename" else self.top(".staging-")
                self.assertEqual(len(kept), 1, "the unverified new tree must be kept, not deleted")

    def test_rollback_faults_demand_manual_recovery_and_lose_nothing(self):
        combos = [("after-commit-rename", "rollback-aside"), ("after-commit-rename", "rollback-restore"), ("post-verify", "rollback-aside"),
                  ("post-verify", "rollback-restore"), ("after-backup-rename", "rollback-restore")]
        for first, second in combos:
            with self.subTest(fault=first, rollback_fault=second):
                self.reset()
                self.install_old_app()
                self.init_data()
                out = self.run_deploy(hooks={first: THROW, second: THROW})
                self.assertIn("MANUAL RECOVERY REQUIRED", out, out)
                self.assertIn("NO DATA WAS DELETED", out)
                self.assertIn("your data folder was never touched", out)
                self.assert_data_untouched(out)
                self.assertTrue([d for d in self.usb.iterdir() if d.is_dir() and snapshot(d) == self.before_app], "the old application folder is not intact anywhere")

    def test_fresh_install_failure_keeps_the_new_tree_and_says_so(self):
        out = self.run_deploy(hooks={"post-verify": THROW}, update=False)
        self.assertIn("there was no previous install", out, out)
        self.assertFalse(self.app.exists())
        self.assertEqual(len(self.top("ZERO-Deck.failed-")), 1)

    def test_data_folder_creation_failure_does_not_undo_a_verified_activation(self):
        out = self.run_deploy(hooks={"data-init": THROW}, update=False)
        self.assertIn("OK", out, out)
        self.assertEqual(self.verify_release().returncode, 0)
        self.assertFalse(self.data.exists())


class CmdletFailureTests(UpdateCase):
    """Fail the REAL cmdlets (not our hooks)."""

    @staticmethod
    def fail_nth(cmdlet, params, nth_set):
        name = cmdlet.replace("-", "_")
        return (f"$script:cnt_{name} = 0\nfunction {cmdlet} {{ [CmdletBinding()] param({params}) "
                f"$script:cnt_{name}++; if (@({nth_set}) -contains $script:cnt_{name}) {{ throw 'INJECTED {cmdlet} FAILURE' }}; "
                f"Microsoft.PowerShell.Management\\{cmdlet} @PSBoundParameters }}\n")

    def test_copy_item_failing_at_any_point_changes_nothing(self):
        for nth in (1, 3, 5, 7):
            with self.subTest(copy_item_call=nth):
                self.reset()
                self.install_old_app()
                self.init_data()
                out = self.run_deploy(overrides=self.fail_nth("Copy-Item", "$LiteralPath, $Destination", str(nth)))
                self.assertIn("NOTHING CHANGED", out, out)
                self.assert_old_app_untouched(out)
                self.assert_data_untouched(out)

    def test_rename_item_failures_roll_back_or_demand_manual_recovery_never_lose_data(self):
        # a successful update makes exactly two renames; calls 3+ are only reached by the rollback
        cases = {"1": "NOTHING CHANGED", "2": "ROLLED BACK", "2,3": "MANUAL RECOVERY REQUIRED", "3,4": "OK backup="}
        for fails, expected in cases.items():
            with self.subTest(rename_item_fails_on_calls=fails):
                self.reset()
                self.install_old_app()
                self.init_data()
                out = self.run_deploy(overrides=self.fail_nth("Rename-Item", "$LiteralPath, $NewName", fails))
                self.assertIn(expected, out, out)
                self.assert_data_untouched(out)
                self.assertTrue([d for d in self.usb.iterdir() if d.is_dir() and d.name != "ZERO-DATA" and (snapshot(d) == self.before_app or d == self.app)])

    def test_the_installer_has_no_delete_or_move_commands_so_injecting_them_is_inert(self):
        self.install_old_app()
        self.init_data()
        stub = ("function Remove-Item { throw 'INSTALLER CALLED Remove-Item' }\nfunction Move-Item { throw 'INSTALLER CALLED Move-Item' }\n"
                "function Set-Content { throw 'INSTALLER CALLED Set-Content' }\nfunction Add-Content { throw 'INSTALLER CALLED Add-Content' }\n")
        out = self.run_deploy(overrides=stub)
        self.assertIn("OK backup=", out, out)
        self.assertNotIn("INSTALLER CALLED", out)
        self.assert_data_untouched(out)


class UsbChecksTests(UpdateCase):
    MOCK = ("function Get-UsbTarget {{ [pscustomobject]@{{ Volume = [pscustomobject]@{{ FileSystemLabel='{label}'; SizeRemaining=1TB; FileSystem='exFAT' }}; "
            "Disk = [pscustomobject]@{{ BusType='{bus}'; FriendlyName='mock'; Size=64GB; Number=9 }} }} }}\n")

    def run_invoke(self, bus, label, extra=""):
        body = f". '{INSTALL}'\n" + self.MOCK.format(bus=bus, label=label) + f"$DriveLetter = 'Z'\n{extra}\ntry {{ Invoke-Deploy }} catch {{ Write-Host \"ERR: $($_.Exception.Message)\" }}\n"
        f = self.tmp / "usbcase.ps1"
        f.write_text(body, encoding="ascii")
        r = ps("-File", str(f))
        return r.stdout + r.stderr

    def test_non_usb_disk_is_refused(self):
        self.assertIn("not detected as USB", self.run_invoke("NVMe", "Ventoy"))

    def test_foreign_label_is_refused(self):
        self.assertIn("not Ventoy's default", self.run_invoke("USB", "DATA"))

    def test_dry_run_verifies_the_release_shows_the_plan_and_writes_nothing(self):
        out = self.run_invoke("USB", "Ventoy", "$DryRun = [switch]$true")
        self.assertIn("Dry run: nothing written.", out)
        self.assertIn("would copy", out)
        self.assertIn("never modified by this script", out)
        self.assertFalse(Path("Z:/ZERO-Deck").exists())


class DataFolderParityTests(UpdateCase):
    def test_powershell_data_state_function_reports_each_state(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        body = (f". '{INSTALL}'\n"
                f"foreach ($d in '{self.tmp / 'nope'}') {{ (Get-DataState $d 1).State }}\n")
        f = self.tmp / "state.ps1"
        f.write_text(body, encoding="ascii")
        self.assertEqual(ps("-File", str(f)).stdout.split(), ["missing"])
        self.init_data(precious=False)
        body = f". '{INSTALL}'\n(Get-DataState '{self.data}' 1).State\ntry {{ Get-DataState '{self.data}' 0 | Out-Null }} catch {{ 'newer' }}\n"
        f.write_text(body, encoding="ascii")
        self.assertEqual(ps("-File", str(f)).stdout.split(), ["ok", "newer"])


if __name__ == "__main__":
    unittest.main()
