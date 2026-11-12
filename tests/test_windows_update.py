"""Fault-injection tests for the USB update (Install-ZeroDeck.ps1 Deploy-DeckFiles). Disposable temp folders only.

Acceptance criterion: NO injected failure may make an existing evidence file disappear or silently change.
Faults are injected through the script's $TestHooks table (empty in production). Every scenario compares a full
sha256 snapshot of the original install against what is left on the disposable "USB" afterwards.
"""
import _isolation  # noqa: F401
import hashlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from linkutil import make_dir_link
import test_windows as tw  # module object only: its test classes must not be collected twice

INSTALL, PS, ps = tw.INSTALL, tw.PS, tw.ps

THROW = "throw 'INJECTED FAULT'"


def snapshot(root):
    """relative posix path -> sha256 for every regular file under root (links are not followed)."""
    out = {}
    root = Path(root)
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            p = Path(dirpath) / name
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


@unittest.skipUnless(PS, "powershell.exe not available")
class UpdateCase(unittest.TestCase):
    PRECIOUS = {
        "results/a_precious.txt": "EVIDENCE-A",
        "results/b_second.txt": "EVIDENCE-B",
        "results/triage_1/system.txt": "TRIAGE",
        "results/audit.log": "AUDIT",
        "notes/n.md": "NOTE",
        "config/scope.txt": "192.168.56.0/24\n",
        "config/scope.local.txt": "10.0.0.5\n",
        "results/README.md": "OLD README",
    }

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()
        self.src = self.tmp / "src"
        for rel, text in (("keep.ps1", "k"), ("config/scope.txt", "# template\n"), ("docs/a.md", "a"), ("lib/x.sh", "x"), ("results/README.md", "NEW README")):
            p = self.src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        self.usb = self.tmp / "usb"
        self.old = self.usb / "ZERO-Deck"
        for rel, text in self.PRECIOUS.items():
            p = self.old / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        (self.old / "stale.txt").write_text("stale")
        self.before = snapshot(self.old)

    def tearDown(self):
        self._tmp.cleanup()

    def reset(self):
        """Fresh disposable USB for the next sub-scenario."""
        self._tmp.cleanup()
        self.setUp()

    def run_update(self, hooks=None, update=True, dest=None):
        table = "".join(f"  '{k}' = {{ {v} }}\n" for k, v in (hooks or {}).items())
        flag = " -UpdateMode" if update else ""
        body = (f". '{INSTALL}'\n$TestHooks = @{{\n{table}}}\n"
                f"try {{ $r = Deploy-DeckFiles -SourceRoot '{self.src}' -Destination '{dest or self.old}'{flag}; Write-Host \"OK backup=$($r.Backup)\" }} "
                "catch { Write-Host \"ERR: $($_.Exception.Message)\" }\n")
        f = self.tmp / "case.ps1"
        f.write_text(body, encoding="ascii")
        r = ps("-File", str(f))
        return r.stdout + r.stderr

    def top(self, token):
        return sorted(p for p in self.usb.iterdir() if token in p.name)

    def assert_original_untouched(self, out):
        self.assertEqual(snapshot(self.old), self.before, out)

    def assert_original_exists_somewhere_intact(self, out):
        hits = [d for d in self.usb.iterdir() if d.is_dir() and snapshot(d) == self.before]
        self.assertTrue(hits, "the original install is not intact anywhere on the USB\n" + out)
        return hits[0]


class NothingChangedTests(UpdateCase):
    STEPS = ["stage-create", "stage-copy:1", "stage-copy:2", "stage-copy:4", "stage-verify", "userdata-copy:1", "userdata-copy:2",
             "userdata-copy:5", "userdata-copy:8", "userdata-verify", "pre-commit-verify", "before-backup-rename"]

    def test_every_pre_commit_fault_leaves_the_old_install_bit_identical(self):
        for step in self.STEPS:
            with self.subTest(step=step):
                out = self.run_update({step: THROW})
                self.assertIn("NOTHING CHANGED", out, out)
                self.assertIn("INJECTED FAULT", out)
                self.assert_original_untouched(out)
                self.assertEqual(self.top(".bak-"), [])
                self.assertEqual(self.top(".failed-"), [])
                # leftovers are the operator's to inspect: nothing is auto-deleted, and the message names them
                for leftover in self.top(".staging-"):
                    shutil.rmtree(leftover)  # test cleanup only, on a disposable dir

    def test_concurrent_modification_of_old_results_aborts_the_update(self):
        target = self.old / "results" / "a_precious.txt"
        out = self.run_update({"userdata-verify": f"Add-Content -LiteralPath '{target}' -Value ' APPENDED-DURING-UPDATE'"})
        self.assertIn("NOTHING CHANGED", out, out)
        self.assertIn("changed while the update was running", out)
        self.assertTrue(target.read_text().startswith("EVIDENCE-A"))  # the concurrent write is preserved, never overwritten
        self.assertEqual(self.top(".bak-"), [])

    def test_new_file_appearing_in_old_results_aborts_the_update(self):
        late = self.old / "results" / "late_capture.pcap.txt"
        out = self.run_update({"userdata-verify": f"Set-Content -LiteralPath '{late}' -Value 'LATE'"})
        self.assertIn("NOTHING CHANGED", out, out)
        self.assertTrue(late.exists())
        self.assertEqual(late.read_text().strip(), "LATE")

    def test_file_deleted_from_old_results_aborts_rather_than_silently_dropping(self):
        victim = self.old / "notes" / "n.md"
        out = self.run_update({"userdata-verify": f"Remove-Item -LiteralPath '{victim}'"})
        self.assertIn("NOTHING CHANGED", out, out)


class RollbackTests(UpdateCase):
    def test_post_rename_faults_roll_back_non_destructively(self):
        for step in ("after-backup-rename", "after-commit-rename", "post-verify"):
            with self.subTest(step=step):
                self.reset()
                out = self.run_update({step: THROW})
                self.assertIn("ROLLED BACK, NOTHING DELETED", out, out)
                self.assert_original_untouched(out)               # restored at its original path, bit-identical
                self.assertEqual(self.top(".bak-"), [])           # renamed back, not left behind
                failed = self.top(".failed-") if step != "after-backup-rename" else self.top(".staging-")
                self.assertEqual(len(failed), 1, f"the unverified new tree must be kept, not deleted: {sorted(p.name for p in self.usb.iterdir())}")

    def test_rollback_faults_require_manual_recovery_and_lose_nothing(self):
        combos = [("after-commit-rename", "rollback-aside"), ("after-commit-rename", "rollback-restore"),
                  ("post-verify", "rollback-aside"), ("post-verify", "rollback-restore"), ("after-backup-rename", "rollback-restore")]
        for first, second in combos:
            with self.subTest(fault=first, rollback_fault=second):
                self.reset()
                out = self.run_update({first: THROW, second: THROW})
                self.assertIn("MANUAL RECOVERY REQUIRED", out, out)
                self.assertIn("NO DATA WAS DELETED", out)
                self.assert_original_exists_somewhere_intact(out)
                self.assertIn(".bak-" if second == "rollback-restore" else "ZERO-Deck", out, "the message must say where the data is")
                self.assertGreaterEqual(sum(len(snapshot(d)) for d in self.usb.iterdir() if d.is_dir()), len(self.before))

    def test_fresh_install_failure_keeps_the_new_tree_and_says_so(self):
        fresh = self.usb / "ZERO-Deck-FRESH"
        out = self.run_update({"post-verify": THROW}, update=False, dest=fresh)
        self.assertIn("there was no previous install", out, out)
        self.assertFalse(fresh.exists())
        self.assertEqual(len(self.top("ZERO-Deck-FRESH.failed-")), 1)
        self.assert_original_untouched(out)


class CmdletFailureTests(UpdateCase):
    """Fail the REAL cmdlets (not our hooks): the exact injection style that exposed the original data loss."""

    def run_with_overrides(self, overrides):
        body = (f". '{INSTALL}'\n{overrides}\n"
                f"try {{ $r = Deploy-DeckFiles -SourceRoot '{self.src}' -Destination '{self.old}' -UpdateMode; Write-Host \"OK backup=$($r.Backup)\" }} "
                "catch { Write-Host \"ERR: $($_.Exception.Message)\" }\n")
        f = self.tmp / "case.ps1"
        f.write_text(body, encoding="ascii")
        r = ps("-File", str(f))
        return r.stdout + r.stderr

    @staticmethod
    def fail_nth(cmdlet, params, nth_set):
        return (f"$script:cnt_{cmdlet.replace('-', '_')} = 0\nfunction {cmdlet} {{ [CmdletBinding()] param({params}) "
                f"$script:cnt_{cmdlet.replace('-', '_')}++; if (@({nth_set}) -contains $script:cnt_{cmdlet.replace('-', '_')}) {{ throw 'INJECTED {cmdlet} FAILURE' }}; "
                f"Microsoft.PowerShell.Management\\{cmdlet} @PSBoundParameters }}\n")

    def test_original_move_item_injection_can_no_longer_lose_data(self):  # the exact style of the original failure
        out = self.run_with_overrides(self.fail_nth("Move-Item", "$LiteralPath, $Destination", "1,2,3"))
        self.assertIn("OK backup=", out, out)  # the installer no longer moves anything, so the injection is inert...
        (backup,) = self.top(".bak-")
        self.assertEqual(snapshot(backup), self.before)  # ...and the original data is byte-identical in the backup

    def test_copy_item_failing_at_any_point_changes_nothing(self):
        for nth in (1, 3, 5, 6, 8, 12):
            with self.subTest(copy_item_call=nth):
                self.reset()
                out = self.run_with_overrides(self.fail_nth("Copy-Item", "$LiteralPath, $Destination, [switch]$Force", str(nth)))
                self.assertIn("NOTHING CHANGED", out, out)
                self.assert_original_untouched(out)
                self.assertEqual(self.top(".bak-"), [])

    def test_rename_item_failures_roll_back_or_demand_manual_recovery_never_lose_data(self):
        # a successful update makes exactly two renames, so faults on calls 3+ are never reached and the update succeeds
        cases = {"1": "NOTHING CHANGED", "2": "ROLLED BACK", "2,3": "MANUAL RECOVERY REQUIRED", "3,4": "OK backup="}
        for fails, expected in cases.items():
            with self.subTest(rename_item_fails_on_calls=fails):
                self.reset()
                out = self.run_with_overrides(self.fail_nth("Rename-Item", "$LiteralPath, $NewName", fails))
                self.assertIn(expected, out, out)
                self.assert_original_exists_somewhere_intact(out)


class SuccessAndRefusalTests(UpdateCase):
    def test_successful_update_is_verified_and_the_old_install_is_kept_intact(self):
        out = self.run_update()
        self.assertIn("OK backup=", out, out)
        new = snapshot(self.old)
        for rel in self.PRECIOUS:
            if rel == "results/README.md":
                self.assertEqual((self.old / rel).read_text(), "NEW README")  # new README wins; the old one is in the backup
                continue
            self.assertEqual(new[rel], self.before[rel], rel)  # sha256 of the content, not just existence
        self.assertNotIn("stale.txt", new)
        (backup,) = self.top(".bak-")
        self.assertEqual(snapshot(backup), self.before)  # byte-identical original, still all there

    def test_update_without_flag_is_refused_and_changes_nothing(self):
        out = self.run_update(update=False)
        self.assertIn("Destination exists", out, out)
        self.assert_original_untouched(out)
        self.assertEqual([p.name for p in self.usb.iterdir()], ["ZERO-Deck"])

    def test_link_inside_user_data_is_refused_before_anything_is_written(self):
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("S")
        link = self.old / "results" / "linked"
        if not make_dir_link(link, outside):
            self.skipTest("neither symlinks nor junctions can be created here")
        before = snapshot(self.old)
        out = self.run_update()
        self.assertIn("refusing to update", out, out)
        self.assertEqual(snapshot(self.old), before)
        self.assertEqual(sorted(p.name for p in self.usb.iterdir()), ["ZERO-Deck"])  # no staging was even created
        self.assertEqual((outside / "secret.txt").read_text(), "S")

    def test_results_folder_that_is_a_link_is_refused(self):
        real = self.tmp / "real_results"
        shutil.move(str(self.old / "results"), str(real))
        if not make_dir_link(self.old / "results", real):
            shutil.move(str(real), str(self.old / "results"))
            self.skipTest("neither symlinks nor junctions can be created here")
        out = self.run_update()
        self.assertIn("refusing to update", out, out)
        self.assertEqual(snapshot(real).get("a_precious.txt"), hashlib.sha256(b"EVIDENCE-A").hexdigest())
        self.assertEqual(sorted(p.name for p in self.usb.iterdir()), ["ZERO-Deck"])

    def test_leftover_staging_path_is_never_reused_or_deleted(self):
        (self.usb / "STAGE").mkdir()
        (self.usb / "STAGE" / "keep.txt").write_text("mine")
        body_hooks = {}
        f = self.tmp / "case.ps1"
        f.write_text(f". '{INSTALL}'\ntry {{ Deploy-DeckFiles -SourceRoot '{self.src}' -Destination '{self.old}' -UpdateMode -StagingName 'STAGE' }} catch {{ Write-Host \"ERR: $($_.Exception.Message)\" }}\n", encoding="ascii")
        out = ps("-File", str(f)).stdout
        self.assertIn("already exists, not touching it", out, out)
        self.assertEqual((self.usb / "STAGE" / "keep.txt").read_text(), "mine")
        self.assert_original_untouched(out)
        self.assertEqual(body_hooks, {})

    def test_no_recursive_delete_exists_in_the_installer(self):
        text = INSTALL.read_text(encoding="ascii")
        for forbidden in ("Remove-Item", "rmdir", "rd ", "Delete(", "Move-Item"):
            self.assertNotIn(forbidden, text, f"the installer must never delete or move user data ({forbidden})")


if __name__ == "__main__":
    unittest.main()
