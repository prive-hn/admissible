"""Evidence-integrity regressions for the repository self-measurement."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "self_admit.py"


def _load_self_admit():
    spec = importlib.util.spec_from_file_location("self_admit_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CurrentHeadIdentityIsMeasuredDirectly(unittest.TestCase):
    def setUp(self):
        self.module = _load_self_admit()
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.repo = Path(self.workspace.name)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "config", "user.email", "admissible-test@example.invalid"],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Admissible Test"],
            cwd=self.repo,
            check=True,
        )
        (self.repo / "subject.txt").write_text("accepted\n", encoding="utf-8")
        subprocess.run(["git", "add", "subject.txt"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "subject"], cwd=self.repo, check=True)
        setattr(self.module, "ROOT", self.repo)

    def test_dirty_tracked_or_untracked_bytes_are_refused_before_measurement(self):
        (self.repo / "subject.txt").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "clean HEAD"):
            self.module.require_clean_head()

        subprocess.run(
            ["git", "checkout", "--", "subject.txt"], cwd=self.repo, check=True
        )
        (self.repo / "shadow.py").write_text("raise RuntimeError\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "clean HEAD"):
            self.module.require_clean_head()

    def test_replacement_object_cannot_substitute_the_measured_head(self):
        accepted = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True
        ).strip()
        (self.repo / "subject.txt").write_text(
            "substituted-private-bytes\n", encoding="utf-8"
        )
        subprocess.run(["git", "add", "subject.txt"], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "substitute"], cwd=self.repo, check=True
        )
        substitute = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, text=True
        ).strip()
        subprocess.run(
            ["git", "replace", accepted, substitute], cwd=self.repo, check=True
        )
        subprocess.run(
            ["git", "reset", "--hard", "-q", accepted], cwd=self.repo, check=True
        )
        self.assertEqual(
            subprocess.check_output(
                ["git", "status", "--porcelain", "--untracked-files=all"],
                cwd=self.repo,
                text=True,
            ),
            "",
        )

        with self.assertRaisesRegex(ValueError, "clean HEAD"):
            self.module.require_clean_head()

    def test_receipt_records_matching_pre_and_post_source_identity(self):
        identity = self.module.require_clean_head()
        receipt = self.repo / "receipt.json"
        setattr(self.module, "OUT", receipt)
        ledger = [self.module.LedgerEntry("case", "killed")]
        stats = {"survived_the_mutation": 0, "survivors": []}

        with mock.patch.object(self.module, "tree_manifest", return_value=b"artifact"):
            with mock.patch.object(
                self.module, "run_defect_model", return_value=(ledger, stats)
            ):
                with mock.patch.object(self.module, "refuse_partial", return_value=None):
                    with mock.patch.object(
                        sys, "argv", [str(SCRIPT)]
                    ), contextlib.redirect_stdout(io.StringIO()):
                        exit_code = self.module.main()

        self.assertEqual(exit_code, 0)
        outcome = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(outcome["source"]["pre"], identity)
        self.assertEqual(outcome["source"]["post"], identity)

    def test_head_movement_after_measurement_is_refused(self):
        identity = self.module.require_clean_head()
        (self.repo / "second.txt").write_text("new\n", encoding="utf-8")
        subprocess.run(["git", "add", "second.txt"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "move head"], cwd=self.repo, check=True)
        with self.assertRaisesRegex(ValueError, "changed during measurement"):
            self.module.assert_same_clean_head(identity)


class ReusedSabotageEvidenceIsNotCurrentHeadEvidence(unittest.TestCase):
    def test_readme_requires_a_fresh_current_head_measurement(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("self_admit.py --reuse", readme)
        self.assertIn("python3 scripts/self_admit.py", readme)
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", "_sabotage.log"],
            cwd=ROOT,
            check=False,
        )
        self.assertEqual(ignored.returncode, 0)

    def test_reuse_is_refused_before_a_receipt_can_be_written(self):
        module = _load_self_admit()
        labels = module.case_labels()
        forged = "".join(
            f"RED (good)             {label} -> fake-suite: forged\n"
            for label in labels
        )
        forged += (
            "\n"
            "undetected sabotage: none\n"
            "source integrity: every target byte-identical to pre-run\n"
            "live sabotage residue: none\n"
        )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            log = root / "forged.log"
            log.write_text(forged, encoding="utf-8")
            receipt = root / "receipt.json"
            setattr(module, "OUT", receipt)
            stderr = io.StringIO()
            with mock.patch.object(sys, "argv", [str(SCRIPT), "--reuse", str(log)]):
                with contextlib.redirect_stderr(stderr):
                    exit_code = module.main()

            self.assertEqual(exit_code, 2)
            self.assertIn("reuse", stderr.getvalue().lower())
            self.assertIn("fresh", stderr.getvalue().lower())
            self.assertFalse(receipt.exists())


if __name__ == "__main__":
    unittest.main()
