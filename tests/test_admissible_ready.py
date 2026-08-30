"""RED contract for the friendly human + agent Ready surface."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import TempCase, git, make_repo, require_module  # noqa: E402

cli = require_module("admissible.cli")
ready = require_module("admissible.ready")
agent_mcp = require_module("admissible.agent_mcp")
schema_module = require_module("admissible.schema")
agent_connection = require_module("admissible.agent_connection")
config_module = require_module("admissible.config")
decision_module = require_module("admissible.decision")
ROOT = Path(__file__).resolve().parent.parent


def decision_document(*, state="CHECKS_PASSED", readiness="READY_FOR_ATTESTATION",
                      reasons=(), remediation=(), checks=()):
    return {
        "scope": "developer-workflow-admission",
        "state": state,
        "readiness": readiness,
        "repository": "github.com/acme/widget",
        "commit_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "policy_digest": "c" * 64,
        "class_id": "default",
        "attempt_id": "d" * 32,
        "reasons": list(reasons),
        "remediation": list(remediation),
        "checks": list(checks),
        "independent_reviews": 0,
        "required_independent_reviews": 0,
        "exit_code": 0 if state == "CHECKS_PASSED" else 1,
    }


class ReadyMappingTest(unittest.TestCase):
    def test_passing_preview_is_checks_complete_not_ready(self):
        document = ready.from_evaluation(decision_document())
        self.assertEqual(document["schema"], "admissible/v0.7/ready-state")
        self.assertEqual(document["status"], "checks_complete")
        self.assertEqual(document["canonical"]["state"], "CHECKS_PASSED")
        self.assertEqual(document["canonical"]["readiness"],
                         "READY_FOR_ATTESTATION")
        self.assertNotEqual(document["status"], "ready")
        self.assertEqual(document["identity"]["commit_sha"], "a" * 40)
        self.assertTrue(document["identity"]["applies_to_current_commit"])
        self.assertEqual(document["next_actions"][0]["owner"],
                         "trusted_infrastructure")

    def test_missing_review_is_friendly_and_reviewer_owned(self):
        source = decision_document(
            state="REFUSED", readiness="AWAITING_REVIEW",
            reasons=[{"code": "missing_independent_review",
                      "subject": "default", "detail": "one review is needed"}],
            remediation=["attach one authenticated independent review"])
        document = ready.from_evaluation(source)
        self.assertEqual(document["status"], "waiting_for_review")
        self.assertIn("review", document["summary"].lower())
        self.assertEqual(document["next_actions"][0]["owner"], "reviewer")
        self.assertEqual(document["next_actions"][0]["reason_codes"],
                         ["missing_independent_review"])

    def test_failed_check_has_stable_agent_action(self):
        source = decision_document(
            state="REFUSED", readiness="NOT_READY",
            reasons=[{"code": "failed_check", "subject": "unit",
                      "detail": "unit exited 1"}],
            remediation=["fix check 'unit', then run Admissible again"],
            checks=[{"check_id": "unit", "required": True,
                     "status": "failed", "exit_code": 1,
                     "duration_ms": 15, "provenance": "recorded",
                     "attempt_id": "d" * 32, "reused_from_attempt": ""}])
        document = ready.from_evaluation(source)
        self.assertEqual(document["status"], "needs_attention")
        action = document["next_actions"][0]
        self.assertEqual(action["id"], "fix_check")
        self.assertEqual(action["owner"], "agent_or_human")
        self.assertTrue(action["retryable"])
        self.assertEqual(action["reason_codes"], ["failed_check"])

    def test_blocked_evaluation_is_unable_to_check(self):
        source = decision_document(
            state="BLOCKED", readiness="NOT_READY",
            reasons=[{"code": "dirty_worktree", "subject": "repository",
                      "detail": "worktree is dirty"}],
            remediation=["commit or stash the change"])
        source["exit_code"] = 2
        document = ready.from_evaluation(source)
        self.assertEqual(document["status"], "unable_to_check")
        self.assertEqual(document["canonical"]["state"], "BLOCKED")
        self.assertEqual(document["next_actions"][0]["owner"], "human")

    def test_ready_document_validates_against_the_packaged_closed_schema(self):
        jsonschema = require_module("jsonschema")

        schema = schema_module.ready_schema()
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(ready.from_evaluation(decision_document()), schema)
        self.assertFalse(schema["additionalProperties"])

    def test_authenticated_ready_with_no_remaining_action_validates(self):
        jsonschema = require_module("jsonschema")

        document = ready.from_evaluation(decision_document())
        document["status"] = "ready"
        document["canonical"].update({
            "state": "ADMITTED", "standing": "CURRENT",
        })
        document["next_actions"] = []
        document["agent_can_continue"] = False
        jsonschema.validate(document, schema_module.ready_schema())

    def test_unsigned_preview_cannot_be_relabelled_ready(self):
        jsonschema = require_module("jsonschema")

        document = ready.from_evaluation(decision_document())
        document["status"] = "ready"
        document["next_actions"] = []
        document["agent_can_continue"] = False
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(document, schema_module.ready_schema())

    def test_authenticated_terminal_state_must_use_ready_status(self):
        jsonschema = require_module("jsonschema")

        document = ready.from_evaluation(decision_document())
        document["canonical"].update({
            "state": "ADMITTED", "standing": "CURRENT", "exit_code": 0,
        })
        document["agent_can_continue"] = False
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(document, schema_module.ready_schema())

    def test_non_ready_state_cannot_omit_its_next_action(self):
        jsonschema = require_module("jsonschema")

        document = ready.from_evaluation(decision_document())
        document["next_actions"] = []
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(document, schema_module.ready_schema())

    def test_ready_status_requires_non_null_exact_artifact_identity(self):
        jsonschema = require_module("jsonschema")
        document = ready.from_evaluation(decision_document())
        document["status"] = "ready"
        document["canonical"].update({
            "state": "ADMITTED", "standing": "CURRENT", "exit_code": 0,
        })
        document["identity"].update({
            "repository": None, "commit_sha": None, "tree_sha": None,
            "policy_digest": None, "class_id": None, "attempt_id": None,
            "applies_to_current_commit": True,
        })
        document["next_actions"] = []
        document["agent_can_continue"] = False
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(document, schema_module.ready_schema())

    def test_optional_failure_copy_says_only_required_checks_passed(self):
        source = decision_document(checks=[
            {"check_id": "required", "required": True,
             "status": "passed", "exit_code": 0, "duration_ms": 1,
             "provenance": "recorded", "attempt_id": "d" * 32,
             "reused_from_attempt": ""},
            {"check_id": "advisory", "required": False,
             "status": "failed", "exit_code": 1, "duration_ms": 1,
             "provenance": "recorded", "attempt_id": "d" * 32,
             "reused_from_attempt": ""},
        ])
        document = ready.from_evaluation(source)
        self.assertEqual(document["status"], "checks_complete")
        self.assertIn("All required checks passed", document["summary"])
        self.assertIn("1 optional check failed", document["summary"])
        self.assertNotIn("Checks passed.", document["summary"])


class ReadyInspectionTest(TempCase):
    def test_dirty_worktree_keeps_provable_repository_and_head_identity(self):
        repo = self.tmp / "repo"
        make_repo(repo)
        sha = git(repo, "rev-parse", "HEAD")
        (repo / "dirty.txt").write_text("not committed\n", encoding="utf-8")
        document = ready.inspect(str(repo))
        self.assertEqual(document["status"], "unable_to_check")
        self.assertEqual(document["identity"]["commit_sha"], sha)
        self.assertFalse(document["identity"]["applies_to_current_commit"])
        self.assertTrue(document["identity"]["repository"])
        self.assertEqual(document["reasons"][0]["code"], "dirty_worktree")

    def test_authenticated_standing_presents_only_its_exact_receipt_attempt(self):
        admitted = decision_document()
        rogue = decision_document()
        rogue.update({
            "attempt_id": "e" * 32,
            "class_id": "rogue",
            "policy_digest": "f" * 64,
        })
        found = ready.identity_module.Identity(
            repository=admitted["repository"],
            commit_sha=admitted["commit_sha"],
            tree_sha=admitted["tree_sha"], root="/candidate", dirty=False)
        receipt = SimpleNamespace(
            repository=admitted["repository"],
            commit_sha=admitted["commit_sha"],
            tree_sha=admitted["tree_sha"],
            policy_digest=admitted["policy_digest"],
            class_id=admitted["class_id"],
            attempt_id=admitted["attempt_id"],
            decision_digest=decision_module.digest_of_document(admitted),
            authenticated_reviews=(), issued_at=10, receipt_hash="1" * 64)
        opened = mock.MagicMock()
        opened.latest_attempt.return_value = {
            "attempt_id": rogue["attempt_id"], "class_id": rogue["class_id"],
            "policy_digest": rogue["policy_digest"],
            "tree_sha": rogue["tree_sha"], "decision": rogue,
        }
        opened.attempt.return_value = {
            "attempt_id": admitted["attempt_id"],
            "repository": admitted["repository"],
            "commit_sha": admitted["commit_sha"],
            "class_id": admitted["class_id"],
            "policy_digest": admitted["policy_digest"],
            "tree_sha": admitted["tree_sha"], "decision": admitted,
        }
        standing = ready.standing_module.Standing(
            state=ready.standing_module.CURRENT,
            repository=found.repository,
            commit_sha=found.commit_sha,
            receipts=(receipt,), defects=(), unknown_scope=False)
        with mock.patch.object(ready.identity_module, "repository_identity",
                               return_value=found), \
                mock.patch.object(ready.store_module, "open_store",
                                  return_value=opened), \
                mock.patch.object(ready.standing_module, "current_standing",
                                  return_value=standing):
            document = ready.inspect("/candidate", signer=object())
        self.assertEqual(document["status"], "ready")
        self.assertEqual(document["identity"]["attempt_id"],
                         admitted["attempt_id"])
        self.assertEqual(document["identity"]["class_id"], "default")
        self.assertEqual(document["advanced"]["check_evidence"], "unavailable")
        opened.latest_attempt.assert_not_called()
        opened.attempt.assert_not_called()

    def test_authenticated_impeachment_does_not_require_a_local_attempt_row(self):
        found = ready.identity_module.Identity(
            repository="github.com/acme/widget",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            root="/candidate", dirty=False)
        receipt = SimpleNamespace(
            repository=found.repository,
            commit_sha=found.commit_sha,
            tree_sha=found.tree_sha,
            policy_digest="c" * 64,
            class_id="default",
            attempt_id="d" * 64,
            issued_at="2026-08-26T10:00:00Z",
            receipt_hash="e" * 64,
            decision_digest="f" * 64,
            authenticated_reviews=())
        defect = {
            "kind": "defect", "defect_id": "defect-1",
            "repository": found.repository, "commit_sha": found.commit_sha,
            "severity": "high", "summary": "The accepted result is wrong.",
            "discovered_at": 1,
        }
        standing = ready.standing_module.Standing(
            state=ready.standing_module.IMPEACHED,
            repository=found.repository,
            commit_sha=found.commit_sha,
            receipts=(receipt,), defects=(defect,), unknown_scope=False)
        opened = mock.MagicMock()
        opened.receipts_for.return_value = (receipt,)

        with mock.patch.object(
                ready.store_module, "open_store", return_value=opened), \
             mock.patch.object(
                ready.standing_module, "current_standing",
                return_value=standing), \
             mock.patch.object(
                ready.identity_module, "repository_identity",
                return_value=found):
            document = ready.inspect(
                "/candidate", signer=object(), identity=found)

        self.assertEqual(document["status"], "needs_attention")
        self.assertEqual(document["canonical"]["state"], "ADMITTED")
        self.assertEqual(
            document["canonical"]["standing"],
            ready.standing_module.IMPEACHED)
        self.assertEqual(document["identity"]["attempt_id"], receipt.attempt_id)
        self.assertEqual(document["advanced"]["receipt_hash"], receipt.receipt_hash)
        self.assertEqual(document["reasons"][0]["code"], "impeached")
        self.assertIn("wrong", document["reasons"][0]["detail"])
        opened.latest_attempt.assert_not_called()
        opened.attempt.assert_not_called()

    def test_authenticated_integrity_problem_never_falls_back_to_preview(self):
        found = ready.identity_module.Identity(
            repository="github.com/acme/widget",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            root="/candidate", dirty=False)
        receipt = SimpleNamespace(receipt_hash="e" * 64)
        corrupted = ready.standing_module.Standing(
            state=ready.standing_module.UNKNOWN,
            repository=found.repository,
            commit_sha=found.commit_sha,
            receipts=(), defects=(), unknown_scope=True,
            historical_receipts=(receipt,),
            integrity_problem=(
                "signed receipt/attachment bijection is not exact"))
        preview = decision_document()
        opened = mock.MagicMock()
        opened.latest_attempt.return_value = {
            "attempt_id": preview["attempt_id"],
            "class_id": preview["class_id"],
            "policy_digest": preview["policy_digest"],
            "tree_sha": preview["tree_sha"],
            "decision": preview,
        }
        opened.receipts_for.return_value = (receipt,)

        with mock.patch.object(
                ready.store_module, "open_store", return_value=opened), \
             mock.patch.object(
                ready.standing_module, "current_standing",
                return_value=corrupted), \
             mock.patch.object(
                ready.identity_module, "repository_identity",
                return_value=found):
            document = ready.inspect(
                "/candidate", signer=object(), identity=found)

        self.assertEqual(document["status"], "unable_to_check")
        self.assertEqual(
            document["canonical"]["standing"],
            ready.standing_module.UNKNOWN)
        self.assertEqual(
            document["reasons"][0]["code"],
            "authenticated_journal_integrity")
        self.assertIn("bijection", document["reasons"][0]["detail"])
        self.assertFalse(document["agent_can_continue"])
        opened.latest_attempt.assert_not_called()
        opened.receipts_for.assert_not_called()

    def test_authenticated_defect_without_receipt_never_claims_admission(self):
        found = ready.identity_module.Identity(
            repository="github.com/acme/widget",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            root="/candidate", dirty=False)
        defect = {
            "kind": "defect", "defect_id": "defect-only",
            "repository": found.repository, "commit_sha": found.commit_sha,
            "severity": "high", "summary": "The result is unsafe.",
            "discovered_at": 1,
        }
        standing = ready.standing_module.Standing(
            state=ready.standing_module.IMPEACHED,
            repository=found.repository,
            commit_sha=found.commit_sha,
            receipts=(), defects=(defect,), unknown_scope=False)
        opened = mock.MagicMock()
        opened.latest_attempt.return_value = {
            "attempt_id": "d" * 32, "class_id": "default",
            "policy_digest": "c" * 64, "tree_sha": found.tree_sha,
            "decision": decision_document(),
        }

        with mock.patch.object(
                ready.store_module, "open_store", return_value=opened), \
             mock.patch.object(
                ready.standing_module, "current_standing",
                return_value=standing), \
             mock.patch.object(
                ready.identity_module, "repository_identity",
                return_value=found):
            document = ready.inspect(
                "/candidate", signer=object(), identity=found)

        self.assertEqual(document["status"], "needs_attention")
        self.assertNotEqual(document["canonical"]["state"], "ADMITTED")
        self.assertEqual(
            document["canonical"]["standing"],
            ready.standing_module.IMPEACHED)
        self.assertEqual(document["reasons"][0]["code"], "impeached")
        self.assertIn("unsafe", document["reasons"][0]["detail"])
        self.assertFalse(document["agent_can_continue"])
        opened.latest_attempt.assert_not_called()
        opened.attempt.assert_not_called()

    def test_legacy_authenticated_receipt_with_empty_attempt_id_is_ready(self):
        found = ready.identity_module.Identity(
            repository="github.com/acme/widget",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            root="/candidate", dirty=False)
        receipt = SimpleNamespace(
            repository=found.repository, commit_sha=found.commit_sha,
            tree_sha=found.tree_sha, policy_digest="c" * 64,
            class_id="default", attempt_id="", issued_at=1,
            receipt_hash="e" * 64, decision_digest="f" * 64,
            authenticated_reviews=())
        standing = ready.standing_module.Standing(
            state=ready.standing_module.CURRENT,
            repository=found.repository,
            commit_sha=found.commit_sha,
            receipts=(receipt,), defects=(), unknown_scope=False)
        opened = mock.MagicMock()

        with mock.patch.object(
                ready.store_module, "open_store", return_value=opened), \
             mock.patch.object(
                ready.standing_module, "current_standing",
                return_value=standing), \
             mock.patch.object(
                ready.identity_module, "repository_identity",
                return_value=found):
            document = ready.inspect(
                "/candidate", signer=object(), identity=found)

        self.assertEqual(document["status"], "ready")
        self.assertIsNone(document["identity"]["attempt_id"])
        require_module("jsonschema").validate(
            document, schema_module.ready_schema())
        opened.latest_attempt.assert_not_called()
        opened.attempt.assert_not_called()

    def test_receipt_only_ready_state_marks_required_review_quorum_unknown(self):
        found = ready.identity_module.Identity(
            repository="github.com/acme/widget",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            root="/candidate", dirty=False)
        receipt = SimpleNamespace(
            repository=found.repository, commit_sha=found.commit_sha,
            tree_sha=found.tree_sha, policy_digest="c" * 64,
            class_id="default", attempt_id="d" * 32, issued_at=1,
            receipt_hash="e" * 64, decision_digest="f" * 64,
            authenticated_reviews=("r" * 64,))
        standing = ready.standing_module.Standing(
            state=ready.standing_module.CURRENT,
            repository=found.repository,
            commit_sha=found.commit_sha,
            receipts=(receipt,), defects=(), unknown_scope=False)
        opened = mock.MagicMock()

        with mock.patch.object(
                ready.store_module, "open_store", return_value=opened), \
             mock.patch.object(
                ready.standing_module, "current_standing",
                return_value=standing), \
             mock.patch.object(
                ready.identity_module, "repository_identity",
                return_value=found):
            document = ready.inspect(
                "/candidate", signer=object(), identity=found)

        self.assertEqual(document["status"], "ready")
        self.assertEqual(document["advanced"]["independent_reviews"], 1)
        self.assertIsNone(
            document["advanced"]["required_independent_reviews"])
        require_module("jsonschema").validate(
            document, schema_module.ready_schema())

    def test_unsigned_attempt_with_nested_identity_drift_is_refused(self):
        found = ready.identity_module.Identity(
            repository="github.com/acme/widget",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            root="/candidate", dirty=False)
        rogue = decision_document()
        rogue.update({
            "repository": "github.com/other/repo",
            "commit_sha": "c" * 40,
            "tree_sha": "d" * 40,
            "attempt_id": "e" * 32,
        })
        standing = ready.standing_module.Standing(
            state=ready.standing_module.UNKNOWN,
            repository=found.repository,
            commit_sha=found.commit_sha,
            receipts=(), defects=(), unknown_scope=False)
        opened = mock.MagicMock()
        opened.latest_attempt.return_value = {
            "attempt_id": "f" * 32,
            "repository": found.repository,
            "commit_sha": found.commit_sha,
            "class_id": "default",
            "policy_digest": "c" * 64,
            "tree_sha": found.tree_sha,
            "decision": rogue,
        }
        opened.receipts_for.return_value = ()

        with mock.patch.object(
                ready.store_module, "open_store", return_value=opened), \
             mock.patch.object(
                ready.standing_module, "current_standing",
                return_value=standing), \
             mock.patch.object(
                ready.identity_module, "repository_identity",
                return_value=found):
            document = ready.inspect("/candidate", identity=found)

        self.assertEqual(document["status"], "unable_to_check")
        self.assertEqual(
            document["reasons"][0]["code"],
            "stored_attempt_identity_mismatch")
        self.assertFalse(document["identity"]["applies_to_current_commit"])

    def test_head_change_during_authenticated_inspection_cannot_report_ready(self):
        found = ready.identity_module.Identity(
            repository="github.com/acme/widget",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            root="/candidate", dirty=False)
        moved = ready.identity_module.Identity(
            repository=found.repository,
            commit_sha="c" * 40,
            tree_sha="d" * 40,
            root=found.root, dirty=False)
        receipt = SimpleNamespace(
            repository=found.repository, commit_sha=found.commit_sha,
            tree_sha=found.tree_sha, policy_digest="c" * 64,
            class_id="default", attempt_id="d" * 32, issued_at=1,
            receipt_hash="e" * 64, decision_digest="f" * 64,
            authenticated_reviews=())
        standing = ready.standing_module.Standing(
            state=ready.standing_module.CURRENT,
            repository=found.repository,
            commit_sha=found.commit_sha,
            receipts=(receipt,), defects=(), unknown_scope=False)
        opened = mock.MagicMock()

        with mock.patch.object(
                ready.store_module, "open_store", return_value=opened), \
             mock.patch.object(
                ready.standing_module, "current_standing",
                return_value=standing), \
             mock.patch.object(
                ready.identity_module, "repository_identity",
                return_value=moved):
            document = ready.inspect(
                "/candidate", signer=object(), identity=found)

        self.assertEqual(document["status"], "unable_to_check")
        self.assertEqual(document["reasons"][0]["code"], "identity_changed")
        self.assertFalse(document["identity"]["applies_to_current_commit"])

    def test_closing_identity_error_during_authenticated_inspection_cannot_report_ready(self):
        found = ready.identity_module.Identity(
            repository="github.com/acme/widget",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            root="/candidate", dirty=False)
        receipt = SimpleNamespace(
            repository=found.repository, commit_sha=found.commit_sha,
            tree_sha=found.tree_sha, policy_digest="c" * 64,
            class_id="default", attempt_id="d" * 32, issued_at=1,
            receipt_hash="e" * 64, decision_digest="f" * 64,
            authenticated_reviews=())
        standing = ready.standing_module.Standing(
            state=ready.standing_module.CURRENT,
            repository=found.repository,
            commit_sha=found.commit_sha,
            receipts=(receipt,), defects=(), unknown_scope=False)
        opened = mock.MagicMock()

        with mock.patch.object(
                ready.store_module, "open_store", return_value=opened), \
             mock.patch.object(
                ready.standing_module, "current_standing",
                return_value=standing), \
             mock.patch.object(
                ready.identity_module, "repository_identity",
                side_effect=ready.identity_module.IdentityError(
                    "HEAD could not be read")):
            document = ready.inspect(
                "/candidate", signer=object(), identity=found)

        self.assertEqual(document["status"], "unable_to_check")
        self.assertEqual(document["reasons"][0]["code"], "identity_changed")
        self.assertFalse(document["identity"]["applies_to_current_commit"])
        self.assertNotEqual(document["status"], "ready")

    def test_authenticated_store_error_never_falls_back_to_preview(self):
        found = ready.identity_module.Identity(
            repository="github.com/acme/widget",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            root="/candidate", dirty=False)
        preview = decision_document()
        opened = mock.MagicMock()
        opened.latest_attempt.return_value = {
            "attempt_id": preview["attempt_id"],
            "class_id": preview["class_id"],
            "policy_digest": preview["policy_digest"],
            "tree_sha": preview["tree_sha"],
            "decision": preview,
        }
        # Standing is computed for real here. Stubbing it out would leave the
        # store-error branch of current_standing untested, and that branch is
        # the one that has to fail closed rather than hand back an empty
        # projection the caller cannot tell from an honest answer.
        opened.authenticated_workflow_state.side_effect = (
            ready.store_module.StoreError("journal unreadable"))

        with mock.patch.object(
                ready.store_module, "open_store", return_value=opened), \
             mock.patch.object(
                ready.identity_module, "repository_identity",
                return_value=found):
            document = ready.inspect(
                "/candidate", signer=object(), identity=found)

        opened.authenticated_workflow_state.assert_called_once()

        self.assertEqual(document["status"], "unable_to_check")
        self.assertEqual(
            document["canonical"]["standing"],
            ready.standing_module.UNKNOWN)
        self.assertEqual(
            document["reasons"][0]["code"],
            "authenticated_journal_integrity")
        self.assertIn("journal unreadable", document["reasons"][0]["detail"])
        self.assertFalse(document["agent_can_continue"])
        opened.latest_attempt.assert_not_called()


class FriendlyCheckCLITest(TempCase):
    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "repo"

    def make(self, check_exit=0):
        make_repo(self.repo)
        config = {
            "version": 1,
            "profile": "python-library",
            "classes": [{
                "id": "default",
                "checks": [{
                    "id": "unit",
                    "argv": [sys.executable, "-c",
                             f"raise SystemExit({check_exit})"],
                    "timeout_seconds": 30,
                    "cost_units": 1,
                    "required": True,
                    "version": "1",
                }],
                "required_independent_reviews": 0,
                "review_max_age_seconds": 86400,
                "max_cost_units": 10,
                "max_wall_seconds": 60,
            }],
        }
        (self.repo / ".admissible.json").write_text(
            json.dumps(config), encoding="utf-8")
        git(self.repo, "add", ".admissible.json")
        git(self.repo, "commit", "-q", "-m", "policy")
        return git(self.repo, "rev-parse", "HEAD")

    def invoke(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(list(argv), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_check_defaults_to_exact_head_and_returns_ready_json(self):
        sha = self.make()
        code, out, err = self.invoke("check", "--repo", str(self.repo), "--json")
        self.assertEqual(code, 0, err + out)
        document = json.loads(out)
        self.assertEqual(document["schema"], "admissible/v0.7/ready-state")
        self.assertEqual(document["identity"]["commit_sha"], sha)
        self.assertEqual(document["status"], "checks_complete")
        self.assertNotEqual(document["status"], "ready")

    def test_check_refuses_to_share_a_process_with_any_signing_secret(self):
        self.make()
        os.environ["ADMISSIBLE_REVIEW_KEY"] = "must-not-reach-candidate-code"
        code, out, err = self.invoke("check", "--repo", str(self.repo), "--json")
        self.assertEqual(code, 2)
        document = json.loads(out)
        self.assertEqual(document["status"], "unable_to_check")
        self.assertIn("credential", document["summary"].lower())
        self.assertNotIn("must-not-reach-candidate-code", out + err)

    def test_plain_check_leads_with_status_and_one_next_action(self):
        self.make(check_exit=1)
        code, out, err = self.invoke("check", "--repo", str(self.repo))
        self.assertEqual(code, 1, err + out)
        self.assertTrue(out.startswith("Needs attention:"), out)
        self.assertEqual(out.count("Next:"), 1)
        self.assertIn("Technical details:", out)

    def test_ready_status_git_children_never_inherit_signing_credentials(self):
        self.make()
        original_run = subprocess.run
        observed = []

        def guarded(*args, **kwargs):
            child_environment = kwargs.get("env")
            if child_environment is None:
                self.fail("Git child was started without an explicit environment")
            self.assertNotIn("ADMISSIBLE_HMAC_KEY", child_environment)
            self.assertNotIn("ADMISSIBLE_HMAC_KEY_FILE", child_environment)
            observed.append(tuple(args[0]))
            return original_run(*args, **kwargs)

        old = os.environ.get("ADMISSIBLE_HMAC_KEY")
        os.environ["ADMISSIBLE_HMAC_KEY"] = "must-not-reach-git"
        try:
            with mock.patch("admissible.identity.subprocess.run",
                            side_effect=guarded):
                self.invoke("ready-status", "--repo", str(self.repo), "--json")
        finally:
            if old is None:
                os.environ.pop("ADMISSIBLE_HMAC_KEY", None)
            else:
                os.environ["ADMISSIBLE_HMAC_KEY"] = old
        self.assertTrue(observed)

    def test_default_config_symlink_cannot_escape_repository(self):
        self.make()
        default_path = self.repo / ".admissible.json"
        outside = self.tmp / "outside-policy.json"
        outside.write_bytes(default_path.read_bytes())
        default_path.unlink()
        default_path.symlink_to(outside)

        with self.assertRaises(config_module.ConfigError):
            config_module.load_config(self.repo)

    def test_trusted_status_never_executes_repository_fsmonitor(self):
        self.make()
        marker = self.tmp / "fsmonitor-ran"
        hook = self.tmp / "candidate-fsmonitor.sh"
        hook.write_text(
            "#!/bin/sh\nprintf ran > " + str(marker) + "\nprintf '\\n'\n",
            encoding="utf-8")
        hook.chmod(0o700)
        git(self.repo, "config", "core.fsmonitor", str(hook))
        old = os.environ.get("ADMISSIBLE_HMAC_KEY")
        os.environ["ADMISSIBLE_HMAC_KEY"] = "trusted-status-canary"
        try:
            self.invoke(
                "ready-status", "--repo", str(self.repo), "--json")
        finally:
            if old is None:
                os.environ.pop("ADMISSIBLE_HMAC_KEY", None)
            else:
                os.environ["ADMISSIBLE_HMAC_KEY"] = old
        self.assertFalse(
            marker.exists(),
            "trusted status executed repository-configured Git code")


class MCPContractTest(unittest.TestCase):
    def test_initialize_then_list_exposes_only_bounded_ready_tools(self):
        server = agent_mcp.Server(
            repo=".", agent_name="Builder",
            purpose="Implement the requested change", runtime="custom")
        initialized = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "contract-test", "version": "1"},
            },
        })
        self.assertEqual(initialized["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(initialized["result"]["capabilities"],
                         {"tools": {"listChanged": False}})
        self.assertIsNone(server.handle({
            "jsonrpc": "2.0", "method": "notifications/initialized"}))
        listing = server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        names = [item["name"] for item in listing["result"]["tools"]]
        self.assertEqual(names, [
            "admissible_get_state",
            "admissible_get_work_package",
            "admissible_check",
            "admissible_get_remediation",
        ])
        self.assertNotIn("finalize", " ".join(names))
        self.assertNotIn("policy", " ".join(names))
        for tool in listing["result"]["tools"]:
            self.assertEqual(tool["inputSchema"]["type"], "object")
            self.assertIn("outputSchema", tool)
        ready_tools = {item["name"]: item for item in listing["result"]["tools"]}
        self.assertEqual(ready_tools["admissible_get_state"]["outputSchema"],
                         schema_module.ready_schema())
        self.assertEqual(ready_tools["admissible_check"]["outputSchema"],
                         schema_module.ready_schema())
        self.assertEqual(
            ready_tools["admissible_check"]["inputSchema"]["properties"]["package_id"],
            {"type": "string", "pattern": "^[0-9a-f]{64}$"})
        self.assertIn(
            "package_id",
            ready_tools["admissible_check"]["inputSchema"]["required"])
        for name in ("admissible_get_state", "admissible_get_work_package",
                     "admissible_get_remediation"):
            self.assertFalse(ready_tools[name]["annotations"]["readOnlyHint"])
        self.assertFalse(
            ready_tools["admissible_get_work_package"]["annotations"]["idempotentHint"])

    def test_every_structured_tool_output_has_a_versioned_closed_schema(self):
        tools = {item["name"]: item for item in agent_mcp.Server.tools()}
        ready_schema = schema_module.ready_schema()
        package_schema = schema_module.work_package_schema()
        remediation_schema = schema_module.remediation_schema()
        self.assertEqual(
            tools["admissible_get_state"]["outputSchema"], ready_schema)
        self.assertEqual(
            tools["admissible_check"]["outputSchema"], ready_schema)
        self.assertEqual(
            tools["admissible_get_work_package"]["outputSchema"],
            package_schema)
        self.assertEqual(
            tools["admissible_get_remediation"]["outputSchema"],
            remediation_schema)
        for document in (ready_schema, package_schema, remediation_schema):
            self.assertFalse(document["additionalProperties"])
        self.assertFalse(
            ready_schema["properties"]["checks"]["items"]
            ["additionalProperties"])
        self.assertFalse(
            ready_schema["properties"]["advanced"]["additionalProperties"])
        validator = require_module("jsonschema")
        validator.Draft202012Validator.check_schema(package_schema)
        validator.Draft202012Validator.check_schema(remediation_schema)

    def test_request_before_initialize_is_protocol_error(self):
        server = agent_mcp.Server(
            repo=".", agent_name="Builder", purpose="Code", runtime="custom")
        response = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        self.assertEqual(response["error"]["code"], -32002)

    def test_request_only_notification_is_silent_and_never_executes(self):
        server = self.initialized_server()
        with mock.patch.object(server, "_call_tool", return_value={}) as call:
            response = server.handle({
                "jsonrpc": "2.0", "method": "tools/call",
                "params": {"name": "admissible_get_state", "arguments": {}},
            })
        self.assertIsNone(response)
        call.assert_not_called()

    def test_initialized_notification_must_not_be_a_request_or_carry_params(self):
        server = agent_mcp.Server(
            repo=".", agent_name="Builder", purpose="Code", runtime="custom")
        server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}},
        })
        response = server.handle({
            "jsonrpc": "2.0", "id": 2,
            "method": "notifications/initialized", "params": {},
        })
        self.assertEqual(response["error"]["code"], -32600)
        self.assertEqual(server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {},
        })["error"]["code"], -32002)
        self.assertIsNone(server.handle({
            "jsonrpc": "2.0", "method": "notifications/initialized",
            "params": {"surprise": True},
        }))
        self.assertEqual(server.handle({
            "jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {},
        })["error"]["code"], -32002)

    def test_no_argument_tool_call_may_omit_arguments(self):
        server = self.initialized_server()
        expected = {"schema": "admissible/v0.7/ready-state"}
        with mock.patch.object(server, "_call_tool", return_value=expected) as call:
            response = server.handle({
                "jsonrpc": "2.0", "id": 8, "method": "tools/call",
                "params": {"name": "admissible_get_state"},
            })
        self.assertNotIn("error", response)
        self.assertEqual(response["result"]["structuredContent"], expected)
        call.assert_called_once_with("admissible_get_state", {})

    def test_version_negotiation_and_unknown_arguments_fail_closed(self):
        server = agent_mcp.Server(
            repo=".", agent_name="Builder", purpose="Code", runtime="custom")
        response = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "old", "version": "1"}},
        })
        self.assertEqual(response["result"]["protocolVersion"], "2025-06-18")

        server = self.initialized_server()
        response = server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list",
            "params": {"surprise": True},
        })
        self.assertEqual(response["error"]["code"], -32602)

    def test_ping_and_request_metadata_follow_mcp_2025_06_18(self):
        server = agent_mcp.Server(
            repo=".", agent_name="Builder", purpose="Code", runtime="custom")
        initialized = server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
                "_meta": {"trace": "init"},
            },
        })
        self.assertNotIn("error", initialized)
        ping = server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "ping",
            "params": {"_meta": {"trace": "ping"}},
        })
        self.assertEqual(ping, {"jsonrpc": "2.0", "id": 2, "result": {}})
        server.handle({"jsonrpc": "2.0",
                       "method": "notifications/initialized"})
        listing = server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/list",
            "params": {"_meta": {"trace": "list"}},
        })
        self.assertNotIn("error", listing)
        with mock.patch.object(
                server, "_call_tool",
                return_value={"schema": "admissible/v0.7/ready-state"}) as call:
            called = server.handle({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {
                    "name": "admissible_get_state", "arguments": {},
                    "_meta": {"trace": "call"},
                },
            })
        self.assertNotIn("error", called)
        call.assert_called_once_with("admissible_get_state", {})

    def test_stdio_writes_only_one_line_json_rpc_messages(self):
        source = io.StringIO("\n".join((
            json.dumps({"jsonrpc": "2.0", "id": 1,
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18",
                                   "capabilities": {},
                                   "clientInfo": {"name": "test",
                                                  "version": "1"}}}),
            json.dumps({"jsonrpc": "2.0",
                        "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2,
                        "method": "tools/list", "params": {}}),
        )) + "\n")
        out, err = io.StringIO(), io.StringIO()
        code = agent_mcp.serve_stdio(
            agent_mcp.Server(repo=".", agent_name="Builder",
                             purpose="Code", runtime="custom"),
            stdin=source, stdout=out, stderr=err)
        self.assertEqual(code, 0)
        messages = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([item["id"] for item in messages], [1, 2])
        self.assertEqual(err.getvalue(), "")

    def test_stdio_rejects_oversized_frames_before_unbounded_iteration(self):
        initialize = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18",
                       "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}},
        }) + "\n"

        class GuardedInput:
            def __init__(self):
                self.source = io.StringIO(
                    "x" * (agent_mcp._MAX_MESSAGE_BYTES + 20) + "\n" +
                    initialize)
                self.sizes = []

            def readline(self, size=-1):
                if size < 0:
                    raise AssertionError("stdio read was not allocation-bounded")
                self.sizes.append(size)
                return self.source.readline(size)

            def __iter__(self):
                raise AssertionError("stdio used unbounded line iteration")

        source = GuardedInput()
        out, err = io.StringIO(), io.StringIO()
        code = agent_mcp.serve_stdio(
            agent_mcp.Server(repo=".", agent_name="Builder",
                             purpose="Code", runtime="custom"),
            stdin=source, stdout=out, stderr=err)
        self.assertEqual(code, 0, err.getvalue())
        messages = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(messages[0]["error"]["code"], -32600)
        self.assertEqual(messages[1]["id"], 1)
        self.assertTrue(source.sizes)
        self.assertTrue(all(
            size <= agent_mcp._MAX_MESSAGE_BYTES + 1 for size in source.sizes))

    def test_stdio_rejects_surrogates_and_non_finite_json_strictly(self):
        source = io.StringIO(
            '{"jsonrpc":"2.0","id":1,"method":"initialize",'
            '"params":{"protocolVersion":"\ud800","capabilities":{},'
            '"clientInfo":{"name":"x","version":"1"}}}\n'
            '{"jsonrpc":"2.0","id":2,"method":"initialize",'
            '"params":{"protocolVersion":NaN,"capabilities":{},'
            '"clientInfo":{"name":"x","version":"1"}}}\n')
        out, err = io.StringIO(), io.StringIO()
        code = agent_mcp.serve_stdio(
            agent_mcp.Server(repo=".", agent_name="Builder",
                             purpose="Code", runtime="custom"),
            stdin=source, stdout=out, stderr=err)
        self.assertEqual(code, 0, err.getvalue())
        self.assertNotIn("NaN", out.getvalue())
        messages = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([item["error"]["code"] for item in messages],
                         [-32700, -32700])

    @staticmethod
    def initialized_server(repo=".", agent_name="Builder"):
        server = agent_mcp.Server(
            repo=repo, agent_name=agent_name, purpose="Code", runtime="custom")
        server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}},
        })
        server.handle({"jsonrpc": "2.0",
                       "method": "notifications/initialized"})
        return server


class MCPToolIntegrationTest(FriendlyCheckCLITest):
    def call(self, server, name, arguments):
        response = server.handle({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
        self.assertNotIn("error", response)
        result = response["result"]
        self.assertFalse(result.get("isError", False), result)
        self.assertEqual(json.loads(result["content"][0]["text"]),
                         result["structuredContent"])
        return result["structuredContent"]

    def test_agent_reads_exact_state_without_running_a_new_check(self):
        sha = self.make()
        code, _, _ = self.invoke("check", "--repo", str(self.repo), "--json")
        self.assertEqual(code, 0)
        before = len(list((self.home / "logs").rglob("*.log")))
        state = self.call(MCPContractTest.initialized_server(str(self.repo)),
                          "admissible_get_state", {})
        after = len(list((self.home / "logs").rglob("*.log")))
        self.assertEqual(state["identity"]["commit_sha"], sha)
        self.assertEqual(state["status"], "checks_complete")
        self.assertEqual(before, after)

    def test_agent_work_package_is_exact_and_cannot_grant_authority(self):
        sha = self.make()
        package = self.call(
            MCPContractTest.initialized_server(str(self.repo)),
            "admissible_get_work_package",
            {"task": "Fix duplicate checkout creation"})
        self.assertEqual(package["schema"],
                         "admissible/v0.7/agent-work-package")
        self.assertEqual(package["identity"]["commit_sha"], sha)
        self.assertEqual(package["task"], "Fix duplicate checkout creation")
        allowed = package["capabilities"]["allowed"]
        forbidden = package["capabilities"]["forbidden"]
        self.assertIn("edit", allowed)
        for authority in ("sign", "finalize", "trust_policy", "merge", "deploy"):
            self.assertNotIn(authority, allowed)
            self.assertIn(authority, forbidden)

    def test_check_requires_the_exact_package_issued_on_this_connection(self):
        self.make()
        server = MCPContractTest.initialized_server(str(self.repo))
        package = self.call(
            server, "admissible_get_work_package", {"task": "Bound work"})
        sibling = self.call(
            server, "admissible_get_work_package", {"task": "Bound sibling"})
        package_id = package["package_id"]
        arguments = dict(package["completion"]["check_arguments"])
        stale_arguments = dict(sibling["completion"]["check_arguments"])
        self.assertEqual(arguments["package_id"], package_id)
        expected = ready.from_evaluation(decision_document())

        with mock.patch.object(
                ready, "run_check", return_value=(0, expected)) as run_check:
            exact = server.handle({
                "jsonrpc": "2.0", "id": 11, "method": "tools/call",
                "params": {"name": "admissible_check",
                           "arguments": arguments},
            })
        self.assertFalse(exact["result"]["isError"], exact)
        run_check.assert_called_once()

        forged = dict(arguments)
        forged["package_id"] = "0" * 64
        with mock.patch.object(
                ready, "run_check",
                side_effect=AssertionError("forged package executed")) as run_check:
            refused = server.handle({
                "jsonrpc": "2.0", "id": 12, "method": "tools/call",
                "params": {"name": "admissible_check",
                           "arguments": forged},
            })
        self.assertTrue(refused["result"]["isError"], refused)
        run_check.assert_not_called()

        (self.repo / "drift.txt").write_text("new head\n", encoding="utf-8")
        git(self.repo, "add", "drift.txt")
        git(self.repo, "commit", "-q", "-m", "move exact head")
        with mock.patch.object(
                ready, "run_check",
                side_effect=AssertionError("stale package executed")) as run_check:
            stale = server.handle({
                "jsonrpc": "2.0", "id": 13, "method": "tools/call",
                "params": {"name": "admissible_check",
                           "arguments": stale_arguments},
            })
        self.assertTrue(stale["result"]["isError"], stale)
        run_check.assert_not_called()

    def test_check_without_package_id_refuses_before_evaluation(self):
        self.make()
        server = MCPContractTest.initialized_server(str(self.repo))
        package = self.call(
            server, "admissible_get_work_package", {"task": "Bound work"})
        with mock.patch.object(
                ready, "run_check",
                side_effect=AssertionError("unbound check executed")) as run_check:
            refused = server.handle({
                "jsonrpc": "2.0", "id": 14, "method": "tools/call",
                "params": {"name": "admissible_check",
                           "arguments": {
                               "class_id": package["identity"]["class_id"],
                               "policy_digest": package["identity"]["policy_digest"],
                               "config_path": package["identity"]["config_path"],
                           }},
            })
        self.assertEqual(refused["error"]["code"], -32602)
        run_check.assert_not_called()

    def test_spent_package_cannot_be_rechecked(self):
        self.make()
        server = MCPContractTest.initialized_server(str(self.repo))
        package = self.call(
            server, "admissible_get_work_package", {"task": "One shot"})
        arguments = dict(package["completion"]["check_arguments"])
        expected = ready.from_evaluation(decision_document())
        with mock.patch.object(ready, "run_check", return_value=(0, expected)):
            first = server.handle({
                "jsonrpc": "2.0", "id": 15, "method": "tools/call",
                "params": {"name": "admissible_check",
                           "arguments": arguments},
            })
        self.assertFalse(first["result"]["isError"], first)
        with mock.patch.object(
                ready, "run_check",
                side_effect=AssertionError("spent package executed")) as run_check:
            second = server.handle({
                "jsonrpc": "2.0", "id": 16, "method": "tools/call",
                "params": {"name": "admissible_check",
                           "arguments": arguments},
            })
        self.assertTrue(second["result"]["isError"], second)
        run_check.assert_not_called()

    def test_work_package_binds_connection_principal(self):
        self.make()
        first = MCPContractTest.initialized_server(str(self.repo), agent_name="alpha")
        second = MCPContractTest.initialized_server(str(self.repo), agent_name="beta")
        a = self.call(first, "admissible_get_work_package", {"task": "Same task"})
        b = self.call(second, "admissible_get_work_package", {"task": "Same task"})
        self.assertNotEqual(a["package_id"], b["package_id"])
        self.assertEqual(a["agent"]["name"], "alpha")
        self.assertEqual(b["agent"]["name"], "beta")

    def test_work_package_identity_matches_latest_explicit_class_attempt(self):
        self.make()
        default_path = self.repo / ".admissible.json"
        config = json.loads(default_path.read_text(encoding="utf-8"))
        secondary = json.loads(json.dumps(config["classes"][0]))
        secondary["id"] = "secondary"
        secondary["checks"][0]["id"] = "secondary-unit"
        config["classes"] = [secondary]
        config_path = self.repo / "policy" / "secondary.json"
        config_path.parent.mkdir()
        config_path.write_text(json.dumps(config), encoding="utf-8")
        git(self.repo, "add", "policy/secondary.json")
        git(self.repo, "commit", "-q", "-m", "add secondary policy")
        code, out, err = self.invoke(
            "check", "--repo", str(self.repo), "--class", "secondary",
            "--config", "policy/secondary.json", "--json")
        self.assertEqual(code, 0, err + out)
        server = MCPContractTest.initialized_server(str(self.repo))
        package = self.call(
            server, "admissible_get_work_package",
            {"task": "Continue the exact run", "class_id": "secondary",
             "config_path": "policy/secondary.json"})
        self.assertEqual(package["identity"]["class_id"], "secondary")
        self.assertEqual(package["identity"]["config_path"],
                         "policy/secondary.json")
        self.assertEqual(package["identity"]["class_id"],
                         package["readiness"]["identity"]["class_id"])
        self.assertEqual(package["identity"]["policy_digest"],
                         package["readiness"]["identity"]["policy_digest"])
        checked = self.call(server, "admissible_check", {
            **package["completion"]["check_arguments"],
            "no_cache": True,
        })
        self.assertEqual(checked["identity"]["class_id"], "secondary")
        self.assertEqual(checked["identity"]["policy_digest"],
                         package["identity"]["policy_digest"])
        drifted_package = self.call(
            server, "admissible_get_work_package",
            {"task": "Drifted policy", "class_id": "secondary",
             "config_path": "policy/secondary.json"})
        drifted = server.handle({
            "jsonrpc": "2.0", "id": 21, "method": "tools/call",
            "params": {"name": "admissible_check",
                       "arguments": {
                           **drifted_package["completion"]["check_arguments"],
                           "policy_digest": "0" * 64,
                           "no_cache": True,
                       }},
        })
        self.assertTrue(drifted["result"]["isError"], drifted)
        # The refusal above is decided before the check runs, by comparing the
        # presented package against HEAD. The completed check is bound to the
        # requested policy a second time, on its own evidence: ask for a policy
        # digest this repository cannot produce and present no package at all,
        # so nothing can short-circuit ahead of the completed-check comparison.
        foreign_digest = "0" * 64
        self.assertNotEqual(package["identity"]["policy_digest"],
                            foreign_digest)
        code, refused = ready.run_check(
            str(self.repo), no_cache=True, class_id="secondary",
            config_path="policy/secondary.json",
            expected_policy_digest=foreign_digest)
        self.assertEqual(code, 2, refused)
        self.assertEqual(refused["status"], "unable_to_check", refused)
        self.assertEqual(refused["reasons"][0]["code"],
                         "work_package_identity_mismatch", refused)
        self.assertIn("does not match the work package policy",
                      refused["reasons"][0]["detail"])
        self.assertEqual(refused["identity"]["policy_digest"],
                         package["identity"]["policy_digest"])
        self.assertEqual(refused["identity"]["class_id"], "secondary")

    def test_agent_check_runs_the_same_gate_and_returns_remediation(self):
        self.make(check_exit=1)
        server = MCPContractTest.initialized_server(str(self.repo))
        package = self.call(
            server, "admissible_get_work_package", {"task": "Fix the check"})
        state = self.call(server, "admissible_check", {
            **package["completion"]["check_arguments"],
            "no_cache": True,
        })
        self.assertEqual(state["status"], "needs_attention")
        remediation = self.call(server, "admissible_get_remediation", {})
        self.assertEqual(remediation["schema"],
                         "admissible/v0.7/remediation")
        self.assertEqual(remediation["identity"], state["identity"])
        self.assertEqual(remediation["actions"][0]["owner"], "agent_or_human")

    def test_tool_arguments_are_closed_and_bounded(self):
        self.make()
        server = MCPContractTest.initialized_server(str(self.repo))
        package = self.call(
            server, "admissible_get_work_package", {"task": "Bound check"})
        response = server.handle({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "admissible_check",
                       "arguments": {
                           **package["completion"]["check_arguments"],
                           "command": "rm -rf /",
                       }},
        })
        self.assertEqual(response["error"]["code"], -32602)
        response = server.handle({
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "admissible_check", "arguments": {}},
        })
        self.assertEqual(response["error"]["code"], -32602)
        response = server.handle({
            "jsonrpc": "2.0", "id": 11, "method": "tools/call",
            "params": {"name": "admissible_get_work_package",
                       "arguments": {"task": "x" * 8001}},
        })
        self.assertEqual(response["error"]["code"], -32602)

    def test_mcp_cli_serves_real_stdio_handshake(self):
        self.make()
        messages = "\n".join((
            json.dumps({"jsonrpc": "2.0", "id": 1,
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18",
                                   "capabilities": {},
                                   "clientInfo": {"name": "agent",
                                                  "version": "1"}}}),
            json.dumps({"jsonrpc": "2.0",
                        "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2,
                        "method": "tools/list", "params": {}}),
        )) + "\n"
        completed = subprocess.run(
            [sys.executable, "-m", "admissible", "mcp",
             "--repo", str(self.repo), "--agent-name", "Builder",
             "--purpose", "Implement changes", "--runtime", "custom"],
            cwd=str(ROOT), env=dict(os.environ), input=messages, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual([item["id"] for item in responses], [1, 2])

    def test_mcp_cli_refuses_to_start_with_signing_credentials(self):
        self.make()
        environment = dict(os.environ)
        environment["ADMISSIBLE_HMAC_KEY"] = "never-print-me"
        completed = subprocess.run(
            [sys.executable, "-m", "admissible", "mcp",
             "--repo", str(self.repo), "--agent-name", "Builder",
             "--purpose", "Implement changes", "--runtime", "custom"],
            cwd=str(ROOT), env=environment, input="", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertIn("credential", completed.stderr.lower())
        self.assertNotIn("never-print-me", completed.stderr)

    def test_stdio_session_is_visible_only_after_initialized_notification(self):
        self.make()
        outer = self
        initialize = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18",
                       "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}},
        }) + "\n"
        initialized = json.dumps({
            "jsonrpc": "2.0", "method": "notifications/initialized",
        }) + "\n"

        class ProbeInput:
            def __init__(self):
                self.index = 0

            def readline(self, size=-1):
                if self.index == 0:
                    outer.assertEqual(
                        agent_connection.active_sessions(str(outer.repo)), [])
                    self.index += 1
                    return initialize
                if self.index == 1:
                    outer.assertEqual(
                        agent_connection.active_sessions(str(outer.repo)), [])
                    self.index += 1
                    return initialized
                if self.index == 2:
                    active = agent_connection.active_sessions(str(outer.repo))
                    outer.assertEqual(
                        [row["name"] for row in active], ["Builder"])
                    self.index += 1
                    return ""
                return ""

            def __iter__(self):
                return self

            def __next__(self):
                line = self.readline(agent_mcp._MAX_MESSAGE_BYTES + 1)
                if line == "":
                    raise StopIteration
                return line

        server = agent_mcp.Server(
            repo=str(self.repo), agent_name="Builder", purpose="Code",
            runtime="hermes")
        code = agent_mcp.serve_stdio(
            server, stdin=ProbeInput(), stdout=io.StringIO(),
            stderr=io.StringIO())
        self.assertEqual(code, 0)
        self.assertEqual(agent_connection.active_sessions(str(self.repo)), [])


class AgentConnectionTest(TempCase):
    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "repo"
        make_repo(self.repo)

    def test_every_runtime_gets_copyable_setup_without_credentials(self):
        for runtime in ("claude-code", "codex", "hermes", "local", "custom"):
            with self.subTest(runtime=runtime):
                document = agent_connection.instructions(
                    str(self.repo), name="Builder",
                    purpose="Implement day-to-day changes", runtime=runtime)
                self.assertEqual(document["schema"],
                                 "admissible/v0.7/agent-connection")
                self.assertEqual(document["runtime"], runtime)
                self.assertEqual(document["command"][1], "mcp")
                self.assertIn(str(self.repo.resolve()), document["command"])
                self.assertIn("Builder", document["command"])
                self.assertIn("Implement day-to-day changes", document["command"])
                serialized = json.dumps(document)
                self.assertNotIn("ADMISSIBLE_HMAC_KEY", serialized)
                self.assertNotIn("finalize", serialized)
                self.assertTrue(document["snippet"].strip())

    def test_codex_setup_is_valid_toml_with_astral_unicode(self):
        toml = require_module(
            "tomllib" if sys.version_info >= (3, 11) else "tomli")

        document = agent_connection.instructions(
            str(self.repo), name="Builder 😀",
            purpose="Repair the launch 🚀", runtime="codex")
        parsed = toml.loads(document["snippet"])
        server = parsed["mcp_servers"]["admissible-builder"]
        self.assertIn("Builder 😀", server["args"])
        self.assertIn("Repair the launch 🚀", server["args"])

    def test_codex_setup_escapes_toml_forbidden_del_in_repository_path(self):
        toml = require_module(
            "tomllib" if sys.version_info >= (3, 11) else "tomli")
        repo = self.tmp / "repo\x7fcontrol"
        make_repo(repo)

        document = agent_connection.instructions(
            str(repo), name="Builder", purpose="Repair", runtime="codex")
        parsed = toml.loads(document["snippet"])
        server = parsed["mcp_servers"]["admissible-builder"]
        self.assertIn(str(repo.resolve()), server["args"])

    def test_connection_inputs_are_bounded_and_closed(self):
        with self.assertRaises(agent_connection.ConnectionError):
            agent_connection.instructions(
                str(self.repo), name="", purpose="Code", runtime="custom")
        with self.assertRaises(agent_connection.ConnectionError):
            agent_connection.instructions(
                str(self.repo), name="Builder", purpose="x" * 2001,
                runtime="custom")
        with self.assertRaises(agent_connection.ConnectionError):
            agent_connection.instructions(
                str(self.repo), name="Builder", purpose="Code",
                runtime="unknown")

    def test_connect_cli_returns_the_same_versioned_contract(self):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main([
            "connect", "--repo", str(self.repo), "--name", "Builder",
            "--purpose", "Implement changes", "--runtime", "hermes",
            "--json",
        ], stdout=out, stderr=err)
        self.assertEqual(code, 0, err.getvalue())
        document = json.loads(out.getvalue())
        self.assertEqual(document["schema"],
                         "admissible/v0.7/agent-connection")
        self.assertIn("mcp_servers:", document["snippet"])

    def test_live_session_registry_is_private_and_cleans_up(self):
        with agent_connection.live_session(
                str(self.repo), name="Builder", purpose="Code",
                runtime="hermes") as session:
            path = Path(session["path"])
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            active = agent_connection.active_sessions(str(self.repo))
            self.assertEqual([row["name"] for row in active], ["Builder"])
            self.assertNotIn("path", active[0])
        self.assertFalse(path.exists())
        self.assertEqual(agent_connection.active_sessions(str(self.repo)), [])

    def test_session_registry_rejects_stale_heartbeat_and_pid_reuse(self):
        with agent_connection.live_session(
                str(self.repo), name="Builder", purpose="Code",
                runtime="hermes") as session:
            path = Path(session["path"])
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertIsInstance(document["process_started_at"], str)
            self.assertTrue(document["process_started_at"])
            self.assertIsInstance(document["heartbeat_at"], int)

            document["heartbeat_at"] = 0
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(
                agent_connection.active_sessions(str(self.repo)), [])

        with agent_connection.live_session(
                str(self.repo), name="Builder", purpose="Code",
                runtime="hermes") as session:
            path = Path(session["path"])
            document = json.loads(path.read_text(encoding="utf-8"))
            document["process_started_at"] = "not-this-process"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(
                agent_connection.active_sessions(str(self.repo)), [])


if __name__ == "__main__":
    unittest.main()
