"""Contract: append-only impeachment, dependents, and missed-check accounting."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import TempCase, require_module  # noqa: E402

standing = require_module("admissible.standing")
receipt = require_module("admissible.receipt")
store = require_module("admissible.store")
decision = require_module("admissible.decision")
evidence = require_module("admissible.evidence")
config = require_module("admissible.config")

SECRET = "unit-test-secret-not-a-real-key"
REPO = "github.com/acme/widget"
TREE = "b" * 40


def sha(marker: str) -> str:
    return (marker * 40)[:40]


class StandingCase(TempCase):
    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET
        self.store = store.open_store(self.home)
        self.addCleanup(self.store.close)
        self.signer = receipt.load_signer()

    def artifact_class(self, **overrides):
        document = {
            "id": "default",
            "checks": [
                {"id": "unit", "argv": ["true"], "timeout_seconds": 60,
                 "cost_units": 1, "required": True, "version": "1"},
                {"id": "lint", "argv": ["true"], "timeout_seconds": 60,
                 "cost_units": 1, "required": True, "version": "1"},
            ],
            "required_independent_reviews": 0,
            "review_max_age_seconds": 86400,
            "max_cost_units": 10, "max_wall_seconds": 600,
        }
        document.update(overrides)
        return config.parse_config(
            {"version": 1, "profile": "python-library",
             "classes": [document]}).select_class("default")

    def admit(self, commit_sha, *, now=2000, dependencies=()):
        klass = self.artifact_class()
        commands = tuple(
            evidence.command_evidence_from_dict({
                "kind": "command", "check_id": check_id, "check_version": "1",
                "repository": REPO, "commit_sha": commit_sha, "tree_sha": TREE,
                "policy_digest": klass.policy_digest,
                "argv_digest": klass.check(check_id).argv_digest,
                "exit_code": 0, "timed_out": False, "launch_failed": False,
                "duration_ms": 10, "stdout_sha256": "e" * 64,
                "stderr_sha256": "f" * 64, "stdout_bytes": 0, "stderr_bytes": 0,
                "output_truncated": False, "started_at": 1000,
                "finished_at": 1001, "attempt_id": "attempt-one"})
            for check_id in ("unit", "lint"))
        result = decision.evaluate(
            artifact_class=klass, repository=REPO, commit_sha=commit_sha,
            tree_sha=TREE, policy_digest=klass.policy_digest,
            commands=commands, reviews=(), now=now,
            attempt_id="attempt-one")
        assert result.state == decision.CHECKS_PASSED, result.reasons
        return receipt.issue_receipt(
            self.store, repository=REPO, commit_sha=commit_sha, tree_sha=TREE,
            class_id=klass.id, policy_digest=klass.policy_digest,
            result=result, commands=commands, reviews=(),
            dependencies=dependencies, signer=self.signer, now=now)

    def defect_document(self, commit_sha, **overrides):
        document = {
            "kind": "defect",
            "defect_id": "d1",
            "repository": REPO,
            "commit_sha": commit_sha,
            "severity": "high",
            "summary": "payment totals rounded the wrong way",
            "missed_check_ids": ["unit"],
            "regression_test_id": "unit",
            "discovered_at": 5000,
        }
        document.update(overrides)
        return document


class ImpeachmentTest(StandingCase):
    def test_admitted_artifact_is_current_before_any_defect(self):
        self.admit(sha("1"))
        found = standing.current_standing(
            self.store, REPO, sha("1"), verifier=self.signer)
        self.assertEqual(found.state, standing.CURRENT)
        self.assertEqual(found.exit_code, 0)

    def test_unknown_artifact_is_reported_unknown_not_current(self):
        found = standing.current_standing(
            self.store, REPO, sha("7"), verifier=self.signer)
        self.assertEqual(found.state, standing.UNKNOWN)
        self.assertEqual(found.exit_code, 1)

    def test_defect_impeaches_current_standing_without_rewriting_history(self):
        issued = self.admit(sha("1"))
        standing.file_defect(self.store, self.defect_document(sha("1")),
                             signer=self.signer, now=6000)
        found = standing.current_standing(
            self.store, REPO, sha("1"), verifier=self.signer)
        self.assertEqual(found.state, standing.IMPEACHED)
        self.assertEqual(found.exit_code, 1)
        stored = self.store.workflow_receipt(issued.receipt_hash)
        self.assertEqual(stored, issued)
        self.assertTrue(receipt.verify_receipt(stored, self.signer))
        self.assertEqual(stored.state, decision.ADMITTED)

    def test_defects_are_append_only_and_idempotent(self):
        self.admit(sha("1"))
        document = self.defect_document(sha("1"))
        standing.file_defect(self.store, document, signer=self.signer, now=6000)
        standing.file_defect(self.store, document, signer=self.signer, now=6000)
        self.assertEqual(len(self.store.defects_for(REPO, sha("1"))), 1)
        standing.file_defect(self.store, self.defect_document(
            sha("1"), defect_id="d2"), signer=self.signer, now=6001)
        self.assertEqual(len(self.store.defects_for(REPO, sha("1"))), 2)

    def test_defect_for_an_unknown_artifact_is_still_recorded_as_unknown_scope(self):
        standing.file_defect(self.store, self.defect_document(sha("9")),
                             signer=self.signer, now=6000)
        found = standing.current_standing(
            self.store, REPO, sha("9"), verifier=self.signer)
        self.assertEqual(found.state, standing.IMPEACHED)
        self.assertTrue(found.unknown_scope)

    def test_a_closed_defect_document_is_required(self):
        with self.assertRaises(evidence.EvidenceError):
            standing.file_defect(self.store, self.defect_document(
                sha("1"), surprise=1), signer=self.signer, now=6000)
        bad = self.defect_document(sha("1"))
        bad["commit_sha"] = "abc"
        with self.assertRaises(evidence.EvidenceError):
            standing.file_defect(self.store, bad, signer=self.signer, now=6000)

    def test_defect_is_anchored_in_the_authenticated_journal(self):
        self.admit(sha("1"))
        before = self.store.current_head(receipt.journal_id_for(REPO)).event_count
        standing.file_defect(self.store, self.defect_document(sha("1")),
                             signer=self.signer, now=6000)
        after = self.store.current_head(receipt.journal_id_for(REPO))
        self.assertEqual(after.event_count, before + 1)
        self.store.verify_journal(receipt.journal_id_for(REPO), self.signer)


class DependentsTest(StandingCase):
    def link(self, consumer, dependency):
        self.admit(
            consumer, dependencies=((REPO, dependency),),
            now=3000 + len(self.store.receipts_in(REPO)))

    def test_direct_and_transitive_dependents_are_returned(self):
        self.link(sha("2"), sha("1"))
        self.link(sha("3"), sha("2"))
        found = standing.dependents(
            self.store, REPO, sha("1"), verifier=self.signer)
        self.assertEqual({item.commit_sha for item in found},
                         {sha("2"), sha("3")})
        self.assertEqual({item.commit_sha for item in found if item.direct},
                         {sha("2")})

    def test_dependency_cycles_terminate(self):
        self.link(sha("2"), sha("1"))
        self.link(sha("1"), sha("2"))
        found = standing.dependents(
            self.store, REPO, sha("1"), verifier=self.signer)
        self.assertEqual({item.commit_sha for item in found}, {sha("2"), sha("1")})

    def test_transitive_impact_does_not_mutate_stored_records(self):
        issued = self.admit(sha("1"))
        self.link(sha("2"), sha("1"))
        standing.file_defect(self.store, self.defect_document(sha("1")),
                             signer=self.signer, now=6000)
        report = standing.impact_report(
            self.store, REPO, sha("1"), verifier=self.signer)
        self.assertEqual(self.store.workflow_receipt(issued.receipt_hash), issued)
        self.assertEqual([d.commit_sha for d in report.dependents], [sha("2")])
        # The dependent keeps its own direct standing: kernel semantics are direct.
        dependent = standing.current_standing(
            self.store, REPO, sha("2"), verifier=self.signer)
        self.assertNotEqual(dependent.state, standing.IMPEACHED)
        self.assertTrue(report.reachable_dependent_impact)


class MissedCheckTest(StandingCase):
    def test_report_names_the_checks_that_approved_the_defective_artifact(self):
        self.admit(sha("1"))
        standing.file_defect(self.store, self.defect_document(sha("1")),
                             signer=self.signer, now=6000)
        report = standing.impact_report(
            self.store, REPO, sha("1"), verifier=self.signer)
        misses = {row.check_id: row for row in report.missed_checks}
        self.assertEqual(set(misses), {"unit", "lint"})
        self.assertEqual(misses["unit"].missed_defects, 1)
        self.assertEqual(misses["unit"].approved_artifacts, 1)
        self.assertEqual(misses["lint"].missed_defects, 1)

    def test_report_makes_no_rate_or_probability_claim(self):
        self.admit(sha("1"))
        standing.file_defect(self.store, self.defect_document(sha("1")),
                             signer=self.signer, now=6000)
        text = json.dumps(standing.report_to_dict(
            standing.impact_report(
                self.store, REPO, sha("1"), verifier=self.signer)))
        for forbidden in ("rate", "probability", "confidence", "percent"):
            self.assertNotIn(forbidden, text.lower())

    def test_plain_report_distinguishes_observed_reachable_and_unknown(self):
        self.admit(sha("1"))
        self.admit(
            sha("2"), dependencies=((REPO, sha("1")),), now=3000)
        standing.file_defect(self.store, self.defect_document(sha("1")),
                             signer=self.signer, now=6000)
        text = standing.render_plain(
            standing.impact_report(
                self.store, REPO, sha("1"), verifier=self.signer)).lower()
        self.assertIn("observed", text)
        self.assertIn("reachable", text)
        self.assertIn("unknown", text)
        self.assertIn("what to do next", text)
        self.assertIn(sha("2"), text)
        self.assertIn("unit", text)

    def test_report_requires_a_future_regression_test(self):
        self.admit(sha("1"))
        standing.file_defect(self.store, self.defect_document(sha("1")),
                             signer=self.signer, now=6000)
        report = standing.impact_report(
            self.store, REPO, sha("1"), verifier=self.signer)
        self.assertIn("unit", " ".join(report.remediation))
        self.assertTrue(any("regression" in line.lower()
                            for line in report.remediation))


if __name__ == "__main__":
    unittest.main()
