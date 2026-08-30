"""Contract: the documents Admissible emits validate against its own schemas."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import (TempCase, require_module,  # noqa: E402
                                source_receipt_document)

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - jsonschema is a dev-only extra
    Draft202012Validator = None

config = require_module("admissible.config")
decision = require_module("admissible.decision")
evidence = require_module("admissible.evidence")
receipt = require_module("admissible.receipt")
schema = require_module("admissible.schema")
standing = require_module("admissible.standing")
store = require_module("admissible.store")

SECRET = "unit-test-secret-not-a-real-key"
REPO = "github.com/acme/widget"
SHA = "a1" * 20
TREE = "b2" * 20


@unittest.skipIf(Draft202012Validator is None, "jsonschema not installed")
class SchemaConformanceTest(TempCase):
    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET
        self.store = store.open_store(self.home)
        self.addCleanup(self.store.close)
        self.signer = receipt.load_signer()

    def validate(self, document, schema_document):
        Draft202012Validator.check_schema(schema_document)
        errors = sorted(
            Draft202012Validator(schema_document).iter_errors(document),
            key=lambda error: list(error.path))
        self.assertEqual(
            [], [f"{list(e.path)}: {e.message}" for e in errors])

    def artifact_class(self):
        return config.parse_config({
            "version": 1, "profile": "python-library",
            "classes": [{
                "id": "default",
                "checks": [{"id": "unit", "argv": ["true"],
                            "timeout_seconds": 60, "cost_units": 1,
                            "required": True, "version": "1"}],
                "required_independent_reviews": 1,
                "reviewer_key_ids": ["reviewer-a"],
                "author_key_ids": ["author-key"],
                "review_max_age_seconds": 86400,
                "max_cost_units": 10, "max_wall_seconds": 600}]}
        ).select_class("default")

    def records(self, klass):
        command = evidence.command_evidence_from_dict({
            "kind": "command", "check_id": "unit", "check_version": "1",
            "repository": REPO, "commit_sha": SHA, "tree_sha": TREE,
            "policy_digest": klass.policy_digest,
            "argv_digest": klass.check("unit").argv_digest,
            "exit_code": 0, "timed_out": False, "launch_failed": False,
            "duration_ms": 10, "stdout_sha256": "e" * 64,
            "stderr_sha256": "f" * 64, "stdout_bytes": 0, "stderr_bytes": 0,
            "output_truncated": False, "started_at": 1000,
            "finished_at": 1001, "attempt_id": "attempt-one"})
        review = evidence.review_evidence_from_dict({
            "kind": "review", "review_id": "r1", "reviewer_id": "a",
            "reviewer_version": "1", "author_id": "b", "verdict": "approve",
            "repository": REPO, "commit_sha": SHA, "tree_sha": TREE,
            "policy_digest": klass.policy_digest,
            "findings_digest": "0" * 64, "issued_at": 1990,
            "attempt_id": "attempt-one"})
        return command, review

    def counted(self, review):
        """The review as an authenticated one; only these satisfy a policy."""

        return evidence.VerifiedReview(record=review, key_id="reviewer-a")

    def authorship(self, klass):
        """Who wrote this commit, established by a pinned author key.

        A class requiring independent review admits nothing without one: the
        rule "nobody reviews their own change" is about keys, so something has
        to say which key authored the change.
        """

        record = evidence.authorship_evidence_from_dict({
            "kind": "authorship", "author_id": "b", "repository": REPO,
            "commit_sha": SHA, "tree_sha": TREE,
            "policy_digest": klass.policy_digest, "issued_at": 1990})
        return evidence.AttestedAuthorship(record=record, key_id="author-key")

    def test_an_evidence_bundle_validates(self):
        klass = self.artifact_class()
        command, review = self.records(klass)
        bundle = evidence.bundle_to_dict(evidence.Bundle(
            commands=(command,), reviews=(review,), defects=()))
        self.validate(bundle, schema.evidence_schema())

    def test_a_defect_record_validates(self):
        document = {
            "kind": "defect", "defect_id": "d1", "repository": REPO,
            "commit_sha": SHA, "severity": "high", "summary": "wrong totals",
            "missed_check_ids": ["unit"], "regression_test_id": "unit",
            "discovered_at": 5000}
        parsed = evidence.defect_from_dict(document)
        self.validate(evidence.defect_to_dict(parsed), schema.defect_schema())
        # The same record must also be valid inside an evidence bundle, whose
        # defect definition is resolved against that document's own $defs.
        self.validate({"schema": evidence.EVIDENCE_SCHEMA, "commands": [],
                       "reviews": [], "defects": [document],
                       "attestations": [], "author_attestations": []},
                      schema.evidence_schema())

    def test_the_defect_schema_refuses_an_abbreviated_sha(self):
        document = {
            "kind": "defect", "defect_id": "d1", "repository": REPO,
            "commit_sha": SHA[:12], "severity": "high", "summary": "x",
            "missed_check_ids": [], "regression_test_id": "unit",
            "discovered_at": 5000}
        self.assertTrue(list(
            Draft202012Validator(schema.defect_schema()).iter_errors(document)))

    def test_a_real_issued_receipt_validates(self):
        klass = self.artifact_class()
        command, review = self.records(klass)
        result = decision.evaluate(
            artifact_class=klass, repository=REPO, commit_sha=SHA,
            tree_sha=TREE, policy_digest=klass.policy_digest,
            commands=(command,), reviews=(self.counted(review),),
            authorships=(self.authorship(klass),), now=2000,
            attempt_id="attempt-one")
        self.assertEqual(result.state, decision.CHECKS_PASSED, result.reasons)
        issued = receipt.issue_receipt(
            self.store, repository=REPO, commit_sha=SHA, tree_sha=TREE,
            class_id=klass.id, policy_digest=klass.policy_digest,
            result=result, commands=(command,), reviews=(review,),
            authorships=(self.authorship(klass).record,),
            dependencies=((REPO, "c3" * 20),), signer=self.signer, now=2000)
        self.validate(receipt.receipt_to_dict(issued), schema.receipt_schema())

    def test_a_receipt_records_which_key_authenticated_each_review(self):
        klass = self.artifact_class()
        command, review = self.records(klass)
        result = decision.evaluate(
            artifact_class=klass, repository=REPO, commit_sha=SHA,
            tree_sha=TREE, policy_digest=klass.policy_digest,
            commands=(command,), reviews=(self.counted(review),),
            authorships=(self.authorship(klass),), now=2000,
            attempt_id="attempt-one")
        issued = receipt.issue_receipt(
            self.store, repository=REPO, commit_sha=SHA, tree_sha=TREE,
            class_id=klass.id, policy_digest=klass.policy_digest,
            result=result, commands=(command,), reviews=(review,),
            authorships=(self.authorship(klass).record,),
            authenticated_reviews=(
                (evidence.evidence_digest(review), "reviewer-a"),),
            signer=self.signer, now=2000)
        document = receipt.receipt_to_dict(issued)
        self.validate(document, schema.receipt_schema())
        self.assertEqual(
            document["authenticated_reviews"],
            [{"evidence_digest": evidence.evidence_digest(review),
              "key_id": "reviewer-a"}])

    def test_an_evaluation_attestation_validates(self):
        attestation = require_module("admissible.attestation")
        klass = self.artifact_class()
        command, review = self.records(klass)
        result = decision.evaluate(
            artifact_class=klass, repository=REPO, commit_sha=SHA,
            tree_sha=TREE, policy_digest=klass.policy_digest,
            commands=(command,), reviews=(self.counted(review),),
            authorships=(self.authorship(klass),), now=2000,
            attempt_id="attempt-one")
        bundle = evidence.Bundle(commands=(command,), reviews=(review,),
                                 defects=(), attestations=())
        preview = {
            "schema": "admissible/v0.6/workflow-preview",
            "repository": REPO, "commit_sha": SHA, "tree_sha": TREE,
            "policy_digest": klass.policy_digest, "class_id": klass.id,
            "state": result.state, "readiness": decision.preview_readiness(result),
            "decision": decision.decision_to_dict(result),
            "evidence": evidence.bundle_to_dict(bundle),
            "dependencies": [], "issued_at": 2000, "fork": False,
            "isolation": "pid-namespace",
            "config_path": ".admissible.json", "policy_anchor": "unanchored",
        }
        document = attestation.attest_preview(
            preview, key_id="observer-1", secret=b"observer-secret",
            isolation="pid-namespace",
            source_receipt=source_receipt_document(preview["commit_sha"]),
            observed_at=2000)
        self.validate(document, schema.evaluation_schema())
        self.assertEqual(
            document["evaluation"]["command_digests"],
            [evidence.evidence_digest(command)])
        self.assertEqual(document["evaluation"]["attempt_id"], "attempt-one")

    def test_the_evaluation_schema_refuses_a_review_attestation(self):
        review_attestation = {
            "schema": evidence.ATTESTATION_SCHEMA, "algorithm": "hmac-sha256",
            "key_id": "reviewer-a", "review": {}, "signature": "0" * 64,
        }
        errors = list(Draft202012Validator(
            schema.evaluation_schema()).iter_errors(review_attestation))
        self.assertTrue(errors, "the two attestation domains are not distinct")

    def test_a_first_receipt_with_an_empty_predecessor_validates(self):
        klass = self.artifact_class()
        command, review = self.records(klass)
        result = decision.evaluate(
            artifact_class=klass, repository=REPO, commit_sha=SHA,
            tree_sha=TREE, policy_digest=klass.policy_digest,
            commands=(command,), reviews=(self.counted(review),),
            authorships=(self.authorship(klass),), now=2000,
            attempt_id="attempt-one")
        issued = receipt.issue_receipt(
            self.store, repository=REPO, commit_sha=SHA, tree_sha=TREE,
            class_id=klass.id, policy_digest=klass.policy_digest,
            result=result, commands=(command,), reviews=(review,),
            authorships=(self.authorship(klass).record,),
            dependencies=(), signer=self.signer, now=2000)
        document = receipt.receipt_to_dict(issued)
        self.assertEqual(document["head"]["previous_receipt_hash"], "")
        self.validate(document, schema.receipt_schema())

    def test_the_schema_refuses_a_receipt_that_claims_another_scope(self):
        klass = self.artifact_class()
        command, review = self.records(klass)
        result = decision.evaluate(
            artifact_class=klass, repository=REPO, commit_sha=SHA,
            tree_sha=TREE, policy_digest=klass.policy_digest,
            commands=(command,), reviews=(self.counted(review),),
            authorships=(self.authorship(klass),), now=2000,
            attempt_id="attempt-one")
        issued = receipt.issue_receipt(
            self.store, repository=REPO, commit_sha=SHA, tree_sha=TREE,
            class_id=klass.id, policy_digest=klass.policy_digest,
            result=result, commands=(command,), reviews=(review,),
            authorships=(self.authorship(klass).record,),
            dependencies=(), signer=self.signer, now=2000)
        document = receipt.receipt_to_dict(issued)
        document["scope"] = "composed-admissibility"
        self.assertTrue(list(
            Draft202012Validator(schema.receipt_schema()).iter_errors(document)))

    def test_every_shipped_profile_document_is_a_valid_policy(self):
        from admissible import profiles as profiles_module

        for name in profiles_module.PROFILE_NAMES:
            parsed = config.parse_config(
                profiles_module.profile_document(name),
                allow_placeholders=True)
            self.assertEqual(len(parsed.policy_digest), 64, name)


if __name__ == "__main__":
    unittest.main()
