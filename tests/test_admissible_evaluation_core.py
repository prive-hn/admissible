"""Regression contract for the frozen evaluation/finalization core."""
from __future__ import annotations

import dataclasses
import inspect
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from admissible_support import (  # noqa: E402
    OBSERVER_KEY_ID,
    OBSERVER_SECRET,
    source_receipt_document,
)
from test_admissible_bounded_repair import BoundedCase  # noqa: E402
from test_admissible_receipt import (  # noqa: E402
    REPO,
    SHA,
    TREE,
    WorkflowReceiptTest,
)

from admissible import attestation  # noqa: E402
from admissible import decision  # noqa: E402
from admissible import evidence  # noqa: E402
from admissible import github  # noqa: E402
from admissible import receipt  # noqa: E402
from admissible import store as store_module  # noqa: E402


class EvaluationStatementContractTest(BoundedCase):
    def sign(self, document=None, *, conclusion="success",
             isolation="pid-namespace", observed_at=None, **overrides):
        document = self.preview_document() if document is None else document
        return attestation.attest_preview(
            document, key_id=OBSERVER_KEY_ID, secret=OBSERVER_SECRET,
            isolation=isolation,
            source_receipt=source_receipt_document(
                document["commit_sha"], conclusion=conclusion),
            observed_at=(document["issued_at"] + 1
                         if observed_at is None else observed_at),
            **overrides)

    def signed_path(self, document=None, **keywords):
        path = self.tmp / "core-evaluation.json"
        path.write_text(json.dumps(self.sign(document, **keywords)),
                        encoding="utf-8")
        return path

    def finalize_document(self, document, *, conclusion="success",
                          isolation="pid-namespace"):
        preview = self.tmp / "core-preview.json"
        preview.write_text(json.dumps(document), encoding="utf-8")
        return github.finalize(
            self.store, preview, signer=self.signer, expected_sha=self.sha,
            now=document["issued_at"] + 10, policy_root=self.root,
            evaluation_attestation=self.signed_path(
                document, conclusion=conclusion, isolation=isolation),
            evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
            environment={})

    def test_observer_isolation_is_a_required_independent_input(self):
        with self.assertRaises(attestation.EvaluationError) as caught:
            attestation.attest_preview(
                self.preview_document(), key_id=OBSERVER_KEY_ID,
                secret=OBSERVER_SECRET,
                source_receipt=source_receipt_document(self.sha),
                observed_at=self.preview_document()["issued_at"] + 1)
        self.assertIn("observer", str(caught.exception).lower())
        self.assertIn("isolation", str(caught.exception).lower())

    def test_signed_statement_binds_preview_schema_and_issued_at(self):
        preview = self.preview_document()
        statement = self.sign(preview)["evaluation"]
        self.assertEqual(statement["preview_schema"], preview["schema"])
        self.assertEqual(statement["issued_at"], preview["issued_at"])

    def test_candidate_none_does_not_override_observer_isolation(self):
        preview = self.preview_document()
        preview["isolation"] = "none"
        issued = self.finalize_document(preview, isolation="pid-namespace")
        self.assertEqual(issued.state, decision.ADMITTED)

    def test_preview_issued_at_cannot_change_after_observation(self):
        preview = self.preview_document()
        signed = self.signed_path(preview)
        preview["issued_at"] += 1
        preview["decision"]["evaluated_at"] = preview["issued_at"]
        path = self.tmp / "changed-issued-at.json"
        path.write_text(json.dumps(preview), encoding="utf-8")
        with self.assertRaises(github.GitHubError) as caught:
            github.finalize(
                self.store, path, signer=self.signer, expected_sha=self.sha,
                now=preview["issued_at"] + 10, policy_root=self.root,
                evaluation_attestation=signed,
                evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
                environment={})
        self.assertIn("issued", str(caught.exception).lower())

    def test_evaluation_state_and_readiness_are_closed_and_coherent(self):
        bad_pairs = (
            (decision.ADMITTED, decision.READINESS_READY_FOR_ATTESTATION),
            ("SOMETHING_ELSE", decision.READINESS_READY_FOR_ATTESTATION),
            (decision.CHECKS_PASSED, "SOMETHING_ELSE"),
            (decision.CHECKS_PASSED, decision.READINESS_AWAITING_REVIEW),
            (decision.REFUSED, decision.READINESS_READY_FOR_ATTESTATION),
            (decision.BLOCKED, decision.READINESS_AWAITING_REVIEW),
        )
        for state, readiness in bad_pairs:
            with self.subTest(state=state, readiness=readiness):
                with self.assertRaises(attestation.EvaluationError):
                    self.sign(state=state, readiness=readiness)

    def test_evaluation_state_enum_is_exact(self):
        with self.assertRaises(attestation.EvaluationError) as caught:
            self.sign(state=decision.ADMITTED)
        self.assertIn("exactly one", str(caught.exception))

    def test_evaluation_readiness_enum_is_exact(self):
        with self.assertRaises(attestation.EvaluationError) as caught:
            self.sign(readiness="SOMETHING_ELSE")
        self.assertIn("exactly one", str(caught.exception))

    def test_evaluation_state_readiness_pair_must_be_coherent(self):
        with self.assertRaises(attestation.EvaluationError) as caught:
            self.sign(state=decision.CHECKS_PASSED,
                      readiness=decision.READINESS_AWAITING_REVIEW)
        self.assertIn("contradict", str(caught.exception))

    def test_top_level_and_embedded_state_readiness_must_match(self):
        preview = self.preview_document()
        # Keep the top-level result honest and forge only the embedded copy. If
        # the explicit correspondence guard disappears, every later trusted
        # recomputation still agrees with the top level and would admit it.
        preview["decision"]["state"] = decision.REFUSED
        preview["decision"]["readiness"] = decision.READINESS_AWAITING_REVIEW
        with self.assertRaises(github.GitHubError) as caught:
            self.finalize_document(preview, conclusion="success")
        self.assertIn("two descriptions", str(caught.exception).lower())

    def test_provider_matrix_uses_rederived_evaluator_readiness(self):
        preview = self.preview_document()
        preview["state"] = decision.REFUSED
        preview["readiness"] = decision.READINESS_AWAITING_REVIEW
        preview["decision"]["state"] = decision.REFUSED
        preview["decision"]["readiness"] = decision.READINESS_AWAITING_REVIEW
        # A forged AWAITING pair used to make provider `failure` admissible,
        # even though the trusted policy and bound command evidence re-derive
        # the evaluator result as CHECKS_PASSED/READY.
        with self.assertRaises(github.GitHubError) as caught:
            self.finalize_document(preview, conclusion="success")
        self.assertIn("re-derived", str(caught.exception).lower())

    def test_observer_none_is_nonfinalizable(self):
        preview = self.preview_document()
        with self.assertRaises(github.GitHubError) as caught:
            self.finalize_document(preview, isolation="none")
        self.assertIn("isolation", str(caught.exception).lower())

    def test_provider_conclusion_matrix_is_exact(self):
        self.assertEqual(attestation.admissible_source_conclusions(
            decision.READINESS_READY_FOR_ATTESTATION),
            frozenset({"success"}))
        self.assertEqual(attestation.admissible_source_conclusions(
            decision.READINESS_AWAITING_REVIEW),
            frozenset({"success", "failure"}))
        self.assertEqual(attestation.admissible_source_conclusions(
            decision.READINESS_NOT_READY), frozenset())
        for readiness in decision.READINESS:
            with self.subTest(readiness=readiness):
                allowed = attestation.admissible_source_conclusions(readiness)
                self.assertNotIn("cancelled", allowed)
                self.assertNotIn("timed_out", allowed)

    def test_provider_matrix_follows_rederived_readiness_in_source_order(self):
        source = inspect.getsource(github._validated_finalization)
        rederive = source.index("evaluator_result = evaluate(")
        matrix = source.index("admissible_source_conclusions(")
        self.assertLess(rederive, matrix)
        self.assertIn(
            "admissible_source_conclusions(\n        evaluator_readiness)",
            source)

    def test_review_signatures_are_not_re_signed_by_the_observer(self):
        self.assertNotIn("attestation_digests",
                         attestation.EVALUATION_BODY_KEYS)
        self.assertNotIn("author_attestation_digests",
                         attestation.EVALUATION_BODY_KEYS)

    def test_public_finalize_has_no_dependency_injection_parameter(self):
        self.assertNotIn("dependencies", inspect.signature(
            github.finalize).parameters)

    def test_expected_finalization_digest_matches_the_issued_body(self):
        preview = self.preview_document()
        preview_path = self.tmp / "digest-preview.json"
        preview_path.write_text(json.dumps(preview), encoding="utf-8")
        evaluation_path = self.signed_path(preview)
        arguments = dict(
            expected_sha=self.sha, now=preview["issued_at"] + 10,
            policy_root=self.root,
            evaluation_attestation=evaluation_path,
            evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
            environment={})
        expected = github.expected_finalization_receipt_body_digest(
            self.store, preview_path, **arguments)
        issued = github.finalize(
            self.store, preview_path, signer=self.signer, **arguments)
        self.assertEqual(expected, issued.body_digest)

    def test_finalize_refuses_if_revalidation_changes_the_expected_body(self):
        preview = self.preview_document()
        preview_path = self.tmp / "guarded-preview.json"
        preview_path.write_text(json.dumps(preview), encoding="utf-8")
        evaluation_path = self.signed_path(preview)
        arguments = dict(
            expected_sha=self.sha, now=preview["issued_at"] + 10,
            policy_root=self.root,
            evaluation_attestation=evaluation_path,
            evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
            environment={})
        expected = github.expected_finalization_receipt_body_digest(
            self.store, preview_path, **arguments)
        evaluation_path.write_text(json.dumps(self.sign(
            preview, observed_at=preview["issued_at"] + 2)),
            encoding="utf-8")
        with self.assertRaises(github.GitHubError) as caught:
            github.finalize(
                self.store, preview_path, signer=self.signer,
                expected_body_digest=expected, **arguments)
        self.assertIn("expected receipt body", str(caught.exception).lower())
        self.assertEqual(self.store.receipt_count(self.repository), 0)

    def test_finalize_accepts_the_exact_expected_body_guard(self):
        preview = self.preview_document()
        preview_path = self.tmp / "exact-guard-preview.json"
        preview_path.write_text(json.dumps(preview), encoding="utf-8")
        evaluation_path = self.signed_path(preview)
        arguments = dict(
            expected_sha=self.sha, now=preview["issued_at"] + 10,
            policy_root=self.root,
            evaluation_attestation=evaluation_path,
            evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
            environment={})
        expected = github.expected_finalization_receipt_body_digest(
            self.store, preview_path, **arguments)
        issued = github.finalize(
            self.store, preview_path, signer=self.signer,
            expected_body_digest=expected, **arguments)
        self.assertEqual(issued.body_digest, expected)

    def test_policy_revocation_before_receipt_commit_refuses(self):
        """Policy authority is rechecked under the receipt write lock."""

        preview = self.preview_document()
        preview_path = self.tmp / "policy-race-preview.json"
        preview_path.write_text(json.dumps(preview), encoding="utf-8")
        evaluation_path = self.signed_path(preview)
        original = receipt.issue_receipt_from_parts

        def revoke_then_issue(store, **keywords):
            store.revoke_policy(
                repository=self.repository, class_id="default",
                policy_digest=preview["policy_digest"],
                revoked_at=preview["issued_at"] + 2)
            return original(store, **keywords)

        receipt.issue_receipt_from_parts = revoke_then_issue
        self.addCleanup(
            setattr, receipt, "issue_receipt_from_parts", original)
        with self.assertRaises((github.GitHubError, receipt.ReceiptError)):
            github.finalize(
                self.store, preview_path, signer=self.signer,
                expected_sha=self.sha, now=preview["issued_at"] + 10,
                policy_root=self.root,
                evaluation_attestation=evaluation_path,
                evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
                environment={})
        self.assertEqual(self.store.receipt_count(self.repository), 0)
        self.assertEqual(
            self.store.trusted_policies(self.repository, "default"), ())


class CachedReceiptAuthenticationTest(WorkflowReceiptTest):
    def test_forged_cached_receipt_is_refused(self):
        issued = self.issue()
        forged = dataclasses.replace(
            issued, head=dataclasses.replace(
                issued.head, signature="0" * len(issued.head.signature)))
        original = type(self.store).workflow_receipt_by_body

        def forged_lookup(_store, _body_digest):
            return forged

        type(self.store).workflow_receipt_by_body = forged_lookup
        try:
            with self.assertRaises(receipt.ReceiptError):
                self.issue()
        finally:
            type(self.store).workflow_receipt_by_body = original

    def test_authentic_but_conflicting_cached_receipt_is_refused(self):
        expected = self.issue()
        other = self.issue(commit_sha="9" * 40, now=2001)
        self.assertTrue(receipt.verify_receipt(other, self.signer))
        original = type(self.store).workflow_receipt_by_body

        def conflicting_lookup(_store, body_digest):
            if body_digest == expected.body_digest:
                return other
            return original(_store, body_digest)

        type(self.store).workflow_receipt_by_body = conflicting_lookup
        try:
            with self.assertRaises(receipt.ReceiptError):
                self.issue()
        finally:
            type(self.store).workflow_receipt_by_body = original

    def test_racing_forged_cached_receipt_is_refused_inside_transaction(self):
        issued = self.issue()
        forged = dataclasses.replace(issued, decision_digest="f" * 64)
        original = type(self.store).workflow_receipt_by_body
        calls = []

        def raced_lookup(_store, body_digest):
            calls.append(body_digest)
            if len(calls) == 1:
                return None
            return forged

        type(self.store).workflow_receipt_by_body = raced_lookup
        try:
            with self.assertRaises(receipt.ReceiptError):
                self.issue()
        finally:
            type(self.store).workflow_receipt_by_body = original

    def test_authenticated_hint_is_never_returned_before_transactional_reread(self):
        issued = self.issue()
        forged = dataclasses.replace(issued, decision_digest="f" * 64)
        original = type(self.store).workflow_receipt_by_body
        calls = []

        def raced_lookup(_store, body_digest):
            calls.append(body_digest)
            return issued if len(calls) == 1 else forged

        type(self.store).workflow_receipt_by_body = raced_lookup
        try:
            with self.assertRaises(receipt.ReceiptError):
                self.issue()
        finally:
            type(self.store).workflow_receipt_by_body = original

    def test_expected_body_digest_is_deterministic_and_matches_issue(self):
        issued = self.issue()
        expected = receipt.expected_receipt_body_digest(
            repository=issued.repository, commit_sha=issued.commit_sha,
            tree_sha=issued.tree_sha, class_id=issued.class_id,
            policy_digest=issued.policy_digest, state=issued.state,
            attempt_id=issued.attempt_id,
            decision_digest_value=issued.decision_digest,
            evidence_digests=issued.evidence_digests,
            authenticated_reviews=issued.authenticated_reviews,
            dependencies=issued.dependencies, issued_at=issued.issued_at)
        self.assertEqual(expected, issued.body_digest)

    def test_every_cached_or_new_receipt_return_is_reauthenticated(self):
        source = inspect.getsource(receipt.issue_receipt_from_parts)
        self.assertNotIn("return hinted", source)
        self.assertIn(
            "return authenticated_expected(duplicate.receipt,", source)
        self.assertIn(
            "return authenticated_expected(stored, where=\"newly stored\")",
            source)


class ReceiptIssuanceCorrespondenceTest(WorkflowReceiptTest):
    def review_record(self, *, verdict="approve", **overrides):
        klass = self.artifact_class()
        document = {
            "kind": "review", "review_id": "review-one",
            "reviewer_id": "reviewer", "reviewer_version": "1",
            "author_id": "author", "verdict": verdict,
            "repository": REPO, "commit_sha": SHA, "tree_sha": TREE,
            "policy_digest": klass.policy_digest,
            "findings_digest": "e" * 64, "issued_at": 1500,
            "attempt_id": "attempt-one",
        }
        document.update(overrides)
        return evidence.review_evidence_from_dict(document)

    def issue_parts(self, records, *, authenticated_reviews=(),
                    dependencies=(), now=2000, attempt_id="attempt-one",
                    decision_digest_value="d" * 64,
                    evidence_digests=None):
        klass = self.artifact_class()
        by_kind = {"command": [], "review": [], "authorship": []}
        for record in records:
            by_kind[record.kind].append(record)
        return receipt.issue_receipt_from_parts(
            self.store, repository=REPO, commit_sha=SHA, tree_sha=TREE,
            class_id=klass.id, policy_digest=klass.policy_digest,
            state=decision.ADMITTED, attempt_id=attempt_id,
            decision_digest_value=decision_digest_value,
            evidence_digests=(tuple(
                evidence.evidence_digest(record) for record in records)
                if evidence_digests is None else evidence_digests),
            commands=tuple(by_kind["command"]),
            reviews=tuple(by_kind["review"]),
            authorships=tuple(by_kind["authorship"]),
            authenticated_reviews=authenticated_reviews,
            dependencies=dependencies, signer=self.signer, now=now)

    def assert_nothing_anchored(self):
        self.assertEqual(self.store.receipt_count(REPO), 0)
        self.assertEqual(self.store.journal_events(
            receipt.journal_id_for(REPO)), ())

    def test_authenticated_review_must_resolve_to_a_review_record(self):
        klass = self.artifact_class()
        command = self.command_record(klass)
        digest = evidence.evidence_digest(command)
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts(
                (command,),
                authenticated_reviews=((digest, "reviewer-key"),))
        self.assert_nothing_anchored()

    def test_authenticated_review_must_be_an_approval(self):
        review = self.review_record(verdict="reject")
        digest = evidence.evidence_digest(review)
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts(
                (review,),
                authenticated_reviews=((digest, "reviewer-key"),))
        self.assert_nothing_anchored()

    def test_authenticated_review_digest_must_be_receipt_bound_and_supplied(self):
        review = self.review_record()
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts(
                (review,),
                authenticated_reviews=(("f" * 64, "reviewer-key"),))
        self.assert_nothing_anchored()

    def test_authenticated_review_identity_must_match_the_receipt(self):
        review = self.review_record(repository="github.com/mallory/widget")
        digest = evidence.evidence_digest(review)
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts(
                (review,),
                authenticated_reviews=((digest, "reviewer-key"),))
        self.assert_nothing_anchored()

    def test_valid_authenticated_approval_is_issued(self):
        review = self.review_record()
        digest = evidence.evidence_digest(review)
        issued = self.issue_parts(
            (review,), authenticated_reviews=((digest, "reviewer-key"),))
        self.assertEqual(
            issued.authenticated_reviews, ((digest, "reviewer-key"),))
        projections, invalid = self.store.authenticated_workflow_state(
            self.signer)
        self.assertEqual(invalid, frozenset())
        self.assertIn(REPO, projections)

    def test_duplicate_evidence_digests_are_refused(self):
        klass = self.artifact_class()
        command = self.command_record(klass)
        digest = evidence.evidence_digest(command)
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts(
                (command,), evidence_digests=(digest, digest))
        self.assert_nothing_anchored()

    def test_duplicate_authenticated_review_attributions_are_refused(self):
        review = self.review_record()
        digest = evidence.evidence_digest(review)
        attribution = (digest, "reviewer-key")
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts(
                (review,), authenticated_reviews=(attribution, attribution))
        self.assert_nothing_anchored()

    def test_duplicate_dependency_edges_are_refused(self):
        klass = self.artifact_class()
        command = self.command_record(klass)
        edge = ("github.com/acme/upstream", "9" * 40)
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts((command,), dependencies=(edge, edge))
        self.assert_nothing_anchored()

    def test_authenticated_review_digest_type_is_closed(self):
        review = self.review_record()
        with self.assertRaises(receipt.ReceiptError) as caught:
            self.issue_parts(
                (review,), authenticated_reviews=((7, "reviewer-key"),))
        self.assertIn("lowercase 64-character", str(caught.exception))
        self.assert_nothing_anchored()

    def test_authenticated_review_key_id_is_nonempty_text(self):
        review = self.review_record()
        digest = evidence.evidence_digest(review)
        for key_id in ("", 7):
            with self.subTest(key_id=key_id):
                with self.assertRaises(receipt.ReceiptError):
                    self.issue_parts(
                        (review,), authenticated_reviews=((digest, key_id),))
        self.assert_nothing_anchored()

    def test_every_supplied_evidence_record_is_receipt_bound(self):
        klass = self.artifact_class()
        command = self.command_record(
            klass, repository="github.com/mallory/widget")
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts((command,))
        self.assert_nothing_anchored()

    def test_conflicting_preexisting_evidence_attachment_is_refused(self):
        klass = self.artifact_class()
        command = self.command_record(klass)
        digest = evidence.evidence_digest(command)
        document = evidence.evidence_to_dict(command)
        conflicting = dict(document)
        conflicting["stdout_sha256"] = "0" * 64
        self.store.put_evidence(
            digest=digest, kind="command", repository=REPO,
            commit_sha=SHA, tree_sha=TREE,
            policy_digest=klass.policy_digest, record=conflicting)
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts((command,))
        self.assert_nothing_anchored()

    def test_exact_preexisting_evidence_attachment_can_be_bound(self):
        klass = self.artifact_class()
        command = self.command_record(klass)
        document = evidence.evidence_to_dict(command)
        self.store.put_evidence(
            digest=evidence.evidence_digest(command), kind="command",
            repository=REPO, commit_sha=SHA, tree_sha=TREE,
            policy_digest=klass.policy_digest, record=document)
        issued = self.issue_parts((command,))
        self.assertEqual(issued.state, decision.ADMITTED)

    def test_first_receipt_refuses_unsigned_dependency_on_another_commit(self):
        klass = self.artifact_class()
        command = self.command_record(klass)
        edge = ("github.com/acme/upstream", "9" * 40)
        self.store.put_dependency(
            consumer_repository=REPO, consumer_commit_sha="8" * 40,
            dependency_repository=edge[0], dependency_commit_sha=edge[1],
            recorded_at=99)
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts((command,))
        self.assert_nothing_anchored()

    def test_exact_preexisting_dependency_attachment_can_be_bound(self):
        klass = self.artifact_class()
        command = self.command_record(klass)
        edge = ("github.com/acme/upstream", "9" * 40)
        self.store.put_dependency(
            consumer_repository=REPO, consumer_commit_sha=SHA,
            dependency_repository=edge[0], dependency_commit_sha=edge[1],
            recorded_at=2000)
        issued = self.issue_parts((command,), dependencies=(edge,))
        self.assertEqual(issued.dependencies, (edge,))

    def test_evidence_attachment_and_receipt_commit_atomically(self):
        klass = self.artifact_class()
        command = self.command_record(klass)
        digest = evidence.evidence_digest(command)
        original = type(self.store).workflow_receipt_row

        def broken_receipt_row(_store, _receipt):
            return ("INSERT INTO table_that_does_not_exist VALUES(?)", (1,))

        type(self.store).workflow_receipt_row = broken_receipt_row
        try:
            with self.assertRaises(store_module.StoreError):
                self.issue_parts((command,))
        finally:
            type(self.store).workflow_receipt_row = original
        stored = self.store.connection.execute(
            "SELECT 1 FROM evidence WHERE digest=?", (digest,)).fetchone()
        self.assertIsNone(stored)
        self.assert_nothing_anchored()

    def test_cached_retry_rechecks_its_evidence_metadata(self):
        klass = self.artifact_class()
        command = self.command_record(klass)
        self.issue_parts((command,))
        self.store.connection.execute("DROP TRIGGER evidence_no_update")
        self.store.connection.execute(
            "UPDATE evidence SET commit_sha=? WHERE digest=?",
            ("f" * 40, evidence.evidence_digest(command)))
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts((command,))

    def test_cached_retry_rechecks_its_dependency_attachment(self):
        klass = self.artifact_class()
        command = self.command_record(klass)
        edge = ("github.com/acme/upstream", "9" * 40)
        self.issue_parts((command,), dependencies=(edge,))
        self.store.connection.execute("DROP TRIGGER dependencies_no_update")
        self.store.connection.execute(
            "UPDATE dependencies SET recorded_at=99 WHERE "
            "consumer_repository=? AND consumer_commit_sha=? AND "
            "dependency_repository=? AND dependency_commit_sha=?",
            (REPO, SHA, edge[0], edge[1]))
        with self.assertRaises(receipt.ReceiptError):
            self.issue_parts((command,), dependencies=(edge,))

    def test_prior_receipt_can_share_an_exact_dependency_attachment(self):
        klass = self.artifact_class()
        edge = ("github.com/acme/upstream", "9" * 40)
        first = self.command_record(klass, attempt_id="attempt-one")
        self.issue_parts((first,), dependencies=(edge,), now=1000)
        second = self.command_record(klass, attempt_id="attempt-two")
        issued = self.issue_parts(
            (second,), dependencies=(edge,), now=2000,
            attempt_id="attempt-two", decision_digest_value="e" * 64)
        self.assertEqual(issued.dependencies, (edge,))


if __name__ == "__main__":
    import unittest

    unittest.main()
