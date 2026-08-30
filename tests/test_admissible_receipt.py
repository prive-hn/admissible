"""Contract: signed developer-workflow receipts and signer key hygiene."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import TempCase, require_module  # noqa: E402

receipt = require_module("admissible.receipt")
store = require_module("admissible.store")
decision = require_module("admissible.decision")
evidence = require_module("admissible.evidence")
config = require_module("admissible.config")

SECRET = "unit-test-secret-not-a-real-key"
REPO = "github.com/acme/widget"
SHA = "a" * 40
TREE = "b" * 40


class SignerLoadingTest(TempCase):
    def test_env_secret_loads_a_signer(self):
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET
        os.environ["ADMISSIBLE_HMAC_KEY_ID"] = "release"
        signer = receipt.load_signer()
        self.assertEqual(signer.key_id, "release")

    def test_missing_key_is_a_named_signing_error(self):
        with self.assertRaises(receipt.SigningError):
            receipt.load_signer()

    def test_key_file_must_not_be_group_or_world_readable(self):
        path = self.tmp / "key"
        path.write_text(SECRET, encoding="utf-8")
        os.chmod(path, 0o644)
        os.environ["ADMISSIBLE_HMAC_KEY_FILE"] = str(path)
        with self.assertRaises(receipt.SigningError):
            receipt.load_signer()
        os.chmod(path, 0o600)
        self.assertTrue(receipt.load_signer().key_id)

    def test_empty_key_is_refused(self):
        os.environ["ADMISSIBLE_HMAC_KEY"] = "   "
        with self.assertRaises(receipt.SigningError):
            receipt.load_signer()

    def test_signer_never_exposes_the_secret(self):
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET
        signer = receipt.load_signer()
        self.assertNotIn(SECRET, repr(signer))
        self.assertNotIn(SECRET, str(vars(receipt)))

    def test_cli_flag_shaped_secret_is_never_accepted(self):
        self.assertFalse(hasattr(receipt, "signer_from_argv"))
        source = (receipt.__file__ or "")
        text = Path(source).read_text(encoding="utf-8") if source else ""
        self.assertNotIn("--hmac-key", text)
        self.assertNotIn("--secret", text)


class WorkflowReceiptTest(TempCase):
    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET
        self.store = store.open_store(self.home)
        self.addCleanup(self.store.close)
        self.signer = receipt.load_signer()

    def artifact_class(self, **overrides):
        document = {
            "id": "default",
            "checks": [{"id": "unit", "argv": ["true"], "timeout_seconds": 60,
                        "cost_units": 1, "required": True, "version": "1"}],
            "required_independent_reviews": 0,
            "review_max_age_seconds": 86400,
            "max_cost_units": 10, "max_wall_seconds": 600,
        }
        document.update(overrides)
        parsed = config.parse_config(
            {"version": 1, "profile": "python-library", "classes": [document]})
        return parsed.select_class("default")

    def command_record(self, klass, **overrides):
        document = {
            "kind": "command", "check_id": "unit", "check_version": "1",
            "repository": REPO, "commit_sha": SHA, "tree_sha": TREE,
            "policy_digest": klass.policy_digest,
            "argv_digest": klass.check("unit").argv_digest,
            "exit_code": 0, "timed_out": False, "launch_failed": False,
            "duration_ms": 10, "stdout_sha256": "e" * 64,
            "stderr_sha256": "f" * 64, "stdout_bytes": 0, "stderr_bytes": 0,
            "output_truncated": False, "started_at": 1000, "finished_at": 1001,
            "attempt_id": "attempt-one",
        }
        document.update(overrides)
        return evidence.command_evidence_from_dict(document)

    def issue(self, **overrides):
        klass = self.artifact_class()
        commit_sha = overrides.get("commit_sha", SHA)
        tree_sha = overrides.get("tree_sha", TREE)
        commands = (self.command_record(klass, commit_sha=commit_sha,
                                        tree_sha=tree_sha),)
        # A receipt may only quote a decision about the artefact it names, so
        # the decision is recomputed for whatever this call is issuing.
        result = decision.evaluate(
            artifact_class=klass, repository=REPO, commit_sha=commit_sha,
            tree_sha=tree_sha, policy_digest=klass.policy_digest,
            commands=commands, reviews=(), now=2000,
            attempt_id="attempt-one")
        arguments = dict(
            repository=REPO, commit_sha=commit_sha, tree_sha=tree_sha,
            class_id=klass.id, policy_digest=klass.policy_digest,
            result=result, commands=commands, reviews=(),
            dependencies=(), signer=self.signer, now=2000)
        arguments.update(overrides)
        return receipt.issue_receipt(self.store, **arguments)

    def test_issued_receipt_verifies(self):
        issued = self.issue()
        self.assertTrue(receipt.verify_receipt(issued, self.signer))
        self.assertEqual(issued.state, decision.ADMITTED)
        self.assertEqual(issued.commit_sha, SHA)
        self.assertEqual(issued.tree_sha, TREE)

    def test_receipt_is_labelled_developer_workflow_admission_only(self):
        document = receipt.receipt_to_dict(self.issue())
        self.assertEqual(document["scope"], "developer-workflow-admission")
        self.assertEqual(document["schema"], receipt.RECEIPT_SCHEMA)
        text = json.dumps(document)
        self.assertNotIn("admissibility-receipt", text)
        self.assertNotIn("composed", text)
        for forbidden in ("identity_predicate", "scrutiny_predicate",
                          "standing_predicate", "admissible"):
            self.assertNotIn(forbidden, document)

    def test_receipt_is_not_an_rga_admissibility_receipt(self):
        import rga
        self.assertNotIsInstance(self.issue(), rga.AdmissibilityReceipt)

    def test_receipt_round_trips_through_plain_json(self):
        issued = self.issue()
        document = receipt.receipt_to_dict(issued)
        self.assertEqual(json.loads(json.dumps(document)), document)
        self.assertEqual(receipt.receipt_from_dict(document), issued)

    def test_tampered_body_fails_verification(self):
        document = receipt.receipt_to_dict(self.issue())
        document["state"] = decision.ADMITTED if document["state"] != decision.ADMITTED else "REFUSED"
        with self.assertRaises(receipt.ReceiptError):
            receipt.verify_receipt(receipt.receipt_from_dict(document), self.signer)

    def test_tampered_evidence_digest_fails_verification(self):
        document = receipt.receipt_to_dict(self.issue())
        document["evidence_digests"] = ["9" * 64]
        with self.assertRaises(receipt.ReceiptError):
            receipt.verify_receipt(receipt.receipt_from_dict(document), self.signer)

    def test_truncated_evidence_list_fails_verification(self):
        document = receipt.receipt_to_dict(self.issue())
        document["evidence_digests"] = []
        with self.assertRaises(receipt.ReceiptError):
            receipt.verify_receipt(receipt.receipt_from_dict(document), self.signer)

    def test_a_forged_body_digest_alone_is_refused(self):
        """The body digest must be checked even when the body is untouched."""
        document = receipt.receipt_to_dict(self.issue())
        document["body_digest"] = "9" * 64
        with self.assertRaises(receipt.ReceiptError):
            receipt.verify_receipt(receipt.receipt_from_dict(document),
                                   self.signer)

    def test_a_head_from_another_admission_cannot_authenticate_this_body(self):
        """A genuinely signed head must not vouch for a body it never covered.

        Everything else about this receipt is internally consistent: the body
        matches its digest, the receipt hash binds body and head, and the head
        signature is authentic. Only the event-to-head binding refuses it.
        """
        first = self.issue()
        second = self.issue(commit_sha="9" * 40, now=2001)
        self.assertNotEqual(first.head.receipt_hash, second.head.receipt_hash)
        document = receipt.receipt_to_dict(first)
        document["head"] = receipt.receipt_to_dict(second)["head"]
        import hashlib
        from fcd.journal import canonical_json
        document["receipt_hash"] = hashlib.sha256(canonical_json({
            "domain": receipt.RECEIPT_DOMAIN,
            "body_digest": first.body_digest,
            "head_receipt_hash": second.head.receipt_hash,
        }).encode("utf-8")).hexdigest()
        forged = receipt.receipt_from_dict(document)
        self.assertTrue(receipt.verify_receipt(second, self.signer))
        with self.assertRaises(receipt.ReceiptError):
            receipt.verify_receipt(forged, self.signer)

    def test_a_foreign_key_cannot_verify(self):
        issued = self.issue()
        other = receipt.signer_from_secret("k1", b"some-other-secret")
        with self.assertRaises(receipt.ReceiptError):
            receipt.verify_receipt(issued, other)

    def test_receipt_carries_no_raw_output_or_secret(self):
        text = json.dumps(receipt.receipt_to_dict(self.issue()))
        self.assertNotIn(SECRET, text)
        self.assertNotIn("stdout", text)
        self.assertNotIn("stderr", text)

    def test_receipt_binds_the_anchored_head_and_is_current(self):
        issued = self.issue()
        current = self.store.current_head(issued.journal_id)
        self.assertEqual(current.receipt_hash, issued.head.receipt_hash)
        self.assertTrue(receipt.verify_current(self.store, issued, self.signer))

    def test_a_receipt_whose_head_is_not_current_is_reported_stale(self):
        first = self.issue()
        self.issue(commit_sha="9" * 40, now=2001)
        with self.assertRaises(receipt.ReceiptError):
            receipt.verify_current(self.store, first, self.signer)
        self.assertTrue(receipt.verify_receipt(first, self.signer))

    def test_receipt_is_durable_across_restart(self):
        issued = self.issue()
        self.store.close()
        reopened = store.open_store(self.home)
        self.addCleanup(reopened.close)
        found = reopened.workflow_receipt(issued.receipt_hash)
        self.assertEqual(found, issued)
        self.assertTrue(receipt.verify_receipt(found, self.signer))

    def test_lookup_by_repository_and_sha(self):
        issued = self.issue()
        found = store.open_store(self.home).receipts_for(REPO, SHA)
        self.assertEqual([r.receipt_hash for r in found], [issued.receipt_hash])

    def test_issuing_the_same_decision_twice_is_idempotent(self):
        first = self.issue()
        again = self.issue()
        self.assertEqual(first.receipt_hash, again.receipt_hash)
        self.assertEqual(len(self.store.receipts_for(REPO, SHA)), 1)

    def test_evidence_is_persisted_with_the_receipt(self):
        issued = self.issue()
        digests = {row["digest"] for row in self.store.evidence_for(REPO, SHA)}
        self.assertTrue(set(issued.evidence_digests) <= digests)

    def test_preview_receipt_cannot_be_issued_without_a_signer(self):
        with self.assertRaises(receipt.SigningError):
            self.issue(signer=None)


class ExportImportTest(TempCase):
    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET
        self.signer = receipt.load_signer()

    def test_export_import_round_trips_and_refuses_rollback(self):
        source = store.open_store(self.home)
        self.addCleanup(source.close)
        for index in range(3):
            receipt.anchor_event(source, "j1", {
                "domain": "admissible/v0.6/developer-workflow-admission",
                "sequence": index, "repository": REPO, "commit_sha": SHA},
                signer=self.signer, now=10 + index)
        bundle = source.export_journal("j1")
        target_home = self.tmp / "target"
        target = store.open_store(target_home)
        self.addCleanup(target.close)
        target.import_journal(bundle, self.signer)
        self.assertEqual(target.current_head("j1").event_count, 3)
        # Re-importing the same bundle is a no-op, not a rollback.
        target.import_journal(bundle, self.signer)
        self.assertEqual(target.current_head("j1").event_count, 3)
        receipt.anchor_event(target, "j1", {
            "domain": "admissible/v0.6/developer-workflow-admission",
            "sequence": 3, "repository": REPO, "commit_sha": SHA},
            signer=self.signer, now=20)
        with self.assertRaises(store.HeadConflict):
            target.import_journal(bundle, self.signer)
        self.assertEqual(target.current_head("j1").event_count, 4)

    def test_import_refuses_an_unauthenticated_bundle(self):
        source = store.open_store(self.home)
        self.addCleanup(source.close)
        receipt.anchor_event(source, "j1", {
            "domain": "admissible/v0.6/developer-workflow-admission",
            "sequence": 0, "repository": REPO, "commit_sha": SHA},
            signer=self.signer, now=10)
        bundle = source.export_journal("j1")
        bundle = json.loads(json.dumps(bundle))
        bundle["events"][0]["sequence"] = 99
        target = store.open_store(self.tmp / "target")
        self.addCleanup(target.close)
        with self.assertRaises(store.StoreError):
            target.import_journal(bundle, self.signer)
        self.assertIsNone(target.current_head("j1"))


if __name__ == "__main__":
    unittest.main()


class ImportForgeryTest(TempCase):
    """An import may extend a journal; it may never smuggle in a forgery."""

    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET
        self.signer = receipt.load_signer()
        self.source = store.open_store(self.home)
        self.addCleanup(self.source.close)

    def bundle(self):
        klass = config.parse_config({
            "version": 1, "profile": "python-library",
            "classes": [{
                "id": "default",
                "checks": [{"id": "unit", "argv": ["true"],
                            "timeout_seconds": 60, "cost_units": 1,
                            "required": True, "version": "1"}],
                "required_independent_reviews": 0,
                "review_max_age_seconds": 86400,
                "max_cost_units": 10, "max_wall_seconds": 600}]}
        ).select_class("default")
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
        result = decision.evaluate(
            artifact_class=klass, repository=REPO, commit_sha=SHA,
            tree_sha=TREE, policy_digest=klass.policy_digest,
            commands=(command,), reviews=(), now=2000,
            attempt_id="attempt-one")
        receipt.issue_receipt(
            self.source, repository=REPO, commit_sha=SHA, tree_sha=TREE,
            class_id=klass.id, policy_digest=klass.policy_digest,
            result=result, commands=(command,), reviews=(), dependencies=(),
            signer=self.signer, now=2000)
        return json.loads(json.dumps(
            self.source.export_journal(receipt.journal_id_for(REPO))))

    def target(self):
        opened = store.open_store(self.tmp / "target")
        self.addCleanup(opened.close)
        return opened

    def test_a_clean_bundle_imports_with_its_receipt_and_evidence(self):
        target = self.target()
        target.import_journal(self.bundle(), self.signer)
        self.assertEqual(len(target.receipts_for(REPO, SHA)), 1)
        self.assertEqual(len(target.evidence_for(REPO, SHA)), 1)

    def test_a_tampered_workflow_receipt_is_refused_and_nothing_lands(self):
        bundle = self.bundle()
        bundle["workflow_receipts"][0]["state"] = "REFUSED"
        target = self.target()
        with self.assertRaises(store.StoreError):
            target.import_journal(bundle, self.signer)
        self.assertIsNone(target.current_head(receipt.journal_id_for(REPO)))
        self.assertEqual(target.receipts_for(REPO, SHA), ())

    def test_evidence_that_does_not_match_its_digest_is_refused(self):
        bundle = self.bundle()
        bundle["evidence"][0]["record"]["exit_code"] = 1
        target = self.target()
        with self.assertRaises(store.StoreError):
            target.import_journal(bundle, self.signer)
        self.assertEqual(target.evidence_for(REPO, SHA), ())

    def test_an_unanchored_defect_cannot_be_smuggled_in(self):
        bundle = self.bundle()
        bundle["defects"].append({
            "kind": "defect", "defect_id": "fake", "repository": REPO,
            "commit_sha": SHA, "severity": "critical",
            "summary": "invented by whoever handed you this file",
            "missed_check_ids": ["unit"], "regression_test_id": "unit",
            "discovered_at": 5000})
        target = self.target()
        with self.assertRaises(store.StoreError):
            target.import_journal(bundle, self.signer)
        self.assertEqual(target.defects_for(REPO, SHA), ())
