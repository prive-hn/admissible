"""Contract: durable import, dependency reconstruction, and atomic issuance."""
from __future__ import annotations

import io
import json
import os
import sqlite3
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import TempCase, require_module  # noqa: E402

config_module = require_module("admissible.config")
decision = require_module("admissible.decision")
evidence = require_module("admissible.evidence")
receipt = require_module("admissible.receipt")
standing = require_module("admissible.standing")
store_module = require_module("admissible.store")

SECRET = b"durability-test-secret"
REPOSITORY = "github.com/acme/widget"


def sha(prefix: str) -> str:
    return (prefix * 40)[:40]


def artifact_class():
    parsed = config_module.parse_config({
        "version": 1, "profile": "python-library",
        "classes": [{
            "id": "default",
            "checks": [{"id": "unit", "argv": ["python3", "-c", "pass"],
                        "timeout_seconds": 60, "cost_units": 1,
                        "required": True, "version": "1"}],
            "required_independent_reviews": 0,
            "review_max_age_seconds": 86400,
            "max_cost_units": 10, "max_wall_seconds": 600}]})
    return parsed.select_class("default")


class DurableCase(TempCase):
    def setUp(self):
        super().setUp()
        self.signer = receipt.signer_from_secret("k1", SECRET)
        self.artifact_class = artifact_class()

    def open(self, name: str):
        opened = store_module.open_store(self.tmp / name)
        self.addCleanup(opened.close)
        return opened

    def command(self, commit_sha, *, attempt="attempt-1"):
        return evidence.command_evidence_from_dict({
            "kind": "command", "check_id": "unit", "check_version": "1",
            "repository": REPOSITORY, "commit_sha": commit_sha,
            "tree_sha": sha("b"),
            "policy_digest": self.artifact_class.policy_digest,
            "argv_digest": self.artifact_class.check("unit").argv_digest,
            "exit_code": 0, "timed_out": False, "launch_failed": False,
            "duration_ms": 1, "stdout_sha256": "0" * 64,
            "stderr_sha256": "0" * 64, "stdout_bytes": 0, "stderr_bytes": 0,
            "output_truncated": False, "started_at": 10, "finished_at": 10,
            "attempt_id": attempt})

    def admit(self, opened, commit_sha, *, dependencies=(), now=1000,
              attempt="attempt-1"):
        record = self.command(commit_sha, attempt=attempt)
        result = decision.evaluate(
            artifact_class=self.artifact_class, repository=REPOSITORY,
            commit_sha=commit_sha, tree_sha=sha("b"),
            policy_digest=self.artifact_class.policy_digest,
            commands=(record,), reviews=(), now=now, attempt_id=attempt)
        assert result.state == decision.CHECKS_PASSED, result.reasons
        return receipt.issue_receipt(
            opened, repository=REPOSITORY, commit_sha=commit_sha,
            tree_sha=sha("b"), class_id="default",
            policy_digest=self.artifact_class.policy_digest, result=result,
            commands=(record,), dependencies=dependencies,
            signer=self.signer, now=now)

    def defect(self, opened, commit_sha, *, now=2000):
        return standing.file_defect(opened, {
            "kind": "defect", "defect_id": "d1", "repository": REPOSITORY,
            "commit_sha": commit_sha, "severity": "high",
            "summary": "production outage", "missed_check_ids": ["unit"],
            "regression_test_id": "unit", "discovered_at": now},
            signer=self.signer, now=now)


class DefectBijectionTest(DurableCase):
    """D18: an anchored defect that the bundle omits is a hard reject."""

    def test_stripping_defects_from_an_authentic_export_is_refused(self):
        source = self.open("source")
        self.admit(source, sha("a"))
        self.defect(source, sha("a"))
        self.assertEqual(
            standing.current_standing(
                source, REPOSITORY, sha("a"), verifier=self.signer).state,
            standing.IMPEACHED)
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        self.assertEqual(len(bundle["defects"]), 1)
        bundle["defects"] = []
        target = self.open("target")
        with self.assertRaises(store_module.StoreError) as caught:
            target.import_journal(bundle, self.signer)
        self.assertIn("defect", str(caught.exception).lower())
        self.assertEqual(
            standing.current_standing(
                target, REPOSITORY, sha("a"), verifier=self.signer).state,
            standing.UNKNOWN)

    def test_a_complete_import_reproduces_the_impeachment(self):
        source = self.open("source")
        self.admit(source, sha("a"))
        self.defect(source, sha("a"))
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        target = self.open("target")
        target.import_journal(bundle, self.signer)
        self.assertEqual(
            standing.current_standing(
                target, REPOSITORY, sha("a"), verifier=self.signer).state,
            standing.IMPEACHED)

    def test_a_same_head_reimport_heals_a_missing_defect_row(self):
        source = self.open("source")
        self.admit(source, sha("a"))
        self.defect(source, sha("a"))
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        target = self.open("target")
        target.import_journal(bundle, self.signer)
        # Simulate a partially populated store: drop the row behind the
        # append-only trigger, exactly as a botched migration would.
        target.connection.execute("PRAGMA writable_schema=OFF")
        target.connection.execute("DROP TRIGGER defects_no_delete")
        target.connection.execute("DELETE FROM defects")
        target.connection.executescript(
            "CREATE TRIGGER defects_no_delete BEFORE DELETE ON defects "
            "BEGIN SELECT RAISE(ABORT, 'defects are append-only'); END;")
        self.assertEqual(
            standing.current_standing(
                target, REPOSITORY, sha("a"), verifier=self.signer).state,
            standing.UNKNOWN)
        target.import_journal(bundle, self.signer)
        self.assertEqual(
            standing.current_standing(
                target, REPOSITORY, sha("a"), verifier=self.signer).state,
            standing.IMPEACHED)

    def test_an_unanchored_defect_is_still_refused(self):
        source = self.open("source")
        self.admit(source, sha("a"))
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        bundle["defects"] = [{
            "kind": "defect", "defect_id": "forged", "repository": REPOSITORY,
            "commit_sha": sha("a"), "severity": "high", "summary": "forged",
            "missed_check_ids": [], "regression_test_id": "",
            "discovered_at": 1}]
        target = self.open("target")
        with self.assertRaises(store_module.StoreError):
            target.import_journal(bundle, self.signer)

    def test_evidence_without_signed_receipt_correspondence_is_refused(self):
        source = self.open("source")
        self.admit(source, sha("a"))
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        bundle["evidence"] = list(bundle["evidence"]) + [{
            "digest": evidence.evidence_digest(self.command(sha("c"))),
            "kind": "command",
            "record": evidence.command_evidence_to_dict(self.command(sha("c")))}]
        target = self.open("target")
        with self.assertRaises(store_module.StoreError):
            target.import_journal(bundle, self.signer)


class DependencyImportTest(DurableCase):
    """D19: authenticated dependency edges survive export and import."""

    def test_direct_consumers_survive_a_round_trip(self):
        source = self.open("source")
        self.admit(source, sha("a"))
        self.admit(source, sha("c"), dependencies=((REPOSITORY, sha("a")),),
                   now=1001)
        self.assertEqual(source.direct_consumers(REPOSITORY, sha("a")),
                         ((REPOSITORY, sha("c")),))
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        target = self.open("target")
        target.import_journal(bundle, self.signer)
        self.assertEqual(target.direct_consumers(REPOSITORY, sha("a")),
                         ((REPOSITORY, sha("c")),))

    def test_three_deep_transitive_impeachment_survives_a_round_trip(self):
        source = self.open("source")
        self.admit(source, sha("a"), now=1000)
        self.admit(source, sha("c"), dependencies=((REPOSITORY, sha("a")),),
                   now=1001)
        self.admit(source, sha("d"), dependencies=((REPOSITORY, sha("c")),),
                   now=1002)
        self.admit(source, sha("e"), dependencies=((REPOSITORY, sha("d")),),
                   now=1003)
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        target = self.open("target")
        target.import_journal(bundle, self.signer)
        self.defect(target, sha("a"), now=2000)
        report = standing.impact_report(
            target, REPOSITORY, sha("a"), verifier=self.signer)
        self.assertEqual(
            {(item.commit_sha, item.distance) for item in report.dependents},
            {(sha("c"), 1), (sha("d"), 2), (sha("e"), 3)})

    def test_a_cycle_stays_bounded_after_import(self):
        source = self.open("source")
        self.admit(source, sha("a"), dependencies=((REPOSITORY, sha("c")),),
                   now=1000)
        self.admit(source, sha("c"), dependencies=((REPOSITORY, sha("a")),),
                   now=1001)
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        target = self.open("target")
        target.import_journal(bundle, self.signer)
        found = standing.dependents(
            target, REPOSITORY, sha("a"), verifier=self.signer)
        self.assertLessEqual(len(found), 2)

    def test_dependency_rows_cannot_be_deleted(self):
        opened = self.open("source")
        self.admit(opened, sha("a"))
        self.admit(opened, sha("c"), dependencies=((REPOSITORY, sha("a")),),
                   now=1001)
        with self.assertRaises(sqlite3.Error):
            opened.connection.execute("DELETE FROM dependencies")


class AtomicIssuanceTest(DurableCase):
    """D20: idempotency lives inside the same compare-and-set transaction."""

    def parts(self, opened, *, now=1000):
        record = self.command(sha("a"))
        result = decision.evaluate(
            artifact_class=self.artifact_class, repository=REPOSITORY,
            commit_sha=sha("a"), tree_sha=sha("b"),
            policy_digest=self.artifact_class.policy_digest,
            commands=(record,), reviews=(), now=now, attempt_id="attempt-1")
        return dict(
            repository=REPOSITORY, commit_sha=sha("a"), tree_sha=sha("b"),
            class_id="default",
            policy_digest=self.artifact_class.policy_digest, result=result,
            commands=(record,), signer=self.signer, now=now)

    def test_two_connections_interleaved_append_one_event_and_one_receipt(self):
        home = self.tmp / "shared"
        first = store_module.open_store(home)
        self.addCleanup(first.close)
        second = store_module.open_store(home)
        self.addCleanup(second.close)

        # Deterministic interleaving: the moment the first writer is about to
        # take the write lock, the second writer commits the identical body.
        original = type(first).accept_head
        raced = []

        def racing(self_store, *args, **kwargs):
            if not raced:
                raced.append(True)
                receipt.issue_receipt(second, **self.parts(second))
            return original(self_store, *args, **kwargs)

        type(first).accept_head = racing
        try:
            issued = receipt.issue_receipt(first, **self.parts(first))
        finally:
            type(first).accept_head = original

        journal = receipt.journal_id_for(REPOSITORY)
        self.assertEqual(len(first.journal_events(journal)), 1)
        self.assertEqual(len(first.receipts_for(REPOSITORY, sha("a"))), 1)
        stored = first.workflow_receipt(issued.receipt_hash)
        self.assertIsNotNone(stored,
                             "issue_receipt returned a receipt it never stored")
        self.assertEqual(stored.receipt_hash, issued.receipt_hash)

    def test_exact_head_race_still_runs_cached_repository_preflight(self):
        home = self.tmp / "shared-preflight"
        first = store_module.open_store(home)
        self.addCleanup(first.close)
        second = store_module.open_store(home)
        self.addCleanup(second.close)
        original = type(first).accept_head
        raced = []

        def racing(self_store, *args, **kwargs):
            if not raced:
                raced.append(True)
                receipt.issue_receipt(second, **self.parts(second))
                standing.record_dependency(
                    second, consumer=(REPOSITORY, sha("c")),
                    dependency=(REPOSITORY, sha("d")), now=1001)
            return original(self_store, *args, **kwargs)

        type(first).accept_head = racing
        try:
            with self.assertRaises(receipt.ReceiptError):
                receipt.issue_receipt(first, **self.parts(first))
        finally:
            type(first).accept_head = original

        journal = receipt.journal_id_for(REPOSITORY)
        self.assertEqual(len(first.journal_events(journal)), 1)
        self.assertEqual(len(first.receipts_for(REPOSITORY, sha("a"))), 1)

    def test_a_repeated_identical_issuance_is_idempotent(self):
        opened = self.open("source")
        first = receipt.issue_receipt(opened, **self.parts(opened))
        again = receipt.issue_receipt(opened, **self.parts(opened))
        self.assertEqual(first.receipt_hash, again.receipt_hash)
        journal = receipt.journal_id_for(REPOSITORY)
        self.assertEqual(len(opened.journal_events(journal)), 1)

    def test_a_writer_that_read_before_the_winner_is_still_idempotent(self):
        """The check before the transaction is a hint; the one inside is law.

        Two writers issuing the identical body both look for it first, and both
        legitimately see nothing: the loser's read happened before the winner
        committed. Only a re-read taken *inside* the compare-and-set can catch
        that, and without it the loser appends a second journal event for a
        receipt row the store then refuses.
        """

        opened = self.open("source")
        first = receipt.issue_receipt(opened, **self.parts(opened))
        journal = receipt.journal_id_for(REPOSITORY)
        self.assertEqual(len(opened.journal_events(journal)), 1)

        real = type(opened).workflow_receipt_by_body
        looked = []

        def read_before_the_winner_committed(store, body_digest):
            # Exactly one blind read: the pre-transaction hint. Everything
            # after it, including the re-read inside the transaction, tells
            # the truth.
            if not looked:
                looked.append(True)
                return None
            return real(store, body_digest)

        type(opened).workflow_receipt_by_body = read_before_the_winner_committed
        try:
            again = receipt.issue_receipt(opened, **self.parts(opened))
        finally:
            type(opened).workflow_receipt_by_body = real
        self.assertEqual(again.receipt_hash, first.receipt_hash)
        self.assertEqual(len(opened.journal_events(journal)), 1)
        self.assertEqual(len(opened.receipts_for(REPOSITORY, sha("a"))), 1)

    def test_a_conflicting_receipt_row_is_never_silently_ignored(self):
        opened = self.open("source")
        issued = receipt.issue_receipt(opened, **self.parts(opened))
        statement, parameters = opened.workflow_receipt_row(issued)
        self.assertNotIn("OR IGNORE", statement)


class ResourceClosureTest(DurableCase):
    """D22: every SQLite connection is closed deterministically."""

    def test_no_store_is_left_open(self):
        opened = store_module.open_store(self.tmp / "closed")
        self.admit(opened, sha("a"))
        opened.close()
        self.assertEqual(store_module.open_store_count(), 0)

    def test_the_store_is_a_context_manager(self):
        with store_module.open_store(self.tmp / "ctx") as opened:
            self.admit(opened, sha("a"))
        self.assertEqual(store_module.open_store_count(), 0)


if __name__ == "__main__":
    unittest.main()
