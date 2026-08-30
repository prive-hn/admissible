"""Focused regressions for durable trust-boundary correspondence."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_admissible_durability import (  # noqa: E402
    DurableCase,
    REPOSITORY,
    sha,
)

from admissible import decision, evidence, receipt, standing  # noqa: E402
from admissible import store as store_module  # noqa: E402


class DefectCorrespondenceSecurityTest(DurableCase):
    def defect_document(self, commit_sha):
        return {
            "kind": "defect", "defect_id": "d1",
            "repository": REPOSITORY, "commit_sha": commit_sha,
            "severity": "high", "summary": "production outage",
            "missed_check_ids": ["unit"], "regression_test_id": "unit",
            "discovered_at": 2000,
        }

    def test_orphan_defect_row_is_not_an_idempotent_success(self):
        opened = self.open("orphan-row")
        document = self.defect_document(sha("a"))
        parsed = evidence.defect_from_dict(document)
        digest = evidence.evidence_digest(parsed)
        statement, parameters = opened.defect_row(
            digest=digest, defect_id=parsed.defect_id,
            repository=parsed.repository, commit_sha=parsed.commit_sha,
            filed_at=parsed.discovered_at, record=document)
        opened.connection.execute(statement, parameters)

        with self.assertRaises(store_module.StoreError):
            standing.file_defect(opened, document, signer=self.signer, now=2000)
        self.assertEqual(opened.journal_events(
            receipt.journal_id_for(REPOSITORY)), ())

    def test_orphan_defect_event_is_not_repaired_with_a_second_event(self):
        opened = self.open("orphan-event")
        document = self.defect_document(sha("a"))
        parsed = evidence.defect_from_dict(document)
        digest = evidence.evidence_digest(parsed)
        event = {
            "domain": receipt.RECEIPT_DOMAIN,
            "type": receipt.EVENT_DEFECT,
            "defect_digest": digest,
            "defect_id": parsed.defect_id,
            "repository": parsed.repository,
            "commit_sha": parsed.commit_sha,
            "severity": parsed.severity,
            "discovered_at": parsed.discovered_at,
            "filed_at": 2000,
        }
        receipt.anchor_event(
            opened, receipt.journal_id_for(REPOSITORY), event,
            signer=self.signer, now=2000)

        with self.assertRaises(store_module.StoreError):
            standing.file_defect(opened, document, signer=self.signer, now=2001)
        events = opened.journal_events(receipt.journal_id_for(REPOSITORY))
        self.assertEqual(len(events), 1)
        self.assertEqual(opened.defects_for(REPOSITORY, sha("a")), ())


class PolicyTransactionSecurityTest(DurableCase):
    @staticmethod
    def _strand_policy_migration(path: str, *, copy: bool = False,
                                 conflict: bool = False) -> None:
        raw = sqlite3.connect(path, isolation_level=None)
        try:
            raw.executescript("""
                DROP TRIGGER trusted_policies_no_update;
                DROP TRIGGER trusted_policies_no_delete;
                DROP INDEX trusted_policy_class;
                ALTER TABLE trusted_policies RENAME TO trusted_policies_v4;
                CREATE TABLE trusted_policies (
                    repository TEXT NOT NULL,
                    class_id TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    enforcement_digest TEXT NOT NULL,
                    trusted_at INTEGER NOT NULL,
                    generation INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (
                        repository, class_id, policy_digest, generation));
                UPDATE schema_meta SET value='5'
                    WHERE key='schema_version';
            """)
            if copy:
                raw.execute(
                    "INSERT INTO trusted_policies SELECT * FROM "
                    "trusted_policies_v4")
            if conflict:
                raw.execute(
                    "UPDATE trusted_policies SET enforcement_digest=?",
                    ("c" * 64,))
        finally:
            raw.close()

    def test_retrusting_a_revoked_policy_opens_a_new_generation(self):
        opened = self.open("policy")
        arguments = dict(
            repository=REPOSITORY, class_id="default",
            policy_digest="a" * 64, enforcement_digest="b" * 64)
        self.assertTrue(opened.trust_policy(**arguments, trusted_at=1))
        self.assertTrue(opened.revoke_policy(
            repository=REPOSITORY, class_id="default",
            policy_digest="a" * 64, revoked_at=2))
        self.assertTrue(opened.trust_policy(**arguments, trusted_at=3))
        self.assertEqual(opened.policy_generation(REPOSITORY, "default"), 2)
        self.assertEqual(
            [row["policy_digest"] for row in
             opened.trusted_policies(REPOSITORY, "default")],
            ["a" * 64])

    def test_failed_commit_rolls_back_before_later_authority_reads(self):
        home = self.tmp / "failed-policy-commit"
        opened = self.open("failed-policy-commit")
        opened.connection.execute("PRAGMA defer_foreign_keys=ON")
        with self.assertRaises(sqlite3.IntegrityError):
            with opened._atomic():
                opened.connection.execute(
                    "INSERT INTO current_head(journal_id, receipt_hash) "
                    "VALUES(?,?)", ("deferred-fk", "a" * 64))

        self.assertFalse(opened.connection.in_transaction)
        self.assertTrue(opened.trust_policy(
            repository=REPOSITORY, class_id="default",
            policy_digest="b" * 64, enforcement_digest="c" * 64,
            trusted_at=10))
        opened.close()
        reopened = store_module.open_store(home)
        self.addCleanup(reopened.close)
        self.assertEqual(
            [row["policy_digest"] for row in
             reopened.trusted_policies(REPOSITORY, "default")],
            ["b" * 64])

    def test_schema_v5_migrates_dependency_time_to_canonical_minimum(self):
        opened = self.open("migration-v5-dependency-time")
        self.admit(opened, sha("a"), now=900, attempt="dependency")
        edge = ((REPOSITORY, sha("a")),)
        self.admit(opened, sha("c"), dependencies=edge, now=2000,
                   attempt="consumer-newer")
        opened.connection.execute(
            "UPDATE schema_meta SET value='5' WHERE key='schema_version'")
        opened.connection.execute("DROP TRIGGER dependencies_no_update")
        opened.connection.execute("""
            CREATE TRIGGER dependencies_no_update
            BEFORE UPDATE ON dependencies
            BEGIN SELECT RAISE(ABORT, 'dependencies are append-only'); END
        """)
        opened.close()

        reopened = store_module.open_store(
            self.tmp / "migration-v5-dependency-time")
        self.addCleanup(reopened.close)
        older = self.admit(
            reopened, sha("c"), dependencies=edge, now=1000,
            attempt="consumer-older")

        self.assertEqual(older.issued_at, 1000)
        row = reopened.connection.execute(
            "SELECT recorded_at FROM dependencies WHERE "
            "consumer_repository=? AND consumer_commit_sha=? AND "
            "dependency_repository=? AND dependency_commit_sha=?",
            (REPOSITORY, sha("c"), REPOSITORY, sha("a"))).fetchone()
        self.assertEqual(row["recorded_at"], 1000)
        self.assertEqual(reopened.schema_version, store_module.SCHEMA_VERSION)

    def test_stranded_v4_policy_table_is_recovered(self):
        opened = self.open("migration")
        opened.trust_policy(
            repository=REPOSITORY, class_id="default",
            policy_digest="a" * 64, enforcement_digest="b" * 64,
            trusted_at=1)
        path = opened.path
        opened.close()
        raw = sqlite3.connect(path, isolation_level=None)
        try:
            raw.executescript("""
                DROP TRIGGER trusted_policies_no_update;
                DROP TRIGGER trusted_policies_no_delete;
                DROP INDEX trusted_policy_class;
                ALTER TABLE trusted_policies RENAME TO trusted_policies_v4;
                CREATE TABLE trusted_policies (
                    repository TEXT NOT NULL,
                    class_id TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    enforcement_digest TEXT NOT NULL,
                    trusted_at INTEGER NOT NULL,
                    generation INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (
                        repository, class_id, policy_digest, generation));
                UPDATE schema_meta SET value='4'
                    WHERE key='schema_version';
            """)
        finally:
            raw.close()

        recovered = store_module.open_store(self.tmp / "migration")
        self.addCleanup(recovered.close)
        self.assertEqual(
            [row["policy_digest"] for row in
             recovered.trusted_policies(REPOSITORY, "default")],
            ["a" * 64])
        legacy = recovered.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='trusted_policies_v4'").fetchone()
        self.assertIsNone(legacy)

    def test_schema_v5_recovers_legacy_after_rename_before_copy(self):
        opened = self.open("migration-v5-before-copy")
        opened.trust_policy(
            repository=REPOSITORY, class_id="default",
            policy_digest="a" * 64, enforcement_digest="b" * 64,
            trusted_at=1)
        path = opened.path
        opened.close()
        self._strand_policy_migration(path)

        recovered = store_module.open_store(
            self.tmp / "migration-v5-before-copy")
        self.addCleanup(recovered.close)
        self.assertEqual(
            [row["policy_digest"] for row in
             recovered.trusted_policies(REPOSITORY, "default")],
            ["a" * 64])
        self.assertIsNone(recovered.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='trusted_policies_v4'").fetchone())

    def test_schema_v5_finishes_matching_copy_before_drop(self):
        opened = self.open("migration-v5-after-copy")
        opened.trust_policy(
            repository=REPOSITORY, class_id="default",
            policy_digest="a" * 64, enforcement_digest="b" * 64,
            trusted_at=1)
        path = opened.path
        opened.close()
        self._strand_policy_migration(path, copy=True)

        recovered = store_module.open_store(
            self.tmp / "migration-v5-after-copy")
        self.addCleanup(recovered.close)
        self.assertEqual(len(recovered.trusted_policies(
            REPOSITORY, "default", include_superseded=True)), 1)
        self.assertIsNone(recovered.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='trusted_policies_v4'").fetchone())

    def test_schema_v5_fails_closed_on_conflicting_legacy_and_new_rows(self):
        opened = self.open("migration-v5-conflict")
        opened.trust_policy(
            repository=REPOSITORY, class_id="default",
            policy_digest="a" * 64, enforcement_digest="b" * 64,
            trusted_at=1)
        path = opened.path
        opened.close()
        self._strand_policy_migration(path, copy=True, conflict=True)

        with self.assertRaises(store_module.StoreError):
            store_module.open_store(self.tmp / "migration-v5-conflict")

    def test_legacy_distinct_enforcement_digests_never_share_current(self):
        opened = self.open("migration-ambiguous-enforcement")
        path = opened.path
        opened.close()
        raw = sqlite3.connect(path, isolation_level=None)
        try:
            raw.executescript("""
                DROP TRIGGER trusted_policies_no_update;
                DROP TRIGGER trusted_policies_no_delete;
                DROP INDEX trusted_policy_class;
                DROP TABLE trusted_policies;
                CREATE TABLE trusted_policies (
                    repository TEXT NOT NULL,
                    class_id TEXT NOT NULL,
                    policy_digest TEXT PRIMARY KEY,
                    enforcement_digest TEXT NOT NULL,
                    trusted_at INTEGER NOT NULL);
                UPDATE schema_meta SET value='4'
                    WHERE key='schema_version';
            """)
            raw.executemany(
                "INSERT INTO trusted_policies VALUES(?,?,?,?,?)", (
                    (REPOSITORY, "default", "a" * 64, "b" * 64, 1),
                    (REPOSITORY, "default", "c" * 64, "d" * 64, 2),
                ))
        finally:
            raw.close()

        with self.assertRaises(store_module.StoreError):
            store_module.open_store(
                self.tmp / "migration-ambiguous-enforcement")

    def test_stranded_generation_cannot_recover_two_current_enforcements(self):
        opened = self.open("migration-ambiguous-stranded-generation")
        opened.trust_policy(
            repository=REPOSITORY, class_id="default",
            policy_digest="a" * 64, enforcement_digest="b" * 64,
            trusted_at=1)
        path = opened.path
        opened.close()
        self._strand_policy_migration(path)
        raw = sqlite3.connect(path, isolation_level=None)
        try:
            raw.execute(
                "INSERT INTO trusted_policies_v4(repository, class_id, "
                "policy_digest, enforcement_digest, trusted_at, generation) "
                "VALUES(?,?,?,?,?,?)",
                (REPOSITORY, "default", "c" * 64, "d" * 64, 2, 1))
        finally:
            raw.close()

        with self.assertRaises(store_module.StoreError):
            store_module.open_store(
                self.tmp / "migration-ambiguous-stranded-generation")

    def test_corrupt_current_generation_never_returns_two_enforcements(self):
        opened = self.open("policy-corrupt-current")
        opened.trust_policy(
            repository=REPOSITORY, class_id="default",
            policy_digest="a" * 64, enforcement_digest="b" * 64,
            trusted_at=1)
        opened.connection.execute(
            "INSERT INTO trusted_policies(repository, class_id, "
            "policy_digest, enforcement_digest, trusted_at, generation) "
            "VALUES(?,?,?,?,?,?)",
            (REPOSITORY, "default", "c" * 64, "d" * 64, 2, 1))
        with self.assertRaises(store_module.StoreError):
            opened.trusted_policies(REPOSITORY, "default")

    def test_concurrent_distinct_policy_changes_serialize_generations(self):
        home = self.tmp / "policy-race"
        seed = store_module.open_store(home)
        seed.close()
        barrier = threading.Barrier(2)
        outcomes = []
        errors = []

        def trust(marker: str):
            try:
                opened = store_module.open_store(home)
                try:
                    barrier.wait(timeout=5)
                    outcomes.append(opened.trust_policy(
                        repository=REPOSITORY, class_id="default",
                        policy_digest=marker * 64,
                        enforcement_digest=marker.upper() * 64,
                        trusted_at=1))
                finally:
                    opened.close()
            except BaseException as error:  # surfaced in the test thread
                errors.append(error)

        threads = [threading.Thread(target=trust, args=(marker,))
                   for marker in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(outcomes, [True, True])
        opened = self.open("policy-race")
        history = opened.trusted_policies(
            REPOSITORY, "default", include_superseded=True)
        self.assertEqual({row["generation"] for row in history}, {1, 2})
        self.assertEqual(len(opened.trusted_policies(REPOSITORY, "default")), 1)

    def test_policy_generation_is_read_inside_the_write_transaction(self):
        opened = self.open("policy-lock-observer")
        original = store_module.Store._policy_generation_locked
        observations = []

        def watched(instance, repository, class_id):
            observations.append(instance.connection.in_transaction)
            return original(instance, repository, class_id)

        store_module.Store._policy_generation_locked = watched
        self.addCleanup(setattr, store_module.Store,
                        "_policy_generation_locked", original)
        opened.trust_policy(
            repository=REPOSITORY, class_id="default",
            policy_digest="a" * 64, enforcement_digest="b" * 64,
            trusted_at=1)
        self.assertTrue(observations)
        self.assertTrue(all(observations))


class CacheTransactionSecurityTest(DurableCase):
    def test_sequence_cannot_be_allocated_outside_its_fact_transaction(self):
        opened = self.open("cache")
        with self.assertRaises(store_module.StoreError):
            opened.next_cache_sequence()
        total = opened.connection.execute(
            "SELECT COUNT(*) FROM cache_order").fetchone()[0]
        self.assertEqual(total, 0)


class ImportMultiplicitySecurityTest(DurableCase):
    def test_export_snapshot_survives_a_writer_between_head_reads(self):
        source = self.open("snapshot")
        first = self.admit(source, sha("a"), now=1000)
        writer = store_module.open_store(self.tmp / "snapshot")
        self.addCleanup(writer.close)
        original = store_module.Store.head_receipt_chain
        interfered = []

        def read_after_writer(opened, journal_id):
            if opened is source and not interfered:
                interfered.append(True)
                self.admit(writer, sha("b"), now=1001)
            return original(opened, journal_id)

        store_module.Store.head_receipt_chain = read_after_writer
        try:
            bundle = source.export_journal(
                receipt.journal_id_for(REPOSITORY))
        finally:
            store_module.Store.head_receipt_chain = original
        self.assertTrue(interfered)
        self.assertEqual(len(bundle["events"]), first.head.event_count)
        self.assertEqual(bundle["receipts"][-1]["receipt_hash"],
                         first.head.receipt_hash)

    def test_duplicate_bound_evidence_is_rejected(self):
        source = self.open("duplicate-source")
        self.admit(source, sha("a"))
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        bundle["evidence"].append(dict(bundle["evidence"][0]))
        target = self.open("duplicate-target")
        with self.assertRaises(store_module.StoreError):
            target.import_journal(bundle, self.signer)

    def test_direct_import_honours_the_same_size_bound_as_the_cli(self):
        source = self.open("large-source")
        self.admit(source, sha("a"))
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        encoded = json.dumps(bundle, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        target = self.open("large-target")
        original = store_module.MAX_JOURNAL_BYTES
        store_module.MAX_JOURNAL_BYTES = len(encoded) - 1
        self.addCleanup(setattr, store_module, "MAX_JOURNAL_BYTES", original)
        with self.assertRaises(store_module.StoreError):
            target.import_journal(bundle, self.signer)

    def test_export_can_select_a_deterministic_bounded_head_prefix(self):
        source = self.open("prefix-source")
        first = self.admit(source, sha("a"), now=1000)
        self.admit(source, sha("b"), now=1001)
        prefix = source.export_journal(
            receipt.journal_id_for(REPOSITORY),
            through_head=first.head.receipt_hash)
        again = source.export_journal(
            receipt.journal_id_for(REPOSITORY),
            through_head=first.head.receipt_hash)
        self.assertEqual(prefix, again)
        self.assertEqual(len(prefix["events"]), first.head.event_count)
        self.assertEqual(
            prefix["receipts"][-1]["receipt_hash"],
            first.head.receipt_hash)

    def test_historical_prefixes_are_cumulative_not_size_chunks(self):
        source = self.open("cumulative-prefix-source")
        first = self.admit(source, sha("a"), now=1000)
        second = self.admit(source, sha("b"), now=1001)
        journal_id = receipt.journal_id_for(REPOSITORY)
        early = source.export_journal(
            journal_id, through_head=first.head.receipt_hash)
        current = source.export_journal(
            journal_id, through_head=second.head.receipt_hash)
        early_size = len(store_module.canonical_json(early).encode("utf-8"))
        current_size = len(
            store_module.canonical_json(current).encode("utf-8"))
        self.assertLess(early_size, current_size)
        original = store_module.MAX_JOURNAL_BYTES
        store_module.MAX_JOURNAL_BYTES = early_size
        self.addCleanup(setattr, store_module, "MAX_JOURNAL_BYTES", original)

        selected = source.export_journal(
            journal_id, through_head=first.head.receipt_hash)
        self.assertEqual(selected, early)
        with self.assertRaises(store_module.StoreError) as caught:
            source.export_journal(
                journal_id, through_head=second.head.receipt_hash)
        self.assertIn("historical", str(caught.exception).lower())

    def test_pre_defect_prefix_is_explicit_historical_as_of_state(self):
        source = self.open("historical-prefix-source")
        admitted = self.admit(source, sha("a"), now=1000)
        standing.file_defect(source, {
            "kind": "defect", "defect_id": "after-cut",
            "repository": REPOSITORY, "commit_sha": sha("a"),
            "severity": "high", "summary": "later finding",
            "missed_check_ids": ["unit"], "regression_test_id": "unit",
            "discovered_at": 2000,
        }, signer=self.signer, now=2000)
        selected = source.export_journal(
            receipt.journal_id_for(REPOSITORY),
            through_head=admitted.head.receipt_hash)
        target = self.open("historical-prefix-target")
        target.import_journal(selected, self.signer)

        self.assertEqual(standing.current_standing(
            source, REPOSITORY, sha("a"), verifier=self.signer).state,
            standing.IMPEACHED)
        # CURRENT is local to the explicitly selected authenticated cut.  It
        # is not evidence that this is the source journal's latest head.
        self.assertEqual(standing.current_standing(
            target, REPOSITORY, sha("a"), verifier=self.signer).state,
            standing.CURRENT)

    def test_transfer_ceiling_does_not_limit_local_authenticated_standing(self):
        opened = self.open("standing-over-transfer-ceiling")
        self.admit(opened, sha("a"), now=1000)
        bundle = opened.export_journal(receipt.journal_id_for(REPOSITORY))
        encoded = store_module.canonical_json(bundle).encode("utf-8")
        original = store_module.MAX_JOURNAL_BYTES
        store_module.MAX_JOURNAL_BYTES = len(encoded) - 1
        self.addCleanup(setattr, store_module, "MAX_JOURNAL_BYTES", original)

        found = standing.current_standing(
            opened, REPOSITORY, sha("a"), verifier=self.signer)

        self.assertEqual(found.state, standing.CURRENT)

    def test_import_preserves_signed_defect_filing_time(self):
        source = self.open("defect-time-source")
        self.admit(source, sha("a"))
        standing.file_defect(source, {
            "kind": "defect", "defect_id": "d-time",
            "repository": REPOSITORY, "commit_sha": sha("a"),
            "severity": "high", "summary": "late filing",
            "missed_check_ids": ["unit"],
            "regression_test_id": "unit", "discovered_at": 1500,
        }, signer=self.signer, now=2000)
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        target = self.open("defect-time-target")
        target.import_journal(bundle, self.signer)
        row = target.connection.execute(
            "SELECT filed_at FROM defects WHERE defect_id='d-time'").fetchone()
        self.assertEqual(row["filed_at"], 2000)
        self.assertEqual(standing.current_standing(
            target, REPOSITORY, sha("a"), verifier=self.signer).state,
            standing.IMPEACHED)

    def test_import_rejects_conflicting_existing_dependency_metadata(self):
        source = self.open("dependency-conflict-source")
        self.admit(source, sha("a"), now=1000)
        self.admit(
            source, sha("c"), dependencies=((REPOSITORY, sha("a")),),
            now=1001)
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        target = self.open("dependency-conflict-target")
        target.put_dependency(
            consumer_repository=REPOSITORY, consumer_commit_sha=sha("c"),
            dependency_repository=REPOSITORY,
            dependency_commit_sha=sha("a"), recorded_at=99)
        with self.assertRaises(store_module.StoreError):
            target.import_journal(bundle, self.signer)

    def test_import_dependency_time_is_independent_of_receipt_array_order(self):
        source = self.open("dependency-order-source")
        self.admit(source, sha("a"), now=900, attempt="dependency")
        edge = ((REPOSITORY, sha("a")),)
        self.admit(source, sha("c"), dependencies=edge, now=2000,
                   attempt="consumer-newer")
        self.admit(source, sha("c"), dependencies=edge, now=1000,
                   attempt="consumer-older")
        bundle = source.export_journal(receipt.journal_id_for(REPOSITORY))
        bundle["workflow_receipts"].reverse()

        target = self.open("dependency-order-target")
        target.import_journal(bundle, self.signer)

        row = target.connection.execute(
            "SELECT recorded_at FROM dependencies WHERE "
            "consumer_repository=? AND consumer_commit_sha=? AND "
            "dependency_repository=? AND dependency_commit_sha=?",
            (REPOSITORY, sha("c"), REPOSITORY, sha("a"))).fetchone()
        self.assertEqual(row["recorded_at"], 1000)
        self.assertEqual(standing.current_standing(
            target, REPOSITORY, sha("c"), verifier=self.signer).state,
            standing.CURRENT)


class AuthenticatedStandingSecurityTest(DurableCase):
    def issue_evidence(self, record, *, authenticated_reviews=()):
        digest = evidence.evidence_digest(record)
        kinds = {
            "command": {"commands": (record,)},
            "review": {"reviews": (record,)},
            "authorship": {"authorships": (record,)},
        }
        return receipt.issue_receipt_from_parts(
            self.opened, repository=REPOSITORY, commit_sha=sha("a"),
            tree_sha=sha("b"), class_id="default",
            policy_digest="c" * 64, state=decision.ADMITTED,
            attempt_id="attempt-auth", decision_digest_value="d" * 64,
            evidence_digests=(digest,),
            authenticated_reviews=authenticated_reviews,
            signer=self.signer, now=1000, **kinds[record.kind])

    def setUp(self):
        super().setUp()
        self.opened = self.open("authenticated-standing")

    def test_no_verifier_means_unknown_even_when_a_row_says_admitted(self):
        opened = self.open("standing-no-key")
        self.admit(opened, sha("a"))
        found = standing.current_standing(opened, REPOSITORY, sha("a"))
        self.assertEqual(found.state, standing.UNKNOWN)
        self.assertEqual(found.receipts, ())

    def test_wrong_verifier_reports_claim_but_attributes_nothing(self):
        opened = self.open("standing-wrong-key")
        self.admit(opened, sha("a"))
        wrong = receipt.signer_from_secret("wrong", b"wrong-secret")
        found = standing.current_standing(
            opened, REPOSITORY, sha("a"), verifier=wrong)
        self.assertEqual(found.state, standing.UNKNOWN)
        self.assertEqual(found.receipts, ())
        self.assertEqual(len(found.unauthenticated), 1)
        report = standing.impact_report(
            opened, REPOSITORY, sha("a"), verifier=wrong)
        self.assertEqual(report.missed_checks, ())
        self.assertEqual(report.missed_reviewers, ())

    def test_tampered_workflow_receipt_cannot_inherit_an_authentic_head(self):
        opened = self.open("standing-tampered-receipt")
        admitted = self.admit(opened, sha("a"))
        document = receipt.receipt_to_dict(admitted)
        document["attempt_id"] = "tampered-attempt"
        opened.connection.execute("DROP TRIGGER workflow_receipts_no_update")
        opened.connection.execute(
            "UPDATE workflow_receipts SET receipt_json=? WHERE receipt_hash=?",
            (store_module.canonical_json(document), admitted.receipt_hash))

        found = standing.current_standing(
            opened, REPOSITORY, sha("a"), verifier=self.signer)
        self.assertEqual(found.state, standing.UNKNOWN)
        self.assertEqual(found.receipts, ())
        self.assertEqual(len(found.unauthenticated), 1)

    def test_orphan_defect_row_cannot_impeach_an_authentic_admission(self):
        opened = self.open("standing-orphan")
        self.admit(opened, sha("a"))
        document = {
            "kind": "defect", "defect_id": "forged",
            "repository": REPOSITORY, "commit_sha": sha("a"),
            "severity": "high", "summary": "forged",
            "missed_check_ids": [], "regression_test_id": "",
            "discovered_at": 2000,
        }
        parsed = evidence.defect_from_dict(document)
        statement, parameters = opened.defect_row(
            digest=evidence.evidence_digest(parsed),
            defect_id=parsed.defect_id, repository=parsed.repository,
            commit_sha=parsed.commit_sha, filed_at=parsed.discovered_at,
            record=document)
        opened.connection.execute(statement, parameters)

        found = standing.current_standing(
            opened, REPOSITORY, sha("a"), verifier=self.signer)
        self.assertEqual(found.state, standing.UNKNOWN)
        self.assertEqual(len(found.historical_receipts), 1)
        self.assertEqual(found.unauthenticated, ())
        report = standing.impact_report(
            opened, REPOSITORY, sha("a"), verifier=self.signer)
        remediation = " ".join(report.remediation)
        self.assertIn("historical", remediation)
        self.assertIn("if this exact evaluation attempt is finalizable",
                      remediation)
        self.assertIn("authenticated signed journal prefix", remediation)

    def test_signed_defect_event_without_its_attachment_is_unknown(self):
        opened = self.open("standing-missing-defect")
        self.admit(opened, sha("a"))
        standing.file_defect(opened, {
            "kind": "defect", "defect_id": "missing-defect",
            "repository": REPOSITORY, "commit_sha": sha("a"),
            "severity": "high", "summary": "attachment removed",
            "missed_check_ids": ["unit"],
            "regression_test_id": "unit", "discovered_at": 1500,
        }, signer=self.signer, now=2000)
        opened.connection.execute("DROP TRIGGER defects_no_delete")
        opened.connection.execute(
            "DELETE FROM defects WHERE defect_id='missing-defect'")

        found = standing.current_standing(
            opened, REPOSITORY, sha("a"), verifier=self.signer)
        self.assertEqual(found.state, standing.UNKNOWN)
        self.assertEqual(len(found.historical_receipts), 1)
        self.assertIn("bijection", found.integrity_problem)

    def test_unbound_evidence_row_confers_no_authority(self):
        opened = self.open("standing-orphan-evidence")
        self.admit(opened, sha("a"))
        extra = self.command(sha("c"), attempt="orphan-attempt")
        document = evidence.command_evidence_to_dict(extra)
        digest = evidence.evidence_digest(extra)
        opened.put_evidence(
            digest=digest, kind="command",
            repository=extra.repository, commit_sha=extra.commit_sha,
            tree_sha=extra.tree_sha, policy_digest=extra.policy_digest,
            record=document)

        found = standing.current_standing(
            opened, REPOSITORY, sha("a"), verifier=self.signer)
        self.assertEqual(found.state, standing.CURRENT)
        projections, invalid = opened.authenticated_workflow_state(self.signer)
        self.assertEqual(invalid, frozenset())
        self.assertNotIn(digest, projections[REPOSITORY]["evidence"])

    def test_missing_receipt_bound_evidence_invalidates_current_authority(self):
        opened = self.open("standing-missing-evidence")
        admitted = self.admit(opened, sha("a"))
        # Model a damaged/tampered durable database; ordinary writers cannot
        # create this state because the table is append-only.
        opened.connection.execute("DROP TRIGGER evidence_no_delete")
        opened.connection.execute(
            "DELETE FROM evidence WHERE digest=?",
            (admitted.evidence_digests[0],))

        found = standing.current_standing(
            opened, REPOSITORY, sha("a"), verifier=self.signer)
        self.assertEqual(found.state, standing.UNKNOWN)
        self.assertEqual(len(found.historical_receipts), 1)
        self.assertIn("not exact", found.integrity_problem)

    def test_new_issuance_refuses_when_prior_evidence_metadata_conflicts(self):
        opened = self.open("issuance-conflicting-prior-evidence")
        admitted = self.admit(
            opened, sha("a"), now=1000, attempt="attempt-one")
        opened.connection.execute("DROP TRIGGER evidence_no_update")
        opened.connection.execute(
            "UPDATE evidence SET commit_sha=? WHERE digest=?",
            (sha("f"), admitted.evidence_digests[0]))

        with self.assertRaises(receipt.ReceiptError):
            self.admit(
                opened, sha("a"), now=1001, attempt="attempt-two")

        self.assertEqual(len(opened.receipts_for(REPOSITORY, sha("a"))), 1)
        self.assertEqual(len(opened.journal_events(
            receipt.journal_id_for(REPOSITORY))), 1)
        attempt_two_digest = evidence.evidence_digest(
            self.command(sha("a"), attempt="attempt-two"))
        self.assertEqual(opened.connection.execute(
            "SELECT COUNT(*) AS total FROM evidence WHERE digest=?",
            (attempt_two_digest,)).fetchone()["total"], 0)

    def test_cached_and_new_issuance_refuse_other_commit_corruption(self):
        opened = self.open("issuance-other-commit-corruption")
        first = self.admit(
            opened, sha("a"), now=1000, attempt="attempt-a")
        cached = self.admit(
            opened, sha("c"), now=1001, attempt="attempt-c")
        opened.connection.execute("DROP TRIGGER evidence_no_delete")
        opened.connection.execute(
            "DELETE FROM evidence WHERE digest=?",
            (first.evidence_digests[0],))

        with self.assertRaises(receipt.ReceiptError):
            self.admit(
                opened, sha("c"), now=1001, attempt="attempt-c")
        with self.assertRaises(receipt.ReceiptError):
            self.admit(
                opened, sha("d"), now=1002, attempt="attempt-d")

        self.assertEqual(len(opened.receipts_for(REPOSITORY, sha("a"))), 1)
        self.assertEqual(len(opened.receipts_for(REPOSITORY, sha("c"))), 1)
        self.assertEqual(opened.receipts_for(REPOSITORY, sha("d")), ())
        self.assertEqual(len(opened.journal_events(
            receipt.journal_id_for(REPOSITORY))), 2)
        self.assertEqual(cached.attempt_id, "attempt-c")

    def test_new_issuance_refuses_unsigned_edge_on_other_commit(self):
        opened = self.open("issuance-other-commit-unsigned-edge")
        self.admit(opened, sha("a"), now=1000, attempt="attempt-a")
        standing.record_dependency(
            opened, consumer=(REPOSITORY, sha("a")),
            dependency=(REPOSITORY, sha("e")), now=1001)

        with self.assertRaises(receipt.ReceiptError):
            self.admit(
                opened, sha("c"), now=1002, attempt="attempt-c")

        self.assertEqual(opened.receipts_for(REPOSITORY, sha("c")), ())
        self.assertEqual(len(opened.journal_events(
            receipt.journal_id_for(REPOSITORY))), 1)

    def test_only_receipt_bound_dependencies_are_authoritative(self):
        opened = self.open("standing-dependencies")
        self.admit(opened, sha("a"), now=1000)
        self.admit(
            opened, sha("c"), dependencies=((REPOSITORY, sha("a")),),
            now=1001)
        found = standing.dependents(
            opened, REPOSITORY, sha("a"), verifier=self.signer)
        self.assertEqual(
            {(item.repository, item.commit_sha) for item in found},
            {(REPOSITORY, sha("c"))})

    def test_repeated_signed_edge_uses_the_earliest_receipt_timestamp(self):
        opened = self.open("standing-repeated-dependency")
        self.admit(opened, sha("a"), now=900, attempt="dependency")
        edge = ((REPOSITORY, sha("a")),)
        self.admit(opened, sha("c"), dependencies=edge, now=1000,
                   attempt="consumer-1")
        self.admit(opened, sha("c"), dependencies=edge, now=1001,
                   attempt="consumer-2")

        row = opened.connection.execute(
            "SELECT recorded_at FROM dependencies WHERE "
            "consumer_repository=? AND consumer_commit_sha=? AND "
            "dependency_repository=? AND dependency_commit_sha=?",
            (REPOSITORY, sha("c"), REPOSITORY, sha("a"))).fetchone()
        self.assertEqual(row["recorded_at"], 1000)
        self.assertEqual(standing.current_standing(
            opened, REPOSITORY, sha("c"), verifier=self.signer).state,
            standing.CURRENT)

    def test_repeated_signed_edge_is_order_independent_when_older_authority_arrives_later(self):
        opened = self.open("standing-reversed-dependency-time")
        self.admit(opened, sha("a"), now=900, attempt="dependency")
        edge = ((REPOSITORY, sha("a")),)
        self.admit(opened, sha("c"), dependencies=edge, now=2000,
                   attempt="consumer-newer")

        older = self.admit(opened, sha("c"), dependencies=edge, now=1000,
                           attempt="consumer-older")

        self.assertEqual(older.issued_at, 1000)
        self.assertEqual(len(opened.receipts_for(REPOSITORY, sha("c"))), 2)
        row = opened.connection.execute(
            "SELECT recorded_at FROM dependencies WHERE "
            "consumer_repository=? AND consumer_commit_sha=? AND "
            "dependency_repository=? AND dependency_commit_sha=?",
            (REPOSITORY, sha("c"), REPOSITORY, sha("a"))).fetchone()
        self.assertEqual(row["recorded_at"], 1000)
        self.assertEqual(standing.current_standing(
            opened, REPOSITORY, sha("c"), verifier=self.signer).state,
            standing.CURRENT)

    def test_unsigned_dependency_row_is_not_authoritative(self):
        opened = self.open("standing-unsigned-dependency")
        self.admit(opened, sha("a"), now=1000)
        standing.record_dependency(
            opened, consumer=(REPOSITORY, sha("c")),
            dependency=(REPOSITORY, sha("a")), now=1001)
        found = standing.dependents(
            opened, REPOSITORY, sha("a"), verifier=self.signer)
        self.assertEqual(found, ())

    def test_unsigned_same_edge_blocks_signed_attachment_issuance(self):
        opened = self.open("standing-dependency-metadata")
        self.admit(opened, sha("a"), now=1000)
        standing.record_dependency(
            opened, consumer=(REPOSITORY, sha("c")),
            dependency=(REPOSITORY, sha("a")), now=99)
        with self.assertRaises(receipt.ReceiptError):
            self.admit(
                opened, sha("c"), dependencies=((REPOSITORY, sha("a")),),
                now=1001)
        self.assertEqual(opened.receipts_for(REPOSITORY, sha("c")), ())
        _projections, invalid = opened.authenticated_workflow_state(
            self.signer)
        self.assertIn(REPOSITORY, invalid)

    def test_unsigned_extra_edge_blocks_receipt_issuance(self):
        opened = self.open("standing-extra-dependency")
        opened.connection.execute("""
            CREATE TRIGGER inject_unsigned_dependency
            AFTER INSERT ON evidence
            BEGIN
                INSERT INTO dependencies(
                    consumer_repository, consumer_commit_sha,
                    dependency_repository, dependency_commit_sha, recorded_at)
                VALUES(
                    'github.com/acme/widget',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'github.com/acme/widget',
                    'cccccccccccccccccccccccccccccccccccccccc', 99);
            END
        """)

        with self.assertRaises(receipt.ReceiptError):
            self.admit(opened, sha("a"), now=1001)

        self.assertEqual(opened.receipts_for(REPOSITORY, sha("a")), ())
        self.assertEqual(opened.connection.execute(
            "SELECT COUNT(*) AS total FROM dependencies WHERE "
            "consumer_repository=? AND consumer_commit_sha=?",
            (REPOSITORY, sha("a"))).fetchone()["total"], 0)

    def test_receipt_bound_authorship_is_reconstructed_as_authenticated_data(self):
        authorship = evidence.authorship_evidence_from_dict({
            "kind": "authorship", "author_id": "developer",
            "repository": REPOSITORY, "commit_sha": sha("a"),
            "tree_sha": sha("b"), "policy_digest": "c" * 64,
            "issued_at": 900,
        })
        self.issue_evidence(authorship)
        projections, invalid = self.opened.authenticated_workflow_state(
            self.signer)
        self.assertEqual(invalid, frozenset())
        rows = projections[REPOSITORY]["evidence"]
        self.assertEqual(rows[evidence.evidence_digest(authorship)]["kind"],
                         "authorship")
        self.assertEqual(standing.current_standing(
            self.opened, REPOSITORY, sha("a"), verifier=self.signer).state,
            standing.CURRENT)

    def test_nonapproving_review_cannot_be_issued_as_authenticated(self):
        review = evidence.review_evidence_from_dict({
            "kind": "review", "review_id": "r1", "reviewer_id": "person",
            "reviewer_version": "1", "author_id": "author",
            "verdict": "reject", "repository": REPOSITORY,
            "commit_sha": sha("a"), "tree_sha": sha("b"),
            "policy_digest": "c" * 64, "findings_digest": "e" * 64,
            "issued_at": 900, "attempt_id": "attempt-auth",
        })
        digest = evidence.evidence_digest(review)
        with self.assertRaises(receipt.ReceiptError):
            self.issue_evidence(
                review, authenticated_reviews=((digest, "reviewer-key"),))
        report = standing.impact_report(
            self.opened, REPOSITORY, sha("a"), verifier=self.signer)
        self.assertEqual(report.state, standing.UNKNOWN)
        self.assertEqual(report.missed_reviewers, ())

    def test_legacy_nonapproving_attribution_invalidates_projection(self):
        """Standing still refuses an authentic receipt from a pre-fix issuer."""

        review = evidence.review_evidence_from_dict({
            "kind": "review", "review_id": "legacy-r1",
            "reviewer_id": "person", "reviewer_version": "1",
            "author_id": "author", "verdict": "reject",
            "repository": REPOSITORY, "commit_sha": sha("a"),
            "tree_sha": sha("b"), "policy_digest": "c" * 64,
            "findings_digest": "e" * 64, "issued_at": 900,
            "attempt_id": "attempt-auth",
        })
        digest = evidence.evidence_digest(review)
        original = receipt._normalized_authenticated_reviews
        receipt._normalized_authenticated_reviews = (
            lambda value, _rows: tuple(value))
        try:
            self.issue_evidence(
                review, authenticated_reviews=((digest, "reviewer-key"),))
        finally:
            receipt._normalized_authenticated_reviews = original
        projections, invalid = self.opened.authenticated_workflow_state(
            self.signer)
        self.assertIn(REPOSITORY, projections)
        self.assertIn(REPOSITORY, invalid)
        report = standing.impact_report(
            self.opened, REPOSITORY, sha("a"), verifier=self.signer)
        self.assertEqual(report.state, standing.UNKNOWN)
        self.assertEqual(report.missed_reviewers, ())


if __name__ == "__main__":
    unittest.main()
