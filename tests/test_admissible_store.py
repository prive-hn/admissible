"""Contract: restart-durable SQLite persistence, CAS heads, append-only rows."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import TempCase, require_module  # noqa: E402

store = require_module("admissible.store")
receipt = require_module("admissible.receipt")

SECRET = "unit-test-secret-not-a-real-key"


def sample_event(index: int) -> dict:
    return {
        "domain": "admissible/v0.6/developer-workflow-admission",
        "sequence": index,
        "repository": "github.com/acme/widget",
        "commit_sha": f"{index:040d}",
    }


class SchemaTest(TempCase):
    def open(self):
        opened = store.open_store(self.home)
        self.addCleanup(opened.close)
        return opened

    def test_store_reports_its_schema_version(self):
        self.assertEqual(self.open().schema_version, store.SCHEMA_VERSION)

    def test_store_enables_wal_foreign_keys_and_busy_timeout(self):
        opened = self.open()
        self.assertEqual(opened.pragma("journal_mode").lower(), "wal")
        self.assertEqual(int(opened.pragma("foreign_keys")), 1)
        self.assertGreaterEqual(int(opened.pragma("busy_timeout")), 1000)

    def test_database_file_is_owner_only(self):
        opened = self.open()
        import stat
        mode = stat.S_IMODE(Path(opened.path).stat().st_mode)
        self.assertEqual(mode & 0o077, 0)

    def test_unwritable_home_fails_closed_without_memory_fallback(self):
        locked = self.tmp / "locked"
        locked.mkdir()
        os.chmod(locked, 0o500)
        self.addCleanup(os.chmod, locked, 0o700)
        with self.assertRaises(store.StoreError):
            store.open_store(locked / "home")

    def test_a_newer_schema_version_is_refused(self):
        opened = self.open()
        path = opened.path
        opened.close()
        with sqlite3.connect(path) as raw:
            raw.execute("UPDATE schema_meta SET value=? WHERE key='schema_version'",
                        (str(store.SCHEMA_VERSION + 1),))
        with self.assertRaises(store.StoreError):
            store.open_store(self.home)


class AppendOnlyTest(TempCase):
    def open(self):
        opened = store.open_store(self.home)
        self.addCleanup(opened.close)
        return opened

    def evidence_record(self, digest: str) -> dict:
        return {
            "digest": digest,
            "kind": "command",
            "repository": "github.com/acme/widget",
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
            "policy_digest": "c" * 64,
            "record": {"kind": "command", "check_id": "unit"},
        }

    def test_evidence_ingestion_is_idempotent_by_digest(self):
        opened = self.open()
        first = opened.put_evidence(**self.evidence_record("1" * 64))
        again = opened.put_evidence(**self.evidence_record("1" * 64))
        self.assertTrue(first)
        self.assertFalse(again)
        self.assertEqual(len(opened.evidence_for("github.com/acme/widget", "a" * 40)), 1)

    def test_evidence_rows_cannot_be_updated_or_deleted(self):
        opened = self.open()
        opened.put_evidence(**self.evidence_record("1" * 64))
        for statement in ("UPDATE evidence SET record_json='{}'",
                          "DELETE FROM evidence"):
            with self.assertRaises(sqlite3.DatabaseError):
                opened.connection.execute(statement)

    def test_journal_events_cannot_be_rewritten(self):
        opened = self.open()
        signer = receipt.signer_from_secret("k1", SECRET.encode("utf-8"))
        receipt.anchor_event(opened, "j1", sample_event(0), signer=signer, now=10)
        for statement in ("UPDATE journal_events SET event_json='{}'",
                          "DELETE FROM journal_events"):
            with self.assertRaises(sqlite3.DatabaseError):
                opened.connection.execute(statement)


class DurableHeadTest(TempCase):
    def signer(self):
        return receipt.signer_from_secret("k1", SECRET.encode("utf-8"))

    def open(self):
        opened = store.open_store(self.home)
        self.addCleanup(opened.close)
        return opened

    def test_head_survives_close_and_reopen(self):
        opened = store.open_store(self.home)
        anchored = receipt.anchor_event(opened, "j1", sample_event(0),
                                        signer=self.signer(), now=10)
        opened.close()
        reopened = self.open()
        current = reopened.current_head("j1")
        self.assertIsNotNone(current)
        self.assertEqual(current.receipt_hash, anchored.receipt_hash)
        self.assertEqual(current.event_count, 1)

    def test_successive_events_extend_the_same_journal(self):
        opened = self.open()
        signer = self.signer()
        first = receipt.anchor_event(opened, "j1", sample_event(0), signer=signer, now=10)
        second = receipt.anchor_event(opened, "j1", sample_event(1), signer=signer, now=11)
        self.assertEqual(second.event_count, 2)
        self.assertEqual(second.previous_receipt_hash, first.receipt_hash)

    def test_stale_predecessor_is_refused_by_compare_and_set(self):
        opened = self.open()
        signer = self.signer()
        stale = receipt.propose_next(opened, "j1", sample_event(0), signer=signer, now=10)
        receipt.anchor_event(opened, "j1", sample_event(1), signer=signer, now=11)
        with self.assertRaises(store.HeadConflict):
            opened.accept_head(stale.head_receipt, stale.events, signer)

    def test_rollback_to_a_shorter_journal_is_refused(self):
        opened = self.open()
        signer = self.signer()
        first = receipt.propose_next(opened, "j1", sample_event(0), signer=signer, now=10)
        opened.accept_head(first.head_receipt, first.events, signer)
        receipt.anchor_event(opened, "j1", sample_event(1), signer=signer, now=11)
        with self.assertRaises(store.HeadConflict):
            opened.accept_head(first.head_receipt, first.events, signer)

    def test_forged_signature_is_refused_before_any_row_is_written(self):
        opened = self.open()
        signer = self.signer()
        proposal = receipt.propose_next(opened, "j1", sample_event(0),
                                        signer=signer, now=10)
        other = receipt.signer_from_secret("k1", b"a-different-secret")
        with self.assertRaises(Exception):
            opened.accept_head(proposal.head_receipt, proposal.events, other)
        self.assertIsNone(opened.current_head("j1"))
        self.assertEqual(opened.journal_events("j1"), ())

    def test_locked_database_fails_closed(self):
        opened = self.open()
        signer = self.signer()
        blocker = sqlite3.connect(opened.path, timeout=0.1)
        self.addCleanup(blocker.close)
        blocker.execute("BEGIN EXCLUSIVE")
        with self.assertRaises(store.StoreError):
            receipt.anchor_event(opened, "j1", sample_event(0), signer=signer,
                                 now=10, busy_timeout_ms=200)
        blocker.rollback()

    def test_matching_durable_registry_and_kernel_registry_refusals(self):
        """Durable acceptance must refuse exactly what the kernel refuses."""
        from fcd import head as fcd_head
        opened = self.open()
        signer = self.signer()
        memory = fcd_head.MonotoneHeadRegistry()
        first = receipt.propose_next(opened, "j1", sample_event(0), signer=signer, now=10)
        opened.accept_head(first.head_receipt, first.events, signer)
        memory.accept(first.head_receipt, signer)
        stale = receipt.propose_next(opened, "j1", sample_event(1), signer=signer, now=11)
        receipt.anchor_event(opened, "j1", sample_event(2), signer=signer, now=12)
        with self.assertRaises(fcd_head.HeadRefused):
            memory.accept(stale.head_receipt, signer)
            memory.accept(receipt.propose_next(opened, "j1", sample_event(3),
                                               signer=signer, now=13).head_receipt, signer)
        with self.assertRaises(store.HeadConflict):
            opened.accept_head(stale.head_receipt, stale.events, signer)


WORKER = r'''
import json, os, sys
sys.path.insert(0, %(root)r)
from admissible import receipt, store
home = sys.argv[1]
label = sys.argv[2]
opened = store.open_store(home)
signer = receipt.signer_from_secret("k1", %(secret)r.encode("utf-8"))
written = 0
for index in range(%(count)d):
    event = {"domain": "admissible/v0.6/developer-workflow-admission",
             "sequence": index, "worker": label,
             "repository": "github.com/acme/widget",
             "commit_sha": "0" * 40}
    receipt.anchor_event(opened, "j1", event, signer=signer, now=100 + index,
                         attempts=200)
    written += 1
opened.close()
print(json.dumps({"written": written}))
'''


class ConcurrentWriterTest(TempCase):
    def test_concurrent_processes_never_lose_or_fork_the_journal(self):
        root = Path(__file__).resolve().parent.parent
        script = self.tmp / "worker.py"
        script.write_text(
            WORKER % {"root": str(root), "secret": SECRET, "count": 6},
            encoding="utf-8")
        env = dict(os.environ)
        env["ADMISSIBLE_HOME"] = str(self.home)
        # Prime the schema once so workers race on acceptance, not creation.
        primed = store.open_store(self.home)
        primed.close()
        processes = [
            subprocess.Popen([sys.executable, str(script), str(self.home), name],
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for name in ("a", "b", "c")]
        results = []
        for process in processes:
            out, err = process.communicate(timeout=180)
            self.assertEqual(process.returncode, 0, err.decode("utf-8"))
            results.append(json.loads(out.decode("utf-8")))
        self.assertEqual(sum(r["written"] for r in results), 18)
        opened = store.open_store(self.home)
        self.addCleanup(opened.close)
        current = opened.current_head("j1")
        self.assertEqual(current.event_count, 18)
        self.assertEqual(len(opened.journal_events("j1")), 18)
        opened.verify_journal("j1", receipt.signer_from_secret(
            "k1", SECRET.encode("utf-8")))


class TransactionRollbackTest(TempCase):
    def test_a_failure_mid_commit_leaves_no_partial_rows(self):
        opened = store.open_store(self.home)
        self.addCleanup(opened.close)
        signer = receipt.signer_from_secret("k1", SECRET.encode("utf-8"))
        proposal = receipt.propose_next(opened, "j1", sample_event(0),
                                        signer=signer, now=10)
        with self.assertRaises(store.StoreError):
            opened.accept_head(proposal.head_receipt, proposal.events, signer,
                               _fault="after_events")
        self.assertEqual(opened.journal_events("j1"), ())
        self.assertIsNone(opened.current_head("j1"))
        # The store stays usable and the same event can be committed cleanly.
        anchored = receipt.anchor_event(opened, "j1", sample_event(0),
                                        signer=signer, now=10)
        self.assertEqual(anchored.event_count, 1)


if __name__ == "__main__":
    unittest.main()
