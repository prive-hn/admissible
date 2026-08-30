"""Contract: Ready's store is a real backend that cannot assert anything.

The split leaves one durable home shared by both authorities.  Core owns its
vocabulary and the capability facades; this distribution owns the schema, the
reads, and the writes that record an observation.  Three things have to be true
at once, and they are three different claims:

* the backend **works** -- it creates the schema the monolith creates, migrates
  an older home in place without losing a row, and answers every read the
  candidate facade grants.  A backend that refused everything would trivially
  withhold the right capabilities and be useless;
* the backend **does not implement** the withheld capabilities at all.  Not
  "raises", not "is guarded": there is no ``trust_policy`` on the object, so
  reaching past the facade finds nothing to reach;
* the facade **grants exactly** the candidate set, so what is reachable is
  checkable rather than a matter of reading the file carefully.

The receipt and head reads are deliberately narrower than the monolith's, and
that is asserted rather than tolerated: they return the stored document, not a
parsed receipt.  Parsing is arithmetic; presenting the result as a receipt is
authority, and there is no verifier here to earn it.

Two further claims are proved here because they are the two ways the split
leaks in practice.

The first is that the backend is not part of this module's surface at all.  A
facade that withholds ``trust_policy`` is worth nothing if the module beside it
exports the class the facade wraps, or if the object holding the ``sqlite3``
connection answers to ``._connection``: either one hands a caller the raw
database and every append-only trigger becomes advice.  So the exported names
are pinned, the backend class is module-private, and the connection is not an
attribute of anything -- and the sweep below looks for a
:class:`sqlite3.Connection` under every obvious name, through ``dir``, through
``repr``, through pickle and through copy.

The second is *when* a refusal happens.  Refusing a home written by a newer
Admissible after switching it to WAL and running ``CREATE TABLE IF NOT
EXISTS`` over it is not a refusal; it is a rewrite followed by an apology.  So
a newer-schema fixture is fingerprinted -- bytes, hash, mtime, mode, every
``sqlite_master`` object, its sentinel rows and the sidecar files beside it --
and opening it must leave all of that identical.  The proof that nothing ran is
not the fingerprint alone: the connection is opened under a SQLite authorizer
that denies every non-read action and a trace callback that records every
statement, so a mutating statement would be caught at the moment it was
attempted rather than inferred afterwards from a checksum.

A v0.7 home is exercised end to end.  The monolith writes it, this backend
opens it, and every row the monolith recorded is still there afterwards --
because "do not reset or rewrite the local store" is a compatibility promise
and not a plan.
"""
from __future__ import annotations

import contextlib
import copy
import gc
import hashlib
import json
import os
import pickle
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import weakref
from pathlib import Path
from unittest import mock

from admissible import store as legacy_store

from admissible_core import store_base, store_open
from admissible_core.store_candidate import CandidateStore

from admissible_ready import store as ready_store

from . import CORE_SRC, READY_SRC, REPO_ROOT

# The names ``admissible_ready.store`` promises, and the whole of them. Pinned
# rather than sampled: the escape this suite exists to forbid is a backend
# class or a connection constructor arriving in the module's public surface,
# and a subset check would not notice one being added.
EXPECTED_EXPORTS = frozenset({
    "DEFAULT_BUSY_TIMEOUT_MS",
    "ReadyStore",
    "SCHEMA_LOCK_TIMEOUT_MS",
    "SCHEMA_VERSION",
    "StoreError",
    "default_home",
    "open_store",
    "open_store_count",
    "require_home_outside",
})

# Names a caller reaching for the raw database would try first, plus the
# manglings of a ``__connection`` slot for every class in the hierarchy. None
# of these may answer at all, on the facade or on the backend.
BACKEND_PROBES = (
    "_connection", "connection", "conn", "_conn", "_db", "db", "sqlite",
    "_sqlite", "_backend", "backend", "_store", "store", "raw", "_raw",
    "_cursor", "cursor", "__dict__",
    "_ReadyStore__connection", "_ReadyStoreBackend__connection",
    "_CapabilityFacade__backend",
)

# The wider set the sweeps follow one level further. These may exist -- every
# object has ``__getstate__`` since 3.11, and a granted call path answers
# ``__self__`` with the facade -- so the question asked of them is not whether
# they answer but whether what they answer with is a connection or a backend.
REACHABILITY_PROBES = BACKEND_PROBES + (
    "__self__", "__func__", "__wrapped__", "__closure__", "__getstate__",
    "_facade", "_name",
)


def is_a_connection(value: object) -> bool:
    """Whether ``value`` is a sqlite connection, or the class that makes one."""

    if isinstance(value, sqlite3.Connection):
        return True
    return isinstance(value, type) and issubclass(value, sqlite3.Connection)


def safely(obj: object, name: str):
    """``getattr`` that answers with ``None`` rather than raising.

    A sweep over ``dir()`` touches names that refuse, and a refusal is the
    right answer to most of them.  The only question asked here is whether some
    name answers with a connection or with the backend.
    """

    try:
        return getattr(obj, name)
    except Exception:  # noqa: BLE001 - any refusal is a non-answer
        return None


class StoreCase(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(self.scratch())

    def scratch(self) -> str:
        raw = tempfile.mkdtemp(prefix="admissible-ready-store-")
        self.addCleanup(shutil.rmtree, raw, True)
        return raw

    def open(self) -> ready_store.ReadyStore:
        opened = ready_store.open_store(self.home)
        self.addCleanup(opened.close)
        return opened

    def backend(self):
        """The backend, reached by its module-private name.

        Deliberately the unsupported path.  These tests are the ones that have
        to talk about the object behind the facade -- to prove the withheld
        capabilities are absent from it rather than merely unreachable -- and
        the leading underscore is the point: there is no supported spelling.
        """

        opened = ready_store._ReadyStoreBackend(self.home)
        self.addCleanup(opened.close)
        return opened

    def legacy(self):
        opened = legacy_store.open_store(self.home)
        self.addCleanup(opened.close)
        return opened

    @contextlib.contextmanager
    def raw(self, path: Path | str):
        """A connection this test really closes.

        ``with sqlite3.connect(...) as connection`` commits and does *not*
        close, so a helper written that way leaves a live connection on a
        WAL-mode home -- which now means a ``-wal`` and a ``-shm`` beside it,
        and a store the opener under test is right to refuse. Autocommit, so
        the commit the context manager used to do is not needed either.
        """

        connection = sqlite3.connect(str(path), isolation_level=None)
        try:
            yield connection
        finally:
            connection.close()

    def rows(self, table: str) -> list[tuple]:
        with self.raw(store_base.database_path(self.home)) as raw:
            return raw.execute(f"SELECT * FROM {table}").fetchall()

    def tables(self) -> set[str]:
        with self.raw(store_base.database_path(self.home)) as raw:
            return {row[0] for row in raw.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}


class SchemaParity(StoreCase):
    """The two backends create the same database."""

    def test_the_schema_version_is_the_monolith_s(self):
        self.assertEqual(legacy_store.SCHEMA_VERSION,
                         ready_store.SCHEMA_VERSION)

    def test_a_fresh_home_has_the_same_tables_either_way(self):
        self.open()
        split_tables = self.tables()
        other = Path(self.scratch())
        legacy = legacy_store.open_store(other)
        self.addCleanup(legacy.close)
        with self.raw(store_base.database_path(other)) as raw:
            legacy_tables = {row[0] for row in raw.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual(legacy_tables, split_tables)

    def test_a_fresh_home_has_the_same_triggers_and_indexes_either_way(self):
        self.open()
        other = Path(self.scratch())
        legacy = legacy_store.open_store(other)
        self.addCleanup(legacy.close)

        def objects(home: Path) -> set[tuple[str, str]]:
            with self.raw(store_base.database_path(home)) as raw:
                return {(row[0], row[1]) for row in raw.execute(
                    "SELECT type, name FROM sqlite_master "
                    "WHERE type IN ('trigger', 'index') "
                    "AND name NOT LIKE 'sqlite_%'")}

        self.assertEqual(objects(other), objects(self.home))

    def test_the_database_and_home_are_owner_only(self):
        self.open()
        self.assertEqual(
            0o600,
            store_base.database_path(self.home).stat().st_mode & 0o777)
        self.assertEqual(0o700, self.home.stat().st_mode & 0o777)

    def test_the_connection_is_configured_the_way_the_monolith_configures_it(self):
        backend = self.backend()
        self.assertEqual("wal", str(backend.pragma("journal_mode")).lower())
        self.assertEqual(1, backend.pragma("foreign_keys"))
        self.assertEqual(2, backend.pragma("synchronous"))

    def test_a_newer_schema_is_refused_rather_than_downgraded(self):
        opened = ready_store.open_store(self.home)
        opened.close()
        with self.raw(store_base.database_path(self.home)) as raw:
            raw.execute(
                "UPDATE schema_meta SET value=? WHERE key='schema_version'",
                (str(ready_store.SCHEMA_VERSION + 1),))
        with self.assertRaises(ready_store.StoreError):
            ready_store.open_store(self.home)


class ExistingHomesSurvive(StoreCase):
    """A v0.7 home opens here and keeps every row it had."""

    def seed_with_the_monolith(self) -> dict:
        """Write one attempt, its evidence and a trusted policy, as v0.7 did."""

        opened = self.legacy()
        opened.put_evidence(
            digest="d" * 64, kind="command", repository="example.com/one",
            commit_sha="a" * 40, tree_sha="b" * 40, policy_digest="c" * 64,
            record={"kind": "command", "check_id": "one"})
        opened.record_attempt(
            attempt_id="attempt-one", repository="example.com/one",
            commit_sha="a" * 40, class_id="default", policy_digest="c" * 64,
            state="CHECKS_PASSED", started_at=1, digests=["d" * 64],
            tree_sha="b" * 40, decision={"state": "CHECKS_PASSED"})
        opened.trust_policy(
            repository="example.com/one", class_id="default",
            policy_digest="c" * 64, enforcement_digest="e" * 64,
            trusted_at=1)
        opened.put_dependency(
            consumer_repository="example.com/two",
            consumer_commit_sha="f" * 40,
            dependency_repository="example.com/one",
            dependency_commit_sha="a" * 40, recorded_at=2)
        before = {name: self.rows(name) for name in (
            "attempts", "attempt_evidence", "evidence", "trusted_policies",
            "dependencies", "schema_meta")}
        opened.close()
        return before

    def test_the_split_reads_a_home_the_monolith_wrote(self):
        self.seed_with_the_monolith()
        opened = self.open()
        self.assertEqual(
            "attempt-one",
            opened.latest_attempt("example.com/one", "a" * 40)["attempt_id"])
        self.assertEqual(
            1, len(opened.evidence_for("example.com/one", "a" * 40)))
        self.assertEqual(
            ("c" * 64,),
            tuple(item["policy_digest"] for item in
                  opened.trusted_policies("example.com/one", "default")))
        self.assertEqual((("example.com/two", "f" * 40),),
                         opened.direct_consumers("example.com/one", "a" * 40))

    def test_opening_it_here_destroys_nothing(self):
        before = self.seed_with_the_monolith()
        opened = self.open()
        opened.close()
        after = {name: self.rows(name) for name in before}
        self.assertEqual(before, after)

    def test_the_monolith_still_reads_what_the_split_wrote(self):
        opened = self.open()
        opened.record_attempt(
            attempt_id="split-attempt", repository="example.com/one",
            commit_sha="a" * 40, class_id="default", policy_digest="c" * 64,
            state="REFUSED", started_at=9, tree_sha="b" * 40,
            decision={"state": "REFUSED"})
        opened.close()
        legacy = self.legacy()
        found = legacy.latest_attempt("example.com/one", "a" * 40)
        self.assertEqual("split-attempt", found["attempt_id"])
        self.assertEqual({"state": "REFUSED"}, found["decision"])

    def test_a_schema_four_home_migrates_in_place_without_losing_a_policy(self):
        """The generation column cannot be ALTERed in, so the table is rebuilt.

        Every existing row lands in generation 1: whatever the home already
        trusted stays trusted. Nothing is deleted, and the version bump and
        the rebuild are one transaction.
        """

        path = store_base.database_path(self.home)
        self.home.mkdir(parents=True, exist_ok=True)
        with self.raw(path) as raw:
            raw.execute("CREATE TABLE schema_meta ("
                        "key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            raw.execute("INSERT INTO schema_meta VALUES('schema_version','4')")
            raw.execute("""
                CREATE TABLE trusted_policies (
                    repository         TEXT NOT NULL,
                    class_id           TEXT NOT NULL,
                    policy_digest      TEXT NOT NULL,
                    enforcement_digest TEXT NOT NULL,
                    trusted_at         INTEGER NOT NULL,
                    PRIMARY KEY (repository, class_id, policy_digest))""")
            raw.execute(
                "INSERT INTO trusted_policies VALUES(?,?,?,?,?)",
                ("example.com/one", "default", "c" * 64, "e" * 64, 1))
        opened = self.open()
        self.assertNotIn("trusted_policies_v4", self.tables())
        trusted = opened.trusted_policies("example.com/one", "default")
        self.assertEqual(1, len(trusted))
        self.assertEqual("c" * 64, trusted[0]["policy_digest"])
        self.assertEqual(1, trusted[0]["generation"])
        with self.raw(path) as raw:
            version = raw.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()[0]
        self.assertEqual(ready_store.SCHEMA_VERSION, int(version))

    def test_an_absent_home_is_created_rather_than_refused(self):
        """Ready is the half that runs first; it may bootstrap its own home."""
        missing = Path(self.scratch()) / "nested" / "home"
        opened = ready_store.open_store(missing)
        self.addCleanup(opened.close)
        self.assertTrue(store_base.database_path(missing).is_file())


class TheReachableSurface(StoreCase):
    """What the facade grants is exactly Core's candidate set."""

    def test_the_store_is_a_candidate_store(self):
        self.assertTrue(issubclass(ready_store.ReadyStore, CandidateStore))
        self.assertIsInstance(self.open(), CandidateStore)

    def test_it_grants_the_reads_and_the_observation_writes(self):
        self.assertEqual(
            store_base.READ_CAPABILITIES | store_base.CANDIDATE_WRITE_CAPABILITIES,
            ready_store.ReadyStore.CAPABILITIES)

    def test_every_granted_capability_is_reachable(self):
        opened = self.open()
        for name in sorted(ready_store.ReadyStore.CAPABILITIES):
            with self.subTest(capability=name):
                self.assertIsNotNone(getattr(opened, name))

    def test_every_withheld_capability_is_refused_through_the_facade(self):
        opened = self.open()
        for name in sorted(store_base.WITHHELD_CAPABILITIES - {"close"}):
            with self.subTest(capability=name):
                with self.assertRaises(store_base.CapabilityError):
                    getattr(opened, name)

    def test_the_withheld_capabilities_are_not_implemented_at_all(self):
        """Past the facade there is nothing to reach.

        This is the claim the facade cannot make on its own. A facade over a
        backend that *has* ``trust_policy`` is a restriction; a backend without
        it is an absence, and only the second survives somebody finding a
        reference to the backend.
        """

        backend = self.backend()
        for name in sorted(store_base.WITHHELD_CAPABILITIES - {"close"}):
            with self.subTest(capability=name):
                self.assertFalse(
                    hasattr(backend, name),
                    f"the Ready backend implements {name}")

    def test_the_legacy_backend_implements_the_legacy_withheld_names(self):
        """The control for 0.7 names; split-Trust names are proved in Core."""
        split_trust_names = {
            "insert_workflow_receipt",
            "insert_defect",
            "insert_receipt_evidence",
            "insert_dependency_edge",
            "lower_dependency_recorded_at",
        }
        legacy = self.legacy()
        for name in sorted(store_base.WITHHELD_CAPABILITIES - split_trust_names):
            with self.subTest(capability=name):
                self.assertTrue(hasattr(legacy, name))

    def test_close_is_granted_because_this_distribution_owns_the_backend(self):
        """Core withholds ``close`` from every facade; Ready opened this one."""
        self.assertNotIn("close", ready_store.ReadyStore.CAPABILITIES)
        opened = ready_store.open_store(self.home)
        self.assertTrue(callable(opened.close))
        opened.close()

    def test_closing_twice_is_harmless(self):
        opened = ready_store.open_store(self.home)
        opened.close()
        opened.close()

    def test_the_facade_does_not_hand_back_the_backend(self):
        opened = self.open()
        self.assertFalse(hasattr(opened, "__dict__"))
        self.assertIs(opened, opened.evidence_for.__self__)

    def test_the_open_count_tracks_what_was_opened_and_closed(self):
        before = ready_store.open_store_count()
        opened = ready_store.open_store(self.home)
        self.assertEqual(before + 1, ready_store.open_store_count())
        opened.close()
        self.assertEqual(before, ready_store.open_store_count())

    def test_it_works_as_a_context_manager(self):
        with ready_store.open_store(self.home) as opened:
            self.assertEqual((), opened.evidence_for("example.com/one", "a" * 40))


class RecordsAreDocumentsNotAuthority(StoreCase):
    """Receipts and heads come back as stored documents, never as receipts."""

    def seed_a_receipt(self) -> dict:
        """Insert one receipt row the way a finalizer would have."""

        path = store_base.database_path(self.home)
        opened = self.open()
        opened.close()
        document = {"schema": "admissible/v0.6/workflow-receipt",
                    "receipt_hash": "r" * 64, "state": "ADMITTED"}
        with self.raw(path) as raw:
            raw.execute(
                "INSERT INTO head_receipts VALUES(?,?,?,?,?)",
                ("h" * 64, "journal", 1, "", json.dumps({"head": True})))
            raw.execute(
                "INSERT INTO workflow_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                ("r" * 64, "b" * 64, "journal", "example.com/one", "a" * 40,
                 "t" * 40, "c" * 64, "default", "ADMITTED", 1,
                 json.dumps(document), "h" * 64))
            raw.execute("INSERT INTO current_head VALUES(?,?)",
                        ("journal", "h" * 64))
        return document

    def test_a_receipt_read_returns_the_stored_document(self):
        document = self.seed_a_receipt()
        opened = self.open()
        self.assertEqual(document, opened.workflow_receipt("r" * 64))
        self.assertEqual((document,),
                         opened.receipts_for("example.com/one", "a" * 40))
        self.assertEqual((document,), opened.receipts_in("example.com/one"))
        self.assertEqual((document,), opened.receipts_in_journal("journal"))
        self.assertEqual(document, opened.latest_receipt("example.com/one"))
        self.assertEqual(1, opened.receipt_count("example.com/one"))

    def test_a_head_read_returns_the_stored_document(self):
        self.seed_a_receipt()
        opened = self.open()
        self.assertEqual({"head": True}, opened.current_head("journal"))
        self.assertEqual(({"head": True},),
                         opened.head_receipt_chain("journal"))
        self.assertTrue(opened.has_head_receipt("h" * 64))

    def test_an_admitted_row_does_not_make_unsigned_ready_say_ready(self):
        """The row exists and Ready still cannot promote it.

        This is the whole reason receipts are readable at all: unsigned Ready
        reports ``UNVERIFIED`` -- "there are receipts here and I cannot vouch
        for them" -- which is different from, and more useful than, knowing of
        none.
        """

        self.seed_a_receipt()
        opened = self.open()
        self.assertTrue(opened.receipts_for("example.com/one", "a" * 40))
        from admissible_ready import ready as ready_state

        self.assertNotIn("ready", ready_state.UNSIGNED_STATUSES)
        self.assertIn("UNVERIFIED", ready_state.UNSIGNED_STANDING)


class ObservationWrites(StoreCase):
    """The writes this distribution may make, and what they cost."""

    def test_evidence_ingest_is_idempotent(self):
        opened = self.open()
        arguments = {
            "digest": "d" * 64, "kind": "command",
            "repository": "example.com/one", "commit_sha": "a" * 40,
            "tree_sha": "b" * 40, "policy_digest": "c" * 64,
            "record": {"kind": "command"},
        }
        self.assertTrue(opened.put_evidence(**arguments))
        self.assertFalse(opened.put_evidence(**arguments))

    def test_a_cache_sequence_may_only_be_allocated_inside_a_transaction(self):
        backend = self.backend()
        with self.assertRaises(ready_store.StoreError):
            backend.next_cache_sequence()

    def test_only_command_evidence_is_cached(self):
        opened = self.open()
        with self.assertRaises(ready_store.StoreError):
            opened.cache_command_evidence({"not": "evidence"}, recorded_at=1)

    def test_attempts_are_append_only_in_the_database_itself(self):
        opened = self.open()
        opened.record_attempt(
            attempt_id="one", repository="example.com/one",
            commit_sha="a" * 40, class_id="default", policy_digest="c" * 64,
            state="REFUSED", started_at=1)
        opened.close()
        with self.raw(store_base.database_path(self.home)) as raw:
            with self.assertRaises(sqlite3.IntegrityError):
                raw.execute("DELETE FROM attempts")

    def test_a_read_transaction_is_consistent_and_writes_nothing(self):
        opened = self.open()
        opened.put_evidence(
            digest="d" * 64, kind="command", repository="example.com/one",
            commit_sha="a" * 40, tree_sha="b" * 40, policy_digest="c" * 64,
            record={"kind": "command"})
        seen = opened.read_transaction(
            lambda: opened.evidence_for("example.com/one", "a" * 40))
        self.assertEqual(1, len(seen))


class TheBackendIsNotPartOfTheSurface(StoreCase):
    """``open_store`` hands out a facade, and nothing leads back from it.

    The facade tests in :class:`TheReachableSurface` prove that withheld
    *capabilities* are refused.  These prove the sharper thing: that the
    ``sqlite3`` connection under them is not reachable either.  A caller who
    obtained one would not need a withheld capability, because a connection can
    ``DROP TRIGGER`` and then do whatever it likes.

    Two doors are checked, because the escape only needs one of them.  The
    module's exported surface is the front door: exporting the backend class
    lets any caller build a second one beside the facade.  The objects
    themselves are the back door: an attribute, a mangled slot, a granted
    method's ``__self__``, a repr, or a pickle that carries state.
    """

    def test_the_declared_exports_are_exactly_the_promised_names(self):
        self.assertEqual(EXPECTED_EXPORTS, frozenset(ready_store.__all__))

    def test_the_backend_class_is_not_a_public_module_attribute(self):
        self.assertFalse(hasattr(ready_store, "ReadyStoreBackend"))
        offenders = sorted(
            name for name in dir(ready_store)
            if not name.startswith("_")
            and ("backend" in name.lower() or "connect" in name.lower()))
        self.assertEqual([], offenders)

    def test_no_public_module_attribute_is_or_makes_a_connection(self):
        offenders = sorted(
            name for name in dir(ready_store)
            if not name.startswith("_")
            and is_a_connection(safely(ready_store, name)))
        self.assertEqual([], offenders)

    def test_a_star_import_binds_the_promised_names_and_no_others(self):
        """``import *`` is the surface a consumer actually gets."""

        namespace: dict = {}
        exec("from admissible_ready.store import *", namespace)  # noqa: S102
        bound = {name: value for name, value in namespace.items()
                 if not name.startswith("__")}
        self.assertEqual(EXPECTED_EXPORTS, frozenset(bound))
        offenders = sorted(
            name for name, value in bound.items() if is_a_connection(value))
        self.assertEqual([], offenders)

    def test_open_store_returns_only_the_facade(self):
        opened = self.open()
        self.assertIs(ready_store.ReadyStore, type(opened))
        self.assertNotIsInstance(opened, ready_store._ReadyStoreBackend)

    def test_the_backend_keeps_the_connection_off_itself(self):
        """No ``_connection``, and no instance dictionary to hide one in.

        The backend is private now, but "private" in Python is a spelling.
        The connection living in module state rather than on the object is
        what makes reaching it a deliberate act instead of an attribute
        access on something a caller already holds.
        """

        backend = self.backend()
        for name in BACKEND_PROBES:
            with self.subTest(name=name):
                self.assertFalse(hasattr(backend, name))
        offenders = sorted(
            name for name in dir(backend)
            if is_a_connection(safely(backend, name)))
        self.assertEqual([], offenders)

    def test_no_obvious_name_answers_on_the_facade_either(self):
        opened = self.open()
        for name in BACKEND_PROBES:
            with self.subTest(name=name):
                self.assertFalse(hasattr(opened, name))

    def swept(self, opened) -> dict:
        """Every name on the facade, and what one step past it answers with."""

        found = {}
        names = (set(dir(opened)) | set(type(opened).CAPABILITIES)
                 | set(REACHABILITY_PROBES))
        for name in sorted(names):
            value = safely(opened, name)
            found[name] = [value] + [safely(value, inner)
                                     for inner in REACHABILITY_PROBES]
        return found

    def test_the_sweep_reaches_real_answers(self):
        """The control: a sweep that found nothing would forbid nothing.

        ``safely`` turns every refusal into ``None``, so the two sweeps below
        would pass just as well against an object that answered no name at
        all. This is what says they ran against a live store.
        """

        opened = self.open()
        reached = self.swept(opened)
        self.assertEqual(str(store_base.database_path(self.home)),
                         reached["path"][0])
        self.assertTrue(callable(reached["evidence_for"][0]))
        # ``__self__`` is one of the probes, so the sweep really does follow a
        # step past each name -- and what it finds there is the facade.
        self.assertIn(opened, reached["evidence_for"])

    def test_no_name_on_the_facade_answers_with_a_connection(self):
        opened = self.open()
        offenders = sorted(
            name for name, reached in self.swept(opened).items()
            if any(is_a_connection(item) for item in reached))
        self.assertEqual([], offenders)

    def test_no_name_on_the_facade_answers_with_the_backend(self):
        """The registry is read directly, so the sweep knows what to look for."""

        opened = self.open()
        backend = ready_store._OWNED[opened]
        offenders = sorted(
            name for name, reached in self.swept(opened).items()
            if any(item is backend for item in reached))
        self.assertEqual([], offenders)

    def test_a_granted_method_is_not_the_backend_s_bound_method(self):
        opened = self.open()
        backend = ready_store._OWNED[opened]
        for name in sorted(type(opened).CAPABILITIES):
            granted = getattr(opened, name)
            if not callable(granted):
                continue
            with self.subTest(capability=name):
                self.assertIsNot(getattr(granted, "__self__", None), backend)
                self.assertIs(granted.__self__, opened)
                self.assertFalse(hasattr(granted, "__func__"))

    def test_neither_repr_carries_a_connection_or_a_handle(self):
        opened = self.open()
        backend = ready_store._OWNED[opened]
        connection = ready_store._CONNECTIONS[backend]
        for text in (repr(opened), repr(opened.evidence_for)):
            with self.subTest(text=text):
                self.assertNotIn("sqlite3.Connection", text)
                self.assertNotIn(repr(connection), text)
                self.assertNotIn(hex(id(connection)), text)
                self.assertNotIn(hex(id(backend)), text)
                self.assertNotIn(str(self.home), text)

    def test_the_facade_cannot_be_pickled_or_copied_into_a_connection(self):
        opened = self.open()
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                with self.assertRaises(store_base.CapabilityError):
                    pickle.dumps(opened, protocol)
        with self.assertRaises(store_base.CapabilityError):
            copy.copy(opened)
        with self.assertRaises(store_base.CapabilityError):
            copy.deepcopy(opened)
        with self.assertRaises(store_base.CapabilityError):
            pickle.dumps(opened.evidence_for)

    def test_the_facade_still_holds_no_trust_capability_after_all_of_that(self):
        """The probing above must not have opened anything on the way past."""

        opened = self.open()
        for name in sorted(store_base.WITHHELD_CAPABILITIES - {"close"}):
            with self.subTest(capability=name):
                with self.assertRaises(store_base.CapabilityError):
                    getattr(opened, name)
                self.assertFalse(
                    hasattr(ready_store._OWNED[opened], name),
                    f"the Ready backend implements {name}")

    def test_the_allowed_surface_still_reaches_the_real_database(self):
        """A store that answered nothing would pass every sweep above."""

        opened = self.open()
        self.assertTrue(opened.put_evidence(
            digest="d" * 64, kind="command", repository="example.com/one",
            commit_sha="a" * 40, tree_sha="b" * 40, policy_digest="c" * 64,
            record={"kind": "command"}))
        self.assertEqual(
            1, len(opened.evidence_for("example.com/one", "a" * 40)))
        self.assertEqual(str(store_base.database_path(self.home)), opened.path)

    def test_closing_the_facade_really_closes_the_connection(self):
        opened = ready_store.open_store(self.home)
        backend = ready_store._OWNED[opened]
        connection = ready_store._CONNECTIONS[backend]
        opened.close()
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
        self.assertNotIn(backend, ready_store._CONNECTIONS)

    def test_a_store_nobody_holds_is_collected_with_its_connection(self):
        """The registries are weak-keyed, so dropping the facade releases it.

        A strong key anywhere would make every store ever opened immortal
        along with the SQLite connection it holds, which is a file handle and
        a lock that a long-running Ready process would never give back.
        """

        before = ready_store.open_store_count()
        opened = ready_store.open_store(self.home)
        backend = ready_store._OWNED[opened]
        released = weakref.ref(backend)
        # Held here so collecting the backend does not also collect the
        # connection: this test is about the registries letting go, and a
        # connection destructed mid-assertion would only add noise.
        connection = ready_store._CONNECTIONS[backend]
        self.addCleanup(connection.close)
        self.assertEqual(before + 1, ready_store.open_store_count())
        del opened, backend
        gc.collect()
        self.assertIsNone(released(), "the backend outlived its facade")
        self.assertEqual(before, ready_store.open_store_count())
        self.assertNotIn(connection, list(ready_store._CONNECTIONS.values()))

    def test_the_registries_are_a_convention_in_this_process_not_a_sandbox(self):
        """Stated as a test so the honest limit is where it can go stale.

        Same-process Python can find anything: these registries are module
        attributes, and so is ``gc.get_referrers``.  What the arrangement buys
        is that no *supported* use of the object this distribution hands out
        reaches the raw database, so an over-grant is a failure here rather
        than an escape in production.  Isolation from code that is already
        running under this account is an operating-system problem, and nothing
        in this file is offered as one.
        """

        opened = self.open()
        backend = ready_store._OWNED[opened]
        self.assertIsInstance(
            ready_store._CONNECTIONS[backend], sqlite3.Connection)


class ANewerSchemaIsRefusedBeforeAnythingIsWritten(StoreCase):
    """A home this build may not open must come out of the attempt untouched.

    The old order refused last: it switched the home to WAL, ran the additive
    schema script over it, read the version and only then declined.  Every one
    of those steps is a write to a database written by a build this one does
    not understand -- a rewritten header, a ``-wal`` beside it, and this
    build's tables created next to a newer build's.  The refusal has to come
    first, and "first" is measured here rather than asserted.
    """

    SENTINEL_TABLE = "future_admissions"

    # Actions an authorizer may allow while this build decides whether it may
    # open a home at all. Everything else -- every CREATE, DROP, INSERT,
    # UPDATE, DELETE, ALTER, TRANSACTION and *every* PRAGMA, including the
    # connection-local ones -- is denied, so an attempt is caught where it
    # happens instead of inferred from a checksum afterwards.
    READ_ONLY_ACTIONS = frozenset({
        sqlite3.SQLITE_OK, sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE,
    })

    def write_a_newer_home(self, version: object | None = None) -> dict:
        """A database this build must refuse, with sentinels a write moves.

        The journal mode is left at SQLite's default on purpose.  A home
        already in WAL grows a ``-wal`` and a ``-shm`` the moment *any*
        connection reads it, so "no sidecar appeared" would be measuring
        SQLite rather than this store.
        """

        recorded = (str(ready_store.SCHEMA_VERSION + 1) if version is None
                    else str(version))
        self.home.mkdir(parents=True, exist_ok=True)
        os.chmod(self.home, 0o700)
        path = store_base.database_path(self.home)
        raw = sqlite3.connect(str(path), isolation_level=None)
        try:
            raw.execute("CREATE TABLE schema_meta ("
                        "key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            raw.execute("INSERT INTO schema_meta VALUES('schema_version', ?)",
                        (recorded,))
            # A table only the newer build knows, holding a row only it wrote.
            # The additive script this build would otherwise run adds its own
            # tables beside these; a migration would rewrite the row.
            raw.execute(f"CREATE TABLE {self.SENTINEL_TABLE} ("
                        "admission_id TEXT PRIMARY KEY, note TEXT NOT NULL)")
            raw.execute(f"INSERT INTO {self.SENTINEL_TABLE} "
                        "VALUES('a-1', 'written by a build from the future')")
        finally:
            raw.close()
        # Already owner-only, so the home hardening this store does on the way
        # in cannot be what changes the mode.
        os.chmod(path, 0o600)
        return self.fingerprint()

    def sidecars(self) -> list[str]:
        """Every ``-wal``/``-shm``/``-journal`` file beside the database."""

        database = store_base.database_path(self.home).name
        return sorted(item.name for item in self.home.iterdir()
                      if item.name.startswith(database)
                      and item.name != database)

    def fingerprint(self) -> dict:
        """Everything about the home that opening it must not change."""

        path = store_base.database_path(self.home)
        status = path.stat()
        raw = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            objects = sorted(tuple(row) for row in raw.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master"))
            rows = sorted(tuple(row) for row in raw.execute(
                f"SELECT * FROM {self.SENTINEL_TABLE}"))
        finally:
            raw.close()
        return {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": status.st_size,
            "mtime_ns": status.st_mtime_ns,
            "mode": status.st_mode & 0o777,
            "objects": objects,
            "sentinel_rows": rows,
            "sidecars": self.sidecars(),
        }

    def refuse(self) -> ready_store.StoreError:
        with self.assertRaises(ready_store.StoreError) as raised:
            ready_store.open_store(self.home)
        return raised.exception

    @contextlib.contextmanager
    def guarded_connect(self, statements: list, denied: list):
        """``sqlite3.connect``, wrapped so every statement is watched.

        The authorizer denies rather than merely records: a mutating statement
        fails at the point of attempt, so it cannot succeed and then be found
        later by comparing checksums.

        Both doors are guarded.  The look that decides whether this build may
        open a home at all is Core's, and the read-write connection is Ready's;
        watching only one of them would leave the other free to run anything.
        """

        real_connect = sqlite3.connect

        def authorizer(action, first, second, database, trigger):
            if action in self.READ_ONLY_ACTIONS:
                return sqlite3.SQLITE_OK
            denied.append((action, first, second))
            return sqlite3.SQLITE_DENY

        def connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            connection.set_authorizer(authorizer)
            return connection

        with mock.patch.object(ready_store.sqlite3, "connect", connect), \
                mock.patch.object(store_open.sqlite3, "connect", connect):
            yield

    @contextlib.contextmanager
    def counted_connections(self, opened: list, looked: list):
        """Record the read-write connections and the read-only looks apart.

        Which of the two was opened is the whole question: a refusal that
        arrives after a read-write connection exists has already let SQLite
        touch a home this build may not use.
        """

        real_connect = sqlite3.connect

        def record(into):
            def connect(*args, **kwargs):
                connection = real_connect(*args, **kwargs)
                into.append(connection)
                return connection

            return connect

        with mock.patch.object(ready_store.sqlite3, "connect", record(opened)), \
                mock.patch.object(store_open.sqlite3, "connect",
                                  record(looked)):
            yield

    def test_a_newer_home_is_refused_and_says_so(self):
        self.write_a_newer_home()
        self.assertIn("newer Admissible", str(self.refuse()))

    def test_the_refusal_changes_nothing_about_the_home(self):
        before = self.write_a_newer_home()
        self.refuse()
        self.assertEqual(before, self.fingerprint())

    def test_the_refusal_creates_no_wal_journal_or_shm(self):
        self.write_a_newer_home()
        self.refuse()
        self.assertEqual([], self.sidecars())

    def test_this_build_s_tables_are_not_created_beside_the_newer_ones(self):
        self.write_a_newer_home()
        self.refuse()
        names = {row[1] for row in self.fingerprint()["objects"]}
        self.assertEqual({"schema_meta", self.SENTINEL_TABLE},
                         {name for name in names
                          if not name.startswith("sqlite_")})

    def test_no_mutating_statement_runs_before_the_refusal(self):
        """Proved at the connection, not inferred from the file afterwards."""

        self.write_a_newer_home()
        statements: list = []
        denied: list = []
        with self.guarded_connect(statements, denied):
            error = self.refuse()
        self.assertIn("newer Admissible", str(error))
        self.assertEqual([], denied)
        self.assertTrue(statements, "the guard saw no statements at all")
        offenders = [item for item in statements
                     if not item.lstrip().upper().startswith("SELECT")]
        self.assertEqual([], offenders)

    def test_no_read_write_connection_is_opened_at_all(self):
        """The refusal happens before there is anything that could write.

        The older order opened the home read-write and refused from inside it,
        which meant SQLite had already been handed a database this build does
        not understand.  Now the only connection made is the immutable look,
        and it is closed before the refusal reaches the caller.
        """

        self.write_a_newer_home()
        opened: list = []
        looked: list = []
        before = ready_store.open_store_count()
        with self.counted_connections(opened, looked):
            self.refuse()
        self.assertEqual([], opened, "a read-write connection was opened")
        self.assertEqual(1, len(looked))
        with self.assertRaises(sqlite3.ProgrammingError):
            looked[0].execute("SELECT 1")
        self.assertEqual(before, ready_store.open_store_count())

    def test_an_unreadable_version_is_refused_without_any_ddl(self):
        """Fail closed: a version that is not a number identifies no layout."""

        for recorded in ("", "  ", "six", "6.0", "0x7", "v7"):
            with self.subTest(recorded=recorded):
                self.home = Path(self.scratch())
                before = self.write_a_newer_home(version=recorded)
                statements: list = []
                denied: list = []
                with self.guarded_connect(statements, denied):
                    error = self.refuse()
                self.assertIn("not a version number", str(error))
                self.assertEqual([], denied)
                self.assertEqual(before, self.fingerprint())

    def test_a_home_at_this_version_still_opens(self):
        """The control: the guard refuses the future, not the present."""

        self.write_a_newer_home(version=ready_store.SCHEMA_VERSION)
        opened = self.open()
        self.assertEqual(ready_store.SCHEMA_VERSION, opened.schema_version)
        self.assertIn("evidence", self.tables())

    def test_a_fresh_home_is_still_created(self):
        missing = Path(self.scratch()) / "fresh"
        opened = ready_store.open_store(missing)
        self.addCleanup(opened.close)
        self.assertEqual(ready_store.SCHEMA_VERSION, opened.schema_version)


# -- the cross-process open protocol -----------------------------------------
# Holds the schema lock for one home, says so by creating ``held``, waits for
# ``release``, and only then creates the database and installs a schema this
# build must refuse. Nothing here imports Ready: it stands in for any process
# -- a newer Ready, the Trust distribution -- that takes the same lock.
_INSTALLER = """
import os, sqlite3, sys, time
from admissible_core.store_open import schema_lock

home, held, release, version = sys.argv[1:5]
database = os.path.join(home, "admissible.sqlite3")
with schema_lock(database, timeout_ms=120000):
    with open(held, "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))
    while not os.path.exists(release):
        time.sleep(0.01)
    descriptor = os.open(database, os.O_CREAT | os.O_RDWR | os.O_EXCL, 0o600)
    os.close(descriptor)
    raw = sqlite3.connect(database, isolation_level=None)
    try:
        raw.execute("CREATE TABLE schema_meta ("
                    "key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        raw.execute("INSERT INTO schema_meta VALUES('schema_version', ?)",
                    (version,))
        raw.execute("CREATE TABLE future_admissions ("
                    "admission_id TEXT PRIMARY KEY, note TEXT NOT NULL)")
        raw.execute("INSERT INTO future_admissions VALUES('a-1', 'future')")
    finally:
        raw.close()
print("installed")
"""

# One real Ready opener, reporting what it got. The lock timeout is set from
# the command line so the same program can either wait for the other process
# or refuse to.
_OPENER = """
import json, sys, time
from admissible_ready import store as ready_store

home, timeout = sys.argv[1], int(sys.argv[2])
ready_store.SCHEMA_LOCK_TIMEOUT_MS = timeout
started = time.monotonic()
try:
    opened = ready_store.open_store(home)
except ready_store.StoreError as error:
    print(json.dumps({"opened": False, "error": str(error),
                      "waited": time.monotonic() - started}))
else:
    version = opened.schema_version
    opened.close()
    print(json.dumps({"opened": True, "schema_version": version,
                      "waited": time.monotonic() - started}))
"""


class MultiprocessCase(StoreCase):
    """Real processes, because an in-process lock proves nothing about them."""

    def environment(self) -> dict[str, str]:
        found = {key: value for key, value in os.environ.items()
                 if key not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")}
        found["PYTHONPATH"] = os.pathsep.join(
            str(entry) for entry in (REPO_ROOT, CORE_SRC, READY_SRC))
        found["PYTHONDONTWRITEBYTECODE"] = "1"
        return found

    def start(self, program: str, *arguments: str) -> subprocess.Popen:
        process = subprocess.Popen(
            [sys.executable, "-c", program, *arguments],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(REPO_ROOT), env=self.environment())
        self.addCleanup(self.reap, process)
        return process

    def reap(self, process: subprocess.Popen) -> None:
        if process.poll() is None:  # pragma: no cover - cleanup path
            process.kill()
        process.communicate()

    def answer(self, process: subprocess.Popen) -> dict:
        stdout, stderr = process.communicate(timeout=120)
        self.assertEqual(0, process.returncode, stderr)
        return json.loads(stdout)

    def await_file(self, path: Path, *, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        while not path.exists():
            if time.monotonic() >= deadline:  # pragma: no cover - diagnostic
                self.fail(f"{path} never appeared")
            time.sleep(0.01)

    def markers(self) -> tuple[Path, Path]:
        scratch = Path(self.scratch())
        return scratch / "held", scratch / "release"


class TwoOpenersCannotRaceOneHome(MultiprocessCase):
    """The window the lock closes, measured with the window held open.

    ``exists()``, ``O_EXCL``, "read the version", "install the schema" is four
    steps over a file two processes can both reach.  Without a lock spanning
    all four, one opener finds no file, another creates it, and the first then
    runs its own initialisation over a database somebody else is still
    writing -- or refuses a version that was not yet recorded when it looked.

    So the process below takes the lock *before* the file exists and installs a
    newer schema under it, and a real Ready opener races it.  The opener must
    wait, and what it must then see is the finished newer home rather than the
    half-built one.
    """

    def database(self) -> Path:
        return store_base.database_path(self.home)

    def objects(self) -> set[str]:
        with sqlite3.connect(
                f"file:{self.database()}?mode=ro&immutable=1", uri=True) as raw:
            return {row[0] for row in raw.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'")}

    def test_an_opener_blocks_while_another_process_holds_the_lock(self):
        held, release = self.markers()
        installer = self.start(_INSTALLER, str(self.home), str(held),
                               str(release),
                               str(ready_store.SCHEMA_VERSION + 1))
        self.await_file(held)
        opener = self.start(_OPENER, str(self.home), "120000")
        time.sleep(0.5)
        self.assertIsNone(opener.poll(), "the opener did not wait for the lock")
        self.assertFalse(self.database().exists(),
                         "the database appeared while the lock was held")
        release.write_text("go", encoding="utf-8")
        installer.communicate(timeout=120)
        answer = self.answer(opener)
        self.assertFalse(answer["opened"], "a newer home was opened")
        self.assertIn("newer Admissible", answer["error"])
        self.assertGreater(answer["waited"], 0.4)

    def test_no_ready_table_is_installed_across_the_lock(self):
        held, release = self.markers()
        installer = self.start(_INSTALLER, str(self.home), str(held),
                               str(release),
                               str(ready_store.SCHEMA_VERSION + 1))
        self.await_file(held)
        opener = self.start(_OPENER, str(self.home), "120000")
        time.sleep(0.5)
        release.write_text("go", encoding="utf-8")
        installer.communicate(timeout=120)
        self.answer(opener)
        self.assertEqual({"schema_meta", "future_admissions"}, self.objects())
        self.assertEqual([], sorted(
            item.name for item in self.home.iterdir()
            if item.name != self.database().name))

    def test_an_opener_that_will_not_wait_creates_no_file_at_all(self):
        """The lock is taken before the existence check, not after it."""

        held, release = self.markers()
        installer = self.start(_INSTALLER, str(self.home), str(held),
                               str(release), str(ready_store.SCHEMA_VERSION))
        self.await_file(held)
        opener = self.start(_OPENER, str(self.home), "200")
        answer = self.answer(opener)
        release.write_text("go", encoding="utf-8")
        installer.communicate(timeout=120)
        self.assertFalse(answer["opened"])
        self.assertIn("schema lock", answer["error"])
        self.assertIn(str(store_open.schema_lock_path(self.database())),
                      answer["error"])

    def test_a_waiting_opener_takes_the_home_the_moment_it_is_free(self):
        """The control: the lock delays an opener, it does not break one."""

        held, release = self.markers()
        holder = self.start(_INSTALLER, str(self.home), str(held),
                            str(release), str(ready_store.SCHEMA_VERSION))
        self.await_file(held)
        opener = self.start(_OPENER, str(self.home), "120000")
        time.sleep(0.4)
        self.assertIsNone(opener.poll())
        release.write_text("go", encoding="utf-8")
        holder.communicate(timeout=120)
        answer = self.answer(opener)
        self.assertTrue(answer["opened"], answer.get("error"))
        self.assertEqual(ready_store.SCHEMA_VERSION, answer["schema_version"])
        self.assertIn("evidence", self.objects())


class TheLastLookIsTakenThroughTheWritingConnection(StoreCase):
    """What protects a home from a process that never took the lock.

    The immutable look and the lock together settle every *cooperating*
    opener.  Neither says anything about a hand-run ``sqlite3``, or a build
    from the future that predates this protocol: such a process can record a
    version in the interval between the look and the read-write connection,
    and an opener that trusted the earlier answer would then run its schema
    script over a layout it had already been told it may not touch.

    So the version is read once more on the connection that would do the
    writing, before the first pragma.  That is what is measured here, by
    changing the version in exactly that interval.
    """

    def setUp(self) -> None:
        super().setUp()
        # The stand-in for another process, captured before any guard replaces
        # ``sqlite3.connect`` on the shared module: a writer that took neither
        # the lock nor this process's authorizer is the whole scenario.
        self.outside_connect = sqlite3.connect

    def write_at(self, path: Path, version: object) -> None:
        connection = self.outside_connect(str(path), isolation_level=None)
        try:
            connection.execute("UPDATE schema_meta SET value=? WHERE key=?",
                               (str(version), "schema_version"))
        finally:
            connection.close()

    def seed(self) -> Path:
        """A home this build made, so only its recorded version is in doubt."""

        opened = ready_store.open_store(self.home)
        opened.close()
        return store_base.database_path(self.home)

    def changing_look(self, path: Path, version: object):
        """The look, followed by a writer that never took the schema lock."""

        real_look = ready_store.refuse_a_layout_this_build_cannot_open

        def look(database, *, supported):
            answer = real_look(database, supported=supported)
            self.write_at(path, version)
            return answer

        return mock.patch.object(
            ready_store, "refuse_a_layout_this_build_cannot_open", look)

    def refuse_after_a_non_cooperating_change(self, version: object,
                                              *guards):
        """Open a home that somebody rewrites the moment the look is over."""

        path = self.seed()
        with contextlib.ExitStack() as stack:
            stack.enter_context(self.changing_look(path, version))
            for guard in guards:
                stack.enter_context(guard)
            with self.assertRaises(ready_store.StoreError) as raised:
                ready_store.open_store(self.home)
        return raised.exception

    def watched_read_write_connect(self, statements: list, denied: list):
        """Ready's own ``connect``, under an authorizer that denies writes.

        Only the read-write door: the look is Core's and has its own suite.
        A pragma, a ``CREATE TABLE IF NOT EXISTS`` or a migration would be
        denied here at the moment it was attempted.
        """

        real_connect = sqlite3.connect
        allowed = frozenset({
            sqlite3.SQLITE_OK, sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
            sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE,
        })

        def authorizer(action, first, second, database, trigger):
            if action in allowed:
                return sqlite3.SQLITE_OK
            denied.append((action, first, second))
            return sqlite3.SQLITE_DENY

        def connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            connection.set_authorizer(authorizer)
            return connection

        return mock.patch.object(ready_store.sqlite3, "connect", connect)

    def test_a_version_raised_after_the_look_is_still_refused(self):
        error = self.refuse_after_a_non_cooperating_change(
            ready_store.SCHEMA_VERSION + 1)
        self.assertIn("newer Admissible", str(error))

    def test_a_version_made_unreadable_after_the_look_is_still_refused(self):
        error = self.refuse_after_a_non_cooperating_change("tomorrow")
        self.assertIn("not a version number", str(error))

    def test_the_refusal_leaves_no_store_open(self):
        before = ready_store.open_store_count()
        self.refuse_after_a_non_cooperating_change(
            ready_store.SCHEMA_VERSION + 1)
        self.assertEqual(before, ready_store.open_store_count())

    def test_no_statement_but_a_select_reaches_the_writing_connection(self):
        """Where the second look has to be: before the first pragma.

        A refusal that arrives after the pragmas and the schema script has
        already configured and written to a layout it then declines -- which
        is the whole difference between refusing and apologising.
        """

        statements: list = []
        denied: list = []
        error = self.refuse_after_a_non_cooperating_change(
            ready_store.SCHEMA_VERSION + 1,
            self.watched_read_write_connect(statements, denied))
        self.assertIn("newer Admissible", str(error))
        self.assertEqual([], denied)
        self.assertTrue(statements, "the guard saw no statements at all")
        offenders = [item for item in statements
                     if not item.lstrip().upper().startswith("SELECT")]
        self.assertEqual([], offenders)

    def test_the_recorded_version_is_left_where_the_other_writer_put_it(self):
        """Nothing drags a version this build does not understand back down."""

        self.refuse_after_a_non_cooperating_change(
            ready_store.SCHEMA_VERSION + 1)
        with self.raw(store_base.database_path(self.home)) as raw:
            recorded = raw.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()[0]
        self.assertEqual(str(ready_store.SCHEMA_VERSION + 1), recorded)


class AnActiveOrUncleanHomeIsRefusedUntouched(StoreCase):
    """A home with a sidecar beside it is not read, not opened, not recovered.

    A ``-wal`` or a hot ``-journal`` says the same two things at once: another
    process may be writing this database right now, and its current contents
    are not in the main file.  Reading it honestly means replaying the journal
    or the log, and both are *writes* -- to a home this build has not yet
    decided it may use, and possibly one a newer build owns.

    So the answer is to stop before touching anything.  That is a refusal, and
    a live writer therefore locks every other process out until it closes: a
    denial of service rather than a wrong answer, which is the trade this
    kernel makes wherever it cannot be sure.
    """

    SENTINEL_TABLE = "future_admissions"

    def sidecar_names(self) -> list[str]:
        database = store_base.database_path(self.home).name
        return sorted(item.name for item in self.home.iterdir()
                      if item.name.startswith(database)
                      and item.name != database)

    def fingerprint(self) -> dict:
        found = {}
        for item in sorted(self.home.iterdir()):
            status = item.stat()
            found[item.name] = (
                hashlib.sha256(item.read_bytes()).hexdigest(),
                status.st_size, status.st_mtime_ns,
                status.st_mode & 0o777)
        return found

    def seed(self, *, journal_mode: str, version: int) -> sqlite3.Connection:
        """A database of the given journal mode, with an open writer on it."""

        self.home.mkdir(parents=True, exist_ok=True)
        os.chmod(self.home, 0o700)
        path = store_base.database_path(self.home)
        raw = sqlite3.connect(str(path), isolation_level=None)
        self.addCleanup(raw.close)
        raw.execute(f"PRAGMA journal_mode={journal_mode}")
        raw.execute("CREATE TABLE schema_meta ("
                    "key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        raw.execute("INSERT INTO schema_meta VALUES('schema_version', ?)",
                    (str(version),))
        raw.execute(f"CREATE TABLE {self.SENTINEL_TABLE} ("
                    "admission_id TEXT PRIMARY KEY, note TEXT NOT NULL)")
        raw.execute(f"INSERT INTO {self.SENTINEL_TABLE} "
                    "VALUES('a-1', 'written by a build from the future')")
        os.chmod(path, 0o600)
        # An open write transaction, so the sidecar is not a leftover: it holds
        # content the main file does not have, exactly as a live writer's does.
        raw.execute("BEGIN IMMEDIATE")
        raw.execute(f"INSERT INTO {self.SENTINEL_TABLE} "
                    "VALUES('a-2', 'uncommitted')")
        return raw

    def refuse(self) -> ready_store.StoreError:
        with self.assertRaises(ready_store.StoreError) as raised:
            ready_store.open_store(self.home)
        return raised.exception

    def test_a_newer_wal_home_with_a_live_writer_is_refused(self):
        self.seed(journal_mode="WAL",
                  version=ready_store.SCHEMA_VERSION + 1)
        self.assertEqual(
            ["admissible.sqlite3-shm", "admissible.sqlite3-wal"],
            self.sidecar_names())
        message = str(self.refuse())
        self.assertIn("-wal", message)

    def test_refusing_it_leaves_every_file_byte_for_byte(self):
        self.seed(journal_mode="WAL",
                  version=ready_store.SCHEMA_VERSION + 1)
        before = self.fingerprint()
        self.refuse()
        self.assertEqual(before, self.fingerprint())

    def test_refusing_it_creates_no_new_file(self):
        self.seed(journal_mode="WAL",
                  version=ready_store.SCHEMA_VERSION + 1)
        before = sorted(item.name for item in self.home.iterdir())
        self.refuse()
        self.assertEqual(before,
                         sorted(item.name for item in self.home.iterdir()))

    def test_nothing_opens_the_database_at_all(self):
        self.seed(journal_mode="WAL",
                  version=ready_store.SCHEMA_VERSION + 1)
        opened: list = []
        real_connect = sqlite3.connect

        def connect(*args, **kwargs):  # pragma: no cover - must not run
            connection = real_connect(*args, **kwargs)
            opened.append(connection)
            return connection

        with mock.patch.object(ready_store.sqlite3, "connect", connect), \
                mock.patch.object(store_open.sqlite3, "connect", connect):
            self.refuse()
        self.assertEqual([], opened)

    def test_a_newer_home_with_a_hot_rollback_journal_is_refused(self):
        self.seed(journal_mode="DELETE",
                  version=ready_store.SCHEMA_VERSION + 1)
        self.assertEqual(["admissible.sqlite3-journal"], self.sidecar_names())
        before = self.fingerprint()
        message = str(self.refuse())
        self.assertIn("-journal", message)
        self.assertEqual(before, self.fingerprint())

    def test_a_home_at_this_version_is_refused_while_it_is_active(self):
        """Fail closed does not ask whose build wrote it: an open store is open.

        This is the denial of service the module documents. A second Ready
        process cannot join a home the first one still holds; it is told to
        wait for the owner rather than given a partial view of it.
        """

        self.seed(journal_mode="WAL", version=ready_store.SCHEMA_VERSION)
        message = str(self.refuse())
        self.assertIn("-wal", message)
        self.assertIn("another process", message)

    def test_the_same_home_opens_once_the_writer_lets_go(self):
        """The control: the refusal is about the sidecar, not about the home."""

        raw = self.seed(journal_mode="WAL",
                        version=ready_store.SCHEMA_VERSION)
        self.refuse()
        raw.execute("ROLLBACK")
        raw.close()
        self.assertEqual([], self.sidecar_names())
        opened = ready_store.open_store(self.home)
        self.addCleanup(opened.close)
        self.assertEqual(ready_store.SCHEMA_VERSION, opened.schema_version)
