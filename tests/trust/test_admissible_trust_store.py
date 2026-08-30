"""Contract: Trust's store is a real backend whose authority is enumerated.

The split leaves one durable home shared by both authorities.  Core owns its
vocabulary and the capability-facade machinery; each distribution owns the
schema it creates and the methods it implements.  Four things have to be true
at once, and they are four different claims:

* the backend **works** -- it creates exactly the schema the monolith creates,
  migrates an older home in place without losing a row, anchors heads, issues
  receipt rows, files defects and records policy trust;
* the schema it writes is **byte-identical** to the one Ready writes, because
  the two open the same file and a home whose layout depends on which
  distribution touched it first is not one home;
* the facade **grants exactly** the enumerated authority set -- and in
  particular grants no ``connection``, no ``transact`` and no way to run SQL,
  so every append-only trigger in the schema is a wall rather than advice;
* the refusals happen **before** anything is written: a home with a live
  sidecar, or one a newer Admissible wrote, is refused without a pragma, a
  ``CREATE TABLE IF NOT EXISTS`` or a migration having run over it.

A v0.7 home is exercised end to end.  The monolith writes it, this backend
opens it, and every row the monolith recorded is still there afterwards --
because "do not reset or rewrite the local store" is a compatibility promise
and not a plan.  The coexistence case is the one the split makes new: Ready
writes candidate rows into a home, Trust opens the same file, and each reads
the other's rows without either rewriting them.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import pickle
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from admissible import store as legacy_store

from admissible_core import store_base, store_open

from admissible_trust import receipt as trust_receipt
from admissible_trust import store as trust_store

from . import REPO_ROOT

# The names ``admissible_trust.store`` promises, and the whole of them. Pinned
# rather than sampled: the escape this suite exists to forbid is a backend
# class or a connection constructor arriving in the module's public surface,
# and a subset check would not notice one being added.
EXPECTED_EXPORTS = frozenset({
    "DEFAULT_BUSY_TIMEOUT_MS",
    "HeadConflict",
    "JOURNAL_EXPORT_SCHEMA",
    "MAX_JOURNAL_BYTES",
    "SCHEMA_LOCK_TIMEOUT_MS",
    "SCHEMA_VERSION",
    "StoreError",
    "TrustStore",
    "default_home",
    "open_store",
    "open_store_count",
    "require_durable_home",
    "require_home_outside",
})

# Names a caller reaching for the raw database would try first.
BACKEND_PROBES = (
    "_connection", "connection", "conn", "_conn", "_db", "db", "sqlite",
    "_sqlite", "_backend", "backend", "_store", "store", "raw", "_raw",
    "_cursor", "cursor", "__dict__",
    "_TrustStore__connection", "_TrustStoreBackend__connection",
    "_CapabilityFacade__backend",
)

# The unrestricted escapes: any one of them is every withheld capability at
# once, because a caller holding it can drop a trigger and write a receipt row
# by hand.
FORBIDDEN_CAPABILITIES = ("connection", "transact", "execute", "executescript",
                          "cursor", "executemany")

SHA = "a" * 40
TREE = "b" * 40
REPOSITORY = "github.com/acme/widget"


def is_a_connection(value: object) -> bool:
    return isinstance(value, sqlite3.Connection) or value is sqlite3.Connection


class StoreCase(unittest.TestCase):
    def setUp(self) -> None:
        raw = tempfile.mkdtemp(prefix="trust-store-")
        self.addCleanup(shutil.rmtree, raw, True)
        self.root = Path(raw)
        self.home = self.root / "home"

    def opened(self, home: Path | None = None):
        store = trust_store.open_store(self.home if home is None else home)
        self.addCleanup(store.close)
        return store

    def objects(self, path: Path) -> dict[str, str]:
        connection = sqlite3.connect(str(path))
        try:
            return {row[0]: (row[1] or "") for row in connection.execute(
                "SELECT name, sql FROM sqlite_master ORDER BY name")}
        finally:
            connection.close()


class SchemaParity(StoreCase):
    """One home, one layout, whichever distribution created it."""

    def test_the_schema_version_is_the_monolith_s(self):
        self.assertEqual(legacy_store.SCHEMA_VERSION,
                         trust_store.SCHEMA_VERSION)

    def test_a_fresh_home_has_the_same_objects_as_the_monolith_s(self):
        self.opened().close()
        legacy_home = self.root / "legacy"
        legacy = legacy_store.open_store(legacy_home)
        legacy.close()
        self.assertEqual(
            self.objects(store_base.database_path(legacy_home)),
            self.objects(store_base.database_path(self.home)))

    def test_the_schema_sql_is_the_same_text_ready_would_write(self):
        """Not merely equivalent: the same statements, in the same order.

        The two distributions create the same file. A ``CREATE TABLE`` that
        differed by a column order or a trigger body would give a home whose
        layout depends on which authority reached it first.
        """

        ready_source = (REPO_ROOT / "packages" / "ready" / "src"
                        / "admissible_ready" / "store.py").read_text(
                            encoding="utf-8")
        trust_source = (REPO_ROOT / "packages" / "trust" / "src"
                        / "admissible_trust" / "store.py").read_text(
                            encoding="utf-8")

        def statements(source: str) -> list[str]:
            body = source.split('_SCHEMA = """', 1)[1].split('"""', 1)[0]
            stripped = "\n".join(
                line for line in body.splitlines()
                if not line.strip().startswith("--"))
            return [" ".join(part.split())
                    for part in stripped.split(";") if part.strip()]

        self.assertEqual(statements(ready_source), statements(trust_source))

    def test_the_database_and_home_are_owner_only(self):
        opened = self.opened()
        self.assertEqual(0o700, os.stat(self.home).st_mode & 0o777)
        self.assertEqual(
            0o600, os.stat(store_base.database_path(self.home)).st_mode & 0o777)
        opened.close()

    def test_the_connection_is_configured_the_way_the_monolith_configures_it(self):
        # Read off the backend, because reading a pragma is not one of the
        # capabilities the facade grants: the facade's job is authority, and
        # "which journal mode is this" is a fact about the file.
        backend = store_base._backend_of(self.opened())
        self.assertEqual("wal", str(backend.pragma("journal_mode")).lower())
        self.assertEqual(1, backend.pragma("foreign_keys"))
        self.assertEqual(2, backend.pragma("synchronous"))

    def test_a_newer_schema_is_refused_rather_than_downgraded(self):
        self.opened().close()
        connection = sqlite3.connect(str(store_base.database_path(self.home)))
        connection.execute("UPDATE schema_meta SET value=? WHERE key=?",
                           (str(trust_store.SCHEMA_VERSION + 1),
                            store_base.SCHEMA_VERSION_KEY))
        connection.commit()
        connection.close()
        with self.assertRaises(trust_store.StoreError):
            trust_store.open_store(self.home)


class TheReachableSurface(StoreCase):
    """What the facade grants, stated as an equality and as an absence."""

    def test_the_declared_exports_are_exactly_the_promised_names(self):
        self.assertEqual(EXPECTED_EXPORTS, set(trust_store.__all__))

    def test_the_backend_class_is_not_a_public_module_attribute(self):
        public = [name for name in dir(trust_store)
                  if not name.startswith("_")]
        for name in public:
            with self.subTest(name=name):
                value = getattr(trust_store, name)
                self.assertFalse(
                    isinstance(value, type)
                    and name.endswith("Backend"),
                    f"{name} exposes the backend")

    def test_no_public_module_attribute_is_or_makes_a_connection(self):
        for name in dir(trust_store):
            if name.startswith("_"):
                continue
            with self.subTest(name=name):
                self.assertFalse(is_a_connection(getattr(trust_store, name)))

    def test_the_facade_grants_the_enumerated_authority_and_no_more(self):
        opened = self.opened()
        self.assertEqual(trust_store.TRUST_CAPABILITIES,
                         type(opened).CAPABILITIES)

    def test_every_granted_capability_is_reachable(self):
        opened = self.opened()
        for name in sorted(type(opened).CAPABILITIES):
            with self.subTest(capability=name):
                self.assertIsNotNone(getattr(opened, name))

    def test_no_unrestricted_sql_escape_is_granted(self):
        opened = self.opened()
        for name in FORBIDDEN_CAPABILITIES:
            with self.subTest(capability=name):
                self.assertNotIn(name, type(opened).CAPABILITIES)
                with self.assertRaises(store_base.CapabilityError):
                    getattr(opened, name)

    def test_the_backend_implements_no_unrestricted_sql_escape_either(self):
        """Not "refused": absent, so reaching past the facade finds nothing."""

        opened = self.opened()
        backend = store_base._backend_of(opened)
        for name in FORBIDDEN_CAPABILITIES:
            with self.subTest(capability=name):
                self.assertFalse(hasattr(backend, name),
                                 f"the backend still implements {name}")

    def test_the_monolith_backend_did_implement_them(self):
        """The control: these names are real, and were reachable before."""

        legacy = legacy_store.open_store(self.root / "legacy")
        try:
            self.assertTrue(hasattr(legacy, "connection"))
            self.assertTrue(hasattr(legacy, "transact"))
        finally:
            legacy.close()

    def test_no_obvious_name_answers_with_a_connection_or_the_backend(self):
        opened = self.opened()
        backend = store_base._backend_of(opened)
        for probe in BACKEND_PROBES:
            for holder, label in ((opened, "facade"), (backend, "backend")):
                with self.subTest(probe=probe, holder=label):
                    value = getattr(holder, probe, None)
                    self.assertFalse(is_a_connection(value))
                    self.assertIsNot(value, backend)

    def test_the_facade_cannot_be_pickled_or_copied(self):
        opened = self.opened()
        with self.assertRaises(store_base.CapabilityError):
            pickle.dumps(opened)
        with self.assertRaises(store_base.CapabilityError):
            copy.copy(opened)

    def test_a_granted_method_is_not_the_backend_s_bound_method(self):
        opened = self.opened()
        granted = opened.trust_policy
        self.assertIs(opened, getattr(granted, "__self__", None))

    def test_the_open_count_tracks_what_was_opened_and_closed(self):
        before = trust_store.open_store_count()
        opened = trust_store.open_store(self.home)
        self.assertEqual(before + 1, trust_store.open_store_count())
        opened.close()
        self.assertEqual(before, trust_store.open_store_count())

    def test_it_works_as_a_context_manager(self):
        with trust_store.open_store(self.home) as opened:
            self.assertEqual(trust_store.SCHEMA_VERSION, opened.schema_version)


class PolicyAuthority(StoreCase):
    """Trusting and revoking a policy: the writes Ready does not have."""

    def test_a_trusted_policy_becomes_enforceable(self):
        opened = self.opened()
        self.assertTrue(opened.trust_policy(
            repository=REPOSITORY, class_id="default",
            policy_digest="c" * 64, enforcement_digest="d" * 64,
            trusted_at=1))
        rows = opened.trusted_policies(REPOSITORY, "default")
        self.assertEqual(["c" * 64], [row["policy_digest"] for row in rows])

    def test_a_revocation_withdraws_authority_without_deleting_history(self):
        opened = self.opened()
        opened.trust_policy(repository=REPOSITORY, class_id="default",
                            policy_digest="c" * 64,
                            enforcement_digest="d" * 64, trusted_at=1)
        self.assertTrue(opened.revoke_policy(
            repository=REPOSITORY, class_id="default",
            policy_digest="c" * 64, revoked_at=2))
        self.assertEqual((), opened.trusted_policies(REPOSITORY, "default"))
        self.assertEqual(
            1, len(opened.trusted_policies(REPOSITORY, "default",
                                           include_superseded=True)))

    def test_a_tightened_policy_opens_the_next_generation(self):
        opened = self.opened()
        opened.trust_policy(repository=REPOSITORY, class_id="default",
                            policy_digest="c" * 64,
                            enforcement_digest="d" * 64, trusted_at=1)
        opened.trust_policy(repository=REPOSITORY, class_id="default",
                            policy_digest="e" * 64,
                            enforcement_digest="f" * 64, trusted_at=2)
        self.assertEqual(2, opened.policy_generation(REPOSITORY, "default"))
        self.assertEqual(
            ["e" * 64],
            [row["policy_digest"]
             for row in opened.trusted_policies(REPOSITORY, "default")])

    def test_the_baseline_matches_the_monolith_s(self):
        opened = self.opened()
        legacy_home = self.root / "legacy"
        legacy = legacy_store.open_store(legacy_home)
        try:
            for store in (opened, legacy):
                store.trust_policy(
                    repository=REPOSITORY, class_id="default",
                    policy_digest="c" * 64, enforcement_digest="d" * 64,
                    trusted_at=1)
                store.trust_policy(
                    repository=REPOSITORY, class_id="default",
                    policy_digest="e" * 64, enforcement_digest="f" * 64,
                    trusted_at=2)
                store.revoke_policy(
                    repository=REPOSITORY, class_id="default",
                    policy_digest="e" * 64, revoked_at=3)
            self.assertEqual(
                [dict(row) for row in
                 legacy.trusted_policies(REPOSITORY, "default",
                                         include_superseded=True)],
                [dict(row) for row in
                 opened.trusted_policies(REPOSITORY, "default",
                                         include_superseded=True)])
        finally:
            legacy.close()


class HeadsAndReceipts(StoreCase):
    """Anchoring, issuance and read-back, against the monolith's answers."""

    def signer(self):
        return trust_receipt.signer_from_secret("test", b"secret-material")

    def test_a_head_is_accepted_and_read_back(self):
        opened = self.opened()
        signer = self.signer()
        journal_id = trust_receipt.journal_id_for(REPOSITORY)
        event = {"domain": trust_receipt.RECEIPT_DOMAIN, "type": "probe"}
        head = trust_receipt.anchor_event(opened, journal_id, event,
                                          signer=signer, now=10)
        current = opened.current_head(journal_id)
        self.assertEqual(head.receipt_hash, current.receipt_hash)
        self.assertTrue(opened.verify_journal(journal_id, signer))

    def test_a_journal_that_does_not_verify_is_refused(self):
        opened = self.opened()
        journal_id = trust_receipt.journal_id_for(REPOSITORY)
        trust_receipt.anchor_event(
            opened, journal_id, {"domain": trust_receipt.RECEIPT_DOMAIN,
                                 "type": "probe"},
            signer=self.signer(), now=10)
        other = trust_receipt.signer_from_secret("test", b"a-different-secret")
        with self.assertRaises(trust_store.StoreError):
            opened.verify_journal(journal_id, other)

    def test_an_unextending_head_is_a_conflict(self):
        opened = self.opened()
        signer = self.signer()
        journal_id = trust_receipt.journal_id_for(REPOSITORY)
        first = trust_receipt.propose_next(
            opened, journal_id,
            {"domain": trust_receipt.RECEIPT_DOMAIN, "type": "one"},
            signer=signer, now=10)
        second = trust_receipt.propose_next(
            opened, journal_id,
            {"domain": trust_receipt.RECEIPT_DOMAIN, "type": "two"},
            signer=signer, now=10)
        opened.accept_head(first.head_receipt, first.events, signer)
        with self.assertRaises(trust_store.HeadConflict):
            opened.accept_head(second.head_receipt, second.events, signer)

    def test_head_and_attachment_land_in_one_transaction(self):
        """A failing attachment builder leaves no head behind."""

        opened = self.opened()
        signer = self.signer()
        journal_id = trust_receipt.journal_id_for(REPOSITORY)
        proposal = trust_receipt.propose_next(
            opened, journal_id,
            {"domain": trust_receipt.RECEIPT_DOMAIN, "type": "one"},
            signer=signer, now=10)

        def explode():
            raise ValueError("the attachment refused")

        with self.assertRaises(ValueError):
            opened.accept_head(proposal.head_receipt, proposal.events, signer,
                               attachments_builder=explode)
        self.assertIsNone(opened.current_head(journal_id))
        self.assertEqual((), opened.journal_events(journal_id))


class ExistingHomesSurvive(StoreCase):
    """A v0.7 home opens here without a destructive rewrite."""

    def write_legacy_home(self) -> dict:
        """One monolith-written home with rows in every trusted table."""

        legacy = legacy_store.open_store(self.home)
        signer = trust_receipt.signer_from_secret("test", b"secret-material")
        try:
            legacy.trust_policy(
                repository=REPOSITORY, class_id="default",
                policy_digest="c" * 64, enforcement_digest="d" * 64,
                trusted_at=1)
            journal_id = trust_receipt.journal_id_for(REPOSITORY)
            head = legacy.accept_head(
                *self.legacy_proposal(legacy, journal_id, signer), signer)
            return {"journal_id": journal_id,
                    "head": head.receipt_hash,
                    "digest": hashlib.sha256(
                        store_base.database_path(self.home).read_bytes()
                    ).hexdigest()}
        finally:
            legacy.close()

    @staticmethod
    def legacy_proposal(store, journal_id, signer):
        from admissible import receipt as legacy_receipt

        proposal = legacy_receipt.propose_next(
            store, journal_id,
            {"domain": legacy_receipt.RECEIPT_DOMAIN, "type": "probe"},
            signer=signer, now=10)
        return proposal.head_receipt, proposal.events

    def test_the_split_reads_a_home_the_monolith_wrote(self):
        written = self.write_legacy_home()
        opened = self.opened()
        self.assertEqual(trust_store.SCHEMA_VERSION, opened.schema_version)
        self.assertEqual(
            ["c" * 64],
            [row["policy_digest"]
             for row in opened.trusted_policies(REPOSITORY, "default")])
        self.assertEqual(written["head"],
                         opened.current_head(written["journal_id"]).receipt_hash)

    def test_the_monolith_still_reads_what_the_split_wrote(self):
        self.write_legacy_home()
        opened = self.opened()
        opened.trust_policy(repository=REPOSITORY, class_id="second",
                            policy_digest="1" * 64,
                            enforcement_digest="2" * 64, trusted_at=5)
        opened.close()
        legacy = legacy_store.open_store(self.home)
        try:
            self.assertEqual(
                ["1" * 64],
                [row["policy_digest"]
                 for row in legacy.trusted_policies(REPOSITORY, "second")])
        finally:
            legacy.close()

    def test_opening_it_here_destroys_nothing(self):
        written = self.write_legacy_home()
        objects_before = self.objects(store_base.database_path(self.home))
        self.opened().close()
        self.assertEqual(objects_before,
                         self.objects(store_base.database_path(self.home)))
        self.assertNotEqual("", written["digest"])

    def test_a_schema_four_home_migrates_in_place_without_losing_a_policy(self):
        """The generation column cannot be ALTERed in, so the table is rebuilt.

        Every existing row lands in generation 1: whatever the home already
        trusted stays trusted. Nothing is deleted, and the version bump and the
        rebuild are one transaction. This is the same migration Ready runs, on
        the same file, and it must produce the same result whichever authority
        opens the home first.
        """

        self.home.mkdir(parents=True, exist_ok=True)
        path = store_base.database_path(self.home)
        connection = sqlite3.connect(str(path))
        try:
            connection.execute("CREATE TABLE schema_meta ("
                               "key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute(
                "INSERT INTO schema_meta VALUES('schema_version','4')")
            connection.execute("""
                CREATE TABLE trusted_policies (
                    repository         TEXT NOT NULL,
                    class_id           TEXT NOT NULL,
                    policy_digest      TEXT NOT NULL,
                    enforcement_digest TEXT NOT NULL,
                    trusted_at         INTEGER NOT NULL,
                    PRIMARY KEY (repository, class_id, policy_digest))""")
            connection.execute(
                "INSERT INTO trusted_policies VALUES(?,?,?,?,?)",
                (REPOSITORY, "default", "c" * 64, "e" * 64, 1))
            connection.commit()
        finally:
            connection.close()
        opened = self.opened()
        self.assertNotIn("trusted_policies_v4",
                         self.objects(path))
        trusted = opened.trusted_policies(REPOSITORY, "default")
        self.assertEqual(1, len(trusted))
        self.assertEqual("c" * 64, trusted[0]["policy_digest"])
        self.assertEqual(1, trusted[0]["generation"])
        self.assertEqual(trust_store.SCHEMA_VERSION, opened.schema_version)

    def test_a_schema_four_home_migrates_the_same_way_ready_would(self):
        """Two authorities, one migration: the resulting layout is identical."""

        def seed(home: Path) -> None:
            home.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(str(store_base.database_path(home)))
            try:
                connection.execute("CREATE TABLE schema_meta ("
                                   "key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                connection.execute(
                    "INSERT INTO schema_meta VALUES('schema_version','4')")
                connection.execute("""
                    CREATE TABLE trusted_policies (
                        repository         TEXT NOT NULL,
                        class_id           TEXT NOT NULL,
                        policy_digest      TEXT NOT NULL,
                        enforcement_digest TEXT NOT NULL,
                        trusted_at         INTEGER NOT NULL,
                        PRIMARY KEY (repository, class_id, policy_digest))""")
                connection.execute(
                    "INSERT INTO trusted_policies VALUES(?,?,?,?,?)",
                    (REPOSITORY, "default", "c" * 64, "e" * 64, 1))
                connection.commit()
            finally:
                connection.close()

        import sys

        entry = str(REPO_ROOT / "packages" / "ready" / "src")
        if entry not in sys.path:
            sys.path.append(entry)
        from admissible_ready import store as ready_store_module

        mine, theirs = self.root / "by-trust", self.root / "by-ready"
        seed(mine)
        seed(theirs)
        self.opened(mine).close()
        ready_store_module.open_store(theirs).close()
        self.assertEqual(self.objects(store_base.database_path(theirs)),
                         self.objects(store_base.database_path(mine)))

    def test_an_absent_home_is_created_rather_than_refused(self):
        """A finalizer may bootstrap its own durable home the first time."""

        missing = self.root / "nested" / "home"
        opened = trust_store.open_store(missing)
        self.addCleanup(opened.close)
        self.assertTrue(store_base.database_path(missing).is_file())


class CandidateAndTrustRowsCoexist(StoreCase):
    """Ready writes observations, Trust writes authority, in one file."""

    def ready_store(self):
        import sys

        entry = str(REPO_ROOT / "packages" / "ready" / "src")
        if entry not in sys.path:
            sys.path.append(entry)
        from admissible_ready import store as ready_store_module

        return ready_store_module

    def test_each_authority_reads_the_other_s_rows(self):
        ready_module = self.ready_store()
        ready = ready_module.open_store(self.home)
        try:
            ready.record_attempt(
                attempt_id="attempt-one", repository=REPOSITORY,
                commit_sha=SHA, class_id="default", policy_digest="c" * 64,
                state="CHECKS_PASSED", started_at=1, tree_sha=TREE)
        finally:
            ready.close()
        opened = self.opened()
        self.assertEqual("attempt-one",
                         opened.latest_attempt(REPOSITORY, SHA)["attempt_id"])
        opened.trust_policy(repository=REPOSITORY, class_id="default",
                            policy_digest="c" * 64,
                            enforcement_digest="d" * 64, trusted_at=2)
        opened.close()
        ready = ready_module.open_store(self.home)
        try:
            self.assertEqual(
                ["c" * 64],
                [row["policy_digest"]
                 for row in ready.trusted_policies(REPOSITORY, "default")])
        finally:
            ready.close()

    def test_neither_opener_changes_the_layout_the_other_created(self):
        ready_module = self.ready_store()
        ready = ready_module.open_store(self.home)
        ready.close()
        before = self.objects(store_base.database_path(self.home))
        self.opened().close()
        self.assertEqual(before, self.objects(store_base.database_path(self.home)))


class ActiveSidecarsAreRefused(StoreCase):
    """A home whose committed contents are in a journal file is not read."""

    def test_a_wal_beside_the_database_is_refused(self):
        self.opened().close()
        path = store_base.database_path(self.home)
        Path(str(path) + "-wal").write_bytes(b"\x00" * 32)
        with self.assertRaises(trust_store.StoreError):
            trust_store.open_store(self.home)

    def test_a_rollback_journal_beside_the_database_is_refused(self):
        self.opened().close()
        path = store_base.database_path(self.home)
        Path(str(path) + "-journal").write_bytes(b"\x00" * 32)
        with self.assertRaises(trust_store.StoreError):
            trust_store.open_store(self.home)

    def test_the_refusal_is_the_same_one_ready_makes(self):
        """Same protocol, same message shape: one home, one rule."""

        self.opened().close()
        path = store_base.database_path(self.home)
        Path(str(path) + "-wal").write_bytes(b"\x00" * 32)
        with self.assertRaises(store_base.StoreError) as caught:
            store_open.refuse_a_layout_this_build_cannot_open(
                path, supported=trust_store.SCHEMA_VERSION)
        with self.assertRaises(trust_store.StoreError) as mine:
            trust_store.open_store(self.home)
        self.assertEqual(str(caught.exception), str(mine.exception))


class TheSchemaLockIsTaken(StoreCase):
    """Initialisation runs under Core's cross-process lock, as Ready's does."""

    def test_the_lock_is_held_from_before_the_preflight_until_the_end(self):
        order: list[str] = []
        real_lock = store_open.schema_lock
        real_preflight = trust_store.refuse_a_layout_this_build_cannot_open

        import contextlib

        @contextlib.contextmanager
        def watched_lock(path, **kwargs):
            order.append("lock")
            with real_lock(path, **kwargs):
                yield
            order.append("unlock")

        def watched_preflight(path, **kwargs):
            order.append("preflight")
            return real_preflight(path, **kwargs)

        with mock.patch.object(trust_store, "schema_lock", watched_lock), \
                mock.patch.object(trust_store,
                                  "refuse_a_layout_this_build_cannot_open",
                                  watched_preflight):
            trust_store.open_store(self.home).close()
        self.assertEqual(["lock", "preflight", "unlock"], order)

    def test_the_lock_file_lives_outside_the_home(self):
        lock_path = store_open.schema_lock_path(
            store_base.database_path(self.home))
        self.assertFalse(str(lock_path).startswith(str(self.home)))


class DurableHomeIsRequiredForSigning(StoreCase):
    """Anchoring on a disposable runner revokes and admits nothing."""

    def test_a_home_inside_the_job_workspace_is_refused(self):
        environment = {"ADMISSIBLE_HOME": str(self.home),
                       "GITHUB_WORKSPACE": str(self.root)}
        with self.assertRaises(trust_store.StoreError):
            trust_store.require_durable_home(environment)

    def test_a_hosted_job_must_declare_its_home_deliberately(self):
        environment = {"ADMISSIBLE_HOME": str(self.home),
                       "GITHUB_ACTIONS": "true"}
        with self.assertRaises(trust_store.StoreError):
            trust_store.require_durable_home(environment)
        environment["ADMISSIBLE_DURABLE_HOME"] = "1"
        self.assertEqual(self.home,
                         trust_store.require_durable_home(environment))

    def test_it_answers_exactly_as_the_monolith_does(self):
        for environment in (
                {"ADMISSIBLE_HOME": str(self.home)},
                {"ADMISSIBLE_HOME": str(self.home), "GITHUB_ACTIONS": "true",
                 "ADMISSIBLE_DURABLE_HOME": "1"}):
            with self.subTest(environment=sorted(environment)):
                self.assertEqual(
                    legacy_store.require_durable_home(environment),
                    trust_store.require_durable_home(environment))


class ExportAndImportAreAuthenticated(StoreCase):
    """The journal travels as documents, and arrives only if it verifies."""

    def signer(self):
        return trust_receipt.signer_from_secret("test", b"secret-material")

    def anchored(self, store):
        journal_id = trust_receipt.journal_id_for(REPOSITORY)
        trust_receipt.anchor_event(
            store, journal_id,
            {"domain": trust_receipt.RECEIPT_DOMAIN, "type": "probe",
             "repository": REPOSITORY},
            signer=self.signer(), now=10)
        return journal_id

    def test_an_export_round_trips_into_a_clean_home(self):
        source = self.opened()
        journal_id = self.anchored(source)
        bundle = source.export_journal(journal_id)
        self.assertEqual(trust_store.JOURNAL_EXPORT_SCHEMA, bundle["schema"])
        target = trust_store.open_store(self.root / "other")
        self.addCleanup(target.close)
        head = target.import_journal(bundle, self.signer())
        self.assertEqual(source.current_head(journal_id).receipt_hash,
                         head.receipt_hash)

    def test_an_import_under_the_wrong_key_is_refused(self):
        source = self.opened()
        journal_id = self.anchored(source)
        bundle = source.export_journal(journal_id)
        target = trust_store.open_store(self.root / "other")
        self.addCleanup(target.close)
        other = trust_receipt.signer_from_secret("test", b"a-different-secret")
        with self.assertRaises(trust_store.StoreError):
            target.import_journal(bundle, other)
        self.assertIsNone(target.current_head(journal_id))

    def test_a_forged_event_appended_past_the_signed_head_is_refused(self):
        source = self.opened()
        journal_id = self.anchored(source)
        bundle = source.export_journal(journal_id)
        bundle["events"].append({"domain": trust_receipt.RECEIPT_DOMAIN,
                                 "type": "forged"})
        target = trust_store.open_store(self.root / "other")
        self.addCleanup(target.close)
        with self.assertRaises(trust_store.StoreError):
            target.import_journal(bundle, self.signer())

    def test_the_bundle_matches_the_monolith_s_bytes(self):
        from fcd.journal import canonical_json

        source = self.opened()
        journal_id = self.anchored(source)
        mine = source.export_journal(journal_id)
        source.close()
        legacy = legacy_store.open_store(self.home)
        try:
            theirs = legacy.export_journal(journal_id)
        finally:
            legacy.close()
        self.assertEqual(canonical_json(theirs), canonical_json(mine))


if __name__ == "__main__":
    unittest.main()
