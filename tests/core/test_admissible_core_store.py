"""Contract: Core owns persistence *mechanism* and hands out no authority.

The split leaves one durable home shared by both authorities.  Core is where
its shared vocabulary lives -- the errors, where the home is, what the database
file is called, how a connection is configured -- because two copies of "which
directory is the store in" is two stores.

What Core must not hand out is the ability to *act*.  So the two surfaces below
are capability facades: a named, closed set of methods forwarded to an injected
backend, and nothing else.  A facade that forwarded whatever it was asked for
would be a rename of the backend rather than a restriction of it, so the denial
is asserted first and the allowance second.

Four properties are proved here rather than assumed:

* the denied names are denied *and exist on the backend*, so the refusal is a
  refusal rather than a typo that would pass whatever the backend offered;
* the allowed names really work against a real SQLite home, so the facade is
  not a stub that denies everything and therefore trivially denies the right
  things;
* the backend is not reachable *through the facade object* -- not under an
  obvious name, not under a mangled one, not in an instance dictionary, not as
  the ``__self__`` of a granted method, not in a repr, and not through pickle
  or copy.  A facade that hands back the backend's own bound method has handed
  back the backend, and every denial above it becomes decoration;
* opening a connection through Core neither migrates nor resets the schema an
  existing home already has.

What that third claim is *not* is a sandbox.  Core and its consumers run in one
interpreter, and Python has no honest way to hide an object from code in its
own process: ``gc.get_referrers``, the module-private registry these facades
use, and the frame stack are all still there.  The claim is the one worth
making and keeping true -- a caller holding a capability-limited view cannot
*use* it to reach withheld authority, so an accidental over-grant fails here --
and it is a claim about mistakes, not about a hostile process sharing the
account.  Isolation from that lives below Python, in the operating system.
"""
from __future__ import annotations

import ast
import copy
import gc
import pickle
import shutil
import sqlite3
import tempfile
import types
import unittest
import weakref
from pathlib import Path

from admissible import store as legacy_store

from admissible_core import store_base
from admissible_core import store_candidate
from admissible_core import store_read

ATTEMPT = "attempt-one"


def _remove(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


class CoreHomeVocabulary(unittest.TestCase):
    """Where the store is, and what it is called, is Core's to say."""

    def test_the_default_home_follows_the_environment_variable(self):
        self.assertEqual(Path("/srv/admissible"),
                         store_base.default_home({"ADMISSIBLE_HOME": "/srv/admissible"}))

    def test_an_empty_setting_falls_back_to_the_dot_directory(self):
        for environment in ({}, {"ADMISSIBLE_HOME": ""}, {"ADMISSIBLE_HOME": "  "}):
            with self.subTest(environment=environment):
                self.assertEqual(Path.home() / ".admissible",
                                 store_base.default_home(environment))

    def test_core_agrees_with_the_home_the_product_uses_today(self):
        """Two answers to "where is the store" is two stores."""
        for environment in ({}, {"ADMISSIBLE_HOME": "/srv/admissible"}):
            with self.subTest(environment=environment):
                self.assertEqual(legacy_store.default_home(environment),
                                 store_base.default_home(environment))

    def test_a_home_inside_the_candidate_is_refused_with_the_same_reason(self):
        with tempfile.TemporaryDirectory(prefix="admissible-core-home-") as raw:
            root = Path(raw)
            inside = {"ADMISSIBLE_HOME": str(root / "store")}
            with self.assertRaises(store_base.StoreError) as caught:
                store_base.require_home_outside(root, inside)
            self.assertIn("inside the repository under evaluation",
                          str(caught.exception))
            with self.assertRaises(legacy_store.StoreError):
                legacy_store.require_home_outside(root, inside)

    def test_a_home_outside_the_candidate_is_returned_unchanged(self):
        with tempfile.TemporaryDirectory(prefix="admissible-core-home-") as raw:
            root = Path(raw)
            outside = {"ADMISSIBLE_HOME": str(root.parent / "elsewhere")}
            self.assertEqual(legacy_store.require_home_outside(root, outside),
                             store_base.require_home_outside(root, outside))

    def test_the_database_file_name_is_the_one_already_on_disk(self):
        with tempfile.TemporaryDirectory(prefix="admissible-core-db-") as raw:
            home = Path(raw) / "home"
            legacy_store.open_store(home).close()
            self.assertTrue(store_base.database_path(home).is_file())
            self.assertEqual(home / "admissible.sqlite3",
                             store_base.database_path(home))


class CoreConnectionsPreserveTheExistingSchema(unittest.TestCase):
    """Core opens the database; owning its schema is a later task's job.

    Core deliberately runs no DDL.  A kernel that created or migrated tables
    would decide the storage contract for two authorities that have not been
    written yet, and the first thing it would do to an existing home is change
    it.
    """

    def home(self) -> Path:
        raw = tempfile.mkdtemp(prefix="admissible-core-schema-")
        self.addCleanup(_remove, Path(raw))
        home = Path(raw) / "home"
        store = legacy_store.open_store(home)
        self.addCleanup(store.close)
        return home

    def objects(self, connection: sqlite3.Connection) -> list[tuple]:
        return sorted(
            tuple(row) for row in connection.execute(
                "SELECT type, name, sql FROM sqlite_master").fetchall()
        )

    def test_connecting_changes_no_schema_object_at_all(self):
        home = self.home()
        direct = sqlite3.connect(store_base.database_path(home))
        try:
            before = self.objects(direct)
        finally:
            direct.close()
        connection = store_base.connect(home)
        self.addCleanup(connection.close)
        self.assertEqual(before, self.objects(connection))
        self.assertTrue(before, "the fixture home must have a schema to preserve")

    def test_the_recorded_schema_version_is_read_and_not_rewritten(self):
        home = self.home()
        connection = store_base.connect(home)
        self.addCleanup(connection.close)
        self.assertEqual(legacy_store.SCHEMA_VERSION,
                         store_base.schema_version(connection))

    def test_the_configured_pragmas_are_the_ones_the_product_uses(self):
        home = self.home()
        connection = store_base.connect(home)
        self.addCleanup(connection.close)
        self.assertEqual(
            "wal",
            connection.execute("PRAGMA journal_mode").fetchone()[0].lower())
        self.assertEqual(
            store_base.DEFAULT_BUSY_TIMEOUT_MS,
            connection.execute("PRAGMA busy_timeout").fetchone()[0])
        self.assertEqual(1, connection.execute("PRAGMA foreign_keys").fetchone()[0])

    def test_an_absent_database_is_refused_rather_than_created_empty(self):
        """A home with no database is not a home with an empty one.

        Creating the file here would hand back a connection with no tables,
        and every read through it would answer "nothing recorded" instead of
        "this is not an Admissible home".
        """
        with tempfile.TemporaryDirectory(prefix="admissible-core-absent-") as raw:
            with self.assertRaises(store_base.StoreError) as caught:
                store_base.connect(Path(raw) / "never-initialised")
            self.assertIn("no Admissible database", str(caught.exception))
            self.assertFalse((Path(raw) / "never-initialised").exists())


class BackendCapabilitiesAreChecked(unittest.TestCase):
    """A facade over a backend that cannot do the job must say so at once."""

    class Hollow:
        """A backend offering none of the capabilities either facade needs."""

    def test_a_backend_missing_a_capability_is_refused_on_construction(self):
        for facade in (store_read.ReadStore, store_candidate.CandidateStore):
            with self.subTest(facade=facade.__name__):
                with self.assertRaises(store_base.StoreError) as caught:
                    facade(self.Hollow())
                message = str(caught.exception)
                self.assertIn("evidence_for", message)
                self.assertIn("Hollow", message)

    def test_the_capability_sets_are_not_empty_and_nest(self):
        """An empty capability set would make every allowance vacuous."""
        self.assertTrue(store_base.READ_CAPABILITIES)
        self.assertTrue(store_base.CANDIDATE_WRITE_CAPABILITIES)
        self.assertTrue(store_base.WITHHELD_CAPABILITIES)
        self.assertLess(store_read.ReadStore.CAPABILITIES,
                        store_candidate.CandidateStore.CAPABILITIES)

    def test_no_withheld_capability_is_reachable_through_either_facade(self):
        overlap = store_base.WITHHELD_CAPABILITIES & (
            store_candidate.CandidateStore.CAPABILITIES)
        self.assertEqual(frozenset(), overlap)

    def test_every_withheld_name_is_a_real_method_of_a_durable_store(self):
        """A denial must name a real legacy or split-Trust operation."""

        trust_source = (Path(__file__).resolve().parents[2]
                        / "packages/trust/src/admissible_trust/store.py")
        tree = ast.parse(trust_source.read_text(encoding="utf-8"))
        trust_class = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "_TrustStoreBackend")
        trust_methods = {
            node.name for node in trust_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        missing = sorted(
            name for name in store_base.WITHHELD_CAPABILITIES
            if not hasattr(legacy_store.Store, name)
            and name not in trust_methods
        )
        self.assertEqual([], missing)

    def test_every_allowed_name_is_a_real_method_of_the_durable_store(self):
        missing = sorted(
            name for name in store_candidate.CandidateStore.CAPABILITIES
            if not hasattr(legacy_store.Store, name)
        )
        self.assertEqual([], missing)


class FacadeCase(unittest.TestCase):
    """A real SQLite home behind whichever facade the case under test needs."""

    REPOSITORY = "github.com/acme/widget"
    SHA = "a" * 40
    TREE = "b" * 40
    POLICY = "c" * 64

    def backend(self):
        raw = tempfile.mkdtemp(prefix="admissible-core-facade-")
        self.addCleanup(_remove, Path(raw))
        store = legacy_store.open_store(Path(raw) / "home")
        self.addCleanup(store.close)
        return store

    def seed(self, store) -> str:
        digest = "d" * 64
        store.put_evidence(
            digest=digest, kind="command", repository=self.REPOSITORY,
            commit_sha=self.SHA, tree_sha=self.TREE, policy_digest=self.POLICY,
            record={"kind": "command", "check_id": "unit"})
        return digest

    def assert_denied(self, facade, name: str, owner: str):
        with self.assertRaises(store_base.CapabilityError) as caught:
            getattr(facade, name)
        message = str(caught.exception)
        self.assertIn(name, message)
        self.assertIn(owner, message)


def safely(obj, name):
    """``getattr`` that answers with a sentinel instead of raising.

    A sweep over ``dir()`` touches names that refuse, and a refusal is the
    correct answer to most of them; the question here is only ever whether some
    name answers *with the backend*.
    """
    try:
        return getattr(obj, name)
    except Exception:  # noqa: BLE001 - any refusal is a non-answer
        return None


class TheBackendIsNotReachableThroughTheFacade(FacadeCase):
    """The denials above are only real if the backend itself stays out of reach.

    Every check is against a real :class:`admissible.store.Store`, because the
    escape that matters is the one a caller would find on the object the
    product actually hands out.
    """

    # Names a caller would try first, plus the manglings of ``__backend`` for
    # every class in the hierarchy. None of them may answer.
    PROBES = (
        "_backend", "backend", "__backend", "_store", "store", "_target",
        "_wrapped", "_inner", "_connection", "connection", "_facade",
        "_registry", "_CapabilityFacade__backend", "_ReadStore__backend",
        "_CandidateStore__backend",
    )

    def bound(self):
        store = self.backend()
        return store, store_read.ReadStore(store)

    def test_no_obvious_or_mangled_name_answers_with_the_backend(self):
        store, reader = self.bound()
        for name in self.PROBES:
            with self.subTest(name=name):
                with self.assertRaises(store_base.CapabilityError):
                    getattr(reader, name)
                self.assertFalse(hasattr(reader, name))

    def test_the_facade_carries_no_instance_dictionary(self):
        """``vars()`` is the first thing anyone tries, and it must find nothing."""
        _store, reader = self.bound()
        with self.assertRaises(AttributeError):
            reader.__dict__  # noqa: B018 - the access is the assertion
        with self.assertRaises(TypeError):
            vars(reader)

    def test_no_slot_in_the_hierarchy_holds_the_backend(self):
        """``__slots__`` moves state off ``__dict__``; it does not hide it."""
        store, reader = self.bound()
        holders = []
        for klass in type(reader).__mro__:
            for name, member in vars(klass).items():
                if not isinstance(member, types.MemberDescriptorType):
                    continue
                if safely(reader, name) is store:
                    holders.append(f"{klass.__name__}.{name}")
        self.assertEqual([], holders)

    def test_sweeping_every_readable_attribute_recovers_nothing(self):
        """The general form: no name on the object answers with the backend."""
        store, reader = self.bound()
        recovered = sorted(
            name for name in dir(reader) if safely(reader, name) is store)
        self.assertEqual([], recovered)
        self.assertIn("evidence_for", dir(store), "the sweep needs a live store")

    def test_a_granted_method_is_a_facade_owned_call_path(self):
        store, reader = self.bound()
        granted = reader.evidence_for
        self.assertIsNot(getattr(granted, "__self__", None), store)
        self.assertIs(granted.__self__, reader)
        self.assertNotIsInstance(granted, types.MethodType)
        self.assertFalse(hasattr(granted, "__func__"))
        self.assertIsNone(getattr(granted, "__closure__", None))

    def test_the_granted_call_path_still_reaches_the_real_backend(self):
        """A wrapper that denied everything would pass every test above."""
        store, reader = self.bound()
        digest = self.seed(store)
        records = reader.evidence_for(self.REPOSITORY, self.SHA)
        self.assertEqual([digest], [row["digest"] for row in records])
        self.assertEqual(store.evidence_for(self.REPOSITORY, self.SHA), records)

    def test_no_attribute_of_a_granted_method_recovers_the_backend(self):
        store, reader = self.bound()
        granted = reader.evidence_for
        recovered = sorted(
            name for name in dir(granted) if safely(granted, name) is store)
        self.assertEqual([], recovered)

    def test_neither_repr_identifies_the_backend_object(self):
        """A repr carrying ``id()`` is an address, and an address is a handle."""
        store, reader = self.bound()
        for text in (repr(reader), repr(reader.evidence_for)):
            with self.subTest(text=text):
                self.assertNotIn(hex(id(store)), text)
                self.assertNotIn(str(id(store)), text)
                self.assertNotIn(repr(store), text)
        self.assertIn("ReadStore", repr(reader))
        self.assertIn("evidence_for", repr(reader.evidence_for))

    def test_a_facade_cannot_be_pickled_or_copied(self):
        """Serialising it would either carry authority or arrive bound to nothing."""
        _store, reader = self.bound()
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol=protocol):
                with self.assertRaises(store_base.CapabilityError):
                    pickle.dumps(reader, protocol)
        with self.assertRaises(store_base.CapabilityError):
            copy.copy(reader)
        with self.assertRaises(store_base.CapabilityError):
            copy.deepcopy(reader)

    def test_a_granted_call_path_cannot_be_pickled_or_copied_either(self):
        _store, reader = self.bound()
        granted = reader.evidence_for
        with self.assertRaises(store_base.CapabilityError):
            pickle.dumps(granted)
        with self.assertRaises(store_base.CapabilityError):
            copy.copy(granted)

    def test_the_withheld_names_are_still_withheld_after_all_of_that(self):
        """The probing above must not have opened anything on the way past."""
        store, _reader = self.bound()
        candidate = store_candidate.CandidateStore(store)
        for name in sorted(store_base.WITHHELD_CAPABILITIES):
            with self.subTest(name=name):
                self.assert_denied(candidate, name,
                                   store_base.WITHHELD_OWNERS[name])

    def test_the_registry_is_a_convention_in_this_process_not_a_sandbox(self):
        """Stated as a test so the limit is documented where it can go stale.

        Same-process Python can find anything: the module-private registry is
        right there, and so is ``gc.get_referrers``.  What the facade buys is
        that no *use* of the granted object reaches withheld authority -- which
        is a guarantee about mistakes, not about a hostile process.
        """
        store, reader = self.bound()
        self.assertIs(store, store_base._BACKENDS[reader])
        self.assertIn(store, list(store_base._BACKENDS.values()))


class FacadeLifetime(unittest.TestCase):
    """Who keeps the store alive, and who lets it go.

    The backend lives in a module-private weak-keyed registry, so the two ways
    to get this wrong are opposite: a strong key would make every facade ever
    built immortal along with its database connection, and a weak *value*
    would collect the store out from under a facade that is still in use.
    """

    class Fake:
        """A weak-referenceable backend answering every read capability."""

        def __getattr__(self, name):
            if name in store_base.READ_CAPABILITIES:
                return lambda *args, **kwargs: name
            raise AttributeError(name)

    def test_a_facade_keeps_its_backend_alive_and_then_lets_it_go(self):
        backend = self.Fake()
        facade = store_read.ReadStore(backend)
        watch = weakref.ref(backend)
        del backend
        gc.collect()
        self.assertIsNotNone(watch(), "a live facade must pin its backend")
        self.assertEqual("current_head", facade.current_head())
        del facade
        gc.collect()
        self.assertIsNone(watch(), "a dead facade must not pin its backend")

    def test_a_granted_call_path_keeps_the_whole_chain_alive(self):
        """The facade may be unnamed; the capability taken from it still works."""
        backend = self.Fake()
        granted = store_read.ReadStore(backend).current_head
        watch = weakref.ref(backend)
        del backend
        gc.collect()
        self.assertIsNotNone(watch())
        self.assertEqual("current_head", granted())

    def test_a_collected_facade_leaves_no_entry_behind(self):
        gc.collect()
        before = len(store_base._BACKENDS)
        facade = store_read.ReadStore(self.Fake())
        self.assertEqual(before + 1, len(store_base._BACKENDS))
        watch = weakref.ref(facade)
        del facade
        gc.collect()
        self.assertIsNone(watch(), "the facade must be weak-referenceable")
        self.assertEqual(before, len(store_base._BACKENDS))

    def test_two_facades_over_one_backend_are_tracked_separately(self):
        backend = self.Fake()
        first = store_read.ReadStore(backend)
        second = store_read.ReadStore(backend)
        self.assertIsNot(first, second)
        self.assertEqual("current_head", first.current_head())
        self.assertEqual("current_head", second.current_head())
        del first
        gc.collect()
        self.assertEqual("current_head", second.current_head())


class ReadStoreGrantsReadsAndNothingElse(FacadeCase):

    def test_a_read_only_property_answers_with_its_value_not_a_call_path(self):
        """``home`` is a property on the store; wrapping it would change it."""
        store = self.backend()
        reader = store_read.ReadStore(store)
        self.assertEqual(store.home, reader.home)
        self.assertEqual(store.path, reader.path)
        self.assertEqual(store.schema_version, reader.schema_version)
        self.assertIsInstance(reader.home, Path)
        self.assertIsInstance(reader.schema_version, int)

    def test_reads_go_through_to_the_backend(self):
        store = self.backend()
        digest = self.seed(store)
        reader = store_read.ReadStore(store)
        records = reader.evidence_for(self.REPOSITORY, self.SHA)
        self.assertEqual(1, len(records))
        self.assertEqual(digest, records[0]["digest"])
        self.assertEqual(store.evidence_for(self.REPOSITORY, self.SHA), records)

    def test_writing_evidence_is_not_a_read(self):
        reader = store_read.ReadStore(self.backend())
        self.assert_denied(reader, "put_evidence", "candidate")

    def test_recording_an_attempt_is_not_a_read(self):
        reader = store_read.ReadStore(self.backend())
        self.assert_denied(reader, "record_attempt", "candidate")

    def test_trust_mutation_is_denied(self):
        reader = store_read.ReadStore(self.backend())
        for name in ("trust_policy", "revoke_policy"):
            with self.subTest(name=name):
                self.assert_denied(reader, name, "Trust")

    def test_reading_the_trusted_baseline_is_still_allowed(self):
        """Denying the *writes* is the point; the baseline is a public fact."""
        store = self.backend()
        reader = store_read.ReadStore(store)
        self.assertEqual((), reader.trusted_policies(self.REPOSITORY, "default"))
        self.assertEqual(0, reader.policy_generation(self.REPOSITORY, "default"))
        self.assertEqual(frozenset(),
                         reader.revoked_policies(self.REPOSITORY, "default"))


class CandidateStoreGrantsCandidateWrites(FacadeCase):

    def test_evidence_written_through_the_facade_is_readable_back(self):
        store = self.backend()
        candidate = store_candidate.CandidateStore(store)
        self.assertTrue(candidate.put_evidence(
            digest="e" * 64, kind="command", repository=self.REPOSITORY,
            commit_sha=self.SHA, tree_sha=self.TREE, policy_digest=self.POLICY,
            record={"kind": "command", "check_id": "unit"}))
        self.assertEqual(
            ("e" * 64,),
            tuple(row["digest"]
                  for row in candidate.evidence_for(self.REPOSITORY, self.SHA)))
        # And it is in the real database, not in the facade.
        self.assertEqual(1, len(store.evidence_for(self.REPOSITORY, self.SHA)))

    def test_an_attempt_recorded_through_the_facade_is_the_latest_attempt(self):
        candidate = store_candidate.CandidateStore(self.backend())
        candidate.record_attempt(
            attempt_id=ATTEMPT, repository=self.REPOSITORY,
            commit_sha=self.SHA, class_id="default", policy_digest=self.POLICY,
            state="CHECKS_PASSED", started_at=1000, tree_sha=self.TREE)
        latest = candidate.latest_attempt(self.REPOSITORY, self.SHA)
        self.assertIsNotNone(latest)
        self.assertEqual(ATTEMPT, latest["attempt_id"])

    def test_head_anchoring_is_withheld(self):
        candidate = store_candidate.CandidateStore(self.backend())
        self.assert_denied(candidate, "accept_head", "Trust")

    def test_receipt_issuance_is_withheld(self):
        candidate = store_candidate.CandidateStore(self.backend())
        for name in ("workflow_receipt_row", "defect_row", "import_journal"):
            with self.subTest(name=name):
                self.assert_denied(candidate, name, "Trust")

    def test_split_trust_write_names_have_specific_owners(self):
        """Current Trust names must not fall through to the generic denial."""
        candidate = store_candidate.CandidateStore(self.backend())
        for name in (
                "insert_workflow_receipt",
                "insert_defect",
                "insert_receipt_evidence",
                "insert_dependency_edge",
                "lower_dependency_recorded_at"):
            with self.subTest(name=name):
                self.assertIn(name, store_base.WITHHELD_OWNERS)
                self.assert_denied(candidate, name, "Trust")

    def test_policy_trust_mutation_is_withheld(self):
        candidate = store_candidate.CandidateStore(self.backend())
        for name in ("trust_policy", "revoke_policy"):
            with self.subTest(name=name):
                self.assert_denied(candidate, name, "Trust")

    def test_the_unrestricted_write_transaction_is_withheld(self):
        """``transact`` is a hole big enough to write anything through."""
        candidate = store_candidate.CandidateStore(self.backend())
        self.assert_denied(candidate, "transact", "Trust")

    def test_closing_the_shared_backend_is_withheld(self):
        """A capability-limited view does not own the connection's lifetime."""
        candidate = store_candidate.CandidateStore(self.backend())
        self.assert_denied(candidate, "close", "owner")

    def test_an_unlisted_name_is_refused_rather_than_forwarded(self):
        """A facade that passes through the unknown restricts nothing."""
        candidate = store_candidate.CandidateStore(self.backend())
        with self.assertRaises(store_base.CapabilityError):
            getattr(candidate, "_connection")
        with self.assertRaises(store_base.CapabilityError):
            getattr(candidate, "some_future_method")

    def test_the_granted_surface_is_exactly_the_declared_capability_set(self):
        """Enumerated, so a capability added by accident fails here first."""
        candidate = store_candidate.CandidateStore(self.backend())
        reachable = {
            name for name in store_candidate.CandidateStore.CAPABILITIES
            if getattr(candidate, name, None) is not None
        }
        self.assertEqual(store_candidate.CandidateStore.CAPABILITIES, reachable)


if __name__ == "__main__":
    unittest.main()
