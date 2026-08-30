"""The durable home, opened by the distribution that decides things.

One Admissible home is shared by both authorities, and Core owns its shared
vocabulary: where it is, what the database file is called, how a connection is
configured, and the machinery that turns a set of method names into a checkable
capability surface.  What Core deliberately does *not* own is the schema -- a
kernel that created tables would fix the storage contract for distributions
that had not been written yet.  This module is the Trust half of that: it
creates and migrates exactly the schema the monolith created and migrated, and
implements the reads plus the writes that only an authority may make.

The SQL below is byte-for-byte the SQL ``admissible_ready.store`` writes, and a
test compares the two statement lists.  Two distributions open the same file;
a home whose layout depended on which authority reached it first would be two
homes wearing one name.

What is here that is not in Ready:

* ``accept_head`` -- the compare-and-set that makes one signed head the
  successor of exactly the stored one, with the event append, the head-receipt
  insert and every attachment inside one ``BEGIN IMMEDIATE``;
* ``insert_workflow_receipt``, ``insert_defect``, ``insert_receipt_evidence``,
  ``insert_dependency_edge`` and ``lower_dependency_recorded_at`` -- the
  attachment writes, each of which may only run inside such a transaction and
  says so;
* ``trust_policy`` and ``revoke_policy`` -- making a policy enforceable, and
  withdrawing one;
* ``verify_journal``, ``authenticated_repository_projection`` and
  ``authenticated_workflow_state`` -- the reads that authenticate before they
  answer, which is what turns "a row says ADMITTED" into standing;
* ``export_journal`` and ``import_journal``.

What is deliberately *not* here, in either the backend or the facade, is any
unrestricted way to reach the database.  There is no ``connection`` property,
no ``transact``, no ``execute``: the monolith had all three, and a caller
holding any one of them can ``DROP TRIGGER`` and write a receipt row by hand,
which makes every append-only guarantee in the schema advice rather than a
wall.  Each authority operation is a named method that writes exactly the row
its own contract describes.  The connection is not an attribute of anything --
not ``store._connection``, not ``backend._connection`` -- it lives in the
module-private registry below, keyed weakly by the backend that opened it, and
``open_store`` hands back only a :class:`TrustStore`.

Migration is additive and non-destructive, exactly as before.  An existing v0.7
home opens, upgrades in place inside one transaction, and loses no row; a home
written by a newer schema is refused rather than downgraded -- and the refusal
comes *first*, before the journal mode is set, before the schema script runs
and before any migration, because refusing a newer home after switching it to
WAL and creating this build's tables inside it is not a refusal, it is a
rewrite followed by an apology.

Opening one is done under :func:`admissible_core.store_open.schema_lock`, held
from before the existence check until the schema and the recorded version are
final.  Everything between those two points is a window a second process can
ruin -- two openers both finding no file and both creating one, two both
finding version 5 and both migrating it -- and SQLite protects none of it,
because at the moment they race there is no database yet.  The Ready
distribution takes the same lock on the same home for the same reason.

The look that decides whether this build may open a home happens before the
read-write connection exists, on an immutable read-only connection that cannot
create a ``-wal`` or replay a journal; a home that already has a sidecar beside
it is refused outright rather than read through, because its committed contents
are in that file and reading them means writing to a database this build has
not yet agreed to touch.  The version is then read once more through the
connection that will do the writing, before the first pragma, since the lock
binds only the processes that agree to take it.

The honest limits, and there are three.  This is a file, under this user, on
this filesystem: nothing here stops a process running as the same account from
deleting the database or corrupting it, and the fail-closed reads then produce
a denial of service rather than a false answer.  Refusing a home with a sidecar
is itself a denial of service -- a store another process holds open cannot be
opened here until that process lets go, and two Admissible processes therefore
cannot share one home at the same time.  And the schema lock is advisory: a
hand-run ``sqlite3`` takes neither it nor any notice of it, so none of this is
a defence against arbitrary same-user SQL.  Package separation removes
accidental capability adjacency; it is not a filesystem sandbox and is not
offered as one.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import weakref
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

from fcd import head as fcd_head
from fcd.journal import canonical_json

from admissible_core import evidence as evidence_module
from admissible_core.store_base import (DEFAULT_BUSY_TIMEOUT_MS,
                                        SCHEMA_VERSION_KEY, CapabilityFacade,
                                        HeadConflict, StoreError,
                                        database_path, default_home,
                                        require_home_outside)
from admissible_core.store_open import (DEFAULT_SCHEMA_LOCK_TIMEOUT_MS,
                                        recorded_schema_version_text,
                                        refuse_a_layout_this_build_cannot_open,
                                        refuse_an_unsupported_version,
                                        schema_lock)

from . import receipt as receiptdata

# The whole of this module's surface.  The backend class is deliberately not
# here and is deliberately not public: exporting it would let any consumer
# build a second one beside the facade, and the object it hands back holds the
# live ``sqlite3`` connection.  ``open_store`` is the only way in, and what it
# returns is a :class:`TrustStore`.
__all__ = [
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
]

SCHEMA_VERSION = 6

# What one journal export may weigh. It is deliberately not the evidence-bundle
# ceiling: a bundle is one attempt's records and a journal is every event a
# repository ever anchored, so bounding the second by the first made a
# long-lived home exportable and un-importable, with no supported way to split
# it. Both sides use this number, and `export` refuses to write a file `import`
# would refuse to read.
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
JOURNAL_EXPORT_SCHEMA = "admissible/v0.6/workflow-journal-export"
_EXPORT_KEYS = {"schema", "journal_id", "events", "receipts",
                "workflow_receipts", "evidence", "defects"}

# How long an opener waits for another process to finish initialising this
# home before it gives up and says who it was waiting for. Read at call time,
# so a deployment that knows its migrations are slower can raise it.
SCHEMA_LOCK_TIMEOUT_MS = DEFAULT_SCHEMA_LOCK_TIMEOUT_MS

_ENVIRONMENT_HOME = "ADMISSIBLE_HOME"


def _inside(child: Path, parent: str) -> bool:
    """Whether ``child`` resolves to somewhere under ``parent``."""

    if not parent.strip():
        return False
    try:
        child.resolve().relative_to(Path(parent).resolve())
    except (ValueError, OSError):
        return False
    return True


def require_durable_home(environment: dict[str, str] | None = None) -> Path:
    """The Admissible home, or a refusal when it could not survive the job.

    Monotone standing is a claim about *history*. A database that lives in a
    hosted runner's workspace is deleted the moment the job ends, so every run
    would start a fresh bootstrap journal and no rollback could ever be
    detected. Signing therefore requires an explicitly durable home: a
    dedicated persistent finalizer, or an external registry boundary the
    operator has arranged. Evaluation is unaffected -- it anchors nothing, and
    it happens in a distribution that cannot reach this function at all.
    """

    source = os.environ if environment is None else environment
    home = default_home(source)
    workspace = source.get("GITHUB_WORKSPACE") or ""
    scratch = source.get("RUNNER_TEMP") or ""
    ephemeral = _inside(home, workspace) or _inside(home, scratch)
    hosted = (source.get("GITHUB_ACTIONS") or "").strip().lower() == "true"
    declared = (source.get("ADMISSIBLE_DURABLE_HOME") or "").strip().lower()
    if ephemeral:
        raise StoreError(
            f"{_ENVIRONMENT_HOME} {home} is inside this job's disposable "
            "workspace, so it is not a durable anchor: the journal would be "
            "destroyed with the runner and every run would bootstrap a new "
            f"one. Point {_ENVIRONMENT_HOME} at storage that outlives the job.")
    if hosted and declared not in ("1", "true", "yes"):
        raise StoreError(
            "signing needs a durable ADMISSIBLE_HOME on a dedicated persistent "
            "finalizer, or a documented external registry boundary. Configure "
            "one and set ADMISSIBLE_DURABLE_HOME=1 to say so deliberately; "
            "until then this job may evaluate but must not sign.")
    return home


_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS journal_events (
    journal_id   TEXT    NOT NULL,
    position     INTEGER NOT NULL,
    event_json   TEXT    NOT NULL,
    event_digest TEXT    NOT NULL,
    PRIMARY KEY (journal_id, position)
);
CREATE TABLE IF NOT EXISTS head_receipts (
    receipt_hash           TEXT PRIMARY KEY,
    journal_id             TEXT    NOT NULL,
    event_count            INTEGER NOT NULL,
    previous_receipt_hash  TEXT    NOT NULL,
    receipt_json           TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS current_head (
    journal_id   TEXT PRIMARY KEY,
    receipt_hash TEXT NOT NULL REFERENCES head_receipts(receipt_hash)
);
CREATE TABLE IF NOT EXISTS evidence (
    digest        TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    repository    TEXT NOT NULL,
    commit_sha    TEXT NOT NULL,
    tree_sha      TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    record_json   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_artifact
    ON evidence (repository, commit_sha);
CREATE TABLE IF NOT EXISTS workflow_receipts (
    receipt_hash      TEXT PRIMARY KEY,
    body_digest       TEXT NOT NULL UNIQUE,
    journal_id        TEXT NOT NULL,
    repository        TEXT NOT NULL,
    commit_sha        TEXT NOT NULL,
    tree_sha          TEXT NOT NULL,
    policy_digest     TEXT NOT NULL,
    class_id          TEXT NOT NULL,
    state             TEXT NOT NULL,
    issued_at         INTEGER NOT NULL,
    receipt_json      TEXT NOT NULL,
    head_receipt_hash TEXT NOT NULL REFERENCES head_receipts(receipt_hash)
);
CREATE INDEX IF NOT EXISTS workflow_receipt_artifact
    ON workflow_receipts (repository, commit_sha);
CREATE TABLE IF NOT EXISTS defects (
    defect_id     TEXT NOT NULL,
    repository    TEXT NOT NULL,
    commit_sha    TEXT NOT NULL,
    digest        TEXT PRIMARY KEY,
    filed_at      INTEGER NOT NULL,
    record_json   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS defect_artifact ON defects (repository, commit_sha);
CREATE TABLE IF NOT EXISTS dependencies (
    consumer_repository   TEXT NOT NULL,
    consumer_commit_sha   TEXT NOT NULL,
    dependency_repository TEXT NOT NULL,
    dependency_commit_sha TEXT NOT NULL,
    recorded_at           INTEGER NOT NULL,
    PRIMARY KEY (consumer_repository, consumer_commit_sha,
                 dependency_repository, dependency_commit_sha)
);
CREATE INDEX IF NOT EXISTS dependency_lookup
    ON dependencies (dependency_repository, dependency_commit_sha);
CREATE TABLE IF NOT EXISTS attempts (
    attempt_id    TEXT PRIMARY KEY,
    repository    TEXT NOT NULL,
    commit_sha    TEXT NOT NULL,
    class_id      TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    state         TEXT NOT NULL,
    started_at    INTEGER NOT NULL,
    tree_sha      TEXT NOT NULL DEFAULT '',
    decision_json TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS attempt_artifact
    ON attempts (repository, commit_sha, started_at);
CREATE TABLE IF NOT EXISTS attempt_evidence (
    attempt_id TEXT NOT NULL,
    digest     TEXT NOT NULL,
    PRIMARY KEY (attempt_id, digest)
);
-- One monotone counter for everything the cache learns, allocated at the
-- moment the fact is written. This distribution never allocates one -- caching
-- a command result is a claim about an execution, and this distribution
-- executes nothing -- but the table is created because the home is shared and
-- a schema that depends on which authority opened it first is two schemas.
CREATE TABLE IF NOT EXISTS cache_order (
    id INTEGER PRIMARY KEY AUTOINCREMENT
);
CREATE TABLE IF NOT EXISTS evidence_cache (
    cache_key   TEXT PRIMARY KEY,
    digest      TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    sequence    INTEGER NOT NULL DEFAULT 0
);
-- A later failure is news about the same cache key. It cannot delete the
-- cached success -- nothing here is deletable -- so it is recorded beside it
-- and read as a floor: no entry older than the newest failure may be reused.
CREATE TABLE IF NOT EXISTS evidence_cache_invalidations (
    cache_key      TEXT NOT NULL,
    digest         TEXT NOT NULL,
    invalidated_at INTEGER NOT NULL,
    sequence       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cache_key, digest)
);
-- The policies this home has deliberately trusted. A candidate may propose a
-- policy; only an operator, in a trusted context, may make one enforceable.
-- ``generation`` is what stops a trusted policy from being trusted forever.
-- Trusting a policy that enforces something new opens a new generation for the
-- class, and only the newest generation is enforceable. Without it, upgrading a
-- class from "no reviews" to `payment-change` left the old zero-review digest
-- permanently valid: reverting the policy file to it restored the weaker gate,
-- and every entry here still matched.
--
-- Nothing is deleted. The old rows stay as history and can be read back; they
-- simply stop being an authority. Revocation is the same idea applied to one
-- entry inside the current generation, for the case where an operator trusted
-- something they should not have.
--
-- This is the distribution that writes here, and it is the only one. The
-- candidate side creates the same tables and reads them; a candidate that
-- could write one would be a candidate approving its own gate.
CREATE TABLE IF NOT EXISTS trusted_policies (
    repository        TEXT NOT NULL,
    class_id          TEXT NOT NULL,
    policy_digest     TEXT NOT NULL,
    enforcement_digest TEXT NOT NULL,
    trusted_at        INTEGER NOT NULL,
    generation        INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (repository, class_id, policy_digest, generation)
);
CREATE INDEX IF NOT EXISTS trusted_policy_class
    ON trusted_policies (repository, class_id, trusted_at);
-- Revocation is scoped to the generation it was made in. A policy an operator
-- withdrew, and later deliberately trusted again, arrives in a new generation
-- and is not still withdrawn; the record of the withdrawal stays where it was.
CREATE TABLE IF NOT EXISTS policy_revocations (
    repository    TEXT NOT NULL,
    class_id      TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    generation    INTEGER NOT NULL,
    revoked_at    INTEGER NOT NULL,
    PRIMARY KEY (repository, class_id, policy_digest, generation)
);
CREATE TRIGGER IF NOT EXISTS policy_revocations_no_update
    BEFORE UPDATE ON policy_revocations
    BEGIN SELECT RAISE(ABORT, 'policy revocations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS policy_revocations_no_delete
    BEFORE DELETE ON policy_revocations
    BEGIN SELECT RAISE(ABORT, 'policy revocations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS attempts_no_delete
    BEFORE DELETE ON attempts
    BEGIN SELECT RAISE(ABORT, 'attempts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS dependencies_no_delete
    BEFORE DELETE ON dependencies
    BEGIN SELECT RAISE(ABORT, 'dependencies are append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_no_update
    BEFORE UPDATE ON evidence
    BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_no_delete
    BEFORE DELETE ON evidence
    BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS journal_events_no_update
    BEFORE UPDATE ON journal_events
    BEGIN SELECT RAISE(ABORT, 'journal events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS journal_events_no_delete
    BEFORE DELETE ON journal_events
    BEGIN SELECT RAISE(ABORT, 'journal events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS head_receipts_no_update
    BEFORE UPDATE ON head_receipts
    BEGIN SELECT RAISE(ABORT, 'head receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS head_receipts_no_delete
    BEFORE DELETE ON head_receipts
    BEGIN SELECT RAISE(ABORT, 'head receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS workflow_receipts_no_update
    BEFORE UPDATE ON workflow_receipts
    BEGIN SELECT RAISE(ABORT, 'workflow receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS workflow_receipts_no_delete
    BEFORE DELETE ON workflow_receipts
    BEGIN SELECT RAISE(ABORT, 'workflow receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS defects_no_update
    BEFORE UPDATE ON defects
    BEGIN SELECT RAISE(ABORT, 'defects are append-only'); END;
CREATE TRIGGER IF NOT EXISTS defects_no_delete
    BEFORE DELETE ON defects
    BEGIN SELECT RAISE(ABORT, 'defects are append-only'); END;
CREATE TRIGGER IF NOT EXISTS dependencies_no_update
    BEFORE UPDATE ON dependencies
    WHEN NEW.consumer_repository <> OLD.consumer_repository
      OR NEW.consumer_commit_sha <> OLD.consumer_commit_sha
      OR NEW.dependency_repository <> OLD.dependency_repository
      OR NEW.dependency_commit_sha <> OLD.dependency_commit_sha
      OR NEW.recorded_at >= OLD.recorded_at
    BEGIN SELECT RAISE(ABORT,
        'dependency identity is append-only and time only moves earlier'); END;
CREATE TRIGGER IF NOT EXISTS trusted_policies_no_update
    BEFORE UPDATE ON trusted_policies
    BEGIN SELECT RAISE(ABORT, 'trusted policies are append-only'); END;
CREATE TRIGGER IF NOT EXISTS trusted_policies_no_delete
    BEFORE DELETE ON trusted_policies
    BEGIN SELECT RAISE(ABORT, 'trusted policies are append-only'); END;
CREATE TRIGGER IF NOT EXISTS cache_invalidations_no_delete
    BEFORE DELETE ON evidence_cache_invalidations
    BEGIN SELECT RAISE(ABORT, 'cache invalidations are append-only'); END;
"""


# Backend -> the connection it opened.  The connection is not an attribute of
# the backend, for the same reason Core keeps its backends in
# ``store_base._BACKENDS`` rather than on the facade: an attribute is a name,
# and a name is a path.  ``backend._connection`` would have undone the whole
# capability model in one attribute access -- a raw connection can drop every
# append-only trigger in ``_SCHEMA`` and write a receipt row by hand.
#
# Weak keys, strong values.  While a backend is alive its connection must be
# too, or a store would go hollow under a caller still using it; and a backend
# nobody holds takes its connection with it.
_CONNECTIONS: "weakref.WeakKeyDictionary[_TrustStoreBackend, sqlite3.Connection]" = (
    weakref.WeakKeyDictionary())


def _sql(backend: "_TrustStoreBackend") -> sqlite3.Connection:
    """The connection a backend opened, or a refusal once it has none."""

    connection = _CONNECTIONS.get(backend)
    if connection is None:
        raise StoreError(
            "this store is closed: its connection was released and no read or "
            "write can be served through it")
    return connection


def _event_digest(event: object) -> str:
    return hashlib.sha256(canonical_json(event).encode("utf-8")).hexdigest()


class _TrustStoreBackend:
    """A durable Admissible home, with the trusted surface and no other.

    Every write here is a named authority operation that inserts exactly the
    row its own contract describes.  There is no ``connection``, no
    ``transact`` and no ``execute``, so a caller who reaches this object
    directly -- rather than through the facade :func:`open_store` hands out --
    gains no way to write a row no method here would write.

    Module-private, and not exported.  "Private" in Python is a spelling rather
    than a wall, and the point is not to hide the class from a determined
    reader in this process -- it is that no supported name leads here, so
    reaching the raw database is a deliberate act against the grain of the
    module instead of an attribute on an object a caller was handed.
    """

    __slots__ = ("_home", "_path", "_schema_version", "__weakref__")

    def __init__(self, home: Path | str) -> None:
        self._home = Path(home)
        try:
            self._home.mkdir(parents=True, exist_ok=True)
            os.chmod(self._home, 0o700)
        except OSError as error:
            raise StoreError(
                f"cannot use Admissible home {self._home}: {error.strerror}"
            ) from None
        self._path = database_path(self._home)
        # Everything that decides what this file is -- whether it exists,
        # whether this build may open it, and the schema it ends up carrying --
        # happens with the cross-process lock held. See the method below.
        with schema_lock(self._path, timeout_ms=SCHEMA_LOCK_TIMEOUT_MS):
            self._initialise_under_the_schema_lock()

    def _initialise_under_the_schema_lock(self) -> None:
        """Create or open the database, and settle its schema, exactly once.

        The lock this runs under starts before the existence check and ends
        after the version is final, because those are the two ends of the
        interval a second opener can ruin: two processes that both find no file
        both create one, and two that both find version 5 both migrate it.
        SQLite cannot help with either -- at the moment they race there is no
        database yet, only a name.

        The look that decides whether this build may open the home at all
        happens *before* the read-write connection exists, on an immutable
        read-only connection that cannot create a ``-wal`` or replay a
        journal. Then the version is read once more, on the connection that
        will do the writing, before a single pragma or statement changes
        anything: the lock binds the processes that agree to take it, and the
        second look is what stands between this store and one that did not.
        """

        fresh = not self._path.exists()
        refuse_a_layout_this_build_cannot_open(self._path,
                                              supported=SCHEMA_VERSION)
        try:
            if fresh:
                descriptor = os.open(str(self._path),
                                     os.O_CREAT | os.O_RDWR | os.O_EXCL, 0o600)
                os.close(descriptor)
            os.chmod(self._path, 0o600)
            connection = sqlite3.connect(
                str(self._path), timeout=DEFAULT_BUSY_TIMEOUT_MS / 1000.0,
                isolation_level=None)
        except (OSError, sqlite3.Error) as error:
            raise StoreError(
                f"cannot open the Admissible database at {self._path}: {error}"
            ) from None
        connection.row_factory = sqlite3.Row
        _CONNECTIONS[self] = connection
        # Before anything is configured, created or migrated.  See the method:
        # the order is the whole guarantee.
        self._refuse_a_layout_this_build_cannot_open()
        try:
            _sql(self).execute("PRAGMA journal_mode=WAL")
            _sql(self).execute("PRAGMA foreign_keys=ON")
            _sql(self).execute(
                f"PRAGMA busy_timeout={DEFAULT_BUSY_TIMEOUT_MS}")
            _sql(self).execute("PRAGMA synchronous=FULL")
            _sql(self).executescript(_SCHEMA)
            row = _sql(self).execute(
                "SELECT value FROM schema_meta WHERE key=?",
                (SCHEMA_VERSION_KEY,)).fetchone()
            if row is None:
                _sql(self).execute(
                    "INSERT INTO schema_meta(key, value) VALUES(?, ?)",
                    (SCHEMA_VERSION_KEY, str(SCHEMA_VERSION)))
                self._schema_version = SCHEMA_VERSION
            else:
                self._schema_version = int(row["value"])
                stranded_policy = _sql(self).execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND "
                    "name='trusted_policies_v4'").fetchone() is not None
                if (self._schema_version < SCHEMA_VERSION
                        or (self._schema_version == SCHEMA_VERSION
                            and stranded_policy)):
                    # The schema script above is additive and idempotent, so an
                    # older home is upgraded in place without losing a row.
                    # Columns added to a table that already exists are the one
                    # thing that script cannot do, so they are named here.
                    # The rebuild, every additive ALTER, and the version bump
                    # are one crash boundary.  A version number must never say
                    # "migrated" while a renamed legacy table is stranded, and
                    # a crash after the rename must roll the rename back.
                    _sql(self).execute("BEGIN IMMEDIATE")
                    try:
                        if self._schema_version < SCHEMA_VERSION:
                            self._add_missing_columns()
                            _sql(self).execute(
                                "UPDATE schema_meta SET value=? WHERE key=?",
                                (str(SCHEMA_VERSION), SCHEMA_VERSION_KEY))
                        else:
                            # A pre-transactional v4->v5 migration could have
                            # bumped the version and crashed between RENAME,
                            # COPY and DROP.  The legacy table itself is the
                            # recovery marker; version 5 does not make it safe
                            # to ignore.
                            self._migrate_trusted_policies()
                        _sql(self).execute("COMMIT")
                    except BaseException:
                        self._rollback()
                        raise
                    self._schema_version = SCHEMA_VERSION
        except (sqlite3.Error, ValueError) as error:
            self.close()
            raise StoreError(
                f"cannot initialise the Admissible database: {error}") from None
        if self._schema_version > SCHEMA_VERSION:
            # Unreachable through either look above, and kept anyway. Both of
            # them run before this block, so the only way here is a version
            # this build's own schema script somehow read as newer -- which
            # would mean one of them stopped being called.
            self.close()
            raise StoreError(
                f"{self._path} was written by a newer Admissible "
                f"(schema {self._schema_version} > {SCHEMA_VERSION}); upgrade "
                "before using this store")

    def _refuse_a_layout_this_build_cannot_open(self) -> None:
        """Read the recorded schema version, and stop before touching anything.

        This runs on the read-write connection before ``PRAGMA
        journal_mode=WAL``, before the schema script and before any migration,
        and it runs ``SELECT`` and nothing else.  The order is the guarantee,
        not a detail.  Switching a home to WAL rewrites its header and drops a
        ``-wal`` beside it; the additive script creates this build's tables
        inside a database a newer build wrote; a migration rewrites rows.  All
        three are changes to a home this build is about to decide it may not
        use, so a refusal that arrives after them is an apology rather than a
        refusal.

        The immutable look already asked the same question a moment ago,
        without opening the home for writing at all, and this is not that check
        repeated for luck.  The lock they both run under binds the processes
        that agree to take it; a process that does not -- a hand-run
        ``sqlite3``, a newer build nobody told about the lock -- can record a
        version between the two moments.  This is the last look before the
        first write, taken through the connection that would do the writing.
        """

        try:
            recorded = recorded_schema_version_text(_sql(self),
                                                    path=self._path)
            refuse_an_unsupported_version(recorded, path=self._path,
                                          supported=SCHEMA_VERSION)
        except StoreError:
            self.close()
            raise

    _ADDED_COLUMNS = (
        ("attempts", "tree_sha", "TEXT NOT NULL DEFAULT ''"),
        ("attempts", "decision_json", "TEXT NOT NULL DEFAULT ''"),
        ("evidence_cache", "sequence", "INTEGER NOT NULL DEFAULT 0"),
        ("evidence_cache_invalidations", "sequence",
         "INTEGER NOT NULL DEFAULT 0"),
    )

    def _migrate_trusted_policies(self) -> None:
        """Widen an older baseline table so a generation can be recorded.

        Schema 4 keyed trusted policies by digest alone, which is exactly the
        shape that made "trusted once" mean "trusted forever". A generation
        cannot be added with ALTER TABLE because it belongs in the primary key,
        so the table is rebuilt and every existing row lands in generation 1:
        whatever this home already trusted stays trusted, and the next
        deliberate change supersedes it.

        Rebuilding a table is not the same as writing a policy into it. This
        moves rows an operator already trusted, from one shape to another,
        and refuses rather than inventing an ordering it cannot derive.
        """

        tables = {row["name"] for row in _sql(self).execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        columns = {row["name"] for row in _sql(self).execute(
            "PRAGMA table_info(trusted_policies)").fetchall()}
        legacy_exists = "trusted_policies_v4" in tables
        if "generation" in columns and not legacy_exists:
            return
        _sql(self).execute(
            "DROP TRIGGER IF EXISTS trusted_policies_no_update")
        _sql(self).execute(
            "DROP TRIGGER IF EXISTS trusted_policies_no_delete")
        _sql(self).execute("DROP INDEX IF EXISTS trusted_policy_class")
        if not legacy_exists:
            _sql(self).execute(
                "ALTER TABLE trusted_policies RENAME TO trusted_policies_v4")
            _sql(self).execute("""
                CREATE TABLE trusted_policies (
                    repository         TEXT NOT NULL,
                    class_id           TEXT NOT NULL,
                    policy_digest      TEXT NOT NULL,
                    enforcement_digest TEXT NOT NULL,
                    trusted_at         INTEGER NOT NULL,
                    generation         INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (
                        repository, class_id, policy_digest, generation)
                )""")
        elif "generation" not in columns:
            raise sqlite3.DatabaseError(
                "both trusted_policies and trusted_policies_v4 have legacy "
                "shapes; refusing an ambiguous policy migration")
        legacy_columns = {row["name"] for row in _sql(self).execute(
            "PRAGMA table_info(trusted_policies_v4)").fetchall()}
        generation = "generation" if "generation" in legacy_columns else "1"
        joined_generation = (
            "legacy.generation" if "generation" in legacy_columns else "1")
        # Schema 4 had no generation.  If it contains two enforcement shapes
        # for one class there is no historical fact from which to infer which
        # one should be current.  Putting both in generation 1 would make two
        # distinct gates authoritative at once, so refuse instead of inventing
        # ordering during migration.
        if "generation" not in legacy_columns:
            ambiguous = _sql(self).execute(
                "SELECT repository, class_id FROM trusted_policies_v4 "
                "GROUP BY repository, class_id HAVING "
                "COUNT(DISTINCT enforcement_digest) > 1 LIMIT 1").fetchone()
            if ambiguous is not None:
                raise sqlite3.DatabaseError(
                    "legacy trusted policies contain distinct enforcement "
                    "digests with no generation ordering")
        conflict = _sql(self).execute(
            "SELECT 1 FROM trusted_policies_v4 legacy JOIN trusted_policies "
            "current ON current.repository=legacy.repository AND "
            "current.class_id=legacy.class_id AND "
            "current.policy_digest=legacy.policy_digest AND "
            f"current.generation={joined_generation} WHERE "
            "current.enforcement_digest<>legacy.enforcement_digest OR "
            "current.trusted_at<>legacy.trusted_at LIMIT 1").fetchone()
        if conflict is not None:
            raise sqlite3.DatabaseError(
                "stranded and current trusted-policy rows conflict")
        _sql(self).execute(
            "INSERT OR IGNORE INTO trusted_policies(repository, class_id, "
            "policy_digest, enforcement_digest, trusted_at, generation) "
            "SELECT repository, class_id, policy_digest, enforcement_digest, "
            f"trusted_at, {generation} FROM trusted_policies_v4")
        ambiguous_current = _sql(self).execute(
            "SELECT repository, class_id, generation FROM trusted_policies "
            "GROUP BY repository, class_id, generation HAVING "
            "COUNT(DISTINCT enforcement_digest) > 1 LIMIT 1").fetchone()
        if ambiguous_current is not None:
            raise sqlite3.DatabaseError(
                "one trusted-policy generation contains distinct "
                "enforcement digests")
        _sql(self).execute("DROP TABLE trusted_policies_v4")
        _sql(self).execute(
            "CREATE INDEX IF NOT EXISTS trusted_policy_class "
            "ON trusted_policies (repository, class_id, trusted_at)")
        _sql(self).execute(
            "CREATE TRIGGER IF NOT EXISTS trusted_policies_no_update "
            "BEFORE UPDATE ON trusted_policies BEGIN SELECT RAISE(ABORT, "
            "'trusted policies are append-only'); END")
        _sql(self).execute(
            "CREATE TRIGGER IF NOT EXISTS trusted_policies_no_delete "
            "BEFORE DELETE ON trusted_policies BEGIN SELECT RAISE(ABORT, "
            "'trusted policies are append-only'); END")

    def _add_missing_columns(self) -> None:
        """Widen tables an older home already created, never rebuild them."""

        self._migrate_trusted_policies()
        # Schema 6 makes the dependency timestamp a canonical projection of
        # all authentic receipts that bind an edge: the minimum issued_at.
        # A valid older authenticated cut may arrive after a newer one, so the
        # derived timestamp must be allowed to move earlier while every edge
        # identity remains immutable.  Replacing the v5 trigger happens in the
        # same migration transaction as the version bump; a crash cannot leave
        # an existing home without either trigger.
        _sql(self).execute(
            "DROP TRIGGER IF EXISTS dependencies_no_update")
        _sql(self).execute("""
            CREATE TRIGGER dependencies_no_update
            BEFORE UPDATE ON dependencies
            WHEN NEW.consumer_repository <> OLD.consumer_repository
              OR NEW.consumer_commit_sha <> OLD.consumer_commit_sha
              OR NEW.dependency_repository <> OLD.dependency_repository
              OR NEW.dependency_commit_sha <> OLD.dependency_commit_sha
              OR NEW.recorded_at >= OLD.recorded_at
            BEGIN SELECT RAISE(ABORT,
                'dependency identity is append-only and time only moves earlier');
            END
        """)
        for table, column, definition in self._ADDED_COLUMNS:
            present = {row["name"] for row in _sql(self).execute(
                f"PRAGMA table_info({table})").fetchall()}
            if column not in present:
                _sql(self).execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # -- basics ---------------------------------------------------------
    @property
    def home(self) -> Path:
        return self._home

    @property
    def path(self) -> str:
        return str(self._path)

    @property
    def schema_version(self) -> int:
        return self._schema_version

    @property
    def log_dir(self) -> Path:
        return self._home / "logs"

    _READABLE_PRAGMAS = frozenset({
        "journal_mode", "foreign_keys", "busy_timeout", "synchronous",
        "user_version", "page_size",
    })

    def pragma(self, name: str) -> Any:
        """Read one allow-listed pragma. The name is never interpolated blind."""

        if name not in self._READABLE_PRAGMAS:
            raise StoreError(f"pragma {name!r} is not readable through this API")
        return _sql(self).execute(f"PRAGMA {name}").fetchone()[0]

    def close(self) -> None:
        """Give the connection back and forget it; closing twice is harmless."""

        _OPEN_BACKENDS.discard(self)
        connection = _CONNECTIONS.pop(self, None)
        if connection is None:
            return
        try:
            connection.close()
        except sqlite3.Error:
            pass

    # -- transaction plumbing, none of it reachable from outside ---------
    def _begin(self, busy_timeout_ms: int | None) -> None:
        if busy_timeout_ms is not None:
            _sql(self).execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        try:
            _sql(self).execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            raise StoreError(
                "the Admissible database is locked or unavailable, so nothing "
                f"was recorded: {error}") from None

    def _rollback(self) -> None:
        try:
            _sql(self).execute("ROLLBACK")
        except (sqlite3.Error, StoreError):
            pass

    def _reset_busy_timeout(self, busy_timeout_ms: int | None) -> None:
        if busy_timeout_ms is not None:
            _sql(self).execute(
                f"PRAGMA busy_timeout={DEFAULT_BUSY_TIMEOUT_MS}")

    def _transact(self, builder, *, busy_timeout_ms: int | None = None):
        """Run ``builder`` inside one ``BEGIN IMMEDIATE`` transaction.

        Module-private on purpose.  The monolith exported this as ``transact``
        and it was every withheld capability at once: a caller holding it, with
        a connection in reach, could write any row it liked.  Here it has no
        public name and no public caller, and the only thing a ``builder``
        can reach is this backend's own named methods.
        """

        self._begin(busy_timeout_ms)
        try:
            result = builder()
            _sql(self).execute("COMMIT")
        except sqlite3.Error as error:
            self._rollback()
            self._reset_busy_timeout(busy_timeout_ms)
            raise StoreError(f"the durable commit failed: {error}") from None
        except BaseException:
            self._rollback()
            self._reset_busy_timeout(busy_timeout_ms)
            raise
        self._reset_busy_timeout(busy_timeout_ms)
        return result

    @contextlib.contextmanager
    def _atomic(self):
        """One write transaction, or a no-op if the caller already opened one."""

        if _sql(self).in_transaction:
            yield
            return
        _sql(self).execute("BEGIN IMMEDIATE")
        try:
            yield
            # COMMIT is part of the fallible transaction boundary.  A deferred
            # foreign-key violation is reported here, not by the statement that
            # created it; leaving this outside the protected block strands the
            # connection in a live transaction.
            _sql(self).execute("COMMIT")
        except BaseException:
            self._rollback()
            raise

    def _require_write_transaction(self, what: str) -> None:
        """Refuse an attachment write outside the transaction that owns it.

        Every insert below is one half of a two-part fact: a signed head event
        and the row that head authenticates. Writing the row on its own commit
        is how an attachment ends up durable with no signature over it, or a
        signature with no attachment -- both of which an authenticated import
        can only read as a forgery.
        """

        if not _sql(self).in_transaction:
            raise StoreError(
                f"{what} may only be written inside the compare-and-set "
                "transaction that anchors the signed event it belongs to")

    def read_transaction(self, reader):
        """Run ``reader`` inside one consistent read transaction."""

        try:
            _sql(self).execute("BEGIN DEFERRED")
        except sqlite3.Error as error:
            raise StoreError(
                f"cannot open a consistent read of the store: {error}") from None
        try:
            result = reader()
        finally:
            self._rollback()
        return result

    # -- evidence -------------------------------------------------------
    def evidence_for(self, repository: str, commit_sha: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT digest, kind, repository, commit_sha, tree_sha, "
            "policy_digest, record_json FROM evidence "
            "WHERE repository=? AND commit_sha=? ORDER BY digest",
            (repository, commit_sha)).fetchall()
        return tuple({
            "digest": row["digest"], "kind": row["kind"],
            "repository": row["repository"], "commit_sha": row["commit_sha"],
            "tree_sha": row["tree_sha"], "policy_digest": row["policy_digest"],
            "record": json.loads(row["record_json"]),
        } for row in rows)

    def evidence_in(self, repository: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT digest, kind, commit_sha, record_json FROM evidence "
            "WHERE repository=? ORDER BY digest", (repository,)).fetchall()
        return tuple({"digest": row["digest"], "kind": row["kind"],
                      "commit_sha": row["commit_sha"],
                      "record": json.loads(row["record_json"])} for row in rows)

    def evidence_in_attempt(self, attempt_id: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT e.digest, e.kind, e.repository, e.commit_sha, e.tree_sha, "
            "e.policy_digest, e.record_json FROM attempt_evidence a "
            "JOIN evidence e ON e.digest = a.digest "
            "WHERE a.attempt_id=? ORDER BY e.digest", (attempt_id,)).fetchall()
        return tuple({
            "digest": row["digest"], "kind": row["kind"],
            "repository": row["repository"], "commit_sha": row["commit_sha"],
            "tree_sha": row["tree_sha"], "policy_digest": row["policy_digest"],
            "record": json.loads(row["record_json"]),
        } for row in rows)

    def receipt_evidence_row(self, digest: str,
                             repository: str | None = None) -> dict | None:
        """One stored evidence row, exactly as it is written down.

        This is the narrow read receipt issuance needs and no wider: it answers
        with the six columns a receipt binds and the canonical JSON text, so
        the caller can compare what is stored against what it is about to
        attach without being handed a way to run a query of its own.
        """

        if repository is None:
            row = _sql(self).execute(
                "SELECT digest, kind, repository, commit_sha, tree_sha, "
                "policy_digest, record_json FROM evidence WHERE digest=?",
                (digest,)).fetchone()
        else:
            row = _sql(self).execute(
                "SELECT digest, kind, repository, commit_sha, tree_sha, "
                "policy_digest, record_json FROM evidence "
                "WHERE digest=? AND repository=?",
                (digest, repository)).fetchone()
        return None if row is None else dict(row)

    def insert_receipt_evidence(self, *, digest: str, kind: str,
                                repository: str, commit_sha: str,
                                tree_sha: str, policy_digest: str,
                                record_json: str,
                                idempotent: bool = False) -> None:
        """Attach one evidence record a receipt in this transaction binds."""

        self._require_write_transaction("receipt-bound evidence")
        verb = "INSERT OR IGNORE" if idempotent else "INSERT"
        try:
            _sql(self).execute(
                f"{verb} INTO evidence(digest, kind, repository, commit_sha, "
                "tree_sha, policy_digest, record_json) VALUES(?,?,?,?,?,?,?)",
                (digest, kind, repository, commit_sha, tree_sha, policy_digest,
                 record_json))
        except sqlite3.Error as error:
            raise StoreError(
                f"cannot attach receipt-bound evidence: {error}") from None

    # -- journals and heads ---------------------------------------------
    def journal_events(self, journal_id: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT event_json FROM journal_events WHERE journal_id=? "
            "ORDER BY position", (journal_id,)).fetchall()
        return tuple(json.loads(row["event_json"]) for row in rows)

    def current_head(self, journal_id: str) -> fcd_head.HeadReceipt | None:
        row = _sql(self).execute(
            "SELECT r.receipt_json FROM current_head c "
            "JOIN head_receipts r ON r.receipt_hash = c.receipt_hash "
            "WHERE c.journal_id=?", (journal_id,)).fetchone()
        if row is None:
            return None
        return fcd_head.head_receipt_from_dict(json.loads(row["receipt_json"]))

    def accept_head(self, head_receipt: fcd_head.HeadReceipt,
                    events: Sequence[dict], verifier,
                    *, before_extend=None,
                    attachments_builder=None,
                    busy_timeout_ms: int | None = None,
                    _fault: str = "") -> fcd_head.HeadReceipt:
        """Durably accept ``head_receipt`` iff it extends the stored head.

        The predecessor check, extension check, event append, receipt insert
        and current-head compare-and-set all happen inside one ``BEGIN
        IMMEDIATE`` transaction, so concurrent writers serialise instead of
        forking.

        The monolith also took a list of ``(statement, parameters)`` pairs
        here.  That parameter is gone: it was an arbitrary-SQL channel into the
        one transaction that matters, and every caller of it now passes an
        ``attachments_builder`` that can reach nothing but this backend's own
        named authority methods.
        """

        if type(head_receipt) is not fcd_head.HeadReceipt:
            raise StoreError("accept_head needs a fcd.head.HeadReceipt")
        journal_id = head_receipt.journal_id
        plain_events = [json.loads(canonical_json(event)) for event in events]
        # Authenticate and self-check before touching the database at all.
        fcd_head.verify_receipt(head_receipt, verifier)
        computed = fcd_head.compute_journal_head(journal_id, plain_events)
        if (computed.head_digest != head_receipt.head_digest
                or computed.event_count != head_receipt.event_count):
            raise StoreError(
                "proposed head does not match the events it claims to cover")

        self._begin(busy_timeout_ms)
        try:
            current = self.current_head(journal_id)
            # This deliberately precedes even an exact-head idempotency return.
            if before_extend is not None:
                before_extend()
            if (current is not None
                    and current.receipt_hash == head_receipt.receipt_hash):
                self._rollback()
                self._reset_busy_timeout(busy_timeout_ms)
                return current
            self._extend_head_locked(head_receipt, plain_events, _fault=_fault)
            if attachments_builder is not None:
                attachments_builder()
            _sql(self).execute("COMMIT")
        except sqlite3.Error as error:
            self._rollback()
            self._reset_busy_timeout(busy_timeout_ms)
            raise StoreError(f"the durable commit failed: {error}") from None
        except BaseException:
            self._rollback()
            self._reset_busy_timeout(busy_timeout_ms)
            raise
        self._reset_busy_timeout(busy_timeout_ms)
        return head_receipt

    def _extend_head_locked(self, head_receipt: fcd_head.HeadReceipt,
                            plain_events: Sequence[dict], *,
                            _fault: str = "") -> None:
        """Append one legal successor head. Callers hold the write transaction.

        Split out of :meth:`accept_head` so that an import can advance several
        heads and write every attachment inside *one* transaction. A multi-head
        import that committed head by head could be interrupted with the
        earlier heads durable and their attachments missing -- which is exactly
        how an anchored defect would end up invisible and an impeached artefact
        would read as CURRENT.
        """

        journal_id = head_receipt.journal_id
        current = self.current_head(journal_id)
        try:
            # Kernel semantics for a legal successor, evaluated against the
            # durable current head rather than an in-memory registry.
            fcd_head.MonotoneHeadRegistry._validate_next(head_receipt, current)
        except fcd_head.HeadRefused as error:
            raise HeadConflict(
                f"refused: {error}. Re-read the current head and propose "
                "again.") from None
        stored = _sql(self).execute(
            "SELECT COUNT(*) AS total FROM journal_events WHERE journal_id=?",
            (journal_id,)).fetchone()["total"]
        expected_prefix = 0 if current is None else current.event_count
        if stored != expected_prefix:
            raise HeadConflict(
                f"stored journal has {stored} events but the current head "
                f"covers {expected_prefix}; refusing to write")
        for position in range(expected_prefix, head_receipt.event_count):
            event = plain_events[position]
            _sql(self).execute(
                "INSERT INTO journal_events(journal_id, position, "
                "event_json, event_digest) VALUES(?,?,?,?)",
                (journal_id, position, canonical_json(event),
                 _event_digest(event)))
        if _fault == "after_events":
            raise StoreError("injected fault after appending events")
        _sql(self).execute(
            "INSERT INTO head_receipts(receipt_hash, journal_id, "
            "event_count, previous_receipt_hash, receipt_json) "
            "VALUES(?,?,?,?,?)",
            (head_receipt.receipt_hash, journal_id,
             head_receipt.event_count, head_receipt.previous_receipt_hash,
             canonical_json(fcd_head.head_receipt_to_dict(head_receipt))))
        if current is None:
            _sql(self).execute(
                "INSERT INTO current_head(journal_id, receipt_hash) "
                "VALUES(?,?)", (journal_id, head_receipt.receipt_hash))
        else:
            cursor = _sql(self).execute(
                "UPDATE current_head SET receipt_hash=? "
                "WHERE journal_id=? AND receipt_hash=?",
                (head_receipt.receipt_hash, journal_id,
                 current.receipt_hash))
            if cursor.rowcount != 1:
                raise HeadConflict(
                    "the current head changed while committing; nothing "
                    "was written")

    def verify_journal(self, journal_id: str, verifier) -> bool:
        """Verify the stored events against the signed current head."""

        current = self.current_head(journal_id)
        if current is None:
            raise StoreError(f"journal {journal_id!r} has no current head")
        events = self.journal_events(journal_id)
        try:
            fcd_head.verify_receipt(current, verifier)
        except fcd_head.HeadVerificationError:
            raise StoreError(
                f"the current head of {journal_id!r} is not authentic") from None
        computed = fcd_head.compute_journal_head(journal_id, list(events))
        if (computed.head_digest != current.head_digest
                or computed.event_count != current.event_count):
            raise StoreError(
                f"stored events of {journal_id!r} do not match the signed head")
        return True

    def has_head_receipt(self, receipt_hash: str) -> bool:
        return _sql(self).execute(
            "SELECT 1 FROM head_receipts WHERE receipt_hash=?",
            (receipt_hash,)).fetchone() is not None

    def head_receipt_chain(self, journal_id: str) -> tuple[fcd_head.HeadReceipt, ...]:
        rows = _sql(self).execute(
            "SELECT receipt_json FROM head_receipts WHERE journal_id=? "
            "ORDER BY event_count", (journal_id,)).fetchall()
        return tuple(
            fcd_head.head_receipt_from_dict(json.loads(row["receipt_json"]))
            for row in rows)

    # -- workflow receipts ----------------------------------------------
    def workflow_receipt(self, receipt_hash: str):
        row = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts WHERE receipt_hash=?",
            (receipt_hash,)).fetchone()
        if row is None:
            return None
        return receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))

    def workflow_receipt_by_body(self, body_digest: str):
        row = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts WHERE body_digest=?",
            (body_digest,)).fetchone()
        if row is None:
            return None
        return receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))

    def receipts_for(self, repository: str, commit_sha: str) -> tuple:
        rows = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts "
            "WHERE repository=? AND commit_sha=? ORDER BY issued_at, receipt_hash",
            (repository, commit_sha)).fetchall()
        return tuple(
            receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))
            for row in rows)

    def receipts_in(self, repository: str) -> tuple:
        rows = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts WHERE repository=? "
            "ORDER BY issued_at, receipt_hash", (repository,)).fetchall()
        return tuple(
            receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))
            for row in rows)

    def receipts_in_journal(self, journal_id: str) -> tuple:
        rows = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts WHERE journal_id=? "
            "ORDER BY issued_at, receipt_hash", (journal_id,)).fetchall()
        return tuple(
            receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))
            for row in rows)

    def receipt_count(self, repository: str) -> int:
        return _sql(self).execute(
            "SELECT COUNT(*) AS total FROM workflow_receipts WHERE repository=?",
            (repository,)).fetchone()["total"]

    def latest_receipt(self, repository: str):
        row = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts WHERE repository=? "
            "ORDER BY issued_at DESC, receipt_hash DESC LIMIT 1",
            (repository,)).fetchone()
        if row is None:
            return None
        return receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))

    def insert_workflow_receipt(self, receipt, *,
                                idempotent: bool = False) -> None:
        """Store ``receipt`` inside the head commit that anchors it.

        The default is a plain ``INSERT``: inside the compare-and-set
        transaction a conflicting row means two different receipts claim one
        identity, and that must abort rather than vanish. ``idempotent`` is for
        replaying an already-authenticated chain during import.

        The monolith returned the statement and let the caller run it. That is
        the same write with an arbitrary-SQL channel attached; here the caller
        hands over a receipt and this method decides what a receipt row is.
        """

        self._require_write_transaction("a workflow receipt row")
        document = receiptdata.receipt_to_dict(receipt)
        verb = "INSERT OR IGNORE" if idempotent else "INSERT"
        try:
            _sql(self).execute(
                f"{verb} INTO workflow_receipts(receipt_hash, body_digest, "
                "journal_id, repository, commit_sha, tree_sha, policy_digest, "
                "class_id, state, issued_at, receipt_json, head_receipt_hash) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (receipt.receipt_hash, receipt.body_digest, receipt.journal_id,
                 receipt.repository, receipt.commit_sha, receipt.tree_sha,
                 receipt.policy_digest, receipt.class_id, receipt.state,
                 receipt.issued_at, canonical_json(document),
                 receipt.head.receipt_hash))
        except sqlite3.Error as error:
            raise StoreError(f"cannot store this receipt: {error}") from None

    # -- defects ---------------------------------------------------------
    def insert_defect(self, *, digest: str, defect_id: str, repository: str,
                      commit_sha: str, filed_at: int, record: dict,
                      idempotent: bool = False) -> None:
        """Store one defect inside the transaction that signs its event.

        The default is a plain ``INSERT``. Inside the compare-and-set
        transaction a conflicting row means a second signed event is being
        appended for a defect that is already recorded, and that must abort:
        ``INSERT OR IGNORE`` there produced two events for one record, which
        import can only read as a forgery. ``idempotent`` is for replaying an
        already-authenticated chain during import.
        """

        self._require_write_transaction("a defect row")
        verb = "INSERT OR IGNORE" if idempotent else "INSERT"
        try:
            _sql(self).execute(
                f"{verb} INTO defects(defect_id, repository, commit_sha, "
                "digest, filed_at, record_json) VALUES(?,?,?,?,?,?)",
                (defect_id, repository, commit_sha, digest, filed_at,
                 canonical_json(record)))
        except sqlite3.Error as error:
            raise StoreError(f"cannot file this defect: {error}") from None

    def defect_row(self, digest: str) -> dict | None:
        """One stored defect row, as written, for a correspondence check."""

        row = _sql(self).execute(
            "SELECT digest, defect_id, repository, commit_sha, filed_at, "
            "record_json FROM defects WHERE digest=?", (digest,)).fetchone()
        return None if row is None else dict(row)

    def defect_rows(self, repository: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT digest, defect_id, commit_sha, filed_at, record_json "
            "FROM defects WHERE repository=? ORDER BY filed_at, digest",
            (repository,)).fetchall()
        return tuple(dict(row) for row in rows)

    def has_defect(self, digest: str) -> bool:
        return _sql(self).execute(
            "SELECT 1 FROM defects WHERE digest=?",
            (digest,)).fetchone() is not None

    def defect_event_count(self, journal_id: str, digest: str) -> int:
        """Count signed-event claims for one defect in the current snapshot."""

        return sum(
            1 for event in self.journal_events(journal_id)
            if type(event) is dict
            and event.get("type") == receiptdata.EVENT_DEFECT
            and event.get("defect_digest") == digest)

    def defect_shas(self, repository: str) -> frozenset[str]:
        rows = _sql(self).execute(
            "SELECT DISTINCT commit_sha FROM defects WHERE repository=?",
            (repository,)).fetchall()
        return frozenset(row["commit_sha"] for row in rows)

    def defects_for(self, repository: str, commit_sha: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT record_json, filed_at FROM defects WHERE repository=? AND "
            "commit_sha=? ORDER BY filed_at, digest", (repository, commit_sha)
        ).fetchall()
        return tuple(json.loads(row["record_json"]) for row in rows)

    def defect_count(self, repository: str) -> int:
        return _sql(self).execute(
            "SELECT COUNT(*) AS total FROM defects WHERE repository=?",
            (repository,)).fetchone()["total"]

    def all_defects(self, repository: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT record_json FROM defects WHERE repository=? "
            "ORDER BY filed_at, digest", (repository,)).fetchall()
        return tuple(json.loads(row["record_json"]) for row in rows)

    # -- dependencies -----------------------------------------------------
    def put_dependency(self, *, consumer_repository: str,
                       consumer_commit_sha: str, dependency_repository: str,
                       dependency_commit_sha: str, recorded_at: int) -> bool:
        try:
            cursor = _sql(self).execute(
                "INSERT OR IGNORE INTO dependencies(consumer_repository, "
                "consumer_commit_sha, dependency_repository, "
                "dependency_commit_sha, recorded_at) VALUES(?,?,?,?,?)",
                (consumer_repository, consumer_commit_sha,
                 dependency_repository, dependency_commit_sha, recorded_at))
        except sqlite3.Error as error:
            raise StoreError(f"cannot record dependency: {error}") from None
        return cursor.rowcount == 1

    def insert_dependency_edge(self, *, consumer_repository: str,
                               consumer_commit_sha: str,
                               dependency_repository: str,
                               dependency_commit_sha: str,
                               recorded_at: int) -> None:
        """Attach one receipt-bound dependency edge inside its transaction."""

        self._require_write_transaction("a dependency attachment")
        try:
            _sql(self).execute(
                "INSERT OR IGNORE INTO dependencies(consumer_repository, "
                "consumer_commit_sha, dependency_repository, "
                "dependency_commit_sha, recorded_at) VALUES(?,?,?,?,?)",
                (consumer_repository, consumer_commit_sha,
                 dependency_repository, dependency_commit_sha, recorded_at))
        except sqlite3.Error as error:
            raise StoreError(
                f"cannot attach this dependency edge: {error}") from None

    def lower_dependency_recorded_at(self, *, consumer_repository: str,
                                     consumer_commit_sha: str,
                                     dependency_repository: str,
                                     dependency_commit_sha: str,
                                     recorded_at: int,
                                     previous_recorded_at: int) -> None:
        """Move one derived edge timestamp earlier, and only earlier.

        Dependency rows are a projection of the authentic receipt bodies that
        bind an edge, not an authority of their own: canonical time is the
        minimum ``issued_at``, and a valid older signed cut can arrive after a
        newer one. The schema's trigger permits exactly this lowering and
        refuses every identity change; the guard here refuses a raise, so the
        one direction this method exists for is the only one it can take.
        """

        self._require_write_transaction("a dependency timestamp correction")
        if recorded_at >= previous_recorded_at:
            raise StoreError(
                "a derived dependency timestamp may only move earlier; "
                "nothing was written")
        try:
            _sql(self).execute(
                "UPDATE dependencies SET recorded_at=? WHERE "
                "consumer_repository=? AND consumer_commit_sha=? AND "
                "dependency_repository=? AND dependency_commit_sha=? "
                "AND recorded_at=?",
                (recorded_at, consumer_repository, consumer_commit_sha,
                 dependency_repository, dependency_commit_sha,
                 previous_recorded_at))
        except sqlite3.Error as error:
            raise StoreError(
                f"cannot correct this dependency edge: {error}") from None

    def dependency_recorded_at(self, *, consumer_repository: str,
                               consumer_commit_sha: str,
                               dependency_repository: str,
                               dependency_commit_sha: str) -> int | None:
        row = _sql(self).execute(
            "SELECT recorded_at FROM dependencies WHERE "
            "consumer_repository=? AND consumer_commit_sha=? AND "
            "dependency_repository=? AND dependency_commit_sha=?",
            (consumer_repository, consumer_commit_sha, dependency_repository,
             dependency_commit_sha)).fetchone()
        return None if row is None else row["recorded_at"]

    def consumer_dependency_rows(self, consumer_repository: str,
                                 consumer_commit_sha: str | None = None
                                 ) -> dict[tuple[str, str, str, str], int]:
        """Every edge one consumer declares, as ``edge -> recorded_at``.

        The whole namespace, not only the edges a caller expects, because an
        unrelated unsigned row beside an authentic receipt is exactly what
        authenticated standing refuses -- and issuance must not report ADMITTED
        from a namespace its own verifier would call UNKNOWN.
        """

        if consumer_commit_sha is None:
            rows = _sql(self).execute(
                "SELECT consumer_repository, consumer_commit_sha, "
                "dependency_repository, dependency_commit_sha, recorded_at "
                "FROM dependencies WHERE consumer_repository=?",
                (consumer_repository,)).fetchall()
        else:
            rows = _sql(self).execute(
                "SELECT consumer_repository, consumer_commit_sha, "
                "dependency_repository, dependency_commit_sha, recorded_at "
                "FROM dependencies WHERE consumer_repository=? AND "
                "consumer_commit_sha=?",
                (consumer_repository, consumer_commit_sha)).fetchall()
        return {(row["consumer_repository"], row["consumer_commit_sha"],
                 row["dependency_repository"], row["dependency_commit_sha"]):
                row["recorded_at"] for row in rows}

    def direct_consumers(self, repository: str,
                         commit_sha: str) -> tuple[tuple[str, str], ...]:
        rows = _sql(self).execute(
            "SELECT consumer_repository, consumer_commit_sha FROM dependencies "
            "WHERE dependency_repository=? AND dependency_commit_sha=? "
            "ORDER BY consumer_repository, consumer_commit_sha",
            (repository, commit_sha)).fetchall()
        return tuple((row["consumer_repository"], row["consumer_commit_sha"])
                     for row in rows)

    # -- attempts, read only ----------------------------------------------
    def latest_attempt(self, repository: str, commit_sha: str) -> dict | None:
        row = _sql(self).execute(
            "SELECT attempt_id, class_id, policy_digest, state, started_at, "
            "tree_sha, decision_json FROM attempts "
            "WHERE repository=? AND commit_sha=? "
            "ORDER BY started_at DESC, rowid DESC LIMIT 1",
            (repository, commit_sha)).fetchone()
        return None if row is None else self._attempt_row(row)

    def attempt(self, attempt_id: str) -> dict | None:
        row = _sql(self).execute(
            "SELECT attempt_id, repository, commit_sha, class_id, "
            "policy_digest, state, started_at, tree_sha, decision_json "
            "FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
        return None if row is None else self._attempt_row(row)

    @staticmethod
    def _attempt_row(row) -> dict:
        found = dict(row)
        raw = found.pop("decision_json", "")
        try:
            found["decision"] = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            found["decision"] = None
        return found

    # -- the trusted-policy baseline --------------------------------------
    def _policy_generation_locked(self, repository: str, class_id: str) -> int:
        row = _sql(self).execute(
            "SELECT MAX(generation) AS current FROM trusted_policies "
            "WHERE repository=? AND class_id=?",
            (repository, class_id)).fetchone()
        return 0 if row is None or row["current"] is None else int(
            row["current"])

    def policy_generation(self, repository: str, class_id: str) -> int:
        """The newest generation, read under the policy write lock."""

        try:
            with self._atomic():
                return self._policy_generation_locked(repository, class_id)
        except sqlite3.Error as error:
            raise StoreError(
                f"cannot read this policy generation: {error}") from None

    def _revoked_policies_locked(self, repository: str, class_id: str,
                                 generation: int) -> frozenset[str]:
        rows = _sql(self).execute(
            "SELECT policy_digest FROM policy_revocations WHERE repository=? "
            "AND class_id=? AND generation=?",
            (repository, class_id, generation)).fetchall()
        return frozenset(row["policy_digest"] for row in rows)

    def trust_policy(self, *, repository: str, class_id: str,
                     policy_digest: str, enforcement_digest: str,
                     trusted_at: int) -> bool:
        """Record that an operator deliberately made this policy enforceable.

        A policy that enforces something the current generation does not opens
        the **next** generation, and everything before it stops being an
        authority for this class. That is what makes an upgrade an upgrade: a
        class raised from no reviews to two does not leave the zero-review
        digest sitting in the baseline where reverting one file restores it.

        A policy that enforces exactly what this generation already enforces --
        the same checks, counts and key ids, different prose -- joins that
        generation instead. Nothing about the gate changed, so nothing about
        which generation is current should.
        """

        try:
            with self._atomic():
                current = self._policy_generation_locked(repository, class_id)
                revoked = self._revoked_policies_locked(
                    repository, class_id, current)
                same_enforcement = _sql(self).execute(
                    "SELECT 1 FROM trusted_policies WHERE repository=? AND "
                    "class_id=? AND generation=? AND enforcement_digest=? "
                    "LIMIT 1",
                    (repository, class_id, current,
                     enforcement_digest)).fetchone()
                # Re-trust is an append-only act.  A revocation in generation
                # N cannot be undone by colliding with the old row in N; the
                # deliberate re-trust opens N+1.
                generation = (
                    current + 1
                    if policy_digest in revoked or same_enforcement is None
                    else current)
                cursor = _sql(self).execute(
                    "INSERT OR IGNORE INTO trusted_policies(repository, "
                    "class_id, policy_digest, enforcement_digest, trusted_at, "
                    "generation) VALUES(?,?,?,?,?,?)",
                    (repository, class_id, policy_digest, enforcement_digest,
                     trusted_at, generation))
        except sqlite3.Error as error:
            raise StoreError(f"cannot trust this policy: {error}") from None
        return cursor.rowcount == 1

    def revoke_policy(self, *, repository: str, class_id: str,
                      policy_digest: str, revoked_at: int) -> bool:
        """Withdraw one trusted policy without rewriting the record of it."""

        try:
            with self._atomic():
                generation = self._policy_generation_locked(
                    repository, class_id)
                cursor = _sql(self).execute(
                    "INSERT OR IGNORE INTO policy_revocations(repository, "
                    "class_id, policy_digest, generation, revoked_at) "
                    "VALUES(?,?,?,?,?)",
                    (repository, class_id, policy_digest, generation,
                     revoked_at))
        except sqlite3.Error as error:
            raise StoreError(f"cannot revoke this policy: {error}") from None
        return cursor.rowcount == 1

    def revoked_policies(self, repository: str, class_id: str, *,
                         generation: int | None = None) -> frozenset[str]:
        """The digests withdrawn in one generation, the current one by default."""

        try:
            with self._atomic():
                current = (self._policy_generation_locked(repository, class_id)
                           if generation is None else generation)
                return self._revoked_policies_locked(
                    repository, class_id, current)
        except sqlite3.Error as error:
            raise StoreError(
                f"cannot read revoked policies: {error}") from None

    def trusted_policies(self, repository: str, class_id: str, *,
                         include_superseded: bool = False) -> tuple[dict, ...]:
        """The policies that are enforceable for one class right now.

        Only the current generation, and only what has not been revoked. The
        history is still here -- pass ``include_superseded`` to read it -- but
        history is not authority: an entry that was trusted before the class
        was tightened describes what this home used to accept, and answering
        "may this policy enforce?" from it is how a tightened gate gets rolled
        back by editing one file.
        """

        try:
            with self._atomic():
                if include_superseded:
                    rows = _sql(self).execute(
                        "SELECT policy_digest, enforcement_digest, trusted_at, "
                        "generation FROM trusted_policies WHERE repository=? "
                        "AND class_id=? ORDER BY generation, trusted_at, "
                        "policy_digest", (repository, class_id)).fetchall()
                    return tuple(dict(row) for row in rows)
                current = self._policy_generation_locked(repository, class_id)
                if not current:
                    return ()
                revoked = self._revoked_policies_locked(
                    repository, class_id, current)
                rows = _sql(self).execute(
                    "SELECT policy_digest, enforcement_digest, trusted_at, "
                    "generation FROM trusted_policies WHERE repository=? AND "
                    "class_id=? AND generation=? ORDER BY trusted_at, "
                    "policy_digest",
                    (repository, class_id, current)).fetchall()
                if len({row["enforcement_digest"] for row in rows}) > 1:
                    raise StoreError(
                        "current trusted-policy generation contains distinct "
                        "enforcement digests")
                return tuple(dict(row) for row in rows
                             if row["policy_digest"] not in revoked)
        except sqlite3.Error as error:
            raise StoreError(f"cannot read trusted policies: {error}") from None

    # -- issuance preflight -----------------------------------------------
    def has_repository_authority(self, journal_id: str,
                                 repository: str) -> bool:
        """Whether any signed artefact exists for a journal with no head.

        Journal events, head receipts, workflow receipts and defects are all
        things a current head should account for. Finding one when there is no
        current head means the repository's authenticated history is not one
        exact namespace, and no receipt may be issued into it.
        """

        for query, parameters in (
                ("SELECT 1 FROM journal_events WHERE journal_id=? LIMIT 1",
                 (journal_id,)),
                ("SELECT 1 FROM head_receipts WHERE journal_id=? LIMIT 1",
                 (journal_id,)),
                ("SELECT 1 FROM workflow_receipts WHERE repository=? LIMIT 1",
                 (repository,)),
                ("SELECT 1 FROM defects WHERE repository=? LIMIT 1",
                 (repository,))):
            if _sql(self).execute(query, parameters).fetchone() is not None:
                return True
        return False

    # -- export / import ---------------------------------------------------
    def export_journal(self, journal_id: str, *,
                       through_head: str | None = None) -> dict:
        """Export the events, the signed head chain, and what they authenticate.

        The export carries no key material and no raw logs: receipts, evidence
        records and defects are all digest-shaped documents.

        Everything is read inside one transaction. Separate reads could observe
        two generations of a journal that another writer was extending between
        them, and produce a bundle whose events, heads and attachments never
        coexisted -- an export its own importer would then reject.

        Repositories are discovered from the *signed events*, not only from the
        workflow receipts. A journal that carries nothing but defect events is
        a supported shape; discovering its repository through receipts it does
        not have would export the signed impeachment with none of the records
        that explain it.
        """

        return self.read_transaction(
            lambda: self._export_journal(journal_id,
                                         through_head=through_head))

    def _export_journal(self, journal_id: str, *,
                        through_head: str | None = None,
                        _enforce_transfer_limit: bool = True) -> dict:
        current = self.current_head(journal_id)
        if current is None:
            raise StoreError(f"journal {journal_id!r} has no current head")
        chain = self.head_receipt_chain(journal_id)
        selected = current
        if (through_head is None and (not chain
                or chain[-1].receipt_hash != current.receipt_hash)):
            raise StoreError(
                "current head is not the unique end of its stored head chain")
        if through_head is not None:
            if type(through_head) is not str:
                raise StoreError("through_head must be a receipt hash")
            matches = [item for item in chain
                       if item.receipt_hash == through_head]
            if len(matches) != 1:
                raise StoreError(
                    "through_head must identify exactly one stored head")
            selected = matches[0]
        chain = tuple(item for item in chain
                      if item.event_count <= selected.event_count)
        events = [json.loads(canonical_json(event)) for event in
                  self.journal_events(journal_id)[:selected.event_count]]
        known_heads = {item.receipt_hash for item in chain}
        receipts = tuple(
            item for item in self.receipts_in_journal(journal_id)
            if item.head.receipt_hash in known_heads)
        repositories = sorted(
            {item.repository for item in receipts}
            | {event["repository"] for event in events
               if type(event) is dict and type(event.get("repository")) is str})
        # Only evidence a signed receipt actually binds travels. An array with
        # no signed correspondence is unverifiable on the far side, so it is
        # not exported and, on import, not accepted.
        anchored = {digest for item in receipts
                    for digest in item.evidence_digests}
        anchored_defects = {
            event.get("defect_digest") for event in events
            if type(event) is dict
            and event.get("type") == receiptdata.EVENT_DEFECT}
        evidence: list[dict] = []
        defects: list[dict] = []
        for repository in repositories:
            for row in self.evidence_in(repository):
                if row["digest"] not in anchored:
                    continue
                evidence.append({"digest": row["digest"], "kind": row["kind"],
                                 "record": row["record"]})
            for defect in self.all_defects(repository):
                if evidence_module.evidence_digest(
                        evidence_module.defect_from_dict(defect)) in anchored_defects:
                    defects.append(defect)
        bundle = {
            "schema": JOURNAL_EXPORT_SCHEMA,
            "journal_id": journal_id,
            "events": events,
            "receipts": [fcd_head.head_receipt_to_dict(item)
                         for item in chain],
            "workflow_receipts": [receiptdata.receipt_to_dict(item)
                                  for item in receipts],
            "evidence": evidence,
            "defects": defects,
        }
        if _enforce_transfer_limit:
            self._ensure_export_size(bundle)
        return bundle

    def authenticated_repository_projection(self, repository: str,
                                            verifier) -> dict:
        """Validate one workflow namespace without trusting a bare SQL row.

        The caller owns a consistent read transaction.  The returned objects
        are the only rows standing may treat as authority: complete signed head
        chain, one admission row per admission event, exact receipt-bound
        evidence, one defect row per defect event, and dependency rows exactly
        reconstructed from signed receipt bodies.
        """

        journal_id = receiptdata.journal_id_for(repository)
        # The 64 MiB ceiling is a hostile-input and single-file transfer
        # boundary, not a limit on how much authentic local history may exist.
        # This projection already reads from the local database inside one
        # consistent transaction, so applying the transport ceiling here would
        # turn a valid CURRENT namespace into UNKNOWN merely as it grows.
        bundle = self._export_journal(
            journal_id, _enforce_transfer_limit=False)
        parsed_journal, events, heads = self._parse_export(
            bundle, _enforce_transfer_limit=False)
        if parsed_journal != journal_id:
            raise StoreError("workflow projection names a different journal")
        self._authenticate_export(journal_id, events, heads, verifier)
        known_heads = {item.receipt_hash for item in heads}

        defect_events: Counter = Counter()
        defect_event_rows: dict[str, dict] = {}
        admission_events: Counter = Counter()
        for event in events:
            if type(event) is not dict:
                continue
            event_type = event.get("type")
            if event_type == receiptdata.EVENT_DEFECT:
                digest = event.get("defect_digest")
                if (type(digest) is not str
                        or event.get("repository") != repository
                        or type(event.get("filed_at")) is not int
                        or event["filed_at"] < 0):
                    raise StoreError("malformed signed defect event")
                defect_events[digest] += 1
                defect_event_rows[digest] = event
            elif event_type == receiptdata.EVENT_WORKFLOW_ADMISSION:
                digest = event.get("body_digest")
                if (type(digest) is not str
                        or event.get("repository") != repository):
                    raise StoreError("malformed signed admission event")
                admission_events[digest] += 1
        if any(total != 1 for total in defect_events.values()) \
                or any(total != 1 for total in admission_events.values()):
            raise StoreError(
                "signed workflow events do not have exact multiplicity")

        receipts = self.receipts_in_journal(journal_id)
        supplied_admissions: set[str] = set()
        bound_evidence: set[str] = set()
        review_attributions: set[tuple[str, str]] = set()
        expected_dependency_times: dict[
            tuple[str, str, str, str], int] = {}
        for item in receipts:
            try:
                receiptdata.verify_receipt(item, verifier)
            except (receiptdata.ReceiptError, ValueError) as error:
                raise StoreError(
                    f"stored workflow receipt is not authentic: {error}"
                ) from None
            if (item.repository != repository
                    or item.journal_id != journal_id
                    or item.head.receipt_hash not in known_heads
                    or item.body_digest not in admission_events
                    or item.body_digest in supplied_admissions):
                raise StoreError(
                    "stored workflow receipt has no unique signed event")
            if len(item.evidence_digests) != len(set(item.evidence_digests)):
                raise StoreError("stored receipt repeats an evidence digest")
            if len(item.dependencies) != len(set(item.dependencies)):
                raise StoreError("stored receipt repeats a dependency")
            if len(item.authenticated_reviews) != len(
                    set(item.authenticated_reviews)):
                raise StoreError("stored receipt repeats reviewer attribution")
            if any(digest not in item.evidence_digests
                   for digest, _key_id in item.authenticated_reviews):
                raise StoreError(
                    "stored reviewer attribution is not receipt-bound")
            supplied_admissions.add(item.body_digest)
            bound_evidence.update(item.evidence_digests)
            review_attributions.update(item.authenticated_reviews)
            for dependency_repository, dependency_sha in item.dependencies:
                edge = (item.repository, item.commit_sha,
                        dependency_repository, dependency_sha)
                expected_dependency_times[edge] = min(
                    item.issued_at,
                    expected_dependency_times.get(edge, item.issued_at))
        if supplied_admissions != set(admission_events):
            raise StoreError(
                "signed admissions and stored receipt rows are not a "
                "bijection")

        # Evidence recorded by an evaluation attempt is history, not a receipt
        # attachment. It confers no standing authority and a later attempt must
        # not impeach an earlier authentic admission merely by existing. Read
        # only the digests the signed receipts bind, and require every one of
        # those attachments to resolve exactly once. Unbound rows are ignored,
        # never projected as authority.
        evidence_rows: dict[str, dict] = {}
        for digest in sorted(bound_evidence):
            row = self.receipt_evidence_row(digest, repository)
            if row is None or digest in evidence_rows:
                raise StoreError(
                    "stored evidence and signed receipt digests are not exact")
            try:
                record = json.loads(row["record_json"])
            except (TypeError, ValueError) as error:
                raise StoreError(
                    f"stored evidence JSON is invalid: {error}") from None
            evidence_rows[digest] = {
                "digest": row["digest"], "kind": row["kind"],
                "record": record,
            }
        parsed_evidence: dict[str, dict] = {}
        for digest, row in evidence_rows.items():
            if type(row) is not dict or set(row) != {
                    "digest", "kind", "record"}:
                raise StoreError("stored evidence row is not closed")
            record = row["record"]
            try:
                if row["kind"] == "command":
                    parsed = evidence_module.command_evidence_from_dict(record)
                elif row["kind"] == "review":
                    parsed = evidence_module.review_evidence_from_dict(record)
                elif row["kind"] == "authorship":
                    parsed = evidence_module.authorship_evidence_from_dict(record)
                else:
                    raise StoreError("stored evidence has an unknown kind")
            except evidence_module.EvidenceError as error:
                raise StoreError(f"stored evidence is invalid: {error}") from None
            if evidence_module.evidence_digest(parsed) != digest:
                raise StoreError("stored evidence does not match its digest")
            binders = [item for item in receipts
                       if digest in item.evidence_digests]
            if not binders or any(
                    parsed.repository != item.repository
                    or parsed.commit_sha != item.commit_sha
                    or parsed.tree_sha != item.tree_sha
                    or parsed.policy_digest != item.policy_digest
                    for item in binders):
                raise StoreError(
                    "stored evidence identity does not match its signed "
                    "receipt")
            parsed_evidence[digest] = {
                "kind": row["kind"], "record": parsed,
                "document": record,
            }
        for digest, _key_id in review_attributions:
            row = parsed_evidence.get(digest)
            if (row is None or row["kind"] != "review"
                    or row["record"].verdict != "approve"):
                raise StoreError(
                    "reviewer attribution lacks a receipt-bound approving "
                    "review")

        defects: list[dict] = []
        supplied_defects: set[str] = set()
        for row in self.defect_rows(repository):
            try:
                document = json.loads(row["record_json"])
            except (TypeError, ValueError) as error:
                raise StoreError(f"stored defect JSON is invalid: {error}") from None
            try:
                parsed = evidence_module.defect_from_dict(document)
            except evidence_module.EvidenceError as error:
                raise StoreError(f"stored defect is invalid: {error}") from None
            digest = evidence_module.evidence_digest(parsed)
            signed_event = defect_event_rows.get(digest)
            if (parsed.repository != repository
                    or row["digest"] != digest
                    or row["defect_id"] != parsed.defect_id
                    or row["commit_sha"] != parsed.commit_sha
                    or digest in supplied_defects):
                raise StoreError("stored defect is duplicated or mis-scoped")
            if (signed_event is None
                    or row["filed_at"] != signed_event["filed_at"]
                    or signed_event.get("defect_id") != parsed.defect_id
                    or signed_event.get("repository") != parsed.repository
                    or signed_event.get("commit_sha") != parsed.commit_sha
                    or signed_event.get("severity") != parsed.severity
                    or signed_event.get("discovered_at")
                    != parsed.discovered_at):
                raise StoreError(
                    "stored defect metadata does not match its signed event")
            supplied_defects.add(digest)
            defects.append(document)
        if supplied_defects != set(defect_events):
            raise StoreError(
                "signed defect events and stored defect rows are not a "
                "bijection")

        stored_dependency_times = self.consumer_dependency_rows(repository)
        if stored_dependency_times != expected_dependency_times:
            raise StoreError(
                "stored dependencies are not exactly receipt-bound")
        return {
            "receipts": tuple(receipts),
            "defects": tuple(defects),
            "evidence": parsed_evidence,
            "dependencies": frozenset(expected_dependency_times),
        }

    def authenticated_workflow_state(self, verifier) -> tuple[dict, frozenset]:
        """Return authenticated standing inputs from one consistent snapshot.

        A corrupt namespace is named in the second return value and contributes
        no authority.  This keeps an unrelated damaged repository from hiding
        valid state while still making the damaged repository fail closed.
        """

        if verifier is None:
            return {}, frozenset()

        def read():
            prefix = receiptdata.JOURNAL_PREFIX + "/"
            repositories = {
                row["journal_id"][len(prefix):]
                for row in _sql(self).execute(
                    "SELECT journal_id FROM current_head WHERE "
                    "journal_id LIKE ?", (prefix + "%",)).fetchall()
                if row["journal_id"].startswith(prefix)}
            for query, key in (
                    ("SELECT DISTINCT repository FROM workflow_receipts",
                     "repository"),
                    ("SELECT DISTINCT repository FROM defects", "repository"),
                    ("SELECT DISTINCT consumer_repository FROM dependencies",
                     "consumer_repository")):
                repositories.update(
                    row[key] for row in _sql(self).execute(query).fetchall())
            projections: dict[str, dict] = {}
            invalid: set[str] = set()
            for repository in sorted(repositories):
                try:
                    projections[repository] = \
                        self.authenticated_repository_projection(
                            repository, verifier)
                except (StoreError, receiptdata.ReceiptError,
                        evidence_module.EvidenceError, sqlite3.Error,
                        TypeError, ValueError) as error:
                    invalid.add(repository)
                    try:
                        # Diagnostic claims travel in the same snapshot, but
                        # the invalid marker ensures none can become authority.
                        claims = self.receipts_in(repository)
                    except (receiptdata.ReceiptError, TypeError, ValueError):
                        claims = ()
                    authentic, rejected = [], []
                    for claim in claims:
                        try:
                            receiptdata.verify_receipt(claim, verifier)
                        except (receiptdata.ReceiptError, ValueError):
                            rejected.append(claim)
                        else:
                            authentic.append(claim)
                    projections[repository] = {
                        "historical_claims": tuple(authentic),
                        "unauthenticated_claims": tuple(rejected),
                        "integrity_error": str(error),
                    }
            return projections, frozenset(invalid)

        return self.read_transaction(read)

    def _import_attachments(self, bundle: dict, journal_id: str,
                            verifier) -> None:
        """Insert what the imported heads authenticate, refusing forgery.

        Both directions of every correspondence are checked, never one. A
        one-way check lets an omission through, and an omission is the quiet
        forgery: dropping an anchored defect erases an impeachment and restores
        CURRENT; dropping a receipt for a signed admission leaves an admission
        nobody can read; dropping a receipt's evidence leaves an artefact that
        is CURRENT on the strength of records that are not here.

        So each of these is a bijection, and a missing *or* extra member on
        either side is a refusal:

        * signed admission event  <->  workflow receipt (by body digest);
        * workflow receipt        <->  the evidence digests its body binds;
        * signed defect event     <->  defect record.

        A bijection is counted, never set-compared. Collapsing the events into
        a set was the quiet version of the same forgery an omission is: two
        signed events for one record would read as one event for one record,
        and the second event -- appended by a writer that lost a race and whose
        row was then dropped -- would become invisible history.

        Dependency edges come from the signed receipt body, so they are rebuilt
        rather than carried: without them, impeachment reachability would
        silently disappear the moment a journal moved machines.
        """

        events = bundle["events"]
        known_heads = {item["receipt_hash"] for item in bundle["receipts"]}
        for event in events:
            if type(event) is not dict:
                continue
            if (event.get("type") == receiptdata.EVENT_DEFECT
                    and type(event.get("defect_digest")) is not str):
                raise StoreError(
                    "a signed defect event must name exactly one digest")
            if (event.get("type") == receiptdata.EVENT_WORKFLOW_ADMISSION
                    and type(event.get("body_digest")) is not str):
                raise StoreError(
                    "a signed admission event must name exactly one digest")
        defect_events = Counter(
            event.get("defect_digest") for event in events
            if type(event) is dict
            and event.get("type") == receiptdata.EVENT_DEFECT
            and event.get("defect_digest") is not None)
        admission_events = Counter(
            event.get("body_digest") for event in events
            if type(event) is dict
            and event.get("type") == receiptdata.EVENT_WORKFLOW_ADMISSION
            and event.get("body_digest") is not None)
        for label, counted in (("defect", defect_events),
                               ("admission", admission_events)):
            repeated = sorted(digest for digest, total in counted.items()
                              if total > 1)
            if repeated:
                raise StoreError(
                    f"this journal anchors {counted[repeated[0]]} signed "
                    f"{label} event(s) for one {label} record "
                    f"({repeated[0]}). One act is one event and one record; "
                    "two events for one record is not history this store will "
                    "replay.")
        anchored_defects = set(defect_events)
        defect_event_rows = {
            event["defect_digest"]: event for event in events
            if type(event) is dict
            and event.get("type") == receiptdata.EVENT_DEFECT}
        anchored_admissions = set(admission_events)
        anchored_evidence: set[str] = set()
        evidence_binders: dict[str, list] = {}
        authenticated_reviews: set[tuple[str, str]] = set()
        expected_dependency_times: dict[
            tuple[str, str, str, str], int] = {}
        supported_dependency_times: dict[
            tuple[str, str, str, str], set[int]] = {}
        supplied_admissions: set[str] = set()
        for document in bundle["workflow_receipts"]:
            try:
                receipt = receiptdata.receipt_from_dict(document)
                receiptdata.verify_receipt(receipt, verifier)
            except (receiptdata.ReceiptError, ValueError) as error:
                raise StoreError(
                    f"imported workflow receipt is not authentic: {error}"
                ) from None
            if (receipt.journal_id != journal_id
                    or receipt.head.receipt_hash not in known_heads):
                raise StoreError(
                    "imported workflow receipt is not anchored in this journal")
            if receipt.body_digest not in anchored_admissions:
                raise StoreError(
                    "imported workflow receipt has no signed admission event "
                    "in this journal; a receipt no head covers is not history")
            if receipt.body_digest in supplied_admissions:
                raise StoreError(
                    "this export supplies two workflow receipts with one body "
                    f"digest ({receipt.body_digest}); a receipt is one "
                    "admission and one row")
            if len(receipt.evidence_digests) != len(
                    set(receipt.evidence_digests)):
                raise StoreError(
                    "a workflow receipt binds one evidence digest more than "
                    "once")
            if len(receipt.dependencies) != len(set(receipt.dependencies)):
                raise StoreError(
                    "a workflow receipt binds one dependency more than once")
            if len(receipt.authenticated_reviews) != len(
                    set(receipt.authenticated_reviews)):
                raise StoreError(
                    "a workflow receipt attributes one review more than once")
            if any(digest not in receipt.evidence_digests
                   for digest, _key_id in receipt.authenticated_reviews):
                raise StoreError(
                    "an authenticated review must name evidence bound by the "
                    "same signed receipt")
            supplied_admissions.add(receipt.body_digest)
            anchored_evidence.update(receipt.evidence_digests)
            for digest in receipt.evidence_digests:
                evidence_binders.setdefault(digest, []).append(receipt)
            authenticated_reviews.update(receipt.authenticated_reviews)
            self.insert_workflow_receipt(receipt, idempotent=True)
            if self.workflow_receipt(receipt.receipt_hash) != receipt:
                raise StoreError(
                    "an existing workflow receipt row conflicts with the "
                    "authenticated import")
            for dependency_repository, dependency_sha in receipt.dependencies:
                edge = (receipt.repository, receipt.commit_sha,
                        dependency_repository, dependency_sha)
                expected_dependency_times[edge] = min(
                    receipt.issued_at,
                    expected_dependency_times.get(edge, receipt.issued_at))
                supported_dependency_times.setdefault(edge, set()).add(
                    receipt.issued_at)
                self.insert_dependency_edge(
                    consumer_repository=receipt.repository,
                    consumer_commit_sha=receipt.commit_sha,
                    dependency_repository=dependency_repository,
                    dependency_commit_sha=dependency_sha,
                    recorded_at=receipt.issued_at)
        for edge, expected_at in expected_dependency_times.items():
            stored = self.dependency_recorded_at(
                consumer_repository=edge[0], consumer_commit_sha=edge[1],
                dependency_repository=edge[2], dependency_commit_sha=edge[3])
            if (stored is not None and stored != expected_at
                    and expected_at < stored
                    and stored in supported_dependency_times[edge]):
                # Receipt arrays are transport containers, not signed
                # authority order.  If a later receipt happened to be replayed
                # first, lower the derived row to the minimum issued_at that
                # the complete authentic set proves.  An unrelated unsigned
                # timestamp is not in the supported set and still refuses.
                self.lower_dependency_recorded_at(
                    consumer_repository=edge[0], consumer_commit_sha=edge[1],
                    dependency_repository=edge[2],
                    dependency_commit_sha=edge[3],
                    recorded_at=expected_at, previous_recorded_at=stored)
                stored = self.dependency_recorded_at(
                    consumer_repository=edge[0], consumer_commit_sha=edge[1],
                    dependency_repository=edge[2],
                    dependency_commit_sha=edge[3])
            if stored is None or stored != expected_at:
                raise StoreError(
                    "an existing dependency row conflicts with the "
                    "authenticated receipt attachment")
        missing_admissions = sorted(anchored_admissions - supplied_admissions)
        if missing_admissions:
            raise StoreError(
                f"this export anchors {len(anchored_admissions)} signed "
                f"admission event(s) but supplies {len(supplied_admissions)} "
                "workflow receipt(s). An admission the journal signed cannot "
                "be dropped in transit. First missing body digest: "
                f"{missing_admissions[0]}")
        supplied_evidence: set[str] = set()
        parsed_evidence: dict[str, tuple[str, object]] = {}
        for row in bundle["evidence"]:
            if type(row) is not dict or set(row) != {"digest", "kind", "record"}:
                raise StoreError("imported evidence row is not a closed object")
            record = row["record"]
            try:
                if row["kind"] == "command":
                    parsed = evidence_module.command_evidence_from_dict(record)
                elif row["kind"] == "review":
                    parsed = evidence_module.review_evidence_from_dict(record)
                elif row["kind"] == "authorship":
                    # Authorship is bound by the same signed receipts as
                    # commands and reviews, and a receipt whose authorship
                    # evidence could not travel was a receipt that could be
                    # exported and never imported: the bijection below refuses
                    # the missing digest, so the whole journal was rejected.
                    parsed = evidence_module.authorship_evidence_from_dict(
                        record)
                else:
                    raise StoreError(
                        f"imported evidence has unknown kind {row['kind']!r}")
            except evidence_module.EvidenceError as error:
                raise StoreError(f"imported evidence is invalid: {error}") from None
            if evidence_module.evidence_digest(parsed) != row["digest"]:
                raise StoreError(
                    "imported evidence does not match its own digest")
            if any(parsed.repository != item.repository
                   or parsed.commit_sha != item.commit_sha
                   or parsed.tree_sha != item.tree_sha
                   or parsed.policy_digest != item.policy_digest
                   for item in evidence_binders.get(row["digest"], ())):
                raise StoreError(
                    "imported evidence identity does not match the signed "
                    "receipt that binds it")
            if row["digest"] not in anchored_evidence:
                raise StoreError(
                    "imported evidence is not bound by any signed receipt in "
                    "this journal; an evidence array with no signed "
                    "correspondence is not accepted")
            if row["digest"] in supplied_evidence:
                raise StoreError(
                    f"this export supplies evidence {row['digest']} twice; "
                    "one signed digest has exactly one attachment")
            supplied_evidence.add(row["digest"])
            parsed_evidence[row["digest"]] = (row["kind"], parsed)
            self.insert_receipt_evidence(
                digest=row["digest"], kind=row["kind"],
                repository=record["repository"],
                commit_sha=record["commit_sha"], tree_sha=record["tree_sha"],
                policy_digest=record["policy_digest"],
                record_json=canonical_json(record), idempotent=True)
            stored = self.receipt_evidence_row(row["digest"])
            if (stored is None or stored["kind"] != row["kind"]
                    or stored["repository"] != record["repository"]
                    or stored["commit_sha"] != record["commit_sha"]
                    or stored["tree_sha"] != record["tree_sha"]
                    or stored["policy_digest"] != record["policy_digest"]
                    or stored["record_json"] != canonical_json(record)):
                raise StoreError(
                    "an existing evidence row conflicts with the "
                    "authenticated import")
        missing_evidence = sorted(anchored_evidence - supplied_evidence)
        if missing_evidence:
            raise StoreError(
                f"this export anchors {len(anchored_evidence)} evidence "
                f"digest(s) in its signed receipts but supplies "
                f"{len(supplied_evidence)} record(s). An artefact cannot be "
                "current on the strength of evidence that did not travel with "
                f"it. First missing digest: {missing_evidence[0]}")
        for digest, _key_id in authenticated_reviews:
            kind, parsed = parsed_evidence[digest]
            if kind != "review" or parsed.verdict != "approve":
                raise StoreError(
                    "authenticated reviewer attribution requires a stored, "
                    "receipt-bound approving review")
        supplied_defects: set[str] = set()
        for document in bundle["defects"]:
            try:
                defect = evidence_module.defect_from_dict(document)
            except evidence_module.EvidenceError as error:
                raise StoreError(f"imported defect is invalid: {error}") from None
            digest = evidence_module.evidence_digest(defect)
            if digest not in anchored_defects:
                raise StoreError(
                    "imported defect is not anchored in this journal")
            if digest in supplied_defects:
                raise StoreError(
                    f"this export supplies the defect {digest} twice; a "
                    "defect is one record and one signed event")
            signed_event = defect_event_rows[digest]
            filed_at = signed_event.get("filed_at")
            if (type(filed_at) is not int or filed_at < 0
                    or signed_event.get("defect_id") != defect.defect_id
                    or signed_event.get("repository") != defect.repository
                    or signed_event.get("commit_sha") != defect.commit_sha
                    or signed_event.get("severity") != defect.severity
                    or signed_event.get("discovered_at")
                    != defect.discovered_at):
                raise StoreError(
                    "signed defect event metadata does not match its defect "
                    "attachment")
            supplied_defects.add(digest)
            document_to_store = evidence_module.defect_to_dict(defect)
            self.insert_defect(
                digest=digest, defect_id=defect.defect_id,
                repository=defect.repository, commit_sha=defect.commit_sha,
                filed_at=filed_at, record=document_to_store, idempotent=True)
            stored = self.defect_row(digest)
            if (stored is None or stored["defect_id"] != defect.defect_id
                    or stored["repository"] != defect.repository
                    or stored["commit_sha"] != defect.commit_sha
                    or stored["filed_at"] != filed_at
                    or stored["record_json"] != canonical_json(
                        document_to_store)):
                raise StoreError(
                    "an existing defect row conflicts with the authenticated "
                    "import")
        missing = sorted(anchored_defects - supplied_defects)
        if missing:
            raise StoreError(
                f"this export anchors {len(anchored_defects)} signed defect "
                f"event(s) but supplies {len(supplied_defects)} defect "
                "record(s). A defect the journal signed cannot be dropped in "
                "transit: importing this bundle would erase an impeachment and "
                f"restore CURRENT. First missing digest: {missing[0]}")

    @staticmethod
    def _ensure_export_size(bundle: dict) -> None:
        try:
            size = len(canonical_json(bundle).encode("utf-8"))
        except (TypeError, ValueError) as error:
            raise StoreError(
                f"journal export is not canonical JSON: {error}") from None
        if size > MAX_JOURNAL_BYTES:
            raise StoreError(
                f"journal export is {size} bytes; the direct store limit is "
                f"{MAX_JOURNAL_BYTES} bytes. Select an earlier stored head "
                "with through_head only for an explicit historical cut. "
                "That cut is cumulative from the first event, may omit later "
                "defects, and cannot transfer current history around this "
                "ceiling")

    @staticmethod
    def _parse_export(bundle: object, *, _enforce_transfer_limit: bool = True
                      ) -> tuple[str, list, list]:
        """The closed, exactly typed shape of an export bundle."""

        if type(bundle) is not dict or set(bundle) != _EXPORT_KEYS:
            raise StoreError("journal export must be a closed JSON object")
        if bundle["schema"] != JOURNAL_EXPORT_SCHEMA:
            raise StoreError(
                f"journal export schema must be {JOURNAL_EXPORT_SCHEMA!r}")
        journal_id = bundle["journal_id"]
        events = bundle["events"]
        receipts_document = bundle["receipts"]
        if (type(journal_id) is not str or type(events) is not list
                or type(receipts_document) is not list or not receipts_document):
            raise StoreError("journal export is not exactly typed")
        for key in ("workflow_receipts", "evidence", "defects"):
            if type(bundle[key]) is not list:
                raise StoreError(f"journal export {key} must be a list")
        if _enforce_transfer_limit:
            _TrustStoreBackend._ensure_export_size(bundle)
        try:
            receipts = [fcd_head.head_receipt_from_dict(item)
                        for item in receipts_document]
        except (TypeError, ValueError) as error:
            raise StoreError(f"journal export head is invalid: {error}") from None
        receipts.sort(key=lambda item: item.event_count)
        if any(item.journal_id != journal_id for item in receipts):
            raise StoreError("journal export head names a different journal")
        return journal_id, events, receipts

    def _authenticate_export(self, journal_id: str, events: list,
                             receipts: list, verifier) -> None:
        """Verify every head, and refuse anything trailing behind the last one.

        An import believes exactly what a signed head covers. Events past the
        final head's ``event_count`` are covered by no signature at all, so a
        forged defect appended after the last head would otherwise arrive
        looking anchored -- and impeach an artefact nobody signed an
        impeachment for.
        """

        final = receipts[-1]
        if len(events) != final.event_count:
            raise StoreError(
                f"this export carries {len(events)} event(s) but its last "
                f"signed head covers {final.event_count}. Only events a signed "
                "head covers are imported, and an export that trails extra "
                "events past its signature is refused rather than truncated.")
        seen_counts = set()
        previous = None
        for item in receipts:
            if item.event_count in seen_counts:
                raise StoreError(
                    "journal export carries two signed heads for one event "
                    "count; the chain forks and cannot be replayed")
            seen_counts.add(item.event_count)
            try:
                fcd_head.verify_receipt(item, verifier)
                fcd_head.MonotoneHeadRegistry._validate_next(item, previous)
            except (fcd_head.HeadVerificationError, fcd_head.HeadRefused):
                raise StoreError(
                    "journal export is not authentic under this key") from None
            computed = fcd_head.compute_journal_head(
                journal_id, events[:item.event_count])
            if (computed.head_digest != item.head_digest
                    or computed.event_count != item.event_count):
                raise StoreError(
                    "a signed head in this export does not match the events it "
                    "claims to cover")
            previous = item

    def import_journal(self, bundle: object, verifier) -> fcd_head.HeadReceipt:
        """Import an exported journal, refusing forgery and rollback.

        The whole signed head chain is authenticated against the events before
        anything is written, so an importer never has to trust a bare latest
        head. Importing a strictly shorter journal is a rollback attempt and is
        refused. Re-importing the *same* head is a full heal-and-verify pass:
        every head and event is checked again -- a shortcut there would let a
        second bundle arrive with the same head and different events -- and any
        attachment a partial earlier import left out is restored.

        The whole bundle lands in one ``BEGIN IMMEDIATE`` transaction. Heads
        committed one at a time could leave an earlier head durable with its
        attachments missing, which is indistinguishable from an export that
        omitted them.
        """

        journal_id, events, receipts = self._parse_export(bundle)
        self._authenticate_export(journal_id, events, receipts, verifier)
        final = receipts[-1]
        plain_events = [json.loads(canonical_json(event)) for event in events]

        def replay():
            current = self.current_head(journal_id)
            if current is not None:
                if current.receipt_hash != final.receipt_hash \
                        and final.event_count <= current.event_count:
                    raise HeadConflict(
                        f"import would roll {journal_id!r} back from "
                        f"{current.event_count} to {final.event_count} events")
            accepted = current
            for item in receipts:
                if self.has_head_receipt(item.receipt_hash):
                    continue
                self._extend_head_locked(
                    item, plain_events[:item.event_count])
                accepted = item
            self._import_attachments(bundle, journal_id, verifier)
            if accepted is None:
                raise StoreError("journal export contained no acceptable head")
            return accepted

        try:
            return self._transact(replay)
        except fcd_head.HeadVerificationError:
            raise StoreError(
                "journal export is not authentic under this key") from None


# The reads a trusted process makes. Every name here is also in Core's
# ``READ_CAPABILITIES`` except the ones that authenticate before answering,
# which Core withholds from every facade because they need a verifier.
TRUST_READ_CAPABILITIES = frozenset({
    # identity of the home itself
    "home", "path", "schema_version",
    # evidence
    "evidence_for", "evidence_in", "evidence_in_attempt",
    "receipt_evidence_row",
    # journals and heads
    "journal_events", "current_head", "head_receipt_chain", "has_head_receipt",
    "verify_journal",
    # receipts
    "workflow_receipt", "workflow_receipt_by_body", "receipts_for",
    "receipts_in", "receipts_in_journal", "receipt_count", "latest_receipt",
    # defects
    "has_defect", "defect_event_count", "defect_shas", "defects_for",
    "defect_count", "all_defects", "defect_row", "defect_rows",
    # dependencies
    "direct_consumers", "dependency_recorded_at", "consumer_dependency_rows",
    # attempts, so `explain` can say what one recorded
    "attempt", "latest_attempt",
    # the trusted-policy baseline
    "policy_generation", "trusted_policies", "revoked_policies",
    # authenticated projections
    "authenticated_repository_projection", "authenticated_workflow_state",
    "has_repository_authority",
    # transfer
    "export_journal",
    # a read-only transaction, so a multi-row read can be consistent
    "read_transaction",
})

# The writes only an authority may make. Each one is a named operation that
# writes exactly the row its own contract describes; there is deliberately no
# general-purpose write here, because a general-purpose write is every one of
# these at once plus the ones nobody listed.
TRUST_WRITE_CAPABILITIES = frozenset({
    "accept_head",
    "insert_workflow_receipt",
    "insert_defect",
    "insert_receipt_evidence",
    "insert_dependency_edge",
    "lower_dependency_recorded_at",
    "put_dependency",
    "trust_policy",
    "revoke_policy",
    "import_journal",
})

TRUST_CAPABILITIES = TRUST_READ_CAPABILITIES | TRUST_WRITE_CAPABILITIES


# Facade -> backend, for the one capability Core withholds from every facade
# and that this distribution genuinely holds: closing the connection it opened.
# Core's phrase for ``close`` is "the owner of this backend, which decides its
# lifetime", and here Trust *is* the owner -- it constructed the backend inside
# ``open_store``. Weak keys, so a store nobody holds is collected with its entry.
_OWNED: "weakref.WeakKeyDictionary[TrustStore, _TrustStoreBackend]" = (
    weakref.WeakKeyDictionary())

_OPEN_BACKENDS: "weakref.WeakSet[_TrustStoreBackend]" = weakref.WeakSet()


class TrustStore(CapabilityFacade):
    """A trusted store this distribution opened, and may therefore close.

    Everything reachable through it is enumerated in
    :data:`TRUST_CAPABILITIES`.  ``close`` is added because the lifetime of a
    connection belongs to whoever opened it, and no capability travels with it
    -- it ends the object's usefulness rather than extending it.
    """

    CAPABILITIES = TRUST_CAPABILITIES

    __slots__ = ()

    def close(self) -> None:
        backend = _OWNED.pop(self, None)
        if backend is not None:
            backend.close()

    def __enter__(self) -> "TrustStore":
        return self

    def __exit__(self, *exception) -> bool:
        self.close()
        return False


def open_store(home: Path | str | None = None) -> TrustStore:
    """Open (creating if needed) the durable store under ``home``.

    The returned object is a capability facade, not the backend: a caller who
    holds it can make every authority decision this distribution is for, and
    there is no name on it that runs a statement of its own choosing.

    This is the only way into a store from outside the module, and a
    :class:`TrustStore` is the only thing it hands back.  The backend it built
    is reachable from here and from nowhere a consumer can name, and the
    connection that backend opened is not an attribute of either object.
    """

    backend = _TrustStoreBackend(default_home() if home is None else home)
    _OPEN_BACKENDS.add(backend)
    try:
        store = TrustStore(backend)
    except BaseException:
        backend.close()
        raise
    _OWNED[store] = backend
    return store


def open_store_count() -> int:
    """How many stores this process opened and has not closed."""

    return len(_OPEN_BACKENDS)
