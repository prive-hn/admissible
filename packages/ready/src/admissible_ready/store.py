"""The durable home, opened by the distribution that only ever describes.

One Admissible home is shared by both authorities, and Core owns its shared
vocabulary: where it is, what the database file is called, how a connection is
configured, and which method names each role may reach.  What Core deliberately
does *not* own is the schema -- a kernel that created tables would fix the
storage contract for distributions that had not been written yet.  This module
is the Ready half of that: it creates and migrates exactly the schema the
monolith created and migrated, and implements exactly the reads and the
observation-writes that :class:`admissible_core.store_candidate.CandidateStore`
grants.

The withheld capabilities are not withheld here, they are **absent**.  There is
no ``trust_policy``, no ``revoke_policy``, no ``accept_head``, no
``workflow_receipt_row``, no ``defect_row``, no ``import_journal``, no
``verify_journal``, no ``authenticated_workflow_state`` and no unrestricted
``transact`` anywhere in this file.  The capability facade is still applied on
top, because a facade is what makes the reachable set *checkable*, but a
capability that does not exist cannot be reached by rediscovering the backend.

Which leaves the last thing worth reaching: the ``sqlite3`` connection itself.
A caller holding one needs none of the withheld capabilities, because a raw
connection can ``DROP TRIGGER`` and write a receipt row by hand -- so the
schema's append-only guarantees are only as good as the reachability of the
connection.  Two rules keep it out of reach.  :func:`open_store` is the only
entry point and returns only a :class:`ReadyStore`; the backend class behind it
is module-private and not exported, so no consumer can build a second one under
a supported name.  And the connection is not an attribute of anything -- not
``store._connection``, not ``backend._connection`` -- it lives in the
module-private registry below, keyed weakly by the backend that opened it.

Two read surfaces are deliberately narrower than the monolith's, and the
difference is the whole point of the split:

* a **workflow receipt** is returned as the stored document, not as a parsed
  ``WorkflowReceipt``.  Parsing one is arithmetic; treating the result as a
  receipt is authority, and this distribution holds no verifier.  What is on
  this side of the line is "a row exists that claims an admission", which is
  what unsigned Ready state is allowed to say and no more;
* a **head receipt** is returned the same way, for the same reason.

Both are honest about what they are: ``receipts_for`` answers "what does this
home record", never "what was authenticated".  The signing distribution reads
the same rows through its own backend, with a verifier, and only there does a
row become evidence of a signature.

Migration is additive and non-destructive, exactly as before.  An existing v0.7
home opens, upgrades in place inside one transaction, and loses no row; a home
written by a newer schema is refused rather than downgraded -- and the refusal
comes *first*.  The version is read before the journal mode is set, before the
schema script runs and before any migration, because refusing a newer home
after switching it to WAL and creating this build's tables inside it is not a
refusal, it is a rewrite followed by an apology.

Opening one is done under :func:`admissible_core.store_open.schema_lock`, held
from before the existence check until the schema and the recorded version are
final.  Everything between those two points is a window a second process can
ruin -- two openers both finding no file and both creating one, two both
finding version 5 and both migrating it -- and SQLite protects none of it,
because at the moment they race there is no database yet.  The Trust
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
import time
import weakref
from pathlib import Path
from typing import Any, Iterable

from fcd.journal import canonical_json

from admissible_core import evidence as evidence_module
from admissible_core.store_base import (DEFAULT_BUSY_TIMEOUT_MS,
                                        SCHEMA_VERSION_KEY, StoreError,
                                        database_path, default_home,
                                        require_home_outside)
from admissible_core.store_candidate import CandidateStore
from admissible_core.store_open import (DEFAULT_SCHEMA_LOCK_TIMEOUT_MS,
                                        recorded_schema_version_text,
                                        refuse_a_layout_this_build_cannot_open,
                                        refuse_an_unsupported_version,
                                        schema_lock)

# The whole of this module's surface.  The backend class is deliberately not
# here and is deliberately not public: exporting it would let any consumer
# build a second one beside the facade, and the object it hands back holds the
# live ``sqlite3`` connection -- which can drop every append-only trigger in
# the schema above and then write whatever it likes.  ``open_store`` is the
# only way in, and what it returns is a :class:`ReadyStore`.
__all__ = [
    "DEFAULT_BUSY_TIMEOUT_MS",
    "ReadyStore",
    "SCHEMA_LOCK_TIMEOUT_MS",
    "SCHEMA_VERSION",
    "StoreError",
    "default_home",
    "open_store",
    "open_store_count",
    "require_home_outside",
]

SCHEMA_VERSION = 6

# How long an opener waits for another process to finish initialising this
# home before it gives up and says who it was waiting for. Read at call time,
# so a deployment that knows its migrations are slower can raise it.
SCHEMA_LOCK_TIMEOUT_MS = DEFAULT_SCHEMA_LOCK_TIMEOUT_MS

# The event type a filed defect is written as inside a journal event. It is a
# string in stored JSON -- a wire constant, like a schema id -- and reading it
# is not the same as being able to write one: filing a defect needs a signed
# journal event, and there is no code in this distribution that appends one.
_EVENT_DEFECT = "defect-filed"

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
-- moment the fact is written. Ordering cache facts by any wall clock was
-- wrong under concurrency: a slow attempt that starts first and fails last
-- carries the *lower* timestamp, so its failure would not invalidate a pass a
-- later-starting attempt had already recorded. Sequence order is observation
-- order, and observation order is the only order that answers "what do we
-- know now?".
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
-- This distribution creates the tables and only ever reads them. Making a
-- policy enforceable, and withdrawing one, are the signing distribution's; a
-- candidate that could write here would be a candidate approving its own gate.
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
# nobody holds takes its connection with it, so a dropped store gives back its
# file handle instead of leaking one for the life of the process.
_CONNECTIONS: "weakref.WeakKeyDictionary[_ReadyStoreBackend, sqlite3.Connection]" = (
    weakref.WeakKeyDictionary())


def _sql(backend: "_ReadyStoreBackend") -> sqlite3.Connection:
    """The connection a backend opened, or a refusal once it has none."""

    connection = _CONNECTIONS.get(backend)
    if connection is None:
        raise StoreError(
            "this store is closed: its connection was released and no read or "
            "write can be served through it")
    return connection


class _ReadyStoreBackend:
    """A durable Admissible home, with the candidate-side surface and no other.

    Every method here either reads, or records an observation.  There is no
    method that anchors a head, issues a receipt, files a defect or makes a
    policy enforceable, so a caller who reaches this object directly -- rather
    than through the facade :func:`open_store` hands out -- gains no authority
    by doing so.  That is deliberate: the facade proves the *reachable* set,
    and the absence proves there is nothing behind it.

    Module-private, and not exported.  "Private" in Python is a spelling
    rather than a wall, and the point is not to hide the class from a
    determined reader in this process -- it is that no supported name leads
    here, so reaching the raw database is a deliberate act against the grain
    of the module instead of an attribute on an object a caller was handed.
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
            # would mean one of them stopped being called. The last word on a
            # newer layout has to be a refusal whichever way it was reached.
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

        A version that is not a number is refused the same way.  It identifies
        no layout, and a layout that cannot be identified cannot be safely
        migrated -- so the answer is to close the connection and say so, not
        to guess and run DDL over whatever is there.
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

    def _rollback(self) -> None:
        try:
            _sql(self).execute("ROLLBACK")
        except (sqlite3.Error, StoreError):
            pass

    @contextlib.contextmanager
    def _atomic(self):
        """One write transaction, or a no-op if the caller already opened one.

        The connection runs in autocommit mode, so every statement outside an
        explicit transaction is its own commit. That is wrong for a fact whose
        *order* is part of its meaning: allocating a cache sequence in one
        commit and writing the row that carries it in another lets two writers
        interleave so that the row with the lower sequence commits last. A
        failure could then take sequence 1, a pass commit as sequence 2, and
        the failure land afterwards -- and the lookup, comparing 1 < 2, would
        reuse a pass that a later observation had already contradicted.
        """

        if _sql(self).in_transaction:
            yield
            return
        _sql(self).execute("BEGIN IMMEDIATE")
        try:
            yield
            # COMMIT is part of the fallible transaction boundary.  In
            # particular, a deferred foreign-key violation is reported here,
            # not by the statement that created it.  Leaving this outside the
            # protected block strands the connection in a live transaction;
            # every later _atomic call then mistakes uncommitted state for an
            # outer owner's durable authority.
            _sql(self).execute("COMMIT")
        except BaseException:
            self._rollback()
            raise

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
    def put_evidence(self, *, digest: str, kind: str, repository: str,
                     commit_sha: str, tree_sha: str, policy_digest: str,
                     record: dict) -> bool:
        """Ingest one evidence record idempotently; ``True`` when it was new."""

        try:
            cursor = _sql(self).execute(
                "INSERT OR IGNORE INTO evidence(digest, kind, repository, "
                "commit_sha, tree_sha, policy_digest, record_json) "
                "VALUES(?,?,?,?,?,?,?)",
                (digest, kind, repository, commit_sha, tree_sha, policy_digest,
                 canonical_json(record)))
        except sqlite3.Error as error:
            raise StoreError(f"cannot record evidence: {error}") from None
        return cursor.rowcount == 1

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

    # -- journals and heads ---------------------------------------------
    def journal_events(self, journal_id: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT event_json FROM journal_events WHERE journal_id=? "
            "ORDER BY position", (journal_id,)).fetchall()
        return tuple(json.loads(row["event_json"]) for row in rows)

    def current_head(self, journal_id: str) -> dict | None:
        """The stored current-head *document*, never a verified head receipt.

        Parsing it into a head receipt would be arithmetic; presenting the
        result as a head is authority, and this distribution holds no verifier
        with which to earn it.
        """

        row = _sql(self).execute(
            "SELECT r.receipt_json FROM current_head c "
            "JOIN head_receipts r ON r.receipt_hash = c.receipt_hash "
            "WHERE c.journal_id=?", (journal_id,)).fetchone()
        return None if row is None else json.loads(row["receipt_json"])

    def head_receipt_chain(self, journal_id: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT receipt_json FROM head_receipts WHERE journal_id=? "
            "ORDER BY event_count", (journal_id,)).fetchall()
        return tuple(json.loads(row["receipt_json"]) for row in rows)

    def has_head_receipt(self, receipt_hash: str) -> bool:
        return _sql(self).execute(
            "SELECT 1 FROM head_receipts WHERE receipt_hash=?",
            (receipt_hash,)).fetchone() is not None

    # -- workflow receipts, as records rather than as authority ----------
    def workflow_receipt(self, receipt_hash: str) -> dict | None:
        row = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts WHERE receipt_hash=?",
            (receipt_hash,)).fetchone()
        return None if row is None else json.loads(row["receipt_json"])

    def workflow_receipt_by_body(self, body_digest: str) -> dict | None:
        row = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts WHERE body_digest=?",
            (body_digest,)).fetchone()
        return None if row is None else json.loads(row["receipt_json"])

    def receipts_for(self, repository: str,
                     commit_sha: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts "
            "WHERE repository=? AND commit_sha=? ORDER BY issued_at, receipt_hash",
            (repository, commit_sha)).fetchall()
        return tuple(json.loads(row["receipt_json"]) for row in rows)

    def receipts_in(self, repository: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts WHERE repository=? "
            "ORDER BY issued_at, receipt_hash", (repository,)).fetchall()
        return tuple(json.loads(row["receipt_json"]) for row in rows)

    def receipts_in_journal(self, journal_id: str) -> tuple[dict, ...]:
        rows = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts WHERE journal_id=? "
            "ORDER BY issued_at, receipt_hash", (journal_id,)).fetchall()
        return tuple(json.loads(row["receipt_json"]) for row in rows)

    def receipt_count(self, repository: str) -> int:
        return _sql(self).execute(
            "SELECT COUNT(*) AS total FROM workflow_receipts WHERE repository=?",
            (repository,)).fetchone()["total"]

    def latest_receipt(self, repository: str) -> dict | None:
        row = _sql(self).execute(
            "SELECT receipt_json FROM workflow_receipts WHERE repository=? "
            "ORDER BY issued_at DESC, receipt_hash DESC LIMIT 1",
            (repository,)).fetchone()
        return None if row is None else json.loads(row["receipt_json"])

    # -- defects, read only ----------------------------------------------
    def has_defect(self, digest: str) -> bool:
        return _sql(self).execute(
            "SELECT 1 FROM defects WHERE digest=?",
            (digest,)).fetchone() is not None

    def defect_event_count(self, journal_id: str, digest: str) -> int:
        """Count signed-event claims for one defect in the current snapshot."""

        return sum(
            1 for event in self.journal_events(journal_id)
            if type(event) is dict
            and event.get("type") == _EVENT_DEFECT
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

    def direct_consumers(self, repository: str,
                         commit_sha: str) -> tuple[tuple[str, str], ...]:
        rows = _sql(self).execute(
            "SELECT consumer_repository, consumer_commit_sha FROM dependencies "
            "WHERE dependency_repository=? AND dependency_commit_sha=? "
            "ORDER BY consumer_repository, consumer_commit_sha",
            (repository, commit_sha)).fetchall()
        return tuple((row["consumer_repository"], row["consumer_commit_sha"])
                     for row in rows)

    # -- attempts --------------------------------------------------------
    def record_attempt(self, *, attempt_id: str, repository: str,
                       commit_sha: str, class_id: str, policy_digest: str,
                       state: str, started_at: int,
                       digests: Iterable[str] = (), tree_sha: str = "",
                       decision: dict | None = None) -> None:
        """Record which evidence belongs to one attempt at one artefact.

        The tree and the decision document are stored with it on purpose. An
        attempt is history: asking later what a refused attempt said must be
        answered from what was recorded then, not from whatever the checkout
        happens to hold today.
        """

        try:
            _sql(self).execute(
                "INSERT OR IGNORE INTO attempts(attempt_id, repository, "
                "commit_sha, class_id, policy_digest, state, started_at, "
                "tree_sha, decision_json) VALUES(?,?,?,?,?,?,?,?,?)",
                (attempt_id, repository, commit_sha, class_id, policy_digest,
                 state, started_at, tree_sha,
                 "" if decision is None else canonical_json(decision)))
            for digest in digests:
                _sql(self).execute(
                    "INSERT OR IGNORE INTO attempt_evidence(attempt_id, digest)"
                    " VALUES(?,?)", (attempt_id, digest))
        except sqlite3.Error as error:
            raise StoreError(f"cannot record this attempt: {error}") from None

    def latest_attempt(self, repository: str, commit_sha: str) -> dict | None:
        """The most recent attempt at one artefact.

        ``started_at`` has one-second resolution and an attempt id is a random
        digest, so two runs inside the same second used to resolve in whichever
        order their ids happened to sort -- which could report an older attempt
        as the latest one, and make "would this pass now?" answer about the
        wrong observation. The tie is broken on ``rowid``, which is the order
        the rows were actually written.
        """

        row = _sql(self).execute(
            "SELECT attempt_id, class_id, policy_digest, state, started_at, "
            "tree_sha, decision_json FROM attempts "
            "WHERE repository=? AND commit_sha=? "
            "ORDER BY started_at DESC, rowid DESC LIMIT 1",
            (repository, commit_sha)).fetchone()
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

    def attempt(self, attempt_id: str) -> dict | None:
        """One recorded attempt, by id."""

        row = _sql(self).execute(
            "SELECT attempt_id, repository, commit_sha, class_id, "
            "policy_digest, state, started_at, tree_sha, decision_json "
            "FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
        return None if row is None else self._attempt_row(row)

    # -- exact-identity evidence cache -----------------------------------
    @staticmethod
    def cache_key(*, repository: str, commit_sha: str, tree_sha: str,
                  policy_digest: str, check_id: str, check_version: str,
                  argv_digest: str, environment_fingerprint: str = "") -> str:
        """Every dimension that would make reuse a lie is in this key.

        ``environment_fingerprint`` is one of them. A command observes the
        machine it ran on as well as the tree it ran against, so a result
        recorded under one interpreter and platform says nothing about another.
        """

        return hashlib.sha256(canonical_json({
            "domain": "admissible/v0.6/evidence-cache",
            "repository": repository, "commit_sha": commit_sha,
            "tree_sha": tree_sha, "policy_digest": policy_digest,
            "check_id": check_id, "check_version": check_version,
            "argv_digest": argv_digest,
            "environment_fingerprint": environment_fingerprint,
        }).encode("utf-8")).hexdigest()

    def cache_command_evidence(self, record, *, recorded_at: int,
                               environment_fingerprint: str = "",
                               cacheable: bool = True) -> bool:
        """Remember one command result, or record that it invalidates reuse.

        A success is remembered so an identical re-run costs nothing. A failure
        is never remembered -- a failing check must be re-run so a repair can be
        observed -- but it is not simply dropped either: it is *news about this
        cache key*, and it is written down as an invalidation so no earlier
        success under the same key can be reused after it. Without that, a pass,
        then a known failure, then an ordinary run would quietly resurrect the
        pass.

        Truncated output is never cached because the digest describes only the
        bytes that were kept. ``cacheable=False`` is for checks whose subject is
        live state rather than the tree: nothing about them is reusable, and the
        honest cache entry is no cache entry.
        """

        if type(record) is not evidence_module.CommandEvidence:
            raise StoreError("only command evidence is cached")
        document = evidence_module.command_evidence_to_dict(record)
        digest = evidence_module.evidence_digest(record)
        key = self.cache_key(
            repository=record.repository, commit_sha=record.commit_sha,
            tree_sha=record.tree_sha, policy_digest=record.policy_digest,
            check_id=record.check_id, check_version=record.check_version,
            argv_digest=record.argv_digest,
            environment_fingerprint=environment_fingerprint)
        if not record.passed:
            try:
                # Allocation and insertion in one transaction, so the sequence
                # a row carries and the moment that row becomes visible are the
                # same event to every other writer.
                with self._atomic():
                    _sql(self).execute(
                        "INSERT OR IGNORE INTO evidence_cache_invalidations("
                        "cache_key, digest, invalidated_at, sequence) "
                        "VALUES(?,?,?,?)",
                        (key, digest, recorded_at, self.next_cache_sequence()))
            except sqlite3.Error as error:
                raise StoreError(
                    f"cannot record a cache invalidation: {error}") from None
            return False
        if record.output_truncated or not cacheable:
            return False
        try:
            with self._atomic():
                self.put_evidence(
                    digest=digest, kind="command",
                    repository=record.repository,
                    commit_sha=record.commit_sha, tree_sha=record.tree_sha,
                    policy_digest=record.policy_digest, record=document)
                _sql(self).execute(
                    "INSERT OR IGNORE INTO evidence_cache(cache_key, digest, "
                    "recorded_at, sequence) VALUES(?,?,?,?)",
                    (key, digest, recorded_at, self.next_cache_sequence()))
        except sqlite3.Error as error:
            raise StoreError(f"cannot cache evidence: {error}") from None
        return True

    def next_cache_sequence(self) -> int:
        """The next monotone position in this store's cache-fact order.

        Allocated from the database, not from a clock. Two writers racing get
        two different numbers in the order SQLite serialised them, which is
        exactly the order in which the facts became known here.
        """

        if not _sql(self).in_transaction:
            raise StoreError(
                "a cache sequence may only be allocated inside the same "
                "transaction as the cache fact it orders")
        try:
            cursor = _sql(self).execute(
                "INSERT INTO cache_order DEFAULT VALUES")
        except sqlite3.Error as error:
            raise StoreError(
                f"cannot order this cache fact: {error}") from None
        return int(cursor.lastrowid)

    def cache_invalidated_at(self, cache_key: str) -> int | None:
        """When this cache key was last known to fail, if it ever was."""

        row = _sql(self).execute(
            "SELECT MAX(invalidated_at) AS latest FROM "
            "evidence_cache_invalidations WHERE cache_key=?",
            (cache_key,)).fetchone()
        return None if row is None else row["latest"]

    def cache_invalidated_sequence(self, cache_key: str) -> int | None:
        """The last position at which this key was observed to fail."""

        row = _sql(self).execute(
            "SELECT MAX(sequence) AS latest FROM "
            "evidence_cache_invalidations WHERE cache_key=?",
            (cache_key,)).fetchone()
        return None if row is None else row["latest"]

    def cached_command_evidence(self, *, repository: str, commit_sha: str,
                                tree_sha: str, policy_digest: str,
                                check_id: str, check_version: str,
                                argv_digest: str,
                                environment_fingerprint: str = "",
                                now: int | None = None,
                                max_age_seconds: int = 0):
        """A cached result, re-validated against every dimension, or ``None``.

        ``max_age_seconds`` above zero bounds how long a result may stand in
        for a fresh observation. Zero means no bound *here*; the rule that a
        cacheable check must declare a positive age lives in
        :mod:`admissible_core.config`, where a policy is parsed and a missing
        bound can still be reported to whoever wrote it. This function is the
        mechanism and not the policy.
        """

        key = self.cache_key(
            repository=repository, commit_sha=commit_sha, tree_sha=tree_sha,
            policy_digest=policy_digest, check_id=check_id,
            check_version=check_version, argv_digest=argv_digest,
            environment_fingerprint=environment_fingerprint)
        # Both facts are read in one statement so the cached row and the
        # newest invalidation for the same key come from one snapshot: reading
        # them separately let a failure commit in between and be missed.
        row = _sql(self).execute(
            "SELECT c.recorded_at, c.sequence, e.record_json, ("
            "  SELECT MAX(i.sequence) FROM evidence_cache_invalidations i "
            "  WHERE i.cache_key = c.cache_key) AS invalidated FROM "
            "evidence_cache c JOIN evidence e ON e.digest = c.digest "
            "WHERE c.cache_key=?", (key,)).fetchone()
        if row is None:
            return None
        try:
            record = evidence_module.command_evidence_from_dict(
                json.loads(row["record_json"]))
        except (evidence_module.EvidenceError, ValueError):
            return None
        # Trust nothing that was stored: re-check the identity before reuse.
        if (record.repository != repository or record.commit_sha != commit_sha
                or record.tree_sha != tree_sha
                or record.policy_digest != policy_digest
                or record.check_id != check_id
                or record.check_version != check_version
                or record.argv_digest != argv_digest
                or not record.passed or record.output_truncated):
            return None
        # A failure *observed after* this success outranks it. "After" is the
        # store's own write order, never the attempt's start time: a slow
        # attempt that started first and failed last carries a lower timestamp
        # than the pass it has to invalidate, and comparing clocks would let
        # that pass survive news that contradicts it.
        invalidated = row["invalidated"]
        if invalidated is not None and invalidated >= (row["sequence"] or 0):
            return None
        if max_age_seconds > 0:
            reference = int(time.time()) if now is None else now
            if reference - record.finished_at > max_age_seconds:
                return None
        return record

    # -- the trusted-policy baseline, read only ---------------------------
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

        Reading the baseline is candidate-side on purpose. It is what lets an
        evaluation report honestly that the policy it just used is one nobody
        trusted; making one enforceable is the withheld half, and it is not in
        this file.
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


# Facade -> backend, for the one capability Core withholds from every facade
# and that this distribution genuinely holds: closing the connection it opened.
# Core's phrase for ``close`` is "the owner of this backend, which decides its
# lifetime", and here Ready *is* the owner -- it constructed the backend inside
# `open_store`. Weak keys, so a store nobody holds is collected with its entry.
_OWNED: "weakref.WeakKeyDictionary[ReadyStore, _ReadyStoreBackend]" = (
    weakref.WeakKeyDictionary())

_OPEN_BACKENDS: "weakref.WeakSet[_ReadyStoreBackend]" = weakref.WeakSet()


class ReadyStore(CandidateStore):
    """A candidate store this distribution opened, and may therefore close.

    Everything reachable through it is Core's :class:`CandidateStore` surface:
    every read, plus the writes that only record an observation.  ``close`` is
    added because the lifetime of a connection belongs to whoever opened it,
    and no capability travels with it -- it ends the object's usefulness rather
    than extending it.
    """

    __slots__ = ()

    def close(self) -> None:
        backend = _OWNED.pop(self, None)
        if backend is not None:
            backend.close()

    def __enter__(self) -> "ReadyStore":
        return self

    def __exit__(self, *exception) -> bool:
        self.close()
        return False


def open_store(home: Path | str | None = None) -> ReadyStore:
    """Open (creating if needed) the durable store under ``home``.

    The returned object is a capability facade, not the backend: a caller who
    holds it can read the home and record what it observed, and there is no
    name on it that anchors a head, issues a receipt or trusts a policy.

    This is the only way into a store from outside the module, and a
    :class:`ReadyStore` is the only thing it hands back.  The backend it built
    is reachable from here and from nowhere a consumer can name, and the
    connection that backend opened is not an attribute of either object.
    """

    backend = _ReadyStoreBackend(default_home() if home is None else home)
    _OPEN_BACKENDS.add(backend)
    try:
        store = ReadyStore(backend)
    except BaseException:
        backend.close()
        raise
    _OWNED[store] = backend
    return store


def open_store_count() -> int:
    """How many stores this process opened and has not closed."""

    return len(_OPEN_BACKENDS)
