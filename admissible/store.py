"""Restart-durable SQLite persistence for evidence, journals, and standing.

Design rules this module enforces:

* Every acceptance of a new current head runs inside one ``BEGIN IMMEDIATE``
  transaction that re-reads the stored head and refuses unless the proposal
  extends *exactly* it. WAL is not serialisation; the immediate transaction is.
* A locked, unreadable, or ambiguous database fails closed. There is no
  in-memory fallback: a decision that cannot be anchored is not anchored.
* Evidence, journal events, head receipts, workflow receipts and defects are
  append-only, enforced by triggers as well as by the API surface.
* Signing key material never reaches this module's tables, parameters or logs.
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
from typing import Any, Iterable, Sequence

from fcd import head as fcd_head
from fcd.journal import canonical_json

from . import evidence as evidence_module
from . import receipt as receiptdata

__all__ = [
    "DEFAULT_BUSY_TIMEOUT_MS",
    "HeadConflict",
    "MAX_JOURNAL_BYTES",
    "SCHEMA_VERSION",
    "Store",
    "StoreError",
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
DEFAULT_BUSY_TIMEOUT_MS = 5000
JOURNAL_EXPORT_SCHEMA = "admissible/v0.6/workflow-journal-export"
_EXPORT_KEYS = {"schema", "journal_id", "events", "receipts",
                "workflow_receipts", "evidence", "defects"}


class StoreError(ValueError):
    """The durable store refused an operation and wrote nothing."""


class HeadConflict(StoreError):
    """A proposed head does not extend the stored current head."""


def default_home(environment: dict[str, str] | None = None) -> Path:
    source = os.environ if environment is None else environment
    configured = (source.get("ADMISSIBLE_HOME") or "").strip()
    if configured:
        return Path(configured)
    return Path.home() / ".admissible"


def _inside(child: Path, parent: str) -> bool:
    if not parent.strip():
        return False
    try:
        child.resolve().relative_to(Path(parent).resolve())
    except (ValueError, OSError):
        return False
    return True


def require_home_outside(root: Path | str,
                         environment: dict[str, str] | None = None) -> Path:
    """The Admissible home, or a refusal when it sits inside the candidate.

    The home holds the store and the private per-check logs, and both are
    written while a run is in progress. Inside the repository under evaluation
    they are an untracked directory that appears part-way through -- and the
    mutation check, which can only see that the tree changed, then blocks the
    commit and names whichever check happened to be running.

    The refusal would be correct and its reason would be false. Say the true
    thing first, before anything is written, so the candidate also stays clean.
    """

    home = default_home(environment)
    if _inside(home, str(root)):
        raise StoreError(
            f"ADMISSIBLE_HOME {home} is inside the repository under evaluation "
            f"({root}). The store and the private check logs are written there "
            "during the run, so they would make the worktree dirty and the "
            "gate would refuse this commit -- blaming a check that did nothing "
            "wrong. Point ADMISSIBLE_HOME at a directory outside this "
            "repository.")
    return home


def require_durable_home(environment: dict[str, str] | None = None) -> Path:
    """The Admissible home, or a refusal when it could not survive the job.

    Monotone standing is a claim about *history*. A database that lives in a
    hosted runner's workspace is deleted the moment the job ends, so every run
    would start a fresh bootstrap journal and no rollback could ever be
    detected. Signing therefore requires an explicitly durable home: a
    dedicated persistent finalizer, or an external registry boundary the
    operator has arranged. Evaluation is unaffected -- it anchors nothing.
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
            f"ADMISSIBLE_HOME {home} is inside this job's disposable "
            "workspace, so it is not a durable anchor: the journal would be "
            "destroyed with the runner and every run would bootstrap a new "
            "one. Point ADMISSIBLE_HOME at storage that outlives the job.")
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


def _event_digest(event: object) -> str:
    import hashlib

    return hashlib.sha256(canonical_json(event).encode("utf-8")).hexdigest()


class Store:
    """A durable Admissible home directory."""

    __slots__ = ("_home", "_path", "_connection", "_schema_version",
                 "__weakref__")


    def __init__(self, home: Path | str) -> None:
        self._home = Path(home)
        try:
            self._home.mkdir(parents=True, exist_ok=True)
            os.chmod(self._home, 0o700)
        except OSError as error:
            raise StoreError(
                f"cannot use Admissible home {self._home}: {error.strerror}"
            ) from None
        self._path = self._home / "admissible.sqlite3"
        try:
            fresh = not self._path.exists()
            if fresh:
                descriptor = os.open(str(self._path),
                                     os.O_CREAT | os.O_RDWR | os.O_EXCL, 0o600)
                os.close(descriptor)
            os.chmod(self._path, 0o600)
            self._connection = sqlite3.connect(
                str(self._path), timeout=DEFAULT_BUSY_TIMEOUT_MS / 1000.0,
                isolation_level=None)
        except (OSError, sqlite3.Error) as error:
            raise StoreError(
                f"cannot open the Admissible database at {self._path}: {error}"
            ) from None
        self._connection.row_factory = sqlite3.Row
        try:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute(
                f"PRAGMA busy_timeout={DEFAULT_BUSY_TIMEOUT_MS}")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.executescript(_SCHEMA)
            row = self._connection.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                self._connection.execute(
                    "INSERT INTO schema_meta(key, value) VALUES(?, ?)",
                    ("schema_version", str(SCHEMA_VERSION)))
                self._schema_version = SCHEMA_VERSION
            else:
                self._schema_version = int(row["value"])
                stranded_policy = self._connection.execute(
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
                    self._connection.execute("BEGIN IMMEDIATE")
                    try:
                        if self._schema_version < SCHEMA_VERSION:
                            self._add_missing_columns()
                            self._connection.execute(
                                "UPDATE schema_meta SET value=? WHERE key=?",
                                (str(SCHEMA_VERSION), "schema_version"))
                        else:
                            # A pre-transactional v4->v5 migration could have
                            # bumped the version and crashed between RENAME,
                            # COPY and DROP.  The legacy table itself is the
                            # recovery marker; version 5 does not make it safe
                            # to ignore.
                            self._migrate_trusted_policies()
                        self._connection.execute("COMMIT")
                    except BaseException:
                        self._rollback()
                        raise
                    self._schema_version = SCHEMA_VERSION
        except (sqlite3.Error, ValueError) as error:
            self._connection.close()
            raise StoreError(
                f"cannot initialise the Admissible database: {error}") from None
        if self._schema_version > SCHEMA_VERSION:
            self._connection.close()
            raise StoreError(
                f"{self._path} was written by a newer Admissible "
                f"(schema {self._schema_version} > {SCHEMA_VERSION}); upgrade "
                "before using this store")

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
        """

        tables = {row["name"] for row in self._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        columns = {row["name"] for row in self._connection.execute(
            "PRAGMA table_info(trusted_policies)").fetchall()}
        legacy_exists = "trusted_policies_v4" in tables
        if "generation" in columns and not legacy_exists:
            return
        self._connection.execute(
            "DROP TRIGGER IF EXISTS trusted_policies_no_update")
        self._connection.execute(
            "DROP TRIGGER IF EXISTS trusted_policies_no_delete")
        self._connection.execute("DROP INDEX IF EXISTS trusted_policy_class")
        if not legacy_exists:
            self._connection.execute(
                "ALTER TABLE trusted_policies RENAME TO trusted_policies_v4")
            self._connection.execute("""
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
        legacy_columns = {row["name"] for row in self._connection.execute(
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
            ambiguous = self._connection.execute(
                "SELECT repository, class_id FROM trusted_policies_v4 "
                "GROUP BY repository, class_id HAVING "
                "COUNT(DISTINCT enforcement_digest) > 1 LIMIT 1").fetchone()
            if ambiguous is not None:
                raise sqlite3.DatabaseError(
                    "legacy trusted policies contain distinct enforcement "
                    "digests with no generation ordering")
        conflict = self._connection.execute(
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
        self._connection.execute(
            "INSERT OR IGNORE INTO trusted_policies(repository, class_id, "
            "policy_digest, enforcement_digest, trusted_at, generation) "
            "SELECT repository, class_id, policy_digest, enforcement_digest, "
            f"trusted_at, {generation} FROM trusted_policies_v4")
        ambiguous_current = self._connection.execute(
            "SELECT repository, class_id, generation FROM trusted_policies "
            "GROUP BY repository, class_id, generation HAVING "
            "COUNT(DISTINCT enforcement_digest) > 1 LIMIT 1").fetchone()
        if ambiguous_current is not None:
            raise sqlite3.DatabaseError(
                "one trusted-policy generation contains distinct "
                "enforcement digests")
        self._connection.execute("DROP TABLE trusted_policies_v4")
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS trusted_policy_class "
            "ON trusted_policies (repository, class_id, trusted_at)")
        self._connection.execute(
            "CREATE TRIGGER IF NOT EXISTS trusted_policies_no_update "
            "BEFORE UPDATE ON trusted_policies BEGIN SELECT RAISE(ABORT, "
            "'trusted policies are append-only'); END")
        self._connection.execute(
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
        self._connection.execute(
            "DROP TRIGGER IF EXISTS dependencies_no_update")
        self._connection.execute("""
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
            present = {row["name"] for row in self._connection.execute(
                f"PRAGMA table_info({table})").fetchall()}
            if column not in present:
                self._connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # -- basics ---------------------------------------------------------
    @property
    def home(self) -> Path:
        return self._home

    @property
    def path(self) -> str:
        return str(self._path)

    @property
    def connection(self) -> sqlite3.Connection:
        return self._connection

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
        return self._connection.execute(f"PRAGMA {name}").fetchone()[0]

    def close(self) -> None:
        _OPEN_STORES.discard(self)
        try:
            self._connection.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exception) -> bool:
        self.close()
        return False

    def _begin(self, busy_timeout_ms: int | None) -> None:
        if busy_timeout_ms is not None:
            self._connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            raise StoreError(
                "the Admissible database is locked or unavailable, so nothing "
                f"was recorded: {error}") from None

    def _rollback(self) -> None:
        try:
            self._connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _reset_busy_timeout(self, busy_timeout_ms: int | None) -> None:
        if busy_timeout_ms is not None:
            self._connection.execute(
                f"PRAGMA busy_timeout={DEFAULT_BUSY_TIMEOUT_MS}")

    # -- evidence -------------------------------------------------------
    def put_evidence(self, *, digest: str, kind: str, repository: str,
                     commit_sha: str, tree_sha: str, policy_digest: str,
                     record: dict) -> bool:
        """Ingest one evidence record idempotently; ``True`` when it was new."""

        try:
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO evidence(digest, kind, repository, "
                "commit_sha, tree_sha, policy_digest, record_json) "
                "VALUES(?,?,?,?,?,?,?)",
                (digest, kind, repository, commit_sha, tree_sha, policy_digest,
                 canonical_json(record)))
        except sqlite3.Error as error:
            raise StoreError(f"cannot record evidence: {error}") from None
        return cursor.rowcount == 1

    def evidence_for(self, repository: str, commit_sha: str) -> tuple[dict, ...]:
        rows = self._connection.execute(
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

    # -- journals and heads ---------------------------------------------
    def journal_events(self, journal_id: str) -> tuple[dict, ...]:
        rows = self._connection.execute(
            "SELECT event_json FROM journal_events WHERE journal_id=? "
            "ORDER BY position", (journal_id,)).fetchall()
        return tuple(json.loads(row["event_json"]) for row in rows)

    def current_head(self, journal_id: str) -> fcd_head.HeadReceipt | None:
        row = self._connection.execute(
            "SELECT r.receipt_json FROM current_head c "
            "JOIN head_receipts r ON r.receipt_hash = c.receipt_hash "
            "WHERE c.journal_id=?", (journal_id,)).fetchone()
        if row is None:
            return None
        return fcd_head.head_receipt_from_dict(json.loads(row["receipt_json"]))

    def accept_head(self, head_receipt: fcd_head.HeadReceipt,
                    events: Sequence[dict], verifier,
                    *, attachments: Iterable[tuple[str, tuple]] = (),
                    before_extend=None,
                    attachments_builder=None,
                    busy_timeout_ms: int | None = None,
                    _fault: str = "") -> fcd_head.HeadReceipt:
        """Durably accept ``head_receipt`` iff it extends the stored head.

        The predecessor check, extension check, event append, receipt insert and
        current-head compare-and-set all happen inside one ``BEGIN IMMEDIATE``
        transaction, so concurrent writers serialise instead of forking.
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
        attachments = tuple(attachments)

        self._begin(busy_timeout_ms)
        try:
            current = self.current_head(journal_id)
            # This deliberately precedes even an exact-head idempotency return.
            if before_extend is not None:
                before_extend()
            if current is not None and current.receipt_hash == head_receipt.receipt_hash:
                self._rollback()
                self._reset_busy_timeout(busy_timeout_ms)
                return current
            self._extend_head_locked(head_receipt, plain_events, _fault=_fault)
            for statement, parameters in attachments:
                self._connection.execute(statement, parameters)
            if attachments_builder is not None:
                attachments_builder()
            self._connection.execute("COMMIT")
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
        stored = self._connection.execute(
            "SELECT COUNT(*) AS total FROM journal_events WHERE journal_id=?",
            (journal_id,)).fetchone()["total"]
        expected_prefix = 0 if current is None else current.event_count
        if stored != expected_prefix:
            raise HeadConflict(
                f"stored journal has {stored} events but the current head "
                f"covers {expected_prefix}; refusing to write")
        for position in range(expected_prefix, head_receipt.event_count):
            event = plain_events[position]
            self._connection.execute(
                "INSERT INTO journal_events(journal_id, position, "
                "event_json, event_digest) VALUES(?,?,?,?)",
                (journal_id, position, canonical_json(event),
                 _event_digest(event)))
        if _fault == "after_events":
            raise StoreError("injected fault after appending events")
        self._connection.execute(
            "INSERT INTO head_receipts(receipt_hash, journal_id, "
            "event_count, previous_receipt_hash, receipt_json) "
            "VALUES(?,?,?,?,?)",
            (head_receipt.receipt_hash, journal_id,
             head_receipt.event_count, head_receipt.previous_receipt_hash,
             canonical_json(fcd_head.head_receipt_to_dict(head_receipt))))
        if current is None:
            self._connection.execute(
                "INSERT INTO current_head(journal_id, receipt_hash) "
                "VALUES(?,?)", (journal_id, head_receipt.receipt_hash))
        else:
            cursor = self._connection.execute(
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

    # -- workflow receipts ----------------------------------------------
    def workflow_receipt(self, receipt_hash: str):
        row = self._connection.execute(
            "SELECT receipt_json FROM workflow_receipts WHERE receipt_hash=?",
            (receipt_hash,)).fetchone()
        if row is None:
            return None
        return receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))

    def workflow_receipt_by_body(self, body_digest: str):
        row = self._connection.execute(
            "SELECT receipt_json FROM workflow_receipts WHERE body_digest=?",
            (body_digest,)).fetchone()
        if row is None:
            return None
        return receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))

    def receipts_for(self, repository: str, commit_sha: str) -> tuple:
        rows = self._connection.execute(
            "SELECT receipt_json FROM workflow_receipts "
            "WHERE repository=? AND commit_sha=? ORDER BY issued_at, receipt_hash",
            (repository, commit_sha)).fetchall()
        return tuple(receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))
                     for row in rows)

    def receipt_count(self, repository: str) -> int:
        return self._connection.execute(
            "SELECT COUNT(*) AS total FROM workflow_receipts WHERE repository=?",
            (repository,)).fetchone()["total"]

    def latest_receipt(self, repository: str):
        row = self._connection.execute(
            "SELECT receipt_json FROM workflow_receipts WHERE repository=? "
            "ORDER BY issued_at DESC, receipt_hash DESC LIMIT 1",
            (repository,)).fetchone()
        if row is None:
            return None
        return receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))

    def workflow_receipt_row(self, receipt, *,
                             idempotent: bool = False) -> tuple[str, tuple]:
        """The insert statement that stores ``receipt`` inside a head commit.

        The default is a plain ``INSERT``: inside the compare-and-set
        transaction a conflicting row means two different receipts claim one
        identity, and that must abort rather than vanish. ``idempotent`` is for
        replaying an already-authenticated chain during import.
        """

        document = receiptdata.receipt_to_dict(receipt)
        verb = "INSERT OR IGNORE" if idempotent else "INSERT"
        return (
            f"{verb} INTO workflow_receipts(receipt_hash, body_digest, "
            "journal_id, repository, commit_sha, tree_sha, policy_digest, "
            "class_id, state, issued_at, receipt_json, head_receipt_hash) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (receipt.receipt_hash, receipt.body_digest, receipt.journal_id,
             receipt.repository, receipt.commit_sha, receipt.tree_sha,
             receipt.policy_digest, receipt.class_id, receipt.state,
             receipt.issued_at, canonical_json(document),
             receipt.head.receipt_hash))

    def dependency_row(self, *, consumer_repository: str,
                       consumer_commit_sha: str, dependency_repository: str,
                       dependency_commit_sha: str,
                       recorded_at: int) -> tuple[str, tuple]:
        return (
            "INSERT OR IGNORE INTO dependencies(consumer_repository, "
            "consumer_commit_sha, dependency_repository, "
            "dependency_commit_sha, recorded_at) VALUES(?,?,?,?,?)",
            (consumer_repository, consumer_commit_sha, dependency_repository,
             dependency_commit_sha, recorded_at))

    # -- defects and dependencies ---------------------------------------
    def defect_row(self, *, digest: str, defect_id: str, repository: str,
                   commit_sha: str, filed_at: int, record: dict,
                   idempotent: bool = False) -> tuple[str, tuple]:
        """The insert that stores one defect inside its signing transaction.

        The default is a plain ``INSERT``. Inside the compare-and-set
        transaction a conflicting row means a second signed event is being
        appended for a defect that is already recorded, and that must abort:
        ``INSERT OR IGNORE`` there produced two events for one record, which
        import can only read as a forgery. ``idempotent`` is for replaying an
        already-authenticated chain during import.
        """

        verb = "INSERT OR IGNORE" if idempotent else "INSERT"
        return (
            f"{verb} INTO defects(defect_id, repository, commit_sha, "
            "digest, filed_at, record_json) VALUES(?,?,?,?,?,?)",
            (defect_id, repository, commit_sha, digest, filed_at,
             canonical_json(record)))

    def has_defect(self, digest: str) -> bool:
        return self._connection.execute(
            "SELECT 1 FROM defects WHERE digest=?", (digest,)).fetchone() is not None

    def defect_event_count(self, journal_id: str, digest: str) -> int:
        """Count signed-event claims for one defect in the current snapshot."""

        return sum(
            1 for event in self.journal_events(journal_id)
            if type(event) is dict
            and event.get("type") == receiptdata.EVENT_DEFECT
            and event.get("defect_digest") == digest)

    def evidence_in(self, repository: str) -> tuple[dict, ...]:
        rows = self._connection.execute(
            "SELECT digest, kind, commit_sha, record_json FROM evidence "
            "WHERE repository=? ORDER BY digest", (repository,)).fetchall()
        return tuple({"digest": row["digest"], "kind": row["kind"],
                      "commit_sha": row["commit_sha"],
                      "record": json.loads(row["record_json"])} for row in rows)

    def receipts_in(self, repository: str) -> tuple:
        rows = self._connection.execute(
            "SELECT receipt_json FROM workflow_receipts WHERE repository=? "
            "ORDER BY issued_at, receipt_hash", (repository,)).fetchall()
        return tuple(receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))
                     for row in rows)

    def defect_shas(self, repository: str) -> frozenset[str]:
        rows = self._connection.execute(
            "SELECT DISTINCT commit_sha FROM defects WHERE repository=?",
            (repository,)).fetchall()
        return frozenset(row["commit_sha"] for row in rows)

    def defects_for(self, repository: str, commit_sha: str) -> tuple[dict, ...]:
        rows = self._connection.execute(
            "SELECT record_json, filed_at FROM defects WHERE repository=? AND "
            "commit_sha=? ORDER BY filed_at, digest", (repository, commit_sha)
        ).fetchall()
        return tuple(json.loads(row["record_json"]) for row in rows)

    def defect_count(self, repository: str) -> int:
        return self._connection.execute(
            "SELECT COUNT(*) AS total FROM defects WHERE repository=?",
            (repository,)).fetchone()["total"]

    def all_defects(self, repository: str) -> tuple[dict, ...]:
        rows = self._connection.execute(
            "SELECT record_json FROM defects WHERE repository=? "
            "ORDER BY filed_at, digest", (repository,)).fetchall()
        return tuple(json.loads(row["record_json"]) for row in rows)

    def put_dependency(self, *, consumer_repository: str,
                       consumer_commit_sha: str, dependency_repository: str,
                       dependency_commit_sha: str, recorded_at: int) -> bool:
        try:
            cursor = self._connection.execute(
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
        rows = self._connection.execute(
            "SELECT consumer_repository, consumer_commit_sha FROM dependencies "
            "WHERE dependency_repository=? AND dependency_commit_sha=? "
            "ORDER BY consumer_repository, consumer_commit_sha",
            (repository, commit_sha)).fetchall()
        return tuple((row["consumer_repository"], row["consumer_commit_sha"])
                     for row in rows)

    # -- transactions ----------------------------------------------------
    def transact(self, builder, *, busy_timeout_ms: int | None = None):
        """Run ``builder`` inside one ``BEGIN IMMEDIATE`` transaction."""

        self._begin(busy_timeout_ms)
        try:
            result = builder()
            self._connection.execute("COMMIT")
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
            self._connection.execute(
                "INSERT OR IGNORE INTO attempts(attempt_id, repository, "
                "commit_sha, class_id, policy_digest, state, started_at, "
                "tree_sha, decision_json) VALUES(?,?,?,?,?,?,?,?,?)",
                (attempt_id, repository, commit_sha, class_id, policy_digest,
                 state, started_at, tree_sha,
                 "" if decision is None else canonical_json(decision)))
            for digest in digests:
                self._connection.execute(
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

        row = self._connection.execute(
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

        row = self._connection.execute(
            "SELECT attempt_id, repository, commit_sha, class_id, "
            "policy_digest, state, started_at, tree_sha, decision_json "
            "FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
        return None if row is None else self._attempt_row(row)

    def evidence_in_attempt(self, attempt_id: str) -> tuple[dict, ...]:
        rows = self._connection.execute(
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

        if self._connection.in_transaction:
            yield
            return
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            # COMMIT is part of the fallible transaction boundary.  In
            # particular, a deferred foreign-key violation is reported here,
            # not by the statement that created it.  Leaving this outside the
            # protected block strands the connection in a live transaction;
            # every later _atomic call then mistakes uncommitted state for an
            # outer owner's durable authority.
            self._connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise

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
                    self._connection.execute(
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
                self._connection.execute(
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

        if not self._connection.in_transaction:
            raise StoreError(
                "a cache sequence may only be allocated inside the same "
                "transaction as the cache fact it orders")
        try:
            cursor = self._connection.execute(
                "INSERT INTO cache_order DEFAULT VALUES")
        except sqlite3.Error as error:
            raise StoreError(
                f"cannot order this cache fact: {error}") from None
        return int(cursor.lastrowid)

    def cache_invalidated_at(self, cache_key: str) -> int | None:
        """When this cache key was last known to fail, if it ever was."""

        row = self._connection.execute(
            "SELECT MAX(invalidated_at) AS latest FROM "
            "evidence_cache_invalidations WHERE cache_key=?",
            (cache_key,)).fetchone()
        return None if row is None else row["latest"]

    def cache_invalidated_sequence(self, cache_key: str) -> int | None:
        """The last position at which this key was observed to fail."""

        row = self._connection.execute(
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
        :mod:`admissible.config`, where a policy is parsed and a missing bound
        can still be reported to whoever wrote it. This function is the
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
        row = self._connection.execute(
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

    # -- trusted policy baseline -----------------------------------------
    def _policy_generation_locked(self, repository: str, class_id: str) -> int:
        row = self._connection.execute(
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
        rows = self._connection.execute(
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
                same_enforcement = self._connection.execute(
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
                cursor = self._connection.execute(
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
                cursor = self._connection.execute(
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
                    rows = self._connection.execute(
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
                rows = self._connection.execute(
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

    # -- export / import -------------------------------------------------
    def has_head_receipt(self, receipt_hash: str) -> bool:
        return self._connection.execute(
            "SELECT 1 FROM head_receipts WHERE receipt_hash=?",
            (receipt_hash,)).fetchone() is not None

    def head_receipt_chain(self, journal_id: str) -> tuple[fcd_head.HeadReceipt, ...]:
        rows = self._connection.execute(
            "SELECT receipt_json FROM head_receipts WHERE journal_id=? "
            "ORDER BY event_count", (journal_id,)).fetchall()
        return tuple(fcd_head.head_receipt_from_dict(json.loads(row["receipt_json"]))
                     for row in rows)

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

    def read_transaction(self, reader):
        """Run ``reader`` inside one consistent read transaction."""

        try:
            self._connection.execute("BEGIN DEFERRED")
        except sqlite3.Error as error:
            raise StoreError(
                f"cannot open a consistent read of the store: {error}") from None
        try:
            result = reader()
        finally:
            self._rollback()
        return result

    def receipts_in_journal(self, journal_id: str) -> tuple:
        rows = self._connection.execute(
            "SELECT receipt_json FROM workflow_receipts WHERE journal_id=? "
            "ORDER BY issued_at, receipt_hash", (journal_id,)).fetchall()
        return tuple(receiptdata.receipt_from_dict(json.loads(row["receipt_json"]))
                     for row in rows)

    def _authenticated_repository_projection_locked(self, repository: str,
                                                      verifier) -> dict:
        """Validate one workflow namespace without trusting a bare SQL row.

        The caller owns a consistent read transaction.  The returned objects
        are the only rows standing may treat as authority: complete signed head
        chain, one admission row per admission event, exact receipt-bound
        evidence, one defect row per defect event, and dependency rows exactly
        reconstructed from signed receipt bodies.
        """

        from collections import Counter

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
            row = self._connection.execute(
                "SELECT digest, kind, record_json FROM evidence "
                "WHERE repository=? AND digest=?",
                (repository, digest)).fetchone()
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
        defect_rows = self._connection.execute(
            "SELECT digest, defect_id, commit_sha, filed_at, record_json "
            "FROM defects WHERE repository=? ORDER BY filed_at, digest",
            (repository,)).fetchall()
        for row in defect_rows:
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

        dependency_rows = self._connection.execute(
            "SELECT consumer_repository, consumer_commit_sha, "
            "dependency_repository, dependency_commit_sha, recorded_at "
            "FROM dependencies "
            "WHERE consumer_repository=?",
            (repository,)).fetchall()
        stored_dependency_times = {
            (row["consumer_repository"], row["consumer_commit_sha"],
             row["dependency_repository"], row["dependency_commit_sha"]):
            row["recorded_at"] for row in dependency_rows}
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
                for row in self._connection.execute(
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
                    row[key] for row in self._connection.execute(query).fetchall())
            projections: dict[str, dict] = {}
            invalid: set[str] = set()
            for repository in sorted(repositories):
                try:
                    projections[repository] = \
                        self._authenticated_repository_projection_locked(
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

        from collections import Counter

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
            statement, parameters = self.workflow_receipt_row(
                receipt, idempotent=True)
            self._connection.execute(statement, parameters)
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
                statement, parameters = self.dependency_row(
                    consumer_repository=receipt.repository,
                    consumer_commit_sha=receipt.commit_sha,
                    dependency_repository=dependency_repository,
                    dependency_commit_sha=dependency_sha,
                    recorded_at=receipt.issued_at)
                self._connection.execute(statement, parameters)
        for edge, expected_at in expected_dependency_times.items():
            stored = self._connection.execute(
                "SELECT recorded_at FROM dependencies WHERE "
                "consumer_repository=? AND consumer_commit_sha=? AND "
                "dependency_repository=? AND dependency_commit_sha=?",
                edge).fetchone()
            if (stored is not None and stored["recorded_at"] != expected_at
                    and expected_at < stored["recorded_at"]
                    and stored["recorded_at"] in
                    supported_dependency_times[edge]):
                # Receipt arrays are transport containers, not signed
                # authority order.  If a later receipt happened to be replayed
                # first, lower the derived row to the minimum issued_at that
                # the complete authentic set proves.  An unrelated unsigned
                # timestamp is not in the supported set and still refuses.
                self._connection.execute(
                    "UPDATE dependencies SET recorded_at=? WHERE "
                    "consumer_repository=? AND consumer_commit_sha=? AND "
                    "dependency_repository=? AND dependency_commit_sha=? "
                    "AND recorded_at=?",
                    (expected_at,) + edge + (stored["recorded_at"],))
                stored = self._connection.execute(
                    "SELECT recorded_at FROM dependencies WHERE "
                    "consumer_repository=? AND consumer_commit_sha=? AND "
                    "dependency_repository=? AND dependency_commit_sha=?",
                    edge).fetchone()
            if stored is None or stored["recorded_at"] != expected_at:
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
            self._connection.execute(
                "INSERT OR IGNORE INTO evidence(digest, kind, repository, "
                "commit_sha, tree_sha, policy_digest, record_json) "
                "VALUES(?,?,?,?,?,?,?)",
                (row["digest"], row["kind"], record["repository"],
                 record["commit_sha"], record["tree_sha"],
                 record["policy_digest"], canonical_json(record)))
            stored = self._connection.execute(
                "SELECT kind, repository, commit_sha, tree_sha, "
                "policy_digest, record_json FROM evidence WHERE digest=?",
                (row["digest"],)).fetchone()
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
            statement, parameters = self.defect_row(
                digest=digest, defect_id=defect.defect_id,
                repository=defect.repository, commit_sha=defect.commit_sha,
                filed_at=filed_at,
                record=evidence_module.defect_to_dict(defect),
                idempotent=True)
            self._connection.execute(statement, parameters)
            stored = self._connection.execute(
                "SELECT defect_id, repository, commit_sha, filed_at, "
                "record_json FROM defects WHERE digest=?", (digest,)).fetchone()
            if (stored is None or stored["defect_id"] != defect.defect_id
                    or stored["repository"] != defect.repository
                    or stored["commit_sha"] != defect.commit_sha
                    or stored["filed_at"] != filed_at
                    or stored["record_json"] != canonical_json(
                        evidence_module.defect_to_dict(defect))):
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
            Store._ensure_export_size(bundle)
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
            return self.transact(replay)
        except fcd_head.HeadVerificationError:
            raise StoreError(
                "journal export is not authentic under this key") from None


_OPEN_STORES: "weakref.WeakSet[Store]" = weakref.WeakSet()


def open_store(home: Path | str | None = None) -> Store:
    """Open (creating if needed) the durable store under ``home``."""

    opened = Store(default_home() if home is None else home)
    _OPEN_STORES.add(opened)
    return opened


def open_store_count() -> int:
    """How many stores this process opened and has not closed."""

    return len(_OPEN_STORES)
