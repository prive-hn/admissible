"""Shared persistence vocabulary, and the capability facades built on it.

One Admissible home is shared by both authorities, so where it is, what the
database file is called, and how a connection to it is configured have to be
said once.  Two answers to "which directory is the store in" is two stores, and
the second one is silently empty.

What this module deliberately does *not* do is own the schema.  There is no
``CREATE TABLE`` here and no migration: a kernel that created tables would be
fixing the storage contract for two distributions that have not been written
yet, and the first thing it would do to a home that already exists is change
it.  :func:`connect` opens what is there and refuses what is not.

Nor does it own the *order* in which a home is opened.  Taking the lock that
makes initialisation exclusive across processes, and looking at a home without
writing to it, live in :mod:`admissible_core.store_open` -- one module further
out, so that this one stays what its name says: where the store is and what a
facade may reach.

The rest of the module is the capability model.  A facade is a *closed* set of
method names forwarded to an injected backend -- never a subclass of it, never
a passthrough for whatever it is asked for.  The distinction matters because
the backend is one object with every method on it: the durable store can accept
a head, issue a receipt and make a policy enforceable, and handing that object
to candidate-side code hands over all three.  Naming the reachable set is what
turns "Ready does not call ``trust_policy``" into "Ready cannot".

:data:`WITHHELD_CAPABILITIES` is the other half of the same statement.  Denying
an unknown name is automatic; denying a name that *does* exist on the backend,
with a message saying whose it is, is the part that has to be written down --
and it is what makes the denial provable, because a test can check that every
withheld name is a real method that a real backend really offers.

Which leaves the object itself.  A facade that stores its backend in an
attribute, or that answers an allowed name with the backend's own bound method,
has handed the whole backend to anyone holding the view: ``facade._backend``,
or ``facade.evidence_for.__self__``, and every denial above is decoration.  So
the backend is not on the facade at all.  It lives in the module-private
registry below, keyed weakly by the facade, and an allowed name is answered
with a facade-owned call path that resolves the backend method at call time and
never hands it out.

None of that is a sandbox, and it is not offered as one.  This is one
interpreter: ``gc.get_referrers``, this module's own registry and the frame
stack are all reachable from any code running in the process, and no
arrangement of Python objects changes that.  The guarantee is narrower and
still worth having -- a component handed a capability-limited view cannot
*use* it to reach withheld authority, so an over-grant is a failure here rather
than an escape in production.  Isolation from code that is actively hostile and
already running in the same account is an operating-system problem, and the
distribution split exists so that such code is not invited in to begin with.
"""
from __future__ import annotations

import os
import sqlite3
import weakref
from pathlib import Path
from typing import Any

__all__ = [
    "CANDIDATE_WRITE_CAPABILITIES",
    "CapabilityError",
    "CapabilityFacade",
    "DATABASE_FILENAME",
    "DEFAULT_BUSY_TIMEOUT_MS",
    "HOME_ENVIRONMENT_VARIABLE",
    "HeadConflict",
    "READ_CAPABILITIES",
    "SCHEMA_VERSION_KEY",
    "StoreError",
    "WITHHELD_CAPABILITIES",
    "WITHHELD_OWNERS",
    "capability_owner",
    "connect",
    "database_path",
    "default_home",
    "require_home_outside",
    "schema_version",
]

HOME_ENVIRONMENT_VARIABLE = "ADMISSIBLE_HOME"
DEFAULT_HOME_DIRECTORY = ".admissible"
DATABASE_FILENAME = "admissible.sqlite3"
DEFAULT_BUSY_TIMEOUT_MS = 5000
SCHEMA_VERSION_KEY = "schema_version"


class StoreError(ValueError):
    """The durable store refused an operation and wrote nothing."""


class HeadConflict(StoreError):
    """A proposed head does not extend the stored current head."""


class CapabilityError(StoreError, AttributeError):
    """A facade was asked for a capability it does not grant.

    Deliberately an :class:`AttributeError` as well as a
    :class:`StoreError`.  ``__getattr__`` is how Python asks whether an object
    can do something, and an exception outside that protocol would make
    ``hasattr`` raise rather than answer -- so a caller probing the surface
    would crash instead of finding out that the capability is withheld.
    """


# -- where the store is ------------------------------------------------------
def default_home(environment: dict[str, str] | None = None) -> Path:
    """The Admissible home this environment selects."""

    source = os.environ if environment is None else environment
    configured = (source.get(HOME_ENVIRONMENT_VARIABLE) or "").strip()
    if configured:
        return Path(configured)
    return Path.home() / DEFAULT_HOME_DIRECTORY


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
            f"{HOME_ENVIRONMENT_VARIABLE} {home} is inside the repository "
            f"under evaluation ({root}). The store and the private check logs "
            "are written there during the run, so they would make the worktree "
            "dirty and the gate would refuse this commit -- blaming a check "
            f"that did nothing wrong. Point {HOME_ENVIRONMENT_VARIABLE} at a "
            "directory outside this repository.")
    return home


def database_path(home: Path | str) -> Path:
    """The one database file an Admissible home keeps its records in."""

    return Path(home) / DATABASE_FILENAME


# -- how a connection is configured ------------------------------------------
def connect(home: Path | str, *,
            busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS
            ) -> sqlite3.Connection:
    """Open the database an Admissible home already has.

    An absent database is refused rather than created.  Creating it here would
    hand back a connection with no tables in it, and every read through that
    connection would answer "nothing was ever recorded" when the true answer is
    "this is not an Admissible home" -- which is the difference between a
    repository with no defects and a repository whose defects are somewhere
    else.

    No schema is written, checked or upgraded.  The pragmas below configure the
    *connection*; they do not touch the contents.
    """

    path = database_path(home)
    if not path.is_file():
        raise StoreError(
            f"no Admissible database at {path}: this home has not been "
            "initialised, and opening it would create an empty one that reads "
            "as a home with nothing in it")
    try:
        connection = sqlite3.connect(
            str(path), timeout=busy_timeout_ms / 1000.0, isolation_level=None)
    except sqlite3.Error as error:
        raise StoreError(
            f"cannot open the Admissible database at {path}: {error}") from None
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        connection.execute("PRAGMA synchronous=FULL")
    except sqlite3.Error as error:
        connection.close()
        raise StoreError(
            f"cannot configure the Admissible database at {path}: {error}"
        ) from None
    return connection


def schema_version(connection: sqlite3.Connection) -> int:
    """The schema version this database records, read and never written."""

    try:
        row = connection.execute(
            "SELECT value FROM schema_meta WHERE key=?",
            (SCHEMA_VERSION_KEY,)).fetchone()
    except sqlite3.Error as error:
        raise StoreError(f"cannot read the schema version: {error}") from None
    if row is None:
        raise StoreError(
            "this database records no schema version, so its layout cannot be "
            "identified; it was not written by Admissible")
    return int(row["value"])


# -- what a facade may reach -------------------------------------------------
# Reads. Nothing here changes a byte, so both facades grant all of it. The
# trusted-policy rows are reads on purpose: knowing which policy an operator
# made enforceable is what lets candidate-side code refuse to evaluate under a
# policy nobody trusted. Making one enforceable is the withheld half.
READ_CAPABILITIES = frozenset({
    # identity of the home itself
    "home", "path", "schema_version",
    # evidence
    "evidence_for", "evidence_in", "evidence_in_attempt",
    # journals and heads
    "journal_events", "current_head", "head_receipt_chain", "has_head_receipt",
    # receipts, as records rather than as authority
    "workflow_receipt", "workflow_receipt_by_body", "receipts_for",
    "receipts_in", "receipts_in_journal", "receipt_count", "latest_receipt",
    # defects
    "has_defect", "defect_event_count", "defect_shas", "defects_for",
    "defect_count", "all_defects",
    # dependencies
    "direct_consumers",
    # attempts
    "attempt", "latest_attempt",
    # the evidence cache
    "cache_key", "cached_command_evidence", "cache_invalidated_at",
    "cache_invalidated_sequence",
    # the trusted-policy baseline, read-only
    "policy_generation", "trusted_policies", "revoked_policies",
    # a read-only transaction, so a multi-row read can be consistent
    "read_transaction",
})

# Writes a candidate-side run makes about its own observations. None of them
# asserts anything: evidence, an attempt and a cache entry describe what was
# seen, and a receipt is what would make a description binding.
CANDIDATE_WRITE_CAPABILITIES = frozenset({
    "put_evidence",
    "record_attempt",
    "put_dependency",
    "cache_command_evidence",
    "next_cache_sequence",
})

# Capabilities the backend has and no Core facade hands out, each with the
# phrase that names whose they are. Written out rather than left to the
# default denial so the refusal is checkable: a test can assert that every
# name here is a real method of a real backend, which a typo would fail.
WITHHELD_OWNERS: dict[str, str] = {
    "accept_head": "the Trust distribution, which anchors heads",
    "import_journal": "the Trust distribution, which authenticates imports",
    "verify_journal": "the Trust distribution, which holds the verifier",
    "authenticated_workflow_state":
        "the Trust distribution, which holds the verifier",
    "workflow_receipt_row": "the Trust distribution, which issues receipts",
    "defect_row": "the Trust distribution, which files defects",
    # Current split-Trust names.  Keep the legacy builder names above because
    # the 0.7 compatibility surface still uses them; both vocabularies must
    # diagnose the same authority boundary rather than fall through to a
    # generic "no capability surface" refusal.
    "insert_workflow_receipt":
        "the Trust distribution, which issues receipts",
    "insert_defect": "the Trust distribution, which files defects",
    "insert_receipt_evidence":
        "the Trust distribution, which binds evidence to receipts",
    "insert_dependency_edge":
        "the Trust distribution, which records dependency evidence",
    "lower_dependency_recorded_at":
        "the Trust distribution, which authenticates imported dependencies",
    "trust_policy": "the Trust distribution, which makes a policy enforceable",
    "revoke_policy": "the Trust distribution, which withdraws one",
    "transact": "the Trust distribution: an unrestricted write transaction is "
                "every withheld capability at once",
    "close": "the owner of this backend, which decides its lifetime",
}
WITHHELD_CAPABILITIES = frozenset(WITHHELD_OWNERS)


def capability_owner(name: str) -> str:
    """The phrase naming who a capability belongs to, for a refusal message."""

    if name in WITHHELD_OWNERS:
        return WITHHELD_OWNERS[name]
    if name in CANDIDATE_WRITE_CAPABILITIES:
        return "the candidate write surface (CandidateStore)"
    return "no capability surface this kernel defines"


# Facade -> backend, keyed weakly so a facade nobody holds is collected and
# takes its entry with it.  The *value* is a strong reference on purpose: while
# a facade is alive its backend must be too, or a view would go hollow under a
# caller who is still using it.  Nothing stored here refers back to a key, so
# the weak keys really do die.
_BACKENDS: "weakref.WeakKeyDictionary[CapabilityFacade, Any]" = (
    weakref.WeakKeyDictionary())

_NOT_PORTABLE = (
    "names a backend held in this process: a copy would either carry that "
    "authority somewhere it was never granted, or arrive bound to nothing and "
    "read as a store with no records in it")


def _backend_of(facade: "CapabilityFacade") -> Any:
    """The backend a facade was built on, or a refusal if it has none."""

    backend = _BACKENDS.get(facade)
    if backend is None:
        raise CapabilityError(
            f"this {type(facade).__name__} is bound to no backend, so nothing "
            "can be reached through it")
    return backend


class _Capability:
    """One named call path into the backend, owned by the facade that made it.

    Deliberately not the backend's bound method.  A bound method carries its
    receiver in ``__self__``, so returning one would answer "you may call
    ``evidence_for``" with the object that can also anchor a head and issue a
    receipt.  This resolves the method at call time and drops it again.
    """

    __slots__ = ("_facade", "_name")

    def __init__(self, facade: "CapabilityFacade", name: str) -> None:
        self._facade = facade
        self._name = name

    @property
    def __self__(self) -> "CapabilityFacade":
        """The facade, so a caller inspecting the binding finds the view."""

        return self._facade

    @property
    def __name__(self) -> str:
        return self._name

    def __call__(self, *args: Any, **kwargs: Any):
        return getattr(_backend_of(self._facade), self._name)(*args, **kwargs)

    def __repr__(self) -> str:
        return (f"<capability {self._name!r} of "
                f"{type(self._facade).__name__}>")

    def __reduce__(self):
        raise CapabilityError(
            f"the capability {self._name!r} cannot be pickled or copied: it "
            f"{_NOT_PORTABLE}")


class CapabilityFacade:
    """A closed set of backend methods, and nothing else.

    Subclasses declare :attr:`CAPABILITIES`; every other name is refused,
    whether or not the backend happens to offer it.  Construction checks that
    the backend actually provides what the facade promises, because a facade
    that forwards to a method nobody implemented is a facade that fails at the
    moment it is used rather than at the moment it is built.

    The instance carries no state at all -- no ``__dict__``, and its one slot
    is the weak-reference support the registry needs.  There is therefore no
    attribute, mangled or otherwise, that answers with the backend.
    """

    CAPABILITIES: frozenset[str] = frozenset()

    __slots__ = ("__weakref__",)

    def __init__(self, backend: Any) -> None:
        capabilities = type(self).CAPABILITIES
        missing = sorted(
            name for name in capabilities if not hasattr(backend, name))
        if missing:
            raise StoreError(
                f"{type(self).__name__} cannot be built on a "
                f"{type(backend).__name__}: it is missing "
                f"{len(missing)} of {len(capabilities)} required capabilities "
                f"({', '.join(missing)})")
        _BACKENDS[self] = backend

    def __getattr__(self, name: str):
        # Reached for every name, since the instance holds no attributes: the
        # facade's own methods resolve on the class and never arrive here.
        if name in type(self).CAPABILITIES:
            value = getattr(_backend_of(self), name)
            # A property's value is a value -- a Path, a version number. Only
            # something callable is authority worth wrapping.
            return _Capability(self, name) if callable(value) else value
        raise CapabilityError(
            f"{name!r} is not available through {type(self).__name__}: it "
            f"belongs to {capability_owner(name)}")

    def __repr__(self) -> str:
        backend = _BACKENDS.get(self)
        over = "nothing" if backend is None else type(backend).__name__
        return (f"<{type(self).__name__} over {over} granting "
                f"{len(type(self).CAPABILITIES)} capabilities>")

    def __reduce__(self):
        raise CapabilityError(
            f"a {type(self).__name__} cannot be pickled or copied: it "
            f"{_NOT_PORTABLE}")
