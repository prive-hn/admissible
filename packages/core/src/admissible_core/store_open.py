"""The protocol every distribution follows before it may write to a home.

Opening the durable store has two moments a second process can ruin, and
neither of them is a moment SQLite protects.

The first is **creation**.  "Does the file exist", "create it with ``O_EXCL``",
"read the recorded version", "install the schema" is four steps over a path two
processes can both reach, and while they run there is no database yet -- only a
zero-byte file.  SQLite's own locking begins at the first page; it has nothing
to say about the interval before one exists.  So the mutual exclusion has to
start *before* the existence check and last until the schema and its version
are final, and it has to hold across processes, which means an operating-system
lock rather than an object in this interpreter.  :func:`schema_lock` is that
lock, keyed by the canonical absolute path of the database file so that two
spellings of one home are one key, and kept in a private directory of this
user's temporary space so that it is never a file inside the home it guards --
a lock that lives in the directory it protects disappears with it.

The second is the **look**.  Deciding whether this build may open a home at all
requires reading it, and the ordinary way to read a SQLite database writes to
it: a home in WAL mode grows a ``-wal`` and a ``-shm`` the moment a connection
touches it, and a home with a hot rollback journal is *replayed* on open.  Both
are writes to a database this build has not yet decided it is allowed to use,
and one of them may have been written by a build this one does not understand.
So the look is a URI connection opened ``mode=ro&immutable=1``: it cannot
create a sidecar, cannot recover one, and cannot be talked into a write by a
statement that gets past a review.

Which leaves the case where a sidecar is already there.  ``immutable=1`` on a
database with a live ``-wal`` would read the *stale* main file and answer
confidently with contents nobody has committed to -- worse than refusing.  A
sidecar also means the store may be open in another process right now.  Both
readings have the same safe answer, so :func:`refuse_open_sidecars` gives it:
stop, touch nothing, and say that the owner has to close or checkpoint the
store first.

That refusal has a cost, and it is deliberate rather than overlooked.  A live
writer locks every other process out of the home until it lets go, so an
abandoned process, or simply a long-running one, is a denial of service for the
rest.  Denial of service is the failure this kernel accepts everywhere it
cannot be sure; a plausible answer read out of a stale page is the one it does
not.

None of this is a sandbox and none of it is offered as one.  The lock is
advisory: it excludes the processes that agree to take it, which is every
Admissible distribution, and it excludes nothing else.  Anything running under
this account can open the database directly and write whatever it likes, and no
arrangement of files here changes that.
"""
from __future__ import annotations

import contextlib
import errno
import hashlib
import os
import sqlite3
import stat
import tempfile
import time
import urllib.parse
from pathlib import Path

from .store_base import SCHEMA_VERSION_KEY, StoreError

__all__ = [
    "DEFAULT_SCHEMA_LOCK_TIMEOUT_MS",
    "SIDECAR_SUFFIXES",
    "canonical_database_path",
    "database_uri",
    "open_sidecars",
    "recorded_schema_version_text",
    "refuse_a_layout_this_build_cannot_open",
    "refuse_an_unsupported_version",
    "refuse_open_sidecars",
    "schema_lock",
    "schema_lock_directory",
    "schema_lock_path",
]

# Long enough to cover a migration of a real home on a slow disk, short enough
# that a process which will never finish is reported rather than waited on for
# ever. A caller with a different tolerance passes its own.
DEFAULT_SCHEMA_LOCK_TIMEOUT_MS = 30_000

# The three files SQLite puts beside a database. Any of them means the store is
# open, or was left unclean by something that stopped.
SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")

_LOCK_DIRECTORY_PREFIX = "admissible-schema-locks"
# The lock is taken on byte 0, and the diagnostic stamp is written after it, so
# that the two never overlap on platforms whose locks are byte ranges.
_LOCK_BYTE = 0
_STAMP_OFFSET = 1
_STAMP_WIDTH = 256
_FIRST_POLL_SECONDS = 0.005
_MAX_POLL_SECONDS = 0.05

# Errno values that mean "somebody else holds it", as opposed to "this lock is
# broken". The first is worth waiting on; the second is worth reporting.
_CONTENDED = frozenset(
    value for value in (getattr(errno, name, None) for name in
                        ("EACCES", "EAGAIN", "EWOULDBLOCK", "EDEADLK"))
    if value is not None)

try:  # POSIX
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised on Windows only
    _fcntl = None
try:  # Windows
    import msvcrt as _msvcrt
except ImportError:  # POSIX
    _msvcrt = None


# -- where the lock lives ----------------------------------------------------
def canonical_database_path(database: Path | str) -> Path:
    """The one absolute path that names this database file.

    Two processes given ``~/.admissible/admissible.sqlite3`` and
    ``/tmp/../home/x/.admissible/admissible.sqlite3`` are talking about one
    file, and a lock keyed on the spelling rather than on the file would let
    them both hold it.  Symlinks are resolved for the same reason.
    """

    try:
        return Path(database).resolve()
    except OSError:  # pragma: no cover - a path the filesystem cannot answer
        return Path(os.path.abspath(str(database)))


def schema_lock_directory() -> Path:
    """The private directory this user's schema locks live in.

    Outside every Admissible home on purpose.  A lock inside the directory it
    guards is removed when that directory is, so the first process to delete a
    home would silently un-guard it for everybody still opening one.
    """

    name = _LOCK_DIRECTORY_PREFIX
    if hasattr(os, "getuid"):
        name = f"{name}-{os.getuid()}"
    return Path(tempfile.gettempdir()) / name


def schema_lock_path(database: Path | str) -> Path:
    """The lock file that guards ``database``.

    Named by digest rather than by path: the temporary directory is a place
    other people can list, and the full path of a home is more than a lock file
    needs to say about it.
    """

    canonical = canonical_database_path(database)
    digest = hashlib.sha256(
        str(canonical).encode("utf-8", "surrogateescape")).hexdigest()
    return schema_lock_directory() / f"{digest}.lock"


def _prepared_lock_directory() -> Path:
    """The lock directory, created if absent and refused if it is not ours.

    The temporary directory is shared, so the questions below are not
    paranoia: a directory somebody else owns, or one anybody may write, is a
    place where another account can plant the lock file this process is about
    to trust for mutual exclusion.
    """

    directory = schema_lock_directory()
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(directory)
    except OSError as error:
        raise StoreError(
            f"cannot use the schema lock directory {directory}: "
            f"{error.strerror}") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise StoreError(
            f"the schema lock directory {directory} is not a directory; "
            "refusing to take a schema lock through it")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise StoreError(
            f"the schema lock directory {directory} belongs to uid "
            f"{info.st_uid} rather than to this user, so a lock taken in it "
            "would exclude nobody; remove it or point TMPDIR elsewhere")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise StoreError(
            f"the schema lock directory {directory} is writable by group or "
            "others, so a lock taken in it would exclude nobody; run "
            "'chmod 700' on it")
    return directory


def _open_lock_file(lock: Path) -> int:
    """A descriptor on the lock file, or a refusal if it is not ours.

    The file is never unlinked, by this function or by the release path.
    Removing it would let one process lock the inode it opened while another
    creates and locks a new one under the same name -- two holders, one home,
    and no error anywhere.
    """

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(lock), flags, 0o600)
    except OSError as error:
        raise StoreError(
            f"cannot open the schema lock {lock}: {error.strerror}") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise StoreError(f"the schema lock {lock} is not a regular file")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise StoreError(
                f"the schema lock {lock} belongs to uid {info.st_uid} rather "
                "than to this user, so holding it would exclude nobody")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise StoreError(
                f"the schema lock {lock} is writable by group or others, so "
                "holding it would exclude nobody; run 'chmod 600' on it")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _take(descriptor: int) -> None:
    """One non-blocking attempt at the lock, raising :class:`OSError` if held."""

    if _fcntl is not None:
        _fcntl.flock(descriptor, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        return
    if _msvcrt is not None:  # pragma: no cover - exercised on Windows only
        os.lseek(descriptor, _LOCK_BYTE, os.SEEK_SET)
        _msvcrt.locking(descriptor, _msvcrt.LK_NBLCK, 1)
        return
    raise StoreError(  # pragma: no cover - no such Python on any target
        "this interpreter offers neither fcntl nor msvcrt, so no cross-process "
        "schema lock can be taken and initialising a store would be a race")


def _drop(descriptor: int) -> None:
    if _fcntl is not None:
        _fcntl.flock(descriptor, _fcntl.LOCK_UN)
    elif _msvcrt is not None:  # pragma: no cover - exercised on Windows only
        os.lseek(descriptor, _LOCK_BYTE, os.SEEK_SET)
        _msvcrt.locking(descriptor, _msvcrt.LK_UNLCK, 1)


def _stamp(descriptor: int, database: Path) -> None:
    """Record who holds the lock, for whoever ends up waiting on it.

    Written at a fixed width so it never has to be truncated, and past the byte
    the lock itself is taken on.  Failing to write it is not failing to hold
    the lock: this is a diagnostic, and turning a lock that was correctly
    acquired into an error because a comment could not be stored would trade a
    working store for a nicer message.
    """

    text = (f"held by pid {os.getpid()} since "
            f"{time.strftime('%Y-%m-%dT%H:%M:%S')} for {database}")
    payload = text.encode("utf-8", "replace")[:_STAMP_WIDTH]
    try:
        os.lseek(descriptor, _STAMP_OFFSET, os.SEEK_SET)
        os.write(descriptor, payload.ljust(_STAMP_WIDTH, b"\x00"))
    except OSError:
        pass


def _holder(descriptor: int) -> str:
    """What the current holder said about itself, if it managed to say it."""

    try:
        os.lseek(descriptor, _STAMP_OFFSET, os.SEEK_SET)
        raw = os.read(descriptor, _STAMP_WIDTH)
    except OSError:
        return "the holder left no diagnostic stamp"
    text = raw.decode("utf-8", "replace").replace("\x00", "").strip()
    return text or "the holder left no diagnostic stamp"


def _acquire(descriptor: int, lock: Path, database: Path,
             timeout_ms: int) -> None:
    deadline = time.monotonic() + max(0.0, timeout_ms / 1000.0)
    interval = _FIRST_POLL_SECONDS
    while True:
        try:
            _take(descriptor)
            return
        except OSError as error:
            if getattr(error, "errno", None) not in _CONTENDED:
                raise StoreError(
                    f"cannot take the schema lock {lock} that guards "
                    f"{database}: {error.strerror}") from None
            if time.monotonic() >= deadline:
                raise StoreError(
                    f"timed out after {timeout_ms} ms waiting for the schema "
                    f"lock {lock} that guards {database} ({_holder(descriptor)}"
                    "). Another Admissible process is creating or upgrading "
                    "this store; wait for it to finish, or stop it."
                ) from None
        time.sleep(interval)
        interval = min(interval * 2, _MAX_POLL_SECONDS)


@contextlib.contextmanager
def schema_lock(database: Path | str, *,
                timeout_ms: int = DEFAULT_SCHEMA_LOCK_TIMEOUT_MS):
    """Hold the cross-process lock that guards one database's initialisation.

    Take it *before* asking whether the file exists and hold it until the
    schema and the recorded version are final.  Anything less leaves the
    interval this lock exists to close.

    Not reentrant: the lock is an operating-system lock on a descriptor, and a
    second one taken in this process waits for the first exactly as another
    process would.  Nothing here nests, and nothing here should.
    """

    canonical = canonical_database_path(database)
    _prepared_lock_directory()
    lock = schema_lock_path(canonical)
    descriptor = _open_lock_file(lock)
    try:
        _acquire(descriptor, lock, canonical, timeout_ms)
        try:
            _stamp(descriptor, canonical)
            yield lock
        finally:
            _drop(descriptor)
    finally:
        os.close(descriptor)


# -- looking at a home without writing to it ---------------------------------
def open_sidecars(database: Path | str) -> tuple[Path, ...]:
    """Every ``-wal``, ``-shm`` or ``-journal`` file beside ``database``.

    A dangling symlink counts.  The question is whether something claims that
    name, not whether following it leads anywhere.
    """

    path = Path(database)
    found = []
    for suffix in SIDECAR_SUFFIXES:
        sibling = path.with_name(path.name + suffix)
        if os.path.lexists(str(sibling)):
            found.append(sibling)
    return tuple(found)


def refuse_open_sidecars(database: Path | str) -> None:
    """Stop if the store is open elsewhere, or was left unclean."""

    present = open_sidecars(database)
    if not present:
        return
    shared = len(Path(database).name)
    suffixes = [item.name[shared:] for item in present]
    names = ("a " + suffixes[0] if len(suffixes) == 1
             else ", ".join(suffixes))
    raise StoreError(
        f"{database} has {names} beside it, so this store is open in "
        "another process or was left behind by one that stopped. Its current "
        "contents are in that file rather than in the database, and reading "
        "them means replaying it -- a write to a home this build has not yet "
        "decided it may use. Close or checkpoint the store from the process "
        "that owns it, then try again.")


def database_uri(database: Path | str, *, query: str) -> str:
    """A SQLite URI for ``database``, with every awkward character quoted.

    ``?`` and ``#`` in a directory name are the ones that matter: unquoted,
    SQLite reads the rest of the path as query parameters or as a fragment, and
    the connection either fails or -- worse -- opens something else.
    """

    text = Path(database).as_posix()
    quoted = urllib.parse.quote(text, safe="/")
    if not quoted.startswith("/"):  # pragma: no cover - Windows drive letters
        quoted = f"/{quoted}"
    return f"file://{quoted}?{query}"


def recorded_schema_version_text(connection: sqlite3.Connection, *,
                                 path: Path | str | None = None) -> str | None:
    """The raw ``schema_version`` value a database records, or ``None``.

    ``None`` means "no version is recorded here" -- an empty file, or a home
    nobody has initialised -- which is a different answer from "the version is
    unreadable" and has a different consequence: one is initialised, the other
    is refused.  Returned as text rather than as a number so the caller decides
    what an uninterpretable value means.
    """

    try:
        versioned = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND "
            "name='schema_meta'").fetchone() is not None
        row = connection.execute(
            "SELECT value FROM schema_meta WHERE key=?",
            (SCHEMA_VERSION_KEY,)).fetchone() if versioned else None
    except sqlite3.Error as error:
        where = "" if path is None else f" of {path}"
        raise StoreError(
            f"cannot read the schema version{where}: {error}") from None
    return None if row is None else row[0]


def refuse_an_unsupported_version(recorded: object, *, path: Path | str,
                                  supported: int) -> int | None:
    """The version this database records, or a refusal this build must make.

    A version that is not a number identifies no layout, and a layout that
    cannot be identified cannot be migrated -- so it is refused rather than
    guessed at and then written over.
    """

    if recorded is None:
        return None
    try:
        version = int(recorded)
    except (TypeError, ValueError):
        raise StoreError(
            f"{path} records the schema version {recorded!r}, which is not a "
            "version number, so its layout cannot be identified; refusing to "
            "migrate or write to it") from None
    if version > supported:
        raise StoreError(
            f"{path} was written by a newer Admissible "
            f"(schema {version} > {supported}); upgrade before using this "
            "store")
    return version


def refuse_a_layout_this_build_cannot_open(database: Path | str, *,
                                           supported: int) -> int | None:
    """Decide whether this build may open a home, without writing to it.

    Call it with the schema lock held and before any read-write connection
    exists.  It answers with the recorded version, ``None`` for a home that
    records none, or a refusal -- and in every case the home comes out of the
    attempt byte for byte as it went in.
    """

    path = Path(database)
    refuse_open_sidecars(path)
    if not path.is_file():
        return None
    try:
        connection = sqlite3.connect(
            database_uri(path, query="mode=ro&immutable=1"), uri=True)
    except sqlite3.Error as error:
        raise StoreError(
            f"cannot read the Admissible database at {path}: {error}") from None
    try:
        recorded = recorded_schema_version_text(connection, path=path)
    finally:
        connection.close()
    return refuse_an_unsupported_version(recorded, path=path,
                                         supported=supported)
