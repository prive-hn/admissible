"""Contract: one cross-process lock, and a look at a store that cannot write.

Opening a durable home has two moments that a second process can ruin.

The first is *creation*.  ``exists()`` then ``O_EXCL`` then "install the
schema" is three steps, and two processes interleaving them produce one file
whose contents nobody agreed on: A creates it, B finds it and reads no version,
both run their own initialisation over it.  Nothing in SQLite prevents that,
because at that moment there is no database yet -- there is a zero-byte file.
So the mutual exclusion has to start *before* the existence check and last
until the schema and its version are final, and it has to hold across
processes, which means an operating-system lock rather than an object in this
interpreter.

The second is the *look*.  Deciding whether this build may open a home at all
requires reading it, and the ordinary way to read a SQLite database writes to
it: a home in WAL mode grows a ``-wal`` and a ``-shm`` the moment a connection
touches it, and a home with a hot rollback journal is *replayed* on open.  Both
are writes to a database this build has not yet decided it is allowed to use --
so the look is a URI connection opened ``mode=ro&immutable=1``, which cannot
create a sidecar and cannot recover one, and a home that already has a sidecar
beside it is refused outright rather than read through.

Refusing an active store is a real cost and it is deliberate.  A store another
process holds open is indistinguishable, from here, from one a crashed process
left unclean, and the safe answer to both is the same: do not touch it.  That
turns a live writer into a refusal for everyone else, which is a denial of
service rather than a wrong answer -- the trade this kernel makes everywhere.

None of this is a sandbox.  The lock is advisory and the processes that take it
are the ones that agree to; anything running under this account can open the
database directly with ``sqlite3`` and write whatever it likes, and no
arrangement of files here changes that.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from . import CORE_SRC, REPO_ROOT

from admissible_core.store_base import StoreError
from admissible_core import store_open

SUPPORTED = 6

# Takes the lock, says so by creating ``held``, and holds it until ``release``
# appears.  Run as a real process so the exclusion being measured is the
# operating system's rather than this interpreter's.
_HOLDER = """
import os, sys, time
from admissible_core.store_open import schema_lock

database, held, release = sys.argv[1], sys.argv[2], sys.argv[3]
with schema_lock(database, timeout_ms=60000):
    with open(held, "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))
    while not os.path.exists(release):
        time.sleep(0.01)
print("released")
"""

# Tries to take the same lock, and reports what happened either way.
_WAITER = """
import json, sys, time
from admissible_core.store_base import StoreError
from admissible_core.store_open import schema_lock

database, timeout = sys.argv[1], int(sys.argv[2])
started = time.monotonic()
try:
    with schema_lock(database, timeout_ms=timeout):
        print(json.dumps({"took": True, "waited": time.monotonic() - started}))
except StoreError as error:
    print(json.dumps({"took": False, "error": str(error)}))
"""


def probe_env() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")}
    environment["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{CORE_SRC}"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


class StoreOpenCase(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(self.scratch())
        self.database = self.home / "admissible.sqlite3"

    def scratch(self) -> str:
        raw = tempfile.mkdtemp(prefix="admissible-core-store-open-")
        self.addCleanup(shutil.rmtree, raw, True)
        return raw

    def write_database(self, version: object = SUPPORTED) -> Path:
        """A plain rollback-journal database recording one schema version."""

        raw = sqlite3.connect(str(self.database), isolation_level=None)
        try:
            raw.execute("CREATE TABLE schema_meta ("
                        "key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            if version is not None:
                raw.execute(
                    "INSERT INTO schema_meta VALUES('schema_version', ?)",
                    (str(version),))
        finally:
            raw.close()
        return self.database

    def fingerprint(self) -> dict:
        found = {}
        for item in sorted(self.home.iterdir()):
            status = item.stat()
            found[item.name] = (
                hashlib.sha256(item.read_bytes()).hexdigest(),
                status.st_size, status.st_mtime_ns,
                stat.S_IMODE(status.st_mode))
        return found

    def run_program(self, program: str, *arguments: str,
                    timeout: float = 60) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-c", program, *arguments],
            capture_output=True, text=True, timeout=timeout,
            cwd=str(REPO_ROOT), env=probe_env())

    def start(self, program: str, *arguments: str) -> subprocess.Popen:
        process = subprocess.Popen(
            [sys.executable, "-c", program, *arguments],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(REPO_ROOT), env=probe_env())
        self.addCleanup(self._reap, process)
        return process

    def _reap(self, process: subprocess.Popen) -> None:
        if process.poll() is None:  # pragma: no cover - cleanup path
            process.kill()
        process.communicate()

    def await_file(self, path: Path, *, timeout: float = 30) -> None:
        deadline = time.monotonic() + timeout
        while not path.exists():
            if time.monotonic() >= deadline:  # pragma: no cover - diagnostic
                self.fail(f"{path} never appeared")
            time.sleep(0.01)


class TheLockIsKeyedByTheCanonicalDatabasePath(StoreOpenCase):
    """One database, one lock -- however the caller spelled the path."""

    def test_a_relative_spelling_keys_the_same_lock_as_the_absolute_one(self):
        self.database.parent.mkdir(parents=True, exist_ok=True)
        absolute = store_open.schema_lock_path(self.database)
        cwd = os.getcwd()
        os.chdir(str(self.home))
        try:
            relative = store_open.schema_lock_path("admissible.sqlite3")
            dotted = store_open.schema_lock_path("./sub/../admissible.sqlite3")
        finally:
            os.chdir(cwd)
        self.assertEqual(absolute, relative)
        self.assertEqual(absolute, dotted)

    def test_a_symlinked_home_keys_the_lock_of_the_real_one(self):
        alias = Path(self.scratch()) / "alias"
        try:
            alias.symlink_to(self.home, target_is_directory=True)
        except (OSError, NotImplementedError) as error:  # pragma: no cover
            self.skipTest(f"symlinks unsupported here: {error}")
        self.assertEqual(
            store_open.schema_lock_path(self.database),
            store_open.schema_lock_path(alias / "admissible.sqlite3"))

    def test_two_databases_get_two_locks(self):
        other = Path(self.scratch()) / "admissible.sqlite3"
        self.assertNotEqual(store_open.schema_lock_path(self.database),
                            store_open.schema_lock_path(other))

    def test_the_lock_is_not_inside_the_admissible_home(self):
        """A lock inside the home is a file the home's owner can delete."""

        lock = store_open.schema_lock_path(self.database)
        self.assertNotIn(self.home.resolve(), lock.resolve().parents)
        self.assertIn(Path(tempfile.gettempdir()).resolve(),
                      lock.resolve().parents)

    def test_the_lock_name_is_a_digest_rather_than_the_path(self):
        """The temp directory is shared; a readable path there leaks the home."""

        lock = store_open.schema_lock_path(self.database)
        digest = hashlib.sha256(
            str(self.database.resolve()).encode("utf-8")).hexdigest()
        self.assertEqual(f"{digest}.lock", lock.name)


class TheLockFileAndItsDirectoryArePrivate(StoreOpenCase):
    def test_the_directory_is_owner_only_and_owned_by_this_user(self):
        with store_open.schema_lock(self.database):
            directory = store_open.schema_lock_directory()
            info = os.lstat(directory)
        self.assertTrue(stat.S_ISDIR(info.st_mode))
        self.assertEqual(0, stat.S_IMODE(info.st_mode) & 0o077)
        if hasattr(os, "getuid"):
            self.assertEqual(os.getuid(), info.st_uid)

    def test_the_lock_file_is_owner_only(self):
        with store_open.schema_lock(self.database) as lock:
            self.assertEqual(0o600, stat.S_IMODE(lock.stat().st_mode))

    def test_the_lock_file_persists_after_release(self):
        """Unlinking it would let two processes lock two different inodes."""

        with store_open.schema_lock(self.database) as lock:
            pass
        self.assertTrue(lock.is_file())

    def test_a_lock_file_owned_by_somebody_else_is_refused(self):
        if not hasattr(os, "getuid"):  # pragma: no cover - POSIX only
            self.skipTest("uid ownership is a POSIX notion")
        lock = store_open.schema_lock_path(self.database)
        store_open.schema_lock_directory().mkdir(mode=0o700, parents=True,
                                                 exist_ok=True)
        lock.write_bytes(b"")
        # Registered before the assertion: a world-writable lock file left in
        # the shared directory would outlive a failing test.
        self.addCleanup(lock.unlink, True)
        lock.chmod(0o666)
        with self.assertRaises(StoreError) as raised:
            with store_open.schema_lock(self.database):
                pass  # pragma: no cover - the lock must not be granted
        self.assertIn("group or others", str(raised.exception))


class TheLockExcludesAnotherProcess(StoreOpenCase):
    """Measured with real processes: an object in this interpreter cannot."""

    def held_and_release(self) -> tuple[Path, Path]:
        scratch = Path(self.scratch())
        return scratch / "held", scratch / "release"

    def test_a_second_process_cannot_take_a_held_lock(self):
        held, release = self.held_and_release()
        holder = self.start(_HOLDER, str(self.database), str(held),
                            str(release))
        self.await_file(held)
        completed = self.run_program(_WAITER, str(self.database), "150")
        release.write_text("go", encoding="utf-8")
        holder.communicate(timeout=30)
        self.assertEqual(0, completed.returncode, completed.stderr)
        answer = json.loads(completed.stdout)
        self.assertFalse(answer["took"], "the lock was granted twice")

    def test_the_timeout_says_what_it_waited_for_and_who_held_it(self):
        held, release = self.held_and_release()
        holder = self.start(_HOLDER, str(self.database), str(held),
                            str(release))
        self.await_file(held)
        pid = held.read_text(encoding="utf-8").strip()
        completed = self.run_program(_WAITER, str(self.database), "150")
        release.write_text("go", encoding="utf-8")
        holder.communicate(timeout=30)
        message = json.loads(completed.stdout)["error"]
        self.assertIn(str(store_open.schema_lock_path(self.database)), message)
        self.assertIn(str(self.database), message)
        self.assertIn("150", message)
        self.assertIn(pid, message, "the timeout must name the holder")

    def test_the_lock_is_granted_the_moment_the_holder_lets_go(self):
        held, release = self.held_and_release()
        holder = self.start(_HOLDER, str(self.database), str(held),
                            str(release))
        self.await_file(held)
        waiter = self.start(_WAITER, str(self.database), "30000")
        time.sleep(0.4)
        self.assertIsNone(waiter.poll(), "the waiter did not block")
        release.write_text("go", encoding="utf-8")
        holder.communicate(timeout=30)
        stdout, stderr = waiter.communicate(timeout=30)
        self.assertEqual(0, waiter.returncode, stderr)
        answer = json.loads(stdout)
        self.assertTrue(answer["took"])
        self.assertGreater(answer["waited"], 0.3)

    def test_a_holder_that_dies_leaves_the_lock_free(self):
        """An operating-system lock, not a flag file somebody has to clean up."""

        held, release = self.held_and_release()
        holder = self.start(_HOLDER, str(self.database), str(held),
                            str(release))
        self.await_file(held)
        holder.kill()
        holder.communicate(timeout=30)
        completed = self.run_program(_WAITER, str(self.database), "10000")
        self.assertTrue(json.loads(completed.stdout)["took"], completed.stderr)

    def test_the_lock_is_released_when_the_body_raises(self):
        class Boom(RuntimeError):
            pass

        with self.assertRaises(Boom):
            with store_open.schema_lock(self.database):
                raise Boom
        completed = self.run_program(_WAITER, str(self.database), "5000")
        self.assertTrue(json.loads(completed.stdout)["took"], completed.stderr)


class SidecarsFailClosed(StoreOpenCase):
    """A ``-wal``, ``-shm`` or ``-journal`` beside the file ends the attempt."""

    def sidecar(self, suffix: str) -> Path:
        path = self.database.with_name(self.database.name + suffix)
        path.write_bytes(b"")
        return path

    def test_each_sidecar_is_named_in_its_own_refusal(self):
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                self.setUp()
                self.write_database()
                self.sidecar(suffix)
                with self.assertRaises(StoreError) as raised:
                    store_open.refuse_a_layout_this_build_cannot_open(
                        self.database, supported=SUPPORTED)
                self.assertIn(suffix, str(raised.exception))

    def test_the_refusal_reads_nothing_and_changes_nothing(self):
        self.write_database()
        self.sidecar("-wal")
        before = self.fingerprint()
        with self.assertRaises(StoreError):
            store_open.refuse_a_layout_this_build_cannot_open(
                self.database, supported=SUPPORTED)
        self.assertEqual(before, self.fingerprint())

    def test_a_sidecar_without_a_database_is_still_refused(self):
        self.sidecar("-wal")
        with self.assertRaises(StoreError):
            store_open.refuse_a_layout_this_build_cannot_open(
                self.database, supported=SUPPORTED)

    def test_a_dangling_sidecar_symlink_is_refused_rather_than_followed(self):
        self.write_database()
        link = self.database.with_name(self.database.name + "-journal")
        try:
            link.symlink_to(self.home / "nowhere")
        except (OSError, NotImplementedError) as error:  # pragma: no cover
            self.skipTest(f"symlinks unsupported here: {error}")
        with self.assertRaises(StoreError):
            store_open.refuse_a_layout_this_build_cannot_open(
                self.database, supported=SUPPORTED)

    def test_a_clean_database_has_no_sidecar_and_is_not_refused(self):
        self.write_database()
        self.assertEqual((), store_open.open_sidecars(self.database))
        self.assertEqual(
            SUPPORTED,
            store_open.refuse_a_layout_this_build_cannot_open(
                self.database, supported=SUPPORTED))


class TheLookIsReadOnlyAndImmutable(StoreOpenCase):
    def test_a_missing_database_records_no_version(self):
        self.assertIsNone(store_open.refuse_a_layout_this_build_cannot_open(
            self.database, supported=SUPPORTED))

    def test_a_database_without_schema_meta_records_no_version(self):
        raw = sqlite3.connect(str(self.database), isolation_level=None)
        raw.execute("CREATE TABLE other (value TEXT)")
        raw.close()
        self.assertIsNone(store_open.refuse_a_layout_this_build_cannot_open(
            self.database, supported=SUPPORTED))

    def test_a_schema_meta_without_the_row_records_no_version(self):
        self.write_database(version=None)
        self.assertIsNone(store_open.refuse_a_layout_this_build_cannot_open(
            self.database, supported=SUPPORTED))

    def test_an_older_version_is_reported_rather_than_refused(self):
        self.write_database(version=SUPPORTED - 2)
        self.assertEqual(
            SUPPORTED - 2,
            store_open.refuse_a_layout_this_build_cannot_open(
                self.database, supported=SUPPORTED))

    def test_a_newer_version_is_refused(self):
        self.write_database(version=SUPPORTED + 1)
        with self.assertRaises(StoreError) as raised:
            store_open.refuse_a_layout_this_build_cannot_open(
                self.database, supported=SUPPORTED)
        self.assertIn("newer Admissible", str(raised.exception))

    def test_a_malformed_version_is_refused(self):
        for recorded in ("", "  ", "six", "6.0", "0x7", "v7"):
            with self.subTest(recorded=recorded):
                self.setUp()
                self.write_database(version=recorded)
                with self.assertRaises(StoreError) as raised:
                    store_open.refuse_a_layout_this_build_cannot_open(
                        self.database, supported=SUPPORTED)
                self.assertIn("not a version number", str(raised.exception))

    def test_the_look_creates_no_sidecar_and_moves_no_byte(self):
        self.write_database()
        before = self.fingerprint()
        store_open.refuse_a_layout_this_build_cannot_open(
            self.database, supported=SUPPORTED)
        self.assertEqual(before, self.fingerprint())
        self.assertEqual([self.database.name], sorted(self.fingerprint()))

    def test_the_look_connection_cannot_write_even_if_asked(self):
        """``immutable=1`` is the guarantee; the ordering is only the plan."""

        self.write_database()
        uri = store_open.database_uri(self.database,
                                      query="mode=ro&immutable=1")
        connection = sqlite3.connect(uri, uri=True)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute("CREATE TABLE intruder (value TEXT)")
        finally:
            connection.close()

    def test_a_path_with_uri_metacharacters_is_quoted_rather_than_parsed(self):
        awkward = Path(self.scratch()) / "a home?x=1#frag 100% odd"
        awkward.mkdir()
        self.home = awkward
        self.database = awkward / "admissible.sqlite3"
        self.write_database(version=SUPPORTED + 1)
        with self.assertRaises(StoreError) as raised:
            store_open.refuse_a_layout_this_build_cannot_open(
                self.database, supported=SUPPORTED)
        self.assertIn("newer Admissible", str(raised.exception))


class TheModuleSurface(unittest.TestCase):
    def test_the_declared_exports_are_exactly_the_promised_names(self):
        self.assertEqual(
            {
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
            },
            set(store_open.__all__))

    def test_every_refusal_is_a_store_error(self):
        """One exception type, so a caller catches the open protocol at once."""

        self.assertTrue(issubclass(StoreError, ValueError))


if __name__ == "__main__":
    unittest.main()
