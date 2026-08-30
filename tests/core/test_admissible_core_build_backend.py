"""Contract: the in-tree PEP 517 backend stages sources it can authenticate.

``packages/core/build_backend.py`` is the only code in this repository that
copies one directory over another at a fixed path while a second process may be
doing the same thing.  Four claims follow from that and are asserted here rather
than assumed.

*Exclusion.*  ``_staged/`` is a single fixed path shared by every hook of every
concurrent build.  Two builds interleaving there produce a wheel assembled from
two different refreshes -- a mixed artefact whose exit status is zero -- so the
whole stage/hook/cleanup lifecycle is held under one cross-process lock, and the
test for it runs real simultaneous builds rather than reasoning about them.

*Authentication.*  "Four sibling directories exist" is a statement about a
parent directory, and the parent directory of an extracted sdist belongs to
whoever extracted it.  The backend must identify *this* checkout -- an exact
project path inside a repository that names itself -- and an extracted sdist
must use its own bundled bytes even when unpacked next to four hostile roots
wearing the right names.

*Symlinks.*  A staged root is copied, so a symlink inside it is a request to
copy whatever it points at into a published artefact.  It is refused by path,
never followed, and the refusal names the file.

*Closure.*  The staged bytes are pinned by a manifest of relative paths and
SHA-256 digests that travels inside the sdist, so a wheel built from the sdist
is built from the bytes the sdist shipped and from no others -- missing, extra,
and altered are three different refusals and all three are refusals.

*Artefacts.*  Everything above is checked before setuptools runs, and setuptools
reads the staged tree afterwards.  The gap between those two moments is real:
another process sharing this UID can alter a verified file, or replace the
directory holding it, while the packager is walking it, and the result is an
artefact whose bytes were never the ones anybody verified.  So the built wheel
and the built sdist are *reopened* and compared against the closure held in
memory, and a mismatch deletes the artefact rather than returning it.

*Descriptors.*  A refusal by path is a statement about what a directory held
when it was looked at.  Reads are therefore anchored to descriptors opened once
with ``O_DIRECTORY|O_NOFOLLOW``: a parent renamed away and replaced by a symlink
mid-walk cannot redirect the reads that follow it, and a directory that became a
link before it was opened is refused.

*Locks.*  Waiting is the answer to contention and to nothing else.  A permanent
descriptor or filesystem fault reported by the locking primitive must be raised
with its real cause immediately, because a build that reports "another build
held the lock for 600s" for an ``EBADF`` sends its reader looking for a process
that never existed.

What none of this claims is a sandbox.  The scope statement lives at the top of
``build_backend.py``; the tests below assert exactly that scope and no more.
"""
from __future__ import annotations

import contextlib
import errno
import hashlib
import importlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import time
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from tests.architecture import inspect_wheel

from . import CORE_PROJECT, REPO_ROOT

BACKEND_PATH = CORE_PROJECT / "build_backend.py"
SDIST_NAME = "admissible_core-0.8.0"

# The roots the backend stages, and the subdirectories it prunes at the copy.
STAGED_ROOTS = {"fcd": (), "rga": (), "atlas": ("tests",), "protocol": ()}


def load_backend():
    """Import ``build_backend.py`` by path, as a PEP 517 frontend would.

    It is not on ``sys.path`` and must not be: ``backend-path`` names a file
    inside the project, and importing it any other way would test a copy.
    """
    spec = importlib.util.spec_from_file_location(
        "admissible_core_build_backend_under_test", BACKEND_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BACKEND = load_backend()


def digest_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree_digests(root: Path, skip: tuple[str, ...] = ()) -> dict[str, str]:
    """``{relative posix path: sha256}`` for every regular file under ``root``."""
    found = {}
    for path in sorted(Path(root).rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in skip or "__pycache__" in relative:
            continue
        found[relative] = digest_of(path)
    return found


def can_symlink(directory: Path) -> bool:
    probe = Path(directory) / "__symlink_probe__"
    try:
        probe.symlink_to(Path(directory))
    except (OSError, NotImplementedError, AttributeError):
        return False
    probe.unlink()
    return True


def sample_tree(root: Path) -> Path:
    """A miniature staged root: two modules and one nested package."""
    root = Path(root)
    (root / "inner").mkdir(parents=True)
    (root / "__init__.py").write_bytes(b"# root\n")
    (root / "core.py").write_bytes(b"VALUE = 1\n")
    (root / "inner" / "__init__.py").write_bytes(b"# inner\n")
    cache = root / "__pycache__"
    cache.mkdir()
    (cache / "core.cpython-999.pyc").write_bytes(b"\x00")
    return root


# -- the sdist, built once ---------------------------------------------------
_SDIST: dict = {}


def built_sdist() -> Path:
    """Build the source distribution once per interpreter."""
    if "path" not in _SDIST:
        workspace = tempfile.TemporaryDirectory(prefix="admissible-core-backend-")
        _SDIST["workspace"] = workspace
        outdir = Path(workspace.name) / "dist"
        outdir.mkdir(parents=True)
        completed = subprocess.run(
            [sys.executable, "-m", "build", "--sdist", "--no-isolation",
             "--outdir", str(outdir), str(CORE_PROJECT)],
            capture_output=True, text=True, timeout=inspect_wheel.BUILD_TIMEOUT,
            cwd=str(CORE_PROJECT), env=inspect_wheel.sanitized_env(),
        )
        produced = sorted(outdir.glob("*.tar.gz"))
        if completed.returncode != 0 or len(produced) != 1:
            raise AssertionError(
                f"sdist build produced {produced} (exit {completed.returncode})\n"
                f"{completed.stderr[-4000:]}")
        _SDIST["path"] = produced[0]
    return _SDIST["path"]


def extract_sdist(destination: Path) -> Path:
    """Unpack the sdist under ``destination`` and return the project directory."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(built_sdist()) as archive:
        archive.extractall(destination, filter="data")
    return destination / SDIST_NAME


def tearDownModule():  # noqa: N802 - unittest's spelling
    workspace = _SDIST.pop("workspace", None)
    if workspace is not None:
        workspace.cleanup()


class TheBackendExposesTheHooksAndTheSeamsUnderTest(unittest.TestCase):
    def test_every_pep_517_hook_this_project_needs_is_exported(self):
        for hook in ("build_wheel", "build_sdist",
                     "get_requires_for_build_wheel",
                     "get_requires_for_build_sdist",
                     "prepare_metadata_for_build_wheel"):
            with self.subTest(hook=hook):
                self.assertIn(hook, BACKEND.__all__)
                self.assertTrue(callable(getattr(BACKEND, hook)))

    def test_the_staged_roots_are_the_four_the_distribution_ships(self):
        self.assertEqual(STAGED_ROOTS, dict(BACKEND.STAGED_ROOTS))

    def test_the_refusals_are_named_types_a_caller_can_catch(self):
        for name in ("BuildBackendError", "SymlinkRefused", "StagingMismatch",
                     "LockTimeout", "SourcesNotIdentified", "ArtifactMismatch",
                     "UnsafeTraversal"):
            with self.subTest(error=name):
                error = getattr(BACKEND, name)
                self.assertTrue(issubclass(error, Exception))


class StagingRefusesEverySymlinkItMeets(unittest.TestCase):
    """A staged root is copied; a symlink in one is a request to copy elsewhere.

    Following it would publish whatever it points at -- a key outside the
    repository, a file in another user's home -- inside a wheel, and would do it
    silently.  Every link is refused by path instead, at any depth, whether it
    names a file or a directory, and the refusal says which path.
    """

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="core-symlink-")
        self.root = Path(self.workspace.name)
        if not can_symlink(self.root):
            self.skipTest("this platform cannot create symlinks")
        self.source = sample_tree(self.root / "source")
        self.destination = self.root / "staged"
        self.outside = self.root / "outside"
        self.outside.mkdir()
        (self.outside / "secret.txt").write_bytes(b"not for publication\n")

    def tearDown(self):
        self.workspace.cleanup()

    def stage(self):
        return BACKEND.stage_root(self.source, self.destination,
                                  STAGED_ROOTS["fcd"])

    def test_a_tree_without_links_stages_and_reports_its_digests(self):
        staged = self.stage()
        self.assertEqual(
            {"__init__.py", "core.py", "inner/__init__.py"}, set(staged))
        self.assertEqual(tree_digests(self.source), staged)

    def test_a_file_symlink_is_refused_and_named(self):
        link = self.source / "leak.py"
        link.symlink_to(self.outside / "secret.txt")
        with self.assertRaises(BACKEND.SymlinkRefused) as refusal:
            self.stage()
        self.assertIn("leak.py", str(refusal.exception))

    def test_a_directory_symlink_is_refused_and_named(self):
        link = self.source / "elsewhere"
        link.symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(BACKEND.SymlinkRefused) as refusal:
            self.stage()
        self.assertIn("elsewhere", str(refusal.exception))

    def test_a_symlink_nested_below_the_top_level_is_refused(self):
        link = self.source / "inner" / "leak.py"
        link.symlink_to(self.outside / "secret.txt")
        with self.assertRaises(BACKEND.SymlinkRefused) as refusal:
            self.stage()
        self.assertIn("leak.py", str(refusal.exception))

    def test_a_symlinked_root_is_refused_rather_than_dereferenced(self):
        linked = self.root / "linked-source"
        linked.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(BACKEND.SymlinkRefused) as refusal:
            BACKEND.stage_root(linked, self.destination, ())
        self.assertIn("linked-source", str(refusal.exception))

    def test_a_refused_link_publishes_nothing_it_pointed_at(self):
        (self.source / "leak.py").symlink_to(self.outside / "secret.txt")
        with self.assertRaises(BACKEND.SymlinkRefused):
            self.stage()
        published = [path for path in self.destination.rglob("*")
                     if path.is_file() and b"not for publication" in path.read_bytes()]
        self.assertEqual([], published)

    def test_a_link_inside_a_pruned_subdirectory_is_not_the_build_s_business(self):
        """``atlas/tests`` never reaches the copy, so it cannot poison it."""
        pruned = self.source / "tests"
        pruned.mkdir()
        (pruned / "leak.py").symlink_to(self.outside / "secret.txt")
        staged = BACKEND.stage_root(self.source, self.destination, ("tests",))
        self.assertEqual(
            {"__init__.py", "core.py", "inner/__init__.py"}, set(staged))

    def test_build_artefacts_are_not_staged(self):
        self.assertNotIn("__pycache__/core.cpython-999.pyc", self.stage())


class StagedBytesAreBoundByAClosedManifest(unittest.TestCase):
    """The manifest is the artefact contract: these paths, these digests, no others.

    An sdist-derived wheel is only worth having if it is built from the bytes the
    sdist shipped.  Nothing else in the archive says which those are -- setuptools
    will happily package whatever is sitting under ``_staged/`` -- so the set is
    closed by name and pinned by digest, and missing, extra and altered are three
    separate refusals.
    """

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="core-manifest-")
        self.root = Path(self.workspace.name)
        self.staging = self.root / "_staged"
        self.files = {}
        for name, pruned in STAGED_ROOTS.items():
            source = sample_tree(self.root / "sources" / name)
            staged = BACKEND.stage_root(source, self.staging / name, pruned)
            self.files.update({f"{name}/{k}": v for k, v in staged.items()})
        BACKEND.write_manifest(self.staging, self.files)

    def tearDown(self):
        self.workspace.cleanup()

    def manifest_path(self) -> Path:
        return self.staging / BACKEND.MANIFEST_NAME

    def test_a_faithful_staging_verifies_and_reports_what_it_holds(self):
        self.assertEqual(self.files, BACKEND.verify_staging(self.staging))

    def test_the_manifest_names_the_package_roots_it_closes_over(self):
        document = json.loads(self.manifest_path().read_text("utf-8"))
        self.assertEqual(sorted(STAGED_ROOTS), document["roots"])

    def test_the_manifest_holds_relative_paths_and_digests_and_nothing_else(self):
        text = self.manifest_path().read_text("utf-8")
        self.assertNotIn(str(self.root), text)
        self.assertNotIn("\\", text)
        for path, sha in self.files.items():
            with self.subTest(path=path):
                self.assertFalse(path.startswith("/"))
                self.assertEqual(64, len(sha))

    def test_the_manifest_carries_no_clock_reading(self):
        """Two identical trees must produce identical manifest bytes."""
        document = json.loads(self.manifest_path().read_text("utf-8"))
        self.assertEqual({"version", "roots", "files"}, set(document))
        before = self.manifest_path().read_bytes()
        BACKEND.write_manifest(self.staging, self.files)
        self.assertEqual(before, self.manifest_path().read_bytes())

    def test_a_missing_staged_file_is_refused_and_named(self):
        (self.staging / "fcd" / "core.py").unlink()
        with self.assertRaises(BACKEND.StagingMismatch) as refusal:
            BACKEND.verify_staging(self.staging)
        self.assertIn("fcd/core.py", str(refusal.exception))

    def test_an_extra_staged_file_is_refused_and_named(self):
        (self.staging / "fcd" / "smuggled.py").write_bytes(b"import os\n")
        with self.assertRaises(BACKEND.StagingMismatch) as refusal:
            BACKEND.verify_staging(self.staging)
        self.assertIn("fcd/smuggled.py", str(refusal.exception))

    def test_an_altered_staged_file_is_refused_and_named(self):
        (self.staging / "rga" / "core.py").write_bytes(b"VALUE = 2\n")
        with self.assertRaises(BACKEND.StagingMismatch) as refusal:
            BACKEND.verify_staging(self.staging)
        self.assertIn("rga/core.py", str(refusal.exception))

    def test_a_staging_with_no_manifest_at_all_is_refused(self):
        self.manifest_path().unlink()
        with self.assertRaises(BACKEND.StagingMismatch):
            BACKEND.verify_staging(self.staging)

    def test_a_manifest_naming_other_roots_is_refused(self):
        document = json.loads(self.manifest_path().read_text("utf-8"))
        document["roots"] = ["fcd"]
        self.manifest_path().write_text(json.dumps(document), "utf-8")
        with self.assertRaises(BACKEND.StagingMismatch):
            BACKEND.verify_staging(self.staging)

    def test_a_symlink_smuggled_into_a_staged_tree_is_refused(self):
        if not can_symlink(self.root):
            self.skipTest("this platform cannot create symlinks")
        target = self.root / "secret.txt"
        target.write_bytes(b"not for publication\n")
        (self.staging / "fcd" / "core.py").unlink()
        (self.staging / "fcd" / "core.py").symlink_to(target)
        with self.assertRaises(BACKEND.SymlinkRefused) as refusal:
            BACKEND.verify_staging(self.staging)
        self.assertIn("core.py", str(refusal.exception))


class TheBuildLockIsExclusiveAcrossProcesses(unittest.TestCase):
    """One lock, held for stage, hook and cleanup together, owned by nobody.

    A lock released between staging and setuptools' hook is not a lock: the
    window it leaves open is exactly the window in which the fixed ``_staged``
    path gets refreshed under a running build.  And a lock whose file is deleted
    on the way out is worse than none, because the next two builds open two
    different inodes and both succeed in taking it.
    """

    def probe(self, *, timeout: str, expect: int) -> subprocess.CompletedProcess:
        """Run one hook in a child process and report how it ended."""
        code = textwrap.dedent(f"""
            import importlib.util, sys
            spec = importlib.util.spec_from_file_location(
                "bb", {str(BACKEND_PATH)!r})
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            try:
                module.get_requires_for_build_wheel()
            except module.LockTimeout as refusal:
                print(type(refusal).__name__)
                print(refusal)
                sys.exit(3)
            sys.exit(0)
        """)
        completed = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
            timeout=inspect_wheel.RUN_TIMEOUT, cwd=str(CORE_PROJECT),
            env=inspect_wheel.sanitized_env(
                {BACKEND.LOCK_TIMEOUT_VARIABLE: timeout}),
        )
        self.assertEqual(expect, completed.returncode,
                         f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}")
        return completed

    def test_the_lock_lives_beside_the_staging_tree_and_not_inside_it(self):
        """Deleting the staging tree must not delete the lock that guards it."""
        self.assertEqual(CORE_PROJECT, BACKEND.LOCK_PATH.parent)
        self.assertNotEqual(BACKEND.STAGING, BACKEND.LOCK_PATH)
        self.assertFalse(
            str(BACKEND.LOCK_PATH).startswith(f"{BACKEND.STAGING}{os.sep}"))

    def test_a_second_holder_waits_rather_than_proceeding(self):
        with BACKEND.build_lock():
            completed = self.probe(timeout="1", expect=3)
        self.assertIn("LockTimeout", completed.stdout)
        self.assertIn(str(BACKEND.LOCK_PATH), completed.stdout)

    def test_the_wait_is_over_when_the_holder_lets_go(self):
        with BACKEND.build_lock():
            pass
        self.probe(timeout="60", expect=0)

    def test_the_lock_file_survives_the_build_that_took_it(self):
        with BACKEND.build_lock():
            pass
        self.assertTrue(BACKEND.LOCK_PATH.is_file())
        self.probe(timeout="60", expect=0)
        self.assertTrue(BACKEND.LOCK_PATH.is_file(),
                        "a cleanup that deletes the lock file un-serialises the "
                        "next two builds")

    def test_a_killed_holder_denies_nobody(self):
        """The operating system releases the lock; no stale marker outlives it."""
        code = textwrap.dedent(f"""
            import importlib.util, sys, time
            spec = importlib.util.spec_from_file_location(
                "bb", {str(BACKEND_PATH)!r})
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with module.build_lock(timeout=60):
                sys.stdout.write("held\\n")
                sys.stdout.flush()
                time.sleep(600)
        """)
        holder = subprocess.Popen(
            [sys.executable, "-c", code], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, cwd=str(CORE_PROJECT),
            env=inspect_wheel.sanitized_env(),
        )
        try:
            self.assertEqual("held\n", holder.stdout.readline())
            with self.assertRaises(BACKEND.LockTimeout):
                with BACKEND.build_lock(timeout=1):
                    pass
        finally:
            holder.kill()
            holder.wait(timeout=inspect_wheel.RUN_TIMEOUT)
            holder.stdout.close()
            holder.stderr.close()
        with BACKEND.build_lock(timeout=30):
            pass

    def test_the_lock_is_reentrant_for_nobody_within_one_process(self):
        """Two threads of one process are two builds as far as ``_staged`` cares."""
        entered = threading.Event()
        second_got_in = threading.Event()

        def contend():
            try:
                with BACKEND.build_lock(timeout=1):
                    second_got_in.set()
            except BACKEND.LockTimeout:
                pass

        with BACKEND.build_lock(timeout=30):
            entered.set()
            worker = threading.Thread(target=contend)
            worker.start()
            worker.join(timeout=inspect_wheel.RUN_TIMEOUT)
        self.assertFalse(second_got_in.is_set())


class ARefusedStagingLeavesNothingInTheCheckout(unittest.TestCase):
    """The refusal happens against the real roots, and cleans up after itself.

    A half-written ``_staged/`` is the same dirty working tree as a leftover
    complete one -- four packages under a second dotted name, which the import
    census refuses -- so the cleanup covers the refusals as well as the hook.
    This is also the only test that plants a link in the repository's own
    ``fcd/``, which is where a real one would have to be to matter.
    """

    def setUp(self):
        self.link = REPO_ROOT / "fcd" / "__staging_link_probe__.py"
        self.addCleanup(self.remove_link)
        # A PEP 517 frontend runs every hook with the project directory as the
        # working directory, and setuptools reads its configuration from there:
        # called from the repository root, these hooks would describe the
        # umbrella project instead of Core.
        origin = Path.cwd()
        self.addCleanup(os.chdir, str(origin))
        os.chdir(str(CORE_PROJECT))
        if not can_symlink(REPO_ROOT / "fcd"):
            self.skipTest("this platform cannot create symlinks")

    def remove_link(self):
        if self.link.is_symlink() or self.link.exists():
            self.link.unlink()

    def test_a_link_in_a_real_root_refuses_the_hook_and_removes_the_half_copy(self):
        self.link.symlink_to(REPO_ROOT / "README.md")
        with self.assertRaises(BACKEND.SymlinkRefused) as refusal:
            BACKEND.get_requires_for_build_wheel()
        self.assertIn("__staging_link_probe__.py", str(refusal.exception))
        self.assertFalse((CORE_PROJECT / "_staged").exists())

    def test_the_hook_works_again_once_the_link_is_gone(self):
        self.link.symlink_to(REPO_ROOT / "README.md")
        with self.assertRaises(BACKEND.SymlinkRefused):
            BACKEND.get_requires_for_build_wheel()
        self.remove_link()
        # setuptools narrates its manifest work on stdout; the hook's answer is
        # what is under test, and the narration is not this suite's output.
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            BACKEND.get_requires_for_build_wheel()
        self.assertFalse((CORE_PROJECT / "_staged").exists())


class CanonicalSourcesAreIdentifiedAndNotMerelyAdjacent(unittest.TestCase):
    """Four sibling directories are a coincidence; a checkout is an identity.

    The old test -- ``fcd``, ``rga``, ``atlas`` and ``protocol`` all exist two
    levels up -- is a statement about a parent directory, and the parent
    directory of an extracted sdist is chosen by whoever extracted it.  This one
    asks the questions only the real checkout can answer.
    """

    def test_this_checkout_is_recognised(self):
        self.assertTrue(BACKEND.is_canonical_checkout())

    def test_the_project_must_sit_at_packages_core_of_its_repository(self):
        self.assertEqual(REPO_ROOT / "packages" / "core", CORE_PROJECT)
        self.assertEqual(REPO_ROOT, BACKEND.REPOSITORY)

    def test_a_lookalike_parent_full_of_the_right_names_is_not_a_checkout(self):
        with tempfile.TemporaryDirectory(prefix="core-lookalike-") as workspace:
            fake = Path(workspace) / "packages" / "core"
            fake.mkdir(parents=True)
            for name in STAGED_ROOTS:
                (Path(workspace) / name).mkdir()
                (Path(workspace) / name / "__init__.py").write_bytes(b"")
            self.assertFalse(BACKEND.is_canonical_checkout(fake))

    def test_a_repository_that_does_not_name_itself_is_not_this_one(self):
        with tempfile.TemporaryDirectory(prefix="core-unnamed-") as workspace:
            root = Path(workspace)
            shutil.copytree(REPO_ROOT / "fcd", root / "fcd")
            shutil.copytree(REPO_ROOT / "rga", root / "rga")
            shutil.copytree(REPO_ROOT / "atlas", root / "atlas",
                            ignore=shutil.ignore_patterns("tests"))
            shutil.copytree(REPO_ROOT / "protocol", root / "protocol")
            (root / ".git").mkdir()
            (root / "pyproject.toml").write_text(
                '[project]\nname = "not-admissible"\n', "utf-8")
            project = root / "packages" / "core"
            project.mkdir(parents=True)
            shutil.copy2(CORE_PROJECT / "pyproject.toml", project / "pyproject.toml")
            self.assertFalse(BACKEND.is_canonical_checkout(project))

    def test_a_bundled_sdist_is_never_treated_as_a_checkout_to_refresh(self):
        """``PKG-INFO`` is present in every sdist and in no working tree."""
        with tempfile.TemporaryDirectory(prefix="core-overridden-") as workspace:
            project = extract_sdist(Path(workspace))
            self.assertTrue((project / "PKG-INFO").is_file())
            self.assertFalse(BACKEND.is_canonical_checkout(project))


class AnExtractedSdistUsesItsOwnBundledBytes(unittest.TestCase):
    """Hostile roots wearing the right names next door change nothing.

    An sdist is unpacked wherever its consumer chooses -- a build container's
    scratch directory, a shared ``/tmp``, a path an attacker also writes to.  If
    "the roots are next door" were the test, unpacking under a prepared parent
    would substitute four packages into a published wheel.  The bundled bytes
    win, and they win even when the hostile parent also carries the repository's
    own name and a ``.git``.
    """

    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="core-hostile-")
        cls.root = Path(cls.workspace.name)
        cls.expected = {
            f"{name}/{relative}": sha
            for name, pruned in STAGED_ROOTS.items()
            for relative, sha in tree_digests(
                REPO_ROOT / name,
            ).items()
            if not any(relative.startswith(f"{skip}/") for skip in pruned)
        }

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def poison(self, parent: Path) -> dict[str, bytes]:
        """Four attacker-controlled roots wearing the names the backend stages."""
        planted = {}
        for name in STAGED_ROOTS:
            root = parent / name
            root.mkdir(parents=True, exist_ok=True)
            payload = f"HOSTILE = {name!r}\n".encode()
            (root / "__init__.py").write_bytes(payload)
            (root / "hostile_marker.py").write_bytes(payload)
            planted[f"{name}/hostile_marker.py"] = payload
        (parent / "protocol" / "hostile.schema.json").write_bytes(b"{}\n")
        return planted

    def assert_wheel_is_bundled(self, wheel: inspect_wheel.Wheel):
        strays = [member for member in wheel.payload if "hostile" in member]
        self.assertEqual([], strays, "an attacker's file reached the wheel")
        for member in wheel.payload:
            root = member.split("/")[0]
            if root not in STAGED_ROOTS:
                continue
            with self.subTest(member=member):
                self.assertEqual(self.expected.get(member), wheel.sha256(member),
                                 f"{member} is not the repository's byte")

    def test_hostile_siblings_of_the_extracted_project_are_ignored(self):
        parent = self.root / "plain"
        project = extract_sdist(parent)
        self.poison(parent)
        wheel = inspect_wheel.inspect_wheel(
            inspect_wheel.build_wheel(project, self.root / "plain-out"))
        self.assert_wheel_is_bundled(wheel)

    def test_a_hostile_parent_dressed_as_this_repository_is_ignored(self):
        """Right path, right repository name, right ``.git`` -- wrong bytes."""
        repository = self.root / "dressed"
        (repository / "packages").mkdir(parents=True)
        (repository / ".git").mkdir()
        (repository / "pyproject.toml").write_text(
            '[project]\nname = "admissible"\nversion = "0.8.0"\n', "utf-8")
        self.poison(repository)
        extracted = extract_sdist(self.root / "dressed-src")
        shutil.move(str(extracted), str(repository / "packages" / "core"))
        project = repository / "packages" / "core"
        wheel = inspect_wheel.inspect_wheel(
            inspect_wheel.build_wheel(project, self.root / "dressed-out"))
        self.assert_wheel_is_bundled(wheel)

    def test_an_extracted_sdist_keeps_its_staged_tree_after_a_build(self):
        """There is no second copy: deleting it would delete the source."""
        parent = self.root / "kept"
        project = extract_sdist(parent)
        inspect_wheel.build_wheel(project, self.root / "kept-out")
        self.assertTrue((project / "_staged" / "fcd" / "__init__.py").is_file())

    def test_a_project_that_is_neither_a_checkout_nor_an_sdist_is_refused(self):
        """Better a named refusal than a wheel that silently ships four fewer packages."""
        stripped = self.root / "stripped"
        project = extract_sdist(stripped)
        shutil.rmtree(project / "_staged")
        (project / "PKG-INFO").unlink()
        with self.assertRaises(inspect_wheel.BuildFailed) as failure:
            inspect_wheel.build_wheel(project, self.root / "stripped-out")
        self.assertIn("SourcesNotIdentified", str(failure.exception))


class TheSdistPinsTheBytesTheWheelIsBuiltFrom(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="core-pinned-")
        self.root = Path(self.workspace.name)

    def tearDown(self):
        self.workspace.cleanup()

    def members(self) -> list[str]:
        with tarfile.open(built_sdist()) as archive:
            return sorted(archive.getnames())

    def test_the_sdist_carries_the_staged_manifest(self):
        self.assertIn(f"{SDIST_NAME}/_staged/{BACKEND.MANIFEST_NAME}",
                      self.members())

    def test_the_manifest_closes_over_every_staged_member_of_the_sdist(self):
        prefix = f"{SDIST_NAME}/_staged/"
        with tarfile.open(built_sdist()) as archive:
            document = json.loads(
                archive.extractfile(f"{prefix}{BACKEND.MANIFEST_NAME}").read())
            staged = {
                member.name[len(prefix):]: hashlib.sha256(
                    archive.extractfile(member).read()).hexdigest()
                for member in archive.getmembers()
                if member.isfile() and member.name.startswith(prefix)
                and member.name != f"{prefix}{BACKEND.MANIFEST_NAME}"
            }
        self.assertEqual(dict(document["files"]), staged)

    def test_the_sdist_does_not_ship_the_lock_that_guarded_its_build(self):
        strays = [member for member in self.members() if member.endswith(".lock")]
        self.assertEqual([], strays)

    def test_a_missing_bundled_file_stops_the_sdist_derived_build(self):
        project = extract_sdist(self.root / "missing")
        (project / "_staged" / "fcd" / "journal.py").unlink()
        with self.assertRaises(inspect_wheel.BuildFailed) as failure:
            inspect_wheel.build_wheel(project, self.root / "missing-out")
        self.assertIn("fcd/journal.py", str(failure.exception))

    def test_an_extra_bundled_file_stops_the_sdist_derived_build(self):
        project = extract_sdist(self.root / "extra")
        (project / "_staged" / "fcd" / "smuggled.py").write_bytes(b"import os\n")
        with self.assertRaises(inspect_wheel.BuildFailed) as failure:
            inspect_wheel.build_wheel(project, self.root / "extra-out")
        self.assertIn("fcd/smuggled.py", str(failure.exception))

    def test_an_altered_bundled_file_stops_the_sdist_derived_build(self):
        project = extract_sdist(self.root / "altered")
        target = project / "_staged" / "rga" / "attestation.py"
        target.write_bytes(target.read_bytes() + b"\nBACKDOOR = True\n")
        with self.assertRaises(inspect_wheel.BuildFailed) as failure:
            inspect_wheel.build_wheel(project, self.root / "altered-out")
        self.assertIn("rga/attestation.py", str(failure.exception))


class SimultaneousBuildsDoNotShareAHalfStagedTree(unittest.TestCase):
    """Two wheels and an sdist built at once, and then compared byte for byte.

    This is the test the lock exists for, and it is written as real concurrent
    processes because the failure it guards against is a schedule, not a branch:
    build A refreshes ``_staged`` while build B is zipping it, and B's wheel
    comes out with a hole in it and an exit status of zero.

    Determinism is the observable.  Both wheels are built from one checkout, so
    every payload member must appear in both with the same digest, and every
    staged research file must carry the repository's bytes.  And nothing may be
    left at the fixed path afterwards: a surviving ``_staged`` is a committable
    second copy of four packages the census forbids.
    """

    BUILDS = 3

    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="core-concurrent-")
        cls.root = Path(cls.workspace.name)
        cls.staging_seen = []

        def build(index: int) -> subprocess.CompletedProcess:
            kind = "--sdist" if index == cls.BUILDS - 1 else "--wheel"
            outdir = cls.root / f"out-{index}"
            outdir.mkdir(parents=True, exist_ok=True)
            return subprocess.run(
                [sys.executable, "-m", "build", kind, "--no-isolation",
                 "--outdir", str(outdir), str(CORE_PROJECT)],
                capture_output=True, text=True,
                timeout=inspect_wheel.BUILD_TIMEOUT, cwd=str(CORE_PROJECT),
                env=inspect_wheel.sanitized_env(),
            )

        start = threading.Barrier(cls.BUILDS)

        def run(index: int):
            start.wait(timeout=60)
            return build(index)

        with ThreadPoolExecutor(max_workers=cls.BUILDS) as pool:
            cls.results = list(pool.map(run, range(cls.BUILDS)))
        cls.wheels = sorted(cls.root.glob("out-*/*.whl"))
        cls.sdists = sorted(cls.root.glob("out-*/*.tar.gz"))

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def assert_all_succeeded(self):
        for index, completed in enumerate(self.results):
            with self.subTest(build=index):
                self.assertEqual(
                    0, completed.returncode,
                    f"concurrent build {index} failed:\n{completed.stderr[-4000:]}")

    def test_every_simultaneous_build_produced_its_artefact(self):
        self.assert_all_succeeded()
        self.assertEqual(self.BUILDS - 1, len(self.wheels))
        self.assertEqual(1, len(self.sdists))

    def test_the_simultaneous_wheels_hold_the_same_members(self):
        self.assert_all_succeeded()
        inspected = [inspect_wheel.inspect_wheel(path) for path in self.wheels]
        first = inspected[0]
        for other in inspected[1:]:
            self.assertEqual(first.payload, other.payload)
            self.assertEqual(first.top_level, other.top_level)
            self.assertEqual(first.modules, other.modules)

    def test_the_simultaneous_wheels_hold_the_same_bytes(self):
        self.assert_all_succeeded()
        digests = [
            {member: wheel.sha256(member) for member in wheel.payload}
            for wheel in map(inspect_wheel.inspect_wheel, self.wheels)
        ]
        for other in digests[1:]:
            self.assertEqual(digests[0], other)

    def test_no_wheel_mixes_a_file_from_another_build_s_refresh(self):
        self.assert_all_succeeded()
        for path in self.wheels:
            wheel = inspect_wheel.inspect_wheel(path)
            for member in wheel.payload:
                root = member.split("/")[0]
                if root not in STAGED_ROOTS:
                    continue
                with self.subTest(wheel=path.name, member=member):
                    self.assertEqual(digest_of(REPO_ROOT / member),
                                     wheel.sha256(member))

    def test_the_simultaneous_sdist_agrees_with_the_simultaneous_wheels(self):
        self.assert_all_succeeded()
        prefix = f"{SDIST_NAME}/_staged/"
        with tarfile.open(self.sdists[0]) as archive:
            staged = {
                member.name[len(prefix):]: hashlib.sha256(
                    archive.extractfile(member).read()).hexdigest()
                for member in archive.getmembers()
                if member.isfile() and member.name.startswith(prefix)
                and not member.name.endswith(BACKEND.MANIFEST_NAME)
            }
        self.assertTrue(staged)
        wheel = inspect_wheel.inspect_wheel(self.wheels[0])
        for member, sha in staged.items():
            with self.subTest(member=member):
                self.assertEqual(digest_of(REPO_ROOT / member), sha)
                if member in wheel.payload:
                    self.assertEqual(sha, wheel.sha256(member))

    def test_the_simultaneous_wheels_are_valid_archives(self):
        self.assert_all_succeeded()
        for path in self.wheels:
            with self.subTest(wheel=path.name):
                with zipfile.ZipFile(path) as archive:
                    self.assertIsNone(archive.testzip())

    def test_nothing_was_left_at_the_fixed_staging_path(self):
        self.assert_all_succeeded()
        self.assertFalse((CORE_PROJECT / "_staged").exists())

    def test_the_lock_outlived_every_build_that_took_it(self):
        self.assert_all_succeeded()
        self.assertTrue(BACKEND.LOCK_PATH.is_file())


def walk_fixture(root: Path) -> tuple[Path, Path]:
    """A small tree, and an attacker's tree wearing the same file names."""
    source = root / "source"
    (source / "inner").mkdir(parents=True)
    (source / "later").mkdir()
    (source / "a.py").write_bytes(b"A = 1\n")
    (source / "inner" / "x.py").write_bytes(b"X = 1\n")
    (source / "inner" / "y.py").write_bytes(b"Y = 1\n")
    (source / "later" / "z.py").write_bytes(b"Z = 1\n")
    hostile = root / "hostile"
    hostile.mkdir()
    for name in ("a.py", "x.py", "y.py", "z.py"):
        (hostile / name).write_bytes(b"HOSTILE = 1\n")
    return source, hostile


class TheSourceWalkIsAnchoredToDescriptorsAndNotToPaths(unittest.TestCase):
    """A refusal by path describes a directory as it was when it was looked at.

    The staging walk refuses every link it *sees*.  What it cannot see by
    looking is a directory replaced after the look: between the moment
    ``inner/`` was found to be a real directory and the moment ``inner/y.py``
    is read, a process sharing this UID can rename ``inner`` away and put a
    symlink to its own tree in its place.  A path-based read would then copy
    that tree into a published artefact, and nothing in the build would say so.

    So each directory is opened once, with ``O_DIRECTORY|O_NOFOLLOW``, and
    every descendant is named relative to that open descriptor.  Nothing is
    reopened by path after it has been validated, which is what makes these two
    tests possible to write deterministically: the swap happens *during* the
    walk, at a point the test chooses, and the walk is unmoved by it.
    """

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="core-descriptor-")
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        if not can_symlink(self.root):
            self.skipTest("this platform cannot create symlinks")
        if not BACKEND.DESCRIPTOR_TRAVERSAL:
            self.skipTest("this platform has no descriptor-relative traversal")
        self.source, self.hostile = walk_fixture(self.root)

    @staticmethod
    def read_all(handle: int) -> bytes:
        blocks = []
        while True:
            block = os.read(handle, 65536)
            if not block:
                break
            blocks.append(block)
        return b"".join(blocks)

    def test_the_backend_says_whether_this_platform_traverses_by_descriptor(self):
        self.assertIsInstance(BACKEND.DESCRIPTOR_TRAVERSAL, bool)

    def test_the_walk_reports_the_same_relative_paths_as_before(self):
        self.assertEqual(["a.py", "inner/x.py", "inner/y.py", "later/z.py"],
                         BACKEND.walk_source_tree(self.source))

    def test_each_file_reaches_the_visitor_as_an_open_regular_descriptor(self):
        seen = {}

        def visit(relative, handle):
            info = os.fstat(handle)
            seen[relative] = (stat.S_ISREG(info.st_mode), info.st_ino)

        found = BACKEND.walk_source_tree(self.source, visit=visit)
        self.assertEqual(found, sorted(seen))
        for relative, (regular, inode) in seen.items():
            with self.subTest(path=relative):
                self.assertTrue(regular)
                self.assertEqual(
                    self.source.joinpath(*relative.split("/")).stat().st_ino, inode)

    def test_a_parent_replaced_mid_walk_cannot_redirect_the_reads_after_it(self):
        seen = {}

        def visit(relative, handle):
            seen[relative] = self.read_all(handle)
            if relative == "inner/x.py":
                os.rename(self.source / "inner", self.root / "moved")
                (self.source / "inner").symlink_to(
                    self.hostile, target_is_directory=True)

        BACKEND.walk_source_tree(self.source, visit=visit)
        self.assertEqual(b"Y = 1\n", seen["inner/y.py"])
        self.assertNotIn(b"HOSTILE = 1\n", set(seen.values()))

    def test_a_directory_that_became_a_link_before_it_is_opened_is_refused(self):
        """The swap lands on a sibling the walk has not reached yet."""
        def visit(relative, handle):
            if relative == "a.py":
                os.rename(self.source / "later", self.root / "moved-later")
                (self.source / "later").symlink_to(
                    self.hostile, target_is_directory=True)

        with self.assertRaises(BACKEND.SymlinkRefused) as refusal:
            BACKEND.walk_source_tree(self.source, visit=visit)
        self.assertIn("later", str(refusal.exception))

    def test_a_file_that_became_a_link_before_it_is_opened_is_refused(self):
        secret = self.root / "secret.txt"
        secret.write_bytes(b"not for publication\n")

        def visit(relative, handle):
            if relative == "inner/x.py":
                (self.source / "inner" / "y.py").unlink()
                (self.source / "inner" / "y.py").symlink_to(secret)

        with self.assertRaises(BACKEND.SymlinkRefused) as refusal:
            BACKEND.walk_source_tree(self.source, visit=visit)
        self.assertIn("y.py", str(refusal.exception))


class TheFallbackWalkFailsClosedRatherThanFollowingASwap(unittest.TestCase):
    """What the walk does where ``openat`` is not available.

    Windows has no ``openat`` and no ``O_NOFOLLOW``, so the same walk runs on
    ``lstat``/``open``/``fstat`` alone: every component is checked for a reparse
    point before it is used, the opened file is confirmed by inode against the
    file that was checked, and every directory the walk descended through is
    re-checked at the moment the bytes are taken.

    That is weaker than a descriptor, and the difference is worth stating
    plainly: there is still a window, and closing it needs a primitive the
    platform does not have.  What it must never do is the thing a naive
    path-based walk does -- read the attacker's file and report success.  So the
    same swaps are replayed here with the descriptor path switched off, and the
    outcome asserted is a refusal.
    """

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="core-fallback-")
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        if not can_symlink(self.root):
            self.skipTest("this platform cannot create symlinks")
        self.source, self.hostile = walk_fixture(self.root)
        patched = mock.patch.object(BACKEND, "DESCRIPTOR_TRAVERSAL", False)
        patched.start()
        self.addCleanup(patched.stop)

    read_all = staticmethod(
        TheSourceWalkIsAnchoredToDescriptorsAndNotToPaths.read_all)

    def test_an_undisturbed_tree_walks_to_the_same_answer(self):
        self.assertEqual(["a.py", "inner/x.py", "inner/y.py", "later/z.py"],
                         BACKEND.walk_source_tree(self.source))

    def test_a_link_in_the_tree_is_still_refused_by_name(self):
        (self.source / "inner" / "leak.py").symlink_to(self.root / "hostile")
        with self.assertRaises(BACKEND.SymlinkRefused) as refusal:
            BACKEND.walk_source_tree(self.source)
        self.assertIn("leak.py", str(refusal.exception))

    def test_a_parent_replaced_mid_walk_cannot_redirect_the_reads_after_it(self):
        """Refused rather than followed: the fallback cannot hold the parent open."""
        seen = {}

        def visit(relative, handle):
            seen[relative] = self.read_all(handle)
            if relative == "inner/x.py":
                os.rename(self.source / "inner", self.root / "moved")
                (self.source / "inner").symlink_to(
                    self.hostile, target_is_directory=True)

        with self.assertRaises(BACKEND.SymlinkRefused) as refusal:
            BACKEND.walk_source_tree(self.source, visit=visit)
        self.assertIn("inner", str(refusal.exception))
        self.assertNotIn(b"HOSTILE = 1\n", set(seen.values()))

    def test_a_parent_swapped_for_another_directory_mid_walk_is_refused(self):
        """No link to notice; the inode is what says it is not the same directory."""
        seen = {}
        replacement = self.root / "replacement"
        replacement.mkdir()
        (replacement / "y.py").write_bytes(b"HOSTILE = 1\n")

        def visit(relative, handle):
            seen[relative] = self.read_all(handle)
            if relative == "inner/x.py":
                os.rename(self.source / "inner", self.root / "moved")
                os.rename(replacement, self.source / "inner")

        with self.assertRaises(BACKEND.UnsafeTraversal) as refusal:
            BACKEND.walk_source_tree(self.source, visit=visit)
        self.assertIn("inner", str(refusal.exception))
        self.assertNotIn(b"HOSTILE = 1\n", set(seen.values()))

    def test_a_platform_that_reports_no_inode_is_refused_outright(self):
        """Without an inode there is nothing left to compare, so nothing is read."""
        real = os.lstat

        def blank(path, *args, **kwargs):
            info = real(path, *args, **kwargs)
            return os.stat_result(tuple(info)[:1] + (0,) + tuple(info)[2:])

        with mock.patch.object(os, "lstat", blank):
            with self.assertRaises(BACKEND.UnsafeTraversal) as refusal:
                BACKEND.walk_source_tree(self.source)
        self.assertIn("inode", str(refusal.exception))


# -- crafted artefacts -------------------------------------------------------
STAGED_SAMPLE = {
    "atlas/__init__.py": b"# atlas\n",
    "fcd/__init__.py": b"# fcd\n",
    "fcd/journal.py": b"VALUE = 1\n",
    "protocol/__init__.py": b"# protocol\n",
    "protocol/receipt.schema.json": b"{}\n",
    "rga/__init__.py": b"# rga\n",
}
EXPECTED_SAMPLE = {
    path: hashlib.sha256(body).hexdigest() for path, body in STAGED_SAMPLE.items()
}


def sample_manifest_bytes(files: dict[str, str]) -> bytes:
    """The manifest the backend itself would write for ``files``."""
    with tempfile.TemporaryDirectory(prefix="core-manifest-bytes-") as workspace:
        BACKEND.write_manifest(workspace, files)
        return (Path(workspace) / BACKEND.MANIFEST_NAME).read_bytes()


def write_wheel(path: Path, members: dict[str, bytes], *,
                links: tuple[str, ...] = ()) -> Path:
    """A minimal wheel-shaped ZIP holding exactly ``members`` as its payload."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("admissible_core/__init__.py", b"# core\n")
        archive.writestr("admissible_core-0.8.0.dist-info/METADATA",
                         "Name: admissible-core\nVersion: 0.8.0\n")
        for name, body in members.items():
            info = zipfile.ZipInfo(name)
            mode = (stat.S_IFLNK | 0o777) if name in links else (stat.S_IFREG | 0o644)
            info.external_attr = mode << 16
            archive.writestr(info, body)
    return path


def write_sdist(path: Path, files: dict[str, bytes], *, manifest: bytes | None,
                symlinks: tuple[tuple[str, str], ...] = (),
                hardlinks: tuple[tuple[str, str], ...] = (),
                devices: tuple[str, ...] = (),
                strays: dict[str, bytes] | None = None) -> Path:
    """A minimal sdist-shaped tar holding ``files`` under ``_staged/``."""
    prefix = f"{SDIST_NAME}/_staged/"
    with tarfile.open(path, "w:gz") as archive:
        def add(name: str, body: bytes) -> None:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(body))

        def add_directory(name: str) -> None:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mtime = 0
            archive.addfile(info)

        add(f"{SDIST_NAME}/PKG-INFO", b"Name: admissible-core\nVersion: 0.8.0\n")
        add(f"{SDIST_NAME}/build_backend.py", b"# backend\n")
        add_directory(f"{SDIST_NAME}/_staged")
        for root in sorted(STAGED_ROOTS):
            add_directory(f"{prefix}{root}")
        if manifest is not None:
            add(f"{prefix}{BACKEND.MANIFEST_NAME}", manifest)
        for name, body in files.items():
            add(f"{prefix}{name}", body)
        for name, target in symlinks:
            info = tarfile.TarInfo(f"{prefix}{name}")
            info.type = tarfile.SYMTYPE
            info.linkname = target
            info.mtime = 0
            archive.addfile(info)
        for name, target in hardlinks:
            info = tarfile.TarInfo(f"{prefix}{name}")
            info.type = tarfile.LNKTYPE
            info.linkname = target
            info.mtime = 0
            archive.addfile(info)
        for name in devices:
            info = tarfile.TarInfo(f"{prefix}{name}")
            info.type = tarfile.FIFOTYPE
            info.mtime = 0
            archive.addfile(info)
        for name, body in (strays or {}).items():
            add(name, body)
    return path


class TheBuiltWheelIsReopenedAndCheckedAgainstTheClosure(unittest.TestCase):
    """setuptools reports a filename; the filename is not the evidence.

    Between the closure being taken and setuptools reading the staged tree, the
    bytes on disk can change.  The wheel is therefore opened as the ZIP archive
    it is, every member installing into a staged root is digested, and the
    result must equal the closure exactly: no missing member, no extra one, no
    altered byte, and no member that installs as a symbolic link.  A wheel that
    fails is deleted before the refusal is raised, so a mismatch can never be
    left lying in the output directory for a publisher to find.
    """

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="core-wheel-check-")
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.wheel = self.root / "admissible_core-0.8.0-py3-none-any.whl"

    def refuse(self, members: dict[str, bytes], **kwargs) -> str:
        write_wheel(self.wheel, members, **kwargs)
        with self.assertRaises(BACKEND.ArtifactMismatch) as refusal:
            BACKEND.verify_built_wheel(self.wheel, EXPECTED_SAMPLE)
        self.assertFalse(self.wheel.exists(),
                         "a refused wheel must not be left in the output directory")
        return str(refusal.exception)

    def test_a_faithful_wheel_verifies_and_survives(self):
        write_wheel(self.wheel, dict(STAGED_SAMPLE))
        BACKEND.verify_built_wheel(self.wheel, EXPECTED_SAMPLE)
        self.assertTrue(self.wheel.is_file())

    def test_a_missing_staged_member_is_refused_and_named(self):
        members = dict(STAGED_SAMPLE)
        del members["fcd/journal.py"]
        self.assertIn("fcd/journal.py", self.refuse(members))

    def test_an_extra_staged_member_is_refused_and_named(self):
        members = dict(STAGED_SAMPLE, **{"fcd/smuggled.py": b"import os\n"})
        self.assertIn("fcd/smuggled.py", self.refuse(members))

    def test_an_altered_staged_member_is_refused_and_named(self):
        members = dict(STAGED_SAMPLE, **{"rga/__init__.py": b"BACKDOOR = True\n"})
        self.assertIn("rga/__init__.py", self.refuse(members))

    def test_a_member_installing_as_a_symbolic_link_is_refused_and_named(self):
        members = dict(STAGED_SAMPLE, **{"fcd/journal.py": b"/etc/passwd"})
        message = self.refuse(members, links=("fcd/journal.py",))
        self.assertIn("fcd/journal.py", message)
        self.assertIn("link", message)

    def test_a_staged_root_hidden_under_a_data_scheme_is_still_checked(self):
        """``*.data/purelib/`` installs onto ``sys.path`` like the archive root."""
        members = dict(STAGED_SAMPLE)
        del members["fcd/journal.py"]
        members["admissible_core-0.8.0.data/purelib/fcd/journal.py"] = b"BACKDOOR\n"
        self.assertIn("fcd/journal.py", self.refuse(members))

    def test_two_members_installing_to_one_path_are_refused(self):
        members = dict(STAGED_SAMPLE)
        members["admissible_core-0.8.0.data/purelib/fcd/journal.py"] = b"VALUE = 1\n"
        self.assertIn("fcd/journal.py", self.refuse(members))

    def test_members_outside_the_staged_roots_are_not_the_closure_s_business(self):
        members = dict(STAGED_SAMPLE, **{"admissible_core/extra.py": b"# fine\n"})
        write_wheel(self.wheel, members)
        BACKEND.verify_built_wheel(self.wheel, EXPECTED_SAMPLE)
        self.assertTrue(self.wheel.is_file())

    def test_a_wheel_that_is_not_an_archive_is_refused_and_deleted(self):
        self.wheel.write_bytes(b"this is not a zip file\n")
        with self.assertRaises(BACKEND.ArtifactMismatch):
            BACKEND.verify_built_wheel(self.wheel, EXPECTED_SAMPLE)
        self.assertFalse(self.wheel.exists())

    def test_a_wheel_setuptools_named_but_did_not_write_is_refused(self):
        with self.assertRaises(BACKEND.ArtifactMismatch) as refusal:
            BACKEND.verify_built_wheel(self.wheel, EXPECTED_SAMPLE)
        self.assertIn(self.wheel.name, str(refusal.exception))

    def test_a_refused_wheel_that_could_not_be_deleted_says_it_is_still_there(self):
        """Two different situations, and the reader is owed the difference."""
        members = dict(STAGED_SAMPLE)
        del members["fcd/journal.py"]
        write_wheel(self.wheel, members)
        with mock.patch.object(os, "unlink",
                               side_effect=PermissionError(13, "read-only")):
            with self.assertRaises(BACKEND.ArtifactMismatch) as refusal:
                BACKEND.verify_built_wheel(self.wheel, EXPECTED_SAMPLE)
        message = str(refusal.exception)
        self.assertIn("fcd/journal.py", message)
        self.assertIn("still there", message)
        self.assertTrue(self.wheel.is_file())


class TheBuiltSdistIsReopenedAndCheckedAgainstTheClosure(unittest.TestCase):
    """The sdist is the thing an sdist-derived wheel is later built from.

    So every ``_staged/`` member is checked as a member: its path, its type and
    its bytes.  A link member is refused outright -- a tar that says
    ``_staged/fcd/journal.py -> /etc/passwd`` unpacks into a staging tree whose
    verification would then read whatever the extracting machine has there --
    and so is anything that is neither a regular file nor a directory.  The
    manifest travels in the archive and must be the closure's own bytes.
    """

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="core-sdist-check-")
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.sdist = self.root / f"{SDIST_NAME}.tar.gz"
        self.manifest = sample_manifest_bytes(EXPECTED_SAMPLE)

    def check(self, **kwargs) -> None:
        BACKEND.verify_built_sdist(self.sdist, EXPECTED_SAMPLE, self.manifest)

    def refuse(self, files: dict[str, bytes] | None = None, *,
               manifest: bytes | None = -1, **kwargs) -> str:
        write_sdist(self.sdist,
                    dict(STAGED_SAMPLE) if files is None else files,
                    manifest=self.manifest if manifest == -1 else manifest,
                    **kwargs)
        with self.assertRaises(BACKEND.ArtifactMismatch) as refusal:
            self.check()
        self.assertFalse(self.sdist.exists(),
                         "a refused sdist must not be left in the output directory")
        return str(refusal.exception)

    def test_a_faithful_sdist_verifies_and_survives(self):
        write_sdist(self.sdist, dict(STAGED_SAMPLE), manifest=self.manifest)
        self.check()
        self.assertTrue(self.sdist.is_file())

    def test_a_missing_staged_member_is_refused_and_named(self):
        files = dict(STAGED_SAMPLE)
        del files["protocol/receipt.schema.json"]
        self.assertIn("protocol/receipt.schema.json", self.refuse(files))

    def test_an_extra_staged_member_is_refused_and_named(self):
        files = dict(STAGED_SAMPLE, **{"rga/smuggled.py": b"import os\n"})
        self.assertIn("rga/smuggled.py", self.refuse(files))

    def test_an_altered_staged_member_is_refused_and_named(self):
        files = dict(STAGED_SAMPLE, **{"fcd/journal.py": b"VALUE = 2\n"})
        self.assertIn("fcd/journal.py", self.refuse(files))

    def test_a_symbolic_link_member_is_refused_and_named(self):
        files = dict(STAGED_SAMPLE)
        del files["fcd/journal.py"]
        message = self.refuse(
            files, symlinks=(("fcd/journal.py", "/etc/passwd"),))
        self.assertIn("fcd/journal.py", message)
        self.assertIn("link", message)

    def test_a_hard_link_member_is_refused_and_named(self):
        files = dict(STAGED_SAMPLE)
        del files["fcd/journal.py"]
        message = self.refuse(
            files, hardlinks=(("fcd/journal.py", f"{SDIST_NAME}/PKG-INFO"),))
        self.assertIn("fcd/journal.py", message)
        self.assertIn("link", message)

    def test_a_member_that_is_neither_file_nor_directory_is_refused(self):
        self.assertIn("fcd/pipe", self.refuse(devices=("fcd/pipe",)))

    def test_an_sdist_carrying_no_manifest_is_refused(self):
        self.assertIn(BACKEND.MANIFEST_NAME, self.refuse(manifest=None))

    def test_a_manifest_that_is_not_the_closure_s_own_bytes_is_refused(self):
        other = sample_manifest_bytes(
            {path: sha for path, sha in list(EXPECTED_SAMPLE.items())[:2]})
        self.assertIn(BACKEND.MANIFEST_NAME, self.refuse(manifest=other))

    def test_a_member_escaping_the_archive_root_is_refused_and_named(self):
        self.assertIn("evil.py", self.refuse(
            strays={f"{SDIST_NAME}/../evil.py": b"import os\n"}))

    def test_an_archive_with_two_top_level_directories_is_refused(self):
        self.assertIn("second", self.refuse(strays={"second/PKG-INFO": b"x\n"}))

    def test_an_sdist_that_is_not_an_archive_is_refused_and_deleted(self):
        self.sdist.write_bytes(b"this is not a tar archive\n")
        with self.assertRaises(BACKEND.ArtifactMismatch):
            self.check()
        self.assertFalse(self.sdist.exists())

    def test_an_sdist_setuptools_named_but_did_not_write_is_refused(self):
        with self.assertRaises(BACKEND.ArtifactMismatch) as refusal:
            self.check()
        self.assertIn(self.sdist.name, str(refusal.exception))


class _Tampering:
    """A setuptools stand-in that edits the staged tree just before packaging.

    This is the TOCTOU window written down.  The backend verified the staging
    tree, took its closure, and handed control to setuptools; a process sharing
    this UID gets to run in exactly this position, and this class stands where
    it would stand.  Everything else is delegated to the real backend, so the
    artefact under test is a genuine setuptools artefact built from mutated
    bytes rather than a fixture pretending to be one.
    """

    def __init__(self, real, tamper):
        self._real = real
        self._tamper = tamper

    def __getattr__(self, name):
        return getattr(self._real, name)

    def build_wheel(self, wheel_directory, config_settings=None,
                    metadata_directory=None):
        self._tamper()
        return self._real.build_wheel(
            wheel_directory, config_settings, metadata_directory)

    def build_sdist(self, sdist_directory, config_settings=None):
        self._tamper()
        return self._real.build_sdist(sdist_directory, config_settings)


class BytesPackagedAfterVerificationAreCheckedAgain(unittest.TestCase):
    """The window between the closure and the packager, exercised for real.

    Each test mutates the verified staging tree at the one instant that matters
    -- after ``verify_staging`` has passed and before setuptools reads a file --
    and then asserts the only two things worth asserting: the refusal is raised,
    and the output directory is empty.  An artefact that is deleted is an
    artefact nobody can publish by mistake.
    """

    @classmethod
    def setUpClass(cls):
        cls.real = BACKEND._setuptools

    @staticmethod
    def forget_created_directories():
        """Drop distutils' memory of directories it made earlier in this process.

        ``dir_util.mkpath`` records every directory it creates in a process-wide
        set and never checks the filesystem again.  ``bdist_wheel`` removes its
        own scratch tree at the end of a build, so the second in-process build
        is told the tree already exists and writes into nothing.  Frontends do
        not meet this because they build once per interpreter; these tests build
        several times, on purpose, and pay for it here.
        """
        for module in ("setuptools._distutils.dir_util", "distutils.dir_util"):
            try:
                dir_util = importlib.import_module(module)
            except ImportError:  # pragma: no cover - version drift
                continue
            cache = getattr(dir_util, "SkipRepeatAbsolutePaths", None)
            if cache is not None and getattr(cache, "instance", None) is not None:
                cache.clear()
            legacy = getattr(dir_util, "_path_created", None)
            if legacy is not None:  # pragma: no cover - older setuptools
                legacy.clear()

    def setUp(self):
        self.forget_created_directories()
        self.addCleanup(self.forget_created_directories)
        origin = Path.cwd()
        self.addCleanup(os.chdir, str(origin))
        os.chdir(str(CORE_PROJECT))
        # ``build/`` is left alone deliberately. setuptools copies into it only
        # when the source is newer, and every staged file is rewritten at the
        # start of every build, so the mutation under test always wins the
        # comparison -- whereas deleting the directory mid-process desynchronises
        # distutils' own record of which directories it has created.
        self.addCleanup(shutil.rmtree, str(CORE_PROJECT / "_staged"), True)
        self.workspace = tempfile.TemporaryDirectory(prefix="core-toctou-")
        self.addCleanup(self.workspace.cleanup)
        self.out = Path(self.workspace.name)

    def build(self, hook: str, tamper):
        patched = mock.patch.object(
            BACKEND, "_setuptools", _Tampering(self.real, tamper))
        with patched, contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return getattr(BACKEND, hook)(str(self.out))

    def refuse(self, hook: str, tamper, pattern: str) -> str:
        with self.assertRaises(BACKEND.ArtifactMismatch) as refusal:
            self.build(hook, tamper)
        self.assertEqual([], sorted(self.out.glob(pattern)),
                         "a refused artefact must not be left for a publisher")
        return str(refusal.exception)

    def test_an_untampered_build_still_returns_its_wheel(self):
        """The harness must not be what makes the other tests red."""
        name = self.build("build_wheel", lambda: None)
        self.assertTrue((self.out / name).is_file())

    def test_a_staged_file_altered_before_packaging_deletes_the_wheel(self):
        def tamper():
            target = BACKEND.STAGING / "fcd" / "journal.py"
            target.write_bytes(target.read_bytes() + b"\nBACKDOOR = True\n")

        self.assertIn("fcd/journal.py",
                      self.refuse("build_wheel", tamper, "*.whl"))

    def test_a_staged_root_replaced_before_packaging_deletes_the_wheel(self):
        def tamper():
            root = BACKEND.STAGING / "fcd"
            shutil.rmtree(root)
            root.mkdir()
            (root / "__init__.py").write_bytes(b"HOSTILE = True\n")

        self.assertIn("fcd/", self.refuse("build_wheel", tamper, "*.whl"))

    def test_a_staged_root_relinked_before_packaging_deletes_the_wheel(self):
        if not can_symlink(self.out):
            self.skipTest("this platform cannot create symlinks")
        hostile = self.out / "hostile-fcd"
        hostile.mkdir()
        (hostile / "__init__.py").write_bytes(b"HOSTILE = True\n")

        def tamper():
            root = BACKEND.STAGING / "fcd"
            shutil.rmtree(root)
            root.symlink_to(hostile, target_is_directory=True)

        self.assertIn("fcd/", self.refuse("build_wheel", tamper, "*.whl"))

    def test_a_wheel_built_from_an_sdist_is_checked_against_the_sdists_closure(self):
        """The bundled manifest is the closure there, and it is the same check.

        A consumer building the published sdist runs this exact path: no
        repository to refresh from, the staged tree already on disk, and the
        manifest that travelled inside the archive standing in for everything
        the checkout would have proved.
        """
        project = extract_sdist(self.out / "sdist-source")
        backend = load_backend()
        backend.PROJECT = project
        backend.REPOSITORY = project.parents[1]
        backend.STAGING = project / "_staged"
        backend.LOCK_PATH = project / "_staged.lock"

        def tamper():
            target = backend.STAGING / "atlas" / "__init__.py"
            target.write_bytes(target.read_bytes() + b"\nBACKDOOR = True\n")

        backend._setuptools = _Tampering(self.real, tamper)
        outdir = self.out / "sdist-wheel"
        outdir.mkdir(parents=True)
        os.chdir(str(project))
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(backend.ArtifactMismatch) as refusal:
                backend.build_wheel(str(outdir))
        self.assertIn("atlas/__init__.py", str(refusal.exception))
        self.assertEqual([], sorted(outdir.glob("*.whl")))
        self.assertTrue((backend.STAGING / "atlas" / "__init__.py").is_file(),
                        "an extracted sdist's staged tree is its source, not a copy")

    def test_a_staged_file_altered_before_packaging_deletes_the_sdist(self):
        def tamper():
            target = BACKEND.STAGING / "rga" / "__init__.py"
            target.write_bytes(target.read_bytes() + b"\nBACKDOOR = True\n")

        self.assertIn("rga/__init__.py",
                      self.refuse("build_sdist", tamper, "*.tar.gz"))


class LockAcquisitionSeparatesContentionFromPermanentFaults(unittest.TestCase):
    """Waiting is the answer to contention, and to nothing else.

    ``LockTimeout`` says a *second build* held the lock.  Reporting it for an
    ``EBADF`` or an ``ENOLCK`` sends whoever reads it looking for a process that
    never existed, and does it only after the full deadline has elapsed -- ten
    minutes, by default, of a fault that was permanent from the first attempt.
    So the retry loop retries genuine contention and re-raises everything else
    at once, with the operating system's own reason attached.
    """

    def taking(self, error: OSError):
        def take(handle):
            raise error

        return mock.patch.object(BACKEND, "_take", take)

    def assert_permanent(self, error: OSError) -> str:
        started = time.monotonic()
        with self.taking(error):
            with self.assertRaises(BACKEND.BuildBackendError) as refusal:
                with BACKEND.build_lock(timeout=30):
                    pass
        elapsed = time.monotonic() - started
        self.assertNotIsInstance(refusal.exception, BACKEND.LockTimeout)
        self.assertIs(error, refusal.exception.__cause__)
        self.assertLess(elapsed, 10, "a permanent fault waited for the deadline")
        return str(refusal.exception)

    def test_a_bad_descriptor_is_raised_with_its_cause_and_not_as_a_timeout(self):
        message = self.assert_permanent(
            OSError(errno.EBADF, os.strerror(errno.EBADF)))
        self.assertIn(os.strerror(errno.EBADF), message)
        self.assertIn(str(BACKEND.LOCK_PATH), message)

    def test_a_filesystem_without_locks_is_raised_with_its_cause(self):
        message = self.assert_permanent(
            OSError(errno.ENOLCK, os.strerror(errno.ENOLCK)))
        self.assertIn(os.strerror(errno.ENOLCK), message)

    def test_an_unsupported_operation_is_raised_with_its_cause(self):
        self.assert_permanent(OSError(errno.EINVAL, os.strerror(errno.EINVAL)))

    def test_genuine_contention_is_retried_until_the_deadline(self):
        attempts = []

        def take(handle):
            attempts.append(handle)
            raise OSError(errno.EAGAIN, os.strerror(errno.EAGAIN))

        with mock.patch.object(BACKEND, "_take", take):
            with self.assertRaises(BACKEND.LockTimeout):
                with BACKEND.build_lock(timeout=1):
                    pass
        self.assertGreater(len(attempts), 1, "contention must be retried")

    def test_the_contention_codes_are_the_ones_a_held_lock_reports(self):
        for code in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
            with self.subTest(code=errno.errorcode.get(code, code)):
                self.assertTrue(BACKEND.is_lock_contention(OSError(code, "held")))

    def test_a_windows_lock_violation_counts_as_contention(self):
        """``msvcrt.locking`` reports the held lock as a Win32 error number."""
        violation = OSError(errno.EINVAL, "lock violation")
        violation.winerror = 33  # ERROR_LOCK_VIOLATION
        self.assertTrue(BACKEND.is_lock_contention(violation))

    def test_a_permanent_fault_is_not_contention(self):
        for code in (errno.EBADF, errno.ENOLCK, errno.EINVAL, errno.EPERM):
            with self.subTest(code=errno.errorcode.get(code, code)):
                self.assertFalse(BACKEND.is_lock_contention(OSError(code, "fault")))


if __name__ == "__main__":
    unittest.main()
