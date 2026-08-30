"""PEP 517 backend: setuptools, with the root-owned sources staged in first.

Core ships four packages it does not contain.  ``fcd``, ``rga`` and ``atlas``
are research sources and ``protocol`` is the schema package; all four live at
the repository root, are owned there, and must reach every dependent as exactly
one copy.  Copying them into ``packages/core/src`` would create a second file
claiming the same dotted module name -- two ``fcd.journal`` implementations,
with import order deciding which one hashes a receipt -- which the repository's
import census rejects, and rightly.

Pointing ``package-dir`` at ``../../fcd`` builds a correct wheel and produces a
broken source distribution.  setuptools' sdist writer has nowhere inside the
archive to put a file whose path leaves the project directory: it resolves the
destination relative to the staging root, so the copies land *outside* the
archive, in sibling directories of the project.  The result is an sdist missing
every research root, and a working tree with four stray directories in it --
which, in this repository, is a tree the gate itself would refuse to admit.

So the sources are staged instead.  Before any hook runs, ``_staged`` refreshes
``packages/core/_staged/<name>`` from the repository root and ``package-dir``
points there; afterwards it removes what it made.  The staging directory is
transient by construction, never committed, and byte-identical to its source,
so the "one copy" rule is kept where it matters -- in the tree, in the census,
and in the wheel.

Building from an *extracted sdist* is the same code with nothing to do: the
repository is not there, the staged copies already are, and they are then the
source rather than a copy of it.

That much is the arrangement.  The rest of this module is about the four ways
it can go wrong, none of which a build's exit status would report.

*``_staged`` is one fixed path, and builds are not solitary.*  ``pip install``,
a wheel build and an sdist build can run against this project directory at the
same moment, and every one of them refreshes and then deletes that same path.
Interleave two and the second zips a tree the first is halfway through
replacing: a wheel with a hole in it, and a zero exit.  So the whole lifecycle
-- refresh, setuptools hook, cleanup -- is held under one exclusive lock taken
on a file *beside* the staging tree, never inside it.  The lock file is created
once and never removed, because a lock you delete on the way out is not a lock:
the next two builds open two different inodes and both take it.  It carries no
recorded owner, so a build killed mid-flight denies nobody -- the kernel drops
the lock when the process dies, and there is no stale marker left to sweep.

*"Four directories exist next door" is not an identity.*  The parent directory
of an extracted sdist is chosen by whoever extracted it, so a sdist unpacked
beside four prepared roots called ``fcd``, ``rga``, ``atlas`` and ``protocol``
would, under that test, stage an attacker's packages into a published wheel.
A checkout is recognised instead: this project must sit at exactly
``<repository>/packages/core``, both ``pyproject.toml`` files must name the
projects they are supposed to name, the repository must carry its own ``.git``,
each root must be a real directory with its package marker in it -- and the
project must not be a bundled sdist, which is decided by ``PKG-INFO``, a file
every sdist has and no working tree does.  An sdist uses its own bundled bytes,
always, wherever it was unpacked.

*A symlink in a staged root is a request to publish what it points at.*  Copying
one would put a file from outside the repository -- a key, another user's home
-- inside a wheel, silently.  Every link is refused by path instead, at any
depth, whether it names a file or a directory, and the refusal says which.

*Nothing else in an sdist says which bytes are Core's.*  setuptools packages
whatever is sitting under ``_staged/``, so the staging tree is closed by a
manifest of relative paths and SHA-256 digests that travels inside the archive.
A wheel built from an sdist is built from the bytes that sdist shipped: missing,
unexpected and altered are three refusals, and all three refuse.  The manifest
holds no clock reading and no absolute path, so two builds of one tree write it
byte for byte the same.

*Verification happens before setuptools reads anything.*  That ordering is
forced -- the closure has to exist before the packager runs -- and it leaves a
window.  Between the last digest and setuptools opening a file, the bytes on
disk can change: a process sharing this UID can rewrite a verified file, or
rename the directory holding it and put its own there.  Nothing about a build
would report it.  So the artefact is the thing checked, not only the tree: the
wheel is reopened as the ZIP archive it is and every member installing into a
staged root is compared with the closure held in memory -- exact path set, no
missing member, no extra one, no altered byte, and no member installing as a
link.  The sdist is reopened as the tar it is and every ``_staged/`` member is
checked by path, by type and by bytes, with the travelling manifest required to
be the closure's own.  A mismatch deletes the artefact and raises
:class:`ArtifactMismatch`, because an artefact that is merely reported as bad is
an artefact somebody uploads anyway.

*And a link check by path expires the moment it is made.*  ``lstat`` describes a
directory as it was when it was looked at; a read that later re-walks the same
path can be handed a different tree entirely.  Every source read is therefore
anchored to a descriptor: one ``O_DIRECTORY|O_NOFOLLOW`` open per directory,
every descendant named relative to that descriptor with ``openat``, every
regular file confirmed by ``fstat`` on the descriptor about to be read, and
nothing reopened by path after it has been validated.  Where the platform has no
such primitives the walk falls back to ``lstat``/``open``/``fstat`` with an
inode identity check and refuses -- :class:`UnsafeTraversal` -- rather than
following a reparse point it cannot rule out.

**Scope.**  None of this is a sandbox, and it is not offered as one.  A process
running as this user can read, write and replace anything in the working tree,
including the staging tree, the lock file and this module; it can also edit the
manifest to close over whatever it just wrote.  What is claimed is narrower and
exact: (1) a *published artefact* cannot silently disagree with the closure the
build verified -- it is reopened, compared and deleted on mismatch, so the
attack's outcome is a failed build rather than a poisoned wheel; and (2) *source
reads* are not redirectable by swapping a path component after it was checked,
because the reads follow descriptors rather than names.  Neither claim survives
an attacker who wins the race *and* rewrites the manifest, and neither is meant
to: the defence against that is not building releases on a machine where
somebody else runs as you.
"""
from __future__ import annotations

import errno
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import stat
import tarfile
import time
import zipfile
from contextlib import contextmanager
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Callable, NamedTuple

from setuptools import build_meta as _setuptools

try:  # 3.11+; the declared floor is 3.10, so there is a fallback below.
    import tomllib as _tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised only on 3.10
    _tomllib = None

__all__ = [
    "build_sdist",
    "build_wheel",
    "get_requires_for_build_sdist",
    "get_requires_for_build_wheel",
    "prepare_metadata_for_build_wheel",
]

PROJECT = Path(__file__).resolve().parent
REPOSITORY = PROJECT.parents[1]
STAGING = PROJECT / "_staged"

# Beside the staging tree, never inside it: cleanup removes ``_staged`` and must
# not be able to remove the thing that decides who may run cleanup.
LOCK_PATH = PROJECT / "_staged.lock"
LOCK_TIMEOUT_VARIABLE = "ADMISSIBLE_CORE_BUILD_LOCK_TIMEOUT"
DEFAULT_LOCK_TIMEOUT = 600.0

# The closure written into the staging tree and carried by the sdist.
MANIFEST_NAME = "staged-manifest.json"
MANIFEST_VERSION = 1

# Package -> the immediate subdirectories that are not part of it.
#
# ``atlas.tests`` imports the top-level ``tests`` package, which no
# distribution ships. Packaging it would install an import error into the one
# place it cannot be fixed, so it is pruned at the copy rather than merely left
# out of the package list.
STAGED_ROOTS = {
    "fcd": (),
    "rga": (),
    "atlas": ("tests",),
    "protocol": (),
}

# Build artefacts of the source tree, never part of the source.
IGNORED = ("__pycache__", "*.pyc", "*.pyo", ".DS_Store")

# What identifies this checkout, as opposed to a directory wearing its shape.
REPOSITORY_PROJECT_NAME = "admissible"
CORE_PROJECT_NAME = "admissible-core"
PACKAGE_MARKER = "__init__.py"
# Present in every source distribution, and in no working tree.
SDIST_MARKER = "PKG-INFO"

_NAME_SEPARATORS = re.compile(r"[-_.]+")
_NAME_LINE = re.compile(
    r"^\s*name\s*=\s*[\"']([^\"']+)[\"']", re.MULTILINE)


class BuildBackendError(RuntimeError):
    """The backend refused to build; the message says what it could not trust."""


class SymlinkRefused(BuildBackendError):
    """A symbolic link was found where only repository sources may be."""


class UnsafeTraversal(BuildBackendError):
    """This platform cannot establish that the file read is the file checked."""


class ArtifactMismatch(BuildBackendError):
    """A built artefact does not carry the bytes its staged manifest pins."""


class StagingMismatch(BuildBackendError):
    """The staged tree is not the one its manifest closes over."""


class SourcesNotIdentified(BuildBackendError):
    """Neither this repository's ``packages/core`` nor an extracted sdist."""


class LockTimeout(BuildBackendError):
    """Another build held the staging lock for longer than this one would wait."""


# -- the lock ----------------------------------------------------------------
#
# An advisory whole-file lock from the standard library, on both platforms this
# project is built on.  Both are released by the kernel when the holding process
# exits for any reason, which is the property that matters: a lock recorded in a
# file's *contents* -- a pid, a hostname, a timestamp -- outlives the crash that
# wrote it and turns one killed build into permanent denial for every build
# after it.
if os.name == "nt":  # pragma: no cover - selected by platform
    import msvcrt

    def _take(handle: int) -> None:
        os.lseek(handle, 0, os.SEEK_SET)
        msvcrt.locking(handle, msvcrt.LK_NBLCK, 1)

    def _drop(handle: int) -> None:
        os.lseek(handle, 0, os.SEEK_SET)
        msvcrt.locking(handle, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _take(handle: int) -> None:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _drop(handle: int) -> None:
        fcntl.flock(handle, fcntl.LOCK_UN)


# Contention, and only contention, is worth waiting for.
#
# ``flock`` reports a lock somebody else holds as ``EWOULDBLOCK``; ``msvcrt``
# reports it as ``EACCES`` or ``EDEADLOCK`` over Win32's ``ERROR_LOCK_VIOLATION``
# or ``ERROR_SHARING_VIOLATION``.  Everything else the call can raise -- a closed
# descriptor, a filesystem with no lock support, an argument this platform will
# never accept -- is permanent from the first attempt.  Waiting out a ten-minute
# deadline for one of those and then reporting "another build held the lock"
# describes a process that does not exist, and hides the one fact that would
# have fixed it.
_CONTENTION_ERRNOS = frozenset(
    code for code in (
        getattr(errno, name, None)
        for name in ("EACCES", "EAGAIN", "EWOULDBLOCK", "EDEADLOCK", "EDEADLK")
    ) if code is not None
)
_LOCK_VIOLATION_WINERRORS = frozenset((32, 33))  # SHARING_VIOLATION, LOCK_VIOLATION


def is_lock_contention(error: BaseException) -> bool:
    """Is ``error`` another holder of the lock, rather than a broken one?"""
    if getattr(error, "winerror", None) in _LOCK_VIOLATION_WINERRORS:
        return True
    return getattr(error, "errno", None) in _CONTENTION_ERRNOS


class _BuildLock:
    """The right to refresh and to remove the staging tree, while held."""

    def __init__(self, path: Path):
        self.path = path
        self.held = False

    def require_held(self, action: str) -> None:
        if not self.held:
            raise BuildBackendError(
                f"refusing to {action}: this process does not hold "
                f"{self.path}, and the staging tree at {STAGING} belongs to "
                f"whichever build does"
            )


def _timeout(explicit: float | None) -> float:
    if explicit is not None:
        return float(explicit)
    raw = os.environ.get(LOCK_TIMEOUT_VARIABLE)
    if raw is None or not raw.strip():
        return DEFAULT_LOCK_TIMEOUT
    try:
        value = float(raw)
    except ValueError as error:
        raise BuildBackendError(
            f"{LOCK_TIMEOUT_VARIABLE}={raw!r} is not a number of seconds"
        ) from error
    if value <= 0:
        raise BuildBackendError(
            f"{LOCK_TIMEOUT_VARIABLE}={raw!r} must be a positive number of seconds")
    return value


@contextmanager
def build_lock(path: Path | str | None = None, timeout: float | None = None):
    """Hold the staging lock, or refuse after ``timeout`` seconds.

    The file is opened and never unlinked.  Waiting is a poll with a backoff
    rather than a blocking acquisition so that the refusal can name a deadline
    and a path instead of hanging a continuous-integration job.
    """
    path = Path(path) if path is not None else LOCK_PATH
    limit = _timeout(timeout)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # ``O_NOFOLLOW``: a lock file replaced by a link is a lock taken on some
        # other inode, which every build would take at once and none would wait
        # for. Refusing is the only safe reading of it.
        handle = os.open(
            path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except OSError as error:
        raise BuildBackendError(
            f"cannot take the staging lock at {path}: {error}") from error
    lock = _BuildLock(path)
    deadline = time.monotonic() + limit
    delay = 0.005
    try:
        while True:
            try:
                _take(handle)
                break
            except OSError as error:
                if not is_lock_contention(error):
                    raise BuildBackendError(
                        f"cannot take the staging lock at {path}: {error}. "
                        f"This is not another build holding it -- contention is "
                        f"reported as EACCES or EAGAIN -- so it is raised now "
                        f"with the reason the operating system gave, rather "
                        f"than after {limit:g}s as a timeout that would name a "
                        f"process that does not exist"
                    ) from error
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LockTimeout(
                        f"another admissible-core build has held {path} for "
                        f"more than {limit:g}s; {STAGING} is a single fixed "
                        f"path shared by every build of this project, so this "
                        f"one waited rather than refreshing it underneath the "
                        f"other"
                    ) from None
                time.sleep(min(delay, remaining))
                delay = min(delay * 2, 0.25)
        lock.held = True
        try:
            yield lock
        finally:
            lock.held = False
            _drop(handle)
    finally:
        os.close(handle)


# -- identifying the sources -------------------------------------------------
def _normalize(name: str) -> str:
    """PEP 503 normalised distribution name."""
    return _NAME_SEPARATORS.sub("-", name.strip()).lower()


def declared_project_name(pyproject: Path) -> str | None:
    """The normalised ``[project] name`` of a ``pyproject.toml``, or ``None``."""
    try:
        text = Path(pyproject).read_text("utf-8")
    except OSError:
        return None
    if _tomllib is not None:
        try:
            document = _tomllib.loads(text)
        except ValueError:  # TOMLDecodeError, and anything it grows into
            return None
        name = (document.get("project") or {}).get("name")
        return _normalize(name) if isinstance(name, str) else None
    head = text.split("[project]", 1)  # pragma: no cover - 3.10 only
    if len(head) != 2:
        return None
    match = _NAME_LINE.search(head[1].split("\n[", 1)[0])
    return _normalize(match.group(1)) if match else None


def is_canonical_checkout(project: Path | str | None = None) -> bool:
    """Is ``project`` this repository's ``packages/core``, and not an sdist?

    Every clause is a question a prepared directory cannot answer by accident.
    The ``PKG-INFO`` clause comes first because it is the one that must never be
    overridden: a bundled sdist uses its own staged bytes even when it has been
    unpacked at exactly the right path inside a directory that also carries this
    repository's name and a ``.git``.
    """
    project = Path(project).resolve() if project is not None else PROJECT
    if (project / SDIST_MARKER).is_file():
        return False
    if len(project.parents) < 2:
        return False
    repository = project.parents[1]
    if project.name != "core" or project.parent.name != "packages":
        return False
    if declared_project_name(project / "pyproject.toml") != _normalize(CORE_PROJECT_NAME):
        return False
    if declared_project_name(repository / "pyproject.toml") != _normalize(
            REPOSITORY_PROJECT_NAME):
        return False
    if not (repository / ".git").exists():
        return False
    for name in STAGED_ROOTS:
        root = repository / name
        if root.is_symlink() or not root.is_dir():
            return False
        if not (root / PACKAGE_MARKER).is_file():
            return False
    if not any((repository / "protocol").glob("*.schema.json")):
        return False
    return True


# -- reading a source root ---------------------------------------------------
def _is_artefact(name: str) -> bool:
    return any(fnmatch(name, pattern) for pattern in IGNORED)


# Descriptor-relative traversal, where the platform has it.
#
# ``O_DIRECTORY|O_NOFOLLOW`` plus ``openat`` is what makes "this file" mean an
# inode rather than a name: the directory is opened once and every descendant is
# named against that open descriptor, so renaming the directory away and putting
# a symlink in its place changes nothing about what is read.  Without those
# primitives the same walk runs on ``lstat``/``open``/``fstat`` and refuses
# wherever it cannot prove the object it read is the object it checked.
DESCRIPTOR_TRAVERSAL = bool(
    hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and os.open in getattr(os, "supports_dir_fd", frozenset())
    and os.lstat in getattr(os, "supports_dir_fd", frozenset())
    and os.listdir in getattr(os, "supports_fd", frozenset())
)

_DIRECTORY_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0))
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)

# What a directory open reports when the name turned out to be a link, or a file,
# after ``lstat`` said otherwise.  POSIX allows either spelling, and macOS and
# Linux disagree, so both are read the same way: the thing that was checked is
# not the thing that would have been opened.
_SWAPPED_ERRNOS = frozenset(
    code for code in (getattr(errno, name, None)
                      for name in ("ELOOP", "EMLINK", "ENOTDIR"))
    if code is not None
)

Visitor = Callable[[str, int], None]


def _read_descriptor(handle: int) -> bytes:
    """Everything left in an open descriptor, read from the descriptor itself."""
    blocks: list[bytes] = []
    while True:
        block = os.read(handle, 1 << 20)
        if not block:
            break
        blocks.append(block)
    return b"".join(blocks)


def _refuse_link(relative: str, source: Path) -> SymlinkRefused:
    return SymlinkRefused(
        f"refusing to stage {relative} from {source}: {source / relative} is a "
        f"symbolic link, and following it would publish whatever it points at "
        f"inside a released artefact"
    )


def _identity(info, where: str) -> tuple[int, int]:
    """``(device, inode)``, or a refusal that this platform cannot name a file."""
    if not info.st_ino:
        raise UnsafeTraversal(
            f"refusing to stage {where}: this platform reports no inode for it, "
            f"so there is no way to establish that the object read is the object "
            f"checked, and a reparse point cannot be ruled out"
        )
    return (info.st_dev, info.st_ino)


def _check_directory(path: Path, description: str):
    """``lstat`` a directory that is about to be descended into."""
    try:
        info = os.lstat(path)
    except OSError as error:
        raise SourcesNotIdentified(
            f"refusing to stage {description}: {error}") from error
    if stat.S_ISLNK(info.st_mode):
        raise SymlinkRefused(
            f"refusing to stage {description}: it is a symbolic link, and a "
            f"staged root must be the directory it claims to be"
        )
    if not stat.S_ISDIR(info.st_mode):
        raise SourcesNotIdentified(
            f"refusing to stage {description}: not a directory")
    return info


def _open_root(source: Path) -> tuple[int, tuple[int, int]]:
    """A descriptor on ``source``, or ``-1`` where the platform has no ``openat``."""
    info = _check_directory(source, str(source))
    identity = _identity(info, str(source))
    if not DESCRIPTOR_TRAVERSAL:
        return -1, identity
    try:
        handle = os.open(source, _DIRECTORY_FLAGS)
    except OSError as error:
        if getattr(error, "errno", None) in _SWAPPED_ERRNOS:
            raise SymlinkRefused(
                f"refusing to stage {source}: it stopped being the directory it "
                f"was a moment ago, which is what a replacement looks like from "
                f"here"
            ) from error
        raise SourcesNotIdentified(
            f"refusing to stage {source}: {error}") from error
    if not stat.S_ISDIR(os.fstat(handle).st_mode):  # pragma: no cover - kernel
        os.close(handle)
        raise SourcesNotIdentified(f"refusing to stage {source}: not a directory")
    return handle, identity


def _open_child(parent: int, name: str, entry: Path, relative: str, source: Path,
                *, directory: bool) -> int:
    """Open ``name`` under ``parent``, never following a link at the last step.

    Returns ``-1`` for a directory on a platform without ``openat``: there is no
    descriptor to anchor to there, and opening a directory by path buys nothing
    the ancestor re-check below does not already have to do.
    """
    if DESCRIPTOR_TRAVERSAL:
        flags = _DIRECTORY_FLAGS if directory else _FILE_FLAGS
        try:
            return os.open(name, flags, dir_fd=parent)
        except OSError as error:
            if getattr(error, "errno", None) in _SWAPPED_ERRNOS:
                raise _refuse_link(relative, source) from error
            raise SourcesNotIdentified(
                f"refusing to stage {relative} from {source}: {error}") from error
    if directory:
        return -1
    try:
        return os.open(entry, _FILE_FLAGS)
    except OSError as error:
        if getattr(error, "errno", None) in _SWAPPED_ERRNOS:
            raise _refuse_link(relative, source) from error
        raise SourcesNotIdentified(
            f"refusing to stage {relative} from {source}: {error}") from error


def _confirm_ancestors(chain, source: Path) -> None:
    """Re-check every directory the walk descended through, from the root down.

    The fallback names each file by path, so every directory above it is part of
    the read.  ``lstat`` said each of them was a real directory on the way down;
    this asks again, at the moment the bytes are about to be taken, and refuses
    if any answer has changed.  It is not the guarantee ``openat`` gives -- there
    is still a window, and it is honest to say so -- but it converts the silent
    substitution into a refused build, which is the point.
    """
    for path, identity, relative in chain:
        try:
            info = os.lstat(path)
        except OSError as error:
            raise UnsafeTraversal(
                f"refusing to stage from {source}: {relative or '.'} stopped "
                f"being readable partway through the walk: {error}"
            ) from error
        if stat.S_ISLNK(info.st_mode):
            raise SymlinkRefused(
                f"refusing to stage from {source}: {relative or '.'} is now a "
                f"symbolic link, and every file read through it would be read "
                f"from wherever it points"
            )
        if _identity(info, str(path)) != identity:
            raise UnsafeTraversal(
                f"refusing to stage from {source}: {relative or '.'} is not the "
                f"directory this walk descended into -- it was replaced, and "
                f"every path resolved through it since names something else"
            )


def _confirm_regular(handle: int, checked, relative: str, source: Path):
    """Fail closed unless the open descriptor is the regular file ``lstat`` saw."""
    opened = os.fstat(handle)
    if not stat.S_ISREG(opened.st_mode):
        raise _refuse_link(relative, source)
    if DESCRIPTOR_TRAVERSAL:
        return opened
    where = f"{relative} from {source}"
    if _identity(opened, where) != _identity(checked, where):
        raise UnsafeTraversal(
            f"refusing to stage {where}: the file opened is not the file "
            f"checked -- it was replaced between the two calls"
        )
    return opened


def walk_source_tree(source: Path | str, pruned: tuple[str, ...] = (), *,
                     visit: Visitor | None = None) -> list[str]:
    """Sorted relative POSIX paths of the regular files under ``source``.

    Raises :class:`SymlinkRefused` for a link anywhere in the tree, including
    ``source`` itself, and never dereferences one.  ``pruned`` names immediate
    subdirectories that are not part of the package, and is applied before the
    link check: what is not copied cannot poison the copy.

    ``visit`` is called as ``visit(relative, descriptor)`` for each regular
    file, with a descriptor already confirmed by ``fstat`` to be that regular
    file and opened relative to its parent directory's descriptor.  It is the
    only way to read a file this walk found: reopening one by path afterwards
    would ask the filesystem the same question a second time and take a
    different answer, which is precisely the swap this traversal exists to
    refuse.  The descriptor is closed when ``visit`` returns.

    Names come from the directory being read and are used one component at a
    time, so nothing here can name anything above ``source``.
    """
    source = Path(source)
    found: list[str] = []

    def descend(handle: int, directory: Path, prefix: str,
                prune: tuple[str, ...], chain: tuple) -> None:
        names = os.listdir(handle if DESCRIPTOR_TRAVERSAL else directory)
        for name in sorted(names):
            if _is_artefact(name) or name in prune:
                continue
            if name in (".", "..") or "/" in name or os.sep in name:
                raise SourcesNotIdentified(  # pragma: no cover - kernel invariant
                    f"refusing to stage {prefix}{name} from {source}: the "
                    f"directory listed a name that is not a single component"
                )
            relative = f"{prefix}{name}"
            entry = directory / name
            try:
                info = (os.lstat(name, dir_fd=handle) if DESCRIPTOR_TRAVERSAL
                        else os.lstat(entry))
            except OSError as error:
                raise SourcesNotIdentified(
                    f"refusing to stage {relative} from {source}: {error}"
                ) from error
            if stat.S_ISLNK(info.st_mode):
                raise _refuse_link(relative, source)
            if stat.S_ISDIR(info.st_mode):
                child = _open_child(handle, name, entry, relative, source,
                                    directory=True)
                try:
                    descend(child, entry, f"{relative}/", (),
                            chain + ((entry, _identity(info, relative), relative),))
                finally:
                    if child >= 0:
                        os.close(child)
            elif stat.S_ISREG(info.st_mode):
                opened = _open_child(handle, name, entry, relative, source,
                                     directory=False)
                try:
                    _confirm_regular(opened, info, relative, source)
                    if not DESCRIPTOR_TRAVERSAL:
                        _confirm_ancestors(chain, source)
                    found.append(relative)
                    if visit is not None:
                        visit(relative, opened)
                finally:
                    os.close(opened)
            else:
                raise SourcesNotIdentified(
                    f"refusing to stage {relative} from {source}: "
                    f"{source / relative} is neither a regular file nor a "
                    f"directory"
                )

    root, identity = _open_root(source)
    try:
        descend(root, source, "", tuple(pruned), ((source, identity, ""),))
    finally:
        if root >= 0:
            os.close(root)
    return sorted(found)


def relative_source_files(source: Path | str,
                          pruned: tuple[str, ...] = ()) -> list[str]:
    """The paths :func:`walk_source_tree` finds, with nothing read."""
    return walk_source_tree(source, pruned)


def stage_root(source: Path | str, destination: Path | str,
               pruned: tuple[str, ...] = ()) -> dict[str, str]:
    """Copy ``source`` to ``destination``; report ``{relative path: sha256}``.

    Content and the executable bit are all that cross.  Timestamps and ownership
    are deliberately not preserved: they are not part of what a source file is,
    and carrying them would make the artefact contract depend on when the tree
    was checked out.

    Each file is written from the descriptor the walk validated, in the same
    pass.  Walking first and copying afterwards would name every file twice and
    read the second name, which is a different question with a possibly
    different answer.
    """
    source = Path(source)
    destination = Path(destination)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    staged: dict[str, str] = {}

    def copy(relative: str, handle: int) -> None:
        target = destination.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = _read_descriptor(handle)
        target.write_bytes(payload)
        executable = bool(os.fstat(handle).st_mode & 0o111)
        os.chmod(target, 0o755 if executable else 0o644)
        staged[relative] = hashlib.sha256(payload).hexdigest()

    try:
        walk_source_tree(source, pruned, visit=copy)
    except BaseException:
        # A refusal partway through has already written some of the tree, and
        # half a copy of four packages is the same dirty worktree as a whole
        # one. Nothing the refused source pointed at survives this.
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return staged


# -- the manifest ------------------------------------------------------------
def write_manifest(staging: Path | str, files: dict[str, str]) -> None:
    """Write the closure over the staged tree, deterministically."""
    document = {
        "version": MANIFEST_VERSION,
        "roots": sorted(STAGED_ROOTS),
        "files": [[path, files[path]] for path in sorted(files)],
    }
    (Path(staging) / MANIFEST_NAME).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", "utf-8")


def scan_staging(staging: Path | str) -> dict[str, str]:
    """``{relative path: sha256}`` for everything staged but the manifest.

    The whole staging tree is walked rather than the four roots, so a file
    smuggled in beside them is seen as the extra file it is.
    """
    found: dict[str, str] = {}

    def digest(relative: str, handle: int) -> None:
        if relative == MANIFEST_NAME:
            return
        found[relative] = hashlib.sha256(_read_descriptor(handle)).hexdigest()

    walk_source_tree(staging, visit=digest)
    return found


def verify_staging(staging: Path | str) -> dict[str, str]:
    """Check the staged tree against its manifest and return what it holds."""
    staging = Path(staging)
    manifest = staging / MANIFEST_NAME
    if not staging.is_dir():
        raise StagingMismatch(f"there are no staged sources at {staging}")
    if not manifest.is_file():
        raise StagingMismatch(
            f"{staging} carries no {MANIFEST_NAME}: nothing in it says which "
            f"bytes belong to admissible-core, so none of them can be used"
        )
    try:
        document = json.loads(manifest.read_text("utf-8"))
    except (OSError, ValueError) as error:
        raise StagingMismatch(f"{manifest} is not readable JSON: {error}") from error
    if document.get("version") != MANIFEST_VERSION:
        raise StagingMismatch(
            f"{manifest} declares version {document.get('version')!r}; this "
            f"backend writes and reads version {MANIFEST_VERSION}"
        )
    if document.get("roots") != sorted(STAGED_ROOTS):
        raise StagingMismatch(
            f"{manifest} closes over roots {document.get('roots')!r}, and this "
            f"distribution ships {sorted(STAGED_ROOTS)}"
        )
    try:
        expected = {str(path): str(sha) for path, sha in document["files"]}
    except (KeyError, TypeError, ValueError) as error:
        raise StagingMismatch(
            f"{manifest} has no readable file list: {error}") from error
    found = scan_staging(staging)
    missing = sorted(set(expected) - set(found))
    unexpected = sorted(set(found) - set(expected))
    altered = sorted(path for path in set(expected) & set(found)
                     if expected[path] != found[path])
    if missing or unexpected or altered:
        raise StagingMismatch(
            f"the staged sources under {staging} are not the ones "
            f"{MANIFEST_NAME} pins -- missing: {missing or 'nothing'}; "
            f"unexpected: {unexpected or 'nothing'}; "
            f"altered: {altered or 'nothing'}"
        )
    return expected


# -- the built artefact ------------------------------------------------------
#
# Everything above answers a question about the staging tree, and answers it
# before setuptools has read a byte of it.  It has to: the closure is what the
# packager is checked against.  The consequence is a window -- verify, hand
# over, package -- and inside it the tree is an ordinary directory that anybody
# running as this user can rewrite.  So the artefact is reopened and asked the
# same question the tree was asked, and the answer must be the same one.
#
# The two ``*.data/`` schemes unpacked onto ``sys.path`` are unwrapped first: a
# wheel that moved ``fcd/journal.py`` to ``<dist>.data/purelib/fcd/journal.py``
# installs it to exactly the same place and would otherwise be compared against
# nothing at all.
_SYS_PATH_DATA_SCHEMES = ("purelib", "platlib")


class _Closure(NamedTuple):
    """What the staged tree was, at the moment it was last verified."""

    files: dict[str, str]
    manifest: bytes


def _installed_name(member: str) -> str | None:
    """Where a wheel member lands under ``site-packages``, or ``None``."""
    parts = member.split("/")
    if not parts[0].endswith(".data"):
        return member
    if len(parts) > 2 and parts[1] in _SYS_PATH_DATA_SCHEMES:
        return "/".join(parts[2:])
    return None


def _discard(artefact: Path) -> str | None:
    """Remove a refused artefact; say so if it survived.

    Deleting it is the whole point of refusing it, so a deletion that fails is
    not a detail to swallow: the caller says it in the refusal, because "this
    wheel is wrong" and "this wheel is wrong and still sitting in your output
    directory" call for different next steps.
    """
    try:
        os.unlink(artefact)
    except FileNotFoundError:
        return None
    except OSError as error:
        return f"and {artefact} could not be removed ({error}), so it is still there"
    return None


def _refuse_and_discard(artefact: Path, refusal: BuildBackendError):
    """Delete ``artefact``, then raise the refusal that condemned it."""
    survived = _discard(artefact)
    if survived is None:
        raise refusal
    raise ArtifactMismatch(f"{refusal}; {survived}") from refusal


def _describe(kind: str, artefact: Path, missing, unexpected, altered) -> str:
    return (
        f"the {kind} {artefact.name} does not carry the bytes "
        f"{MANIFEST_NAME} pins -- missing: {sorted(missing) or 'nothing'}; "
        f"unexpected: {sorted(unexpected) or 'nothing'}; "
        f"altered: {sorted(altered) or 'nothing'}. The staged tree verified "
        f"before setuptools ran and the artefact it produced disagree, which is "
        f"what a file replaced underneath the packager looks like from here"
    )


def _compare(kind: str, artefact: Path, found: dict[str, str],
             expected: dict[str, str]) -> None:
    missing = set(expected) - set(found)
    unexpected = set(found) - set(expected)
    altered = {path for path in set(expected) & set(found)
               if expected[path] != found[path]}
    if missing or unexpected or altered:
        raise ArtifactMismatch(_describe(kind, artefact, missing, unexpected, altered))


def _check_built_wheel(wheel: Path, expected: dict[str, str]) -> None:
    if not wheel.is_file():
        raise ArtifactMismatch(
            f"setuptools reported {wheel.name}, and there is no such file at "
            f"{wheel}: a build's own account of what it produced is not evidence"
        )
    found: dict[str, str] = {}
    try:
        with zipfile.ZipFile(wheel) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                installed = _installed_name(info.filename)
                if installed is None or installed.split("/")[0] not in STAGED_ROOTS:
                    continue
                if stat.S_ISLNK(info.external_attr >> 16):
                    raise ArtifactMismatch(
                        f"{wheel.name} carries {installed} as a symbolic link to "
                        f"{archive.read(info.filename)!r}; an installer would "
                        f"resolve it on the installing machine, so a staged "
                        f"source shipped as a link is a source nobody has read"
                    )
                if installed in found:
                    raise ArtifactMismatch(
                        f"{wheel.name} carries two members installing to "
                        f"{installed}; which of them a consumer imports is "
                        f"decided by the unpacking order, not by this build"
                    )
                found[installed] = hashlib.sha256(
                    archive.read(info.filename)).hexdigest()
    except (OSError, zipfile.BadZipFile) as error:
        raise ArtifactMismatch(
            f"{wheel} is not a readable wheel: {error}") from error
    _compare("wheel", wheel, found, expected)


def verify_built_wheel(wheel: Path | str, expected: dict[str, str]) -> None:
    """Reopen a built wheel and refuse it unless it matches the closure.

    Deleted on refusal, and deleted before the refusal is raised: an artefact
    left in the output directory is an artefact somebody uploads.
    """
    wheel = Path(wheel)
    try:
        _check_built_wheel(wheel, expected)
    except BuildBackendError as refusal:
        _refuse_and_discard(wheel, refusal)


def _check_built_sdist(sdist: Path, expected: dict[str, str],
                       manifest: bytes) -> None:
    if not sdist.is_file():
        raise ArtifactMismatch(
            f"setuptools reported {sdist.name}, and there is no such file at "
            f"{sdist}: a build's own account of what it produced is not evidence"
        )
    found: dict[str, str] = {}
    carried: bytes | None = None
    try:
        with tarfile.open(sdist) as archive:
            members = archive.getmembers()
            tops = {member.name.split("/")[0] for member in members}
            if len(tops) != 1:
                raise ArtifactMismatch(
                    f"{sdist.name} holds {sorted(tops)} at its root; a source "
                    f"distribution unpacks into exactly one directory"
                )
            prefix = f"{tops.pop()}/_staged/"
            for member in members:
                parts = PurePosixPath(member.name).parts
                if member.name.startswith("/") or ".." in parts:
                    raise ArtifactMismatch(
                        f"{sdist.name} carries {member.name}, which unpacks "
                        f"outside the directory the archive claims"
                    )
                if not member.name.startswith(prefix):
                    continue
                relative = member.name[len(prefix):]
                if member.issym() or member.islnk():
                    raise ArtifactMismatch(
                        f"{sdist.name} carries {relative} as a "
                        f"{'symbolic' if member.issym() else 'hard'} link to "
                        f"{member.linkname!r}; extracting it would put whatever "
                        f"the unpacking machine has there into the staging tree "
                        f"an sdist-derived wheel is then built from"
                    )
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ArtifactMismatch(
                        f"{sdist.name} carries {relative} as neither a regular "
                        f"file nor a directory, and a staged source is one or "
                        f"the other"
                    )
                payload = archive.extractfile(member).read()
                if relative == MANIFEST_NAME:
                    carried = payload
                    continue
                found[relative] = hashlib.sha256(payload).hexdigest()
    except (OSError, tarfile.TarError) as error:
        raise ArtifactMismatch(
            f"{sdist} is not a readable source distribution: {error}") from error
    if carried is None:
        raise ArtifactMismatch(
            f"{sdist.name} carries no _staged/{MANIFEST_NAME}: its consumer "
            f"would have the staged bytes and nothing to check them against"
        )
    if carried != manifest:
        raise ArtifactMismatch(
            f"the _staged/{MANIFEST_NAME} in {sdist.name} is not the one this "
            f"build verified; the closure that travels with an sdist is the "
            f"closure an sdist-derived wheel is judged by, so it may not be "
            f"rewritten between the two"
        )
    _compare("sdist", sdist, found, expected)


def verify_built_sdist(sdist: Path | str, expected: dict[str, str],
                       manifest: bytes) -> None:
    """Reopen a built sdist and refuse it unless it matches the closure."""
    sdist = Path(sdist)
    try:
        _check_built_sdist(sdist, expected, manifest)
    except BuildBackendError as refusal:
        _refuse_and_discard(sdist, refusal)


# -- the lifecycle -----------------------------------------------------------
def _refresh(lock: _BuildLock) -> None:
    """Replace the staging tree with a fresh copy of the repository's roots.

    Whatever is there is replaced without being read: a tree left behind by a
    build that crashed is residue, not evidence, and the lock is what says this
    process may remove it.
    """
    lock.require_held("refresh the staged sources")
    shutil.rmtree(STAGING, ignore_errors=True)
    STAGING.mkdir(parents=True)
    files: dict[str, str] = {}
    for name in sorted(STAGED_ROOTS):
        staged = stage_root(REPOSITORY / name, STAGING / name, STAGED_ROOTS[name])
        files.update({f"{name}/{relative}": sha for relative, sha in staged.items()})
    write_manifest(STAGING, files)


def _closure(staging: Path) -> _Closure:
    """Verify the staged tree and take the closure the artefact is judged by.

    Read back from disk rather than trusting the dictionary just written: the
    manifest is only worth carrying if it describes the files, not the plan.
    The bytes are kept in memory because the file they came from is exactly what
    an attacker in the window would rewrite next.
    """
    return _Closure(verify_staging(staging), (staging / MANIFEST_NAME).read_bytes())


@contextmanager
def _staged():
    """Hold the lock across staging, the setuptools hook, and cleanup.

    Yields the closure, so that every hook producing an artefact can compare
    what setuptools wrote with what was verified before setuptools ran.
    """
    with build_lock() as lock:
        owned = is_canonical_checkout()
        try:
            if owned:
                _refresh(lock)
            elif not STAGING.is_dir():
                raise SourcesNotIdentified(
                    f"{PROJECT} is neither this repository's packages/core nor "
                    f"an extracted admissible-core sdist: there is no staged "
                    f"source tree at {STAGING}, and no identified repository to "
                    f"stage one from. Build from the checkout, or from an "
                    f"unmodified sdist."
                )
            # For an extracted sdist, what is staged *is* the source, and the
            # manifest that travelled with it says which bytes those are.
            yield _closure(STAGING)
        finally:
            # The refusals above run inside this ``try`` as well as the hook: a
            # refresh that stopped halfway through leaves the same half-copy of
            # four packages in the working tree as a failed build does.
            if owned:
                # Cleaned unconditionally, including after a failed build: a
                # stray copy of the research roots left in the tree is a dirty
                # worktree, and a dirty worktree is a refused commit. Only ever
                # the tree this build staged, and only while it still holds the
                # lock that made it this build's to remove.
                lock.require_held("remove the staged sources")
                shutil.rmtree(STAGING, ignore_errors=True)


def get_requires_for_build_wheel(config_settings=None):
    with _staged():
        return _setuptools.get_requires_for_build_wheel(config_settings)


def get_requires_for_build_sdist(config_settings=None):
    with _staged():
        return _setuptools.get_requires_for_build_sdist(config_settings)


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    with _staged():
        return _setuptools.prepare_metadata_for_build_wheel(
            metadata_directory, config_settings)


def _setuptools_distribution_version() -> str:
    """Version of the setuptools package that owns the loaded backend.

    ``setuptools.__version__`` is computed through ``importlib.metadata`` at
    import time.  In Python 3.14's PEP 517 subprocess an extracted project's
    local ``*.egg-info`` can satisfy that unscoped lookup first, making
    setuptools report the *project* version (``0.8.0``) as its own.  Search only
    the site-packages directory containing the loaded ``build_meta`` module and
    then require the distribution's exact metadata name instead.
    """

    site_packages = Path(_setuptools.__file__).resolve().parent.parent
    versions = {
        distribution.version
        for distribution in importlib.metadata.distributions(
            path=[str(site_packages)])
        if _normalize(distribution.metadata["Name"] or "") == "setuptools"
    }
    if len(versions) != 1:
        raise BuildBackendError(
            "cannot identify the setuptools distribution that loaded "
            f"{_setuptools.__file__}: found versions {sorted(versions)!r} in "
            f"{site_packages}")
    return versions.pop()


@contextmanager
def _honest_wheel_generator():
    """Make WHEEL name the loaded setuptools, not local project metadata."""

    from setuptools.command.bdist_wheel import bdist_wheel

    original = bdist_wheel.write_wheelfile
    expected_generator = f"setuptools ({_setuptools_distribution_version()})"

    def write_wheelfile(self, wheelfile_base: str,
                        generator: str = expected_generator) -> None:
        return original(self, wheelfile_base, generator)

    bdist_wheel.write_wheelfile = write_wheelfile
    try:
        yield
    finally:
        bdist_wheel.write_wheelfile = original


def build_wheel(wheel_directory, config_settings=None,
                metadata_directory=None):
    """Build the wheel, then reopen it and check it against the closure.

    The same check covers the direct build and the sdist-derived one: the
    closure an extracted sdist yields is the manifest that travelled inside it,
    so a wheel built from an sdist is judged by the bytes that sdist shipped.
    """
    with _staged() as closure:
        with _honest_wheel_generator():
            name = _setuptools.build_wheel(
                wheel_directory, config_settings, metadata_directory)
        verify_built_wheel(Path(wheel_directory) / name, closure.files)
        return name


def build_sdist(sdist_directory, config_settings=None):
    with _staged() as closure:
        name = _setuptools.build_sdist(sdist_directory, config_settings)
        verify_built_sdist(
            Path(sdist_directory) / name, closure.files, closure.manifest)
        return name
