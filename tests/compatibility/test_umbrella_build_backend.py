"""Contract: the umbrella's build is pinned, offline, isolated and repeatable.

Every other suite that builds this distribution builds it with
``--no-isolation``, against whatever ``setuptools`` the interpreter running the
tests happens to hold.  That proves the *sources* are right and proves nothing
at all about the *build*: a range like ``setuptools>=77`` resolves to a
different backend on every machine and on every day, so "the wheel is these
bytes" is a statement about one laptop at one moment, and an isolated build --
the one a release actually performs, and the one ``pip install .`` performs --
was never run here even once.

So this suite does the thing the others cannot:

* **the pin is exact** -- ``[build-system].requires`` names one version with
  ``==`` and no range, floor, ceiling or wildcard, the pinned backend supports
  the ``>=3.10`` floor this project declares, and the backend is asked what
  further requirements it has so that a second entry is present only when the
  backend genuinely wants one;
* **the wheelhouse is local** -- the pinned backend is taken from a directory on
  this machine, verified by the metadata *inside* the wheel rather than by its
  filename, and installed with no index, no cache and no network.  A missing
  backend fails, loudly, with the command that fixes it: a skipped
  reproducibility test reads exactly like a reproducibility that holds;
* **the build is isolated** -- two throwaway environments are built from that
  one wheelhouse, and the checkout is not on either one's import path.  A
  poisoned ``PYTHONPATH`` in the parent shell is proved not to reach them, by
  building with one set and comparing the bytes;
* **the bytes repeat** -- each environment builds a wheel and an sdist from its
  own pristine copy of the project with ``SOURCE_DATE_EPOCH`` pinned, and the
  complete SHA-256 of the wheel file is compared, not a list of member names.
  The wheel built from the sdist is compared the same way.

One asymmetry is stated rather than papered over.  ``setuptools`` honours
``SOURCE_DATE_EPOCH`` when it writes a wheel and ignores it entirely when it
writes an sdist: the vendored wheel writer reads the variable, and the sdist
path goes through ``distutils.archive_util.make_tarball``, which opens the
archive as ``w|gz`` -- so ``tarfile`` stamps the RFC 1952 header from
``time.time()`` -- copies each member's mtime off the file system, and writes a
PAX extended header carrying a sub-second ``mtime`` for every file the build
itself creates.  No environment variable changes any of that, at any version of
the backend, so the sdist file's own digest cannot repeat and saying it does
would be false.

What is done instead is to normalise the build environment as far as it can be
normalised -- pristine copies of the project whose every mtime is set to the
pinned epoch, a fixed ``TZ``, a fixed locale, a fixed hash seed, no byte-code --
and then to assert something complete rather than something weaker.  The
archive is compared as bytes, uncompressed, with exactly the timestamps taken
out of it: each header's mtime digits, the number in the checksum covering it,
the declared size of an extended header, and the value of a PAX time record
with the padding length that value decides.  Everything else is in that digest
as the bytes the writer wrote -- names, modes, ownership, type flags, link
targets, device numbers, magic, prefixes, every payload byte, the block
padding, the end-of-archive marker, and the 512 bytes of each PAX extended
header block that ``tarfile`` never shows a caller.  A checksum is not
discarded but compared as its difference from the sum its own block produces,
which is zero for anything a writer wrote and is not a clock.

That exclusion list is a tested property and not a description:
:class:`TheNormalisationReadsEveryByteButTheClock` moves every byte of an
archive one at a time and asserts, as an equality, that the bytes the digest
does not notice are the digits of a PAX timestamp and nothing else.  The
previous normalisation is kept beside it as the control, because it replaced
each extended header block and payload with a rendering of the records that
were not a clock -- and since the only record setuptools writes *is* a clock,
that rendering was a constant, and every other byte those blocks carried was
compared against nothing.

The timestamps that were removed are then asserted as themselves -- the
checked-in files must carry the pinned epoch exactly, and the files that carry
a clock must be exactly the ones setuptools generates.  The content assertion is
not weakened to a list of paths anywhere.
"""
from __future__ import annotations

import atexit
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 support
    import tomli as tomllib  # type: ignore[import-not-found, no-redef]
import unittest
import venv
import zipfile
from pathlib import Path
from unittest import mock

from tests.architecture import inspect_wheel

from tests.compatibility import REPO_ROOT, UMBRELLA_PACKAGE, UMBRELLA_PROJECT

VERSION = "0.8.1"
DISTRIBUTION = "admissible"

#: The backend, named once and exactly.
#:
#: 83.0.0 and not a range: this is the version installed in the interpreter the
#: repository's own ``Makefile`` runs, its wheel is a pure-Python
#: ``py3-none-any`` archive that needs no compiler to install offline, and its
#: own ``Requires-Python`` is ``>=3.10``, which is this project's floor exactly.
#: A range would mean the artefact this repository ships is whatever the
#: resolver felt like on the day of the release, and "the same wheel" would stop
#: being a checkable claim.
BACKEND_DISTRIBUTION = "setuptools"
BACKEND_VERSION = "83.0.0"
BACKEND_REQUIREMENT = f"{BACKEND_DISTRIBUTION}=={BACKEND_VERSION}"
BACKEND_WHEEL = f"{BACKEND_DISTRIBUTION}-{BACKEND_VERSION}-py3-none-any.whl"
BUILD_BACKEND = "setuptools.build_meta"

#: ``[build-system].requires``, as an equality.  ``wheel`` is deliberately
#: absent: setuptools has vendored the wheel writer since 70.1, and
#: :meth:`TheBackendNeedsNothingFurther.test_the_backend_asks_for_no_further_requirement`
#: asks the backend itself rather than taking that on trust.
EXPECTED_BUILD_REQUIRES = [BACKEND_REQUIREMENT]

REQUIRES_PYTHON = ">=3.10"

#: Anything that makes a requirement resolve to more than one version.
#: ``===`` is exact string equality rather than a version match, and is refused
#: with the ranges because it pins a spelling instead of a release.
RANGE_OPERATORS = (">=", "<=", "~=", "!=", "===", ">", "<")

#: Where the pinned backend may be found without a network.  A directory in
#: this variable is consulted first, so an air-gapped machine can be told once.
WHEELHOUSE_VARIABLE = "ADMISSIBLE_WHEELHOUSE"

#: The clock both builds are told to use.  Shared with the rest of the artefact
#: suites so one pinned epoch means one thing in this repository.
EPOCH = int(inspect_wheel.SOURCE_DATE_EPOCH)

#: What the sdist holds that no file in the checkout does.  setuptools writes
#: each of these during the build, so each carries the wall clock and not the
#: pinned epoch; the assertion below is that this list is *exactly* the set of
#: members the clock touches, which is what keeps "only timestamps differ" from
#: quietly growing into "only some content differs".
GENERATED_SDIST_FILES = ("PKG-INFO", "setup.cfg")
GENERATED_SDIST_PREFIX = f"{DISTRIBUTION}.egg-info/"
EGG_INFO_FILES = ("PKG-INFO", "SOURCES.txt", "dependency_links.txt",
                  "entry_points.txt", "requires.txt", "top_level.txt")

#: The modules the archives must hold, derived from the checkout rather than
#: retyped: a facade added tomorrow is covered on the day it is added.
SOURCE_MODULES = tuple(sorted(path.name
                              for path in UMBRELLA_PACKAGE.rglob("*.py")))

#: The single directory every sdist member sits under, per PEP 625.
SDIST_ROOT = f"{DISTRIBUTION}-{VERSION}"


def expected_sdist_members() -> set[str]:
    """Every member name the sdist must hold, and no other."""
    members = {
        SDIST_ROOT,
        f"{SDIST_ROOT}/LICENSE",
        f"{SDIST_ROOT}/MANIFEST.in",
        f"{SDIST_ROOT}/NOTICE",
        f"{SDIST_ROOT}/PKG-INFO",
        f"{SDIST_ROOT}/README.md",
        f"{SDIST_ROOT}/pyproject.toml",
        f"{SDIST_ROOT}/setup.cfg",
        f"{SDIST_ROOT}/compat",
        f"{SDIST_ROOT}/compat/{DISTRIBUTION}",
        f"{SDIST_ROOT}/{DISTRIBUTION}.egg-info",
    }
    members |= {f"{SDIST_ROOT}/compat/{DISTRIBUTION}/{name}"
                for name in SOURCE_MODULES}
    members |= {f"{SDIST_ROOT}/{GENERATED_SDIST_PREFIX}{name}"
                for name in EGG_INFO_FILES}
    return members


def expected_source_members() -> set[str]:
    """The sdist members copied out of the checkout, whose mtime is the epoch."""
    return {
        f"{SDIST_ROOT}/LICENSE",
        f"{SDIST_ROOT}/MANIFEST.in",
        f"{SDIST_ROOT}/NOTICE",
        f"{SDIST_ROOT}/README.md",
        f"{SDIST_ROOT}/pyproject.toml",
        *(f"{SDIST_ROOT}/compat/{DISTRIBUTION}/{name}"
          for name in SOURCE_MODULES),
    }


def expected_generated_members() -> set[str]:
    """The sdist members setuptools writes while the build runs.

    Each carries the wall clock rather than ``SOURCE_DATE_EPOCH``, because the
    sdist writer reads neither that variable nor anything else that could pin
    it.  The directories are here for the same reason: the staging tree they
    describe is created during the build, not copied out of the checkout.
    """
    return {
        SDIST_ROOT,
        f"{SDIST_ROOT}/compat",
        f"{SDIST_ROOT}/compat/{DISTRIBUTION}",
        f"{SDIST_ROOT}/{DISTRIBUTION}.egg-info",
        *(f"{SDIST_ROOT}/{name}" for name in GENERATED_SDIST_FILES),
        *(f"{SDIST_ROOT}/{GENERATED_SDIST_PREFIX}{name}"
          for name in EGG_INFO_FILES),
    }


class PreparationError(RuntimeError):
    """The isolated build could not be set up, with the reason a human needs."""


# -- the pinned declaration --------------------------------------------------
def build_system() -> dict:
    """``[build-system]`` as the resolver reads it."""
    document = tomllib.loads(
        (UMBRELLA_PROJECT / "pyproject.toml").read_text(encoding="utf-8"))
    return document.get("build-system", {})


def wheel_metadata(path: Path) -> dict[str, str]:
    """``Name``/``Version``/``Requires-Python`` read from inside a wheel.

    From inside, because a filename is a claim and the archive is the evidence:
    a renamed wheel in a wheelhouse would otherwise satisfy an exact pin with
    an entirely different release.  ``inspect_wheel`` is what reads it, so the
    distribution's own ``.dist-info`` is told apart from the ``.dist-info``
    fixtures a packaging library ships inside its test data.
    """
    wheel = inspect_wheel.inspect_wheel(path)
    return {
        "Name": wheel.name,
        "Version": wheel.version,
        "Requires-Python": wheel.requires_python,
    }


# -- the local wheelhouse ----------------------------------------------------
def declared_requirements() -> list[tuple[str, str]]:
    """``[build-system].requires`` read as ``(distribution, version)`` pairs.

    This is where the argument for an exact pin stops being a preference and
    becomes a mechanism: a wheelhouse is a directory of files, and a
    requirement that does not name one release cannot say which file belongs in
    it.  A ranged declaration therefore cannot be prepared offline at all, and
    is refused here rather than quietly resolved against whatever happens to be
    lying around -- which is the same thing an isolated build does when it is
    allowed to reach an index.
    """
    pairs: list[tuple[str, str]] = []
    for requirement in build_system().get("requires", []):
        floating = [operator for operator in RANGE_OPERATORS
                    if operator in requirement]
        name, separator, version = requirement.partition("==")
        if floating or not separator or not version.strip() or any(
                character in requirement for character in ",*"):
            raise PreparationError(
                f"'{requirement}' does not name one release, so no offline "
                "wheelhouse can be built from it and no isolated build of this "
                "project is reproducible: resolving it would mean reaching an "
                f"index. Declare an exact '==' pin in "
                f"{UMBRELLA_PROJECT / 'pyproject.toml'}.")
        pairs.append((inspect_wheel.normalize_name(name.strip()),
                      version.strip()))
    if not pairs:
        raise PreparationError("[build-system].requires names no backend")
    return pairs


def _pip_cached_wheels(distribution: str) -> list[Path]:
    """Wheels for ``distribution`` pip already holds on this machine."""
    completed = subprocess.run(
        [inspect_wheel.sys.executable, "-m", "pip", "cache", "list",
         distribution, "--format=abspath"],
        capture_output=True, text=True, timeout=inspect_wheel.RUN_TIMEOUT,
        env=inspect_wheel.sanitized_env())
    if completed.returncode != 0:
        return []
    return [Path(line.strip()) for line in completed.stdout.splitlines()
            if line.strip().endswith(".whl")]


def _local_candidates(distribution: str, version: str) -> list[Path]:
    """Every local file that might be that release, before it is verified."""
    candidates: list[Path] = []
    declared = os.environ.get(WHEELHOUSE_VARIABLE)
    if declared:
        candidates += sorted(Path(declared).glob("*.whl"))
    candidates += _pip_cached_wheels(distribution)
    return [path for path in candidates if path.is_file()]


def populate_wheelhouse(destination: Path) -> list[Path]:
    """Copy every declared build requirement into ``destination``, or say why not.

    This never reaches an index.  The two places a wheel may come from are a
    directory the operator named and pip's own local cache, and each is
    verified against the metadata *inside* the archive rather than against its
    filename before being used.
    """
    destination.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for distribution, version in declared_requirements():
        rejected: list[str] = []
        found = None
        for candidate in _local_candidates(distribution, version):
            try:
                metadata = wheel_metadata(candidate)
            except (PreparationError, inspect_wheel.WheelError, OSError,
                    zipfile.BadZipFile) as error:
                rejected.append(f"{candidate}: {error}")
                continue
            if (metadata["Name"] != distribution
                    or metadata["Version"] != version):
                rejected.append(
                    f"{candidate}: metadata says "
                    f"{metadata['Name']}=={metadata['Version']}")
                continue
            found = destination / candidate.name
            shutil.copyfile(candidate, found)
            break
        if found is None:
            raise PreparationError(
                f"no local wheel for {distribution}=={version} was found, so "
                "the isolated build could not be proved offline. This is a "
                "failure and not a skip: an unproved reproducible build reads "
                "exactly like a proved one.\n"
                f"  looked in: ${WHEELHOUSE_VARIABLE} and `pip cache list "
                f"{distribution} --format=abspath`\n"
                f"  rejected: {rejected or 'nothing'}\n"
                f"  to fix, once, with a network: pip download "
                f"{distribution}=={version} --only-binary=:all: -d <dir> && "
                f"export {WHEELHOUSE_VARIABLE}=<dir>")
        copied.append(found)
    return copied


# -- the isolated environment ------------------------------------------------
def build_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    """The environment every build subprocess gets.

    :func:`tests.architecture.inspect_wheel.sanitized_env` already removes
    ``PYTHONPATH`` and friends, refuses an index and pins ``SOURCE_DATE_EPOCH``.
    What is added here is the rest of what a timestamp or a sort order could be
    read off: the time zone, the collation locale, and pip's cache.
    """
    return inspect_wheel.sanitized_env({
        "TZ": "UTC",
        "LC_ALL": "C",
        "LANG": "C",
        "PYTHONHASHSEED": "0",
        "PIP_NO_CACHE_DIR": "1",
        **(extra or {}),
    })


def create_isolated_environment(root: Path, wheelhouse: Path) -> dict:
    """A venv holding the declared build requirements and nothing else.

    The requirements come from the project's own ``[build-system].requires``
    rather than from a constant in this file, so what is exercised below is the
    declaration a release actually builds against.
    """
    venv.EnvBuilder(with_pip=True, system_site_packages=False, clear=True,
                    symlinks=os.name != "nt").create(str(root))
    interpreter = inspect_wheel.venv_python(root)
    if not interpreter.is_file():
        raise PreparationError(f"no interpreter at {interpreter}")
    requirements = [f"{name}=={version}"
                    for name, version in declared_requirements()]
    command = [
        str(interpreter), "-m", "pip", "install", "--no-index", "--no-cache-dir",
        "--find-links", str(wheelhouse), *requirements,
    ]
    completed = subprocess.run(
        command, capture_output=True, text=True,
        timeout=inspect_wheel.RUN_TIMEOUT,
        env=build_environment({"PIP_CACHE_DIR": str(root / "pip-cache")}))
    if completed.returncode != 0:
        raise PreparationError(
            f"installing {requirements} offline failed\n"
            f"  exit: {completed.returncode}\n  stderr: {completed.stderr[-2000:]}")
    return {"interpreter": interpreter, "install_log": completed.stdout,
            "requirements": requirements, "root": root}


#: Ask the backend to build, and report what the backend could see while it did.
#:
#: The report is written to a file rather than to stdout because setuptools
#: narrates its own work on stdout, and a report that has to be found in that
#: narration is a report that can be lost in it.
_PEP517_DRIVER = """
import json, os, sys

import setuptools
from setuptools import build_meta as backend

outdir, kind, report_path = sys.argv[1], sys.argv[2], sys.argv[3]
report = {
    "setuptools": setuptools.__version__,
    "executable": sys.executable,
    "prefix": sys.prefix,
    "cwd": os.getcwd(),
    "sys_path": [os.path.realpath(entry or os.getcwd()) for entry in sys.path],
    "requires_wheel": list(backend.get_requires_for_build_wheel({})),
    "requires_sdist": list(backend.get_requires_for_build_sdist({})),
    "source_date_epoch": os.environ.get("SOURCE_DATE_EPOCH"),
    "pythonpath": os.environ.get("PYTHONPATH"),
}
report["artifact"] = (
    backend.build_wheel(outdir, {}) if kind == "wheel"
    else backend.build_sdist(outdir, {}))
with open(report_path, "w", encoding="utf-8") as handle:
    json.dump(report, handle)
"""

#: What the isolated interpreter can import.  Everything named is a package the
#: checkout holds and no wheel in the wheelhouse ships, so a ``True`` anywhere
#: is the checkout reaching a build that must not be able to see it.
_IMPORT_PROBE = """
import importlib.util, json, sys

found = {}
for name in sys.argv[1:]:
    try:
        found[name] = importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        found[name] = False
sys.stdout.write(json.dumps(found))
"""

CHECKOUT_PACKAGES = ("admissible", "admissible_core", "admissible_ready",
                     "admissible_trust", "fcd", "rga", "atlas", "protocol",
                     "server", "tests")


def pep517(environment: dict, project: Path, outdir: Path,
           kind: str, *, env: dict[str, str] | None = None) -> tuple[Path, dict]:
    """Drive one PEP 517 hook in an isolated environment and read its report."""
    outdir.mkdir(parents=True, exist_ok=True)
    report_path = outdir / f"{kind}-report.json"
    completed = subprocess.run(
        [str(environment["interpreter"]), "-c", _PEP517_DRIVER, str(outdir),
         kind, str(report_path)],
        capture_output=True, text=True, cwd=str(project),
        timeout=inspect_wheel.BUILD_TIMEOUT, env=env or build_environment())
    if completed.returncode != 0 or not report_path.is_file():
        raise PreparationError(
            f"the isolated {kind} build of {project} failed\n"
            f"  exit: {completed.returncode}\n"
            f"  stdout: {completed.stdout[-2000:]}\n"
            f"  stderr: {completed.stderr[-2000:]}")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return outdir / report["artifact"], report


def clean_copy(destination: Path) -> Path:
    """A pristine copy of the project whose every mtime is the pinned epoch.

    Two builds are only comparable when their inputs are.  ``setuptools``
    copies a source file's mtime into the sdist verbatim, so an input tree that
    remembers when it was checked out is an input tree that makes the artefact
    depend on when it was checked out.
    """
    shutil.copytree(
        UMBRELLA_PROJECT, destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "build", "dist",
                                      "*.egg-info"))
    for path in [destination, *destination.rglob("*")]:
        os.utime(path, (EPOCH, EPOCH))
    return destination


def poison_directory(destination: Path) -> Path:
    """A directory no build may see, shaped so that seeing it is fatal.

    ``setuptools`` here is a module that raises on import: if the parent
    shell's ``PYTHONPATH`` reached the isolated interpreter, the backend the
    build resolves would be this one and the build would fail loudly rather
    than quietly produce different bytes.  ``fcd`` and ``admissible`` are named
    packages the checkout also holds, so a leak that somehow survived the
    backend would still show up as a directory on the build's ``sys.path``.
    """
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "setuptools.py").write_text(
        "raise RuntimeError('the parent PYTHONPATH reached an isolated "
        "build')\n", encoding="utf-8")
    for name in ("fcd", "admissible"):
        package = destination / name
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").write_text(
            f"SENTINEL = {name!r}\n", encoding="utf-8")
    return destination


# -- reading the artefacts ---------------------------------------------------
def digest(path: Path) -> str:
    """SHA-256 of every byte of a file, which is what "the same artefact" means."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


#: A ``ustar`` header block, field by field, covering all 512 bytes.  Naming
#: every one of them is what lets the normalisation below say which bytes it
#: excludes by pointing at a field rather than by trusting that the fields it
#: forgot to mention were unimportant.
_TAR_BLOCK = 512
_TAR_NAME = slice(0, 100)
_TAR_MODE = slice(100, 108)
_TAR_UID = slice(108, 116)
_TAR_GID = slice(116, 124)
_TAR_SIZE = slice(124, 136)
_TAR_MTIME = slice(136, 148)
_TAR_CHECKSUM = slice(148, 156)
_TAR_TYPE = slice(156, 157)
_TAR_LINKNAME = slice(157, 257)
_TAR_MAGIC = slice(257, 265)
_TAR_UNAME = slice(265, 297)
_TAR_GNAME = slice(297, 329)
_TAR_DEVMAJOR = slice(329, 337)
_TAR_DEVMINOR = slice(337, 345)
_TAR_PREFIX = slice(345, 500)
_TAR_UNUSED = slice(500, 512)

#: Every field of the block, in order and with no gap.  Asserted, so that a
#: field renamed or resized here cannot silently stop covering the block.
_TAR_FIELDS = (
    ("name", _TAR_NAME), ("mode", _TAR_MODE), ("uid", _TAR_UID),
    ("gid", _TAR_GID), ("size", _TAR_SIZE), ("mtime", _TAR_MTIME),
    ("checksum", _TAR_CHECKSUM), ("type", _TAR_TYPE),
    ("linkname", _TAR_LINKNAME), ("magic", _TAR_MAGIC), ("uname", _TAR_UNAME),
    ("gname", _TAR_GNAME), ("devmajor", _TAR_DEVMAJOR),
    ("devminor", _TAR_DEVMINOR), ("prefix", _TAR_PREFIX),
    ("unused", _TAR_UNUSED),
)


def _member_size(header: bytes) -> int:
    """The declared payload size of one tar header block.

    A block whose size field is not a number is not a block this module can
    frame, and it reports zero rather than raising: the walkers below are run
    over deliberately corrupted archives, where an exception would be a
    different answer than "these bytes are not the same archive".
    """
    raw = header[_TAR_SIZE]
    if raw[0] & 0x80:  # base-256, for sizes octal cannot express
        return int.from_bytes(raw[1:], "big")
    text = raw.split(b"\0")[0].strip()
    try:
        return int(text, 8) if text else 0
    except ValueError:
        return 0


#: The two extended-header types PAX defines.  ``setuptools`` writes an sdist
#: in :data:`tarfile.PAX_FORMAT`, so a member whose mtime is not a whole number
#: of seconds -- which is every file the build itself creates -- gets one of
#: these carrying ``mtime=<float>`` as text.  The *length* of that text is part
#: of the record and of the block's declared size, so the timestamp is not a
#: fixed-width field there and cannot be blanked in place.
_PAX_TYPES = (b"x", b"g")

#: The record keys that hold a clock.  Everything else a PAX header carries is
#: compared.
_PAX_TIME_KEYS = ("mtime", "atime", "ctime")

#: What stands in the block where a clock-decided field used to sit.  Each is
#: exactly as wide as the field it replaces, so the block that is compared is
#: still a 512-byte block with every other field where a reader expects it.
#: The replaced fields are not lost: each is re-emitted beside the block with
#: its digits, and only its digits, taken out.
_MTIME_ELIDED = b"<mtime-drop>"
_CHECKSUM_ELIDED = b"<chksum>"
_SIZE_ELIDED = b"<pax-length>"


def split_pax_records(payload: bytes) -> tuple[list[bytes], bytes]:
    """The payload cut into raw ``length key=value\\n`` records, plus the rest.

    The second element is whatever could not be framed as a record: empty for
    every archive a writer produced, and a non-empty remainder for one whose
    length prefixes were tampered with.  Returning it rather than raising is
    what lets a corrupted archive still normalise to *something*, so a
    comparison reports "these are not the same bytes" instead of an exception --
    and so that the remainder's bytes are themselves compared rather than lost.
    """
    records: list[bytes] = []
    offset = 0
    while offset < len(payload):
        space = payload.find(b" ", offset)
        if space < 0:
            break
        try:
            length = int(payload[offset:space])
        except ValueError:
            break
        if length <= space - offset or offset + length > len(payload):
            break
        records.append(payload[offset:offset + length])
        offset += length
    return records, payload[offset:]


def pax_record_key(record: bytes) -> bytes:
    """The key of one raw record, or ``b""`` when it carries none."""
    return record.partition(b" ")[2].partition(b"=")[0]


def pax_records(payload: bytes) -> list[tuple[str, str]]:
    """``length key=value\\n`` records, as PAX writes them."""
    records: list[tuple[str, str]] = []
    for raw in split_pax_records(payload)[0]:
        body = raw.partition(b" ")[2].rstrip(b"\n")
        key, _, value = body.partition(b"=")
        records.append((key.decode("utf-8", "surrogateescape"),
                        value.decode("utf-8", "surrogateescape")))
    return records


def header_checksum(header: bytes) -> int:
    """The ``ustar`` checksum: the block summed with its checksum field blank."""
    return sum(header[:_TAR_CHECKSUM.start] + b" " * 8
               + header[_TAR_CHECKSUM.stop:])


def _framed(tag: bytes, payload: bytes) -> bytes:
    """``tag:<length>:<bytes>``, so a concatenation decodes exactly one way.

    Every piece of the rendering below is emitted through this, which is what
    makes the digest collision-resistant rather than merely different: no two
    archives can produce the same stream by one of them carrying, inside a
    payload, the bytes another carries as a header.
    """
    return tag + b":" + str(len(payload)).encode("ascii") + b":" + payload


def _digits_elided(field: bytes, marker: bytes) -> bytes:
    """One numeric header field with its digits replaced and the rest kept.

    ``ustar`` writes a number as octal text with a terminator after it, and
    writers disagree about whether that terminator is a NUL, a space or both.
    Only the number is a clock here, so only the number goes: the bytes around
    it are carried through, and a field whose *shape* changed -- a terminator
    moved, a width that grew -- is a difference the comparison still sees.
    """
    digits = field.split(b"\0")[0].strip()
    if not digits:
        return b"raw:" + field
    start = field.index(digits)
    return field[:start] + marker + field[start + len(digits):]


def canonical_checksum(header: bytes) -> bytes:
    """The checksum field with only its number replaced by a clock-free one.

    The recorded checksum covers the mtime, and on an extended header it covers
    the declared size too, so its digits cannot be compared between two builds.
    What *is* clock-free is the difference between the number recorded and the
    number the block's own bytes produce: zero for every block a writer wrote,
    and non-zero the instant a field moves without its checksum following.  So
    the checksum is not discarded -- it is compared as that difference, which
    is why moving a checksum on its own is caught here rather than excused as a
    field the clock decides.
    """
    field = bytes(header[_TAR_CHECKSUM])
    digits = field.split(b"\0")[0].strip()
    try:
        recorded = int(digits, 8)
    except ValueError:
        return b"raw:" + field
    start = field.index(digits)
    return (field[:start] + b"<%+d>" % (recorded - header_checksum(header))
            + field[start + len(digits):])


def canonical_pax_payload(payload: bytes, size: int) -> bytes:
    """An extended header's records, with the clock's digits and only those out.

    Each record is emitted as the raw bytes the writer wrote -- its length
    prefix, its key, its value, its newline -- so a vendor key, a long name, a
    large uid or a second copy of a record is compared exactly.  A time record
    is emitted as its key alone, because the value is decimal text whose length
    is part of the record's length and of the block's declared size, so nothing
    of it can be compared between two builds.

    The zero padding behind the records is compared for content but not for
    length, since the length is what the timestamp's digits decide: any
    non-zero byte anywhere in it survives, and a padding of a different size
    made entirely of zeroes does not.  Whatever could not be framed as a record
    is carried through as bytes rather than dropped.
    """
    body, padding = payload[:size], payload[size:]
    records, remainder = split_pax_records(body)
    out = bytearray()
    for record in records:
        key = pax_record_key(record)
        if key.decode("utf-8", "replace") in _PAX_TIME_KEYS:
            out += _framed(b"clock", key)
        else:
            out += _framed(b"record", record)
    out += _framed(b"unframed", remainder)
    out += _framed(b"padding", padding.rstrip(b"\0"))
    return bytes(out)


def normalized_tar(tar_bytes: bytes) -> bytes:
    """The tar stream with every timestamp, and only those, taken out of it.

    Every block of the archive is carried through as the 512 raw bytes the
    writer wrote, header and payload alike -- name, mode, owner, group, size,
    type flag, link target, magic, user and group names, device numbers,
    ``ustar`` prefix, the twelve bytes at the end of the block that nothing
    uses, the member's complete payload, the zero padding to the next boundary,
    the end-of-archive marker and whatever follows it.  A PAX extended header
    is one of those blocks and is treated as one: it is not summarised and it
    is not dropped, which is what it used to be.

    Four things cannot be carried through, and each is replaced by a rendering
    that keeps everything about it except the clock:

    * a header's ``mtime`` field -- its digits go, its terminator stays;
    * an extended header's declared ``size`` -- the same, because that size is
      the byte length of a record whose value is a decimal timestamp;
    * a header's ``checksum`` -- replaced by the difference between the number
      recorded and the number the block's bytes produce, which is zero for any
      block a writer wrote and is not a clock;
    * a PAX time record's value and terminator, and the padding length behind
      the records that the value's length decides.

    Nothing else is excluded.  :class:`TheNormalisationReadsEveryByteButTheClock`
    establishes that as an equality by moving every byte of an archive one at a
    time, so this docstring is a description of a tested property rather than a
    promise about one.
    """
    out = bytearray()
    offset = 0
    while offset + _TAR_BLOCK <= len(tar_bytes):
        header = tar_bytes[offset:offset + _TAR_BLOCK]
        if not any(header):  # end-of-archive: the rest is padding, kept as is
            out += _framed(b"end", tar_bytes[offset:])
            return bytes(out)
        size = _member_size(header)
        blocks = -(-size // _TAR_BLOCK)
        payload = tar_bytes[offset + _TAR_BLOCK:
                            offset + _TAR_BLOCK * (1 + blocks)]
        extended = header[_TAR_TYPE] in _PAX_TYPES
        block = bytearray(header)
        block[_TAR_MTIME] = _MTIME_ELIDED
        block[_TAR_CHECKSUM] = _CHECKSUM_ELIDED
        if extended:
            block[_TAR_SIZE] = _SIZE_ELIDED
        out += _framed(b"block", bytes(block))
        out += _framed(b"mtime", _digits_elided(bytes(header[_TAR_MTIME]),
                                                b"<mtime>"))
        out += _framed(b"checksum", canonical_checksum(header))
        if extended:
            out += _framed(b"size", _digits_elided(bytes(header[_TAR_SIZE]),
                                                   b"<size>"))
            out += canonical_pax_payload(payload, size)
        else:
            out += _framed(b"payload", payload)
        offset += _TAR_BLOCK * (1 + blocks)
    out += _framed(b"tail", tar_bytes[offset:])
    return bytes(out)


def pax_header_blocks(tar_bytes: bytes) -> list[dict]:
    """Every PAX extended header *block*, read as the ``ustar`` header it is.

    ``tarfile`` never shows these to a caller: it reads the records, folds them
    into the member that follows, and drops the block.  So an sdist inspected
    through ``tarfile`` alone has 512 bytes per extended header that nothing
    looked at -- a name, a mode, an owner, a magic, a prefix and a padding that
    the writer chose and that a released artefact carries.  They are read here
    from the bytes, with the clock left out, so that two builds compare equal
    and so that the values themselves can be asserted rather than assumed.
    """
    def text(field: bytes) -> str:
        return field.split(b"\0")[0].decode("utf-8", "replace")

    found: list[dict] = []
    for position, (offset, header, size) in enumerate(tar_blocks(tar_bytes)):
        if header[_TAR_TYPE] not in _PAX_TYPES:
            continue
        payload = tar_bytes[offset + _TAR_BLOCK:
                            offset + _TAR_BLOCK * (1 + -(-size // _TAR_BLOCK))]
        records, remainder = split_pax_records(payload[:size])
        found.append({
            "position": position,
            "name": text(header[_TAR_NAME]),
            "mode": text(header[_TAR_MODE]),
            "uid": text(header[_TAR_UID]),
            "gid": text(header[_TAR_GID]),
            "mtime": text(header[_TAR_MTIME]),
            "checksum_delta": (
                int(header[_TAR_CHECKSUM].split(b"\0")[0].strip() or b"-1", 8)
                - header_checksum(header)),
            "type": header[_TAR_TYPE].decode("ascii", "replace"),
            "linkname": text(header[_TAR_LINKNAME]),
            "magic": header[_TAR_MAGIC].decode("latin-1"),
            "uname": text(header[_TAR_UNAME]),
            "gname": text(header[_TAR_GNAME]),
            "devmajor": header[_TAR_DEVMAJOR].decode("latin-1"),
            "devminor": header[_TAR_DEVMINOR].decode("latin-1"),
            "prefix": text(header[_TAR_PREFIX]),
            "unused": header[_TAR_UNUSED].decode("latin-1"),
            "keys": [pax_record_key(record).decode("utf-8", "replace")
                     for record in records],
            # The clock's value is left out; every other record is kept whole.
            "non_clock_records": [
                record.decode("utf-8", "replace") for record in records
                if pax_record_key(record).decode("utf-8", "replace")
                not in _PAX_TIME_KEYS],
            "unframed_bytes": len(remainder),
            "padding_is_zero": not payload[size:].strip(b"\0"),
        })
    return found


def tar_pax_keys(tar_bytes: bytes) -> set[str]:
    """Every PAX record key the archive uses, so the set can be asserted."""
    keys: set[str] = set()
    offset = 0
    while offset + _TAR_BLOCK <= len(tar_bytes):
        header = tar_bytes[offset:offset + _TAR_BLOCK]
        if not any(header):
            break
        size = _member_size(header)
        blocks = (size + _TAR_BLOCK - 1) // _TAR_BLOCK
        if header[156:157] in _PAX_TYPES:
            payload = tar_bytes[offset + _TAR_BLOCK:offset + _TAR_BLOCK + size]
            keys |= {key for key, _value in pax_records(payload)}
        offset += _TAR_BLOCK * (1 + blocks)
    return keys


# -- the control, and the mutations that separate it from the real thing -----
def discarded_pax_normalisation(tar_bytes: bytes) -> bytes:
    """The normalisation this module used to perform, kept as the control.

    It blanked a ``ustar`` header's mtime and checksum in place and replaced a
    PAX extended header -- the whole 512-byte block *and* its whole payload --
    with a rendering of the records that were not a clock.  Since the only
    record ``setuptools`` writes is a clock, that rendering was the constant
    ``PAXx[]``: the extended header's name, mode, ownership, magic, declared
    size, checksum, link and prefix fields, its payload's block padding and
    every other byte of it were compared against nothing at all.  The header's
    own checksum was dropped from a ``ustar`` block too, so a checksum that
    stopped covering its header was invisible there as well.

    :data:`MUTATIONS` records, for every byte this function could not see, that
    it cannot see it -- so the replacement below is a strengthening that is
    demonstrated rather than a restatement that is asserted.
    """
    out = bytearray()
    offset = 0
    while offset + _TAR_BLOCK <= len(tar_bytes):
        header = bytearray(tar_bytes[offset:offset + _TAR_BLOCK])
        if not any(header):
            out += tar_bytes[offset:]
            return bytes(out)
        size = _member_size(header)
        blocks = (size + _TAR_BLOCK - 1) // _TAR_BLOCK
        payload = tar_bytes[offset + _TAR_BLOCK:
                            offset + _TAR_BLOCK * (1 + blocks)]
        if bytes(header[_TAR_TYPE]) in _PAX_TYPES:
            kept = [record for record in pax_records(payload[:size])
                    if record[0] not in _PAX_TIME_KEYS]
            out += b"PAX" + bytes(header[_TAR_TYPE]) + repr(kept).encode("utf-8")
        else:
            header[_TAR_MTIME] = b"0" * 12
            header[_TAR_CHECKSUM] = b" " * 8
            out += bytes(header) + payload
        offset += _TAR_BLOCK * (1 + blocks)
    return bytes(out)


#: A tar/PAX archive written here rather than by a backend, so that every byte
#: a real sdist carries has a counterpart that a test is free to move.  It
#: holds a directory and a symlink -- ``ustar`` members with a whole-second
#: mtime, so neither gets an extended header -- and one regular file whose
#: fractional mtime forces a PAX header that carries a non-clock record beside
#: the clock, which is the shape the assertions below need and the shape a real
#: sdist would have the moment ``setuptools`` recorded anything but a time.
SYNTHETIC_PAYLOAD = b"the payload of one member, shorter than a block\n"


def synthetic_pax_tar(*, comment: str = "aaa") -> bytes:
    """An uncompressed tar stream in :data:`tarfile.PAX_FORMAT`."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w",
                      format=tarfile.PAX_FORMAT) as archive:
        directory = tarfile.TarInfo("root")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.mtime = EPOCH
        archive.addfile(directory)

        member = tarfile.TarInfo("root/file.txt")
        member.size = len(SYNTHETIC_PAYLOAD)
        member.mode = 0o644
        member.mtime = EPOCH + 0.5  # fractional: this is what forces a PAX header
        member.uid, member.gid = 501, 20
        member.uname, member.gname = "builder", "staff"
        member.pax_headers = {"comment": comment}
        archive.addfile(member, io.BytesIO(SYNTHETIC_PAYLOAD))

        link = tarfile.TarInfo("root/link.txt")
        link.type = tarfile.SYMTYPE
        link.linkname = "file.txt"
        link.mtime = EPOCH
        archive.addfile(link)
    return buffer.getvalue()


def tar_blocks(tar_bytes: bytes) -> list[tuple[int, bytes, int]]:
    """``(offset, header, declared size)`` for each header block, in order."""
    found: list[tuple[int, bytes, int]] = []
    offset = 0
    while offset + _TAR_BLOCK <= len(tar_bytes):
        header = tar_bytes[offset:offset + _TAR_BLOCK]
        if not any(header):
            break
        size = _member_size(header)
        found.append((offset, header, size))
        offset += _TAR_BLOCK * (1 + (size + _TAR_BLOCK - 1) // _TAR_BLOCK)
    return found


def find_block(tar_bytes: bytes, *, pax: bool,
               index: int = 0) -> tuple[int, bytes, int]:
    """The ``index``-th extended header block, or the ``index``-th member."""
    return [item for item in tar_blocks(tar_bytes)
            if (item[1][_TAR_TYPE] in _PAX_TYPES) is pax][index]


def patched(tar_bytes: bytes, offset: int, replacement: bytes) -> bytes:
    """``tar_bytes`` with ``replacement`` written over it at ``offset``."""
    return (tar_bytes[:offset] + replacement
            + tar_bytes[offset + len(replacement):])


def _field(field: slice, value: bytes, *, pax: bool, index: int = 0):
    """Overwrite one header field, in place and to its exact width."""
    width = field.stop - field.start

    def mutate(tar_bytes: bytes) -> bytes:
        offset, _header, _size = find_block(tar_bytes, pax=pax, index=index)
        return patched(tar_bytes, offset + field.start,
                       value.ljust(width, b"\0")[:width])
    return mutate


def _checksum_field(*, pax: bool, index: int = 0):
    """Move the recorded checksum and nothing else, so it stops covering."""
    def mutate(tar_bytes: bytes) -> bytes:
        offset, header, _size = find_block(tar_bytes, pax=pax, index=index)
        stated = int(header[_TAR_CHECKSUM].split(b"\0")[0].strip() or b"0", 8)
        return patched(tar_bytes, offset + _TAR_CHECKSUM.start,
                       b"%06o\0 " % ((stated + 1) % 0o1000000))
    return mutate


def _pax_payload_padding(tar_bytes: bytes) -> bytes:
    """One byte of the zero padding that follows an extended header's records."""
    offset, _header, size = find_block(tar_bytes, pax=True)
    return patched(tar_bytes, offset + _TAR_BLOCK + size, b"\xff")


def _pax_record_value(tar_bytes: bytes) -> bytes:
    """The value of the extended header's one non-clock record, same width."""
    offset, _header, size = find_block(tar_bytes, pax=True)
    body = tar_bytes[offset + _TAR_BLOCK:offset + _TAR_BLOCK + size]
    at = body.index(b"comment=") + len(b"comment=")
    return patched(tar_bytes, offset + _TAR_BLOCK + at, b"b")


def _member_payload(tar_bytes: bytes) -> bytes:
    offset, _header, _size = find_block(tar_bytes, pax=False, index=1)
    return patched(tar_bytes, offset + _TAR_BLOCK, b"T")


def _member_payload_padding(tar_bytes: bytes) -> bytes:
    offset, _header, size = find_block(tar_bytes, pax=False, index=1)
    return patched(tar_bytes, offset + _TAR_BLOCK + size, b"\xff")


def _end_of_archive(tar_bytes: bytes) -> bytes:
    """A byte of the trailing padding, past the end-of-archive marker."""
    return patched(tar_bytes, len(tar_bytes) - 1, b"\xff")


#: Every mutation, and whether :func:`discarded_pax_normalisation` could see
#: it.  ``False`` is the blind spot this repair closes: each of those moves a
#: byte the extended header genuinely carried, leaves every timestamp's meaning
#: alone, and produced an identical "normalised" digest before.
MUTATIONS: dict[str, tuple[object, bool]] = {
    "the extended header's name": (
        _field(_TAR_NAME, b"././@PaxHeadeR", pax=True), False),
    "the extended header's mode": (
        _field(_TAR_MODE, b"0000644\0", pax=True), False),
    "the extended header's uid": (
        _field(_TAR_UID, b"0001750\0", pax=True), False),
    "the extended header's gid": (
        _field(_TAR_GID, b"0001750\0", pax=True), False),
    "the extended header's declared size": (
        _field(_TAR_SIZE, b"00000000037\0", pax=True), False),
    "the extended header's checksum": (_checksum_field(pax=True), False),
    "the extended header's linkname": (
        _field(_TAR_LINKNAME, b"elsewhere", pax=True), False),
    "the extended header's magic": (
        _field(_TAR_MAGIC, b"ustar  \0", pax=True), False),
    "the extended header's uname": (
        _field(_TAR_UNAME, b"root", pax=True), False),
    "the extended header's gname": (
        _field(_TAR_GNAME, b"wheel", pax=True), False),
    "the extended header's devmajor": (
        _field(_TAR_DEVMAJOR, b"0000003\0", pax=True), False),
    "the extended header's devminor": (
        _field(_TAR_DEVMINOR, b"0000004\0", pax=True), False),
    "the extended header's prefix": (
        _field(_TAR_PREFIX, b"somewhere", pax=True), False),
    "the extended header's trailing bytes": (
        _field(_TAR_UNUSED, b"\x01", pax=True), False),
    "the padding after the extended header's records": (
        _pax_payload_padding, False),
    "a member header's checksum": (_checksum_field(pax=False, index=1), False),
    "the extended header's type flag": (
        _field(_TAR_TYPE, b"g", pax=True), True),
    "a non-clock record's value": (_pax_record_value, True),
    "a member's name": (
        _field(_TAR_NAME, b"root/other.txt", pax=False, index=1), True),
    "a member's mode": (
        _field(_TAR_MODE, b"0000600\0", pax=False, index=1), True),
    "a member's uid": (
        _field(_TAR_UID, b"0001750\0", pax=False, index=1), True),
    "a member's gid": (
        _field(_TAR_GID, b"0001750\0", pax=False, index=1), True),
    "a member's uname": (
        _field(_TAR_UNAME, b"root", pax=False, index=1), True),
    "a member's type flag": (
        _field(_TAR_TYPE, b"7", pax=False, index=1), True),
    "a member's linkname": (
        _field(_TAR_LINKNAME, b"other.txt", pax=False, index=2), True),
    "a member's payload": (_member_payload, True),
    "the padding after a member's payload": (_member_payload_padding, True),
    "the padding past the end-of-archive marker": (_end_of_archive, True),
}


def _pax_record(key: str, value: str) -> bytes:
    """One ``length key=value\\n`` record, with the length its own length says.

    The length prefix counts itself, so it is a fixed point rather than a
    number that can be computed in one step: a record that grows past ten,
    a hundred or a thousand bytes grows its own prefix with it.
    """
    body = f"{key}={value}\n".encode("utf-8")
    length = len(body) + 2
    while len(str(length)) + 1 + len(body) != length:
        length = len(str(length)) + 1 + len(body)
    return f"{length} ".encode("ascii") + body


def reclocked(tar_bytes: bytes, *, mtime: int, pax_mtime: str) -> bytes:
    """The archive a writer with a different clock would have produced.

    Every ``ustar`` mtime field, every PAX time record, and every field those
    two decide -- the record's own length prefix, the extended header's
    declared size, the zero padding that follows the records, and both
    checksums -- is rewritten consistently.  Nothing else moves.

    This is the other half of :data:`MUTATIONS`: an archive and its reclocking
    differ in exactly the bytes the normalisation is allowed to drop, so
    "identical after normalisation" is asserted for a real clock change and not
    only for the two builds, which could agree by being the same second.
    """
    out = bytearray()
    offset = 0
    while offset + _TAR_BLOCK <= len(tar_bytes):
        header = bytearray(tar_bytes[offset:offset + _TAR_BLOCK])
        if not any(header):
            out += tar_bytes[offset:]
            return bytes(out)
        size = _member_size(header)
        blocks = (size + _TAR_BLOCK - 1) // _TAR_BLOCK
        payload = tar_bytes[offset + _TAR_BLOCK:
                            offset + _TAR_BLOCK * (1 + blocks)]
        if bytes(header[_TAR_TYPE]) in _PAX_TYPES:
            body = bytearray()
            for raw in split_pax_records(payload[:size])[0]:
                key = pax_record_key(raw).decode("ascii", "replace")
                body += (_pax_record(key, pax_mtime)
                         if key in _PAX_TIME_KEYS else raw)
            if -(-len(body) // _TAR_BLOCK) != blocks:
                raise ValueError("the reclocking changed the block count")
            header[_TAR_SIZE] = b"%011o\0" % len(body)
            payload = bytes(body).ljust(_TAR_BLOCK * blocks, b"\0")
        else:
            header[_TAR_MTIME] = b"%011o\0" % mtime
        header[_TAR_CHECKSUM] = b"%06o\0 " % header_checksum(bytes(header))
        out += bytes(header) + payload
        offset += _TAR_BLOCK * (1 + blocks)
    out += tar_bytes[offset:]
    return bytes(out)


def gzip_frame(raw: bytes) -> bytes:
    """The gzip framing minus the four bytes RFC 1952 calls MTIME.

    Magic, compression method, flags, extra flags and operating system, plus
    the NUL-terminated original filename when the FNAME flag says one is there.
    Compared as bytes so that a change of compression level, of writer, or of
    the recorded name is a failure rather than a difference nobody looked at.
    """
    header = raw[:4] + raw[8:10]
    if raw[3] & 0x08:  # FNAME
        end = raw.index(b"\0", 10)
        header += raw[10:end + 1]
    return header


def read_sdist(path: Path) -> dict:
    """An sdist decomposed into the parts a reproducibility claim is about.

    ``normalized`` is the headline: a SHA-256 over every byte of the
    uncompressed archive with only the timestamps' own digits neutralised, as
    :func:`normalized_tar` describes exactly.  ``content`` is the same claim
    made member by member, so that a failure says *which* member moved rather
    than only that the file did, and ``pax_blocks`` is the part of the archive
    ``tarfile`` does not surface at all.  The timestamps themselves are kept in
    ``mtimes`` and ``gzip_mtime`` and asserted as themselves, rather than
    dropped.
    """
    raw = Path(path).read_bytes()
    tar_bytes = gzip.decompress(raw)
    order: list[str] = []
    members: dict[str, dict] = {}
    mtimes: dict[str, int] = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as archive:
        for info in archive.getmembers():
            order.append(info.name)
            payload = b""
            if info.isfile():
                handle = archive.extractfile(info)
                payload = handle.read() if handle is not None else b""
            members[info.name] = {
                "type": info.type.decode("ascii"),
                "mode": info.mode,
                "uid": info.uid,
                "gid": info.gid,
                "uname": info.uname,
                "gname": info.gname,
                "size": info.size,
                "linkname": info.linkname,
                "devmajor": info.devmajor,
                "devminor": info.devminor,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            mtimes[info.name] = int(info.mtime)
    canonical = json.dumps({"order": order, "members": members},
                           sort_keys=True).encode("utf-8")
    neutralised = normalized_tar(tar_bytes)
    return {
        "path": Path(path),
        "order": tuple(order),
        "members": members,
        "mtimes": mtimes,
        "content": hashlib.sha256(canonical).hexdigest(),
        "normalized": hashlib.sha256(neutralised).hexdigest(),
        "normalized_bytes": neutralised,
        "pax_keys": tar_pax_keys(tar_bytes),
        "pax_blocks": pax_header_blocks(tar_bytes),
        "tar_length": len(tar_bytes),
        "tar_sha256": hashlib.sha256(tar_bytes).hexdigest(),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
        "gzip_mtime": int.from_bytes(raw[4:8], "little"),
        "gzip_frame": gzip_frame(raw),
    }


# -- the fixture -------------------------------------------------------------
_STATE: dict = {}


def prepared() -> dict:
    """Build everything once per interpreter, and remember the outcome.

    Six builds and two environments is the whole cost of this module, and it is
    paid once: every class below reads this dictionary.
    """
    if _STATE:
        return _STATE
    workspace = tempfile.TemporaryDirectory(prefix="admissible-umbrella-pep517-")
    atexit.register(workspace.cleanup)
    root = Path(workspace.name)
    _STATE["workspace"] = root
    _STATE["error"] = None
    try:
        wheelhouse = root / "wheelhouse"
        _STATE["backend_wheels"] = populate_wheelhouse(wheelhouse)
        _STATE["wheelhouse"] = wheelhouse
        first = create_isolated_environment(root / "env-a", wheelhouse)
        second = create_isolated_environment(root / "env-b", wheelhouse)
        _STATE["first"] = first
        _STATE["second"] = second

        for label, environment in (("a", first), ("b", second)):
            for kind in ("wheel", "sdist"):
                source = clean_copy(root / f"src-{kind}-{label}")
                path, report = pep517(environment, source,
                                      root / f"out-{label}", kind)
                _STATE[f"{kind}_{label}"] = path
                _STATE[f"{kind}_{label}_report"] = report

        # A wheel from the sdist, built in the first environment: the archive a
        # user downloads must produce the archive a user installs.
        unpacked = root / "unpacked"
        unpacked.mkdir(parents=True, exist_ok=True)
        with tarfile.open(_STATE["sdist_a"]) as archive:
            archive.extractall(unpacked, filter="data")
        roots = [item for item in unpacked.iterdir() if item.is_dir()]
        if len(roots) != 1:
            raise PreparationError(f"expected one sdist root, got {roots}")
        _STATE["sdist_root"] = roots[0]
        _STATE["wheel_from_sdist"], _ = pep517(
            first, roots[0], root / "out-from-sdist", "wheel")

        # The same build again, with the parent shell holding a PYTHONPATH that
        # would break it if it leaked.
        poison = poison_directory(root / "poison")
        _STATE["poison"] = poison
        source = clean_copy(root / "src-wheel-poisoned")
        with mock.patch.dict(os.environ, {"PYTHONPATH": str(poison)}):
            _STATE["wheel_poisoned"], _STATE["poisoned_report"] = pep517(
                first, source, root / "out-poisoned", "wheel")
            _STATE["poisoned_environment"] = build_environment()

        completed = subprocess.run(
            [str(first["interpreter"]), "-c", _IMPORT_PROBE, *CHECKOUT_PACKAGES],
            capture_output=True, text=True, cwd=str(first["root"]),
            timeout=inspect_wheel.RUN_TIMEOUT, env=build_environment())
        if completed.returncode != 0:
            raise PreparationError(
                f"the import probe failed: {completed.stderr[-2000:]}")
        _STATE["importable"] = json.loads(completed.stdout)

        completed = subprocess.run(
            [str(first["interpreter"]), "-m", "pip", "list", "--format=json",
             "--disable-pip-version-check"],
            capture_output=True, text=True, cwd=str(first["root"]),
            timeout=inspect_wheel.RUN_TIMEOUT, env=build_environment())
        if completed.returncode != 0:
            raise PreparationError(
                f"listing the isolated environment failed: {completed.stderr[-2000:]}")
        _STATE["installed"] = {
            inspect_wheel.normalize_name(item["name"]): item["version"]
            for item in json.loads(completed.stdout)}
    except (PreparationError, inspect_wheel.WheelError, OSError,
            subprocess.SubprocessError, tarfile.TarError,
            json.JSONDecodeError) as error:
        _STATE["error"] = f"{type(error).__name__}: {error}"
    return _STATE


class PreparedCase(unittest.TestCase):
    """Every class here fails with the preparation's reason.  None skips."""

    @classmethod
    def setUpClass(cls):
        cls.state = prepared()

    def prepared(self) -> dict:
        if self.state["error"]:
            self.fail(self.state["error"])
        return self.state


class TheBackendPinIsExact(unittest.TestCase):
    """A range is a different artefact on every machine that resolves it."""

    def setUp(self):
        self.section = build_system()

    def test_the_backend_is_the_one_this_project_names(self):
        self.assertEqual(BUILD_BACKEND, self.section.get("build-backend"))

    def test_the_requirements_are_exactly_the_pinned_backend(self):
        self.assertEqual(EXPECTED_BUILD_REQUIRES,
                         list(self.section.get("requires", [])))

    def test_no_requirement_carries_a_range_operator(self):
        for requirement in self.section.get("requires", []):
            with self.subTest(requirement=requirement):
                for operator in RANGE_OPERATORS:
                    self.assertNotIn(
                        operator, requirement,
                        f"'{operator}' lets the build resolve more than one "
                        "backend, so the artefact is not a function of this "
                        "checkout")

    def test_every_requirement_pins_one_version_with_a_single_clause(self):
        for requirement in self.section.get("requires", []):
            with self.subTest(requirement=requirement):
                self.assertNotIn(",", requirement, "one clause, not a set")
                self.assertNotIn("*", requirement, "a wildcard is a range")
                name, separator, version = requirement.partition("==")
                self.assertEqual("==", separator,
                                 "a requirement with no '==' floats")
                self.assertTrue(name.strip())
                self.assertTrue(version.strip())
                self.assertNotIn("=", version)

    def test_the_pinned_backend_is_not_the_range_this_replaces(self):
        text = (UMBRELLA_PROJECT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertNotIn("setuptools>=", text)
        self.assertIn(BACKEND_REQUIREMENT, text)

    def test_the_wheel_writer_is_not_declared_unless_the_backend_wants_it(self):
        """``wheel`` is vendored by this backend; a second copy is a second
        writer, and which one runs would be an installation-order question."""
        names = [requirement.partition("==")[0].strip()
                 for requirement in self.section.get("requires", [])]
        self.assertNotIn("wheel", names)

    def test_the_project_floor_is_unchanged(self):
        document = tomllib.loads(
            (UMBRELLA_PROJECT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(REQUIRES_PYTHON,
                         document["project"]["requires-python"])

    def test_the_runtime_dependencies_are_untouched_by_the_pin(self):
        """The backend is a build-time fact.  It must not become a run-time one."""
        document = tomllib.loads(
            (UMBRELLA_PROJECT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(
            [f"admissible-core=={VERSION}", f"admissible-ready=={VERSION}",
             f"admissible-trust=={VERSION}"],
            list(document["project"]["dependencies"]))
        self.assertNotIn(BACKEND_DISTRIBUTION,
                         " ".join(document["project"]["dependencies"]))


class TheWheelhouseHoldsThePinnedBackend(PreparedCase):
    """Local, verified by its own metadata, and never skipped when absent."""

    def backend(self) -> Path:
        wheels = self.prepared()["backend_wheels"]
        self.assertEqual(1, len(wheels), "one declared requirement, one wheel")
        return wheels[0]

    def test_a_wheel_for_the_pin_was_found_on_this_machine(self):
        self.assertTrue(self.backend().is_file())
        self.assertEqual(BACKEND_WHEEL, self.backend().name)

    def test_the_wheelhouse_holds_exactly_the_declared_requirements(self):
        state = self.prepared()
        self.assertEqual([BACKEND_WHEEL],
                         sorted(path.name
                                for path in state["wheelhouse"].iterdir()))

    def test_the_declaration_names_one_release_per_requirement(self):
        self.prepared()
        self.assertEqual([(BACKEND_DISTRIBUTION, BACKEND_VERSION)],
                         declared_requirements())

    def test_the_archive_metadata_says_what_the_filename_says(self):
        metadata = wheel_metadata(self.backend())
        self.assertEqual(BACKEND_DISTRIBUTION, metadata["Name"])
        self.assertEqual(BACKEND_VERSION, metadata["Version"])

    def test_the_pinned_backend_supports_this_project_s_python_floor(self):
        """A pin the declared floor cannot install is a build that fails on the
        oldest interpreter this project promises and nowhere else."""
        self.assertEqual(REQUIRES_PYTHON,
                         wheel_metadata(self.backend())["Requires-Python"])

    def test_the_pinned_backend_installs_without_a_compiler(self):
        self.assertTrue(self.backend().name.endswith("-py3-none-any.whl"))

    def test_the_install_asked_for_the_pin_and_nothing_looser(self):
        self.assertEqual([BACKEND_REQUIREMENT],
                         self.prepared()["first"]["requirements"])

    def test_the_install_reached_the_wheelhouse_and_no_index(self):
        log = self.prepared()["first"]["install_log"]
        self.assertIn("Looking in links", log)
        self.assertIn(BACKEND_WHEEL, log)
        for forbidden in ("Downloading", "https://", "pypi.org"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, log)


class TheIsolatedEnvironmentIsOnlyTheBackend(PreparedCase):
    """What is installed is the pin, and the checkout is not reachable."""

    def test_the_environment_holds_the_pinned_backend_exactly(self):
        installed = self.prepared()["installed"]
        self.assertEqual(BACKEND_VERSION, installed.get(BACKEND_DISTRIBUTION))

    def test_nothing_else_that_builds_is_installed(self):
        """``pip`` comes from ``ensurepip`` and is how the pin got here; a
        second build-time distribution would be one this pin does not name."""
        installed = dict(self.prepared()["installed"])
        installed.pop("pip", None)
        self.assertEqual({BACKEND_DISTRIBUTION: BACKEND_VERSION}, installed)

    def test_the_backend_the_build_imported_is_the_pinned_one(self):
        for label in ("a", "b"):
            with self.subTest(environment=label):
                self.assertEqual(
                    BACKEND_VERSION,
                    self.prepared()[f"wheel_{label}_report"]["setuptools"])

    def test_the_build_ran_under_the_environment_s_own_interpreter(self):
        state = self.prepared()
        for label, key in (("a", "first"), ("b", "second")):
            with self.subTest(environment=label):
                report = state[f"wheel_{label}_report"]
                self.assertEqual(str(state[key]["root"].resolve()),
                                 str(Path(report["prefix"]).resolve()))

    def test_no_checkout_package_is_importable_in_the_build_environment(self):
        found = self.prepared()["importable"]
        self.assertEqual({name: False for name in CHECKOUT_PACKAGES}, found)

    def test_no_import_path_entry_lies_inside_the_checkout(self):
        state = self.prepared()
        root = str(REPO_ROOT.resolve())
        for label in ("a", "b"):
            for kind in ("wheel", "sdist"):
                report = state[f"{kind}_{label}_report"]
                with self.subTest(environment=label, kind=kind):
                    inside = [entry for entry in report["sys_path"]
                              if entry == root or entry.startswith(f"{root}/")]
                    self.assertEqual([], inside)
                    self.assertFalse(report["cwd"].startswith(f"{root}/"))

    def test_the_build_saw_no_inherited_pythonpath(self):
        state = self.prepared()
        for label in ("a", "b"):
            with self.subTest(environment=label):
                self.assertIsNone(state[f"wheel_{label}_report"]["pythonpath"])

    def test_the_build_saw_the_pinned_clock(self):
        state = self.prepared()
        for label in ("a", "b"):
            with self.subTest(environment=label):
                self.assertEqual(
                    inspect_wheel.SOURCE_DATE_EPOCH,
                    state[f"wheel_{label}_report"]["source_date_epoch"])


class TheBackendNeedsNothingFurther(PreparedCase):
    """``get_requires_for_build_*`` is what decides whether the pin is complete."""

    def test_the_backend_asks_for_no_further_requirement(self):
        state = self.prepared()
        for label in ("a", "b"):
            for kind in ("wheel", "sdist"):
                with self.subTest(environment=label, kind=kind):
                    report = state[f"{kind}_{label}_report"]
                    self.assertEqual([], report["requires_wheel"])
                    self.assertEqual([], report["requires_sdist"])

    def test_nothing_the_backend_asks_for_is_missing_from_the_pin(self):
        """The pin is complete only if the backend wants nothing beyond it.

        A dynamic requirement that is not in ``[build-system].requires`` is one
        pip would fetch from an index at build time, which is the floating
        backend problem again, one level down.
        """
        state = self.prepared()
        declared = {requirement.partition("==")[0].strip()
                    for requirement in EXPECTED_BUILD_REQUIRES}
        asked = set()
        for label in ("a", "b"):
            for kind in ("wheel", "sdist"):
                report = state[f"{kind}_{label}_report"]
                asked |= {name.split("=")[0].split(">")[0].split("<")[0].strip()
                          for name in (report["requires_wheel"]
                                       + report["requires_sdist"])}
        self.assertEqual(set(), asked - declared)


class TheWheelIsByteIdenticalTwice(PreparedCase):
    """The claim the whole module exists for, made over complete bytes."""

    def test_two_isolated_builds_produce_the_same_wheel_filename(self):
        state = self.prepared()
        self.assertEqual(state["wheel_a"].name, state["wheel_b"].name)
        self.assertEqual(f"{DISTRIBUTION}-{VERSION}-py3-none-any.whl",
                         state["wheel_a"].name)

    def test_two_isolated_builds_produce_the_same_wheel_bytes(self):
        state = self.prepared()
        self.assertEqual(digest(state["wheel_a"]), digest(state["wheel_b"]),
                         "the wheel is not a function of this checkout alone")

    def test_the_digest_is_a_digest_of_a_non_empty_archive(self):
        state = self.prepared()
        self.assertGreater(state["wheel_a"].stat().st_size, 0)
        self.assertEqual(64, len(digest(state["wheel_a"])))

    def test_the_wheel_built_from_the_sdist_is_the_same_bytes(self):
        """What a user downloads must produce what a user installs."""
        state = self.prepared()
        self.assertEqual(digest(state["wheel_a"]),
                         digest(state["wheel_from_sdist"]))

    def test_a_poisoned_parent_pythonpath_changes_nothing(self):
        state = self.prepared()
        self.assertEqual(digest(state["wheel_a"]),
                         digest(state["wheel_poisoned"]))

    def test_the_poisoned_build_never_saw_the_poison(self):
        state = self.prepared()
        self.assertIsNone(state["poisoned_report"]["pythonpath"])
        self.assertNotIn("PYTHONPATH", state["poisoned_environment"])
        self.assertNotIn(str(state["poison"]),
                         " ".join(state["poisoned_report"]["sys_path"]))

    def test_the_poison_would_have_been_fatal_had_it_arrived(self):
        """The control for the test above: this fixture is not inert."""
        state = self.prepared()
        self.assertTrue((state["poison"] / "setuptools.py").is_file())
        self.assertIn("raise RuntimeError",
                      (state["poison"] / "setuptools.py").read_text(
                          encoding="utf-8"))


class TheWheelArchiveHoldsTheDispatcherAlone(PreparedCase):
    """The bytes repeat; this says which bytes they are."""

    def wheel(self) -> inspect_wheel.Wheel:
        return inspect_wheel.inspect_wheel(self.prepared()["wheel_a"])

    def test_the_payload_is_the_compatibility_namespace(self):
        self.assertEqual({DISTRIBUTION}, self.wheel().top_level)

    def test_the_archive_holds_every_checked_in_module_and_no_other(self):
        wheel = self.wheel()
        self.assertEqual(
            sorted(f"{DISTRIBUTION}/{name}" for name in SOURCE_MODULES),
            sorted(wheel.installed_paths))

    def test_each_shipped_module_is_the_checked_in_bytes(self):
        wheel = self.wheel()
        for path in sorted(UMBRELLA_PACKAGE.rglob("*.py")):
            member = f"{DISTRIBUTION}/{path.name}"
            with self.subTest(member=member):
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    wheel.sha256(member))

    def test_no_byte_code_or_cache_rides_along(self):
        strays = sorted(member for member in self.wheel().members
                        if member.endswith(".pyc") or "__pycache__" in member)
        self.assertEqual([], strays)

    def test_the_metadata_the_pin_produced_is_the_declared_one(self):
        wheel = self.wheel()
        self.assertEqual(DISTRIBUTION, wheel.name)
        self.assertEqual(VERSION, wheel.version)
        self.assertEqual(REQUIRES_PYTHON, wheel.requires_python)
        self.assertEqual({DISTRIBUTION: f"{DISTRIBUTION}.cli:main"},
                         wheel.console_scripts)

    def test_the_generator_recorded_in_the_archive_is_the_pinned_backend(self):
        """The wheel says which backend wrote it; a drifted pin shows up here
        before it shows up as a digest that stopped matching."""
        with zipfile.ZipFile(self.prepared()["wheel_a"]) as archive:
            text = archive.read(
                f"{DISTRIBUTION}-{VERSION}.dist-info/WHEEL").decode("utf-8")
        self.assertIn(f"Generator: setuptools ({BACKEND_VERSION})", text)


class TheSdistContentIsByteIdenticalTwice(PreparedCase):
    """Complete byte equality, plus the fields the backend will not pin.

    See the module docstring: ``setuptools`` reads ``SOURCE_DATE_EPOCH`` in its
    wheel writer and nowhere in its sdist writer, at every version.  So the
    archive is compared as bytes with the timestamps removed, and the
    timestamps are then compared as themselves against an exact partition of
    the members, rather than the assertion being softened to a list of names.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.first = cls.second = None
        if cls.state["error"]:
            return
        cls.first = read_sdist(cls.state["sdist_a"])
        cls.second = read_sdist(cls.state["sdist_b"])

    def sdists(self) -> tuple[dict, dict]:
        self.prepared()
        return self.first, self.second

    def test_two_isolated_builds_produce_the_same_sdist_filename(self):
        state = self.prepared()
        self.assertEqual(f"{DISTRIBUTION}-{VERSION}.tar.gz",
                         state["sdist_a"].name)
        self.assertEqual(state["sdist_a"].name, state["sdist_b"].name)

    def test_the_complete_archive_bytes_are_identical_but_for_the_timestamps(self):
        """The headline claim, made over the file and not over a summary.

        Every byte of the uncompressed archive is in this digest except the
        digits of a timestamp and the two fields whose value those digits
        decide.  Names, modes, ownership, sizes, type flags, link targets,
        device numbers, every payload byte, the block padding, the
        end-of-archive marker and every byte of every PAX extended header
        block are all inside it, and
        :meth:`test_no_non_clock_mutation_of_the_built_archive_survives` moves
        each of them to prove it.
        """
        first, second = self.sdists()
        self.assertEqual(first["normalized"], second["normalized"])

    def test_no_non_clock_mutation_of_the_built_archive_survives(self):
        """The blind-spot battery, run against the artefact and not a fixture.

        :class:`TheNormalisationReadsEveryByteButTheClock` establishes this
        over an archive written by the tests.  Running the same mutations over
        the archive the pinned backend actually produced is what makes the
        claim about *this* sdist: every one of them moves a byte the released
        file carries, none of them changes what any timestamp means, and each
        must be a failing comparison.
        """
        first, _ = self.sdists()
        tar_bytes = gzip.decompress(first["path"].read_bytes())
        baseline = normalized_tar(tar_bytes)
        self.assertEqual(first["normalized"],
                         hashlib.sha256(baseline).hexdigest())
        for label, (mutate, _seen) in sorted(MUTATIONS.items()):
            if label in _SYNTHETIC_ONLY:
                continue
            with self.subTest(mutation=label):
                self.assertNotEqual(baseline, normalized_tar(mutate(tar_bytes)),
                                    f"the normalisation cannot see {label}")

    def test_a_consistent_reclocking_of_the_built_archive_changes_nothing(self):
        """What is dropped is a clock, and it is dropped whatever it says."""
        first, _ = self.sdists()
        tar_bytes = gzip.decompress(first["path"].read_bytes())
        moved = reclocked(tar_bytes, mtime=EPOCH + 98765,
                          pax_mtime="1787949844.1112683")
        self.assertNotEqual(tar_bytes, moved)
        self.assertEqual(normalized_tar(tar_bytes), normalized_tar(moved))

    def test_every_extended_header_block_is_the_canonical_one(self):
        """The 512 bytes ``tarfile`` never shows a caller.

        A PAX extended header is a member of the archive with a name, a mode,
        an owner, a magic and a padding of its own, and ``tarfile`` folds its
        records into the following member and discards the block.  Nothing that
        reads an sdist through ``tarfile`` can see those bytes, so they are
        read here and asserted: a writer that started stamping the builder's
        uid, a long name or a second record on them would be changing the
        released artefact, and this is where that shows up.
        """
        first, second = self.sdists()
        for label, archive in (("a", first), ("b", second)):
            with self.subTest(archive=label):
                blocks = archive["pax_blocks"]
                self.assertTrue(blocks, "the sdist carries extended headers")
                for block in blocks:
                    self.assertEqual("././@PaxHeader", block["name"])
                    self.assertEqual("x", block["type"])
                    self.assertEqual("0000000", block["mode"])
                    self.assertEqual("0000000", block["uid"])
                    self.assertEqual("0000000", block["gid"])
                    self.assertEqual("00000000000", block["mtime"])
                    self.assertEqual(0, block["checksum_delta"])
                    self.assertEqual("ustar\x0000", block["magic"])
                    self.assertEqual("", block["linkname"])
                    self.assertEqual("", block["uname"])
                    self.assertEqual("", block["gname"])
                    self.assertEqual("", block["prefix"])
                    self.assertEqual("\x00" * 8, block["devmajor"])
                    self.assertEqual("\x00" * 8, block["devminor"])
                    self.assertEqual("\x00" * 12, block["unused"])
                    self.assertEqual(["mtime"], block["keys"])
                    self.assertEqual([], block["non_clock_records"])
                    self.assertEqual(0, block["unframed_bytes"])
                    self.assertTrue(block["padding_is_zero"])

    def test_the_two_builds_agree_on_every_extended_header_block(self):
        first, second = self.sdists()
        self.assertEqual(first["pax_blocks"], second["pax_blocks"])

    def test_every_member_field_the_format_can_carry_is_asserted(self):
        """Not only the fields a reproducibility bug happens to move.

        ``type``, ``mode``, ``uid``, ``gid``, ``uname``, ``gname``, ``size``
        and the payload digest are compared between the two builds by the
        tests above.  ``linkname`` and the device numbers are compared there
        too, and pinned here: an sdist that grew a symlink or a device node
        would be shipping something no source distribution should hold, and
        equality between two builds would not notice because both would grow
        it.
        """
        first, second = self.sdists()
        for label, archive in (("a", first), ("b", second)):
            for name in sorted(archive["members"]):
                member = archive["members"][name]
                with self.subTest(archive=label, member=name):
                    self.assertIn(member["type"], ("0", "5"))
                    self.assertEqual(0o755 if member["type"] == "5" else 0o644,
                                     member["mode"])
                    self.assertEqual("", member["linkname"])
                    self.assertEqual(0, member["devmajor"])
                    self.assertEqual(0, member["devminor"])
        self.assertEqual(first["order"], second["order"])

    def test_the_only_extended_header_records_are_the_timestamps(self):
        """What the normalisation drops is a clock, and nothing else.

        A PAX header could carry a long name, a large uid or an arbitrary
        vendor key.  Such a record *is* compared, byte for byte, by
        :func:`canonical_pax_payload` -- but a released artefact growing one
        would be a change in what the archive says about itself, so the set of
        keys the two builds use is asserted rather than merely compared.
        """
        first, second = self.sdists()
        for label, archive in (("a", first), ("b", second)):
            with self.subTest(archive=label):
                self.assertEqual({"mtime"}, archive["pax_keys"])

    def test_the_normalisation_neutralises_something_and_nothing_more(self):
        """The control for the digest above: it is not the identity function.

        A normaliser that silently did nothing would turn the comparison into a
        comparison of raw bytes -- a stronger claim, which would be failing --
        and one that dropped whole members would be comparing something that is
        not the archive.
        """
        first, _ = self.sdists()
        raw = gzip.decompress(first["path"].read_bytes())
        self.assertNotEqual(raw, first["normalized_bytes"])
        self.assertNotEqual(first["tar_sha256"], first["normalized"])
        for name in sorted(first["order"]):
            with self.subTest(member=name):
                self.assertIn(name.encode("utf-8"), first["normalized_bytes"])

    def test_the_complete_content_of_the_two_archives_is_identical(self):
        """The same claim member by member, so a failure says which member."""
        first, second = self.sdists()
        self.assertEqual(first["content"], second["content"])

    def test_every_member_holds_identical_bytes(self):
        first, second = self.sdists()
        for name in sorted(first["members"]):
            with self.subTest(member=name):
                self.assertEqual(first["members"][name]["sha256"],
                                 second["members"][name]["sha256"])

    def test_every_member_header_except_its_timestamp_is_identical(self):
        first, second = self.sdists()
        self.assertEqual(first["members"], second["members"])

    def test_the_members_appear_in_the_same_order(self):
        first, second = self.sdists()
        self.assertEqual(first["order"], second["order"])

    def test_the_archive_holds_exactly_the_expected_members(self):
        first, second = self.sdists()
        self.assertEqual(expected_sdist_members(), set(first["order"]))
        self.assertEqual(expected_sdist_members(), set(second["order"]))

    def test_no_byte_code_build_directory_or_cache_is_shipped(self):
        first, _ = self.sdists()
        strays = sorted(name for name in first["order"]
                        if name.endswith(".pyc") or "__pycache__" in name
                        or "/build/" in name or name.endswith("/build"))
        self.assertEqual([], strays)

    def test_every_copied_source_member_carries_the_pinned_epoch(self):
        """The half of the normalisation the environment *can* control."""
        first, second = self.sdists()
        for archive in (first, second):
            for name in sorted(expected_source_members()):
                with self.subTest(member=name):
                    self.assertEqual(EPOCH, archive["mtimes"][name])

    def test_the_only_members_the_clock_reaches_are_the_generated_ones(self):
        """An equality, so "only timestamps differ" cannot quietly grow.

        Comparing the two archives' timestamps to each other would pass by
        coincidence whenever both builds land in the same second.  What is
        asserted instead is which members carry the pinned epoch and which
        carry a clock, in each archive on its own: the partition is exactly
        the checked-in files against the ones setuptools writes during the
        build, and a checked-in file that started carrying a clock would move
        across it.
        """
        first, second = self.sdists()
        self.assertEqual(expected_sdist_members(),
                         expected_source_members() | expected_generated_members())
        for label, archive in (("a", first), ("b", second)):
            with self.subTest(archive=label):
                off_epoch = {name for name in archive["order"]
                             if archive["mtimes"][name] != EPOCH}
                self.assertEqual(expected_generated_members(), off_epoch)

    def test_the_gzip_framing_is_identical_apart_from_its_timestamp(self):
        """RFC 1952 MTIME, written by ``tarfile`` from the wall clock.

        Every other byte of the gzip framing -- magic, method, flags, extra
        flags, OS and the recorded filename -- is compared, so a change of
        compression level or of writer is a failure here rather than a
        difference nobody looked at.  This field is the reason the two files'
        own digests differ even when their contents do not: CPython's
        ``tarfile`` writes it from ``time.time()`` on the ``w|gz`` path, with
        no hook any environment variable can reach.
        """
        first, second = self.sdists()
        self.assertEqual(first["gzip_frame"], second["gzip_frame"])
        self.assertGreater(first["gzip_mtime"], EPOCH,
                           "the container timestamp is the wall clock")

    def test_the_sdist_is_the_archive_the_derived_wheel_was_built_from(self):
        state = self.prepared()
        self.assertTrue((state["sdist_root"] / "pyproject.toml").is_file())
        self.assertEqual(f"{DISTRIBUTION}-{VERSION}", state["sdist_root"].name)


#: The mutations that need a record no real sdist carries.  Everything else in
#: :data:`MUTATIONS` is run against the built archive as well as this one.
_SYNTHETIC_ONLY = frozenset({"a non-clock record's value"})


class TheNormalisationReadsEveryByteButTheClock(unittest.TestCase):
    """The normalised digest's blind spot, established rather than described.

    The digest above is the whole reproducibility claim for the sdist, so what
    it *cannot* see is the size of the hole in that claim.  This class works on
    an archive written here -- no backend, no build, nothing to install -- and
    establishes the hole exactly: every byte of it is moved, one at a time, and
    the set of bytes the digest does not notice is compared against the set of
    bytes that hold a timestamp.  An equality, not a containment: a normaliser
    that dropped an extended header wholesale would fail this as loudly as one
    that stopped dropping the clock.

    :func:`discarded_pax_normalisation` is kept beside it as the control.  It
    is what this module used to compare, and the tests below record which of
    these mutations it could not see -- the whole 512-byte extended header
    block and the whole padding behind it -- so that the repair is a
    demonstrated strengthening and not a claim about itself.
    """

    def setUp(self):
        self.tar = synthetic_pax_tar()
        self.baseline = normalized_tar(self.tar)

    def flipped(self, index: int) -> bytes:
        """The archive with the byte at ``index`` inverted, and nothing else."""
        return patched(self.tar, index, bytes([self.tar[index] ^ 0xFF]))

    def unread(self, span: range) -> set[int]:
        """The offsets in ``span`` the normalisation does not notice."""
        return {index for index in span
                if normalized_tar(self.flipped(index)) == self.baseline}

    def clock_offsets(self) -> set[int]:
        """Every byte that holds a timestamp's digits, and no other byte.

        A PAX time record's value is decimal text, so its length is part of the
        record and of the block's declared size: the value, its terminator and
        the framing those decide are the bytes two builds are allowed to differ
        in.  The key is not among them -- ``mtime`` is compared -- and neither
        is any other record.
        """
        offsets: set[int] = set()
        for offset, header, size in tar_blocks(self.tar):
            if header[_TAR_TYPE] not in _PAX_TYPES:
                continue
            at = offset + _TAR_BLOCK
            for record in split_pax_records(self.tar[at:at + size])[0]:
                if pax_record_key(record).decode("ascii") in _PAX_TIME_KEYS:
                    offsets |= set(range(at + record.index(b"=") + 1,
                                         at + len(record)))
                at += len(record)
        return offsets

    def test_the_named_fields_tile_the_whole_header_block(self):
        """A field map with a gap is a field map that excuses a blind spot."""
        covered: list[int] = []
        for _name, field in _TAR_FIELDS:
            covered.extend(range(field.start, field.stop))
        self.assertEqual(list(range(_TAR_BLOCK)), covered)

    def test_the_fixture_holds_an_extended_header_and_plain_members(self):
        """The control for everything below: the archive has the shape used."""
        blocks = tar_blocks(self.tar)
        extended = [item for item in blocks if item[1][_TAR_TYPE] in _PAX_TYPES]
        plain = [item for item in blocks if item[1][_TAR_TYPE] not in _PAX_TYPES]
        self.assertEqual(1, len(extended), "one extended header is expected")
        self.assertEqual(3, len(plain), "a directory, a file and a symlink")
        offset, _header, size = extended[0]
        payload = self.tar[offset + _TAR_BLOCK:offset + _TAR_BLOCK + size]
        self.assertEqual({"comment", "mtime"},
                         {key for key, _value in pax_records(payload)},
                         "the fixture must carry a non-clock record beside the "
                         "clock, or 'the rest is compared' is untested")

    def test_every_non_clock_mutation_changes_the_normalised_bytes(self):
        for label, (mutate, _seen) in sorted(MUTATIONS.items()):
            with self.subTest(mutation=label):
                self.assertNotEqual(self.baseline, normalized_tar(mutate(self.tar)),
                                    f"the normalisation cannot see {label}")

    def test_the_discarded_normalisation_could_not_see_the_extended_header(self):
        """The blind spot this repair closes, asserted as the fact it was."""
        control = discarded_pax_normalisation(self.tar)
        blind = sorted(label for label, (_m, seen) in MUTATIONS.items()
                       if not seen)
        self.assertTrue(blind, "the control must have had a blind spot")
        for label in blind:
            with self.subTest(mutation=label):
                self.assertEqual(
                    control,
                    discarded_pax_normalisation(MUTATIONS[label][0](self.tar)),
                    f"{label} was supposed to be invisible to the control")

    def test_the_discarded_normalisation_did_see_everything_else(self):
        """The control was not useless, and the table says which half was which."""
        control = discarded_pax_normalisation(self.tar)
        for label, (mutate, seen) in sorted(MUTATIONS.items()):
            if not seen:
                continue
            with self.subTest(mutation=label):
                self.assertNotEqual(
                    control, discarded_pax_normalisation(mutate(self.tar)))

    def test_the_unread_bytes_are_exactly_the_timestamps(self):
        """Every byte of the archive, moved one at a time.

        This is the assertion the whole class exists for, and it is an
        equality: the bytes the normalised digest does not notice are the
        digits of a PAX timestamp and its terminator, and nothing else in any
        header, any payload, any padding or the end-of-archive marker.
        """
        expected = self.clock_offsets()
        self.assertTrue(expected, "the fixture must hold a PAX timestamp")
        self.assertEqual(expected, self.unread(range(len(self.tar))))

    def test_no_byte_of_an_extended_header_block_is_unread(self):
        """Stated separately, because this block is the one that was dropped."""
        offset, _header, _size = find_block(self.tar, pax=True)
        self.assertEqual(
            set(), self.unread(range(offset, offset + _TAR_BLOCK)))

    def test_a_consistent_reclocking_normalises_to_the_same_bytes(self):
        """The other direction: what is dropped really is dropped.

        The archive is rewritten as a writer running at a different moment
        would have written it -- every mtime field, every time record, the
        record lengths, the declared size and both checksums -- and normalises
        identically.  Two builds landing in the same second would satisfy the
        digest comparison by accident; this cannot.
        """
        moved = reclocked(self.tar, mtime=EPOCH + 98765,
                          pax_mtime="1787949844.1112683")
        self.assertNotEqual(self.tar, moved)
        self.assertEqual(normalized_tar(self.tar), normalized_tar(moved))

    def test_the_reclocking_really_moved_every_clock(self):
        """The control for the test above: the fixture is not inert."""
        moved = reclocked(self.tar, mtime=EPOCH + 98765,
                          pax_mtime="1787949844.1112683")
        with tarfile.open(fileobj=io.BytesIO(moved)) as archive:
            found = {info.name: info.mtime for info in archive.getmembers()}
        self.assertTrue(found)
        for name, mtime in sorted(found.items()):
            with self.subTest(member=name):
                self.assertNotEqual(EPOCH, int(mtime))
        self.assertEqual(len(self.tar), len(moved),
                         "a reclocking that resized the archive would be "
                         "testing something else")

    def test_the_normalisation_carries_the_bytes_rather_than_summarising(self):
        """A digest over a summary would pass the tests above and prove less."""
        normalised = normalized_tar(self.tar)
        self.assertIn(SYNTHETIC_PAYLOAD, normalised)
        for name in (b"root", b"root/file.txt", b"root/link.txt",
                     b"././@PaxHeader", b"builder", b"staff", b"file.txt",
                     b"comment=aaa"):
            with self.subTest(fragment=name):
                self.assertIn(name, normalised)


if __name__ == "__main__":
    unittest.main()
