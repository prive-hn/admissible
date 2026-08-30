"""Build, inspect, and install wheels from the standard library alone.

The separation contract is about artefacts, not about source layout: two
distributions can import cleanly in a checkout and still ship each other's
modules.  So everything here reads the built ``.whl`` -- a ZIP file -- member by
member, and the installation helpers put those exact files into throwaway
virtual environments with no index configured.

Four rules shape the API.  A build is proved by its output and never by its exit
status alone: :func:`build_wheel` diffs the output directory and raises when a
zero exit produced no new wheel.  A resource is identified by its bytes:
:meth:`Wheel.sha256` exists so that "the same schema" means the same digest
rather than the same filename.  A member is located where it installs, not where
it sits in the archive: :func:`install_path` unwraps ``*.data/purelib/`` and
``*.data/platlib/`` so a package cannot hide one directory sideways.  And no
subprocess inherits the caller's import environment: :func:`sanitized_env`
strips ``PYTHONPATH`` and friends, so an absence proved here is an absence.

Usable directly::

    python -m tests.architecture.inspect_wheel dist/admissible_core-0.8.0-*.whl
"""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import subprocess
import sys
import sysconfig
import venv
import zipfile
from dataclasses import dataclass, field
from email import message_from_string
from pathlib import Path

__all__ = [
    "WheelError",
    "BuildFailed",
    "Wheel",
    "build_wheel",
    "inspect_wheel",
    "create_venv",
    "venv_python",
    "venv_script",
    "install_wheels",
    "run_python",
    "importable",
    "sanitized_env",
    "INHERITED_IMPORT_VARIABLES",
    "SYS_PATH_DATA_SCHEMES",
    "install_path",
]

# Wheels record file mtimes; pinning the clock keeps two builds of one tree
# byte-identical, so a digest comparison stays a statement about content.
SOURCE_DATE_EPOCH = "1580601600"

# The build and the installs must both be reproducible and offline.  A build
# that silently reaches an index is a build whose result depends on the network.
_OFFLINE_ENV = {
    "PIP_NO_INDEX": "1",
    "PIP_NO_INPUT": "1",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PIP_RETRIES": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
}

# Nothing about this suite's answers may depend on the shell that started it.
# An inherited ``PYTHONPATH`` puts the checkout back on ``sys.path`` inside the
# throwaway environments, so a module the wheel never shipped imports anyway and
# every absence assertion silently becomes a presence assertion; ``PYTHONHOME``
# is worse still, because it repoints the environment's standard library at the
# parent's.  Both are removed rather than overridden: an empty ``PYTHONPATH``
# is not the same thing as no ``PYTHONPATH``.
INHERITED_IMPORT_VARIABLES = (
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
)

# The user site directory is the other way a module can be present without any
# wheel having shipped it, and it is not reachable by deleting a variable.
_SANITIZED_ENV = {
    "PYTHONNOUSERSITE": "1",
    "PIP_USER": "0",
}

# Distribution names are compared after PEP 503 normalisation, so that
# ``admissible_core`` and ``admissible-core`` are one name and not two.
_NAME_SEPARATORS = re.compile(r"[-_.]+")

# The two ``*.data/`` schemes whose contents are unpacked onto ``sys.path``.
# A package under either is as importable as one at the archive root, so both
# are unwrapped before any containment question is asked.
SYS_PATH_DATA_SCHEMES = ("purelib", "platlib")

BUILD_TIMEOUT = 900
RUN_TIMEOUT = 300


class WheelError(RuntimeError):
    """A wheel could not be built, found, or read."""


class BuildFailed(WheelError):
    """``python -m build`` did not produce exactly one new wheel."""

    def __init__(self, reason: str, *, command: list[str], returncode: int | None,
                 stdout: str = "", stderr: str = ""):
        self.command = list(command)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"{reason}\n"
            f"  command: {' '.join(command)}\n"
            f"  exit: {returncode}\n"
            f"  stdout tail:\n{_tail(stdout)}\n"
            f"  stderr tail:\n{_tail(stderr)}"
        )


def _tail(text: str, lines: int = 25) -> str:
    """The last few lines of captured output, indented for a failure message."""
    kept = [line for line in (text or "").splitlines() if line.strip()][-lines:]
    return "\n".join(f"    {line}" for line in kept) or "    (empty)"


def normalize_name(name: str) -> str:
    """PEP 503 normalised distribution name."""
    return _NAME_SEPARATORS.sub("-", name.strip()).lower()


def sanitized_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """This process's environment with the import-leaking variables removed.

    Every subprocess this module starts -- builds, installs, import probes, and
    the console-command canaries -- is launched with this environment, because
    a canary that inherits ``PYTHONPATH`` reports the developer's shell rather
    than the wheel.
    """
    environment = {
        key: value for key, value in os.environ.items()
        if key not in INHERITED_IMPORT_VARIABLES
    }
    environment.update(_OFFLINE_ENV)
    environment.update(_SANITIZED_ENV)
    environment.update(extra or {})
    return environment


def install_path(member: str) -> str | None:
    """Where a payload member lands relative to ``site-packages``, or ``None``.

    ``<dist>.data/purelib/`` and ``<dist>.data/platlib/`` are unpacked straight
    onto ``sys.path``, so a package hidden under either is exactly as importable
    as one at the archive root and is reported at the path it lands on.  The
    remaining schemes -- ``scripts``, ``data``, ``headers`` -- install outside
    ``sys.path`` and are not module locations at all, so they answer ``None``.
    """
    parts = member.split("/")
    if not parts[0].endswith(".data"):
        return member
    if len(parts) > 2 and parts[1] in SYS_PATH_DATA_SCHEMES:
        return "/".join(parts[2:])
    return None


def build_wheel(project: Path | str, outdir: Path | str, *,
                python: str = sys.executable,
                timeout: int = BUILD_TIMEOUT) -> Path:
    """Build ``project`` into ``outdir`` and return the wheel that appeared.

    ``--no-isolation`` deliberately builds against the interpreter running the
    tests: an isolated build would download its own backend, and a test that
    needs the network is a test that reports the network's health.

    The exit status is not the evidence.  ``outdir`` is diffed across the call,
    and a zero exit that produced no new wheel -- or produced two -- raises
    :class:`BuildFailed` with the captured output, because both of those are a
    build that did not do what it claimed.
    """
    project = Path(project)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    if not (project / "pyproject.toml").is_file():
        raise BuildFailed(
            f"no project to build: {project / 'pyproject.toml'} does not exist",
            command=[python, "-m", "build", str(project)], returncode=None,
        )
    before = {path.name for path in outdir.glob("*.whl")}
    command = [
        python, "-m", "build", "--wheel", "--no-isolation",
        "--outdir", str(outdir), str(project),
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            cwd=str(project), env=sanitized_env(),
        )
    except subprocess.TimeoutExpired as expired:  # pragma: no cover - slow path
        raise BuildFailed(
            f"build timed out after {timeout}s", command=command, returncode=None,
            stdout=expired.stdout or "", stderr=expired.stderr or "",
        ) from expired
    produced = sorted({path.name for path in outdir.glob("*.whl")} - before)
    if completed.returncode != 0:
        raise BuildFailed(
            f"build of {project} failed", command=command,
            returncode=completed.returncode,
            stdout=completed.stdout, stderr=completed.stderr,
        )
    if len(produced) != 1:
        raise BuildFailed(
            f"build of {project} exited 0 but produced {len(produced)} new "
            f"wheels ({produced or 'none'})",
            command=command, returncode=completed.returncode,
            stdout=completed.stdout, stderr=completed.stderr,
        )
    return outdir / produced[0]


@dataclass(frozen=True)
class Wheel:
    """A built wheel read as a ZIP archive.

    Every accessor answers from the archive itself.  Nothing is inferred from
    the project that produced it, because the gap between the two is the thing
    under test.
    """

    path: Path
    members: tuple[str, ...]
    metadata_text: str
    entry_points_text: str
    _digests: dict[str, str] = field(default_factory=dict, repr=False)

    # -- identity -------------------------------------------------------
    @property
    def metadata(self):
        return message_from_string(self.metadata_text)

    @property
    def name(self) -> str:
        return normalize_name(self.metadata.get("Name") or "")

    @property
    def version(self) -> str:
        return (self.metadata.get("Version") or "").strip()

    @property
    def requires_python(self) -> str:
        return (self.metadata.get("Requires-Python") or "").strip()

    @property
    def requires_dist(self) -> list[str]:
        return sorted(
            requirement.strip()
            for requirement in (self.metadata.get_all("Requires-Dist") or [])
        )

    @property
    def provides_extra(self) -> list[str]:
        return sorted(
            extra.strip() for extra in (self.metadata.get_all("Provides-Extra") or [])
        )

    @property
    def unconditional_requirements(self) -> dict[str, str]:
        """``{normalised name: specifier}`` for every unmarked ``Requires-Dist``.

        This is the dependency set every install of the wheel gets, so it is the
        set worth asserting exactly: a dependency that appears here and nowhere
        in the contract is a distribution the split did not agree to pull in.
        """
        found: dict[str, str] = {}
        for requirement in self.requires_dist:
            head, _, marker = requirement.partition(";")
            if marker.strip():
                continue
            name, specifier = _split_requirement(head)
            found[normalize_name(name)] = specifier
        return found

    @property
    def conditional_requirements(self) -> dict[str, str]:
        """``{normalised name: marker}`` for every marked ``Requires-Dist``."""
        found: dict[str, str] = {}
        for requirement in self.requires_dist:
            head, _, marker = requirement.partition(";")
            if not marker.strip():
                continue
            name, _specifier = _split_requirement(head)
            found[normalize_name(name)] = marker.strip()
        return found

    @property
    def requirements_requesting_extras(self) -> list[str]:
        """Requirements that ask for an extra of the distribution they name.

        ``admissible-core[everything]`` pulls in whatever that extra names, so
        it is a dependency edge the exact-pin map cannot see.
        """
        return sorted(
            requirement for requirement in self.requires_dist
            if "[" in requirement.partition(";")[0]
        )

    def requirement_on(self, distribution: str) -> str | None:
        """The unconditional ``Requires-Dist`` naming ``distribution``, if any.

        Returns the specifier (``"==0.8.0"``) so a caller can assert an exact
        pin.  A requirement carrying an environment marker is not an
        unconditional dependency and is skipped.
        """
        return self.unconditional_requirements.get(normalize_name(distribution))

    @property
    def console_scripts(self) -> dict[str, str]:
        parser = configparser.ConfigParser()
        parser.optionxform = str
        if self.entry_points_text:
            parser.read_string(self.entry_points_text)
        if not parser.has_section("console_scripts"):
            return {}
        return dict(parser.items("console_scripts"))

    # -- contents -------------------------------------------------------
    @property
    def payload(self) -> tuple[str, ...]:
        """Members outside ``*.dist-info/``: the files this wheel installs."""
        return tuple(
            member for member in self.members
            if not member.split("/", 1)[0].endswith(".dist-info")
        )

    @property
    def installed_paths(self) -> tuple[str, ...]:
        """Payload members as the paths they occupy under ``site-packages``.

        Every containment question is asked here rather than of :attr:`payload`,
        because ``<dist>.data/purelib/admissible_trust/`` and
        ``admissible_trust/`` install to the same place: a wheel could otherwise
        pass every ownership assertion by moving the forbidden package one
        directory sideways.
        """
        return tuple(sorted(
            path for path in map(install_path, self.payload) if path is not None
        ))

    @property
    def top_level(self) -> set[str]:
        """First path segment of every member that lands on ``sys.path``."""
        return {path.split("/")[0].removesuffix(".py") for path in self.installed_paths}

    @property
    def modules(self) -> set[str]:
        """Dotted names of every ``.py`` module the wheel ships."""
        found: set[str] = set()
        for path in self.installed_paths:
            if not path.endswith(".py"):
                continue
            dotted = path[: -len(".py")].replace("/", ".")
            found.add(dotted.removesuffix(".__init__"))
        return found

    def owns(self, package: str) -> bool:
        """Does the wheel ship ``package`` as a package or a single module?"""
        return bool(self.members_under(package))

    def members_under(self, package: str) -> list[str]:
        """Installed paths belonging to ``package``, ``*.data`` unwrapped."""
        prefix = package.replace(".", "/")
        return sorted(
            path for path in self.installed_paths
            if path == f"{prefix}.py" or path.startswith(f"{prefix}/")
        )

    def read(self, member: str) -> bytes:
        with zipfile.ZipFile(self.path) as archive:
            return archive.read(member)

    def sha256(self, member: str) -> str:
        if member not in self._digests:
            self._digests[member] = hashlib.sha256(self.read(member)).hexdigest()
        return self._digests[member]

    def members_named(self, basename: str) -> list[str]:
        """Archive members with this basename, named so they can be read back."""
        return sorted(
            member for member in self.payload
            if member.rsplit("/", 1)[-1] == basename
        )

    def summary(self) -> dict:
        """JSON-ready description, for the command line and for diagnostics."""
        return {
            "wheel": self.path.name,
            "name": self.name,
            "version": self.version,
            "requires_python": self.requires_python,
            "requires_dist": self.requires_dist,
            "unconditional_requirements": self.unconditional_requirements,
            "provides_extra": self.provides_extra,
            "console_scripts": self.console_scripts,
            "top_level": sorted(self.top_level),
            "modules": sorted(self.modules),
            "members": list(self.payload),
            "installed_paths": list(self.installed_paths),
        }


def _split_requirement(text: str) -> tuple[str, str]:
    """``"admissible-core==0.8.0"`` -> ``("admissible-core", "==0.8.0")``."""
    head = text.strip()
    # Extras belong to the requiring project, not to the required name.
    if "[" in head:
        name, _, rest = head.partition("[")
        _extras, _, specifier = rest.partition("]")
        return name.strip(), specifier.strip()
    for index, character in enumerate(head):
        if character in "=<>!~ (":
            return head[:index].strip(), head[index:].strip().strip("()").strip()
    return head, ""


def inspect_wheel(path: Path | str) -> Wheel:
    """Read a built wheel; raises :class:`WheelError` if it is not one."""
    path = Path(path)
    if not path.is_file():
        raise WheelError(f"no such wheel: {path}")
    if not zipfile.is_zipfile(path):
        raise WheelError(f"not a ZIP archive, so not a wheel: {path}")
    with zipfile.ZipFile(path) as archive:
        members = tuple(sorted(
            info.filename for info in archive.infolist() if not info.is_dir()
        ))
        dist_info = sorted(
            member.split("/", 1)[0] for member in members
            if member.endswith("/METADATA")
            and member.split("/", 1)[0].endswith(".dist-info")
        )
        if len(dist_info) != 1:
            raise WheelError(
                f"{path.name} has {len(dist_info)} .dist-info/METADATA members "
                f"({dist_info or 'none'}); a wheel has exactly one"
            )
        metadata_text = archive.read(f"{dist_info[0]}/METADATA").decode("utf-8")
        entry_points = f"{dist_info[0]}/entry_points.txt"
        entry_points_text = (
            archive.read(entry_points).decode("utf-8")
            if entry_points in members else ""
        )
    return Wheel(
        path=path, members=members,
        metadata_text=metadata_text, entry_points_text=entry_points_text,
    )


# -- installation ------------------------------------------------------------
def venv_python(root: Path | str) -> Path:
    """Interpreter inside a virtual environment, on this platform."""
    root = Path(root)
    scripts = "Scripts" if os.name == "nt" else "bin"
    name = "python.exe" if os.name == "nt" else "python"
    return root / scripts / name


def venv_script(root: Path | str, command: str) -> Path:
    """Console script inside a virtual environment, on this platform."""
    root = Path(root)
    scripts = "Scripts" if os.name == "nt" else "bin"
    suffix = ".exe" if os.name == "nt" else ""
    return root / scripts / f"{command}{suffix}"


def create_venv(root: Path | str) -> Path:
    """Create a virtual environment with pip and return its interpreter.

    ``ensurepip`` installs the interpreter's own bundled pip, so this is
    offline; the environment is created without site-packages inheritance so an
    absent module is genuinely absent rather than visible from the parent.
    """
    root = Path(root)
    builder = venv.EnvBuilder(
        with_pip=True, system_site_packages=False, clear=True, symlinks=os.name != "nt",
    )
    builder.create(str(root))
    interpreter = venv_python(root)
    if not interpreter.is_file():
        raise WheelError(
            f"virtual environment at {root} has no interpreter at {interpreter}; "
            f"platform scheme is {sysconfig.get_default_scheme()}"
        )
    return interpreter


def install_wheels(interpreter: Path | str, wheels) -> subprocess.CompletedProcess:
    """Install exactly these wheel files and nothing else.

    ``--no-index`` and ``--no-deps`` together mean the environment contains the
    named wheels and their contents alone: no resolver is allowed to quietly
    add the very distribution a test is asserting is absent.
    """
    paths = [str(Path(wheel)) for wheel in wheels]
    command = [
        str(interpreter), "-m", "pip", "install",
        "--no-index", "--no-deps", "--disable-pip-version-check", *paths,
    ]
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=RUN_TIMEOUT, env=sanitized_env(),
    )
    if completed.returncode != 0:
        raise WheelError(
            f"installing {[Path(p).name for p in paths]} failed\n"
            f"  exit: {completed.returncode}\n"
            f"  stdout tail:\n{_tail(completed.stdout)}\n"
            f"  stderr tail:\n{_tail(completed.stderr)}"
        )
    return completed


def run_python(interpreter: Path | str, code: str, *args: str,
               timeout: int = RUN_TIMEOUT) -> subprocess.CompletedProcess:
    """Run a snippet in an environment, from a directory that is not the repo.

    ``cwd`` is the environment's own root: run from the checkout, ``sys.path[0]``
    would put the source tree ahead of site-packages and every import would
    resolve against files the wheel never shipped.
    """
    root = Path(interpreter).parent.parent
    return subprocess.run(
        [str(interpreter), "-c", code, *args],
        capture_output=True, text=True, timeout=timeout, cwd=str(root), env=sanitized_env(),
    )


_IMPORTABLE = """
import importlib.util, json, sys

found = {}
for name in sys.argv[1:]:
    try:
        found[name] = importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        # A missing parent package makes a dotted name unfindable, which is
        # the same answer as absent, and never an error for the caller.
        found[name] = False
print(json.dumps(found))
"""


def importable(interpreter: Path | str, *names: str) -> dict[str, bool]:
    """``{name: find_spec(name) is not None}`` inside that environment."""
    completed = run_python(interpreter, _IMPORTABLE, *names)
    if completed.returncode != 0:
        raise WheelError(
            f"import probe failed in {interpreter}\n"
            f"  exit: {completed.returncode}\n"
            f"  stderr tail:\n{_tail(completed.stderr)}"
        )
    return json.loads(completed.stdout)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(f"usage: {Path(__file__).name} <wheel> [wheel ...]", file=sys.stderr)
        return 2
    for candidate in argv:
        try:
            print(json.dumps(inspect_wheel(candidate).summary(), indent=2))
        except WheelError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
