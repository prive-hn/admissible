"""Focused tests for the ``admissible`` compatibility umbrella.

The umbrella is one distribution with one job: keep the command a developer
already types working, by dispatching it to the distribution that owns it.  It
holds no authority of its own, so everything asserted below is about *where an
invocation goes* and *what a facade re-exports* -- never about what either
domain then decides.

Nothing here imports ``admissible`` into the test process, and that is
deliberate.  The repository root still holds the legacy monolith under the same
name, ``tests/admissible_support`` puts the root on ``sys.path``, and the whole
suite runs in one interpreter: an in-process ``import admissible`` here would
resolve to whichever of the two got imported first, and every assertion below
would be an assertion about import order.  So the umbrella is exercised the way
a user's process exercises it -- in a child process, with a sanitized
environment and an explicit import path -- and the answers come back as JSON.

The umbrella's sources live in ``packages/umbrella/compat`` rather than
``packages/umbrella/src``.  ``tests/architecture/test_import_census`` names
every module under ``packages/*/src`` relative to that ``src`` directory, so a
second permanent ``packages/umbrella/src/admissible/cli.py`` would claim the
dotted name ``admissible.cli`` that the root monolith already claims, and the
census refuses that collision outright rather than silently keeping one of the
two.  ``packages/core`` solves the same problem for ``fcd``/``rga``/``atlas``/
``protocol`` with a transient ``_staged/`` copy; the umbrella solves it by
keeping its own sources out of the censused path until the monolith retires.
:mod:`tests.compatibility.test_legacy_imports` censuses them here instead, with
the same parser, so nothing is unclassified merely because it is unscanned.
"""
from __future__ import annotations

import atexit
import json
import subprocess
import sysconfig
import tempfile
from pathlib import Path

from tests.architecture import inspect_wheel

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGES = REPO_ROOT / "packages"
UMBRELLA_PROJECT = PACKAGES / "umbrella"
#: The umbrella's compatibility namespace root; see the module docstring for
#: why it is not ``src``.
UMBRELLA_SRC = UMBRELLA_PROJECT / "compat"
UMBRELLA_PACKAGE = UMBRELLA_SRC / "admissible"
CORE_SRC = PACKAGES / "core" / "src"
READY_SRC = PACKAGES / "ready" / "src"
TRUST_SRC = PACKAGES / "trust" / "src"
SITE_PACKAGES = Path(sysconfig.get_paths()["purelib"])

#: The import path a child process gets, in this order and for this reason:
#: the umbrella first, so ``import admissible`` finds the dispatcher rather
#: than the monolith the repository root still holds under that name; then the
#: three distributions it pins; then the root, last, because ``admissible_core``
#: is written against ``fcd``/``rga``/``protocol``, which the Core *wheel* ships
#: as staged copies and the Core *source tree* reaches at the root. Installed
#: dependencies remain available last, but child interpreters use ``-S`` so a
#: root editable install cannot activate its ``.pth`` finder and leak monolith
#: submodules into the umbrella package. Ordering is what makes the fixture
#: honest, so
#: :class:`~tests.compatibility.test_legacy_cli.TheFixtureImportsTheUmbrella`
#: proves it rather than assuming it.
IMPORT_PATH = (
    UMBRELLA_SRC, CORE_SRC, READY_SRC, TRUST_SRC, REPO_ROOT, SITE_PACKAGES,
)

#: The module a dispatched invocation must end up in, per domain.
READY_TARGET = "admissible_ready.cli"
TRUST_TARGET = "admissible_trust.cli"

#: Every credential this product knows about.  A router that reads one of them
#: is a router whose answer depends on what the machine happens to hold, which
#: is the failure mode the split exists to make impossible.
CREDENTIAL_VARIABLES = (
    "ADMISSIBLE_HMAC_KEY",
    "ADMISSIBLE_REVIEW_KEY",
    "ADMISSIBLE_REVIEW_KEYRING",
    "ADMISSIBLE_EVALUATION_KEY",
    "ADMISSIBLE_EVALUATION_KEYRING",
)

_SCRATCH: tempfile.TemporaryDirectory | None = None


def _scratch() -> Path:
    global _SCRATCH
    if _SCRATCH is None:
        _SCRATCH = tempfile.TemporaryDirectory(prefix="admissible-umbrella-")
        atexit.register(_SCRATCH.cleanup)
        for name in ("cwd", "home"):
            (Path(_SCRATCH.name) / name).mkdir()
    return Path(_SCRATCH.name)


def neutral_directory() -> Path:
    """A working directory that holds no ``admissible`` package.

    ``python -c`` puts the working directory on ``sys.path`` ahead of
    everything else, so a child started in the checkout would import the
    monolith no matter what ``PYTHONPATH`` said.
    """
    return _scratch() / "cwd"


def umbrella_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """A sanitized environment that can import the umbrella and its siblings.

    ``ADMISSIBLE_HOME`` points at a throwaway directory unless a caller says
    otherwise: several of the commands routed below read and write the local
    store, and a test that reached the developer's real home would be a test
    whose answer depends on what that developer happens to have done.
    """
    overrides = {
        "PYTHONPATH": ":".join(str(entry) for entry in IMPORT_PATH),
        "ADMISSIBLE_HOME": str(_scratch() / "home"),
    }
    overrides.update(extra or {})
    return inspect_wheel.sanitized_env(overrides)


def run_python(code: str, *args: str, stdin: str | None = None,
               env: dict[str, str] | None = None,
               cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run ``code`` in a child that can see the umbrella and nothing else."""
    return subprocess.run(
        [inspect_wheel.sys.executable, "-S", "-c", code, *args],
        capture_output=True, text=True, timeout=inspect_wheel.RUN_TIMEOUT,
        cwd=str(cwd or neutral_directory()), env=env or umbrella_env(),
        input=stdin)


def run_module(module: str, *args: str, stdin: str | None = None,
               env: dict[str, str] | None = None,
               cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run ``python -m <module>`` in the same child environment."""
    return subprocess.run(
        [inspect_wheel.sys.executable, "-S", "-m", module, *args],
        capture_output=True, text=True, timeout=inspect_wheel.RUN_TIMEOUT,
        cwd=str(cwd or neutral_directory()), env=env or umbrella_env(),
        input=stdin)


#: Dispatch one invocation through the umbrella and report where it went.
#:
#: ``sys.modules`` is the evidence: a Ready command that reached Trust would
#: have imported ``admissible_trust``, and no amount of matching output would
#: hide that.  Both streams are captured in memory so that this program's own
#: stdout carries the JSON and nothing else.
DISPATCH_PROBE = """
import io, json, sys

arguments = json.loads(sys.argv[1])
from admissible import cli

out, err = io.StringIO(), io.StringIO()
try:
    code = cli.main(arguments, stdout=out, stderr=err)
    failure = None
except BaseException as error:  # reported, never swallowed
    code, failure = None, f"{type(error).__name__}: {error}"
loaded = sorted(
    name for name in sys.modules
    if name.split(".")[0] in ("admissible", "admissible_core",
                              "admissible_ready", "admissible_trust"))
sys.stdout.write(json.dumps({
    "exit_code": code,
    "failure": failure,
    "stdout": out.getvalue(),
    "stderr": err.getvalue(),
    "modules": loaded,
}))
"""


def dispatch(arguments: list[str], *, env: dict[str, str] | None = None) -> dict:
    """Run :data:`DISPATCH_PROBE` and return its report."""
    completed = run_python(DISPATCH_PROBE, json.dumps(arguments), env=env)
    if completed.returncode != 0:
        raise AssertionError(
            f"the dispatch probe for {arguments} failed:\n{completed.stderr}")
    return json.loads(completed.stdout)


def loaded_domains(report: dict) -> set[str]:
    """The split distributions an invocation actually imported."""
    return {
        name.split(".")[0] for name in report["modules"]
        if name.split(".")[0] in ("admissible_ready", "admissible_trust")
    }
