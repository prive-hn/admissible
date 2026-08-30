"""The architecture guard registry: twelve invariants and the sabotage that proves them.

Every separation claim this repository makes is asserted somewhere.  This
module is the other half of that: for each claim it records a *concrete guard
site* in the production sources and one or more bounded mutations of that site,
each paired with the single named test that must go red when the mutation is
applied.  A claim with no mutant is a claim nobody has watched fail.

Three vocabularies are kept apart on purpose.

``SEP1``--``SEP12`` are **invariants**.  They are stable identifiers: a
receipt printed by ``scripts/sabotage_admissible.py`` or by
``tests.architecture.test_separation_sabotage`` names one of them, and the name
means the same thing across runs and across releases.  They are never renumbered.

A **mutant** is one bounded, deterministic edit -- or a small set of edits that
only make sense together, such as a file and the packaging line that ships it.
Each mutant carries its own identifier (``SEP4-trust-imports-ready``), the
invariant it attacks, the *shape* of sabotage it performs, and ``kills``: the
fully qualified test method that must fail.  Some also carry a ``control``: a
second named test that must still *pass* under the same mutation, which is what
turns "something went red" into "this guard, and only this guard, noticed".

A **shape** is the kind of sabotage, taken from the ten the task requires.
Registering shapes explicitly is what makes "every required kind of attack is
represented" a checkable statement rather than a reading of the list.

Every mutant also records ``expects``: the exception class and the message
fragments of the *one* failure its sabotage is supposed to cause.  "The named
test went red" is a much weaker statement than it looks, and the difference is
what this module is careful about.

How a mutant is judged
----------------------

``evaluate()`` copies this checkout into a temporary directory, applies the
edits there, and runs the named test in that copy.  Nothing in the live
worktree is touched, so there is nothing to restore and no path -- signal,
crash, timeout -- on which restoration can be skipped.

The judgement is made from a structured account of what each test did, never
from an exit status.  ``python -m unittest`` exits non-zero for a module that
will not import, a fixture that raises, a test that dies of an unrelated
exception, a test that fails an assertion about something else -- and for the
guard actually catching the sabotage.  As one bit those five are the same
answer, and four of them are a harness reporting a kill nobody saw.

A kill is the *complete* outcome this mutant registered, and not a matching
record inside a larger one: the named test and no other ran, and ran as exactly
one test; nothing errored, was skipped or passed; and the failures are exactly
the registered ones, in exactly the registered number, every one of them
matching a signature written down before the run.  A test that fails its
intended case *and* an unrelated one is the run a mutation that broke something
else produces, so it is an error.  The declared control, if there is one, must
also still be green.

That account is produced inside the process running the mutated code, because
"which assertion failed, and saying what" exists nowhere else -- but it is not
*delivered* by it.  The tested process gets no descriptor on the harness's
channel, no key, no nonce and no path, and an argv that is the test ids and
nothing more; a trusted observer outside the disposable clone watches it from
the far side of that boundary and authenticates what it saw to this process
with a per-run key.  A tested process can therefore not author the evidence the
parent reads, and a record it adds makes the run ambiguous rather than a kill.
:mod:`tests.architecture.separation_observer` states the protocol, and the
limits of what it proves.

The verdicts are deliberately four, not two:

``KILLED``
    the named test ran, failed, and failed exactly as its registered signatures
    say, in the registered number.  The guard is load-bearing.
``SURVIVED``
    the named test ran and passed under sabotage.  The guard is decorative,
    and this is a defect in the *test*, not in the harness.
``ERROR``
    the harness could not make the claim: a needle that matched zero or twice,
    an edit that moved no bytes, a test that never ran, a test that errored
    instead of failing, a failure that was not the expected one, a failure
    beside the expected one, a run whose record frame was missing, duplicated,
    malformed or unauthenticated, a suite that hung, a control that broke, or a
    platform on which the isolation below cannot be enforced.  An error is
    never counted as a kill, because a mutation that silently did nothing
    produces exactly the green run that a working guard produces, and the two
    must not be allowed to look alike.
``PASSED``
    used only by :func:`control_receipt`: the unmutated tree is green.

What a mutant is allowed to reach
---------------------------------

A mutant is arbitrary code: a broken build backend, a broken test, a broken
product module, running on a developer's machine.  It gets an environment
built from an allowlist rather than inherited and pruned, with a synthetic
home, cache and temporary root inside the workspace that is about to be
deleted, and it runs behind this platform's strongest deterministic network
boundary -- as does the observer that watches it, which is started inside the
same boundary and hands the same allowlisted environment down.  If that
boundary cannot be enforced here, nothing runs and the verdict is ``ERROR``:
an isolation claimed but not enforced is worse than one refused, because
everything downstream reads it as enforced.
"""
from __future__ import annotations

import atexit
import base64
import binascii
import builtins
import contextlib
import hashlib
import hmac
import importlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from . import separation_observer

__all__ = [
    "BOUNDARY_ADDED_NAMES",
    "Creation",
    "Copy",
    "ERROR",
    "EXTRA_ALLOWED",
    "FORCED_ENVIRONMENT_NAMES",
    "FRAME_VERSION",
    "GuardFailure",
    "INHERITED_NAMES",
    "INVARIANTS",
    "IsolationUnavailable",
    "KILLED",
    "MUTANTS",
    "Mutant",
    "MutationError",
    "NETWORK_PROFILE",
    "OBSERVER_SOURCE",
    "Outcome",
    "PASSED",
    "RECORD_MARKER",
    "Receipt",
    "REQUIRED_SHAPES",
    "SEP_IDS",
    "STATUSES",
    "SURVIVED",
    "Substitution",
    "TestRecord",
    "apply_edits",
    "check_edits",
    "control_receipt",
    "disposable_clone",
    "evaluate",
    "judge",
    "make_private_root",
    "mutants_for",
    "network_boundary",
    "network_denial_problem",
    "network_denied_command",
    "new_channel_secret",
    "orphaned_workspaces",
    "report_from_frame",
    "run_named_tests",
    "scrubbed_environment",
    "sealed_frame",
    "signature_problems",
    "source_files",
    "test_exists",
    "worktree_digest",
]

REPO_ROOT = Path(__file__).resolve().parents[2]

#: How long one named test may take before the harness calls the run useless.
#: A suite that hangs proves nothing either way, so it is an error rather than
#: a kill -- exactly as the legacy harness treats a timeout.
TEST_TIMEOUT_SECONDS = 900

#: Prefix for every temporary clone, so a leaked one is identifiable by name.
WORKSPACE_PREFIX = "admissible-separation-sabotage-"

KILLED = "KILLED"
SURVIVED = "SURVIVED"
ERROR = "ERROR"
PASSED = "PASSED"


# ---------------------------------------------------------------------------
# The twelve invariants.

SEP_IDS = tuple(f"SEP{number}" for number in range(1, 13))

INVARIANTS: dict[str, str] = {
    "SEP1": (
        "The Ready wheel ships no admissible_trust module, no Trust-surface "
        "module under any name, and installs no Trust console script."),
    "SEP2": (
        "The Trust wheel ships no runner, no MCP or agent surface, no HTTP "
        "server and no static UI asset."),
    "SEP3": (
        "Ready source imports Core and the standard library only; it reaches "
        "Trust neither directly nor through a relative or dynamic name."),
    "SEP4": (
        "Trust source imports Core and the standard library only; it reaches "
        "Ready neither directly nor through a relative or dynamic name."),
    "SEP5": (
        "Every Ready entry point refuses before any repository read, store "
        "open, attempt record, subprocess or socket side effect when any "
        "signing, review, observer or finalizer credential variable is "
        "present -- present, not merely non-empty."),
    "SEP6": (
        "Trust exposes no reachable candidate executor: only the fixed Git "
        "identity adapter may start a process, and nothing takes argv from a "
        "repository's policy."),
    "SEP7": (
        "Passing Ready checks can neither write nor emit the ADMITTED state "
        "nor an authenticated CURRENT standing; the candidate side's terminal "
        "word is checks_complete."),
    "SEP8": (
        "An authenticated `ready` requires Trust to verify the exact current "
        "receipt: no verifier, no impeached admission and no unverified claim "
        "may produce it."),
    "SEP9": (
        "The umbrella is a developer convenience and not a trusted deployment "
        "artifact: an isolated Ready-only or Trust-only install can neither "
        "install nor import it."),
    "SEP10": (
        "Every shared schema has exactly one owning distribution -- Core -- "
        "and the bytes every consumer sees are the canonical source bytes."),
    "SEP11": (
        "Legacy dispatch routes from the typed command alone: it can neither "
        "send a candidate verb into Trust nor a trust mutation into Ready, "
        "and it never routes by ambient credential or falls back to the "
        "opposite owner."),
    "SEP12": (
        "Removing any package, import or credential guard kills one named "
        "architecture test, and leaves that test's declared control green."),
}


# ---------------------------------------------------------------------------
# The sabotage shapes the task requires, plus the two this registry adds.

REQUIRED_SHAPES = (
    "ready-to-trust-import-prohibition-weakened",
    "trust-to-ready-import-prohibition-weakened",
    "trust-surface-placed-in-the-ready-wheel",
    "execution-surface-placed-in-the-trust-wheel",
    "ready-credential-refusal-removed",
    "unsigned-projection-emits-an-authenticated-ready",
    "umbrella-routes-by-ambient-credential-or-falls-back",
    "schema-forked-or-drifted-away-from-core",
    "candidate-executor-exposed-through-trust",
    "umbrella-admitted-into-an-isolated-install",
)

DECLARED_SHAPES = REQUIRED_SHAPES + (
    "umbrella-misroutes-a-domain-verb",
    "guard-removal-is-specifically-detected",
)


# ---------------------------------------------------------------------------
# Edits.

class MutationError(RuntimeError):
    """An edit could not be applied as written, so nothing was proved."""


@dataclass(frozen=True)
class Substitution:
    """Replace one exact occurrence of ``needle`` in ``path``."""

    path: str
    needle: str
    replacement: str

    def describe(self) -> str:
        return f"substitute in {self.path}"

    def check(self, root: Path) -> None:
        target = root / self.path
        if not target.is_file():
            raise MutationError(f"{self.path} does not exist")
        text = target.read_text(encoding="utf-8")
        occurrences = text.count(self.needle)
        if occurrences != 1:
            raise MutationError(
                f"{self.path}: anchor occurs {occurrences} times, expected 1: "
                f"{self.needle!r}")
        if self.needle == self.replacement:
            raise MutationError(
                f"{self.path}: the replacement is the anchor, so this "
                "mutation would move no bytes")

    def apply(self, root: Path) -> None:
        self.check(root)
        target = root / self.path
        text = target.read_text(encoding="utf-8")
        target.write_text(text.replace(self.needle, self.replacement, 1),
                          encoding="utf-8")


@dataclass(frozen=True)
class Creation:
    """Write a file that must not already exist."""

    path: str
    body: str

    def describe(self) -> str:
        return f"create {self.path}"

    def check(self, root: Path) -> None:
        target = root / self.path
        if target.exists():
            raise MutationError(
                f"{self.path} already exists, so creating it proves nothing")
        if not self.body:
            raise MutationError(f"{self.path}: an empty body moves no bytes")

    def apply(self, root: Path) -> None:
        self.check(root)
        target = root / self.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.body, encoding="utf-8")


@dataclass(frozen=True)
class Copy:
    """Duplicate an existing file's exact bytes to a second path.

    This is the shape a forked schema actually takes: not a rewrite, but a
    second byte-identical copy in a distribution that does not own it.
    """

    source: str
    path: str

    def describe(self) -> str:
        return f"copy {self.source} -> {self.path}"

    def check(self, root: Path) -> None:
        origin = root / self.source
        if not origin.is_file():
            raise MutationError(f"{self.source} does not exist to copy")
        target = root / self.path
        if target.exists():
            raise MutationError(
                f"{self.path} already exists, so copying onto it proves "
                "nothing")

    def apply(self, root: Path) -> None:
        self.check(root)
        target = root / self.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((root / self.source).read_bytes())


@dataclass(frozen=True)
class GuardFailure:
    """The exact failure one mutant must provoke, written down in advance.

    "The named test went red" is not the claim this harness makes.  A test goes
    red for its own assertion, and it also goes red because the module holding
    it stopped importing, because a fixture raised, or because something else
    in it disagreed about something else -- and a mutation is quite capable of
    causing any of those instead of the one it was aimed at.  So each mutant
    says which failure it expects: the exception class, and fragments of the
    message that only the intended assertion produces.

    ``contains`` is checked as a set of substrings of one failure's message.
    Fragments are deliberately drawn from what the guard *says*, never from the
    name of the test that says it: a test-name matcher would be satisfied by
    any failure at all in that test, which is the hole this class exists to
    close.

    ``count`` is how many failure records must carry exactly this signature --
    one for a plain assertion, and for a guard that checks its property in a
    subtest loop the exact number of cases the mutation breaks.  It is an
    equality and not a floor.  "At least one of the failures matched" is not a
    claim about this mutation: a run in which the intended case failed *and*
    something unrelated failed looks identical to it from the outside, and one
    of those two readings is a guard nobody watched work.
    """

    exception: str
    contains: tuple[str, ...]
    count: int = 1

    def describe(self) -> str:
        many = "" if self.count == 1 else f"{self.count} failures each "
        return (f"{many}{self.exception} carrying "
                + ", ".join(repr(item) for item in self.contains))

    def mismatch(self, record: "TestRecord") -> str:
        """Why ``record`` is not this failure, or ``""`` if it is."""

        if record.exception != self.exception:
            return (f"the failure was {record.exception or 'unnamed'}, not "
                    f"{self.exception}")
        missing = [item for item in self.contains if item not in record.message]
        if missing:
            return ("the failure message carries none of "
                    + ", ".join(repr(item) for item in missing))
        return ""


@dataclass(frozen=True)
class Mutant:
    """One bounded sabotage, the named test that must notice it, and how.

    ``expects`` is the failure the sabotage is aimed at.  ``also_expects`` is
    for the guards that check their property once per case: removing one of
    those does not break one case, it breaks a known set of them, and some of
    those cases fail in a second way that belongs to the same mutation.  Both
    are registered, both carry an exact count, and the complete set is what a
    kill has to be -- so a failure this registry did not write down in advance
    is an error however plausible it looks.
    """

    mutant_id: str
    sep: str
    shape: str
    summary: str
    edits: tuple
    kills: str
    expects: GuardFailure
    control: str | None = None
    also_expects: tuple[GuardFailure, ...] = ()

    @property
    def signatures(self) -> tuple[GuardFailure, ...]:
        return (self.expects, *self.also_expects)

    @property
    def expected_failures(self) -> int:
        return sum(signature.count for signature in self.signatures)

    def describe_expectation(self) -> str:
        return " and ".join(item.describe() for item in self.signatures)


def check_edits(root: Path, edits) -> None:
    """Raise :class:`MutationError` unless every edit addresses one real site."""

    for edit in edits:
        edit.check(Path(root))


def apply_edits(root: Path, edits) -> None:
    """Apply every edit in order, refusing any that would move no bytes."""

    root = Path(root)
    before = worktree_digest(root)
    for edit in edits:
        edit.apply(root)
    if worktree_digest(root) == before:
        raise MutationError(
            "the mutation left the tree byte-identical; a no-op mutation is "
            "an error, never a kill")


# ---------------------------------------------------------------------------
# The registry.

_READY_SRC = "packages/ready/src/admissible_ready"
_TRUST_SRC = "packages/trust/src/admissible_trust"
_UMBRELLA_CLI = "packages/umbrella/compat/admissible/cli.py"
_READY_PYPROJECT = "packages/ready/pyproject.toml"
_TRUST_PYPROJECT = "packages/trust/pyproject.toml"

_PLANTED = ('"""Planted by the separation sabotage harness. Not product '
            'source."""\n')

_TRUST_PACKAGES_ANCHOR = (
    'packages = ["admissible_trust"]\n'
    "\n"
    "[tool.setuptools.package-dir]\n"
    'admissible_trust = "src/admissible_trust"\n'
)

_TRUST_EXCLUDE_ANCHOR = (
    "[tool.setuptools.exclude-package-data]\n"
    '"*" = ["__pycache__/*", "*.pyc"]\n'
)

MUTANTS: tuple[Mutant, ...] = (
    # -- SEP1: no Trust surface inside the Ready wheel ----------------------
    Mutant(
        mutant_id="SEP1-trust-module-in-ready-wheel",
        sep="SEP1",
        shape="trust-surface-placed-in-the-ready-wheel",
        summary="Ready ships a module named after the Trust receipt surface.",
        edits=(Creation(f"{_READY_SRC}/receipt.py", _PLANTED),),
        expects=GuardFailure('AssertionError', (
            'admissible_ready.receipt',
            'Ready must not ship the trust surface',
        )),
        kills="tests.architecture.test_distribution_separation."
              "ReadyWheelIsolation.test_ready_ships_no_trust_authority_modules",
    ),
    Mutant(
        mutant_id="SEP1-trust-script-in-ready-wheel",
        sep="SEP1",
        shape="trust-surface-placed-in-the-ready-wheel",
        summary="The Ready wheel installs an `admissible-trust` command.",
        edits=(Substitution(
            _READY_PYPROJECT,
            'admissible-ready = "admissible_ready.cli:main"',
            'admissible-ready = "admissible_ready.cli:main"\n'
            'admissible-trust = "admissible_ready.cli:main"'),),
        expects=GuardFailure('AssertionError', (
            "'admissible-trust': 'admissible_ready.cli:main'",
        )),
        kills="tests.architecture.test_distribution_separation."
              "ReadyWheelIsolation.test_ready_installs_only_its_own_command",
    ),

    # -- SEP2: no execution surface inside the Trust wheel ------------------
    Mutant(
        mutant_id="SEP2-runner-module-in-trust-wheel",
        sep="SEP2",
        shape="execution-surface-placed-in-the-trust-wheel",
        summary="Trust ships a module named after the candidate runner.",
        edits=(Creation(f"{_TRUST_SRC}/runner.py", _PLANTED),),
        expects=GuardFailure('AssertionError', (
            'admissible_trust.runner',
            'a distribution that signs must not also be able to run candidates',
        )),
        kills="tests.architecture.test_distribution_separation."
              "TrustWheelIsolation.test_trust_ships_no_runner_or_agent_surface",
    ),
    Mutant(
        mutant_id="SEP2-static-asset-in-trust-wheel",
        sep="SEP2",
        shape="execution-surface-placed-in-the-trust-wheel",
        summary="Trust ships a browser asset, and the packaging line for it.",
        edits=(
            Creation(f"{_TRUST_SRC}/ready.js",
                     "// Planted by the separation sabotage harness.\n"),
            Substitution(
                _TRUST_PYPROJECT,
                _TRUST_EXCLUDE_ANCHOR,
                "[tool.setuptools.package-data]\n"
                'admissible_trust = ["*.js"]\n'
                "\n" + _TRUST_EXCLUDE_ANCHOR),
        ),
        expects=GuardFailure('AssertionError', (
            'admissible_trust/ready.js',
            "the Ready server's assets are not Trust's",
        )),
        kills="tests.architecture.test_distribution_separation."
              "TrustWheelIsolation.test_trust_ships_no_browser_assets",
    ),

    # -- SEP3: Ready reaches Core only --------------------------------------
    Mutant(
        mutant_id="SEP3-ready-imports-trust",
        sep="SEP3",
        shape="ready-to-trust-import-prohibition-weakened",
        summary="admissible_ready.ready imports the Trust receipt module.",
        edits=(Substitution(
            f"{_READY_SRC}/ready.py",
            "from . import git_reader\n"
            "from . import runner as runner_module\n"
            "from . import store as store_module\n",
            "from . import git_reader\n"
            "from . import runner as runner_module\n"
            "from . import store as store_module\n"
            "from admissible_trust import receipt as trust_receipt_module\n"),),
        expects=GuardFailure('AssertionError', (
            'admissible_ready.ready -> admissible_trust',
        )),
        kills="tests.ready.test_admissible_ready_isolation."
              "ReadySourceImportsCoreOnly.test_no_module_imports_a_forbidden_root",
    ),
    Mutant(
        mutant_id="SEP3-ready-reaches-trust-dynamically",
        sep="SEP3",
        shape="ready-to-trust-import-prohibition-weakened",
        summary="Ready loads a Trust-surface module by dynamic name.",
        edits=(Substitution(
            f"{_READY_SRC}/ready.py",
            "def from_problem(message: str, remediation: Sequence[str] = (), *,",
            "def _authenticated_standing():\n"
            "    import importlib\n"
            '    return importlib.import_module("admissible_ready.standing")\n'
            "\n"
            "\n"
            "def from_problem(message: str, remediation: Sequence[str] = (), *,"),),
        expects=GuardFailure('AssertionError', (
            'admissible_ready.ready -> admissible_ready.standing',
        )),
        kills="tests.ready.test_admissible_ready_isolation."
              "ReadySourceImportsCoreOnly."
              "test_no_module_reaches_trust_through_a_relative_or_dynamic_name",
    ),

    # -- SEP4: Trust reaches Core only --------------------------------------
    Mutant(
        mutant_id="SEP4-trust-imports-ready",
        sep="SEP4",
        shape="trust-to-ready-import-prohibition-weakened",
        summary="admissible_trust.standing imports the candidate runner.",
        edits=(Substitution(
            f"{_TRUST_SRC}/standing.py",
            "from admissible_core.decision import ADMITTED\n"
            "from admissible_core.store_base import StoreError\n",
            "from admissible_core.decision import ADMITTED\n"
            "from admissible_core.store_base import StoreError\n"
            "from admissible_ready import runner as candidate_runner\n"),),
        expects=GuardFailure('AssertionError', (
            'admissible_trust.standing -> admissible_ready',
        )),
        kills="tests.trust.test_admissible_trust_isolation."
              "TrustSourceImportsCoreOnly.test_no_module_imports_a_forbidden_root",
    ),
    Mutant(
        mutant_id="SEP4-trust-reaches-ready-dynamically",
        sep="SEP4",
        shape="trust-to-ready-import-prohibition-weakened",
        summary="Trust loads a runner-surface module by dynamic name.",
        edits=(Substitution(
            f"{_TRUST_SRC}/standing.py",
            "def current_standing(store, repository: str, commit_sha: str, *,",
            "def _candidate_runner():\n"
            "    import importlib\n"
            '    return importlib.import_module("admissible_trust.runner")\n'
            "\n"
            "\n"
            "def current_standing(store, repository: str, commit_sha: str, *,"),),
        expects=GuardFailure('AssertionError', (
            'admissible_trust.standing -> admissible_trust.runner',
        )),
        kills="tests.trust.test_admissible_trust_isolation."
              "TrustSourceImportsCoreOnly."
              "test_no_module_reaches_ready_through_a_relative_or_dynamic_name",
    ),

    # -- SEP5: Ready refuses beside a credential, before any side effect ----
    Mutant(
        mutant_id="SEP5-runner-credential-guard-removed",
        sep="SEP5",
        shape="ready-credential-refusal-removed",
        summary="run_check, the deepest direct executor, stops looking.",
        edits=(Substitution(
            f"{_READY_SRC}/runner.py",
            "    present = present_signing_credentials()\n"
            "    if present:\n"
            "        raise RunnerError(",
            "    present = ()\n"
            "    if present:\n"
            "        raise RunnerError("),),
        # One refusal per credential and per shape of it: this guard asks the
        # same question eleven times over two shapes, so the whole outcome is
        # twenty-two identical failures rather than one, and twenty-two is
        # what is registered. If the product's closed credential list grows,
        # this count stops matching and the mutant becomes an error -- which is
        # the intended reading, because at that point nobody has checked what
        # the new case does.
        expects=GuardFailure('AssertionError', (
            "not found in 'run_check needs a parsed Check'",
        ), count=22),
        kills="tests.ready.test_admissible_ready_credentials."
              "RunnerRefusesFirst."
              "test_every_credential_refuses_before_any_argument_is_judged",
    ),
    Mutant(
        mutant_id="SEP5-entrypoint-credential-guard-removed",
        sep="SEP5",
        shape="ready-credential-refusal-removed",
        summary="The CLI credential canary reports nothing present.",
        edits=(Substitution(
            f"{_READY_SRC}/cli.py",
            "    present = runner_module.present_signing_credentials()\n"
            "    if not present:\n"
            "        return None\n",
            "    present = ()\n"
            "    if not present:\n"
            "        return None\n"),),
        # Eleven credentials, two shapes, three entry points: sixty-six cases,
        # and removing the canary breaks all of them in two ways that belong to
        # the same mutation. Two entry points get far enough to reach a trap;
        # the third refuses for its own reasons but no longer names what it
        # refused over. Both are registered, exactly, because a failure this
        # registry did not write down in advance is an error -- and "44 of the
        # 66 matched" is the reading that would let an unrelated break through.
        expects=GuardFailure('TrapFired', (
            'subprocess.run was reached in a credential-bearing process',
        ), count=44),
        also_expects=(GuardFailure('AssertionError', (
            'refused without naming ADMISSIBLE',
        ), count=22),),
        kills="tests.ready.test_admissible_ready_credentials."
              "CredentialMatrix."
              "test_every_entry_point_refuses_every_credential_without_side_effects",
    ),

    # -- SEP6: no reachable candidate executor in Trust ---------------------
    Mutant(
        mutant_id="SEP6-candidate-executor-in-trust",
        sep="SEP6",
        shape="candidate-executor-exposed-through-trust",
        summary="The Trust store gains a subprocess-backed candidate runner.",
        edits=(Substitution(
            f"{_TRUST_SRC}/store.py",
            "import contextlib\n"
            "import hashlib\n"
            "import json\n"
            "import os\n"
            "import sqlite3\n",
            "import contextlib\n"
            "import hashlib\n"
            "import json\n"
            "import os\n"
            "import sqlite3\n"
            "import subprocess\n"
            "\n"
            "\n"
            "def run_candidate_check(argv):\n"
            '    """Planted by the separation sabotage harness."""\n'
            "    return subprocess.run(list(argv), capture_output=True)\n"),),
        expects=GuardFailure('AssertionError', (
            'store.py imports subprocess',
        )),
        kills="tests.trust.test_admissible_trust_boundary."
              "TheSourceNamesOneExecutor."
              "test_only_the_adapter_imports_a_process_starting_module",
    ),

    # -- SEP7: the candidate side cannot claim an admission -----------------
    Mutant(
        mutant_id="SEP7-passing-checks-claim-ready",
        sep="SEP7",
        shape="unsigned-projection-emits-an-authenticated-ready",
        summary="Passing preview checks map straight onto the `ready` status.",
        edits=(Substitution(
            f"{_READY_SRC}/ready.py",
            '        return "checks_complete", (',
            '        return "ready", ('),),
        # One case per standing the projection can be asked about: four
        # standings, four identical refusals.
        expects=GuardFailure('AssertionError', (
            "'ready' not found in",
            "'checks_complete', 'unable_to_check'",
        ), count=4),
        kills="tests.ready.test_admissible_ready_isolation."
              "UnsignedStatusVocabulary.test_from_evaluation_never_produces_ready",
    ),
    Mutant(
        mutant_id="SEP7-unsigned-document-emits-admitted",
        sep="SEP7",
        shape="unsigned-projection-emits-an-authenticated-ready",
        summary="The unsigned Ready document writes the ADMITTED state.",
        edits=(Substitution(
            f"{_READY_SRC}/ready.py",
            '        "canonical": {\n'
            '            "state": state,\n'
            '            "readiness": readiness,\n'
            '            "standing": standing,\n',
            '        "canonical": {\n'
            '            "state": "ADMITTED",\n'
            '            "readiness": readiness,\n'
            '            "standing": standing,\n'),),
        expects=GuardFailure('AssertionError', (
            'admissible_ready.ready:',
        )),
        kills="tests.ready.test_admissible_ready_isolation."
              "UnsignedStatusVocabulary."
              "test_no_ready_source_line_can_emit_the_admitted_state",
    ),

    # -- SEP8: authenticated `ready` needs a verified current receipt -------
    Mutant(
        mutant_id="SEP8-projection-needs-no-verifier",
        sep="SEP8",
        shape="unsigned-projection-emits-an-authenticated-ready",
        summary="The authenticated projection answers without a verifier.",
        edits=(Substitution(
            f"{_TRUST_SRC}/ready_status.py",
            "    if verifier is None:\n"
            "        raise ReadyError(\n"
            '            "an authenticated Ready projection needs a verifier;',
            "    if False:\n"
            "        raise ReadyError(\n"
            '            "an authenticated Ready projection needs a verifier;'),),
        expects=GuardFailure('AssertionError', (
            'ReadyError not raised',
        )),
        kills="tests.trust.test_admissible_trust_finalization."
              "ARetainedPreviewBecomesAReceipt."
              "test_an_authenticated_projection_needs_a_verifier",
    ),
    Mutant(
        mutant_id="SEP8-impeached-admission-still-ready",
        sep="SEP8",
        shape="unsigned-projection-emits-an-authenticated-ready",
        summary="An impeached -- not current -- admission still says `ready`.",
        edits=(Substitution(
            f"{_TRUST_SRC}/ready_status.py",
            "        impeached = reported_standing == standing_module.IMPEACHED\n",
            "        impeached = False\n"),),
        expects=GuardFailure('AssertionError', (
            "'needs_attention' != 'ready'",
        )),
        kills="tests.trust.test_admissible_trust_finalization."
              "ImpeachmentChangesStandingAndNeverAReceipt."
              "test_an_impeached_commit_is_not_ready",
    ),

    # -- SEP9: the umbrella is not a trusted deployment artifact ------------
    Mutant(
        mutant_id="SEP9-umbrella-namespace-in-trust-only-install",
        sep="SEP9",
        shape="umbrella-admitted-into-an-isolated-install",
        summary="The Trust wheel ships the `admissible` namespace, so a "
                "Trust-only environment can import the umbrella.",
        edits=(
            Creation("packages/trust/src/admissible/__init__.py", _PLANTED),
            Substitution(
                _TRUST_PYPROJECT,
                _TRUST_PACKAGES_ANCHOR,
                'packages = ["admissible_trust", "admissible"]\n'
                "\n"
                "[tool.setuptools.package-dir]\n"
                'admissible_trust = "src/admissible_trust"\n'
                'admissible = "src/admissible"\n'),
        ),
        expects=GuardFailure('AssertionError', (
            'in the trust-only environment: find_spec disagrees with the contract',
            "'admissible': True",
        )),
        kills="tests.architecture.test_distribution_separation."
              "TrustOnlyInstallation.test_trust_is_importable_and_ready_is_not",
    ),

    # -- SEP10: one schema, one Core owner, one set of bytes ----------------
    Mutant(
        mutant_id="SEP10-schema-forked-into-the-trust-wheel",
        sep="SEP10",
        shape="schema-forked-or-drifted-away-from-core",
        summary="A second, byte-identical copy of a schema ships from Trust.",
        edits=(
            Copy("protocol/ready-state.schema.json",
                 f"{_TRUST_SRC}/ready-state.schema.json"),
            Substitution(
                _TRUST_PYPROJECT,
                _TRUST_EXCLUDE_ANCHOR,
                "[tool.setuptools.package-data]\n"
                'admissible_trust = ["*.json"]\n'
                "\n" + _TRUST_EXCLUDE_ANCHOR),
        ),
        expects=GuardFailure('AssertionError', (
            'admissible-trust:admissible_trust/ready-state.schema.json (identical)',
            'one schema, one owner, one copy',
        )),
        kills="tests.architecture.test_distribution_separation."
              "SchemaResourceOwnership."
              "test_no_other_distribution_carries_a_forked_schema_copy",
    ),
    Mutant(
        mutant_id="SEP10-shipped-schema-bytes-drift",
        sep="SEP10",
        shape="schema-forked-or-drifted-away-from-core",
        summary="Core's build backend rewrites schema bytes while staging.",
        edits=(Substitution(
            "packages/core/build_backend.py",
            "        payload = _read_descriptor(handle)\n"
            "        target.write_bytes(payload)\n",
            "        payload = _read_descriptor(handle)\n"
            '        if relative.endswith(".json"):\n'
            '            payload = payload + b"\\n"\n'
            "        target.write_bytes(payload)\n"),),
        # Every schema every distribution ships, once each: the staging rewrite
        # is not selective, so the whole outcome is all twenty-seven of them.
        expects=GuardFailure('AssertionError', (
            'has drifted from protocol/',
        ), count=27),
        kills="tests.architecture.test_distribution_separation."
              "SchemaResourceOwnership."
              "test_shipped_schema_bytes_match_the_canonical_source",
    ),

    # -- SEP11: legacy dispatch reads the typed command and nothing else ----
    Mutant(
        mutant_id="SEP11-routing-reads-an-ambient-credential",
        sep="SEP11",
        shape="umbrella-routes-by-ambient-credential-or-falls-back",
        summary="`admissible run --preview` routes to Trust when a signing "
                "key happens to be set.",
        edits=(Substitution(
            _UMBRELLA_CLI,
            "    for index, argument in enumerate(arguments):\n"
            f'        if argument.startswith(f"{{_PREVIEW}}="):\n',
            "    import os\n"
            '    if os.environ.get("ADMISSIBLE_HMAC_KEY"):\n'
            "        return TRUST_TARGET\n"
            "    for index, argument in enumerate(arguments):\n"
            f'        if argument.startswith(f"{{_PREVIEW}}="):\n'),),
        expects=GuardFailure('AssertionError', (
            'First differing element 3:',
            "'admissible_ready.cli'",
            "'admissible_trust.cli'",
        )),
        kills="tests.compatibility.test_legacy_cli."
              "RoutingNeverReadsTheEnvironment."
              "test_the_answers_are_identical_under_every_credential",
    ),
    Mutant(
        mutant_id="SEP11-broken-owner-falls-back-to-the-opposite-domain",
        sep="SEP11",
        shape="umbrella-routes-by-ambient-credential-or-falls-back",
        summary="An owner that fails to import is retried in the other "
                "authority's distribution.",
        edits=(Substitution(
            _UMBRELLA_CLI,
            "    try:\n"
            "        owner = _LOADERS[target]()\n"
            "    except ImportError as error:\n"
            "        distribution = target.partition(\".\")[0].replace(\"_\", \"-\")\n",
            "    try:\n"
            "        owner = _LOADERS[target]()\n"
            "    except ImportError as error:\n"
            "        other = TRUST_TARGET if target == READY_TARGET else READY_TARGET\n"
            "        try:\n"
            "            return _LOADERS[other]().main(\n"
            "                arguments, stdout=out, stderr=err)\n"
            "        except ImportError:\n"
            "            pass\n"
            "        distribution = target.partition(\".\")[0].replace(\"_\", \"-\")\n"),),
        # One case per way an owner can fail to import, all five of which the
        # fallback answers the same wrong way.
        expects=GuardFailure('AssertionError', (
            "'admissible_trust' unexpectedly found in",
        ), count=5),
        kills="tests.compatibility.test_legacy_cli."
              "AnOwnerThatFailsToImportIsNotCalledAbsent."
              "test_a_broken_owner_never_falls_through_to_the_other_domain",
    ),
    Mutant(
        mutant_id="SEP11-candidate-verb-routed-into-trust",
        sep="SEP11",
        shape="umbrella-misroutes-a-domain-verb",
        summary="`check`, a verb that starts candidate commands, is routed "
                "into the distribution that holds the key.",
        edits=(
            Substitution(
                _UMBRELLA_CLI,
                'READY_COMMANDS = frozenset({\n'
                '    "profiles", "init", "check", "mcp", "connect", "ui",\n'
                "})",
                'READY_COMMANDS = frozenset({\n'
                '    "profiles", "init", "mcp", "connect", "ui",\n'
                "})"),
            Substitution(
                _UMBRELLA_CLI,
                'TRUST_COMMANDS = frozenset({\n'
                '    "ready-status", "attest-review", "attest-evaluation", '
                '"policy",\n',
                'TRUST_COMMANDS = frozenset({\n'
                '    "check",\n'
                '    "ready-status", "attest-review", "attest-evaluation", '
                '"policy",\n'),
        ),
        expects=GuardFailure('AssertionError', (
            "'check': 'admissible_trust.cli'",
        )),
        kills="tests.compatibility.test_legacy_cli.ResolutionMatrix."
              "test_every_ready_command_resolves_to_the_ready_distribution",
    ),

    # -- SEP12: removing a guard kills one named test, and only that one ----
    Mutant(
        mutant_id="SEP12-package-guard-removed",
        sep="SEP12",
        shape="guard-removal-is-specifically-detected",
        summary="The Trust project's package enumeration admits the Ready "
                "namespace, and one named test -- not the whole suite -- says so.",
        edits=(
            Creation("packages/trust/src/admissible_ready/__init__.py",
                     _PLANTED),
            Substitution(
                _TRUST_PYPROJECT,
                _TRUST_PACKAGES_ANCHOR,
                'packages = ["admissible_trust", "admissible_ready"]\n'
                "\n"
                "[tool.setuptools.package-dir]\n"
                'admissible_trust = "src/admissible_trust"\n'
                'admissible_ready = "src/admissible_ready"\n'),
        ),
        expects=GuardFailure('AssertionError', (
            'admissible_ready/__init__.py',
            'the Trust wheel must not contain admissible_ready',
        )),
        kills="tests.architecture.test_distribution_separation."
              "TrustWheelIsolation.test_trust_does_not_ship_the_ready_namespace",
        control="tests.architecture.test_distribution_separation."
                "CoreWheelOwnership.test_core_ships_its_own_namespace",
    ),
    Mutant(
        mutant_id="SEP12-import-guard-removed",
        sep="SEP12",
        shape="guard-removal-is-specifically-detected",
        summary="A Ready module imports outside the allowed roots, and one "
                "named test -- not the whole suite -- says so.",
        edits=(Substitution(
            f"{_READY_SRC}/github.py",
            "from admissible_core.identity import normalize_remote\n",
            "from admissible_core.identity import normalize_remote\n"
            "from admissible_trust import review as trust_review_module\n"),),
        expects=GuardFailure('AssertionError', (
            'admissible_ready.github -> admissible_trust',
            'Ready may import the standard library and Core',
        )),
        kills="tests.ready.test_admissible_ready_isolation."
              "ReadySourceImportsCoreOnly.test_every_import_resolves_to_an_allowed_root",
        control="tests.ready.test_admissible_ready_isolation."
                "ReadySourceImportsCoreOnly."
                "test_the_ready_package_exists_and_ships_modules",
    ),
    Mutant(
        mutant_id="SEP12-credential-guard-removed",
        sep="SEP12",
        shape="guard-removal-is-specifically-detected",
        summary="A key id drops out of the closed credential list, so no "
                "Ready entry point refuses beside it any more -- and one "
                "named test, not the whole suite, says so.",
        edits=(Substitution(
            f"{_READY_SRC}/runner.py",
            '    "ADMISSIBLE_REVIEW_KEY_FILE",\n'
            '    "ADMISSIBLE_REVIEW_KEY_ID",\n',
            '    "ADMISSIBLE_REVIEW_KEY_FILE",\n'),),
        # Deliberately not the entry-point matrix. That matrix iterates the
        # very list this mutant shortens, so it would go on passing while the
        # hole was open: the test that notices is the one comparing the list to
        # the credentials the product documents.
        expects=GuardFailure('AssertionError', (
            "'ADMISSIBLE_REVIEW_KEY_ID'",
            'First list contains 1 additional elements',
        )),
        kills="tests.ready.test_admissible_ready_credentials."
              "CredentialMatrix."
              "test_the_matrix_covers_every_credential_the_product_documents",
        control="tests.ready.test_admissible_ready_credentials."
                "CredentialMatrix."
                "test_every_entry_point_refuses_every_credential_without_side_effects",
    ),
)


#: A mutation nothing is supposed to notice.  It exists so the harness's own
#: SURVIVED path is exercised: without it, a harness that reported every run as
#: a kill would look exactly like this one.
HARMLESS_MUTANT = Mutant(
    mutant_id="CONTROL-harmless-file",
    sep="SEP1",
    shape="trust-surface-placed-in-the-ready-wheel",
    summary="A file no distribution ships and no test reads.",
    edits=(Creation("SEPARATION_SABOTAGE_PROBE.txt",
                    "Written by the separation sabotage harness.\n"),),
    # Never consulted: this mutant exists to survive, and a signature is only
    # read on the way to a kill. It is written down anyway so that the shape of
    # a registry row stays the same whether or not anything is expected to
    # notice it.
    expects=GuardFailure("AssertionError", (
        "the Ready package ships no module at all",)),
    kills="tests.ready.test_admissible_ready_isolation."
          "ReadySourceImportsCoreOnly.test_the_ready_package_exists_and_ships_modules",
)


def mutants_for(sep: str) -> tuple[Mutant, ...]:
    """Every registered mutant that attacks ``sep``, in registry order."""

    return tuple(mutant for mutant in MUTANTS if mutant.sep == sep)


def killing_tests() -> tuple[str, ...]:
    """Every distinct named test the registry depends on, sorted."""

    names = {mutant.kills for mutant in MUTANTS}
    names |= {mutant.control for mutant in MUTANTS if mutant.control}
    return tuple(sorted(names))


# ---------------------------------------------------------------------------
# The tree: what a clone contains, and what "unchanged" means.

#: Directories never copied and never digested.  Build output, caches and
#: virtual environments are derived, so including them would make the digest a
#: function of what has been run rather than of what is in the tree.
IGNORED_DIRECTORY_NAMES = frozenset({
    ".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist",
    "coverage", "_staged", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", "raw", "secrets", ".hypothesis",
    # eval/realdefects fetches third-party source and clones a bug corpus
    # beside its scripts; both are gitignored, and the walk must agree with
    # git or the source-list check fails for anyone who reproduces the study.
    "srccache", "bugsinpy",
})

#: Files never copied and never digested, by exact name or by suffix.
#:
#: ``.git`` is here as well as in the directory set because this checkout is a
#: git *worktree*, where ``.git`` is a file pointing back at the real
#: repository.  Copying it would give every clone a link to the live object
#: store, and a mutant running there would be one ``git`` invocation away from
#: the tree this harness exists to leave alone.
IGNORED_FILE_NAMES = frozenset({".git", ".DS_Store", "_staged.lock", ".env"})
IGNORED_FILE_SUFFIXES = (".pyc", ".pyo", ".sqlite", ".jsonl", ".egg-link")


def _is_ignored_directory(name: str) -> bool:
    return name in IGNORED_DIRECTORY_NAMES or name.endswith(".egg-info")


def source_files(root: Path) -> tuple[str, ...]:
    """Every source file under ``root``, as sorted POSIX-relative paths.

    Deliberately computed by walking rather than by asking Git: a disposable
    clone is not a repository, and the two answers have to be comparable for
    "the clone is complete" to be a property this suite can assert.
    """

    root = Path(root)
    found: list[str] = []
    for current, directories, filenames in os.walk(root):
        directories[:] = sorted(
            name for name in directories if not _is_ignored_directory(name))
        base = Path(current)
        for name in sorted(filenames):
            if name in IGNORED_FILE_NAMES:
                continue
            if name.endswith(IGNORED_FILE_SUFFIXES):
                continue
            path = base / name
            if path.is_symlink() or not path.is_file():
                continue
            found.append(path.relative_to(root).as_posix())
    return tuple(sorted(found))


def worktree_digest(root: Path) -> str:
    """One digest over every source path and its bytes under ``root``."""

    root = Path(root)
    running = hashlib.sha256()
    for relative in source_files(root):
        running.update(relative.encode("utf-8"))
        running.update(b"\0")
        running.update(hashlib.sha256((root / relative).read_bytes()).digest())
    return running.hexdigest()


_WORKSPACES: list[Path] = []


def _discard(path: Path) -> None:
    """Remove a directory this harness made, sealed or not.

    The observer's directory is read-only while it runs, and a read-only
    directory is one nothing inside it can be unlinked from.  Removing it means
    unsealing it first, which is this function's whole reason for existing.
    """

    with contextlib.suppress(OSError):
        path.chmod(0o700)
        for child in path.rglob("*"):
            with contextlib.suppress(OSError):
                child.chmod(0o600 if child.is_file() else 0o700)
    shutil.rmtree(path, ignore_errors=True)


def _initialise_repository(clone: Path, *,
                           private_root: Path | None = None) -> None:
    """Give the clone a repository of its own, with nothing in it.

    ``packages/core/build_backend`` refuses to stage the shared research roots
    unless the directory above it is a checkout, and ``.git`` existing is one
    of the clauses it asks about.  Copying this worktree's ``.git`` would
    answer that clause by handing every clone a link to the live object store,
    so the clone gets a freshly initialised, empty, remote-less repository
    instead: the same answer, with nothing on the other end of it.
    """

    try:
        command = network_denied_command(
            ("git", "init", "--quiet", "--initial-branch=main", str(clone)))
    except IsolationUnavailable as error:
        raise MutationError(str(error)) from error
    completed = subprocess.run(
        command, capture_output=True, timeout=120,
        env=scrubbed_environment(private_root=private_root))
    if completed.returncode != 0:
        raise MutationError(
            "the clone could not be given a repository of its own: "
            + completed.stderr.decode("utf-8", "replace").strip())


@contextlib.contextmanager
def disposable_clone(root: Path):
    """A complete copy of ``root``'s sources in a temporary directory.

    The copy is removed on the way out, on every path including an exception,
    and its path is recorded so :func:`orphaned_workspaces` can prove that
    nothing was left behind.
    """

    root = Path(root)
    workspace = Path(tempfile.mkdtemp(prefix=WORKSPACE_PREFIX))
    _WORKSPACES.append(workspace)
    clone = workspace / "checkout"
    try:
        for relative in source_files(root):
            target = clone / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, target)
        # The private world a mutant runs in lives beside the checkout rather
        # than inside it, so nothing a mutant writes to `~` can change the
        # tree it is being judged against -- and both go when the workspace
        # does.
        make_private_root(workspace)
        _initialise_repository(clone, private_root=workspace)
        yield clone
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
        if workspace in _WORKSPACES:
            _WORKSPACES.remove(workspace)


def orphaned_workspaces() -> list[str]:
    """Any clone workspace this process created and did not remove."""

    return sorted(str(path) for path in _WORKSPACES if path.exists())


@atexit.register
def _remove_any_remaining_workspace() -> None:
    """Last resort: a clone must not outlive the process that made it.

    ``disposable_clone`` already removes its own workspace on every ordinary
    path.  This covers the ones that are not ordinary -- an unhandled
    exception torn down between the copy and the ``yield``, or an interpreter
    exiting from somewhere the context manager never resumed -- because a
    forgotten clone is a directory with a sabotaged copy of this product in
    it, and nothing labels it as one.
    """

    for workspace in list(_WORKSPACES):
        _discard(workspace)
    _WORKSPACES.clear()
    for private in list(_PRIVATE_ROOTS):
        _discard(private)
    _PRIVATE_ROOTS.clear()


# ---------------------------------------------------------------------------
# The environment a mutant runs in.
#
# A mutant is arbitrary code.  It is a build backend, a test module and a
# product source file that this harness has deliberately broken, and it runs
# with whatever the harness hands it.  So what it is handed is an allowlist:
# the child's environment is built from nothing and the harness names every
# variable in it, rather than started from this developer's environment and
# pruned.  A denylist is the wrong shape for the question, because the names it
# does not know about are exactly the ones nobody thought of -- ``NETRC``,
# ``KUBECONFIG``, ``GNUPGHOME``, the next tool's -- and, most of all, ``HOME``,
# which is not a credential itself but is where every credential lives.

#: Ambient variables a child inherits, by name.
#:
#: Empty on POSIX.  Nothing at all is carried over: ``PATH`` is rebuilt below
#: from fixed system directories, so not one value from the calling shell
#: reaches a mutant.  Windows cannot be run that way -- a process there needs
#: ``SystemRoot`` before it can open a socket or spawn a child, and its ``PATH``
#: cannot be synthesised -- so the names it genuinely cannot do without are
#: written down here instead of assumed.
INHERITED_NAMES: tuple[str, ...] = () if os.name == "posix" else (
    "SYSTEMROOT", "COMSPEC", "PATHEXT", "WINDIR", "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE", "PATH",
)

#: The only names :func:`scrubbed_environment` will accept from a caller.
#:
#: ``extra`` exists so the harness can pass its own settings to its own child.
#: It is not a hole through which ``HOME``, a proxy, a token or an import path
#: can be put back, so it is a closed list of two harness-owned knobs whose
#: values are validated as well as their names.
EXTRA_ALLOWED = frozenset({"PYTHONWARNINGS", "SOURCE_DATE_EPOCH"})

#: An accepted ``extra`` value: printable, bounded, single-line.  A newline
#: would let one setting smuggle in a second one on some readers.
_EXTRA_VALUE = re.compile(r"[ -~]{0,200}")

#: Names the contract test checks by hand.  Under an allowlist their absence is
#: structural rather than pattern-matched, which is the point: the list is kept
#: so that a future change back towards inheritance fails here first.
SCRUBBED_EXAMPLES = (
    "ADMISSIBLE_HMAC_KEY", "ADMISSIBLE_HMAC_KEY_ID", "ADMISSIBLE_REVIEW_KEY",
    "ADMISSIBLE_REVIEW_KEYRING", "ADMISSIBLE_EVALUATION_KEY",
    "ADMISSIBLE_EVALUATION_KEYRING", "ADMISSIBLE_HOME", "GITHUB_TOKEN",
    "GH_TOKEN", "GIT_DIR", "GIT_WORK_TREE", "PYTHONPATH", "https_proxy",
    "NETRC", "KUBECONFIG", "GNUPGHOME", "CLOUDSDK_CONFIG",
    "REQUESTS_CA_BUNDLE", "SSH_AUTH_SOCK", "PYTHONSTARTUP",
)

#: The private world each child gets, relative to its own disposable root.
_PRIVATE_DIRECTORIES = (
    "home", "home/.config", "home/.cache", "home/.cache/pip",
    "home/.local/share", "home/.local/state", "tmp", "run",
)

#: The fixed system directories a child's ``PATH`` is built from, so that no
#: shim, version manager or user ``bin`` directory from the calling shell can
#: decide which ``git`` -- or which anything -- a mutant runs.
_SYSTEM_PATH = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")

#: A program that exists to fail.  Git and ssh run it when they want to ask a
#: human for a password, and a mutant must get a refusal rather than a prompt.
#: Resolved against the fixed directories above rather than by asking the
#: calling shell's ``PATH``, which is the thing none of this trusts.  Where
#: there is no such program the name is passed through unresolved: failing to
#: start is the same refusal by a shorter route.
_REFUSING_PROGRAM = next(
    (f"{directory}/false" for directory in _SYSTEM_PATH
     if Path(f"{directory}/false").is_file()), "false")


def _harness_path() -> str:
    """A ``PATH`` built from fixed directories, plus this interpreter's own."""

    if os.name != "posix":  # pragma: no cover - not this platform
        return os.environ.get("PATH", os.defpath)
    directories: list[str] = []
    candidates = [entry for entry in os.defpath.split(os.pathsep) if entry]
    candidates.extend(_SYSTEM_PATH)
    candidates.append(str(Path(sys.executable).resolve().parent))
    for candidate in candidates:
        if candidate not in directories:
            directories.append(candidate)
    return os.pathsep.join(directories)


def make_private_root(base: Path) -> Path:
    """Create the synthetic home, config, cache and temp roots under ``base``."""

    base = Path(base)
    for relative in _PRIVATE_DIRECTORIES:
        (base / relative).mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        (base / "run").chmod(0o700)
    return base


def _forced_environment(private: Path) -> dict[str, str]:
    """Every variable the harness sets, and the only ones a child will have."""

    home = private / "home"
    temporary = private / "tmp"
    return {
        "PATH": _harness_path(),
        # A home of its own. Nothing a mutant reads through `~` is this
        # developer's, and nothing it writes there survives the workspace.
        "HOME": str(home),
        "USERPROFILE": str(home),
        "LOGNAME": "admissible-sabotage",
        "USER": "admissible-sabotage",
        "TMPDIR": str(temporary),
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "XDG_STATE_HOME": str(home / ".local/state"),
        "XDG_RUNTIME_DIR": str(private / "run"),
        "APPDATA": str(home / ".config"),
        "LOCALAPPDATA": str(home / ".local/share"),
        # Git: no system config, no global config, no credential helper, no
        # prompt, and no transport that leaves this filesystem.
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "3",
        "GIT_CONFIG_KEY_0": "credential.helper",
        "GIT_CONFIG_VALUE_0": "",
        "GIT_CONFIG_KEY_1": "user.name",
        "GIT_CONFIG_VALUE_1": "Admissible Sabotage Harness",
        "GIT_CONFIG_KEY_2": "user.email",
        "GIT_CONFIG_VALUE_2": "sabotage@harness.invalid",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_ASKPASS": _REFUSING_PROGRAM,
        "SSH_ASKPASS": _REFUSING_PROGRAM,
        # Python: no user site, no user configuration, no inherited import
        # path, and no bytecode written beside a mutated source.
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        # pip: no index, no prompt, no user install, no configuration file.
        "PIP_NO_INDEX": "1",
        "PIP_NO_INPUT": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_USER": "0",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_RETRIES": "0",
        "PIP_TIMEOUT": "1",
        "PIP_CACHE_DIR": str(home / ".cache/pip"),
        # No proxy is inherited, and none may be introduced.
        "no_proxy": "*",
        "NO_PROXY": "*",
    }


#: Exactly the names :func:`_forced_environment` sets, so the contract test can
#: assert that a child's environment is the harness's and nothing else.
FORCED_ENVIRONMENT_NAMES: tuple[str, ...] = tuple(
    sorted(_forced_environment(Path(os.devnull))))

_DEFAULT_PRIVATE_ROOT: Path | None = None
_PRIVATE_ROOTS: list[Path] = []


def _default_private_root() -> Path:
    """One private world for callers that have no workspace of their own."""

    global _DEFAULT_PRIVATE_ROOT
    if _DEFAULT_PRIVATE_ROOT is None or not _DEFAULT_PRIVATE_ROOT.is_dir():
        created = Path(tempfile.mkdtemp(prefix=f"{WORKSPACE_PREFIX}private-"))
        _PRIVATE_ROOTS.append(created)
        _DEFAULT_PRIVATE_ROOT = make_private_root(created)
    return _DEFAULT_PRIVATE_ROOT


def scrubbed_environment(extra: dict[str, str] | None = None, *,
                         private_root: Path | None = None) -> dict[str, str]:
    """The whole environment a child gets: an allowlist, built from nothing.

    ``private_root`` is the disposable directory the child's home, cache and
    temporary roots are made inside.  Callers running a mutant pass the
    workspace that will be deleted afterwards; callers that only need a clean
    environment get a private root of this process's own.
    """

    private = (make_private_root(private_root) if private_root is not None
               else _default_private_root())
    environment = {name: os.environ[name] for name in INHERITED_NAMES
                   if name in os.environ}
    environment.update(_forced_environment(private))
    for name, value in (extra or {}).items():
        if name not in EXTRA_ALLOWED:
            raise MutationError(
                f"{name} is not a harness-owned setting; the child environment "
                f"is an allowlist and only {sorted(EXTRA_ALLOWED)} may be "
                "added to it")
        if not isinstance(value, str) or _EXTRA_VALUE.fullmatch(value) is None:
            raise MutationError(
                f"{name} was given a value this harness will not pass on; a "
                "setting must be printable, single-line and under 200 "
                "characters")
        environment[name] = value
    return environment


# ---------------------------------------------------------------------------
# The network a mutant does not get.

class IsolationUnavailable(RuntimeError):
    """This platform offers no boundary the harness is willing to claim."""


#: The sandbox profile every child runs under: everything as usual, except
#: that no socket may be opened.  Denying the syscall is the point -- a mutated
#: build backend can spawn a non-Python client, so a monkeypatched
#: :mod:`socket` inside one interpreter would prove nothing about the process
#: tree underneath it.
NETWORK_PROFILE = "(version 1)(allow default)(deny network*)"

_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")

#: What the harness expects a refused socket to look like from inside.  A
#: connection that is merely *refused* or that times out is the network
#: answering, not the boundary; only a permission error is the kernel saying
#: the call was never made.
_DENIED_ERRNO = ("EPERM", "EACCES")

_DENIAL_PROBE = (
    "import errno, socket, sys\n"
    "probe = socket.socket()\n"
    "probe.settimeout(5)\n"
    "try:\n"
    "    probe.connect(('127.0.0.1', 9))\n"
    "    sys.stdout.write('CONNECTED')\n"
    "except OSError as error:\n"
    "    sys.stdout.write(errno.errorcode.get(error.errno, 'NO_ERRNO'))\n"
    "finally:\n"
    "    probe.close()\n"
)

#: The same question one process deeper.  The harness starts the observer
#: inside the boundary and the observer starts the test process, so what has to
#: be refused a socket is the *grandchild* -- and "the boundary is inherited"
#: is exactly the kind of platform behaviour that is true until it is not.
_NESTED_DENIAL_PROBE = (
    "import subprocess, sys\n"
    "answer = subprocess.run([sys.executable, '-I', '-c', %r],\n"
    "                        capture_output=True, timeout=60)\n"
    "sys.stdout.write(answer.stdout.decode('utf-8', 'replace'))\n"
) % _DENIAL_PROBE

#: Each depth a mutant's process tree reaches, and what to call it in a receipt.
_DENIAL_DEPTHS = (
    ("the process this harness starts", _DENIAL_PROBE),
    ("the process that one starts in turn", _NESTED_DENIAL_PROBE),
)


#: Names the boundary program itself puts into a child's environment.
#:
#: ``sandbox-exec`` is a CoreFoundation program, and it hands whatever it
#: launches a locale and a text-encoding hint of its own.  They are not carried
#: over from the caller -- the contract test proves that by seeding the
#: caller's copies with a marker value that never arrives -- but they are in
#: the child, so they are named here rather than quietly tolerated by a test
#: that would otherwise be asserting "the harness owns every variable".
BOUNDARY_ADDED_NAMES: tuple[str, ...] = (
    ("LC_CTYPE", "__CF_USER_TEXT_ENCODING") if sys.platform == "darwin"
    else ())


def network_boundary() -> str:
    """The name of the boundary this platform can actually enforce, or ``""``."""

    if (sys.platform == "darwin" and _SANDBOX_EXEC.is_file()
            and os.access(_SANDBOX_EXEC, os.X_OK)):
        return "sandbox-exec"
    return ""


def network_denied_command(command) -> list[str]:
    """``command``, wrapped so that it cannot open a socket."""

    if network_boundary() != "sandbox-exec":
        raise IsolationUnavailable(
            f"no verified network boundary on {sys.platform}: this harness "
            "runs mutated build backends and mutated tests, and it will not "
            "claim an isolation it cannot enforce")
    return [str(_SANDBOX_EXEC), "-p", NETWORK_PROFILE, *map(str, command)]


_DENIAL_PROBLEM: str | None = None


def network_denial_problem() -> str:
    """``""`` if a socket really is refused inside the boundary, else why not.

    Asked once per process and remembered.  The claim being checked is not
    "the wrapper is installed" but "a socket opened inside it fails with a
    permission error", which is the only form of the claim that a mutant
    cannot be affected by and a reader cannot take on trust.  It is asked at
    both depths a run reaches, because the process that actually runs the
    mutated tests is a grandchild of the boundary and an isolation that stops
    at the first generation would leave it outside.
    """

    global _DENIAL_PROBLEM
    if _DENIAL_PROBLEM is not None:
        return _DENIAL_PROBLEM
    for depth, probe in _DENIAL_DEPTHS:
        try:
            command = network_denied_command([sys.executable, "-I", "-c",
                                              probe])
        except IsolationUnavailable as error:
            _DENIAL_PROBLEM = str(error)
            return _DENIAL_PROBLEM
        try:
            completed = subprocess.run(command, capture_output=True,
                                       timeout=120,
                                       env=scrubbed_environment())
        except (OSError, subprocess.SubprocessError) as error:
            _DENIAL_PROBLEM = (f"the network boundary could not be started: "
                               f"{error}")
            return _DENIAL_PROBLEM
        answer = completed.stdout.decode("utf-8", "replace").strip()
        if answer not in _DENIED_ERRNO:
            _DENIAL_PROBLEM = (
                f"{network_boundary()} did not refuse a loopback socket to "
                f"{depth}; the probe reported {answer or 'nothing'} instead of "
                f"one of {_DENIED_ERRNO}")
            return _DENIAL_PROBLEM
    _DENIAL_PROBLEM = ""
    return _DENIAL_PROBLEM


# ---------------------------------------------------------------------------
# Running one named test, and judging what came back.
#
# Two things are wrong with reading a run's exit status.  The obvious one is
# that ``python -m unittest`` exits non-zero for a module that will not import,
# a fixture that raises, a test that dies of an unrelated exception and a test
# that fails an assertion about something else -- and for the guard actually
# catching the sabotage.  Read as one bit those five are the same answer, and
# four of them are a harness reporting a kill it did not see.
#
# The subtler one is who is talking.  The account has to say which test failed
# and with what message, and that only exists inside the process running the
# test -- which is the process running code this harness deliberately broke.
# So the account is produced there and *delivered* from somewhere else: the
# tested process writes one record frame on its own stdout and is given nothing
# else -- no descriptor on the parent's channel, no key, no nonce, no path, and
# an argv that is the test ids and nothing more -- while a trusted observer
# outside the disposable clone watches it from the far side of that boundary
# and authenticates what it saw to this process.  The protocol, and the honest
# limits of what it proves, are in :mod:`tests.architecture.separation_observer`.

PASSED_STATUS = "passed"
FAILED_STATUS = "failed"
ERRORED_STATUS = "errored"
SKIPPED_STATUS = "skipped"

#: Every status a record may carry, shared with the observer so that the two
#: halves of the protocol cannot drift into disagreeing about what a result is.
STATUSES = separation_observer.STATUSES

#: How much of one failure message is carried back.  Bounded so that a mutant
#: cannot make the report unreadable, or unwritable, by failing very loudly.
MESSAGE_LIMIT = 4000

#: How many individual results one run may report.  A subtest loop can produce
#: dozens; a mutation that broke every one of them must not be able to turn the
#: report into something this process has to hold all of.  A run that reaches
#: the limit says so, and saying so is an error: a truncated account is not the
#: account of what happened.
RECORD_LIMIT = 200

#: The observer this harness runs, the frame format it signs with, and how long
#: after the child's own deadline the parent waits for it to say something.
OBSERVER_SOURCE = REPO_ROOT / "tests" / "architecture" / "separation_observer.py"
FRAME_VERSION = separation_observer.FRAME_VERSION
OBSERVER_GRACE_SECONDS = 120

#: The most the observer channel will be read.  The observer writes one bounded
#: frame; anything beyond this is not a frame.
CHANNEL_LIMIT = 8 * 1024 * 1024

#: The marker introducing the child's one record frame.
#:
#: Assembled rather than written out, so the literal appears in no source file
#: of this checkout: a guard test that prints a source file must not be able to
#: look like a record frame by accident.  It is not a secret and nothing rests
#: on it being one -- the forgery probes are handed it deliberately.  What makes
#: a forged frame useless is that the observer accepts exactly one.
RECORD_MARKER = "<<<ADMISSIBLE-" + "SEPARATION-RECORD" + ">>>"

#: The child that runs the named tests and writes down what each of them did.
#: Passed with ``-c``, so there is no file to plant in the clone, nothing for
#: the digest of the mutated tree to notice, and no path in argv.
#:
#: Everything the recorder needs is captured before a single line of the clone
#: is imported, and passed into a function rather than left in ``__main__``:
#: the write and exit primitives, the encoders, the loader, the runner and the
#: unbound result methods it delegates to.  Replacing ``json``, ``open``,
#: ``sys.stdout``, ``unittest``'s result classes or the methods on them
#: therefore changes what the tested code sees and not what is recorded.  The
#: run ends with the captured ``os._exit``, so nothing registered on the way out
#: -- an ``atexit`` hook above all -- runs after the frame is written.
_REPORT_RUNNER = r'''
import base64
import json
import os
import sys
import unittest

_CAPTURED = (
    os.write, os._exit, json.dumps, base64.b64encode,
    unittest.TestLoader, unittest.TextTestRunner, unittest.TextTestResult,
    unittest.TextTestResult.addSuccess, unittest.TextTestResult.addFailure,
    unittest.TextTestResult.addError, unittest.TextTestResult.addSkip,
    unittest.TextTestResult.addExpectedFailure,
    unittest.TextTestResult.addUnexpectedSuccess,
    unittest.TextTestResult.addSubTest, sys.stderr, sys.argv[1:],
)


def _run(captured):
    (write, leave, dumps, encode, loader, runner, result_class, base_success,
     base_failure, base_error, base_skip, base_expected, base_unexpected,
     base_subtest, stream, requested) = captured
    marker = %(marker)r
    message_limit, record_limit = %(message_limit)d, %(record_limit)d
    records, truncated = [], []

    def text(value, limit=message_limit):
        try:
            return str(value)[:limit]
        except BaseException:
            return "<unreadable>"

    def note(test, status, error=None, subtest=None):
        if len(records) >= record_limit:
            truncated.append(status)
            return
        entry = {"test": text(test.id(), 500), "status": status,
                 "exception": "", "message": "",
                 "subtest": "" if subtest is None else text(subtest, 500)}
        if error is not None:
            try:
                entry["exception"] = text(error[0].__name__, 200)
            except BaseException:
                entry["exception"] = "<unreadable>"
            entry["message"] = text(error[1])
        records.append(entry)

    class Recorder(result_class):
        def addSuccess(self, test):
            base_success(self, test)
            note(test, "passed")

        def addFailure(self, test, err):
            base_failure(self, test, err)
            note(test, "failed", err)

        def addError(self, test, err):
            base_error(self, test, err)
            note(test, "errored", err)

        def addSkip(self, test, reason):
            base_skip(self, test, reason)
            note(test, "skipped")

        def addExpectedFailure(self, test, err):
            base_expected(self, test, err)
            note(test, "errored", err)

        def addUnexpectedSuccess(self, test):
            base_unexpected(self, test)
            note(test, "errored")

        def addSubTest(self, test, subtest, err):
            base_subtest(self, test, subtest, err)
            if err is None:
                return
            status = ("failed" if issubclass(err[0], test.failureException)
                      else "errored")
            note(test, status, err, subtest)

    ran, successful, crashed = 0, False, ""
    try:
        result = runner(verbosity=2, resultclass=Recorder, stream=stream).run(
            loader().loadTestsFromNames(requested))
        ran, successful = result.testsRun, bool(result.wasSuccessful())
    except BaseException as error:
        crashed = text(type(error).__name__, 200) + ": " + text(error)
    try:
        payload = dumps({"ran": ran, "successful": successful,
                         "records": records, "truncated": bool(truncated),
                         "crashed": crashed})
    except BaseException:
        payload = ('{"ran": 0, "successful": false, "records": [], '
                   '"truncated": false, "crashed": "the recorder could not '
                   'write down what it saw"}')
    write(1, marker.encode("ascii") + b" " + encode(payload.encode("utf-8"))
          + b"\n")
    leave(0 if successful else 1)


del base64, json, os, sys, unittest
_run(_CAPTURED)
''' % {"marker": RECORD_MARKER, "message_limit": MESSAGE_LIMIT,
       "record_limit": RECORD_LIMIT}


@dataclass(frozen=True)
class TestRecord:
    """What one named test, or one subtest of it, did."""

    test: str
    status: str
    exception: str = ""
    message: str = ""
    subtest: str = ""

    def describe(self) -> str:
        where = f"{self.test}[{self.subtest}]" if self.subtest else self.test
        if self.exception:
            first = self.message.strip().splitlines()[:1]
            return (f"{where}: {self.status} with {self.exception}"
                    + (f": {first[0][:200]}" if first else ""))
        return f"{where}: {self.status}"


@dataclass(frozen=True)
class Outcome:
    """What one run of the named tests did, as the observer reported it."""

    returncode: int | None
    ran: int
    detail: str
    timed_out: bool = False
    records: tuple[TestRecord, ...] = ()
    reported: bool = False
    problem: str = ""

    def for_test(self, dotted: str) -> tuple[TestRecord, ...]:
        return tuple(item for item in self.records if item.test == dotted)

    def strays(self, dotted: str) -> tuple[TestRecord, ...]:
        return tuple(item for item in self.records if item.test != dotted)

    def summary(self) -> str:
        return "; ".join(item.describe() for item in self.records[:8]) or "-"


# ---------------------------------------------------------------------------
# The channel the tested process has no way to reach.

sealed_frame = separation_observer.sealed_frame


def new_channel_secret() -> tuple[bytes, str]:
    """One run's authentication key and its nonce, used for nothing else."""

    return secrets.token_bytes(32), secrets.token_hex(16)


def report_from_frame(data: bytes, key: bytes,
                      nonce: str) -> tuple[dict | None, str]:
    """The one report this run's observer signed, or why these bytes are not it.

    Everything here fails closed.  A channel that carried nothing, that carried
    a second frame, that carried a frame signed with another key or naming
    another run is not a report about this run, and the difference between
    "could not be authenticated" and "says the guard caught it" must never be
    resolved in favour of the second.
    """

    lines = [line for line in bytes(data).split(b"\n") if line.strip()]
    if not lines:
        return None, ("the observer wrote no authenticated report, so nothing "
                      "this run did can be judged")
    if len(lines) != 1:
        return None, (f"the observer channel carried more than one frame "
                      f"({len(lines)}), and exactly one is the protocol")
    fields = lines[0].split(b" ")
    if len(fields) != 4:
        return None, ("the observer frame is malformed: expected four fields, "
                      f"found {len(fields)}")
    version, seen, signature, body = fields
    if version != FRAME_VERSION.encode("ascii"):
        return None, f"the observer frame does not announce {FRAME_VERSION}"
    if not hmac.compare_digest(seen, nonce.encode("ascii")):
        return None, "the observer frame carries another run's nonce"
    expected = hmac.new(key, seen + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature.decode("ascii", "replace"), expected):
        return None, ("the observer frame is not authentic; only this run's "
                      "observer holds the key that signs one")
    try:
        report = json.loads(base64.b64decode(body, validate=True))
    except (ValueError, binascii.Error) as error:
        return None, f"the observer frame could not be read: {error}"
    if not isinstance(report, dict):
        return None, "the observer frame does not carry a report"
    if report.get("nonce") != nonce:
        return None, "the observer frame is not this run's report"
    return report, ""


@contextlib.contextmanager
def _sealed_observer():
    """A copy of the observer, outside the clone and read-only while it runs.

    The observer is the half of the protocol the tested code must not be able
    to edit, so it is never run from the tree under test.  It is copied out to
    a directory of its own, sealed, executed with ``-I`` -- no environment, no
    user site, no importable siblings -- and removed afterwards.
    """

    directory = Path(tempfile.mkdtemp(prefix=f"{WORKSPACE_PREFIX}observer-"))
    _PRIVATE_ROOTS.append(directory)
    script = directory / OBSERVER_SOURCE.name
    try:
        shutil.copyfile(OBSERVER_SOURCE, script)
        with contextlib.suppress(OSError):
            script.chmod(0o500)
            directory.chmod(0o500)
        yield directory, script
    finally:
        _discard(directory)
        if directory in _PRIVATE_ROOTS:
            _PRIVATE_ROOTS.remove(directory)


def _drain(read_fd: int, into: bytearray) -> None:
    """Read the observer's channel to its end, so no writer can ever block."""

    with os.fdopen(read_fd, "rb", closefd=True) as handle:
        while len(into) < CHANNEL_LIMIT:
            chunk = handle.read(65536)
            if not chunk:
                return
            into.extend(chunk)


def _tail_of(text: str) -> str:
    return " | ".join(line.strip() for line in text.strip().splitlines()[-4:]
                      if line.strip())[:1000]


def _outcome_from(report: dict, tail: str) -> Outcome:
    """One observed report, as the verdict rules read it."""

    if report.get("problem"):
        return Outcome(report.get("returncode"), int(report.get("ran") or 0),
                       report.get("tail") or tail,
                       timed_out=bool(report.get("timed_out")),
                       problem=str(report["problem"]))
    records = []
    for row in report.get("records", ()):
        if row.get("status") not in STATUSES:
            problem = "the observer reported a result that is not a status"
            return Outcome(None, 0, tail, problem=problem)
        records.append(TestRecord(
            test=str(row.get("test", "")), status=str(row["status"]),
            exception=str(row.get("exception", "")),
            message=str(row.get("message", "")),
            subtest=str(row.get("subtest", ""))))
    return Outcome(report.get("returncode"), int(report.get("ran") or 0),
                   report.get("tail") or tail, records=tuple(records),
                   reported=True)


def _observed_run(config: dict, key: bytes, nonce: str,
                  environment: dict[str, str], timeout: int) -> Outcome:
    """Start the observer, hand it the run, and read back the one frame."""

    with _sealed_observer() as (directory, script):
        read_fd, write_fd = os.pipe()
        os.set_inheritable(write_fd, True)
        collected = bytearray()
        reading = False
        try:
            try:
                command = network_denied_command(
                    [sys.executable, "-I", str(script), str(write_fd)])
            except IsolationUnavailable as error:
                return Outcome(None, 0, str(error), problem=str(error))
            try:
                process = subprocess.Popen(
                    command, cwd=str(directory), env=environment,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, pass_fds=(write_fd,))
            except (OSError, subprocess.SubprocessError) as error:
                detail = f"the observer could not be started: {error}"
                return Outcome(None, 0, detail, problem=detail)
            finally:
                os.close(write_fd)
            reader = threading.Thread(target=_drain,
                                      args=(read_fd, collected), daemon=True)
            reader.start()
            reading = True
            deadline = timeout + OBSERVER_GRACE_SECONDS
            hung = False
            try:
                _out, err = process.communicate(
                    json.dumps(config).encode("utf-8"), timeout=deadline)
            except subprocess.TimeoutExpired:
                process.kill()
                _out, err = process.communicate()
                hung = True
            reader.join(30)
        finally:
            if not reading:
                os.close(read_fd)
        tail = _tail_of(err.decode("utf-8", "replace"))
        if hung:
            problem = (f"the observer gave no answer inside {deadline}s, so "
                       "the run it was watching cannot be judged")
            return Outcome(None, 0, tail, timed_out=True, problem=problem)
        report, problem = report_from_frame(bytes(collected), key, nonce)
        if problem:
            return Outcome(None, 0, tail,
                           problem=f"{problem}: {tail or 'no output'}")
        if process.returncode != 0:
            problem = (f"the observer exited {process.returncode} after "
                       f"signing a report: {tail or 'no output'}")
            return Outcome(None, 0, tail, problem=problem)
        return _outcome_from(report, tail)


def run_named_tests(root: Path, test_ids, *,
                    timeout: int = TEST_TIMEOUT_SECONDS,
                    private_root: Path | None = None) -> Outcome:
    """Run exactly these test ids inside ``root`` and report what happened.

    The observer and the test process both run behind this platform's network
    boundary and inside a private environment built from an allowlist.  If
    there is no boundary to put them behind, nothing is run at all: an
    unenforced claim of isolation is worse than a refusal, because everything
    downstream reads it as enforced.
    """

    test_ids = [str(item) for item in test_ids]
    denial = network_denial_problem()
    if denial:
        return Outcome(None, 0, denial, problem=denial)
    scratch = None
    if private_root is None:
        scratch = Path(tempfile.mkdtemp(prefix=f"{WORKSPACE_PREFIX}private-"))
        _PRIVATE_ROOTS.append(scratch)
    private = make_private_root(scratch if scratch is not None else private_root)
    try:
        try:
            environment = scrubbed_environment(private_root=private)
        except MutationError as error:
            return Outcome(None, 0, str(error), problem=str(error))
        key, nonce = new_channel_secret()
        # Everything the observer needs, on a channel the tested process is
        # not on: the key and the nonce travel down the observer's standard
        # input, never through an environment or an argument list.
        config = {
            "version": FRAME_VERSION,
            "nonce": nonce,
            "key": key.hex(),
            "marker": RECORD_MARKER,
            "runner": _REPORT_RUNNER,
            "executable": sys.executable,
            "tests": test_ids,
            "cwd": str(root),
            "environment": environment,
            "timeout": timeout,
            "record_limit": RECORD_LIMIT,
        }
        return _observed_run(config, key, nonce, environment, timeout)
    finally:
        if scratch is not None:
            _discard(scratch)
            if scratch in _PRIVATE_ROOTS:
                _PRIVATE_ROOTS.remove(scratch)


@dataclass(frozen=True)
class Receipt:
    """One mutant's verdict, with enough detail to act on it."""

    mutant_id: str
    sep: str
    shape: str
    verdict: str
    kills: str
    detail: str
    control: str | None = None

    @property
    def ok(self) -> bool:
        return self.verdict in (KILLED, PASSED)


def _receipt(mutant: Mutant, verdict: str, detail: str) -> Receipt:
    return Receipt(mutant_id=mutant.mutant_id, sep=mutant.sep,
                   shape=mutant.shape, verdict=verdict, kills=mutant.kills,
                   detail=detail, control=mutant.control)


def judge(mutant: Mutant, outcome: Outcome) -> tuple[str, str]:
    """Turn one run of ``mutant.kills`` into a verdict and a reason.

    Separated from :func:`evaluate` so that the rules can be read, and tested,
    without building a clone for every one of them.  The order matters: every
    way of not reaching the guard's assertion is answered before the two ways
    of reaching it, because each of those ways otherwise looks exactly like a
    kill from the outside.

    A kill is the *complete* registered outcome and not a matching record
    inside a larger one: this test and no other, nothing errored, nothing
    skipped, nothing passed, and exactly the registered failures, every one of
    them a signature this mutant wrote down before it ran.  A run carrying one
    intended failure and one unrelated one is the run a mutation that broke
    something else produces, and it is an error.
    """

    if outcome.timed_out:
        return ERROR, f"{mutant.kills} gave no answer: {outcome.detail}"
    if outcome.problem:
        return ERROR, f"{mutant.kills} could not be judged: {outcome.problem}"
    if not outcome.reported:
        return ERROR, (f"{mutant.kills} produced no structured report: "
                       f"{outcome.detail}")
    strays = outcome.strays(mutant.kills)
    if strays:
        return ERROR, (
            f"the run reported {len(strays)} result(s) for a test other than "
            f"{mutant.kills}, so what came back is not this test's outcome: "
            f"{strays[0].describe()}")
    named = outcome.for_test(mutant.kills)
    if not named:
        return ERROR, (
            f"{mutant.kills} did not run as itself -- a module that will not "
            f"import or a name that no longer resolves exits non-zero without "
            f"reaching any assertion. The run reported: {outcome.summary()}")
    if outcome.ran != 1:
        return ERROR, (f"{mutant.kills} did not run as exactly one test "
                       f"(ran {outcome.ran}): {outcome.detail}")
    errored = [item for item in named if item.status == ERRORED_STATUS]
    if errored:
        return ERROR, (
            f"{mutant.kills} errored rather than failing, so its assertion "
            f"never ran: {errored[0].describe()}")
    skipped = [item for item in named if item.status == SKIPPED_STATUS]
    if skipped:
        return ERROR, f"{mutant.kills} was skipped, which proves nothing"
    failures = [item for item in named if item.status == FAILED_STATUS]
    passes = [item for item in named if item.status == PASSED_STATUS]
    if not failures:
        if outcome.returncode != 0:
            return ERROR, (
                f"{mutant.kills} reported no failure yet the run exited "
                f"{outcome.returncode}: {outcome.detail}")
        return SURVIVED, (
            f"{mutant.kills} passed under {mutant.summary} "
            f"-- the guard is not load-bearing: {outcome.detail}")
    if passes:
        return ERROR, (
            f"{mutant.kills} was reported as both passing and failing in one "
            f"run, which is not an outcome a test has: {passes[0].describe()}")
    if outcome.returncode == 0:
        return ERROR, (f"{mutant.kills} reported a failure yet the run exited "
                       f"0: {outcome.detail}")
    counted, problem = _matched_failures(mutant, failures)
    if problem:
        return ERROR, problem
    return KILLED, f"{counted[0].describe()} | {outcome.detail}"


def _matched_failures(mutant: Mutant, failures: list[TestRecord],
                      ) -> tuple[list[TestRecord], str]:
    """Every failure against the signatures registered for it, exactly.

    Each failure must match one registered signature and no more than one, and
    each signature must be matched by exactly as many failures as it registered.
    Anything else -- an unmatched failure, a second copy of an expected one, a
    case that stopped failing -- means the run is not the outcome this mutant
    described, and a verdict may not be read out of it.
    """

    signatures = mutant.signatures
    tally = [0] * len(signatures)
    for failure in failures:
        matches = [index for index, signature in enumerate(signatures)
                   if not signature.mismatch(failure)]
        if not matches:
            return [], (
                f"{mutant.kills} failed, but not as "
                f"{mutant.describe_expectation()}; a mutation that broke "
                f"something else is not this guard noticing this sabotage. "
                f"{signatures[0].mismatch(failure)} ({failure.describe()})")
        if len(matches) > 1:
            return [], (
                f"{mutant.kills} produced a failure that answers to more than "
                f"one registered signature, so which guard noticed it cannot "
                f"be told: {failure.describe()}")
        tally[matches[0]] += 1
    for index, signature in enumerate(signatures):
        if tally[index] != signature.count:
            return [], (
                f"{mutant.kills} failed {tally[index]} time(s) as "
                f"{signature.describe()} where this mutant registers exactly "
                f"{signature.count}; a kill is the whole outcome the registry "
                f"described, not a matching record inside a different one")
    return failures, ""


def _control_problem(mutant: Mutant, outcome: Outcome) -> str:
    """Why ``mutant``'s declared control is not green, or ``""`` if it is."""

    if outcome.timed_out or outcome.problem or not outcome.reported:
        return (f"the control {mutant.control} gave no answer: "
                f"{outcome.problem or outcome.detail}")
    strays = outcome.strays(mutant.control)
    if strays:
        return (f"the control run reported a result for something other than "
                f"{mutant.control}: {strays[0].describe()}")
    named = outcome.for_test(mutant.control)
    if outcome.ran != 1 or not named:
        return (f"the control {mutant.control} did not run as exactly one "
                f"test (ran {outcome.ran}): {outcome.detail}")
    unwell = [item for item in named if item.status != PASSED_STATUS]
    if unwell or outcome.returncode != 0:
        return (f"the control {mutant.control} did not stay green, so the "
                f"kill is not specific: "
                f"{unwell[0].describe() if unwell else outcome.detail}")
    return ""


def evaluate(mutant: Mutant, *, root: Path = REPO_ROOT,
             timeout: int = TEST_TIMEOUT_SECONDS) -> Receipt:
    """Apply ``mutant`` to a disposable clone and judge its named test."""

    try:
        with disposable_clone(root) as clone:
            try:
                apply_edits(clone, mutant.edits)
            except MutationError as error:
                return _receipt(mutant, ERROR, str(error))
            outcome = run_named_tests(clone, [mutant.kills], timeout=timeout,
                                      private_root=clone.parent)
            verdict, detail = judge(mutant, outcome)
            if verdict == KILLED and mutant.control is not None:
                control = run_named_tests(clone, [mutant.control],
                                          timeout=timeout,
                                          private_root=clone.parent)
                problem = _control_problem(mutant, control)
                if problem:
                    return _receipt(mutant, ERROR, problem)
            return _receipt(mutant, verdict, detail)
    except (MutationError, OSError) as error:
        # The clone itself could not be prepared. That is an error and never a
        # kill: a mutant that never ran proves nothing about the guard it was
        # aimed at, and counting it as red is how a broken harness reads green.
        return _receipt(mutant, ERROR, f"the clone could not be made: {error}")


CONTROL_ID = "CONTROL-unmutated-candidate"


def control_receipt(root: Path = REPO_ROOT, *,
                    timeout: int = TEST_TIMEOUT_SECONDS) -> Receipt:
    """The negative control: every named test is green on an unmutated clone."""

    names = killing_tests()
    try:
        with disposable_clone(root) as clone:
            outcome = run_named_tests(clone, names, timeout=timeout,
                                      private_root=clone.parent)
    except (MutationError, OSError) as error:
        return Receipt(mutant_id=CONTROL_ID, sep="-", shape="negative-control",
                       verdict=ERROR, kills=", ".join(names),
                       detail=f"the clone could not be made: {error}")
    detail = f"{outcome.ran} named test(s): {outcome.detail}"
    unwell = [item for item in outcome.records
              if item.status != PASSED_STATUS]
    reported = {item.test for item in outcome.records}
    if outcome.timed_out or outcome.problem or not outcome.reported:
        verdict = ERROR
        detail = outcome.problem or outcome.detail
    elif outcome.ran != len(names) or reported != set(names):
        verdict = ERROR
        detail = (f"expected {len(names)} named tests, ran {outcome.ran} and "
                  f"heard from {len(reported)}: "
                  + (", ".join(sorted(set(names) - reported)) or outcome.detail))
    elif unwell or outcome.returncode != 0:
        verdict = ERROR
        detail = ("the unmutated candidate is not green: "
                  + (unwell[0].describe() if unwell else outcome.detail))
    else:
        verdict = PASSED
    return Receipt(mutant_id=CONTROL_ID, sep="-", shape="negative-control",
                   verdict=verdict, kills=", ".join(names), detail=detail)


# ---------------------------------------------------------------------------
# Registry introspection used by the contract tests.

def test_exists(root: Path, dotted: str) -> bool:
    """Is ``module.Class.method`` a real test method in this tree?"""

    try:
        module_name, class_name, method_name = dotted.rsplit(".", 2)
    except ValueError:
        return False
    root = str(Path(root))
    inserted = root not in sys.path
    if inserted:
        sys.path.insert(0, root)
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        return False
    finally:
        if inserted and root in sys.path:
            sys.path.remove(root)
    case = getattr(module, class_name, None)
    if case is None:
        return False
    return callable(getattr(case, method_name, None))


#: The shortest fragment a signature may be built from.  Anything shorter is a
#: word rather than a claim, and a word appears in failures that have nothing
#: to do with the guard.
MINIMUM_FRAGMENT = 16


def signature_problems(mutants=None) -> tuple[str, ...]:
    """Every way the registry's expected failures are not usable as evidence.

    A signature is the only thing standing between "the named test went red"
    and "the named test caught this sabotage", so it is checked as data before
    it is ever relied on as a verdict: it must name a real exception, carry at
    least one fragment, say something longer than a word, not be a restatement
    of the test's own name, and not be shared with another mutant.

    The cardinalities are checked here too, for the same reason.  An exact
    count is what turns "one of the failures matched" into "this is the whole
    outcome", so a count that is not a positive number this harness could ever
    observe would quietly return the registry to the weaker claim.
    """

    found: list[str] = []
    seen: dict[tuple, str] = {}
    for mutant in (MUTANTS if mutants is None else tuple(mutants)):
        where = mutant.mutant_id
        if not isinstance(mutant.expects, GuardFailure):
            found.append(f"{where}: no expected failure is registered")
            continue
        within: set[tuple] = set()
        for expected in mutant.signatures:
            if not isinstance(expected, GuardFailure):
                found.append(f"{where}: an expected failure is not a signature")
                continue
            exception = getattr(builtins, expected.exception, None)
            known = (isinstance(exception, type)
                     and issubclass(exception, BaseException))
            if not expected.exception:
                found.append(
                    f"{where}: the expected failure names no exception")
            elif not known and not expected.exception.isidentifier():
                found.append(f"{where}: {expected.exception!r} is not an "
                             "exception name")
            if not expected.contains:
                found.append(
                    f"{where}: {expected.exception} on its own is what every "
                    "failed assertion in Python looks like; the signature has "
                    "to say which assertion")
            for fragment in expected.contains:
                if len(fragment.strip()) < MINIMUM_FRAGMENT:
                    found.append(
                        f"{where}: {fragment!r} is too short to identify one "
                        f"failure (under {MINIMUM_FRAGMENT} characters)")
                if fragment and fragment in mutant.kills:
                    found.append(
                        f"{where}: {fragment!r} is part of the test's own "
                        "name, so it would match any failure that test ever "
                        "has")
            if (not isinstance(expected.count, int)
                    or isinstance(expected.count, bool)
                    or not 1 <= expected.count <= RECORD_LIMIT):
                found.append(
                    f"{where}: {expected.count!r} is not a number of failures "
                    f"a run can report (1 to {RECORD_LIMIT})")
            key = (expected.exception, expected.contains)
            if key in within:
                found.append(
                    f"{where}: the same signature is registered twice, so the "
                    "two cannot be told apart in one run")
            within.add(key)
        if mutant.expected_failures > RECORD_LIMIT:
            found.append(
                f"{where}: {mutant.expected_failures} expected failures is "
                f"more than the {RECORD_LIMIT} one run may report")
        key = (mutant.expects.exception, mutant.expects.contains)
        if key in seen:
            found.append(f"{where}: its expected failure is the same as "
                         f"{seen[key]}'s, so neither identifies its own guard")
        seen[key] = where
    return tuple(found)


def registry_rows() -> tuple[dict[str, str], ...]:
    """The registry as flat rows, for a report or a manifest diff."""

    return tuple({
        "mutant_id": mutant.mutant_id,
        "sep": mutant.sep,
        "shape": mutant.shape,
        "summary": mutant.summary,
        "kills": mutant.kills,
        "expects": mutant.expects.describe(),
        "control": mutant.control or "",
        "sites": "; ".join(edit.describe() for edit in mutant.edits),
    } for mutant in MUTANTS)
