"""Contract: Ready and Trust ship as physically separate distributions.

An import census proves that the source tree *could* be split.  It cannot
prove that the artefacts are split, because a single wheel that contains every
module satisfies every import rule there is.  This suite therefore builds the
four proposed distributions and reads the resulting ZIP archives member by
member.

Four projects, one authority each::

    packages/core     -> admissible-core    (admissible_core + shared roots)
    packages/ready    -> admissible-ready   (admissible_ready, no signing)
    packages/trust    -> admissible-trust   (admissible_trust, no runner)
    packages/umbrella -> admissible         (compatibility dispatcher only)

What is asserted is deliberately physical.  Ready must not merely avoid
importing Trust; the Ready wheel must not *contain* Trust's modules, because a
wheel that contains them is a wheel from which they can be imported, monkey-
patched, or loaded by a path that no census walks.  The same holds in reverse,
and it holds for the ``admissible`` compatibility namespace: if the split
packages ship it too, then installing them re-creates the monolith under a
different name.

The final two classes install the built wheels into throwaway environments,
because containment and installation are different claims.  ``find_spec`` in a
Ready-only environment is the question a user's process actually asks.

This suite is RED until ``packages/`` exists.  Every failure below names the
missing project, and none of them skips: a skipped separation test reads as a
separation that holds.
"""

from __future__ import annotations

import atexit
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from unittest import mock

from . import inspect_wheel
from .test_import_census import CORE as CORE_OWNER
from .test_import_census import READY, TRUST, load_manifest

REPO_ROOT = Path(__file__).resolve().parents[2]

VERSION = "0.8.1"
REQUIRES_PYTHON = ">=3.10"


@dataclass(frozen=True)
class ProposedProject:
    """One distribution the split must produce."""

    directory: str
    distribution: str
    namespace: str
    # The one console command this distribution is allowed to install, and the
    # ``module:callable`` it must resolve to.  Core is a library: it installs no
    # command at all, so both are None.
    console_script: str | None
    console_target: str | None

    @property
    def path(self) -> Path:
        return REPO_ROOT / self.directory

    @property
    def entry_points(self) -> dict[str, str]:
        """The exact ``console_scripts`` section this distribution must ship."""
        if self.console_script is None:
            return {}
        return {self.console_script: self.console_target}


CORE = ProposedProject(
    "packages/core", "admissible-core", "admissible_core", None, None)
READY_PROJECT = ProposedProject(
    "packages/ready", "admissible-ready", "admissible_ready",
    "admissible-ready", "admissible_ready.cli:main")
TRUST_PROJECT = ProposedProject(
    "packages/trust", "admissible-trust", "admissible_trust",
    "admissible-trust", "admissible_trust.cli:main")
UMBRELLA = ProposedProject(
    "packages/umbrella", "admissible", "admissible",
    "admissible", "admissible.cli:main")

PROJECTS = (CORE, READY_PROJECT, TRUST_PROJECT, UMBRELLA)
PROJECTS_BY_NAME = {project.distribution: project for project in PROJECTS}

# Namespaces Core carries for every consumer.  ``protocol`` is the schema
# package; the research roots ride along with it rather than being duplicated
# into each dependent wheel.
SHARED_NAMESPACES = ("fcd", "rga", "atlas", "protocol")

# The complete payload of each wheel, named as top-level import names.  This is
# an equality, not a list of prohibitions: a wheel that ships one namespace more
# than its authority needs is a wheel whose authority is not what it claims, and
# no exclusion list written in advance can name a namespace nobody has invented
# yet.  ``*.dist-info/`` (metadata, licences, ``RECORD``) is not payload, and
# the ``*.data/`` schemes that install off ``sys.path`` are not import names;
# both are excluded by :attr:`inspect_wheel.Wheel.installed_paths`.
EXPECTED_TOP_LEVEL = {
    CORE.distribution: {CORE.namespace, *SHARED_NAMESPACES},
    READY_PROJECT.distribution: {READY_PROJECT.namespace},
    TRUST_PROJECT.distribution: {TRUST_PROJECT.namespace},
    UMBRELLA.distribution: {UMBRELLA.namespace},
}

# Which distribution is allowed to ship each namespace: the inverse of the map
# above, and the thing "exclusive ownership" means.  Two wheels shipping
# ``admissible_core`` is two kernels, with installation order picking which one
# a process gets.
NAMESPACE_OWNER = {
    namespace: distribution
    for distribution, namespaces in EXPECTED_TOP_LEVEL.items()
    for namespace in namespaces
}

# The dependency edges the split declares, unconditionally, for every install.
# Core depends on nothing: it is the floor, and a floor with dependencies of its
# own is a floor that can pull the split back together.
EXPECTED_REQUIREMENTS = {
    CORE.distribution: {},
    READY_PROJECT.distribution: {CORE.distribution: f"=={VERSION}"},
    TRUST_PROJECT.distribution: {CORE.distribution: f"=={VERSION}"},
    UMBRELLA.distribution: {
        CORE.distribution: f"=={VERSION}",
        READY_PROJECT.distribution: f"=={VERSION}",
        TRUST_PROJECT.distribution: f"=={VERSION}",
    },
}

def marked_requirements(wheel: inspect_wheel.Wheel) -> list[str]:
    """Every ``Requires-Dist`` of ``wheel`` that carries an environment marker.

    The split declares no conditional dependencies at all, not merely no
    extra-gated ones.  ``; extra == "trust"`` is the marker people think of, but
    ``Requires-Dist: admissible; python_version >= "3.10"`` is satisfied by
    every interpreter this project supports, so a plain ``pip install
    admissible-ready`` would pull the umbrella -- and with it Trust -- back in.
    The installation shapes below use ``--no-deps``, so they would never notice:
    the marker has to be rejected here, in the metadata, or not at all.
    """
    return sorted(
        f"{required}; {marker}"
        for required, marker in wheel.conditional_requirements.items()
    )


# Every console command the split installs, from any distribution.  Asserting
# against this set is what makes "only ``admissible-ready``" mean "and not the
# other three", rather than "and nothing I happened to think of".
ALL_CONSOLE_SCRIPTS = frozenset(
    project.console_script for project in PROJECTS if project.console_script
)

# ``command -> module:callable``, across the whole split.  A name alone proves
# nothing: ``admissible-trust = admissible_ready.runner:main`` installs a
# correctly named command that runs the wrong authority's code.
ALL_CONSOLE_TARGETS = {
    project.console_script: project.console_target
    for project in PROJECTS if project.console_script
}

def _owned_basenames(owner: str) -> set[str]:
    """Module basenames one authority owns, from the manifest, not retyped."""

    return {
        module.rpartition(".")[2]
        for module, value
        in load_manifest()["target_policy"]["target_owners"].items()
        if value == owner
    }


# Trust surface, derived from the ownership manifest rather than retyped: if a
# module changes authority there, this exclusion follows it.
#
# Basenames another authority also owns are subtracted, and that subtraction is
# the whole meaning of "only". While Trust had no namespace of its own, every
# Trust module was ``admissible.<something>`` and every basename was unique, so
# a bare basename set said exactly "a module Trust has". Now each distribution
# ships its own ``cli``, ``store``, ``github`` and ``git_reader``; excluding
# ``cli`` from the Ready wheel would exclude the wheel's own entry point, and a
# check that did so would be asserting that the split cannot exist. What
# remains -- receipts, reviews, attestations, standing, defects and the
# authenticated Ready projection -- is the set of names only the signing
# distribution has, which is the set this exclusion was always about.
TRUST_ONLY_MODULES = tuple(sorted(
    _owned_basenames(TRUST) - _owned_basenames(READY)
    - _owned_basenames(CORE_OWNER)
))

# Signing-credential loading is the capability the Ready distribution exists to
# not have.  These names are checked in addition to the manifest-derived set,
# so a credential loader introduced under a new name is still caught.
CREDENTIAL_LOADER_MARKERS = ("credential", "signing", "keyring", "secret")

# Execution surface, the capability Trust exists to not have: the runner, the
# agent/MCP connection, the Ready server and its browser assets.
RUNNER_ONLY_MODULES = (
    "runner", "agent_mcp", "agent_connection", "ready_server", "ready_static",
)
STATIC_ASSET_SUFFIXES = (".html", ".css", ".js")

# Schema resources have one canonical source in the repository root.
SCHEMA_SOURCE = REPO_ROOT / "protocol"
SCHEMA_OWNER = CORE.distribution


@dataclass
class BuildOutcome:
    """What building the four proposed projects produced, or did not."""

    wheelhouse: Path
    missing_projects: list[str] = field(default_factory=list)
    build_failures: dict[str, str] = field(default_factory=dict)
    wheels: dict[str, inspect_wheel.Wheel] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return len(self.wheels) == len(PROJECTS)

    def blocking_reason(self) -> str | None:
        """Why no wheel-level assertion can be made yet, or None."""
        if self.missing_projects:
            return (
                "the proposed package projects do not exist yet; each must be a "
                "buildable project directory with its own pyproject.toml:\n  "
                + "\n  ".join(self.missing_projects)
            )
        if self.build_failures:
            return "proposed distributions failed to build:\n" + "\n".join(
                f"[{name}] {reason}"
                for name, reason in sorted(self.build_failures.items())
            )
        if not self.complete:
            built = sorted(self.wheels)
            return f"only {built} of {sorted(PROJECTS_BY_NAME)} were built"
        return None


_BUILD: BuildOutcome | None = None
_WORKSPACE: tempfile.TemporaryDirectory | None = None


def build_outcome() -> BuildOutcome:
    """Build all four proposed distributions once per interpreter.

    Memoised because four builds plus four environments is the expensive part
    of this suite and none of it depends on which test asked.  Failures are
    recorded rather than raised, so each test can fail on its own contract with
    its own diagnostic instead of every test erroring out of a shared setup.
    """
    global _BUILD, _WORKSPACE
    if _BUILD is not None:
        return _BUILD
    _WORKSPACE = tempfile.TemporaryDirectory(prefix="admissible-separation-")
    atexit.register(_WORKSPACE.cleanup)
    outcome = BuildOutcome(wheelhouse=Path(_WORKSPACE.name) / "wheelhouse")
    outcome.wheelhouse.mkdir(parents=True, exist_ok=True)
    for project in PROJECTS:
        if not (project.path / "pyproject.toml").is_file():
            outcome.missing_projects.append(
                f"{project.directory}/pyproject.toml -> {project.distribution} "
                f"(namespace {project.namespace})"
            )
    if not outcome.missing_projects:
        for project in PROJECTS:
            try:
                built = inspect_wheel.build_wheel(project.path, outcome.wheelhouse)
                outcome.wheels[project.distribution] = inspect_wheel.inspect_wheel(built)
            except inspect_wheel.WheelError as error:
                outcome.build_failures[project.distribution] = str(error)
    _BUILD = outcome
    return outcome


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:  # pragma: no cover - only for paths outside the repo
        return str(path)


class WheelContractCase(unittest.TestCase):
    """Base: wheels are built once, at class setup, and shared."""

    @classmethod
    def setUpClass(cls):
        cls.build = build_outcome()

    def wheels(self) -> dict[str, inspect_wheel.Wheel]:
        """The four built wheels, or a failure that says what is missing."""
        reason = self.build.blocking_reason()
        if reason is not None:
            self.fail(reason)
        return self.build.wheels

    def wheel(self, distribution: str) -> inspect_wheel.Wheel:
        return self.wheels()[distribution]


class BuildEnvironment(unittest.TestCase):
    """The build must be possible here; an unbuildable suite must not be quiet.

    ``dev`` already declares ``build``.  These assertions exist so that a
    missing build backend fails as itself, rather than as a separation contract
    that appears to be violated.
    """

    def test_build_frontend_is_importable(self):
        self.assertIsNotNone(
            importlib.util.find_spec("build"),
            "python -m build is required: pip install -e '.[dev]'",
        )

    def test_setuptools_backend_is_importable(self):
        self.assertIsNotNone(
            importlib.util.find_spec("setuptools"),
            "--no-isolation builds against this interpreter's setuptools",
        )

    def test_the_repository_still_declares_the_build_dependency(self):
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('dev = ["build==1.4.0"', text)


class ProposedProjectLayout(WheelContractCase):
    """The four projects exist and each builds exactly one wheel."""

    def test_every_proposed_project_directory_exists(self):
        missing = [
            f"{project.directory} ({project.distribution})"
            for project in PROJECTS
            if not (project.path / "pyproject.toml").is_file()
        ]
        self.assertEqual(
            [], missing,
            "each proposed distribution needs its own buildable project",
        )

    def test_every_proposed_project_builds_a_wheel(self):
        self.assertEqual({}, self.build.build_failures)
        self.assertEqual(sorted(PROJECTS_BY_NAME), sorted(self.wheels()))

    def test_the_wheelhouse_holds_exactly_four_wheels(self):
        self.wheels()
        self.assertEqual(
            len(PROJECTS), len(sorted(self.build.wheelhouse.glob("*.whl"))),
            "one wheel per distribution and no strays",
        )


class DistributionMetadata(WheelContractCase):
    """Names, versions, and the Python floor are the same across the split."""

    def test_distribution_names_are_exactly_the_four_proposed(self):
        self.assertEqual(
            sorted(PROJECTS_BY_NAME),
            sorted(wheel.name for wheel in self.wheels().values()),
        )

    def test_every_distribution_is_version_0_8_0(self):
        for name, wheel in sorted(self.wheels().items()):
            with self.subTest(distribution=name):
                self.assertEqual(VERSION, wheel.version)
                self.assertIn(VERSION, wheel.path.name)

    def test_every_distribution_keeps_the_python_floor(self):
        for name, wheel in sorted(self.wheels().items()):
            with self.subTest(distribution=name):
                self.assertEqual(REQUIRES_PYTHON, wheel.requires_python)


class DeclaredDependencies(WheelContractCase):
    """Each wheel's unconditional ``Requires-Dist`` is exactly the agreed set.

    The dependency graph is the other half of the separation.  A Ready wheel
    that ships no Trust module but declares ``Requires-Dist: admissible-trust``
    installs Trust anyway, and the environment a user ends up with -- which is
    what the contract is about -- holds both authorities again.

    So the assertion is an equality on the whole map, not a lookup per expected
    name: an extra edge nobody listed must fail, and it must fail here.
    """

    def test_unconditional_requirements_are_exactly_the_declared_pins(self):
        for name, wheel in sorted(self.wheels().items()):
            with self.subTest(distribution=name):
                self.assertEqual(
                    EXPECTED_REQUIREMENTS[name],
                    wheel.unconditional_requirements,
                    f"Requires-Dist is {wheel.requires_dist}",
                )

    def test_core_depends_on_nothing_at_all(self):
        """Not even conditionally: Core is the floor the other three stand on."""
        core = self.wheel(CORE.distribution)
        self.assertEqual([], core.requires_dist)

    def test_no_distribution_declares_an_extra(self):
        """``Provides-Extra`` is a second dependency graph reachable on demand.

        ``pip install admissible-ready[trust]`` must not be a way to get signing
        authority back, so the split declares no extras anywhere.
        """
        for name, wheel in sorted(self.wheels().items()):
            with self.subTest(distribution=name):
                self.assertEqual([], wheel.provides_extra)

    def test_no_requirement_carries_an_environment_marker_at_all(self):
        """A marked requirement is a dependency edge the pin map cannot see.

        Every marker in a wheel's metadata is a condition under which pip adds a
        distribution, and the conditions that matter are the ones that hold:
        ``python_version >= "3.10"`` is the project's own floor, so it is not a
        condition at all.  The isolated environments in this suite install with
        ``--no-deps`` and would report a separation that a normal ``pip
        install`` does not have, which is why this is asserted on the metadata.
        """
        for name, wheel in sorted(self.wheels().items()):
            with self.subTest(distribution=name):
                self.assertEqual(
                    [], marked_requirements(wheel),
                    f"Requires-Dist is {wheel.requires_dist}",
                )

    def test_no_requirement_is_hidden_behind_an_extra_marker(self):
        """A ``; extra == "x"`` requirement is invisible to the pin map above.

        It carries a marker, so it is not unconditional; it is still installed
        the moment anyone asks for the extra.  Neither half of that may exist.
        """
        for name, wheel in sorted(self.wheels().items()):
            with self.subTest(distribution=name):
                gated = sorted(
                    required for required, marker
                    in wheel.conditional_requirements.items() if "extra" in marker
                )
                self.assertEqual(
                    [], gated,
                    f"extra-gated requirements in {name}: {wheel.requires_dist}",
                )

    def test_no_requirement_requests_an_extra_of_another_distribution(self):
        """``admissible-core[all]`` pins a name and pulls in an unknown set."""
        for name, wheel in sorted(self.wheels().items()):
            with self.subTest(distribution=name):
                self.assertEqual([], wheel.requirements_requesting_extras)

    def test_neither_authority_depends_on_the_other(self):
        """Stated as itself, so the failure names the edge that reappeared."""
        pairs = ((READY_PROJECT, TRUST_PROJECT), (TRUST_PROJECT, READY_PROJECT))
        for requiring, forbidden in pairs:
            with self.subTest(requiring=requiring.distribution):
                wheel = self.wheel(requiring.distribution)
                self.assertNotIn(
                    forbidden.distribution,
                    set(wheel.unconditional_requirements)
                    | set(wheel.conditional_requirements),
                )


class PayloadNamespacePartition(WheelContractCase):
    """Each wheel's top-level payload is exactly its own namespaces.

    ``owns`` and ``members_under`` read installed paths, so a package parked
    under ``*.data/purelib/`` is counted where it lands rather than where it is
    stored; see :class:`HelperContract` for the proof of that unwrapping.
    """

    def test_each_wheel_ships_exactly_its_allowed_namespaces(self):
        for name, wheel in sorted(self.wheels().items()):
            with self.subTest(distribution=name):
                self.assertEqual(
                    EXPECTED_TOP_LEVEL[name], wheel.top_level,
                    f"{wheel.path.name} installs {sorted(wheel.installed_paths)[:20]}",
                )

    def test_every_namespace_has_exactly_one_owning_wheel(self):
        wheels = self.wheels()
        for namespace, owner in sorted(NAMESPACE_OWNER.items()):
            with self.subTest(namespace=namespace):
                owners = sorted(
                    name for name, wheel in wheels.items() if wheel.owns(namespace)
                )
                self.assertEqual([owner], owners)

    def test_the_kernel_namespace_is_owned_by_core_alone(self):
        """``admissible_core`` twice is two kernels, and install order decides.

        Vendoring it into Ready or Trust would make each authority's checks run
        against its own copy, which is precisely the divergence the split is
        meant to make impossible.
        """
        for name, wheel in sorted(self.wheels().items()):
            if name == CORE.distribution:
                continue
            with self.subTest(distribution=name):
                self.assertEqual(
                    [], wheel.members_under(CORE.namespace),
                    f"{name} vendors {CORE.namespace}",
                )

    def test_no_wheel_ships_a_namespace_another_wheel_owns(self):
        strays = []
        for name, wheel in sorted(self.wheels().items()):
            for namespace, owner in sorted(NAMESPACE_OWNER.items()):
                if owner == name:
                    continue
                strays += [f"{name}:{path}" for path in wheel.members_under(namespace)]
        self.assertEqual([], strays, "one namespace, one owning distribution")


class CoreWheelOwnership(WheelContractCase):
    """Core owns its own namespace and the shared roots, and no command."""

    def test_core_ships_its_own_namespace(self):
        core = self.wheel(CORE.distribution)
        self.assertTrue(
            core.owns(CORE.namespace),
            f"{core.path.name} ships {sorted(core.top_level)}",
        )

    def test_core_is_the_only_owner_of_each_shared_namespace(self):
        """A shared root lives in exactly one wheel, and that wheel is Core.

        Core's own configuration decides which files of ``protocol`` or
        ``atlas`` ship; it does not get to decide that a second wheel ships
        them too.  Two wheels owning ``protocol`` is two schema copies that can
        disagree, with installation order picking the winner.
        """
        wheels = self.wheels()
        for namespace in SHARED_NAMESPACES:
            with self.subTest(namespace=namespace):
                owners = sorted(
                    name for name, wheel in wheels.items() if wheel.owns(namespace)
                )
                self.assertEqual(
                    [CORE.distribution], owners,
                    f"{namespace} must be shipped by Core alone",
                )

    def test_core_ships_no_console_command(self):
        core = self.wheel(CORE.distribution)
        self.assertEqual(
            {}, core.console_scripts,
            "Core is a library; Ready/Trust/Umbrella own the commands",
        )
        for command in sorted(ALL_CONSOLE_SCRIPTS):
            self.assertNotIn(command, core.console_scripts)


class ReadyWheelIsolation(WheelContractCase):
    """The Ready wheel contains no Trust surface and no umbrella namespace."""

    def ready(self) -> inspect_wheel.Wheel:
        return self.wheel(READY_PROJECT.distribution)

    def test_ready_ships_its_own_namespace(self):
        self.assertTrue(self.ready().owns(READY_PROJECT.namespace))

    def test_ready_does_not_ship_the_trust_namespace(self):
        ready = self.ready()
        self.assertEqual(
            [], ready.members_under(TRUST_PROJECT.namespace),
            "the Ready wheel must not contain admissible_trust",
        )

    def test_ready_does_not_ship_the_compatibility_namespace(self):
        ready = self.ready()
        self.assertEqual(
            [], ready.members_under(UMBRELLA.namespace),
            "only the umbrella distribution ships the `admissible` namespace",
        )
        self.assertNotIn(UMBRELLA.namespace, ready.top_level)

    def test_ready_ships_no_trust_authority_modules(self):
        """Receipts, reviews, attestations, standing: none of them ship here."""
        ready = self.ready()
        found = sorted(
            module for module in ready.modules
            if module.rpartition(".")[2] in TRUST_ONLY_MODULES
        )
        self.assertEqual(
            [], found,
            f"Ready must not ship the trust surface {list(TRUST_ONLY_MODULES)}",
        )

    def test_ready_ships_no_credential_loader(self):
        ready = self.ready()
        found = sorted(
            module for module in ready.modules
            if any(marker in module.rpartition(".")[2]
                   for marker in CREDENTIAL_LOADER_MARKERS)
        )
        self.assertEqual(
            [], found,
            "the Ready distribution must be unable to load signing credentials",
        )

    def test_ready_installs_only_its_own_command(self):
        """Exactly one command, pointed at exactly one callable in Ready."""
        self.assertEqual(READY_PROJECT.entry_points, self.ready().console_scripts)


class TrustWheelIsolation(WheelContractCase):
    """The Trust wheel contains no execution surface and no umbrella namespace."""

    def trust(self) -> inspect_wheel.Wheel:
        return self.wheel(TRUST_PROJECT.distribution)

    def test_trust_ships_its_own_namespace(self):
        self.assertTrue(self.trust().owns(TRUST_PROJECT.namespace))

    def test_trust_does_not_ship_the_ready_namespace(self):
        self.assertEqual(
            [], self.trust().members_under(READY_PROJECT.namespace),
            "the Trust wheel must not contain admissible_ready",
        )

    def test_trust_does_not_ship_the_compatibility_namespace(self):
        trust = self.trust()
        self.assertEqual([], trust.members_under(UMBRELLA.namespace))
        self.assertNotIn(UMBRELLA.namespace, trust.top_level)

    def test_trust_ships_no_runner_or_agent_surface(self):
        trust = self.trust()
        found = sorted(
            module for module in trust.modules
            if module.rpartition(".")[2] in RUNNER_ONLY_MODULES
        )
        self.assertEqual(
            [], found,
            "a distribution that signs must not also be able to run candidates",
        )

    def test_trust_ships_no_browser_assets(self):
        trust = self.trust()
        assets = sorted(
            member for member in trust.payload
            if member.endswith(STATIC_ASSET_SUFFIXES)
        )
        self.assertEqual([], assets, "the Ready server's assets are not Trust's")

    def test_trust_installs_only_its_own_command(self):
        self.assertEqual(TRUST_PROJECT.entry_points, self.trust().console_scripts)


class UmbrellaWheelIsDispatcherOnly(WheelContractCase):
    """The umbrella keeps the old name working and holds nothing else."""

    def umbrella(self) -> inspect_wheel.Wheel:
        return self.wheel(UMBRELLA.distribution)

    def test_umbrella_ships_only_the_compatibility_namespace(self):
        umbrella = self.umbrella()
        self.assertTrue(umbrella.owns(UMBRELLA.namespace))
        self.assertEqual(
            {UMBRELLA.namespace}, umbrella.top_level,
            "the umbrella is a dispatcher: it re-exports, it does not contain",
        )

    def test_umbrella_ships_no_split_namespace_of_its_own(self):
        umbrella = self.umbrella()
        for namespace in (CORE.namespace, READY_PROJECT.namespace,
                          TRUST_PROJECT.namespace, *SHARED_NAMESPACES):
            with self.subTest(namespace=namespace):
                self.assertEqual([], umbrella.members_under(namespace))

    def test_umbrella_installs_only_the_legacy_command(self):
        self.assertEqual(UMBRELLA.entry_points, self.umbrella().console_scripts)

    def test_umbrella_pins_each_split_distribution_exactly(self):
        """Exact pins, because a dispatcher that floats can dispatch anywhere."""
        umbrella = self.umbrella()
        for project in (CORE, READY_PROJECT, TRUST_PROJECT):
            with self.subTest(requires=project.distribution):
                self.assertEqual(
                    f"=={VERSION}",
                    umbrella.requirement_on(project.distribution),
                    f"Requires-Dist is {umbrella.requires_dist}",
                )


class ConsoleCommandPartition(WheelContractCase):
    """Each command is installed by exactly one wheel."""

    def test_no_command_is_installed_by_two_distributions(self):
        owners: dict[str, list[str]] = {}
        for name, wheel in sorted(self.wheels().items()):
            for command in wheel.console_scripts:
                owners.setdefault(command, []).append(name)
        duplicated = {c: o for c, o in owners.items() if len(o) > 1}
        self.assertEqual({}, duplicated, "a command may have one owner only")

    def test_the_installed_commands_are_exactly_the_declared_three(self):
        installed = {
            command
            for wheel in self.wheels().values()
            for command in wheel.console_scripts
        }
        self.assertEqual(sorted(ALL_CONSOLE_SCRIPTS), sorted(installed))

    def test_every_command_points_at_its_own_distributions_callable(self):
        """The whole split's ``console_scripts``, as one ``name -> target`` map.

        Checked as a mapping because the name is the part a user types and the
        target is the part that runs: ``admissible-trust`` wired to
        ``admissible_ready.runner:main`` passes every name-only assertion while
        handing the signing command to the runner.
        """
        installed = {}
        for name, wheel in sorted(self.wheels().items()):
            for command, target in wheel.console_scripts.items():
                installed[command] = target
        self.assertEqual(ALL_CONSOLE_TARGETS, installed)

    def test_each_command_targets_a_module_inside_its_own_namespace(self):
        for project in PROJECTS:
            if project.console_script is None:
                continue
            with self.subTest(command=project.console_script):
                wheel = self.wheel(project.distribution)
                target = wheel.console_scripts.get(project.console_script)
                self.assertEqual(project.console_target, target)
                module, _, attribute = str(target).partition(":")
                self.assertEqual("main", attribute)
                self.assertIn(
                    module, wheel.modules,
                    f"{project.distribution} must ship the module it points at",
                )


class SchemaResourceOwnership(WheelContractCase):
    """Schemas ship once, from the canonical source, with matching bytes."""

    def source_schemas(self) -> dict[str, tuple[Path, str]]:
        """``basename -> (path, sha256)`` for every root schema resource."""
        found = {}
        for path in sorted(SCHEMA_SOURCE.glob("*.json")):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            found[path.name] = (path, digest)
        return found

    def test_the_canonical_schema_source_is_not_empty(self):
        self.assertTrue(
            self.source_schemas(),
            f"{_relative(SCHEMA_SOURCE)} is the canonical schema source",
        )

    def test_each_schema_is_shipped_by_exactly_one_distribution(self):
        wheels = self.wheels()
        for basename in sorted(self.source_schemas()):
            with self.subTest(schema=basename):
                owners = sorted(
                    name for name, wheel in wheels.items() if wheel.members_named(basename)
                )
                self.assertEqual(
                    [SCHEMA_OWNER], owners,
                    f"{basename} must be shipped by {SCHEMA_OWNER} alone",
                )

    def test_shipped_schema_bytes_match_the_canonical_source(self):
        """Compared by digest: a same-named file is not the same schema."""
        core = self.wheel(SCHEMA_OWNER)
        for basename, (path, digest) in sorted(self.source_schemas().items()):
            with self.subTest(schema=basename):
                members = core.members_named(basename)
                self.assertEqual(
                    1, len(members),
                    f"{basename} is shipped {len(members)} times: {members}",
                )
                self.assertEqual(
                    digest, core.sha256(members[0]),
                    f"{members[0]} has drifted from {_relative(path)}",
                )

    def test_no_other_distribution_carries_a_forked_schema_copy(self):
        wheels = self.wheels()
        strays = []
        for basename, (_path, digest) in sorted(self.source_schemas().items()):
            for name, wheel in sorted(wheels.items()):
                if name == SCHEMA_OWNER:
                    continue
                for member in wheel.members_named(basename):
                    same = wheel.sha256(member) == digest
                    strays.append(
                        f"{name}:{member} ({'identical' if same else 'forked'})"
                    )
        self.assertEqual([], strays, "one schema, one owner, one copy")


@dataclass
class Environments:
    """Throwaway environments, one per supported installation shape."""

    interpreters: dict[str, Path] = field(default_factory=dict)
    reason: str | None = None


_ENVIRONMENTS: Environments | None = None
_ENV_WORKSPACE: tempfile.TemporaryDirectory | None = None

# Installation shapes: name -> the distributions installed, in dependency
# order.  Core is present everywhere because both Ready and Trust depend on it;
# what varies is precisely the sibling authority under test.
INSTALL_SHAPES = {
    "core-only": (CORE.distribution,),
    "ready-only": (CORE.distribution, READY_PROJECT.distribution),
    "trust-only": (CORE.distribution, TRUST_PROJECT.distribution),
    "umbrella": (
        CORE.distribution, READY_PROJECT.distribution,
        TRUST_PROJECT.distribution, UMBRELLA.distribution,
    ),
}


def environments() -> Environments:
    """Create every installation shape once, from the built wheels."""
    global _ENVIRONMENTS, _ENV_WORKSPACE
    if _ENVIRONMENTS is not None:
        return _ENVIRONMENTS
    build = build_outcome()
    blocking = build.blocking_reason()
    if blocking is not None:
        _ENVIRONMENTS = Environments(reason=blocking)
        return _ENVIRONMENTS
    _ENV_WORKSPACE = tempfile.TemporaryDirectory(prefix="admissible-envs-")
    atexit.register(_ENV_WORKSPACE.cleanup)
    root = Path(_ENV_WORKSPACE.name)
    result = Environments()
    try:
        for shape, distributions in INSTALL_SHAPES.items():
            interpreter = inspect_wheel.create_venv(root / shape)
            inspect_wheel.install_wheels(
                interpreter, [build.wheels[name].path for name in distributions]
            )
            result.interpreters[shape] = interpreter
    except (inspect_wheel.WheelError, OSError, subprocess.SubprocessError) as error:
        result.reason = f"could not prepare installation environments: {error}"
    _ENVIRONMENTS = result
    return result


class InstalledEnvironmentCase(unittest.TestCase):
    """Base: every installation shape is created once, at class setup."""

    @classmethod
    def setUpClass(cls):
        cls.environments = environments()

    def interpreter(self, shape: str) -> Path:
        if self.environments.reason is not None:
            self.fail(self.environments.reason)
        return self.environments.interpreters[shape]

    def assert_presence(self, shape: str, expected: dict[str, bool]):
        interpreter = self.interpreter(shape)
        found = inspect_wheel.importable(interpreter, *sorted(expected))
        self.assertEqual(
            expected, found,
            f"in the {shape} environment: find_spec disagrees with the contract",
        )

    def assert_command_help(self, shape: str, command: str):
        """The command exists and answers ``--help`` from a clean process.

        Clean means the sanitized environment: a command that only works
        because ``PYTHONPATH`` still points at the checkout is a command that
        does not work from its wheel, and that is the claim under test.
        """
        interpreter = self.interpreter(shape)
        script = inspect_wheel.venv_script(interpreter.parent.parent, command)
        self.assertTrue(script.is_file(), f"{command} is not installed in {shape}")
        completed = subprocess.run(
            [str(script), "--help"], capture_output=True, text=True,
            timeout=inspect_wheel.RUN_TIMEOUT, cwd=str(interpreter.parent.parent),
            env=inspect_wheel.sanitized_env(),
        )
        self.assertEqual(
            0, completed.returncode,
            f"{command} --help failed in {shape}:\n{completed.stderr}",
        )
        self.assertTrue(completed.stdout.strip(), f"{command} --help printed nothing")


class ReadyOnlyInstallation(InstalledEnvironmentCase):
    """Installing Ready must not make Trust importable."""

    SHAPE = "ready-only"

    def test_ready_is_importable_and_trust_is_not(self):
        self.assert_presence(self.SHAPE, {
            CORE.namespace: True,
            READY_PROJECT.namespace: True,
            TRUST_PROJECT.namespace: False,
            UMBRELLA.namespace: False,
        })

    def test_trust_authority_modules_are_unreachable(self):
        self.assert_presence(self.SHAPE, {
            f"{TRUST_PROJECT.namespace}.{module}": False
            for module in TRUST_ONLY_MODULES
        })

    def test_the_ready_command_runs(self):
        self.assert_command_help(self.SHAPE, READY_PROJECT.console_script)

    def test_the_other_commands_are_absent(self):
        environment = self.interpreter(self.SHAPE).parent.parent
        for command in sorted(ALL_CONSOLE_SCRIPTS - {READY_PROJECT.console_script}):
            with self.subTest(command=command):
                self.assertFalse(
                    inspect_wheel.venv_script(environment, command).exists(),
                    f"{command} must not be installed by Ready",
                )


class TrustOnlyInstallation(InstalledEnvironmentCase):
    """Installing Trust must not make Ready importable."""

    SHAPE = "trust-only"

    def test_trust_is_importable_and_ready_is_not(self):
        self.assert_presence(self.SHAPE, {
            CORE.namespace: True,
            TRUST_PROJECT.namespace: True,
            READY_PROJECT.namespace: False,
            UMBRELLA.namespace: False,
        })

    def test_the_runner_surface_is_unreachable(self):
        self.assert_presence(self.SHAPE, {
            f"{READY_PROJECT.namespace}.{module}": False
            for module in RUNNER_ONLY_MODULES
        })

    def test_the_trust_command_runs(self):
        self.assert_command_help(self.SHAPE, TRUST_PROJECT.console_script)

    def test_the_other_commands_are_absent(self):
        environment = self.interpreter(self.SHAPE).parent.parent
        for command in sorted(ALL_CONSOLE_SCRIPTS - {TRUST_PROJECT.console_script}):
            with self.subTest(command=command):
                self.assertFalse(
                    inspect_wheel.venv_script(environment, command).exists(),
                    f"{command} must not be installed by Trust",
                )


class CoreOnlyInstallation(InstalledEnvironmentCase):
    """Core alone carries neither authority."""

    SHAPE = "core-only"

    def test_neither_ready_nor_trust_is_importable(self):
        self.assert_presence(self.SHAPE, {
            CORE.namespace: True,
            READY_PROJECT.namespace: False,
            TRUST_PROJECT.namespace: False,
            UMBRELLA.namespace: False,
        })

    def test_core_installs_no_command(self):
        environment = self.interpreter(self.SHAPE).parent.parent
        for command in sorted(ALL_CONSOLE_SCRIPTS):
            with self.subTest(command=command):
                self.assertFalse(
                    inspect_wheel.venv_script(environment, command).exists()
                )


class UmbrellaInstallation(InstalledEnvironmentCase):
    """The umbrella keeps every explicit package and the legacy name."""

    SHAPE = "umbrella"

    def test_every_namespace_is_importable(self):
        self.assert_presence(self.SHAPE, {
            CORE.namespace: True,
            READY_PROJECT.namespace: True,
            TRUST_PROJECT.namespace: True,
            UMBRELLA.namespace: True,
        })

    def test_the_legacy_command_runs(self):
        self.assert_command_help(self.SHAPE, UMBRELLA.console_script)

    def test_every_command_is_installed(self):
        environment = self.interpreter(self.SHAPE).parent.parent
        for command in sorted(ALL_CONSOLE_SCRIPTS):
            with self.subTest(command=command):
                self.assertTrue(
                    inspect_wheel.venv_script(environment, command).is_file(),
                    f"{command} must be installed by the full set",
                )


class HelperContract(unittest.TestCase):
    """The inspection helper answers about bytes, not about names.

    These run against a synthetic wheel-shaped archive, so the helper is proved
    before it is trusted: without them a helper that quietly returned nothing
    would make every containment assertion above pass.
    """

    def scratch(self) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="admissible-helper-"))
        self.addCleanup(shutil.rmtree, directory, True)
        return directory

    def build_archive(self, members: dict[str, bytes]) -> Path:
        directory = self.scratch()
        path = directory / "demo-0.8.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as archive:
            for name, payload in members.items():
                archive.writestr(name, payload)
        return path

    def demo(self, extra: dict[str, bytes] | None = None) -> inspect_wheel.Wheel:
        members = {
            "demo-0.8.0.dist-info/METADATA": (
                b"Metadata-Version: 2.1\nName: demo-dist\nVersion: 0.8.0\n"
                b"Requires-Python: >=3.10\n"
                b"Requires-Dist: admissible-core==0.8.0\n"
                b"Requires-Dist: only-on-windows==1.0; sys_platform == 'win32'\n"
            ),
            "demo-0.8.0.dist-info/entry_points.txt": (
                b"[console_scripts]\ndemo = demo.cli:main\n"
            ),
            "demo/__init__.py": b"",
            "demo/cli.py": b"def main():\n    return 0\n",
            "demo/schema.json": b'{"ok": true}\n',
        }
        members.update(extra or {})
        return inspect_wheel.inspect_wheel(self.build_archive(members))

    def test_metadata_is_read_from_the_archive(self):
        wheel = self.demo()
        self.assertEqual("demo-dist", wheel.name)
        self.assertEqual("0.8.0", wheel.version)
        self.assertEqual(">=3.10", wheel.requires_python)
        self.assertEqual({"demo": "demo.cli:main"}, wheel.console_scripts)

    def test_dist_info_is_not_counted_as_payload(self):
        wheel = self.demo()
        self.assertEqual({"demo"}, wheel.top_level)
        self.assertEqual({"demo", "demo.cli"}, wheel.modules)

    def test_ownership_is_by_member_path(self):
        wheel = self.demo()
        self.assertTrue(wheel.owns("demo"))
        self.assertFalse(wheel.owns("admissible_trust"))
        self.assertEqual([], wheel.members_under("admissible_trust"))

    def test_a_single_module_distribution_is_owned_too(self):
        wheel = self.demo({"lonely.py": b"VALUE = 1\n"})
        self.assertTrue(wheel.owns("lonely"))
        self.assertIn("lonely", wheel.top_level)

    def test_digests_distinguish_identical_filenames(self):
        payload = b'{"ok": true}\n'
        wheel = self.demo({"demo/vendored/schema.json": b'{"ok": false}\n'})
        self.assertEqual(
            ["demo/schema.json", "demo/vendored/schema.json"],
            wheel.members_named("schema.json"),
        )
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(), wheel.sha256("demo/schema.json")
        )
        self.assertNotEqual(
            wheel.sha256("demo/schema.json"),
            wheel.sha256("demo/vendored/schema.json"),
            "same name, different bytes: the helper must tell them apart",
        )

    def test_only_unconditional_requirements_count_as_pins(self):
        wheel = self.demo()
        self.assertEqual("==0.8.0", wheel.requirement_on("admissible_core"))
        self.assertIsNone(
            wheel.requirement_on("only-on-windows"),
            "a marked requirement is conditional, so it is not a dependency",
        )
        self.assertIsNone(wheel.requirement_on("admissible-ready"))

    def test_the_requirement_maps_split_marked_from_unmarked(self):
        wheel = self.demo()
        self.assertEqual({"admissible-core": "==0.8.0"},
                         wheel.unconditional_requirements)
        self.assertEqual({"only-on-windows"},
                         set(wheel.conditional_requirements))
        self.assertIn("sys_platform",
                      wheel.conditional_requirements["only-on-windows"])

    def test_extras_are_reported_rather_than_absorbed_into_the_name(self):
        """``core[all]`` must not read as a plain pin on ``core``."""
        wheel = self.demo({
            "demo-0.8.0.dist-info/METADATA": (
                b"Metadata-Version: 2.1\nName: demo-dist\nVersion: 0.8.0\n"
                b"Provides-Extra: trust\n"
                b"Requires-Dist: admissible-core[all]==0.8.0\n"
                b'Requires-Dist: admissible-trust==0.8.0; extra == "trust"\n'
            ),
        })
        self.assertEqual(["trust"], wheel.provides_extra)
        self.assertEqual(
            ["admissible-core[all]==0.8.0"], wheel.requirements_requesting_extras
        )
        self.assertEqual(
            'extra == "trust"',
            wheel.conditional_requirements["admissible-trust"],
            "an extra-gated requirement is still a requirement",
        )
        self.assertNotIn("admissible-trust", wheel.unconditional_requirements)

    def test_a_non_extra_environment_marker_is_detected_and_rejected(self):
        """The marker that is not an extra is the one that actually installs.

        ``admissible; python_version >= "3.10"`` names the umbrella -- and so
        Ready, Trust, and Core -- under a condition every supported interpreter
        satisfies.  It is invisible to the exact-pin map, and invisible to a
        check that looks only for ``extra ==``, so both of those are shown
        failing to see it here before :func:`marked_requirements` catches it.
        """
        wheel = self.demo({
            "demo-0.8.0.dist-info/METADATA": (
                b"Metadata-Version: 2.1\nName: demo-dist\nVersion: 0.8.0\n"
                b"Requires-Python: >=3.10\n"
                b"Requires-Dist: admissible-core==0.8.0\n"
                b'Requires-Dist: admissible; python_version >= "3.10"\n'
            ),
        })
        self.assertEqual({"admissible-core": "==0.8.0"},
                         wheel.unconditional_requirements)
        self.assertIsNone(
            wheel.requirement_on("admissible"),
            "the pin map cannot see a marked requirement",
        )
        self.assertEqual([], wheel.provides_extra)
        self.assertEqual([], wheel.requirements_requesting_extras)
        self.assertEqual(
            'python_version >= "3.10"',
            wheel.conditional_requirements["admissible"],
            "the marker must be read back whole, not merely noticed",
        )
        self.assertEqual(
            [],
            sorted(required for required, marker
                   in wheel.conditional_requirements.items() if "extra" in marker),
            "an extra-only check passes this metadata, which is the point",
        )
        self.assertEqual(
            ['admissible; python_version >= "3.10"'], marked_requirements(wheel),
            "every marked requirement is rejected, not only the extra-gated ones",
        )

    def test_every_marker_shape_is_rejected_including_the_always_true_one(self):
        """One marked requirement per shape a split might plausibly grow."""
        for marker in ('sys_platform == "linux"', 'python_version >= "3.10"',
                       'extra == "trust"', 'os_name == "posix" or os_name == "nt"'):
            with self.subTest(marker=marker):
                wheel = self.demo({
                    "demo-0.8.0.dist-info/METADATA": (
                        b"Metadata-Version: 2.1\nName: demo-dist\nVersion: 0.8.0\n"
                        b"Requires-Dist: admissible-trust==0.8.0; "
                        + marker.encode("utf-8") + b"\n"
                    ),
                })
                self.assertEqual({}, wheel.unconditional_requirements)
                self.assertEqual(
                    [f"admissible-trust; {marker}"], marked_requirements(wheel)
                )

    def test_an_unmarked_requirement_is_not_reported_as_marked(self):
        """The control: the rejection must not fire on the pins the split has."""
        wheel = self.demo({
            "demo-0.8.0.dist-info/METADATA": (
                b"Metadata-Version: 2.1\nName: demo-dist\nVersion: 0.8.0\n"
                b"Requires-Dist: admissible-core==0.8.0\n"
            ),
        })
        self.assertEqual([], marked_requirements(wheel))
        self.assertEqual("==0.8.0", wheel.requirement_on("admissible-core"))

    def test_a_package_under_data_purelib_is_seen_where_it_installs(self):
        """``*.data/purelib/`` unpacks onto ``sys.path``, so it is not a hiding place."""
        wheel = self.demo({
            "demo-0.8.0.data/purelib/admissible_trust/__init__.py": b"",
            "demo-0.8.0.data/purelib/admissible_trust/receipts.py": b"KEY = 1\n",
        })
        self.assertTrue(wheel.owns("admissible_trust"))
        self.assertEqual(
            ["admissible_trust/__init__.py", "admissible_trust/receipts.py"],
            wheel.members_under("admissible_trust"),
            "members are reported at their installed path, not their archive path",
        )
        self.assertIn("admissible_trust.receipts", wheel.modules)
        self.assertEqual({"demo", "admissible_trust"}, wheel.top_level)

    def test_a_package_under_data_platlib_is_seen_where_it_installs(self):
        wheel = self.demo({
            "demo-0.8.0.data/platlib/admissible_trust/__init__.py": b"",
            "demo-0.8.0.data/platlib/admissible_trust/signing.py": b"KEY = 1\n",
        })
        self.assertTrue(wheel.owns("admissible_trust"))
        self.assertEqual(
            ["admissible_trust/__init__.py", "admissible_trust/signing.py"],
            wheel.members_under("admissible_trust"),
        )
        self.assertIn("admissible_trust.signing", wheel.modules)
        self.assertEqual({"demo", "admissible_trust"}, wheel.top_level)

    def test_data_schemes_off_sys_path_are_not_import_names(self):
        """``scripts``/``data``/``headers`` install elsewhere, so they own nothing."""
        wheel = self.demo({
            "demo-0.8.0.data/scripts/demo-tool": b"#!/bin/sh\n",
            "demo-0.8.0.data/data/share/demo/notes.txt": b"hello\n",
        })
        self.assertEqual({"demo"}, wheel.top_level)
        self.assertFalse(wheel.owns("share"))
        self.assertIsNone(inspect_wheel.install_path("demo-0.8.0.data/scripts/demo-tool"))
        self.assertEqual(
            "admissible_trust/cli.py",
            inspect_wheel.install_path(
                "demo-0.8.0.data/purelib/admissible_trust/cli.py"),
        )
        self.assertEqual("demo/cli.py", inspect_wheel.install_path("demo/cli.py"))

    def test_a_non_wheel_is_rejected_rather_than_read_as_empty(self):
        directory = self.scratch()
        plain = directory / "not-a-wheel.whl"
        plain.write_bytes(b"this is not a zip archive")
        with self.assertRaises(inspect_wheel.WheelError):
            inspect_wheel.inspect_wheel(plain)
        with self.assertRaises(inspect_wheel.WheelError):
            inspect_wheel.inspect_wheel(directory / "absent.whl")

    def test_building_a_project_that_does_not_exist_fails_loudly(self):
        directory = self.scratch()
        with self.assertRaises(inspect_wheel.BuildFailed) as caught:
            inspect_wheel.build_wheel(directory / "packages" / "absent", directory)
        self.assertIn("pyproject.toml", str(caught.exception))

    def test_the_command_line_summary_is_json(self):
        wheel = self.demo()
        completed = subprocess.run(
            [sys.executable, str(Path(inspect_wheel.__file__)), str(wheel.path)],
            capture_output=True, text=True, timeout=inspect_wheel.RUN_TIMEOUT,
            env=inspect_wheel.sanitized_env(),
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        summary = json.loads(completed.stdout)
        self.assertEqual("demo-dist", summary["name"])
        self.assertEqual(["demo"], summary["top_level"])


class SanitizedEnvironmentContract(unittest.TestCase):
    """No canary may inherit the caller's import environment.

    Every absence in this suite is proved by a subprocess failing to import
    something.  ``PYTHONPATH`` makes that proof worthless: with the checkout on
    it, ``admissible_trust`` imports inside a Ready-only environment and the
    test still passes, reporting a separation that the wheels do not have.

    So the sanitizing is tested as a claim of its own, with a control that shows
    the leak is real when the environment is not sanitized.
    """

    ECHO = (
        "import json, os, sys;"
        "print(json.dumps({'env': {k: os.environ.get(k) for k in sys.argv[1:]},"
        " 'path': sys.path}))"
    )

    def leaky_module(self) -> tuple[Path, str]:
        """A directory holding a module no installed distribution ships."""
        directory = Path(tempfile.mkdtemp(prefix="admissible-leak-"))
        self.addCleanup(shutil.rmtree, directory, True)
        name = "admissible_leaked_marker"
        (directory / f"{name}.py").write_bytes(b"VALUE = 1\n")
        return directory, name

    def echo(self, env: dict[str, str]) -> dict:
        completed = subprocess.run(
            [sys.executable, "-c", self.ECHO, *inspect_wheel.INHERITED_IMPORT_VARIABLES],
            capture_output=True, text=True, timeout=inspect_wheel.RUN_TIMEOUT, env=env,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)

    def test_the_import_variables_are_removed_and_not_merely_emptied(self):
        polluted = {
            variable: "/tmp/somewhere"
            for variable in inspect_wheel.INHERITED_IMPORT_VARIABLES
        }
        with mock.patch.dict(os.environ, polluted):
            environment = inspect_wheel.sanitized_env()
        for variable in inspect_wheel.INHERITED_IMPORT_VARIABLES:
            with self.subTest(variable=variable):
                self.assertNotIn(
                    variable, environment,
                    "an empty value is still a value; the key must be gone",
                )

    def test_user_site_packages_are_disabled(self):
        environment = inspect_wheel.sanitized_env()
        self.assertEqual("1", environment["PYTHONNOUSERSITE"])
        self.assertEqual("0", environment["PIP_USER"])

    def test_the_offline_build_settings_survive_sanitizing(self):
        environment = inspect_wheel.sanitized_env()
        self.assertEqual("1", environment["PIP_NO_INDEX"])
        self.assertEqual(
            inspect_wheel.SOURCE_DATE_EPOCH, environment["SOURCE_DATE_EPOCH"]
        )

    def test_unrelated_variables_and_explicit_overrides_are_kept(self):
        with mock.patch.dict(os.environ, {"ADMISSIBLE_UNRELATED": "kept"}):
            environment = inspect_wheel.sanitized_env({"EXTRA": "value"})
        self.assertEqual("kept", environment["ADMISSIBLE_UNRELATED"])
        self.assertEqual("value", environment["EXTRA"])
        self.assertIn("PATH", environment, "the interpreter still needs a PATH")

    def test_a_subprocess_started_with_it_sees_none_of_them(self):
        directory, _name = self.leaky_module()
        polluted = {
            "PYTHONPATH": str(directory),
            "PYTHONSTARTUP": str(directory / "startup.py"),
            "PYTHONUSERBASE": str(directory),
        }
        with mock.patch.dict(os.environ, polluted):
            observed = self.echo(inspect_wheel.sanitized_env())
        self.assertEqual(
            {variable: None for variable in inspect_wheel.INHERITED_IMPORT_VARIABLES},
            observed["env"],
        )
        self.assertNotIn(
            str(directory), observed["path"],
            "an inherited PYTHONPATH entry must not reach the child's sys.path",
        )

    def test_an_inherited_pythonpath_would_otherwise_leak(self):
        """The control: without sanitizing, the same probe imports the module.

        This is what makes the test above evidence rather than a tautology.
        """
        directory, name = self.leaky_module()
        with mock.patch.dict(os.environ, {"PYTHONPATH": str(directory)}):
            leaked = self.echo(dict(os.environ))
            self.assertEqual(str(directory), leaked["env"]["PYTHONPATH"])
            self.assertIn(str(directory), leaked["path"])
            self.assertEqual(
                {name: True},
                self.find_spec(name, env=dict(os.environ)),
                "the fixture must actually be importable through PYTHONPATH",
            )
            self.assertEqual(
                {name: False},
                inspect_wheel.importable(sys.executable, name),
                "importable() must answer from the wheels, not from the shell",
            )

    def find_spec(self, name: str, *, env: dict[str, str]) -> dict[str, bool]:
        """``importable`` with a caller-chosen environment, for the control."""
        completed = subprocess.run(
            [sys.executable, "-c",
             "import importlib.util, json, sys;"
             "print(json.dumps({n: importlib.util.find_spec(n) is not None"
             " for n in sys.argv[1:]}))", name],
            capture_output=True, text=True, timeout=inspect_wheel.RUN_TIMEOUT,
            cwd=str(Path(sys.executable).parent), env=env,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)


class SeparationConstantsAreDerived(unittest.TestCase):
    """The exclusion lists must keep meaning something.

    An empty forbidden set is a test that always passes, so the sets are
    asserted non-empty and the manifest-derived one is checked against the
    ownership manifest it came from.
    """

    def test_the_trust_surface_comes_from_the_ownership_manifest(self):
        owners = load_manifest()["target_policy"]["target_owners"]
        trust = {m.rpartition(".")[2] for m, o in owners.items() if o == TRUST}
        others = {m.rpartition(".")[2] for m, o in owners.items()
                  if o in (READY, CORE_OWNER)}
        self.assertEqual(sorted(trust - others), sorted(TRUST_ONLY_MODULES))
        self.assertTrue(TRUST_ONLY_MODULES, "an empty exclusion excludes nothing")

    def test_the_excluded_names_are_the_ones_only_trust_has(self):
        """Named outright, so the subtraction cannot quietly empty the set.

        ``receipt``, ``review``, ``attestation`` and ``standing`` are the four
        the monolith already kept apart; ``defects`` and ``ready_status`` are
        the two the split added. A Ready wheel containing any of them is a
        Ready wheel with an authority it must not have.
        """

        for basename in ("attestation", "defects", "ready_status", "receipt",
                         "review", "standing"):
            with self.subTest(module=basename):
                self.assertIn(basename, TRUST_ONLY_MODULES)

    def test_a_name_both_distributions_have_is_not_an_exclusion(self):
        """The control: excluding these would forbid Ready's own entry point."""

        for shared in ("cli", "store", "github", "git_reader", "__main__"):
            with self.subTest(module=shared):
                self.assertNotIn(shared, TRUST_ONLY_MODULES)

    def test_the_runner_surface_is_ready_owned_in_the_manifest(self):
        owners = load_manifest()["target_policy"]["target_owners"]
        ready = {m.rpartition(".")[2] for m, o in owners.items() if o == READY}
        self.assertEqual(
            [], sorted(set(RUNNER_ONLY_MODULES) - ready),
            "every excluded runner module must be a Ready-owned module today",
        )

    def test_the_two_exclusion_sets_do_not_overlap(self):
        self.assertEqual(
            set(), set(TRUST_ONLY_MODULES) & set(RUNNER_ONLY_MODULES),
            "a module cannot be excluded from both distributions",
        )

    def test_every_project_maps_to_a_distinct_namespace_and_command(self):
        self.assertEqual(
            len(PROJECTS), len({project.namespace for project in PROJECTS})
        )
        self.assertEqual(
            len(PROJECTS), len({project.directory for project in PROJECTS})
        )
        self.assertEqual(3, len(ALL_CONSOLE_SCRIPTS))

    def test_every_console_target_lives_in_its_own_namespace(self):
        """The contract's own targets must be consistent before they are asserted."""
        for project in PROJECTS:
            with self.subTest(distribution=project.distribution):
                if project.console_script is None:
                    self.assertIsNone(project.console_target)
                    self.assertEqual({}, project.entry_points)
                    continue
                module, separator, attribute = project.console_target.partition(":")
                self.assertEqual(":", separator)
                self.assertEqual("main", attribute)
                self.assertEqual(project.namespace, module.split(".")[0])

    def test_the_top_level_map_partitions_the_namespaces(self):
        """No namespace is listed for two distributions, and none is missing."""
        listed = [n for names in EXPECTED_TOP_LEVEL.values() for n in names]
        self.assertEqual(len(listed), len(set(listed)), "a namespace has one owner")
        self.assertEqual(
            {*(project.namespace for project in PROJECTS), *SHARED_NAMESPACES},
            set(listed),
        )
        self.assertEqual(sorted(PROJECTS_BY_NAME), sorted(EXPECTED_TOP_LEVEL))

    def test_the_dependency_map_covers_every_distribution_and_no_other(self):
        self.assertEqual(sorted(PROJECTS_BY_NAME), sorted(EXPECTED_REQUIREMENTS))
        for distribution, requirements in sorted(EXPECTED_REQUIREMENTS.items()):
            with self.subTest(distribution=distribution):
                self.assertEqual([], sorted(set(requirements) - set(PROJECTS_BY_NAME)))
                self.assertNotIn(distribution, requirements, "nothing requires itself")
                self.assertEqual(
                    {f"=={VERSION}"} if requirements else set(),
                    set(requirements.values()),
                    "every declared edge is an exact pin",
                )

    def test_the_namespaces_match_the_ownership_manifest(self):
        namespaces = load_manifest()["target_policy"]["namespaces"]
        self.assertEqual(
            {"Core": CORE.namespace, "Ready": READY_PROJECT.namespace,
             "Trust": TRUST_PROJECT.namespace, "Umbrella": UMBRELLA.namespace},
            namespaces,
        )


if __name__ == "__main__":
    unittest.main()
