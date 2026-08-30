"""Contract: the built Trust wheel is what it claims, and runs without Ready.

The source suites prove that Trust *could* be installed alone.  They cannot
prove that it *works* alone, because a source tree with the whole monorepo on
``sys.path`` satisfies every import a wheel would fail.  So this suite builds
the wheel, reads the archive member by member, installs it beside Core alone in
a throwaway environment with a sanitized environment, and drives the installed
command against real temporary repositories and stores.

Three separate claims:

* **content** -- the archive holds exactly ``admissible_trust``; no runner, no
  MCP or HTTP server, no browser asset, no ``admissible`` namespace, no
  vendored kernel, one console command pointed at one callable;
* **installation** -- in an environment that has Core and Trust and nothing
  else, ``find_spec("admissible_ready")`` and ``find_spec("admissible")`` are
  both ``None``, and every Ready module name is unreachable;
* **behaviour** -- the installed command answers ``--help``, signs a review,
  signs an evaluation, trusts and lists a policy, finalizes a retained preview,
  verifies it, reports authenticated status, exports and imports the journal,
  and files a defect.

The sdist is built too, and a wheel is built *from it*, because the two builds
take different code paths and a released wheel that differs from the direct one
is the wheel a user actually gets.

Nothing here skips.  A skipped isolation test reads as an isolation that holds.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from tests.architecture import inspect_wheel

from . import CORE_PROJECT, READY_PROJECT, REPO_ROOT, TRUST_PROJECT

VERSION = "0.8.0"
DISTRIBUTION = "admissible-trust"
NAMESPACE = "admissible_trust"
CONSOLE_SCRIPT = "admissible-trust"
CONSOLE_TARGET = "admissible_trust.cli:main"

# Ready's execution surface by module basename: the capability this
# distribution exists to not have.
RUNNER_MODULE_NAMES = ("runner", "agent_mcp", "agent_connection",
                       "ready_server", "ready_static")
STATIC_ASSET_SUFFIXES = (".html", ".css", ".js")

EXPECTED_MODULES = sorted([
    NAMESPACE,
    f"{NAMESPACE}.__main__",
    f"{NAMESPACE}.attestation",
    f"{NAMESPACE}.cli",
    f"{NAMESPACE}.defects",
    f"{NAMESPACE}.git_reader",
    f"{NAMESPACE}.github",
    f"{NAMESPACE}.ready_status",
    f"{NAMESPACE}.receipt",
    f"{NAMESPACE}.review",
    f"{NAMESPACE}.standing",
    f"{NAMESPACE}.store",
])

_STATE: dict = {}


def built() -> dict:
    """Build Core and Trust once per interpreter, and remember the outcome.

    Failures are recorded rather than raised, so each test fails on its own
    contract with its own diagnostic instead of erroring out of a shared setup
    -- and so that "the wheel would not build" is never mistaken for "the
    separation does not hold".
    """

    if _STATE:
        return _STATE
    workspace = tempfile.TemporaryDirectory(prefix="admissible-trust-dist-")
    atexit.register(workspace.cleanup)
    root = Path(workspace.name)
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True, exist_ok=True)
    _STATE["workspace"] = root
    _STATE["wheelhouse"] = wheelhouse
    _STATE["error"] = None
    try:
        core = inspect_wheel.build_wheel(CORE_PROJECT, wheelhouse)
        trust = inspect_wheel.build_wheel(TRUST_PROJECT, wheelhouse)
        _STATE["core_path"] = core
        _STATE["trust_path"] = trust
        _STATE["core"] = inspect_wheel.inspect_wheel(core)
        _STATE["trust"] = inspect_wheel.inspect_wheel(trust)
    except inspect_wheel.WheelError as error:
        _STATE["error"] = str(error)
    return _STATE


def installed() -> dict:
    """A Trust-only environment: Core and Trust, with no resolver involved."""

    state = built()
    if "interpreter" in state or state["error"]:
        return state
    try:
        interpreter = inspect_wheel.create_venv(state["workspace"] / "trust-only")
        inspect_wheel.install_wheels(
            interpreter, [state["core_path"], state["trust_path"]])
        state["interpreter"] = interpreter
    except (inspect_wheel.WheelError, OSError,
            subprocess.SubprocessError) as error:
        state["error"] = f"could not prepare the Trust-only environment: {error}"
    return state


class BuiltCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = built()

    def wheel(self) -> inspect_wheel.Wheel:
        if self.state["error"]:
            self.fail(self.state["error"])
        return self.state["trust"]


class WheelMetadata(BuiltCase):
    """Name, version, floor, dependency: the four things pip reads."""

    def test_the_project_builds_one_wheel(self):
        if self.state["error"]:
            self.fail(self.state["error"])
        self.assertTrue(self.state["trust_path"].is_file())

    def test_the_distribution_is_named_and_versioned_exactly(self):
        wheel = self.wheel()
        self.assertEqual(DISTRIBUTION, wheel.name)
        self.assertEqual(VERSION, wheel.version)
        self.assertIn(VERSION, wheel.path.name)

    def test_the_python_floor_is_the_coordinated_one(self):
        self.assertEqual(">=3.10", self.wheel().requires_python)

    def test_the_only_dependency_is_the_exact_kernel_pin(self):
        self.assertEqual({"admissible-core": f"=={VERSION}"},
                         self.wheel().unconditional_requirements)

    def test_no_dependency_carries_an_environment_marker(self):
        self.assertEqual({}, self.wheel().conditional_requirements)

    def test_no_extra_is_declared(self):
        """``pip install admissible-trust[ready]`` must not be a door."""
        self.assertEqual([], self.wheel().provides_extra)

    def test_no_requirement_asks_for_an_extra_of_another_distribution(self):
        self.assertEqual([], self.wheel().requirements_requesting_extras)

    def test_ready_is_not_a_dependency_under_any_condition(self):
        wheel = self.wheel()
        for name in ("admissible-ready", "admissible"):
            with self.subTest(distribution=name):
                self.assertNotIn(name, wheel.unconditional_requirements)
                self.assertNotIn(name, wheel.conditional_requirements)

    def test_exactly_one_console_command_pointing_at_one_callable(self):
        self.assertEqual({CONSOLE_SCRIPT: CONSOLE_TARGET},
                         self.wheel().console_scripts)

    def test_the_console_target_is_a_module_this_wheel_ships(self):
        module = CONSOLE_TARGET.partition(":")[0]
        self.assertIn(module, self.wheel().modules)


class WheelContents(BuiltCase):
    """What is in the archive, asserted as an equality where it can be."""

    def test_the_payload_is_exactly_the_trust_namespace(self):
        self.assertEqual({NAMESPACE}, self.wheel().top_level)

    def test_the_modules_are_exactly_the_ones_this_task_creates(self):
        self.assertEqual(EXPECTED_MODULES, sorted(self.wheel().modules))

    def test_no_runner_or_agent_module_is_in_the_archive(self):
        wheel = self.wheel()
        found = sorted(module for module in wheel.modules
                       if module.rpartition(".")[2] in RUNNER_MODULE_NAMES)
        self.assertEqual(
            [], found,
            "a distribution that signs must not also be able to run candidates")

    def test_no_browser_asset_is_in_the_archive(self):
        assets = sorted(member for member in self.wheel().payload
                        if member.endswith(STATIC_ASSET_SUFFIXES))
        self.assertEqual([], assets, "the Ready server's assets are not Trust's")

    def test_no_ci_template_is_in_the_archive(self):
        """The caller template writes a candidate workflow; Trust runs none."""
        wheel = self.wheel()
        for name in ("consumer-workflow.yml", "reusable-workflow.yml",
                     "action.yml", "workflow.yml"):
            with self.subTest(template=name):
                self.assertEqual([], wheel.members_named(name))

    def test_the_kernel_is_not_vendored(self):
        """Two copies of ``admissible_core`` is two kernels, and pip picks."""
        self.assertEqual([], self.wheel().members_under("admissible_core"))

    def test_the_ready_namespace_is_not_shipped(self):
        self.assertEqual([], self.wheel().members_under("admissible_ready"))

    def test_the_compatibility_namespace_is_not_shipped(self):
        wheel = self.wheel()
        self.assertEqual([], wheel.members_under("admissible"))
        self.assertNotIn("admissible", wheel.top_level)

    def test_no_research_root_or_schema_rides_along(self):
        wheel = self.wheel()
        for namespace in ("fcd", "rga", "atlas", "protocol", "server"):
            with self.subTest(namespace=namespace):
                self.assertEqual([], wheel.members_under(namespace))

    def test_no_schema_document_is_forked_into_this_wheel(self):
        wheel = self.wheel()
        strays = []
        for source in sorted((REPO_ROOT / "protocol").glob("*.json")):
            strays += wheel.members_named(source.name)
        self.assertEqual([], strays, "schemas ship from Core alone")

    def test_no_test_module_is_shipped(self):
        wheel = self.wheel()
        self.assertEqual(
            [], sorted(m for m in wheel.modules if ".tests" in m
                       or m.rpartition(".")[2].startswith("test_")))

    def test_the_wheel_bytes_can_be_digested(self):
        """Printed in the completion receipt; asserted here so it exists."""
        digest = hashlib.sha256(self.wheel().path.read_bytes()).hexdigest()
        self.assertEqual(64, len(digest))


class SdistDerivedWheelAgrees(BuiltCase):
    """A wheel built from the sdist installs the same paths as the direct one.

    The two builds take different code paths, and a released wheel that differs
    from the one a developer built is the wheel a user actually gets.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.derived = None
        cls.sdist = None
        cls.reason = cls.state["error"]
        if cls.reason:
            return
        outdir = cls.state["workspace"] / "sdist"
        outdir.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            [inspect_wheel.sys.executable, "-m", "build", "--sdist",
             "--no-isolation", "--outdir", str(outdir), str(TRUST_PROJECT)],
            capture_output=True, text=True,
            timeout=inspect_wheel.BUILD_TIMEOUT,
            env=inspect_wheel.sanitized_env())
        if completed.returncode != 0:
            cls.reason = f"sdist build failed:\n{completed.stderr[-2000:]}"
            return
        archives = sorted(outdir.glob("*.tar.gz"))
        if len(archives) != 1:
            cls.reason = f"expected one sdist, got {archives}"
            return
        cls.sdist = archives[0]
        unpacked = cls.state["workspace"] / "unpacked"
        unpacked.mkdir(parents=True, exist_ok=True)
        with tarfile.open(cls.sdist) as archive:
            archive.extractall(unpacked, filter="data")
        roots = [item for item in unpacked.iterdir() if item.is_dir()]
        if len(roots) != 1:
            cls.reason = f"expected one sdist root, got {roots}"
            return
        try:
            path = inspect_wheel.build_wheel(
                roots[0], cls.state["workspace"] / "from-sdist")
        except inspect_wheel.WheelError as error:
            cls.reason = f"building from the sdist failed: {error}"
            return
        cls.derived = inspect_wheel.inspect_wheel(path)

    def sdist_wheel(self) -> inspect_wheel.Wheel:
        if self.derived is None:
            self.fail(self.reason or "no wheel was built from the sdist")
        return self.derived

    def test_the_sdist_is_named_for_the_distribution(self):
        self.sdist_wheel()
        self.assertEqual("admissible_trust-0.8.0.tar.gz", self.sdist.name)

    def test_both_wheels_install_the_same_paths(self):
        self.assertEqual(sorted(self.wheel().installed_paths),
                         sorted(self.sdist_wheel().installed_paths))

    def test_both_wheels_declare_the_same_metadata(self):
        direct, derived = self.wheel(), self.sdist_wheel()
        self.assertEqual(direct.name, derived.name)
        self.assertEqual(direct.version, derived.version)
        self.assertEqual(direct.console_scripts, derived.console_scripts)
        self.assertEqual(direct.unconditional_requirements,
                         derived.unconditional_requirements)

    def test_the_sdist_derived_wheel_ships_no_runner(self):
        found = sorted(module for module in self.sdist_wheel().modules
                       if module.rpartition(".")[2] in RUNNER_MODULE_NAMES)
        self.assertEqual([], found)


class TaskTwoTrustAssertionsAreSatisfiable(BuiltCase):
    """The Trust half of the separation contract, evaluated against this wheel.

    ``tests/architecture/test_distribution_separation`` is the contract, and it
    stays RED until all four projects exist -- it builds every one of them and
    every assertion blocks on the one that does not.  That is correct and it is
    also uninformative about *this* task: "the suite is red" says nothing about
    whether the Trust wheel would satisfy it.

    So the Trust-specific predicates are imported from that module -- not
    retyped -- and applied to the wheel this project builds.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from tests.architecture import test_distribution_separation as contract

        cls.contract = contract

    def test_the_expected_top_level_payload_is_this_wheel_s(self):
        self.assertEqual(
            self.contract.EXPECTED_TOP_LEVEL[DISTRIBUTION],
            self.wheel().top_level)

    def test_the_expected_requirements_are_this_wheel_s(self):
        self.assertEqual(
            self.contract.EXPECTED_REQUIREMENTS[DISTRIBUTION],
            self.wheel().unconditional_requirements)

    def test_no_requirement_carries_a_marker_the_contract_rejects(self):
        self.assertEqual([], self.contract.marked_requirements(self.wheel()))

    def test_the_expected_console_entry_points_are_this_wheel_s(self):
        self.assertEqual(self.contract.TRUST_PROJECT.entry_points,
                         self.wheel().console_scripts)

    def test_the_contract_s_runner_surface_is_absent_here(self):
        wheel = self.wheel()
        self.assertTrue(self.contract.RUNNER_ONLY_MODULES,
                        "an empty exclusion excludes nothing")
        self.assertEqual(
            [], sorted(module for module in wheel.modules
                       if module.rpartition(".")[2]
                       in self.contract.RUNNER_ONLY_MODULES))

    def test_the_contract_s_asset_suffixes_match_nothing_here(self):
        wheel = self.wheel()
        self.assertEqual(
            [], sorted(member for member in wheel.payload
                       if member.endswith(self.contract.STATIC_ASSET_SUFFIXES)))

    def test_every_project_the_separation_contract_names_now_exists(self):
        """Why the separation suite can be green, stated rather than guessed.

        This task created Trust and Task 6 created the umbrella.  The contract
        suite builds all four and blocks on any that is missing, so asserting
        the set here keeps "green because everything is built" from being
        confused with "green because nothing was checked".
        """

        for project in self.contract.PROJECTS:
            with self.subTest(project=project.directory):
                self.assertTrue((project.path / "pyproject.toml").is_file())
        self.assertEqual(4, len(self.contract.PROJECTS))


class TrustOnlyEnvironmentCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = installed()

    def interpreter(self) -> Path:
        if self.state["error"]:
            self.fail(self.state["error"])
        return self.state["interpreter"]

    def environment(self) -> Path:
        return self.interpreter().parent.parent

    def script(self, command: str) -> Path:
        return inspect_wheel.venv_script(self.environment(), command)


class ImportAbsence(TrustOnlyEnvironmentCase):
    """The question a user's process actually asks."""

    def test_ready_and_the_umbrella_are_both_unimportable(self):
        self.assertEqual(
            {"admissible_core": True, "admissible_trust": True,
             "admissible_ready": False, "admissible": False},
            inspect_wheel.importable(
                self.interpreter(), "admissible_core", "admissible_trust",
                "admissible_ready", "admissible"))

    def test_every_runner_module_name_is_unreachable(self):
        names = [f"admissible_ready.{module}" for module in RUNNER_MODULE_NAMES]
        names += [f"admissible.{module}" for module in RUNNER_MODULE_NAMES]
        self.assertEqual(
            {name: False for name in names},
            inspect_wheel.importable(self.interpreter(), *names))

    def test_every_trust_module_is_importable_from_the_wheel(self):
        names = [name for name in EXPECTED_MODULES
                 if not name.endswith("__main__")]
        self.assertEqual({name: True for name in names},
                         inspect_wheel.importable(self.interpreter(), *names))

    def test_no_ready_file_is_anywhere_under_an_admissible_package(self):
        completed = inspect_wheel.run_python(self.interpreter(), _SITE_PACKAGES)
        self.assertEqual(0, completed.returncode, completed.stderr)
        found = json.loads(completed.stdout)
        self.assertTrue(found, "nothing named admissible* was installed")
        for basename in RUNNER_MODULE_NAMES:
            with self.subTest(module=basename):
                self.assertEqual(
                    [], [name for name in found
                         if name.rsplit("/", 1)[-1] == f"{basename}.py"])

    def test_the_installed_python_files_are_the_kernel_and_trust_only(self):
        completed = inspect_wheel.run_python(self.interpreter(), _SITE_PACKAGES)
        self.assertEqual(0, completed.returncode, completed.stderr)
        found = json.loads(completed.stdout)
        packages = {name.partition("/")[0] for name in found}
        self.assertEqual({"admissible_core", "admissible_trust"}, packages)

    def test_no_other_command_is_installed(self):
        for command in ("admissible", "admissible-ready"):
            with self.subTest(command=command):
                self.assertFalse(self.script(command).exists())


_SITE_PACKAGES = """
import json, sysconfig
from pathlib import Path

# Every module under a top-level package whose name starts with `admissible`,
# named as `<package>/<relative path>`. Matching on the whole path would match
# the temporary directory the environment happens to live in, and would report
# every file pip vendored.
root = Path(sysconfig.get_paths()["purelib"])
found = []
for package in sorted(root.iterdir()):
    if not package.is_dir() or not package.name.startswith("admissible"):
        continue
    for path in sorted(package.rglob("*.py")):
        found.append(f"{package.name}/{path.relative_to(package).as_posix()}")
print(json.dumps(found))
"""


class InstalledCommandRuns(TrustOnlyEnvironmentCase):
    """The command works from its wheel, in a sanitized environment."""

    def run_command(self, *args: str, **overrides) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.script(CONSOLE_SCRIPT)), *args], capture_output=True,
            text=True, timeout=inspect_wheel.RUN_TIMEOUT,
            cwd=str(self.environment()),
            env=inspect_wheel.sanitized_env(overrides or None))

    def test_help_answers_and_names_the_trust_commands(self):
        completed = self.run_command("--help")
        self.assertEqual(0, completed.returncode, completed.stderr)
        for command in ("ready-status", "attest-review", "attest-evaluation",
                        "policy trust", "policy revoke", "policy list",
                        "finalize", "verify", "explain", "status", "export",
                        "import", "impeach"):
            with self.subTest(command=command):
                self.assertIn(command, completed.stdout)

    def test_help_does_not_offer_a_ready_command(self):
        completed = self.run_command("--help")
        for absent in ("profiles", "init ", "check ", "mcp ", "connect ",
                       "ui ", "--preview-out"):
            with self.subTest(command=absent):
                self.assertNotIn(f"\n  {absent}", completed.stdout)

    def test_a_ready_command_is_unknown_rather_than_refused(self):
        for command in ("check", "mcp", "ui", "init", "profiles", "connect"):
            with self.subTest(command=command):
                completed = self.run_command(command, "--json")
                self.assertEqual(2, completed.returncode)

    def test_run_is_a_refusal_with_migration_guidance(self):
        """The transitional verb is retained as a refusal, never as a runner."""
        completed = self.run_command("run", "--json")
        self.assertEqual(2, completed.returncode)
        document = json.loads(completed.stdout)
        self.assertIn("finalize", document["message"])

    def test_verify_without_a_key_refuses_rather_than_crashing(self):
        completed = self.run_command("verify", "0" * 40, "--json")
        self.assertEqual(2, completed.returncode)
        self.assertTrue(completed.stdout.strip())


if __name__ == "__main__":
    unittest.main()
