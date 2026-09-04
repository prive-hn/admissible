"""Contract: the built umbrella wheel is a dispatcher and nothing else.

The source suites prove that the umbrella *routes* correctly.  They cannot
prove what it *ships*, because a source tree with the whole monorepo on
``sys.path`` satisfies imports that no wheel provides.  So this suite builds
the wheel, reads the archive member by member, builds the sdist and a wheel
from it, and installs all four distributions into a throwaway environment to
drive the legacy command the way a developer does.

Three separate claims:

* **content** -- the archive holds exactly the ``admissible`` compatibility
  namespace: no ``admissible_core``/``admissible_ready``/``admissible_trust``,
  no runner, no MCP or server module, no browser asset, no schema, no research
  root; one console command pointed at one callable;
* **metadata** -- name, version, Python floor, and three unconditional exact
  pins with no marker and no extra anywhere;
* **behaviour** -- installed beside the three distributions it pins, the legacy
  command answers ``--help``, dispatches a Ready verb to Ready and a Trust verb
  to Trust, and refuses a verb that has no owner.

Nothing here skips.  A skipped containment test reads as a containment that
holds.
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

from tests.compatibility import (CORE_SRC, CREDENTIAL_VARIABLES, READY_SRC,
                                 REPO_ROOT, TRUST_SRC, UMBRELLA_PACKAGE,
                                 UMBRELLA_PROJECT)

VERSION = "0.8.1"
DISTRIBUTION = "admissible"
NAMESPACE = "admissible"
CONSOLE_SCRIPT = "admissible"
CONSOLE_TARGET = "admissible.cli:main"

CORE_PROJECT = REPO_ROOT / "packages" / "core"
READY_PROJECT = REPO_ROOT / "packages" / "ready"
TRUST_PROJECT = REPO_ROOT / "packages" / "trust"

#: The facades, named once.  ``tests/compatibility/test_documented_imports``
#: is where this set is derived from what the repository documents; here it is
#: the list of module names the archive must hold and no more.
FACADE_NAMES = ("config", "evidence", "github", "identity", "ready", "receipt")

EXPECTED_MODULES = sorted([
    NAMESPACE,
    f"{NAMESPACE}.__main__",
    f"{NAMESPACE}.cli",
    *(f"{NAMESPACE}.{name}" for name in FACADE_NAMES),
])

#: What an installed umbrella must put in ``site-packages`` under its own
#: namespace, and nothing else.
EXPECTED_INSTALLED_FILES = sorted(
    f"{NAMESPACE}/{name}.py"
    for name in ("__init__", "__main__", "cli", *FACADE_NAMES))

EXPECTED_REQUIREMENTS = {
    "admissible-core": f"=={VERSION}",
    "admissible-ready": f"=={VERSION}",
    "admissible-trust": f"=={VERSION}",
}

# The surfaces the umbrella must never contain under any spelling: nothing
# here is documented as a legacy import, so a module with one of these names in
# this wheel is an implementation with no authority behind it, and a second
# copy of one that does.
#
# ``config``, ``identity``, ``github`` and ``ready`` are deliberately *not*
# here.  The repository documents an import from each, so the wheel ships a
# module with each name -- and each is a facade holding no implementation,
# which is asserted by shape in
# ``tests/compatibility/test_legacy_imports.FacadesHoldNoImplementation`` and
# by bytes in :meth:`WheelContents.test_the_shipped_sources_are_the_project_s_own_bytes`
# rather than by hoping the name stays unused.
FORBIDDEN_MODULE_NAMES = (
    "runner", "agent_mcp", "agent_connection", "ready_server", "ready_static",
    "attestation", "review", "standing", "defects", "ready_status", "store",
    "git_reader", "decision", "profiles", "schema", "isolation",
)
STATIC_ASSET_SUFFIXES = (".html", ".css", ".js")

_STATE: dict = {}


def built() -> dict:
    """Build the four wheels once per interpreter, and remember the outcome."""
    if _STATE:
        return _STATE
    workspace = tempfile.TemporaryDirectory(prefix="admissible-umbrella-dist-")
    atexit.register(workspace.cleanup)
    root = Path(workspace.name)
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True, exist_ok=True)
    _STATE["workspace"] = root
    _STATE["wheelhouse"] = wheelhouse
    _STATE["error"] = None
    try:
        for key, project in (("core", CORE_PROJECT), ("ready", READY_PROJECT),
                             ("trust", TRUST_PROJECT),
                             ("umbrella", UMBRELLA_PROJECT)):
            path = inspect_wheel.build_wheel(project, wheelhouse)
            _STATE[f"{key}_path"] = path
            _STATE[key] = inspect_wheel.inspect_wheel(path)
    except inspect_wheel.WheelError as error:
        _STATE["error"] = str(error)
    return _STATE


def installed() -> dict:
    """A developer machine: all four distributions, no resolver involved."""
    state = built()
    if "interpreter" in state or state["error"]:
        return state
    try:
        interpreter = inspect_wheel.create_venv(state["workspace"] / "developer")
        inspect_wheel.install_wheels(interpreter, [
            state["core_path"], state["ready_path"], state["trust_path"],
            state["umbrella_path"]])
        state["interpreter"] = interpreter
    except (inspect_wheel.WheelError, OSError,
            subprocess.SubprocessError) as error:
        state["error"] = f"could not prepare the developer environment: {error}"
    return state


class BuiltCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = built()

    def wheel(self) -> inspect_wheel.Wheel:
        if self.state["error"]:
            self.fail(self.state["error"])
        return self.state["umbrella"]


class WheelMetadata(BuiltCase):
    """Name, version, floor, dependencies: the four things pip reads."""

    def test_the_project_builds_one_wheel(self):
        if self.state["error"]:
            self.fail(self.state["error"])
        self.assertTrue(self.state["umbrella_path"].is_file())

    def test_the_distribution_is_named_and_versioned_exactly(self):
        wheel = self.wheel()
        self.assertEqual(DISTRIBUTION, wheel.name)
        self.assertEqual(VERSION, wheel.version)
        self.assertIn(VERSION, wheel.path.name)

    def test_the_python_floor_is_the_coordinated_one(self):
        self.assertEqual(">=3.10", self.wheel().requires_python)

    def test_the_dependencies_are_the_three_exact_sibling_pins(self):
        """A dispatcher that floats can dispatch to anything."""
        self.assertEqual(EXPECTED_REQUIREMENTS,
                         self.wheel().unconditional_requirements)

    def test_no_dependency_carries_an_environment_marker(self):
        self.assertEqual({}, self.wheel().conditional_requirements)

    def test_no_extra_is_declared(self):
        self.assertEqual([], self.wheel().provides_extra)

    def test_no_requirement_asks_for_an_extra_of_another_distribution(self):
        self.assertEqual([], self.wheel().requirements_requesting_extras)

    def test_exactly_one_console_command_pointing_at_one_callable(self):
        self.assertEqual({CONSOLE_SCRIPT: CONSOLE_TARGET},
                         self.wheel().console_scripts)

    def test_the_console_target_is_a_module_this_wheel_ships(self):
        self.assertIn(CONSOLE_TARGET.partition(":")[0], self.wheel().modules)

    def test_the_split_commands_are_not_reinstalled_here(self):
        """``admissible-ready`` belongs to the wheel that has a runner."""
        for command in ("admissible-ready", "admissible-trust"):
            with self.subTest(command=command):
                self.assertNotIn(command, self.wheel().console_scripts)


class WheelContents(BuiltCase):
    """What is in the archive, asserted as an equality where it can be."""

    def test_the_payload_is_exactly_the_compatibility_namespace(self):
        self.assertEqual({NAMESPACE}, self.wheel().top_level)

    def test_the_modules_are_exactly_the_dispatcher_and_its_facades(self):
        self.assertEqual(EXPECTED_MODULES, sorted(self.wheel().modules))

    def test_no_split_namespace_is_vendored(self):
        wheel = self.wheel()
        for namespace in ("admissible_core", "admissible_ready",
                          "admissible_trust"):
            with self.subTest(namespace=namespace):
                self.assertEqual([], wheel.members_under(namespace))

    def test_no_research_root_or_schema_package_rides_along(self):
        wheel = self.wheel()
        for namespace in ("fcd", "rga", "atlas", "protocol", "server"):
            with self.subTest(namespace=namespace):
                self.assertEqual([], wheel.members_under(namespace))

    def test_no_implementation_module_is_shipped_under_a_familiar_name(self):
        wheel = self.wheel()
        found = sorted(module for module in wheel.modules
                       if module.rpartition(".")[2] in FORBIDDEN_MODULE_NAMES)
        self.assertEqual(
            [], found,
            "the umbrella re-exports an implementation; it never holds one")

    def test_no_browser_asset_or_template_is_in_the_archive(self):
        wheel = self.wheel()
        assets = sorted(member for member in wheel.payload
                        if member.endswith(STATIC_ASSET_SUFFIXES)
                        or member.endswith((".yml", ".yaml")))
        self.assertEqual([], assets)

    def test_no_schema_document_is_forked_into_this_wheel(self):
        wheel = self.wheel()
        strays = []
        for source in sorted((REPO_ROOT / "protocol").glob("*.json")):
            strays += wheel.members_named(source.name)
        self.assertEqual([], strays, "schemas ship from Core alone")

    def test_no_test_module_is_shipped(self):
        self.assertEqual(
            [], sorted(m for m in self.wheel().modules if ".tests" in m
                       or m.rpartition(".")[2].startswith("test_")))

    def test_the_shipped_sources_are_the_project_s_own_bytes(self):
        """A wheel whose bytes are not the repository's is a wheel nobody read."""
        wheel = self.wheel()
        for path in sorted(UMBRELLA_PACKAGE.rglob("*.py")):
            member = f"admissible/{path.name}"
            with self.subTest(member=member):
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    wheel.sha256(member))

    def test_the_wheel_bytes_can_be_digested(self):
        digest = hashlib.sha256(self.wheel().path.read_bytes()).hexdigest()
        self.assertEqual(64, len(digest))


class SdistDerivedWheelAgrees(BuiltCase):
    """A wheel built from the sdist installs the same paths as the direct one."""

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
             "--no-isolation", "--outdir", str(outdir), str(UMBRELLA_PROJECT)],
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
        self.assertEqual("admissible-0.8.1.tar.gz", self.sdist.name)

    def test_both_wheels_install_the_same_paths(self):
        self.assertEqual(sorted(self.wheel().installed_paths),
                         sorted(self.sdist_wheel().installed_paths))

    def test_both_wheels_ship_the_same_module_bytes(self):
        direct, derived = self.wheel(), self.sdist_wheel()
        for member in sorted(direct.installed_paths):
            with self.subTest(member=member):
                self.assertEqual(direct.sha256(member), derived.sha256(member))

    def test_both_wheels_declare_the_same_metadata(self):
        direct, derived = self.wheel(), self.sdist_wheel()
        self.assertEqual(direct.name, derived.name)
        self.assertEqual(direct.version, derived.version)
        self.assertEqual(direct.console_scripts, derived.console_scripts)
        self.assertEqual(direct.unconditional_requirements,
                         derived.unconditional_requirements)


class TaskTwoUmbrellaAssertionsAreSatisfiable(BuiltCase):
    """The umbrella half of the separation contract, against this wheel.

    The predicates are imported from the contract suite rather than retyped, so
    a change there is a change here.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from tests.architecture import test_distribution_separation as contract

        cls.contract = contract

    def test_the_expected_top_level_payload_is_this_wheel_s(self):
        self.assertEqual(self.contract.EXPECTED_TOP_LEVEL[DISTRIBUTION],
                         self.wheel().top_level)

    def test_the_expected_requirements_are_this_wheel_s(self):
        self.assertEqual(self.contract.EXPECTED_REQUIREMENTS[DISTRIBUTION],
                         self.wheel().unconditional_requirements)

    def test_no_requirement_carries_a_marker_the_contract_rejects(self):
        self.assertEqual([], self.contract.marked_requirements(self.wheel()))

    def test_the_expected_console_entry_points_are_this_wheel_s(self):
        self.assertEqual(self.contract.UMBRELLA.entry_points,
                         self.wheel().console_scripts)

    def test_every_proposed_project_now_exists(self):
        """Task 6 is the one that makes the separation contract answerable."""
        for project in self.contract.PROJECTS:
            with self.subTest(project=project.directory):
                self.assertTrue((project.path / "pyproject.toml").is_file())


class DeveloperEnvironmentCase(unittest.TestCase):
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

    def command(self, *args: str, **overrides) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.script(CONSOLE_SCRIPT)), *args], capture_output=True,
            text=True, timeout=inspect_wheel.RUN_TIMEOUT,
            cwd=str(self.environment()),
            env=inspect_wheel.sanitized_env({
                "ADMISSIBLE_HOME": str(self.environment() / "home"),
                **overrides}))


class InstalledUmbrella(DeveloperEnvironmentCase):
    """The developer machine the umbrella exists for."""

    def test_all_four_namespaces_are_importable(self):
        self.assertEqual(
            {"admissible": True, "admissible_core": True,
             "admissible_ready": True, "admissible_trust": True},
            inspect_wheel.importable(
                self.interpreter(), "admissible", "admissible_core",
                "admissible_ready", "admissible_trust"))

    def test_the_facades_import_from_their_installed_owners(self):
        facades = [f"{NAMESPACE}.{name}" for name in FACADE_NAMES]
        self.assertEqual(
            {facade: True for facade in facades},
            inspect_wheel.importable(self.interpreter(), *facades))

    def test_the_split_facade_resolves_each_half_from_its_own_wheel(self):
        """Installed, not just on a source path: the two halves are two wheels.

        ``admissible.github`` is the one facade whose names come from different
        distributions, so it is the one whose resolution proves the pins in the
        metadata are load-bearing rather than decorative.
        """
        completed = inspect_wheel.run_python(
            self.interpreter(),
            "import json, sys\n"
            "import admissible.github as github\n"
            "before = [m for m in sys.modules if m.startswith('admissible_')]\n"
            "ready = github.evaluation_context\n"
            "trust = github.assert_trusted_tool\n"
            "import admissible_ready.github as r\n"
            "import admissible_trust.github as t\n"
            "print(json.dumps({\n"
            "    'clean': sorted(before),\n"
            "    'ready': ready is r.evaluation_context,\n"
            "    'trust': trust is t.assert_trusted_tool,\n"
            "}))\n")
        self.assertEqual(0, completed.returncode, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual([], report["clean"],
                         "importing the facade loaded a distribution")
        self.assertTrue(report["ready"])
        self.assertTrue(report["trust"])

    def test_every_command_is_installed(self):
        for command in ("admissible", "admissible-ready", "admissible-trust"):
            with self.subTest(command=command):
                self.assertTrue(self.script(command).is_file())

    def test_the_installed_admissible_files_are_the_dispatcher_alone(self):
        completed = inspect_wheel.run_python(self.interpreter(), _SITE_PACKAGES)
        self.assertEqual(0, completed.returncode, completed.stderr)
        found = json.loads(completed.stdout)
        self.assertEqual(
            EXPECTED_INSTALLED_FILES,
            sorted(name for name in found if name.startswith("admissible/")))

    def test_help_answers_and_names_every_legacy_command(self):
        completed = self.command("--help")
        self.assertEqual(0, completed.returncode, completed.stderr)
        for command in ("profiles", "init", "run", "check", "mcp", "connect",
                        "ui", "ready-status", "verify", "explain", "status",
                        "impeach", "attest-review", "attest-evaluation",
                        "policy", "finalize", "export", "import"):
            with self.subTest(command=command):
                self.assertIn(command, completed.stdout)

    def test_a_ready_verb_is_answered_by_the_ready_distribution(self):
        completed = self.command("profiles", "--json")
        self.assertEqual(0, completed.returncode, completed.stderr)
        names = [row["name"] for row in json.loads(completed.stdout)["profiles"]]
        self.assertIn("python-library", names)

    def test_a_trust_verb_is_answered_by_the_trust_distribution(self):
        completed = self.command("verify", "0" * 40, "--json")
        self.assertEqual(2, completed.returncode)
        self.assertTrue(json.loads(completed.stdout)["message"])

    def test_a_verb_with_no_owner_is_refused(self):
        completed = self.command("finalise", "--json")
        self.assertEqual(2, completed.returncode)
        self.assertIn("finalise", json.loads(completed.stdout)["message"])

    def test_a_ready_verb_beside_a_credential_refuses_in_ready(self):
        for variable in CREDENTIAL_VARIABLES:
            with self.subTest(credential=variable):
                completed = self.command("check", "--json",
                                         **{variable: "not-a-real-key"})
                self.assertEqual(2, completed.returncode)
                self.assertIn(variable, completed.stdout)

    def test_the_module_entry_point_works_from_the_installed_wheel(self):
        completed = inspect_wheel.run_python(
            self.interpreter(), "import runpy, sys\n"
            "sys.argv = ['admissible', '--help']\n"
            "runpy.run_module('admissible', run_name='__main__')\n")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("admissible-ready", completed.stdout)


_SITE_PACKAGES = """
import json, sysconfig
from pathlib import Path

root = Path(sysconfig.get_paths()["purelib"])
found = []
for package in sorted(root.iterdir()):
    if not package.is_dir() or not package.name.startswith("admissible"):
        continue
    for path in sorted(package.rglob("*.py")):
        found.append(f"{package.name}/{path.relative_to(package).as_posix()}")
print(json.dumps(found))
"""


class SourceAndArtifactAgree(unittest.TestCase):
    """The checked-in sources are the only place the wheel comes from."""

    def test_the_project_declares_no_source_outside_its_own_directory(self):
        text = (UMBRELLA_PROJECT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertNotIn("..", text.split("[tool.setuptools.package-dir]")[1])

    def test_the_sibling_projects_are_where_this_suite_expects_them(self):
        for source in (CORE_SRC, READY_SRC, TRUST_SRC):
            with self.subTest(source=str(source)):
                self.assertTrue(source.is_dir())


if __name__ == "__main__":
    unittest.main()
