"""Contract: the built Ready wheel is what it claims, and runs without Trust.

The source suites prove that Ready *could* be installed alone.  They cannot
prove that it *works* alone, because a source tree with the whole monorepo on
``sys.path`` satisfies every import a wheel would fail.  So this suite builds
the wheel, reads the archive member by member, installs it beside Core alone in
a throwaway environment with a sanitized environment, and drives the installed
command.

Three separate claims:

* **content** -- the archive holds exactly ``admissible_ready``, its browser
  assets and its CI template; no Trust module, no credential loader, no
  ``admissible`` namespace, no vendored kernel, one console command pointed at
  one callable;
* **installation** -- in an environment that has Core and Ready and nothing
  else, ``find_spec("admissible_trust")`` and ``find_spec("admissible")`` are
  both ``None``, and every Trust module name is unreachable;
* **behaviour** -- the installed command answers ``--help``, scaffolds a
  policy, evaluates a commit, speaks MCP over stdio, and serves the loopback
  API and its real assets.

The sdist is built too, and a wheel is built *from it*, because the two builds
take different code paths through package data: a `package-data` entry that the
sdist does not carry produces a wheel with no browser assets and a UI that
answers 500, and only a build from the sdist finds it.

Nothing here skips.  A skipped isolation test reads as an isolation that holds.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from tests.architecture import inspect_wheel

from . import CORE_PROJECT, READY_PROJECT, REPO_ROOT

VERSION = "0.8.0"
DISTRIBUTION = "admissible-ready"
NAMESPACE = "admissible_ready"
CONSOLE_SCRIPT = "admissible-ready"
CONSOLE_TARGET = "admissible_ready.cli:main"

# Trust's surface by module basename, and the markers that name a credential
# loader. Both are checked against every module the wheel ships.
TRUST_MODULE_NAMES = ("attestation", "receipt", "review", "standing")
CREDENTIAL_MARKERS = ("credential", "signing", "keyring", "secret")

_STATE = {}


def built() -> dict:
    """Build Core and Ready once per interpreter, and remember the outcome.

    Failures are recorded rather than raised, so each test fails on its own
    contract with its own diagnostic instead of erroring out of a shared
    setup -- and so that "the wheel would not build" is never mistaken for
    "the separation does not hold".
    """

    if _STATE:
        return _STATE
    workspace = tempfile.TemporaryDirectory(prefix="admissible-ready-dist-")
    import atexit

    atexit.register(workspace.cleanup)
    root = Path(workspace.name)
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True, exist_ok=True)
    _STATE["workspace"] = root
    _STATE["wheelhouse"] = wheelhouse
    _STATE["error"] = None
    try:
        core = inspect_wheel.build_wheel(CORE_PROJECT, wheelhouse)
        ready = inspect_wheel.build_wheel(READY_PROJECT, wheelhouse)
        _STATE["core_path"] = core
        _STATE["ready_path"] = ready
        _STATE["core"] = inspect_wheel.inspect_wheel(core)
        _STATE["ready"] = inspect_wheel.inspect_wheel(ready)
    except inspect_wheel.WheelError as error:
        _STATE["error"] = str(error)
    return _STATE


def installed() -> dict:
    """A Ready-only environment: Core and Ready, with no resolver involved."""

    state = built()
    if "interpreter" in state or state["error"]:
        return state
    try:
        interpreter = inspect_wheel.create_venv(state["workspace"] / "ready-only")
        inspect_wheel.install_wheels(
            interpreter, [state["core_path"], state["ready_path"]])
        state["interpreter"] = interpreter
    except (inspect_wheel.WheelError, OSError,
            subprocess.SubprocessError) as error:
        state["error"] = f"could not prepare the Ready-only environment: {error}"
    return state


class BuiltCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = built()

    def wheel(self) -> inspect_wheel.Wheel:
        if self.state["error"]:
            self.fail(self.state["error"])
        return self.state["ready"]


class WheelMetadata(BuiltCase):
    """Name, version, floor, dependency: the four things pip reads."""

    def test_the_project_builds_one_wheel(self):
        if self.state["error"]:
            self.fail(self.state["error"])
        self.assertTrue(self.state["ready_path"].is_file())

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
        """A marked requirement is an edge the pin map cannot see.

        ``Requires-Dist: admissible; python_version >= "3.10"`` is satisfied by
        every interpreter this project supports, so it is not a condition at
        all -- it is the umbrella, and Trust with it, in every install.
        """
        self.assertEqual({}, self.wheel().conditional_requirements)

    def test_no_extra_is_declared(self):
        """``pip install admissible-ready[trust]`` must not be a door."""
        self.assertEqual([], self.wheel().provides_extra)

    def test_no_requirement_asks_for_an_extra_of_another_distribution(self):
        self.assertEqual([], self.wheel().requirements_requesting_extras)

    def test_trust_is_not_a_dependency_under_any_condition(self):
        wheel = self.wheel()
        for name in ("admissible-trust", "admissible"):
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

    def test_the_payload_is_exactly_the_ready_namespace(self):
        self.assertEqual({NAMESPACE}, self.wheel().top_level)

    def test_no_trust_module_is_in_the_archive(self):
        wheel = self.wheel()
        found = sorted(module for module in wheel.modules
                       if module.rpartition(".")[2] in TRUST_MODULE_NAMES)
        self.assertEqual([], found)

    def test_no_credential_loader_is_in_the_archive(self):
        wheel = self.wheel()
        found = sorted(module for module in wheel.modules
                       if any(marker in module.rpartition(".")[2]
                              for marker in CREDENTIAL_MARKERS))
        self.assertEqual([], found)

    def test_the_kernel_is_not_vendored(self):
        """Two copies of ``admissible_core`` is two kernels, and pip picks."""
        self.assertEqual([], self.wheel().members_under("admissible_core"))

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

    def test_the_modules_are_exactly_the_ones_this_task_creates(self):
        self.assertEqual(
            sorted([
                NAMESPACE,
                f"{NAMESPACE}.__main__",
                f"{NAMESPACE}.agent_connection",
                f"{NAMESPACE}.agent_mcp",
                f"{NAMESPACE}.cli",
                f"{NAMESPACE}.git_reader",
                f"{NAMESPACE}.github",
                f"{NAMESPACE}.ready",
                f"{NAMESPACE}.ready_server",
                f"{NAMESPACE}.ready_static",
                f"{NAMESPACE}.runner",
                f"{NAMESPACE}.store",
            ]),
            sorted(self.wheel().modules))

    def test_the_browser_assets_ship_with_their_source_bytes(self):
        wheel = self.wheel()
        source_root = REPO_ROOT / "admissible" / "ready_static"
        for name in ("index.html", "ready.css", "ready.js"):
            with self.subTest(asset=name):
                members = wheel.members_named(name)
                self.assertEqual(1, len(members), f"{name}: {members}")
                self.assertEqual(
                    hashlib.sha256(
                        (source_root / name).read_bytes()).hexdigest(),
                    wheel.sha256(members[0]))

    def test_the_ci_template_ships_with_its_source_bytes(self):
        wheel = self.wheel()
        source = REPO_ROOT / "admissible" / "templates" / "consumer-workflow.yml"
        members = wheel.members_named("consumer-workflow.yml")
        self.assertEqual(1, len(members), f"{members}")
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                         wheel.sha256(members[0]))

    def test_only_the_consumer_template_ships(self):
        """The reusable workflow and the action are the tool's, not a caller's."""
        wheel = self.wheel()
        for name in ("reusable-workflow.yml", "action.yml", "workflow.yml"):
            with self.subTest(template=name):
                self.assertEqual([], wheel.members_named(name))

    def test_no_test_module_is_shipped(self):
        wheel = self.wheel()
        self.assertEqual(
            [], sorted(m for m in wheel.modules if ".tests" in m
                       or m.rpartition(".")[2].startswith("test_")))

    def test_the_wheel_bytes_can_be_digested(self):
        """Printed in the completion receipt; asserted here so it exists."""
        digest = hashlib.sha256(self.wheel().path.read_bytes()).hexdigest()
        self.assertEqual(64, len(digest))


class ShippedTemplateMatchesTheRepository(unittest.TestCase):
    """The one duplicated file in the tree, and the guard against drift.

    ``admissible/templates/consumer-workflow.yml`` stays where it is until the
    umbrella task removes the legacy package, so for this release the bytes
    exist twice.  A second copy is a second answer waiting to happen, so it is
    pinned to the first.
    """

    def test_the_ready_copy_is_byte_identical_to_the_legacy_copy(self):
        legacy = REPO_ROOT / "admissible" / "templates" / "consumer-workflow.yml"
        shipped = (READY_PROJECT / "src" / "admissible_ready" / "templates"
                   / "consumer-workflow.yml")
        self.assertTrue(shipped.is_file(), f"{shipped} is missing")
        self.assertEqual(legacy.read_bytes(), shipped.read_bytes())

    def test_the_ready_assets_are_byte_identical_to_the_legacy_assets(self):
        for name in ("index.html", "ready.css", "ready.js", "__init__.py"):
            with self.subTest(asset=name):
                legacy = REPO_ROOT / "admissible" / "ready_static" / name
                shipped = (READY_PROJECT / "src" / "admissible_ready"
                           / "ready_static" / name)
                self.assertEqual(legacy.read_bytes(), shipped.read_bytes())


class SdistDerivedWheelAgrees(BuiltCase):
    """A wheel built from the sdist carries the same package data.

    ``package-data`` fills the wheel and ``MANIFEST.in`` fills the sdist. They
    are different mechanisms, and an entry present in one and missing from the
    other produces a direct wheel that works and a released wheel that does
    not.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.derived = None
        cls.reason = cls.state["error"]
        if cls.reason:
            return
        outdir = cls.state["workspace"] / "sdist"
        outdir.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            [inspect_wheel.sys.executable, "-m", "build", "--sdist",
             "--no-isolation", "--outdir", str(outdir), str(READY_PROJECT)],
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

    def test_the_sdist_carries_the_browser_assets_and_the_template(self):
        self.sdist_wheel()
        with tarfile.open(self.sdist) as archive:
            names = {Path(name).name for name in archive.getnames()}
        for name in ("index.html", "ready.css", "ready.js",
                     "consumer-workflow.yml"):
            with self.subTest(member=name):
                self.assertIn(name, names)

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


class TaskTwoReadyAssertionsAreSatisfiable(BuiltCase):
    """The Ready half of the separation contract, evaluated against this wheel.

    ``tests/architecture/test_distribution_separation`` is the contract, and it
    stays RED until all four projects exist -- it builds every one of them and
    every assertion blocks on the two that do not.  That is correct and it is
    also uninformative about *this* task: "the suite is red" says nothing about
    whether the Ready wheel would satisfy it.

    So the Ready-specific predicates are imported from that module -- not
    retyped -- and applied to the wheel this project builds.  If the contract
    changes there, this follows; if this wheel stops satisfying it, this goes
    red long before the whole separation suite can turn green.
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
        self.assertEqual([],
                         self.contract.marked_requirements(self.wheel()))

    def test_the_expected_console_entry_points_are_this_wheel_s(self):
        self.assertEqual(self.contract.READY_PROJECT.entry_points,
                         self.wheel().console_scripts)

    def test_the_manifest_derived_trust_surface_is_absent(self):
        """``TRUST_ONLY_MODULES`` comes from the ownership manifest, not a list."""
        wheel = self.wheel()
        self.assertTrue(self.contract.TRUST_ONLY_MODULES,
                        "the manifest must name a Trust surface")
        self.assertEqual(
            [], sorted(module for module in wheel.modules
                       if module.rpartition(".")[2]
                       in self.contract.TRUST_ONLY_MODULES))

    def test_the_contract_s_credential_markers_match_nothing_here(self):
        wheel = self.wheel()
        self.assertEqual(
            [], sorted(module for module in wheel.modules
                       if any(marker in module.rpartition(".")[2]
                              for marker in
                              self.contract.CREDENTIAL_LOADER_MARKERS)))

    def test_the_runner_surface_the_contract_names_is_all_present_here(self):
        """The mirror image: what Trust must not ship, Ready must."""
        wheel = self.wheel()
        shipped = {module.rpartition(".")[2] for module in wheel.modules}
        self.assertEqual(
            [], sorted(set(self.contract.RUNNER_ONLY_MODULES) - shipped),
            "Ready owns the execution surface Trust is forbidden")

    def test_every_project_the_separation_contract_names_now_exists(self):
        """Why the separation suite can be green, stated rather than guessed.

        This task created Ready, Task 5 created Trust and Task 6 created the
        umbrella.  The contract suite builds all four and blocks on any that is
        missing, so asserting the set here keeps "green because everything is
        built" from being confused with "green because nothing was checked".
        """

        for project in self.contract.PROJECTS:
            with self.subTest(project=project.directory):
                self.assertTrue((project.path / "pyproject.toml").is_file())
        self.assertEqual(4, len(self.contract.PROJECTS))


class ReadyOnlyEnvironmentCase(unittest.TestCase):
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

    def run_command(self, *args: str, **kwargs) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.script(CONSOLE_SCRIPT)), *args], capture_output=True,
            text=True, timeout=inspect_wheel.RUN_TIMEOUT,
            cwd=str(self.environment()), env=inspect_wheel.sanitized_env(),
            **kwargs)


class ImportAbsence(ReadyOnlyEnvironmentCase):
    """The question a user's process actually asks."""

    def test_trust_and_the_umbrella_are_both_unimportable(self):
        self.assertEqual(
            {"admissible_core": True, "admissible_ready": True,
             "admissible_trust": False, "admissible": False},
            inspect_wheel.importable(
                self.interpreter(), "admissible_core", "admissible_ready",
                "admissible_trust", "admissible"))

    def test_every_trust_module_name_is_unreachable(self):
        names = [f"admissible_trust.{module}" for module in TRUST_MODULE_NAMES]
        names += [f"admissible.{module}" for module in TRUST_MODULE_NAMES]
        self.assertEqual(
            {name: False for name in names},
            inspect_wheel.importable(self.interpreter(), *names))

    def test_every_ready_module_is_importable_from_the_wheel(self):
        names = [f"{NAMESPACE}.{module}" for module in (
            "cli", "git_reader", "runner", "store", "ready", "github",
            "agent_connection", "agent_mcp", "ready_server", "ready_static")]
        self.assertEqual({name: True for name in names},
                         inspect_wheel.importable(self.interpreter(), *names))

    def test_no_trust_file_is_anywhere_under_an_admissible_package(self):
        completed = inspect_wheel.run_python(self.interpreter(), _SITE_PACKAGES)
        self.assertEqual(0, completed.returncode, completed.stderr)
        installed = json.loads(completed.stdout)
        self.assertTrue(installed, "nothing named admissible* was installed")
        for basename in TRUST_MODULE_NAMES:
            with self.subTest(module=basename):
                self.assertEqual(
                    [], [name for name in installed
                         if name.rsplit("/", 1)[-1] == f"{basename}.py"])

    def test_the_installed_python_files_are_the_kernel_and_ready_only(self):
        completed = inspect_wheel.run_python(self.interpreter(), _SITE_PACKAGES)
        self.assertEqual(0, completed.returncode, completed.stderr)
        installed = json.loads(completed.stdout)
        packages = {name.partition("/")[0] for name in installed}
        self.assertEqual({"admissible_core", "admissible_ready"}, packages)

    def test_no_other_command_is_installed(self):
        for command in ("admissible", "admissible-trust"):
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


class InstalledCommandRuns(ReadyOnlyEnvironmentCase):
    """The command works from its wheel, in a sanitized environment."""

    def test_help_answers_and_names_the_ready_commands(self):
        completed = self.run_command("--help")
        self.assertEqual(0, completed.returncode, completed.stderr)
        for command in ("profiles", "init", "run --preview", "check", "mcp",
                        "connect", "ui"):
            with self.subTest(command=command):
                self.assertIn(command, completed.stdout)

    def test_help_does_not_offer_a_trust_command(self):
        completed = self.run_command("--help")
        for absent in ("ready-status", "attest-review", "finalize", "impeach"):
            with self.subTest(command=absent):
                self.assertNotIn(f"\n  {absent} ", completed.stdout)

    def test_a_trust_command_is_unknown_rather_than_refused(self):
        completed = self.run_command("finalize", "--json")
        self.assertEqual(2, completed.returncode)

    def test_profiles_prints_the_shipped_profiles(self):
        completed = self.run_command("profiles", "--json")
        self.assertEqual(0, completed.returncode, completed.stderr)
        names = [row["name"]
                 for row in json.loads(completed.stdout)["profiles"]]
        self.assertIn("python-library", names)

    def test_a_credential_makes_the_installed_command_refuse(self):
        completed = subprocess.run(
            [str(self.script(CONSOLE_SCRIPT)), "check", "--json"],
            capture_output=True, text=True,
            timeout=inspect_wheel.RUN_TIMEOUT, cwd=str(self.environment()),
            env=inspect_wheel.sanitized_env(
                {"ADMISSIBLE_HMAC_KEY": "not-a-real-key"}))
        self.assertEqual(2, completed.returncode)
        self.assertIn("ADMISSIBLE_HMAC_KEY", completed.stdout)


class InstalledCommandEvaluates(ReadyOnlyEnvironmentCase):
    """A real repository, scaffolded and evaluated by the installed wheel."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.repo = None
        if cls.state["error"]:
            return
        cls.repo = cls.state["workspace"] / "candidate"
        cls.repo.mkdir(parents=True, exist_ok=True)
        cls.home = cls.state["workspace"] / "candidate-home"
        for args in (("init", "--quiet"),
                     ("config", "user.email", "e2e@example.com"),
                     ("config", "user.name", "E2E")):
            subprocess.run(("git", "-C", str(cls.repo), *args), check=True,
                           timeout=60, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)

    def environment_variables(self) -> dict[str, str]:
        return inspect_wheel.sanitized_env({"ADMISSIBLE_HOME": str(self.home)})

    def command(self, *args: str, stdin: str | None = None):
        self.interpreter()
        return subprocess.run(
            [str(self.script(CONSOLE_SCRIPT)), *args], capture_output=True,
            text=True, timeout=inspect_wheel.RUN_TIMEOUT,
            cwd=str(self.environment()), env=self.environment_variables(),
            input=stdin)

    def git(self, *args: str) -> None:
        subprocess.run(("git", "-C", str(self.repo), *args), check=True,
                       timeout=60, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)

    def scaffold(self) -> None:
        completed = self.command(
            "init", "--repo", str(self.repo), "--profile", "python-library",
            "--force", "--json")
        self.assertEqual(0, completed.returncode, completed.stderr)
        policy = json.loads(
            (self.repo / ".admissible.json").read_text(encoding="utf-8"))
        policy["classes"][0]["checks"] = [{
            "id": "one", "version": "1", "argv": ["/usr/bin/true"],
            "timeout_seconds": 30, "cost_units": 1, "required": True,
            "description": "A command every machine has.",
            "cacheable": True, "cache_max_age_seconds": 86400,
        }]
        (self.repo / ".admissible.json").write_text(
            json.dumps(policy, indent=2) + "\n", encoding="utf-8")
        self.git("add", "-A")
        # These tests share one repository, so a later one may find the tree
        # already clean. An exact-SHA run refuses a dirty worktree and says
        # nothing about a clean one, so committing only what changed is what
        # keeps the fixture usable in any order.
        status = subprocess.run(
            ("git", "-C", str(self.repo), "status", "--porcelain"),
            capture_output=True, text=True, check=True, timeout=60)
        if status.stdout.strip():
            self.git("commit", "--quiet", "-m", "policy")

    def test_init_scaffolds_a_policy_from_the_installed_wheel(self):
        completed = self.command(
            "init", "--repo", str(self.repo), "--profile", "python-library",
            "--force", "--json")
        self.assertEqual(0, completed.returncode, completed.stderr)
        document = json.loads(completed.stdout)
        self.assertEqual([], document["trusted"])
        self.assertTrue((self.repo / ".admissible.json").is_file())

    def test_init_with_ci_writes_the_packaged_template(self):
        completed = self.command(
            "init", "--repo", str(self.repo), "--profile", "python-library",
            "--force", "--ci", "github", "--tool-sha", "0" * 40, "--json")
        self.assertEqual(0, completed.returncode, completed.stderr)
        workflow = (self.repo / ".github" / "workflows" / "admissible.yml")
        self.assertTrue(workflow.is_file())
        body = workflow.read_text(encoding="utf-8")
        self.assertIn("0" * 40, body)
        self.assertNotIn("TOOL_SHA_PLACEHOLDER", body)

    def test_check_evaluates_and_stays_unsigned(self):
        self.scaffold()
        completed = self.command("check", "--repo", str(self.repo), "--json")
        self.assertEqual(0, completed.returncode, completed.stderr)
        document = json.loads(completed.stdout)
        self.assertEqual("checks_complete", document["status"])
        self.assertEqual("CHECKS_PASSED", document["canonical"]["state"])
        self.assertNotEqual("ready", document["status"])

    def test_run_preview_writes_a_preview_the_finalizer_would_read(self):
        self.scaffold()
        preview = self.state["workspace"] / "preview.json"
        completed = self.command(
            "run", "--preview", "--repo", str(self.repo), "--json",
            "--preview-out", str(preview))
        self.assertEqual(0, completed.returncode, completed.stderr)
        document = json.loads(preview.read_text(encoding="utf-8"))
        self.assertEqual("admissible/v0.6/workflow-preview", document["schema"])
        self.assertEqual("CHECKS_PASSED", document["state"])
        self.assertEqual("none", document["isolation"])
        self.assertFalse(document["fork"])

    def test_the_mcp_handshake_works_over_real_stdio(self):
        self.scaffold()
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "canary"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "admissible_get_state", "arguments": {}}},
        ]
        completed = self.command(
            "mcp", "--repo", str(self.repo), "--agent-name", "canary",
            "--purpose", "prove the wheel speaks MCP", "--runtime", "local",
            stdin="".join(json.dumps(item) + "\n" for item in requests))
        self.assertEqual(0, completed.returncode, completed.stderr)
        frames = [json.loads(line)
                  for line in completed.stdout.splitlines() if line]
        self.assertEqual(3, len(frames), completed.stdout)
        self.assertEqual("2025-06-18",
                         frames[0]["result"]["protocolVersion"])
        self.assertEqual("admissible-ready",
                         frames[0]["result"]["serverInfo"]["name"])
        self.assertEqual(
            ["admissible_check", "admissible_get_remediation",
             "admissible_get_state", "admissible_get_work_package"],
            sorted(tool["name"] for tool in frames[1]["result"]["tools"]))
        state = frames[2]["result"]["structuredContent"]
        self.assertEqual("admissible/v0.7/ready-state", state["schema"])

    def test_the_loopback_server_serves_its_assets_and_api(self):
        self.scaffold()
        completed = inspect_wheel.run_python(
            self.interpreter(), _LOOPBACK_CANARY, str(self.repo),
            timeout=inspect_wheel.RUN_TIMEOUT)
        self.assertEqual(0, completed.returncode, completed.stderr)
        answers = json.loads(completed.stdout)
        self.assertEqual(200, answers["index"]["status"])
        self.assertIn("<!doctype html", answers["index"]["body"].lower())
        self.assertEqual(200, answers["css"]["status"])
        self.assertEqual(200, answers["js"]["status"])
        self.assertEqual(200, answers["state"]["status"])
        self.assertEqual("admissible/v0.7/ready-state",
                         answers["state"]["schema"])
        self.assertIn(answers["state"]["ready_status"],
                      ("needs_attention", "waiting_for_review",
                       "checks_complete", "unable_to_check"))
        self.assertEqual(403, answers["cross_origin"]["status"])


_LOOPBACK_CANARY = """
import json
import sys
import threading
import urllib.error
import urllib.request

from admissible_ready import ready_server

repo = sys.argv[1]
server = ready_server.make_server(repo, port=0)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
base = "http://127.0.0.1:%d" % server.server_address[1]


def fetch(path, headers):
    request = urllib.request.Request(base + path, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read().decode("utf-8", "replace")


answers = {}
local = {"X-Admissible-Ready": "1"}
for name, path in (("index", "/"), ("css", "/ready.css"), ("js", "/ready.js")):
    status, body = fetch(path, {})
    answers[name] = {"status": status, "body": body[:200]}
status, body = fetch("/api/v1/state", local)
document = json.loads(body) if status == 200 else {}
answers["state"] = {"status": status, "schema": document.get("schema"),
                    "ready_status": document.get("status")}
status, _ = fetch("/api/v1/state", {"Origin": "http://evil.example"})
answers["cross_origin"] = {"status": status}
server.shutdown()
server.server_close()
print(json.dumps(answers))
"""
