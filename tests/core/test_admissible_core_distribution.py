"""Contract: ``admissible-core==0.8.1`` builds, ships, and installs as itself.

Task 2's separation suite asserts the whole four-way split and stays red until
every project exists.  This one is narrower on purpose: it is the Core half of
that contract, stated so it can be satisfied and kept satisfied now, and so a
Core regression fails as a Core failure rather than as one more line in a suite
that is red for a different reason.

Every claim is read out of the built archive.  A build's exit status says the
backend did not crash; it does not say which files came out, and "the wheel
contains the schema" is a statement about bytes.  The installation half is
separate again, because containment and importability are different claims: a
module can be in the archive and still not land on ``sys.path``, and a wheel
that installs is the artefact a user actually gets.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.architecture import inspect_wheel

from . import CORE_PROJECT, REPO_ROOT

DISTRIBUTION = "admissible-core"
NAMESPACE = "admissible_core"
VERSION = "0.8.1"
REQUIRES_PYTHON = ">=3.10"

# Core carries the kernel plus the shared roots every dependent needs.  Stated
# as an equality: a wheel with one namespace more than this is a wheel whose
# authority is not the one it claims, and no list of prohibitions written today
# can name a namespace nobody has invented yet.
EXPECTED_TOP_LEVEL = {NAMESPACE, "fcd", "rga", "atlas", "protocol"}

# Namespaces that belong to the other three distributions, or to nothing that
# ships at all.  ``atlas.tests`` is here because it imports the top-level
# ``tests`` package, which no wheel ships: shipping it would make the installed
# ``atlas`` un-importable in the one place it matters.
FORBIDDEN_MEMBERS = ("admissible", "admissible_ready", "admissible_trust",
                     "server", "tests", "atlas.tests")

SCHEMA_SOURCE = REPO_ROOT / "protocol"

# Directories a build could leave behind in the checkout, watched as a set so
# that a *new* stray name is caught rather than only the ones seen so far.
WATCHED_FOR_RESIDUE = (REPO_ROOT / "packages", REPO_ROOT)


def repository_residue() -> set[str]:
    """Top-level entries of the directories a build could pollute.

    Compared before and after a build.  Ignored build artefacts are filtered
    out because they are expected; anything else appearing is not.
    """
    ignored = {"build", "__pycache__", ".DS_Store"}
    found = set()
    for directory in WATCHED_FOR_RESIDUE:
        for entry in directory.iterdir():
            if entry.name in ignored or entry.name.endswith(".egg-info"):
                continue
            found.add(str(entry.relative_to(REPO_ROOT)))
    return found


_BUILD: dict = {}


def built_wheel() -> inspect_wheel.Wheel:
    """Build Core once per interpreter and hand back the inspected archive."""
    if "wheel" not in _BUILD:
        workspace = tempfile.TemporaryDirectory(prefix="admissible-core-build-")
        atexit.register(workspace.cleanup)
        path = inspect_wheel.build_wheel(CORE_PROJECT, Path(workspace.name))
        _BUILD["workspace"] = workspace
        _BUILD["wheel"] = inspect_wheel.inspect_wheel(path)
    return _BUILD["wheel"]


class CoreWheelCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wheel = built_wheel()


class CoreProjectBuilds(unittest.TestCase):
    def test_the_project_directory_is_a_buildable_project(self):
        self.assertTrue(
            (CORE_PROJECT / "pyproject.toml").is_file(),
            f"{CORE_PROJECT}/pyproject.toml must exist",
        )

    def test_building_produces_one_wheel_whose_bytes_can_be_digested(self):
        wheel = built_wheel()
        digest = hashlib.sha256(wheel.path.read_bytes()).hexdigest()
        self.assertEqual(64, len(digest))
        self.assertTrue(wheel.path.name.startswith("admissible_core-0.8.1-"))
        self.assertTrue(wheel.path.name.endswith(".whl"))


class CoreWheelMetadata(CoreWheelCase):
    def test_the_distribution_is_named_and_versioned_as_agreed(self):
        self.assertEqual(DISTRIBUTION, self.wheel.name)
        self.assertEqual(VERSION, self.wheel.version)

    def test_the_python_floor_is_declared(self):
        self.assertEqual(REQUIRES_PYTHON, self.wheel.requires_python)

    def test_core_depends_on_nothing_at_all(self):
        """Core is the floor; a floor with dependencies can pull the split back."""
        self.assertEqual([], self.wheel.requires_dist)
        self.assertEqual({}, self.wheel.unconditional_requirements)
        self.assertEqual({}, self.wheel.conditional_requirements)
        self.assertEqual([], self.wheel.provides_extra)

    def test_core_installs_no_console_command(self):
        self.assertEqual({}, self.wheel.console_scripts)
        self.assertEqual("", self.wheel.entry_points_text)


class CoreWheelPayload(CoreWheelCase):
    def test_the_shipped_namespaces_are_exactly_the_agreed_set(self):
        self.assertEqual(
            EXPECTED_TOP_LEVEL, self.wheel.top_level,
            f"{self.wheel.path.name} installs "
            f"{sorted(self.wheel.installed_paths)[:20]}",
        )

    def test_the_kernel_namespace_is_shipped(self):
        self.assertTrue(self.wheel.owns(NAMESPACE))
        self.assertIn(f"{NAMESPACE}.schema", self.wheel.modules)
        self.assertIn(f"{NAMESPACE}.decision", self.wheel.modules)
        self.assertIn(f"{NAMESPACE}.store_base", self.wheel.modules)

    def test_the_research_roots_ride_along_rather_than_being_duplicated(self):
        for namespace in ("fcd", "rga", "atlas", "protocol"):
            with self.subTest(namespace=namespace):
                self.assertTrue(self.wheel.owns(namespace))

    def test_no_forbidden_namespace_is_anywhere_in_the_archive(self):
        strays = []
        for namespace in FORBIDDEN_MEMBERS:
            strays += [f"{namespace}:{path}"
                       for path in self.wheel.members_under(namespace)]
        self.assertEqual([], strays)

    def test_the_atlas_test_suite_is_not_shipped(self):
        """It imports the top-level ``tests`` package, which no wheel ships."""
        self.assertEqual([], self.wheel.members_under("atlas.tests"))
        self.assertEqual(
            [], sorted(m for m in self.wheel.modules if ".tests" in m))

    def test_no_browser_asset_or_workflow_template_is_shipped(self):
        """Static assets and CI templates belong to Ready, not to the kernel."""
        assets = sorted(
            member for member in self.wheel.payload
            if member.endswith((".html", ".css", ".js", ".yml"))
        )
        self.assertEqual([], assets)

    def test_every_shipped_module_is_a_module_core_or_research_owns(self):
        outside = sorted(
            module for module in self.wheel.modules
            if module.split(".")[0] not in EXPECTED_TOP_LEVEL
        )
        self.assertEqual([], outside)


class CoreShipsTheSchemaResources(CoreWheelCase):
    """One schema, one owner, one copy, and the same bytes as the source."""

    def source_schemas(self) -> dict[str, str]:
        return {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(SCHEMA_SOURCE.glob("*.json"))
        }

    def test_the_canonical_source_is_not_empty(self):
        self.assertTrue(self.source_schemas())

    def test_every_schema_ships_exactly_once_with_matching_bytes(self):
        for basename, digest in sorted(self.source_schemas().items()):
            with self.subTest(schema=basename):
                members = self.wheel.members_named(basename)
                self.assertEqual(1, len(members),
                                 f"{basename} ships {len(members)} times: {members}")
                self.assertEqual(f"protocol/{basename}", members[0])
                self.assertEqual(digest, self.wheel.sha256(members[0]),
                                 f"{members[0]} has drifted from the source")

    def test_the_shipped_schema_set_is_the_source_schema_set(self):
        shipped = sorted(
            member.rsplit("/", 1)[-1] for member in self.wheel.payload
            if member.startswith("protocol/") and member.endswith(".json")
        )
        self.assertEqual(sorted(self.source_schemas()), shipped)


class CoreSdistCarriesEverythingItNeeds(unittest.TestCase):
    """The source distribution builds the same wheel, and leaves no residue.

    Core packages four namespaces the project directory does not contain, so
    the sdist is where that arrangement is most easily wrong: setuptools has
    nowhere inside the archive to put a file whose path leaves the project, and
    the naive spelling of this mapping silently wrote those files into sibling
    directories of the checkout instead -- an sdist missing four packages, and
    a working tree the gate would refuse.

    So both halves are asserted: what came out, and what was left behind.
    """

    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="admissible-core-sdist-")
        root = Path(cls.workspace.name)
        cls.before = repository_residue()
        cls.completed = subprocess.run(
            [sys.executable, "-m", "build", "--sdist", "--no-isolation",
             "--outdir", str(root / "dist"), str(CORE_PROJECT)],
            capture_output=True, text=True, timeout=inspect_wheel.BUILD_TIMEOUT,
            cwd=str(CORE_PROJECT), env=inspect_wheel.sanitized_env(),
        )
        cls.after = repository_residue()
        cls.sdists = sorted((root / "dist").glob("*.tar.gz"))
        cls.root = root

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def sdist(self) -> Path:
        self.assertEqual(0, self.completed.returncode,
                         f"sdist build failed:\n{self.completed.stderr}")
        self.assertEqual(1, len(self.sdists), f"built {self.sdists}")
        return self.sdists[0]

    def members(self) -> list[str]:
        with tarfile.open(self.sdist()) as archive:
            return sorted(archive.getnames())

    def test_the_sdist_is_named_for_the_distribution_and_version(self):
        self.assertEqual("admissible_core-0.8.1.tar.gz", self.sdist().name)

    def test_the_sdist_carries_every_namespace_the_wheel_ships(self):
        members = self.members()
        for namespace in sorted(EXPECTED_TOP_LEVEL):
            with self.subTest(namespace=namespace):
                self.assertTrue(
                    any(f"/{namespace}/" in f"{member}/" for member in members),
                    f"{namespace} is not in the sdist",
                )

    def test_the_sdist_carries_the_backend_that_builds_it(self):
        """``backend-path`` names a file; an sdist without it cannot build."""
        self.assertIn("admissible_core-0.8.1/build_backend.py", self.members())

    def test_the_sdist_prunes_the_atlas_test_suite(self):
        stowaways = [member for member in self.members() if "/atlas/tests" in member]
        self.assertEqual([], stowaways)

    def test_the_sdist_schema_bytes_are_the_source_bytes(self):
        expected = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(SCHEMA_SOURCE.glob("*.json"))
        }
        found = {}
        with tarfile.open(self.sdist()) as archive:
            for member in archive.getmembers():
                name = member.name.rsplit("/", 1)[-1]
                if member.isfile() and name in expected:
                    found[name] = hashlib.sha256(
                        archive.extractfile(member).read()).hexdigest()
        self.assertEqual(expected, found)

    def test_building_the_sdist_left_nothing_behind_in_the_checkout(self):
        """The staged copies are transient; a leftover copy is a dirty tree."""
        self.sdist()
        self.assertEqual(self.before, self.after)
        self.assertFalse((CORE_PROJECT / "_staged").exists())

    def test_a_wheel_built_from_the_sdist_ships_the_same_namespaces(self):
        """The claim that makes the sdist worth having at all."""
        extracted = self.root / "extracted"
        with tarfile.open(self.sdist()) as archive:
            archive.extractall(extracted, filter="data")
        project = extracted / "admissible_core-0.8.1"
        rebuilt = inspect_wheel.inspect_wheel(
            inspect_wheel.build_wheel(project, self.root / "rebuilt"))
        self.assertEqual(EXPECTED_TOP_LEVEL, rebuilt.top_level)
        self.assertEqual(DISTRIBUTION, rebuilt.name)
        self.assertEqual(VERSION, rebuilt.version)
        self.assertEqual([], rebuilt.requires_dist)
        self.assertEqual({}, rebuilt.console_scripts)
        # Same modules as the direct build, so the two routes cannot diverge.
        self.assertEqual(built_wheel().modules, rebuilt.modules)

    def test_a_wheel_built_from_the_sdist_names_the_pinned_generator(self):
        """Project metadata must not impersonate the setuptools version."""
        extracted = self.root / "generator-extracted"
        with tarfile.open(self.sdist()) as archive:
            archive.extractall(extracted, filter="data")
        project = extracted / "admissible_core-0.8.1"
        wheel = inspect_wheel.build_wheel(project, self.root / "generator-wheel")
        with zipfile.ZipFile(wheel) as archive:
            member = next(
                name for name in archive.namelist()
                if name.endswith(".dist-info/WHEEL"))
            metadata = archive.read(member).decode("utf-8")
        self.assertIn("Generator: setuptools (83.0.0)\n", metadata)
        self.assertNotIn("Generator: setuptools (0.8.1)\n", metadata)


class CoreInstallsAndImports(unittest.TestCase):
    """The wheel is installed offline into a throwaway environment and used.

    Containment is not importability.  This is the question a user's process
    actually asks, answered from a sanitized environment so the checkout on
    the developer's ``PYTHONPATH`` cannot answer it instead.
    """

    interpreter: Path

    @classmethod
    def setUpClass(cls):
        wheel = built_wheel()
        cls.workspace = tempfile.TemporaryDirectory(prefix="admissible-core-env-")
        root = Path(cls.workspace.name) / "core-only"
        cls.interpreter = inspect_wheel.create_venv(root)
        inspect_wheel.install_wheels(cls.interpreter, [wheel.path])

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def test_the_kernel_and_the_research_roots_import(self):
        self.assertEqual(
            {NAMESPACE: True, f"{NAMESPACE}.decision": True,
             f"{NAMESPACE}.store_candidate": True,
             "fcd": True, "rga": True, "atlas": True, "protocol": True},
            inspect_wheel.importable(
                self.interpreter, NAMESPACE, f"{NAMESPACE}.decision",
                f"{NAMESPACE}.store_candidate", "fcd", "rga", "atlas",
                "protocol"),
        )

    def test_no_other_distribution_became_importable(self):
        self.assertEqual(
            {"admissible": False, "admissible_ready": False,
             "admissible_trust": False, "server": False, "atlas.tests": False},
            inspect_wheel.importable(
                self.interpreter, "admissible", "admissible_ready",
                "admissible_trust", "server", "atlas.tests"),
        )

    def test_the_installed_kernel_reports_its_own_version(self):
        completed = inspect_wheel.run_python(
            self.interpreter,
            "import admissible_core; print(admissible_core.__version__)")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(VERSION, completed.stdout.strip())

    def test_the_installed_kernel_loads_a_schema_and_decides(self):
        """A smoke test that exercises resources, digests and the decision path."""
        code = (
            "import json\n"
            "from admissible_core import schema, profiles, config, "
            "evidence, decision\n"
            "document = profiles.profile_document('python-library')\n"
            "policy = config.parse_config(document, allow_placeholders=True)\n"
            "print(json.dumps({\n"
            "  'schema_id': schema.evidence_schema()['$id'],\n"
            "  'policy_digest': policy.policy_digest,\n"
            "  'states': [decision.CHECKS_PASSED, decision.REFUSED],\n"
            "  'evidence_names': len(evidence.__all__),\n"
            "}))\n"
        )
        completed = inspect_wheel.run_python(self.interpreter, code)
        self.assertEqual(0, completed.returncode, completed.stderr)
        summary = json.loads(completed.stdout)
        self.assertTrue(summary["schema_id"])
        self.assertEqual(64, len(summary["policy_digest"]))
        self.assertGreater(summary["evidence_names"], 0)

    def test_the_installed_policy_digest_is_the_checkout_policy_digest(self):
        """The wheel must not quietly carry a different kernel to the source."""
        from admissible_core import config as core_config
        from admissible_core import profiles as core_profiles

        expected = core_config.parse_config(
            core_profiles.profile_document("python-library"),
            allow_placeholders=True).policy_digest
        completed = inspect_wheel.run_python(
            self.interpreter,
            "from admissible_core import config, profiles;"
            "print(config.parse_config(profiles.profile_document"
            "('python-library'), allow_placeholders=True).policy_digest)")
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(expected, completed.stdout.strip())

    def test_no_console_command_was_installed(self):
        environment = self.interpreter.parent.parent
        for command in ("admissible", "admissible-ready", "admissible-trust",
                        "admissible-core"):
            with self.subTest(command=command):
                self.assertFalse(
                    inspect_wheel.venv_script(environment, command).exists(),
                    f"{command} must not be installed by Core",
                )


if __name__ == "__main__":
    unittest.main()
