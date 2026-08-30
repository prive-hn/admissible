"""Contract: bounded live output, stable failure reporting, honest packaging."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import (TempCase, git, make_repo,  # noqa: E402
                                require_module)

cli = require_module("admissible.cli")
config_module = require_module("admissible.config")
runner = require_module("admissible.runner")

ROOT = Path(__file__).resolve().parent.parent


class BoundedOutputTest(TempCase):
    """E23: storage stays bounded while the child is still producing."""

    def check(self, argv, *, timeout=120):
        return config_module.Check(
            id="loud", argv=tuple(argv), timeout_seconds=timeout,
            cost_units=1, required=True, version="1")

    def test_a_high_volume_producer_never_fills_the_disk(self):
        limit = 4096
        script = (
            "import sys\n"
            "block = b'x' * 65536\n"
            "for _ in range(512):\n"
            "    sys.stdout.buffer.write(block)\n"
            "    sys.stderr.buffer.write(block)\n"
            "sys.stdout.buffer.flush()\n")
        log_dir = self.tmp / "logs"
        result = runner.run_check(
            self.check([sys.executable, "-c", script]), cwd=str(self.tmp),
            log_dir=log_dir, max_output_bytes=limit)
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.output_truncated)
        self.assertEqual(result.stdout_bytes, limit)
        self.assertEqual(result.stderr_bytes, limit)
        written = sum(path.stat().st_size for path in log_dir.rglob("*"))
        self.assertLess(written, 4 * limit + 4096,
                        f"the private log grew to {written} bytes")

    def test_retained_bytes_hash_exactly_what_the_log_keeps(self):
        import hashlib

        limit = 1024
        script = ("import sys\n"
                  "sys.stdout.buffer.write(b'a' * 100000)\n")
        log_dir = self.tmp / "logs"
        result = runner.run_check(
            self.check([sys.executable, "-c", script]), cwd=str(self.tmp),
            log_dir=log_dir, max_output_bytes=limit)
        log = next(iter(log_dir.rglob("*.log")))
        kept = runner.read_stdout_bytes(log)
        self.assertEqual(len(kept), limit)
        self.assertEqual(hashlib.sha256(kept).hexdigest(), result.stdout_sha256)

    def test_a_timeout_kills_a_noisy_child_and_stays_bounded(self):
        script = ("import sys, time\n"
                  "while True:\n"
                  "    sys.stdout.buffer.write(b'y' * 65536)\n")
        log_dir = self.tmp / "logs"
        result = runner.run_check(
            self.check([sys.executable, "-u", "-c", script], timeout=1),
            cwd=str(self.tmp), log_dir=log_dir, max_output_bytes=2048)
        self.assertTrue(result.timed_out)
        written = sum(path.stat().st_size for path in log_dir.rglob("*"))
        self.assertLess(written, 32768)

    def test_no_unbounded_scratch_file_is_created(self):
        source = (ROOT / "admissible" / "runner.py").read_text(encoding="utf-8")
        self.assertNotIn("TemporaryDirectory", source)


class OperationalFailureTest(TempCase):
    """E24: filesystem failures still honour the exit-2 JSON/prose contract."""

    def run_cli(self, *argv):
        # `run` evaluates and never signs, so it always previews.
        argv = tuple(argv)
        if argv[:1] == ("run",) and "--preview" not in argv:
            argv = ("run", "--preview") + argv[1:]
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(list(argv), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def read_only(self) -> Path:
        target = self.tmp / "read-only"
        target.mkdir()
        os.chmod(target, 0o500)
        self.addCleanup(lambda: os.chmod(target, 0o700))
        return target

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_init_into_a_read_only_directory_reports_json(self):
        target = self.read_only()
        code, out, err = self.run_cli("init", "--profile", "python-library",
                                      "--repo", str(target), "--json")
        self.assertEqual(code, 2, out + err)
        document = json.loads(out)
        self.assertEqual(document["state"], "BLOCKED")
        self.assertTrue(document["message"])

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_init_into_a_read_only_directory_reports_prose(self):
        target = self.read_only()
        code, out, err = self.run_cli("init", "--profile", "python-library",
                                      "--repo", str(target))
        self.assertEqual(code, 2, out + err)
        self.assertIn("BLOCKED", err)
        self.assertNotIn("Traceback", err)

    def test_an_unusable_log_directory_is_reported_not_raised(self):
        root = self.tmp / "candidate"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps({
                "version": 1, "profile": "python-library",
                "classes": [{"id": "default", "checks": [
                    {"id": "unit", "argv": ["python3", "-c", "pass"],
                     "timeout_seconds": 60, "cost_units": 1,
                     "required": True, "version": "1"}],
                    "required_independent_reviews": 0,
                    "review_max_age_seconds": 86400,
                    "max_cost_units": 10, "max_wall_seconds": 600}]})})
        # A plain file where the private log directory must go: mkdir cannot
        # succeed and no amount of chmod repairs it.
        (self.home / "logs").write_text("not a directory", encoding="utf-8")
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--preview", "--json")
        self.assertEqual(code, 2, out + err)
        document = json.loads(out)
        self.assertEqual(document["state"], "BLOCKED")

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_an_uncreatable_store_home_is_reported_not_raised(self):
        parent = self.read_only()
        os.environ["ADMISSIBLE_HOME"] = str(parent / "admissible-home")
        root = self.tmp / "candidate-home"
        make_repo(root)
        code, out, err = self.run_cli("status", "--repo", str(root), "--json")
        self.assertEqual(code, 2, out + err)
        self.assertEqual(json.loads(out)["state"], "BLOCKED")

    def test_an_unwritable_preview_path_is_reported_not_raised(self):
        root = self.tmp / "candidate2"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps({
                "version": 1, "profile": "python-library",
                "classes": [{"id": "default", "checks": [
                    {"id": "unit", "argv": ["python3", "-c", "pass"],
                     "timeout_seconds": 60, "cost_units": 1,
                     "required": True, "version": "1"}],
                    "required_independent_reviews": 0,
                    "review_max_age_seconds": 86400,
                    "max_cost_units": 10, "max_wall_seconds": 600}]})})
        code, out, err = self.run_cli(
            "run", "--repo", str(root), "--sha", sha, "--preview-out",
            str(self.tmp / "missing" / "dir" / "p.json"),
            "--json")
        self.assertEqual(code, 2, out + err)
        self.assertEqual(json.loads(out)["state"], "BLOCKED")

    def test_an_unreadable_store_is_reported_not_raised(self):
        os.environ["ADMISSIBLE_HOME"] = str(self.tmp / "not-a-dir")
        (self.tmp / "not-a-dir").write_text("i am a file", encoding="utf-8")
        code, out, err = self.run_cli("status", "--repo", str(self.tmp),
                                      "--json")
        self.assertEqual(code, 2, out + err)
        self.assertEqual(json.loads(out)["state"], "BLOCKED")

    def test_an_unwritable_export_path_is_reported_not_raised(self):
        root = self.tmp / "candidate3"
        make_repo(root)
        code, out, err = self.run_cli(
            "export", "--out", str(self.tmp / "nope" / "x.json"),
            "--repo", str(root), "--json")
        self.assertEqual(code, 2, out + err)
        self.assertEqual(json.loads(out)["state"], "BLOCKED")


class HomeInsideCandidateTest(TempCase):
    """E29: the gate must not dirty the tree it is about to judge.

    ``$ADMISSIBLE_HOME`` holds the store and the private check logs. Pointed
    inside the repository under evaluation it becomes an untracked directory
    that appears part-way through the run -- and the mutation check, which
    cannot tell whose write it was, then blocks the commit and blames the first
    check that happened to run. The refusal is correct and the reason is a lie,
    so the misconfiguration has to be named up front instead.
    """

    def repo(self):
        root = self.tmp / "candidate"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps({
                "version": 1, "profile": "python-library",
                "classes": [{
                    "id": "default",
                    "checks": [{"id": "unit",
                                "argv": [sys.executable, "-c", "pass"],
                                "timeout_seconds": 60, "cost_units": 1,
                                "required": True, "version": "1"}],
                    "required_independent_reviews": 0,
                    "review_max_age_seconds": 86400,
                    "max_cost_units": 10, "max_wall_seconds": 600}]})})
        return root, sha

    def run_cli(self, *argv):
        # `run` evaluates and never signs, so it always previews.
        argv = tuple(argv)
        if argv[:1] == ("run",) and "--preview" not in argv:
            argv = ("run", "--preview") + argv[1:]
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(list(argv), stdout=out, stderr=err)
        return code, out.getvalue() + err.getvalue()

    def test_a_home_inside_the_candidate_is_refused_by_name(self):
        root, sha = self.repo()
        os.environ["ADMISSIBLE_HOME"] = str(root / ".admissible-home")
        code, output = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                    "--preview")
        self.assertEqual(code, 2, output)
        self.assertIn("ADMISSIBLE_HOME", output)
        self.assertNotIn("mutated", output.lower())
        self.assertEqual(git(root, "status", "--porcelain"), "",
                         "the refusal still left the candidate dirty")

    def test_a_home_outside_the_candidate_is_fine(self):
        root, sha = self.repo()
        os.environ["ADMISSIBLE_HOME"] = str(self.home)
        code, output = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                    "--preview")
        self.assertEqual(code, 0, output)


class QuickstartHonestyTest(TempCase):
    """E25: the quickstart must describe what actually happens."""

    def test_init_does_not_promise_an_immediately_green_run(self):
        root = self.tmp / "candidate"
        make_repo(root)
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["init", "--profile", "python-library",
                         "--repo", str(root)], stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        text = out.getvalue().lower()
        self.assertIn("commit", text)
        self.assertIn("starting template", text)
        self.assertNotIn("will pass", text)

    def test_preview_documents_its_private_log_writes(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("preview", readme)
        workflow = (ROOT / "docs" / "DEVELOPER_WORKFLOW.md").read_text(
            encoding="utf-8").lower()
        self.assertIn("private log", workflow)
        self.assertIn("no signer", workflow)


class SdistContractTest(unittest.TestCase):
    """E26: never ship a partial, unrunnable test suite."""

    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="admissible-sdist-")
        out = Path(cls.workspace.name)
        completed = subprocess.run(
            (sys.executable, "-m", "build", "--sdist", "--no-isolation",
             "--outdir", str(out)),
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        cls.built = completed.returncode == 0
        cls.log = completed.stdout.decode("utf-8", "replace")
        cls.archives = sorted(out.glob("*.tar.gz"))

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def test_the_sdist_builds(self):
        self.assertTrue(self.built, self.build_failure())
        self.assertTrue(self.archives, "build reported success and made nothing")

    @classmethod
    def build_failure(cls) -> str:
        return (
            "'python -m build --sdist' failed, and this test asserts that it "
            "succeeds. Skipping here would report a green suite for a package "
            "nobody can build, which is exactly the failure this test exists "
            "to catch. 'build' is in the dev extra; install it with "
            f"'pip install -e .[dev]'.\n{cls.log[-2000:]}")

    def names(self):
        self.assertTrue(self.built and self.archives, self.build_failure())
        with tarfile.open(self.archives[0]) as archive:
            return archive.getnames()

    def test_the_sdist_has_no_partial_test_suite(self):
        if not self.built:
            self.skipTest("python -m build unavailable")
        tests = [name for name in self.names()
                 if "/tests/" in name and name.endswith(".py")]
        if tests:
            # If tests ship at all, the helper they import must ship with them.
            self.assertIn(
                next((name for name in tests
                      if name.endswith("admissible_support.py")), ""),
                tests, f"tests shipped without their support module: {tests}")
        else:
            self.assertEqual(tests, [])

    def test_the_sdist_carries_the_package_schemas_and_templates(self):
        if not self.built:
            self.skipTest("python -m build unavailable")
        names = self.names()
        for needed in ("admissible/cli.py", "admissible/review.py",
                       "admissible/templates/reusable-workflow.yml",
                       "admissible/templates/consumer-workflow.yml",
                       "protocol/workflow-receipt.schema.json",
                       "protocol/workflow-evidence.schema.json",
                       "protocol/evaluation-attestation.schema.json"):
            self.assertTrue(any(name.endswith("/" + needed) for name in names),
                            needed)

    def test_the_unpacked_sdist_runs_the_cli(self):
        if not self.built:
            self.skipTest("python -m build unavailable")
        with tempfile.TemporaryDirectory(prefix="admissible-unpack-") as into:
            with tarfile.open(self.archives[0]) as archive:
                archive.extractall(into, filter="data")
            root = next(Path(into).glob("admissible-*"))
            completed = subprocess.run(
                (sys.executable, "-m", "admissible", "profiles", "--json"),
                cwd=str(root), env={**os.environ, "PYTHONPATH": str(root)},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(completed.returncode, 0,
                             completed.stderr.decode("utf-8", "replace"))
            listed = json.loads(completed.stdout.decode("utf-8"))["profiles"]
            self.assertEqual(len(listed), 8)

    def test_the_version_is_the_product_layer_version(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.7.0"', text)

    def test_the_documented_test_command_never_half_works(self):
        """An sdist ships a runnable suite or visibly none at all.

        The README documents one test command. Run inside an unpacked sdist it
        must either pass outright or fail loudly naming what is missing. What it
        must never do is discover a handful of files whose fixtures did not
        ship and report a green tick over them.
        """

        if not self.built:
            self.skipTest("python -m build unavailable")
        with tempfile.TemporaryDirectory(prefix="admissible-unpack-") as into:
            with tarfile.open(self.archives[0]) as archive:
                archive.extractall(into, filter="data")
            root = next(Path(into).glob("admissible-*"))
            ships_tests = (root / "tests").is_dir()
            # When no suite ships, the subject is the archive's contents and
            # not the machine's. `-S` keeps site-packages out of the way: some
            # unrelated distribution shipping a top-level `tests` package would
            # otherwise turn "no suite here" into an obscure traceback about
            # somebody else's directory, and the assertion below would be
            # measuring the wrong thing.
            argv = [sys.executable]
            if not ships_tests:
                argv.append("-S")
            argv += ["-m", "unittest", "discover", "-s", "tests",
                     "-p", "test_*.py"]
            completed = subprocess.run(
                argv, cwd=str(root),
                env={**os.environ, "PYTHONPATH": str(root)},
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = completed.stdout.decode("utf-8", "replace")
            if ships_tests:
                self.assertEqual(completed.returncode, 0, output)
                self.assertIn("OK", output)
                return
            # No suite shipped: the command must say so and must not look green.
            self.assertNotEqual(completed.returncode, 0, output)
            self.assertIn("tests", output)
            self.assertNotIn("\nOK\n", output)


class WheelContractTest(unittest.TestCase):
    """E28: the wheel a consumer installs carries everything the CLI needs."""

    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="admissible-wheel-")
        out = Path(cls.workspace.name)
        completed = subprocess.run(
            # The default path builds the wheel from a fresh unpacked sdist.
            # That prevents a stale repository-local build/ directory from
            # smuggling files into the artefact and masking a package-data
            # omission this contract is meant to catch.
            (sys.executable, "-m", "build", "--no-isolation", "--outdir",
             str(out)),
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        cls.built = completed.returncode == 0
        cls.log = completed.stdout.decode("utf-8", "replace")
        cls.wheels = sorted(out.glob("*.whl"))

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def test_the_wheel_builds(self):
        self.assertTrue(self.built, self.build_failure())
        self.assertTrue(self.wheels, "build reported success and made nothing")

    @classmethod
    def build_failure(cls) -> str:
        return (
            "'python -m build --no-isolation' failed, and this test asserts that it "
            "succeeds. Skipping here would report a green suite for a package "
            "nobody can install. 'build' is in the dev extra; install it with "
            f"'pip install -e .[dev]'.\n{cls.log[-2000:]}")

    def wheel(self):
        self.assertTrue(self.built and self.wheels, self.build_failure())
        import zipfile

        return zipfile.ZipFile(self.wheels[0])

    def test_the_wheel_carries_the_cli_schemas_and_every_template(self):
        with self.wheel() as archive:
            names = set(archive.namelist())
        for needed in (
                "admissible/cli.py", "admissible/__main__.py",
                "admissible/review.py", "admissible/github.py",
                "admissible/templates/workflow.yml",
                "admissible/templates/action.yml",
                "admissible/templates/reusable-workflow.yml",
                "admissible/templates/consumer-workflow.yml",
                "protocol/workflow-evidence.schema.json",
                "protocol/workflow-receipt.schema.json",
                "protocol/defect-record.schema.json",
                "protocol/evaluation-attestation.schema.json"):
            self.assertIn(needed, names, needed)

    def test_the_wheel_evaluation_schema_has_the_closed_observer_contract(self):
        with self.wheel() as archive:
            document = json.loads(archive.read(
                "protocol/evaluation-attestation.schema.json"))
        self.assertEqual(
            document["properties"]["schema"]["const"],
            "admissible/v0.6/evaluation-attestation")
        statement = document["$defs"]["statement"]
        self.assertIn("preview_schema", statement["required"])
        self.assertIn("issued_at", statement["required"])
        self.assertIn("isolation", statement["required"])
        self.assertNotIn("attestation_digests", statement["properties"])
        self.assertNotIn("author_attestation_digests",
                         statement["properties"])

    def test_the_wheel_declares_the_console_command(self):
        with self.wheel() as archive:
            entry = next(name for name in archive.namelist()
                         if name.endswith(".dist-info/entry_points.txt"))
            text = archive.read(entry).decode("utf-8")
        self.assertIn("[console_scripts]", text)
        self.assertIn("admissible = admissible.cli:main", text)

    def test_the_wheel_requires_nothing_to_install(self):
        with self.wheel() as archive:
            metadata = next(name for name in archive.namelist()
                            if name.endswith(".dist-info/METADATA"))
            text = archive.read(metadata).decode("utf-8")
        unconditional = [
            line for line in text.splitlines()
            if line.startswith("Requires-Dist:") and "extra ==" not in line]
        self.assertEqual(unconditional, [],
                         "the wheel declares a mandatory dependency")
        self.assertIn("Requires-Python: >=3.10", text)

    def test_the_wheel_ships_no_compiled_bytecode(self):
        with self.wheel() as archive:
            stray = [name for name in archive.namelist()
                     if "__pycache__" in name or name.endswith(".pyc")]
        self.assertEqual(stray, [])

    def test_the_installed_console_command_runs_from_the_wheel(self):
        """E28: install the artefact and run the entry point it generated.

        Reading `entry_points.txt` out of the archive proves the declaration.
        It does not prove that installing this wheel produces a working
        `admissible` command: the console script is generated at install time,
        it imports `admissible.cli`, and everything that import needs has to
        have been packaged. A test that injects the source checkout through
        PYTHONPATH and runs `python -m admissible` answers a different question
        and cannot notice a file the wheel left out.

        So this installs into a throwaway virtual environment -- offline, with
        no index and no dependencies, which the wheel is entitled to expect
        because it declares none -- and runs the generated script by name.
        """

        self.assertTrue(self.built and self.wheels, self.build_failure())
        with tempfile.TemporaryDirectory(prefix="admissible-venv-") as area:
            environment = Path(area) / "venv"
            made = subprocess.run(
                (sys.executable, "-m", "venv", str(environment)),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(
                made.returncode, 0,
                "cannot create a virtual environment to install into:\n"
                + made.stdout.decode("utf-8", "replace")[-2000:])
            bin_directory = environment / (
                "Scripts" if os.name == "nt" else "bin")
            installed = subprocess.run(
                (str(bin_directory / "python"), "-m", "pip", "install",
                 "--no-index", "--no-deps", "--disable-pip-version-check",
                 str(self.wheels[0])),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(
                installed.returncode, 0,
                "the wheel declares no dependencies, so installing it with no "
                "index must succeed:\n"
                + installed.stdout.decode("utf-8", "replace")[-2000:])
            console = bin_directory / (
                "admissible.exe" if os.name == "nt" else "admissible")
            self.assertTrue(console.is_file(),
                            f"installing the wheel generated no {console.name} "
                            "console command")
            # Run it by name, from a directory that is not the checkout, with
            # no PYTHONPATH: whatever answers has to be the installed package.
            clean = {key: value for key, value in os.environ.items()
                     if key != "PYTHONPATH"}
            listed = subprocess.run(
                (str(console), "profiles"), cwd=area, env=clean,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.assertEqual(listed.returncode, 0, listed.stdout[-2000:])
            for name in ("python-library", "payment-change",
                         "documentation-only"):
                self.assertIn(name, listed.stdout)
            # The templates and schemas are package data, so a scaffold from
            # the installed wheel is the honest check that they shipped.
            scaffolded = subprocess.run(
                (str(console), "init", "--profile", "python-library",
                 "--ci", "github", "--ci-placeholder", "--repo", area),
                cwd=area, env=clean, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True)
            self.assertEqual(scaffolded.returncode, 0,
                             scaffolded.stdout[-2000:])
            self.assertTrue((Path(area) / ".admissible.json").is_file())
            self.assertTrue((Path(area) / ".github" / "workflows"
                             / "admissible.yml").is_file())


class TemplateIdentityTest(unittest.TestCase):
    """E27: shipped templates never drift from the repository copies."""

    def test_every_shipped_template_matches_its_repository_copy(self):
        pairs = (
            ("admissible/templates/workflow.yml",
             ".github/workflows/admissible.yml"),
            ("admissible/templates/action.yml",
             ".github/actions/admissible/action.yml"),
            ("admissible/templates/reusable-workflow.yml",
             ".github/workflows/admissible-gate.yml"),
        )
        for shipped, canonical in pairs:
            shipped_path = ROOT / shipped
            self.assertTrue(shipped_path.is_file(), shipped)
            self.assertEqual(shipped_path.read_text(encoding="utf-8"),
                             (ROOT / canonical).read_text(encoding="utf-8"),
                             f"{shipped} has drifted from {canonical}")

    def test_the_consumer_template_is_shipped(self):
        self.assertTrue(
            (ROOT / "admissible" / "templates" / "consumer-workflow.yml"
             ).is_file())

    def test_all_eight_profiles_survive(self):
        profiles = require_module("admissible.profiles")
        self.assertEqual(profiles.PROFILE_NAMES, (
            "python-library", "typescript-application", "rest-api",
            "database-migration", "authentication-change", "payment-change",
            "infrastructure-change", "documentation-only"))


class DemoInterpreterPathTest(unittest.TestCase):
    """The documented PYTHON override may be relative to the repository."""

    def test_demo_resolves_a_relative_python_before_changing_directory(self):
        environment = dict(os.environ)
        environment["PYTHON"] = ".venv/bin/python"
        completed = subprocess.run(
            ("bash", "examples/developer-workflow/demo.sh"),
            cwd=ROOT, env=environment, text=True, capture_output=True,
            timeout=180)
        self.assertEqual(completed.returncode, 0,
                         completed.stdout + completed.stderr)
        self.assertIn("Demo complete", completed.stdout)


if __name__ == "__main__":
    unittest.main()
