"""Contract: a repository that is not this one can adopt the gate and run it.

Everything here is done the way an outside consumer would do it, and nothing
here imports the product as a library. A fresh repository scaffolds its own
policy and caller workflow with the shipped CLI, commits them, and is then
evaluated by a tool that lives in a *separate* checkout -- which is the whole
point of the CI trust boundary, and the one thing an in-process test cannot
demonstrate.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import (TempCase, git, make_repo,  # noqa: E402
                                require_module)

ghmod = require_module("admissible.github")
profiles_module = require_module("admissible.profiles")

ROOT = Path(__file__).resolve().parent.parent

# A consumer pins one commit. What it is does not matter here; that it appears
# in both places, and only in both places, does.
TOOL_SHA = "b" * 40

EIGHT_PROFILES = (
    "python-library", "typescript-application", "rest-api",
    "database-migration", "authentication-change", "payment-change",
    "infrastructure-change", "documentation-only",
)


class ExternalConsumerTest(TempCase):
    """A5/A6: init, commit, evaluate -- from outside, with the tool outside."""

    def setUp(self):
        super().setUp()
        self.consumer = self.tmp / "consumer"
        self.environment = dict(os.environ)
        # The consumer never installs the tool into its own tree; it reaches a
        # trusted checkout of it. This is exactly what the reusable workflow
        # does with two `actions/checkout` steps into two different paths.
        self.environment["PYTHONPATH"] = str(ROOT)
        self.environment["ADMISSIBLE_HOME"] = str(self.home)
        self.environment.pop("ADMISSIBLE_HMAC_KEY", None)
        self.environment.pop("ADMISSIBLE_REVIEW_KEYRING", None)

    def tool(self, *argv, expect=None):
        """Run the CLI from the trusted tool checkout, not the candidate.

        ``run`` evaluates and never signs, so it always previews; the flag is
        added here to keep every call site about what it is testing.
        """

        argv = tuple(argv)
        if argv[:1] == ("run",) and "--preview" not in argv:
            argv = ("run", "--preview") + argv[1:]

        result = subprocess.run(
            (sys.executable, "-m", "admissible", *argv),
            cwd=str(ROOT), env=self.environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode("utf-8") + result.stderr.decode("utf-8")
        if expect is not None:
            self.assertEqual(result.returncode, expect, output)
        return result.returncode, result.stdout.decode("utf-8"), output

    def scaffold(self):
        make_repo(self.consumer, files={"README.md": "consumer\n"})
        self.tool("init", "--profile", "python-library", "--ci", "github",
                  "--tool-sha", TOOL_SHA, "--repo", str(self.consumer),
                  expect=0)
        return self.consumer

    def commit_scaffold(self) -> str:
        git(self.consumer, "add", "-A")
        git(self.consumer, "commit", "-q", "-m", "adopt the admissible gate")
        return git(self.consumer, "rev-parse", "HEAD")

    def use_offline_checks(self):
        """What a real consumer does next: point the policy at its own commands.

        The starter profile names `pytest` and `build`, which this fixture has
        no business assuming are installed. Only the argv changes; the class
        keeps its ids, versions, ceilings and review rule.
        """

        path = self.consumer / ".admissible.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        for check in document["classes"][0]["checks"]:
            check["argv"] = [sys.executable, "-c", "pass"]
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    # -- the CLI surface a consumer sees ---------------------------------

    def test_the_cli_offers_exactly_the_eight_shipped_profiles(self):
        _, out, _ = self.tool("profiles", "--json", expect=0)
        names = tuple(row["name"] for row in json.loads(out)["profiles"])
        self.assertEqual(names, EIGHT_PROFILES)
        self.assertEqual(names, profiles_module.PROFILE_NAMES)

    def test_the_trusted_checkout_cli_reports_the_same_profiles(self):
        _, out, _ = self.tool("profiles", expect=0)
        for name in EIGHT_PROFILES:
            self.assertIn(name, out)

    # -- scaffolding -----------------------------------------------------

    def test_init_scaffolds_a_committable_policy_and_caller(self):
        root = self.scaffold()
        policy = root / ".admissible.json"
        workflow = root / ".github" / "workflows" / "admissible.yml"
        self.assertTrue(policy.is_file())
        self.assertTrue(workflow.is_file())
        # It must be committable as written: valid JSON, valid YAML-ish caller.
        json.loads(policy.read_text(encoding="utf-8"))
        text = workflow.read_text(encoding="utf-8")
        self.assertIn(f"admissible-gate.yml@{TOOL_SHA}", text)
        self.assertIn(f"tool-sha: {TOOL_SHA}", text)
        self.commit_scaffold()
        self.assertEqual(git(root, "status", "--porcelain"), "")

    def test_the_scaffolded_caller_pins_the_workflow_and_the_program(self):
        """One commit, written twice, because the gate compares the two."""

        root = self.scaffold()
        text = (root / ".github" / "workflows"
                / "admissible.yml").read_text(encoding="utf-8")
        jobs = text.split("\njobs:", 1)[1]
        uses = [line for line in jobs.splitlines()
                if line.strip().startswith("uses:")]
        self.assertEqual(len(uses), 1, uses)
        self.assertTrue(uses[0].strip().endswith(f"@{TOOL_SHA}"), uses[0])
        self.assertIn(f"tool-sha: {TOOL_SHA}", jobs)
        lowered = text.lower()
        self.assertIn("commit", lowered)
        self.assertIn("replace", lowered)

    def test_the_scaffolded_caller_carries_no_secret_and_cannot_sign(self):
        root = self.scaffold()
        text = (root / ".github" / "workflows"
                / "admissible.yml").read_text(encoding="utf-8")
        # The prose explains where the keys live; the configuration must not
        # carry one. Read the configuration.
        jobs = text.split("\njobs:", 1)[1]
        self.assertNotIn("secrets:", jobs)
        self.assertNotIn("ADMISSIBLE_", jobs)
        self.assertNotIn("finalize", jobs)

    def test_a_caller_with_no_pin_is_refused_rather_than_guessed(self):
        make_repo(self.consumer, files={"README.md": "consumer\n"})
        code, _, combined = self.tool(
            "init", "--profile", "python-library", "--ci", "github",
            "--repo", str(self.consumer))
        self.assertEqual(code, 2, combined)
        self.assertIn("--tool-sha", combined)
        self.assertFalse((self.consumer / ".github").exists())

    def test_init_ignores_what_its_own_profile_checks_write(self):
        """A gate that blocks on its own checks' output is not usable."""

        root = self.scaffold()
        ignores = (root / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("__pycache__/", ignores)
        self.assertIn("dist/", ignores)

    # -- the evaluate-only path ------------------------------------------

    def test_the_consumer_is_evaluated_by_a_tool_it_does_not_ship(self):
        root = self.scaffold()
        self.use_offline_checks()
        sha = self.commit_scaffold()
        # The candidate ships no `admissible` package, so a finalizer could
        # safely treat it as policy and data.
        self.assertTrue(ghmod.assert_trusted_tool(root))
        preview = self.tmp / "preview.json"
        code, out, combined = self.tool(
            "run", "--repo", str(root), "--sha", sha,
            "--preview-out", str(preview), "--json", expect=0)
        document = json.loads(out)
        self.assertEqual(document["state"], "CHECKS_PASSED")
        self.assertEqual(document["readiness"], "READY_FOR_ATTESTATION")
        self.assertTrue(document["preview"])
        self.assertIsNone(document["receipt"],
                          "an evaluate-only run must anchor nothing")
        handover = json.loads(preview.read_text(encoding="utf-8"))
        self.assertEqual(handover["commit_sha"], sha)
        self.assertEqual(handover["repository"], document["repository"])

    def test_the_checks_leave_the_consumer_worktree_clean(self):
        root = self.scaffold()
        self.use_offline_checks()
        sha = self.commit_scaffold()
        self.tool("run", "--repo", str(root), "--sha", sha, "--json", expect=0)
        self.assertEqual(git(root, "status", "--porcelain"), "",
                         "the gate left the candidate dirty")

    def test_a_second_evaluation_of_the_same_commit_still_admits(self):
        root = self.scaffold()
        self.use_offline_checks()
        sha = self.commit_scaffold()
        self.tool("run", "--repo", str(root), "--sha", sha, "--json", expect=0)
        _, out, _ = self.tool("run", "--repo", str(root), "--sha", sha,
                              "--json", expect=0)
        document = json.loads(out)
        self.assertEqual(
            {check["provenance"] for check in document["checks"]}, {"reused"})
        # Reuse is recorded as reuse: the derived record belongs to this
        # attempt and still names the attempt the command actually ran in.
        for check in document["checks"]:
            self.assertEqual(check["attempt_id"], document["attempt_id"])
            self.assertTrue(check["reused_from_attempt"])
            self.assertNotEqual(check["reused_from_attempt"],
                                document["attempt_id"])

    # -- the failure a consumer must not be able to hide -----------------

    def test_deleting_the_policy_fails_the_gate(self):
        root = self.scaffold()
        self.use_offline_checks()
        self.commit_scaffold()
        (root / ".admissible.json").unlink()
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "remove the policy")
        sha = git(root, "rev-parse", "HEAD")
        code, _, combined = self.tool(
            "run", "--repo", str(root), "--sha", sha, "--json")
        self.assertEqual(code, 2, combined)
        self.assertIn("admissible init", combined)

    def test_the_scaffolded_workflow_fails_a_commit_with_no_policy(self):
        """The same rule, in the caller's own trust domain.

        The CLI refusing is not enough: the workflow the consumer commits has
        to fail too, or deleting one file turns the gate into a green tick.
        """

        gate = (ROOT / ".github" / "workflows"
                / "admissible-gate.yml").read_text(encoding="utf-8")
        self.assertIn('if [ ! -f "$CONFIG_PATH" ]; then', gate)
        guard = gate.split('if [ ! -f "$CONFIG_PATH" ]; then', 1)[1]
        self.assertIn("exit 1", guard.split("\n          fi\n", 1)[0])


class InstalledExternalConsumerTest(unittest.TestCase):
    """The named external-consumer contract executes the installed artefact."""

    def test_a_wheel_install_generates_and_runs_the_public_console(self):
        with tempfile.TemporaryDirectory(
                prefix="admissible-external-wheel-") as temporary:
            area = Path(temporary)
            source = area / "source"
            shutil.copytree(
                ROOT, source,
                ignore=shutil.ignore_patterns(
                    ".git", ".venv", "node_modules", "build", "dist",
                    "*.egg-info", "__pycache__", ".pytest_cache"))
            wheelhouse = area / "wheelhouse"
            wheelhouse.mkdir()
            built = subprocess.run(
                # Build from a clean temporary source copy, install that wheel
                # into a fresh environment, and invoke only its generated
                # console script.
                (sys.executable, "-m", "build", "--no-isolation", "--outdir",
                 str(wheelhouse)),
                cwd=str(source), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True)
            self.assertEqual(built.returncode, 0, built.stdout[-3000:])
            wheels = tuple(wheelhouse.glob("*.whl"))
            self.assertEqual(len(wheels), 1, wheels)

            environment = area / "venv"
            made = subprocess.run(
                (sys.executable, "-m", "venv", str(environment)),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.assertEqual(made.returncode, 0, made.stdout[-3000:])
            bin_directory = environment / (
                "Scripts" if os.name == "nt" else "bin")
            installed = subprocess.run(
                (str(bin_directory / "python"), "-m", "pip", "install",
                 "--no-index", "--no-deps", "--disable-pip-version-check",
                 str(wheels[0])),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.assertEqual(installed.returncode, 0,
                             installed.stdout[-3000:])

            self.console = bin_directory / (
                "admissible.exe" if os.name == "nt" else "admissible")
            self.assertTrue(self.console.is_file(), self.console)
            clean = {key: value for key, value in os.environ.items()
                     if key != "PYTHONPATH"}
            listed = subprocess.run(
                (str(self.console), "profiles", "--json"), cwd=str(area),
                env=clean, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True)
            self.assertEqual(listed.returncode, 0,
                             listed.stdout + listed.stderr)
            names = tuple(row["name"]
                          for row in json.loads(listed.stdout)["profiles"])
            self.assertEqual(names, EIGHT_PROFILES)

            schema_check = subprocess.run(
                (str(bin_directory / "python"), "-c",
                 "from admissible.schema import evaluation_schema; "
                 "assert evaluation_schema()['properties']['schema']['const'] "
                 "== 'admissible/v0.6/evaluation-attestation'"),
                cwd=str(area), env=clean, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True)
            self.assertEqual(schema_check.returncode, 0,
                             schema_check.stdout + schema_check.stderr)


if __name__ == "__main__":
    unittest.main()
