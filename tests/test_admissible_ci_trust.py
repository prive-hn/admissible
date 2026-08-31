"""Contract: the GitHub trust boundary a consumer can actually pin and run.

The finalizer holds the signing key. It must therefore never checkout, import,
or execute candidate-owned code, and it must never claim that an ephemeral
hosted database is a durable monotone anchor.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import (TempCase, make_repo,  # noqa: E402
                                require_module, source_receipt_document)

cli = require_module("admissible.cli")
ghmod = require_module("admissible.github")
config_module = require_module("admissible.config")
store_module = require_module("admissible.store")

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / ".github" / "workflows" / "admissible-gate.yml"
CALLER = ROOT / ".github" / "workflows" / "admissible.yml"
CHECKOUT_PIN = "11bd71901bbe5b1630ceea73d27597364c9af683"
# Any full 40-hex sha: what is under test is that both places carry the same
# one, never that this particular commit exists.
TOOL_SHA = "a" * 40
SECRET = "finalizer-secret-not-a-real-key"


def read(path: Path) -> str:
    if not path.is_file():
        raise AssertionError(f"missing {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def job_block(text: str, name: str) -> str:
    """The YAML lines of one top-level job, without any sibling job."""

    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line == f"  {name}:":
            start = index
            break
    if start is None:
        raise AssertionError(f"no job named {name!r} in this workflow")
    collected = [lines[start]]
    for line in lines[start + 1:]:
        if re.match(r"^  \S", line):
            break
        collected.append(line)
    return "\n".join(collected)


class ReusableWorkflowTest(unittest.TestCase):
    """A1, A3, A4, A6: a real ``workflow_call`` surface a consumer can pin."""

    def gate(self) -> str:
        return read(GATE)

    def test_the_gate_is_a_reusable_workflow(self):
        text = self.gate()
        self.assertIn("workflow_call:", text)
        trigger = text.split("jobs:")[0]
        self.assertNotIn("pull_request:", trigger)
        self.assertNotIn("push:", trigger)

    def test_the_gate_has_no_signing_job_at_all(self):
        """Signing is not disabled here; it is absent.

        A `finalize` job in this file would hold the admission key in the same
        run as the job that executes candidate-owned commands, and would decide
        to run on the strength of that job's own output. Turning it off by
        default was not enough: the safe configuration has to be the only
        configuration the file can express.
        """

        text = self.gate()
        self.assertNotIn("\n  finalize:", text)
        self.assertNotIn("secrets:", text)
        self.assertNotIn("ADMISSIBLE_HMAC_KEY", text)
        self.assertNotIn("ADMISSIBLE_REVIEW_KEY:", text)

    def test_evaluate_never_uses_a_candidate_owned_local_action(self):
        evaluate = job_block(self.gate(), "evaluate")
        for line in evaluate.splitlines():
            stripped = line.strip()
            if stripped.startswith("uses:"):
                reference = stripped.split("uses:", 1)[1].strip()
                self.assertFalse(
                    reference.startswith("./"),
                    f"evaluate must not run repository-local code: {reference}")

    def test_evaluate_runs_tool_code_from_the_trusted_tool_checkout(self):
        evaluate = job_block(self.gate(), "evaluate")
        self.assertIn("admissible-tool", evaluate)
        self.assertIn("working-directory:", evaluate)
        for line in evaluate.splitlines():
            if "working-directory:" in line:
                self.assertIn(("admissible-tool" if "gate" in line or
                               "tool" in line else "candidate"), line)

    def test_the_tool_and_the_candidate_land_in_separate_paths(self):
        evaluate = job_block(self.gate(), "evaluate")
        paths = [line.split("path:", 1)[1].strip()
                 for line in evaluate.splitlines() if "path:" in line]
        self.assertGreaterEqual(len(paths), 2, paths)
        self.assertEqual(len(set(paths)), len(paths), paths)

    def test_the_tool_checkout_is_the_exact_pinned_tool_sha(self):
        evaluate = job_block(self.gate(), "evaluate")
        self.assertIn("ref: ${{ inputs.tool-sha }}", evaluate)
        self.assertNotIn("v0.6.0", self.gate())

    def test_a_pin_that_disagrees_with_the_running_workflow_is_refused(self):
        evaluate = job_block(self.gate(), "evaluate")
        self.assertIn("job_workflow_sha", evaluate)
        self.assertIn('"$JOB_WORKFLOW_SHA" != "$TOOL_SHA"', evaluate)
        # Hosted GitHub left github.job_workflow_sha empty. Skipping the
        # comparison then is fail-open: a PR can keep uses: pinned and
        # point tool-sha at candidate-owned code.
        self.assertNotIn(
            '[ -n "$JOB_WORKFLOW_SHA" ] &&', evaluate)
        self.assertIn('[ -z "$JOB_WORKFLOW_SHA" ]', evaluate)

    def test_the_preview_is_published_as_a_workflow_call_output(self):
        header = self.gate().split("jobs:")[0]
        outputs = header.split("    outputs:", 1)
        self.assertEqual(len(outputs), 2, "no workflow_call outputs")
        for name in ("preview:", "sha:", "state:", "readiness:", "fork:"):
            self.assertIn(f"      {name}", outputs[1], name)

    def test_every_external_action_is_pinned_to_the_verified_checkout_commit(self):
        text = self.gate() + read(CALLER)
        seen = 0
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("uses:") or stripped.startswith("- uses:"):
                reference = stripped.split("uses:", 1)[1].strip()
                if reference.startswith("./"):
                    continue
                self.assertRegex(reference, r"@[0-9a-f]{40}$", reference)
                if reference.startswith("actions/checkout@"):
                    seen += 1
                    self.assertTrue(reference.endswith(CHECKOUT_PIN), reference)
        self.assertGreater(seen, 0, "no pinned checkout found")

    def test_the_call_surface_exposes_the_documented_inputs(self):
        text = self.gate().split("jobs:")[0]
        for name in ("tool-sha", "config-path", "class", "evidence-path",
                     "evaluate-runs-on"):
            self.assertIn(f"      {name}:", text, name)

    def test_tool_sha_is_required_and_has_no_default(self):
        header = self.gate().split("jobs:")[0]
        block = header.split("      tool-sha:", 1)[1].split("\n      config")[0]
        self.assertIn("required: true", block)
        self.assertNotIn("default:", block)

    def test_the_selected_config_path_is_the_one_the_cli_is_given(self):
        evaluate = job_block(self.gate(), "evaluate")
        self.assertIn('if [ ! -f "$CONFIG_PATH" ]', evaluate)
        self.assertIn('--config "$ADMISSIBLE_CONFIG"', evaluate)
        self.assertIn("ADMISSIBLE_CONFIG: ${{ inputs.config-path }}", evaluate)

    def test_a_fork_is_still_reported_so_a_finalizer_can_refuse_it(self):
        evaluate = job_block(self.gate(), "evaluate")
        self.assertIn("fork=", evaluate)

    def test_missing_policy_is_never_a_green_skip(self):
        text = self.gate()
        self.assertNotIn("configured=false", text)
        self.assertNotIn("the gate is idle", text)
        # The gate must actively look for the policy and fail when it is gone.
        evaluate = job_block(text, "evaluate")
        self.assertIn('if [ ! -f "$CONFIG_PATH" ]; then', evaluate)
        guard = evaluate.split('if [ ! -f "$CONFIG_PATH" ]; then', 1)[1]
        self.assertIn("exit 1", guard.split("\n          fi\n", 1)[0])

    def test_the_admissible_repository_evaluates_itself_with_a_pinned_gate(self):
        """Public CI is Ready evaluate. Trust stays off GitHub Actions.

        The tool pin is a reviewed commit, not ``github.sha``: using the
        candidate as the program would let a PR rewrite the gate it is
        evaluated by.
        """

        caller = read(CALLER)
        trigger = caller.split("jobs:")[0]
        self.assertIn("pull_request:", trigger)
        self.assertIn("push:", trigger)
        self.assertNotIn("workflow_dispatch:", trigger)
        self.assertNotIn("secrets:", caller)
        self.assertNotIn("ADMISSIBLE_HMAC_KEY", caller)
        self.assertNotIn("tool-sha: ${{ github.sha }}", caller)
        pins = re.findall(
            r"admissible-gate\.yml@([0-9a-f]{40})", caller)
        self.assertEqual(1, len(pins), caller)
        self.assertIn("tool-sha: " + pins[0], caller)

    def test_job_summary_is_a_friendly_exact_commit_ready_card(self):
        evaluate = job_block(self.gate(), "evaluate")
        self.assertIn("### Admissible Ready", evaluate)
        self.assertIn("from admissible.ready import", evaluate)
        self.assertIn("Needs attention", evaluate)
        self.assertIn("Waiting for review", evaluate)
        self.assertIn("Checks complete", evaluate)
        self.assertIn("Result applies to", evaluate)
        self.assertIn("What should happen next", evaluate)
        self.assertIn("<details>", evaluate)
        # Friendly presentation must not erase the canonical state/readiness.
        self.assertIn("Canonical state", evaluate)
        self.assertIn("Canonical readiness", evaluate)


class PreviewHandoverLimitTest(unittest.TestCase):
    """A7: a preview that the workflow accepts must fit a GitHub job output."""

    def test_the_accepted_preview_fits_the_one_mebibyte_job_output_limit(self):
        raw = ghmod.MAX_PREVIEW_HANDOVER_BYTES
        base64_characters = 4 * ((raw + 2) // 3)
        utf16_bytes = 2 * base64_characters
        self.assertLessEqual(utf16_bytes, ghmod.GITHUB_JOB_OUTPUT_LIMIT_BYTES,
                             f"{raw} raw bytes become {utf16_bytes} counted bytes")

    def test_the_workflow_enforces_exactly_that_limit(self):
        self.assertIn(str(ghmod.MAX_PREVIEW_HANDOVER_BYTES), read(GATE))


class PreviewCeilingEnforcementTest(TempCase):
    """A7: the CLI refuses to write a preview the workflow could not carry.

    The ceiling is patched down rather than met with hundreds of real checks:
    what is under test is that the guard exists and refuses, not arithmetic
    that :class:`PreviewHandoverLimitTest` already pins.
    """

    def test_an_oversized_preview_is_refused_rather_than_written(self):
        import io

        root = self.tmp / "candidate"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps({
                "version": 1, "profile": "documentation-only",
                "classes": [{
                    "id": "default",
                    "checks": [{"id": "noop", "argv": [sys.executable, "-c",
                                                       "pass"],
                                "timeout_seconds": 60, "cost_units": 1,
                                "required": True, "version": "1"}],
                    "required_independent_reviews": 0,
                    "review_max_age_seconds": 3600,
                    "max_cost_units": 10, "max_wall_seconds": 600}]})})
        preview = self.tmp / "preview.json"
        original = ghmod.MAX_PREVIEW_HANDOVER_BYTES
        ghmod.MAX_PREVIEW_HANDOVER_BYTES = 64
        self.addCleanup(
            setattr, ghmod, "MAX_PREVIEW_HANDOVER_BYTES", original)
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["run", "--repo", str(root), "--sha", sha, "--preview",
                         "--preview-out", str(preview)],
                        stdout=out, stderr=err)
        self.assertEqual(code, 2, out.getvalue() + err.getvalue())
        self.assertIn("ceiling", (out.getvalue() + err.getvalue()).lower())
        self.assertFalse(preview.exists(),
                         "an oversized preview was written anyway")


class TrustedFinalizerTest(TempCase):
    """A1: candidate-owned action and module code cannot run in finalize."""

    def candidate(self) -> tuple[Path, str]:
        root = self.tmp / "candidate"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps({
                "version": 1,
                "profile": "documentation-only",
                "classes": [{
                    "id": "default",
                    "checks": [{
                        "id": "noop", "argv": ["python3", "-c", "pass"],
                        "timeout_seconds": 60, "cost_units": 1,
                        "required": True, "version": "1"}],
                    "required_independent_reviews": 0,
                    "review_max_age_seconds": 3600,
                    "max_cost_units": 10, "max_wall_seconds": 600}]}),
            # Candidate-owned surfaces the old finalizer executed.
            ".github/actions/admissible/action.yml":
                "runs:\n  using: composite\n  steps:\n"
                "    - run: printf '%s' \"$ADMISSIBLE_HMAC_KEY\" > /tmp/stolen\n",
            "tools/steal.py":
                "import os, pathlib\n"
                "pathlib.Path(os.environ['ADMISSIBLE_STOLEN_PATH']).write_text(\n"
                "    os.environ.get('ADMISSIBLE_HMAC_KEY', 'none'))\n",
        })
        return root, sha

    def shadowing_candidate(self) -> tuple[Path, str]:
        """A candidate that ships its own ``admissible`` package."""

        root = self.tmp / "shadow"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps({
                "version": 1,
                "profile": "documentation-only",
                "classes": [{
                    "id": "default",
                    "checks": [{
                        "id": "noop", "argv": ["python3", "-c", "pass"],
                        "timeout_seconds": 60, "cost_units": 1,
                        "required": True, "version": "1"}],
                    "required_independent_reviews": 0,
                    "review_max_age_seconds": 3600,
                    "max_cost_units": 10, "max_wall_seconds": 600}]}),
            "admissible/__init__.py": "",
            "admissible/__main__.py":
                "import os, pathlib\n"
                "pathlib.Path(os.environ['ADMISSIBLE_STOLEN_PATH']).write_text(\n"
                "    os.environ.get('ADMISSIBLE_HMAC_KEY', 'none'))\n",
        })
        return root, sha

    def test_a_candidate_that_ships_its_own_admissible_package_is_refused(self):
        """The exact attack: the finalizer executing the candidate's module.

        Once the candidate's module is the one Python imported, no code of ours
        gets a turn. The repair is that the finalizer keeps the two checkouts
        apart -- and that it refuses outright to finalize a checkout that is one
        `cd` away from shadowing the tool.
        """

        root, sha = self.shadowing_candidate()
        preview = self.tmp / "preview.json"
        stolen = self.tmp / "stolen.txt"
        environment = dict(os.environ)
        environment.pop("ADMISSIBLE_HMAC_KEY", None)
        environment["ADMISSIBLE_STOLEN_PATH"] = str(stolen)
        environment["PYTHONPATH"] = str(ROOT)
        subprocess.run(
            (sys.executable, "-m", "admissible", "run", "--repo", str(root),
             "--sha", sha, "--preview", "--preview-out", str(preview), "--json"),
            cwd=str(ROOT), env=environment, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        environment["ADMISSIBLE_HMAC_KEY"] = SECRET
        environment["ADMISSIBLE_HOME"] = str(self.home)
        environment["ADMISSIBLE_DURABLE_HOME"] = "1"
        finalized = subprocess.run(
            (sys.executable, "-m", "admissible", "finalize", "--preview",
             str(preview), "--sha", sha, "--policy-root", str(root), "--json"),
            cwd=str(ROOT), env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self.assertEqual(finalized.returncode, 2,
                         finalized.stdout.decode() + finalized.stderr.decode())
        self.assertFalse(
            stolen.exists(),
            "the candidate's own admissible module executed with the key")
        self.assertNotIn(SECRET, finalized.stdout.decode("utf-8"))

    def test_finalize_refuses_a_tool_that_lives_inside_the_policy_root(self):
        root, sha = self.shadowing_candidate()
        with self.assertRaises(ghmod.GitHubError):
            ghmod.assert_trusted_tool(root)

    def test_finalize_accepts_a_candidate_that_ships_no_tool_copy(self):
        root, sha = self.candidate()
        self.assertTrue(ghmod.assert_trusted_tool(root))

    def test_finalize_runs_only_trusted_tool_code(self):
        """The whole four-process path, each in its own trust domain.

        Evaluate holds no key. The observer holds only the evaluation key. The
        operator's baseline is recorded once, deliberately. Only the finalizer
        holds the admission key, and it never imports a line of the candidate's
        code -- the candidate here ships an ``admissible.py`` that would write
        the key out if anything ever executed it.
        """

        root, sha = self.candidate()
        preview = self.tmp / "preview.json"
        attestation_path = self.tmp / "evaluation.json"
        keyring_path = self.tmp / "observers.json"
        keyring_path.write_text(json.dumps({"observer-1": "observer-secret"}),
                                encoding="utf-8")
        os.chmod(keyring_path, 0o600)
        stolen = self.tmp / "stolen.txt"

        evaluating = dict(os.environ)
        evaluating.pop("ADMISSIBLE_HMAC_KEY", None)
        evaluating["ADMISSIBLE_STOLEN_PATH"] = str(stolen)
        evaluating["PYTHONPATH"] = str(ROOT)
        evaluating["ADMISSIBLE_HOME"] = str(self.home)

        def cli(*arguments, env, expect=0):
            done = subprocess.run(
                (sys.executable, "-m", "admissible", *arguments),
                cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            self.assertEqual(done.returncode, expect,
                             done.stdout.decode() + done.stderr.decode())
            return done.stdout.decode("utf-8")

        cli("run", "--repo", str(root), "--sha", sha, "--preview",
            "--preview-out", str(preview), "--json", env=evaluating)

        # A candidate may propose a policy; an operator makes one enforceable.
        cli("policy", "trust", "--repo", str(root), "--json", env=evaluating)

        # The external observer signs after the evaluation is over, with a key
        # the evaluating process never had.
        observing = dict(evaluating)
        observing["ADMISSIBLE_EVALUATION_KEY_ID"] = "observer-1"
        observing["ADMISSIBLE_EVALUATION_KEY"] = "observer-secret"
        # The observer also states which external receipt it read. Without one
        # the attestation would only re-sign the candidate's own account of
        # itself, so the CLI refuses to produce it.
        source = self.tmp / "source-receipt.json"
        source.write_text(json.dumps(source_receipt_document(sha)),
                          encoding="utf-8")
        cli("attest-evaluation", "--preview", str(preview), "--out",
            str(attestation_path), "--source-receipt", str(source),
            "--isolation", "pid-namespace",
            "--json", env=observing)

        finalizing = dict(os.environ)
        finalizing["PYTHONPATH"] = str(ROOT)
        finalizing["ADMISSIBLE_STOLEN_PATH"] = str(stolen)
        finalizing["ADMISSIBLE_HMAC_KEY"] = SECRET
        finalizing["ADMISSIBLE_HOME"] = str(self.home)
        finalizing["ADMISSIBLE_DURABLE_HOME"] = "1"
        finalizing["ADMISSIBLE_EVALUATION_KEYRING"] = str(keyring_path)
        stdout = cli("finalize", "--preview", str(preview), "--sha", sha,
                     "--policy-root", str(root), "--evaluation-attestation",
                     str(attestation_path), "--json", env=finalizing)

        self.assertFalse(stolen.exists(),
                         "candidate module executed inside the finalizer")
        document = json.loads(stdout)
        self.assertEqual(document["commit_sha"], sha)
        self.assertNotIn(SECRET, stdout)

    def test_finalize_without_the_observer_attestation_signs_nothing(self):
        root, sha = self.candidate()
        preview = self.tmp / "preview.json"
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT)
        environment["ADMISSIBLE_HOME"] = str(self.home)
        environment.pop("ADMISSIBLE_HMAC_KEY", None)
        subprocess.run(
            (sys.executable, "-m", "admissible", "run", "--repo", str(root),
             "--sha", sha, "--preview", "--preview-out", str(preview), "--json"),
            cwd=str(ROOT), env=environment, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        environment["ADMISSIBLE_HMAC_KEY"] = SECRET
        environment["ADMISSIBLE_DURABLE_HOME"] = "1"
        refused = subprocess.run(
            (sys.executable, "-m", "admissible", "finalize", "--preview",
             str(preview), "--sha", sha, "--policy-root", str(root), "--json"),
            cwd=str(ROOT), env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self.assertEqual(refused.returncode, 2)
        self.assertIn("evaluation-attestation",
                      refused.stdout.decode() + refused.stderr.decode())


class DurableFinalizationTest(TempCase):
    """A2: hosted ephemeral SQLite is not a monotone durable anchor."""

    def test_finalize_refuses_an_ephemeral_home_on_a_hosted_runner(self):
        workspace = self.tmp / "workspace"
        workspace.mkdir()
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(workspace),
            "RUNNER_TEMP": str(self.tmp / "runner-temp"),
            "ADMISSIBLE_HOME": str(workspace / ".admissible-home"),
        }
        with self.assertRaises(store_module.StoreError) as caught:
            store_module.require_durable_home(environment)
        self.assertIn("durable", str(caught.exception).lower())

    def test_an_external_durable_home_is_accepted(self):
        workspace = self.tmp / "workspace"
        workspace.mkdir()
        durable = self.tmp / "durable"
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(workspace),
            "ADMISSIBLE_HOME": str(durable),
            "ADMISSIBLE_DURABLE_HOME": "1",
        }
        self.assertEqual(store_module.require_durable_home(environment),
                         durable)

    def test_a_hosted_runner_must_declare_its_durable_home(self):
        """Outside the workspace is not the same as durable.

        A path on a hosted runner can be anywhere and still vanish with the
        job. Nothing here can tell the difference, so the operator has to say
        so deliberately rather than have it inferred from a path shape.
        """

        durable = self.tmp / "elsewhere"
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(self.tmp / "workspace"),
            "RUNNER_TEMP": str(self.tmp / "runner-temp"),
            "ADMISSIBLE_HOME": str(durable),
        }
        with self.assertRaises(store_module.StoreError) as caught:
            store_module.require_durable_home(environment)
        self.assertIn("ADMISSIBLE_DURABLE_HOME", str(caught.exception))

    def test_declaring_a_disposable_home_durable_does_not_make_it_durable(self):
        workspace = self.tmp / "workspace"
        workspace.mkdir()
        environment = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(workspace),
            "ADMISSIBLE_HOME": str(workspace / ".admissible-home"),
            "ADMISSIBLE_DURABLE_HOME": "1",
        }
        with self.assertRaises(store_module.StoreError) as caught:
            store_module.require_durable_home(environment)
        self.assertIn("disposable", str(caught.exception))

    def test_a_local_developer_home_is_not_treated_as_a_ci_finalizer(self):
        self.assertEqual(
            store_module.require_durable_home({"ADMISSIBLE_HOME": str(self.home)}),
            self.home)

    def test_documentation_states_what_restoring_an_old_database_costs(self):
        text = read(ROOT / "docs" / "GITHUB_ACTIONS.md").lower()
        self.assertIn("rollback protection", text)


class ConsumerScaffoldTest(TempCase):
    """A5: ``init --ci github`` produces something a consumer can commit."""

    def repo(self) -> Path:
        root = self.tmp / "consumer"
        make_repo(root)
        return root

    def run_cli(self, *argv):
        import io

        out, err = io.StringIO(), io.StringIO()
        code = cli.main(list(argv), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_init_with_ci_github_scaffolds_config_and_a_caller_workflow(self):
        root = self.repo()
        code, out, err = self.run_cli(
            "init", "--profile", "python-library", "--ci", "github",
            "--tool-sha", TOOL_SHA, "--repo", str(root))
        self.assertEqual(code, 0, out + err)
        self.assertTrue((root / ".admissible.json").is_file())
        workflow = root / ".github" / "workflows" / "admissible.yml"
        self.assertTrue(workflow.is_file(), "no consumer workflow scaffolded")
        text = workflow.read_text(encoding="utf-8")
        self.assertIn("uses:", text)
        # The same commit in both places, because the gate compares them.
        self.assertIn(f"admissible-gate.yml@{TOOL_SHA}", text)
        self.assertIn(f"tool-sha: {TOOL_SHA}", text)

    def test_init_with_ci_refuses_an_unpinned_caller(self):
        root = self.repo()
        code, out, err = self.run_cli(
            "init", "--profile", "python-library", "--ci", "github",
            "--repo", str(root))
        self.assertEqual(code, 2, out + err)
        self.assertIn("--tool-sha", out + err)
        self.assertFalse((root / ".github").exists(),
                         "a refused scaffold still wrote a workflow")
        self.assertFalse((root / ".admissible.json").exists(),
                         "a refused scaffold still wrote a policy")

    def test_init_refuses_to_overwrite_a_scaffolded_workflow(self):
        root = self.repo()
        self.run_cli("init", "--profile", "python-library", "--ci", "github",
                     "--tool-sha", TOOL_SHA, "--repo", str(root))
        code, out, err = self.run_cli(
            "init", "--profile", "rest-api", "--ci", "github",
            "--tool-sha", TOOL_SHA, "--repo", str(root))
        self.assertEqual(code, 2, out + err)
        code, out, err = self.run_cli(
            "init", "--profile", "rest-api", "--ci", "github", "--force",
            "--tool-sha", TOOL_SHA, "--repo", str(root))
        self.assertEqual(code, 0, out + err)

    def test_a_collision_on_either_file_writes_neither(self):
        """Preflight, not partial progress with an apology afterwards."""

        root = self.repo()
        self.run_cli("init", "--profile", "python-library", "--ci", "github",
                     "--tool-sha", TOOL_SHA, "--repo", str(root))
        policy = root / ".admissible.json"
        before = policy.read_text(encoding="utf-8")
        policy.unlink()
        code, out, err = self.run_cli(
            "init", "--profile", "rest-api", "--ci", "github",
            "--tool-sha", TOOL_SHA, "--repo", str(root))
        self.assertEqual(code, 2, out + err)
        self.assertFalse(policy.exists(),
                         "the policy was written before the collision was found")
        self.assertIn("Nothing was written", out + err)
        # And the workflow that caused the refusal is untouched.
        self.assertIn(TOOL_SHA, (root / ".github" / "workflows"
                                 / "admissible.yml").read_text(encoding="utf-8"))
        self.assertTrue(before)

    def test_a_placeholder_caller_is_written_only_when_asked_for(self):
        root = self.repo()
        code, out, err = self.run_cli(
            "init", "--profile", "python-library", "--ci", "github",
            "--ci-placeholder", "--repo", str(root))
        self.assertEqual(code, 0, out + err)
        text = (root / ".github" / "workflows" / "admissible.yml").read_text(
            encoding="utf-8")
        self.assertIn(config_module.TOOL_SHA_PLACEHOLDER, text)

    def test_init_tells_the_developer_to_commit_and_tighten_before_running(self):
        root = self.repo()
        code, out, err = self.run_cli(
            "init", "--profile", "python-library", "--repo", str(root))
        self.assertEqual(code, 0, out + err)
        lowered = out.lower()
        self.assertIn("commit", lowered)
        self.assertIn("tighten", lowered)

    def test_init_without_ci_stays_valid(self):
        root = self.repo()
        code, out, err = self.run_cli(
            "init", "--profile", "python-library", "--repo", str(root))
        self.assertEqual(code, 0, out + err)
        self.assertFalse((root / ".github").exists())


if __name__ == "__main__":
    unittest.main()
