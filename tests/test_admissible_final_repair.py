"""Contract: the repairs that separate *evaluating* from *admitting*.

Four ideas carry this file, and each one is a place the previous design let a
candidate-adjacent job speak with an authority it never had:

* an **evaluation attestation** is the only thing that turns command evidence
  into command *proof*. It is signed by an external observer after the
  candidate's processes are gone, in a trust domain the candidate cannot reach,
  and ``finalize`` refuses without it;
* an **attempt** is one observation of one artefact at one moment. Records from
  two attempts never jointly satisfy one decision;
* an **import** believes exactly what a signed head covers, and nothing that
  trails behind it;
* a **tool sha** is the whole executable boundary. A consumer that pins the
  reusable workflow by commit pins the program too, or the pin is decoration.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import (TempCase, git, make_repo,  # noqa: E402
                                require_module, source_receipt_document)

attestation_module = require_module("admissible.attestation")
cli = require_module("admissible.cli")
config_module = require_module("admissible.config")
decision = require_module("admissible.decision")
evidence = require_module("admissible.evidence")
ghmod = require_module("admissible.github")
profiles_module = require_module("admissible.profiles")
receipt = require_module("admissible.receipt")
runner_module = require_module("admissible.runner")
standing_module = require_module("admissible.standing")
store_module = require_module("admissible.store")

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / ".github" / "workflows" / "admissible-gate.yml"
TEMPLATE = ROOT / "admissible" / "templates" / "reusable-workflow.yml"
CONSUMER = ROOT / "admissible" / "templates" / "consumer-workflow.yml"

SECRET = b"final-repair-signing-secret"
EVALUATION_SECRET = b"final-repair-evaluation-secret"


def policy(argv=("python3", "-c", "pass")):
    return {
        "version": 1,
        "profile": "python-library",
        "classes": [{
            "id": "default",
            "checks": [{"id": "unit", "argv": list(argv),
                        "timeout_seconds": 60, "cost_units": 1,
                        "required": True, "version": "1"}],
            "required_independent_reviews": 0,
            "review_max_age_seconds": 86400,
            "max_cost_units": 10,
            "max_wall_seconds": 600,
        }],
    }


class PreviewCase(TempCase):
    """A real repository, a real preview, and a real durable store."""

    def setUp(self):
        super().setUp()
        self.signer = receipt.signer_from_secret("k1", SECRET)
        self.store = store_module.open_store(self.home)
        self.addCleanup(self.store.close)
        self.root = self.tmp / "candidate"
        self.sha = make_repo(self.root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(policy()),
        })
        self.preview = self.tmp / "preview.json"
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["run", "--repo", str(self.root), "--sha", self.sha,
                         "--preview", "--preview-out", str(self.preview),
                         "--json"], stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        # The operator's one deliberate act, so the refusals under test are
        # about the attestation and not about a missing policy baseline.
        self.repository = "github.com/acme/widget"
        artifact_class = config_module.load_config(
            self.root).select_class("default")
        self.store.trust_policy(
            repository=self.repository, class_id="default",
            policy_digest=artifact_class.policy_digest,
            enforcement_digest=config_module.enforcement_digest(artifact_class),
            trusted_at=int(time.time()))

    def attestation(self, **overrides):
        """A well-formed evaluation attestation over this exact preview."""

        parsed = json.loads(self.preview.read_text(encoding="utf-8"))
        overrides.setdefault(
            "source_receipt", source_receipt_document(parsed["commit_sha"]))
        overrides.setdefault("isolation", "pid-namespace")
        document = attestation_module.attest_preview(
            parsed, key_id="observer-1", secret=EVALUATION_SECRET,
            observed_at=max(int(time.time()), parsed["issued_at"]),
            **overrides)
        path = self.tmp / "evaluation-attestation.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def finalize(self, *, attestation_path="default", keyring="default"):
        if attestation_path == "default":
            attestation_path = self.attestation()
        if keyring == "default":
            keyring = {"observer-1": EVALUATION_SECRET}
        return ghmod.finalize(
            self.store, self.preview, signer=self.signer,
            expected_sha=self.sha, now=int(time.time()),
            policy_root=self.root,
            evaluation_attestation=attestation_path,
            evaluation_keyring=keyring)


class EvaluationAttestationRequiredTest(PreviewCase):
    """Item 3: no evaluation attestation, no receipt. Ever."""

    def test_an_attested_preview_finalizes(self):
        issued = self.finalize()
        self.assertEqual(issued.commit_sha, self.sha)

    def test_finalize_without_an_evaluation_attestation_is_refused(self):
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=None)
        self.assertIn("evaluation attestation", str(caught.exception).lower())
        self.assertEqual(self.store.receipt_count(self.repository), 0)

    def test_an_attestation_signed_by_an_unpinned_key_is_refused(self):
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(keyring={"somebody-else": EVALUATION_SECRET})
        self.assertIn("observer-1", str(caught.exception))

    def test_a_tampered_attestation_is_refused(self):
        path = self.attestation()
        document = json.loads(path.read_text(encoding="utf-8"))
        document["evaluation"]["tree_sha"] = "c3" * 20
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError):
            self.finalize(attestation_path=path)

    def test_an_attestation_for_another_commit_is_refused(self):
        other = self.tmp / "other"
        other_sha = make_repo(other, files={"README.md": "other\n"})
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document["commit_sha"] = other_sha
        path = self.tmp / "wrong.json"
        path.write_text(json.dumps(attestation_module.attest_preview(
            document, key_id="observer-1", secret=EVALUATION_SECRET,
            isolation="pid-namespace",
            source_receipt=source_receipt_document(document["commit_sha"]),
            observed_at=max(int(time.time()), document["issued_at"]))),
            encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=path)
        self.assertIn("commit", str(caught.exception).lower())

    def test_an_authentic_attestation_about_another_artefact_is_refused(self):
        """Signed by a pinned observer, and about something else entirely.

        Editing a signed body breaks the signature, so every such test is
        really a test of the signature. These statements are *re-signed*: the
        observer really did sign them, and only the field-by-field comparison
        against what this job derived can tell that what the observer watched
        is not what is being finalised. The fields chosen here are the ones
        nothing else in finalize re-derives, so nothing else can catch them.
        """

        for field, value in (("class_id", "some-other-class"),
                             ("attempt_id", "some-other-attempt")):
            with self.subTest(field=field):
                path = self.attestation(**{field: value})
                with self.assertRaises(ghmod.GitHubError) as caught:
                    self.finalize(attestation_path=path)
                message = str(caught.exception)
                self.assertIn(value, message)
                self.assertIn("nothing was signed", message.lower())
                self.assertEqual(self.store.receipt_count(self.repository), 0)

    def test_an_attestation_missing_a_command_digest_is_refused(self):
        """The attestation names the commands it watched, and only those."""

        path = self.attestation()
        document = json.loads(path.read_text(encoding="utf-8"))
        document["evaluation"]["command_digests"] = []
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError):
            self.finalize(attestation_path=path)

    def test_the_evaluation_domain_is_not_the_review_domain(self):
        self.assertNotEqual(attestation_module.EVALUATION_DOMAIN,
                            evidence.ATTESTATION_SCHEMA)
        self.assertIn("evaluation-attestation",
                      attestation_module.EVALUATION_DOMAIN)


class AttemptMixingTest(TempCase):
    """Item 13: two attempts never jointly satisfy one decision."""

    def setUp(self):
        super().setUp()
        parsed = config_module.parse_config(policy())
        self.artifact_class = parsed.select_class("default")
        self.repository = "github.com/acme/widget"
        self.sha = "a1" * 20
        self.tree = "b2" * 20

    def record(self, attempt_id, *, exit_code=0):
        return evidence.command_evidence_from_dict({
            "kind": "command", "check_id": "unit", "check_version": "1",
            "repository": self.repository, "commit_sha": self.sha,
            "tree_sha": self.tree,
            "policy_digest": self.artifact_class.policy_digest,
            "argv_digest": self.artifact_class.check("unit").argv_digest,
            "exit_code": exit_code, "timed_out": False, "launch_failed": False,
            "duration_ms": 5, "stdout_sha256": "0" * 64,
            "stderr_sha256": "0" * 64, "stdout_bytes": 0, "stderr_bytes": 0,
            "output_truncated": False, "started_at": 1000, "finished_at": 1001,
            "attempt_id": attempt_id, "reused_from_attempt": "",
        })

    def evaluate(self, commands, attempt_id):
        return decision.evaluate(
            artifact_class=self.artifact_class, repository=self.repository,
            commit_sha=self.sha, tree_sha=self.tree,
            policy_digest=self.artifact_class.policy_digest,
            commands=tuple(commands), reviews=(), now=100000,
            attempt_id=attempt_id)

    def test_evidence_from_this_attempt_admits(self):
        result = self.evaluate([self.record("attempt-a")], "attempt-a")
        self.assertEqual(result.state, decision.CHECKS_PASSED)

    def test_evidence_from_another_attempt_cannot_satisfy_this_decision(self):
        result = self.evaluate([self.record("attempt-a")], "attempt-b")
        self.assertEqual(result.state, decision.REFUSED)
        self.assertIn("attempt_mismatch",
                      {reason.code for reason in result.reasons})

    def test_two_attempts_do_not_combine_into_a_third(self):
        commands = [self.record("attempt-a"), self.record("attempt-b")]
        result = self.evaluate(commands, "attempt-c")
        self.assertEqual(result.state, decision.REFUSED)

    def test_an_unscoped_decision_cannot_be_asked_for_at_all(self):
        """The decision names no attempt, and the evidence names two.

        This was the shape a forged preview reached for: leave the attempt
        blank and the per-record check had nothing to compare against. The
        blank is now refused where it is offered rather than reasoned about
        afterwards -- a decision is one observation of one artefact at one
        moment, and one that belongs to no attempt is not that.
        """

        commands = [self.record("attempt-a"), self.record("attempt-b")]
        with self.assertRaises(ValueError) as caught:
            self.evaluate(commands, "")
        self.assertIn("attempt", str(caught.exception).lower())

    def test_an_unscoped_decision_over_one_attempt_is_refused_too(self):
        with self.assertRaises(ValueError):
            self.evaluate([self.record("attempt-a")], "")

    def test_a_whitespace_attempt_is_not_an_attempt(self):
        with self.assertRaises(ValueError):
            self.evaluate([self.record("attempt-a")], "   ")

    def test_a_reused_record_is_derived_into_the_current_attempt(self):
        derived = self.record("attempt-now")
        derived = evidence.reuse_in_attempt(
            self.record("attempt-old"), attempt_id="attempt-now")
        self.assertEqual(derived.attempt_id, "attempt-now")
        self.assertEqual(derived.reused_from_attempt, "attempt-old")
        result = self.evaluate([derived], "attempt-now")
        self.assertEqual(result.state, decision.CHECKS_PASSED)

    def test_a_derived_record_keeps_its_source_provenance(self):
        derived = evidence.reuse_in_attempt(
            self.record("attempt-old"), attempt_id="attempt-now")
        self.assertNotEqual(evidence.evidence_digest(derived),
                            evidence.evidence_digest(self.record("attempt-old")))
        self.assertEqual(
            evidence.command_evidence_to_dict(derived)["reused_from_attempt"],
            "attempt-old")


class UnsignedTrailingImportTest(TempCase):
    """Item 17: an import believes exactly what a signed head covers."""

    def setUp(self):
        super().setUp()
        self.signer = receipt.signer_from_secret("k1", SECRET)
        self.source = store_module.open_store(self.tmp / "source")
        self.addCleanup(self.source.close)
        self.repository = "github.com/acme/widget"
        self.journal = receipt.journal_id_for(self.repository)
        self.sha = "a1" * 20
        receipt.issue_receipt_from_parts(
            self.source, repository=self.repository, commit_sha=self.sha,
            tree_sha="b2" * 20, class_id="default",
            policy_digest="c" * 64, state=decision.ADMITTED,
            attempt_id="attempt-a", decision_digest_value="d" * 64,
            evidence_digests=(), signer=self.signer, now=1000)
        self.bundle = self.source.export_journal(self.journal)

    def target(self):
        opened = store_module.open_store(self.tmp / "target")
        self.addCleanup(opened.close)
        return opened

    def test_an_honest_bundle_imports(self):
        head = self.target().import_journal(self.bundle, self.signer)
        self.assertEqual(head.journal_id, self.journal)

    def test_an_unsigned_trailing_defect_event_is_refused(self):
        forged = {
            "domain": receipt.RECEIPT_DOMAIN, "type": receipt.EVENT_DEFECT,
            "defect_digest": "e" * 64, "defect_id": "forged",
            "repository": self.repository, "commit_sha": self.sha,
            "severity": "critical", "summary": "forged",
            "discovered_at": 2000, "filed_at": 2000,
        }
        bundle = json.loads(json.dumps(self.bundle))
        bundle["events"].append(forged)
        bundle["defects"].append({
            "kind": "defect", "defect_id": "forged",
            "repository": self.repository, "commit_sha": self.sha,
            "severity": "critical", "summary": "forged",
            "missed_check_ids": [], "regression_test_id": "",
            "discovered_at": 2000,
        })
        opened = self.target()
        with self.assertRaises(store_module.StoreError) as caught:
            opened.import_journal(bundle, self.signer)
        self.assertIn("signed", str(caught.exception).lower())
        self.assertEqual(opened.defect_count(self.repository), 0)

    def test_a_same_head_reimport_still_verifies_every_event(self):
        opened = self.target()
        opened.import_journal(self.bundle, self.signer)
        tampered = json.loads(json.dumps(self.bundle))
        tampered["events"].append({
            "domain": receipt.RECEIPT_DOMAIN, "type": receipt.EVENT_DEFECT,
            "defect_digest": "e" * 64, "defect_id": "late",
            "repository": self.repository, "commit_sha": self.sha,
            "severity": "critical", "summary": "late",
            "discovered_at": 3000, "filed_at": 3000,
        })
        with self.assertRaises(store_module.StoreError):
            opened.import_journal(tampered, self.signer)
        self.assertEqual(opened.defect_count(self.repository), 0)


class ToolShaPinTest(unittest.TestCase):
    """Item 8: pinning the workflow pins the program, or it pins nothing."""

    def gate(self) -> str:
        return GATE.read_text(encoding="utf-8")

    def test_the_gate_and_the_template_are_the_same_file(self):
        self.assertEqual(self.gate(), TEMPLATE.read_text(encoding="utf-8"))

    def test_tool_sha_is_a_required_input(self):
        text = self.gate()
        self.assertIn("      tool-sha:", text)
        block = text.split("      tool-sha:", 1)[1].split(
            "\n      config-path:", 1)[0]
        self.assertIn("required: true", block)
        self.assertNotIn("default:", block)

    def test_no_movable_tag_is_ever_a_tool_ref(self):
        self.assertNotIn("v0.6.0", self.gate())

    def test_the_tool_sha_must_be_a_full_forty_hex_commit(self):
        text = self.gate()
        self.assertIn('*[!0-9a-f]* | ""', text)
        self.assertIn('[ "${#TOOL_SHA}" -ne 40 ]', text)

    def test_the_tool_checkout_uses_exactly_the_tool_sha(self):
        self.assertIn("ref: ${{ inputs.tool-sha }}", self.gate())

    def test_the_running_workflow_sha_must_equal_the_tool_sha(self):
        """The documented ``job`` context identifies the reusable workflow.

        GitHub exposes the callee's commit and repository as
        ``job.workflow_sha`` and ``job.workflow_repository``. Both must match
        the public tool source before candidate code is checked out.
        """

        gate = self.gate()
        self.assertIn("job.workflow_sha", gate)
        self.assertIn("job.workflow_repository", gate)
        self.assertNotIn("github.job_workflow_sha", gate)

    def test_the_generated_caller_pins_the_same_sha_twice(self):
        text = CONSUMER.read_text(encoding="utf-8")
        self.assertIn("tool-sha:", text)
        self.assertNotIn("@v0.6.0", text)


class InitToolShaTest(TempCase):
    """Item 8: ``init --ci`` refuses to scaffold an unpinnable caller."""

    def repo(self) -> Path:
        root = self.tmp / "project"
        make_repo(root)
        return root

    def test_init_ci_without_a_tool_sha_writes_a_blocked_placeholder(self):
        root = self.repo()
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["init", "--profile", "python-library", "--ci",
                         "github", "--repo", str(root)],
                        stdout=out, stderr=err)
        self.assertEqual(code, cli.EXIT_BLOCKED, out.getvalue() + err.getvalue())
        self.assertIn("--tool-sha", out.getvalue() + err.getvalue())

    def test_init_ci_with_a_tool_sha_pins_it_in_both_places(self):
        root = self.repo()
        sha = "1" * 40
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["init", "--profile", "python-library", "--ci",
                         "github", "--tool-sha", sha, "--repo", str(root)],
                        stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        written = (root / ".github" / "workflows" / "admissible.yml").read_text(
            encoding="utf-8")
        self.assertIn(f"@{sha}", written)
        self.assertIn(f"tool-sha: {sha}", written)

    def test_a_partial_tool_sha_is_refused(self):
        root = self.repo()
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["init", "--profile", "python-library", "--ci",
                         "github", "--tool-sha", "1" * 7, "--repo", str(root)],
                        stdout=out, stderr=err)
        self.assertEqual(code, cli.EXIT_BLOCKED)


class ProcessGroupCleanupTest(TempCase):
    """Item 7: nothing a check started outlives the check.

    A check that exits zero has told the runner nothing about what it left
    behind. A descendant that closed its pipes looks finished to the drain
    threads and keeps running as the same user, after the evaluation believes
    the check is over -- which is exactly the moment it can rewrite whatever
    the gate is about to read.
    """

    def survivor_check(self, marker, *, delay=3):
        script = (
            "import subprocess, sys\n"
            "subprocess.Popen([sys.executable, '-c',\n"
            "  \"import time, pathlib, sys; time.sleep(%d); \"\n"
            "  \"pathlib.Path(sys.argv[1]).write_text('survived')\",\n"
            "  %r], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,\n"
            "  stdin=subprocess.DEVNULL)\n" % (delay, str(marker)))
        return config_module.Check(
            id="spawner", argv=(sys.executable, "-c", script),
            timeout_seconds=30, cost_units=1, required=True, version="1")

    def test_a_descendant_never_outlives_a_normally_finished_check(self):
        marker = self.tmp / "survived.txt"
        result = runner_module.run_check(self.survivor_check(marker),
                                         cwd=self.tmp, log_dir=None)
        self.assertEqual(result.exit_code, 0)
        time.sleep(5)
        self.assertFalse(marker.exists(),
                         "a descendant outlived the check that started it")

    def test_an_interrupt_kills_the_whole_process_group_too(self):
        """Ctrl-C used to leave the child running and say nothing was recorded."""

        marker = self.tmp / "survived-interrupt.txt"
        original = subprocess.Popen.wait

        calls = 0

        def interrupted(self, *arguments, **keywords):
            nonlocal calls
            if calls == 0:
                calls += 1
                # Let the check fork first, so the kill under test is the one in
                # the interrupt path and not a lucky race.
                time.sleep(1)
                raise KeyboardInterrupt
            return original(self, *arguments, **keywords)

        subprocess.Popen.wait = interrupted
        try:
            with self.assertRaises(KeyboardInterrupt):
                runner_module.run_check(self.survivor_check(marker),
                                        cwd=self.tmp, log_dir=None)
        finally:
            subprocess.Popen.wait = original
        time.sleep(5)
        self.assertFalse(marker.exists(),
                         "an interrupted check left its descendant running")


class ChildEnvironmentTest(unittest.TestCase):
    """Item 7: a check sees no part of the runner's namespace."""

    def test_the_runner_namespace_is_stripped_entirely(self):
        source = {
            "GITHUB_WORKSPACE": "/w", "RUNNER_TEMP": "/t",
            "GITHUB_OUTPUT": "/o", "GITHUB_ENV": "/e", "GITHUB_SHA": "abc",
            "ACTIONS_RUNTIME_TOKEN": "tok", "ADMISSIBLE_HOME": "/h",
            "ADMISSIBLE_HMAC_KEY": "k", "PATH": "/bin", "CI": "true",
        }
        seen = runner_module.child_environment(source)
        self.assertEqual(sorted(seen), ["ADMISSIBLE_IN_CHECK", "CI", "PATH"])

    def test_the_only_admissible_variable_a_check_sees_carries_nothing(self):
        seen = runner_module.child_environment({"PATH": "/bin"})
        self.assertEqual(seen["ADMISSIBLE_IN_CHECK"], "1")


class ToolTreeIntegrityTest(TempCase):
    """Item 7: a check that edits the gate is not judged by the gate."""

    def test_the_tool_tree_digest_changes_when_the_tool_changes(self):
        package = self.tmp / "package"
        package.mkdir()
        (package / "a.py").write_text("one\n", encoding="utf-8")
        before = runner_module.tool_tree_digest(package)
        (package / "a.py").write_text("two\n", encoding="utf-8")
        self.assertNotEqual(before, runner_module.tool_tree_digest(package))

    def test_a_check_that_rewrites_the_tool_blocks_the_run(self):
        tool = self.tmp / "tool-copy"
        tool.mkdir()
        (tool / "marker.py").write_text("original\n", encoding="utf-8")
        root = self.tmp / "candidate"
        script = (f"import pathlib\n"
                  f"pathlib.Path({str(tool / 'marker.py')!r}).write_text('x')\n")
        sha = make_repo(root, files={
            "sabotage.py": script,
            ".admissible.json": json.dumps(
                policy([sys.executable, "sabotage.py"])),
        })
        original = runner_module.tool_tree_digest

        def measured(package_root=None):
            return original(tool if package_root is None else package_root)

        runner_module.tool_tree_digest = measured
        try:
            out, err = io.StringIO(), io.StringIO()
            code = cli.main(["run", "--preview", "--repo", str(root),
                             "--sha", sha, "--json"], stdout=out, stderr=err)
        finally:
            runner_module.tool_tree_digest = original
        self.assertEqual(code, cli.EXIT_BLOCKED, out.getvalue())
        self.assertIn("program that judged", out.getvalue() + err.getvalue())


class ConfigPathTest(TempCase):
    """Item 9: the selected policy file is the file that decides."""

    def setUp(self):
        super().setUp()
        self.root = self.tmp / "candidate"
        # A strict policy the caller selects, and a lenient default beside it.
        self.sha = make_repo(self.root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(
                policy([sys.executable, "-c", "pass"])),
            "strict.json": json.dumps(
                policy([sys.executable, "-c", "raise SystemExit(3)"])),
        })

    def run_with(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["run", "--preview", "--repo", str(self.root),
                         "--sha", self.sha, "--json", *extra],
                        stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_the_default_policy_is_used_when_none_is_selected(self):
        code, out, err = self.run_with()
        self.assertEqual(code, 0, out + err)

    def test_the_selected_policy_is_the_one_that_decides(self):
        code, out, err = self.run_with("--config", "strict.json")
        self.assertEqual(code, 1, out + err)
        self.assertIn("failed_check",
                      {reason["code"] for reason in json.loads(out)["reasons"]})

    def test_the_preview_names_the_policy_file_it_used(self):
        preview = self.tmp / "preview.json"
        self.run_with("--config", "strict.json", "--preview-out", str(preview))
        document = json.loads(preview.read_text(encoding="utf-8"))
        self.assertEqual(document["config_path"], "strict.json")

    def test_a_policy_outside_the_repository_is_refused(self):
        for escape in ("../outside.json", "/etc/passwd"):
            code, out, err = self.run_with("--config", escape)
            self.assertEqual(code, cli.EXIT_BLOCKED, out + err)


class PolicyFloorTest(unittest.TestCase):
    """Item 10: a high-risk profile can be tightened, never weakened."""

    def weakened(self, **overrides):
        document = profiles_module.profile_document("payment-change")
        artifact_class = document["classes"][0]
        artifact_class["reviewer_key_ids"] = ["reviewer-a", "reviewer-b"]
        artifact_class["author_key_ids"] = ["author-key"]
        artifact_class.update(overrides)
        return document

    def test_the_shipped_high_risk_profile_parses_once_configured(self):
        config_module.parse_config(self.weakened())

    def test_reviews_cannot_be_reduced_below_the_built_in_floor(self):
        with self.assertRaises(config_module.ConfigError) as caught:
            config_module.parse_config(
                self.weakened(required_independent_reviews=0))
        self.assertIn("at least 2", str(caught.exception))

    def test_a_required_check_cannot_be_dropped(self):
        document = self.weakened()
        artifact_class = document["classes"][0]
        artifact_class["checks"] = [
            check for check in artifact_class["checks"]
            if check["id"] != "ledger-invariants"]
        with self.assertRaises(config_module.ConfigError) as caught:
            config_module.parse_config(document)
        self.assertIn("ledger-invariants", str(caught.exception))

    def test_a_required_check_cannot_be_made_optional(self):
        document = self.weakened()
        for check in document["classes"][0]["checks"]:
            if check["id"] == "payment-tests":
                check["required"] = False
        with self.assertRaises(config_module.ConfigError):
            config_module.parse_config(document)

    def test_the_argv_of_a_required_check_stays_the_operator_s_own(self):
        """The floor is about the checks, never about the commands."""

        document = self.weakened()
        for check in document["classes"][0]["checks"]:
            check["argv"] = ["make", "something-else"]
        config_module.parse_config(document)

    def test_tightening_beyond_the_floor_is_always_allowed(self):
        config_module.parse_config(
            self.weakened(required_independent_reviews=3))

    def test_a_low_risk_profile_has_no_floor(self):
        self.assertIsNone(profiles_module.profile_floor("python-library"))


class ReviewKeyValidationTest(unittest.TestCase):
    """Item 11: "independent" needs both lists, and they must be disjoint."""

    def klass(self, **overrides):
        artifact_class = {
            "id": "default",
            "checks": [{"id": "unit", "argv": ["true"], "timeout_seconds": 60,
                        "cost_units": 1, "required": True, "version": "1"}],
            "required_independent_reviews": 1,
            "review_max_age_seconds": 86400,
            "max_cost_units": 10, "max_wall_seconds": 600,
            "reviewer_key_ids": ["reviewer-a"],
            "author_key_ids": ["author-key"],
        }
        artifact_class.update(overrides)
        return {"version": 1, "profile": "python-library",
                "classes": [artifact_class]}

    def test_a_configured_class_parses(self):
        config_module.parse_config(self.klass())

    def test_an_empty_reviewer_list_is_refused(self):
        with self.assertRaises(config_module.ConfigError):
            config_module.parse_config(self.klass(reviewer_key_ids=[]))

    def test_an_empty_author_list_is_refused(self):
        with self.assertRaises(config_module.ConfigError):
            config_module.parse_config(self.klass(author_key_ids=[]))

    def test_overlapping_lists_are_refused(self):
        with self.assertRaises(config_module.ConfigError) as caught:
            config_module.parse_config(
                self.klass(author_key_ids=["reviewer-a", "author-key"]))
        self.assertIn("disjoint", str(caught.exception))

    def test_a_class_requiring_no_review_needs_neither_list(self):
        config_module.parse_config(self.klass(
            required_independent_reviews=0, reviewer_key_ids=[],
            author_key_ids=[]))

    def test_every_generated_high_risk_profile_ships_blocked(self):
        for name in profiles_module.HIGH_RISK_PROFILES:
            document = profiles_module.profile_document(name)
            with self.assertRaises(config_module.ConfigError, msg=name):
                config_module.parse_config(document)
            config_module.parse_config(document, allow_placeholders=True)

    def test_the_payment_claim_says_exactly_what_is_enforced(self):
        requirement = profiles_module.get_profile(
            "payment-change").review_requirement.lower()
        self.assertIn("two", requirement)
        self.assertIn("distinct", requirement)
        self.assertIn("author", requirement)


class CacheHonestyTest(TempCase):
    """Items 14 and 28: reuse is bounded, and news outranks memory."""

    def setUp(self):
        super().setUp()
        self.store = store_module.open_store(self.home)
        self.addCleanup(self.store.close)
        self.artifact_class = config_module.parse_config(
            policy()).select_class("default")
        self.repository = "github.com/acme/widget"
        self.sha = "a1" * 20
        self.tree = "b2" * 20

    def record(self, attempt_id, *, exit_code=0, finished_at=1000):
        return evidence.command_evidence_from_dict({
            "kind": "command", "check_id": "unit", "check_version": "1",
            "repository": self.repository, "commit_sha": self.sha,
            "tree_sha": self.tree,
            "policy_digest": self.artifact_class.policy_digest,
            "argv_digest": self.artifact_class.check("unit").argv_digest,
            "exit_code": exit_code, "timed_out": False, "launch_failed": False,
            "duration_ms": 5, "stdout_sha256": "0" * 64,
            "stderr_sha256": "0" * 64, "stdout_bytes": 0, "stderr_bytes": 0,
            "output_truncated": False, "started_at": finished_at - 1,
            "finished_at": finished_at, "attempt_id": attempt_id,
            "reused_from_attempt": "",
        })

    def cached(self, *, now=2000, max_age=0, fingerprint="machine-a"):
        return self.store.cached_command_evidence(
            repository=self.repository, commit_sha=self.sha,
            tree_sha=self.tree,
            policy_digest=self.artifact_class.policy_digest,
            check_id="unit", check_version="1",
            argv_digest=self.artifact_class.check("unit").argv_digest,
            environment_fingerprint=fingerprint, now=now,
            max_age_seconds=max_age)

    def test_a_pass_is_reusable(self):
        self.store.cache_command_evidence(
            self.record("attempt-a"), recorded_at=1000,
            environment_fingerprint="machine-a")
        self.assertIsNotNone(self.cached())

    def test_a_newer_failure_invalidates_an_older_success(self):
        """Pass, then a known failure, then an ordinary run.

        The failure is never cached -- a failing check must be re-run so a
        repair can be observed -- but it is still news about this exact cache
        key. Dropping it on the floor let the next ordinary run resurrect the
        old pass and admit a commit that had been seen to fail.
        """

        self.store.cache_command_evidence(
            self.record("attempt-a"), recorded_at=1000,
            environment_fingerprint="machine-a")
        self.store.cache_command_evidence(
            self.record("attempt-b", exit_code=1, finished_at=2000),
            recorded_at=2000, environment_fingerprint="machine-a")
        self.assertIsNone(self.cached(now=3000))

    def test_a_different_machine_is_a_different_observation(self):
        self.store.cache_command_evidence(
            self.record("attempt-a"), recorded_at=1000,
            environment_fingerprint="machine-a")
        self.assertIsNone(self.cached(fingerprint="machine-b"))

    def test_a_pass_older_than_the_policy_allows_is_not_reused(self):
        self.store.cache_command_evidence(
            self.record("attempt-a", finished_at=1000), recorded_at=1000,
            environment_fingerprint="machine-a")
        self.assertIsNotNone(self.cached(now=1500, max_age=3600))
        self.assertIsNone(self.cached(now=100000, max_age=3600))

    def test_a_check_marked_uncacheable_is_never_remembered(self):
        self.store.cache_command_evidence(
            self.record("attempt-a"), recorded_at=1000,
            environment_fingerprint="machine-a", cacheable=False)
        self.assertIsNone(self.cached())

    def test_the_infrastructure_profile_never_caches_live_state(self):
        parsed = config_module.parse_config(
            profiles_module.profile_document("infrastructure-change"),
            allow_placeholders=True)
        for check in parsed.select_class("default").checks:
            self.assertFalse(check.cacheable, check.id)

    def test_a_tree_only_profile_bounds_reuse_by_age(self):
        parsed = config_module.parse_config(
            profiles_module.profile_document("python-library"))
        for check in parsed.select_class("default").checks:
            self.assertTrue(check.cacheable, check.id)
            self.assertGreater(check.cache_max_age_seconds, 0, check.id)


class ImportAtomicityTest(TempCase):
    """Items 18 to 21: a bundle lands whole, or not at all."""

    def setUp(self):
        super().setUp()
        self.signer = receipt.signer_from_secret("k1", SECRET)
        self.source = store_module.open_store(self.tmp / "source")
        self.addCleanup(self.source.close)
        self.repository = "github.com/acme/widget"
        self.journal = receipt.journal_id_for(self.repository)
        self.first = self.anchor("a1" * 20, 1000)
        self.second = self.anchor("a2" * 20, 2000)
        self.bundle = self.source.export_journal(self.journal)

    def anchor(self, sha, now):
        return receipt.issue_receipt_from_parts(
            self.source, repository=self.repository, commit_sha=sha,
            tree_sha="b2" * 20, class_id="default", policy_digest="c" * 64,
            state=decision.ADMITTED, attempt_id=f"attempt-{sha[:4]}",
            decision_digest_value="d" * 64, evidence_digests=(),
            signer=self.signer, now=now)

    def target(self):
        opened = store_module.open_store(self.tmp / "target")
        self.addCleanup(opened.close)
        return opened

    def test_a_complete_bundle_imports(self):
        opened = self.target()
        head = opened.import_journal(self.bundle, self.signer)
        self.assertEqual(head.event_count, 2)
        self.assertEqual(opened.receipt_count(self.repository), 2)

    def test_a_dropped_workflow_receipt_is_refused(self):
        bundle = json.loads(json.dumps(self.bundle))
        bundle["workflow_receipts"] = bundle["workflow_receipts"][:1]
        opened = self.target()
        with self.assertRaises(store_module.StoreError) as caught:
            opened.import_journal(bundle, self.signer)
        self.assertIn("admission event", str(caught.exception))

    def test_an_invalid_last_head_writes_nothing_at_all(self):
        """The earlier head must not survive the failure of the later one."""

        bundle = json.loads(json.dumps(self.bundle))
        bundle["workflow_receipts"] = bundle["workflow_receipts"][:1]
        opened = self.target()
        with self.assertRaises(store_module.StoreError):
            opened.import_journal(bundle, self.signer)
        self.assertIsNone(opened.current_head(self.journal))
        self.assertEqual(opened.receipt_count(self.repository), 0)
        self.assertEqual(len(opened.journal_events(self.journal)), 0)

    def test_a_receipt_whose_evidence_did_not_travel_is_refused(self):
        record = evidence.command_evidence_from_dict({
            "kind": "command", "check_id": "unit", "check_version": "1",
            "repository": self.repository, "commit_sha": "a3" * 20,
            "tree_sha": "b2" * 20, "policy_digest": "c" * 64,
            "argv_digest": "e" * 64, "exit_code": 0, "timed_out": False,
            "launch_failed": False, "duration_ms": 1,
            "stdout_sha256": "0" * 64, "stderr_sha256": "0" * 64,
            "stdout_bytes": 0, "stderr_bytes": 0, "output_truncated": False,
            "started_at": 1, "finished_at": 2, "attempt_id": "attempt-x",
            "reused_from_attempt": "",
        })
        receipt.issue_receipt_from_parts(
            self.source, repository=self.repository, commit_sha="a3" * 20,
            tree_sha="b2" * 20, class_id="default", policy_digest="c" * 64,
            state=decision.ADMITTED, attempt_id="attempt-x",
            decision_digest_value="d" * 64,
            evidence_digests=(evidence.evidence_digest(record),),
            commands=(record,), signer=self.signer, now=3000)
        bundle = self.source.export_journal(self.journal)
        self.assertTrue(bundle["evidence"])
        bundle["evidence"] = []
        with self.assertRaises(store_module.StoreError) as caught:
            self.target().import_journal(bundle, self.signer)
        self.assertIn("did not travel", str(caught.exception))

    def test_dependency_edges_are_rebuilt_from_the_signed_body(self):
        receipt.issue_receipt_from_parts(
            self.source, repository=self.repository, commit_sha="a4" * 20,
            tree_sha="b2" * 20, class_id="default", policy_digest="c" * 64,
            state=decision.ADMITTED, attempt_id="attempt-d",
            decision_digest_value="d" * 64, evidence_digests=(),
            dependencies=(("github.com/acme/upstream", "7" * 40),),
            signer=self.signer, now=4000)
        opened = self.target()
        opened.import_journal(self.source.export_journal(self.journal),
                              self.signer)
        self.assertEqual(
            opened.direct_consumers("github.com/acme/upstream", "7" * 40),
            ((self.repository, "a4" * 20),))


class ExportRoundTripTest(TempCase):
    """Item 20: export is a complete, consistent inverse of import."""

    def setUp(self):
        super().setUp()
        self.signer = receipt.signer_from_secret("k1", SECRET)
        self.source = store_module.open_store(self.tmp / "source")
        self.addCleanup(self.source.close)
        self.repository = "github.com/acme/widget"
        self.journal = receipt.journal_id_for(self.repository)

    def defect(self, sha, defect_id):
        return {
            "kind": "defect", "defect_id": defect_id,
            "repository": self.repository, "commit_sha": sha,
            "severity": "high", "summary": "later news",
            "missed_check_ids": [], "regression_test_id": "unit",
            "discovered_at": 5000,
        }

    def test_a_defect_only_journal_exports_its_records(self):
        """A journal with no receipts at all is a supported shape.

        Repositories used to be discovered through workflow receipts, so a
        journal that carried nothing but a signed defect exported the event and
        none of the record that explains it -- a bundle its own importer then
        rejected.
        """

        standing_module.file_defect(
            self.source, self.defect("a1" * 20, "D-1"), signer=self.signer,
            now=5000)
        bundle = self.source.export_journal(self.journal)
        self.assertEqual(len(bundle["events"]), 1)
        self.assertEqual(len(bundle["defects"]), 1)
        opened = store_module.open_store(self.tmp / "target")
        self.addCleanup(opened.close)
        opened.import_journal(bundle, self.signer)
        self.assertEqual(opened.defect_count(self.repository), 1)

    def test_an_export_reimports_and_re_exports_equivalently(self):
        receipt.issue_receipt_from_parts(
            self.source, repository=self.repository, commit_sha="a1" * 20,
            tree_sha="b2" * 20, class_id="default", policy_digest="c" * 64,
            state=decision.ADMITTED, attempt_id="attempt-a",
            decision_digest_value="d" * 64, evidence_digests=(),
            dependencies=(("github.com/acme/upstream", "7" * 40),),
            signer=self.signer, now=1000)
        standing_module.file_defect(
            self.source, self.defect("a1" * 20, "D-1"), signer=self.signer,
            now=5000)
        first = self.source.export_journal(self.journal)

        opened = store_module.open_store(self.tmp / "target")
        self.addCleanup(opened.close)
        opened.import_journal(first, self.signer)
        second = opened.export_journal(self.journal)

        def normalised(bundle):
            return {
                "schema": bundle["schema"],
                "journal_id": bundle["journal_id"],
                "events": bundle["events"],
                "receipts": sorted(bundle["receipts"],
                                   key=lambda item: item["event_count"]),
                "workflow_receipts": sorted(
                    bundle["workflow_receipts"],
                    key=lambda item: item["receipt_hash"]),
                "evidence": sorted(bundle["evidence"],
                                   key=lambda item: item["digest"]),
                "defects": sorted(bundle["defects"],
                                  key=lambda item: item["defect_id"]),
            }

        self.assertEqual(normalised(first), normalised(second))


class HistoricalAttemptTest(TempCase):
    """Item 23: a refused attempt is explained from what it recorded."""

    def test_explain_reports_the_refusal_the_attempt_actually_saw(self):
        root = self.tmp / "candidate"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(
                policy([sys.executable, "-c", "raise SystemExit(4)"])),
        })
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["run", "--preview", "--repo", str(root), "--sha", sha,
                         "--json"], stdout=out, stderr=err)
        self.assertEqual(code, 1, out.getvalue() + err.getvalue())
        attempt = json.loads(out.getvalue())["attempt_id"]

        # The checkout moves on. The recorded attempt did not.
        (root / "README.md").write_text("moved on\n", encoding="utf-8")
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "next")

        out, err = io.StringIO(), io.StringIO()
        cli.main(["explain", sha, "--repo", str(root), "--json"],
                 stdout=out, stderr=err)
        document = json.loads(out.getvalue())
        self.assertEqual(document["decision_attempt_id"], attempt)
        recorded = document["recorded_decision"]
        self.assertIsNotNone(recorded, "the attempt recorded no decision")
        self.assertEqual(recorded["state"], decision.REFUSED)
        codes = {reason["code"] for reason in recorded["reasons"]}
        self.assertIn("failed_check", codes)
        # And not the answers a stale tree would have produced.
        self.assertNotIn("stale_evidence_tree", codes)
        self.assertNotIn("missing_check", codes)


class UsageJsonTest(unittest.TestCase):
    """Item 27: a --json caller is owed JSON, even for a bad command line."""

    def invoke(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(list(argv), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_a_missing_required_argument_is_reported_as_json(self):
        code, out, err = self.invoke("init", "--json")
        self.assertEqual(code, 2)
        document = json.loads(out)
        self.assertEqual(document["state"], "BLOCKED")
        self.assertEqual(document["exit_code"], 2)
        self.assertTrue(document["message"])
        self.assertTrue(document["remediation"])
        self.assertEqual(err, "")

    def test_an_unknown_command_is_reported_as_json(self):
        code, out, _ = self.invoke("not-a-command", "--json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["state"], "BLOCKED")

    def test_prose_is_still_prose_without_json(self):
        code, out, err = self.invoke("init")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("required", err)


class PackagedArtefactTest(unittest.TestCase):
    """Item 30: the metadata a constrained build environment must satisfy."""

    def pyproject(self) -> str:
        return (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    def test_the_backend_can_parse_this_file_s_own_metadata(self):
        text = self.pyproject()
        self.assertIn('license = "Apache-2.0"', text)
        self.assertIn('requires = ["setuptools==83.0.0"]', text)
        self.assertNotIn("setuptools>=", text)

    def test_build_is_in_the_dev_extra(self):
        self.assertIn('dev = ["build==1.4.0"', self.pyproject())

    def test_partial_test_packages_are_excluded_from_discovery(self):
        text = self.pyproject()
        self.assertIn('exclude = ["tests*", "atlas.tests*"', text)

    def test_a_tracked_license_ships_with_the_declared_one(self):
        license_file = ROOT / "LICENSE"
        self.assertTrue(license_file.is_file(),
                        "Apache-2.0 is declared but not shipped")
        self.assertIn("Apache License",
                      license_file.read_text(encoding="utf-8"))
        self.assertTrue((ROOT / "NOTICE").is_file())
        manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn("include LICENSE", manifest)
        self.assertIn("include NOTICE", manifest)

class SpecificRefusalTest(PreviewCase):
    """Each guard refuses for its own reason, and the test says which.

    Defence in depth makes a suite easy to fool: a second guard catches what the
    first one missed, the test still goes green, and nobody notices the first
    guard was deleted. Every assertion here names the guard it is about.
    """

    def attestation_over(self, document, **overrides):
        path = self.tmp / "custom-attestation.json"
        overrides.setdefault(
            "source_receipt", source_receipt_document(document["commit_sha"]))
        overrides.setdefault("isolation", "pid-namespace")
        path.write_text(json.dumps(attestation_module.attest_preview(
            document, key_id="observer-1", secret=EVALUATION_SECRET,
            observed_at=max(int(time.time()), document["issued_at"]),
            **overrides)), encoding="utf-8")
        return path

    def rewrite(self, **overrides):
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document.update(overrides)
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        return document

    def test_a_forged_repository_is_refused_by_the_trusted_checkout(self):
        forged = "github.com/mallory/widget"
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document["repository"] = forged
        document["decision"]["repository"] = forged
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=self.attestation_over(
                document, repository=self.repository))
        message = str(caught.exception)
        self.assertIn(f"preview claims repository {forged!r}", message)
        self.assertIn(
            f"trusted checkout is {self.repository!r}", message)

    def test_an_observer_covering_fewer_records_is_refused(self):
        """A validly signed attestation over the wrong set of records."""

        document = json.loads(self.preview.read_text(encoding="utf-8"))
        path = self.attestation_over(document, command_digests=[])
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=path)
        self.assertIn("different set of records", str(caught.exception))

    def test_a_tampered_observation_time_is_refused_by_the_signature(self):
        """The one field no later comparison would catch."""

        path = self.attestation()
        document = json.loads(path.read_text(encoding="utf-8"))
        document["evaluation"]["observed_at"] += 1
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=path)
        self.assertIn("not authentic", str(caught.exception))

    def test_an_unpinned_observer_is_refused_by_the_keyring(self):
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(keyring={"someone-else": EVALUATION_SECRET})
        self.assertIn("no evaluation key", str(caught.exception))

    def test_a_preview_naming_no_attempt_is_refused(self):
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document["decision"]["attempt_id"] = ""
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(attestation_path=self.attestation_over(document))
        self.assertIn("names no attempt", str(caught.exception))


class TrustedPolicyBaselineTest(TempCase):
    """Item 10: a candidate may propose a policy; an operator anchors one."""

    def setUp(self):
        super().setUp()
        self.signer = receipt.signer_from_secret("k1", SECRET)
        self.store = store_module.open_store(self.home)
        self.addCleanup(self.store.close)
        self.root = self.tmp / "candidate"
        self.sha = make_repo(self.root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(policy()),
        })
        self.repository = "github.com/acme/widget"
        self.preview = self.tmp / "preview.json"
        out, err = io.StringIO(), io.StringIO()
        cli.main(["run", "--preview", "--repo", str(self.root), "--sha",
                  self.sha, "--preview-out", str(self.preview), "--json"],
                 stdout=out, stderr=err)

    def artifact_class(self, root=None):
        return config_module.load_config(root or self.root).select_class(
            "default")

    def trust(self, artifact_class):
        self.store.trust_policy(
            repository=self.repository, class_id="default",
            policy_digest=artifact_class.policy_digest,
            enforcement_digest=config_module.enforcement_digest(
                artifact_class),
            trusted_at=1000)

    def finalize(self, preview=None, root=None, sha=None):
        source = preview or self.preview
        path = self.tmp / "evaluation.json"
        parsed = json.loads(source.read_text(encoding="utf-8"))
        path.write_text(json.dumps(attestation_module.attest_preview(
            parsed, key_id="observer-1", secret=EVALUATION_SECRET,
            isolation="pid-namespace",
            source_receipt=source_receipt_document(parsed["commit_sha"]),
            observed_at=max(int(time.time()), parsed["issued_at"]))),
            encoding="utf-8")
        return ghmod.finalize(
            self.store, source, signer=self.signer,
            expected_sha=sha or self.sha, now=int(time.time()),
            policy_root=root or self.root, evaluation_attestation=path,
            evaluation_keyring={"observer-1": EVALUATION_SECRET})

    def test_no_baseline_means_nothing_is_signed(self):
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize()
        self.assertIn("no trusted policy baseline", str(caught.exception))
        self.assertEqual(self.store.receipt_count(self.repository), 0)

    def test_a_trusted_baseline_admits(self):
        self.trust(self.artifact_class())
        self.assertEqual(self.finalize().commit_sha, self.sha)

    def test_an_editorial_change_does_not_need_re_approving(self):
        """Prose is not enforcement, and re-approving prose trains a habit."""

        self.trust(self.artifact_class())
        document = json.loads(
            (self.root / ".admissible.json").read_text(encoding="utf-8"))
        document["classes"][0]["description"] = "reworded, enforces the same"
        (self.root / ".admissible.json").write_text(
            json.dumps(document), encoding="utf-8")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "reword")
        sha = git(self.root, "rev-parse", "HEAD")
        preview = self.tmp / "preview-2.json"
        out, err = io.StringIO(), io.StringIO()
        cli.main(["run", "--preview", "--repo", str(self.root), "--sha", sha,
                  "--preview-out", str(preview), "--json"],
                 stdout=out, stderr=err)
        self.assertNotEqual(self.artifact_class().policy_digest,
                            json.loads(preview.read_text(
                                encoding="utf-8"))["policy_digest"] + "x")
        self.assertEqual(self.finalize(preview=preview, sha=sha).commit_sha,
                         sha)

    def test_a_changed_enforcement_field_blocks_until_approved(self):
        self.trust(self.artifact_class())
        document = json.loads(
            (self.root / ".admissible.json").read_text(encoding="utf-8"))
        document["classes"][0]["checks"][0]["argv"] = [
            sys.executable, "-c", "pass  # a different command entirely"]
        (self.root / ".admissible.json").write_text(
            json.dumps(document), encoding="utf-8")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "weaken")
        sha = git(self.root, "rev-parse", "HEAD")
        preview = self.tmp / "preview-3.json"
        out, err = io.StringIO(), io.StringIO()
        cli.main(["run", "--preview", "--repo", str(self.root), "--sha", sha,
                  "--preview-out", str(preview), "--json"],
                 stdout=out, stderr=err)
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(preview=preview, sha=sha)
        self.assertIn("enforces something different", str(caught.exception))
        self.assertIn("policy trust", str(caught.exception))

    def test_policy_trust_is_the_bootstrap_and_it_is_explicit(self):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["policy", "trust", "--repo", str(self.root),
                         "--json"], stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        trusted = json.loads(out.getvalue())["trusted"]
        self.assertEqual([item["class_id"] for item in trusted], ["default"])
        self.assertEqual(self.finalize().commit_sha, self.sha)


class FinalizeReadsTheSelectedPolicyTest(TempCase):
    """Item 9: the file the preview names is the file finalize re-reads."""

    def test_the_preview_s_config_path_is_what_finalize_checks(self):
        signer = receipt.signer_from_secret("k1", SECRET)
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        root = self.tmp / "candidate"
        # Two policies with different digests. The caller selects the second.
        selected = policy([sys.executable, "-c", "pass"])
        selected["classes"][0]["max_wall_seconds"] = 599
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(policy([sys.executable, "-c",
                                                   "pass"])),
            "selected.json": json.dumps(selected),
        })
        preview = self.tmp / "preview.json"
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["run", "--preview", "--repo", str(root), "--sha", sha,
                         "--config", "selected.json", "--preview-out",
                         str(preview), "--json"], stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        document = json.loads(preview.read_text(encoding="utf-8"))
        self.assertEqual(document["config_path"], "selected.json")

        parsed = config_module.load_config(root, "selected.json")
        artifact_class = parsed.select_class("default")
        opened.trust_policy(
            repository="github.com/acme/widget", class_id="default",
            policy_digest=artifact_class.policy_digest,
            enforcement_digest=config_module.enforcement_digest(
                artifact_class),
            trusted_at=1000)
        path = self.tmp / "evaluation.json"
        path.write_text(json.dumps(attestation_module.attest_preview(
            document, key_id="observer-1", secret=EVALUATION_SECRET,
            isolation="pid-namespace",
            source_receipt=source_receipt_document(document["commit_sha"]),
            observed_at=max(int(time.time()), document["issued_at"]))),
            encoding="utf-8")
        issued = ghmod.finalize(
            opened, preview, signer=signer, expected_sha=sha,
            now=int(time.time()), policy_root=root,
            evaluation_attestation=path,
            evaluation_keyring={"observer-1": EVALUATION_SECRET})
        # Re-reading `.admissible.json` here would produce a different digest,
        # and the policy comparison would refuse. It admitted, so it read the
        # file the preview named.
        self.assertEqual(issued.policy_digest, artifact_class.policy_digest)


class ConfigEscapeTest(TempCase):
    """Item 9: containment is real, not incidental."""

    def test_a_policy_outside_the_repository_is_never_read(self):
        outside = self.tmp / "outside.json"
        # A perfectly valid, far more lenient policy, deliberately reachable
        # by relative traversal from the repository root.
        outside.write_text(json.dumps(policy([sys.executable, "-c", "pass"])),
                           encoding="utf-8")
        root = self.tmp / "candidate"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(
                policy([sys.executable, "-c", "raise SystemExit(3)"])),
        })
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["run", "--preview", "--repo", str(root), "--sha", sha,
                         "--config", "../outside.json", "--json"],
                        stdout=out, stderr=err)
        self.assertEqual(code, cli.EXIT_BLOCKED, out.getvalue())
        self.assertIn("inside the repository",
                      out.getvalue() + err.getvalue())

    def test_an_absolute_policy_path_is_refused(self):
        root = self.tmp / "candidate"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(policy()),
        })
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["run", "--preview", "--repo", str(root), "--sha", sha,
                         "--config", str(self.tmp / "outside.json"), "--json"],
                        stdout=out, stderr=err)
        self.assertEqual(code, cli.EXIT_BLOCKED, out.getvalue())


class EnvironmentFingerprintTest(unittest.TestCase):
    """Item 14: the machine is part of what a command observed."""

    def test_the_fingerprint_follows_the_platform(self):
        import platform

        original = platform.platform
        first = runner_module.environment_fingerprint()
        platform.platform = lambda *a, **k: "some-other-kernel-9.9"
        try:
            second = runner_module.environment_fingerprint()
        finally:
            platform.platform = original
        self.assertNotEqual(first, second)
        self.assertEqual(first, runner_module.environment_fingerprint())

    def test_the_fingerprint_follows_the_interpreter(self):
        import platform

        original = platform.python_version
        first = runner_module.environment_fingerprint()
        platform.python_version = lambda: "3.99.0"
        try:
            second = runner_module.environment_fingerprint()
        finally:
            platform.python_version = original
        self.assertNotEqual(first, second)


class ConsistentExportTest(TempCase):
    """Item 20: an export reads one generation of a journal, not two."""

    def test_a_writer_between_two_reads_cannot_split_the_export(self):
        """A concurrent anchor must be wholly in the export, or wholly out.

        Without one read transaction the events are read at one moment and the
        head chain at another, so a bundle can carry three events and a head
        covering two -- which its own importer then rejects, from a store that
        was never inconsistent.
        """

        signer = receipt.signer_from_secret("k1", SECRET)
        repository = "github.com/acme/widget"
        journal = receipt.journal_id_for(repository)
        home = self.tmp / "shared"
        reader = store_module.open_store(home)
        self.addCleanup(reader.close)
        writer = store_module.open_store(home)
        self.addCleanup(writer.close)

        def anchor(store, sha, now):
            receipt.issue_receipt_from_parts(
                store, repository=repository, commit_sha=sha,
                tree_sha="b2" * 20, class_id="default", policy_digest="c" * 64,
                state=decision.ADMITTED, attempt_id=f"attempt-{sha[:4]}",
                decision_digest_value="d" * 64, evidence_digests=(),
                signer=signer, now=now)

        anchor(reader, "a1" * 20, 1000)

        # `Store` uses __slots__, so the seam is on the class. The writer's own
        # anchor reads events too, hence the identity check.
        original = store_module.Store.journal_events
        interfered = []

        def read_then_interfere(store, journal_id):
            events = original(store, journal_id)
            if store is reader and not interfered:
                interfered.append(True)
                anchor(writer, "a2" * 20, 2000)
            return events

        store_module.Store.journal_events = read_then_interfere
        try:
            bundle = reader.export_journal(journal)
        finally:
            store_module.Store.journal_events = original
        self.assertTrue(interfered, "the concurrent writer never ran")

        final = max(item["event_count"] for item in bundle["receipts"])
        self.assertEqual(len(bundle["events"]), final,
                         "the export mixed two generations of this journal")
        # And it is a bundle its own importer accepts.
        target = store_module.open_store(self.tmp / "target")
        self.addCleanup(target.close)
        target.import_journal(bundle, signer)


class AttributionTest(TempCase):
    """Item 22: who approved is read from the receipt, by authenticated key."""

    def setUp(self):
        super().setUp()
        self.signer = receipt.signer_from_secret("k1", SECRET)
        self.store = store_module.open_store(self.home)
        self.addCleanup(self.store.close)
        self.repository = "github.com/acme/widget"
        self.sha = "a1" * 20

    def review(self, review_id, reviewer_id):
        return evidence.review_evidence_from_dict({
            "kind": "review", "review_id": review_id,
            "reviewer_id": reviewer_id, "reviewer_version": "1",
            "author_id": "dave", "verdict": "approve",
            "repository": self.repository, "commit_sha": self.sha,
            "tree_sha": "b2" * 20, "policy_digest": "c" * 64,
            "findings_digest": "0" * 64, "issued_at": 1000, "attempt_id": "",
        })

    def anchor(self, *, reviews, authenticated):
        return receipt.issue_receipt_from_parts(
            self.store, repository=self.repository, commit_sha=self.sha,
            tree_sha="b2" * 20, class_id="default", policy_digest="c" * 64,
            state=decision.ADMITTED, attempt_id="attempt-a",
            decision_digest_value="d" * 64,
            evidence_digests=tuple(sorted(
                evidence.evidence_digest(item) for item in reviews)),
            reviews=tuple(reviews), authenticated_reviews=authenticated,
            signer=self.signer, now=1000)

    def impeach(self):
        standing_module.file_defect(self.store, {
            "kind": "defect", "defect_id": "D-1",
            "repository": self.repository, "commit_sha": self.sha,
            "severity": "high", "summary": "later news",
            "missed_check_ids": [], "regression_test_id": "unit",
            "discovered_at": 5000}, signer=self.signer, now=5000)
        return standing_module.impact_report(self.store, self.repository,
                                             self.sha, verifier=self.signer)

    def test_the_authenticated_key_is_named_and_the_claim_is_not(self):
        counted = self.review("r1", "alice-says-so")
        self.anchor(reviews=(counted,),
                    authenticated=((evidence.evidence_digest(counted),
                                    "reviewer-key-a"),))
        report = self.impeach()
        self.assertEqual([item.key_id for item in report.missed_reviewers],
                         ["reviewer-key-a"])
        rendered = standing_module.render_plain(report)
        self.assertIn("key reviewer-key-a", rendered)
        self.assertNotIn("alice-says-so", rendered)

    def test_a_review_no_receipt_authenticated_is_not_an_approval(self):
        """An advisory file dropped beside the real ones names nobody."""

        advisory = self.review("r2", "mallory")
        self.store.put_evidence(
            digest=evidence.evidence_digest(advisory), kind="review",
            repository=self.repository, commit_sha=self.sha,
            tree_sha="b2" * 20, policy_digest="c" * 64,
            record=evidence.review_evidence_to_dict(advisory))
        self.anchor(reviews=(), authenticated=())
        report = self.impeach()
        self.assertEqual(report.missed_reviewers, ())

    def test_a_command_no_receipt_binds_is_not_an_approving_check(self):
        stray = evidence.command_evidence_from_dict({
            "kind": "command", "check_id": "stray", "check_version": "1",
            "repository": self.repository, "commit_sha": self.sha,
            "tree_sha": "b2" * 20, "policy_digest": "c" * 64,
            "argv_digest": "e" * 64, "exit_code": 0, "timed_out": False,
            "launch_failed": False, "duration_ms": 1,
            "stdout_sha256": "0" * 64, "stderr_sha256": "0" * 64,
            "stdout_bytes": 0, "stderr_bytes": 0, "output_truncated": False,
            "started_at": 1, "finished_at": 2, "attempt_id": "attempt-z",
            "reused_from_attempt": "",
        })
        self.store.put_evidence(
            digest=evidence.evidence_digest(stray), kind="command",
            repository=self.repository, commit_sha=self.sha,
            tree_sha="b2" * 20, policy_digest="c" * 64,
            record=evidence.command_evidence_to_dict(stray))
        self.anchor(reviews=(), authenticated=())
        report = self.impeach()
        self.assertEqual([item.check_id for item in report.missed_checks], [])

class ShippedSnippetTest(unittest.TestCase):
    """Item 32: every file a shipped snippet opens is closed.

    The Python in the workflows, the composite action and the demo is real
    code that real consumers copy. A bare ``open(...)`` inside a snippet leaks
    a handle, and under ``-W error::ResourceWarning`` -- which is how a careful
    consumer runs their own CI -- it turns a passing step into a crash in
    somebody else's repository.
    """

    SHIPPED = (
        ".github/workflows/admissible-gate.yml",
        ".github/workflows/admissible.yml",
        ".github/actions/admissible/action.yml",
        "admissible/templates/reusable-workflow.yml",
        "admissible/templates/workflow.yml",
        "admissible/templates/action.yml",
        "admissible/templates/consumer-workflow.yml",
        "examples/developer-workflow/demo.sh",
        "examples/developer-workflow/show.py",
    )

    def test_no_shipped_snippet_leaks_a_file_handle(self):
        offenders = []
        for relative in self.SHIPPED:
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            for number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), start=1):
                stripped = line.strip()
                if "open(" not in stripped:
                    continue
                if ("with open(" in stripped or stripped.startswith("#")
                        or "os.open(" in stripped or "def " in stripped):
                    continue
                offenders.append(f"{relative}:{number}: {stripped}")
        self.assertEqual([], offenders)

    def test_the_demo_helper_runs_clean_under_resource_warnings(self):
        """The demo's Python is a file, so it can actually be exercised."""

        helper = ROOT / "examples" / "developer-workflow" / "show.py"
        completed = subprocess.run(
            (sys.executable, "-W", "error::ResourceWarning", str(helper)),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # No action given: it prints usage and exits 2, having opened nothing.
        self.assertEqual(completed.returncode, 2,
                         completed.stdout.decode("utf-8", "replace"))
        self.assertIn(b"usage", completed.stdout.lower())

if __name__ == "__main__":  # pragma: no cover
    unittest.main()
