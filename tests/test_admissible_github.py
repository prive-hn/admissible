"""Contract: GitHub evaluate/finalize trust boundaries."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import (TempCase, make_repo,  # noqa: E402
                                require_module, source_receipt_document)

attestation = require_module("admissible.attestation")
ghmod = require_module("admissible.github")
receipt = require_module("admissible.receipt")
store = require_module("admissible.store")
decision = require_module("admissible.decision")

ROOT = Path(__file__).resolve().parent.parent
SECRET = "unit-test-secret-not-a-real-key"
OBSERVER = b"unit-test-observer-secret-not-a-real-key"
HEAD_SHA = "a1" * 20
MERGE_SHA = "b2" * 20


class ContextTest(TempCase):
    def event(self, document) -> str:
        path = self.tmp / "event.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return str(path)

    def env(self, **overrides):
        base = {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REPOSITORY": "acme/widget",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_SHA": MERGE_SHA,
            "GITHUB_REF": "refs/heads/main",
        }
        base.update(overrides)
        return base

    def test_push_binds_the_pushed_sha(self):
        context = ghmod.evaluation_context(self.env())
        self.assertEqual(context.commit_sha, MERGE_SHA)
        self.assertEqual(context.repository, "github.com/acme/widget")
        self.assertFalse(context.is_fork)

    def test_pull_request_binds_head_sha_not_the_synthetic_merge_sha(self):
        path = self.event({"pull_request": {
            "head": {"sha": HEAD_SHA, "repo": {"full_name": "acme/widget"}},
            "base": {"repo": {"full_name": "acme/widget"}}}})
        context = ghmod.evaluation_context(self.env(
            GITHUB_EVENT_NAME="pull_request", GITHUB_EVENT_PATH=path))
        self.assertEqual(context.commit_sha, HEAD_SHA)
        self.assertNotEqual(context.commit_sha, MERGE_SHA)
        self.assertTrue(context.can_sign)

    def test_fork_pull_request_can_evaluate_but_never_sign(self):
        path = self.event({"pull_request": {
            "head": {"sha": HEAD_SHA, "repo": {"full_name": "mallory/widget"}},
            "base": {"repo": {"full_name": "acme/widget"}}}})
        context = ghmod.evaluation_context(self.env(
            GITHUB_EVENT_NAME="pull_request", GITHUB_EVENT_PATH=path))
        self.assertTrue(context.is_fork)
        self.assertFalse(context.can_sign)
        self.assertTrue(context.preview_only)

    def test_pull_request_target_is_refused(self):
        path = self.event({"pull_request": {
            "head": {"sha": HEAD_SHA, "repo": {"full_name": "mallory/widget"}},
            "base": {"repo": {"full_name": "acme/widget"}}}})
        with self.assertRaises(ghmod.GitHubError):
            ghmod.evaluation_context(self.env(
                GITHUB_EVENT_NAME="pull_request_target", GITHUB_EVENT_PATH=path))

    def test_missing_event_payload_is_refused_not_guessed(self):
        with self.assertRaises(ghmod.GitHubError):
            ghmod.evaluation_context(self.env(GITHUB_EVENT_NAME="pull_request"))

    def test_partial_or_non_hex_sha_is_refused(self):
        for bad in (HEAD_SHA[:12], HEAD_SHA.upper(), "z" * 40, ""):
            path = self.event({"pull_request": {
                "head": {"sha": bad, "repo": {"full_name": "acme/widget"}},
                "base": {"repo": {"full_name": "acme/widget"}}}})
            with self.assertRaises(ghmod.GitHubError):
                ghmod.evaluation_context(self.env(
                    GITHUB_EVENT_NAME="pull_request", GITHUB_EVENT_PATH=path))

    def test_context_carries_no_environment_dump(self):
        document = ghmod.context_to_dict(ghmod.evaluation_context(
            self.env(ACTIONS_RUNTIME_TOKEN="tok", GITHUB_TOKEN="tok")))
        self.assertNotIn("tok", json.dumps(document))
        self.assertEqual(set(document) & {"env", "environment", "secrets"}, set())


class FinalizeTest(TempCase):
    """Finalization against a real trusted checkout, as the workflow runs it."""

    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET
        self.store = store.open_store(self.home)
        self.addCleanup(self.store.close)
        self.signer = receipt.load_signer()
        config_module = require_module("admissible.config")
        self.policy = {
            "version": 1, "profile": "documentation-only",
            "classes": [{
                "id": "default",
                "checks": [{"id": "noop", "argv": ["true"],
                            "timeout_seconds": 60, "cost_units": 1,
                            "required": False, "version": "1"}],
                "required_independent_reviews": 0,
                "review_max_age_seconds": 86400,
                "max_cost_units": 10, "max_wall_seconds": 600}]}
        self.trusted = self.tmp / "trusted"
        self.sha = make_repo(self.trusted, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(self.policy)})
        self.tree = self.trusted_tree()
        self.artifact_class = config_module.parse_config(
            self.policy).select_class("default")
        # An operator has deliberately made this policy enforceable here. A
        # finalizer without a baseline refuses everything, which is a separate
        # guarantee with its own tests.
        self.store.trust_policy(
            repository="github.com/acme/widget", class_id="default",
            policy_digest=self.artifact_class.policy_digest,
            enforcement_digest=config_module.enforcement_digest(
                self.artifact_class),
            trusted_at=1000)

    def trusted_tree(self) -> str:
        from admissible_support import git

        return git(self.trusted, "rev-parse", "HEAD^{tree}")

    def bundle(self, **overrides):
        result = decision.evaluate(
            artifact_class=self.artifact_class,
            repository="github.com/acme/widget", commit_sha=self.sha,
            tree_sha=self.tree,
            policy_digest=self.artifact_class.policy_digest,
            commands=(), reviews=(), now=1000, attempt_id="attempt-1")
        document = {
            "schema": "admissible/v0.6/workflow-preview",
            "repository": "github.com/acme/widget",
            "commit_sha": self.sha,
            "tree_sha": self.tree,
            "policy_digest": self.artifact_class.policy_digest,
            "class_id": "default",
            "state": "CHECKS_PASSED",
            "readiness": "READY_FOR_ATTESTATION",
            "decision": decision.decision_to_dict(result),
            "evidence": {"schema": "admissible/v0.6/workflow-evidence",
                         "commands": [], "reviews": [], "defects": [],
                         "attestations": []},
            "dependencies": [],
            "issued_at": 1000,
            "fork": False,
            # An operator declaring the boundary that confined the checks.
            # There is no honest default: absent is "none", and finalize
            # refuses that on purpose, which has its own test.
            "isolation": "pid-namespace",
            "config_path": ".admissible.json",
            "policy_anchor": "unanchored",
        }
        document.update(overrides)
        path = self.tmp / "preview.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def attest(self, path):
        """What the external observer signs about that preview."""

        preview = json.loads(path.read_text(encoding="utf-8"))
        document = attestation.attest_preview(
            preview, key_id="observer-1", secret=OBSERVER,
            isolation="pid-namespace",
            source_receipt=source_receipt_document(preview["commit_sha"]),
            observed_at=max(1000, preview["issued_at"]))
        out = self.tmp / "evaluation.json"
        out.write_text(json.dumps(document), encoding="utf-8")
        return out

    def finalize(self, path, *, expected_sha=None, now=2000,
                 evaluation="default"):
        if evaluation == "default":
            evaluation = self.attest(path)
        return ghmod.finalize(self.store, path, signer=self.signer,
                              expected_sha=expected_sha or self.sha, now=now,
                              policy_root=self.trusted,
                              evaluation_attestation=evaluation,
                              evaluation_keyring={"observer-1": OBSERVER})

    def test_an_honest_preview_finalizes(self):
        issued = self.finalize(self.bundle())
        self.assertEqual(issued.commit_sha, self.sha)
        self.assertEqual(issued.tree_sha, self.tree)

    def test_finalize_refuses_a_fork_preview(self):
        with self.assertRaises(ghmod.GitHubError):
            self.finalize(self.bundle(fork=True))

    def test_finalize_refuses_a_sha_that_is_not_the_evaluated_head(self):
        with self.assertRaises(ghmod.GitHubError):
            self.finalize(self.bundle(), expected_sha=MERGE_SHA)

    def test_finalize_refuses_an_unknown_bundle_key(self):
        with self.assertRaises(ghmod.GitHubError):
            self.finalize(self.bundle(surprise=1))

    def test_finalize_refuses_a_non_admitted_preview(self):
        path = self.bundle()
        document = json.loads(path.read_text(encoding="utf-8"))
        document["state"] = "REFUSED"
        document["readiness"] = "AWAITING_REVIEW"
        document["decision"]["state"] = "REFUSED"
        document["decision"]["readiness"] = "AWAITING_REVIEW"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError):
            self.finalize(path)

    def test_finalize_refuses_a_tree_the_trusted_checkout_contradicts(self):
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(self.bundle(tree_sha="c3" * 20))
        self.assertIn("tree", str(caught.exception).lower())

    def test_finalize_refuses_a_repository_the_checkout_contradicts(self):
        with self.assertRaises(ghmod.GitHubError):
            self.finalize(self.bundle(repository="github.com/mallory/widget"))

    def test_finalize_executes_no_candidate_owned_command(self):
        import subprocess as subprocess_module
        path = self.bundle()
        # The trusted checkout's own identity is read before the patch below,
        # so the assertion is about candidate code and not about git.
        ghmod.assert_trusted_tool(self.trusted)
        calls = []

        original = subprocess_module.Popen

        def refuse(argv, *args, **kwargs):
            # Reading the trusted checkout's own identity with git is the
            # finalizer doing its job. Anything else would be candidate code.
            words = list(argv) if isinstance(argv, (list, tuple)) else [argv]
            if words[:1] != ["git"]:
                calls.append(tuple(words))
                raise AssertionError(
                    f"finalize must not execute candidate commands: {words}")
            return original(argv, *args, **kwargs)

        subprocess_module.Popen = refuse
        try:
            issued = self.finalize(path)
        finally:
            subprocess_module.Popen = original
        self.assertEqual(calls, [])
        self.assertEqual(issued.commit_sha, self.sha)
        self.assertTrue(receipt.verify_receipt(issued, self.signer))

    def test_finalize_is_idempotent_for_the_same_preview(self):
        path = self.bundle()
        first = self.finalize(path)
        again = self.finalize(path)
        self.assertEqual(first.receipt_hash, again.receipt_hash)
        self.assertEqual(len(self.store.receipts_for(
            "github.com/acme/widget", self.sha)), 1)


class WorkflowTemplateTest(unittest.TestCase):
    def workflow_text(self) -> str:
        path = ROOT / ".github" / "workflows" / "admissible-gate.yml"
        self.assertTrue(path.is_file(), f"missing {path}")
        return path.read_text(encoding="utf-8")

    def test_action_and_workflow_templates_exist(self):
        for relative in (".github/actions/admissible/action.yml",
                         ".github/workflows/admissible.yml",
                         ".github/workflows/admissible-gate.yml"):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_evaluate_job_checks_out_the_pull_request_head_sha(self):
        text = self.workflow_text()
        self.assertIn("github.event.pull_request.head.sha", text)

    def test_the_workflow_receives_no_secret_of_any_kind(self):
        text = self.workflow_text()
        self.assertNotIn("ADMISSIBLE_HMAC_KEY", text)
        self.assertNotIn("secrets:", text)
        self.assertNotIn("${{ secrets.", text)

    def test_there_is_no_signing_job_to_gate(self):
        """Signing lives outside GitHub Actions, so it is not a job here.

        A gated `finalize` job was the previous shape. Its gate ran on the
        evaluate job's own output, in the same run, with the admission key in
        it -- and it was skipped entirely on pull requests, which is where a
        review requirement matters most. There is nothing to gate now.
        """

        text = self.workflow_text()
        self.assertNotIn("\n  finalize:", text)
        self.assertNotIn("needs: evaluate", text)
        self.assertIn("attest-evaluation", text)
        self.assertIn("finalize", text)  # named in prose, as the next step

    def test_no_unpinned_third_party_actions(self):
        text = self.workflow_text() + (
            ROOT / ".github" / "actions" / "admissible" / "action.yml"
        ).read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("uses:"):
                reference = stripped.split("uses:", 1)[1].strip()
                if reference.startswith("./"):
                    continue
                self.assertRegex(reference, r"@[0-9a-f]{40}$", reference)

    def test_workflow_never_claims_a_shared_self_hosted_label_is_safe(self):
        text = self.workflow_text()
        lowered = text.lower()
        # A self-hosted evaluate runner is the caller's choice and carries no
        # secret here, so the old warning about sharing a signing runner no
        # longer applies to this file: there is no signing runner in it.
        self.assertNotIn("secrets:", lowered)
        for line in text.splitlines():
            if line.strip().startswith("runs-on:"):
                self.assertNotIn("self-hosted", line,
                                 "a self-hosted label must be caller input")

    def test_the_default_runner_is_never_silently_self_hosted(self):
        text = self.workflow_text()
        block = text.split("evaluate-runs-on:", 1)[1].split("\n\n", 1)[0]
        default = [line for line in block.splitlines()
                   if line.strip().startswith("default:")]
        self.assertTrue(default)
        self.assertNotIn("self-hosted", default[0])


if __name__ == "__main__":
    unittest.main()
