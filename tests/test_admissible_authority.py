"""Contract: evidence authority and exact identity at the signing boundary.

Nothing here trusts what a preview *asserts*. Finalization re-derives the
repository, the tree and the policy from a trusted checkout, compares every
command against the argv the policy actually configures, and refuses to count
a review that no reviewer key ever signed.
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
from admissible_support import (OBSERVER_KEY_ID,  # noqa: E402
                                OBSERVER_SECRET, TempCase, make_repo,
                                require_module, source_receipt_document)

attestation = require_module("admissible.attestation")
cli = require_module("admissible.cli")
config_module = require_module("admissible.config")
decision = require_module("admissible.decision")
evidence = require_module("admissible.evidence")
ghmod = require_module("admissible.github")
receipt = require_module("admissible.receipt")
review_module = require_module("admissible.review")
runner = require_module("admissible.runner")
standing = require_module("admissible.standing")
store_module = require_module("admissible.store")

SECRET = b"authority-test-secret"
REVIEW_SECRET = b"reviewer-test-secret"


def policy(argv, *, reviews=0, reviewer_key_ids=None, author_key_ids=None):
    document = {
        "version": 1,
        "profile": "python-library",
        "classes": [{
            "id": "default",
            "checks": [{"id": "unit", "argv": list(argv),
                        "timeout_seconds": 60, "cost_units": 1,
                        "required": True, "version": "1"}],
            "required_independent_reviews": reviews,
            "review_max_age_seconds": 86400,
            "max_cost_units": 10,
            "max_wall_seconds": 600,
        }],
    }
    if reviewer_key_ids is not None:
        document["classes"][0]["reviewer_key_ids"] = list(reviewer_key_ids)
    if author_key_ids is not None:
        document["classes"][0]["author_key_ids"] = list(author_key_ids)
    elif reviews:
        # A class that requires review must name the author keys too, or the
        # word "independent" in the requirement means nothing.
        document["classes"][0]["author_key_ids"] = ["author-key"]
    return document


class ArgvDigestTest(TempCase):
    """B8: a forged success for a command nobody configured must not count."""

    def setUp(self):
        super().setUp()
        self.parsed = config_module.parse_config(policy(["false"]))
        self.artifact_class = self.parsed.select_class("default")

    def record(self, argv_digest_value, **overrides):
        document = {
            "kind": "command", "check_id": "unit", "check_version": "1",
            "repository": "github.com/acme/widget", "commit_sha": "a1" * 20,
            "tree_sha": "b2" * 20,
            "policy_digest": self.artifact_class.policy_digest,
            "argv_digest": argv_digest_value, "exit_code": 0,
            "timed_out": False, "launch_failed": False, "duration_ms": 1,
            "stdout_sha256": "0" * 64, "stderr_sha256": "0" * 64,
            "stdout_bytes": 0, "stderr_bytes": 0, "output_truncated": False,
            "started_at": 1000, "finished_at": 1000, "attempt_id": "attempt-1",
        }
        document.update(overrides)
        return evidence.command_evidence_from_dict(document)

    def evaluate(self, record):
        return decision.evaluate(
            artifact_class=self.artifact_class,
            repository="github.com/acme/widget", commit_sha="a1" * 20,
            tree_sha="b2" * 20,
            policy_digest=self.artifact_class.policy_digest,
            commands=(record,), reviews=(), now=2000,
            attempt_id="attempt-1")

    def test_the_configured_argv_digest_is_admitted(self):
        digest = self.artifact_class.check("unit").argv_digest
        self.assertEqual(self.evaluate(self.record(digest)).state,
                         decision.CHECKS_PASSED)

    def test_a_forged_argv_digest_is_refused(self):
        result = self.evaluate(self.record("c" * 64))
        self.assertEqual(result.state, decision.REFUSED)
        self.assertIn("argv_mismatch",
                      {reason.code for reason in result.reasons})

    def test_evidence_for_another_check_version_is_not_reused(self):
        digest = self.artifact_class.check("unit").argv_digest
        result = self.evaluate(self.record(digest, check_version="2"))
        self.assertEqual(result.state, decision.REFUSED)


class TrustedFinalizeIdentityTest(TempCase):
    """B8: finalize binds the tree it can see, not the tree it is told."""

    def setUp(self):
        super().setUp()
        self.signer = receipt.signer_from_secret("k1", SECRET)
        self.store = store_module.open_store(self.home)
        self.addCleanup(self.store.close)
        self.root = self.tmp / "candidate"
        self.sha = make_repo(self.root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(policy(["python3", "-c", "pass"])),
        })
        self.preview = self.tmp / "preview.json"
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["run", "--preview", "--repo", str(self.root),
                         "--sha", self.sha, "--preview-out",
                         str(self.preview), "--json"], stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        artifact_class = config_module.load_config(
            self.root).select_class("default")
        self.store.trust_policy(
            repository="github.com/acme/widget", class_id="default",
            policy_digest=artifact_class.policy_digest,
            enforcement_digest=config_module.enforcement_digest(artifact_class),
            trusted_at=int(time.time()))

    def rewrite(self, **overrides):
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document.update(overrides)
        self.preview.write_text(json.dumps(document), encoding="utf-8")

    def attestation(self, preview=None):
        """The external observer's statement about that evaluation."""

        path = self.tmp / "evaluation.json"
        document = json.loads(
            (preview or self.preview).read_text(encoding="utf-8"))
        path.write_text(json.dumps(attestation.attest_preview(
            document, key_id=OBSERVER_KEY_ID, secret=OBSERVER_SECRET,
            isolation="pid-namespace",
            source_receipt=source_receipt_document(document["commit_sha"]),
            observed_at=max(int(time.time()), document["issued_at"]))),
            encoding="utf-8")
        return path

    def finalize(self):
        return ghmod.finalize(self.store, self.preview, signer=self.signer,
                              expected_sha=self.sha, now=int(time.time()),
                              policy_root=self.root,
                              evaluation_attestation=self.attestation(),
                              evaluation_keyring={
                                  OBSERVER_KEY_ID: OBSERVER_SECRET})

    def test_an_honest_preview_finalizes(self):
        issued = self.finalize()
        self.assertEqual(issued.commit_sha, self.sha)

    def test_a_forged_tree_sha_is_refused(self):
        self.rewrite(tree_sha="c3" * 20)
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize()
        self.assertIn("tree", str(caught.exception).lower())

    def test_a_forged_repository_is_refused(self):
        self.rewrite(repository="github.com/mallory/widget")
        with self.assertRaises(ghmod.GitHubError):
            self.finalize()

    def test_finalize_requires_a_trusted_checkout(self):
        with self.assertRaises(ghmod.GitHubError):
            ghmod.finalize(self.store, self.preview, signer=self.signer,
                           expected_sha=self.sha, now=int(time.time()),
                           policy_root=None)

    def test_a_dirty_trusted_checkout_is_refused(self):
        (self.root / "scratch.txt").write_text("dirt", encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError):
            self.finalize()

    def test_a_consistently_forged_tree_is_still_refused(self):
        """The interesting forgery is the one with no loose ends.

        Rewriting only ``tree_sha`` leaves the evidence bound to the real tree,
        and the binding check catches it for the wrong reason. Rewriting the
        tree *everywhere* produces a preview that is internally perfect and
        describes a tree that does not exist. Only re-deriving the tree from
        the trusted checkout can refuse that one.
        """

        forged = "c3" * 20
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document["tree_sha"] = forged
        document["decision"]["tree_sha"] = forged
        for key in ("commands", "reviews"):
            for record in document["evidence"][key]:
                record["tree_sha"] = forged
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize()
        self.assertIn("trusted checkout", str(caught.exception))

    def test_a_forged_required_command_success_is_refused(self):
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        for record in document["evidence"]["commands"]:
            record["argv_digest"] = "d" * 64
            record["exit_code"] = 0
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError):
            self.finalize()


class PostCheckIdentityTest(TempCase):
    """B9: a check that repairs the tree may not be signed against it."""

    def repo(self, script: str) -> tuple[Path, str]:
        root = self.tmp / "candidate"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            "broken.py": "def go(:\n",
            "repair.py": script,
            ".admissible.json": json.dumps(
                policy(["python3", "repair.py"])),
        })
        return root, sha

    def run_gate(self, root, sha):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["run", "--preview", "--repo", str(root), "--sha", sha,
                         "--preview", "--json"], stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_a_check_that_repairs_tracked_content_blocks(self):
        root, sha = self.repo(
            "import pathlib\n"
            "pathlib.Path('broken.py').write_text('def go():\\n    pass\\n')\n")
        code, out, err = self.run_gate(root, sha)
        self.assertEqual(code, 2, out + err)
        self.assertIn("mutat", (out + err).lower())

    def test_a_check_that_stages_content_blocks(self):
        root, sha = self.repo(
            "import subprocess\n"
            "pathlib = __import__('pathlib')\n"
            "pathlib.Path('README.md').write_text('changed\\n')\n"
            "subprocess.run(['git', 'add', 'README.md'], check=True)\n")
        code, out, err = self.run_gate(root, sha)
        self.assertEqual(code, 2, out + err)

    def test_a_check_that_leaves_untracked_content_blocks(self):
        root, sha = self.repo(
            "import pathlib\n"
            "pathlib.Path('artefact.txt').write_text('left behind\\n')\n")
        code, out, err = self.run_gate(root, sha)
        self.assertEqual(code, 2, out + err)

    def test_a_check_that_tidies_up_after_itself_still_blocks(self):
        """The mutation window is between the checks, not only at the end.

        A check that dirties the tree and a later check that cleans it up leave
        a clean worktree by the time anything is signed -- and every observation
        the first check made was made against a tree nobody can reconstruct.
        Only the comparison taken immediately after each check can see it.
        """

        root = self.tmp / "candidate"
        sha = make_repo(root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps({
                "version": 1, "profile": "python-library",
                "classes": [{
                    "id": "default",
                    "checks": [
                        {"id": "dirty", "argv": ["python3", "dirty.py"],
                         "timeout_seconds": 60, "cost_units": 1,
                         "required": True, "version": "1"},
                        {"id": "tidy", "argv": ["python3", "tidy.py"],
                         "timeout_seconds": 60, "cost_units": 2,
                         "required": True, "version": "1"}],
                    "required_independent_reviews": 0,
                    "review_max_age_seconds": 86400,
                    "max_cost_units": 10, "max_wall_seconds": 600}]}),
            "dirty.py": "import pathlib\n"
                        "pathlib.Path('scratch.txt').write_text('here\\n')\n",
            "tidy.py": "import pathlib\n"
                       "pathlib.Path('scratch.txt').unlink(missing_ok=True)\n",
        })
        code, out, err = self.run_gate(root, sha)
        self.assertEqual(code, 2, out + err)
        self.assertIn("mutat", (out + err).lower())
        self.assertIn("dirty", (out + err))

    def test_a_check_that_commits_its_own_repair_blocks(self):
        """Moving HEAD is the mutation that makes the worktree look clean."""

        root, sha = self.repo(
            "import pathlib, subprocess\n"
            "pathlib.Path('broken.py').write_text('def go():\\n    pass\\n')\n"
            "subprocess.run(['git', 'add', '-A'], check=True)\n"
            "subprocess.run(['git', 'commit', '-q', '-m', 'repair'],\n"
            "               check=True)\n")
        code, out, err = self.run_gate(root, sha)
        self.assertEqual(code, 2, out + err)
        self.assertIn("HEAD moved", out + err)

    def test_a_well_behaved_check_still_admits(self):
        root, sha = self.repo("pass\n")
        code, out, err = self.run_gate(root, sha)
        self.assertEqual(code, 0, out + err)


class ChildEnvironmentTest(TempCase):
    """B10: a candidate command cannot reach GitHub's control channels."""

    def test_control_channels_and_secrets_are_removed(self):
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        os.environ.update({
            "GITHUB_OUTPUT": "/tmp/out", "GITHUB_ENV": "/tmp/env",
            "GITHUB_PATH": "/tmp/path", "GITHUB_STEP_SUMMARY": "/tmp/summary",
            "GITHUB_TOKEN": "ghs_secret", "ACTIONS_RUNTIME_TOKEN": "rt",
            "ADMISSIBLE_HMAC_KEY": "signing", "ADMISSIBLE_REVIEW_KEY": "review",
            "MY_API_TOKEN": "hunter2", "AWS_SECRET_ACCESS_KEY": "s3cr3t",
            "PATH": os.environ.get("PATH", ""),
        })
        child = runner.child_environment()
        for name in ("GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH",
                     "GITHUB_STEP_SUMMARY", "GITHUB_TOKEN",
                     "ACTIONS_RUNTIME_TOKEN", "ADMISSIBLE_HMAC_KEY",
                     "ADMISSIBLE_REVIEW_KEY", "MY_API_TOKEN",
                     "AWS_SECRET_ACCESS_KEY"):
            self.assertNotIn(name, child, name)
        self.assertIn("PATH", child)
        self.assertEqual(child.get("ADMISSIBLE_IN_CHECK"), "1")

    def test_a_check_cannot_write_the_evaluator_job_output(self):
        root = self.tmp / "candidate"
        target = self.tmp / "github-output"
        target.write_text("", encoding="utf-8")
        sha = make_repo(root, files={
            "README.md": "widget\n",
            "sneak.py": (
                "import os\n"
                "path = os.environ.get('GITHUB_OUTPUT')\n"
                "if path:\n"
                "    open(path, 'a').write('state=ADMITTED\\n')\n"),
            ".admissible.json": json.dumps(policy(["python3", "sneak.py"])),
        })
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        os.environ["GITHUB_OUTPUT"] = str(target)
        out, err = io.StringIO(), io.StringIO()
        cli.main(["run", "--preview", "--repo", str(root), "--sha", sha,
                  "--json"], stdout=out, stderr=err)
        self.assertEqual(target.read_text(encoding="utf-8"), "")


class SignedReviewTest(TempCase):
    """B11/B12: only an authenticated reviewer key can satisfy a review."""

    def setUp(self):
        super().setUp()
        self.keyring = {"reviewer-a": REVIEW_SECRET,
                        "reviewer-b": b"second-reviewer-secret"}

    def review(self, review_id="r1", reviewer="alice", issued_at=1000,
               verdict="approve"):
        return {
            "kind": "review", "review_id": review_id, "reviewer_id": reviewer,
            "reviewer_version": "1", "author_id": "bob", "verdict": verdict,
            "repository": "github.com/acme/widget", "commit_sha": "a1" * 20,
            "tree_sha": "b2" * 20, "policy_digest": "f" * 64,
            "findings_digest": "0" * 64, "issued_at": issued_at,
            "attempt_id": "attempt-1",
        }

    def test_an_attestation_round_trips_and_verifies(self):
        document = review_module.attest(
            self.review(), key_id="reviewer-a", secret=REVIEW_SECRET)
        self.assertEqual(document["algorithm"], "hmac-sha256")
        self.assertEqual(document["key_id"], "reviewer-a")
        parsed = review_module.verify_attestation(document, self.keyring)
        self.assertEqual(parsed.reviewer_id, "alice")

    def test_a_tampered_attestation_is_refused(self):
        document = review_module.attest(
            self.review(), key_id="reviewer-a", secret=REVIEW_SECRET)
        document["review"]["verdict"] = "approve"
        document["review"]["reviewer_id"] = "mallory"
        with self.assertRaises(review_module.ReviewError):
            review_module.verify_attestation(document, self.keyring)

    def test_an_unknown_key_id_is_refused(self):
        document = review_module.attest(
            self.review(), key_id="reviewer-z", secret=b"anything")
        with self.assertRaises(review_module.ReviewError):
            review_module.verify_attestation(document, self.keyring)

    def test_unsigned_review_never_satisfies_a_required_review(self):
        parsed = config_module.parse_config(
            policy(["python3", "-c", "pass"], reviews=1,
                   reviewer_key_ids=["reviewer-a"]))
        artifact_class = parsed.select_class("default")
        record = evidence.review_evidence_from_dict(
            dict(self.review(), policy_digest=artifact_class.policy_digest))
        result = decision.evaluate(
            artifact_class=artifact_class, repository="github.com/acme/widget",
            commit_sha="a1" * 20, tree_sha="b2" * 20,
            policy_digest=artifact_class.policy_digest, commands=(),
            reviews=(record,), now=2000, attempt_id="attempt-1")
        self.assertEqual(result.independent_reviews, 0)
        self.assertIn("missing_independent_review",
                      {reason.code for reason in result.reasons})

    def test_two_signatures_from_one_key_count_once(self):
        parsed = config_module.parse_config(
            policy(["python3", "-c", "pass"], reviews=2,
                   reviewer_key_ids=["reviewer-a", "reviewer-b"]))
        artifact_class = parsed.select_class("default")
        first = evidence.review_evidence_from_dict(dict(
            self.review(review_id="r1", reviewer="alice"),
            policy_digest=artifact_class.policy_digest))
        second = evidence.review_evidence_from_dict(dict(
            self.review(review_id="r2", reviewer="carol"),
            policy_digest=artifact_class.policy_digest))
        verified = (
            evidence.VerifiedReview(record=first, key_id="reviewer-a"),
            evidence.VerifiedReview(record=second, key_id="reviewer-a"),
        )
        result = decision.evaluate(
            artifact_class=artifact_class, repository="github.com/acme/widget",
            commit_sha="a1" * 20, tree_sha="b2" * 20,
            policy_digest=artifact_class.policy_digest, commands=(),
            reviews=verified, now=2000, attempt_id="attempt-1")
        self.assertEqual(result.independent_reviews, 1)

    def test_a_policy_naming_one_key_as_both_is_refused_at_parse(self):
        """The first line of defence is that this policy cannot exist."""

        with self.assertRaises(config_module.ConfigError) as caught:
            config_module.parse_config(
                policy(["python3", "-c", "pass"], reviews=1,
                       reviewer_key_ids=["reviewer-a"],
                       author_key_ids=["reviewer-a"]))
        self.assertIn("disjoint", str(caught.exception))

    def test_the_author_key_can_never_count_as_an_independent_reviewer(self):
        """The second line of defence, for a class assembled some other way.

        Parsing refuses the overlapping policy above, so this class is built
        directly. The decision must still refuse to count the author's key: a
        rule that only exists at the ingress boundary is a rule that stops
        applying the moment anything else builds a class.
        """

        parsed = config_module.parse_config(
            policy(["python3", "-c", "pass"], reviews=1,
                   reviewer_key_ids=["reviewer-a"],
                   author_key_ids=["author-key"]))
        base = parsed.select_class("default")
        artifact_class = config_module.ArtifactClass(
            **{**{field: getattr(base, field) for field in
                  base.__dataclass_fields__},
               "author_key_ids": ("reviewer-a",)})
        record = evidence.review_evidence_from_dict(dict(
            self.review(), policy_digest=artifact_class.policy_digest))
        result = decision.evaluate(
            artifact_class=artifact_class, repository="github.com/acme/widget",
            commit_sha="a1" * 20, tree_sha="b2" * 20,
            policy_digest=artifact_class.policy_digest, commands=(),
            reviews=(evidence.VerifiedReview(record=record,
                                             key_id="reviewer-a"),),
            now=2000, attempt_id="attempt-1")
        self.assertEqual(result.independent_reviews, 0)

    def test_a_key_id_outside_the_pinned_set_is_refused(self):
        parsed = config_module.parse_config(
            policy(["python3", "-c", "pass"], reviews=1,
                   reviewer_key_ids=["reviewer-a"]))
        artifact_class = parsed.select_class("default")
        record = evidence.review_evidence_from_dict(dict(
            self.review(), policy_digest=artifact_class.policy_digest))
        result = decision.evaluate(
            artifact_class=artifact_class, repository="github.com/acme/widget",
            commit_sha="a1" * 20, tree_sha="b2" * 20,
            policy_digest=artifact_class.policy_digest, commands=(),
            reviews=(evidence.VerifiedReview(record=record,
                                             key_id="reviewer-unpinned"),),
            now=2000, attempt_id="attempt-1")
        self.assertEqual(result.independent_reviews, 0)
        self.assertIn("unpinned_reviewer_key",
                      {reason.code for reason in result.reasons})

    def test_a_future_dated_review_is_refused(self):
        parsed = config_module.parse_config(
            policy(["python3", "-c", "pass"], reviews=1,
                   reviewer_key_ids=["reviewer-a"]))
        artifact_class = parsed.select_class("default")
        record = evidence.review_evidence_from_dict(dict(
            self.review(issued_at=4102444800),
            policy_digest=artifact_class.policy_digest))
        result = decision.evaluate(
            artifact_class=artifact_class, repository="github.com/acme/widget",
            commit_sha="a1" * 20, tree_sha="b2" * 20,
            policy_digest=artifact_class.policy_digest, commands=(),
            reviews=(evidence.VerifiedReview(record=record,
                                             key_id="reviewer-a"),),
            now=2000, attempt_id="attempt-1")
        self.assertIn("future_dated_review",
                      {reason.code for reason in result.reasons})
        self.assertEqual(result.independent_reviews, 0)

    def test_the_clock_skew_allowance_is_small_and_documented(self):
        self.assertLessEqual(decision.MAX_CLOCK_SKEW_SECONDS, 900)
        text = (Path(__file__).resolve().parent.parent
                / "docs" / "DEVELOPER_WORKFLOW.md").read_text(encoding="utf-8")
        self.assertIn(str(decision.MAX_CLOCK_SKEW_SECONDS), text)

    def test_attest_review_command_signs_a_closed_review(self):
        source = self.write_json(self.tmp / "review.json", self.review())
        out_path = self.tmp / "attested.json"
        os.environ["ADMISSIBLE_REVIEW_KEY"] = REVIEW_SECRET.decode()
        os.environ["ADMISSIBLE_REVIEW_KEY_ID"] = "reviewer-a"
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["attest-review", "--review", str(source),
                         "--out", str(out_path), "--json"],
                        stdout=out, stderr=err)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        document = json.loads(out_path.read_text(encoding="utf-8"))
        parsed = review_module.verify_attestation(document, self.keyring)
        self.assertEqual(parsed.review_id, "r1")

    def test_admissible_makes_no_model_call(self):
        root = Path(__file__).resolve().parent.parent / "admissible"
        for path in sorted(root.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for token in ("anthropic", "openai", "api.", "urllib.request",
                          "http.client", "socket"):
                self.assertNotIn(token, text, f"{path.name}: {token}")


class ReceiptIdentityTest(TempCase):
    """B13: a receipt may only be issued for an ADMITTED, matching decision."""

    def setUp(self):
        super().setUp()
        self.signer = receipt.signer_from_secret("k1", SECRET)
        self.store = store_module.open_store(self.home)
        self.addCleanup(self.store.close)
        self.parsed = config_module.parse_config(policy(["python3", "-c", "pass"]))
        self.artifact_class = self.parsed.select_class("default")

    def decide(self, state):
        result = decision.evaluate(
            artifact_class=self.artifact_class,
            repository="github.com/acme/widget", commit_sha="a1" * 20,
            tree_sha="b2" * 20,
            policy_digest=self.artifact_class.policy_digest,
            commands=(), reviews=(), now=1000, attempt_id="attempt-1")
        self.assertEqual(result.state, state)
        return result

    def test_a_refused_decision_can_never_be_issued(self):
        refused = self.decide(decision.REFUSED)
        with self.assertRaises(receipt.ReceiptError) as caught:
            receipt.issue_receipt(
                self.store, repository="github.com/acme/widget",
                commit_sha="a1" * 20, tree_sha="b2" * 20, class_id="default",
                policy_digest=self.artifact_class.policy_digest,
                result=refused, signer=self.signer, now=1000)
        # The refusal must name the decision it was handed, not merely the
        # state string it would have written: this is the check that reads a
        # Decision, and it is the one that has to fire.
        self.assertIn("Nothing was anchored", str(caught.exception))
        self.assertIn(decision.REFUSED, str(caught.exception))

    def test_receipt_arguments_must_match_the_decision(self):
        # The decision has to *pass* its state check first, or this asserts
        # nothing about the artefact comparison: a state the earlier guard
        # already refuses never reaches the field-by-field comparison, and a
        # test that stops there would go on passing with that comparison gone.
        passed = self.decide(decision.REFUSED)
        object.__setattr__(passed, "state", decision.CHECKS_PASSED)
        for field, arguments in (
                ("commit_sha", {"commit_sha": "c3" * 20}),
                ("tree_sha", {"tree_sha": "c3" * 20}),
                ("repository", {"repository": "github.com/acme/other"}),
                ("class_id", {"class_id": "other"}),
                ("policy_digest", {"policy_digest": "f" * 64})):
            with self.subTest(field=field):
                parts = {
                    "repository": "github.com/acme/widget",
                    "commit_sha": "a1" * 20, "tree_sha": "b2" * 20,
                    "class_id": "default",
                    "policy_digest": self.artifact_class.policy_digest,
                }
                parts.update(arguments)
                with self.assertRaises(receipt.ReceiptError) as caught:
                    receipt.issue_receipt(
                        self.store, result=passed, signer=self.signer,
                        now=1000, **parts)
                message = str(caught.exception)
                self.assertIn("different artefact", message)
                self.assertIn(field, message)
                self.assertEqual(
                    self.store.receipt_count("github.com/acme/widget"), 0)

    def test_the_receipt_schema_admits_only_admitted(self):
        path = (Path(__file__).resolve().parent.parent
                / "protocol" / "workflow-receipt.schema.json")
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["properties"]["state"]["enum"], ["ADMITTED"])

    def test_a_non_admitted_receipt_cannot_make_standing_current(self):
        self.assertEqual(
            standing.current_standing(
                self.store, "github.com/acme/widget", "a1" * 20).state,
            standing.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
