"""Contract tests for the final exact-head review findings.

Each class here names one boundary a final review found open at
``c932b1d``. They are written to fail against that revision and to keep
failing if the repair is undone.
"""
from __future__ import annotations

import io
import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import (  # noqa: E402
    OBSERVER_KEY_ID, OBSERVER_SECRET, TempCase, git, make_repo,
    source_receipt_document)

from admissible import attestation as attestation_module  # noqa: E402
from admissible import cli as cli_module
from admissible import config as config_module
from admissible import evidence as evidence_module
from admissible import github as github_module
from admissible import receipt as receipt_module
from admissible import review as review_module
from admissible import runner as runner_module
from admissible import store as store_module

SECRET = b"finalizer-secret-not-real"
KEY_A = b"reviewer-a-secret-not-real"
KEY_B = b"reviewer-b-secret-not-real"
AUTHOR_KEY = b"author-secret-not-real"


def payment_policy():
    """A two-review class whose checks are cheap and always pass."""

    from admissible import profiles as profiles_module

    document = profiles_module.profile_document("payment-change")
    artifact_class = document["classes"][0]
    for check in artifact_class["checks"]:
        check["argv"] = [sys.executable, "-c", "pass"]
    artifact_class["reviewer_key_ids"] = ["reviewer-a", "reviewer-b"]
    artifact_class["author_key_ids"] = ["author-key"]
    return document


class ClosureCase(TempCase):
    """One payment-class artefact, evaluated and finalised the honest way."""

    def setUp(self):
        super().setUp()
        self.signer = receipt_module.signer_from_secret("finalizer-1", SECRET)
        self.keyring = {"reviewer-a": KEY_A, "reviewer-b": KEY_B,
                        "author-key": AUTHOR_KEY}
        self.now = int(time.time())
        self.document = payment_policy()
        self.root = self.tmp / "candidate"
        self.sha = make_repo(self.root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(self.document, indent=2) + "\n",
        })
        self.tree = git(self.root, "rev-parse", "HEAD^{tree}")
        self.klass = config_module.parse_config(self.document).select_class(
            "default")

    # -- evidence builders ------------------------------------------------
    def review(self, review_id, *, reviewer="alice", verdict="approve",
               issued_at=None):
        return {
            "kind": "review", "review_id": review_id, "reviewer_id": reviewer,
            "reviewer_version": "1", "author_id": "mallory",
            "verdict": verdict, "repository": "github.com/acme/widget",
            "commit_sha": self.sha, "tree_sha": self.tree,
            "policy_digest": self.klass.policy_digest,
            "findings_digest": "0" * 64,
            "issued_at": self.now if issued_at is None else issued_at,
            "attempt_id": "",
        }

    def authorship_document(self, *, key_id="author-key", secret=AUTHOR_KEY,
                            issued_at=None):
        return review_module.attest_authorship({
            "kind": "authorship", "author_id": "mallory",
            "repository": "github.com/acme/widget", "commit_sha": self.sha,
            "tree_sha": self.tree, "policy_digest": self.klass.policy_digest,
            "issued_at": self.now if issued_at is None else issued_at},
            key_id=key_id, secret=secret)

    def two_attestations(self):
        return [
            review_module.attest(self.review("r1", reviewer="alice"),
                                 key_id="reviewer-a", secret=KEY_A),
            review_module.attest(self.review("r2", reviewer="carol"),
                                 key_id="reviewer-b", secret=KEY_B),
        ]

    def bundle_file(self, name="reviews.json", *, attestations=(), reviews=(),
                    author_attestations=()):
        path = self.tmp / name
        path.write_text(json.dumps({
            "schema": evidence_module.EVIDENCE_SCHEMA, "commands": [],
            "reviews": list(reviews), "defects": [],
            "attestations": list(attestations),
            "author_attestations": list(author_attestations)}),
            encoding="utf-8")
        return path

    # -- the three trust domains -----------------------------------------
    def evaluate(self, *, evidence_path=None, isolation="pid-namespace"):
        if isolation is None:
            os.environ.pop("ADMISSIBLE_ISOLATION", None)
        else:
            os.environ["ADMISSIBLE_ISOLATION"] = isolation
        self.preview = self.tmp / "preview.json"
        argv = ["run", "--repo", str(self.root), "--sha", self.sha,
                "--preview", "--preview-out", str(self.preview), "--json"]
        if evidence_path is not None:
            argv += ["--evidence", str(evidence_path)]
        out, err = io.StringIO(), io.StringIO()
        code = cli_module.main(argv, stdout=out, stderr=err)
        text = out.getvalue()
        return code, (json.loads(text) if text.strip() else {}), err.getvalue()

    def attest(self, preview=None, **overrides):
        source = preview or self.preview
        parsed = json.loads(source.read_text(encoding="utf-8"))
        overrides.setdefault("isolation", "pid-namespace")
        document = attestation_module.attest_preview(
            parsed, key_id=OBSERVER_KEY_ID, secret=OBSERVER_SECRET,
            source_receipt=source_receipt_document(parsed["commit_sha"]),
            observed_at=max(self.now, parsed["issued_at"]), **overrides)
        path = self.tmp / "evaluation.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def finalize(self, *, preview=None, evaluation=None, reviews=None,
                 keyring=None, trust=True, now=None):
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        if trust:
            opened.trust_policy(
                repository="github.com/acme/widget", class_id=self.klass.id,
                policy_digest=self.klass.policy_digest,
                enforcement_digest=config_module.enforcement_digest(
                    self.klass), trusted_at=self.now)
        return github_module.finalize(
            opened, preview or self.preview, signer=self.signer,
            expected_sha=self.sha,
            now=self.now if now is None else now, policy_root=self.root,
            evaluation_attestation=(evaluation if evaluation is not None
                                    else self.attest(preview)),
            evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
            reviews=reviews,
            keyring=self.keyring if keyring is None else keyring,
            environment={})


class AttestationClosureTest(ClosureCase):
    """W2/F1: observer evidence and human authorities stay separate."""

    def test_the_observer_does_not_re_sign_review_or_authorship_authority(self):
        self.assertNotIn("attestation_digests",
                         attestation_module.EVALUATION_BODY_KEYS)
        self.assertNotIn("author_attestation_digests",
                         attestation_module.EVALUATION_BODY_KEYS)

    def test_out_of_band_authorities_added_after_observation_are_bound(self):
        # The observer signs the evaluator's review-pending result. Human
        # signatures arrive through the finalizer's separate authenticated
        # channel and do not need the observer to re-sign them.
        self.evaluate()
        signed = self.attest()
        authorship = self.authorship_document()
        authorities = self.bundle_file(
            name="out-of-band-authorities.json",
            attestations=self.two_attestations(),
            author_attestations=[authorship])
        issued = self.finalize(evaluation=signed, reviews=authorities)
        author_digest = evidence_module.evidence_digest(
            evidence_module.authorship_evidence_from_dict(
                authorship["authorship"]))
        self.assertIn(author_digest, issued.evidence_digests)

    def test_later_out_of_band_authorities_do_not_need_observer_resigning(self):
        """Human authority may arrive after the observer closed the run."""

        self.evaluate()
        signed = self.attest()
        observed_at = json.loads(signed.read_text(
            encoding="utf-8"))["evaluation"]["observed_at"]
        authority_time = observed_at + 301
        attestations = [
            review_module.attest(
                self.review("late-r1", reviewer="alice",
                            issued_at=authority_time),
                key_id="reviewer-a", secret=KEY_A),
            review_module.attest(
                self.review("late-r2", reviewer="carol",
                            issued_at=authority_time),
                key_id="reviewer-b", secret=KEY_B),
        ]
        authorities = self.bundle_file(
            name="later-out-of-band-authorities.json",
            attestations=attestations,
            author_attestations=[self.authorship_document(
                issued_at=authority_time)])

        issued = self.finalize(
            evaluation=signed, reviews=authorities, now=authority_time)

        self.assertEqual(issued.state, "ADMITTED")
        self.assertEqual(issued.issued_at, authority_time)

    def test_out_of_band_authority_ahead_of_finalizer_clock_refuses(self):
        self.evaluate()
        signed = self.attest()
        observed_at = json.loads(signed.read_text(
            encoding="utf-8"))["evaluation"]["observed_at"]
        future = observed_at + 301
        attestations = [
            review_module.attest(
                self.review("future-r1", reviewer="alice",
                            issued_at=future),
                key_id="reviewer-a", secret=KEY_A),
            review_module.attest(
                self.review("future-r2", reviewer="carol",
                            issued_at=future),
                key_id="reviewer-b", secret=KEY_B),
        ]
        authorities = self.bundle_file(
            name="future-out-of-band-authorities.json",
            attestations=attestations,
            author_attestations=[self.authorship_document(issued_at=future)])

        with self.assertRaises(github_module.GitHubError) as caught:
            self.finalize(
                evaluation=signed, reviews=authorities, now=observed_at)

        self.assertIn("future", str(caught.exception).lower())

    def test_an_authorship_dropped_after_observation_is_refused(self):
        path = self.bundle_file(attestations=self.two_attestations(),
                                author_attestations=[
                                    self.authorship_document()])
        self.evaluate(evidence_path=path)
        signed = self.attest()
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document["evidence"]["author_attestations"] = []
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(github_module.GitHubError) as caught:
            self.finalize(evaluation=signed)
        self.assertIn("authorship", str(caught.exception).lower())

    def test_the_observed_authorship_still_admits(self):
        path = self.bundle_file(attestations=self.two_attestations(),
                                author_attestations=[
                                    self.authorship_document()])
        self.evaluate(evidence_path=path)
        issued = self.finalize()
        self.assertEqual(issued.state, "ADMITTED")


class IsolationRequirementTest(ClosureCase):
    """W1: only the observer's independently validated boundary decides."""

    def test_an_undeclared_evaluation_records_isolation_none(self):
        self.evaluate(isolation=None)
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        self.assertEqual(document["isolation"], runner_module.ISOLATION_NONE)

    def test_observer_boundary_can_finalize_a_candidate_none_preview(self):
        path = self.bundle_file(attestations=self.two_attestations(),
                                author_attestations=[
                                    self.authorship_document()])
        self.evaluate(evidence_path=path, isolation=None)
        issued = self.finalize()
        self.assertEqual(issued.state, "ADMITTED")

    def test_observer_none_is_never_finalizable(self):
        path = self.bundle_file(attestations=self.two_attestations(),
                                author_attestations=[
                                    self.authorship_document()])
        self.evaluate(evidence_path=path)
        with self.assertRaises(github_module.GitHubError) as caught:
            self.finalize(evaluation=self.attest(isolation="none"))
        self.assertIn("isolation", str(caught.exception).lower())

    def test_isolation_is_inside_the_observer_signature(self):
        path = self.bundle_file(attestations=self.two_attestations(),
                                author_attestations=[
                                    self.authorship_document()])
        self.evaluate(evidence_path=path, isolation=None)
        signed = self.attest(isolation="pid-namespace")
        document = json.loads(signed.read_text(encoding="utf-8"))
        document["evaluation"]["isolation"] = "single-use-vm"
        signed.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(github_module.GitHubError) as caught:
            self.finalize(evaluation=signed)
        self.assertIn("authentic", str(caught.exception).lower())

    def test_an_unknown_isolation_mode_is_refused_at_evaluation(self):
        code, document, _ = self.evaluate(isolation="whatever-i-like")
        self.assertEqual(code, 2)
        self.assertIn("ADMISSIBLE_ISOLATION", document["message"])


class SignedReviewTransportTest(ClosureCase):
    """W5/U1: a review-required class must be completable, out of band.

    A review binds the commit and tree it approves, so it cannot be committed
    into the tree it approves -- the hash would have to contain itself. The
    hosted evaluate job therefore cannot carry one, and before this repair
    ``finalize`` had no input for one either: the documented path for a
    payment change ended nowhere.
    """

    def signed_bundle(self, name="out-of-band.json", *, attestations=None,
                      author_attestations=None, **extra):
        document = {
            "schema": evidence_module.EVIDENCE_SCHEMA,
            "commands": [], "reviews": [], "defects": [],
            "attestations": list(self.two_attestations()
                                 if attestations is None else attestations),
            "author_attestations": list(
                [self.authorship_document()]
                if author_attestations is None else author_attestations),
        }
        document.update(extra)
        path = self.tmp / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_reviews_that_never_touched_the_preview_still_admit(self):
        # The evaluate job carries no review at all: exactly the hosted case.
        code, document, _ = self.evaluate()
        self.assertEqual(document["readiness"], "AWAITING_REVIEW")
        self.assertEqual(document["reviews"]["independent_approving"], 0)
        issued = self.finalize(reviews=self.signed_bundle())
        self.assertEqual(issued.state, "ADMITTED")
        self.assertEqual(
            sorted(key_id for _d, key_id in issued.authenticated_reviews),
            ["reviewer-a", "reviewer-b"])

    def test_an_out_of_band_bundle_may_not_smuggle_command_evidence(self):
        self.evaluate()
        forged = {
            "kind": "command", "check_id": "unit", "check_version": "1",
            "repository": "github.com/acme/widget", "commit_sha": self.sha,
            "tree_sha": self.tree,
            "policy_digest": self.klass.policy_digest,
            "argv_digest": "0" * 64, "exit_code": 0, "timed_out": False,
            "launch_failed": False, "duration_ms": 1,
            "stdout_sha256": "0" * 64, "stderr_sha256": "0" * 64,
            "stdout_bytes": 0, "stderr_bytes": 0, "output_truncated": False,
            "started_at": self.now, "finished_at": self.now,
            "attempt_id": "a", "reused_from_attempt": "",
        }
        path = self.signed_bundle(commands=[forged])
        with self.assertRaises(github_module.GitHubError) as caught:
            self.finalize(reviews=path)
        self.assertIn("command", str(caught.exception))

    def test_an_out_of_band_review_for_another_commit_is_refused(self):
        self.evaluate()
        other = self.review("r1")
        other["commit_sha"] = "b" * 40
        path = self.signed_bundle(attestations=[
            review_module.attest(other, key_id="reviewer-a", secret=KEY_A)])
        with self.assertRaises(github_module.GitHubError) as caught:
            self.finalize(reviews=path)
        self.assertIn("exact", str(caught.exception))

    def test_an_out_of_band_review_signed_by_an_unpinned_key_is_refused(self):
        self.evaluate()
        path = self.signed_bundle(attestations=[
            review_module.attest(self.review("r1"), key_id="stranger",
                                 secret=b"stranger-secret")])
        with self.assertRaises(github_module.GitHubError) as caught:
            self.finalize(reviews=path)
        self.assertIn("stranger", str(caught.exception))

    def test_the_cli_exposes_the_transport(self):
        parser = cli_module._build_parser()
        options = parser.parse_args(
            ["finalize", "--preview", "p.json", "--sha", "a" * 40,
             "--policy-root", ".", "--evaluation-attestation", "e.json",
             "--reviews", "r.json"])
        self.assertEqual(options.reviews, "r.json")


class DistinctCredentialTest(ClosureCase):
    """W3: two reviewer ids must be two secrets, not one worn twice."""

    def keyring_file(self, **entries):
        path = self.tmp / "keyring.json"
        path.write_text(json.dumps(entries), encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def test_an_aliased_reviewer_keyring_is_refused_at_load(self):
        path = self.keyring_file(**{"reviewer-a": "one-secret",
                                    "reviewer-b": "one-secret"})
        with self.assertRaises(review_module.ReviewError) as caught:
            review_module.load_keyring({"ADMISSIBLE_REVIEW_KEYRING": str(path)})
        self.assertIn("same secret", str(caught.exception))

    def test_an_aliased_observer_keyring_is_refused_at_load(self):
        path = self.keyring_file(**{"observer-1": "one-secret",
                                    "observer-2": "one-secret"})
        with self.assertRaises(attestation_module.EvaluationError) as caught:
            attestation_module.load_evaluation_keyring(
                {"ADMISSIBLE_EVALUATION_KEYRING": str(path)})
        self.assertIn("same secret", str(caught.exception))

    def test_a_reviewer_and_observer_may_not_share_one_secret(self):
        self.evaluate()
        aliased = dict(self.keyring, **{"reviewer-a": OBSERVER_SECRET})
        with self.assertRaises(github_module.GitHubError) as caught:
            self.finalize(keyring=aliased)
        message = str(caught.exception).lower()
        self.assertIn("reviewer", message)
        self.assertIn("observer", message)
        self.assertIn("same secret", message)

    def test_one_credential_cannot_satisfy_the_two_review_rule(self):
        # Two ids, one secret: two "distinct" reviewer keys sign, and both
        # reviews are really one holder.
        aliased = dict(self.keyring, **{"reviewer-b": KEY_A})
        attestations = [
            review_module.attest(self.review("r1", reviewer="alice"),
                                 key_id="reviewer-a", secret=KEY_A),
            review_module.attest(self.review("r2", reviewer="carol"),
                                 key_id="reviewer-b", secret=KEY_A),
        ]
        self.evaluate()
        path = self.tmp / "aliased.json"
        path.write_text(json.dumps({
            "schema": evidence_module.EVIDENCE_SCHEMA, "commands": [],
            "reviews": [], "defects": [], "attestations": attestations,
            "author_attestations": [self.authorship_document()]}),
            encoding="utf-8")
        with self.assertRaises(github_module.GitHubError) as caught:
            self.finalize(reviews=path, keyring=aliased)
        self.assertIn("same secret", str(caught.exception))

    def test_an_author_key_that_is_also_a_reviewer_key_is_refused(self):
        aliased = dict(self.keyring, **{"author-key": KEY_A})
        self.evaluate()
        with self.assertRaises(github_module.GitHubError) as caught:
            self.finalize(reviews=self.signed_bundle_for_alias(),
                          keyring=aliased)
        self.assertIn("same secret", str(caught.exception))

    def signed_bundle_for_alias(self):
        path = self.tmp / "aliased-author.json"
        path.write_text(json.dumps({
            "schema": evidence_module.EVIDENCE_SCHEMA, "commands": [],
            "reviews": [], "defects": [],
            "attestations": list(self.two_attestations()),
            "author_attestations": [
                self.authorship_document(secret=KEY_A)]}), encoding="utf-8")
        return path

    def test_the_admission_key_may_not_also_be_a_reviewer_key(self):
        self.evaluate()
        with self.assertRaises(github_module.GitHubError) as caught:
            github_module.finalize(
                store_module.open_store(self.home), self.preview,
                signer=self.signer, expected_sha=self.sha, now=self.now,
                policy_root=self.root,
                evaluation_attestation=self.attest(),
                evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
                keyring=dict(self.keyring, **{"reviewer-a": SECRET}),
                environment={"ADMISSIBLE_HMAC_KEY": SECRET.decode()})
        self.assertIn("admission key", str(caught.exception))

    def test_supplied_signer_is_compared_without_an_environment_copy(self):
        authorities = self.bundle_file(
            attestations=self.two_attestations(),
            author_attestations=[self.authorship_document()])
        self.evaluate(evidence_path=authorities)
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        opened.trust_policy(
            repository="github.com/acme/widget", class_id=self.klass.id,
            policy_digest=self.klass.policy_digest,
            enforcement_digest=config_module.enforcement_digest(self.klass),
            trusted_at=self.now)
        shared = receipt_module.signer_from_secret("finalizer-1", KEY_A)
        with self.assertRaises(github_module.GitHubError) as caught:
            github_module.finalize(
                opened, self.preview, signer=shared,
                expected_sha=self.sha, now=self.now, policy_root=self.root,
                evaluation_attestation=self.attest(),
                evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
                keyring=self.keyring, environment={})
        self.assertIn("admission key", str(caught.exception))


class PolicyGenerationTest(ClosureCase):
    """W4: a superseded baseline is history, never a live authority."""

    def opened(self):
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        return opened

    def trust(self, opened, artifact_class, *, at=None):
        return opened.trust_policy(
            repository="github.com/acme/widget", class_id=artifact_class.id,
            policy_digest=artifact_class.policy_digest,
            enforcement_digest=config_module.enforcement_digest(
                artifact_class), trusted_at=self.now if at is None else at)

    def custom(self, *, reviews=0, reviewer_key_ids=(), author_key_ids=()):
        """A hand-written class under no profile floor, at a chosen strength."""

        return config_module.parse_config({
            "version": 1, "profile": "python-library",
            "classes": [{
                "id": "default",
                "checks": [{"id": "unit", "argv": ["true"],
                            "timeout_seconds": 60, "cost_units": 1,
                            "required": True, "version": "1"}],
                "required_independent_reviews": reviews,
                "review_max_age_seconds": 86400,
                "max_cost_units": 10, "max_wall_seconds": 600,
                "reviewer_key_ids": list(reviewer_key_ids),
                "author_key_ids": list(author_key_ids),
            }],
        }).select_class("default")

    def weak_class(self):
        """The gate as it was before the class was raised: no review at all."""

        return self.custom()

    def strong_class(self):
        return self.custom(reviews=2,
                           reviewer_key_ids=("reviewer-a", "reviewer-b"),
                           author_key_ids=("author-key",))

    def test_tightening_a_class_supersedes_the_weaker_baseline(self):
        opened = self.opened()
        weak, strong = self.weak_class(), self.strong_class()
        self.trust(opened, weak)
        self.trust(opened, strong)
        enforceable = [item["policy_digest"] for item in
                       opened.trusted_policies("github.com/acme/widget",
                                               "default")]
        self.assertEqual(enforceable, [strong.policy_digest])

    def test_the_superseded_baseline_is_still_readable_history(self):
        opened = self.opened()
        weak, strong = self.weak_class(), self.strong_class()
        self.trust(opened, weak)
        self.trust(opened, strong)
        history = [item["policy_digest"] for item in opened.trusted_policies(
            "github.com/acme/widget", "default", include_superseded=True)]
        self.assertIn(weak.policy_digest, history)
        self.assertIn(strong.policy_digest, history)

    def test_reverting_to_the_weaker_policy_no_longer_finalizes(self):
        opened = self.opened()
        self.trust(opened, self.weak_class())
        self.trust(opened, self.strong_class())
        with self.assertRaises(github_module.GitHubError) as caught:
            github_module.require_trusted_policy(
                opened, repository="github.com/acme/widget",
                class_id="default", artifact_class=self.weak_class(),
                now=self.now)
        self.assertIn("superseded", str(caught.exception))

    def test_trusting_the_same_policy_twice_opens_no_new_generation(self):
        opened = self.opened()
        self.trust(opened, self.klass)
        first = opened.policy_generation("github.com/acme/widget", "default")
        self.trust(opened, self.klass)
        self.assertEqual(
            opened.policy_generation("github.com/acme/widget", "default"),
            first)
        github_module.require_trusted_policy(
            opened, repository="github.com/acme/widget", class_id="default",
            artifact_class=self.klass, now=self.now)

    def test_a_revoked_policy_cannot_enforce(self):
        opened = self.opened()
        self.trust(opened, self.klass)
        opened.revoke_policy(repository="github.com/acme/widget",
                             class_id="default",
                             policy_digest=self.klass.policy_digest,
                             revoked_at=self.now)
        self.assertEqual(
            opened.trusted_policies("github.com/acme/widget", "default"), ())
        with self.assertRaises(github_module.GitHubError):
            github_module.require_trusted_policy(
                opened, repository="github.com/acme/widget",
                class_id="default", artifact_class=self.klass, now=self.now)

    def test_re_trusting_brings_a_superseded_policy_forward(self):
        opened = self.opened()
        weak = self.weak_class()
        self.trust(opened, weak)
        self.trust(opened, self.strong_class())
        self.trust(opened, weak)
        enforceable = [item["policy_digest"] for item in
                       opened.trusted_policies("github.com/acme/widget",
                                               "default")]
        self.assertEqual(enforceable, [weak.policy_digest])

    def test_finalize_refuses_after_the_baseline_moves_on(self):
        path = self.bundle_file(attestations=self.two_attestations(),
                                author_attestations=[
                                    self.authorship_document()])
        self.evaluate(evidence_path=path)
        opened = self.opened()
        self.trust(opened, self.klass)
        # An operator later tightens the class further; the policy the preview
        # was evaluated under is now a previous generation.
        document = json.loads(json.dumps(self.document))
        document["classes"][0]["required_independent_reviews"] = 3
        document["classes"][0]["reviewer_key_ids"] = [
            "reviewer-a", "reviewer-b", "reviewer-c"]
        self.trust(opened, config_module.parse_config(
            document).select_class("default"))
        with self.assertRaises(github_module.GitHubError) as caught:
            github_module.finalize(
                opened, self.preview, signer=self.signer,
                expected_sha=self.sha, now=self.now, policy_root=self.root,
                evaluation_attestation=self.attest(),
                evaluation_keyring={OBSERVER_KEY_ID: OBSERVER_SECRET},
                keyring=self.keyring, environment={})
        self.assertIn("superseded", str(caught.exception))

    def test_the_cli_lists_and_revokes(self):
        parser = cli_module._build_parser()
        options = parser.parse_args(
            ["policy", "revoke", "--class", "default", "--digest", "a" * 64])
        self.assertEqual(options.policy_command, "revoke")
        self.assertEqual(options.policy_digest, "a" * 64)
        options = parser.parse_args(["policy", "list", "--all"])
        self.assertTrue(options.include_superseded)

    def test_policy_options_before_the_action_are_refused(self):
        parser = cli_module._build_parser()
        for argv in (["policy", "--repo", "/wrong", "trust"],
                     ["policy", "--json", "list"]):
            with self.subTest(argv=argv), self.assertRaises(cli_module._Usage):
                parser.parse_args(argv)

    def test_policy_options_after_the_action_are_preserved(self):
        options = cli_module._build_parser().parse_args(
            ["policy", "list", "--repo", "/expected", "--json"])
        self.assertEqual(options.repo, "/expected")
        self.assertTrue(options.json)


class SecretFileDescriptorTest(TempCase):
    """C1: a key is read from the object that was checked, not from a path.

    The old shape stat-ed the path and then reopened it. Anybody who could
    write the containing directory -- a shared CI home, a world-writable
    scratch -- could swap the checked file for a link between the two calls and
    have a file that passed none of the rules read as key material.
    """

    def key_file(self, name="key", body=b"secret", mode=0o600):
        path = self.tmp / name
        path.write_bytes(body)
        os.chmod(path, mode)
        return path

    def test_a_symlinked_key_file_is_refused_rather_than_followed(self):
        target = self.key_file()
        link = self.tmp / "link"
        link.symlink_to(target)
        from admissible.fsutil import SecretFileError, read_secret_file
        with self.assertRaises(SecretFileError) as caught:
            read_secret_file(str(link), "ADMISSIBLE_REVIEW_KEY_FILE")
        self.assertIn("symbolic link", str(caught.exception))

    def test_a_world_readable_key_is_still_refused(self):
        from admissible.fsutil import SecretFileError, read_secret_file
        path = self.key_file(mode=0o644)
        with self.assertRaises(SecretFileError):
            read_secret_file(str(path), "ADMISSIBLE_REVIEW_KEY_FILE")

    def test_a_directory_is_refused(self):
        from admissible.fsutil import SecretFileError, read_secret_file
        directory = self.tmp / "dir"
        directory.mkdir(mode=0o700)
        with self.assertRaises(SecretFileError):
            read_secret_file(str(directory), "ADMISSIBLE_REVIEW_KEY_FILE")

    def test_an_oversized_key_is_refused_by_content_not_only_by_stat(self):
        from admissible.fsutil import SecretFileError, read_secret_file
        path = self.key_file(body=b"x" * 64)
        with self.assertRaises(SecretFileError):
            read_secret_file(str(path), "ADMISSIBLE_REVIEW_KEY_FILE",
                             max_bytes=16)

    def test_the_bytes_read_are_the_bytes_of_the_checked_object(self):
        from admissible.fsutil import read_secret_file
        path = self.key_file(body=b"the-real-key")
        self.assertEqual(
            read_secret_file(str(path), "ADMISSIBLE_REVIEW_KEY_FILE"),
            b"the-real-key")

    def test_the_helper_never_reopens_the_path_after_checking_it(self):
        """Structural: one open, then fstat and read on that descriptor."""

        source = Path(
            __file__).resolve().parent.parent / "admissible" / "fsutil.py"
        body = source.read_text(encoding="utf-8")
        helper = body[body.index("def read_secret_file"):]
        self.assertIn("os.fstat(descriptor)", helper)
        self.assertNotIn("path.read_bytes()", helper)
        self.assertIn("O_NOFOLLOW", helper)


class AmbientCredentialTest(ClosureCase):
    """W1: run must refuse to start while holding any signing credential."""

    def test_an_ambient_admission_key_refuses_the_run(self):
        os.environ["ADMISSIBLE_HMAC_KEY"] = "not-a-real-key"
        code, document, _ = self.evaluate()
        self.assertEqual(code, 2)
        self.assertIn("ADMISSIBLE_HMAC_KEY", document["message"])

    def test_an_ambient_reviewer_key_refuses_the_run(self):
        os.environ["ADMISSIBLE_REVIEW_KEY"] = "not-a-real-key"
        code, document, _ = self.evaluate()
        self.assertEqual(code, 2)
        self.assertIn("ADMISSIBLE_REVIEW_KEY", document["message"])

    def test_an_ambient_observer_key_refuses_the_run(self):
        os.environ["ADMISSIBLE_EVALUATION_KEY"] = "not-a-real-key"
        code, document, _ = self.evaluate()
        self.assertEqual(code, 2)
        self.assertIn("ADMISSIBLE_EVALUATION_KEY", document["message"])


if __name__ == "__main__":
    unittest.main()
