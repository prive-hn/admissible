"""Contract: evaluate produces evidence; only a trusted finalizer admits.

The evaluate job runs candidate-owned commands, so it never receives a reviewer
keyring. It therefore *cannot* authenticate a blocking review, and a high-risk
class -- payment, authentication, migration, infrastructure -- can never
honestly reach ADMITTED there.

The repair is to say that out loud rather than to weaken either side. Evaluate
emits an operationally valid preview whose deterministic required checks all
passed and whose only outstanding blocker is independent review; that preview is
marked ``AWAITING_REVIEW`` and is never called ADMITTED. The trusted finalizer,
holding the pinned reviewer keyring, verifies the signed attestations,
recomputes the whole decision against its own trusted checkout, and issues the
only ADMITTED that exists anywhere.
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
from admissible_support import (TempCase, git, make_repo,  # noqa: E402
                                require_module, source_receipt_document)

attestation = require_module("admissible.attestation")
cli = require_module("admissible.cli")
config_module = require_module("admissible.config")
decision = require_module("admissible.decision")
evidence = require_module("admissible.evidence")
ghmod = require_module("admissible.github")
profiles_module = require_module("admissible.profiles")
receipt = require_module("admissible.receipt")
review_module = require_module("admissible.review")
store_module = require_module("admissible.store")

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / ".github" / "workflows" / "admissible-gate.yml"
ACTION = ROOT / ".github" / "actions" / "admissible" / "action.yml"

SECRET = b"handoff-finalizer-secret-not-real"
KEY_A = b"reviewer-a-secret-not-real"
KEY_B = b"reviewer-b-secret-not-real"
AUTHOR_KEY = b"author-key-secret-not-real"
OBSERVER = b"external-observer-secret-not-real"
OFFLINE = [sys.executable, "-c", "pass"]


def payment_policy(*, reviewer_key_ids=("reviewer-a", "reviewer-b"),
                   author_key_ids=("author-key",), argv=None, max_cost=None):
    """The shipped ``payment-change`` policy with offline check commands.

    Only the argv changes: the class keeps the profile's three required checks,
    its two required independent reviews, its ceilings and its freshness rule,
    so the fixture exercises the real high-risk shape rather than a toy one.
    """

    document = profiles_module.profile_document("payment-change")
    artifact_class = document["classes"][0]
    for check in artifact_class["checks"]:
        check["argv"] = list(argv or OFFLINE)
    artifact_class["reviewer_key_ids"] = list(reviewer_key_ids)
    artifact_class["author_key_ids"] = list(author_key_ids)
    if max_cost is not None:
        artifact_class["max_cost_units"] = max_cost
    return document


class HandoffCase(TempCase):
    def setUp(self):
        super().setUp()
        self.signer = receipt.signer_from_secret("finalizer-1", SECRET)
        self.keyring = {"reviewer-a": KEY_A, "reviewer-b": KEY_B,
                        "author-key": AUTHOR_KEY}
        self.now = int(time.time())

    def build(self, document):
        self.root = self.tmp / "candidate"
        self.sha = make_repo(self.root, files={
            "README.md": "widget\n",
            ".admissible.json": json.dumps(document, indent=2) + "\n",
        })
        self.tree = git(self.root, "rev-parse", "HEAD^{tree}")
        parsed = config_module.parse_config(document)
        self.klass = parsed.select_class("default")
        return self.sha

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

    def authorship(self, *, key_id="author-key"):
        """The author's own signed claim on this commit.

        A class requiring independent review admits nothing without one: the
        rule that nobody reviews their own change is a statement about keys,
        and until a key claims authorship there is nothing to exclude.
        """

        return review_module.attest_authorship({
            "kind": "authorship", "author_id": "mallory",
            "repository": "github.com/acme/widget", "commit_sha": self.sha,
            "tree_sha": self.tree, "policy_digest": self.klass.policy_digest,
            "issued_at": self.now}, key_id=key_id, secret=AUTHOR_KEY)

    def bundle_file(self, attestations, *, reviews=(), authorship="default"):
        if authorship == "default":
            authorship = [self.authorship()]
        path = self.tmp / "reviews.json"
        path.write_text(json.dumps({
            "schema": evidence.EVIDENCE_SCHEMA, "commands": [],
            "reviews": list(reviews), "defects": [],
            "attestations": list(attestations),
            "author_attestations": list(authorship)}), encoding="utf-8")
        return path

    def two_attestations(self):
        return [
            review_module.attest(self.review("r1", reviewer="alice"),
                                 key_id="reviewer-a", secret=KEY_A),
            review_module.attest(self.review("r2", reviewer="carol"),
                                 key_id="reviewer-b", secret=KEY_B),
        ]

    def evaluate(self, *, evidence_path=None, keyring_path=None):
        """The untrusted evaluate job: no reviewer keyring, no signing key."""

        os.environ.pop("ADMISSIBLE_HMAC_KEY", None)
        if keyring_path is None:
            os.environ.pop("ADMISSIBLE_REVIEW_KEYRING", None)
        else:
            os.environ["ADMISSIBLE_REVIEW_KEYRING"] = str(keyring_path)
        self.preview = self.tmp / "preview.json"
        argv = ["run", "--repo", str(self.root), "--sha", self.sha,
                "--preview", "--preview-out", str(self.preview), "--json"]
        if evidence_path is not None:
            argv += ["--evidence", str(evidence_path)]
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(argv, stdout=out, stderr=err)
        text = out.getvalue()
        document = json.loads(text) if text.strip() else {}
        return code, document, err.getvalue()

    def attest_evaluation(self, preview=None, **overrides):
        """The external observer, signing after the evaluate job is gone."""

        source = preview or self.preview
        parsed = json.loads(source.read_text(encoding="utf-8"))
        overrides.setdefault("isolation", "pid-namespace")
        document = attestation.attest_preview(
            parsed, key_id="observer-1", secret=OBSERVER,
            source_receipt=source_receipt_document(parsed["commit_sha"]),
            observed_at=max(self.now, parsed["issued_at"]), **overrides)
        path = self.tmp / "evaluation-attestation.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def finalize(self, *, keyring=None, preview=None, evaluation="default",
                 evaluation_keyring="default", trust=True):
        """The trusted finalizer: pinned keyrings, signing key, baseline."""

        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        if trust:
            opened.trust_policy(
                repository="github.com/acme/widget", class_id=self.klass.id,
                policy_digest=self.klass.policy_digest,
                enforcement_digest=config_module.enforcement_digest(self.klass),
                trusted_at=self.now)
        if evaluation == "default":
            evaluation = self.attest_evaluation(preview)
        if evaluation_keyring == "default":
            evaluation_keyring = {"observer-1": OBSERVER}
        return ghmod.finalize(
            opened, preview or self.preview, signer=self.signer,
            expected_sha=self.sha, now=self.now, policy_root=self.root,
            evaluation_attestation=evaluation,
            evaluation_keyring=evaluation_keyring,
            keyring=self.keyring if keyring is None else keyring,
            environment={})


class PaymentChangeHandoffTest(HandoffCase):
    """C1: the end-to-end high-risk path, evaluate through finalize."""

    def test_evaluate_without_a_keyring_hands_over_but_never_admits(self):
        self.build(payment_policy())
        path = self.bundle_file(self.two_attestations())
        code, document, err = self.evaluate(evidence_path=path)

        # Not admitted, and not an operational failure either: this is evidence
        # production that ran to completion.
        self.assertEqual(code, 1, document or err)
        self.assertEqual(document["state"], decision.REFUSED)
        self.assertEqual(document["readiness"],
                         decision.READINESS_AWAITING_REVIEW)

        # Every deterministic required check really did pass.
        for outcome in document["checks"]:
            self.assertEqual(outcome["status"], "passed", outcome)

        # And the handoff exists, carrying both signatures untouched.
        preview = json.loads(self.preview.read_text(encoding="utf-8"))
        self.assertEqual(preview["readiness"],
                         decision.READINESS_AWAITING_REVIEW)
        self.assertEqual(preview["state"], decision.REFUSED)
        self.assertEqual(len(preview["evidence"]["attestations"]), 2)

    def test_the_word_admitted_is_never_used_for_a_pending_preview(self):
        self.build(payment_policy())
        path = self.bundle_file(self.two_attestations())
        _, document, _ = self.evaluate(evidence_path=path)
        self.assertNotEqual(document["state"], decision.ADMITTED)
        self.assertNotEqual(document["readiness"],
                            decision.READINESS_READY_FOR_ATTESTATION)

    def test_finalize_with_the_pinned_keyring_admits(self):
        self.build(payment_policy())
        path = self.bundle_file(self.two_attestations())
        self.evaluate(evidence_path=path)
        issued = self.finalize()
        self.assertEqual(issued.commit_sha, self.sha)
        self.assertEqual(issued.state, decision.ADMITTED)
        self.assertEqual(issued.class_id, "default")

    def test_finalize_without_a_keyring_cannot_admit_either(self):
        self.build(payment_policy())
        path = self.bundle_file(self.two_attestations())
        self.evaluate(evidence_path=path)
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize(keyring={})
        self.assertIn("review", str(caught.exception).lower())

    def test_a_tampered_attestation_never_finalizes(self):
        self.build(payment_policy())
        attestations = self.two_attestations()
        attestations[0]["review"]["reviewer_id"] = "mallory"
        path = self.bundle_file(attestations)
        self.evaluate(evidence_path=path)
        with self.assertRaises(ghmod.GitHubError):
            self.finalize()

    def test_an_unknown_reviewer_key_never_finalizes(self):
        self.build(payment_policy())
        attestations = [
            review_module.attest(self.review("r1"), key_id="reviewer-a",
                                 secret=KEY_A),
            review_module.attest(self.review("r2"), key_id="reviewer-z",
                                 secret=b"whatever-mallory-likes"),
        ]
        path = self.bundle_file(attestations)
        self.evaluate(evidence_path=path)
        with self.assertRaises(ghmod.GitHubError):
            self.finalize()

    def test_a_policy_letting_an_author_review_cannot_be_built_at_all(self):
        """The author-reviews case is now unreachable, not merely refused.

        A policy naming one key as both a reviewer key and an author key is
        rejected where policies are parsed, so no evaluation and no
        finalization ever sees it. That is stronger than catching it at the
        signing boundary and cheaper to be sure of.
        """

        with self.assertRaises(config_module.ConfigError) as caught:
            config_module.parse_config(payment_policy(
                author_key_ids=("reviewer-b",)))
        self.assertIn("disjoint", str(caught.exception))

    def test_a_future_dated_review_never_finalizes(self):
        self.build(payment_policy())
        attestations = [
            review_module.attest(self.review("r1"), key_id="reviewer-a",
                                 secret=KEY_A),
            review_module.attest(self.review("r2", issued_at=4102444800),
                                 key_id="reviewer-b", secret=KEY_B),
        ]
        path = self.bundle_file(attestations)
        self.evaluate(evidence_path=path)
        with self.assertRaises(ghmod.GitHubError):
            self.finalize()

    def test_two_reviews_from_one_key_never_finalize(self):
        self.build(payment_policy())
        attestations = [
            review_module.attest(self.review("r1", reviewer="alice"),
                                 key_id="reviewer-a", secret=KEY_A),
            review_module.attest(self.review("r2", reviewer="carol"),
                                 key_id="reviewer-a", secret=KEY_A),
        ]
        path = self.bundle_file(attestations)
        self.evaluate(evidence_path=path)
        with self.assertRaises(ghmod.GitHubError):
            self.finalize()

    def test_an_unsigned_review_is_pending_and_never_finalizes(self):
        """A plain JSON approval is a claim by whoever wrote the file."""

        self.build(payment_policy())
        path = self.bundle_file([], reviews=[self.review("r1")])
        code, document, _ = self.evaluate(evidence_path=path)
        self.assertEqual(code, 1)
        self.assertEqual(document["readiness"],
                         decision.READINESS_AWAITING_REVIEW)
        self.evaluate(evidence_path=path)
        with self.assertRaises(ghmod.GitHubError):
            self.finalize()


class EvaluateStillFailsTest(HandoffCase):
    """C2: a handoff is not an escape hatch for anything but review."""

    def test_a_failed_required_check_is_not_awaiting_review(self):
        self.build(payment_policy(
            argv=[sys.executable, "-c", "raise SystemExit(3)"]))
        path = self.bundle_file(self.two_attestations())
        code, document, _ = self.evaluate(evidence_path=path)
        self.assertEqual(code, 1)
        self.assertEqual(document["readiness"], decision.READINESS_NOT_READY)
        self.assertIn("failed_check",
                      {reason["code"] for reason in document["reasons"]})

    def test_a_cost_ceiling_is_not_awaiting_review(self):
        self.build(payment_policy(max_cost=2))
        code, document, _ = self.evaluate()
        self.assertEqual(code, 2)
        self.assertEqual(document["state"], decision.BLOCKED)
        self.assertEqual(document["readiness"], decision.READINESS_NOT_READY)

    def test_invalid_evidence_is_an_operational_failure(self):
        self.build(payment_policy())
        path = self.tmp / "broken.json"
        path.write_text('{"schema": "nope"}', encoding="utf-8")
        code, _, err = self.evaluate(evidence_path=path)
        self.assertEqual(code, 2, err)

    def test_a_rejecting_signed_review_is_not_awaiting_review(self):
        self.build(payment_policy())
        attestations = [
            review_module.attest(self.review("r1", verdict="reject"),
                                 key_id="reviewer-a", secret=KEY_A),
        ]
        path = self.bundle_file(attestations)
        code, document, _ = self.evaluate(evidence_path=path)
        self.assertEqual(code, 1)
        self.assertEqual(document["readiness"], decision.READINESS_NOT_READY)

    def test_an_unpinned_reviewer_key_is_not_awaiting_review(self):
        self.build(payment_policy())
        attestations = [
            review_module.attest(self.review("r1"), key_id="reviewer-a",
                                 secret=KEY_A),
            review_module.attest(self.review("r2"), key_id="reviewer-outside",
                                 secret=b"outside-secret"),
        ]
        path = self.bundle_file(attestations)
        code, document, _ = self.evaluate(evidence_path=path)
        self.assertEqual(code, 1)
        self.assertEqual(document["readiness"], decision.READINESS_NOT_READY)

    def test_a_class_with_no_pinned_keyring_cannot_be_written_at_all(self):
        """A class that can never authenticate a review is not a policy.

        Evaluating it and reporting NOT_READY was the old answer, and it was a
        true statement about a policy nobody should have been able to commit.
        The policy is now refused where policies are parsed, so the repository
        is told what is wrong before a single check is spawned.
        """

        with self.assertRaises(config_module.ConfigError) as caught:
            config_module.parse_config(payment_policy(reviewer_key_ids=()))
        self.assertIn("reviewer_key_ids", str(caught.exception))

    def test_finalize_refuses_a_preview_that_is_not_ready(self):
        self.build(payment_policy(
            argv=[sys.executable, "-c", "raise SystemExit(3)"]))
        path = self.bundle_file(self.two_attestations())
        self.evaluate(evidence_path=path)
        with self.assertRaises(ghmod.GitHubError) as caught:
            self.finalize()
        # It must refuse *as* a readiness refusal, before spending the work of
        # authenticating reviews and recomputing a decision for a preview whose
        # own evaluation already said no keyring could rescue it.
        message = str(caught.exception)
        self.assertIn(decision.READINESS_NOT_READY, message)
        self.assertIn(
            "did not establish the deterministic evidence", message)
        self.assertIn(
            "Only READY_FOR_ATTESTATION or AWAITING_REVIEW is worth finalising",
            message)

    def test_a_preview_that_calls_itself_admitted_is_refused(self):
        # ADMITTED is not a decision state at all any more: an evaluation signs
        # nothing, so it cannot have admitted anything, and a preview claiming
        # otherwise is refused on that alone.
        self.build(payment_policy())
        path = self.bundle_file(self.two_attestations())
        self.evaluate(evidence_path=path)
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document["state"] = decision.ADMITTED
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(attestation.EvaluationError) as caught:
            self.attest_evaluation(self.preview)
        self.assertIn("ADMITTED belongs only to a durable receipt",
                      str(caught.exception))

    def test_a_preview_that_contradicts_itself_is_refused(self):
        self.build(payment_policy())
        path = self.bundle_file(self.two_attestations())
        self.evaluate(evidence_path=path)
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document["readiness"] = decision.READINESS_READY_FOR_ATTESTATION
        document["state"] = decision.REFUSED
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(attestation.EvaluationError) as caught:
            self.attest_evaluation(self.preview)
        self.assertIn("contradict", str(caught.exception))

    def test_an_awaiting_review_preview_that_passed_its_checks_is_refused(self):
        # The other half of the contradiction, and the dangerous half. A
        # preview that says "the checks all passed" while also saying "reviews
        # are still outstanding" is describing two different evaluations; the
        # observer here signs *that* document, so nothing downstream can catch
        # it by comparison and this guard is the only thing between it and a
        # receipt for a class whose reviews were never counted.
        self.build(payment_policy())
        path = self.bundle_file(self.two_attestations())
        self.evaluate(evidence_path=path)
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document["readiness"] = decision.READINESS_AWAITING_REVIEW
        document["state"] = decision.CHECKS_PASSED
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(attestation.EvaluationError) as caught:
            self.attest_evaluation(self.preview)
        self.assertIn("contradict", str(caught.exception))
        self.assertIn(decision.READINESS_AWAITING_REVIEW,
                      str(caught.exception))

    def test_a_forged_readiness_field_does_not_admit_anything(self):
        self.build(payment_policy(
            argv=[sys.executable, "-c", "raise SystemExit(3)"]))
        path = self.bundle_file(self.two_attestations())
        self.evaluate(evidence_path=path)
        document = json.loads(self.preview.read_text(encoding="utf-8"))
        document["readiness"] = decision.READINESS_AWAITING_REVIEW
        self.preview.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ghmod.GitHubError):
            self.finalize()


class RunNeverAuthenticatesTest(HandoffCase):
    """C3: ``run`` authenticates no review, and now refuses to hold a keyring.

    An earlier design let ``run`` authenticate reviews when a keyring happened
    to be present, and admit on the strength of them. That made the boundary a
    property of the environment rather than of the program: a keyring exported
    for some other reason turned the process that starts candidate-owned
    commands into the process that decides who reviewed the change.

    The boundary is now the program, in two layers. ``run`` reads no keyring,
    so nothing it decides depends on a secret; and ``run`` refuses to start at
    all while a reviewer keyring is visible to this process, because a check
    runs as this user and can read the file that variable names. Stripping the
    name from the child environment was never enough -- the file it pointed at
    was still one open() away.
    """

    def keyring_file(self, **entries):
        path = self.tmp / "keyring.json"
        path.write_text(json.dumps(entries), encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def test_a_complete_keyring_in_the_environment_refuses_the_run(self):
        self.build(payment_policy())
        path = self.bundle_file(self.two_attestations())
        keyring = self.keyring_file(**{"reviewer-a": KEY_A.decode(),
                                       "reviewer-b": KEY_B.decode()})
        code, document, err = self.evaluate(evidence_path=path,
                                            keyring_path=keyring)
        self.assertEqual(code, 2, document or err)
        self.assertEqual(document["state"], decision.BLOCKED)
        self.assertIn("ADMISSIBLE_REVIEW_KEYRING", document["message"])
        self.assertFalse(self.preview.exists(),
                         "a refused run must hand over nothing")

    def test_a_partial_keyring_is_refused_on_the_same_ground(self):
        """Half a keyring is still a reviewer secret in this process."""

        self.build(payment_policy())
        path = self.bundle_file(self.two_attestations())
        keyring = self.keyring_file(**{"reviewer-a": KEY_A.decode()})
        code, document, err = self.evaluate(evidence_path=path,
                                            keyring_path=keyring)
        self.assertEqual(code, 2, document or err)
        self.assertIn("ADMISSIBLE_REVIEW_KEYRING", document["message"])

    def test_without_a_keyring_the_signatures_are_carried_and_not_counted(self):
        """The original guarantee, in the environment run is allowed to have.

        Two valid attestations are present, and the evaluation counts neither:
        it has nothing to authenticate them with and does not go looking.
        """

        self.build(payment_policy())
        path = self.bundle_file(self.two_attestations())
        code, document, err = self.evaluate(evidence_path=path)
        self.assertEqual(code, 1, document or err)
        self.assertEqual(document["readiness"],
                         decision.READINESS_AWAITING_REVIEW)
        self.assertEqual(document["reviews"]["independent_approving"], 0)
        self.assertEqual(document["reviews"]["pending_authentication"], 2)

    def test_the_same_preview_still_finalizes_where_the_keyring_belongs(self):
        self.build(payment_policy())
        path = self.bundle_file(self.two_attestations())
        code, document, err = self.evaluate(evidence_path=path)
        self.assertEqual(code, 1, document or err)
        issued = self.finalize()
        self.assertEqual(issued.state, decision.ADMITTED)
        self.assertEqual(
            sorted(key_id for _digest, key_id in issued.authenticated_reviews),
            ["reviewer-a", "reviewer-b"])


class ReadinessFunctionTest(unittest.TestCase):
    """C5: ``preview_readiness`` is a pure function, and both of its guards
    are load-bearing on their own.

    The reason codes and the check outcomes are two independent descriptions of
    the same evaluation, and readiness consults both. Trusting only the codes
    would mean one mislabelled code could carry a failing check into a handoff;
    trusting only the outcomes would mean a rejection with every check green
    looked like it was merely waiting for somebody.
    """

    def build(self, *, state, reasons, checks):
        return decision.Decision(
            state=state, repository="github.com/acme/widget",
            commit_sha="a1" * 20, tree_sha="b2" * 20,
            policy_digest="f" * 64, class_id="default",
            reasons=tuple(decision.Reason(code, "default", code)
                          for code in reasons),
            remediation=(),
            checks=tuple(decision.CheckOutcome(check_id, required, status,
                                               None, 0)
                         for check_id, required, status in checks),
            independent_reviews=0, required_independent_reviews=2,
            cost_units=1, max_cost_units=10, wall_seconds=1,
            max_wall_seconds=600, evidence_digests=(), evaluated_at=1000)

    def test_pending_codes_with_every_required_check_passed_is_awaiting(self):
        result = self.build(
            state=decision.REFUSED, reasons=("missing_independent_review",),
            checks=(("unit", True, "passed"), ("lint", False, "failed")))
        self.assertEqual(decision.preview_readiness(result),
                         decision.READINESS_AWAITING_REVIEW)

    def test_a_failing_required_check_is_never_awaiting_review(self):
        """Even when every reason code says the reviews are what is missing."""

        result = self.build(
            state=decision.REFUSED, reasons=("missing_independent_review",),
            checks=(("unit", True, "failed"),))
        self.assertEqual(decision.preview_readiness(result),
                         decision.READINESS_NOT_READY)

    def test_a_non_pending_reason_is_never_awaiting_review(self):
        result = self.build(
            state=decision.REFUSED,
            reasons=("missing_independent_review", "rejecting_review"),
            checks=(("unit", True, "passed"),))
        self.assertEqual(decision.preview_readiness(result),
                         decision.READINESS_NOT_READY)

    def test_a_blocked_decision_is_never_awaiting_review(self):
        result = self.build(
            state=decision.BLOCKED, reasons=("missing_independent_review",),
            checks=(("unit", True, "passed"),))
        self.assertEqual(decision.preview_readiness(result),
                         decision.READINESS_NOT_READY)

    def test_readiness_is_not_a_fourth_decision_state(self):
        result = self.build(
            state=decision.REFUSED, reasons=("missing_independent_review",),
            checks=(("unit", True, "passed"),))
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(decision.decision_to_dict(result)["state"],
                         decision.REFUSED)


class WorkflowReviewGateTest(unittest.TestCase):
    """C4: the reusable workflow gates on readiness, not on hope."""

    def gate(self) -> str:
        return GATE.read_text(encoding="utf-8")

    def test_the_evaluate_job_publishes_readiness(self):
        text = self.gate()
        self.assertTrue("readiness:" in text, "no readiness job output")
        self.assertTrue("readiness=" in text, "readiness is never written")

    def test_a_pending_review_is_always_red(self):
        """There is no finalize job here, so there is no conditional green.

        The old shape reported AWAITING_REVIEW as success whenever a finalize
        job was enabled, on the reasoning that the finalizer would complete the
        review. It never did on a pull request, where finalize was skipped
        outright, so every review-gated PR went green with zero authenticated
        reviews. The workflow no longer signs at all, so the answer no longer
        depends on anything: a review this run cannot authenticate is red.
        """

        report = self.gate().split("- name: report the decision", 1)
        self.assertEqual(len(report), 2, "no report step in the evaluate job")
        step = report[1]
        self.assertIn(decision.READINESS_AWAITING_REVIEW, step)
        self.assertNotIn("FINALIZE_ENABLED", step)
        pending = step.split(f'"{decision.READINESS_AWAITING_REVIEW}"', 1)[1]
        self.assertIn("exit 1", pending.split("esac")[0])

    def test_the_composite_action_reports_readiness_too(self):
        text = ACTION.read_text(encoding="utf-8")
        self.assertTrue("readiness" in text,
                        "the evaluate-only action hides readiness")

    def test_the_gate_has_no_signing_job_and_takes_no_secret(self):
        text = self.gate()
        self.assertNotIn("secrets:", text)
        self.assertNotIn("ADMISSIBLE_HMAC_KEY:", text)
        self.assertNotIn("\n  finalize:", text)


if __name__ == "__main__":
    unittest.main()
