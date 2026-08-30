"""Contract: closed evidence records and plain, actionable decisions."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import TempCase, require_module  # noqa: E402

evidence = require_module("admissible.evidence")
decision = require_module("admissible.decision")
config = require_module("admissible.config")
runner = require_module("admissible.runner")

SHA = "a" * 40
TREE = "b" * 40
POLICY = "c" * 64
REPO = "github.com/acme/widget"
# The digest of the argv the classes below configure. Evidence that names any
# other command proves nothing about the configured one.
ARGV = runner.argv_digest(("true",))
ATTEMPT = "attempt-one"


def command_document(**overrides) -> dict:
    document = {
        "kind": "command",
        "check_id": "unit",
        "check_version": "1",
        "repository": REPO,
        "commit_sha": SHA,
        "tree_sha": TREE,
        "policy_digest": POLICY,
        "argv_digest": ARGV,
        "exit_code": 0,
        "timed_out": False,
        "launch_failed": False,
        "duration_ms": 1200,
        "stdout_sha256": "e" * 64,
        "stderr_sha256": "f" * 64,
        "stdout_bytes": 6,
        "stderr_bytes": 0,
        "output_truncated": False,
        "started_at": 1000,
        "finished_at": 1002,
        "attempt_id": ATTEMPT,
        "reused_from_attempt": "",
    }
    document.update(overrides)
    return document


def authorship_document(**overrides) -> dict:
    document = {
        "kind": "authorship",
        "author_id": "author-one",
        "repository": REPO,
        "commit_sha": SHA,
        "tree_sha": TREE,
        "policy_digest": POLICY,
        "issued_at": 1000,
    }
    document.update(overrides)
    return document


def review_document(**overrides) -> dict:
    document = {
        "kind": "review",
        "review_id": "r1",
        "reviewer_id": "reviewer-one",
        "reviewer_version": "1",
        "author_id": "author-one",
        "verdict": "approve",
        "repository": REPO,
        "commit_sha": SHA,
        "tree_sha": TREE,
        "policy_digest": POLICY,
        "findings_digest": "0" * 64,
        "issued_at": 1000,
        "attempt_id": ATTEMPT,
    }
    document.update(overrides)
    return document


class ClosedEvidenceTest(unittest.TestCase):
    def test_command_evidence_round_trips_exactly(self):
        document = command_document()
        record = evidence.command_evidence_from_dict(document)
        self.assertEqual(evidence.command_evidence_to_dict(record), document)

    def test_review_evidence_round_trips_exactly(self):
        document = review_document()
        record = evidence.review_evidence_from_dict(document)
        self.assertEqual(evidence.review_evidence_to_dict(record), document)

    def test_unknown_key_is_refused(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.command_evidence_from_dict(command_document(extra=1))

    def test_missing_key_is_refused(self):
        document = command_document()
        del document["exit_code"]
        with self.assertRaises(evidence.EvidenceError):
            evidence.command_evidence_from_dict(document)

    def test_bool_exit_code_is_refused(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.command_evidence_from_dict(command_document(exit_code=True))

    def test_short_sha_is_refused(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.command_evidence_from_dict(command_document(commit_sha="a" * 12))

    def test_unknown_verdict_is_refused(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.review_evidence_from_dict(review_document(verdict="maybe"))

    def test_evidence_digest_is_stable_and_content_bound(self):
        first = evidence.evidence_digest(
            evidence.command_evidence_from_dict(command_document()))
        again = evidence.evidence_digest(
            evidence.command_evidence_from_dict(command_document()))
        other = evidence.evidence_digest(
            evidence.command_evidence_from_dict(command_document(exit_code=1)))
        self.assertEqual(first, again)
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, other)

    def test_evidence_cannot_carry_raw_output(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.command_evidence_from_dict(
                command_document(stdout="secret token in the clear"))


class LoadEvidenceFileTest(TempCase):
    def test_bundle_file_loads_commands_and_reviews(self):
        path = self.write_json(self.tmp / "bundle.json", {
            "schema": evidence.EVIDENCE_SCHEMA,
            "commands": [command_document()],
            "reviews": [review_document()],
            "defects": [], "attestations": [],
        })
        bundle = evidence.load_evidence_file(path)
        self.assertEqual(len(bundle.commands), 1)
        self.assertEqual(len(bundle.reviews), 1)
        self.assertEqual(bundle.source_sha256, evidence.file_digest(path))

    def test_unknown_bundle_key_is_refused(self):
        path = self.write_json(self.tmp / "bundle.json", {
            "schema": evidence.EVIDENCE_SCHEMA, "commands": [],
            "reviews": [], "defects": [], "attestations": [], "nope": 1})
        with self.assertRaises(evidence.EvidenceError):
            evidence.load_evidence_file(path)

    def test_wrong_schema_is_refused(self):
        path = self.write_json(self.tmp / "bundle.json", {
            "schema": "someone-elses/schema", "commands": [],
            "reviews": [], "defects": [], "attestations": []})
        with self.assertRaises(evidence.EvidenceError):
            evidence.load_evidence_file(path)

    def test_evidence_cannot_forge_a_kernel_journal_event(self):
        path = self.write_json(self.tmp / "bundle.json", {
            "schema": evidence.EVIDENCE_SCHEMA,
            "commands": [], "reviews": [], "defects": [], "attestations": [],
            "events": [{"type": "open", "id": "x"}]})
        with self.assertRaises(evidence.EvidenceError):
            evidence.load_evidence_file(path)

    def test_oversized_bundle_is_refused(self):
        path = self.tmp / "bundle.json"
        path.write_text("[" + "0," * 5_000_000 + "0]", encoding="utf-8")
        with self.assertRaises(evidence.EvidenceError):
            evidence.load_evidence_file(path)


class DecisionTest(unittest.TestCase):
    def artifact_class(self, **overrides):
        document = {
            "id": "default",
            "checks": [
                {"id": "unit", "argv": ["true"], "timeout_seconds": 60,
                 "cost_units": 2, "required": True, "version": "1"},
                {"id": "lint", "argv": ["true"], "timeout_seconds": 60,
                 "cost_units": 1, "required": False, "version": "1"},
            ],
            "required_independent_reviews": 0,
            "review_max_age_seconds": 86400,
            "max_cost_units": 10,
            "max_wall_seconds": 600,
        }
        document.update(overrides)
        if document["required_independent_reviews"]:
            # A class that requires review must name who may review and who
            # authors, or the word "independent" in the requirement means
            # nothing. Tests that care about the key lists override them.
            document.setdefault("reviewer_key_ids", ["reviewer-a", "reviewer-b"])
            document.setdefault("author_key_ids", ["author-key"])
        parsed = config.parse_config(
            {"version": 1, "profile": "python-library", "classes": [document]})
        return parsed.select_class("default")

    def evaluate(self, artifact_class, commands, reviews=(), *, now=2000,
                 commit_sha=SHA, tree_sha=TREE, repository=REPO,
                 signed_by=None, authored_by="author-key",
                 base_sha="", patch_sha256=""):
        """Evaluate one attempt.

        ``signed_by`` names the reviewer key that authenticated each review, in
        order. A review with no key is advisory: it is reported, and it can
        refuse, but it can never satisfy a required independent review.

        ``authored_by`` is the key that attested authorship of this commit. A
        class requiring independent review admits nothing without one, so the
        helper supplies the pinned author key by default and tests that care
        about its absence pass ``authored_by=None``.
        """

        parsed = [evidence.review_evidence_from_dict(r) for r in reviews]
        keys = list(signed_by or [])
        marked = tuple(
            evidence.VerifiedReview(record=record, key_id=keys[index])
            if index < len(keys) and keys[index] else record
            for index, record in enumerate(parsed))
        authorships = ()
        if authored_by and artifact_class.required_independent_reviews:
            authorships = (evidence.AttestedAuthorship(
                record=evidence.authorship_evidence_from_dict(
                    authorship_document(
                        repository=repository, commit_sha=commit_sha,
                        tree_sha=tree_sha,
                        policy_digest=artifact_class.policy_digest)),
                key_id=authored_by),)
        return decision.evaluate(
            artifact_class=artifact_class,
            repository=repository,
            commit_sha=commit_sha,
            tree_sha=tree_sha,
            policy_digest=artifact_class.policy_digest,
            commands=tuple(evidence.command_evidence_from_dict(c) for c in commands),
            reviews=marked, authorships=authorships,
            now=now, attempt_id=ATTEMPT,
            base_sha=base_sha, patch_sha256=patch_sha256)

    def bound(self, artifact_class, **overrides):
        return command_document(policy_digest=artifact_class.policy_digest,
                                **overrides)

    def test_all_required_checks_passing_admits(self):
        klass = self.artifact_class()
        result = self.evaluate(klass, [self.bound(klass)])
        self.assertEqual(result.state, decision.CHECKS_PASSED)
        self.assertEqual(result.exit_code, 0)

    def test_failed_required_check_refuses_with_remediation(self):
        klass = self.artifact_class()
        result = self.evaluate(klass, [self.bound(klass, exit_code=1)])
        self.assertEqual(result.state, decision.REFUSED)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("failed_check", [r.code for r in result.reasons])
        self.assertTrue(result.remediation)
        self.assertIn("unit", " ".join(result.remediation))

    def test_missing_required_check_refuses(self):
        klass = self.artifact_class()
        result = self.evaluate(klass, [])
        self.assertIn("missing_check", [r.code for r in result.reasons])
        self.assertEqual(result.state, decision.REFUSED)

    def test_timed_out_required_check_refuses_with_its_own_code(self):
        klass = self.artifact_class()
        result = self.evaluate(
            klass, [self.bound(klass, exit_code=-9, timed_out=True)])
        self.assertIn("check_timeout", [r.code for r in result.reasons])

    def test_stale_sha_evidence_is_refused(self):
        klass = self.artifact_class()
        result = self.evaluate(klass, [self.bound(klass, commit_sha="9" * 40)])
        codes = [r.code for r in result.reasons]
        self.assertIn("stale_evidence_sha", codes)
        self.assertIn("missing_check", codes)

    def test_cross_repository_evidence_is_refused(self):
        klass = self.artifact_class()
        result = self.evaluate(
            klass, [self.bound(klass, repository="github.com/evil/other")])
        self.assertIn("cross_repository_evidence", [r.code for r in result.reasons])

    def test_tree_mismatch_is_refused(self):
        klass = self.artifact_class()
        result = self.evaluate(klass, [self.bound(klass, tree_sha="9" * 40)])
        self.assertIn("stale_evidence_tree", [r.code for r in result.reasons])

    def test_policy_mismatch_is_refused(self):
        klass = self.artifact_class()
        result = self.evaluate(klass, [command_document()])
        self.assertIn("policy_mismatch", [r.code for r in result.reasons])

    def test_optional_check_failure_does_not_refuse_but_is_reported(self):
        klass = self.artifact_class()
        result = self.evaluate(klass, [
            self.bound(klass),
            self.bound(klass, check_id="lint", exit_code=1)])
        self.assertEqual(result.state, decision.CHECKS_PASSED)
        self.assertIn("lint", json.dumps(decision.decision_to_dict(result)))

    def test_a_failing_record_is_never_overridden_by_a_passing_one(self):
        """Two records for one check must resolve to the worse outcome."""
        klass = self.artifact_class()
        # Imported evidence arrives after locally observed evidence; it must not
        # be able to paper over a check that actually failed here.
        result = self.evaluate(klass, [
            self.bound(klass, exit_code=1),
            self.bound(klass, exit_code=0)])
        self.assertEqual(result.state, decision.REFUSED)
        self.assertIn("failed_check", [r.code for r in result.reasons])

    def test_a_timeout_outranks_a_later_passing_record(self):
        klass = self.artifact_class()
        result = self.evaluate(klass, [
            self.bound(klass, exit_code=-9, timed_out=True),
            self.bound(klass, exit_code=0)])
        self.assertIn("check_timeout", [r.code for r in result.reasons])

    def test_required_independent_review_is_enforced(self):
        klass = self.artifact_class(required_independent_reviews=1)
        result = self.evaluate(klass, [self.bound(klass)])
        self.assertIn("missing_independent_review",
                      [r.code for r in result.reasons])

    def test_self_review_is_not_independent(self):
        # Parsing refuses a policy naming one key as both, so this class is
        # built directly: the decision must refuse the author's key on its own.
        base = self.artifact_class(required_independent_reviews=1,
                                   reviewer_key_ids=["key-a"],
                                   author_key_ids=["author-key"])
        klass = config.ArtifactClass(
            **{**{field: getattr(base, field)
                  for field in base.__dataclass_fields__},
               "author_key_ids": ("key-a",)})
        result = self.evaluate(
            klass, [self.bound(klass)],
            [review_document(policy_digest=klass.policy_digest,
                             reviewer_id="same", author_id="same")],
            signed_by=["key-a"])
        self.assertIn("missing_independent_review",
                      [r.code for r in result.reasons])

    def test_duplicate_reviewer_does_not_satisfy_two_reviews(self):
        klass = self.artifact_class(required_independent_reviews=2,
                                    reviewer_key_ids=["key-a", "key-b"])
        reviews = [
            review_document(review_id="r1", policy_digest=klass.policy_digest),
            review_document(review_id="r2", policy_digest=klass.policy_digest),
        ]
        # Two reviews, one signing key: one reviewer, whatever the strings say.
        result = self.evaluate(klass, [self.bound(klass)], reviews,
                               signed_by=["key-a", "key-a"])
        self.assertEqual(result.independent_reviews, 1)
        self.assertIn("missing_independent_review",
                      [r.code for r in result.reasons])

    def test_two_distinct_independent_reviews_admit(self):
        klass = self.artifact_class(required_independent_reviews=2,
                                    reviewer_key_ids=["key-a", "key-b"])
        reviews = [
            review_document(review_id="r1", reviewer_id="a",
                            policy_digest=klass.policy_digest),
            review_document(review_id="r2", reviewer_id="b",
                            policy_digest=klass.policy_digest),
        ]
        result = self.evaluate(klass, [self.bound(klass)], reviews,
                               signed_by=["key-a", "key-b"])
        self.assertEqual(result.state, decision.CHECKS_PASSED)

    def test_an_unsigned_review_never_satisfies_a_required_review(self):
        klass = self.artifact_class(required_independent_reviews=1,
                                    reviewer_key_ids=["key-a"])
        reviews = [
            review_document(review_id="r1", reviewer_id="a",
                            policy_digest=klass.policy_digest),
        ]
        result = self.evaluate(klass, [self.bound(klass)], reviews)
        self.assertEqual(result.independent_reviews, 0)
        self.assertEqual(result.state, decision.REFUSED)

    def test_a_class_that_requires_review_must_pin_reviewer_keys(self):
        """Parsing refuses it, and the decision refuses it again.

        A class with no pinned reviewer keys cannot authenticate anything, so
        the policy is rejected at the ingress boundary. The decision keeps its
        own check for a class assembled some other way: a rule that only exists
        at the boundary stops applying the moment anything else builds a class.
        """

        with self.assertRaises(config.ConfigError):
            config.parse_config({
                "version": 1, "profile": "python-library",
                "classes": [{
                    "id": "default",
                    "checks": [{"id": "unit", "argv": ["true"],
                                "timeout_seconds": 60, "cost_units": 1,
                                "required": True, "version": "1"}],
                    "required_independent_reviews": 1,
                    "review_max_age_seconds": 86400,
                    "max_cost_units": 10, "max_wall_seconds": 600,
                }]})
        base = self.artifact_class(required_independent_reviews=1)
        klass = config.ArtifactClass(
            **{**{field: getattr(base, field)
                  for field in base.__dataclass_fields__},
               "reviewer_key_ids": ()})
        result = self.evaluate(klass, [self.bound(klass)])
        self.assertIn("unpinned_reviewer_keyring",
                      [r.code for r in result.reasons])

    def test_rejecting_review_refuses(self):
        klass = self.artifact_class(required_independent_reviews=1,
                                    reviewer_key_ids=["key-a"])
        reviews = [review_document(reviewer_id="a", verdict="reject",
                                   policy_digest=klass.policy_digest)]
        # Even unsigned: an objection is heeded, an approval is not.
        result = self.evaluate(klass, [self.bound(klass)], reviews)
        self.assertIn("rejecting_review", [r.code for r in result.reasons])

    def test_expired_review_is_not_counted(self):
        klass = self.artifact_class(required_independent_reviews=1,
                                    review_max_age_seconds=10,
                                    reviewer_key_ids=["key-a"])
        reviews = [review_document(reviewer_id="a", issued_at=1,
                                   policy_digest=klass.policy_digest)]
        result = self.evaluate(klass, [self.bound(klass)], reviews,
                               now=100000, signed_by=["key-a"])
        self.assertIn("expired_review", [r.code for r in result.reasons])

    def test_a_future_dated_review_is_not_counted(self):
        klass = self.artifact_class(required_independent_reviews=1,
                                    reviewer_key_ids=["key-a"])
        reviews = [review_document(reviewer_id="a", issued_at=4102444800,
                                   policy_digest=klass.policy_digest)]
        result = self.evaluate(klass, [self.bound(klass)], reviews,
                               signed_by=["key-a"])
        self.assertIn("future_dated_review", [r.code for r in result.reasons])
        self.assertEqual(result.independent_reviews, 0)

    def test_future_dated_command_evidence_is_not_counted(self):
        """A check cannot prove itself by claiming to have run tomorrow.

        Staleness rules bound how *old* evidence may be. Nothing bounds how far
        ahead a clock can be set, so evidence dated past the skew allowance is
        discarded and the check is reported as having no evidence at all.
        """

        klass = self.artifact_class()
        ahead = 2000 + decision.MAX_CLOCK_SKEW_SECONDS + 60
        result = self.evaluate(
            klass, [self.bound(klass, started_at=ahead, finished_at=ahead + 1)])
        codes = [reason.code for reason in result.reasons]
        self.assertIn("future_dated_evidence", codes)
        self.assertIn("missing_check", codes)
        self.assertEqual(result.state, decision.REFUSED)
        self.assertEqual(
            [outcome.status for outcome in result.checks
             if outcome.check_id == "unit"], ["missing"])

    def test_evidence_inside_the_skew_allowance_still_counts(self):
        klass = self.artifact_class()
        ahead = 2000 + decision.MAX_CLOCK_SKEW_SECONDS - 1
        result = self.evaluate(
            klass, [self.bound(klass, started_at=ahead, finished_at=ahead + 1)])
        self.assertEqual(result.state, decision.CHECKS_PASSED, result.reasons)

    def test_cost_ceiling_blocks(self):
        klass = self.artifact_class(max_cost_units=1)
        result = self.evaluate(klass, [self.bound(klass)])
        self.assertEqual(result.state, decision.BLOCKED)
        self.assertEqual(result.exit_code, 2)
        self.assertIn("cost_ceiling", [r.code for r in result.reasons])

    def test_wall_time_ceiling_blocks(self):
        klass = self.artifact_class(max_wall_seconds=1)
        result = self.evaluate(klass, [self.bound(klass, duration_ms=90000)])
        self.assertEqual(result.state, decision.BLOCKED)
        self.assertIn("time_ceiling", [r.code for r in result.reasons])

    def test_decision_json_is_stable_and_plain(self):
        klass = self.artifact_class()
        first = decision.decision_to_dict(self.evaluate(klass, [self.bound(klass)]))
        again = decision.decision_to_dict(self.evaluate(klass, [self.bound(klass)]))
        self.assertEqual(json.dumps(first, sort_keys=True),
                         json.dumps(again, sort_keys=True))
        self.assertIs(type(first), dict)

    def test_decision_never_claims_the_composed_predicate(self):
        klass = self.artifact_class()
        document = decision.decision_to_dict(self.evaluate(klass, [self.bound(klass)]))
        text = json.dumps(document)
        self.assertNotIn("composed-receipt", text)
        self.assertEqual(document["scope"], "developer-workflow-admission")

    def test_plain_output_says_what_happened_known_and_next(self):
        klass = self.artifact_class()
        text = decision.render_plain(self.evaluate(klass, [self.bound(klass, exit_code=1)]))
        lowered = text.lower()
        self.assertIn("what happened", lowered)
        self.assertIn("what is known", lowered)
        self.assertIn("what to do next", lowered)
        self.assertIn("unit", lowered)

    def test_plain_output_is_produced_for_every_state(self):
        klass = self.artifact_class()
        for result in (self.evaluate(klass, [self.bound(klass)]),
                       self.evaluate(klass, []),
                       self.evaluate(self.artifact_class(max_cost_units=1),
                                     [self.bound(klass)])):
            self.assertTrue(decision.render_plain(result).strip())

    def test_named_review_without_finalizer_candidate_is_unbound(self):
        klass = self.artifact_class()
        review = review_document(
            policy_digest=klass.policy_digest,
            base_sha="e" * 40, patch_sha256="f" * 64)
        result = self.evaluate(klass, [self.bound(klass)], [review])
        self.assertIn("review_candidate_mismatch",
                      [reason.code for reason in result.reasons])

    def test_named_review_must_match_finalizer_candidate(self):
        klass = self.artifact_class()
        review = review_document(
            policy_digest=klass.policy_digest,
            base_sha="e" * 40, patch_sha256="f" * 64)
        matched = self.evaluate(
            klass, [self.bound(klass)], [review],
            base_sha="e" * 40, patch_sha256="f" * 64)
        self.assertNotIn("review_candidate_mismatch",
                         [reason.code for reason in matched.reasons])
        drifted = self.evaluate(
            klass, [self.bound(klass)], [review],
            base_sha="e" * 40, patch_sha256="0" * 64)
        self.assertIn("review_candidate_mismatch",
                      [reason.code for reason in drifted.reasons])

    def test_unnamed_review_cannot_authorize_a_supplied_candidate(self):
        klass = self.artifact_class()
        review = review_document(policy_digest=klass.policy_digest)
        result = self.evaluate(
            klass, [self.bound(klass)], [review],
            base_sha="e" * 40, patch_sha256="f" * 64)
        self.assertIn("review_candidate_mismatch",
                      [reason.code for reason in result.reasons])


class CheapFirstOrderingTest(unittest.TestCase):
    def test_checks_run_cheapest_first_then_by_id(self):
        document = {
            "version": 1, "profile": "python-library",
            "classes": [{
                "id": "default",
                "checks": [
                    {"id": "slow", "argv": ["true"], "timeout_seconds": 60,
                     "cost_units": 9, "required": True, "version": "1"},
                    {"id": "zeta", "argv": ["true"], "timeout_seconds": 60,
                     "cost_units": 1, "required": True, "version": "1"},
                    {"id": "alpha", "argv": ["true"], "timeout_seconds": 60,
                     "cost_units": 1, "required": True, "version": "1"},
                ],
                "required_independent_reviews": 0,
                "review_max_age_seconds": 86400,
                "max_cost_units": 100, "max_wall_seconds": 600,
            }],
        }
        klass = config.parse_config(document).select_class("default")
        self.assertEqual([c.id for c in runner.order_checks(klass.checks)],
                         ["alpha", "zeta", "slow"])


if __name__ == "__main__":
    unittest.main()
