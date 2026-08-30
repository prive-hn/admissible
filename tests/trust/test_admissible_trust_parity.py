"""Contract: the extracted trusted half answers exactly as the monolith does.

``admissible_trust`` is a copy of the credentialed half of ``admissible``, made
so the two halves can ship as separate distributions.  A copy that drifts is
worse than no copy: two implementations of a receipt body, a review signature
or a standing document can disagree, and whichever one a process happens to
import decides what it admits.

So the parity asserted here is *observational*, not textual.  Comparing the two
files byte for byte would prove they are the same text today and would have to
be deleted the moment the root module becomes a facade; comparing what the two
modules compute from identical inputs stays true through that change and is the
claim that actually matters.  Signatures are the sharpest form of it: an HMAC
is a function of the exact bytes that were signed, so equal signatures mean the
two modules canonicalised the same document.

Refusals are compared too.  A module that accepts a document the other rejects
is not a parity failure that shows up in a digest -- it shows up as an artefact
admitted by the wrong build.

The last class compares this distribution's Ready presentation against the
*other* distribution's, in a child interpreter, because the two are deliberate
copies of one JSON contract living in two wheels that must never import each
other.  That is the one duplication the split creates, and it is the one place
a silent divergence would be invisible to every other test here.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest

from fcd.journal import canonical_json

from admissible import attestation as legacy_attestation
from admissible import ready as legacy_ready
from admissible import receipt as legacy_receipt
from admissible import review as legacy_review
from admissible import standing as legacy_standing

from admissible_trust import attestation as trust_attestation
from admissible_trust import ready_status as trust_ready_status
from admissible_trust import receipt as trust_receipt
from admissible_trust import review as trust_review
from admissible_trust import standing as trust_standing

from . import CORE_SRC, READY_PROJECT, TRUST_SRC

SHA = "a" * 40
TREE = "b" * 40
POLICY_DIGEST = "c" * 64
REPOSITORY = "github.com/acme/widget"

REVIEW_DOCUMENT = {
    "kind": "review",
    "review_id": "review-1",
    "reviewer_id": "reviewer-a",
    "reviewer_version": "1",
    "author_id": "author-a",
    "verdict": "approve",
    "repository": REPOSITORY,
    "commit_sha": SHA,
    "tree_sha": TREE,
    "policy_digest": POLICY_DIGEST,
    "findings_digest": "0" * 64,
    "issued_at": 1700000000,
    "attempt_id": "attempt-one",
}

AUTHORSHIP_DOCUMENT = {
    "kind": "authorship",
    "author_id": "author-a",
    "repository": REPOSITORY,
    "commit_sha": SHA,
    "tree_sha": TREE,
    "policy_digest": POLICY_DIGEST,
    "issued_at": 1700000000,
}

SECRET = b"a-reviewer-secret-that-is-not-real"


class ReviewAttestationParity(unittest.TestCase):
    """Same document, same key: the same signature, both ways round."""

    def test_a_review_signed_here_verifies_there_and_the_reverse(self):
        mine = trust_review.attest(REVIEW_DOCUMENT, key_id="reviewer-a",
                                   secret=SECRET)
        theirs = legacy_review.attest(REVIEW_DOCUMENT, key_id="reviewer-a",
                                      secret=SECRET)
        self.assertEqual(canonical_json(theirs), canonical_json(mine))
        keyring = {"reviewer-a": SECRET}
        from admissible import evidence as legacy_evidence
        from admissible_core import evidence as core_evidence

        self.assertEqual(
            canonical_json(legacy_evidence.review_evidence_to_dict(
                legacy_review.verify_attestation(mine, keyring))),
            canonical_json(core_evidence.review_evidence_to_dict(
                trust_review.verify_attestation(theirs, keyring))))

    def test_an_authorship_claim_signed_here_verifies_there(self):
        mine = trust_review.attest_authorship(
            AUTHORSHIP_DOCUMENT, key_id="author-a", secret=SECRET)
        theirs = legacy_review.attest_authorship(
            AUTHORSHIP_DOCUMENT, key_id="author-a", secret=SECRET)
        self.assertEqual(canonical_json(theirs), canonical_json(mine))
        keyring = {"author-a": SECRET}
        # Compared as documents: the two dataclasses are different classes in
        # different packages, so equality between the records themselves would
        # be false whatever the bytes said.
        from admissible import evidence as legacy_evidence
        from admissible_core import evidence as core_evidence

        self.assertEqual(
            canonical_json(legacy_evidence.authorship_evidence_to_dict(
                legacy_review.verify_authorship_attestation(mine, keyring))),
            canonical_json(core_evidence.authorship_evidence_to_dict(
                trust_review.verify_authorship_attestation(theirs, keyring))))

    def test_a_tampered_attestation_is_refused_by_both(self):
        document = trust_review.attest(REVIEW_DOCUMENT, key_id="reviewer-a",
                                       secret=SECRET)
        document["review"] = dict(document["review"], verdict="reject")
        keyring = {"reviewer-a": SECRET}
        for module in (legacy_review, trust_review):
            with self.subTest(module=module.__name__):
                with self.assertRaises(module.ReviewError):
                    module.verify_attestation(document, keyring)

    def test_an_unknown_key_id_is_refused_by_both(self):
        document = trust_review.attest(REVIEW_DOCUMENT, key_id="reviewer-a",
                                       secret=SECRET)
        for module in (legacy_review, trust_review):
            with self.subTest(module=module.__name__):
                with self.assertRaises(module.ReviewError):
                    module.verify_attestation(document, {"someone-else": SECRET})

    def test_the_domain_strings_are_the_same_wire_constants(self):
        self.assertEqual(legacy_review.ATTESTATION_DOMAIN,
                         trust_review.ATTESTATION_DOMAIN)
        self.assertEqual(legacy_review.AUTHORSHIP_DOMAIN,
                         trust_review.AUTHORSHIP_DOMAIN)

    def test_a_colliding_keyring_is_refused_by_both(self):
        keyring = {"reviewer-a": b"shared", "reviewer-b": b"shared"}
        for module in (legacy_review, trust_review):
            with self.subTest(module=module.__name__):
                with self.assertRaises(module.ReviewError):
                    module.assert_distinct_secrets(keyring, where="a fixture")


class EvaluationAttestationParity(unittest.TestCase):
    """The observer's statement is one closed body, canonicalised once."""

    def body(self) -> dict:
        return {
            "preview_schema": "admissible/v0.6/workflow-preview",
            "issued_at": 1700000000,
            "repository": REPOSITORY,
            "commit_sha": SHA,
            "tree_sha": TREE,
            "policy_digest": POLICY_DIGEST,
            "class_id": "default",
            "attempt_id": "attempt-one",
            "state": "CHECKS_PASSED",
            "readiness": "READY_FOR_ATTESTATION",
            "config_path": ".admissible.json",
            "fork": False,
            "isolation": "pid-namespace",
            "dependencies": [],
            "command_digests": ["d" * 64],
            "review_digests": [],
            "decision_digest": "e" * 64,
            "source_receipt": {
                "provider": "github-actions",
                "run_id": "1",
                "commit_sha": SHA,
                "conclusion": "success",
                "receipt_digest": "f" * 64,
            },
            "observed_at": 1700000100,
        }

    def test_the_signed_bodies_are_identical(self):
        mine = trust_attestation.attest(self.body(), key_id="observer-a",
                                        secret=SECRET)
        theirs = legacy_attestation.attest(self.body(), key_id="observer-a",
                                           secret=SECRET)
        self.assertEqual(canonical_json(theirs), canonical_json(mine))

    def test_each_verifies_the_other_s_attestation(self):
        mine = trust_attestation.attest(self.body(), key_id="observer-a",
                                        secret=SECRET)
        keyring = {"observer-a": SECRET}
        self.assertEqual(
            legacy_attestation.verify_evaluation(mine, keyring),
            trust_attestation.verify_evaluation(mine, keyring))

    def test_the_body_key_tuple_and_schema_are_the_same(self):
        self.assertEqual(legacy_attestation.EVALUATION_BODY_KEYS,
                         trust_attestation.EVALUATION_BODY_KEYS)
        self.assertEqual(legacy_attestation.EVALUATION_SCHEMA,
                         trust_attestation.EVALUATION_SCHEMA)
        self.assertEqual(legacy_attestation.EVALUATION_DOMAIN,
                         trust_attestation.EVALUATION_DOMAIN)
        self.assertEqual(legacy_attestation.SOURCE_RECEIPT_KEYS,
                         trust_attestation.SOURCE_RECEIPT_KEYS)

    def test_an_unknown_isolation_mode_is_refused_by_both(self):
        body = self.body()
        body["isolation"] = "a-boundary-nobody-defined"
        for module in (legacy_attestation, trust_attestation):
            with self.subTest(module=module.__name__):
                with self.assertRaises(module.EvaluationError):
                    module.attest(body, key_id="observer-a", secret=SECRET)

    def test_an_incoherent_state_and_readiness_pair_is_refused_by_both(self):
        body = self.body()
        body["readiness"] = "AWAITING_REVIEW"
        for module in (legacy_attestation, trust_attestation):
            with self.subTest(module=module.__name__):
                with self.assertRaises(module.EvaluationError):
                    module.attest(body, key_id="observer-a", secret=SECRET)

    def test_the_admissible_conclusion_sets_agree_at_every_readiness(self):
        for readiness in ("READY_FOR_ATTESTATION", "AWAITING_REVIEW",
                          "NOT_READY"):
            with self.subTest(readiness=readiness):
                self.assertEqual(
                    legacy_attestation.admissible_source_conclusions(readiness),
                    trust_attestation.admissible_source_conclusions(readiness))


class ReceiptBodyParity(unittest.TestCase):
    """The receipt body is the identity of an admission; it must be one thing."""

    def arguments(self, **overrides) -> dict:
        arguments = {
            "repository": REPOSITORY,
            "commit_sha": SHA,
            "tree_sha": TREE,
            "class_id": "default",
            "policy_digest": POLICY_DIGEST,
            "state": "ADMITTED",
            "decision_digest_value": "e" * 64,
            "evidence_digests": ("d" * 64,),
            "attempt_id": "attempt-one",
            "authenticated_reviews": (("d" * 64, "reviewer-a"),),
            "dependencies": (("other/repo", "9" * 40),),
            "issued_at": 1700000000,
        }
        arguments.update(overrides)
        return arguments

    def test_the_bodies_and_their_digests_are_identical(self):
        arguments = self.arguments()
        self.assertEqual(
            canonical_json(legacy_receipt.expected_receipt_body(**arguments)),
            canonical_json(trust_receipt.expected_receipt_body(**arguments)))
        self.assertEqual(
            legacy_receipt.expected_receipt_body_digest(**arguments),
            trust_receipt.expected_receipt_body_digest(**arguments))

    def test_a_non_admitted_state_is_refused_by_both(self):
        arguments = self.arguments(state="CHECKS_PASSED")
        for module in (legacy_receipt, trust_receipt):
            with self.subTest(module=module.__name__):
                with self.assertRaises(module.ReceiptError):
                    module.expected_receipt_body(**arguments)

    def test_the_wire_constants_are_the_same(self):
        for name in ("RECEIPT_SCHEMA", "RECEIPT_DOMAIN", "RECEIPT_SCOPE",
                     "JOURNAL_PREFIX", "EVENT_WORKFLOW_ADMISSION",
                     "EVENT_DEFECT"):
            with self.subTest(constant=name):
                self.assertEqual(getattr(legacy_receipt, name),
                                 getattr(trust_receipt, name))

    def test_the_journal_id_of_a_repository_is_the_same(self):
        self.assertEqual(legacy_receipt.journal_id_for(REPOSITORY),
                         trust_receipt.journal_id_for(REPOSITORY))

    def test_a_receipt_round_trips_through_the_other_module(self):
        signer = trust_receipt.signer_from_secret("local", SECRET)
        head = _head_receipt(signer)
        arguments = self.arguments()
        body = trust_receipt.expected_receipt_body(**arguments)
        receipt = trust_receipt.WorkflowReceipt(
            schema=trust_receipt.RECEIPT_SCHEMA,
            scope=trust_receipt.RECEIPT_SCOPE,
            journal_id=body["journal_id"], repository=REPOSITORY,
            commit_sha=SHA, tree_sha=TREE, policy_digest=POLICY_DIGEST,
            class_id="default", state="ADMITTED", attempt_id="attempt-one",
            decision_digest="e" * 64, evidence_digests=("d" * 64,),
            authenticated_reviews=(("d" * 64, "reviewer-a"),),
            dependencies=(("other/repo", "9" * 40),), issued_at=1700000000,
            body_digest=trust_receipt.expected_receipt_body_digest(**arguments),
            receipt_hash="0" * 64, head=head)
        document = trust_receipt.receipt_to_dict(receipt)
        parsed = legacy_receipt.receipt_from_dict(document)
        self.assertEqual(canonical_json(document),
                         canonical_json(legacy_receipt.receipt_to_dict(parsed)))


def _head_receipt(signer):
    from fcd import head as fcd_head

    head = fcd_head.compute_journal_head("admissible/workflow/x", [])
    return fcd_head.make_receipt(head, "", 1700000000, signer)


class StandingDocumentParity(unittest.TestCase):
    """The standing envelope is a published shape; both must render it alike."""

    def standing(self, module):
        return module.Standing(
            state=module.UNKNOWN, repository=REPOSITORY, commit_sha=SHA,
            receipts=(), defects=(), unknown_scope=True,
            unauthenticated=(), historical_receipts=(),
            integrity_problem="a verifier is required for standing")

    def test_the_state_words_and_exit_codes_agree(self):
        self.assertEqual(legacy_standing.CURRENT, trust_standing.CURRENT)
        self.assertEqual(legacy_standing.IMPEACHED, trust_standing.IMPEACHED)
        self.assertEqual(legacy_standing.UNKNOWN, trust_standing.UNKNOWN)
        for state in (legacy_standing.CURRENT, legacy_standing.IMPEACHED,
                      legacy_standing.UNKNOWN):
            with self.subTest(state=state):
                self.assertEqual(
                    legacy_standing._EXIT_CODES[state],
                    trust_standing._EXIT_CODES[state])

    def test_the_standing_document_is_identical(self):
        self.assertEqual(
            canonical_json(legacy_standing.standing_to_dict(
                self.standing(legacy_standing))),
            canonical_json(trust_standing.standing_to_dict(
                self.standing(trust_standing))))

    def test_a_verifierless_query_is_unknown_in_both(self):
        for module in (legacy_standing, trust_standing):
            with self.subTest(module=module.__name__):
                found = module.current_standing(None, REPOSITORY, SHA,
                                                verifier=None)
                self.assertEqual(module.UNKNOWN, found.state)
                self.assertEqual(1, found.exit_code)

    def test_the_report_document_is_identical(self):
        reports = {}
        for name, module in (("legacy", legacy_standing),
                             ("trust", trust_standing)):
            reports[name] = module.report_to_dict(module.Report(
                repository=REPOSITORY, commit_sha=SHA, state=module.UNKNOWN,
                defects=(), receipts=(), dependents=(), missed_checks=(),
                missed_reviewers=(), reachable_dependent_impact=False,
                unknown_scope=True, remediation=("do the thing",),
                unauthenticated=(), historical_receipts=(),
                integrity_problem=""))
        self.assertEqual(canonical_json(reports["legacy"]),
                         canonical_json(reports["trust"]))


class ReadyDocumentParityWithTheMonolith(unittest.TestCase):
    """The authenticated presentation is the monolith's, label for label."""

    CANONICAL = {
        "state": "CHECKS_PASSED",
        "readiness": "READY_FOR_ATTESTATION",
        "repository": REPOSITORY,
        "commit_sha": SHA,
        "tree_sha": TREE,
        "policy_digest": POLICY_DIGEST,
        "class_id": "default",
        "attempt_id": "attempt-one",
        "reasons": [],
        "remediation": [],
        "checks": [{"id": "unit", "status": "passed", "required": True}],
        "independent_reviews": 0,
        "required_independent_reviews": 0,
        "exit_code": 0,
    }

    def test_from_evaluation_produces_the_same_document(self):
        for standing in ("UNKNOWN", "CURRENT", "IMPEACHED", "UNVERIFIED"):
            with self.subTest(standing=standing):
                self.assertEqual(
                    canonical_json(legacy_ready.from_evaluation(
                        self.CANONICAL, standing=standing)),
                    canonical_json(trust_ready_status.from_evaluation(
                        self.CANONICAL, standing=standing)))

    def test_from_problem_produces_the_same_document(self):
        self.assertEqual(
            canonical_json(legacy_ready.from_problem(
                "the tree moved", ("re-run",), reason_code="identity_changed",
                summary="HEAD moved.")),
            canonical_json(trust_ready_status.from_problem(
                "the tree moved", ("re-run",), reason_code="identity_changed",
                summary="HEAD moved.")))

    def test_render_plain_produces_the_same_text_including_ready(self):
        document = legacy_ready.from_evaluation(self.CANONICAL,
                                                standing="CURRENT")
        document["status"] = "ready"
        document["summary"] = "This exact commit is admitted."
        self.assertEqual(legacy_ready.render_plain(document),
                         trust_ready_status.render_plain(document))

    def test_the_schema_id_is_unchanged(self):
        self.assertEqual(legacy_ready.READY_SCHEMA,
                         trust_ready_status.READY_SCHEMA)


class ReadyDocumentParityWithTheCandidateDistribution(unittest.TestCase):
    """One JSON contract, two wheels, and no import between them.

    ``admissible_ready.ready`` and ``admissible_trust.ready_status`` are
    deliberate copies of the same presentation, because neither distribution
    may import the other and the schema id they both emit is one contract.
    That duplication is the split's one real cost, so it is measured: the
    candidate half is run in a child interpreter that has Core and Ready on its
    path and nothing else, and its documents are compared byte for byte with
    the ones produced here.
    """

    FIXTURES = [
        {"kind": "evaluation", "standing": "UNKNOWN"},
        {"kind": "evaluation", "standing": "UNVERIFIED"},
        {"kind": "problem"},
    ]

    def candidate_documents(self) -> list[str]:
        source = _CANDIDATE_PROBE % (
            json.dumps(ReadyDocumentParityWithTheMonolith.CANONICAL),)
        completed = subprocess.run(
            [sys.executable, "-c", source], capture_output=True, text=True,
            timeout=120,
            env={"PYTHONPATH": f"{READY_PROJECT / 'src'}:{CORE_SRC}",
                 "PATH": "/usr/bin:/bin"})
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)

    def mine(self) -> list[str]:
        canonical = ReadyDocumentParityWithTheMonolith.CANONICAL
        found = []
        for fixture in self.FIXTURES:
            if fixture["kind"] == "evaluation":
                found.append(canonical_json(
                    trust_ready_status.from_evaluation(
                        canonical, standing=fixture["standing"])))
            else:
                found.append(canonical_json(trust_ready_status.from_problem(
                    "the tree moved", ("re-run",),
                    reason_code="identity_changed", summary="HEAD moved.")))
        return found

    def test_the_two_distributions_emit_the_same_documents(self):
        self.assertEqual(self.candidate_documents(), self.mine())

    def test_the_candidate_half_cannot_produce_the_ready_status(self):
        """The one difference, asserted as itself rather than assumed."""

        completed = subprocess.run(
            [sys.executable, "-c",
             "from admissible_ready import ready;"
             "print(';'.join(ready.UNSIGNED_STATUSES))"],
            capture_output=True, text=True, timeout=120,
            env={"PYTHONPATH": f"{READY_PROJECT / 'src'}:{CORE_SRC}",
                 "PATH": "/usr/bin:/bin"})
        self.assertEqual(0, completed.returncode, completed.stderr)
        unsigned = completed.stdout.strip().split(";")
        self.assertNotIn("ready", unsigned)
        self.assertIn("ready", trust_ready_status.AUTHENTICATED_STATUSES)
        self.assertEqual(
            sorted(unsigned),
            sorted(set(trust_ready_status.AUTHENTICATED_STATUSES) - {"ready"}))


_CANDIDATE_PROBE = """
import json

from fcd.journal import canonical_json

from admissible_ready import ready

canonical = json.loads(%r)
found = [
    canonical_json(ready.from_evaluation(canonical, standing="UNKNOWN")),
    canonical_json(ready.from_evaluation(canonical, standing="UNVERIFIED")),
    canonical_json(ready.from_problem(
        "the tree moved", ("re-run",), reason_code="identity_changed",
        summary="HEAD moved.")),
]
print(json.dumps(found))
"""


if __name__ == "__main__":
    unittest.main()
