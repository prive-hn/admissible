"""Human-review evidence is a separate conclusion from automation."""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))

from fcd.head import HMACSHA256Keyring, HMACSHA256Signer


class HumanReviewReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reviewer = HMACSHA256Signer("human-1", b"h" * 32)
        self.keyring = HMACSHA256Keyring({
            "human-1": b"h" * 32,
            "gateway-1": b"g" * 32,
            "alice": b"a" * 32,
        })

    def issue(self, **overrides):
        from fcd.human_review import issue_human_review
        fields = dict(
            artifact_hash="c" * 64,
            reviewer_id="human-1",
            independent_of=("alice", "gateway-1"),
            scope="exact-head identity and adapter receipts",
            verdict="accept",
            reviewed_at=20,
        )
        fields.update(overrides)
        return issue_human_review(signer=self.reviewer, **fields)

    def test_human_receipt_names_artifact_reviewer_scope_verdict_and_time(self) -> None:
        from fcd.human_review import verify_human_review
        receipt = self.issue()
        self.assertEqual(receipt.artifact_hash, "c" * 64)
        self.assertEqual(receipt.reviewer_id, "human-1")
        self.assertEqual(receipt.independent_of, ("alice", "gateway-1"))
        self.assertEqual(receipt.scope, "exact-head identity and adapter receipts")
        self.assertEqual(receipt.verdict, "accept")
        self.assertEqual(receipt.reviewed_at, 20)
        self.assertTrue(verify_human_review(receipt, self.keyring))

    def test_reviewer_sharing_a_generator_or_gateway_secret_is_refused(self) -> None:
        from fcd.human_review import HumanReviewError, issue_human_review
        same = HMACSHA256Signer("human-1", b"g" * 32)
        with self.assertRaises(HumanReviewError):
            issue_human_review(
                signer=same,
                artifact_hash="c" * 64,
                reviewer_id="human-1",
                independent_of=("gateway-1",),
                scope="head",
                verdict="accept",
                reviewed_at=20,
                peer_secrets={"gateway-1": b"g" * 32},
            )

    def test_conclusions_never_collapse_automation_and_human_into_one_check(self) -> None:
        from fcd.human_review import ReviewConclusions
        automation = {"attested": True, "passed": True}
        conclusions = ReviewConclusions(automation=automation, human=None)
        view = conclusions.as_view()
        self.assertIn("automation", view)
        self.assertIn("human", view)
        self.assertIsNone(view["human"])
        self.assertTrue(view["automation"]["passed"])
        self.assertNotIn("green", view)
        self.assertFalse(conclusions.admitted(require_human=True))
        self.assertTrue(conclusions.admitted(require_human=False))

        with_human = ReviewConclusions(automation=automation, human=self.issue())
        self.assertTrue(with_human.admitted(require_human=True))
        self.assertEqual(with_human.as_view()["human"]["verdict"], "accept")
        self.assertTrue(with_human.as_view()["automation"]["passed"])

    def test_rejected_human_review_blocks_admission_even_if_automation_passed(self) -> None:
        from fcd.human_review import ReviewConclusions
        rejected = self.issue(verdict="reject")
        conclusions = ReviewConclusions(
            automation={"attested": True, "passed": True},
            human=rejected,
        )
        self.assertFalse(conclusions.admitted(require_human=True))
        self.assertEqual(conclusions.as_view()["human"]["verdict"], "reject")
        self.assertTrue(conclusions.as_view()["automation"]["passed"])


if __name__ == "__main__":
    unittest.main()
