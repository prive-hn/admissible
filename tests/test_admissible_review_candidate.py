"""Candidate identity on review evidence — family P3 tuple-binding."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from admissible import evidence


def _review(**overrides):
    document = {
        "kind": "review",
        "review_id": "r1",
        "reviewer_id": "alice",
        "reviewer_version": "1",
        "author_id": "bob",
        "verdict": "approve",
        "repository": "example",
        "commit_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "policy_digest": "c" * 64,
        "findings_digest": "d" * 64,
        "issued_at": 1,
        "attempt_id": "att-1",
    }
    document.update(overrides)
    return evidence.review_evidence_from_dict(document)


class ReviewCandidateTest(unittest.TestCase):
    def test_legacy_review_without_candidate_fields_still_parses(self):
        record = _review()
        self.assertEqual(record.base_sha, "")
        self.assertEqual(record.patch_sha256, "")

    def test_legacy_review_cannot_authorize_a_candidate(self):
        record = _review()
        with self.assertRaises(evidence.EvidenceError) as caught:
            evidence.verify_review_candidate(
                record, base_sha="e" * 40, commit_sha="a" * 40,
                tree_sha="b" * 40, patch_sha256="f" * 64)
        self.assertIn("does not name a candidate", str(caught.exception))

    def test_partial_candidate_fields_are_refused(self):
        with self.assertRaises(evidence.EvidenceError) as caught:
            _review(base_sha="e" * 40)
        self.assertIn("paired", str(caught.exception))

    def test_present_falsy_candidate_fields_are_refused(self):
        with self.assertRaises(evidence.EvidenceError):
            _review(base_sha="", patch_sha256="")
        with self.assertRaises(evidence.EvidenceError):
            _review(base_sha=None, patch_sha256=None)

    def test_published_schema_names_candidate_fields(self):
        schema = json.loads(
            (Path(__file__).resolve().parents[1]
             / "protocol" / "workflow-evidence.schema.json").read_text())
        properties = schema["$defs"]["review"]["properties"]
        self.assertIn("base_sha", properties)
        self.assertIn("patch_sha256", properties)
        self.assertEqual(
            schema["$defs"]["review"].get("dependentRequired"),
            {"base_sha": ["patch_sha256"], "patch_sha256": ["base_sha"]})

    def test_named_candidate_must_match_exactly(self):
        record = _review(base_sha="e" * 40, patch_sha256="f" * 64)
        evidence.verify_review_candidate(
            record, base_sha="e" * 40, commit_sha="a" * 40,
            tree_sha="b" * 40, patch_sha256="f" * 64)
        with self.assertRaises(evidence.EvidenceError) as caught:
            evidence.verify_review_candidate(
                record, base_sha="e" * 40, commit_sha="a" * 40,
                tree_sha="b" * 40, patch_sha256="0" * 64)
        self.assertIn("different candidate", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
