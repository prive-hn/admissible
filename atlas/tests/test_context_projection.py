"""Project/context atlas projection — TDD RED first."""
from __future__ import annotations

import unittest

from atlas.context import build_context_atlas
from fcd.context import ContextAuthority, KnowledgeDelta, ProjectState
from tests.test_context_envelope import refs


class ContextAtlasTests(unittest.TestCase):
    def setUp(self):
        self.accepted = {"A"}
        self.auth = ContextAuthority(is_accepted=lambda w: w in self.accepted)
        self.auth.add_project(ProjectState("p", 18, 12, "policy-4", strict_unknown=True))
        self.auth.open_work("p", "A", 1)
        self.auth.open_work("p", "B", 1)
        self.auth.open_work("p", "C", 1)

    def test_project_and_all_sibling_lines_are_visible(self):
        snap = build_context_atlas(self.auth, "p")
        self.assertEqual((snap.project.project_version, snap.project.memory_version), (18, 12))
        self.assertEqual(tuple(w.work_item_id for w in snap.work_items), ("A", "B", "C"))

    def test_attempt_projects_exact_model_context_and_locked_state(self):
        attempt = self.auth.admit("B", refs(mode="fresh_blind"), specialist="reviewer")
        snap = build_context_atlas(self.auth, "p")
        view = next(a for a in snap.attempts if a.attempt_id == attempt.envelope.attempt_id)
        self.assertEqual(view.model_api_id, "model-a")
        self.assertEqual(view.context_mode, "fresh_blind")
        self.assertTrue(view.locked)
        self.assertEqual(view.receipt_status, "missing")

    def test_project_advance_marks_pinned_siblings_drifted_and_review_navigation(self):
        self.auth.promote("A", KnowledgeDelta(("A accepted",), ()), expected_head=(18, 12))
        snap = build_context_atlas(self.auth, "p")
        drift = {d.work_item_id: d for d in snap.drift}
        self.assertEqual(drift["B"].status, "needs_review")
        self.assertEqual(drift["C"].status, "needs_review")
        self.assertEqual(snap.counts["drift"], 2)

        self.auth.review_impact("B", "reachable", "continue_pinned", "owner")
        snap2 = build_context_atlas(self.auth, "p")
        drift2 = {d.work_item_id: d for d in snap2.drift}
        self.assertEqual(drift2["B"].status, "reviewed")
        self.assertEqual(drift2["C"].status, "needs_review")

    def test_projection_is_immutable(self):
        snap = build_context_atlas(self.auth, "p")
        with self.assertRaises(AttributeError):
            snap.work_items.append("X")  # type: ignore[attr-defined]


if __name__ == "__main__":
    unittest.main()
