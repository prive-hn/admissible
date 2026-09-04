"""Property sweep for the latest decision logic: the clock-skew freshness guard
anchored at decision time (decided_at) and the stale-evidence guards, asserted
against the live admissible.decision.evaluate over a generated space of evidence
clocks (PRs #17/#18).

This is not an I/R/C paper invariant — it is the gate/decision-tool logic added
after the papers: evidence or a review dated more than MAX_CLOCK_SKEW_SECONDS
beyond the *decision* clock is refused (a max-age rule cannot bound a future
date), and the window is anchored at decided_at, not at the moment a check ran
or the wall clock `now`. Evidence bound to another commit or tree is stale.
Reuses the decision fixtures in tests/test_admissible_decision.py.
"""
from __future__ import annotations

import os
import sys
import unittest

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

HERE = os.path.dirname(__file__)
for _p in (os.path.join(HERE, ".."), HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import admissible.decision as decision  # noqa: E402
# Reference the fixture through the module, NOT as a top-level name: importing
# DecisionTest directly would make it an attribute of this module and unittest
# would re-collect and re-run its whole suite here.
import test_admissible_decision as _tad  # noqa: E402
SHA, TREE = _tad.SHA, _tad.TREE

DEEP = bool(os.environ.get("ADMISSIBLE_DEEP"))
EXAMPLES = 400 if DEEP else 60
_SUPPRESS = [HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much]
SKEW = decision.MAX_CLOCK_SKEW_SECONDS


def sweep(**kw):
    p = dict(max_examples=EXAMPLES, deadline=None, derandomize=not DEEP, suppress_health_check=_SUPPRESS)
    p.update(kw)
    return settings(**p)


class DecisionFreshnessProperties(unittest.TestCase):
    """The clock-skew and stale-evidence guards as universal properties over
    generated evidence clocks."""

    def setUp(self):
        # A helper instance for the decision fixtures (artifact_class/evaluate/
        # bound); the methodName only needs to exist so TestCase can construct.
        self.fx = _tad.DecisionTest("test_all_required_checks_passing_admits")

    @sweep()
    @given(decided_at=st.integers(min_value=10_000, max_value=1_000_000),
           offset=st.integers(min_value=-1000, max_value=1000))
    def test_clock_skew_is_anchored_at_decided_at(self, decided_at, offset):
        """A required check started more than SKEW seconds past decided_at is
        future-dated and not counted (so the decision refuses); one inside the
        window is counted. The wall clock `now` does not move the boundary."""
        started_at = decided_at + offset
        klass = self.fx.artifact_class()
        result = self.fx.evaluate(
            klass, [self.fx.bound(klass, started_at=started_at)],
            now=decided_at, decided_at=decided_at)
        codes = [r.code for r in result.reasons]
        if offset > SKEW:
            self.assertIn("future_dated_evidence", codes, (decided_at, offset))
            self.assertEqual(result.state, decision.REFUSED, (decided_at, offset))
        else:
            self.assertNotIn("future_dated_evidence", codes, (decided_at, offset))
            self.assertEqual(result.state, decision.CHECKS_PASSED, (decided_at, offset))

    @sweep()
    @given(now=st.integers(min_value=10_000, max_value=1_000_000),
           decided_gap=st.integers(min_value=1, max_value=5000))
    def test_now_does_not_widen_the_window_decided_at_does(self, now, decided_gap):
        """With decided_at earlier than the wall clock, a check dated between
        decided_at+SKEW and now is refused: the window follows the decision
        clock, the fix of #17/#18 (a check-time or now-anchored window would
        have let it through)."""
        decided_at = now
        started_at = decided_at + SKEW + decided_gap        # just past the decided_at window
        klass = self.fx.artifact_class()
        result = self.fx.evaluate(
            klass, [self.fx.bound(klass, started_at=started_at)],
            now=started_at + 10_000, decided_at=decided_at)  # now is far ahead; must not rescue it
        self.assertIn("future_dated_evidence", [r.code for r in result.reasons], (now, decided_gap))
        self.assertEqual(result.state, decision.REFUSED)

    @sweep()
    @given(bad_sha=st.sampled_from(["9" * 40, "c" * 40]),
           which=st.sampled_from(["commit", "tree"]))
    def test_stale_evidence_is_refused(self, bad_sha, which):
        """Evidence bound to another commit or tree is stale and refused."""
        klass = self.fx.artifact_class()
        kw = {"commit_sha": bad_sha} if which == "commit" else {"tree_sha": bad_sha}
        result = self.fx.evaluate(klass, [self.fx.bound(klass, **kw)], now=2000, decided_at=2000)
        codes = [r.code for r in result.reasons]
        self.assertTrue("stale_evidence_sha" in codes or "stale_evidence_tree" in codes, (which, codes))
        self.assertEqual(result.state, decision.REFUSED)

    def test_decided_at_defaults_to_now(self):
        """When decided_at is not supplied, the decision clock is now — a check
        dated now+SKEW+1 is future-dated against the defaulted window."""
        klass = self.fx.artifact_class()
        result = self.fx.evaluate(
            klass, [self.fx.bound(klass, started_at=2000 + SKEW + 1)],
            now=2000, decided_at=None)
        self.assertIn("future_dated_evidence", [r.code for r in result.reasons])
        self.assertEqual(result.state, decision.REFUSED)

    def test_a_check_inside_the_window_after_a_slow_earlier_check_still_counts(self):
        """The fix's intent: a check that started before decided_at but finished
        after an earlier long check is not future-dated — its start is inside the
        window, so it counts and the decision passes."""
        klass = self.fx.artifact_class()
        result = self.fx.evaluate(
            klass, [self.fx.bound(klass, started_at=2000)],
            now=2000 + 5000, decided_at=2000 + 5000)         # decided long after the check started
        self.assertNotIn("future_dated_evidence", [r.code for r in result.reasons])
        self.assertEqual(result.state, decision.CHECKS_PASSED)


if __name__ == "__main__":
    unittest.main()
