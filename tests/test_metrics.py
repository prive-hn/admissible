"""Metrics from the event stream. Written first (TDD RED).

Rates per metrics/SCHEMA.md over a named cut [t0, t1], W:
- misbind: first Observe per stage with norm(exec)!=norm(decl)
- silent-fail: well-formed stage w/o decide/accept within W, + orphan opens
- bleed: assigned a outside pi* (check stages exclude authors)
- time-to-stage: right-censored survival, exclude ts > t1-W
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fcd.metrics import rates, survival  # noqa: F401


def ev(**kw):
    base = {"work_item_id": "w1", "stage_id": "s1"}
    base.update(kw)
    return base


class MetricsTests(unittest.TestCase):
    def test_misbind_first_observe_only(self):
        events = [
            ev(type="stage", ts=1, class_="impl", stage_kind="write",
               assigned="alice", declared="model-a", authors=[], well_formed=True),
            ev(type="call", ts=2, executed="model-X", declared="model-a"),
            ev(type="call", ts=3, executed="model-a", declared="model-a"),
            ev(type="decide", ts=4, result="pass"),
        ]
        r = rates(events, t0=0, t1=10, W=2, policy=None)
        self.assertEqual(r["misbind"]["num"], 1)
        self.assertEqual(r["misbind"]["den"], 1)

    def test_silent_fail_includes_orphan_open(self):
        events = [
            ev(type="open", ts=1),
            # never a stage for w1
            ev(type="stage", ts=2, class_="impl", stage_kind="write",
               assigned="alice", declared="model-a", authors=[], well_formed=True,
               work_item_id="w2", stage_id="s2"),
            ev(type="decide", ts=3, result="fail_closed", work_item_id="w2", stage_id="s2"),
        ]
        r = rates(events, t0=0, t1=10, W=2, policy=None)
        self.assertEqual(r["silent_fail"]["num"], 1)  # the orphan open
        self.assertEqual(r["silent_fail"]["den"], 2)  # one stage + one orphan

    def test_bleed_uses_pi_chk_on_check_stage(self):
        policy = {"allow": {"impl": {"alice", "bob"}},
                  "deny": {"impl": set()},
                  "phi": {"alice": "model-a", "bob": "model-b"}}
        events = [
            ev(type="stage", ts=1, class_="impl", stage_kind="check",
               assigned="alice", declared="model-a", authors=["alice"],
               well_formed=True),
        ]
        r = rates(events, t0=0, t1=10, W=2, policy=policy)
        # alice authored the write stage; check must exclude her
        self.assertEqual(r["bleed"]["num"], 1)
        self.assertEqual(r["bleed"]["den"], 1)

    def test_survival_right_censors(self):
        events = [
            ev(type="stage", ts=1, class_="impl", stage_kind="write",
               assigned="alice", declared="model-a", authors=[], well_formed=True),
            ev(type="decide", ts=2, result="pass"),           # completed, t=1
            ev(type="stage", ts=9.5, class_="impl", stage_kind="write",
               assigned="bob", declared="model-b", authors=[], well_formed=True,
               work_item_id="w3", stage_id="s3"),
            ev(type="decide", ts=10.4, result="pass", work_item_id="w3", stage_id="s3"),
        ]
        s = survival(events, t0=0, t1=10, W=2)
        # stage at ts=9.5 > t1-W=8 is censored out of the sample
        self.assertEqual(s["n"], 1)
        self.assertEqual(s["durations"], [1.0])


if __name__ == "__main__":
    unittest.main()
