"""The bench is itself under test: deterministic, fresh, and honest.

Determinism is what makes the bench a record rather than an anecdote —
two runs must produce identical results. Freshness pins the committed
RESULTS.md to the code that claims to have generated it: edit either
without the other and this goes red. The honesty checks are the bench's
own basic soundness — honest lines all seal, and escapes never exceed
the latent-defect seals they were hunted on.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "eval" / "bench"))

import bench  # noqa: E402


class BenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = bench.run()

    def test_two_runs_are_identical(self):
        self.assertEqual(self.results, bench.run())

    def test_committed_results_are_fresh(self):
        committed = (HERE.parent / "eval" / "bench" / "RESULTS.md").read_text()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "RESULTS.md"
            bench.write_results(self.results, out)
            self.assertEqual(out.read_text(), committed,
                             "eval/bench/RESULTS.md is stale: re-run "
                             "`python3 eval/bench/bench.py --write`")

    def test_every_honest_line_seals_and_none_is_impeached(self):
        for t, r in self.results["targets"].items():
            self.assertEqual(r["outcomes"]["honest"]["sealed"],
                             self.results["lines"]["honest"], t)
            # impeachment identity, not a count inequality: escapes fall on
            # latent-defect (sloppy) seals only, by the record's own scenario
            # attribution — an impeached honest seal offset by an unimpeached
            # sloppy one cannot slip through a <= on totals.
            by_sc = r["escapes"]["impeached_by_scenario"]
            self.assertEqual(by_sc.get("honest", 0), 0, t)
            self.assertEqual(by_sc.get("unstable", 0), 0, t)
            self.assertEqual(r["escapes"]["impeached_lines"], by_sc.get("sloppy", 0), t)
            self.assertLessEqual(by_sc.get("sloppy", 0),
                                 r["outcomes"]["sloppy"]["sealed"], t)

    def test_journal_hashes_are_present_and_stable(self):
        for t, r in self.results["targets"].items():
            hashes = r["journals"]["hashes"]
            self.assertEqual(set(hashes), {"fcd", "rga", "cal"}, t)
            for h in hashes.values():
                self.assertRegex(h, r"^[0-9a-f]{64}$")

    def test_defect_models_carry_killing_witnesses(self):
        for t in self.results["targets"]:
            _, kept, _ = bench.build_defect_model(t)
            self.assertGreater(len(kept), 0, t)
            self.assertEqual(len(kept), self.results["targets"][t]["defect_model"]["size"])


if __name__ == "__main__":
    unittest.main()
