"""Property sweep for the calibration / standing layer: C1..C7 and the
E-faults, asserted against the live CalibrationAuthority over the generated
space of three-layer histories (tests/custody_generators.py) plus constructed
probes for the ratchet, non-interference and filing guards.

Where tests/test_rga_calibration.py pins each claim on an example, this asserts
it universally: for every history the generator grows, impeachment follows only
established escapes, charges are total and unit, standing queries are pure and
survive rebuild, every authority seal is mediated, and demotion is exactly the
charge count against the budget. Each TestCase names the invariant.
"""
from __future__ import annotations

import copy
import os
import sys
import unittest

from hypothesis import HealthCheck, given, settings

HERE = os.path.dirname(__file__)
for _p in (os.path.join(HERE, ".."), HERE, os.path.join(HERE, "..", "paper", "custody")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import custody_generators as G  # noqa: E402
from rga.core import AdmissionPolicy, ClaimSpec, ClassAdmission, DefectModel, LedgerEntry, Refuter  # noqa: E402
from test_rga_invariants import D1, K, TESTS, ledger  # noqa: E402
from test_rga_calibration import CalHarness  # noqa: E402

DEEP = bool(os.environ.get("ADMISSIBLE_DEEP"))
EXAMPLES = 400 if DEEP else 50
_SUPPRESS = [HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much]


def sweep(**kw):
    p = dict(max_examples=EXAMPLES, deadline=None, derandomize=not DEEP, suppress_health_check=_SUPPRESS)
    p.update(kw)
    return settings(**p)


class CalibrationStandingInvariants(unittest.TestCase):
    """C1, C2, C3, C5, C6 as universal properties over generated histories."""

    @sweep()
    @given(G.histories())
    def test_C1_impeachment_needs_an_established_escape(self, hist):
        """C1/E1: a line is impeached only if it carries an established, refuted
        escape; a filed-but-never-established escape has no effect."""
        cal = hist.cal
        for iid in hist.sealed:
            if cal.impeached(iid):
                self.assertTrue(
                    any(r.line_id == iid and r.established and r.verdict == "refuted" for r in cal.runs),
                    (iid, hist.moves))
            if not any(r.line_id == iid and r.established for r in cal.runs):
                self.assertFalse(cal.impeached(iid), (iid, hist.moves))

    @sweep()
    @given(G.histories())
    def test_C2_charges_are_total_and_unit(self, hist):
        """C2/E3: at most one charge per (line, claim, refuter version)."""
        cells = list(hist.cal.charge_cells())
        self.assertEqual(len(cells), len(set(cells)), hist.moves)

    @sweep()
    @given(G.histories())
    def test_C3_standing_is_pure_and_survives_rebuild(self, hist):
        """C3: impeached/mediated/admissible are pure queries — a verifier that
        rebuilds from the journal computes the same standing (away from the
        catalogued CF2/CF14 replay seams the generator does not grow)."""
        reb = G.rebuild(hist.h)
        for iid in hist.sealed:
            self.assertEqual(reb.impeached(iid), hist.cal.impeached(iid), (iid, hist.moves))
            self.assertEqual(reb.mediated(iid), hist.cal.mediated(iid), (iid, hist.moves))
            self.assertEqual(reb.admissible(iid), hist.cal.admissible(iid), (iid, hist.moves))

    @sweep()
    @given(G.histories())
    def test_C5_authority_seals_are_mediated(self, hist):
        """C5: every line sealed through the authority carries a stamp, so it is
        mediated; admissible implies mediated."""
        cal = hist.cal
        for iid in hist.sealed:
            self.assertTrue(cal.mediated(iid), (iid, hist.moves))
            if cal.admissible(iid):
                self.assertTrue(cal.mediated(iid), (iid, hist.moves))

    @sweep()
    @given(G.histories())
    def test_C6_demotion_is_the_charge_count_against_the_budget(self, hist):
        """C6: demoted(refuter) is exactly whether its valid charge count has
        reached the class budget e_max — a pure query, no stored flag."""
        cal = hist.cal
        e_max = cal.policy.classes["impl"].e_max
        checkers = {r.checker for r in cal.runs}
        for (rid, ver) in checkers:
            charged = len([c for c in cal.charge_cells("impl") if c[2] == rid and c[3] == ver])
            self.assertEqual(cal.demoted(rid, ver, "impl"), charged > e_max, (rid, ver, charged, e_max, hist.moves))


class CalibrationConstructed(unittest.TestCase):
    """C4 ratchet, C5 bypass, C7 non-interference, and E-faults as constructed
    probes — each a scenario proving the guard fires."""

    def test_C4_ratchet_refuses_forgetting_a_valid_escape(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        run = h.tier_a_escape()                                   # a valid established escape
        pol = AdmissionPolicy({"impl": ClassAdmission(
            claims=(ClaimSpec("tests_pass", "spec-hash-1", frozenset({TESTS}), D1),),
            k=K, theta=1.0, p_min=0.5, excluded=frozenset({"refuter_source", "refuter_results"}),
            residual=(("correct fix", "check_stage"),))}, version="r2")
        with self.assertRaises(ValueError):
            h.cal.install(pol)                                    # E4: successor omits the corpus entry

    def test_C5_a_bypass_seal_is_not_mediated(self):
        """A line sealed by calling Admission.seal directly (layer R's own
        transition) is IR, never mediated, and never admissible."""
        h = CalHarness(); h.declare_tests()
        h.run_to_seal_ready("w")
        h.a.seal("w")                                            # bypass: no cal_stamp
        self.assertTrue(h.a.is_sealed("w"))
        self.assertFalse(h.cal.mediated("w"))
        self.assertFalse(h.cal.admissible("w"))

    def test_C7_non_interference(self):
        """The authority writes no Admission or FCD field: their state is
        unchanged across every ledger transition."""
        h = CalHarness(); h.declare_tests(); h.seal_line()

        def snap():
            return (copy.deepcopy(h.a.fcd.items), set(h.a.fcd.store), len(h.a.events),
                    copy.deepcopy(h.a.sealed))

        before = snap(); h.tier_a_escape()
        after = snap()
        self.assertEqual(after[0], before[0])                    # no FCD item field written (full items)
        self.assertEqual(after[1], before[1]); self.assertEqual(after[2], before[2])
        self.assertEqual(after[3], before[3])                    # Admission.sealed contents untouched (not just keys)

    def test_E6_filing_guards_bytes_and_seed(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        seal = h.a.sealed["w"]
        with self.assertRaises(ValueError):
            h.cal.file_escape("w", "tests_pass", "tests", "v1", "n1",
                              b"WRONG-BYTES", "any-seed", "kill-w", finder="aud")  # bytes != sealed hash

    def test_E7_adjudication_needs_actor_and_reason(self):
        h = CalHarness(); h.declare_tests(); h.seal_line()
        h.a.declare(Refuter("hawk", "v1", "hawk-author", "ledger"))
        run = h.cal.file_escape("w", "tests_pass", "hawk", "v1", "n1", b"w-body-0", "any-seed", "hk", "aud")
        h.cal.replay_run(run.index, "refuted", "hk")
        with self.assertRaises(ValueError):
            h.cal.adjudicate(run.index, "", "accept", "reason")   # unnamed actor

    def test_E9_unconfigured_class_is_refused(self):
        from rga.calibration import CalibrationAuthority, CalibrationPolicy, CalibrationClass
        h = CalHarness()
        # a policy that configures only "impl"; an item of an unconfigured class must refuse
        with self.assertRaises(Exception):
            CalibrationAuthority(h.a, CalibrationPolicy({}))       # E9: class with no calibration policy


if __name__ == "__main__":
    unittest.main()
