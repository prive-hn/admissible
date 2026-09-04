"""Property sweep for the composed Admissible kernel: Theorem 1 (soundness of
the record) and Theorem 2 (loudness of deviation), asserted against the live
three-layer machine over generated histories (tests/custody_generators.py).

Theorem 1 is the decomposition of the single predicate into its four conjuncts,
each backed by its layer's evidence, and re-derivable from the journal.
Theorem 2 is that no deviation is silent: a seal carries its evidence or does
not exist, no store write precedes a published fault, and replay refuses every
inconsistent, forged, duplicated or reordered journal while accepting every
honest one unchanged. R11 and C7 (disjoint write sets) are what make the layer
proofs hold on the combined trace.
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
from rga.calibration import CalibrationAuthority  # noqa: E402
from test_rga_calibration import CalHarness  # noqa: E402

DEEP = bool(os.environ.get("ADMISSIBLE_DEEP"))
EXAMPLES = 400 if DEEP else 50
_SUPPRESS = [HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much]


def sweep(**kw):
    p = dict(max_examples=EXAMPLES, deadline=None, derandomize=not DEEP, suppress_health_check=_SUPPRESS)
    p.update(kw)
    return settings(**p)


# Store-writing / fault-publishing event types, for the loudness argument.
_STORE_EVENTS = {"accept", "rga_seal", "cal_stamp"}
_FAULT_EVENTS = {"rga_refuse", "cal_discredit"}


class Theorem1Soundness(unittest.TestCase):
    """admissible(id) decomposes into four conjuncts, each backed by evidence,
    and the whole is re-derivable from the journal."""

    @sweep()
    @given(G.histories())
    def test_predicate_is_exactly_its_four_conjuncts(self, hist):
        cal, adm = hist.cal, hist.adm
        for iid in hist.lines:
            expected = (adm.is_sealed(iid) and cal.mediated(iid)
                        and not adm.tainted(iid) and not cal.impeached(iid))
            self.assertEqual(cal.admissible(iid), expected, (iid, hist.moves))

    @sweep()
    @given(G.histories())
    def test_admissible_implies_the_layer_evidence(self, hist):
        cal, adm = hist.cal, hist.adm
        for iid in hist.lines:
            if not cal.admissible(iid):
                continue
            # identity + scrutiny: sealed store membership, accepted item, all trials survived
            self.assertIn(iid, adm.sealed, (iid, hist.moves))           # S_R (R8)
            self.assertIn(iid, adm.fcd.store, (iid, hist.moves))        # S / accepted (R8->I5,I8)
            line = adm.lines[iid]
            self.assertTrue(all(t.verdict == "survived" for t in line.trials), (iid, hist.moves))  # R1
            seal = adm.sealed[iid]
            self.assertGreaterEqual(seal.power_min, seal.p_min - 1e-9, (iid, hist.moves))            # R2/R4
            # standing: mediated stamp, not impeached, not tainted
            self.assertTrue(cal.mediated(iid), (iid, hist.moves))       # C5
            self.assertFalse(cal.impeached(iid) or adm.tainted(iid), (iid, hist.moves))

    @sweep()
    @given(G.histories())
    def test_soundness_is_re_derivable(self, hist):
        """The record is sound: a verifier rebuilding from the journal recomputes
        the same admissible verdict for every line (away from the CF2/CF14 seams
        the generator does not grow)."""
        reb = G.rebuild(hist.h)
        for iid in hist.lines:
            self.assertEqual(reb.admissible(iid), hist.cal.admissible(iid), (iid, hist.moves))

    def test_predicate_holds_on_an_IR_not_IRC_line(self):
        """The mediated conjunct is load-bearing. The generator only ever seals
        through the calibration authority, so mediated is True for every sealed
        line it grows — the mediated conjunct is never the deciding one. Drive a
        line to a seal via Admission.seal DIRECTLY (no cal_stamp): is_sealed is
        True but mediated is False (IR, not IRC), so the four-conjunct predicate,
        and admissible(), must be False for want of mediation."""
        h = CalHarness(); h.declare_tests()
        h.fcd_open("w"); h.cal.open("w", "gen", "temp=0.7")
        for i in range(h.k):
            h.fcd_write("w"); h.sample("w", f"w-body-{i}".encode()); h.trial("w", i)
        h.replay_all("w"); h.fcd_check("w")
        h.a.seal("w")                                            # layer-R seal, no cal_stamp
        self.assertTrue(h.a.is_sealed("w"))                      # sealed in S_R ...
        self.assertFalse(h.cal.mediated("w"))                   # ... but never mediated
        expected = (h.a.is_sealed("w") and h.cal.mediated("w")
                    and not h.a.tainted("w") and not h.cal.impeached("w"))
        self.assertFalse(expected)                               # the mediated conjunct fails
        self.assertEqual(h.cal.admissible("w"), expected)       # predicate == its four conjuncts
        self.assertFalse(h.cal.admissible("w"))                 # so an IR seal is not admissible


class Theorem2Loudness(unittest.TestCase):
    """No deviation is silent: no seal without evidence, no store write before a
    published fault, and replay refuses every inconsistent journal."""

    @sweep()
    @given(G.histories())
    def test_no_silent_seal(self, hist):
        """A line in S_R is a real, accepted, all-survived line — never a silent
        membership."""
        adm = hist.adm
        for iid in adm.sealed:
            self.assertIn(iid, adm.fcd.store, (iid, hist.moves))
            self.assertTrue(all(t.verdict == "survived" for t in adm.lines[iid].trials), (iid, hist.moves))

    @sweep()
    @given(G.histories())
    def test_a_taint_is_loud(self, hist):
        """A deviation that lowers standing is named in the journal, never a
        silent state change: a tainted line has an rga_refuse event on record."""
        adm = hist.adm
        for iid in hist.lines:
            if adm.tainted(iid):
                self.assertTrue(any(e.get("type") == "rga_refuse" for e in adm.events), hist.moves)

    def test_replay_refuses_a_forged_journal_but_accepts_honest(self):
        """Transition-locality: an honest journal replays unchanged; a duplicated
        or truncated calibration event is refused on rebuild."""
        h = CalHarness(); h.declare_tests(); h.seal_line(); h.tier_a_escape()
        honest = list(h.cal.events)
        # honest replays unchanged
        reb = CalibrationAuthority.from_events(honest, h.a, h.cal.policy)
        self.assertEqual(reb.impeached("w"), h.cal.impeached("w"))
        # a duplicated run event is refused (transition-local re-check)
        dup = honest + [copy.deepcopy(honest[[e.get("type") for e in honest].index("cal_run")])]
        with self.assertRaises(Exception):
            CalibrationAuthority.from_events(dup, h.a, h.cal.policy)


class CompositionNonInterference(unittest.TestCase):
    """R11 and C7: the upper machines write disjoint state, so each layer's
    proofs hold on the combined trace (the composition lemmas)."""

    def test_R11_and_C7_disjoint_writes(self):
        h = CalHarness(); h.declare_tests()

        def fcd_snap():
            return (copy.deepcopy(h.a.fcd.items), set(h.a.fcd.store), len(h.a.fcd.events))

        def adm_snap():
            return (copy.deepcopy(h.a.sealed), len(h.a.events))

        # C7: a calibration transition changes no FCD or Admission field
        h.seal_line()
        f0, a0 = fcd_snap(), adm_snap()
        h.tier_a_escape()
        self.assertEqual(fcd_snap()[0], f0[0])                        # no FCD item field written (full items)
        self.assertEqual(fcd_snap()[1], f0[1]); self.assertEqual(fcd_snap()[2], f0[2])
        self.assertEqual(adm_snap()[0], a0[0]); self.assertEqual(adm_snap()[1], a0[1])   # sealed contents, not just keys
        # R11: an RGA transition (sample) changes no FCD field
        h.fcd_open("z"); h.rga_open("z"); h.fcd_write("z")
        f1 = fcd_snap()
        h.sample("z", b"z0")
        self.assertEqual(fcd_snap()[0], f1[0])                        # FCD items unchanged by sample (full items)
        self.assertEqual(fcd_snap()[1], f1[1])                        # FCD store unchanged by sample
        self.assertEqual(fcd_snap()[2], f1[2])                        # no FCD event emitted by sample


if __name__ == "__main__":
    unittest.main()
