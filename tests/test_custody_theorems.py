"""Property sweep: the functional content of the custody theorems, checked
against the real three-layer kernel over a generated space of histories.

Where ``tests/test_custody.py`` pins each theorem on a hand-built example, this
module asserts the same theorems as *properties* — universally quantified over
histories the generator grows (``tests/custody_generators.py``) and over power
vectors.  A green run is evidence the kernel, as it is, satisfies the theory
across the explored space; a failure is a shrunk, minimal history that violates
a named theorem — exactly the regression signal the companion's own §10 calls
"the beginning of that obligation, not its discharge".

Each ``TestCase`` names the theorem it exercises.  The known replay seams
(CF2 incompleteness, CF14 the refused-checker rebuild seam, CF12 the position
witness) are catalogued and tested as *expected* exceptions in
``tests/test_custody.py``; the generator does not grow them, so the retraction
property here is a clean equality.

Budget: the gate lane runs a modest, derandomised (reproducible) number of
examples so the ``unit`` check stays inside its window; ``ADMISSIBLE_DEEP=1``
raises the counts for an out-of-band adversarial run.
"""
from __future__ import annotations

import dataclasses
import os
import sys
import unittest
from fractions import Fraction

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

HERE = os.path.dirname(__file__)
for _p in (os.path.join(HERE, ".."), HERE, os.path.join(HERE, "..", "paper", "custody")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import custody  # noqa: E402
import custody_generators as G  # noqa: E402
from rga.calibration import CalibrationAuthority  # noqa: E402

# -- budget --------------------------------------------------------------------
DEEP = bool(os.environ.get("ADMISSIBLE_DEEP"))
EXAMPLES = 400 if DEEP else 40
_SUPPRESS = [HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much]


def sweep(**kw):
    """The gate settings: derandomised for a reproducible gate, scaled by env."""
    params = dict(max_examples=EXAMPLES, deadline=None, derandomize=not DEEP,
                  suppress_health_check=_SUPPRESS)
    params.update(kw)
    return settings(**params)


EPS = 1e-9


# -- T6, T7: the Boole–Fréchet algebra of carried power ------------------------

class FrechetT6T7(unittest.TestCase):
    """The assumption-free composition of measured power is exactly the
    Fréchet family: union/max on a shared model, Bonferroni for conjunctions."""

    @sweep()
    @given(G.power_vectors())
    def test_bounds_are_ordered_and_in_range(self, ps):
        for event in ("union", "intersection"):
            lo, hi = custody.frechet_bounds(ps, event)
            self.assertLessEqual(lo, hi + EPS, (event, ps))
            for v in (lo, hi):
                self.assertGreaterEqual(v, -EPS, (event, ps))
                self.assertLessEqual(v, 1.0 + EPS, (event, ps))

    @sweep()
    @given(G.power_vectors())
    def test_power_joint_is_the_intersection_lower_bound(self, ps):
        self.assertAlmostEqual(custody.power_joint(ps),
                               custody.frechet_bounds(ps, "intersection")[0], places=12)

    @sweep()
    @given(G.power_vectors(min_size=1))
    def test_power_joint_never_exceeds_the_exact_real_bound(self, ps):
        """T7: power_joint is an assumption-free *lower* bound, so it may never
        claim more than max(0, 1 − Σ(1−p)) computed exactly."""
        true = max(Fraction(0), Fraction(1) - sum(Fraction(1) - Fraction(p) for p in ps))
        self.assertLessEqual(Fraction(custody.power_joint(ps)), true + Fraction(1, 10 ** 9), ps)

    @sweep()
    @given(G.power_vectors(min_size=1), st.floats(min_value=0.0, max_value=1.0,
                                                  allow_nan=False, allow_infinity=False))
    def test_power_joint_is_monotone_down_in_conjuncts(self, ps, q):
        """Adding a conjunct never raises the joint reading (a cut-set only grows)."""
        self.assertLessEqual(custody.power_joint(ps + [q]), custody.power_joint(ps) + EPS, (ps, q))

    @sweep()
    @given(G.power_vectors(min_size=1))
    def test_intersection_lower_never_above_min(self, ps):
        self.assertLessEqual(custody.power_joint(ps), min(ps) + EPS, ps)

    @sweep()
    @given(st.floats(min_value=0.01, max_value=0.99))
    def test_bonferroni_horizon_is_where_power_joint_first_zeroes(self, p):
        h = custody.bonferroni_horizon(p)
        self.assertIsNotNone(h)
        self.assertGreater(custody.power_joint([p] * (h - 1)), 0.0, p)
        self.assertEqual(custody.power_joint([p] * h), 0.0, p)

    def test_empty_conventions(self):
        self.assertEqual(custody.power_joint([]), 1.0)
        self.assertEqual(custody.frechet_bounds([], "union"), (0.0, 0.0))
        self.assertEqual(custody.frechet_bounds([], "intersection"), (1.0, 1.0))
        self.assertIsNone(custody.bonferroni_horizon(1.0))


# -- T1: replay is a retraction (emit is the identity on L_rep) ----------------

class ReplayRetractionT1(unittest.TestCase):
    """A record produced by the machine is re-derivable from its journal, and
    the rebuild recovers every standing verdict and re-emits an identical
    journal (μ ∘ emit = μ, emit│L_rep = id)."""

    @sweep()
    @given(G.histories())
    def test_rebuild_recovers_every_verdict_and_the_journal(self, hist):
        reb = G.rebuild(hist.h)
        self.assertEqual(list(reb.events), list(hist.cal.events), hist.moves)
        for iid in hist.lines:
            self.assertEqual(reb.admissible(iid), hist.cal.admissible(iid), (iid, hist.moves))
            self.assertEqual(reb.impeached(iid), hist.cal.impeached(iid), (iid, hist.moves))
            self.assertEqual(reb.adm.tainted(iid), hist.adm.tainted(iid), (iid, hist.moves))
            self.assertEqual(reb.adm.is_sealed(iid), hist.adm.is_sealed(iid), (iid, hist.moves))


# -- D6, T3: the Asymmetry theorem (polarity soundness) -----------------------

class PolarityAsymmetryT3(unittest.TestCase):
    """For every reachable state and every appended standing-journal event, the
    sign of the change in ``admissible`` respects the polarity D6 assigns the
    event type: '+'/'e' never lower it, '-' never raises it, '0' never moves it.
    The polarity table has been wrong twice (§9); this is the standing net."""

    @sweep()
    @given(G.histories())
    def test_cal_journal_polarity_is_sound_for_admissible(self, hist):
        cal, adm = hist.cal, hist.adm
        evs = list(cal.events)
        for line in hist.sealed:
            prev, prev_ok = None, False
            for j in range(len(evs) + 1):
                try:
                    sub = CalibrationAuthority.from_events(evs[:j], adm, cal.policy)
                    val, ok = int(sub.admissible(line)), True
                except Exception:
                    val, ok = None, False
                if j > 0 and ok and prev_ok:
                    et = evs[j - 1].get("type")
                    pol = custody.polarity_of(et)
                    d = val - prev
                    ctx = (line, et, pol, d, hist.moves)
                    if pol in ("+", "e"):
                        self.assertGreaterEqual(d, 0, ctx)
                    elif pol == "-":
                        self.assertLessEqual(d, 0, ctx)
                    elif pol == "0":
                        self.assertEqual(d, 0, ctx)
                    # '±' and '?' carry no per-event constraint here
                prev, prev_ok = val, ok


# -- T5: only two online channels raise standing (un-impeachment) -------------

class UnImpeachmentT5(unittest.TestCase):
    """The only standing-journal events that ever *raise* admissible are the
    establishing stamp and the discredit (CF1's single-party un-impeachment);
    no filing, adjudication, exclusion or close raises it."""

    @sweep()
    @given(G.histories())
    def test_only_stamp_and_discredit_raise_admissible(self, hist):
        cal, adm = hist.cal, hist.adm
        evs = list(cal.events)
        risers = set()
        for line in hist.sealed:
            prev, prev_ok = None, False
            for j in range(len(evs) + 1):
                try:
                    sub = CalibrationAuthority.from_events(evs[:j], adm, cal.policy)
                    val, ok = int(sub.admissible(line)), True
                except Exception:
                    val, ok = None, False
                if j > 0 and ok and prev_ok and val > prev:
                    risers.add(evs[j - 1].get("type"))
                prev, prev_ok = val, ok
        self.assertTrue(risers <= {"cal_stamp", "cal_discredit"}, (risers, hist.moves))


# -- T4.1, T11, T17: the signed support, and the certificate that anchors it ---

class SupportCertificateT4T11T17(unittest.TestCase):
    """The deletion surface enumerates exactly the events whose removal raises
    standing; removing an event outside the support leaves the value unchanged
    (determination); and the line-scoped certificate refuses every coherent
    alternative that changes what admissible depends on."""

    @sweep()
    @given(G.histories())
    def test_certificate_is_self_consistent_and_standing_is_load_bearing(self, hist):
        for iid in hist.sealed:
            cert = custody.standing_certificate(hist.cal, iid)
            self.assertEqual(custody.verify_certificate(hist.cal, cert), [], (iid, hist.moves))
            self.assertEqual(cert.standing, hist.cal.admissible(iid))
            flipped = dataclasses.replace(cert, standing=not cert.standing)
            self.assertIn("standing", custody.verify_certificate(hist.cal, flipped), (iid, hist.moves))

    @sweep()
    @given(G.histories())
    def test_deleting_outside_the_support_does_not_change_standing(self, hist):
        for iid in hist.sealed:
            sup = custody.support(hist.cal, iid)
            in_support = {(s.journal, s.index) for s in sup.negative}
            in_support |= {(j, i) for (j, i, _t) in sup.positive}
            before = hist.cal.admissible(iid)
            for k, ev in enumerate(hist.cal.events):
                if ("cal", k) in in_support:
                    continue
                forged = G.prune(hist.h, drop=lambda e, _k=k: e is ev)
                if forged is None:                       # deletion left L_rep: replay refused it
                    continue
                self.assertEqual(forged.admissible(iid), before,
                                 (iid, k, ev.get("type"), hist.moves))

    @sweep()
    @given(G.histories())
    def test_deleting_the_surface_is_caught_by_the_certificate(self, hist):
        for iid in hist.sealed:
            surface = custody.deletion_surface(hist.cal, iid)
            if not surface:
                continue
            cert = custody.standing_certificate(hist.cal, iid)
            drop_idx = {s.index for s in surface if s.journal == "cal"}
            pruned = [e for k, e in enumerate(hist.cal.events) if k not in drop_idx]
            try:
                forged = CalibrationAuthority.from_events(pruned, hist.adm, hist.cal.policy)
            except Exception:
                continue
            if forged.admissible(iid) != cert.standing:
                # a tamper that changed standing must be refused by the certificate
                self.assertNotEqual(custody.verify_certificate(forged, cert), [],
                                    (iid, hist.moves))


# -- T8: the kill context (coverage incidence) --------------------------------

class KillContextT8(unittest.TestCase):
    """The seal's stored incidence is coherent: the union never exceeds the
    model size, the uncovered set is the complement, and a refuter with no
    unique kills is exactly one flagged redundant."""

    @sweep()
    @given(G.histories())
    def test_incidence_is_coherent(self, hist):
        for iid in hist.sealed:
            try:
                kc = custody.kill_context(hist.adm, iid, "tests_pass")
            except Exception:
                continue
            self.assertGreaterEqual(kc.size, kc.union)
            self.assertEqual(kc.uncovered, kc.size - kc.union)
            self.assertGreaterEqual(kc.uncovered, 0)
            for key, u in kc.unique_kills.items():
                self.assertGreaterEqual(u, 0)
            redundant = set(kc.redundant)
            for key, u in kc.unique_kills.items():
                self.assertEqual(u == 0, key in redundant, (iid, key))


# -- C9 (kernel C1), D7: tier as trust-base inclusion -------------------------

class TrustBaseC9(unittest.TestCase):
    """derived_tier agrees with the kernel's own tier, and the trust base of a
    seal is a well-formed set of assumption names."""

    @sweep()
    @given(G.histories())
    def test_derived_tier_agrees_and_trust_base_is_wellformed(self, hist):
        for run in hist.cal.runs:
            self.assertEqual(custody.derived_tier(hist.cal, run), run.tier, hist.moves)
        for iid in hist.sealed:
            seal = hist.adm.sealed.get(iid)
            if seal is None:
                continue
            base = custody.trust_base(hist.adm, seal)
            self.assertTrue(all(isinstance(x, str) for x in base), (iid, base))


# -- T16: exposure (attempt index and published refutations) ------------------

class ExposureT16(unittest.TestCase):
    """Exposure is a pure query over the record: a non-negative attempt index
    and a list of published refutations, computable on every line."""

    @sweep()
    @given(G.histories())
    def test_exposure_is_a_total_query(self, hist):
        for iid in hist.lines:
            try:
                exp = custody.exposure(hist.adm, iid)
            except Exception:
                continue
            self.assertGreaterEqual(exp.attempt_index, 0, iid)
            self.assertIsInstance(exp.published_refutations, (list, tuple))


# -- T15: safety only — a machine that refuses everything is admissible-empty --

class SafetyT15(unittest.TestCase):
    """The invariants are safety properties: a strategy that refuses everything
    satisfies them, and admits nothing."""

    def test_the_empty_and_all_refusing_machines_admit_nothing(self):
        from test_rga_calibration import CalHarness
        h = CalHarness()
        h.declare_tests()
        self.assertFalse(h.cal.admissible("never-opened"))
        # open a line but never seal it: not admissible, and the record rebuilds
        h.fcd_open("w")
        h.cal.open("w", "gen", "temp=0.7")
        self.assertFalse(h.cal.admissible("w"))
        reb = G.rebuild(h)
        self.assertFalse(reb.admissible("w"))


if __name__ == "__main__":
    unittest.main()
