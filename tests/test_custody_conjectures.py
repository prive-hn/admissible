"""Conjecture-attack lane: standing adversarial searches against the open
conjectures the custody paper's §9 novelty ledger records.

These do not prove the conjectures — a property test cannot — but they turn each
into a live search that either accumulates evidence on every commit or shrinks a
counterexample.  Two of these mechanisms have paid out before: computing the
polarity table this way is how ``cal_discredit`` and ``rga_refuse`` were caught
mislabelled (§9(i), "wrong twice"), and searching coherent deletions for an
unpriced standing-raise is how CF5 and CF11 were found (§9(iv)).

Conjectures attacked here:
  (i)   the polarity table N3 is complete for ``admissible``;
  (iv)  the anchoring relation T4.1 is complete (every standing-raising coherent
        deletion is priced by the surface or refused by the certificate);
  (ii)  N7's nonce chaining does not weaken B9 (nonces are unique and seeds are
        reproducible functions of their roots).
Conjecture (iii) — T14(b)'s spanning condition — has its executable shadow in
the anchoring search below (every standing-changing deletion must be accounted
for); a full guard-deletion spanning search is the mutation suite's remit
(``tests/test_rga_mutation.py``), cross-referenced rather than duplicated.

Budget: gate runs a modest derandomised search (single-event deletions);
``ADMISSIBLE_DEEP=1`` widens it to more examples and pair deletions, and prints
the empirical polarity table it observed.
"""
from __future__ import annotations

import itertools
import os
import sys
import unittest

from hypothesis import HealthCheck, given, settings

HERE = os.path.dirname(__file__)
for _p in (os.path.join(HERE, ".."), HERE, os.path.join(HERE, "..", "paper", "custody")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import custody  # noqa: E402
import custody_generators as G  # noqa: E402
from rga.core import derive_seed  # noqa: E402
from rga.calibration import CalibrationAuthority  # noqa: E402
from test_rga_invariants import D1, K, TESTS  # noqa: E402

DEEP = bool(os.environ.get("ADMISSIBLE_DEEP"))
EXAMPLES = 600 if DEEP else 60
_SUPPRESS = [HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much]


def attack(**kw):
    params = dict(max_examples=EXAMPLES, deadline=None, derandomize=not DEEP,
                  suppress_health_check=_SUPPRESS)
    params.update(kw)
    return settings(**params)


_SIGN = {"+": {0, 1}, "e": {0, 1}, "-": {-1, 0}, "0": {0}, "±": {-1, 0, 1}, "?": {-1, 0, 1}}


# -- Conjecture (i): the polarity table is complete for `admissible` -----------

class PolarityCompletenessI(unittest.TestCase):

    @attack()
    @given(G.histories())
    def test_every_reachable_event_type_is_classified(self, hist):
        """Completeness's first obligation: the table names every event type the
        machines actually emit.  A new, unclassified event type (polarity '?')
        is a gap the table does not yet cover."""
        for journal in (hist.fcd.events, hist.adm.events, hist.cal.events):
            for ev in journal:
                t = ev.get("type")
                self.assertNotEqual(custody.polarity_of(t), "?",
                                    f"unclassified event type {t!r} (moves: {hist.moves})")

    @attack()
    @given(G.histories())
    def test_observed_signs_never_contradict_the_declared_polarity(self, hist):
        """The empirical sign set of each standing-journal event type must lie
        inside what its declared polarity allows.  A '+' that ever lowers, or a
        '0' that ever moves, admissible refutes the table (§9(i))."""
        cal, adm = hist.cal, hist.adm
        evs = list(cal.events)
        observed: dict[str, set] = {}
        for line in hist.sealed:
            prev, prev_ok = None, False
            for j in range(len(evs) + 1):
                try:
                    sub = CalibrationAuthority.from_events(evs[:j], adm, cal.policy)
                    val, ok = int(sub.admissible(line)), True
                except Exception:
                    val, ok = None, False
                if j > 0 and ok and prev_ok:
                    t = evs[j - 1].get("type")
                    observed.setdefault(t, set()).add(max(-1, min(1, val - prev)))
                prev, prev_ok = val, ok
        for t, signs in observed.items():
            allowed = _SIGN[custody.polarity_of(t)]
            self.assertTrue(signs <= allowed,
                            f"{t}: observed {sorted(signs)} outside declared "
                            f"{custody.polarity_of(t)} {sorted(allowed)} (moves: {hist.moves})")

    def test_rga_refuse_exhibits_both_signs_so_pm_is_neither_over_nor_understated(self):
        """rga_refuse is labelled '±' (§9's other mislabel).  A targeted probe
        that it genuinely both lowers standing (taint) and raises it (CF1's
        second path), so neither a '-' nor a '+' would be correct.  The raise
        path mirrors tests/test_custody.py::FindingCF1RefusalPath."""
        from test_rga_calibration import CalHarness
        from rga.core import AdmissionPolicy, ClassAdmission, ClaimSpec, DefectModel, LedgerEntry, Refuter
        # -- lower path: refusing a pinned checker taints a seal that pinned it --
        h = CalHarness(); h.declare_tests(); h.seal_line()
        self.assertTrue(h.cal.admissible("w"))
        h.fcd_open("z"); h.a.open("z", "gen", "temp=0.7")
        h.fcd_write("z"); h.sample("z", b"z0"); h.trial("z")
        h.a.replay("z", 0, "refuted", "w-same")            # rga_refuse: taints -> lowers
        self.assertFalse(h.cal.admissible("w"))
        # -- raise path: a tier-B checker impeaches w, then is refused elsewhere --
        g = CalHarness(e_max=0); g.declare_tests(); g.seal_line()
        g.a.declare(Refuter("hawk", "v1", "hawk-author", "ledger"))
        run = g.cal.file_escape("w", "tests_pass", "hawk", "v1", "n1", b"w-body-0", "any-seed", "hk", "aud")
        g.cal.replay_run(run.index, "refuted", "hk")
        g.cal.adjudicate(run.index, "owner", "accept", "reproduced by hand")
        self.assertTrue(g.cal.impeached("w"))              # impeached by hawk's accepted escape
        g.a.measure("hawk", "v1", DefectModel("d-hawk", "mutator"), [LedgerEntry("m0", "killed")])
        pol = AdmissionPolicy({"impl": ClassAdmission(
            claims=(ClaimSpec("tests_pass", "spec-hash-1", frozenset({TESTS, ("hawk", "v1")}), D1),),
            k=K, theta=1.0, p_min=0.5, excluded=frozenset({"refuter_source", "refuter_results"}),
            residual=(("correct fix", "check_stage"),))}, version="r2")
        g.a.install(pol)
        g.fcd_open("z"); g.a.open("z", "gen", "temp=0.7")
        g.fcd_write("z"); g.sample("z", b"z0"); g.trial("z", 0, refuter=("hawk", "v1"))
        g.a.replay("z", 0, "refuted", "w-same")            # rga_refuse of hawk: raises w
        self.assertIn(("hawk", "v1"), g.a.refused)
        self.assertTrue(g.cal.admissible("w"))


# -- Conjecture (iv): the anchoring relation T4.1 is complete ------------------

class AnchoringCompletenessIV(unittest.TestCase):
    """Every coherent deletion that RAISES standing must be accounted for: the
    deleted event is named on the deletion surface, or the line-scoped
    certificate refuses the forged record.  An unpriced standing-raise is a
    missed anchoring residue — the class of CF5 and CF11."""

    def _assert_priced(self, hist, iid, drop_idx, cert, before):
        pruned = [e for k, e in enumerate(hist.cal.events) if k not in drop_idx]
        try:
            forged = CalibrationAuthority.from_events(pruned, hist.adm, hist.cal.policy)
        except Exception:
            return                                          # deletion left L_rep
        after = forged.admissible(iid)
        if after and not before:                            # a standing-raise
            surface_idx = {s.index for s in custody.deletion_surface(hist.cal, iid)
                           if s.journal == "cal"}
            on_surface = bool(drop_idx & surface_idx)
            caught = custody.verify_certificate(forged, cert) != []
            self.assertTrue(on_surface or caught,
                            f"unpriced standing-raise on {iid} by deleting "
                            f"cal events {sorted(drop_idx)} "
                            f"({[hist.cal.events[i].get('type') for i in drop_idx]}); "
                            f"moves: {hist.moves}")

    @attack()
    @given(G.histories())
    def test_no_unpriced_standing_raise(self, hist):
        for iid in hist.sealed:
            before = hist.cal.admissible(iid)
            if before:
                continue                                    # already standing; nothing to raise
            cert = custody.standing_certificate(hist.cal, iid)
            n = len(hist.cal.events)
            for k in range(n):                              # single-event deletions
                self._assert_priced(hist, iid, {k}, cert, before)
            if DEEP:
                for a, b in itertools.combinations(range(n), 2):   # pair deletions
                    self._assert_priced(hist, iid, {a, b}, cert, before)


# -- Conjecture (ii): N7 nonce chaining does not weaken B9 ---------------------

class NonceChainingII(unittest.TestCase):
    """B9: nonces are read from the journal and never redrawn.  A chained nonce
    must stay unique per line, and every recorded seed must be the deterministic
    function of its roots that replay recomputes."""

    @attack()
    @given(G.histories())
    def test_sample_nonces_unique_and_seeds_reproducible(self, hist):
        by_line: dict[str, list] = {}
        for ev in hist.adm.events:
            if ev.get("type") == "rga_sample":
                by_line.setdefault(ev.get("work_item_id"), []).append(ev.get("nonce"))
        for iid, nonces in by_line.items():
            self.assertEqual(len(nonces), len(set(nonces)), (iid, nonces))
        # every filed escape seed re-derives from (nonce, artifact, checker, claim)
        for run in hist.cal.runs:
            recomputed = derive_seed(run.nonce, run.artifact_hash,
                                     run.checker[0], run.checker[1], run.claim_id)
            if run.seed is not None and run.seed != "any-seed":
                self.assertEqual(run.seed, recomputed, run)


if __name__ == "__main__":
    unittest.main()
