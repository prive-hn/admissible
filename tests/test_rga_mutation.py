"""Delete the guard; prove the invariant goes red.

GUARDS maps every guard and check method in rga/core.py to the fault it
enforces (paper/RGA/INVARIANTS.md §5, V1–V15) and a scenario that reaches
that fault's forbidden state when THAT METHOD ALONE is replaced by a no-op.
Each test asserts two things:

  intact:  the forbidden state is unreachable;
  deleted: it is reached.

JOINT covers theorems that two guards enforce together (a refuted trial both
publishes a close at Trial and is refused at Seal): deleting both reaches the
theorem-level forbidden state.

test_every_guard_method_has_a_scenario fails if a guard method exists in the
kernel that no scenario here turns red; test_every_fault_has_a_scenario fails
if any fault V1–V15 has no scenario.
"""
from __future__ import annotations

import os
import sys
import unittest
from contextlib import ExitStack
from unittest.mock import patch

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

from fcd.core import Enforcer, Policy  # noqa: E402
from rga.core import Admission, DefectModel, LedgerEntry, Refuter, derive_seed, sha256  # noqa: E402
from test_rga_invariants import D1, K, TESTS, Harness, ledger  # noqa: E402


def noop(*args, **kwargs):
    return None


def never_closes(*args, **kwargs):
    return True


def never_diverges(*args, **kwargs):
    return False


def attempt(fn):
    """Run a scenario body; a guard refusal is 'forbidden state unreachable'."""
    try:
        return bool(fn())
    except (ValueError, AssertionError, AttributeError, TypeError):
        return False


# -- per-guard scenarios ---------------------------------------------------------

def s_check_refuted():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample()
        h.trial(verdict="refuted")
        return h.a.lines["w"].pc == "Open"          # refutation not published
    return attempt(body)


def s_check_inconclusive():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample()
        h.trial(verdict="inconclusive")
        return h.a.lines["w"].pc == "Open"
    return attempt(body)


def s_check_concordance():
    def body():
        h = Harness(theta=1.0); h.declare_tests()
        h.run_to_seal_ready(witnesses=["w-a", "w-a", "w-b"])
        h.a.seal("w")
        return "w" in h.a.sealed and h.a.sealed["w"].claims[0].agreeing < K
    return attempt(body)


def s_check_replay():
    def body():
        h = Harness(); h.declare_tests()
        h.run_to_seal_ready()
        h.a.replay("w", 0, "refuted", "w-other")    # diverges from the recorded survival
        if TESTS in h.a.refused:
            return False
        h.a.seal("w")
        return "w" in h.a.sealed
    return attempt(body)


def s_check_power_floor():
    def body():
        h = Harness(p_min=0.95); h.declare_tests(kills=9, size=10)
        h.run_to_seal_ready()
        h.a.seal("w")
        return "w" in h.a.sealed and h.a.sealed["w"].power_min < 0.95
    return attempt(body)


def s_guard_replay_verdict():
    def body():
        from rga.core import VERDICTS
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample(); h.trial()
        h.a.replay("w", 0, "maybe", "w-same")   # out-of-enum verdict
        return any(e["type"] == "rga_replay" and e["verdict"] not in VERDICTS
                   for e in h.a.events)
    return attempt(body)


def s_guard_not_refused():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample(); h.trial()
        h.a.replay("w", 0, "refuted", "w-same")     # diverges -> tests refused
        h.a.measure("tests", "v1", DefectModel("d2", "mutator"), ledger(9, 10))
        return ("tests", "v1", "d2") in h.a.power   # refused refuter re-measured
    return attempt(body)


def s_guard_pinned_before_open():
    def body():
        h = Harness(); h.declare_tests(author="gen")   # refuter authored by the generator
        h.fcd_open(); h.rga_open()
        return "w" in h.a.lines
    return attempt(body)


def s_guard_open_before_generation():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.fcd_write()                    # sample stage attempted first
        h.rga_open()
        return "w" in h.a.lines
    return attempt(body)


def s_guard_sample_count():
    def body():
        h = Harness(writes=K + 1); h.declare_tests()   # FCD has k+1 write stages
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode())
        h.fcd_write()                                  # stage K passes too
        h.sample(body=b"extra")
        return len(h.a.lines["w"].samples) > K
    return attempt(body)


def s_guard_sample_stage():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open()
        h.e.admit("w", "gen"); h.e.bind("w", True); h.e.observe("w", "vendorX:other"); h.e.decide_pass("w")
        h.sample()
        return len(h.a.lines["w"].samples) == 1 and h.e.items["w"].stages[0].pc != "Passed"
    return attempt(body)


def s_guard_sample_package():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write()
        h.sample(categories=("contract", "refuter_source"))
        return len(h.a.lines["w"].samples) == 1
    return attempt(body)


def s_guard_sample_order():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open()
        h.fcd_write(); h.fcd_write()                   # stage 1 attempted before sample 0
        h.sample()
        return len(h.a.lines["w"].samples) == 1
    return attempt(body)


def s_guard_trial_pinned():
    def body():
        h = Harness(); h.declare_tests()
        h.a.declare(Refuter("rogue", "v1", "someone", "ledger"))
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample()
        seed = h.a.seed_for("w", 0, "rogue", "v1", "tests_pass")
        h.a.trial("w", "rogue", "v1", "tests_pass", 0, seed, "inputs", "survived", "w")
        return any(t.refuter_id == "rogue" for t in h.a.lines["w"].trials)
    return attempt(body)


def s_guard_trial_seed():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); s = h.sample(body=b"bytes")
        bad = derive_seed(s.nonce, sha256(b"other"), "tests", "v1", "tests_pass")
        h.trial(seed=bad)
        return h.a.lines["w"].trials[0].seed == bad
    return attempt(body)


def s_guard_trial_once():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample()
        h.trial(); h.trial()
        return len(h.a.lines["w"].trials) == 2
    return attempt(body)


def s_guard_power_once():
    def body():
        h = Harness(); h.declare_tests(kills=5, size=10)
        h.a.measure("tests", "v1", DefectModel(D1, "mutator"), ledger(10, 10))
        return h.a.power[("tests", "v1", D1)].power == 1.0
    return attempt(body)


def s_guard_bound_once():
    def body():
        h = Harness()
        h.a.declare(Refuter("pbt", "v1", "tester", "bounded"))
        h.a.bound("pbt", "v1", 0.5, 1)
        h.a.bound("pbt", "v1", 1.0, 1)
        return h.a.power[("pbt", "v1", None)].power == 1.0
    return attempt(body)


def s_guard_model_author_fixed():
    def body():
        h = Harness(); h.declare_tests()               # first record: (D1, 'mutator')
        h.a.declare(Refuter("lint", "v1", "linter", "ledger"))
        h.a.measure("lint", "v1", DefectModel(D1, "gen"), ledger(9, 10))
        return ("lint", "v1", D1) in h.a.power         # same hash, second author
    return attempt(body)


def s_guard_independent_model():
    def body():
        h = Harness()
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        h.a.measure("tests", "v1", DefectModel(D1, "tester"), ledger(9, 10))   # D by the refuter's author
        return ("tests", "v1", D1) in h.a.power
    return attempt(body)


def s_guard_seal_complete():
    def body():
        h = Harness(theta=0.6); h.declare_tests()
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode())
            if i < K - 1:
                h.trial(i=i)                           # sample 2 never tried
        h.replay_all(); h.fcd_check()
        h.a.seal("w")
        return "w" in h.a.sealed and len(h.a.lines["w"].trials) < K
    return attempt(body)


def s_guard_seal_replayed():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode()); h.trial(i=i)
        h.fcd_check()
        h.a.seal("w")
        return "w" in h.a.sealed and all(t.replays == 0 for t in h.a.lines["w"].trials)
    return attempt(body)


def s_guard_seal_measured():
    def body():
        h = Harness(p_min=0.0)
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))   # never measured
        h.run_to_seal_ready()
        h.a.seal("w")
        return "w" in h.a.sealed and h.a.sealed["w"].claims[0].refuters[0].size is None
    return attempt(body)


def s_guard_seal_independent():
    def body():
        h = Harness()
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        h.fcd_open(); h.rga_open()                                   # no D record yet
        h.a.measure("tests", "v1", DefectModel(D1, "gen"), ledger(9, 10))   # D by the generator, after Open
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode()); h.trial(i=i)
        h.replay_all(); h.fcd_check()
        h.a.seal("w")
        return "w" in h.a.sealed
    return attempt(body)


def s_guard_seal_accepted():
    def body():
        h = Harness(residual=(("correct fix", "unreviewed"),)); h.declare_tests()
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode()); h.trial(i=i)
        h.replay_all()                                               # no FCD check -> not in S
        h.a.seal("w")
        return "w" in h.a.sealed and "w" not in h.e.store
    return attempt(body)


def s_guard_seal_residual():
    def body():
        h = Harness(k=1, residual=(("correct fix", "check_stage"),)); h.declare_tests()
        h.e = Enforcer(Policy(allow={"impl": {"gen"}}, deny={"impl": set()},
                              phi={"gen": "vendorA:model-g"},
                              required={"impl": [("write", "s0")]}, version="v1"))
        h.a.fcd = h.e
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample(); h.trial(); h.replay_all()
        h.a.seal("w")                                                # in S with no check stage at all
        return "w" in h.a.sealed and h.a.sealed["w"].residual == (("correct fix", "check_stage"),)
    return attempt(body)


GUARDS: dict[str, tuple[str, object, object]] = {
    # guard method                    fault  replacement     scenario
    "_check_refuted":                 ("V1", noop,           s_check_refuted),
    "_check_concordance":             ("V2", never_closes,   s_check_concordance),
    "_check_inconclusive":            ("V3", noop,           s_check_inconclusive),
    "_check_replay":                  ("V4", never_diverges, s_check_replay),
    "_guard_not_refused":             ("V4", noop,           s_guard_not_refused),
    "_guard_replay_verdict":          ("V4", noop,           s_guard_replay_verdict),
    "_check_power_floor":             ("V5", never_closes,   s_check_power_floor),
    "_guard_sample_stage":            ("V6", noop,           s_guard_sample_stage),
    "_guard_sample_package":          ("V7", noop,           s_guard_sample_package),
    "_guard_open_before_generation":  ("V8", noop,           s_guard_open_before_generation),
    "_guard_sample_order":            ("V8", noop,           s_guard_sample_order),
    "_guard_trial_pinned":            ("V8", noop,           s_guard_trial_pinned),
    "_guard_trial_seed":              ("V9", noop,           s_guard_trial_seed),
    "_guard_seal_complete":           ("V10", noop,          s_guard_seal_complete),
    "_guard_seal_replayed":           ("V11", noop,          s_guard_seal_replayed),
    "_guard_seal_measured":           ("V12", noop,          s_guard_seal_measured),
    "_guard_power_once":              ("V13", noop,          s_guard_power_once),
    "_guard_bound_once":              ("V13", noop,          s_guard_bound_once),
    "_guard_sample_count":            ("V13", noop,          s_guard_sample_count),
    "_guard_trial_once":              ("V13", noop,          s_guard_trial_once),
    "_guard_model_author_fixed":      ("V13", noop,          s_guard_model_author_fixed),
    "_guard_pinned_before_open":      ("V14", noop,          s_guard_pinned_before_open),
    "_guard_independent_model":       ("V14", noop,          s_guard_independent_model),
    "_guard_seal_independent":        ("V14", noop,          s_guard_seal_independent),
    "_guard_seal_accepted":           ("V15", noop,          s_guard_seal_accepted),
    "_guard_seal_residual":           ("V15", noop,          s_guard_seal_residual),
}


# -- joint scenarios: theorems two guards enforce together ------------------------------

def j_v1():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode())
            h.trial(i=i, verdict="refuted" if i == 1 else "survived")
        if h.a.lines["w"].pc != "Open":
            return False
        h.replay_all(); h.fcd_check()
        h.a.seal("w")
        return "w" in h.a.sealed and any(t.verdict == "refuted" for t in h.a.lines["w"].trials)
    return attempt(body)


def j_v3():
    def body():
        h = Harness(); h.declare_tests()
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode())
            h.trial(i=i, verdict="inconclusive" if i == 2 else "survived")
        if h.a.lines["w"].pc != "Open":
            return False
        h.replay_all(); h.fcd_check()
        h.a.seal("w")
        return "w" in h.a.sealed and any(t.verdict == "inconclusive" for t in h.a.lines["w"].trials)
    return attempt(body)


JOINT: dict[str, tuple[list[str], object]] = {
    "V1": (["_check_refuted", "_guard_seal_complete"], j_v1),
    "V3": (["_check_inconclusive", "_guard_seal_complete"], j_v3),
}


def deleted(names):
    stack = ExitStack()
    for name in names:
        stack.enter_context(patch.object(Admission, name, GUARDS[name][1]))
    return stack


class GuardDeletionTests(unittest.TestCase):
    """One test per guard: unreachable with it, reachable without it."""

    def _one(self, name: str) -> None:
        fault, _, scenario = GUARDS[name]
        self.assertFalse(scenario(), f"{fault}/{name}: forbidden state reachable with the guard intact")
        with deleted([name]):
            self.assertTrue(scenario(), f"{fault}/{name}: deleting the guard did not go red")

    def _joint(self, fault: str) -> None:
        names, scenario = JOINT[fault]
        self.assertFalse(scenario(), f"{fault}: forbidden state reachable with guards intact")
        with deleted(names):
            self.assertTrue(scenario(), f"{fault}: deleting {names} did not go red")


for _name in GUARDS:
    setattr(GuardDeletionTests, f"test_{GUARDS[_name][0].lower()}_{_name.strip('_')}",
            (lambda n: lambda self: self._one(n))(_name))
for _fault in JOINT:
    setattr(GuardDeletionTests, f"test_{_fault.lower()}_joint",
            (lambda f: lambda self: self._joint(f))(_fault))


class EveryGuardIsLoadBearing(unittest.TestCase):
    def test_every_guard_method_has_a_scenario(self):
        methods = {n for n in dir(Admission) if n.startswith("_guard_") or n.startswith("_check_")}
        self.assertEqual(methods - set(GUARDS), set(), "guards no scenario turns red")
        self.assertEqual(set(GUARDS) - methods, set(), "scenarios naming no guard")

    def test_every_fault_has_a_scenario(self):
        covered = {fault for fault, _, _ in GUARDS.values()} | set(JOINT)
        self.assertEqual(covered, {f"V{i}" for i in range(1, 16)})


if __name__ == "__main__":
    unittest.main()
