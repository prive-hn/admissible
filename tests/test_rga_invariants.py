"""Executable checks of R1–R13 on the Python machine (paper/RGA/INVARIANTS.md).

Each test drives the same transition guards as rga/core.py. A failing test is
a counterexample to the corresponding claim on the machine. Positive traces
show the antecedent is satisfiable; negative traces show the guard is a
filter that can fail. Delete-the-guard proofs are in test_rga_mutation.py.
Fault codes are V1–V15 (paper/RGA/INVARIANTS.md §5); theorem names are R1–R13.
"""
from __future__ import annotations

import copy
import itertools
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fcd.core import Enforcer, Policy
from rga.core import (
    Admission, AdmissionPolicy, ClaimSpec, ClassAdmission, DefectModel,
    LedgerEntry, Refuter, derive_seed, sha256,
)

K = 3
TESTS = ("tests", "v1")
LINT = ("lint", "v1")
PBT = ("pbt", "v1")
D1 = "d1-hash"


def fcd_policy(k: int = K, writes: int | None = None) -> Policy:
    writes = k if writes is None else writes
    return Policy(
        allow={"impl": {"gen", "gen2", "rev"}},
        deny={"impl": set()},
        phi={"gen": "vendorA:model-g", "gen2": "vendorB:model-g2", "rev": "vendorC:model-r"},
        required={"impl": [("write", f"s{i}") for i in range(writes)] + [("check", "c1")]},
        version="v1",
    )


def admission_policy(*, theta: float = 1.0, p_min: float = 0.5, k: int = K,
                     refuters=frozenset({TESTS}), residual=(("correct fix", "check_stage"),),
                     claims=None, version: str = "r1") -> AdmissionPolicy:
    claims = claims or (ClaimSpec("tests_pass", "spec-hash-1", frozenset(refuters), D1),)
    return AdmissionPolicy({
        "impl": ClassAdmission(
            claims=claims, k=k, theta=theta, p_min=p_min,
            excluded=frozenset({"refuter_source", "refuter_results"}),
            residual=residual,
        )
    }, version=version)


def ledger(kills: int, size: int):
    return [LedgerEntry(f"m{i}", "killed" if i < kills else "survived") for i in range(size)]


class Harness:
    """Drives FCD + RGA together with a deterministic nonce source."""

    def __init__(self, *, theta=1.0, p_min=0.5, k=K, refuters=frozenset({TESTS}),
                 residual=(("correct fix", "check_stage"),), claims=None, writes=None):
        self.k = k
        self.e = Enforcer(fcd_policy(k, writes))
        self.counter = itertools.count()
        self.a = Admission(self.e, admission_policy(theta=theta, p_min=p_min, k=k,
                                                    refuters=refuters, residual=residual,
                                                    claims=claims),
                           nonce=lambda: f"nonce-{next(self.counter)}")

    # -- registry ---------------------------------------------------------------
    def declare_tests(self, kills=9, size=10, author="tester", model_author="mutator"):
        self.a.declare(Refuter("tests", "v1", author, "ledger"))
        self.a.measure("tests", "v1", DefectModel(D1, model_author), ledger(kills, size))

    # -- fcd ----------------------------------------------------------------------
    def fcd_open(self, iid="w"):
        self.e.open(iid, "impl", "body-hash")

    def fcd_write(self, iid="w", who="gen", ran=None):
        self.e.admit(iid, who)
        self.e.bind(iid, True)
        self.e.observe(iid, ran or self.e.policy_for(iid).phi[who])
        self.e.decide_pass(iid)

    def fcd_check(self, iid="w", who="rev"):
        self.e.admit(iid, who)
        self.e.bind(iid, True)
        self.e.observe(iid, self.e.policy_for(iid).phi[who])
        self.e.decide_pass(iid)

    # -- rga -----------------------------------------------------------------------
    def rga_open(self, iid="w", generator="gen", sampling="temp=0.7"):
        return self.a.open(iid, generator, sampling)

    def sample(self, iid="w", body=b"artifact", categories=("contract",), sampling="temp=0.7"):
        return self.a.sample(iid, body, categories, sampling)

    def trial(self, iid="w", i=0, refuter=TESTS, claim="tests_pass", verdict="survived",
              witness="w-same", seed=None):
        seed = seed or self.a.seed_for(iid, i, refuter[0], refuter[1], claim)
        return self.a.trial(iid, refuter[0], refuter[1], claim, i, seed, "inputs", verdict, witness)

    def replay_all(self, iid="w"):
        for idx, t in enumerate(self.a.lines[iid].trials):
            self.a.replay(iid, idx, t.verdict, t.witness_hash)

    def run_to_seal_ready(self, iid="w", witnesses=None, bodies=None):
        """Open FCD item, open line, k samples interleaved with their stages,
        all trials survived, replayed, FCD check passed. Does not seal()."""
        witnesses = witnesses or ["w-same"] * self.k
        bodies = bodies or [f"artifact-{i}".encode() for i in range(self.k)]
        self.fcd_open(iid)
        self.rga_open(iid)
        for i in range(self.k):
            self.fcd_write(iid)
            self.sample(iid, bodies[i])
            self.trial(iid, i, witness=witnesses[i])
        self.replay_all(iid)
        self.fcd_check(iid)
        return self.a.lines[iid]


class R1NoAdmissionWithoutSurvival(unittest.TestCase):
    def test_all_survived_seals(self):
        h = Harness()
        h.declare_tests()
        h.run_to_seal_ready()
        s = h.a.seal("w")
        self.assertIn("w", h.a.sealed)
        self.assertEqual(h.a.lines["w"].pc, "Sealed")
        self.assertTrue(all(t.verdict == "survived" for t in h.a.lines["w"].trials))
        self.assertEqual(s.claims[0].refuters[0].power, 0.9)

    def test_refuted_trial_closes_published_and_never_seals(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open()
        h.fcd_write(); h.sample()
        h.trial(verdict="refuted")
        line = h.a.lines["w"]
        self.assertEqual((line.pc, line.pub, line.fault), ("Closed", True, "V1"))
        with self.assertRaises(ValueError):
            h.a.seal("w")
        self.assertNotIn("w", h.a.sealed)
        last = [e for e in h.a.events if e["type"] == "rga_close"][-1]
        self.assertEqual(last["fault"], "V1")

    def test_inconclusive_is_not_survival(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open()
        h.fcd_write(); h.sample()
        h.trial(verdict="inconclusive")
        line = h.a.lines["w"]
        self.assertEqual((line.pc, line.fault), ("Closed", "V3"))
        self.assertNotIn("w", h.a.sealed)

    def test_missing_cell_refuses_seal(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode())
            if i < K - 1:
                h.trial(i=i)
        h.replay_all()
        h.fcd_check()
        with self.assertRaises(ValueError) as ctx:
            h.a.seal("w")
        self.assertIn("no trial", str(ctx.exception))
        self.assertNotIn("w", h.a.sealed)


class R2PowerCarriedNeverInferred(unittest.TestCase):
    def test_kernel_counts_kills_from_ledger(self):
        h = Harness()
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        rec = h.a.measure("tests", "v1", DefectModel(D1, "mutator"),
                          [LedgerEntry("m0", "killed"), LedgerEntry("m1", "killed"),
                           LedgerEntry("m2", "survived"), LedgerEntry("m3", "inconclusive")])
        self.assertEqual((rec.kills, rec.size), (2, 4))
        self.assertEqual(rec.power, 0.5)   # inconclusive counts in size, not kills

    def test_bounded_power_is_computed_and_the_seal_carries_epsilon_and_n(self):
        h = Harness(refuters=frozenset({PBT}))
        h.a.declare(Refuter("pbt", "v1", "tester", "bounded"))
        rec = h.a.bound("pbt", "v1", 0.1, 20)
        self.assertAlmostEqual(rec.power, 1 - 0.9 ** 20)
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode())
            h.trial(i=i, refuter=PBT)
        h.replay_all(); h.fcd_check()
        s = h.a.seal("w")
        r = s.claims[0].refuters[0]
        self.assertEqual((r.mode, r.epsilon, r.n, r.kills, r.size), ("bounded", 0.1, 20, None, None))
        self.assertAlmostEqual(r.power, 1 - 0.9 ** 20)
        self.assertEqual(s.claims[0].composition, "single")

    def test_bound_is_write_once(self):
        h = Harness(refuters=frozenset({PBT}))
        h.a.declare(Refuter("pbt", "v1", "tester", "bounded"))
        h.a.bound("pbt", "v1", 0.5, 1)
        with self.assertRaises(ValueError):
            h.a.bound("pbt", "v1", 1.0, 1)
        self.assertEqual(h.a.power[("pbt", "v1", None)].power, 0.5)

    def test_record_is_write_once_per_refuter_and_model(self):
        h = Harness()
        h.declare_tests(kills=5, size=10)
        with self.assertRaises(ValueError):
            h.a.measure("tests", "v1", DefectModel(D1, "mutator"), ledger(10, 10))
        self.assertEqual(h.a.power[("tests", "v1", D1)].power, 0.5)

    def test_seal_carries_the_record_and_nothing_raises_it_after(self):
        h = Harness()
        h.declare_tests(kills=7, size=10)
        h.run_to_seal_ready()
        s = h.a.seal("w")
        self.assertEqual(s.claims[0].refuters[0].power, 0.7)
        self.assertEqual(s.power_min, 0.7)
        with self.assertRaises(ValueError):
            h.a.measure("tests", "v1", DefectModel(D1, "mutator"), ledger(10, 10))
        self.assertEqual(h.a.sealed["w"].power_min, 0.7)

    def test_seal_requires_a_record_for_every_refuter(self):
        h = Harness()
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))   # declared, never measured
        h.run_to_seal_ready()
        with self.assertRaises(ValueError) as ctx:
            h.a.seal("w")
        self.assertIn("no power record", str(ctx.exception))

    def test_composite_is_union_on_shared_model_never_product(self):
        h = Harness(refuters=frozenset({TESTS, LINT}))
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        h.a.declare(Refuter("lint", "v1", "linter", "ledger"))
        # tests kills m0..m4, lint kills m3..m7: union = 8 of 10, not 1-(0.5)(0.5)=0.75
        h.a.measure("tests", "v1", DefectModel(D1, "mutator"),
                    [LedgerEntry(f"m{i}", "killed" if i < 5 else "survived") for i in range(10)])
        h.a.measure("lint", "v1", DefectModel(D1, "mutator"),
                    [LedgerEntry(f"m{i}", "killed" if 3 <= i < 8 else "survived") for i in range(10)])
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode())
            h.trial(i=i, refuter=TESTS); h.trial(i=i, refuter=LINT)
        h.replay_all(); h.fcd_check()
        s = h.a.seal("w")
        self.assertEqual(s.claims[0].composition, "union")
        self.assertAlmostEqual(s.claims[0].composite, 0.8)

    def test_underpowered_closes_with_v5(self):
        h = Harness(p_min=0.95)
        h.declare_tests(kills=9, size=10)
        h.run_to_seal_ready()
        with self.assertRaises(ValueError):
            h.a.seal("w")
        line = h.a.lines["w"]
        self.assertEqual((line.pc, line.pub, line.fault), ("Closed", True, "V5"))
        self.assertNotIn("w", h.a.sealed)

    def test_two_claims_power_min_is_the_weakest(self):
        claims = (ClaimSpec("tests_pass", "spec-1", frozenset({TESTS}), D1),
                  ClaimSpec("lint_clean", "spec-2", frozenset({LINT}), "d2-hash"))
        h = Harness(claims=claims)
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        h.a.declare(Refuter("lint", "v1", "linter", "ledger"))
        h.a.measure("tests", "v1", DefectModel(D1, "mutator"), ledger(9, 10))
        h.a.measure("lint", "v1", DefectModel("d2-hash", "mutator"), ledger(6, 10))
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode())
            h.trial(i=i, refuter=TESTS, claim="tests_pass")
            h.trial(i=i, refuter=LINT, claim="lint_clean", witness="lint-w")
        h.replay_all(); h.fcd_check()
        s = h.a.seal("w")
        self.assertEqual(len(s.claims), 2)
        self.assertAlmostEqual(s.power_min, 0.6)


class R3SeparationOfDuty(unittest.TestCase):
    def test_refuter_authored_by_generator_cannot_be_pinned(self):
        h = Harness()
        h.declare_tests(author="gen")
        h.fcd_open()
        with self.assertRaises(ValueError) as ctx:
            h.rga_open()
        self.assertIn("authored by the generator", str(ctx.exception))

    def test_defect_model_authored_by_generator_refused_at_open(self):
        h = Harness()
        h.declare_tests(model_author="gen")
        h.fcd_open()
        with self.assertRaises(ValueError):
            h.rga_open()

    def test_defect_model_authored_by_generator_after_open_refused_at_seal(self):
        h = Harness()
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        h.fcd_open(); h.rga_open()                    # D1 has no record yet
        h.a.measure("tests", "v1", DefectModel(D1, "gen"), ledger(9, 10))
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode()); h.trial(i=i)
        h.replay_all(); h.fcd_check()
        with self.assertRaises(ValueError) as ctx:
            h.a.seal("w")
        self.assertIn("authored by the generator", str(ctx.exception))

    def test_defect_model_author_is_fixed_by_first_record(self):
        h = Harness()
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        h.a.declare(Refuter("lint", "v1", "linter", "ledger"))
        h.a.measure("tests", "v1", DefectModel(D1, "mutator"), ledger(9, 10))
        with self.assertRaises(ValueError) as ctx:
            h.a.measure("lint", "v1", DefectModel(D1, "gen"), ledger(9, 10))
        self.assertIn("first record", str(ctx.exception))
        self.assertNotIn(("lint", "v1", D1), h.a.power)

    def test_defect_model_authored_by_refuter_author_refused(self):
        h = Harness()
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        with self.assertRaises(ValueError):
            h.a.measure("tests", "v1", DefectModel(D1, "tester"), ledger(9, 10))

    def test_refuter_must_be_declared_before_open(self):
        h = Harness()
        h.fcd_open()
        with self.assertRaises(ValueError) as ctx:
            h.rga_open()
        self.assertIn("not declared", str(ctx.exception))
        h.declare_tests()
        h.rga_open()
        self.assertLess(h.a.declared_at[TESTS], h.a.lines["w"].opened_at)

    def test_generator_package_may_not_contain_refuter_categories(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write()
        with self.assertRaises(ValueError) as ctx:
            h.sample(categories=("contract", "refuter_source"))
        self.assertIn("refuter categories", str(ctx.exception))
        self.assertEqual(h.a.lines["w"].samples, [])

    def test_line_must_open_before_generation(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.fcd_write()   # sample stage already attempted
        with self.assertRaises(ValueError):
            h.rga_open()

    def test_caller_cannot_supply_an_fcd_position(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.fcd_write()
        with self.assertRaises(TypeError):
            h.a.open("w", "gen", "temp=0.7", fcd_position=0)  # type: ignore[call-arg]
        self.assertNotIn("w", h.a.lines)

    def test_sample_must_be_registered_before_the_next_stage_runs(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open()
        h.fcd_write(); h.fcd_write()   # stage 1 attempted before sample 0 registered
        with self.assertRaises(ValueError) as ctx:
            h.sample()
        self.assertIn("before stage", str(ctx.exception))
        self.assertEqual(h.a.lines["w"].samples, [])


class R4ConcordanceIsAPrecondition(unittest.TestCase):
    def test_discord_closes_with_v2_and_names_the_differing_refuter(self):
        h = Harness(theta=1.0, refuters=frozenset({TESTS, LINT}))
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        h.a.declare(Refuter("lint", "v1", "linter", "ledger"))
        h.a.measure("tests", "v1", DefectModel(D1, "mutator"), ledger(9, 10))
        h.a.measure("lint", "v1", DefectModel(D1, "mutator"), ledger(8, 10))
        h.fcd_open(); h.rga_open()
        lint_w = ["w-a", "w-a", "w-b"]                 # lint's witnesses diverge
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode())
            h.trial(i=i, refuter=TESTS, witness="w-same")
            h.trial(i=i, refuter=LINT, witness=lint_w[i])
        h.replay_all(); h.fcd_check()
        with self.assertRaises(ValueError):
            h.a.seal("w")
        line = h.a.lines["w"]
        self.assertEqual((line.pc, line.fault), ("Closed", "V2"))
        close = [e for e in h.a.events if e["type"] == "rga_close"][-1]
        self.assertEqual(close["concordance"], [{"claim_id": "tests_pass", "agreeing": 2, "k": 3}])
        self.assertEqual(close["miss_observed"], [["lint", "v1"]])   # tests agreed everywhere

    def test_threshold_below_one_seals_and_carries_agreeing(self):
        h = Harness(theta=0.6)
        h.declare_tests()
        h.run_to_seal_ready(witnesses=["w-a", "w-a", "w-b"])
        s = h.a.seal("w")
        self.assertEqual((s.claims[0].agreeing, s.claims[0].k), (2, 3))

    def test_majority_against_designated_is_discord_not_a_winner(self):
        h = Harness(theta=0.6)
        h.declare_tests()
        h.run_to_seal_ready(witnesses=["w-a", "w-b", "w-b"])   # 1 and 2 agree; 0 is alone
        with self.assertRaises(ValueError):
            h.a.seal("w")
        self.assertEqual(h.a.lines["w"].fault, "V2")

    def test_sealed_artifact_is_stage_zero(self):
        h = Harness()
        h.declare_tests()
        bodies = [b"first", b"second", b"third"]
        h.run_to_seal_ready(bodies=bodies)
        s = h.a.seal("w")
        self.assertEqual(s.artifact_hash, sha256(b"first"))

    def test_seal_carries_the_sampling_configuration(self):
        h = Harness()
        h.declare_tests()
        h.run_to_seal_ready()
        s = h.a.seal("w")
        self.assertEqual(s.sampling_hash, "temp=0.7")
        self.assertEqual([e for e in h.a.events if e["type"] == "rga_seal"][-1]["sampling_hash"], "temp=0.7")

    def test_k_equals_one_is_visibly_trivial(self):
        h = Harness(k=1)
        h.declare_tests()
        h.run_to_seal_ready()
        s = h.a.seal("w")
        self.assertEqual((s.claims[0].agreeing, s.claims[0].k), (1, 1))


class R5NondeterminismRefuses(unittest.TestCase):
    def test_divergent_replay_refuses_refuter_and_closes_line(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample(); h.trial()
        h.a.replay("w", 0, "survived", "w-different")
        self.assertIn(TESTS, h.a.refused)
        line = h.a.lines["w"]
        self.assertEqual((line.pc, line.fault), ("Closed", "V4"))

    def test_refused_refuter_closes_siblings_and_cannot_be_pinned_or_measured(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open("w"); h.rga_open("w"); h.fcd_write("w"); h.sample("w"); h.trial("w")
        h.fcd_open("x"); h.rga_open("x"); h.fcd_write("x"); h.sample("x")
        h.a.replay("w", 0, "refuted", "w-same")
        self.assertEqual(h.a.lines["x"].fault, "V4")   # sibling line closed too
        h.fcd_open("y")
        with self.assertRaises(ValueError):
            h.rga_open("y")                             # cannot pin a refused refuter
        with self.assertRaises(ValueError):
            h.a.measure("tests", "v1", DefectModel("d9", "mutator"), ledger(9, 10))

    def test_refusal_is_monotone(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample(); h.trial()
        h.a.replay("w", 0, "refuted", "w-same")
        with self.assertRaises(ValueError):
            h.a.replay("w", 0, "survived", "w-same")   # agreeing replay later does not un-refuse
        self.assertIn(TESTS, h.a.refused)

    def test_tainted_is_a_query_and_check_dependencies_refuses_it(self):
        h = Harness()
        h.declare_tests()
        h.run_to_seal_ready("w")
        h.a.seal("w")
        self.assertFalse(h.a.tainted("w"))
        self.assertTrue(h.a.admissible("w"))
        h.a.check_dependencies(["w"], floor=0.5)
        h.fcd_open("x"); h.rga_open("x"); h.fcd_write("x"); h.sample("x"); h.trial("x")
        h.a.replay("x", 0, "refuted", "w-same")
        self.assertTrue(h.a.tainted("w"))
        self.assertFalse(h.a.admissible("w"))
        self.assertIn("w", h.a.sealed)                 # the seal record is unchanged
        with self.assertRaises(ValueError) as ctx:
            h.a.check_dependencies(["w"], floor=0.5)
        self.assertIn("refused after sealing", str(ctx.exception))


class R6ReplayExercised(unittest.TestCase):
    def test_seal_requires_one_identical_replay_per_refuter(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode()); h.trial(i=i)
        h.fcd_check()
        with self.assertRaises(ValueError) as ctx:
            h.a.seal("w")
        self.assertIn("no consistent replay", str(ctx.exception))
        h.a.replay("w", 1, "survived", "w-same")
        h.a.seal("w")
        self.assertIn("w", h.a.sealed)


class R7SampleIntegrityInherited(unittest.TestCase):
    def test_sample_requires_fcd_pass(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open()
        h.e.admit("w", "gen"); h.e.bind("w", True); h.e.observe("w", "vendorX:other")
        h.e.decide_pass("w")                       # F1: Closed, not Passed
        with self.assertRaises(ValueError) as ctx:
            h.sample()
        self.assertIn("Passed", str(ctx.exception))

    def test_sample_requires_the_lines_bind_key(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(generator="gen")
        h.fcd_write(who="gen2")                    # passed, but a different bind
        with self.assertRaises(ValueError) as ctx:
            h.sample()
        self.assertIn("different specialist", str(ctx.exception))

    def test_sample_requires_the_sampling_configuration(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(sampling="temp=0.7"); h.fcd_write()
        with self.assertRaises(ValueError):
            h.sample(sampling="temp=0.0")

    def test_k_bound_refuses_a_sample_beyond_k(self):
        h = Harness(k=1)
        h.declare_tests()
        h.fcd_open(); h.rga_open()
        h.fcd_write(); h.sample()
        h.fcd_check()
        with self.assertRaises(ValueError) as ctx:
            h.sample(body=b"again")
        self.assertIn("already has k", str(ctx.exception))

    def test_every_sealed_sample_satisfies_i1(self):
        h = Harness()
        h.declare_tests()
        h.run_to_seal_ready()
        s = h.a.seal("w")
        item = h.e.items["w"]
        for i in range(K):
            st = item.stages[i]
            self.assertEqual((st.kind, st.pc, st.a), ("write", "Passed", "gen"))
            self.assertEqual(st.m_exec, st.m_decl)
        self.assertEqual(s.m_exec, "vendorA:model-g")

    def test_accepted_item_cannot_be_failed_or_reopened_underneath_a_seal(self):
        """The FCD guards R7/R8 lean on: no_admit refuses a Passed stage of an
        accepted item, and open refuses an existing id."""
        h = Harness()
        h.declare_tests()
        h.run_to_seal_ready()
        h.a.seal("w")
        with self.assertRaises(ValueError):
            h.e.no_admit("w")
        with self.assertRaises(ValueError):
            h.e.open("w", "impl", "other-body")
        self.assertEqual(h.e.items["w"].status, "accepted")
        self.assertEqual(h.e.items["w"].body, "body-hash")


class R8SealImpliesAccept(unittest.TestCase):
    def test_seal_requires_fcd_accept(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode()); h.trial(i=i)
        h.replay_all()
        self.assertNotIn("w", h.e.store)           # check stage not passed
        with self.assertRaises(ValueError) as ctx:
            h.a.seal("w")
        self.assertIn("FCD Accept", str(ctx.exception))

    def test_sealed_is_subset_of_store(self):
        h = Harness()
        h.declare_tests()
        h.run_to_seal_ready()
        h.a.seal("w")
        self.assertTrue(set(h.a.sealed) <= h.e.store)
        self.assertEqual(h.e.items["w"].status, "accepted")

    def test_bypass_forbidden(self):
        h = Harness()
        with self.assertRaises(PermissionError):
            h.a.sealed_put("w")
        self.assertEqual(h.a.sealed, {})

    def test_dag_gate_reads_sealed_store_with_floor(self):
        h = Harness()
        h.declare_tests(kills=7, size=10)
        h.run_to_seal_ready()
        h.a.seal("w")
        h.a.check_dependencies(["w"], floor=0.7)
        with self.assertRaises(ValueError):
            h.a.check_dependencies(["w"], floor=0.8)
        with self.assertRaises(ValueError):
            h.a.check_dependencies(["nope"], floor=0.0)
        self.assertTrue(h.a.is_sealed("w"))
        self.assertFalse(h.a.is_sealed("nope"))

    def test_residual_check_stage_is_derived_from_fcd(self):
        h = Harness(k=1, residual=(("correct fix", "check_stage"),), writes=1)
        h.declare_tests()
        h.e = Enforcer(Policy(allow={"impl": {"gen"}}, deny={"impl": set()},
                              phi={"gen": "vendorA:model-g"},
                              required={"impl": [("write", "s0")]}, version="v1"))
        h.a.fcd = h.e
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample(); h.trial(); h.replay_all()
        self.assertIn("w", h.e.store)
        with self.assertRaises(ValueError) as ctx:
            h.a.seal("w")
        self.assertIn("check_stage", str(ctx.exception))


class R9R10ArtifactAndSeedBinding(unittest.TestCase):
    def test_seed_is_derived_from_post_artifact_nonce(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write()
        with self.assertRaises(ValueError):
            h.a.seed_for("w", 0, "tests", "v1", "tests_pass")   # no artifact yet
        s = h.sample(body=b"bytes")
        seed = h.a.seed_for("w", 0, "tests", "v1", "tests_pass")
        self.assertEqual(seed, derive_seed(s.nonce, sha256(b"bytes"), "tests", "v1", "tests_pass"))
        self.assertEqual(s.nonce, "nonce-0")

    def test_refused_sample_consumes_no_nonce(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write()
        with self.assertRaises(ValueError):
            h.sample(categories=("refuter_source",))
        s = h.sample()
        self.assertEqual(s.nonce, "nonce-0")            # the refusal drew nothing

    def test_trial_with_foreign_seed_refused(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); s = h.sample(body=b"bytes")
        bad = derive_seed(s.nonce, sha256(b"other-bytes"), "tests", "v1", "tests_pass")
        with self.assertRaises(ValueError) as ctx:
            h.trial(seed=bad)
        self.assertIn("seed", str(ctx.exception))
        self.assertEqual(h.a.lines["w"].trials, [])

    def test_negative_sample_index_refused(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample()
        with self.assertRaises(ValueError):
            h.a.seed_for("w", -1, "tests", "v1", "tests_pass")
        with self.assertRaises(ValueError):
            h.a.trial("w", "tests", "v1", "tests_pass", -1, "x", "inputs", "survived", "w")
        self.assertEqual(h.a.lines["w"].trials, [])

    def test_seal_artifact_hash_is_kernel_computed(self):
        h = Harness()
        h.declare_tests()
        h.run_to_seal_ready(bodies=[b"a", b"b", b"c"])
        s = h.a.seal("w")
        self.assertEqual(s.artifact_hash, sha256(b"a"))
        self.assertEqual([x.artifact_hash for x in h.a.lines["w"].samples],
                         [sha256(b"a"), sha256(b"b"), sha256(b"c")])


class R11RGAWritesNoFCDField(unittest.TestCase):
    def test_fcd_state_identical_across_every_rga_transition(self):
        h = Harness()

        def snap():
            return (copy.deepcopy(h.e.items), set(h.e.store), list(h.e.events), h.e.policy)

        before = snap()
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        h.a.declare(Refuter("pbt9", "v9", "tester", "bounded"))
        h.a.measure("tests", "v1", DefectModel(D1, "mutator"), ledger(9, 10))
        h.a.bound("pbt9", "v9", 0.1, 5)
        h.a.install(admission_policy(version="r7"))
        h.a.install(admission_policy())              # back to r1 for the line
        self.assertEqual(snap(), before)
        h.fcd_open()
        before = snap(); h.rga_open(); self.assertEqual(snap(), before)
        for i in range(K):
            h.fcd_write()
            before = snap()
            h.sample(body=f"b{i}".encode()); h.trial(i=i)
            self.assertEqual(snap(), before)
        before = snap(); h.replay_all(); self.assertEqual(snap(), before)
        h.fcd_check()
        before = snap(); h.a.seal("w"); self.assertEqual(snap(), before)
        # A published RGA close and an operator close write nothing to FCD either.
        h.fcd_open("x"); h.rga_open("x"); h.fcd_write("x"); h.sample("x")
        before = snap(); h.trial("x", verdict="refuted"); self.assertEqual(snap(), before)
        h.fcd_open("y"); h.rga_open("y")
        before = snap(); h.a.close("y"); self.assertEqual(snap(), before)


class R12FrozenLine(unittest.TestCase):
    def test_line_pins_admission_policy_version(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); line = h.rga_open()
        h.a.install(admission_policy(p_min=0.99, version="r2"))
        self.assertEqual(line.policy_version, "r1")
        self.assertEqual(h.a.policy_for("w").version, "r1")
        self.assertEqual(line.p_min, 0.5)

    def test_same_version_different_content_refused(self):
        h = Harness()
        with self.assertRaises(ValueError):
            h.a.install(admission_policy(p_min=0.99, version="r1"))

    def test_policy_validation(self):
        with self.assertRaises(ValueError):
            admission_policy(k=0)
        with self.assertRaises(ValueError):
            admission_policy(theta=0.0)
        with self.assertRaises(ValueError):
            admission_policy(p_min=1.5)
        with self.assertRaises(ValueError):
            admission_policy(refuters=frozenset())
        with self.assertRaises(ValueError):
            admission_policy(residual=(("x", "maybe"),))
        with self.assertRaises(ValueError):
            admission_policy(claims=(ClaimSpec("c", "s1", frozenset({TESTS}), D1),
                                     ClaimSpec("c", "s2", frozenset({TESTS}), D1)))


class R13Bounded(unittest.TestCase):
    def test_at_most_k_samples_even_with_more_write_stages(self):
        h = Harness(writes=K + 1)                    # FCD has k+1 write stages
        h.declare_tests()
        h.fcd_open(); h.rga_open()
        for i in range(K):
            h.fcd_write(); h.sample(body=f"b{i}".encode())
        h.fcd_write()                                # stage K passes as well
        with self.assertRaises(ValueError) as ctx:
            h.sample(body=b"extra")
        self.assertIn("already has k", str(ctx.exception))

    def test_one_trial_per_cell(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample(); h.trial()
        with self.assertRaises(ValueError):
            h.trial()

    def test_defect_model_id_set_fixed_by_first_record(self):
        h = Harness()
        h.a.declare(Refuter("tests", "v1", "tester", "ledger"))
        h.a.declare(Refuter("lint", "v1", "linter", "ledger"))
        h.a.measure("tests", "v1", DefectModel(D1, "mutator"), ledger(5, 10))
        with self.assertRaises(ValueError):
            h.a.measure("lint", "v1", DefectModel(D1, "mutator"), ledger(5, 11))


class ReplayTests(unittest.TestCase):
    def _rebuild(self, h: Harness, policy=None):
        fcd_rebuilt = Enforcer.from_events(list(h.e.events), fcd_policy())
        return Admission.from_events(list(h.a.events), fcd_rebuilt, policy or admission_policy())

    def test_from_events_rebuilds_sealed_store_without_redrawing_nonces(self):
        h = Harness()
        h.declare_tests()
        h.run_to_seal_ready()
        sealed = h.a.seal("w")
        rebuilt = self._rebuild(h)
        self.assertEqual(rebuilt.sealed["w"], sealed)
        self.assertEqual(rebuilt.events, h.a.events)
        self.assertEqual([s.nonce for s in rebuilt.lines["w"].samples],
                         [s.nonce for s in h.a.lines["w"].samples])

    def test_from_events_keeps_a_v1_close_closed(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample(); h.trial(verdict="refuted")
        rebuilt = self._rebuild(h)
        self.assertEqual((rebuilt.lines["w"].pc, rebuilt.lines["w"].fault), ("Closed", "V1"))
        self.assertEqual(len(rebuilt.events), len(h.a.events))

    def test_from_events_rebuilds_a_discord_close(self):
        h = Harness(theta=1.0)
        h.declare_tests()
        h.run_to_seal_ready(witnesses=["w-a", "w-a", "w-b"])
        with self.assertRaises(ValueError):
            h.a.seal("w")
        rebuilt = self._rebuild(h)
        self.assertEqual((rebuilt.lines["w"].pc, rebuilt.lines["w"].fault), ("Closed", "V2"))
        self.assertNotIn("w", rebuilt.sealed)
        self.assertEqual(rebuilt.events, h.a.events)

    def test_from_events_rebuilds_an_underpower_close(self):
        h = Harness(p_min=0.95)
        h.declare_tests(kills=5, size=10)
        h.run_to_seal_ready()
        with self.assertRaises(ValueError):
            h.a.seal("w")
        rebuilt = self._rebuild(h, admission_policy(p_min=0.95))
        self.assertEqual((rebuilt.lines["w"].pc, rebuilt.lines["w"].fault), ("Closed", "V5"))
        self.assertNotIn("w", rebuilt.sealed)

    def test_from_events_unknown_policy_version_is_an_error(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open()
        with self.assertRaises(ValueError):
            self._rebuild(h, admission_policy(version="r9"))

    def test_from_events_refuses_a_policy_that_differs_from_the_journal(self):
        h = Harness(theta=1.0)
        h.declare_tests()
        h.fcd_open(); h.rga_open()
        with self.assertRaises(ValueError) as ctx:
            self._rebuild(h, admission_policy(theta=0.6))   # same version string, other content
        self.assertIn("replay diverged", str(ctx.exception))

    def test_rebuilt_admission_keeps_a_live_nonce_source(self):
        h = Harness()
        h.declare_tests()
        h.fcd_open(); h.rga_open(); h.fcd_write(); h.sample()
        counter = itertools.count(100)
        fcd_rebuilt = Enforcer.from_events(list(h.e.events), fcd_policy())
        rebuilt = Admission.from_events(list(h.a.events), fcd_rebuilt, admission_policy(),
                                        nonce=lambda: f"live-{next(counter)}")
        # continue the line live on the rebuilt machine
        fcd_rebuilt.admit("w", "gen"); fcd_rebuilt.bind("w", True)
        fcd_rebuilt.observe("w", "vendorA:model-g"); fcd_rebuilt.decide_pass("w")
        s = rebuilt.sample("w", b"next", ("contract",), "temp=0.7")
        self.assertEqual(s.nonce, "live-100")           # not the constant ""

    def test_from_events_restores_current_admission_policy_after_replay(self):
        # Historical line w opens and seals under r1; the live version is r2.
        h = Harness()
        h.declare_tests()
        h.run_to_seal_ready()
        h.a.seal("w")
        h.a.install(admission_policy(p_min=0.9, version="r2"))  # live version is now r2
        fcd_rebuilt = Enforcer.from_events(list(h.e.events), fcd_policy())
        rebuilt = Admission.from_events(
            list(h.a.events), fcd_rebuilt,
            admission_policy(), admission_policy(p_min=0.9, version="r2"))

        # historical line remains pinned to r1
        self.assertEqual(rebuilt.lines["w"].policy_version, "r1")
        self.assertEqual(rebuilt.policy_for("w").version, "r1")
        self.assertEqual(rebuilt.lines["w"].p_min, 0.5)
        # rebuilt current admission policy is the LAST supplied policy, r2 (RED before fix)
        self.assertEqual(rebuilt.policy.version, "r2")
        # a new line opened after rebuild uses r2
        fcd_rebuilt.open("n2", "impl", "body2")
        new_line = rebuilt.open("n2", "gen", "temp=0.7")
        self.assertEqual(new_line.policy_version, "r2")
        self.assertEqual(new_line.p_min, 0.9)


if __name__ == "__main__":
    unittest.main()
