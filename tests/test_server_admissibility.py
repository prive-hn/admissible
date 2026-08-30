"""The reference server routed through the admissibility stack.

The consumer-redirection obligation the papers list, discharged: the server
opens an RGA line at first generation, registers the sample and runs the
measured demo refuter as a replayed trial, seals through the calibration
authority at Accept, and gates memory promotion on admissible() — with the
per-line layer stated plainly in state when sealing is impossible.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from fcd.core import Policy
from rga.core import derive_seed
from server.app import (
    DEMO_CLAIM, DEMO_DEFECTS, DEMO_REFUTER, CockpitEngine, run_demo_refuter,
)

REPO = Path(__file__).resolve().parents[1]
PROJECT = {
    "id": "adm-test",
    "name": "Admissibility Test",
    "local_path": str(REPO),
    "github": "prive-hn/admissible",
    "base_branch": "main",
}


def engine() -> CockpitEngine:
    e = CockpitEngine(seed=False)
    e.load_project(PROJECT)
    return e


def accept_item(e: CockpitEngine, prompt: str = "Ship the export") -> str:
    item = e.create_work_item(prompt)["workItem"]
    iid = item["id"]
    e.answer_question(item["openQuestionId"], "CSV first")     # write stage
    e.action(iid, f"{iid}.1", "/retry")                        # check stage -> Accept
    return iid


class MeasuredNotDeclared(unittest.TestCase):
    def test_the_demo_refuter_power_is_counted_from_real_runs(self):
        e = engine()
        rec = e.admission.power[(DEMO_REFUTER[0], DEMO_REFUTER[1], "demo-defects-v1")]
        # every seeded defect is actually killed by running the checker
        expected_kills = sum(
            1 for _, mutant in DEMO_DEFECTS if run_demo_refuter(mutant, "calibration")[0] == "refuted")
        self.assertEqual((rec.kills, rec.size), (expected_kills, len(DEMO_DEFECTS)))
        self.assertGreaterEqual(rec.power, 0.5)                # else every seal would close V5


class SealedFlow(unittest.TestCase):
    def test_accepted_work_is_sealed_and_promotes(self):
        e = engine()
        head_before = e.context.project_head("adm-test")
        iid = accept_item(e)
        adm = e._project_item(iid)["admissibility"]
        self.assertEqual(adm["layer"], "IRC")
        self.assertTrue(adm["sealed"] and adm["admissible"])
        self.assertFalse(adm["impeached"] or adm["tainted"])
        self.assertEqual((adm["agreeing"], adm["k"]), (1, 1))  # concordance visibly unmeasured
        self.assertIn("unmeasured at k=1", adm["sentence"])
        self.assertIsNotNone(adm["trackRecords"])
        self.assertGreater(e.context.project_head("adm-test"), head_before)  # promoted

    def test_seal_binds_the_served_bytes(self):
        e = engine()
        iid = accept_item(e)
        from rga.core import sha256
        self.assertEqual(e.admission.sealed[iid].artifact_hash,
                         sha256(e.artifacts[iid]["srcDoc"].encode()))

    def test_residual_names_the_check_stage(self):
        e = engine()
        iid = accept_item(e)
        self.assertEqual(e._project_item(iid)["admissibility"]["residual"],
                         [["meets the operator's intent", "check_stage"]])


class UnsealableFlowIsHonest(unittest.TestCase):
    def test_a_bind_change_leaves_layer_one_and_blocks_promotion(self):
        e = engine()
        item = e.create_work_item("Force a foreign bind")["workItem"]
        iid = item["id"]
        # Pin the RGA line to a DIFFERENT allowed specialist before the write
        # stage runs: the sample then fails the bind key (R7/V6), the item is
        # accepted by the identity gates alone, and promotion must refuse.
        policy: Policy = e.enforcer.policy
        cls = e.enforcer.items[iid].cls
        gate = e._gate_definition(iid)
        default = e._specialist_for(iid, gate)
        allow = policy.pi_star(cls, "write", set())
        other = sorted(a for a in allow if a != default)
        if not other:
            self.skipTest(f"class {cls!r} has a single allowed specialist")
        e.admission.open(iid, other[0], "demo:greedy")
        head_before = e.context.project_head("adm-test")
        e.answer_question(item["openQuestionId"], "go")        # write runs under the default
        e.action(iid, f"{iid}.1", "/retry")                    # check stage -> FCD Accept
        self.assertEqual(e.enforcer.items[iid].status, "accepted")
        adm = e._project_item(iid)["admissibility"]
        self.assertEqual(adm["layer"], "I")
        self.assertFalse(adm["sealed"] or adm["admissible"])
        self.assertIn("Identity gates only", adm["sentence"])
        self.assertIn("sample", adm["failure"])
        self.assertEqual(e.context.project_head("adm-test"), head_before)  # promotion refused

    def test_state_carries_the_block_for_every_item(self):
        e = engine()
        iid = accept_item(e)
        state_item = next(w for w in e.state()["workItems"] if w["id"] == iid)
        self.assertIn("admissibility", state_item)
        self.assertTrue(state_item["admissibility"]["sealed"])


class AcceptedItemsAreImmutableToActions(unittest.TestCase):
    """steer() already refuses accepted artifacts; /discard and /fix must
    too — a sealed line relabelled 'failed' would render as closed-with-
    nothing-written while the store serves it, and a fix question on an
    immutable line consumes an answer it can never use."""

    def test_discard_on_an_accepted_item_is_refused(self):
        e = engine()
        iid = accept_item(e)
        with self.assertRaises(ValueError):
            e.action(iid, f"{iid}.1", "/discard")
        self.assertEqual(e._project_item(iid)["status"], "accepted")

    def test_fix_on_an_accepted_item_is_refused(self):
        e = engine()
        iid = accept_item(e)
        with self.assertRaises(ValueError):
            e.action(iid, f"{iid}.1", "/fix")
        self.assertIsNone(e.meta[iid].get("open_question_id"))


class EverySentenceSaysWhatHappened(unittest.TestCase):
    """State's one sentence is what the cockpit renders as the explanation.
    It may not swallow a fact the same block reports, and it may not describe
    a stopped line as still in flight."""

    def test_a_published_fault_carries_its_reason(self):
        e = engine()
        first = accept_item(e)
        item = e.create_work_item("Second line")["workItem"]
        iid = item["id"]
        e.answer_question(item["openQuestionId"], "go")
        # refuse the pinned refuter through a diverging replay on the first line
        e.admission.replay(first, 0, "refuted", "divergent-witness")
        adm = e._project_item(iid)["admissibility"]
        if adm["failure"] and adm["failure"].startswith("V4"):
            self.assertNotIn("):  —", adm["sentence"])      # the empty-reason rendering
            self.assertIn("refused", adm["sentence"])       # the reason itself

    def test_a_stopped_line_is_not_described_as_still_in_flight(self):
        e = engine()
        item = e.create_work_item("Abandon this")["workItem"]
        iid = item["id"]
        e.action(iid, f"{iid}.0", "/discard")
        adm = e._project_item(iid)["admissibility"]
        self.assertNotIn("yet", adm["sentence"])
        self.assertIn("ended without", adm["sentence"])

    def test_an_impeached_unmediated_seal_says_both(self):
        e = engine()
        iid = accept_item(e)
        e.calibration._events = [ev for ev in e.calibration.events if ev["type"] != "cal_stamp"]
        seal = e.admission.sealed[iid]
        src = e.artifacts[iid]["srcDoc"].encode()
        seed = derive_seed("finder-nonce", seal.artifact_hash, *DEMO_REFUTER, DEMO_CLAIM)
        run = e.calibration.file_escape(iid, DEMO_CLAIM, *DEMO_REFUTER, "finder-nonce",
                                        src, seed, "kill-w", finder="auditor")
        e.calibration.replay_run(run.index, "refuted", "kill-w")
        adm = e._project_item(iid)["admissibility"]
        self.assertTrue(adm["impeached"])
        self.assertFalse(adm["mediated"])
        self.assertIn("impeached", adm["sentence"])          # the worse fact leads
        self.assertIn("never mediated", adm["sentence"])     # the other is not swallowed
        self.assertNotIn("carries layer-R standing only", adm["sentence"])


class UnmediatedSealsRenderIR(unittest.TestCase):
    def test_a_seal_the_calibration_authority_never_stamped_is_IR(self):
        """A consumer must be able to tell an IRC seal from one that reached
        layer R only. The layer letter is derived from the record, so a seal
        without its calibration stamp reads IR and is not admissible."""
        e = engine()
        iid = accept_item(e)
        adm = e._project_item(iid)["admissibility"]
        self.assertEqual(adm["layer"], "IRC")
        self.assertTrue(adm["mediated"])
        # strip the stamp: the seal stands, its calibration standing does not
        e.calibration._events = [ev for ev in e.calibration.events if ev["type"] != "cal_stamp"]
        adm = e._project_item(iid)["admissibility"]
        self.assertEqual(adm["layer"], "IR")
        self.assertTrue(adm["sealed"])
        self.assertFalse(adm["mediated"])
        self.assertFalse(adm["admissible"])
        self.assertIn("not mediated", adm["sentence"])


class ReloadEvolvesBothPoliciesTogether(unittest.TestCase):
    """The review's exact-head trace: reload installed a new Admission policy
    while the calibration policy kept the old class set, so a class added on
    reload sealed and answered admissible with no budget ever declared for
    it. Both policies now move together or neither does."""

    BASE = {
        **PROJECT, "id": "reload-cov",
        "models": [{"id": "m", "provider": "demo", "api_id": "builder"},
                   {"id": "mr", "provider": "demo", "api_id": "reviewer"}],
        "agents": [{"id": "builder", "default_model_id": "m"},
                   {"id": "reviewer", "default_model_id": "mr"}],
        "gates": [{"id": "implement", "agent_id": "builder", "model_id": "m"},
                  {"id": "review", "agent_id": "reviewer", "model_id": "mr", "kind": "check"}],
        "classes": [{"id": "feature", "gate_ids": ["implement", "review"]}],
    }

    def test_a_class_added_on_reload_carries_an_explicit_budget(self):
        e = CockpitEngine(seed=False)
        e.load_project(self.BASE)
        before = sorted(e.calibration.policy.classes)
        grown = {**self.BASE, "policy_version": "policy-2",
                 "classes": [{"id": "feature", "gate_ids": ["implement", "review"]},
                             {"id": "new_lane", "gate_ids": ["implement", "review"]}]}
        e.load_project(grown)
        self.assertEqual(sorted(e.admission.policy.classes),
                         sorted(e.calibration.policy.classes),
                         "an admission class with no calibration budget is an unlimited one")
        self.assertIn("new_lane", e.calibration.policy.classes)
        self.assertNotEqual(before, sorted(e.calibration.policy.classes))

    def test_every_admission_class_has_a_budget_at_load(self):
        e = CockpitEngine(seed=False)
        e.load_project(self.BASE)
        for cls in e.admission.policy.classes:
            self.assertIn(cls, e.calibration.policy.classes)


class RefutedLinesAreLoud(unittest.TestCase):
    def test_a_refuted_trial_is_named_in_state_not_hidden_behind_no_claim(self):
        """When the pinned refuter kills the sample, the journal publishes a
        V1 close — and state must repeat that, not say 'no admissibility
        claim is made' as if scrutiny never happened."""
        e = engine()
        item = e.create_work_item("Ship the export")["workItem"]
        iid = item["id"]
        from unittest.mock import patch
        with patch("server.app.run_demo_refuter",
                   side_effect=lambda src, seed: ("refuted", "kill-w")):
            e.answer_question(item["openQuestionId"], "CSV first")   # write; trial refutes
        adm = e._project_item(iid)["admissibility"]
        self.assertEqual(adm["layer"], "I")
        self.assertFalse(adm["sealed"])
        self.assertIn("V1", adm["failure"])
        self.assertIn("refuted", adm["sentence"])
        head_before = e.context.project_head("adm-test")
        e.action(iid, f"{iid}.1", "/retry")                          # check -> FCD Accept
        self.assertEqual(e.enforcer.items[iid].status, "accepted")
        adm = e._project_item(iid)["admissibility"]
        self.assertIn("V1", adm["failure"])
        self.assertIn("refuted", adm["sentence"].lower())
        self.assertEqual(e.context.project_head("adm-test"), head_before)  # no promotion


class MultiWriteClassesRefuseTheSeal(unittest.TestCase):
    """The kernel binds sample i to FCD stage i, so a k=1 line can only ever
    bind the FIRST write's bytes — while the store serves the LAST write's.
    A class with more than one write gate therefore must not open an RGA
    line at all: layer I, the reason stated, promotion refused. The
    alternative — sealing bytes the refuter never attacked — is the exact
    laundering this stack exists to prevent."""

    def _engine(self) -> CockpitEngine:
        e = CockpitEngine(seed=False)
        e.load_project({
            **PROJECT, "id": "multi-write",
            "models": [{"id": "m", "provider": "demo", "api_id": "builder"},
                       {"id": "mr", "provider": "demo", "api_id": "reviewer"}],
            "agents": [{"id": "builder", "default_model_id": "m"},
                       {"id": "reviewer", "default_model_id": "mr"}],
            "gates": [
                {"id": "draft", "agent_id": "builder", "model_id": "m"},
                {"id": "refine", "agent_id": "builder", "model_id": "m"},
                {"id": "review", "agent_id": "reviewer", "model_id": "mr", "kind": "check"},
            ],
        })
        return e

    def test_two_write_gates_stay_layer_one_with_the_reason_stated(self):
        e = self._engine()
        item = e.create_work_item("Ship the export")["workItem"]
        iid = item["id"]
        head_before = e.context.project_head("multi-write")
        e.answer_question(item["openQuestionId"], "CSV first")   # write 1
        nxt = e._project_item(iid)
        q2 = nxt.get("openQuestionId")
        if q2:
            e.answer_question(q2, "go")                          # write 2
        else:
            e.action(iid, f"{iid}.1", "/retry")
        e.action(iid, f"{iid}.2", "/retry")                      # check -> Accept
        self.assertEqual(e.enforcer.items[iid].status, "accepted")
        adm = e._project_item(iid)["admissibility"]
        self.assertEqual(adm["layer"], "I")
        self.assertFalse(adm["sealed"])
        self.assertIn("write stages", adm["failure"])
        self.assertNotIn(iid, e.admission.sealed)                # no seal over unserved bytes
        self.assertEqual(e.context.project_head("multi-write"), head_before)


class EscapeThroughTheServer(unittest.TestCase):
    def test_a_filed_escape_impeaches_a_sealed_item_end_to_end(self):
        e = engine()
        iid = accept_item(e)
        seal = e.admission.sealed[iid]
        src = e.artifacts[iid]["srcDoc"].encode()
        # counterfactual trial of the PINNED refuter at a finder-chosen nonce
        seed = derive_seed("finder-nonce", seal.artifact_hash, *DEMO_REFUTER, DEMO_CLAIM)
        run = e.calibration.file_escape(iid, DEMO_CLAIM, *DEMO_REFUTER, "finder-nonce",
                                        src, seed, "kill-w", finder="auditor")
        self.assertFalse(e._project_item(iid)["admissibility"]["impeached"])  # not established yet
        e.calibration.replay_run(run.index, "refuted", "kill-w")
        adm = e._project_item(iid)["admissibility"]
        self.assertTrue(adm["impeached"])
        self.assertFalse(adm["admissible"])
        self.assertIn("impeached", adm["sentence"])
        self.assertTrue(e.admission.is_sealed(iid))            # the seal itself never rewrites
        # the charge stands against the pinned refuter, once
        self.assertEqual(e.calibration.charges(*DEMO_REFUTER, e.enforcer.items[iid].cls), 1)


if __name__ == "__main__":
    unittest.main()
