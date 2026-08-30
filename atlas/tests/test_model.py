"""TDD for atlas.model — the pure reducer from fcd journal to AtlasSnapshot.

These tests are the contract. They ground every field of the snapshot in a
real fcd journal (events produced by the actual Enforcer), plus declared
plan / evidence / artifact / question records. No pixel, no node, no impact
claim exists without a backing event or an explicit declared record.

Run:
    python3 -m unittest discover -s atlas/tests -p 'test_*.py' -v
"""
from __future__ import annotations

import copy
import dataclasses
import unittest
from types import MappingProxyType

# admissible core: the journal is real, not synthesized by hand.
from fcd.core import Enforcer, Policy

from atlas.model import (
    AtlasSnapshot,
    Impact,
    Node,
    Question,
    build_snapshot,
    capabilities_from_policy,
)


def policy(version: str, allow: set[str]) -> Policy:
    return Policy(
        allow={"impl": set(allow)},
        deny={"impl": set()},
        phi={"alice": "vendorA:model-a", "carol": "vendorC:model-c", "bob": "vendorB:model-b"},
        required={"impl": [("write", "w1"), ("check", "c1")]},
        version=version,
    )


def accepted_line(e: Enforcer, iid: str, depends_on: tuple[str, ...] = ()) -> None:
    """Drive a line all the way to accepted through real transitions."""
    e.open(iid, "impl", f"hash-{iid}", depends_on=depends_on)
    # write stage: alice
    e.admit(iid, "alice")
    e.bind(iid, True)
    e.observe(iid, e.policy_for(iid).phi["alice"])
    e.decide_pass(iid)
    # check stage: carol (not an author)
    e.admit(iid, "carol")
    e.bind(iid, True)
    e.observe(iid, e.policy_for(iid).phi["carol"])
    e.decide_pass(iid)


def failed_line(e: Enforcer, iid: str) -> None:
    """Drive a line to a published fail-closed on its write stage (F1 then
    exhausted allow set → item.status == 'failed'). allow is {alice} only."""
    e.open(iid, "impl", f"hash-{iid}")
    e.admit(iid, "alice")
    e.bind(iid, True)
    e.observe(iid, "vendorX:wrong-model")   # mismatch
    e.decide_pass(iid)                        # F1: stage Closed, published
    e.no_admit(iid)                           # allow exhausted → item failed


def build_journal() -> list[dict]:
    """A accepted; B accepted on A; D failed closed. allow {alice,carol}
    for A/B, {alice} for D via a separate enforcer segment is awkward, so
    keep one policy and fail D by mismatch+exhaust after removing carol.

    Simpler: two enforcers would fork the store. Use one policy where D is a
    distinct class with a single-specialist allow set."""
    pol = Policy(
        allow={"impl": {"alice", "carol"}, "solo": {"alice"}},
        deny={"impl": set(), "solo": set()},
        phi={"alice": "vendorA:model-a", "carol": "vendorC:model-c", "bob": "vendorB:model-b"},
        required={"impl": [("write", "w1"), ("check", "c1")], "solo": [("write", "w1")]},
        version="v1",
    )
    e = Enforcer(pol, clock=lambda: 0.0)
    accepted_line(e, "A")
    accepted_line(e, "B", depends_on=("A",))
    # D: solo class, single specialist, forced fail closed
    e.open("D", "solo", "hash-D")
    e.admit("D", "alice")
    e.bind("D", True)
    e.observe("D", "vendorX:wrong-model")
    e.decide_pass("D")     # F1
    e.no_admit("D")        # exhausted → failed
    return list(e.events)


CAP_POLICY = policy("v1", {"alice", "carol"})


class CapabilityHierarchyTests(unittest.TestCase):
    """Capabilities are the DEFAULT hierarchy of the atlas: class -> specialist
    -> bound model, present even before any work item exists."""

    def test_capabilities_present_with_empty_journal(self) -> None:
        snap = build_snapshot([], policies=CAP_POLICY, generated_at=0.0)
        self.assertTrue(snap.capabilities, "capabilities must be the default view even with no work")
        self.assertEqual(snap.roots, ())  # no work items yet

    def test_hierarchy_is_class_specialist_model(self) -> None:
        caps = capabilities_from_policy(CAP_POLICY)
        classes = {c.id: c for c in caps}
        self.assertIn("impl", classes)
        impl = classes["impl"]
        self.assertEqual(impl.kind, "class")
        specialists = {s.id: s for s in impl.children}
        self.assertEqual(set(specialists), {"alice", "carol"})
        # each specialist carries its bound model as a leaf
        alice_models = [m.label for m in specialists["alice"].children]
        self.assertEqual(alice_models, ["vendorA:model-a"])

    def test_deny_excluded_from_default_hierarchy(self) -> None:
        pol = Policy(
            allow={"impl": {"alice", "carol"}},
            deny={"impl": {"carol"}},
            phi={"alice": "vendorA:model-a", "carol": "vendorC:model-c"},
            required={"impl": [("write", "w1")]},
            version="v9",
        )
        caps = capabilities_from_policy(pol)
        impl = {c.id: c for c in caps}["impl"]
        self.assertEqual({s.id for s in impl.children}, {"alice"})


class NodeTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snap = build_snapshot(build_journal(), policies=CAP_POLICY, generated_at=7.0)

    def test_item_and_stage_nodes_exist(self) -> None:
        self.assertIn("A", self.snap.nodes)
        a = self.snap.nodes["A"]
        self.assertEqual(a.kind, "item")
        self.assertEqual(a.status, "accepted")
        # two required stages became stage nodes, children of the item
        self.assertEqual(len(a.children), 2)
        for sid in a.children:
            self.assertEqual(self.snap.nodes[sid].kind, "stage")
            self.assertEqual(self.snap.nodes[sid].parent, "A")

    def test_declared_and_executed_models_recorded_on_stage(self) -> None:
        a = self.snap.nodes["A"]
        write_stage = self.snap.nodes[a.children[0]]
        self.assertEqual(write_stage.declared_model, "vendorA:model-a")
        self.assertEqual(write_stage.executed_model, "vendorA:model-a")

    def test_depends_on_edge_from_journal(self) -> None:
        self.assertEqual(self.snap.nodes["B"].depends_on, ("A",))

    def test_failed_item_status_and_fault(self) -> None:
        d = self.snap.nodes["D"]
        self.assertEqual(d.status, "failed")
        write_stage = self.snap.nodes[d.children[0]]
        self.assertEqual(write_stage.fault, "F1")


class ImpactSeparationTests(unittest.TestCase):
    """A failure classifies every item node into exactly one of observed /
    reachable / unknown. The three sets are disjoint and their union is the
    full item-node set. Unknown is NOT 'safe' — it is 'not asserted'."""

    def setUp(self) -> None:
        # plan declares a downstream line F that depends on the failing D,
        # and an unrelated line G. Neither is opened yet (planned only).
        plan = [
            {"id": "F", "class": "impl", "label": "downstream of D", "depends_on": ["D"]},
            {"id": "G", "class": "impl", "label": "unrelated", "depends_on": []},
        ]
        self.snap = build_snapshot(
            build_journal(), policies=CAP_POLICY, plan=plan, generated_at=0.0
        )
        self.imp = self.snap.impact

    def test_observed_is_the_failed_line(self) -> None:
        self.assertIn("D", self.imp.observed)
        self.assertNotIn("A", self.imp.observed)
        self.assertNotIn("F", self.imp.observed)

    def test_reachable_is_declared_dependents_of_failure(self) -> None:
        self.assertIn("F", self.imp.reachable)      # F depends_on D
        self.assertNotIn("D", self.imp.reachable)

    def test_unknown_is_everything_not_asserted(self) -> None:
        # A, B, G have neither observed failure nor a dependency path to D.
        self.assertIn("G", self.imp.unknown)
        self.assertIn("A", self.imp.unknown)

    def test_three_sets_partition_item_nodes(self) -> None:
        items = {nid for nid, n in self.snap.nodes.items() if n.kind == "item"}
        o, r, u = set(self.imp.observed), set(self.imp.reachable), set(self.imp.unknown)
        self.assertEqual(o | r | u, items)             # cover
        self.assertEqual(o & r, set())                 # disjoint
        self.assertEqual(o & u, set())
        self.assertEqual(r & u, set())

    def test_no_failure_means_empty_observed_and_reachable(self) -> None:
        pol = Policy(
            allow={"impl": {"alice", "carol"}},
            deny={"impl": set()},
            phi={"alice": "vendorA:model-a", "carol": "vendorC:model-c"},
            required={"impl": [("write", "w1"), ("check", "c1")]},
            version="v1",
        )
        e = Enforcer(pol, clock=lambda: 0.0)
        accepted_line(e, "A")
        snap = build_snapshot(list(e.events), policies=pol, generated_at=0.0)
        self.assertEqual(snap.impact.observed, ())
        self.assertEqual(snap.impact.reachable, ())
        self.assertIn("A", snap.impact.unknown)


class QuestionAttachmentTests(unittest.TestCase):
    """An unresolved question blocks ONLY the node it is attached to
    (its line), never the whole atlas."""

    def setUp(self) -> None:
        questions = [{"id": "q1", "node_id": "D", "text": "which provider replaces the dead bind?"}]
        self.snap = build_snapshot(
            build_journal(), policies=CAP_POLICY, questions=questions, generated_at=0.0
        )

    def test_question_attached_to_exact_node(self) -> None:
        d = self.snap.nodes["D"]
        self.assertEqual([q.id for q in d.questions], ["q1"])
        self.assertIsInstance(d.questions[0], Question)

    def test_only_the_affected_node_is_blocked(self) -> None:
        self.assertTrue(self.snap.nodes["D"].blocked)
        self.assertFalse(self.snap.nodes["A"].blocked)
        self.assertFalse(self.snap.nodes["B"].blocked)

    def test_snapshot_lists_all_questions(self) -> None:
        self.assertEqual([q.id for q in self.snap.questions], ["q1"])

    def test_question_for_missing_node_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_snapshot(
                build_journal(),
                policies=CAP_POLICY,
                questions=[{"id": "qz", "node_id": "NOPE", "text": "?"}],
                generated_at=0.0,
            )


class ArtifactTests(unittest.TestCase):
    """The real runnable artifact is a first-class record attached to a node."""

    def test_artifact_attached_and_flags_preserved(self) -> None:
        artifacts = [
            {"id": "art-A", "node_id": "A", "kind": "python_module",
             "uri": "atlas/model.py", "present": True, "runnable": True}
        ]
        snap = build_snapshot(
            build_journal(), policies=CAP_POLICY, artifacts=artifacts, generated_at=0.0
        )
        a = snap.nodes["A"]
        self.assertEqual(len(a.artifacts), 1)
        self.assertEqual(a.artifacts[0].uri, "atlas/model.py")
        self.assertTrue(a.artifacts[0].runnable)


class PolicyAndTimePreservationTests(unittest.TestCase):
    def test_item_pins_policy_version_from_open(self) -> None:
        pol_v1 = policy("v1", {"alice", "carol"})
        pol_v2 = policy("v2", {"carol"})
        e = Enforcer(pol_v1, clock=lambda: 0.0)
        e.open("A", "impl", "hash-A")           # pins v1
        e.install(pol_v2)                          # new live version
        e.admit("A", "alice")
        e.bind("A", True)
        e.observe("A", "vendorA:model-a")
        e.decide_pass("A")
        e.admit("A", "carol")
        e.bind("A", True)
        e.observe("A", "vendorC:model-c")
        e.decide_pass("A")
        snap = build_snapshot(list(e.events), policies=(pol_v1, pol_v2),
                              policy_version="v2", generated_at=3.5)
        self.assertEqual(snap.nodes["A"].policy_version, "v1")  # pinned, not live
        self.assertEqual(snap.policy_version, "v2")             # atlas render version
        self.assertEqual(snap.generated_at, 3.5)                # time preserved

    def test_generated_at_defaults_and_survives(self) -> None:
        snap = build_snapshot(build_journal(), policies=CAP_POLICY, generated_at=99.25)
        self.assertEqual(snap.generated_at, 99.25)


class ImmutabilityAndSkinTests(unittest.TestCase):
    """Skins are read-only projections. They cannot mutate canonical state."""

    def setUp(self) -> None:
        self.snap = build_snapshot(build_journal(), policies=CAP_POLICY, generated_at=1.0)

    def test_snapshot_is_frozen(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.snap.policy_version = "hacked"          # type: ignore[misc]

    def test_nodes_mapping_is_read_only(self) -> None:
        self.assertIsInstance(self.snap.nodes, MappingProxyType)
        with self.assertRaises(TypeError):
            self.snap.nodes["A"] = None                  # type: ignore[index]

    def test_node_is_frozen(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.snap.nodes["A"].status = "tampered"     # type: ignore[misc]

    def test_project_returns_distinct_equal_snapshot(self) -> None:
        proj = self.snap.project()
        self.assertIsInstance(proj, AtlasSnapshot)
        self.assertIsNot(proj, self.snap)
        self.assertEqual(proj, self.snap)

    def test_projection_mutation_does_not_touch_canonical(self) -> None:
        # A skin deep-copies then tries to mutate; canonical stays intact.
        proj = self.snap.project()
        mutable_view = copy.deepcopy({k: dataclasses.asdict(v) for k, v in proj.nodes.items()})
        mutable_view["A"]["status"] = "SKIN-TAMPERED"
        self.assertEqual(self.snap.nodes["A"].status, "accepted")


class DeterminismTests(unittest.TestCase):
    def test_same_inputs_same_snapshot(self) -> None:
        j = build_journal()
        s1 = build_snapshot(j, policies=CAP_POLICY, generated_at=0.0)
        s2 = build_snapshot(j, policies=CAP_POLICY, generated_at=0.0)
        self.assertEqual(s1, s2)
        self.assertEqual(s1.to_dict(), s2.to_dict())


class SerializationTests(unittest.TestCase):
    """to_dict() is the language-neutral wire form validated against
    protocol/atlas-snapshot.schema.json."""

    def test_to_dict_shape(self) -> None:
        snap = build_snapshot(build_journal(), policies=CAP_POLICY, generated_at=2.0)
        d = snap.to_dict()
        for key in ("policy_version", "generated_at", "capabilities", "nodes",
                    "roots", "store", "questions", "impact"):
            self.assertIn(key, d)
        self.assertIn("observed", d["impact"])
        self.assertIn("reachable", d["impact"])
        self.assertIn("unknown", d["impact"])
        self.assertIsInstance(d["nodes"], dict)
        self.assertEqual(d["nodes"]["A"]["status"], "accepted")


if __name__ == "__main__":
    unittest.main()
