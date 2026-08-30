"""I10–I17 context/memory/model/cache extension — TDD RED first."""
from __future__ import annotations

import dataclasses
import unittest

import fcd
import protocol
from fcd.context import (
    AdapterReceipt,
    AgentRef,
    ContextAuthority,
    ContextPolicy,
    ExecutionAdapterRef,
    GateSpec,
    InstructionLayer,
    KnowledgeDelta,
    ModelRef,
    ProjectState,
    compile_instruction_manifest,
    hash_bytes,
)


def refs(*, model="model-a", mode="project_shared", continuity="fresh", caps=frozenset()):
    agent = AgentRef("builder", 1, "Build the requested outcome")
    executor = ExecutionAdapterRef("codex", 1, caps)
    model_ref = ModelRef("openai", model, "Builder model")
    policy = ContextPolicy(
        mode=mode,
        include=frozenset({"accepted_project_facts", "contract", "candidate_diff"}),
        exclude=frozenset(),
        memory_scope="accepted_only",
        continuity=continuity,
    )
    gate = GateSpec(
        id="implement", revision=1, agent=agent, executor=executor,
        model=model_ref, context_policy=policy,
        tool_manifest_hash="tools-v1", instruction_hash="instructions-v1",
    )
    return gate


class PackageSurfaceTests(unittest.TestCase):
    def test_context_authority_remains_public_in_version_0_5(self):
        self.assertEqual(fcd.__version__, "0.5.0")
        for name in ("ContextAuthority", "ExecutionEnvelope", "AdapterReceipt", "ProjectState"):
            self.assertTrue(hasattr(fcd, name), name)
        self.assertTrue(protocol.schema_path("execution-readiness.schema.json").is_file())


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.accepted = set()
        self.auth = ContextAuthority(is_accepted=lambda w: w in self.accepted)
        self.auth.add_project(ProjectState("p", 18, 12, "policy-4", strict_unknown=True))
        self.work = self.auth.open_work("p", "W1", contract_revision=3)

    def test_i10_work_pins_project_memory_and_envelope_is_frozen(self):
        attempt = self.auth.admit("W1", refs(), specialist="worker-1")
        self.auth.advance_project_for_test("p", 19, 13)
        self.assertEqual((self.work.project_version, self.work.memory_version), (18, 12))
        self.assertEqual((attempt.envelope.project_version, attempt.envelope.memory_version), (18, 12))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            attempt.envelope.project_version = 19  # type: ignore[misc]

    def test_retry_has_new_counter_nonce_and_hash(self):
        a1 = self.auth.admit("W1", refs(), specialist="worker-1")
        self.auth.close(a1.envelope.attempt_id)
        a2 = self.auth.admit("W1", refs(), specialist="worker-2")
        self.assertNotEqual(a1.envelope.attempt_id, a2.envelope.attempt_id)
        self.assertNotEqual(a1.envelope.nonce, a2.envelope.nonce)
        self.assertNotEqual(a1.envelope.envelope_hash, a2.envelope.envelope_hash)

    def test_pre_admit_steering_is_frozen_but_live_steering_chains(self):
        self.auth.record_pre_admit_steering("W1", "work", "Keep API stable")
        a = self.auth.admit("W1", refs(), specialist="worker-1")
        s0 = a.envelope.initial_steering_hash
        ev = self.auth.append_steering(a.envelope.attempt_id, "gate", "W1", "Redo UI only")
        self.assertEqual(a.envelope.initial_steering_hash, s0)
        self.assertEqual(ev.sequence, 1)
        self.assertNotEqual(ev.continuation_hash, s0)
        self.assertFalse(self.auth.can_pass(a.envelope.attempt_id))

    def test_steering_cannot_target_sibling_or_accepted_state(self):
        self.auth.open_work("p", "W2", contract_revision=1)
        a = self.auth.admit("W1", refs(), specialist="worker-1")
        with self.assertRaises(ValueError):
            self.auth.append_steering(a.envelope.attempt_id, "work", "W2", "Leak")
        self.accepted.add("W1")
        with self.assertRaises(ValueError):
            self.auth.append_steering(a.envelope.attempt_id, "artifact", "W1", "Mutate accepted")


class ContextAndReceiptTests(unittest.TestCase):
    def setUp(self):
        self.auth = ContextAuthority(is_accepted=lambda _: False)
        self.auth.add_project(ProjectState("p", 1, 1, "policy-1"))
        self.auth.open_work("p", "W", contract_revision=1)

    def test_i12_fresh_blind_excludes_author_context_and_continuity(self):
        gate = refs(mode="fresh_blind")
        gate = dataclasses.replace(
            gate,
            context_policy=dataclasses.replace(
                gate.context_policy,
                include=frozenset({"contract", "candidate_diff", "builder_transcript"}),
                exclude=frozenset({"builder_transcript", "builder_reasoning", "previous_review_verdict"}),
            ),
        )
        a = self.auth.admit("W", gate, specialist="reviewer")
        package = self.auth.compile_package(a.envelope.attempt_id, {
            "contract": b"contract", "candidate_diff": b"diff",
            "builder_transcript": b"secret", "builder_reasoning": b"secret2",
        })
        self.assertEqual(package.categories, ("candidate_diff", "contract"))
        self.assertNotIn(b"secret", package.payload)

        bad = refs(mode="fresh_blind", continuity="executor_continue", caps=frozenset({"continue"}))
        with self.assertRaises(ValueError):
            self.auth.admit("W", bad, specialist="reviewer")

    def test_adapter_hash_is_independent_and_receipt_mismatch_refuses(self):
        a = self.auth.admit("W", refs(), specialist="worker")
        package = self.auth.compile_package(a.envelope.attempt_id, {"contract": b"c"})
        wrong = AdapterReceipt(
            attempt_id=a.envelope.attempt_id, nonce=a.envelope.nonce,
            executor_id="codex", run_id="r1", package_hash_observed=hash_bytes(b"wrong"),
            continuation_hash=a.latest_continuation_hash,
            executed_provider="openai", executed_model="model-a",
        )
        self.assertFalse(self.auth.accept_receipt(wrong))
        self.assertFalse(self.auth.can_pass(a.envelope.attempt_id))

        right = dataclasses.replace(wrong, package_hash_observed=hash_bytes(package.payload))
        self.assertTrue(self.auth.accept_receipt(right))
        self.assertTrue(self.auth.can_pass(a.envelope.attempt_id))

    def test_prior_attempt_receipt_is_rejected(self):
        a1 = self.auth.admit("W", refs(), specialist="worker")
        p1 = self.auth.compile_package(a1.envelope.attempt_id, {"contract": b"c"})
        stale = AdapterReceipt(
            attempt_id=a1.envelope.attempt_id, nonce=a1.envelope.nonce,
            executor_id="codex", run_id="r1", package_hash_observed=hash_bytes(p1.payload),
            continuation_hash=a1.latest_continuation_hash,
            executed_provider="openai", executed_model="model-a",
        )
        self.auth.close(a1.envelope.attempt_id)
        a2 = self.auth.admit("W", refs(), specialist="worker2")
        self.auth.compile_package(a2.envelope.attempt_id, {"contract": b"c"})
        self.assertFalse(self.auth.accept_receipt_for(a2.envelope.attempt_id, stale))

    def test_stale_steering_sequence_blocks_pass(self):
        a = self.auth.admit("W", refs(), specialist="worker")
        p = self.auth.compile_package(a.envelope.attempt_id, {"contract": b"c"})
        old_hash = a.latest_continuation_hash
        self.auth.append_steering(a.envelope.attempt_id, "gate", "W", "change")
        stale = AdapterReceipt(
            attempt_id=a.envelope.attempt_id, nonce=a.envelope.nonce,
            executor_id="codex", run_id="r1", package_hash_observed=hash_bytes(p.payload),
            continuation_hash=old_hash, executed_provider="openai", executed_model="model-a",
        )
        self.assertFalse(self.auth.accept_receipt(stale))

    def test_i10_i17_events_are_append_only_receipts(self):
        a = self.auth.admit("W", refs(), specialist="worker")
        package = self.auth.compile_package(a.envelope.attempt_id, {"contract": b"c"})
        self.auth.append_steering(a.envelope.attempt_id, "gate", "W", "bounded change")
        receipt = AdapterReceipt(
            attempt_id=a.envelope.attempt_id, nonce=a.envelope.nonce,
            executor_id="codex", run_id="r1", package_hash_observed=hash_bytes(package.payload),
            continuation_hash=a.latest_continuation_hash,
            executed_provider="openai", executed_model="model-a",
        )
        self.assertTrue(self.auth.accept_receipt(receipt))
        types = [e["type"] for e in self.auth.events]
        self.assertEqual(types[:2], ["work_pin", "envelope_admit"])
        self.assertIn("context_package", types)
        self.assertIn("steering", types)
        self.assertIn("adapter_receipt", types)
        observed = next(e for e in self.auth.events if e["type"] == "adapter_receipt")
        self.assertEqual(observed["nonce"], a.envelope.nonce)
        self.assertEqual(observed["executed_model"], "model-a")


class CacheAndCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.auth = ContextAuthority(is_accepted=lambda _: False)
        self.auth.add_project(ProjectState("p", 1, 1, "policy"))
        self.auth.open_work("p", "W", 1)

    def test_i16_cache_identity_changes_for_every_attempt_dimension(self):
        a1 = self.auth.admit("W", refs(), specialist="worker")
        base = self.auth.cache_id(a1.envelope.attempt_id)
        self.auth.close(a1.envelope.attempt_id)
        variants = [
            refs(model="model-b"),
            dataclasses.replace(refs(), tool_manifest_hash="tools-v2"),
            dataclasses.replace(refs(), instruction_hash="instructions-v2"),
            refs(mode="contract_only"),
        ]
        for i, gate in enumerate(variants):
            a = self.auth.admit("W", gate, specialist=f"worker-{i}")
            self.assertNotEqual(base, self.auth.cache_id(a.envelope.attempt_id))
            self.auth.close(a.envelope.attempt_id)

    def test_executor_continuity_requires_declared_capability_and_is_telemetry_only(self):
        with self.assertRaises(ValueError):
            self.auth.admit("W", refs(continuity="executor_fork"), specialist="worker")
        gate = refs(continuity="executor_fork", caps=frozenset({"fork"}))
        a = self.auth.admit("W", gate, specialist="worker")
        self.auth.record_executor_reuse(a.envelope.attempt_id, True, "opaque-cache")
        self.assertFalse(self.auth.can_pass(a.envelope.attempt_id))


class InstructionTests(unittest.TestCase):
    def test_lower_layer_cannot_widen_higher_denial(self):
        layers = [
            InstructionLayer("project", "Never deploy", deny_tools=frozenset({"deploy"})),
            InstructionLayer("gate", "Deploy it", allow_tools=frozenset({"deploy"})),
        ]
        with self.assertRaises(ValueError):
            compile_instruction_manifest(layers)


class PromotionAndDriftTests(unittest.TestCase):
    def setUp(self):
        self.accepted = {"A", "B"}
        self.auth = ContextAuthority(is_accepted=lambda w: w in self.accepted)
        self.auth.add_project(ProjectState("p", 18, 12, "policy", strict_unknown=True))
        self.auth.open_work("p", "A", 1)
        self.auth.open_work("p", "B", 1)

    def test_i13_concurrent_cas_has_one_winner(self):
        delta_a = KnowledgeDelta(("A added",), ("artifact:A",))
        delta_b = KnowledgeDelta(("B added",), ("artifact:B",))
        h = self.auth.project_head("p")
        self.assertEqual(self.auth.promote("A", delta_a, expected_head=h), (19, 13))
        with self.assertRaises(ValueError):
            self.auth.promote("B", delta_b, expected_head=h)
        self.assertEqual(self.auth.project_head("p"), (19, 13))

    def test_drift_blocks_until_signed_review_and_review_invalidates_on_new_head(self):
        h = self.auth.project_head("p")
        self.auth.promote("A", KnowledgeDelta(("A",), ()), expected_head=h)
        with self.assertRaises(ValueError):
            self.auth.promote("B", KnowledgeDelta(("B",), ()), expected_head=self.auth.project_head("p"))
        review = self.auth.review_impact("B", classification="reachable", decision="continue_pinned", actor="owner")
        reviewed_head = review.reviewed_head
        # Another accepted item advances the head; B's review is stale.
        self.auth.open_work("p", "C", 1)
        self.accepted.add("C")
        self.auth.promote("C", KnowledgeDelta(("C",), ()), expected_head=reviewed_head)
        with self.assertRaises(ValueError):
            self.auth.promote("B", KnowledgeDelta(("B",), ()), expected_head=self.auth.project_head("p"))

    def test_unknown_strict_requires_explicit_owner_override(self):
        h = self.auth.project_head("p")
        self.auth.promote("A", KnowledgeDelta(("A",), ()), expected_head=h)
        with self.assertRaises(ValueError):
            self.auth.review_impact("B", "unknown", "continue_pinned", "agent")
        review = self.auth.review_impact("B", "unknown", "owner_override", "owner")
        self.assertEqual(review.reviewed_head, self.auth.project_head("p"))


if __name__ == "__main__":
    unittest.main()
