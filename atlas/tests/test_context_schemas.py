"""Context/memory/model protocol schemas — TDD RED first."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - jsonschema is a dev-only extra
    # A missing dev extra must skip, never break collection: an ImportError
    # here aborts the whole discovery run and reads as a broken suite.
    Draft202012Validator = None

ROOT = Path(__file__).resolve().parents[2] / "protocol"


EXAMPLES = {
    "project-definition.schema.json": {
        "id": "fcd", "name": "Fail Closed Dispatch", "revision": 1,
        "local_path": "/repo", "github": "org/repo", "base_branch": "main",
        "project_version": 18, "memory_version": 12, "policy_version": "p4",
        "strict_unknown": True, "skin": "instrument",
    },
    "agent-definition.schema.json": {
        "id": "reviewer", "revision": 7, "name": "Reviewer",
        "instructions": "Review independently", "default_model_id": "opus",
        "tools": ["read", "test"], "authority": ["review"],
    },
    "model-definition.schema.json": {
        "id": "opus", "revision": 2, "provider": "anthropic",
        "api_id": "claude-opus-4-8", "display": "Claude Opus 4.8",
        "context_profile": "1m", "reasoning": "high",
    },
    "gate-definition.schema.json": {
        "id": "review", "revision": 2, "name": "Independent review",
        "agent_id": "reviewer", "executor_id": "claude-code", "model_id": "opus",
        "context_mode": "fresh_blind", "continuity": "fresh",
    },
    "execution-envelope.schema.json": {
        "attempt_id": "W/review/2/abc", "nonce": "abc", "work_item_id": "W",
        "gate_id": "review", "attempt_counter": 2, "project_version": 18,
        "memory_version": 12, "contract_revision": 3, "gate_revision": 2,
        "agent_id": "reviewer", "agent_revision": 7, "specialist": "reviewer-2",
        "executor_id": "claude-code", "executor_revision": 1,
        "model_provider": "anthropic", "model_api_id": "claude-opus-4-8",
        "instruction_hash": "a" * 64, "context_mode": "fresh_blind",
        "memory_scope": "accepted_only", "tool_manifest_hash": "b" * 64,
        "initial_steering_hash": "c" * 64, "steering_channel": "steering/W/review/2",
        "envelope_hash": "d" * 64,
    },
    "context-package.schema.json": {
        "attempt_id": "W/review/2/abc", "categories": ["candidate_diff", "contract"],
        "payload_b64": "e30=", "expected_hash": "a" * 64,
    },
    "adapter-receipt.schema.json": {
        "attempt_id": "W/review/2/abc", "nonce": "abc", "executor_id": "claude-code",
        "run_id": "r1", "package_hash_observed": "a" * 64,
        "continuation_hash": "b" * 64, "executed_provider": "anthropic",
        "executed_model": "claude-opus-4-8",
    },
    "memory-delta.schema.json": {
        "work_item_id": "W", "expected_project_version": 18,
        "expected_memory_version": 12, "facts": ["API added"],
        "references": ["artifact:W"], "raw_transcript_included": False,
    },
    "impact-review.schema.json": {
        "work_item_id": "W", "classification": "reachable",
        "decision": "continue_pinned", "actor": "owner",
        "reviewed_project_version": 19, "reviewed_memory_version": 13,
        "signature": "sig",
    },
    "steering-event.schema.json": {
        "attempt_id": "W/review/2/abc", "sequence": 1, "scope": "gate",
        "target_id": "W", "text": "Redo UI only", "continuation_hash": "a" * 64,
    },
    "context-journal-event.schema.json": {
        "type": "adapter_receipt", "ts": 1.0, "attempt_id": "W/review/2/abc",
        "nonce": "abc", "executor_id": "demo", "run_id": "r1",
        "package_hash_observed": "a" * 64, "continuation_hash": "b" * 64,
        "executed_provider": "demo", "executed_model": "reviewer",
    },
    "execution-readiness.schema.json": {
        "executor_id": "demo", "declared_executor_id": "demo", "executor_connected": True,
        "provider": "demo", "model_api_id": "reviewer",
        "installed": True, "authenticated": True, "model_resolves": True,
        "project_access": True, "tools_available": True, "canary": True,
        "receipt_available": True, "death_observable": True, "ready": True,
    },
}


@unittest.skipIf(Draft202012Validator is None, "jsonschema not installed")
class ContextSchemaTests(unittest.TestCase):
    def test_all_new_schemas_validate_examples(self):
        for filename, example in EXAMPLES.items():
            with self.subTest(filename=filename):
                schema = json.loads((ROOT / filename).read_text())
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(schema).validate(example)

    def test_receipt_requires_attempt_nonce_and_observed_package_hash(self):
        schema = json.loads((ROOT / "adapter-receipt.schema.json").read_text())
        bad = dict(EXAMPLES["adapter-receipt.schema.json"])
        del bad["nonce"]
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(bad)))

    def test_fresh_blind_continuity_is_fresh(self):
        schema = json.loads((ROOT / "gate-definition.schema.json").read_text())
        bad = json.loads(json.dumps(EXAMPLES["gate-definition.schema.json"]))
        bad["continuity"] = "executor_continue"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(bad)))

    def test_project_schema_accepts_complete_model_agent_gate_definition(self):
        schema = json.loads((ROOT / "project-definition.schema.json").read_text())
        full = json.loads(json.dumps(EXAMPLES["project-definition.schema.json"]))
        full["models"] = [{"id": "m", "revision": 1, "provider": "demo", "api_id": "builder"}]
        full["agents"] = [{"id": "a", "revision": 1, "default_model_id": "m", "instructions": "Build"}]
        full["gates"] = [{"id": "g", "revision": 1, "agent_id": "a", "executor_id": "demo", "model_id": "m", "context_mode": "project_shared", "continuity": "fresh"}]
        Draft202012Validator(schema).validate(full)


if __name__ == "__main__":
    unittest.main()
