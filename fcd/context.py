"""Formal context/memory/model/cache extension for fail-closed dispatch.

This module does not implement executor tool/session loops. It pins and validates
what crosses that black-box boundary: project/work snapshots, gate attempts,
context packages, steering sequences, model receipts, cache identity and
accepted-only memory promotion.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, NoReturn


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canon(value) -> bytes:
    def convert(v):
        if dataclasses.is_dataclass(v) and not isinstance(v, type):
            return convert(dataclasses.asdict(v))
        if isinstance(v, Mapping):
            return {str(k): convert(v[k]) for k in sorted(v)}
        if isinstance(v, (set, frozenset)):
            return [convert(x) for x in sorted(v)]
        if isinstance(v, (tuple, list)):
            return [convert(x) for x in v]
        return v

    return json.dumps(convert(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass(frozen=True)
class AgentRef:
    id: str
    revision: int
    instructions: str


@dataclass(frozen=True)
class ExecutionAdapterRef:
    id: str
    revision: int
    capabilities: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ModelRef:
    provider: str
    api_id: str
    display: str = ""


@dataclass(frozen=True)
class ContextPolicy:
    mode: str
    include: frozenset[str]
    exclude: frozenset[str]
    memory_scope: str
    continuity: str = "fresh"


@dataclass(frozen=True)
class GateSpec:
    id: str
    revision: int
    agent: AgentRef
    executor: ExecutionAdapterRef
    model: ModelRef
    context_policy: ContextPolicy
    tool_manifest_hash: str
    instruction_hash: str


@dataclass(frozen=True)
class ProjectState:
    id: str
    project_version: int
    memory_version: int
    policy_version: str
    strict_unknown: bool = True


@dataclass(frozen=True)
class WorkPin:
    project_id: str
    work_item_id: str
    project_version: int
    memory_version: int
    contract_revision: int


@dataclass(frozen=True)
class ExecutionEnvelope:
    attempt_id: str
    nonce: str
    work_item_id: str
    gate_id: str
    attempt_counter: int
    project_version: int
    memory_version: int
    contract_revision: int
    gate_revision: int
    agent_id: str
    agent_revision: int
    specialist: str
    executor_id: str
    executor_revision: int
    model_provider: str
    model_api_id: str
    instruction_hash: str
    context_mode: str
    memory_scope: str
    tool_manifest_hash: str
    initial_steering_hash: str
    steering_channel: str
    envelope_hash: str


@dataclass(frozen=True)
class ContextPackage:
    attempt_id: str
    categories: tuple[str, ...]
    payload: bytes
    expected_hash: str


@dataclass(frozen=True)
class SteeringEvent:
    attempt_id: str
    sequence: int
    scope: str
    target_id: str
    text: str
    continuation_hash: str


@dataclass(frozen=True)
class AdapterReceipt:
    attempt_id: str
    nonce: str
    executor_id: str
    run_id: str
    package_hash_observed: str
    continuation_hash: str
    executed_provider: str
    executed_model: str


@dataclass(frozen=True)
class AttemptRecord:
    envelope: ExecutionEnvelope
    state: str
    package_hash: str | None
    latest_continuation_hash: str
    acknowledged_continuation_hash: str | None
    receipt: AdapterReceipt | None
    executor_reuse: tuple[bool, str | None] | None


@dataclass(frozen=True)
class KnowledgeDelta:
    facts: tuple[str, ...]
    references: tuple[str, ...]


@dataclass(frozen=True)
class ImpactReview:
    work_item_id: str
    classification: str
    decision: str
    actor: str
    reviewed_head: tuple[int, int]


@dataclass(frozen=True)
class InstructionLayer:
    name: str
    text: str
    allow_tools: frozenset[str] = frozenset()
    deny_tools: frozenset[str] = frozenset()


@dataclass(frozen=True)
class InstructionManifest:
    layers: tuple[InstructionLayer, ...]
    allowed_tools: frozenset[str]
    denied_tools: frozenset[str]
    manifest_hash: str


def compile_instruction_manifest(layers: Iterable[InstructionLayer]) -> InstructionManifest:
    """Higher-layer denial cannot be widened by a lower layer."""
    ordered = tuple(layers)
    allowed: set[str] = set()
    denied: set[str] = set()
    for layer in ordered:
        if layer.allow_tools & layer.deny_tools:
            raise ValueError(f"instruction layer {layer.name!r} both allows and denies a tool")
        conflict = set(layer.allow_tools) & denied
        if conflict:
            raise ValueError(f"lower instruction layer widens denied tools: {sorted(conflict)}")
        denied.update(layer.deny_tools)
        allowed.difference_update(layer.deny_tools)
        allowed.update(layer.allow_tools)
    payload = {"layers": ordered, "allowed": sorted(allowed), "denied": sorted(denied)}
    return InstructionManifest(ordered, frozenset(allowed), frozenset(denied), hash_bytes(_canon(payload)))


@dataclass
class _Attempt:
    envelope: ExecutionEnvelope
    gate: GateSpec
    state: str = "Running"
    package: ContextPackage | None = None
    steering_sequence: int = 0
    latest_continuation_hash: str = ""
    acknowledged_continuation_hash: str | None = None
    receipt: AdapterReceipt | None = None
    executor_reuse: tuple[bool, str | None] | None = None


class ContextAuthority:
    """State authority for I10–I17.

    All executor/model behavior remains external. This class proves only the
    envelope/package/receipt/state properties it can observe.
    """

    _PACKAGE_MODES = {"fresh_blind", "fresh_scoped", "project_shared", "contract_only"}
    _CONTINUITY = {"fresh", "executor_continue", "executor_fork"}
    _SCOPES = {"project", "work", "gate", "stage", "artifact", "evidence", "failure"}

    def __init__(self, *, is_accepted: Callable[[str], bool], clock: Callable[[], float] = time.time) -> None:
        self._is_accepted = is_accepted
        self._clock = clock
        self.events: list[dict] = []
        self._projects: dict[str, ProjectState] = {}
        self._works: dict[str, WorkPin] = {}
        self._pre_steering: dict[str, list[dict[str, str]]] = {}
        self._attempts: dict[str, _Attempt] = {}
        self._attempt_counters: dict[tuple[str, str], int] = {}
        self._open_attempt: dict[tuple[str, str], str] = {}
        self._impact_reviews: dict[str, ImpactReview] = {}
        self._knowledge: dict[str, list[KnowledgeDelta]] = {}

    def _emit(self, event_type: str, **fields) -> None:
        self.events.append({"type": event_type, "ts": self._clock(), **fields})

    def add_project(self, project: ProjectState) -> None:
        if project.id in self._projects:
            raise ValueError("project already exists")
        self._projects[project.id] = project
        self._knowledge[project.id] = []

    def advance_project_for_test(self, project_id: str, project_version: int, memory_version: int) -> None:
        p = self._projects[project_id]
        self._projects[project_id] = dataclasses.replace(
            p, project_version=project_version, memory_version=memory_version
        )

    def project_head(self, project_id: str) -> tuple[int, int]:
        p = self._projects[project_id]
        return (p.project_version, p.memory_version)

    def project_state(self, project_id: str) -> ProjectState:
        return self._projects[project_id]

    def is_accepted(self, work_item_id: str) -> bool:
        return self._is_accepted(work_item_id)

    def work_pins(self, project_id: str | None = None) -> tuple[WorkPin, ...]:
        return tuple(
            w for w in self._works.values()
            if project_id is None or w.project_id == project_id
        )

    def attempt_records(self, project_id: str | None = None) -> tuple[AttemptRecord, ...]:
        allowed_work = {w.work_item_id for w in self.work_pins(project_id)}
        return tuple(
            AttemptRecord(
                envelope=a.envelope,
                state=a.state,
                package_hash=a.package.expected_hash if a.package else None,
                latest_continuation_hash=a.latest_continuation_hash,
                acknowledged_continuation_hash=a.acknowledged_continuation_hash,
                receipt=a.receipt,
                executor_reuse=a.executor_reuse,
            )
            for a in self._attempts.values()
            if a.envelope.work_item_id in allowed_work
        )

    def impact_reviews(self, project_id: str | None = None) -> tuple[ImpactReview, ...]:
        allowed_work = {w.work_item_id for w in self.work_pins(project_id)}
        return tuple(r for r in self._impact_reviews.values() if r.work_item_id in allowed_work)

    def open_work(self, project_id: str, work_item_id: str, contract_revision: int) -> WorkPin:
        if work_item_id in self._works:
            raise ValueError("work item already exists")
        p = self._projects[project_id]
        pin = WorkPin(project_id, work_item_id, p.project_version, p.memory_version, contract_revision)
        self._works[work_item_id] = pin
        self._pre_steering[work_item_id] = []
        self._emit("work_pin", project_id=project_id, work_item_id=work_item_id,
                   project_version=pin.project_version, memory_version=pin.memory_version,
                   contract_revision=contract_revision)
        return pin

    def record_pre_admit_steering(self, work_item_id: str, scope: str, text: str) -> None:
        if scope not in self._SCOPES:
            raise ValueError("invalid steering scope")
        self._pre_steering[work_item_id].append({"scope": scope, "text": text})

    def admit(self, work_item_id: str, gate: GateSpec, *, specialist: str) -> _Attempt:
        if gate.context_policy.mode not in self._PACKAGE_MODES:
            raise ValueError("unknown FCD package mode")
        if gate.context_policy.continuity not in self._CONTINUITY:
            raise ValueError("unknown executor continuity hint")
        if gate.context_policy.mode == "fresh_blind" and gate.context_policy.continuity != "fresh":
            raise ValueError("fresh_blind forbids executor continuity")
        if gate.context_policy.continuity == "executor_continue" and "continue" not in gate.executor.capabilities:
            raise ValueError("executor lacks continue capability")
        if gate.context_policy.continuity == "executor_fork" and "fork" not in gate.executor.capabilities:
            raise ValueError("executor lacks fork capability")

        key = (work_item_id, gate.id)
        if key in self._open_attempt and self._attempts[self._open_attempt[key]].state != "Closed":
            raise ValueError("gate already has a live attempt")
        count = self._attempt_counters.get(key, 0) + 1
        self._attempt_counters[key] = count
        nonce = secrets.token_hex(16)
        attempt_id = f"{work_item_id}/{gate.id}/{count}/{nonce}"
        work = self._works[work_item_id]
        s0 = hash_bytes(_canon(self._pre_steering[work_item_id]))
        channel = f"steering/{work_item_id}/{gate.id}/{count}"
        fields = {
            "attempt_id": attempt_id,
            "nonce": nonce,
            "work_item_id": work_item_id,
            "gate_id": gate.id,
            "attempt_counter": count,
            "project_version": work.project_version,
            "memory_version": work.memory_version,
            "contract_revision": work.contract_revision,
            "gate_revision": gate.revision,
            "agent_id": gate.agent.id,
            "agent_revision": gate.agent.revision,
            "specialist": specialist,
            "executor_id": gate.executor.id,
            "executor_revision": gate.executor.revision,
            "model_provider": gate.model.provider,
            "model_api_id": gate.model.api_id,
            "instruction_hash": gate.instruction_hash,
            "context_mode": gate.context_policy.mode,
            "memory_scope": gate.context_policy.memory_scope,
            "tool_manifest_hash": gate.tool_manifest_hash,
            "initial_steering_hash": s0,
            "steering_channel": channel,
        }
        envelope_hash = hash_bytes(_canon(fields))
        envelope = ExecutionEnvelope(**fields, envelope_hash=envelope_hash)
        attempt = _Attempt(envelope=envelope, gate=gate, latest_continuation_hash=s0)
        self._attempts[attempt_id] = attempt
        self._open_attempt[key] = attempt_id
        self._emit("envelope_admit", attempt_id=attempt_id, nonce=nonce,
                   work_item_id=work_item_id, gate_id=gate.id, attempt_counter=count,
                   project_version=work.project_version, memory_version=work.memory_version,
                   contract_revision=work.contract_revision, gate_revision=gate.revision,
                   agent_id=gate.agent.id, agent_revision=gate.agent.revision,
                   specialist=specialist, executor_id=gate.executor.id,
                   executor_revision=gate.executor.revision,
                   model_provider=gate.model.provider, model_api_id=gate.model.api_id,
                   instruction_hash=gate.instruction_hash, context_mode=gate.context_policy.mode,
                   memory_scope=gate.context_policy.memory_scope,
                   tool_manifest_hash=gate.tool_manifest_hash,
                   initial_steering_hash=s0, steering_channel=channel,
                   envelope_hash=envelope_hash)
        return attempt

    def close(self, attempt_id: str) -> None:
        self._attempts[attempt_id].state = "Closed"

    def mark_passed(self, attempt_id: str) -> None:
        if not self.can_pass(attempt_id):
            raise ValueError("attempt cannot pass without current valid receipt")
        self._attempts[attempt_id].state = "Passed"

    def append_steering(self, attempt_id: str, scope: str, target_id: str, text: str) -> SteeringEvent:
        a = self._attempts[attempt_id]
        if a.state != "Running":
            raise ValueError("attempt is not running")
        if scope not in self._SCOPES:
            raise ValueError("invalid steering scope")
        if target_id != a.envelope.work_item_id:
            raise ValueError("steering cannot target sibling work")
        if self._is_accepted(target_id):
            raise ValueError("accepted state is immutable")
        seq = a.steering_sequence + 1
        payload = {
            "attempt_id": attempt_id, "sequence": seq, "scope": scope,
            "target_id": target_id, "text": text,
        }
        continuation = hash_bytes(
            a.latest_continuation_hash.encode() + b"\0" + _canon(payload)
        )
        a.steering_sequence = seq
        a.latest_continuation_hash = continuation
        a.acknowledged_continuation_hash = None
        a.receipt = None
        self._emit("steering", attempt_id=attempt_id, sequence=seq, scope=scope,
                   target_id=target_id, text_hash=hash_bytes(text.encode()),
                   continuation_hash=continuation)
        return SteeringEvent(attempt_id, seq, scope, target_id, text, continuation)

    def compile_package(self, attempt_id: str, records: Mapping[str, bytes]) -> ContextPackage:
        a = self._attempts[attempt_id]
        policy = a.gate.context_policy
        effective = sorted((set(policy.include) - set(policy.exclude)) & set(records))
        if policy.mode == "fresh_blind":
            excluded = {"builder_transcript", "builder_reasoning", "previous_review_verdict", "unaccepted_memory"}
            if set(effective) & excluded:
                raise ValueError("fresh_blind package contains excluded author context")
        encoded = [
            {"category": category, "content_b64": base64.b64encode(records[category]).decode()}
            for category in effective
        ]
        payload = _canon({
            "attempt_id": attempt_id,
            "categories": effective,
            "records": encoded,
        })
        package = ContextPackage(attempt_id, tuple(effective), payload, hash_bytes(payload))
        a.package = package
        a.receipt = None
        self._emit("context_package", attempt_id=attempt_id, nonce=a.envelope.nonce,
                   categories=list(package.categories), package_hash_expected=package.expected_hash)
        return package

    def accept_receipt(self, receipt: AdapterReceipt) -> bool:
        return self.accept_receipt_for(receipt.attempt_id, receipt)

    def accept_receipt_for(self, attempt_id: str, receipt: AdapterReceipt) -> bool:
        a = self._attempts[attempt_id]
        e = a.envelope
        valid = bool(
            a.state == "Running"
            and a.package is not None
            and receipt.attempt_id == attempt_id
            and receipt.nonce == e.nonce
            and receipt.executor_id == e.executor_id
            and receipt.package_hash_observed == a.package.expected_hash
            and receipt.continuation_hash == a.latest_continuation_hash
            and receipt.executed_provider == e.model_provider
            and receipt.executed_model == e.model_api_id
        )
        if valid:
            a.receipt = receipt
            a.acknowledged_continuation_hash = receipt.continuation_hash
            self._emit("adapter_receipt", attempt_id=receipt.attempt_id,
                       nonce=receipt.nonce, executor_id=receipt.executor_id,
                       run_id=receipt.run_id,
                       package_hash_observed=receipt.package_hash_observed,
                       continuation_hash=receipt.continuation_hash,
                       executed_provider=receipt.executed_provider,
                       executed_model=receipt.executed_model)
        else:
            self._emit("receipt_refuse", target_attempt_id=attempt_id,
                       receipt_attempt_id=receipt.attempt_id, nonce=receipt.nonce,
                       executor_id=receipt.executor_id, run_id=receipt.run_id,
                       package_hash_observed=receipt.package_hash_observed,
                       continuation_hash=receipt.continuation_hash,
                       executed_provider=receipt.executed_provider,
                       executed_model=receipt.executed_model)
        return valid

    def can_pass(self, attempt_id: str) -> bool:
        a = self._attempts[attempt_id]
        return bool(
            a.state == "Running"
            and a.package is not None
            and a.receipt is not None
            and a.acknowledged_continuation_hash == a.latest_continuation_hash
        )

    def cache_id(self, attempt_id: str) -> str:
        a = self._attempts[attempt_id]
        return hash_bytes(_canon({
            "envelope_hash": a.envelope.envelope_hash,
            "attempt_id": attempt_id,
            "nonce": a.envelope.nonce,
            "context_mode": a.envelope.context_mode,
            "initial_steering_hash": a.envelope.initial_steering_hash,
            "continuation_hash": a.latest_continuation_hash,
        }))

    def record_executor_reuse(self, attempt_id: str, reported_reuse: bool, opaque_id: str | None) -> None:
        self._attempts[attempt_id].executor_reuse = (reported_reuse, opaque_id)

    def review_impact(self, work_item_id: str, classification: str, decision: str, actor: str) -> ImpactReview:
        if classification not in {"unaffected", "reachable", "direct_conflict", "unknown"}:
            raise ValueError("invalid impact classification")
        project = self._projects[self._works[work_item_id].project_id]
        if classification == "direct_conflict" and decision != "refresh":
            raise ValueError("direct conflict requires refresh")
        if classification == "reachable" and decision not in {"continue_pinned", "refresh"}:
            raise ValueError("reachable impact requires signed continue or refresh")
        if classification == "unknown":
            if project.strict_unknown and not (decision == "owner_override" and actor == "owner"):
                raise ValueError("strict unknown impact requires owner override")
        review = ImpactReview(work_item_id, classification, decision, actor, self.project_head(project.id))
        self._impact_reviews[work_item_id] = review
        self._emit("impact_review", work_item_id=work_item_id,
                   classification=classification, decision=decision, actor=actor,
                   reviewed_project_version=review.reviewed_head[0],
                   reviewed_memory_version=review.reviewed_head[1],
                   signature=hash_bytes(_canon(review)))
        return review

    def _promotion_refuse(self, work_item_id: str, expected_head: tuple[int, int], reason: str) -> NoReturn:
        work = self._works[work_item_id]
        current = self.project_head(work.project_id)
        self._emit("memory_promote", work_item_id=work_item_id,
                   expected_project_version=expected_head[0],
                   expected_memory_version=expected_head[1],
                   current_project_version=current[0], current_memory_version=current[1],
                   result="refuse", reason=reason)
        raise ValueError(reason)

    def promote(self, work_item_id: str, delta: KnowledgeDelta, *, expected_head: tuple[int, int]) -> tuple[int, int]:
        if not self._is_accepted(work_item_id):
            self._promotion_refuse(work_item_id, expected_head, "only accepted work may promote knowledge")
        work = self._works[work_item_id]
        current = self.project_head(work.project_id)
        if expected_head != current:
            self._promotion_refuse(work_item_id, expected_head, "promotion CAS failed: project head changed")
        pin = (work.project_version, work.memory_version)
        if pin != current:
            review = self._impact_reviews.get(work_item_id)
            if review is None or review.reviewed_head != current:
                self._promotion_refuse(work_item_id, expected_head, "stale work requires impact review of current head")
            if review.decision not in {"continue_pinned", "owner_override"}:
                self._promotion_refuse(work_item_id, expected_head, "impact review requires refresh, not promotion")
        p = self._projects[work.project_id]
        new = (p.project_version + 1, p.memory_version + 1)
        self._projects[work.project_id] = dataclasses.replace(
            p, project_version=new[0], memory_version=new[1]
        )
        self._knowledge[work.project_id].append(delta)
        self._emit("memory_promote", work_item_id=work_item_id,
                   expected_project_version=expected_head[0],
                   expected_memory_version=expected_head[1],
                   resulting_project_version=new[0], resulting_memory_version=new[1],
                   knowledge_delta_hash=hash_bytes(_canon(delta)),
                   references=list(delta.references), result="success")
        return new
