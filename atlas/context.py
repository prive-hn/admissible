"""Immutable project/context projection for the FCD cockpit."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from fcd.context import ContextAuthority


@dataclass(frozen=True)
class ProjectView:
    id: str
    project_version: int
    memory_version: int
    policy_version: str
    strict_unknown: bool


@dataclass(frozen=True)
class WorkLineView:
    work_item_id: str
    project_version: int
    memory_version: int
    contract_revision: int


@dataclass(frozen=True)
class AttemptView:
    attempt_id: str
    work_item_id: str
    gate_id: str
    attempt_counter: int
    state: str
    agent_id: str
    specialist: str
    executor_id: str
    model_provider: str
    model_api_id: str
    context_mode: str
    project_version: int
    memory_version: int
    locked: bool
    package_status: str
    receipt_status: str
    steering_sequence_acknowledged: bool
    executor_reuse_reported: bool | None


@dataclass(frozen=True)
class DriftView:
    work_item_id: str
    pinned_head: tuple[int, int]
    current_head: tuple[int, int]
    status: str                  # needs_review | reviewed
    classification: str | None
    decision: str | None


@dataclass(frozen=True)
class ContextAtlas:
    project: ProjectView
    work_items: tuple[WorkLineView, ...]
    attempts: tuple[AttemptView, ...]
    drift: tuple[DriftView, ...]
    counts: Mapping[str, int]


def build_context_atlas(authority: ContextAuthority, project_id: str) -> ContextAtlas:
    """Project/work-first projection. Executor sessions are evidence fields,
    never the hierarchy."""
    project = authority.project_state(project_id)
    head = authority.project_head(project_id)
    works = authority.work_pins(project_id)
    reviews = {r.work_item_id: r for r in authority.impact_reviews(project_id)}

    work_views = tuple(
        WorkLineView(w.work_item_id, w.project_version, w.memory_version, w.contract_revision)
        for w in works
    )

    attempt_views = []
    for record in authority.attempt_records(project_id):
        e = record.envelope
        reuse = None if record.executor_reuse is None else record.executor_reuse[0]
        attempt_views.append(AttemptView(
            attempt_id=e.attempt_id,
            work_item_id=e.work_item_id,
            gate_id=e.gate_id,
            attempt_counter=e.attempt_counter,
            state=record.state,
            agent_id=e.agent_id,
            specialist=e.specialist,
            executor_id=e.executor_id,
            model_provider=e.model_provider,
            model_api_id=e.model_api_id,
            context_mode=e.context_mode,
            project_version=e.project_version,
            memory_version=e.memory_version,
            locked=True,
            package_status="ready" if record.package_hash else "missing",
            receipt_status="valid" if record.receipt else "missing",
            steering_sequence_acknowledged=(
                record.acknowledged_continuation_hash == record.latest_continuation_hash
                if record.receipt else False
            ),
            executor_reuse_reported=reuse,
        ))

    drift_views = []
    for w in works:
        if authority.is_accepted(w.work_item_id):
            continue
        pin = (w.project_version, w.memory_version)
        if pin == head:
            continue
        review = reviews.get(w.work_item_id)
        current_review = review is not None and review.reviewed_head == head
        classification = review.classification if current_review and review is not None else None
        decision = review.decision if current_review and review is not None else None
        drift_views.append(DriftView(
            work_item_id=w.work_item_id,
            pinned_head=pin,
            current_head=head,
            status="reviewed" if current_review else "needs_review",
            classification=classification,
            decision=decision,
        ))

    counts = MappingProxyType({
        "work_items": len(work_views),
        "attempts": len(attempt_views),
        "drift": sum(d.status == "needs_review" for d in drift_views),
        "drift_reviewed": sum(d.status == "reviewed" for d in drift_views),
    })
    return ContextAtlas(
        project=ProjectView(project.id, project.project_version, project.memory_version,
                            project.policy_version, project.strict_unknown),
        work_items=work_views,
        attempts=tuple(attempt_views),
        drift=tuple(drift_views),
        counts=counts,
    )
