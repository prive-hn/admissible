"""atlas.model — pure, deterministic reducer: fcd journal -> AtlasSnapshot.

No I/O, no clock, no filesystem, stdlib only. Given an append-only fcd
journal (list of event dicts, exactly as emitted by `fcd.core.Enforcer`)
plus declared plan / question / artifact records, produce ONE immutable
`AtlasSnapshot`. That snapshot is the canonical cockpit state. Skins render
it; they cannot mutate it.

Grounding rule (inherited from fcd's "a pixel without an event is F1"):
every `item`/`stage` node is derived from a real journal event. Nodes that
only exist in a plan are marked `status="planned"` and carry no executed
model — they are declared, not observed.

Impact taxonomy on failure — the three sets are disjoint and cover every
item node:

  observed   items with a published fail-closed decision in the journal.
  reachable  not-observed items that declare a dependency path (depends_on,
             transitively) onto an observed item. Declared-but-unproven
             blast radius.
  unknown    everything else. NOT asserted safe — merely not asserted
             failed and not asserted reachable. Absence of a claim.

This mirrors the paper: publish what was observed, bound what is reachable,
refuse to pretend the rest is fine.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping, Optional, Sequence, Union

from fcd.core import Policy


# --------------------------------------------------------------------------
# Value objects. All frozen: a snapshot and everything it holds is immutable.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Question:
    """An unresolved question. Blocks ONLY `node_id` — never the atlas."""
    id: str
    node_id: str
    text: str
    resolved: bool = False

    def to_dict(self) -> dict:
        return {"id": self.id, "node_id": self.node_id, "text": self.text,
                "resolved": self.resolved}


@dataclass(frozen=True)
class Artifact:
    """A real, addressable artifact projected from evidence. `present` and
    `runnable` are observed facts about the artifact, not aspirations."""
    id: str
    node_id: str
    kind: str
    uri: str
    present: bool = False
    runnable: bool = False

    def to_dict(self) -> dict:
        return {"id": self.id, "node_id": self.node_id, "kind": self.kind,
                "uri": self.uri, "present": self.present, "runnable": self.runnable}


@dataclass(frozen=True)
class Node:
    """A work node in the atlas tree.

    kind: "item" | "stage" (both derived from the journal or a plan record).
    Capability nodes use `CapabilityNode` (a distinct tree).
    """
    id: str
    kind: str
    label: str
    parent: Optional[str] = None
    children: tuple[str, ...] = ()
    status: Optional[str] = None            # planned|open|failed|accepted (item); pc (stage)
    node_class: Optional[str] = None
    policy_version: Optional[str] = None
    declared_model: Optional[str] = None
    executed_model: Optional[str] = None
    fault: Optional[str] = None
    depends_on: tuple[str, ...] = ()
    blocked: bool = False
    questions: tuple[Question, ...] = ()
    artifacts: tuple[Artifact, ...] = ()

    def to_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "label": self.label,
            "parent": self.parent, "children": list(self.children),
            "status": self.status, "node_class": self.node_class,
            "policy_version": self.policy_version,
            "declared_model": self.declared_model,
            "executed_model": self.executed_model, "fault": self.fault,
            "depends_on": list(self.depends_on), "blocked": self.blocked,
            "questions": [q.to_dict() for q in self.questions],
            "artifacts": [a.to_dict() for a in self.artifacts],
        }


@dataclass(frozen=True)
class CapabilityNode:
    """Capability-hierarchy node: class -> specialist -> model. Carries its
    child objects directly so the default view is a real tree."""
    id: str
    kind: str                               # "class" | "specialist" | "model"
    label: str
    parent: Optional[str] = None
    node_class: Optional[str] = None
    children: tuple["CapabilityNode", ...] = ()

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label,
                "parent": self.parent, "node_class": self.node_class,
                "children": [c.to_dict() for c in self.children]}


@dataclass(frozen=True)
class Impact:
    """Failure impact, three disjoint sets over item-node ids."""
    observed: tuple[str, ...] = ()
    reachable: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"observed": list(self.observed),
                "reachable": list(self.reachable),
                "unknown": list(self.unknown)}


@dataclass(frozen=True)
class AtlasSnapshot:
    """Canonical, immutable cockpit state. `project()` returns an equal copy
    (a skin renders a projection; it never touches this object)."""
    policy_version: str
    generated_at: float
    capabilities: tuple[CapabilityNode, ...]
    nodes: Mapping[str, Node]                # MappingProxyType (read-only)
    roots: tuple[str, ...]                   # item nodes with no depends_on
    store: tuple[str, ...]                   # accepted artifact ids
    questions: tuple[Question, ...]
    impact: Impact

    def project(self) -> "AtlasSnapshot":
        """Return an independent, equal snapshot for a skin to consume.
        Every field is frozen/immutable, so this is a safe hand-off: a skin
        cannot reach back into canonical state through it."""
        return AtlasSnapshot(
            policy_version=self.policy_version,
            generated_at=self.generated_at,
            capabilities=self.capabilities,
            nodes=MappingProxyType(dict(self.nodes)),
            roots=self.roots,
            store=self.store,
            questions=self.questions,
            impact=self.impact,
        )

    def to_dict(self) -> dict:
        return {
            "policy_version": self.policy_version,
            "generated_at": self.generated_at,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "roots": list(self.roots),
            "store": list(self.store),
            "questions": [q.to_dict() for q in self.questions],
            "impact": self.impact.to_dict(),
        }


# --------------------------------------------------------------------------
# Capability hierarchy (default view): class -> specialist -> model.
# --------------------------------------------------------------------------

def capabilities_from_policy(policy: Policy) -> tuple[CapabilityNode, ...]:
    """The default atlas hierarchy, present before any work item exists.

    For each class, the effective allow set (allow minus deny) becomes
    specialist children; each specialist carries its bound model φ(a) as a
    single model leaf. Deterministic ordering (sorted)."""
    classes: list[CapabilityNode] = []
    for cls in sorted(policy.required):
        allowed = sorted(set(policy.allow.get(cls, ())) - set(policy.deny.get(cls, ())))
        specialists: list[CapabilityNode] = []
        for a in allowed:
            model_id = policy.phi.get(a)
            model_children: tuple[CapabilityNode, ...] = ()
            if model_id is not None:
                model_children = (CapabilityNode(
                    id=f"{cls}:{a}:{model_id}", kind="model", label=model_id,
                    parent=a),)
            specialists.append(CapabilityNode(
                id=a, kind="specialist", label=a,
                parent=cls, children=model_children))
        classes.append(CapabilityNode(
            id=cls, kind="class", label=cls, node_class=cls,
            children=tuple(specialists)))
    return tuple(classes)


# --------------------------------------------------------------------------
# Journal reduction.
# --------------------------------------------------------------------------

def _resolve_policies(policies: Union[Policy, Iterable[Policy]]) -> dict[str, Policy]:
    if isinstance(policies, Policy):
        return {policies.version: policies}
    out: dict[str, Policy] = {}
    for p in policies:
        out[p.version] = p
    if not out:
        raise ValueError("build_snapshot requires at least one Policy")
    return out


def build_snapshot(
    journal: Sequence[Mapping],
    *,
    policies: Union[Policy, Iterable[Policy]],
    plan: Optional[Sequence[Mapping]] = None,
    questions: Optional[Sequence[Mapping]] = None,
    artifacts: Optional[Sequence[Mapping]] = None,
    policy_version: Optional[str] = None,
    generated_at: float = 0.0,
) -> AtlasSnapshot:
    """Reduce an fcd journal (+ declared records) to an immutable snapshot.

    Deterministic and pure. `journal` is the append-only event list from
    `Enforcer.events`. `plan` declares not-yet-opened lines. `questions` and
    `artifacts` are declared records keyed to node ids.
    """
    pol_map = _resolve_policies(policies)
    plan = list(plan or [])
    q_records = list(questions or [])
    a_records = list(artifacts or [])

    item_order: list[str] = []
    items: dict[str, dict] = {}
    stages: dict[str, dict] = {}
    stage_order: dict[str, list[str]] = {}

    def ensure_item(iid: str, cls: Optional[str], pv: Optional[str],
                    depends_on: tuple[str, ...], status: str) -> dict:
        if iid not in items:
            item_order.append(iid)
            items[iid] = {"class": cls, "policy_version": pv,
                          "depends_on": depends_on, "status": status}
            stage_order[iid] = []
        it = items[iid]
        if cls is not None:
            it["class"] = cls
        if pv is not None:
            it["policy_version"] = pv
        if depends_on:
            it["depends_on"] = depends_on
        return it

    def ensure_stage(sid: str, iid: str, kind: Optional[str]) -> dict:
        if sid not in stages:
            stages[sid] = {"item": iid, "kind": kind, "status": "Open",
                           "declared_model": None, "executed_model": None,
                           "fault": None, "class": items[iid].get("class")}
            stage_order[iid].append(sid)
        if kind is not None:
            stages[sid]["kind"] = kind
        return stages[sid]

    observed_failures: set[str] = set()

    # ---- fold the journal ----
    for ev in journal:
        t = ev.get("type")
        iid = ev.get("work_item_id")
        if not isinstance(iid, str):
            continue
        if t == "open":
            ensure_item(iid, ev.get("class"), ev.get("policy_version"),
                        tuple(ev.get("depends_on", ())), status="open")
        elif t == "stage":
            ensure_item(iid, ev.get("class"), ev.get("policy_version"), (), "open")
            st = ensure_stage(ev["stage_id"], iid, ev.get("stage_kind"))
            st["status"] = "Admitted"
            st["declared_model"] = ev.get("declared_model")
        elif t == "bind":
            st = ensure_stage(ev["stage_id"], iid, None)
            st["status"] = "Running"
            if ev.get("declared_model") is not None:
                st["declared_model"] = ev.get("declared_model")
        elif t == "call":
            st = ensure_stage(ev["stage_id"], iid, None)
            st["executed_model"] = ev.get("executed_model")
            if ev.get("declared_model") is not None:
                st["declared_model"] = ev.get("declared_model")
        elif t == "decide":
            st = ensure_stage(ev["stage_id"], iid, None)
            if ev.get("result") == "pass":
                st["status"] = "Passed"
            else:  # fail_closed
                st["status"] = "Closed"
                if ev.get("fault") is not None:
                    st["fault"] = ev.get("fault")
                items[iid]["status"] = "failed"
                observed_failures.add(iid)
        elif t == "accept":
            items[iid]["status"] = "accepted"

    # ---- fold the plan (declared, not observed) ----
    for rec in plan:
        pid = rec["id"]
        ensure_item(pid, rec.get("class"), rec.get("policy_version"),
                    tuple(rec.get("depends_on", ())), status="planned")
        if "label" in rec:
            items[pid]["label"] = rec["label"]

    known_node_ids = set(items) | set(stages)

    # ---- questions: attach to exact node, block only that node ----
    q_by_node: dict[str, list[Question]] = {}
    all_questions: list[Question] = []
    for rec in q_records:
        q = Question(id=rec["id"], node_id=rec["node_id"],
                     text=rec.get("text", ""), resolved=rec.get("resolved", False))
        if q.node_id not in known_node_ids:
            raise ValueError(f"question {q.id!r} targets unknown node {q.node_id!r}")
        q_by_node.setdefault(q.node_id, []).append(q)
        all_questions.append(q)

    # ---- artifacts: attach to exact node ----
    art_by_node: dict[str, list[Artifact]] = {}
    for rec in a_records:
        art = Artifact(id=rec["id"], node_id=rec["node_id"], kind=rec.get("kind", ""),
                       uri=rec.get("uri", ""), present=rec.get("present", False),
                       runnable=rec.get("runnable", False))
        if art.node_id not in known_node_ids:
            raise ValueError(f"artifact {art.id!r} targets unknown node {art.node_id!r}")
        art_by_node.setdefault(art.node_id, []).append(art)

    # ---- impact taxonomy (disjoint, covering) ----
    item_ids = list(item_order)
    reachable: set[str] = set()
    changed = True
    while changed:
        changed = False
        for iid in item_ids:
            if iid in observed_failures or iid in reachable:
                continue
            deps = set(items[iid]["depends_on"])
            if deps & (observed_failures | reachable):
                reachable.add(iid)
                changed = True
    unknown = [i for i in item_ids
               if i not in observed_failures and i not in reachable]
    impact = Impact(
        observed=tuple(sorted(observed_failures)),
        reachable=tuple(sorted(reachable)),
        unknown=tuple(sorted(unknown)),
    )

    # ---- freeze nodes ----
    nodes: dict[str, Node] = {}
    for iid in item_order:
        it = items[iid]
        child_stage_ids = tuple(stage_order.get(iid, ()))
        qs = tuple(q_by_node.get(iid, ()))
        nodes[iid] = Node(
            id=iid, kind="item", label=it.get("label", iid),
            parent=None, children=child_stage_ids,
            status=it["status"], node_class=it.get("class"),
            policy_version=it.get("policy_version"),
            depends_on=tuple(it.get("depends_on", ())),
            blocked=any(not q.resolved for q in qs),
            questions=qs,
            artifacts=tuple(art_by_node.get(iid, ())),
        )
        for sid in child_stage_ids:
            st = stages[sid]
            sqs = tuple(q_by_node.get(sid, ()))
            nodes[sid] = Node(
                id=sid, kind="stage", label=sid, parent=iid,
                status=st["status"], node_class=st.get("class"),
                declared_model=st.get("declared_model"),
                executed_model=st.get("executed_model"),
                fault=st.get("fault"),
                blocked=any(not q.resolved for q in sqs),
                questions=sqs,
                artifacts=tuple(art_by_node.get(sid, ())),
            )

    roots = tuple(iid for iid in item_order if not items[iid].get("depends_on"))
    store = tuple(sorted(iid for iid in item_order
                         if items[iid]["status"] == "accepted"))

    resolved_pv = policy_version or next(iter(pol_map))
    if resolved_pv not in pol_map:
        raise ValueError(f"policy_version {resolved_pv!r} not among supplied policies")

    return AtlasSnapshot(
        policy_version=resolved_pv,
        generated_at=generated_at,
        capabilities=capabilities_from_policy(pol_map[resolved_pv]),
        nodes=MappingProxyType(nodes),
        roots=roots,
        store=store,
        questions=tuple(all_questions),
        impact=impact,
    )
