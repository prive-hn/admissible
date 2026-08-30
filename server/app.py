"""FCD cockpit authority server.

Project/work/artifact are the product hierarchy. Existing executors remain
black-box workers behind ExecutionAdapter; only fcd can Pass/Accept.
"""
from __future__ import annotations

import argparse
import json
import threading
from contextlib import contextmanager
from functools import wraps
import ipaddress
import mimetypes
import re
import socket
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse, urlsplit

from atlas.context import build_context_atlas
from rga.calibration import CalibrationAuthority, CalibrationClass, CalibrationPolicy
from rga.core import Admission, AdmissionPolicy, ClaimSpec, ClassAdmission, DefectModel, LedgerEntry, Refuter
from fcd.context import (
    AgentRef,
    ContextAuthority,
    ContextPolicy,
    ExecutionAdapterRef,
    GateSpec,
    KnowledgeDelta,
    ModelRef,
    ProjectState,
    hash_bytes,
)
from fcd.core import Enforcer, Policy
from fcd.journal import to_plain_json
from .execution import DemoExecutionAdapter, ExecutionAdapter, ExecutionRequest
from .project import (
    ClassDefinition,
    default_roots,
    discover_projects,
    AgentDefinition,
    GateDefinition,
    LoadedProject,
    ModelDefinition,
    ProjectDefinition,
    ProjectRegistry,
)

ROOT = Path(__file__).resolve().parents[1]
BUNDLED_DIST = Path(__file__).resolve().parent / "static"
DEV_DIST = ROOT / "apps" / "cockpit" / "dist"
DIST = BUNDLED_DIST if BUNDLED_DIST.is_dir() else DEV_DIST
SLASH = {"/inspect", "/why", "/impact", "/fix", "/run", "/retry", "/pause", "/discard", "/accept"}
#  The largest request body this server will hold. A project definition with
#  its models, agents, gates and classes is the biggest thing anyone posts
#  here and is orders of magnitude under this; the number exists so that a
#  body has a ceiling at all, not to be tight.
MAX_BODY_BYTES = 1 << 20


@dataclass
class _Runtime:
    project: LoadedProject
    enforcer: Enforcer
    context: ContextAuthority
    admission: Admission
    calibration: CalibrationAuthority
    meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    questions: dict[str, dict[str, Any]] = field(default_factory=dict)
    artifacts: dict[str, dict[str, Any]] = field(default_factory=dict)
    interactions: list[dict[str, Any]] = field(default_factory=list)
    revision: int = 0
    next_id: int = 1
    settings: dict[str, Any] = field(default_factory=lambda: {
        "versionLabel": "cockpit-settings-v2",
        "acceptanceMode": "strict-match",
        "intakeMode": "class-inferred",
        "repairMode": "retry-in-allow-set",
    })



def _event_label(ev: dict[str, Any]) -> str:
    """Say what a journal event records, not just its type.

    The row still carries the exact payload; this is the reading above it. Every
    phrase here is derived from fields already in the event — nothing is
    softened and no outcome is implied that the event does not state.
    """
    kind = ev.get("type")
    if kind == "open":
        return f"Line opened under class {ev.get('class', '?')}"
    if kind == "stage":
        return f"Gate {ev.get('stage_id', '')} declared"
    if kind == "bind":
        return f"Bound {ev.get('declared_model', '?')}"
    if kind == "call":
        executed = ev.get("executed_model", "?")
        return (f"Provider reported {executed}"
                + ("" if ev.get("on_bind") else " — not the bound model"))
    if kind == "decide":
        if ev.get("result") == "pass":
            return "Gate held"
        fault = ev.get("fault")
        return "Fail closed and published" + (f" · {fault}" if fault else "")
    if kind == "accept":
        return "Accepted into the store"
    return f"{kind} journal event"


def _demo_artifact_html(title: str, subtitle: str, note: str) -> str:
    """Reference-demo artifact body.

    The cockpit renders whatever a harness ships; this is what the bundled demo
    harness ships, so it is a real self-contained document rather than a bare
    fragment.
    """
    import html as _html
    return (
        "<!doctype html><html><head><meta charset='utf-8'><style>"
        "body{font:15px/1.55 system-ui,-apple-system,sans-serif;margin:0;"
        "background:#f7f5ef;color:#17202a}"
        "main{padding:32px;max-width:720px;margin:auto}"
        ".card{background:#fff;border:1px solid #d7d3c8;border-radius:12px;"
        "padding:24px;box-shadow:0 8px 30px #0000000f}"
        "small{color:#667085;text-transform:uppercase;letter-spacing:.08em;font-size:11px}"
        "h1{font-size:22px;margin:8px 0 6px}p{margin:0 0 10px}"
        ".note{margin-top:16px;padding:12px 14px;background:#fbf3f2;border-left:3px solid "
        "#b4463c;border-radius:0 6px 6px 0;color:#5b2a25;font-size:13px}"
        "</style></head><body><main><div class='card'>"
        f"<small>Candidate</small><h1>{_html.escape(title)}</h1>"
        f"<p>{_html.escape(subtitle)}</p>"
        f"<div class='note'>{_html.escape(note)}</div>"
        "</div></main></body></html>"
    )


def _default_definition(body: dict[str, Any], executor_id: str) -> ProjectDefinition:
    supplied = [key in body for key in ("models", "agents", "gates")]
    if any(supplied) and not all(supplied):
        raise ValueError("models, agents and gates must be supplied together")
    if all(supplied):
        models = tuple(ModelDefinition(
            id=m["id"], revision=int(m.get("revision", 1)), provider=m["provider"],
            api_id=m["api_id"], display=m.get("display", m["api_id"]),
            context_profile=m.get("context_profile", ""), reasoning=m.get("reasoning", ""),
        ) for m in body["models"])
        agents = tuple(AgentDefinition(
            id=a["id"], revision=int(a.get("revision", 1)), name=a.get("name", a["id"]),
            instructions=a.get("instructions", ""), default_model_id=a["default_model_id"],
            tools=tuple(a.get("tools", ())), authority=tuple(a.get("authority", ())),
        ) for a in body["agents"])
        gates = tuple(GateDefinition(
            id=g["id"], revision=int(g.get("revision", 1)), name=g.get("name", g["id"]),
            agent_id=g["agent_id"], executor_id=g.get("executor_id", executor_id),
            model_id=g["model_id"], context_mode=g.get("context_mode", "project_shared"),
            continuity=g.get("continuity", "fresh"), kind=g.get("kind", "write"),
        ) for g in body["gates"])
    else:
        models = (
            ModelDefinition("builder-model", 1, "demo", "builder", "Builder model", "reference", "high"),
            ModelDefinition("review-model", 1, "demo", "reviewer", "Reviewer model", "reference", "high"),
        )
        agents = (
            AgentDefinition("builder", 1, "Builder", "Implement the visible contract", "builder-model",
                            ("read", "write", "test", "build"), ("implement",)),
            AgentDefinition("reviewer", 1, "Reviewer", "Review independently; do not implement", "review-model",
                            ("read", "test"), ("review",)),
            AgentDefinition("analyst", 1, "Analyst", "Investigate the repository and answer the question asked",
                            "review-model", ("read",), ("answer",)),
        )
        gates = (
            GateDefinition("implement", 1, "Implement", "builder", executor_id,
                           "builder-model", "project_shared", kind="write"),
            GateDefinition("review", 1, "Independent review", "reviewer", executor_id,
                           "review-model", "fresh_blind", kind="check"),
            GateDefinition("answer", 1, "Investigate and answer", "analyst", executor_id,
                           "review-model", "project_shared", kind="write"),
        )
    if "classes" in body:
        classes = tuple(ClassDefinition(
            id=c["id"], name=c.get("name", c["id"]), summary=c.get("summary", ""),
            gate_ids=tuple(c["gate_ids"]), hints=tuple(c.get("hints", ())),
        ) for c in body["classes"])
    elif all(supplied):
        # A project that declares its own gates but no classes gets one class
        # over exactly those gates, in the order given. Forcing the demo
        # classes here would reference gate ids the project does not have.
        classes = (ClassDefinition(
            "feature", "Feature or fix",
            "Every declared gate, in the order the project declares them.",
            tuple(g.id for g in gates),
        ),)
    else:
        classes = (
            ClassDefinition(
                "investigate", "Investigate", 
                "Answer a question about the repository. One specialist answers; nothing is built.",
                ("answer",),
                ("investigate", "question", "why", "how does", "explain", "audit", "find out", "look into"),
            ),
            ClassDefinition(
                "feature", "Feature or fix",
                "Build the work, then have a specialist who did not build it review it.",
                ("implement", "review"),
                ("add", "build", "implement", "fix", "bug", "refactor", "feature", "endpoint", "migrate"),
            ),
        )

    return ProjectDefinition(
        id=body["id"], name=body.get("name", body["id"]), revision=int(body.get("revision", 1)),
        local_path=body["local_path"], github=body["github"], base_branch=body.get("base_branch", "main"),
        project_version=int(body.get("project_version", 1)), memory_version=int(body.get("memory_version", 1)),
        policy_version=body.get("policy_version", "policy-1"), strict_unknown=bool(body.get("strict_unknown", True)),
        skin=body.get("skin", "instrument"), models=models, agents=agents, gates=gates,
        classes=classes,
    )


def _fcd_policy(project: ProjectDefinition) -> Policy:
    """Compile the project's declared classes into one dispatch policy.

    Three of Policy's four fields are keyed by class; phi is keyed by
    specialist and is deliberately global, because I3 quantifies over
    {norm(phi(x))} and that set is only well defined when a specialist has
    exactly one model. Gate ids are unique project-wide (enforced at load), so
    the specialist key agent:gate cannot collide across classes.
    """
    model_by_id = {m.id: m for m in project.models}
    gate_by_id = {g.id: g for g in project.gates}
    phi = {
        f"{g.agent_id}:{g.id}": f"{model_by_id[g.model_id].provider}:{model_by_id[g.model_id].api_id}"
        for g in project.gates
    }
    allow: dict[str, set[str]] = {}
    deny: dict[str, set[str]] = {}
    required: dict[str, list[tuple[str, str]]] = {}
    for klass in project.classes:
        gates = [gate_by_id[gid] for gid in klass.gate_ids]
        allow[klass.id] = {f"{g.agent_id}:{g.id}" for g in gates}
        deny[klass.id] = set()
        # The gate declares its own kind; position no longer decides whether a
        # step is subject to the author exclusion.
        required[klass.id] = [(g.kind, g.id) for g in gates]
    return Policy(allow=allow, deny=deny, phi=phi, required=required,
                  version=project.policy_version)


DEMO_REFUTER = ("html_check", "v1")
DEMO_DEFECT_MODEL = "demo-defects-v1"
DEMO_SAMPLING = "demo:greedy"
DEMO_CLAIM = "artifact_renders"


def run_demo_refuter(src: str, seed: str) -> tuple[str, str]:
    """The bundled deterministic refuter: the candidate is a non-empty HTML
    document with a heading and no unterminated tag. A pure function of
    (bytes, seed) — the seed is carried into the witness so replays are
    checked against the exact run (B2/B10). The server is the harness here:
    verdicts it reports are B1 reports, exactly as adapter receipts are."""
    problems = []
    if not src.strip():
        problems.append("empty")
    if "<h1>" not in src:
        problems.append("no-heading")
    if src.count("<") != src.count(">"):
        problems.append("unbalanced-tags")
    if "</html>" not in src:
        problems.append("unterminated-document")
    verdict = "refuted" if problems else "survived"
    witness = hash_bytes(f"{seed}|{verdict}|{','.join(problems) or 'ok'}".encode())
    return verdict, witness


#  Seeded defects for the demo defect model: each ships its killing witness by
#  construction (B5) — the kill is demonstrated by running the refuter below.
DEMO_DEFECTS: list[tuple[str, str]] = [
    ("empty-document", ""),
    ("missing-heading", "<!doctype html><html><body><p>x</p></body></html>"),
    ("unbalanced-tag", "<!doctype html><html><body><h1>x</h1><p</body></html>"),
    ("truncated-document", "<!doctype html><html><body><h1>x</h1>"),
    ("whitespace-only", "   \n  "),
]


def _measure_demo_refuter(admission: Admission) -> None:
    """Declare the demo refuter and MEASURE its power by running it against
    the seeded defects — the ledger is counted from real runs, never declared
    (R2). The demo refuter has no unbalanced-tag detection blind spots by
    design here; whatever it misses shows up honestly in kills/size."""
    admission.declare(Refuter(DEMO_REFUTER[0], DEMO_REFUTER[1], "fcd-server", "ledger"))
    ledger = []
    for defect_id, mutant in DEMO_DEFECTS:
        verdict, _ = run_demo_refuter(mutant, seed="calibration")
        ledger.append(LedgerEntry(defect_id, "killed" if verdict == "refuted" else "survived"))
    admission.measure(DEMO_REFUTER[0], DEMO_REFUTER[1],
                      DefectModel(DEMO_DEFECT_MODEL, "demo-mutator"), ledger)


#: The reference deployment's miss budget for every class, stated here and in
#: README.md because a budget nobody can read is a budget nobody can audit.
#: Three valid escapes against one refuter version in a class demote it; the
#: gate is applied at Seal.
DEMO_E_MAX = 3


def _calibration_policy(policy: Policy) -> CalibrationPolicy:
    """One explicit budget per class, derived wherever the dispatch policy is
    derived. e_max and demotion_gate have no defaults (E9), so this must be
    rebuilt with every policy evolution — a class the calibration policy does
    not name is a class with no budget, and the kernel refuses it."""
    return CalibrationPolicy(
        {cls: CalibrationClass(e_max=DEMO_E_MAX, demotion_gate="seal")
         for cls in policy.required},
        # Versioned with the dispatch policy it accompanies: two different
        # budgets must not be journal-indistinguishable.
        version=f"cal-{policy.version}")


def _admission_policy(policy: Policy) -> AdmissionPolicy:
    """One claim per class, attacked by the measured demo refuter. k=1: the
    seal shows (agreeing, k) = (1, 1) — concordance visibly unmeasured, per
    the papers, rather than pretended. The residual names what only a check
    stage (or nobody) looked at."""
    classes = {}
    for cls, required in policy.required.items():
        has_check = any(kind == "check" for kind, _ in required)
        classes[cls] = ClassAdmission(
            claims=(ClaimSpec(DEMO_CLAIM, "renders-v1", frozenset({DEMO_REFUTER}), DEMO_DEFECT_MODEL),),
            k=1, theta=1.0, p_min=0.5,
            excluded=frozenset({"refuter_source", "refuter_results", "defect_model"}),
            residual=(("meets the operator's intent", "check_stage" if has_check else "unreviewed"),),
        )
    return AdmissionPolicy(classes, version=f"rga-{policy.version}")


def propose_class(project: ProjectDefinition, prompt: str) -> tuple[str | None, str]:
    """Read the prompt and name the kind of work it looks like.

    Deterministic and local: intake proposes, it never decides. The class is
    write-once at Open (I4), so choosing it chooses how much scrutiny the work
    gets — a wrong guess accepted silently would be a hop in requirement space.
    An ambiguous prompt returns no class, and `guarded` intake refuses rather
    than defaulting.
    """
    # Word boundaries, not substrings: "address" contains "add", which routed
    # "address the prefix handling" into the class whose hint was "add".
    words = set(re.findall(r"[a-z]+", prompt.lower()))
    scored = [
        (sum(1 for h in c.hints if h in words), c.id)
        for c in project.classes
    ]
    scored.sort(reverse=True)
    if not scored or scored[0][0] == 0:
        return None, "No declared class clearly matches this prompt."
    if len(scored) > 1 and scored[0][0] == scored[1][0]:
        return None, (f"This reads as both {scored[0][1]!r} and {scored[1][1]!r}. "
                      "Pick the one you mean.")
    return scored[0][1], ""


def _scrutiny(required: list[tuple[str, str]]) -> tuple[int, int]:
    """How much review a class actually imposes.

    Gate *count* is not scrutiny. Only a check gate excludes the authors of
    the line (A6, I6), so a three-write-gate class reviews nothing while a
    write-then-check class enforces dual control. Rank by checks first.
    """
    return sum(1 for kind, _ in required if kind == "check"), len(required)


def _scrutiny_reason(required: list[tuple[str, str]]) -> str:
    checks = sum(1 for kind, _ in required if kind == "check")
    if checks:
        return (f"it is the strictest declared class "
                f"({checks} independent check{'s' if checks > 1 else ''})")
    return ("no declared class requires an independent check, so this is the "
            f"longest of them ({len(required)} gates, none of them a review)")


def _strictest_class(project: ProjectDefinition, policy: Policy) -> ClassDefinition:
    """The class that reviews the most, for when intake cannot tell.

    A default must never be the cheap option: the class is write-once at Open
    (I4), so guessing low buys scrutiny that can never be added back.
    """
    return max(project.classes, key=lambda c: _scrutiny(policy.required[c.id]))


def _serialized(method):
    """Run one engine entry point at a time.

    Readers and writers share `rt.meta`, `rt.questions` and the enforcer's
    event list. Without this, `state()` iterates a dict a POST thread is
    inserting into and raises RuntimeError mid-snapshot.
    """
    @wraps(method)
    def guarded(self, *args, **kwargs):
        with self.lock:
            self._lock_depth += 1
            try:
                return method(self, *args, **kwargs)
            finally:
                self._lock_depth -= 1
    return guarded


class CockpitEngine:
    def __init__(self, *, seed: bool = False, execution: ExecutionAdapter | None = None) -> None:
        # One writer at a time, and no reader mid-write. Without this, `state()`
        # iterates `rt.meta` while a POST thread inserts into it, and the reader
        # dies with RuntimeError — which the SSE loop did not catch, so the
        # stream ended and the client silently fell back to rendering its last
        # good snapshot. A dead authority that looks healthy is the one failure
        # mode this machine must not have.
        self.lock = threading.RLock()
        #  How many `_serialized` frames this thread is inside, so `_unlocked`
        #  can release a re-entrantly held RLock all the way down and take it
        #  back to the same depth.
        self._lock_depth = 0
        #  Monotonic across projects: see `_touch`.
        self._revision = 0
        self.execution = execution or DemoExecutionAdapter()
        self.registry = ProjectRegistry()
        self._runtimes: dict[str, _Runtime] = {}
        if seed:
            self.load_project({
                "id": "admissible", "name": "Admissible",
                "local_path": str(ROOT), "github": "prive-hn/admissible",
                "base_branch": "main", "project_version": 1, "memory_version": 1,
                "policy_version": "cockpit-v2", "skin": "instrument",
            })
            self._seed()

    @property
    def current(self) -> _Runtime | None:
        loaded = self.registry.current
        return self._runtimes.get(loaded.definition.id) if loaded else None

    def _rt(self) -> _Runtime:
        if self.current is None:
            raise ValueError("load a project before creating work")
        return self.current

    # Compatibility/readback properties used by tests and adapters.
    @property
    def enforcer(self) -> Enforcer:
        return self._rt().enforcer

    @property
    def context(self) -> ContextAuthority:
        return self._rt().context

    @property
    def admission(self) -> Admission:
        return self._rt().admission

    @property
    def calibration(self) -> CalibrationAuthority:
        return self._rt().calibration

    @property
    def meta(self): return self._rt().meta
    @property
    def questions(self): return self._rt().questions
    @property
    def artifacts(self): return self._rt().artifacts
    @property
    def interactions(self): return self._rt().interactions
    @property
    def settings(self): return self._rt().settings
    @property
    def revision(self): return self._revision

    def _touch(self) -> None:
        """Bump the one counter every stream watches.

        This used to bump a per-project counter, and neither selecting nor
        loading a project bumped anything. Two projects sitting at the same
        number meant switching between them emitted no frame: the acting tab
        was rescued by its own refresh, while a second tab kept rendering the
        previous project's lines and gates under a green Live badge. One
        monotonic counter for the engine makes every change a change.
        """
        self._revision += 1
        if self.current:
            self._rt().revision = self._revision

    @_serialized
    def load_project(self, body: dict[str, Any]) -> dict[str, Any]:
        definition = _default_definition(body, self.execution.id)
        loaded = self.registry.load(definition)
        # The registry may rewrite the definition — it derives a class when
        # none is declared — so the policy must be built from what it loaded,
        # not from what was submitted. Building from the submitted object gave
        # a policy with no classes while the UI listed the derived one, and
        # every intake then died on KeyError with no way to repair it.
        definition = loaded.definition
        existing = self._runtimes.get(definition.id)
        if existing is None:
            fcd_policy = _fcd_policy(definition)
            enforcer = Enforcer(fcd_policy, clock=time.time)
            context = ContextAuthority(is_accepted=lambda w, e=enforcer: w in e.store)
            context.add_project(ProjectState(
                definition.id, definition.project_version, definition.memory_version,
                definition.policy_version, definition.strict_unknown,
            ))
            admission = Admission(enforcer, _admission_policy(fcd_policy), clock=time.time)
            _measure_demo_refuter(admission)
            calibration = CalibrationAuthority(
                admission, _calibration_policy(fcd_policy), clock=time.time)
            self._runtimes[definition.id] = _Runtime(loaded, enforcer, context, admission, calibration)
            loaded.runtime_data["runtime"] = self._runtimes[definition.id]
        else:
            # Re-loading an id that already has running work would put the new
            # definition in the rail and keep the old policy, repository and
            # gates underneath it — the snapshot would disagree with itself
            # about which repository the work belongs to. Project ids come
            # from a directory basename, so two repositories of the same name
            # under different roots collide here; refuse rather than swap.
            if existing.project.definition.local_path != definition.local_path:
                raise ValueError(
                    f"project id {definition.id!r} is already loaded from "
                    f"{existing.project.definition.local_path}. Two repositories "
                    "cannot share an id; rename one or give this a distinct id.")
            # `install` is the kernel's own guard: reusing a version label with
            # different gates or classes is refused, and in-flight lines keep
            # the version they pinned at Open (I10, I14). Changing the rules
            # therefore requires bumping `policy_version`, which is the point.
            new_policy = _fcd_policy(definition)
            # Reload must not half-apply. Enforcer.install's only refusal is
            # a reused version label with different content — checked here
            # first, without installing — so the calibration ratchet (C4,
            # the deep gate: a model that forgot an established escape
            # refuses) runs next, and only then does the FCD install run,
            # now unable to fail. Either both policies land or neither does.
            prior = existing.enforcer._policies.get(new_policy.version)
            if prior is not None and prior != new_policy:
                raise ValueError(
                    f"policy version {new_policy.version!r} already installed with different content")
            # Both policies evolve in one step: a class added on reload
            # arrives with its explicit calibration budget or the install
            # refuses (E9), so no class is ever dispatchable without one.
            existing.calibration.install(_admission_policy(new_policy),
                                         cal_policy=_calibration_policy(new_policy))
            existing.enforcer.install(new_policy)
            existing.project = loaded
            loaded.runtime_data["runtime"] = existing
        self._touch()
        return self._project_dict(loaded)

    #  The exact sets `SettingsModal` offers. They are duplicated rather than
    #  derived because the authority must not accept a value simply because a
    #  client sent it — but they have to be the SAME sets, or the panel offers
    #  choices that are refused on save.
    ACCEPTANCE_MODES = ("strict-match", "quorum", "manual-final")
    INTAKE_MODES = ("class-inferred", "explicit-class", "guarded")
    REPAIR_MODES = ("retry-in-allow-set", "ask-first", "stop-on-break")

    @_serialized
    def update_settings(self, changes: dict[str, Any]) -> dict[str, Any]:
        """Record the operator's choices where the authority can read them.

        The settings panel only ever wrote to React state — there was no
        endpoint — so choosing `guarded` intake changed a label and nothing
        else. A control that cannot reach the authority is not a setting.
        """
        rt = self._rt()
        allowed = {
            "acceptanceMode": self.ACCEPTANCE_MODES,
            "intakeMode": self.INTAKE_MODES,
            "repairMode": self.REPAIR_MODES,
        }
        unknown = set(changes) - set(allowed)
        if unknown:
            raise ValueError(f"unknown setting(s): {', '.join(sorted(unknown))}")
        for key, value in changes.items():
            if value not in allowed[key]:
                raise ValueError(
                    f"{key} must be one of {', '.join(allowed[key])}, not {value!r}")
        rt.settings.update(changes)
        self._touch()
        return dict(rt.settings)

    @_serialized
    def select_project(self, project_id: str) -> dict[str, Any]:
        loaded = self.registry.select(project_id)
        self._touch()
        return self._project_dict(loaded)

    def _project_dict(self, loaded: LoadedProject) -> dict[str, Any]:
        data = loaded.to_dict()
        rt = self._runtimes.get(loaded.definition.id)
        if rt:
            p = rt.context.project_state(loaded.definition.id)
            data["project_version"] = p.project_version
            data["memory_version"] = p.memory_version
        return data

    def _contract(self, prompt: str, cls: str | None = None) -> dict[str, Any]:
        rt = self._rt()
        definition = rt.project.definition
        title = prompt.strip().split("\n", 1)[0][:72] or "Untitled work item"
        p = rt.enforcer.policy

        proposed, why = propose_class(definition, prompt)
        mode = rt.settings.get("intakeMode", "class-inferred")
        if cls and cls not in p.required:
            raise ValueError(f"unknown class {cls!r}")
        # `explicit-class` was offered in settings and never read by the
        # authority, so it behaved exactly like `class-inferred` — a safety
        # setting that did nothing. It means what it says: the operator names
        # the class, and a reading of the prompt is only a suggestion.
        if mode == "explicit-class" and not cls:
            raise ValueError(
                "intake refused: this project requires you to name the class. "
                + (f"This reads as {proposed!r}." if proposed else why))
        chosen = cls or proposed
        if chosen is None and mode == "guarded":
            # guarded: an unclear class blocks intake instead of guessing.
            raise ValueError(f"intake refused: {why} Choose a class explicitly.")
        chose_by = "operator" if cls else ("intake" if proposed else "default")
        if chosen is None:
            chosen = _strictest_class(definition, p).id

        klass = next(c for c in definition.classes if c.id == chosen)
        return {
            "cls": chosen, "className": klass.name, "classSummary": klass.summary,
            "proposedClass": proposed, "classChosenBy": chose_by,
            "classNote": (f"{why} Defaulted to {klass.name!r}: "
                          f"{_scrutiny_reason(p.required[chosen])}."
                          if chose_by == "default" else ""),
            "classes": [
                {"id": c.id, "name": c.name, "summary": c.summary,
                 "gates": [{"kind": g[0], "name": g[1]} for g in p.required[c.id]]}
                for c in definition.classes
            ],
            "title": title, "summary": prompt.strip(),
            "policyVersion": p.version,
            "requiredStages": [{"kind": k, "name": n} for k, n in p.required[chosen]],
            "allowSet": sorted(p.allow[chosen] - p.deny[chosen]),
            "acceptanceMode": rt.settings["acceptanceMode"], "dependsOn": [],
        }

    @_serialized
    def compile_contract(self, prompt: str, cls: str | None = None) -> dict[str, Any]:
        """The contract an operator approves, compiled by the authority itself.

        The cockpit must never show a locally guessed contract and then open a
        line under different terms: the class, required gates, allow set and
        policy version here are read straight off the live policy. Compiling
        opens nothing and writes nothing.
        """
        if not prompt.strip():
            raise ValueError("prompt is required")
        return self._contract(prompt, cls)

    def _new_id(self) -> str:
        rt = self._rt()
        value = f"W{rt.next_id}"
        rt.next_id += 1
        return value

    @_serialized
    def create_work_item(self, prompt: str, project_id: str | None = None,
                         cls: str | None = None) -> dict[str, Any]:
        rt = self._rt()
        if project_id and project_id not in {"default", rt.project.definition.id}:
            raise ValueError("work item project does not match selected project")
        if not prompt.strip():
            raise ValueError("prompt is required")
        iid = self._new_id()
        contract = self._contract(prompt, cls)
        # The line opens under the class the operator approved, not a default.
        rt.enforcer.open(iid, contract["cls"], f"contract:{iid}")
        rt.context.open_work(rt.project.definition.id, iid, contract_revision=1)
        qid = f"Q-{iid}-contract"
        rt.meta[iid] = {
            "title": contract["title"], "contract": contract,
            "project_id": rt.project.definition.id, "open_question_id": qid,
            "status_override": None, "paused": False,
            "created_at": time.time(), "updated_at": time.time(), "steering": [],
            "gate_overrides": {}, "context_failure": None,
        }
        rt.questions[qid] = {
            "id": qid, "workItemId": iid, "stageId": f"{iid}.0",
            "prompt": "Confirm the outcome and acceptance focus for this contract.",
            "allowFreeText": True, "context": contract["summary"], "options": [],
        }
        self._touch()
        item = self._project_item(iid)
        return {"id": iid, "contract": contract, "workItem": item}

    def _model_readiness(self, model: ModelDefinition) -> dict[str, Any]:
        rt = self._rt()
        checks = self.execution.readiness(
            provider=model.provider, model_api_id=model.api_id,
            project_path=rt.project.definition.local_path,
        )
        return {"executor_id": self.execution.id, "declared_executor_id": self.execution.id,
                "executor_connected": True, "provider": model.provider,
                "model_api_id": model.api_id, **checks}

    def _gate_readiness(self, gate: GateDefinition) -> dict[str, Any]:
        model = self._rt().project.model(gate.model_id)
        readiness = self._model_readiness(model)
        connected = gate.executor_id == self.execution.id
        return {**readiness, "declared_executor_id": gate.executor_id,
                "executor_connected": connected,
                "ready": bool(readiness.get("ready") and connected)}

    def _assert_gate_ready(self, iid: str) -> None:
        gate = self._gate_definition(iid)
        model = self._rt().project.model(gate.model_id)
        readiness = self._gate_readiness(gate)
        if not readiness.get("ready"):
            failed = ", ".join(k for k, v in readiness.items() if k != "ready" and not v)
            raise ValueError(f"execution route not ready for {model.provider}/{model.api_id}: {failed}")

    @_serialized
    def answer_question(self, question_id: str, answer: str) -> dict[str, Any]:
        rt = self._rt()
        if question_id not in rt.questions:
            raise ValueError("question not found")
        if not answer.strip():
            raise ValueError("answer is required")
        q = rt.questions[question_id]
        iid = q["workItemId"]
        self._assert_gate_ready(iid)
        rt.questions.pop(question_id)
        rt.meta[iid]["open_question_id"] = None
        ev = {"type": "answer", "question_id": question_id, "work_item_id": iid,
              "answer": answer.strip(), "ts": time.time()}
        rt.interactions.append(ev)
        rt.context.record_pre_admit_steering(iid, "work", f"Question answer: {answer.strip()}")
        self._run_stage(iid)
        self._touch()
        return {"event": ev, "workItem": self._project_item(iid)}

    @_serialized
    def steer(self, item_id: str, node_id: str, text: str, *, scope: str = "stage") -> dict[str, Any]:
        rt = self._rt()
        if item_id not in rt.meta or not text.strip():
            raise ValueError("work item and steering text are required")
        if item_id in rt.enforcer.store:
            raise ValueError("accepted artifacts are immutable")
        ev = {"type": "steer", "work_item_id": item_id, "node_id": node_id,
              "scope": scope, "text": text.strip(), "ts": time.time()}
        rt.meta[item_id]["steering"].append(ev)
        rt.meta[item_id]["updated_at"] = ev["ts"]
        rt.interactions.append(ev)
        # Synchronous reference adapter has no Running window; this becomes S0
        # for the next attempt. Real async adapters append to the live stream.
        rt.context.record_pre_admit_steering(item_id, scope, text.strip())
        self._touch()
        return ev

    @_serialized
    def action(self, item_id: str, node_id: str, command: str) -> dict[str, Any]:
        rt = self._rt()
        if command not in SLASH:
            raise ValueError(f"unsupported command {command!r}")
        if item_id not in rt.meta:
            raise ValueError("work item not found")
        ev = {"type": "action", "work_item_id": item_id, "node_id": node_id,
              "command": command, "ts": time.time()}
        rt.interactions.append(ev)
        meta = rt.meta[item_id]
        if command == "/accept":
            if item_id not in rt.enforcer.store:
                raise ValueError("machine gates have not accepted this item")
        elif command == "/discard":
            # steer() already refuses accepted artifacts; so does this. A
            # sealed line relabelled failed would render as closed-with-
            # nothing-written while the store still serves it.
            if item_id in rt.enforcer.store:
                raise ValueError("accepted artifacts are immutable; a fix is a new line")
            meta["status_override"] = "failed"; meta["paused"] = True
        elif command == "/pause":
            meta["paused"] = True
        elif command in ("/run", "/retry"):
            # Same work, two honest names: a gate that has never run is being
            # started, not retried.
            self._assert_runnable_stage(item_id, node_id)
            self._run_stage(item_id)
        elif command == "/fix":
            if item_id in rt.enforcer.store:
                raise ValueError("accepted artifacts are immutable; a fix is a new line")
            qid = f"Q-{item_id}-fix-{rt.revision}"
            rt.questions[qid] = {"id": qid, "workItemId": item_id, "stageId": node_id,
                                 "prompt": "What should change before the next attempt?",
                                 "allowFreeText": True, "options": []}
            meta["open_question_id"] = qid
        meta["updated_at"] = ev["ts"]
        self._touch()
        return ev

    def _assert_runnable_stage(self, item_id: str, node_id: str) -> None:
        """Run the gate the operator is looking at, or refuse.

        There is one pointer and no transition that runs a gate out of order,
        but the tray is rendered per selected stage and sent that stage's id —
        which the dispatcher discarded, so asking to run a downstream gate ran
        the current one instead and reported it as the gate that was asked for.
        A silently substituted gate is worse than a refusal.

        An open question is also a refusal: it carries the acceptance criteria
        recorded as pre-admit steering, so running before it is answered admits
        without the terms the operator is still being asked for.
        """
        rt = self._rt()
        meta = rt.meta[item_id]
        if meta.get("open_question_id"):
            raise ValueError(
                "this line is waiting on a question; answer it to run this gate")
        item = rt.enforcer.items.get(item_id)
        if item is None:
            raise ValueError("work item has no machine state")
        prefix, _, index = (node_id or "").rpartition(".")
        if not index.isdigit() or prefix != item_id:
            raise ValueError(f"{node_id!r} does not name a gate on {item_id}")
        asked = int(index)
        if asked >= len(item.stages):
            raise ValueError(f"this line has no gate {asked}")
        if asked != item.pointer:
            raise ValueError(
                f"this line is on {item.stages[item.pointer].name!r}; "
                f"{item.stages[asked].name!r} runs only once every gate "
                "before it has held")

    @_serialized
    def configure_gate(self, item_id: str, gate_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        rt = self._rt()
        if item_id not in rt.meta:
            raise ValueError("work item not found")
        base = next((g for g in rt.project.definition.gates if g.id == gate_id), None)
        if base is None:
            raise ValueError("gate not found")
        records = [r for r in rt.context.attempt_records() if r.envelope.work_item_id == item_id and r.envelope.gate_id == gate_id]
        if records and records[-1].state != "Closed":
            raise ValueError("admitted gate envelope is locked")
        allowed = {"agent_id", "executor_id", "model_id", "context_mode", "continuity"}
        if set(changes) - allowed:
            raise ValueError("unsupported gate override field")
        candidate = {**asdict(base), **{k: v for k, v in changes.items() if k in allowed}}
        agent_ids = {a.id for a in rt.project.definition.agents}
        model_ids = {m.id for m in rt.project.definition.models}
        if candidate["agent_id"] not in agent_ids or candidate["model_id"] not in model_ids:
            raise ValueError("gate override references unknown agent/model")
        if candidate["executor_id"] != self.execution.id:
            raise ValueError("selected execution adapter is not connected")
        if candidate["context_mode"] == "fresh_blind" and candidate["continuity"] != "fresh":
            raise ValueError("fresh_blind forbids executor continuity")
        previous = rt.meta[item_id]["gate_overrides"].get(gate_id, {})
        revision = int(previous.get("_revision", 0)) + 1
        rt.meta[item_id]["gate_overrides"][gate_id] = {**{k: candidate[k] for k in allowed}, "_revision": revision}
        self._touch()
        effective = self._effective_gate(item_id, base)
        return {**asdict(effective), "override_revision": revision}

    @_serialized
    def review_impact(self, item_id: str, classification: str, decision: str, actor: str) -> dict[str, Any]:
        rt = self._rt()
        if item_id not in rt.meta:
            raise ValueError("work item not found")
        review = rt.context.review_impact(item_id, classification, decision, actor)
        rt.interactions.append({"type": "impact_review", **asdict(review), "ts": time.time()})
        self._touch()
        return asdict(review)

    def _effective_gate(self, iid: str, base: GateDefinition) -> GateDefinition:
        override = self._rt().meta[iid].get("gate_overrides", {}).get(base.id)
        if not override:
            return base
        fields = {k: v for k, v in override.items() if not k.startswith("_")}
        return replace(base, revision=base.revision + int(override.get("_revision", 0)), **fields)

    def _gate_definition(self, iid: str) -> GateDefinition:
        """The gate this item's current stage names.

        Stages come from `Required(c)`, which is the class's gate list — a
        subset of the project's, in the class's own order. Indexing the
        project's tuple by the stage pointer only agreed with that while
        there was one class over every gate. It now silently returns a
        different gate, so the envelope is built from the wrong agent,
        model and context mode. The stage's name is the gate id; use it.
        """
        rt = self._rt()
        item = rt.enforcer.items[iid]
        return self._effective_gate(iid, rt.project.gate(item.stages[item.pointer].name))

    def _gate_spec(self, iid: str, gate: GateDefinition) -> GateSpec:
        rt = self._rt()
        agent = rt.project.agent(gate.agent_id)
        model = rt.project.model(gate.model_id)
        include = {"contract", "candidate_diff", "acceptance_criteria"}
        exclude: set[str] = set()
        if gate.context_mode == "project_shared":
            include.add("accepted_project_facts")
        if gate.context_mode == "fresh_blind":
            exclude |= {"builder_transcript", "builder_reasoning", "previous_review_verdict", "unaccepted_memory"}
        policy = ContextPolicy(gate.context_mode, frozenset(include), frozenset(exclude),
                               "accepted_only", gate.continuity)
        instruction_hash = hash_bytes(
            f"{agent.instructions}|{gate.name}|{rt.meta[iid]['contract']['summary']}".encode()
        )
        return GateSpec(
            gate.id, gate.revision,
            AgentRef(agent.id, agent.revision, agent.instructions),
            ExecutionAdapterRef(gate.executor_id, 1, self.execution.capabilities),
            ModelRef(model.provider, model.api_id, model.display),
            policy, tool_manifest_hash=hash_bytes("|".join(agent.tools).encode()),
            instruction_hash=instruction_hash,
        )

    def _specialist_for(self, iid: str, gate: GateDefinition) -> str:
        rt = self._rt()
        specialist = f"{gate.agent_id}:{gate.id}"
        item = rt.enforcer.items[iid]
        stage = item.stages[item.pointer]
        allow = rt.enforcer.policy_for(iid).pi_star(item.cls, stage.kind, item.authors)
        if specialist not in allow or specialist in stage.tried:
            unused = sorted(allow - stage.tried)
            if not unused:
                raise ValueError("no unused allowed specialist")
            specialist = unused[0]
        return specialist

    @contextmanager
    def _unlocked(self):
        """Drop the engine lock for one long call, then take it back.

        `self.lock` is re-entrant and may be held several frames deep, so a
        single `release()` would not actually let anyone else in. Unwind to
        zero and rebuild to the same depth.
        """
        depth = self._lock_depth
        self._lock_depth = 0
        for _ in range(depth):
            self.lock.release()
        try:
            yield
        finally:
            for _ in range(depth):
                self.lock.acquire()
            self._lock_depth = depth

    def _run_stage(self, iid: str) -> None:
        rt = self._rt()
        item = rt.enforcer.items[iid]
        stage = item.stages[item.pointer]
        if stage.pc not in {"Open", "Closed"}:
            raise ValueError("stage is not runnable")
        self._assert_gate_ready(iid)
        gate = self._gate_definition(iid)
        specialist = self._specialist_for(iid, gate)
        spec = self._gate_spec(iid, gate)

        # Final Accept path cannot run on stale project memory without review.
        work_pin = next(w for w in rt.context.work_pins() if w.work_item_id == iid)
        if item.pointer == len(item.stages) - 1 and (work_pin.project_version, work_pin.memory_version) != rt.context.project_head(rt.project.definition.id):
            reviews = {r.work_item_id: r for r in rt.context.impact_reviews()}
            review = reviews.get(iid)
            if (review is None or review.reviewed_head != rt.context.project_head(rt.project.definition.id)
                    or review.decision not in {"continue_pinned", "owner_override"}):
                raise ValueError("context drift requires signed continue-pinned review before final gate")

        stage_index = item.pointer
        if stage_index == 0 and stage.kind == "write" and iid not in rt.admission.lines:
            # The RGA line opens at first generation, not at intake: the gate
            # is reconfigurable pre-admit, and R3 requires only that the line
            # open before any sample stage is ATTEMPTED. The specialist
            # resolved here becomes the pinned generator; a later retry on a
            # different specialist cannot be a sample of this bind, and the
            # item then carries layer-I guarantees only, said in state.
            # The kernel binds sample i to FCD stage i, so a k=1 line can
            # only ever bind the FIRST write's bytes — while the store
            # serves the LAST write's. A class with more than one write
            # gate therefore never opens a line here: sealing bytes the
            # refuter never attacked is the exact laundering this stack
            # exists to prevent, so the class stays layer I and says why.
            n_writes = sum(1 for s in item.stages if s.kind == "write")
            if n_writes != 1:
                rt.meta[iid]["admissibility_failure"] = (
                    f"open: class {item.cls!r} has {n_writes} write stages; the reference "
                    "server binds single-write classes only (the sample must be the "
                    "bytes the store serves)")
            else:
                try:
                    # Through the authority, never Admission.open directly:
                    # CalOpen is where C6 blocks a demoted pin and E9 refuses
                    # a class with no budget, and a deployment that opens
                    # underneath it leaves both guards dead.
                    rt.calibration.open(iid, specialist, DEMO_SAMPLING)
                except ValueError as exc:
                    rt.meta[iid]["admissibility_failure"] = f"open: {exc}"

        attempt = rt.context.admit(iid, spec, specialist=specialist)
        records = {
            "contract": json.dumps(rt.meta[iid]["contract"], sort_keys=True).encode(),
            "acceptance_criteria": rt.meta[iid]["contract"]["summary"].encode(),
            "candidate_diff": rt.artifacts.get(iid, {}).get("srcDoc", "no candidate").encode(),
            "accepted_project_facts": json.dumps({
                "project": rt.project.definition.id,
                "head": rt.context.project_head(rt.project.definition.id),
            }, sort_keys=True).encode(),
        }
        package = rt.context.compile_package(attempt.envelope.attempt_id, records)

        rt.enforcer.admit(iid, specialist)
        rt.enforcer.bind(iid, True)
        request = ExecutionRequest(
            envelope=attempt.envelope, package=package, specialist=gate.agent_id,
            contract=rt.meta[iid]["contract"], steering=tuple(rt.meta[iid]["steering"]),
            latest_continuation_hash=attempt.latest_continuation_hash,
            continuity_hint=gate.continuity,
        )
        with self._unlocked():
            # The executor is the one call here with unbounded duration, and
            # holding the lock across it froze every reader for its whole run —
            # the board would stop updating at exactly the moment it should
            # read "executor is producing evidence". Releasing is safe because
            # the attempt is already Admitted and Bound: the envelope is frozen
            # (I10), and any concurrent attempt to run this stage is refused by
            # the `pc not in {Open, Closed}` guard above.
            result = self.execution.run(request)
        if result.reported_reuse is not None:
            rt.context.record_executor_reuse(attempt.envelope.attempt_id, result.reported_reuse, result.opaque_cache_id)
        receipt_ok = rt.context.accept_receipt(result.receipt)

        observed = f"{result.receipt.executed_provider}:{result.receipt.executed_model}"
        rt.enforcer.observe(iid, observed)
        if result.artifact:
            if stage.kind == "write":
                artifact = dict(result.artifact)
                artifact.update({"workItemId": iid, "state": "candidate",
                                 "beforeSrcDoc": rt.artifacts.get(iid, {}).get("srcDoc", "")})
                rt.artifacts[iid] = artifact
            else:
                # A check stage's executor output is review evidence, never the
                # candidate. Overwriting here let a steered review replace the
                # reviewed bytes, so the store served bytes the reviewer never
                # saw while every gate was green (body-provenance defect, found
                # by the RGA premise round).
                rt.meta[iid].setdefault("review_artifacts", []).append(
                    {"stage": item.pointer, **result.artifact})
        rt.meta[iid].setdefault("execution_evidence", []).extend(result.evidence)

        if not receipt_ok or not rt.context.can_pass(attempt.envelope.attempt_id):
            # Exact model mismatch still gets canonical F1 via decide_pass.
            expected = rt.enforcer.policy_for(iid).phi[specialist]
            if observed != expected:
                rt.enforcer.decide_pass(iid)
            else:
                rt.enforcer.close(iid, "refuse")
                rt.meta[iid]["context_failure"] = "receipt_mismatch"
                rt.meta[iid]["status_override"] = "failed"
            rt.context.close(attempt.envelope.attempt_id)
            return

        rt.enforcer.decide_pass(iid)
        if rt.enforcer.items[iid].stages[item.pointer if item.pointer < len(item.stages) else -1].pc == "Closed":
            rt.context.close(attempt.envelope.attempt_id)
            return
        rt.context.mark_passed(attempt.envelope.attempt_id)
        if (stage.kind == "write" and stage_index == 0 and stage.pc == "Passed"
                and iid in rt.admission.lines and "admissibility_failure" not in rt.meta[iid]):
            # Register the sample and run the pinned refuter as a trial, then
            # replay it (R6). The server is the harness: verdicts are B1
            # reports, and the refuter is a pure function of (bytes, seed).
            try:
                src = rt.artifacts.get(iid, {}).get("srcDoc", "")
                rt.admission.sample(iid, src.encode(), package.categories, DEMO_SAMPLING)
                seed = rt.admission.seed_for(iid, 0, *DEMO_REFUTER, DEMO_CLAIM)
                verdict, witness = run_demo_refuter(src, seed)
                rt.admission.trial(iid, *DEMO_REFUTER, DEMO_CLAIM, 0, seed,
                                   inputs_hash=hash_bytes(src.encode()),
                                   verdict=verdict, witness_hash=witness)
                if verdict == "survived":
                    verdict2, witness2 = run_demo_refuter(src, seed)
                    rt.admission.replay(iid, len(rt.admission.lines[iid].trials) - 1,
                                        verdict2, witness2)
            except ValueError as exc:
                rt.meta[iid]["admissibility_failure"] = f"sample: {exc}"
        if iid in rt.enforcer.store:
            if stage.kind == "check":
                # The bytes stamped accepted must be the bytes this final check
                # attempt's package hashed (I11): what the reviewer saw is what
                # the store serves. With the write-stage-only overwrite above
                # these always agree; this guard is what would have caught the
                # original defect, so it stays.
                served = rt.artifacts.get(iid, {}).get("srcDoc", "").encode()
                if served != records["candidate_diff"]:
                    raise ValueError("accepted artifact bytes differ from the reviewed candidate")
            if iid in rt.artifacts:
                rt.artifacts[iid]["state"] = "accepted"
            if iid in rt.admission.lines and "admissibility_failure" not in rt.meta[iid]:
                try:
                    rt.calibration.seal(iid)
                except ValueError as exc:
                    rt.meta[iid]["admissibility_failure"] = f"seal: {exc}"
            elif "admissibility_failure" not in rt.meta[iid]:
                rt.meta[iid]["admissibility_failure"] = "no RGA line: no sample stage ran under an open line"
            # Promotion is a consumer of admissibility, not of the layer-I
            # store: accepted-but-unsealed work does not advance project
            # memory, and the state says why (the redirection obligation the
            # papers list; PROOFS R8 remark, calibration C-sections).
            if rt.calibration.admissible(iid):
                expected_head = rt.context.project_head(rt.project.definition.id)
                rt.context.promote(
                    iid,
                    KnowledgeDelta((f"Accepted capability: {rt.meta[iid]['title']}",), (f"artifact:{iid}",)),
                    expected_head=expected_head,
                )

    def _seed(self) -> None:
        accepted = self.create_work_item("Accepted customer status capability", cls="feature")["workItem"]
        self.answer_question(accepted["openQuestionId"], "Status, evidence, next action")
        self.action(accepted["id"], f"{accepted['id']}.1", "/retry")

        failed = self.create_work_item("Candidate export capability with a bind failure", cls="feature")["workItem"]
        rt = self._rt(); iid = failed["id"]
        rt.questions.pop(failed["openQuestionId"]); rt.meta[iid]["open_question_id"] = None
        specialist = "builder:implement"
        rt.enforcer.admit(iid, specialist); rt.enforcer.bind(iid, True)
        rt.enforcer.observe(iid, "other:unexpected"); rt.enforcer.decide_pass(iid)
        rt.meta[iid]["status_override"] = "failed"
        rt.artifacts[iid] = {
            "workItemId": iid, "title": "Export candidate", "kind": "html",
            "state": "candidate", "beforeSrcDoc": "",
            "srcDoc": _demo_artifact_html(
                "Export candidate",
                "The export view the builder produced before the bind was refused.",
                "This candidate is outside the store. It was never accepted, and nothing "
                "downstream ran.",
            ),
        }

    def _evidence(self, iid: str, stage_id: str) -> list[dict[str, Any]]:
        rt = self._rt(); result = []
        for index, ev in enumerate(rt.enforcer.events):
            if ev.get("work_item_id") == iid and ev.get("stage_id") in {None, stage_id}:
                result.append({"id": f"E{index}", "kind": ev["type"], "label": _event_label(ev),
                               "detail": json.dumps(to_plain_json(ev)), "journalIndex": index, "ts": ev.get("ts")})
        for j, ev in enumerate(rt.meta[iid].get("execution_evidence", [])):
            result.append({"id": f"X{j}-{iid}", **ev})
        return result

    def _admissibility(self, iid: str) -> dict[str, Any]:
        """The per-line admissibility record: which layer's guarantee this
        work carries, said plainly. Never softened — accepted-but-unsealed is
        layer I, with the reason, not a smaller green."""
        rt = self._rt()
        status = rt.meta[iid].get("status_override") or rt.enforcer.items[iid].status
        sealed = rt.admission.is_sealed(iid)
        admissible = rt.calibration.admissible(iid)
        impeached = rt.calibration.impeached(iid)
        tainted = rt.admission.tainted(iid)
        failure = rt.meta[iid].get("admissibility_failure")
        # A line the scrutiny layer CLOSED is not "no claim made": the kernel
        # published a fault (V1 refuted, V2 discord, ...) and state repeats
        # the journal's own words rather than hiding them behind a seal error.
        line = rt.admission.lines.get(iid)
        closed_reason = None
        if line is not None and line.pc == "Closed" and line.fault:
            closed_reason = next(
                (ev.get("reason", "") for ev in reversed(rt.admission.events)
                 if ev.get("type") == "rga_close" and ev.get("work_item_id") == iid), "")
            failure = f"{line.fault}: {closed_reason}" if closed_reason else line.fault
        # The layer letters are read off the record, never assumed: a seal
        # the calibration authority never stamped reached layer R only, and
        # a consumer must be able to tell IR from IRC (C5 totality).
        mediated = rt.calibration.mediated(iid)
        block: dict[str, Any] = {
            "layer": "IRC" if sealed and mediated else "IR" if sealed else "I",
            "sealed": sealed, "mediated": mediated, "admissible": admissible,
            "impeached": impeached, "tainted": tainted, "failure": failure,
        }
        if sealed:
            seal = rt.admission.sealed[iid]
            stamp = rt.calibration.sealed_stamp(iid)
            block.update({
                "powerMin": seal.power_min, "k": seal.k,
                "agreeing": seal.claims[0].agreeing,
                "residual": [list(x) for x in seal.residual],
                "trackRecords": stamp["track_records"] if stamp else None,
            })
            # Lost standing outranks missing standing: an impeached or tainted
            # seal must say so first, and an unmediated one must not claim to
            # "carry layer-R standing" when its layer-R seal is impeached.
            # Both facts are said when both hold; neither is swallowed.
            unmediated_note = ("" if mediated else
                               " Its seal was also never mediated by the calibration authority — "
                               "no track-record stamp binds it — so it is layer IR.")
            if impeached:
                block["sentence"] = ("Sealed, then impeached: a replayed escape stands against a "
                                     "sealed claim." + unmediated_note)
            elif tainted:
                block["sentence"] = ("Sealed, then tainted: a refuter it relied on was refused "
                                     "after sealing." + unmediated_note)
            elif not mediated:
                block["sentence"] = ("Sealed under scrutiny, but not mediated by the calibration "
                                     "authority: no track-record stamp binds this seal, so it "
                                     "carries layer-R standing only.")
            else:
                block["sentence"] = (f"Sealed: survived the pinned refuter at measured power {seal.power_min:g}; "
                                     f"concordance is ({seal.claims[0].agreeing}, {seal.k}) — unmeasured at k=1.")
        elif closed_reason is not None:
            reason = f": {closed_reason}" if closed_reason else ""
            block["sentence"] = (f"Closed under scrutiny ({line.fault}){reason} "
                                 "— the fault is published; this line cannot seal.")
        elif failure:
            block["sentence"] = f"Identity gates only: {failure}"
        elif status in ("failed", "accepted"):
            # "yet" describes work still in flight; this line has stopped.
            block["sentence"] = ("This line ended without a scrutiny seal: no admissibility "
                                 "claim is made for it.")
        else:
            block["sentence"] = "Not sealed yet: no admissibility claim is made for this line."
        return block

    def _project_item(self, iid: str) -> dict[str, Any]:
        rt = self._rt(); item = rt.enforcer.items[iid]; meta = rt.meta[iid]
        status = meta.get("status_override") or item.status; stages = []
        for i, stage in enumerate(item.stages):
            sid = f"{iid}.{i}"; evidence = self._evidence(iid, sid); failure = None
            if stage.pc == "Closed":
                failure = {
                    "fault": stage.fault,
                    "whatHappened": "Executed model did not match the declared bind." if stage.fault == "F1" else "The stage closed without acceptance.",
                    "whatRemainsSafe": "Accepted artifacts and dependent project state were not modified.",
                    "impact": {"observed": [f"{sid} closed and cannot enter the store"],
                               "reachable": ["Dependent work items remain gated by the DAG"],
                               "unknown": ["Runtime paths without trace evidence"]},
                    "evidence": evidence,
                    "recovery": [{"label": "Retry inside allow set", "action": "/retry"},
                                 {"label": "Request a fix", "action": "/fix"},
                                 {"label": "Discard candidate", "action": "/discard"}],
                }
            sentence = {"Open": "Waiting to start.", "Admitted": "Specialist admitted.",
                        "Running": "Executor is producing evidence.", "Passed": "Stage held.",
                        "Closed": "Stage sheared; project remains safe.", "Stopped": "Work stopped."}[stage.pc]
            stages.append({"id": sid, "kind": stage.kind, "name": stage.name, "pc": stage.pc,
                           "specialist": stage.a, "declaredModel": stage.m_decl, "executedModel": stage.m_exec,
                           "tried": sorted(stage.tried),
                           "allowSet": sorted(rt.enforcer.policy_for(iid).pi_star(item.cls, stage.kind, item.authors)),
                           "sentence": sentence, "failure": failure, "evidence": evidence})
        pin = next(w for w in rt.context.work_pins() if w.work_item_id == iid)
        return {"id": iid, "title": meta["title"], "cls": item.cls, "status": status,
                "policyVersion": item.policy_version, "projectVersion": pin.project_version,
                "memoryVersion": pin.memory_version, "pointer": item.pointer, "stages": stages,
                "dependsOn": list(item.depends_on), "authors": sorted(item.authors),
                "contract": meta["contract"], "openQuestionId": meta.get("open_question_id"),
                "createdAt": meta["created_at"], "updatedAt": meta["updated_at"],
                "paused": meta.get("paused", False), "contextFailure": meta.get("context_failure"),
                "admissibility": self._admissibility(iid)}

    def _context_state(self) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        rt = self._rt(); snap = build_context_atlas(rt.context, rt.project.definition.id)
        visible_drift = [
            d for d in snap.drift
            if rt.enforcer.items[d.work_item_id].status == "open"
            and rt.meta[d.work_item_id].get("status_override") not in {"failed", "accepted"}
        ]
        counts = dict(snap.counts)
        counts["drift"] = sum(d.status == "needs_review" for d in visible_drift)
        counts["drift_reviewed"] = sum(d.status == "reviewed" for d in visible_drift)
        context = {
            "project": asdict(snap.project), "counts": counts,
            "drift": [asdict(d) for d in visible_drift],
        }
        envelopes = [asdict(a) for a in snap.attempts]
        latest = {(a["work_item_id"], a["gate_id"]): a for a in envelopes}
        configs = []
        for iid in rt.meta:
            for base_gate in rt.project.definition.gates:
                gate = self._effective_gate(iid, base_gate)
                att = latest.get((iid, gate.id))
                configs.append({
                    "work_item_id": iid, "gate_id": gate.id, "name": gate.name,
                    "agent_id": gate.agent_id, "executor_id": gate.executor_id,
                    "model_id": gate.model_id, "context_mode": gate.context_mode,
                    "continuity": gate.continuity, "editable": att is None or att["state"] == "Closed",
                    "attempt_id": att["attempt_id"] if att else None,
                    "locked": bool(att and att["state"] != "Closed"),
                    "readiness": self._gate_readiness(gate),
                })
        return context, envelopes, configs

    @_serialized
    def state(self) -> dict[str, Any]:
        if self.current is None:
            return {"connection": "live", "revision": 0, "projects": [], "currentProject": None,
                    "atlas": {"outcome": {"active": 0, "accepted": 0, "degraded": 0, "question": 0}, "capabilities": []},
                    "workItems": [], "questions": [], "settings": {}, "artifacts": [],
                    "interactions": [], "models": [], "agents": [], "gatePolicies": [], "classes": [],
                    "contextAtlas": {"project": None, "counts": {"drift": 0}, "drift": []},
                    "envelopes": [], "gateConfigs": [], "adapter": self.execution.id}
        rt = self._rt(); work = [self._project_item(iid) for iid in rt.meta]
        counts = {"active": sum(w["status"] == "open" and not w.get("openQuestionId") for w in work),
                  "accepted": sum(w["status"] == "accepted" for w in work),
                  "degraded": sum(w["status"] == "failed" for w in work),
                  "question": sum(bool(w.get("openQuestionId")) for w in work)}
        # All sibling lines remain separately selectable under one capability/component.
        components = [{"id": "component-work", "name": "Work items", "workItemIds": [w["id"] for w in work],
                       "outcome": counts}]
        context, envelopes, configs = self._context_state()
        definition = rt.project.definition
        return {"connection": "live", "revision": self._revision,
                "projects": [self._project_dict(p) for p in self.registry.list()],
                "currentProject": self._project_dict(rt.project),
                "atlas": {"outcome": counts, "capabilities": [{"id": "cap-reference", "name": definition.name,
                           "outcome": counts, "components": components}]},
                "workItems": work, "questions": list(rt.questions.values()), "settings": rt.settings,
                "artifacts": list(rt.artifacts.values()), "interactions": rt.interactions[-50:],
                "models": [{**asdict(m), "readiness": self._model_readiness(m)} for m in definition.models],
                "agents": [asdict(a) for a in definition.agents],
                "gatePolicies": [asdict(g) for g in definition.gates],
                "classes": [asdict(c) for c in definition.classes],
                "contextAtlas": context, "envelopes": envelopes, "gateConfigs": configs,
                "adapter": self.execution.id}


def _is_address_literal(hostname: str) -> bool:
    """Whether `hostname` is an IP address rather than a name."""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


class _AnyAddress(frozenset):
    """Host acceptance for a server bound to every interface.

    Binding to 0.0.0.0 is the operator asking to be reachable at an address
    this process cannot enumerate, so there is no list to compare a Host header
    against. The earlier shape accepted *every* Host for that reason, and said
    that cross-site was still refused because `_same_site` requires Origin to
    equal Host. That reasoning has a hole, and it is the whole attack: in DNS
    rebinding the page really is served from the attacker's name, so the
    browser sets Origin *and* Host to that name, they match, and the rule that
    was meant to refuse a cross-site write passes it.

    An address cannot be rebound. Rebinding needs a name whose address the
    attacker changes after the page has loaded; a page served from
    `http://192.168.1.50:8791` is already a page served by this server, which
    is what same-site means. So an address is accepted here and a name is not,
    and `--host 0.0.0.0` keeps doing the thing it is used for -- reaching the
    cockpit at this machine's LAN address.

    An operator who reaches it by name instead says which name with
    `--allow-host`, once, rather than every name being trusted by default.
    """
    def __contains__(self, item: object) -> bool:
        return (type(item) is str
                and (_is_address_literal(item) or frozenset.__contains__(self, item)))


class Handler(BaseHTTPRequestHandler):
    engine: CockpitEngine
    #  Replaced by `make_server` with the address actually bound. The default
    #  covers a Handler built directly, as the tests do.
    allowed_hosts: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
    #  A ceiling on the body bounds what one request can make this server hold;
    #  it does not bound how long it holds it. A client that announces a length
    #  and then sends nothing parks a thread in `read`, and every connection
    #  here gets a thread. So the socket expires after this long *idle*, which
    #  releases that client. The stream endpoint writes at least once a second,
    #  well inside it, and treats the expiry as the reader having gone away.
    #
    #  What this does not close, and is not claimed to: a client that dribbles
    #  a byte just under the interval keeps resetting it and holds its thread
    #  indefinitely. Bounding that needs a deadline for the whole request and a
    #  cap on concurrent connections, neither of which `ThreadingHTTPServer`
    #  has. Loopback by default is what keeps that from being reachable; an
    #  operator who binds this to a network is exposed to it.
    timeout = 30
    def log_message(self, format: str, *args: Any) -> None: pass

    def _json(self, status: int, payload: Any) -> None:
        data = json.dumps(payload, default=str).encode(); self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self._allow_origin()
        self.end_headers(); self.wfile.write(data)

    def _allow_origin(self) -> None:
        """Echo the request's own origin, and only when it is this site's."""
        origin = self.headers.get("Origin")
        if origin and self._same_site():
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _body(self) -> dict[str, Any]:
        """The request body, bounded by what this server agreed to hold.

        `Content-Length` is the client's claim about the body, not a fact, and
        it was previously handed straight to `read`. A negative value turns
        that into `read(-1)`, which is "read until the peer stops sending" and
        ignores the declared length entirely; a large one reserves that much
        for a body the client never has to finish. Either way one request holds
        a thread and its memory for as long as it likes, and this server gives
        every connection a thread.
        """
        raw = self.headers.get("Content-Length")
        if raw is None:
            return {}
        try:
            length = int(raw)
        except ValueError:
            raise ValueError("Content-Length must be an integer") from None
        if length < 0:
            raise ValueError("Content-Length must not be negative")
        if length > MAX_BODY_BYTES:
            raise ValueError(
                f"request body is larger than the {MAX_BODY_BYTES}-byte limit")
        if length == 0:
            return {}
        body = self.rfile.read(length)
        # A short read is a client that stopped early, not a shorter body: the
        # bytes that did arrive are a prefix of a document nobody sent.
        if len(body) != length:
            raise ValueError("request body is shorter than its Content-Length")
        return json.loads(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/") and not self._same_site():
            return self._json(403, {"error": self._refusal()})
        if path == "/api/state": return self._json(200, self.engine.state())
        if path == "/api/state/stream": return self._stream()
        if path == "/api/projects": return self._json(200, {"projects": self.engine.state()["projects"]})
        if path == "/api/projects/discover":
            # The client sends a filter, never a path: discovery is confined to
            # the server's own roots so it cannot be aimed at a directory.
            query = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            return self._json(200, {
                "roots": [str(r) for r in default_roots()],
                "candidates": [c.to_dict() for c in discover_projects(query)],
            })
        if path == "/api/events":
            state = self.engine.state(); rt = self.engine.current
            events = ([] if rt is None else
                      [to_plain_json(ev) for ev in rt.enforcer.events]
                      + rt.context.events + rt.interactions)
            return self._json(200, {"events": events,
                                    "revision": state["revision"]})
        # An unmatched API path is a 404, never the SPA shell: serving index.html
        # to a JSON or EventSource client hides the mistake behind a parse error.
        if path.startswith("/api/"): return self._json(404, {"error": "not found"})
        self._static(path)

    def _stream(self) -> None:
        """Server-sent state. One frame on connect, then one per revision.

        Read-only, like every other cockpit surface: the stream carries the same
        snapshot `GET /api/state` returns and accepts nothing back.
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._allow_origin()
        self.end_headers()
        last: int | None = None
        try:
            while True:
                state = self.engine.state()
                revision = state.get("revision")
                if revision != last:
                    last = revision
                    self.wfile.write(f"data: {json.dumps(state, default=str)}\n\n".encode())
                else:
                    self.wfile.write(b": keep-alive\n\n")   # keeps proxies from idling us out
                self.wfile.flush()
                time.sleep(1.0)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return  # the operator closed the tab
        except Exception:
            # Never end the stream quietly: the client treats a dropped stream
            # as a blip and keeps rendering its last snapshot, so a crash here
            # would show a dead authority as a healthy board.
            try:
                self.wfile.write(b"event: fault\ndata: {\"error\":\"stream failed\"}\n\n")
                self.wfile.flush()
            except OSError:
                pass
            raise

    def _same_site(self) -> bool:
        """Refuse cross-site writes and DNS-rebound reads.

        A browser on any page the operator visits can reach 127.0.0.1, and a
        text/plain POST is a CORS-simple request so no preflight protects it.
        Loopback is not an authentication boundary, so check the two things the
        browser sets and a page cannot forge: Origin and Host.

        Both are checked against the address the server actually bound, not a
        hardcoded list. A hardcoded list made `--port` and `--host` silently
        half-broken: static files and same-origin reads still worked, so the
        board showed Live while every write got a 403.
        """
        host = self.headers.get("Host") or ""
        try:
            hostname = urlsplit(f"//{host}").hostname or ""
        except ValueError:
            return False
        # An absent Host is not a pass. HTTP/1.1 requires the header, every
        # browser sends it, and treating "" as "nothing to check" made the one
        # check that pins this server's identity skippable by omitting it.
        if not hostname or hostname.lower() not in self.allowed_hosts:
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            return True  # not a browser form post, or same-origin
        try:
            parts = urlsplit(origin)
        except ValueError:
            # Same reason the Host split above is guarded: an unparseable
            # Origin is a refusal, not a traceback. `_same_site` is called
            # outside `do_POST`'s try, so an exception here escapes the
            # handler and answers the request by dropping the connection.
            return False
        if parts.scheme not in ("http", "https"):
            return False
        # Same site means the page was served by this address. Comparing the
        # origin to the Host header is exact at any port, and needs no list.
        return parts.netloc.lower() == host.lower()

    def _refusal(self) -> str:
        """Why this request was not this server's own page.

        Both cases are refused; only the wording differs. A Host that is
        simply not on the list is usually the operator reaching their own
        cockpit by a name it was never told to answer to -- their machine's
        hostname, most often -- and answering that with "cross-site" sends
        them looking for an attacker instead of at `--allow-host`.
        """
        host = self.headers.get("Host") or ""
        try:
            hostname = (urlsplit(f"//{host}").hostname or "").lower()
        except ValueError:
            hostname = ""
        if hostname and hostname not in self.allowed_hosts:
            # The name is stated so the operator can see what was sent, but
            # not as a ready-made command: a refused name is as likely to be
            # an attacker's as their own, and this must not hand back a
            # paste-able line that would allow it.
            return (f"refused: this server was not told to answer to the host "
                    f"{hostname!r}. If that is genuinely how you reach your "
                    f"own cockpit, restart it with --allow-host and that name")
        return "refused: cross-site request"

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not self._same_site():
            return self._json(403, {"error": self._refusal()})
        try:
            body = self._body(); parts = [p for p in path.split("/") if p]
            if path == "/api/projects/load": return self._json(201, self.engine.load_project(body))
            if len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "select":
                return self._json(200, self.engine.select_project(parts[2]))
            if path == "/api/settings":
                return self._json(200, {"settings": self.engine.update_settings(body)})
            if path == "/api/work-items/compile":
                return self._json(200, {"contract": self.engine.compile_contract(
                    body.get("prompt", ""), body.get("cls") or body.get("class"))})
            if path == "/api/work-items":
                return self._json(201, self.engine.create_work_item(
                    body.get("prompt", ""), body.get("project_id", body.get("projectId")),
                    (body.get("contract") or {}).get("cls") or body.get("cls")))
            if len(parts) == 6 and parts[:2] == ["api", "work-items"] and parts[3] == "gates" and parts[5] == "configure":
                return self._json(200, self.engine.configure_gate(parts[2], parts[4], body))
            if len(parts) == 4 and parts[:2] == ["api", "work-items"] and parts[3] == "impact-review":
                return self._json(200, self.engine.review_impact(
                    parts[2], body.get("classification", ""), body.get("decision", ""), body.get("actor", "owner")
                ))
            if len(parts) == 4 and parts[:2] == ["api", "work-items"] and parts[3] == "steer":
                text = body.get("text", "") or ("/" + str(body.get("command", "")).lstrip("/"))
                ev = self.engine.steer(parts[2], body.get("node_id", body.get("nodeId", "")), text,
                                       scope=body.get("scope", "stage"))
                return self._json(200, {"event": ev})
            if len(parts) == 4 and parts[:2] == ["api", "work-items"] and parts[3] == "action":
                command = "/" + str(body.get("command") or body.get("action", "")).lstrip("/")
                return self._json(200, {"event": self.engine.action(parts[2], body.get("node_id", body.get("nodeId", "")), command),
                                        "state": self.engine.state()})
            if len(parts) == 4 and parts[:2] == ["api", "questions"] and parts[3] == "answer":
                answer = body.get("answer") or body.get("text") or body.get("value", "")
                return self._json(200, self.engine.answer_question(parts[2], answer))
            return self._json(404, {"error": "not found"})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            return self._json(400, {"error": str(exc)})

    def do_OPTIONS(self) -> None:
        self.send_response(204); self._allow_origin()
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS"); self.end_headers()

    def _static(self, path: str) -> None:
        target = (DIST / ("index.html" if path == "/" else path.lstrip("/"))).resolve()
        if DIST.resolve() not in target.parents and target != DIST.resolve(): return self._json(403, {"error": "forbidden"})
        if not target.is_file(): target = DIST / "index.html"
        if not target.is_file(): return self._json(404, {"error": "cockpit build not found; run npm build"})
        data = target.read_bytes(); self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)


#  Loopback under every name a browser may use for it, plus the Vite dev
#  server's host. The port is not part of this: `_same_site` pins the port by
#  comparing Origin to the Host header, which is exact wherever the server is
#  bound. `ANY_HOST` is what binding to 0.0.0.0 means — the operator asked to
#  be reachable by an address this process cannot enumerate. It does NOT follow
#  that the Origin-equals-Host rule still refuses every cross-site write: under
#  DNS rebinding the page really is served from the attacker's name, so the
#  browser sets both headers to that name and they agree. That is the whole
#  attack, and `_AnyAddress` below is the answer to it.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
ANY_HOST = frozenset({"0.0.0.0", "::"})


def allowed_hosts_for(host: str, allow_hosts: Iterable[str] = ()) -> frozenset[str]:
    """The Host values this server answers to, given the address it bound.

    Separate from `make_server` because deciding *which* hosts are ours is the
    security question, and binding a socket is not. Kept apart, the decision
    can be asserted on directly rather than only through a served request.
    """
    bound = (host or "").lower()
    named = frozenset(name.strip().lower() for name in allow_hosts if name.strip())
    base = LOOPBACK_HOSTS | named | ({bound} if bound else set())
    #  Binding to every interface has no enumerable address list, so that case
    #  accepts address literals as well as these names. Binding to one address
    #  does have one, and it stays closed.
    return _AnyAddress(base) if bound in ANY_HOST else frozenset(base)


def make_server(host: str, port: int, engine: CockpitEngine | None = None,
                allow_hosts: Iterable[str] = ()) -> ThreadingHTTPServer:
    impl = engine or CockpitEngine(seed=(ROOT / ".git").exists())
    literal = host.split("%", 1)[0]
    try:
        ipv6 = ipaddress.ip_address(literal).version == 6
    except ValueError:
        ipv6 = False
    server_type = ThreadingHTTPServer
    if ipv6:
        server_type = type(
            "IPv6ThreadingHTTPServer",
            (ThreadingHTTPServer,),
            {"address_family": socket.AF_INET6},
        )
    return server_type((host, port), type(
        "CockpitHandler", (Handler,),
        {"engine": impl, "allowed_hosts": allowed_hosts_for(host, allow_hosts)}))


def main() -> None:
    parser = argparse.ArgumentParser(description="fcd reference cockpit")
    parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8791)
    parser.add_argument(
        "--allow-host", action="append", default=[], metavar="NAME",
        help="additional Host name to accept, for reaching the cockpit by name "
             "rather than by address. Repeatable.")
    args = parser.parse_args()
    httpd = make_server(args.host, args.port, allow_hosts=args.allow_host)
    print(f"cockpit http://{args.host}:{args.port}"); httpd.serve_forever()


if __name__ == "__main__": main()
