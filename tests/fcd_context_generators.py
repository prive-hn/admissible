"""Hypothesis strategies over ContextAuthority histories, for the envelope /
memory property sweep (tests/test_fcd_context_properties.py).

The three-layer history generator never touches the ContextAuthority (I10-I17);
this one drives it: a project, work opens that pin the project/memory head, one
or more admitted attempts per work item (retries mint a fresh counter, nonce and
envelope), live steering, and project-head advances interleaved so the write-once
pins can be checked against a moved head. Every call is guard-checked; a refused
move is dropped.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from hypothesis import strategies as st

HERE = os.path.dirname(__file__)
for _p in (os.path.join(HERE, ".."), HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fcd.context import (AgentRef, ContextAuthority, ContextPolicy,  # noqa: E402
                         ExecutionAdapterRef, GateSpec, ModelRef, ProjectState)


def gate_spec(*, model="model-a", mode="project_shared", continuity="fresh", caps=frozenset()):
    return GateSpec(
        id="implement", revision=1,
        agent=AgentRef("builder", 1, "Build the requested outcome"),
        executor=ExecutionAdapterRef("codex", 1, caps),
        model=ModelRef("openai", model, "Builder model"),
        context_policy=ContextPolicy(
            mode=mode,
            include=frozenset({"accepted_project_facts", "contract", "candidate_diff"}),
            exclude=frozenset(), memory_scope="accepted_only", continuity=continuity),
        tool_manifest_hash="tools-v1", instruction_hash="instructions-v1")


@dataclass
class ContextHistory:
    auth: object
    project: str
    works: tuple                    # work item ids opened
    attempts: tuple                 # (_Attempt) objects admitted, in order
    pins: dict                      # work id -> (project_version, memory_version) at open
    moves: tuple


def _try(fn):
    try:
        return fn(), True
    except Exception:
        return None, False


@st.composite
def context_histories(draw, *, max_works: int = 3, max_steps: int = 8):
    accepted: set[str] = set()
    auth = ContextAuthority(is_accepted=lambda w: w in accepted)
    pv = draw(st.integers(min_value=1, max_value=50))
    mv = draw(st.integers(min_value=1, max_value=50))
    auth.add_project(ProjectState("p", pv, mv, "policy-1", strict_unknown=True))
    moves: list[str] = []
    works: list[str] = []
    pins: dict = {}
    attempts: list = []

    n = draw(st.integers(min_value=1, max_value=max_works))
    for i in range(n):
        wid = f"W{i}"
        pin, ok = _try(lambda w=wid: auth.open_work("p", w, contract_revision=1))
        if ok:
            works.append(wid)
            pins[wid] = (pin.project_version, pin.memory_version)
            moves.append(f"open {wid}")

    for _ in range(draw(st.integers(min_value=1, max_value=max_steps))):
        if not works:
            break
        action = draw(st.sampled_from(["admit", "admit", "retry", "steer", "advance"]))
        wid = draw(st.sampled_from(works))
        if action == "advance":
            npv = draw(st.integers(min_value=pv, max_value=pv + 5))
            nmv = draw(st.integers(min_value=mv, max_value=mv + 5))
            _, ok = _try(lambda: auth.advance_project_for_test("p", npv, nmv))
            if ok:
                pv, mv = npv, nmv
                moves.append(f"advance {npv},{nmv}")
        elif action in ("admit", "retry"):
            mode = draw(st.sampled_from(["project_shared", "project_shared", "fresh_scoped"]))
            a, ok = _try(lambda w=wid, m=mode: auth.admit(w, gate_spec(mode=m), specialist=f"s{len(attempts)}"))
            if ok:
                attempts.append(a)
                moves.append(f"admit {wid}")
                if action == "retry":
                    _try(lambda aid=a.envelope.attempt_id: auth.close(aid))
        elif action == "steer" and attempts:
            a = attempts[-1]
            _, ok = _try(lambda aid=a.envelope.attempt_id, w=wid: auth.append_steering(aid, "work", w, "adjust"))
            if ok:
                moves.append(f"steer {wid}")

    return ContextHistory(auth=auth, project="p", works=tuple(works),
                          attempts=tuple(attempts), pins=pins, moves=tuple(moves))
