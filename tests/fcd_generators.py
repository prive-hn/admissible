"""Hypothesis strategies over valid FCD Enforcer histories with fault injection,
for the identity-layer property sweep (tests/test_fcd_enforcer_properties.py).

The custody generator drives the Enforcer only on the happy path (always
bind(True), always observe the matching model). This one draws the faults the
identity invariants exist to forbid — a foreign or bracket-variant executed
model, an out-of-policy or already-tried specialist, a bind failure, a re-open
of a live id — so I1..I9 are exercised against the paths that could break them,
not only the ones that cannot. Every move is guard-checked; a refused move is
dropped, so each produced history is a real trace of the machine (a member of
its accepted language).
"""
from __future__ import annotations

import itertools
import os
import sys
from dataclasses import dataclass, field

from hypothesis import strategies as st

HERE = os.path.dirname(__file__)
for _p in (os.path.join(HERE, ".."), HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fcd.core import Enforcer, Policy, norm  # noqa: E402

# Specialists and their pinned API model identities.
PHI = {
    "gen": "vendorA:model-g",
    "gen2": "vendorB:model-g2",
    "rev": "vendorC:model-r",
    "aux": "vendorA:model-x",
}
SPECIALISTS = tuple(PHI)
# Executed-model draws that are NOT the identity of any admissible specialist.
FOREIGN_MODELS = ("vendorZ:rogue", "unbound:none", "vendorA:model-g-evil")


def gen_policy(deny=(), writes=1, version="v1") -> Policy:
    """A multi-specialist policy with write+check stages. `deny` lets a drawn
    specialist be forbidden (F6), and >=1 write stage means the check stage's
    pi* excludes the write author (I6)."""
    return Policy(
        allow={"impl": set(SPECIALISTS)},
        deny={"impl": set(deny)},
        phi=dict(PHI),
        required={"impl": [("write", f"s{i}") for i in range(writes)] + [("check", "c1")]},
        version=version,
    )


@dataclass
class FcdHistory:
    e: Enforcer
    policy: Policy
    items: tuple           # every id opened
    accepted: tuple        # ids that reached the store
    moves: tuple           # human-readable log


def _try(fn) -> bool:
    try:
        fn()
        return True
    except Exception:
        return False


def _model_for(draw, e: Enforcer, item_id: str, a: str) -> str:
    """Draw an executed model: the bound identity, a bracket-variant of it (norm
    equal), another admissible specialist's identity, or a foreign one."""
    phi_a = e.policy_for(item_id).phi[a]
    kind = draw(st.sampled_from(["match", "bracket", "other", "foreign"]))
    if kind == "match":
        return phi_a
    if kind == "bracket":
        return f"{phi_a}[attempt=1]"           # norm() strips the suffix -> matches
    if kind == "other":
        return PHI[draw(st.sampled_from(SPECIALISTS))]
    return draw(st.sampled_from(FOREIGN_MODELS))


@st.composite
def fcd_histories(draw, *, max_items: int = 3, max_steps: int = 10):
    """Grow a valid FCD history over one Enforcer, with fault injection."""
    deny = draw(st.sampled_from([(), (), ("aux",)]))     # sometimes a denied specialist
    writes = draw(st.integers(min_value=1, max_value=2))
    e = Enforcer(gen_policy(deny=deny, writes=writes))
    moves: list[str] = []
    n_items = draw(st.integers(min_value=1, max_value=max_items))
    items = [f"w{i}" for i in range(n_items)]
    for iid in items:
        if _try(lambda i=iid: e.open(i, "impl", f"body-{i}")):
            moves.append(f"open {iid}")

    for _ in range(draw(st.integers(min_value=1, max_value=max_steps))):
        live = [i for i in items if e.items[i].status == "open"]
        if not live:
            break
        iid = draw(st.sampled_from(live))
        item = e.items[iid]
        st_obj = item.stages[item.pointer]
        pc = st_obj.pc
        if pc in ("Open", "Closed"):
            # admit a drawn specialist (valid, denied, tried, or unknown), else no_admit
            action = draw(st.sampled_from(["admit", "admit", "admit", "no_admit"]))
            if action == "no_admit":
                if _try(lambda i=iid: e.no_admit(i)):
                    moves.append(f"no_admit {iid}")
                continue
            a = draw(st.sampled_from(SPECIALISTS + ("ghost",)))   # 'ghost' is unknown -> refused
            if _try(lambda i=iid, s=a: e.admit(i, s)):
                moves.append(f"admit {iid} {a}")
        elif pc == "Admitted":
            usable = draw(st.sampled_from([True, True, True, False]))  # mostly usable; False -> F3
            if _try(lambda i=iid, u=usable: e.bind(i, u)):
                moves.append(f"bind {iid} {usable}")
        elif pc == "Running":
            sub = draw(st.sampled_from(["observe_decide", "observe_decide", "close", "death"]))
            if sub == "close":
                if _try(lambda i=iid: e.close(i, "refuse")):
                    moves.append(f"close {iid}")
                continue
            if sub == "death":
                if _try(lambda i=iid: e.death_observed(i)):
                    moves.append(f"death {iid}")
                continue
            a = st_obj.a
            m = _model_for(draw, e, iid, a)
            if _try(lambda i=iid, mm=m: e.observe(i, mm)):
                moves.append(f"observe {iid} {m}")
                if _try(lambda i=iid: e.decide_pass(i)):
                    moves.append(f"decide {iid}")

    accepted = tuple(i for i in items if e.items[i].status == "accepted")
    return FcdHistory(e=e, policy=e.policy, items=tuple(items), accepted=accepted, moves=tuple(moves))
