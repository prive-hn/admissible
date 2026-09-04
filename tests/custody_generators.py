"""Hypothesis strategies that grow valid three-layer kernel histories, for the
custody theorem property sweep (``tests/test_custody_theorems.py``) and the
conjecture-attack lane (``tests/test_custody_conjectures.py``).

A history is grown by drawing a sequence of legal moves and applying each to a
real ``CalHarness`` (FCD + RGA + calibration).  A move whose guards refuse it is
dropped, so every produced history is a member of the machines' accepted
language ``L(mu)`` by construction: the generator explores the reachable state
space, never a forged one.  The custody functions under test are pure queries
over that state, so property failures are always about the theory or the kernel,
never about a malformed fixture.

The returned :class:`History` bundle names the lines, which sealed, and the
moves applied, so a property can address structure without re-deriving it.  The
tamper helpers (:func:`rebuild`, :func:`prune`) reproduce the exact
``from_events`` round-trip a verifier performs, so a property that deletes a
group and rebuilds is doing what the paper's deletion moves (D17) describe.

This module is imported by the property tests; it defines no ``test_*`` itself.
"""
from __future__ import annotations

import dataclasses
import itertools
import os
import sys
from dataclasses import dataclass, field
from typing import Callable, Optional

from hypothesis import strategies as st

HERE = os.path.dirname(__file__)
for _p in (os.path.join(HERE, ".."), HERE, os.path.join(HERE, "..", "paper", "custody")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import custody  # noqa: E402
from fcd.core import Enforcer  # noqa: E402
from rga.core import Admission, DefectModel, LedgerEntry, Refuter  # noqa: E402
from rga.calibration import CalibrationAuthority  # noqa: E402
from test_rga_invariants import D1, K, TESTS, admission_policy, fcd_policy  # noqa: E402
from test_rga_calibration import CalHarness  # noqa: E402


# -- the history bundle --------------------------------------------------------

@dataclass
class History:
    """A grown three-layer history plus the structure a property needs."""
    h: object                       # CalHarness
    lines: tuple                    # every FCD item id opened
    sealed: tuple                   # the subset that carries a seal
    moves: tuple                    # human-readable log of the moves applied
    config: dict = field(default_factory=dict)

    @property
    def cal(self) -> CalibrationAuthority:
        return self.h.cal

    @property
    def adm(self) -> Admission:
        return self.h.a

    @property
    def fcd(self) -> Enforcer:
        return self.h.e


# -- verifier round-trips (the deletion move D17 / replay T1) ------------------

def rebuild(h) -> CalibrationAuthority:
    """Rebuild all three machines from their journals, as a third party holding
    only the record would (T1: replay is a retraction).  Raises the kernel's own
    error if a journal is not re-derivable."""
    fcd2 = Enforcer.from_events(list(h.e.events), fcd_policy(h.k))
    adm2 = Admission.from_events(list(h.a.events), fcd2, h.a.policy)
    return CalibrationAuthority.from_events(list(h.cal.events), adm2, h.cal.policy)


def prune(h, *, drop: Callable[[dict], bool]) -> Optional[CalibrationAuthority]:
    """Rebuild the calibration machine from its journal with the events matching
    ``drop`` removed (a recompute-free deletion, D17).  Returns the rebuilt
    authority, or ``None`` if the pruned journal is not re-derivable (replay
    refuses the tamper — outside ``L_rep``)."""
    pruned = [e for e in h.cal.events if not drop(e)]
    try:
        return CalibrationAuthority.from_events(pruned, h.a, h.cal.policy)
    except Exception:
        return None


# -- move application (each guarded; a refused move is simply not in L(mu)) ----

def _try(fn) -> bool:
    try:
        fn()
        return True
    except Exception:
        return False


class _Builder:
    """Applies drawn moves to a CalHarness, dropping any the guards refuse."""

    def __init__(self, h: CalHarness):
        self.h = h
        self.sealed: list[str] = []
        self.moves: list[str] = []
        self._nonce = itertools.count()
        self._hawk_declared = False

    # sealing ------------------------------------------------------------------
    def seal(self, iid: str) -> None:
        if _try(lambda: self.h.seal_line(iid)):
            self.sealed.append(iid)
            self.moves.append(f"seal {iid}")

    # tier-A escape, established (impeaches the line) --------------------------
    def escape_impeach(self, iid: str, witness: str) -> None:
        n = f"esc-{next(self._nonce)}"

        def go():
            run = self.h.tier_a_escape(iid, nonce=n, witness=witness, replay=True)
            return run
        if _try(go):
            self.moves.append(f"escape_impeach {iid} @{n}")

    # tier-A escape, divergent replay (CF1: discredits the checker) -----------
    def escape_discredit(self, iid: str, witness: str) -> None:
        n = f"dis-{next(self._nonce)}"

        def go():
            seal = self.h.a.sealed[iid]
            from rga.core import derive_seed
            seed = derive_seed(n, seal.artifact_hash, "tests", "v1", "tests_pass")
            run = self.h.cal.file_escape(iid, "tests_pass", "tests", "v1", n,
                                         f"{iid}-body-0".encode(), seed, witness, finder="auditor")
            # divergent replay: verdict disagrees with the filed 'refuted'
            self.h.cal.replay_run(run.index, "survived", witness)
        if _try(go):
            self.moves.append(f"escape_discredit {iid} @{n}")

    # tier-A escape only (filed, not established) -----------------------------
    def escape_only(self, iid: str, witness: str) -> None:
        n = f"only-{next(self._nonce)}"
        if _try(lambda: self.h.tier_a_escape(iid, nonce=n, witness=witness, replay=False)):
            self.moves.append(f"escape_only {iid} @{n}")

    # tier-B escape + adjudication (cal_adjudicate polarity) ------------------
    def tier_b(self, iid: str, decision: str) -> None:
        ver = f"v{next(self._nonce)}"
        n = f"hawk-{next(self._nonce)}"

        def go():
            if not self._hawk_declared:
                self.h.a.declare(Refuter("hawk", ver, "hawk-author", "ledger"))
                self._hawk_declared = True
            else:
                self.h.a.declare(Refuter("hawk", ver, "hawk-author", "ledger"))
            run = self.h.cal.file_escape(iid, "tests_pass", "hawk", ver, n,
                                         f"{iid}-body-0".encode(), "any-seed", "hk", "aud")
            self.h.cal.replay_run(run.index, "refuted", "hk")
            self.h.cal.adjudicate(run.index, "owner", decision, "adjudicated by generator")
        if _try(go):
            self.moves.append(f"tier_b {iid} {decision} {ver}")

    # a refusal that taints every line pinning `tests` (rga_refuse, +/-) ------
    def taint(self, zid: str) -> None:
        def go():
            self.h.fcd_open(zid)
            self.h.a.open(zid, "gen", "temp=0.7")
            self.h.fcd_write(zid)
            self.h.sample(zid, f"{zid}0".encode())
            self.h.trial(zid)                                   # filed 'survived'
            self.h.a.replay(zid, 0, "refuted", "w-same")        # diverges -> refuses `tests`
        if _try(go):
            self.moves.append(f"taint via {zid}")

    # exclude a run by index (the named exit) --------------------------------
    def exclude_first(self, iid: str) -> None:
        runs = [r for r in self.h.cal.runs if r.line_id == iid]
        if not runs:
            return
        idx = runs[0].index

        def go():
            self.h.cal.exclude("impl", [idx], "owner", "class retired by generator")
        if _try(go):
            self.moves.append(f"exclude {iid} run{idx}")


# -- the strategy --------------------------------------------------------------

_WITNESSES = ["kill-w", "kill-x", "w-same"]
_POST_MOVES = ["escape_impeach", "escape_discredit", "escape_only",
               "tier_b_accept", "tier_b_reject", "taint", "exclude"]


@st.composite
def histories(draw, *, max_lines: int = 3, max_moves: int = 6):
    """Grow a valid, varied three-layer history.

    Draws a class configuration, seals a handful of lines, then applies a drawn
    sequence of post-seal calibration moves — escapes (established, divergent,
    or merely filed), tier-B adjudications, a tainting refusal, and exclusions.
    Every move is guard-checked; refused moves are dropped.
    """
    k = draw(st.integers(min_value=1, max_value=2))
    e_max = draw(st.integers(min_value=1, max_value=3))
    gate = draw(st.sampled_from(["seal", "carry"]))
    n_lines = draw(st.integers(min_value=1, max_value=max_lines))
    kills = draw(st.integers(min_value=3, max_value=10))   # <5 stays below p_min (unsealable)

    h = CalHarness(k=k, e_max=e_max, gate=gate)
    h.declare_tests(kills=kills, size=10)
    b = _Builder(h)

    lines = [f"w{i}" for i in range(n_lines)]
    for iid in lines:
        b.seal(iid)

    n_moves = draw(st.integers(min_value=0, max_value=max_moves))
    tainted = False
    ztick = itertools.count()
    for _ in range(n_moves):
        if not b.sealed:
            break
        move = draw(st.sampled_from(_POST_MOVES))
        iid = draw(st.sampled_from(b.sealed))
        witness = draw(st.sampled_from(_WITNESSES))
        if move == "escape_impeach":
            b.escape_impeach(iid, witness)
        elif move == "escape_discredit":
            b.escape_discredit(iid, witness)
        elif move == "escape_only":
            b.escape_only(iid, witness)
        elif move == "tier_b_accept":
            b.tier_b(iid, "accept")
        elif move == "tier_b_reject":
            b.tier_b(iid, "reject")
        elif move == "taint" and not tainted:
            b.taint(f"z{next(ztick)}")
            tainted = True
        elif move == "exclude":
            b.exclude_first(iid)

    return History(
        h=h,
        lines=tuple(lines),
        sealed=tuple(b.sealed),
        moves=tuple(b.moves),
        config={"k": k, "e_max": e_max, "gate": gate, "kills": kills, "tainted": tainted},
    )


# -- power vectors for the pure-math theorems (T6, T7) -------------------------

def power_vectors(min_size: int = 0, max_size: int = 6):
    """Vectors of powers in [0, 1] for the Fréchet/Bonferroni properties."""
    return st.lists(
        st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        min_size=min_size, max_size=max_size,
    )
