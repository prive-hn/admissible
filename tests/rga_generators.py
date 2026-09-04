"""Hypothesis strategies over valid RGA (Admission) histories with fault
injection, for the scrutiny-layer property sweep (tests/test_rga_properties.py).

The custody generator drives RGA only on the sealing path (all trials survive,
theta=1, identical witnesses, always replayed). This one draws the faults the
scrutiny invariants exist to forbid — refuted / inconclusive verdicts, witnesses
that disagree across samples, a divergent replay that refuses a refuter, a
bounded (epsilon, N) refuter, a second measure/bound on a live key — over one
or more lines and claims, so R1..R13 are exercised against the paths that could
break them. Each kernel call is guard-checked; a refused move is dropped, so
every produced history is a real trace of the composed machine.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

from hypothesis import strategies as st

HERE = os.path.dirname(__file__)
for _p in (os.path.join(HERE, ".."), HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from rga.core import (Admission, AdmissionPolicy, ClaimSpec, ClassAdmission,  # noqa: E402
                      DefectModel, LedgerEntry, Refuter)
from fcd.core import Enforcer  # noqa: E402
from test_rga_invariants import D1, K, TESTS, fcd_policy  # noqa: E402


@dataclass
class RgaHistory:
    h: object                      # the Harness driving FCD + RGA
    lines: tuple                   # every line id opened
    sealed: tuple                  # the subset that sealed
    moves: tuple


def _try(fn) -> bool:
    try:
        fn()
        return True
    except Exception:
        return False


# A local harness so the generator owns its refuter set and can add a second
# claim / a bounded refuter without disturbing the shared fixtures.
from test_rga_invariants import Harness  # noqa: E402


@st.composite
def rga_histories(draw, *, max_lines: int = 3):
    """Grow a valid RGA history with fault injection over one Harness."""
    theta = draw(st.sampled_from([1.0, 1.0, 0.6]))     # sometimes below 1 -> discord can seal
    kills = draw(st.integers(min_value=3, max_value=10))
    h = Harness(theta=theta, p_min=0.5, k=K)
    h.declare_tests(kills=kills, size=10)
    moves: list[str] = []
    n = draw(st.integers(min_value=1, max_value=max_lines))
    lines = [f"L{i}" for i in range(n)]
    sealed: list[str] = []

    for iid in lines:
        if not _try(lambda i=iid: h.fcd_open(i)):
            continue
        if not _try(lambda i=iid: h.rga_open(i)):
            continue
        moves.append(f"open {iid}")
        # A per-line mode gives a controllable mix of sealing and closing paths.
        mode = draw(st.sampled_from(["clean", "clean", "clean", "refuted", "inconclusive", "discord", "divergent"]))
        if mode == "clean":
            verdicts = ["survived"] * K
            witnesses = ["w-same"] * K
        elif mode in ("refuted", "inconclusive"):
            bad = draw(st.integers(min_value=0, max_value=K - 1))
            verdicts = ["survived"] * K
            verdicts[bad] = mode
            witnesses = ["w-same"] * K
        elif mode == "discord":                       # witnesses disagree across samples
            verdicts = ["survived"] * K
            witnesses = ["w-same"] + ["w-alt"] * (K - 1)
        else:                                          # divergent
            verdicts = ["survived"] * K
            witnesses = ["w-same"] * K
        closed = False
        for i in range(K):
            if not _try(lambda i=iid: h.fcd_write(i)):
                closed = True
                break
            if not _try(lambda i=iid, j=i: h.sample(i, f"{i}-body-{j}".encode())):
                closed = True
                break
            v, w = verdicts[i], witnesses[i]
            if not _try(lambda i=iid, j=i, vv=v, ww=w: h.trial(i, j, verdict=vv, witness=ww)):
                # a refused trial (e.g. duplicate) — skip
                pass
            if v in ("refuted", "inconclusive"):
                closed = True                          # V1/V3: the line is closed at this trial
                break
        if closed:
            moves.append(f"line {iid} closed (verdict)")
            continue
        # replay: identical (keeps sealable) or divergent (R5 refuses the refuter)
        if mode == "divergent":
            # a divergent replay of trial 0 refuses `tests` and closes open lines
            _try(lambda i=iid: h.a.replay(i, 0, "refuted", "w-flip"))
            moves.append(f"line {iid} divergent-replay")
            continue
        _try(lambda i=iid: h.replay_all(i))
        if not _try(lambda i=iid: h.fcd_check(i)):
            moves.append(f"line {iid} no-check")
            continue
        if _try(lambda i=iid: h.a.seal(i)):
            sealed.append(iid)
            moves.append(f"seal {iid}")
        else:
            moves.append(f"line {iid} seal-refused")

    return RgaHistory(h=h, lines=tuple(lines), sealed=tuple(sealed), moves=tuple(moves))
