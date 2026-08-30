"""Rates and survival from the event journal.

Implements metrics/SCHEMA.md exactly:

- named cut [t0, t1]: events outside the window are excluded; stages
  with ts > t1 - W are right-censored out of the samples they would
  bias (they have not had time to complete).
- misbind: FIRST Observe per stage (first_attempt=True). Later
  observes are re-observe territory — metric, not gate.
- silent_fail: well-formed stages without a decide/accept within W,
  PLUS orphan opens (opened, never staged). fail_closed counts as
  published, so it is NOT silent.
- bleed: assigned specialist outside pi* as-of ts; check stages use
  pi_chk (authors excluded). Paired with silent-fail in reporting.
- survival: durations to decide/accept for stages fully inside the
  cut, right-censored tail dropped. Report as a curve, never a mean.

All functions are pure: (events, cut, policy) -> numbers. No I/O, no
clock reads. Deterministic for tests and replays.
"""
from __future__ import annotations

from typing import Optional

from .core import norm


def _stage_key(e: dict) -> tuple:
    return (e.get("work_item_id"), e.get("stage_id"))


def _model_fields(c: dict) -> tuple[Optional[str], Optional[str]]:
    """(declared, executed) from schema names or short names."""
    decl = c.get("declared_model", c.get("declared"))
    exec_ = c.get("executed_model", c.get("executed"))
    return decl, exec_


def rates(
    events: list[dict],
    t0: float,
    t1: float,
    W: float,
    policy: Optional[dict],
) -> dict:
    """misbind / silent_fail / bleed over a named cut.

    `policy` is the as-of snapshot at each event's ts when the caller
    tracks versions; here a single dict {allow, deny, phi} (already
    resolved as-of). None disables bleed (den=0).
    """
    in_cut = [e for e in events if t0 <= e.get("ts", 0) <= t1]
    censor = t1 - W

    stages = [e for e in in_cut if e.get("type") == "stage" and e.get("well_formed")]
    opens = [e for e in in_cut if e.get("type") == "open"]
    calls = [e for e in in_cut if e.get("type") == "call"]
    decides = [e for e in in_cut if e.get("type") in ("decide", "accept")]

    # --- misbind: first observe per stage, in-cut, mismatch ---------
    first_calls: dict[tuple, dict] = {}
    for c in calls:
        k = _stage_key(c)
        if k not in first_calls:
            first_calls[k] = c
    mis_num = mis_den = 0
    for k, c in first_calls.items():
        if c.get("ts", 0) > censor:
            continue
        mis_den += 1
        # Recompute from raw fields when present; fall back to the
        # emitter's on_bind flag. Never default a mismatch to clean.
        decl, exec_ = _model_fields(c)
        if decl is not None and exec_ is not None:
            on_bind = norm(exec_) == norm(decl)
        else:
            on_bind = c.get("on_bind", True)
        if not on_bind:
            mis_num += 1

    # --- silent fail: stages w/o published close + orphan opens -----
    closed = {_stage_key(d) for d in decides}
    sil_den = sil_num = 0
    for s in stages:
        if s.get("ts", 0) > censor:
            continue
        sil_den += 1
        if _stage_key(s) not in closed:
            sil_num += 1
    staged_items = {s.get("work_item_id") for s in stages}
    for o in opens:
        if o.get("ts", 0) > censor:
            continue
        if o.get("work_item_id") not in staged_items:
            sil_den += 1
            sil_num += 1

    # --- bleed: assigned outside pi* as-of ts ----------------------
    bl_num = bl_den = 0
    if policy is not None:
        allow = policy.get("allow", {})
        deny = policy.get("deny", {})
        for s in stages:
            if s.get("ts", 0) > censor:
                continue
            cls = s.get("class")
            a = s.get("assigned_specialist_id")
            allowed = set(allow.get(cls, ()))
            if s.get("stage_kind") == "check":
                allowed -= set(s.get("authors", ()))
            allowed -= set(deny.get(cls, ()))
            bl_den += 1
            if a not in allowed:
                bl_num += 1

    return {
        "misbind": {"num": mis_num, "den": mis_den},
        "silent_fail": {"num": sil_num, "den": sil_den},
        "bleed": {"num": bl_num, "den": bl_den},
    }


def survival(events: list[dict], t0: float, t1: float, W: float) -> dict:
    """Right-censored time-to-stage. Durations to decide/accept for
    stages whose open ts <= t1 - W. Later stages are censored out of
    this sample; report them separately, do not average."""
    in_cut = [e for e in events if t0 <= e.get("ts", 0) <= t1]
    censor = t1 - W
    stage_open: dict[tuple, float] = {}
    for e in in_cut:
        if e.get("type") == "stage" and e.get("well_formed"):
            stage_open[_stage_key(e)] = e.get("ts", 0)
    durations: list[float] = []
    censored = 0
    seen: set[tuple] = set()
    for e in in_cut:
        if e.get("type") in ("decide", "accept") and _stage_key(e) in stage_open:
            k = _stage_key(e)
            if k in seen:
                continue
            seen.add(k)
            if stage_open[k] > censor:
                censored += 1
                continue
            durations.append(round(e.get("ts", 0) - stage_open[k], 3))
    return {"n": len(durations), "durations": sorted(durations), "censored": censored}
