"""Custody theory — executable companion to paper/custody/DRAFT.md §8.

Pure queries over the three kernels (fcd.core.Enforcer, rga.core.Admission,
rga.calibration.CalibrationAuthority). Every function here reads journal
state and writes nothing: no transition, no event, no field of any machine.
Research code beside the paper, in the paper's discipline — each function
names the theorem it computes — and not part of the gate.

    N1  deletion_surface        T4.1   the events whose removal raises standing;
        exposed / support        §5     the part deletable at no cost, and the signed support
    N2  standing_certificate    T11    the line-scoped anchor, and its verifier
    N3  POLARITY / polarity_of  D6,T3  the event alphabet signed for admissible
    N4  power_joint, horizon    T7     the Bonferroni reading beside power_min
    N5  kill_context            T8     uncovered size and unique kills per refuter
    N6  provenance, hereditary  T7.1   transitive standing along depends_on
    N8  exposure                T16    attempt index and published refutations
    N9  trust_base, derived_tier D7,kernel C1 tier A as trust-base inclusion
        frechet_bounds          T6,T7  the coupling interval every composite lies in
"""
from __future__ import annotations

import hashlib
import json
import dataclasses
from dataclasses import dataclass, field
from typing import Iterable, Optional

from fcd.core import norm
from rga.core import Admission, Seal
from rga.calibration import CalibrationAuthority, CalibrationPolicy, Run


# -- N3: polarity of the event alphabet for `admissible` (D6, T3) -------------

POLARITY: dict[str, str] = {
    # identity journal: neutral at the granularity of admissible, except accept,
    # which is enabling-positive (never lowers; required by the seal). The event
    # at which CalibrationAuthority.admissible actually flips is cal_stamp.
    "open": "0", "stage": "0", "bind": "0", "call": "0", "decide": "0",
    "accept": "e",
    # scrutiny journal
    "rga_declare": "0", "rga_measure": "0", "rga_bound": "0", "rga_open": "0",
    "rga_sample": "0", "rga_trial": "0",
    "rga_replay": "0",          # agreement is neutral; divergence is carried by rga_refuse
    "rga_refuse": "±",          # NEGATIVE for every seal that pinned the refuter after sealing
                                # (tainted); POSITIVE for every line impeached only by that
                                # checker's escapes, which _check_valid voids on refusal — F1's
                                # second path, with no taint when the checker was tier B there
    "rga_seal": "e",            # enabling: never lowers; the flip is at cal_stamp
    "rga_close": "0",
    # standing journal
    "cal_run": "0",             # filed is not established (C1); see cal_replay
    "cal_replay": "-",          # an establishing replay of a refuted run impeaches
    "cal_discredit": "+",       # strictly positive, by a second-order route: never lowers
                                # admissible of any line, raises it for every line the checker's
                                # escapes impeached (discredited enters only via _check_valid) — T3
    "cal_adjudicate": "-",      # decision=accept impeaches a tier-B run; reject is neutral
    "cal_exclude": "0", "cal_install": "0", "cal_close": "0",
    "cal_stamp": "+",           # mediated
}


def polarity_of(event_type: str) -> str:
    """'+' is the event at which admissible rises for some line (strictly
    positive), 'e' never lowers and is required by such an event (enabling),
    '-' lowers, '0' neither, '±' both (a second-order effect through validity
    degradation)."""
    return POLARITY.get(event_type, "?")


# -- helpers -------------------------------------------------------------------

def _establishing_replay_indices(cal: CalibrationAuthority, run: Run) -> list[int]:
    """Every non-diverged replay of `run`, in journal order. The kernel accepts
    a second successful replay of an established run; each is a witness that
    the demonstration stands, and the demonstration falls only when all of
    them are gone."""
    return [i for i, ev in enumerate(cal.events)
            if ev.get("type") == "cal_replay" and ev.get("run_index") == run.index
            and not ev.get("diverged")]


def _valid_at(cal: CalibrationAuthority, run: Run, j: int, rga_cut: Optional[int], *,
              ignore_refusal: bool = False, without: Optional[int] = None) -> bool:
    """`run` as `from_events` sees it when it recomputes the reader at cal
    index `j`: established by a non-diverged replay before `j` (the replay at
    index `without`, if given, deleted), its checker not discredited before
    `j`, tier B adjudicated `accept` before `j`, and — unless `ignore_refusal`
    — not refused at rga position `rga_cut` or earlier (`None`: the final
    registry, as `_guard_audit_checker` reads it, F2). Mirrors
    `rga/calibration.py:_check_valid(as_of)` at the reader's own point."""
    adm = cal.adm
    before = cal.events[:j]
    if not any(k < j and k != without for k in _establishing_replay_indices(cal, run)):
        return False
    if any(ev.get("type") == "cal_discredit"
           and (ev.get("checker_id"), ev.get("checker_version")) == run.checker for ev in before):
        return False
    if not ignore_refusal and run.checker in adm.refused:
        if rga_cut is None or adm.refused_at.get(run.checker, -1) <= rga_cut:
            return False
    if run.verdict == "refuted" and run.tier == "B":
        if not any(ev.get("type") == "cal_adjudicate" and ev.get("run_index") == run.index
                   and ev.get("decision") == "accept" for ev in before):
            return False
    return True


def _e_max_at(cal: CalibrationAuthority, cls: str, j: int,
              initial_policy: Optional[CalibrationPolicy] = None) -> int:
    """The budget in force when the reader at cal index `j` was written: the
    last `cal_install` before `j` carries the successor budgets replay adopts
    (`from_events`, `cal_install` branch). Before the first install the budget
    is replay's *input*, not a journal fact — `from_events` takes the initial
    policy as a parameter, and so does this query (`initial_policy`); without
    it the authority's current policy stands in, which is exact only while no
    install has replaced it."""
    for ev in reversed(cal.events[:j]):
        if ev.get("type") == "cal_install" and ev.get("budgets") and cls in ev["budgets"]:
            return int(ev["budgets"][cls]["e_max"])
    return (initial_policy or cal.policy).classes[cls].e_max


def _charges_without(cal: CalibrationAuthority, run: Run, refuter: tuple[str, str],
                     cls: str, j: int, rga_cut: Optional[int]) -> int:
    """The refuter's charge count as the reader at `j` recomputes it with
    `run` deleted: one charge per (line, claim) cell however many witnesses
    (C2), over the escapes valid at `j`."""
    adm = cal.adm
    cells = set()
    for r in cal.runs:
        if r is run or r.verdict != "refuted" or r.cls != cls or not _valid_at(cal, r, j, rga_cut):
            continue
        seal = adm.sealed.get(r.line_id)
        if seal is not None and refuter in cal._pinned_on_claim(seal, r.claim_id):
            cells.add((r.line_id, r.claim_id))
    return len(cells)


def _adjudication_index(cal: CalibrationAuthority, run: Run) -> Optional[int]:
    for i, ev in enumerate(cal.events):
        if ev.get("type") == "cal_adjudicate" and ev.get("run_index") == run.index:
            return i
    return None


def _seals_pinning(adm: Admission, key: tuple[str, str]) -> list[Seal]:
    return [s for s in adm.sealed.values()
            if any((r.id, r.version) == key for c in s.claims for r in c.refuters)]


# -- N1: the deletion surface (T4.1) -------------------------------------------

@dataclass(frozen=True)
class SurfaceEvent:
    journal: str            # "rga" | "cal"
    index: int              # position in that journal
    type: str
    line_id: str            # the line whose standing the event lowers
    reason: str             # "escape" | "taint"
    anchored_by: tuple = () # later (journal, index) events whose recomputation refuses its deletion
    redundant_with: tuple = ()  # sibling establishing replays of the same run (cal indices)
    refusal_at: Optional[int] = None  # taint events: the rga index of the refusal this group belongs to

    @property
    def exposed(self) -> bool:
        """Deletable alone by a coherent alternative, and load-bearing: no
        later event recomputes it and no sibling replay stands in for it. A
        redundant replay is deletable alone at no change to any standing."""
        return not self.anchored_by and not self.redundant_with


def deletion_surface(cal: CalibrationAuthority, line_id: Optional[str] = None, *,
                     initial_policy: Optional[CalibrationPolicy] = None) -> tuple[SurfaceEvent, ...]:
    """Every journal event whose removal would raise the standing of some
    sealed line (of `line_id`, if given): the witnesses of the negated
    demonstrations of `admissible` — established escapes with their
    establishing replay (and accepting adjudication for tier B), and refusals
    that taint a seal, with the diverged replay that produced them.
    Computable by the same re-derivation replay performs; T4.1."""
    out: list[SurfaceEvent] = []
    for run in cal.runs:
        if run.verdict != "refuted" or not cal._check_valid(run):
            continue
        if line_id is not None and run.line_id != line_id:
            continue
        out.append(SurfaceEvent("cal", run.position, "cal_run", run.line_id, "escape"))
        for rep in _establishing_replay_indices(cal, run):
            out.append(SurfaceEvent("cal", rep, "cal_replay", run.line_id, "escape"))
        if run.tier == "B":
            adj = _adjudication_index(cal, run)
            if adj is not None:
                out.append(SurfaceEvent("cal", adj, "cal_adjudicate", run.line_id, "escape"))
    adm = cal.adm
    for key, at in adm.refused_at.items():
        for seal in _seals_pinning(adm, key):
            if at < seal.sealed_at:
                continue                       # refused before sealing: the seal never relied on it
            if line_id is not None and seal.line_id != line_id:
                continue
            out.append(SurfaceEvent("rga", at, "rga_refuse", seal.line_id, "taint", refusal_at=at))
            if at >= 1 and adm.events[at - 1].get("type") == "rga_replay" and adm.events[at - 1].get("diverged"):
                out.append(SurfaceEvent("rga", at - 1, "rga_replay", seal.line_id, "taint", refusal_at=at))
            # _refuse cascades a V4 close onto every open line pinning the refuter,
            # immediately after rga_refuse; the group is not deletable without them
            j = at + 1
            while j < len(adm.events) and adm.events[j].get("type") == "rga_close" and adm.events[j].get("fault") == "V4":
                out.append(SurfaceEvent("rga", j, "rga_close", seal.line_id, "taint", refusal_at=at))
                j += 1
    anchored = [dataclasses.replace(s, anchored_by=_anchors_of(cal, s, initial_policy),
                                    redundant_with=_redundant_with(cal, s))
                for s in set(out)]
    return tuple(sorted(anchored, key=lambda s: (s.journal, s.index, s.line_id)))


def _run_of(cal: CalibrationAuthority, s: SurfaceEvent) -> Optional[Run]:
    """The run a surface event belongs to: a `cal_run` by its position, a
    replay or adjudication by the run its own event names."""
    if s.type == "cal_run":
        return next((r for r in cal.runs if r.position == s.index), None)
    run_index = cal.events[s.index].get("run_index")
    if isinstance(run_index, int) and 0 <= run_index < len(cal.runs):
        return cal.runs[run_index]
    return None


def _redundant_with(cal: CalibrationAuthority, s: SurfaceEvent) -> tuple:
    if s.reason != "escape" or s.type != "cal_replay":
        return ()
    run = _run_of(cal, s)
    if run is None:
        return ()
    return tuple(k for k in _establishing_replay_indices(cal, run) if k != s.index)


def _anchors_of(cal: CalibrationAuthority, s: SurfaceEvent,
                initial_policy: Optional[CalibrationPolicy] = None) -> tuple:
    """The later events whose replay guard or recomputation reads what `s`
    contributed, so that deleting `s` alone is refused on rebuild. Enumerated
    from the readers in rga/calibration.py:from_events, each evaluated as
    replay evaluates it — with the witness valid AT THE READER (established
    before it, its checker's refusal within the reader's own cut, tier B
    adjudicated before it), and, for a replay, only while no sibling replay
    before the reader establishes the run without it. Under the move set in
    which recorded positions and indices may be renumbered consistently
    (T12(c)) position fields anchor nothing, and only content does:

    for an escape —
      * a later `cal_stamp` of the same class whose cut (`sealed_at`) the
        witness's validity precedes (its `track_records` and
        `corpus_provenance` are recomputed from the escapes valid as of it);
      * a later `cal_close(E5)` of the same class naming a refuter this
        escape charges, when the demotion it records (`demoted(..., as_of)`)
        would no longer hold without this escape's charge cell (C2: one
        charge per cell however many witnesses) under the budget in force
        at the close (`_e_max_at`);
      * a later *audit* (`cal_run` with verdict `survived`) filed by this
        escape's checker on a claim where the checker is not pinned, when
        this is the checker's only valid escape of the class at that point
        (`_guard_audit_checker` needs one; a later escape reads nothing);
      * a later `cal_exclude` naming this run (`_guard_exclusion` needs it
        valid as of the exclusion's cut);
    for a refusal group —
      * a later `cal_stamp` of a class in which the refused checker had a run
        valid at the stamp but for the refusal, and whose cut the refusal
        precedes (`refused_at <= sealed_at`): the refusal voids that run, so
        the stamp's corpus and charges differ. A refusal after the stamp's
        cut is invisible to it (`_check_valid(as_of)`), and the group is
        exposed.

    An anchored witness is still deletable together with its anchors, at the
    cost of the anchors' own lines (T10(b)); `deletion_closure` lists them."""
    adm = cal.adm
    anchors = []
    if s.reason == "escape":
        run = _run_of(cal, s)
        if run is None:
            return ()
        cls = adm.sealed[s.line_id].cls
        charged = cal._pinned_on_claim(adm.sealed[run.line_id], run.claim_id)
        siblings = [k for k in _establishing_replay_indices(cal, run) if k != s.index]
        for j in range(s.index + 1, len(cal.events)):
            if s.type == "cal_replay" and any(k < j for k in siblings):
                break                          # a sibling establishes the run without this replay
            ev = cal.events[j]; t = ev.get("type")
            if t == "cal_stamp":
                seal = adm.sealed.get(ev.get("line_id"))
                if seal is not None and seal.cls == cls and _valid_at(cal, run, j, seal.sealed_at):
                    anchors.append(("cal", j))
            elif t == "cal_close" and ev.get("fault") == "E5":
                line = adm.lines.get(ev.get("line_id"))
                refuter = (ev.get("refuter_id"), ev.get("refuter_version"))
                if (line is not None and line.cls == cls and refuter in charged
                        and _valid_at(cal, run, j, ev.get("as_of"))
                        and _charges_without(cal, run, refuter, cls, j, ev.get("as_of"))
                        <= _e_max_at(cal, cls, j, initial_policy)):
                    anchors.append(("cal", j))
            elif (t == "cal_run" and ev.get("verdict") == "survived"
                  and (ev.get("checker_id"), ev.get("checker_version")) == run.checker):
                # only an AUDIT reads an earlier escape (_guard_audit_checker fires
                # under expect == "survived", over escapes(cls) of the audit's own
                # class); a later escape by the checker reads nothing
                seal = adm.sealed.get(ev.get("line_id"))
                if (seal is not None and seal.cls == cls
                        and run.checker not in cal._pinned_on_claim(seal, ev.get("claim_id"))
                        and _valid_at(cal, run, j, None)
                        and not any(r is not run and r.checker == run.checker and r.verdict == "refuted"
                                    and r.cls == cls and _valid_at(cal, r, j, None) for r in cal.runs)):
                    anchors.append(("cal", j))
            elif t == "cal_exclude" and run.index in ev.get("run_indices", ()):
                if _valid_at(cal, run, j, ev.get("as_of")):
                    anchors.append(("cal", j))
    else:
        key = next((k for k, at in adm.refused_at.items() if at == s.refusal_at), None)
        refused_at = adm.refused_at.get(key, None)
        for j, ev in enumerate(cal.events):
            if ev.get("type") != "cal_stamp":
                continue
            seal = adm.sealed.get(ev.get("line_id"))
            if seal is None or refused_at is None or refused_at > seal.sealed_at:
                continue                       # the stamp's cut does not see the refusal
            voided = any(r.checker == key and r.verdict == "refuted" and r.cls == seal.cls
                         and _valid_at(cal, r, j, seal.sealed_at, ignore_refusal=True)
                         for r in cal.runs)
            if voided:
                anchors.append(("cal", j))
    return tuple(sorted(set(anchors)))


def deletion_closure(cal: CalibrationAuthority, s: SurfaceEvent) -> tuple:
    """What a coherent alternative must remove besides `s` to delete it: its
    anchors, each of which is itself exposed in the kernel as it is (a stamp's
    deletion lowers its own line to IR; an E5 close, an audit or an exclusion
    is recomputed against by nothing later). The cost of the deletion is the
    standing those anchors carried."""
    return tuple(a for a in s.anchored_by)


def exposed(cal: CalibrationAuthority, line_id: Optional[str] = None, *,
            initial_policy: Optional[CalibrationPolicy] = None) -> tuple[SurfaceEvent, ...]:
    """The part of the surface deletable at no cost to any other line: witnesses
    no later event recomputes against. Anchored witnesses are deletable too,
    together with their anchors (T10b); the anchor of T11 must therefore count
    every valid witness, not only these. `initial_policy` is the calibration
    policy in force before the first install, replay's own input (`_e_max_at`)."""
    return tuple(s for s in deletion_surface(cal, line_id, initial_policy=initial_policy) if s.exposed)


@dataclass(frozen=True)
class Support:
    """The signed support of admissible(line_id): the recorded atoms its value
    depends on. Positive atoms are the necessity events (their roots are what
    T11 hashes); negative atoms are the surface (their presence is what T11
    counts). Every event outside the support can be removed from the record
    without changing the value (determination), which tests/test_custody.py
    checks by deleting a later unrelated line."""
    line_id: str
    positive: tuple          # ((journal, index, type), ...)
    negative: tuple          # (SurfaceEvent, ...)


def _degraders(cal: CalibrationAuthority, line_id: str) -> list[tuple[str, int, str]]:
    """The events that void a refuted run against line_id — the diverged
    replay and discredit of its checker, the refusal group of its checker —
    which are POSITIVE atoms of admissible(line_id): deleting one revives the
    witness and lowers standing (T17(i)). A rejecting adjudication is not one:
    deleting it leaves a tier-B run unadjudicated and still invalid."""
    adm = cal.adm
    out: list[tuple[str, int, str]] = []
    for run in cal.runs:
        if run.line_id != line_id or run.verdict != "refuted":
            continue
        for j, ev in enumerate(cal.events):
            t = ev.get("type")
            if t == "cal_discredit" and (ev.get("checker_id"), ev.get("checker_version")) == run.checker:
                out.append(("cal", j, t))
                if j >= 1 and cal.events[j - 1].get("type") == "cal_replay" and cal.events[j - 1].get("diverged"):
                    out.append(("cal", j - 1, "cal_replay"))
        at = adm.refused_at.get(run.checker)
        if at is not None:
            out.append(("rga", at, "rga_refuse"))
            if at >= 1 and adm.events[at - 1].get("type") == "rga_replay":
                out.append(("rga", at - 1, "rga_replay"))
    return sorted(set(out))


def support(cal: CalibrationAuthority, line_id: str) -> Support:
    pos = [(j, i, r["type"]) for j, i, r in _necessity_events(cal, line_id)] + _degraders(cal, line_id)
    return Support(line_id, tuple(sorted(set(pos))), deletion_surface(cal, line_id))


# -- N2: the line-scoped standing certificate (T11) ---------------------------

# Root fields per event type: what a transition consumed from outside. Derived
# fields (on_bind, pi_star, seed, power, composite, track_records, ...) are
# functions of these and of prior state, and re-derive under replay (D1).
ROOT_FIELDS: dict[str, tuple[str, ...]] = {
    "open": ("work_item_id", "class", "body_hash", "policy_version", "depends_on"),
    "stage": ("work_item_id", "stage_id", "assigned_specialist_id"),
    "bind": ("work_item_id", "stage_id"),
    "call": ("work_item_id", "stage_id", "executed_model"),
    "decide": ("work_item_id", "stage_id", "result", "fault", "next"),
    "accept": ("work_item_id",),
    "rga_declare": ("refuter_id", "refuter_version", "author", "mode"),
    "rga_measure": ("refuter_id", "refuter_version", "defect_model_hash", "defect_model_author", "ledger"),
    "rga_bound": ("refuter_id", "refuter_version", "epsilon", "n"),
    "rga_open": ("work_item_id", "generator", "sampling_hash", "fcd_position"),
    "rga_sample": ("work_item_id", "sample_index", "artifact_hash", "nonce", "package_categories",
                   "sampling_hash", "fcd_position"),
    "rga_trial": ("work_item_id", "refuter_id", "refuter_version", "claim_id", "sample_index",
                  "inputs_hash", "verdict", "witness_hash"),
    "rga_replay": ("work_item_id", "trial_index", "verdict", "witness_hash"),
    "rga_seal": ("work_item_id",),
    "cal_stamp": ("line_id", "sealed_at"),
}


def _roots(ev) -> dict:
    fields = ROOT_FIELDS.get(ev.get("type"), ())
    return {"type": ev.get("type"), **{f: ev.get(f) for f in fields}}


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=list)


def _necessity_events(cal: CalibrationAuthority, line_id: str) -> list[tuple[str, int, dict]]:
    """The events whose roots the necessity conjuncts of admissible(line_id)
    mention: the item's identity history, the line's scrutiny history, the
    registry records of every refuter its seal pinned, and the stamp."""
    adm = cal.adm
    seal = adm.sealed.get(line_id)
    pinned = {(r.id, r.version) for c in seal.claims for r in c.refuters} if seal else set()
    out: list[tuple[str, int, dict]] = []
    for i, ev in enumerate(adm.fcd.events):
        if ev.get("work_item_id") == line_id and ev.get("type") in ROOT_FIELDS:
            out.append(("fcd", i, _roots(ev)))
    for i, ev in enumerate(adm.events):
        t = ev.get("type")
        if t in ("rga_declare", "rga_measure", "rga_bound"):
            if (ev.get("refuter_id"), ev.get("refuter_version")) in pinned:
                out.append(("rga", i, _roots(ev)))
        elif ev.get("work_item_id") == line_id and t in ROOT_FIELDS:
            out.append(("rga", i, _roots(ev)))
    for i, ev in enumerate(cal.events):
        if ev.get("type") == "cal_stamp" and ev.get("line_id") == line_id:
            out.append(("cal", i, _roots(ev)))
    return out


@dataclass(frozen=True)
class StandingCertificate:
    line_id: str
    roots_hash: str         # H(roots of the necessity events, with journal and position)
    demonstrations: int     # |Δ_line(t)|: surface events against this line
    lengths: tuple[int, int, int]   # (|fcd|, |rga|, |cal|) at t
    standing: bool          # admissible(line_id) at t — what the certificate certifies


def standing_certificate(cal: CalibrationAuthority, line_id: str) -> StandingCertificate:
    """T11: (H(roots), |Δ|, |r|) pins admissible(line_id) against every
    coherent alternative. Unsigned here; signing is the authority's (B14)."""
    roots = _necessity_events(cal, line_id)
    digest = hashlib.sha256(_canon(roots).encode()).hexdigest()
    adm = cal.adm
    return StandingCertificate(
        line_id=line_id,
        roots_hash=digest,
        demonstrations=len(deletion_surface(cal, line_id)),
        lengths=(len(adm.fcd.events), len(adm.events), len(cal.events)),
        standing=cal.admissible(line_id),
    )


def verify_certificate(cal: CalibrationAuthority, cert: StandingCertificate) -> list[str]:
    """Recompute against a presented custody; the list of mismatched
    components (empty iff the presented record agrees with the certificate on
    everything admissible(line_id) depends on, and on the value it claims —
    a certificate whose `standing` field alone was altered is refused)."""
    now = standing_certificate(cal, cert.line_id)
    bad = []
    if now.roots_hash != cert.roots_hash:
        bad.append("roots")
    if now.demonstrations != cert.demonstrations:
        bad.append("demonstrations")
    if now.lengths != cert.lengths:
        bad.append("lengths")
    if now.standing != cert.standing:
        bad.append("standing")
    return bad


# -- N4: the joint reading beside power_min (T7) --------------------------------

def power_joint(composites: Iterable[float]) -> float:
    """max(0, 1 − Σ(1 − p_j)): the greatest aggregator sound for the joint
    reading 'every conjunct caught' under every coupling (T7). Zero is the
    fail-closed value past the Bonferroni horizon."""
    # rounded so that exactly-at-horizon sums (ten 0.9s) read 0, not 2e-16
    return max(0.0, round(1.0 - sum(1.0 - p for p in composites), 12))


def bonferroni_horizon(p: float) -> Optional[int]:
    """The number of conjuncts at power p past which the assumption-free joint
    reading is zero: ceil(1/(1-p)); None at p = 1."""
    if p >= 1.0:
        return None
    import math
    # smallest n with n(1 - p) >= 1; rounded first so 1/(1-0.9) is 10, not 11
    return math.ceil(round(1.0 / (1.0 - p), 9))


def seal_joint(seal: Seal) -> float:
    return power_joint(c.composite for c in seal.claims)


def frechet_bounds(powers: Iterable[float], event: str) -> tuple[float, float]:
    """The interval every coupling's value of the composite lies in.
    event='union' (some refuter catches): [max, min(1, Σ)] — T6(b).
    event='intersection' (every conjunct caught): [max(0, 1−Σ(1−p)), min] — T7."""
    ps = list(powers)
    if not ps:
        return (0.0, 0.0)
    if event == "union":
        return (max(ps), min(1.0, sum(ps)))
    if event == "intersection":
        return (power_joint(ps), min(ps))
    raise ValueError(f"unknown event {event!r}")


# -- N5: the kill context (D15, T8) ----------------------------------------------

@dataclass(frozen=True)
class KillContext:
    claim_id: str
    defect_model_hash: str
    size: int
    union: int
    uncovered: int
    unique_kills: dict[tuple[str, str], int] = field(default_factory=dict)
    redundant: tuple[tuple[str, str], ...] = ()


def kill_context(adm: Admission, line_id: str, claim_id: str) -> KillContext:
    """The incidence the seal stores and does not report: the union's size,
    the uncovered set, each ledger refuter's unique kills,
    and the refuters redundant on D (empty unique-kill set) — T8."""
    line = adm.lines[line_id]
    claim = adm._claim(line, claim_id)
    records = {}
    for key in claim.refuters:
        r = adm.refuters[key]
        if r.mode != "ledger":
            continue
        rec = adm.power.get((r.id, r.version, claim.defect_model_hash))
        if rec is not None:
            records[key] = rec
    ids = adm.defect_ids.get(claim.defect_model_hash, frozenset())
    union: frozenset[str] = frozenset()
    for rec in records.values():
        union |= rec.killed_ids
    unique = {}
    for key, rec in records.items():
        others: frozenset[str] = frozenset()
        for k2, r2 in records.items():
            if k2 != key:
                others |= r2.killed_ids
        unique[key] = len(rec.killed_ids - others)
    return KillContext(
        claim_id=claim_id, defect_model_hash=claim.defect_model_hash,
        size=len(ids), union=len(union), uncovered=len(ids - union),
        unique_kills=unique,
        redundant=tuple(sorted(k for k, n in unique.items() if n == 0)),
    )


# -- N6: hereditary standing (T7.1, T13) ---------------------------------------

@dataclass(frozen=True)
class Standing:
    sealed: bool
    mediated: bool
    tainted: bool
    impeached: bool
    admissible: bool
    power_min: Optional[float]


def standing_of(cal: CalibrationAuthority, line_id: str) -> Standing:
    adm = cal.adm
    seal = adm.sealed.get(line_id)
    return Standing(
        sealed=seal is not None, mediated=cal.mediated(line_id),
        tainted=adm.tainted(line_id), impeached=cal.impeached(line_id),
        admissible=cal.admissible(line_id),
        power_min=seal.power_min if seal else None,
    )


def ancestors(adm: Admission, line_id: str) -> tuple[str, ...]:
    """Transitive closure of depends_on, in a stable order, excluding line_id."""
    seen: list[str] = []
    stack = list(adm.fcd.items[line_id].depends_on) if line_id in adm.fcd.items else []
    while stack:
        a = stack.pop(0)
        if a in seen:
            continue
        seen.append(a)
        item = adm.fcd.items.get(a)
        if item is not None:
            stack.extend(item.depends_on)
    return tuple(seen)


def provenance(cal: CalibrationAuthority, line_id: str) -> dict[str, Standing]:
    """Every ancestor's standing — the fold suspect() leaves to the consumer,
    answered by the authority as a pure query (N6)."""
    return {a: standing_of(cal, a) for a in ancestors(cal.adm, line_id)}


def hereditary_admissible(cal: CalibrationAuthority, line_id: str) -> bool:
    return cal.admissible(line_id) and all(s.admissible for s in provenance(cal, line_id).values())


def power_joint_closure(cal: CalibrationAuthority, line_id: str) -> float:
    """The Bonferroni reading over every claim of line_id and of every
    ancestor: what a per-edge floor cannot see (T7.1)."""
    adm = cal.adm
    composites: list[float] = []
    for lid in (line_id,) + ancestors(adm, line_id):
        seal = adm.sealed.get(lid)
        if seal is None:
            return 0.0                       # an unsealed ancestor: nothing is certified jointly
        composites.extend(c.composite for c in seal.claims)
    return power_joint(composites)


# -- N8: exposure (D25, T16) -----------------------------------------------------

@dataclass(frozen=True)
class Exposure:
    line_id: str
    attempt_index: int
    prior_lines: tuple[str, ...]
    published_refutations: tuple[tuple[str, str, str, int, str], ...]   # (refuter, version, claim, sample, line)


def _bind_key(line) -> tuple:
    return (line.cls, line.body, line.fcd_policy_version, line.generator, norm(line.m_decl), line.sampling_hash)


def exposure(adm: Admission, line_id: str) -> Exposure:
    """The journaled part of what the generator may have seen: every earlier
    line on the same bind key, and every published refutation on those lines
    (read from their trials, not from the close's reason string)."""
    line = adm.lines[line_id]
    key = _bind_key(line)
    prior = [l for l in adm.lines.values()
             if l.id != line_id and _bind_key(l) == key and l.opened_at < line.opened_at]
    prior.sort(key=lambda l: l.opened_at)
    refs = []
    for l in prior:
        for t in l.trials:
            if t.verdict == "refuted":
                refs.append((t.refuter_id, t.refuter_version, t.claim_id, t.sample_index, l.id))
    return Exposure(line_id, 1 + len(prior), tuple(l.id for l in prior), tuple(refs))


# -- N9: trust bases and derived tiers (D7, C1) ----------------------------------

SEAL_BASE_ALWAYS = frozenset({"B0", "B1", "B2", "B7", "B9", "B10", "B11", "B12"})
RUN_BASE_TIER_A = frozenset({"B1", "B2", "B7", "B10"})
ADJUDICATION = "E2:claim-fidelity-adjudicated"


def trust_base(adm: Admission, seal: Seal) -> frozenset[str]:
    """The assumptions a seal's standing consumes, read from the seal: the
    common base, B5 if any ledger refuter measured against D, and the declared
    (ε, N) independence if any bounded refuter contributed."""
    base = set(SEAL_BASE_ALWAYS)
    for c in seal.claims:
        for r in c.refuters:
            if r.mode == "ledger":
                base.add("B5")
            elif r.mode == "bounded":
                base.add("declared-(epsilon,N)-independence")
    return frozenset(base)


def run_base(cal: CalibrationAuthority, run: Run) -> frozenset[str]:
    """A tier-A escape re-runs the pinned instrument: B1, B2, B7, B10 and
    nothing the seal did not carry. Any other checker adds the claim-fidelity
    judgment E2 makes visible."""
    seal = cal.adm.sealed[run.line_id]
    pinned = cal._pinned_on_claim(seal, run.claim_id)
    if run.checker in pinned:
        return RUN_BASE_TIER_A
    return RUN_BASE_TIER_A | {ADJUDICATION}


def derived_tier(cal: CalibrationAuthority, run: Run) -> str:
    """Tier A iff base(run) ⊆ base(seal): the kernel's pinned-membership rule
    restated in trust-base vocabulary (N9). `run_base` applies that same rule,
    so this cannot disagree with the kernel; the restatement is the point,
    not an independent derivation."""
    seal = cal.adm.sealed[run.line_id]
    return "A" if run_base(cal, run) <= trust_base(cal.adm, seal) else "B"
