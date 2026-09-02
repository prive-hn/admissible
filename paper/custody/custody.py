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
    "cal_discredit": "+",       # strictly positive, second-order: never lowers; raises a line impeached only by its escapes
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
    group_with: tuple = ()  # (journal, index) events structurally tied to this one: they must go with it
    rewrites: tuple = ()    # (journal, index) events a deletion must rewrite, not delete: shared exclusions
    coherent: bool = True   # the group-deletion re-derives: `from_events` accepts it (soundness net, T4.1)

    @property
    def exposed(self) -> bool:
        """Deletable by a coherent alternative at no cost to any other line,
        and load-bearing: no later event recomputes it and no sibling replay
        stands in for it. Deletable *with its group* (`group_with`): a run's
        replays, adjudication and an exclusion naming it alone name the run
        and go with its `cal_run` (an exclusion naming other runs too is
        rewritten to keep them, `rewrites`); a tier-B run's sole establishing
        replay, and the accepting adjudication, take the exclusions that named
        their now-unestablished run; a taint event takes the rest of its
        refusal group. `coherent` is the soundness net: the companion deletes
        the group and its rewrites and re-derives, so a reader no analytic
        anchor named (an install reading a position-derived id, an exclusion
        left naming an invalid run) still keeps the event off the exposed set.
        `deletion_closure` lists anchors and group together."""
        return not self.anchored_by and not self.redundant_with and self.coherent


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
    filled = []
    for s in set(out):
        s = dataclasses.replace(s, anchored_by=_anchors_of(cal, s, initial_policy),
                                redundant_with=_redundant_with(cal, s), group_with=_group_of(cal, s, out),
                                rewrites=_rewrites_of(cal, s))
        if s.reason == "escape":
            # an install can anchor a deletion alongside a stamp, E5 or audit —
            # its base deletes those analytic anchors too, so the probe finds
            # what the renumbering still breaks (R4-17); union, do not gate
            extra = _install_anchors_for_escape(cal, s, initial_policy)
            if extra:
                s = dataclasses.replace(s, anchored_by=tuple(sorted(set(s.anchored_by) | set(extra))))
        filled.append(dataclasses.replace(s, coherent=_coherent(cal, s, initial_policy)))
    return tuple(sorted(filled, key=lambda s: (s.journal, s.index, s.line_id)))


def _invalidates(cal: CalibrationAuthority, s: SurfaceEvent) -> bool:
    """Deleting `s` alone makes its run no longer a valid escape (so an
    exclusion that named the run would name a non-valid escape on rebuild):
    the sole establishing replay of the run, or its accepting adjudication."""
    if s.reason != "escape":
        return False
    run = _run_of(cal, s)
    if run is None:
        return False
    if s.type == "cal_adjudicate":
        return True
    if s.type == "cal_replay":
        return len(_establishing_replay_indices(cal, run)) == 1
    return False


def _alt_delete(cal: CalibrationAuthority, delete: set, invalidated=()) -> list:
    """The journal a coherent alternative leaves, consistently renumbered as
    the move set of §5 allows (T12c): the cal events at indices `delete`
    removed, every later `run_index` renumbered as replay range-checks them,
    every `cal_exclude` that named a deleted or `invalidated` run dropping it
    (emptied ones removed), and every `cal_stamp`'s `track_records[*].as_of`
    reset to the stamp's new position — that field records `_position()` at
    the stamp and `from_events` recomputes it, so a stamp shifted by a
    deletion before it must carry its new index or the recompute refuses an
    otherwise valid alternative. `invalidated` covers a run whose `cal_run`
    stays but whose sole witness is gone."""
    deleted_runs = {cal.events[i].get("run_index") for i in delete
                    if cal.events[i].get("type") == "cal_run"}
    drop = {r for r in (set(deleted_runs) | set(invalidated)) if r is not None}

    def newri(ri: int) -> int:
        return ri - sum(1 for d in deleted_runs if d is not None and d < ri)

    out = []
    for j, ev in enumerate(cal.events):
        if j in delete:
            continue
        ev = dict(ev)
        if isinstance(ev.get("run_index"), int):
            ev["run_index"] = newri(ev["run_index"])
        if ev.get("type") == "cal_exclude":
            kept = [newri(i) for i in ev.get("run_indices", ()) if i not in drop]
            if not kept:
                continue
            ev["run_indices"] = kept
        if ev.get("type") == "cal_stamp" and ev.get("track_records"):
            # as_of is the stamp's own `_position()`; on rebuild it is
            # recomputed at the shifted index, so carry the new position
            records = {k: dict(v) for k, v in dict(ev["track_records"]).items()}
            for rec in records.values():
                if "as_of" in rec:
                    rec["as_of"] = len(out)
            ev["track_records"] = records
        out.append(ev)
    return out


def _rebuilds(cal: CalibrationAuthority, alt: list,
              initial_policy: Optional[CalibrationPolicy]) -> bool:
    """Whether `from_events` accepts the alternative cal journal, read against
    the same admission and the calibration policy in force before the first
    install (`initial_policy`, replay's own input; the current policy stands
    in only while no install has replaced it, `_e_max_at`)."""
    try:
        CalibrationAuthority.from_events(list(alt), cal.adm, initial_policy or cal.policy)
        return True
    except Exception:
        return False


def _group_deletion(cal: CalibrationAuthority, s: SurfaceEvent) -> tuple:
    """The (delete, invalidated) a coherent deletion of `s` with its group
    applies to the cal journal."""
    delete = {s.index} | {i for jr, i in s.group_with if jr == "cal"}
    invalidated = {_run_of(cal, s).index} if _invalidates(cal, s) else set()
    return delete, invalidated


def _coherent(cal: CalibrationAuthority, s: SurfaceEvent,
              initial_policy: Optional[CalibrationPolicy]) -> bool:
    """Does deleting `s` with its group (and its rewrites) re-derive? Only the
    escape branch is checked by rebuild here — its deletions are cal-only, so
    the admission is reused unchanged; a taint group's deletion reaches the
    admission journal and its install anchor is enumerated instead (F5, R4-9).
    Checked for every escape, anchored or not: the field states plainly
    whether the group alone re-derives (an anchor makes the event non-exposed
    regardless), so a reader the analytic list missed keeps it off the set."""
    if s.reason != "escape" or _run_of(cal, s) is None:
        return True
    delete, invalidated = _group_deletion(cal, s)
    return _rebuilds(cal, _alt_delete(cal, delete, invalidated), initial_policy)


def _install_anchors_for_escape(cal: CalibrationAuthority, s: SurfaceEvent,
                                initial_policy: Optional[CalibrationPolicy]) -> list:
    """The later `cal_install`s whose deletion, added to `s`'s group deletion,
    is what lets the alternative re-derive: an install reads a run through the
    position-derived corpus id (`derived_defect_id`), so deleting an earlier
    `cal_run` renumbers a later covered run and its ledger no longer covers
    the new id (`_guard_install_covers`); the install anchors the deletion.
    The needed installs are jointly necessary, not singly sufficient: two
    installs may each cover only the original id, so retaining either still
    refuses — the whole set is found (remove all, then add back each that the
    rebuild does not need), so `deletion_closure` names every one. The base
    deletes the analytic anchors too (a stamp, E5 or audit with its own
    structural group), so an install the renumbering breaks is found even when
    the escape is already anchored (R4-17). Found by re-derivation so no
    reader is assumed (T4.1 conjectural (iv))."""
    if _run_of(cal, s) is None:
        return []
    delete, invalidated = _group_deletion(cal, s)
    delete = set(delete)
    for jr, j in s.anchored_by:                # delete the analytic anchors and their structure too
        if jr != "cal":
            continue
        delete.add(j)
        if cal.events[j].get("type") in ("cal_run", "cal_replay", "cal_adjudicate"):
            run = _run_at_index(cal, j)
            if run is not None:
                delete |= {k for k in _run_structural(cal, run)}
    if _rebuilds(cal, _alt_delete(cal, delete, invalidated), initial_policy):
        return []

    # probe installs by journal index, not policy version: the same version can
    # be installed twice (unchanged content), and deleting the target may break
    # only one of them, so removing a version would over-state the deletion
    installs = [j for j, ev in enumerate(cal.events) if ev.get("type") == "cal_install"]

    def rebuilds_without(remove: set) -> bool:
        # a removed install's downstream E5 close reads the budget it set, so it
        # must go with the install while probing (else the E5 replays under the
        # pre-install budget and refuses); `deletion_closure` adds it back per
        # anchored install and minimises which E5 the deletion truly needs
        extra = {k for j in remove for k in _install_e5_candidates(cal, j)}
        return _rebuilds(cal, _alt_delete(cal, delete | remove | extra, invalidated), initial_policy)

    if not rebuilds_without(set(installs)):
        return []       # not curable by installs alone; `coherent` still keeps the event off exposed

    needed = set(installs)
    for j in installs:                # add each back; keep removed only if the rebuild needs it gone
        if j in needed and rebuilds_without(needed - {j}):
            needed.discard(j)
    return [("cal", j) for j in sorted(needed)]


def _run_of(cal: CalibrationAuthority, s: SurfaceEvent) -> Optional[Run]:
    """The run a surface event belongs to: a `cal_run` by its position, a
    replay or adjudication by the run its own event names."""
    if s.type == "cal_run":
        return next((r for r in cal.runs if r.position == s.index), None)
    if s.journal != "cal" or s.index >= len(cal.events):
        return None                            # a taint event's index is an rga position
    run_index = cal.events[s.index].get("run_index")
    if isinstance(run_index, int) and 0 <= run_index < len(cal.runs):
        return cal.runs[run_index]
    return None


def _group_of(cal: CalibrationAuthority, s: SurfaceEvent, surface: list) -> tuple:
    """The events structurally tied to `s`, which a coherent alternative that
    deletes `s` must delete too because replay range-checks their `run_index`
    without it: for a `cal_run`, every replay, discredit and adjudication
    naming its run; for the sole establishing replay of a tier-B run (or its
    accepting adjudication), the adjudication (adjudication requires an
    established escape); for a taint event, the other events of its refusal
    group. An exclusion that names the run is a *rewrite*, not a tie — the run
    is dropped from its `run_indices` (`_rewrites_of`, `_alt_delete`), which
    empties and so removes one that named the run alone — so it is not here.
    Events that name a run cost no line its standing."""
    if s.reason == "taint":
        return tuple(sorted((e.journal, e.index) for e in surface
                            if e.reason == "taint" and e.refusal_at == s.refusal_at
                            and (e.journal, e.index) != (s.journal, s.index)))
    run = _run_of(cal, s)
    if run is None:
        return ()
    group = []
    if s.type == "cal_run":
        for j, ev in enumerate(cal.events):
            if (ev.get("type") in ("cal_replay", "cal_discredit", "cal_adjudicate")
                    and ev.get("run_index") == run.index):
                group.append(("cal", j))
    elif s.type == "cal_replay" and run.tier == "B" and len(_establishing_replay_indices(cal, run)) == 1:
        adj = _adjudication_index(cal, run)
        if adj is not None:
            group.append(("cal", adj))
    return tuple(sorted(set(group)))


def _rewrites_of(cal: CalibrationAuthority, s: SurfaceEvent) -> tuple:
    """The `cal_exclude` events a coherent alternative that deletes `s` must
    rewrite rather than delete: deleting a `cal_run`, or invalidating a run by
    deleting its sole witness (`_invalidates`), drops the run from every
    exclusion that named it (renumbered, T12c) — one that named it alongside
    other runs keeps them (deleted whole it would release them into the
    obligation of a later install, D16), one that named it alone empties and
    is removed. `_alt_delete` applies this from the deleted or invalidated
    run, so the closure need not list the exclusion as a deletion."""
    if s.type != "cal_run" and not _invalidates(cal, s):
        return ()
    run = _run_of(cal, s)
    if run is None:
        return ()
    return tuple(("cal", j) for j, ev in enumerate(cal.events)
                 if ev.get("type") == "cal_exclude" and run.index in ev.get("run_indices", ()))


def _excluded_before(cal: CalibrationAuthority, j: int) -> dict:
    """Class -> run indices excluded by the `cal_exclude` events before `j`,
    the exclusions replay has accumulated when it recomputes the reader at `j`."""
    out: dict[str, set[int]] = {}
    for ev in cal.events[:j]:
        if ev.get("type") == "cal_exclude":
            out.setdefault(ev["class"], set()).update(ev.get("run_indices", ()))
    return out


def _install_reads(cal: CalibrationAuthority, pol, run: Run) -> bool:
    """Whether the ratchet of an install of `pol` fails once `run` is back in
    the obligation: its class dropped while owing coverage, a bounded-only
    claim against a nonempty corpus, or a ledger claim whose id-set omits the
    run's derived id (`_guard_install_covers`, `_guard_install_bounded`)."""
    spec = pol.classes.get(run.cls)
    if spec is None:
        return True
    did = cal.derived_defect_id(run)
    for claim in spec.claims:
        if not cal._claim_is_ledger(claim):
            return True
        if did not in cal.adm.defect_ids.get(claim.defect_model_hash, frozenset()):
            return True
    return False


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
        (`_guard_audit_checker` needs one; a later escape reads nothing).
      A `cal_exclude` naming the run is a tie, not an anchor (`_group_of`,
      `_rewrites_of`), and a `cal_install` reads no escape: the ratchet only
      eases when one vanishes (F5);
    for a refusal group —
      * a later `cal_stamp` of a class in which the refused checker had a run
        valid at the stamp but for the refusal, and whose cut the refusal
        precedes (`refused_at <= sealed_at`): the refusal voids that run, so
        the stamp's corpus and charges differ. A refusal after the stamp's
        cut is invisible to it (`_check_valid(as_of)`), and the group is
        exposed;
      * a later `cal_install` whose cut the refusal precedes
        (`refused_at <= as_of`), when the refused checker had a run valid at
        the install but for the refusal, not excluded before it, that the
        installed policy does not cover (`_install_reads`: its class dropped,
        a bounded-only claim, or a ledger id-set omitting the run's derived
        id): the refusal is what emptied the obligation (D16), and with the
        group deleted the ratchet, recomputed on rebuild, refuses the install.

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
    else:
        key = next((k for k, at in adm.refused_at.items() if at == s.refusal_at), None)
        refused_at = adm.refused_at.get(key, None)
        if key is None or refused_at is None:
            return ()

        def revived(j: int, rga_cut: Optional[int], cls: Optional[str] = None) -> list[Run]:
            # the refused checker's runs valid at the reader `j` but for the refusal
            return [r for r in cal.runs
                    if r.checker == key and r.verdict == "refuted" and (cls is None or r.cls == cls)
                    and _valid_at(cal, r, j, rga_cut, ignore_refusal=True)]

        for j, ev in enumerate(cal.events):
            t = ev.get("type")
            if t == "cal_stamp":
                seal = adm.sealed.get(ev.get("line_id"))
                if seal is None or refused_at > seal.sealed_at:
                    continue                   # the stamp's cut does not see the refusal
                if revived(j, seal.sealed_at, seal.cls):
                    anchors.append(("cal", j))
            elif t == "cal_install":
                pol = adm._policies.get(ev.get("policy_version"))
                as_of = ev.get("as_of")
                if pol is None or (as_of is not None and refused_at > as_of):
                    continue                   # the install's cut does not see the refusal
                excluded = _excluded_before(cal, j)
                if any(r.index not in excluded.get(r.cls, ()) and _install_reads(cal, pol, r)
                       for r in revived(j, as_of)):
                    anchors.append(("cal", j))
    return tuple(sorted(set(anchors)))


def _run_at_index(cal: CalibrationAuthority, j: int) -> Optional[Run]:
    ev = cal.events[j]
    if ev.get("type") == "cal_run":
        return next((r for r in cal.runs if r.position == j), None)
    ri = ev.get("run_index")
    return cal.runs[ri] if isinstance(ri, int) and 0 <= ri < len(cal.runs) else None


def _run_structural(cal: CalibrationAuthority, run: Run) -> list:
    """Every event that names `run` and must go if its `cal_run` is deleted:
    the run's replays, discredit and adjudication (from_events range-checks
    each `run_index`)."""
    return [k for k, ev in enumerate(cal.events)
            if ev.get("run_index") == run.index
            and ev.get("type") in ("cal_run", "cal_replay", "cal_adjudicate", "cal_discredit")]


def _install_e5_candidates(cal: CalibrationAuthority, j: int) -> list:
    """Later `cal_close(E5)` events of a class the install at `j` budgets — a
    superset the minimizer prunes to those whose demotion the install actually
    carries (a close whose charge count clears the pre-install budget too
    survives the install's deletion; an intervening install supersedes it)."""
    budgets = cal.events[j].get("budgets") or {}
    return [k for k in range(j + 1, len(cal.events))
            if cal.events[k].get("type") == "cal_close" and cal.events[k].get("fault") == "E5"
            and (line := cal.adm.lines.get(cal.events[k].get("line_id"))) is not None
            and line.cls in budgets]


def _shift_adm_positions(events: list, adm_del: set) -> list:
    """Rewrite the cal journal's recorded admission positions after deleting
    `adm_del` from the admission journal: `cal_stamp.sealed_at` and the `as_of`
    of a `cal_close`, `cal_exclude` or `cal_install` each name an admission
    position, and `from_events` checks them against the rebuilt admission, so
    each shifts by the deletions before it (T12c)."""
    def shift(p: int) -> int:
        return p - sum(1 for d in adm_del if d < p)

    out = []
    for ev in events:
        ev = dict(ev)
        if ev.get("type") == "cal_stamp" and isinstance(ev.get("sealed_at"), int):
            ev["sealed_at"] = shift(ev["sealed_at"])
        if ev.get("type") in ("cal_close", "cal_exclude", "cal_install") and isinstance(ev.get("as_of"), int):
            ev["as_of"] = shift(ev["as_of"])
        out.append(ev)
    return out


def _runs_unestablished_by(cal: CalibrationAuthority, cal_del: set) -> set:
    """The runs a cal deletion set leaves unestablished, so a coherent
    alternative must treat them as invalidated (drop them from exclusions,
    T12c/D16, and carry their accepting adjudication). A refuted run is
    unestablished once every establishing replay is deleted, or — tier B —
    its accepting adjudication is. Generalises `_invalidates` from the single
    surface event to the whole deletion (a run replayed twice loses its
    establishment only when both replays go)."""
    out = set()
    for run in cal.runs:
        if run.verdict != "refuted":
            continue
        reps = _establishing_replay_indices(cal, run)
        if reps and all(r in cal_del for r in reps):
            out.add(run.index)
        elif run.tier == "B":
            adj = _adjudication_index(cal, run)
            if adj is not None and adj in cal_del:
                out.add(run.index)
    return out


def _rebuild_alt(cal: CalibrationAuthority, s: SurfaceEvent, deletions: set,
                 initial_policy: Optional[CalibrationPolicy]) -> bool:
    """Whether deleting `s` and `deletions` re-derives: the rga events rebuild
    the admission, the cal events rebuild calibration against it, both
    consistently renumbered (T12c). Deleting rga events shifts admission
    positions, so the surviving cal journal's admission-position fields
    (`cal_stamp.sealed_at`, the `as_of` of a close, exclusion or install) move
    with them, and the rebuilt admission is seeded so its live policy — which
    `from_events` restores from the last supplied policy — is preserved even
    when a version was re-installed. A cross-journal generalisation of
    `_rebuilds` for closures."""
    adm = cal.adm
    rga_del = {i for jr, i in deletions if jr == "rga"} | ({s.index} if s.journal == "rga" else set())
    cal_del = {i for jr, i in deletions if jr == "cal"} | ({s.index} if s.journal == "cal" else set())
    if rga_del:
        try:
            live = adm.policy
            pols = list(adm._policies.values())         # first is the initial policy
            ordered = [pols[0]] + [p for p in pols[1:] if p.version != live.version] + [live]
            alt_adm = [e for i, e in enumerate(adm.events) if i not in rga_del]
            adm = Admission.from_events(alt_adm, adm.fcd, *ordered)
        except Exception:
            return False
    invalidated = _runs_unestablished_by(cal, cal_del)
    alt_cal = _alt_delete(cal, cal_del, invalidated)
    if rga_del:
        alt_cal = _shift_adm_positions(alt_cal, rga_del)
    try:
        CalibrationAuthority.from_events(alt_cal, adm, initial_policy or cal.policy)
        return True
    except Exception:
        return False


def deletion_closure(cal: CalibrationAuthority, s: SurfaceEvent, *,
                     initial_policy: Optional[CalibrationPolicy] = None) -> tuple:
    """What a coherent alternative must remove besides `s` to delete it: the
    events structurally tied to it (`group_with`, at no cost to any other
    line) and the anchors, each carried with its own structural group — an
    anchored `cal_run` (an audit) takes its replays and adjudication, an
    anchored `cal_install` its later `cal_close(E5)` readers. When `s` is one
    of several establishing replays of its run (`redundant_with`), deleting it
    alone leaves a sibling to establish the run, so the closure carries every
    sibling replay too, and — the run then no longer an established escape —
    whatever reads it as one (a later stamp, E5 close or audit) anchors the
    collective removal exactly as it anchors the run's own deletion (R4-24).
    The set is then
    *minimised by re-derivation*: a candidate anchor or downstream reader is
    dropped whenever the alternative still rebuilds without deleting it (an E5
    whose charge count clears the pre-install budget survives the install's
    deletion, R4-16; an audit's replay does not, R4-15). So the closure is
    exactly the deletion the kernel refuses to do without, and its cost is the
    standing those events carried. Events in `rewrites` are edited, not
    removed, and are not listed here."""
    struct = set(s.group_with)
    anchors = set(s.anchored_by)
    if s.redundant_with:
        struct |= {("cal", k) for k in s.redundant_with}   # every sibling must go too
        run = _run_of(cal, s)
        if run is not None:
            # the run, once none of its replays remain, is no longer an
            # established escape: a tier-B accepting adjudication would then be
            # orphaned (from_events: "adjudication requires an established
            # escape"), so it goes with the siblings; the invalidation also
            # rewrites any exclusion naming the run (`_rebuild_alt`). And
            # whatever read the run as an established escape anchors that removal
            if run.tier == "B":
                adj = _adjudication_index(cal, run)
                if adj is not None:
                    struct.add(("cal", adj))
            run_ev = SurfaceEvent("cal", run.position, "cal_run", run.line_id, "escape")
            anchors |= set(_anchors_of(cal, run_ev, initial_policy))
    cand: set = set()
    for jr, j in anchors:
        cand.add((jr, j))
        if jr != "cal":
            continue
        t = cal.events[j].get("type")
        if t in ("cal_run", "cal_replay", "cal_adjudicate"):
            run = _run_at_index(cal, j)
            if run is not None:
                struct |= {("cal", k) for k in _run_structural(cal, run)}
        elif t == "cal_install":
            cand |= {("cal", k) for k in _install_e5_candidates(cal, j)}
    needed = set(struct) | set(cand)
    for e in sorted(cand):                     # keep only what the rebuild cannot do without
        if e in needed and _rebuild_alt(cal, s, needed - {e}, initial_policy):
            needed.discard(e)
    # completeness net: removing an install anchor can renumber a later run and
    # break a *further* install that covered it by its old position-derived id
    # — a downstream reader the analytic enumeration (stamps, E5 closes) does
    # not name (V). If the alternative still does not rebuild, find the jointly
    # necessary further installs by re-derivation, carried with their own E5
    # readers, then re-minimise; if none help, the group stays incoherent.
    if not _rebuild_alt(cal, s, needed, initial_policy):
        rest = [j for j, ev in enumerate(cal.events)
                if ev.get("type") == "cal_install" and ("cal", j) not in needed]

        def with_installs(keep: set) -> set:
            extra = {("cal", j) for j in keep}
            extra |= {("cal", k) for j in keep for k in _install_e5_candidates(cal, j)}
            return needed | extra

        if rest and _rebuild_alt(cal, s, with_installs(set(rest)), initial_policy):
            keep = set(rest)                   # remove all, add each back the rebuild does not need
            for j in sorted(rest):
                if _rebuild_alt(cal, s, with_installs(keep - {j}), initial_policy):
                    keep.discard(j)
            needed = with_installs(keep)
    return tuple(sorted(needed))


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
    fail-closed value past the Bonferroni horizon. The floating-point
    correction is a *downward* clamp only — the accumulation error of the sum
    is O(n·ε), so a residual within that scale of zero is indistinguishable
    from the exact horizon zero (ten 0.9s sum to 1, read as 0 not 2e-16) and
    is clamped to it — never a rounding of a positive residual *upward*, which
    would over-claim the assumption-free lower bound (a one-element `[p]`
    stays `p`, not 1; a genuine 6e-13 stays 6e-13, not 1e-12)."""
    import sys
    ps = list(composites)
    residual = 1.0 - sum(1.0 - p for p in ps)
    if residual < 4.0 * max(1, len(ps)) * sys.float_info.epsilon:
        return 0.0                             # numerical noise around the horizon, or negative
    return residual


def bonferroni_horizon(p: float) -> Optional[int]:
    """The smallest number of conjuncts at power p at which the assumption-free
    joint reading `power_joint` reaches its fail-closed zero (≈ ceil(1/(1−p)));
    None at p = 1. Decided by `power_joint` itself, so the two cannot disagree:
    a genuine near-boundary excess (p just above 1−1/k) leaves `power_joint`
    positive and pushes the horizon one past k, while representation noise at
    an exact boundary still reads zero there."""
    if p >= 1.0:
        return None
    import math
    n = max(1, math.floor(1.0 / (1.0 - p)))
    while power_joint([p] * n) > 0.0:
        n += 1
    while n > 1 and power_joint([p] * (n - 1)) == 0.0:
        n -= 1
    return n


def seal_joint(seal: Seal) -> float:
    return power_joint(c.composite for c in seal.claims)


def frechet_bounds(powers: Iterable[float], event: str) -> tuple[float, float]:
    """The interval every coupling's value of the composite lies in.
    event='union' (some refuter catches): [max, min(1, Σ)] — T6(b).
    event='intersection' (every conjunct caught): [max(0, 1−Σ(1−p)), min] — T7.
    The empty conjunction is the identity of its event: an empty union
    catches nothing (0) and an empty intersection is vacuously caught (1,
    the value `power_joint([])` already returns), so emptiness is resolved
    per event, not to a single fail-closed pair."""
    ps = list(powers)
    if event == "union":
        return (max(ps), min(1.0, sum(ps))) if ps else (0.0, 0.0)
    if event == "intersection":
        return (power_joint(ps), min(ps) if ps else 1.0)
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
    """The journaled part of what the generator may have seen (D25): every
    earlier line on the same bind key, and every refutation on those lines
    journaled before this line's open — read from the `rga_trial` events in
    `r[0 : open(ℓ)]`, not from a close's reason string and not from the
    lines' final trial lists, which may hold refutations published later."""
    line = adm.lines[line_id]
    key = _bind_key(line)
    prior = [l for l in adm.lines.values()
             if l.id != line_id and _bind_key(l) == key and l.opened_at < line.opened_at]
    prior.sort(key=lambda l: l.opened_at)
    prior_ids = {l.id for l in prior}
    refs = []
    for ev in adm.events[:line.opened_at]:
        if (ev.get("type") == "rga_trial" and ev.get("verdict") == "refuted"
                and ev.get("work_item_id") in prior_ids):
            refs.append((ev.get("refuter_id"), ev.get("refuter_version"), ev.get("claim_id"),
                         ev.get("sample_index"), ev.get("work_item_id")))
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
