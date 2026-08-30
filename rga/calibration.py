"""Calibration — the escape ledger (paper/RGA/INVARIANTS.md §8).

Composed over rga.core.Admission the way Admission composes over FCD. Six ideas:

1. An ESCAPE is a counterfactual trial: the claim's PINNED refuter, run at a
   finder-chosen nonce against the sealed bytes, verdict refuted, replayed.
   The finder authors nothing but a nonce; the kernel hashes the bytes and
   derives the seed itself, so tier A adds no assumption the seal did not
   already carry (C1). Any other checker is tier B and has no effect until a
   named, journaled adjudication accepts it (E2).
2. A CHARGE is the journaled wrong-verdict cell (line, claim, refuter
   version), write-once by construction: witness and checker multiplicity
   never multiply charges (C2, E3).
3. IMPEACHMENT is a pure query entailed by a valid escape. Seals are never
   rewritten; validity degrades by journal facts (checker discredited or
   refused), never by discretion (C3).
4. The RATCHET runs at Install: every referenced defect model must be
   Measured, and must cover the class corpus minus journaled exclusions;
   the install event carries the primaries and the dropped-id diff.
   Forgetting is loud (C4, E4).
5. DEMOTION is a query over charges against a declared budget: it blocks new
   pins at CalOpen, gates CalSeal exactly where the class declared it (E5),
   and never cascades events or touches an existing seal (C6).
6. The authority writes no Admission or FCD field directly; its only effect
   on the lower machines is through their own guarded transitions, so every
   R- and I-theorem holds on the combined trace (C7).

What none of this proves: that the corpus resembles the generator's real
defects. The theorems are about the ledger of found misses, never the
distribution of real ones (§8.3, Not theorems).
"""
from __future__ import annotations

import copy
import functools
from dataclasses import dataclass
from typing import Callable, Iterable, Optional
from fcd.journal import JournalEvent, JournalValueError, normalize_journal
from .core import Admission, AdmissionPolicy, derive_seed, sha256

GATES = frozenset({"seal", "carry"})
RUN_VERDICTS = frozenset({"refuted", "survived"})


@dataclass(frozen=True)
class CalibrationClass:
    e_max: int
    demotion_gate: str              # "seal" | "carry"


def _require_coverage(admission_policy: AdmissionPolicy, policy: "CalibrationPolicy") -> None:
    """E9. Every class the admission policy admits carries an explicit
    calibration budget. Checked wherever the pair can change — construction
    and install — so an unconfigured class never becomes an unlimited one."""
    missing = sorted(set(admission_policy.classes) - set(policy.classes))
    if missing:
        raise ValueError(
            f"classes {missing} have no calibration policy; e_max and demotion_gate "
            "are explicit per class and have no default")


@dataclass(frozen=True)
class CalibrationPolicy:
    classes: dict[str, CalibrationClass]
    version: str = "c1"

    def __post_init__(self) -> None:
        for cls, c in self.classes.items():
            if c.e_max < 0:
                raise ValueError(f"class {cls!r}: e_max must be >= 0")
            if c.demotion_gate not in GATES:
                raise ValueError(f"class {cls!r}: demotion_gate must be one of {sorted(GATES)}")


@dataclass
class Run:
    """One filed counterfactual run against a sealed line. verdict `refuted`
    is an escape; `survived` is an audit record."""
    index: int
    line_id: str
    cls: str
    claim_id: str
    checker: tuple[str, str]
    tier: str                       # "A" | "B"
    nonce: str
    artifact_hash: str
    seed: str
    verdict: str
    witness_hash: str
    finder: str                     # journal-cited provenance; never gates anything
    position: int
    established: bool = False
    adjudication: Optional[str] = None   # tier B: "accept" | "reject"


def _journal_atomic(*state_fields):
    """Restore only the calibration/delegated cells one row can write."""

    def decorate(method):
        @functools.wraps(method)
        def wrapped(self, *args, **kwargs):
            snapshot = {}
            for name in state_fields:
                if name == "runs_append":
                    snapshot[name] = len(self.runs)
                elif name == "run":
                    index = args[0]
                    snapshot[name] = (index, copy.deepcopy(self.runs[index]))
                elif name == "admission_policy":
                    incoming = args[0]
                    snapshot[name] = (
                        self.adm.policy, incoming.version,
                        incoming.version in self.adm._policies,
                        self.adm._policies.get(incoming.version),
                    )
                elif name == "admission_line":
                    item_id = args[0]
                    snapshot[name] = (
                        item_id,
                        copy.deepcopy(self.adm.lines[item_id]),
                        copy.deepcopy(self.adm.sealed.get(item_id)),
                        item_id in self.adm.sealed,
                        len(self.adm._events),
                    )
                elif name == "exclusions":
                    cls = args[0]
                    snapshot[name] = (
                        cls, cls in self.exclusions,
                        set(self.exclusions.get(cls, ())),
                    )
                elif name == "policy":
                    snapshot[name] = self.policy
                elif name == "discredited":
                    checker = self.runs[args[0]].checker
                    snapshot[name] = (checker, checker in self.discredited)
                else:
                    snapshot[name] = copy.deepcopy(getattr(self, name))
            event_count = len(self._events)
            try:
                return method(self, *args, **kwargs)
            except Exception as exc:
                delegated_event = any(
                    name == "admission_line"
                    and len(self.adm._events) > value[4]
                    for name, value in snapshot.items())
                if (isinstance(exc, ValueError)
                        and not isinstance(exc, JournalValueError)
                        and (len(self._events) > event_count or delegated_event)):
                    raise
                for name, value in snapshot.items():
                    if name == "runs_append":
                        del self.runs[value:]
                    elif name == "run":
                        index, run = value
                        self.runs[index] = run
                    elif name == "admission_policy":
                        current, version, existed, prior = value
                        self.adm.policy = current
                        if existed:
                            self.adm._policies[version] = prior
                        else:
                            self.adm._policies.pop(version, None)
                    elif name == "admission_line":
                        item_id, line, seal, had_seal, adm_event_count = value
                        self.adm.lines[item_id] = line
                        if had_seal:
                            self.adm.sealed[item_id] = seal
                        else:
                            self.adm.sealed.pop(item_id, None)
                        del self.adm._events[adm_event_count:]
                    elif name == "exclusions":
                        cls, existed, excluded = value
                        if existed:
                            self.exclusions[cls] = excluded
                        else:
                            self.exclusions.pop(cls, None)
                    elif name == "discredited":
                        checker, existed = value
                        if existed:
                            self.discredited.add(checker)
                        else:
                            self.discredited.discard(checker)
                    else:
                        setattr(self, name, value)
                del self._events[event_count:]
                if isinstance(exc, RecursionError):
                    raise JournalValueError(
                        "journal event must contain canonical JSON values") from None
                raise
        return wrapped
    return decorate


class CalibrationAuthority:
    """The escape ledger. Reads Admission and FCD state; writes only its own.

    CalOpen/CalSeal/CalInstall drive the Admission machine through its own
    guarded transitions (the interposition pattern the reference server uses
    for receipts). A deployment that bypasses this authority has RGA's
    guarantees and not these."""

    def __init__(self, admission: Admission, policy: CalibrationPolicy,
                 clock: Callable[[], float] = lambda: 0.0) -> None:
        self.adm = admission
        self.policy = policy
        self.clock = clock
        _require_coverage(admission.policy, policy)                       # E9
        self._events: list[JournalEvent] = []
        self.runs: list[Run] = []
        self.discredited: set[tuple[str, str]] = set()      # monotone (E1)
        self.exclusions: dict[str, set[int]] = {}           # cls -> excluded run indices

    # -- journal -------------------------------------------------------------

    @property
    def events(self) -> tuple[JournalEvent, ...]:
        """Immutable snapshot of the authority-owned append-only journal."""
        return tuple(self._events)

    def _position(self) -> int:
        return len(self._events)

    def _emit(self, **event) -> None:
        try:
            event.setdefault("ts", self.clock())
        except Exception:
            raise JournalValueError(
                "journal event must contain canonical JSON values") from None
        self._events.append(JournalEvent(event))

    # -- helpers -------------------------------------------------------------

    def _seal_of(self, line_id: str):
        seal = self.adm.sealed.get(line_id)
        if seal is None:
            raise ValueError(f"line {line_id!r} is not in S_R")
        return seal

    def _pinned_on_claim(self, seal, claim_id: str) -> frozenset[tuple[str, str]]:
        for c in seal.claims:
            if c.claim_id == claim_id:
                return frozenset((r.id, r.version) for r in c.refuters)
        raise ValueError(f"claim {claim_id!r} not in the seal of {seal.line_id!r}")

    def derived_defect_id(self, run: Run) -> str:
        """The corpus entry id an escape contributes: its journal identity."""
        return f"escape-{run.line_id}-{run.claim_id}-{run.position}"

    # -- filing (FileEscape / Audit) -----------------------------------------

    def file_escape(self, line_id: str, claim_id: str, checker_id: str, checker_version: str,
                    nonce: str, artifact: bytes, seed: str, witness_hash: str,
                    finder: str, verdict: str = "refuted") -> Run:
        return self._file_run(line_id, claim_id, (checker_id, checker_version), nonce,
                              artifact, seed, witness_hash, finder, verdict, expect="refuted")

    def file_audit(self, line_id: str, claim_id: str, checker_id: str, checker_version: str,
                   nonce: str, artifact: bytes, seed: str, witness_hash: str,
                   finder: str, verdict: str = "survived") -> Run:
        """A null-audit record: the same mechanics with the opposite verdict.
        Consequence-free except audit exposure, so its checker must be pinned
        on the claim or be the checker of a valid escape of the class."""
        return self._file_run(line_id, claim_id, (checker_id, checker_version), nonce,
                              artifact, seed, witness_hash, finder, verdict, expect="survived")

    @_journal_atomic("runs_append")
    def _file_run(self, line_id: str, claim_id: str, checker: tuple[str, str], nonce: str,
                  artifact: bytes, seed: str, witness_hash: str, finder: str,
                  verdict: str, expect: str) -> Run:
        seal = self._seal_of(line_id)                                    # E6
        pinned = self._pinned_on_claim(seal, claim_id)                   # E6
        self._guard_run_verdict(verdict, expect)                         # E6/E1
        self._guard_run_checker(checker)                                 # E1
        artifact_hash = sha256(artifact)
        self._guard_run_bytes(seal, artifact_hash)                       # E6
        tier = "A" if checker in pinned else "B"
        if tier == "A":
            self._guard_run_seed(nonce, seal.artifact_hash, checker, claim_id, seed)  # E6
        if expect == "survived":
            self._guard_audit_checker(seal.cls, checker, pinned)         # E1 (audit shape)
        run = Run(index=len(self.runs), line_id=line_id, cls=seal.cls, claim_id=claim_id,
                  checker=checker, tier=tier, nonce=nonce, artifact_hash=artifact_hash,
                  seed=seed, verdict=verdict, witness_hash=witness_hash, finder=finder,
                  position=self._position())
        self.runs.append(run)
        self._emit(type="cal_run", run_index=run.index, line_id=line_id, **{"class": seal.cls},
                   claim_id=claim_id, checker_id=checker[0], checker_version=checker[1],
                   tier=tier, nonce=nonce, artifact_hash=artifact_hash, seed=seed,
                   verdict=verdict, witness_hash=witness_hash, finder=finder)
        return run

    @_journal_atomic("run", "discredited")
    def replay_run(self, run_index: int, verdict: str, witness_hash: str) -> None:
        """Establishment and its falsifier. Equal outcome establishes;
        divergence discredits the checker in this ledger, monotonically (E1)."""
        run = self.runs[run_index]
        if run.checker in self.discredited:
            raise ValueError(f"checker {run.checker!r} is discredited")
        self._guard_replay_verdict(verdict)                               # E1
        diverged = self._check_run_replay(run, verdict, witness_hash)     # E1
        self._emit(type="cal_replay", run_index=run_index, verdict=verdict,
                   witness_hash=witness_hash, diverged=diverged)
        if diverged:
            self.discredited.add(run.checker)
            self._emit(type="cal_discredit", checker_id=run.checker[0],
                       checker_version=run.checker[1], run_index=run_index)
        else:
            run.established = True

    def _guard_replay_verdict(self, verdict: str) -> None:
        """A replay may only speak the run vocabulary: an out-of-enum verdict
        would enter the ledger as a cal_replay event no schema knows — and
        from_events already refuses such journals, so the live path must too."""
        if verdict not in RUN_VERDICTS:
            raise ValueError(f"unknown verdict {verdict!r}")

    @_journal_atomic("run")
    def adjudicate(self, run_index: int, actor: str, decision: str, reason: str) -> None:
        """Tier B only: the per-escape claim-fidelity judgment, made visible (E2, E7)."""
        run = self.runs[run_index]
        self._guard_adjudication(run, actor, decision, reason)            # E7
        run.adjudication = decision
        self._emit(type="cal_adjudicate", run_index=run_index, actor=actor,
                   decision=decision, reason=reason)

    @_journal_atomic("exclusions")
    def exclude(self, cls: str, run_indices: Iterable[int], actor: str, reason: str) -> None:
        """The ratchet's named exit: releases corpus entries from successor
        coverage. Waives nothing else (E7)."""
        indices = tuple(run_indices)
        self._guard_exclusion(cls, indices, actor, reason)                # E7
        self.exclusions.setdefault(cls, set()).update(indices)
        self._emit(type="cal_exclude", **{"class": cls}, as_of=self.adm._position(),
                   run_indices=list(indices),
                   actor=actor, reason=reason,
                   corpus_size=len(self._corpus_all(cls)),
                   excluded_total=len(self.exclusions[cls]))

    # -- validity and derived state (pure) ------------------------------------

    def _check_valid(self, run: Run, as_of: Optional[int] = None) -> bool:
        """E1/E2 read at query time, the tainted() pattern: established, the
        checker neither discredited here nor refused in the Admission
        registry, and tier B adjudicated accepted."""
        if not run.established:
            return False
        if run.checker in self.discredited:
            return False
        if run.checker in self.adm.refused:
            # Bounded by position when the caller has one: a refusal that
            # happened AFTER the record being recomputed did not exist when
            # that record was written, and treating the final refused set as
            # timeless made replay refuse journals the live machine produced.
            if as_of is None or self.adm.refused_at.get(run.checker, -1) <= as_of:
                return False
        if run.verdict == "refuted" and run.tier == "B" and run.adjudication != "accept":
            return False   # adjudication gates escape EFFECT; audits carry none
        return True

    def escapes(self, cls: Optional[str] = None, as_of: Optional[int] = None) -> tuple[Run, ...]:
        return tuple(r for r in self.runs
                     if r.verdict == "refuted" and self._check_valid(r, as_of)
                     and (cls is None or r.cls == cls))

    def _corpus_all(self, cls: str, as_of: Optional[int] = None) -> tuple[Run, ...]:
        return tuple(r for r in self.escapes(cls, as_of))

    def corpus(self, cls: str, as_of: Optional[int] = None) -> tuple[Run, ...]:
        """Valid escapes of the class minus journaled exclusions."""
        excluded = self.exclusions.get(cls, set())
        return tuple(r for r in self._corpus_all(cls, as_of) if r.index not in excluded)

    def charge_cells(self, cls: Optional[str] = None,
                     as_of: Optional[int] = None) -> frozenset[tuple[str, str, str, str]]:
        """C2: the valid wrong-verdict cells (line, claim, refuter id, version),
        one per cell however many witnesses or checkers proved the miss."""
        cells: set[tuple[str, str, str, str]] = set()
        for run in self.runs:
            if run.verdict != "refuted" or not self._check_valid(run, as_of):
                continue
            if cls is not None and run.cls != cls:
                continue
            seal = self.adm.sealed[run.line_id]
            for key in self._pinned_on_claim(seal, run.claim_id):
                cells.add((run.line_id, run.claim_id, key[0], key[1]))
        return frozenset(cells)

    def charges(self, refuter_id: str, version: str, cls: str,
                as_of: Optional[int] = None) -> int:
        return sum(1 for c in self.charge_cells(cls, as_of) if (c[2], c[3]) == (refuter_id, version))

    def demoted(self, refuter_id: str, version: str, cls: str,
                as_of: Optional[int] = None) -> bool:
        """C6: a pure query — charges past the declared budget. Never an event.
        A class nobody configured has no budget of infinity; the query refuses
        rather than answering "never demoted" (E9)."""
        self._guard_class_configured(cls)                                 # E9
        spec = self.policy.classes.get(cls)
        if spec is None:
            # Unreachable past the guard, and kept deliberately: it is the
            # behaviour the guard exists to prevent, so deleting the guard
            # exposes the defect (an unconfigured class that never demotes)
            # instead of crashing on a lookup. The deletion proof reads it.
            return False
        return self.charges(refuter_id, version, cls, as_of) > spec.e_max

    def impeached(self, line_id: str) -> bool:
        """C3: entailed by a valid escape; the seal is never rewritten."""
        return any(r.verdict == "refuted" and r.line_id == line_id and self._check_valid(r)
                   for r in self.runs)

    def mediated(self, line_id: str) -> bool:
        """C5 totality: this seal passed through CalSeal, evidenced by exactly
        one stamp bound to its position. A seal produced by calling
        Admission.seal directly carries layer-R standing only — it is IR, not
        IRC — and a consumer must be able to tell the two apart."""
        seal = self.adm.sealed.get(line_id)
        if seal is None:
            return False
        stamps = [ev for ev in self._events
                  if ev.get("type") == "cal_stamp" and ev.get("line_id") == line_id]
        return len(stamps) == 1 and stamps[0].get("sealed_at") == seal.sealed_at

    def admissible(self, line_id: str) -> bool:
        return (self.mediated(line_id) and self.adm.admissible(line_id)
                and not self.impeached(line_id))

    def suspect(self, line_id: str) -> bool:
        """Direct dependencies only; transitive coverage is the consumer's
        fold over depends_on (RFC 5280 shape), never a write."""
        item = self.adm.fcd.items.get(line_id)
        if item is None:
            return False
        return any(self.impeached(dep) or self.adm.tainted(dep) for dep in item.depends_on)

    def check_dependencies(self, deps: Iterable[str], floor: float) -> None:
        for dep in deps:
            self.adm.check_dependencies([dep], floor)
            if not self.mediated(dep):
                raise ValueError(f"dependency {dep!r} is not mediated by this authority (IR, not IRC)")
            if self.impeached(dep):
                raise ValueError(f"dependency {dep!r} is impeached by a valid escape")

    def audit_exposure(self, line_id: str) -> tuple[Run, ...]:
        return tuple(r for r in self.runs
                     if r.verdict == "survived" and r.line_id == line_id and self._check_valid(r))

    def track_record(self, refuter_id: str, version: str, cls: str,
                     as_of_seal: Optional[int] = None) -> dict:
        """C5 primaries. Never a rate; a zero is absence of filed evidence.

        `as_of_seal` bounds the seal count to those sealed at or before that
        Admission position, which is what the live stamp saw. Without it,
        replay recomputes against the fully rebuilt Admission and every
        stamp but the last disagrees — refusing honest journals."""
        participated = sum(
            1 for s in self.adm.sealed.values()
            if s.cls == cls and (as_of_seal is None or s.sealed_at <= as_of_seal)
            and any((r.id, r.version) == (refuter_id, version)
                    for c in s.claims for r in c.refuters))
        corpus = self._corpus_all(cls, as_of_seal)
        return {
            "charged_cells": self.charges(refuter_id, version, cls, as_of_seal),
            "seals_participated": participated,
            "corpus_size": len(corpus),
            "corpus_excluded": len(self.exclusions.get(cls, set())),
            "as_of": self._position(),
        }

    # -- wrapped transitions ----------------------------------------------------

    @_journal_atomic("policy", "admission_policy")
    def install(self, policy: AdmissionPolicy,
                cal_policy: Optional["CalibrationPolicy"] = None) -> None:
        """CalInstall: the ratchet (C4, E4), then Admission.install, then the
        journal event Admission.install never had. A successor admission
        policy may add classes only alongside their explicit calibration
        budgets (E9); the pair moves atomically, so a refused ratchet leaves
        both standing."""
        successor_cal = self.policy if cal_policy is None else cal_policy
        _require_coverage(policy, successor_cal)                          # E9
        self._guard_install_measured(policy)                              # E4
        self._guard_install_covers(policy)                                # E4
        self._guard_install_bounded(policy)                               # E4
        dropped = self._dropped_ids(policy)
        dropped_classes = sorted(set(self.adm.policy.classes) - set(policy.classes))
        self.adm.install(policy)
        self.policy = successor_cal
        coverage = {
            cls: {"corpus_size": len(self._corpus_all(cls)),
                  "excluded": len(self.exclusions.get(cls, set())),
                  "models": {claim.id: claim.defect_model_hash for claim in spec.claims}}
            for cls, spec in policy.classes.items()
        }
        self._emit(type="cal_install", policy_version=policy.version,
                   as_of=self.adm._position(),
                   calibration_policy_version=successor_cal.version,
                   budgets={cls: {"e_max": c.e_max, "demotion_gate": c.demotion_gate}
                            for cls, c in sorted(successor_cal.classes.items())},
                   coverage=coverage, dropped_defect_ids=sorted(dropped),
                   dropped_classes=dropped_classes)

    def open(self, item_id: str, generator: str, sampling_hash: str):
        """CalOpen: the class carries an explicit budget (E9) and no demoted
        pin (C6); Admission.open does the rest."""
        item = self.adm.fcd.items.get(item_id)
        if item is not None:
            self._guard_class_configured(item.cls)                        # E9
            spec = self.adm.policy.classes.get(item.cls)
            if spec is not None:
                self._guard_open_demoted(item.cls, spec)                  # C6
        return self.adm.open(item_id, generator, sampling_hash)

    @_journal_atomic("admission_line")
    def seal(self, item_id: str):
        """CalSeal: the demotion gate where the class declared it (E5), and
        the track-record stamp in the same step as the seal (C5)."""
        line = self.adm.lines[item_id]
        self._guard_class_configured(line.cls)                            # E9
        if line.pc != "Open":
            # Before any E5 emission: a spurious close event for a line that
            # stays Sealed would be a journaled step that never happened
            # (calibration round-1 finding).
            raise ValueError("seal requires pc=Open")
        gated = self._check_seal_demotion(line)                           # E5
        if gated is not None:
            at = self.adm._position()
            self._emit(type="cal_close", line_id=item_id, fault="E5", as_of=at,
                       refuter_id=gated[0], refuter_version=gated[1],
                       primaries=self.track_record(gated[0], gated[1], line.cls, as_of_seal=at))
            self.adm.close(item_id, reason=f"E5: {gated!r} demoted past e_max")
            raise ValueError(f"line {item_id!r} closed with E5: {gated!r} is demoted")
        seal = self.adm.seal(item_id)
        self._stamp(seal)                                                 # C5
        return seal

    def _stamp(self, seal) -> None:
        records = {}
        for c in seal.claims:
            for r in c.refuters:
                records[f"{r.id}@{r.version}"] = self.track_record(
                    r.id, r.version, seal.cls, as_of_seal=seal.sealed_at)
        self._emit(type="cal_stamp", line_id=seal.line_id, sealed_at=seal.sealed_at,
                   track_records=records,
                   corpus_provenance=self._corpus_provenance(seal.cls, seal.generator,
                                                             as_of=seal.sealed_at))

    def _corpus_provenance(self, cls: str, generator: str,
                           as_of: Optional[int] = None) -> dict:
        """C5: the class corpus split by finder provenance — entries found by
        this seal's generator versus independent finders. Primaries; the
        finder string gates nothing (journal-cited metadata only)."""
        entries = self._corpus_all(cls, as_of)
        participant = sum(1 for r in entries if r.finder == generator)
        return {"finder_is_generator": participant, "independent": len(entries) - participant}

    def sealed_stamp(self, line_id: str) -> Optional[dict]:
        for ev in self._events:
            if ev.get("type") == "cal_stamp" and ev.get("line_id") == line_id:
                return ev
        return None

    # -- guards: each is named by the fault table (§8.4) --------------------------

    def _guard_class_configured(self, cls: str) -> None:
        """E9. e_max and demotion_gate are explicit per class, with no
        defaults: an unconfigured class must not behave as an unlimited one,
        so every transition and budget query over it refuses."""
        if cls not in self.policy.classes:
            raise ValueError(
                f"class {cls!r} has no calibration policy; e_max and demotion_gate "
                "are explicit per class and have no default")

    def _guard_run_verdict(self, verdict: str, expect: str) -> None:
        """E6/E1. An escape is a refuting run; an audit is a surviving one."""
        if verdict not in RUN_VERDICTS or verdict != expect:
            raise ValueError(f"filing requires verdict {expect!r}, got {verdict!r}")

    def _guard_run_checker(self, checker: tuple[str, str]) -> None:
        """E1. The checker is declared and neither discredited nor refused."""
        if checker not in self.adm.refuters:
            raise ValueError(f"checker {checker!r} not declared")
        if checker in self.discredited:
            raise ValueError(f"checker {checker!r} is discredited")
        if checker in self.adm.refused:
            raise ValueError(f"checker {checker!r} is refused")

    def _guard_run_bytes(self, seal, artifact_hash: str) -> None:
        """E6, single-holder: the kernel hashed the filed bytes itself and they
        are the sealed bytes. Naming a hash is assertion; handing bytes is not."""
        if artifact_hash != seal.artifact_hash:
            raise ValueError("filed bytes do not hash to the seal's artifact hash")

    def _guard_run_seed(self, nonce: str, artifact_hash: str, checker: tuple[str, str],
                        claim_id: str, seed: str) -> None:
        """E6, tier A: the seed is the kernel's derivation — a counterfactual
        trial of the pinned refuter, nothing else."""
        if seed != derive_seed(nonce, artifact_hash, checker[0], checker[1], claim_id):
            raise ValueError("tier-A seed is not the kernel's derivation")

    def _guard_audit_checker(self, cls: str, checker: tuple[str, str],
                             pinned: frozenset[tuple[str, str]]) -> None:
        """E1, audit shape: a surviving run pads exposure, so its checker must
        be pinned on the claim or be the checker of a valid escape of the class
        — a realized instrument, never a junk one."""
        if checker in pinned:
            return
        if any(r.checker == checker for r in self.escapes(cls)):
            return
        raise ValueError(f"audit checker {checker!r} is neither pinned nor a valid escape's checker")

    def _check_run_replay(self, run: Run, verdict: str, witness_hash: str) -> bool:
        """E1. True iff the replay diverged from the filed outcome."""
        return (verdict, witness_hash) != (run.verdict, run.witness_hash)

    def _guard_adjudication(self, run: Run, actor: str, decision: str, reason: str) -> None:
        """E7/E2. Tier B, established, named actor, a reason, one decision."""
        if run.tier != "B":
            raise ValueError("adjudication is for tier-B escapes; tier A needs none")
        if run.verdict != "refuted":
            raise ValueError("adjudication is for escapes, not audits")
        if not run.established:
            raise ValueError("adjudication requires an established escape")
        if run.adjudication is not None:
            raise ValueError("escape already adjudicated")
        if decision not in {"accept", "reject"}:
            raise ValueError(f"unknown decision {decision!r}")
        if not actor or not reason:
            raise ValueError("adjudication requires a named actor and a reason")

    def _guard_exclusion(self, cls: str, indices: tuple[int, ...], actor: str, reason: str,
                         as_of: Optional[int] = None) -> None:
        """E7. Named actor, a reason, and only valid escapes of this class."""
        if not actor or not reason:
            raise ValueError("exclusion requires a named actor and a reason")
        if not indices:
            raise ValueError("exclusion names at least one escape")
        valid = {r.index for r in self._corpus_all(cls, as_of)}
        unknown = [i for i in indices if i not in valid]
        if unknown:
            raise ValueError(f"not valid escapes of class {cls!r}: {unknown}")

    def _guard_install_measured(self, policy: AdmissionPolicy) -> None:
        """E4. Measure before Install: every referenced ledger defect model has
        a kernel-fixed id-set — always achievable, since measure() reads no
        policy state."""
        for cls, spec in policy.classes.items():
            for claim in spec.claims:
                if self._claim_is_ledger(claim) and claim.defect_model_hash not in self.adm.defect_ids:
                    raise ValueError(
                        f"class {cls!r} claim {claim.id!r}: defect model {claim.defect_model_hash!r} has no Measure record")

    def _guard_install_covers(self, policy: AdmissionPolicy,
                              as_of: Optional[int] = None) -> None:
        """E4, the ratchet: each ledger claim's id-set covers the class corpus
        minus journaled exclusions as of this position."""
        # A class that owes coverage cannot be dropped from the policy: the
        # drop would release its whole corpus with no journal trace
        # (calibration round-1, attacker gap).
        for cls in {r.cls for r in self.runs if r.verdict == "refuted"}:
            if self.corpus(cls, as_of) and cls not in policy.classes:
                raise ValueError(f"class {cls!r} owes coverage for its escape corpus and cannot be dropped")
        for cls, spec in policy.classes.items():
            required = {self.derived_defect_id(r) for r in self.corpus(cls, as_of)}
            if not required:
                continue
            for claim in spec.claims:
                if not self._claim_is_ledger(claim):
                    continue
                ids = self.adm.defect_ids.get(claim.defect_model_hash, frozenset())
                missing = required - ids
                if missing:
                    raise ValueError(
                        f"class {cls!r} claim {claim.id!r}: defect model omits corpus entries {sorted(missing)}")

    def _guard_install_bounded(self, policy: AdmissionPolicy) -> None:
        """E4. A bounded-only claim has no D to cover with; against a nonempty
        net corpus that is a silent forget, refused."""
        for cls, spec in policy.classes.items():
            if not self.corpus(cls):
                continue
            for claim in spec.claims:
                if not self._claim_is_ledger(claim):
                    raise ValueError(
                        f"class {cls!r} claim {claim.id!r} is bounded-only against a nonempty escape corpus")

    def _guard_open_demoted(self, cls: str, spec) -> None:
        """C6 at CalOpen: a demoted refuter cannot be pinned by a new line."""
        for claim in spec.claims:
            for key in claim.refuters:
                if self.demoted(key[0], key[1], cls):
                    raise ValueError(f"refuter {key!r} is demoted in class {cls!r}")

    def _check_seal_demotion(self, line) -> Optional[tuple[str, str]]:
        """E5. Where the class declared the gate, a pinned refuter demoted as
        of this position closes the line, published, with primaries."""
        spec = self.policy.classes.get(line.cls)
        if spec is None or spec.demotion_gate != "seal":
            return None
        for key in sorted(line.pinned()):
            if self.demoted(key[0], key[1], line.cls):
                return key
        return None

    def _claim_is_ledger(self, claim) -> bool:
        return any(self.adm.refuters[key].mode == "ledger"
                   for key in claim.refuters if key in self.adm.refuters)

    def _dropped_ids(self, policy: AdmissionPolicy) -> set[str]:
        """The predecessor-diff the install event enumerates: defect ids the
        outgoing policy's models carried that no incoming model carries, per
        class the incoming policy names. Cheap hygiene — journal-computable
        anyway, impossible to overlook once enumerated."""
        dropped: set[str] = set()
        for cls, spec in policy.classes.items():
            old = self.adm.policy.classes.get(cls)
            if old is None:
                continue
            old_ids: set[str] = set()
            for claim in old.claims:
                old_ids |= self.adm.defect_ids.get(claim.defect_model_hash, frozenset())
            new_ids: set[str] = set()
            for claim in spec.claims:
                new_ids |= self.adm.defect_ids.get(claim.defect_model_hash, frozenset())
            dropped |= old_ids - new_ids
        return dropped

    # -- replay ---------------------------------------------------------------------

    @classmethod
    def from_events(cls, journal: object, admission: Admission,
                    policy: CalibrationPolicy,
                    clock: Callable[[], float] = lambda: 0.0) -> "CalibrationAuthority":
        """Rebuild ledger state from cal_* events over an already-rebuilt
        Admission — re-checking every filing guard and entailment before
        writing, so a journal live execution refuses is refused on rebuild
        (calibration round-1 defect: the first version trusted the journaled
        tier, seed, checker standing and exclusion actor). Wrapped transitions
        (install/open/seal/close) were re-driven by Admission.from_events;
        their calibration halves are verified here by recomputation, never
        re-driven. One-sided residue, stated in PROOFS: the rebuilt Admission
        registry is the final one, so a checker declared or a defect model
        measured later in that journal cannot be ordered against these events;
        membership checks here are against the final registry."""
        a = cls(admission, policy, clock=clock)
        events = normalize_journal(journal)
        cal_events = tuple(ev for ev in events
                           if type(ev.get("type")) is str
                           and ev["type"].startswith("cal_"))
        pending_discredit: Optional[tuple[tuple[str, str], int]] = None
        for ev in cal_events:
            t = ev["type"]
            if pending_discredit is not None and t != "cal_discredit":
                raise ValueError("replay diverged: diverged replay without its discredit event")
            if t == "cal_run":
                checker = (ev["checker_id"], ev["checker_version"])
                if ev["run_index"] != len(a.runs):
                    raise ValueError("replay diverged: run index out of order")
                seal = admission.sealed.get(ev["line_id"])
                if seal is None:
                    raise ValueError(f"replay diverged: run against unsealed line {ev['line_id']!r}")
                pinned = a._pinned_on_claim(seal, ev["claim_id"])
                tier = "A" if checker in pinned else "B"
                if tier != ev["tier"]:
                    raise ValueError("replay diverged: journaled tier is not the seal's")
                if ev["verdict"] not in RUN_VERDICTS:
                    raise ValueError(f"replay diverged: unknown verdict {ev['verdict']!r}")
                if checker not in admission.refuters:
                    raise ValueError(f"replay diverged: undeclared checker {checker!r}")
                if checker in a.discredited:
                    raise ValueError(f"replay diverged: run filed by discredited checker {checker!r}")
                if ev["artifact_hash"] != seal.artifact_hash:
                    raise ValueError("replay diverged: run hash differs from the seal")
                if tier == "A":
                    a._guard_run_seed(ev["nonce"], seal.artifact_hash, checker, ev["claim_id"], ev["seed"])
                if ev["verdict"] == "survived":
                    a._guard_audit_checker(seal.cls, checker, pinned)
                run = Run(index=ev["run_index"], line_id=ev["line_id"], cls=seal.cls,
                          claim_id=ev["claim_id"], checker=checker, tier=tier,
                          nonce=ev["nonce"], artifact_hash=ev["artifact_hash"], seed=ev["seed"],
                          verdict=ev["verdict"], witness_hash=ev["witness_hash"],
                          finder=ev["finder"], position=a._position())
                a.runs.append(run)
                a._events.append(JournalEvent(dict(ev)))
            elif t == "cal_replay":
                # A tampered journal is refused, never a crash: an index the
                # rebuilt ledger does not have is exactly what a deleted run
                # leaves behind.
                if not 0 <= ev["run_index"] < len(a.runs):
                    raise ValueError("replay diverged: replay of a run the journal does not contain")
                run = a.runs[ev["run_index"]]
                if run.checker in a.discredited:
                    raise ValueError("replay diverged: replay of a discredited checker")
                diverged = a._check_run_replay(run, ev["verdict"], ev["witness_hash"])
                if ev["diverged"] != diverged:
                    raise ValueError("replay diverged: journaled divergence flag is wrong")
                a._events.append(JournalEvent(dict(ev)))
                if diverged:
                    pending_discredit = (run.checker, ev["run_index"])
                else:
                    run.established = True
            elif t == "cal_adjudicate" and not 0 <= ev["run_index"] < len(a.runs):
                raise ValueError("replay diverged: adjudication of a run the journal does not contain")
            elif t == "cal_discredit":
                key = (ev["checker_id"], ev["checker_version"])
                if pending_discredit != (key, ev["run_index"]):
                    raise ValueError("replay diverged: discredit without its diverged replay")
                a.discredited.add(key)
                pending_discredit = None
                a._events.append(JournalEvent(dict(ev)))
            elif t == "cal_adjudicate":
                run = a.runs[ev["run_index"]]
                a._guard_adjudication(run, ev["actor"], ev["decision"], ev["reason"])
                run.adjudication = ev["decision"]
                a._events.append(JournalEvent(dict(ev)))
            elif t == "cal_exclude":
                a._guard_exclusion(ev["class"], tuple(ev["run_indices"]), ev["actor"],
                                   ev["reason"], as_of=ev.get("as_of"))
                a.exclusions.setdefault(ev["class"], set()).update(ev["run_indices"])
                a._events.append(JournalEvent(dict(ev)))
            elif t == "cal_install":
                pol = admission._policies.get(ev["policy_version"])
                if pol is None:
                    raise ValueError(f"replay diverged: admission never installed {ev['policy_version']!r}")
                a._guard_install_covers(pol, as_of=ev.get("as_of"))
                a._guard_install_bounded(pol)
                a._guard_install_measured(pol)   # one-sided: final registry, see docstring
                # The rebuild ADOPTS the budgets the journal installed rather
                # than carrying one supplied policy across the whole history:
                # demoted() gates CalOpen and CalSeal, so replaying a journal
                # under a budget it never ran under answers a different
                # question — silently. The supplied policy is the one in force
                # before the first install, exactly as Admission takes its
                # starting policies.
                journaled = ev.get("budgets")
                if journaled is not None:
                    a.policy = CalibrationPolicy(
                        {cls: CalibrationClass(e_max=b["e_max"], demotion_gate=b["demotion_gate"])
                         for cls, b in journaled.items()},
                        version=ev.get("calibration_policy_version", a.policy.version))
                    _require_coverage(pol, a.policy)                      # E9 on rebuild
                a._events.append(JournalEvent(dict(ev)))
            elif t == "cal_stamp":
                seal = admission.sealed.get(ev["line_id"])
                if seal is None:
                    raise ValueError(f"replay diverged: stamp for unsealed line {ev['line_id']!r}")
                # A stamp is bound to one seal and there is exactly one of it.
                # Adding or re-pointing a stamp is refused here; DELETING one
                # is not detectable — an unstamped seal is indistinguishable
                # from a line this authority never mediated — but it can only
                # lower standing to IR, never raise it (mediated(), C5).
                if ev.get("sealed_at") != seal.sealed_at:
                    raise ValueError("replay diverged: stamp is not bound to its seal")
                if a.sealed_stamp(ev["line_id"]) is not None:
                    raise ValueError("replay diverged: a second stamp for one seal")
                prior = [e for e in a._events if e.get("type") == "cal_stamp"]
                if prior and prior[-1]["sealed_at"] >= ev["sealed_at"]:
                    raise ValueError("replay diverged: stamps out of seal order")
                recomputed = {}
                for c in seal.claims:
                    for r in c.refuters:
                        recomputed[f"{r.id}@{r.version}"] = a.track_record(
                            r.id, r.version, seal.cls, as_of_seal=seal.sealed_at)
                if recomputed != dict(ev["track_records"]):
                    raise ValueError("replay diverged: stamp does not recompute from the ledger")
                if a._corpus_provenance(seal.cls, seal.generator,
                                        as_of=seal.sealed_at) != dict(ev["corpus_provenance"]):
                    raise ValueError("replay diverged: stamp provenance does not recompute")
                a._events.append(JournalEvent(dict(ev)))
            elif t == "cal_close":
                line = admission.lines.get(ev["line_id"])
                if line is None:
                    raise ValueError(f"replay diverged: close of an unknown line {ev['line_id']!r}")
                if ev.get("fault") == "E5" and not a.demoted(
                        ev["refuter_id"], ev["refuter_version"], line.cls, as_of=ev.get("as_of")):
                    raise ValueError("replay diverged: E5 close without a demotion at that point")
                a._events.append(JournalEvent(dict(ev)))
        if pending_discredit is not None:
            raise ValueError("replay diverged: diverged replay without its discredit event")
        if len(a._events) != len(cal_events):
            raise ValueError("replay diverged: event count mismatch")
        a._events = list(cal_events)
        return a
