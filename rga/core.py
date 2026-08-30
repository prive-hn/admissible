"""Refutation-gated admission — core machine (portable).

Composed over fcd.core.Enforcer. Six ideas:

1. A line is one FCD work item whose first k stages are write stages bound to
   one specialist. A SAMPLE is such a stage after FCD Pass, so I1 (executed
   model equals declared) holds of every sample by citation, not re-derivation
   (paper/PROOFS.md I1; fcd/core.py decide_pass). RGA reads FCD state and
   writes none of it (R11).
2. Claims and the refuters that attack them are pinned by class at Open,
   before any sample stage is attempted. A refuter authored by the generator
   cannot be pinned; a defect model's author is fixed by its first record and
   may be neither the generator nor the refuter's author (R3).
3. Power is a RECORD. Ledger mode accepts no scalar: the kernel counts kills
   from a ledger of per-defect verdicts. Bounded mode accepts a declared
   (epsilon, N) and carries 1 - (1 - epsilon)^N with both parameters in the
   seal, so the declaration is visible. Write-once per key (R2, V13).
4. A trial's verdict is refuted | survived | inconclusive. Only survived
   counts. Refuted and inconclusive close the line, published (V1, V3).
5. Concordance is agreement with the designated sample — stage 0, fixed
   before any sample exists and registered before the next stage is
   attempted — never a plurality. Below theta the line closes; it does not
   pick a winner (R4).
6. Seal is the only writer of S_R, requires FCD Accept (id in S), and carries
   the power it found, the concordance it measured, the sampling regime, and
   what it did not attack (R8). S_R is a subset of S.

Every guard the fault table (paper/RGA/INVARIANTS.md §5) names is a named
method, and tests/test_rga_mutation.py replaces each with a no-op and proves
the forbidden state becomes reachable. Transition-shape preconditions — a
transition on a line whose pc is not the one its row names, an unknown id, a
malformed verdict, an index outside the sample range — are inline raises
witnessed by tests/test_rga_invariants.py.
"""
from __future__ import annotations

import functools
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional
from fcd.core import Enforcer, _compare_regenerated, norm
from fcd.journal import JournalEvent, JournalValueError, normalize_journal

VERDICTS = frozenset({"refuted", "survived", "inconclusive"})
LEDGER_VERDICTS = frozenset({"killed", "survived", "inconclusive"})
MODES = frozenset({"ledger", "bounded"})
DISPOSITIONS = frozenset({"check_stage", "unreviewed"})
PUBLISHED_FAULTS = frozenset({"V1", "V2", "V3", "V4", "V5"})


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_seed(nonce: str, artifact_hash: str, refuter_id: str,
                refuter_version: str, claim_id: str) -> str:
    """R10. A seed exists only after the artifact hash and a post-artifact
    nonce exist; it is a pure function of them."""
    return sha256(f"{nonce}|{artifact_hash}|{refuter_id}|{refuter_version}|{claim_id}".encode())


# -- registry objects -------------------------------------------------------

@dataclass(frozen=True)
class Refuter:
    id: str
    version: str
    author: str                     # a declared identity string (B11)
    mode: str                       # "ledger" | "bounded"

    @property
    def key(self) -> tuple[str, str]:
        return (self.id, self.version)


@dataclass(frozen=True)
class DefectModel:
    hash: str
    author: str                     # fixed by the first record against hash (V13)


@dataclass(frozen=True)
class LedgerEntry:
    defect_id: str
    verdict: str                    # killed | survived | inconclusive


@dataclass(frozen=True)
class PowerRecord:
    refuter_id: str
    refuter_version: str
    mode: str
    defect_model_hash: Optional[str]
    kills: int = 0
    size: int = 0
    killed_ids: frozenset[str] = frozenset()
    epsilon: float = 0.0
    n: int = 0

    @property
    def power(self) -> float:
        if self.mode == "ledger":
            return self.kills / self.size if self.size else 0.0
        return 1.0 - (1.0 - self.epsilon) ** self.n


# -- policy ------------------------------------------------------------------

@dataclass(frozen=True)
class ClaimSpec:
    id: str
    spec_hash: str
    refuters: frozenset[tuple[str, str]]     # (refuter id, version)
    defect_model_hash: str


@dataclass(frozen=True)
class ClassAdmission:
    claims: tuple[ClaimSpec, ...]
    k: int
    theta: float
    p_min: float
    excluded: frozenset[str] = frozenset()   # categories the generator must not receive
    residual: tuple[tuple[str, str], ...] = ()   # (intent, disposition)


@dataclass(frozen=True)
class AdmissionPolicy:
    classes: dict[str, ClassAdmission]
    version: str = "r0"

    def __post_init__(self) -> None:
        for cls, c in self.classes.items():
            if c.k < 1:
                raise ValueError(f"class {cls!r}: k must be >= 1")
            if not (0.0 < c.theta <= 1.0):
                raise ValueError(f"class {cls!r}: theta must be in (0, 1]")
            if not (0.0 <= c.p_min <= 1.0):
                raise ValueError(f"class {cls!r}: p_min must be in [0, 1]")
            if not c.claims:
                raise ValueError(f"class {cls!r}: at least one claim is required")
            ids = [claim.id for claim in c.claims]
            if len(set(ids)) != len(ids):
                raise ValueError(f"class {cls!r}: duplicate claim ids")
            for claim in c.claims:
                if not claim.refuters:
                    raise ValueError(f"class {cls!r} claim {claim.id!r}: at least one refuter is required")
            for intent, disposition in c.residual:
                if disposition not in DISPOSITIONS:
                    raise ValueError(f"class {cls!r} residual {intent!r}: unknown disposition {disposition!r}")


# -- line objects ------------------------------------------------------------

@dataclass
class Sample:
    index: int
    artifact_hash: str
    nonce: str
    m_exec: str


@dataclass
class Trial:
    refuter_id: str
    refuter_version: str
    claim_id: str
    sample_index: int
    seed: str
    inputs_hash: str
    verdict: str
    witness_hash: str
    replays: int = 0

    @property
    def cell(self) -> tuple[str, str, str, int]:
        return (self.refuter_id, self.refuter_version, self.claim_id, self.sample_index)


@dataclass
class Line:
    id: str
    cls: str
    body: str
    generator: str
    m_decl: str
    fcd_policy_version: str
    sampling_hash: str
    policy_version: str
    claims: tuple[ClaimSpec, ...]
    k: int
    theta: float
    p_min: float
    excluded: frozenset[str]
    residual: tuple[tuple[str, str], ...]
    opened_at: int
    samples: list[Sample] = field(default_factory=list)
    trials: list[Trial] = field(default_factory=list)
    pc: str = "Open"                # Open | Sealed | Closed
    pub: bool = False
    fault: Optional[str] = None

    def pinned(self) -> set[tuple[str, str]]:
        out: set[tuple[str, str]] = set()
        for c in self.claims:
            out |= set(c.refuters)
        return out


# -- seal ---------------------------------------------------------------------

@dataclass(frozen=True)
class RefuterSeal:
    id: str
    version: str
    mode: str
    power: float
    defect_model_hash: Optional[str]
    kills: Optional[int]
    size: Optional[int]
    epsilon: Optional[float] = None
    n: Optional[int] = None


@dataclass(frozen=True)
class ClaimSeal:
    claim_id: str
    spec_hash: str
    refuters: tuple[RefuterSeal, ...]
    composite: float
    composition: str                # single | union | max
    agreeing: int
    k: int


@dataclass(frozen=True)
class Seal:
    line_id: str
    artifact_hash: str
    k: int
    theta: float
    p_min: float
    sampling_hash: str
    policy_version: str
    cls: str
    body: str
    generator: str
    m_exec: str
    fcd_policy_version: str
    claims: tuple[ClaimSeal, ...]
    power_min: float
    residual: tuple[tuple[str, str], ...]
    sealed_at: int


_RESTORED_STATE = (
    "policy", "_events", "lines", "sealed", "refuters", "declared_at",
    "refused", "refused_at", "power", "defect_ids", "defect_authors",
    "_policies",
)


def _journal_atomic(*_state_fields):
    """Rebuild pre-call RGA state only on an unexpected journal failure."""

    def decorate(method):
        @functools.wraps(method)
        def wrapped(self, *args, **kwargs):
            event_count = len(self._events)
            policies = tuple(
                policy for version, policy in self._policies.items()
                if version != self.policy.version) + (self.policy,)
            try:
                return method(self, *args, **kwargs)
            except Exception as exc:
                if (isinstance(exc, ValueError)
                        and not isinstance(exc, JournalValueError)
                        and len(self._events) > event_count):
                    raise
                rebuilt = Admission.from_events(
                    tuple(self._events[:event_count]), self.fcd, *policies,
                    clock=lambda: 0.0, nonce=self.nonce)
                for name in _RESTORED_STATE:
                    setattr(self, name, getattr(rebuilt, name))
                if isinstance(exc, RecursionError):
                    raise JournalValueError(
                        "journal event must contain canonical JSON values") from None
                raise
        return wrapped
    return decorate


# -- the machine ---------------------------------------------------------------

class Admission:
    """The RGA machine. Reads an fcd.core.Enforcer; never writes it.

    The caller provides the clock and the nonce source (injectable for
    deterministic tests; replay reads nonces from the journal and keeps the
    injected source for live use afterwards)."""

    def __init__(self, fcd: Enforcer, policy: AdmissionPolicy,
                 clock: Callable[[], float] = lambda: 0.0,
                 nonce: Callable[[], str] = lambda: secrets.token_hex(16)) -> None:
        self.fcd = fcd
        self.policy = policy
        self.clock = clock
        self.nonce = nonce
        self._events: list[JournalEvent] = []
        self.lines: dict[str, Line] = {}
        self.sealed: dict[str, Seal] = {}           # S_R
        self.refuters: dict[tuple[str, str], Refuter] = {}
        self.declared_at: dict[tuple[str, str], int] = {}
        self.refused: set[tuple[str, str]] = set()
        self.refused_at: dict[tuple[str, str], int] = {}
        self.power: dict[tuple[str, str, Optional[str]], PowerRecord] = {}
        self.defect_ids: dict[str, frozenset[str]] = {}   # D hash -> fixed ledger id-set
        self.defect_authors: dict[str, str] = {}          # D hash -> fixed author (V13)
        self._policies: dict[str, AdmissionPolicy] = {policy.version: policy}

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

    # -- policy versions -----------------------------------------------------

    def install(self, policy: AdmissionPolicy) -> None:
        existing = self._policies.get(policy.version)
        if existing is not None and existing != policy:
            raise ValueError(f"admission policy version {policy.version!r} already installed with different content")
        self._policies[policy.version] = policy
        self.policy = policy

    def policy_for(self, item_id: str) -> AdmissionPolicy:
        return self._policies[self.lines[item_id].policy_version]

    # -- helpers --------------------------------------------------------------

    def _line(self, item_id: str) -> Line:
        return self.lines[item_id]

    def _refuter(self, refuter_id: str, version: str) -> Refuter:
        key = (refuter_id, version)
        if key not in self.refuters:
            raise ValueError(f"refuter {key!r} not declared")
        return self.refuters[key]

    def _claim(self, line: Line, claim_id: str) -> ClaimSpec:
        for c in line.claims:
            if c.id == claim_id:
                return c
        raise ValueError(f"claim {claim_id!r} not pinned on line {line.id!r}")  # V8

    def _record_for(self, r: Refuter, claim: ClaimSpec) -> Optional[PowerRecord]:
        if r.mode == "ledger":
            return self.power.get((r.id, r.version, claim.defect_model_hash))
        return self.power.get((r.id, r.version, None))

    # -- registry transitions --------------------------------------------------

    @_journal_atomic("refuters", "declared_at")
    def declare(self, r: Refuter) -> None:
        if r.key in self.refuters:
            raise ValueError(f"refuter {r.key!r} already declared")
        if not r.author:
            raise ValueError("refuter requires an author")
        if r.mode not in MODES:
            raise ValueError(f"unknown refuter mode {r.mode!r}")
        self.refuters[r.key] = r
        self.declared_at[r.key] = self._position()
        self._emit(type="rga_declare", refuter_id=r.id, refuter_version=r.version,
                   author=r.author, mode=r.mode)

    @_journal_atomic("power", "defect_ids", "defect_authors")
    def measure(self, refuter_id: str, version: str, defect_model: DefectModel,
                ledger: Iterable[LedgerEntry]) -> PowerRecord:
        """Power from a ledger. The kernel counts; nothing is declared."""
        r = self._refuter(refuter_id, version)
        if r.mode != "ledger":
            raise ValueError("measure requires a ledger-mode refuter")
        self._guard_not_refused(r.key)                                   # V4
        entries = tuple(ledger)
        self._guard_power_once(r, defect_model, entries)                 # V13
        self._guard_model_author_fixed(defect_model)                     # V13/V14
        self._guard_independent_model(r, defect_model)                   # V14 (refuter side)
        killed = frozenset(e.defect_id for e in entries if e.verdict == "killed")
        rec = PowerRecord(r.id, r.version, "ledger", defect_model.hash,
                          kills=len(killed), size=len(entries), killed_ids=killed)
        self.power[(r.id, r.version, defect_model.hash)] = rec
        self.defect_ids.setdefault(defect_model.hash, frozenset(e.defect_id for e in entries))
        self.defect_authors.setdefault(defect_model.hash, defect_model.author)
        self._emit(type="rga_measure", refuter_id=r.id, refuter_version=r.version,
                   defect_model_hash=defect_model.hash, defect_model_author=defect_model.author,
                   ledger=[{"defect_id": e.defect_id, "verdict": e.verdict} for e in entries],
                   kills=rec.kills, size=rec.size, power=rec.power)
        return rec

    @_journal_atomic("power")
    def bound(self, refuter_id: str, version: str, epsilon: float, n: int) -> PowerRecord:
        """Power from a declared (epsilon, N): 1 - (1 - epsilon)^N, computed
        here, with both parameters carried into the seal. The figure is as
        declared as epsilon is; the seal labels the mode so a reader sees it."""
        r = self._refuter(refuter_id, version)
        if r.mode != "bounded":
            raise ValueError("bound requires a bounded-mode refuter")
        self._guard_not_refused(r.key)                                   # V4
        self._guard_bound_once(r)                                        # V13
        if not (0.0 < epsilon <= 1.0) or n < 1:
            raise ValueError("bound requires 0 < epsilon <= 1 and N >= 1")
        rec = PowerRecord(r.id, r.version, "bounded", None, epsilon=epsilon, n=n)
        self.power[(r.id, r.version, None)] = rec
        self._emit(type="rga_bound", refuter_id=r.id, refuter_version=r.version,
                   epsilon=epsilon, n=n, power=rec.power)
        return rec

    # -- line transitions --------------------------------------------------------

    @_journal_atomic("line")
    def open(self, item_id: str, generator: str, sampling_hash: str) -> Line:
        """The public row takes no journal position: the kernel reads its own
        (a caller-supplied position would bypass the before-generation guard).
        Replay supplies the recorded value through _open."""
        return self._open(item_id, generator, sampling_hash, self.fcd._position())

    def _open(self, item_id: str, generator: str, sampling_hash: str, fpos: int) -> Line:
        if item_id in self.lines:
            raise ValueError(f"line {item_id!r} already open")
        if item_id not in self.fcd.items:
            raise ValueError(f"no FCD work item {item_id!r}")
        item = self.fcd.items[item_id]
        if item.cls not in self.policy.classes:
            raise ValueError(f"class {item.cls!r} has no admission policy")
        spec = self.policy.classes[item.cls]
        fpol = self.fcd.policy_for(item_id)
        if generator not in fpol.pi_star(item.cls, "write", set()):
            raise ValueError("generator not in pi* of the pinned FCD policy")
        if len(item.stages) < spec.k or any(s.kind != "write" for s in item.stages[:spec.k]):
            raise ValueError(f"FCD class must have {spec.k} leading write stages")
        self._guard_open_before_generation(item_id, spec.k, fpos)       # V8 (temporal)
        position = self._position()
        self._guard_pinned_before_open(spec, generator)                  # V14
        line = Line(
            id=item_id, cls=item.cls, body=item.body, generator=generator,
            m_decl=fpol.phi[generator], fcd_policy_version=item.policy_version,
            sampling_hash=sampling_hash, policy_version=self.policy.version,
            claims=spec.claims, k=spec.k, theta=spec.theta, p_min=spec.p_min,
            excluded=spec.excluded, residual=spec.residual, opened_at=position,
        )
        self.lines[item_id] = line
        self._emit(type="rga_open", work_item_id=item_id, **{"class": item.cls},
                   body_hash=item.body, generator=generator, declared_model=line.m_decl,
                   fcd_policy_version=item.policy_version, sampling_hash=sampling_hash,
                   policy_version=self.policy.version, k=spec.k, theta=spec.theta,
                   p_min=spec.p_min, claims=[c.id for c in spec.claims],
                   refuters=sorted(line.pinned()), fcd_position=fpos)
        return line

    @_journal_atomic("line")
    def sample(self, item_id: str, artifact: bytes, package_categories: Iterable[str],
               sampling_hash: str) -> Sample:
        """Register FCD stage |samples| as a sample. The kernel hashes the bytes
        it is handed (single-holder) and draws the post-artifact nonce (B9)
        after every guard has passed, so a refused sample consumes nothing."""
        return self._register_sample(item_id, sha256(artifact), frozenset(package_categories),
                                     sampling_hash, None, None)

    def _register_sample(self, item_id: str, artifact_hash: str,
                         package_categories: frozenset[str], sampling_hash: str,
                         nonce: Optional[str], fcd_position: Optional[int]) -> Sample:
        line = self._line(item_id)
        if line.pc != "Open":
            raise ValueError("sample requires pc=Open")
        i = len(line.samples)
        self._guard_sample_count(line, i)                                  # V13
        fpos = self.fcd._position() if fcd_position is None else fcd_position
        stage = self.fcd.items[item_id].stages[i]
        self._guard_sample_stage(line, stage)                              # V6
        self._guard_sample_package(line, package_categories, sampling_hash)  # V7 (+ bind key)
        self._guard_sample_order(line, i, fpos)                            # V8 (interleaving)
        if nonce is None:
            nonce = self.nonce()
        s = Sample(index=i, artifact_hash=artifact_hash, nonce=nonce, m_exec=stage.m_exec)  # type: ignore[arg-type]
        line.samples.append(s)
        self._emit(type="rga_sample", work_item_id=item_id, sample_index=i,
                   stage_id=f"{item_id}.{i}", artifact_hash=artifact_hash, nonce=nonce,
                   executed_model=stage.m_exec, declared_model=stage.m_decl,
                   package_categories=sorted(package_categories), sampling_hash=sampling_hash,
                   fcd_position=fpos)
        return s

    def seed_for(self, item_id: str, sample_index: int, refuter_id: str,
                 refuter_version: str, claim_id: str) -> str:
        line = self._line(item_id)
        if not 0 <= sample_index < len(line.samples):
            raise ValueError("no such sample; a seed exists only after its artifact")  # R10
        s = line.samples[sample_index]
        return derive_seed(s.nonce, s.artifact_hash, refuter_id, refuter_version, claim_id)

    @_journal_atomic("line")
    def trial(self, item_id: str, refuter_id: str, refuter_version: str, claim_id: str,
              sample_index: int, seed: str, inputs_hash: str, verdict: str,
              witness_hash: str) -> Trial:
        line = self._line(item_id)
        if line.pc != "Open":
            raise ValueError("trial requires pc=Open")
        if verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {verdict!r}")
        if not 0 <= sample_index < len(line.samples):
            raise ValueError("no such sample")
        claim = self._claim(line, claim_id)                                 # V8
        r = self._refuter(refuter_id, refuter_version)
        self._guard_trial_pinned(line, claim, r)                             # V8
        self._guard_trial_seed(line, sample_index, r, claim, seed)           # V9
        self._guard_trial_once(line, (r.id, r.version, claim.id, sample_index))  # V13
        t = Trial(r.id, r.version, claim.id, sample_index, seed, inputs_hash, verdict, witness_hash)
        line.trials.append(t)
        self._emit(type="rga_trial", work_item_id=item_id, trial_index=len(line.trials) - 1,
                   refuter_id=r.id, refuter_version=r.version, claim_id=claim.id,
                   sample_index=sample_index, seed=seed, inputs_hash=inputs_hash,
                   verdict=verdict, witness_hash=witness_hash)
        self._check_refuted(line, t)                                         # V1
        self._check_inconclusive(line, t)                                    # V3
        return t

    @_journal_atomic("all_lines", "refused", "refused_at")
    def replay(self, item_id: str, trial_index: int, verdict: str, witness_hash: str) -> None:
        """Check 2 of B2: a falsifier. Divergence refuses the refuter for
        every line, monotonically. Agreement counts one replay. Enabled in any
        line state: a post-seal audit replay that diverges still refuses the
        refuter, which is what tainted() reports; the replays counter is not
        part of any seal."""
        line = self._line(item_id)
        t = line.trials[trial_index]
        key = (t.refuter_id, t.refuter_version)
        self._guard_not_refused(key)                                         # V4
        self._guard_replay_verdict(verdict)                                  # V4
        diverged = self._check_replay(t, verdict, witness_hash)              # V4
        self._emit(type="rga_replay", work_item_id=item_id, trial_index=trial_index,
                   refuter_id=t.refuter_id, refuter_version=t.refuter_version,
                   verdict=verdict, witness_hash=witness_hash, diverged=diverged)
        if diverged:
            self._refuse(key, f"replay of {item_id}#{trial_index} diverged")
        else:
            t.replays += 1

    def _guard_replay_verdict(self, verdict: str) -> None:
        """A replay may only speak the trial vocabulary: an out-of-enum
        verdict would enter the journal as an rga_replay event no schema
        knows, and always 'diverge' — refusing a refuter over a typo."""
        if verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {verdict!r}")

    def _refuse(self, key: tuple[str, str], reason: str) -> None:
        self.refused.add(key)
        self.refused_at[key] = self._position()
        self._emit(type="rga_refuse", refuter_id=key[0], refuter_version=key[1], reason=reason)
        for other in self.lines.values():
            if other.pc == "Open" and key in other.pinned():
                self._close(other, "V4",
                            reason=f"pinned refuter {key[0]}@{key[1]} was refused: {reason}")

    @_journal_atomic("line", "sealed_item")
    def seal(self, item_id: str) -> Seal:
        """The only writer of S_R."""
        line = self._line(item_id)
        if line.pc != "Open":
            raise ValueError("seal requires pc=Open")
        self._guard_seal_complete(line)                                       # V10, survival half of V1/V3
        self._guard_seal_replayed(line)                                       # V11
        self._guard_seal_measured(line)                                       # V12
        self._guard_seal_independent(line)                                    # V14
        self._guard_seal_accepted(line)                                       # V15
        self._guard_seal_residual(line)                                       # V15
        claims = tuple(self._claim_seal(line, c) for c in line.claims)
        if not self._check_concordance(line, claims):                         # V2
            return self._closed_seal_attempt(line)
        power_min = min(c.composite for c in claims)
        if not self._check_power_floor(line, power_min):                      # V5
            return self._closed_seal_attempt(line)
        designated = line.samples[0]
        s = Seal(
            line_id=item_id, artifact_hash=designated.artifact_hash, k=line.k,
            theta=line.theta, p_min=line.p_min, sampling_hash=line.sampling_hash,
            policy_version=line.policy_version, cls=line.cls, body=line.body,
            generator=line.generator, m_exec=designated.m_exec,
            fcd_policy_version=line.fcd_policy_version, claims=claims, power_min=power_min,
            residual=tuple(line.residual), sealed_at=self._position(),
        )
        self.sealed[item_id] = s
        line.pc = "Sealed"
        self._emit(type="rga_seal", work_item_id=item_id, **{"class": line.cls},
                   body_hash=line.body, artifact_hash=s.artifact_hash,
                   k=s.k, theta=s.theta, p_min=s.p_min, power_min=s.power_min,
                   sampling_hash=s.sampling_hash, policy_version=s.policy_version,
                   fcd_policy_version=s.fcd_policy_version,
                   generator=s.generator, executed_model=s.m_exec,
                   claims=[{"claim_id": c.claim_id, "spec_hash": c.spec_hash,
                            "composite": c.composite, "composition": c.composition,
                            "agreeing": c.agreeing, "k": c.k,
                            "refuters": [{"id": r.id, "version": r.version, "mode": r.mode,
                                          "power": r.power, "defect_model_hash": r.defect_model_hash,
                                          "kills": r.kills, "size": r.size,
                                          "epsilon": r.epsilon, "n": r.n} for r in c.refuters]}
                           for c in claims],
                   residual=[list(x) for x in s.residual])
        return s

    def _closed_seal_attempt(self, line: Line) -> Seal:
        raise ValueError(f"line {line.id!r} closed with {line.fault}")

    @_journal_atomic("line")
    def close(self, item_id: str, reason: str = "stop") -> None:
        """Operator close. Published. No fault code: nothing was observed."""
        line = self._line(item_id)
        if line.pc != "Open":
            raise ValueError("close requires pc=Open")
        self._close(line, None, reason=reason)

    def _close(self, line: Line, fault: Optional[str], reason: str = "", **extra) -> None:
        line.pc = "Closed"
        line.pub = True
        line.fault = fault
        self._emit(type="rga_close", work_item_id=line.id, result="fail_closed",
                   fault=fault, reason=reason, next="ask", **extra)

    def sealed_put(self, item_id: str) -> None:
        """Deliberately forbidden (V15). Calling it is a bug, not a feature."""
        raise PermissionError("S_R admits only via Seal")

    # -- queries (pure) -------------------------------------------------------------

    def is_sealed(self, item_id: str) -> bool:
        """Membership in S_R. For promotion and DAG edges prefer admissible()."""
        return item_id in self.sealed

    def tainted(self, item_id: str) -> bool:
        """A sealed line relied on a refuter refused after sealing. A query, not a write."""
        s = self.sealed.get(item_id)
        if s is None:
            return False
        for c in s.claims:
            for r in c.refuters:
                key = (r.id, r.version)
                if key in self.refused and self.refused_at[key] >= s.sealed_at:
                    return True
        return False

    def admissible(self, item_id: str) -> bool:
        """Sealed and not tainted. What a promotion predicate should read."""
        return self.is_sealed(item_id) and not self.tainted(item_id)

    def check_dependencies(self, deps: Iterable[str], floor: float) -> None:
        """Power-aware DAG gate. Call before fcd.open(..., depends_on=deps).
        Refuses an unsealed, underpowered or tainted dependency."""
        for dep in deps:
            if dep not in self.sealed:
                raise ValueError(f"dependency {dep!r} not in S_R (sealed artifacts)")
            if self.sealed[dep].power_min < floor:
                raise ValueError(f"dependency {dep!r} sealed at power {self.sealed[dep].power_min:.3f} < floor {floor:.3f}")
            if self.tainted(dep):
                raise ValueError(f"dependency {dep!r} relies on a refuter refused after sealing")

    # -- guards: each is named by the fault table ------------------------------------

    def _guard_not_refused(self, key: tuple[str, str]) -> None:
        """V4 at Measure, Bound and Replay. (At Trial and Seal a refused
        refuter is unreachable: refusal closes every open line pinning it and
        a refused refuter cannot be pinned at Open.)"""
        if key in self.refused:
            raise ValueError(f"refuter {key!r} is refused")

    def _guard_pinned_before_open(self, spec: ClassAdmission, generator: str) -> None:
        """V14 at Open: every pinned refuter is declared (hence, by the
        append-only journal, declared strictly before this position), not
        refused, and not authored by the generator; a defect model already
        recorded is not authored by the generator."""
        for claim in spec.claims:
            for key in claim.refuters:
                if key not in self.refuters:
                    raise ValueError(f"pinned refuter {key!r} is not declared")
                if key in self.refused:
                    raise ValueError(f"pinned refuter {key!r} is refused")
                if self.refuters[key].author == generator:
                    raise ValueError(f"refuter {key!r} is authored by the generator")
            if self.defect_authors.get(claim.defect_model_hash) == generator:
                raise ValueError(f"defect model {claim.defect_model_hash!r} is authored by the generator")

    def _guard_open_before_generation(self, item_id: str, k: int, fcd_position: int) -> None:
        """V8, temporal half of R3: no sample stage was attempted before this
        line opened. FCD emits a `stage` event on every Admit (fcd/core.py
        admit), so the FCD journal up to the recorded position is the witness;
        reading it rather than current state keeps replay faithful."""
        first = {f"{item_id}.{i}" for i in range(k)}
        for ev in self.fcd._events[:fcd_position]:
            if ev.get("type") == "stage" and ev.get("stage_id") in first:
                raise ValueError("line must open before any sample stage is attempted")

    def _guard_sample_count(self, line: Line, i: int) -> None:
        """V13. At most k samples."""
        if i >= line.k:
            raise ValueError(f"line already has k={line.k} samples")

    def _guard_sample_stage(self, line: Line, stage) -> None:
        """V6. The stage is FCD-Passed and bound to the line's generator.
        Write-kind and declared-model equality hold by construction: Open
        requires the first k stages to be write stages, and both m_decl values
        come from phi(generator) under the policy the item pinned."""
        if stage.pc != "Passed":
            raise ValueError("sample requires FCD pc=Passed (I1)")
        if stage.a != line.generator:
            raise ValueError("sample bound to a different specialist than the line")

    def _guard_sample_package(self, line: Line, categories: frozenset[str], sampling_hash: str) -> None:
        """V7 and the sampling half of the bind key."""
        leaked = categories & line.excluded
        if leaked:
            raise ValueError(f"generator package contained refuter categories {sorted(leaked)}")
        if sampling_hash != line.sampling_hash:
            raise ValueError("sampling configuration differs from the line's bind key")

    def _guard_sample_order(self, line: Line, i: int, fcd_position: int) -> None:
        """V8, interleaving: sample i is registered before any later sample
        stage is attempted, so bytes cannot be assigned to slots after seeing
        the whole batch. Witnessed by the FCD journal up to the recorded
        position, as the Open guard is."""
        later = {f"{line.id}.{j}" for j in range(i + 1, line.k)}
        for ev in self.fcd._events[:fcd_position]:
            if ev.get("type") == "stage" and ev.get("stage_id") in later:
                raise ValueError(f"sample {i} must be registered before stage {ev.get('stage_id')} is attempted")

    def _guard_trial_pinned(self, line: Line, claim: ClaimSpec, r: Refuter) -> None:
        """V8. (A refused refuter here is unreachable: see _guard_not_refused.)"""
        if r.key not in claim.refuters:
            raise ValueError(f"refuter {r.key!r} not pinned to claim {claim.id!r}")

    def _guard_trial_seed(self, line: Line, sample_index: int, r: Refuter, claim: ClaimSpec, seed: str) -> None:
        """V9. The trial's seed is the kernel-derived seed for this cell."""
        s = line.samples[sample_index]
        if seed != derive_seed(s.nonce, s.artifact_hash, r.id, r.version, claim.id):
            raise ValueError("trial seed is not the kernel-derived seed for this sample")

    def _guard_trial_once(self, line: Line, cell: tuple[str, str, str, int]) -> None:
        """V13. At most one trial per (refuter, claim, sample)."""
        if any(t.cell == cell for t in line.trials):
            raise ValueError("trial already recorded for this (refuter, claim, sample)")

    def _guard_power_once(self, r: Refuter, defect_model: DefectModel, entries: tuple[LedgerEntry, ...]) -> None:
        """V13. Write-once per (refuter, D); a D's id-set is fixed by its first record."""
        if (r.id, r.version, defect_model.hash) in self.power:
            raise ValueError("power record already written for this (refuter, defect model)")
        if not entries:
            raise ValueError("ledger is empty")
        ids = [e.defect_id for e in entries]
        if len(set(ids)) != len(ids):
            raise ValueError("ledger has duplicate defect ids")
        for e in entries:
            if e.verdict not in LEDGER_VERDICTS:
                raise ValueError(f"unknown ledger verdict {e.verdict!r}")
        fixed = self.defect_ids.get(defect_model.hash)
        if fixed is not None and fixed != frozenset(ids):
            raise ValueError("ledger id-set differs from the defect model's first record")

    def _guard_bound_once(self, r: Refuter) -> None:
        """V13. Write-once per bounded refuter."""
        if (r.id, r.version, None) in self.power:
            raise ValueError("power record already written for this refuter")

    def _guard_model_author_fixed(self, defect_model: DefectModel) -> None:
        """V13/V14. A defect model's author is fixed by its first record, so
        Open and Seal read one value and cannot disagree."""
        fixed = self.defect_authors.get(defect_model.hash)
        if fixed is not None and fixed != defect_model.author:
            raise ValueError("defect model author differs from the defect model's first record")

    def _guard_independent_model(self, r: Refuter, defect_model: DefectModel) -> None:
        """V14, refuter side: the defect model is not authored by the refuter's author."""
        if defect_model.author == r.author:
            raise ValueError("defect model authored by the refuter's author")

    def _guard_seal_complete(self, line: Line) -> None:
        """V10 and the survival half of V1/V3: k samples and a surviving trial in every cell."""
        if len(line.samples) != line.k:
            raise ValueError(f"seal requires k={line.k} samples, have {len(line.samples)}")
        have = {t.cell: t for t in line.trials}
        for claim in line.claims:
            for key in claim.refuters:
                for i in range(line.k):
                    t = have.get((key[0], key[1], claim.id, i))
                    if t is None:
                        raise ValueError(f"no trial for ({key}, {claim.id!r}, sample {i})")
                    if t.verdict != "survived":
                        raise ValueError(f"trial ({key}, {claim.id!r}, sample {i}) did not survive")

    def _guard_seal_replayed(self, line: Line) -> None:
        """V11. Every refuter used has an identical replay on this line."""
        for key in line.pinned():
            if not any(t.replays >= 1 for t in line.trials if (t.refuter_id, t.refuter_version) == key):
                raise ValueError(f"refuter {key!r} has no consistent replay on this line")

    def _guard_seal_measured(self, line: Line) -> None:
        """V12. Every refuter has a power record against the claim's defect model."""
        for claim in line.claims:
            for key in claim.refuters:
                r = self.refuters[key]
                if self._record_for(r, claim) is None:
                    raise ValueError(f"refuter {key!r} has no power record for claim {claim.id!r}")

    def _guard_seal_independent(self, line: Line) -> None:
        """V14 at Seal: a defect model first recorded after Open is still not
        the generator's. (The refuter-author side is unreachable here: a record
        by a refuter whose author equals the model's author is refused at
        Measure, and Seal requires the record.)"""
        for claim in line.claims:
            if self.defect_authors.get(claim.defect_model_hash) == line.generator:
                raise ValueError(f"defect model {claim.defect_model_hash!r} authored by the generator")

    def _guard_seal_accepted(self, line: Line) -> None:
        """V15. Seal implies FCD Accept: id in S."""
        if line.id not in self.fcd.store:
            raise ValueError("seal requires FCD Accept (id in S)")

    def _guard_seal_residual(self, line: Line) -> None:
        """V15. A residual disposition of check_stage is derived from FCD
        state, never taken on trust: some FCD check stage of this item Passed."""
        item = self.fcd.items[line.id]
        reviewed = any(s.kind == "check" and s.pc == "Passed" for s in item.stages)
        for intent, disposition in line.residual:
            if disposition == "check_stage" and not reviewed:
                raise ValueError(f"residual {intent!r} claims check_stage but no FCD check stage Passed")

    # -- observed-fault checks: each publishes a Close ------------------------------

    def _check_refuted(self, line: Line, t: Trial) -> None:
        """V1."""
        if t.verdict == "refuted":
            self._close(line, "V1", reason=f"{t.refuter_id}@{t.refuter_version} refuted {t.claim_id} on sample {t.sample_index}")

    def _check_inconclusive(self, line: Line, t: Trial) -> None:
        """V3."""
        if t.verdict == "inconclusive":
            self._close(line, "V3", reason=f"{t.refuter_id}@{t.refuter_version} inconclusive on {t.claim_id} sample {t.sample_index}")

    def _check_replay(self, t: Trial, verdict: str, witness_hash: str) -> bool:
        """V4. True iff the replay diverged from the recorded outcome."""
        return (verdict, witness_hash) != (t.verdict, t.witness_hash)

    def _check_concordance(self, line: Line, claims: tuple[ClaimSeal, ...]) -> bool:
        """V2. Every claim agrees with the designated sample at >= theta.
        miss_observed names exactly the refuters whose own witnesses differ
        from their sample-0 witness on a below-theta claim."""
        bad = [c for c in claims if c.agreeing / c.k < line.theta]
        if bad:
            misses: set[tuple[str, str]] = set()
            for c in bad:
                spec = self._claim(line, c.claim_id)
                for key in spec.refuters:
                    w0 = self._witness_of(line, spec, key, 0)
                    if any(self._witness_of(line, spec, key, i) != w0 for i in range(1, line.k)):
                        misses.add(key)
            self._close(line, "V2", reason="discord with designated sample",
                        concordance=[{"claim_id": c.claim_id, "agreeing": c.agreeing, "k": c.k} for c in claims],
                        miss_observed=[list(m) for m in sorted(misses)])
            return False
        return True

    def _check_power_floor(self, line: Line, power_min: float) -> bool:
        """V5."""
        if power_min < line.p_min:
            self._close(line, "V5", reason=f"power_min {power_min:.4f} < p_min {line.p_min:.4f}",
                        power_min=power_min)
            return False
        return True

    # -- seal computation -----------------------------------------------------------

    def _witness_of(self, line: Line, claim: ClaimSpec, key: tuple[str, str], i: int) -> Optional[str]:
        for t in line.trials:
            if (t.refuter_id, t.refuter_version) == key and t.claim_id == claim.id and t.sample_index == i:
                return t.witness_hash
        return None

    def _witness_vector(self, line: Line, claim: ClaimSpec, i: int) -> tuple[tuple[str, str, str], ...]:
        return tuple(sorted((t.refuter_id, t.refuter_version, t.witness_hash)
                            for t in line.trials if t.claim_id == claim.id and t.sample_index == i))

    def _claim_seal(self, line: Line, claim: ClaimSpec) -> ClaimSeal:
        v0 = self._witness_vector(line, claim, 0)
        agreeing = sum(1 for i in range(line.k) if self._witness_vector(line, claim, i) == v0)
        refs: list[RefuterSeal] = []
        ledger_records: list[PowerRecord] = []
        bounded_powers: list[float] = []
        for key in sorted(claim.refuters):
            r = self.refuters[key]
            rec = self._record_for(r, claim)
            if rec is None:
                # Unreachable past _guard_seal_measured (V12). Represented, not
                # substituted: an unmeasured refuter carries power 0 and no ledger.
                refs.append(RefuterSeal(r.id, r.version, r.mode, 0.0, None, None, None))
                continue
            if rec.mode == "ledger":
                ledger_records.append(rec)
                refs.append(RefuterSeal(r.id, r.version, "ledger", rec.power, rec.defect_model_hash, rec.kills, rec.size))
            else:
                bounded_powers.append(rec.power)
                refs.append(RefuterSeal(r.id, r.version, "bounded", rec.power, None, None, None,
                                        epsilon=rec.epsilon, n=rec.n))
        union_power = 0.0
        if ledger_records:
            size = ledger_records[0].size
            killed: frozenset[str] = frozenset()
            for rec in ledger_records:
                killed |= rec.killed_ids
            union_power = len(killed) / size if size else 0.0
        composite = max([union_power] + bounded_powers) if (ledger_records or bounded_powers) else 0.0
        if len(refs) == 1:
            composition = "single"
        elif ledger_records and not bounded_powers and len(ledger_records) >= 2:
            composition = "union"
        else:
            composition = "max"
        return ClaimSeal(claim.id, claim.spec_hash, tuple(refs), composite, composition, agreeing, line.k)

    # -- replay ----------------------------------------------------------------------

    @classmethod
    def from_events(cls, journal: object, fcd: Enforcer,
                    *policies: AdmissionPolicy,
                    clock: Callable[[], float] = lambda: 0.0,
                    nonce: Callable[[], str] = lambda: secrets.token_hex(16)) -> "Admission":
        """Deterministic rebuild from an append-only journal.

        The FCD enforcer must already be rebuilt (fcd.core.Enforcer.from_events).
        Nonces and journal positions are read from the journal, never redrawn;
        the injected nonce source serves live use after the rebuild. V1/V3
        closes are regenerated by re-driving rga_trial, V4 by rga_replay, V2/V5
        by re-driving the failed seal attempt the rga_close records — which
        must refuse with the journaled fault; operator closes are re-driven as
        close(). The rebuilt line is cross-checked against the rga_open event's
        recorded parameters, so a supplied policy that differs from the one the
        journal ran under is an error, never a silent substitution."""
        if not policies:
            raise ValueError("from_events requires at least one AdmissionPolicy")
        events = normalize_journal(journal)
        # `*policies` is ordered oldest-first: the LAST supplied policy is the
        # live admission policy after rebuild. Historical `rga_open` events
        # temporarily select their pinned version only during re-drive (below);
        # the live policy is restored before returning so a new line opened
        # after recovery uses the current version, not whatever the last
        # historical Open pinned.
        a = cls(fcd, policies[0], clock=clock, nonce=nonce)
        for p in policies[1:]:
            a.install(p)
        current = a.policy
        # Re-driven transitions emit into a.events so journal positions
        # (declared_at, opened_at, sealed_at) advance exactly as they did live;
        # the journal then replaces those regenerated events verbatim.
        rga_events = tuple(ev for ev in events
                           if type(ev.get("type")) is str
                           and ev["type"].startswith("rga_"))
        for ev in rga_events:
            t = ev["type"]
            if t == "rga_declare":
                a.declare(Refuter(ev["refuter_id"], ev["refuter_version"], ev["author"], ev["mode"]))
            elif t == "rga_measure":
                a.measure(ev["refuter_id"], ev["refuter_version"],
                          DefectModel(ev["defect_model_hash"], ev["defect_model_author"]),
                          [LedgerEntry(e["defect_id"], e["verdict"]) for e in ev["ledger"]])
            elif t == "rga_bound":
                a.bound(ev["refuter_id"], ev["refuter_version"], ev["epsilon"], ev["n"])
            elif t == "rga_open":
                pv = ev["policy_version"]
                if pv not in a._policies:
                    raise ValueError(f"journal references unknown admission policy version {pv!r}")
                if a.policy.version != pv:
                    a.install(a._policies[pv])
                if not 0 <= ev["fcd_position"] <= fcd._position():
                    raise ValueError("journal fcd_position out of range")
                line = a._open(ev["work_item_id"], ev["generator"], ev["sampling_hash"],
                               ev["fcd_position"])
                if (line.k != ev["k"] or line.theta != ev["theta"] or line.p_min != ev["p_min"]
                        or [c.id for c in line.claims] != list(ev["claims"])
                        or sorted(line.pinned()) != [tuple(x) for x in ev["refuters"]]):
                    raise ValueError("replay diverged: supplied policy differs from the journaled line")
            elif t == "rga_sample":
                if not 0 <= ev["fcd_position"] <= fcd._position():
                    raise ValueError("journal fcd_position out of range")
                a._register_sample(ev["work_item_id"], ev["artifact_hash"],
                                   frozenset(ev["package_categories"]), ev["sampling_hash"],
                                   ev["nonce"], ev["fcd_position"])
            elif t == "rga_trial":
                a.trial(ev["work_item_id"], ev["refuter_id"], ev["refuter_version"], ev["claim_id"],
                        ev["sample_index"], ev["seed"], ev["inputs_hash"], ev["verdict"], ev["witness_hash"])
            elif t == "rga_replay":
                a.replay(ev["work_item_id"], ev["trial_index"], ev["verdict"], ev["witness_hash"])
            elif t == "rga_refuse":
                pass  # emitted by replay; not re-driven
            elif t == "rga_seal":
                a.seal(ev["work_item_id"])
            elif t == "rga_close":
                fault = ev.get("fault")
                if fault in {"V2", "V5"}:
                    try:
                        a.seal(ev["work_item_id"])   # the failed attempt that emitted this close
                    except ValueError:
                        pass
                    if a.lines[ev["work_item_id"]].fault != fault:
                        raise ValueError(f"replay diverged: seal re-drive did not reproduce fault {fault!r}")
                elif fault in PUBLISHED_FAULTS:
                    pass  # emitted by trial (V1, V3) or replay (V4); re-driven by those events
                else:
                    a.close(ev["work_item_id"], ev.get("reason", "stop"))
        a.policy = current   # restore the live policy; re-drive only borrowed pinned versions
        # Field by field, not merely counted: a count check leaves every
        # re-driven event's contents trusted, and a review altered a seal's
        # power_min in the journal and watched the rebuilt machine carry the
        # correct value while the SERVED record kept the tampered one.
        _compare_regenerated(a.events, rga_events)
        a._events = list(rga_events)
        return a
