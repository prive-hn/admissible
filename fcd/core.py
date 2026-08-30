"""Fail-closed class dispatch — core machine (portable).

One transition table, five ideas:

1. Admit by class. a must be in pi*(c) \\ delta(c) \\ tried.
   On check stages pi* = pi(c) \\ authors  (dual control, I6).
2. Bind writes the DECLARED model only (m_decl = phi(a)).
3. Observe writes the EXECUTED model (m_exec) from the provider report.
   Bind never writes m_exec — that made the Pass guard tautological
   (see paper/PROOFS.md, round-3 finding). Observe is what makes I1
   non-vacuous.
4. Pass is enabled only when norm(m_exec) == norm(m_decl).
   A mismatch is fault F1: the stage closes, publishes, and never hops.
5. The store is written only by Accept (I8). No other path exists.

Every transition appends an immutable JSON-shaped event to authority-owned
private storage; ``events`` exposes a tuple snapshot matching metrics/SCHEMA.md.

norm() keeps the vendor segment and only strips a bracketed context
suffix ("claude-x[1m]" -> "claude-x"). Keeping the vendor segment removes
the vendorA/vendorB collision round 4 flagged; the remaining bracket-suffix
collisions are fail-open and I1/I3 hold only up to them (PROOFS, Norm injectivity).
"""
from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import Callable, Optional
from .journal import JournalEvent, JournalValueError, ReplayError, normalize_journal

def norm(x: Optional[str]) -> Optional[str]:
    """Normalize a model identity for equality.

    Strips a bracketed context suffix only. Vendor/namespace prefixes
    are significant. Returns None for None so callers can distinguish
    "not observed" from "observed as empty".
    """
    if x is None:
        return None
    return x.split("[", 1)[0].strip()


@dataclass(frozen=True)
class Policy:
    """Immutable dispatch policy. Mutating it mid-item is F10-adjacent:
    snapshot the policy_version into every event instead."""

    allow: dict[str, set[str]]                     # class -> allowed specialists
    deny: dict[str, set[str]]                      # class -> forbidden specialists
    phi: dict[str, str]                            # specialist -> API model id
    required: dict[str, list[tuple[str, str]]]     # class -> [(kind, name)]
    version: str = "v0"

    def pi_star(self, cls: str, kind: str, authors: set[str]) -> set[str]:
        """Effective allow set. Check stages exclude prior authors (I6)."""
        base = set(self.allow.get(cls, ()))
        if kind == "check":
            base -= authors
        return base - set(self.deny.get(cls, ()))


@dataclass
class Stage:
    kind: str                       # "write" | "check"
    name: str
    pc: str = "Open"                # Open Admitted Running Passed Closed Stopped
    a: Optional[str] = None         # bound specialist
    m_decl: Optional[str] = None    # written by Bind
    m_exec: Optional[str] = None    # written by Observe ONLY
    tried: set[str] = field(default_factory=set)
    pub: bool = False               # failure published?
    fault: Optional[str] = None     # F1..F10 label
    ts_open: float = 0.0


@dataclass
class Item:
    id: str
    cls: str
    body: str                       # frozen body hash
    authors: set[str] = field(default_factory=set)
    pointer: int = 0
    status: str = "open"            # open | failed | accepted
    stages: list[Stage] = field(default_factory=list)
    policy_version: str = "v0"      # pinned at Open. Evolution-safe (see README)
    depends_on: tuple[str, ...] = ()  # DAG: items whose accepted artifacts this body builds on


def _journal_atomic(method):
    """Rebuild the pre-call state only on an unexpected journal failure."""

    @functools.wraps(method)
    def wrapped(self, item_id, *args, **kwargs):
        outermost = self._journal_transaction_depth == 0
        event_count = 0
        policies: tuple[Policy, ...] = ()
        if outermost:
            event_count = len(self._events)
            policies = tuple(
                policy for version, policy in self._policies.items()
                if version != self.policy.version) + (self.policy,)
        self._journal_transaction_depth += 1
        try:
            return method(self, item_id, *args, **kwargs)
        except Exception as exc:
            if not outermost:
                raise
            # Published semantic closes deliberately raise ordinary ValueError
            # after their event commits; those transitions must remain durable.
            if (isinstance(exc, ValueError)
                    and not isinstance(exc, JournalValueError)
                    and len(self._events) > event_count):
                raise
            rebuilt = Enforcer.from_events(
                tuple(self._events[:event_count]), *policies,
                clock=lambda: 0.0)
            self.policy = rebuilt.policy
            self.items = rebuilt.items
            self.store = rebuilt.store
            self._events = rebuilt._events
            self._policies = rebuilt._policies
            if isinstance(exc, RecursionError):
                raise JournalValueError(
                    "journal event must contain canonical JSON values") from None
            raise
        finally:
            self._journal_transaction_depth -= 1
    return wrapped


def _compare_regenerated(regenerated: list[JournalEvent] | tuple[JournalEvent, ...],
                         journal: tuple[JournalEvent, ...]) -> None:
    """Refuse a journal whose events are not the ones a re-drive produces.

    Field-by-field, `ts` excluded (the clock is injected). Count and field
    mismatches catch inconsistent derived/output fields. A coherent rewrite of
    a root transition input is another valid history and is accepted by replay;
    only an authenticated current head distinguishes it from the anchored one.
    """
    if len(regenerated) != len(journal):
        raise ValueError(
            f"replay diverged: regenerated {len(regenerated)} events "
            f"for a journal of {len(journal)}")
    for i, (mine, theirs) in enumerate(zip(regenerated, journal)):
        a = {k: v for k, v in mine.items() if k != "ts"}
        b = {k: v for k, v in theirs.items() if k != "ts"}
        if a != b:
            differing = sorted(set(a) | set(b))
            first = next((k for k in differing if a.get(k) != b.get(k)), "?")
            raise ValueError(
                f"replay diverged: journal event {i} ({theirs.get('type')!r}) does not match "
                f"the re-driven transition on {first!r}: journal {b.get(first)!r}, "
                f"re-driven {a.get(first)!r}")


class Enforcer:
    """The machine. Single-writer per item; the caller provides the clock
    (injectable for deterministic tests and for platforms without a wall
    clock)."""

    def __init__(self, policy: Policy, clock: Callable[[], float] = lambda: 0.0):
        self.policy = policy
        self.clock = clock
        self.items: dict[str, Item] = {}
        self.store: set[str] = set()
        self._events: list[JournalEvent] = []
        self._policies: dict[str, Policy] = {policy.version: policy}
        self._journal_transaction_depth = 0

    # -- policy versions ----------------------------------------------

    def install(self, policy: Policy) -> None:
        """Install a NEW policy version. In-flight items keep the version
        they pinned at Open (test: VersionPinTests). Installing a version
        string that already exists with DIFFERENT sets is rejected — a
        version label is an identity, not a slot to mutate under live work."""
        existing = self._policies.get(policy.version)
        if existing is not None and existing != policy:
            raise ValueError(f"policy version {policy.version!r} already installed with different content")
        self._policies[policy.version] = policy
        self.policy = policy

    def policy_for(self, item_id: str) -> Policy:
        """The policy an item pinned at Open — not the current one."""
        return self._policies[self.items[item_id].policy_version]

    # -- helpers -------------------------------------------------------

    @property
    def events(self) -> tuple[JournalEvent, ...]:
        """Immutable snapshot of the authority-owned append-only journal."""
        return tuple(self._events)

    def _position(self) -> int:
        return len(self._events)

    def _item(self, item_id: str) -> Item:
        return self.items[item_id]

    def _stage(self, item: Item) -> Stage:
        return item.stages[item.pointer]

    def _emit(self, **event) -> None:
        try:
            event.setdefault("ts", self.clock())
        except Exception:
            raise JournalValueError(
                "journal event must contain canonical JSON values") from None
        self._events.append(JournalEvent(event))

    # -- transitions ---------------------------------------------------

    @_journal_atomic
    def open(self, item_id: str, cls: str, body: str,
             depends_on: tuple[str, ...] = ()) -> None:
        if item_id in self.items:
            # An id is an identity (I4): re-opening it would let a stored id
            # silently refer to a different body. A new item is a new id.
            raise ValueError(f"work item {item_id!r} already exists")
        if cls not in self.policy.required:
            raise ValueError(f"unknown class {cls!r}")
        # DAG gate: a line may open only on top of ACCEPTED lines.
        for dep in depends_on:
            if dep not in self.store:
                raise ValueError(f"dependency {dep!r} not in the store (accepted artifacts)")
        req = self.policy.required[cls]
        item = Item(
            id=item_id,
            cls=cls,
            body=body,
            stages=[Stage(kind=k, name=n, ts_open=self.clock()) for k, n in req],
            policy_version=self.policy.version,
            depends_on=tuple(depends_on),
        )
        self.items[item_id] = item
        ev = {"type": "open", "work_item_id": item_id, "class": cls,
              "body_hash": body, "policy_version": self.policy.version,
              "depends_on": list(depends_on)}
        self._emit(**ev)

    @_journal_atomic
    def admit(self, item_id: str, a: str) -> None:
        item = self._item(item_id)
        st = self._stage(item)
        if st.pc not in {"Open", "Closed"}:
            raise ValueError("admit requires pc in {Open, Closed}")
        pol = self.policy_for(item_id)
        allow = pol.pi_star(item.cls, st.kind, set(item.authors))
        if a not in allow or a in st.tried:
            raise ValueError("not in pi* or already tried")
        st.a = a
        st.tried.add(a)
        st.m_decl = None
        st.m_exec = None
        st.fault = None
        st.pc = "Admitted"
        ev = {"type": "stage", "work_item_id": item_id,
              "stage_id": f"{item_id}.{item.pointer}",
              "class": item.cls, "stage_kind": st.kind,
              "assigned_specialist_id": a,
              "declared_model": pol.phi[a],
              "authors": sorted(item.authors),
              "body_hash": item.body,
              "policy_version": item.policy_version,
              "well_formed": True, "pi_star": sorted(allow)}
        self._emit(**ev)

    @_journal_atomic
    def no_admit(self, item_id: str) -> None:
        """Allow set exhausted: fail closed, publish. No catalog search.

        Measured against the policy the item pinned at Open, like every other
        transition. Reading `self.policy` evaluated the remainder against
        whatever version is current, which contradicted the version pinning
        the rest of this class promises (I10, I14). Both directions of that
        divergence erred toward refusal, so nothing unsound was reachable —
        it was still a different policy than the one the line runs under.
        """
        item = self._item(item_id)
        st = self._stage(item)
        if st.pc not in {"Open", "Closed"}:
            # Same guard as Admit. Without it, NoAdmit could fire on a Passed
            # stage of an accepted item and write status="failed" while the id
            # stays in S — a second writer of status that broke I8 as a state
            # invariant (found by the RGA round-1 formal review).
            raise ValueError("no_admit requires pc in {Open, Closed}")
        allow = self.policy_for(item_id).pi_star(item.cls, st.kind, set(item.authors))
        if allow - st.tried:
            raise ValueError("remainder nonempty")
        st.pc = "Closed"
        st.pub = True
        item.status = "failed"
        self._emit(
            type="decide", work_item_id=item_id,
            stage_id=f"{item_id}.{item.pointer}",
            result="fail_closed", fault=None, next="stop",
            tried=sorted(st.tried),
        )

    @_journal_atomic
    def bind(self, item_id: str, usable: bool) -> None:
        """u(phi(a)) observed at bind time. False => BindFail (closed,
        published). True => Running with m_decl set and m_exec cleared."""
        item = self._item(item_id)
        st = self._stage(item)
        if st.pc != "Admitted" or st.a is None:
            raise ValueError("bind requires pc=Admitted")
        pol = self.policy_for(item_id)
        if not usable:
            st.pc = "Closed"
            st.pub = True
            self._emit(
                type="decide", work_item_id=item_id,
                stage_id=f"{item_id}.{item.pointer}",
                result="fail_closed", fault="F3", next="retry",
                tried=sorted(st.tried),
            )
            return
        st.m_decl = pol.phi[st.a]
        st.m_exec = None
        st.pc = "Running"
        # Bind success must be durable: replay restores Running even if
        # the process died between Bind and the first provider call.
        self._emit(
            type="bind", work_item_id=item_id,
            stage_id=f"{item_id}.{item.pointer}",
            declared_model=st.m_decl, policy_version=item.policy_version,
        )

    @_journal_atomic
    def observe(self, item_id: str, m_exec: str) -> None:
        """Record what the provider says actually ran. The ONLY writer of
        m_exec. May be called repeatedly (last-writer-wins); I1 constrains
        the Pass-time value — see paper/PROOFS.md 'What is not proved'."""
        item = self._item(item_id)
        st = self._stage(item)
        if st.pc != "Running":
            raise ValueError("observe requires pc=Running")
        st.m_exec = m_exec
        prior_calls = [
            e for e in self._events
            if e.get("type") == "call"
            and e.get("work_item_id") == item_id
            and e.get("stage_id") == f"{item_id}.{item.pointer}"
        ]
        self._emit(
            type="call", work_item_id=item_id,
            stage_id=f"{item_id}.{item.pointer}",
            declared_model=st.m_decl, executed_model=m_exec,
            on_bind=norm(m_exec) == norm(st.m_decl),
            first_attempt=not prior_calls,
        )

    @_journal_atomic
    def decide_pass(self, item_id: str) -> None:
        """Pass only if the executed model matches the declared bind.
        Anything else closes with F1. There is no hop transition."""
        item = self._item(item_id)
        st = self._stage(item)
        if st.pc != "Running" or st.m_exec is None:
            raise ValueError("pass requires pc=Running and an Observe")
        if norm(st.m_exec) != norm(st.m_decl):
            st.pc = "Closed"
            st.pub = True
            st.fault = "F1"
            self._emit(
                type="decide", work_item_id=item_id,
                stage_id=f"{item_id}.{item.pointer}",
                result="fail_closed", fault="F1", next="ask",
                tried=sorted(st.tried),
            )
            return
        st.pc = "Passed"
        if st.kind == "write":
            item.authors.add(st.a)  # type: ignore[arg-type]
        self._emit(
            type="decide", work_item_id=item_id,
            stage_id=f"{item_id}.{item.pointer}",
            result="pass", fault=None, next="accept",
            tried=sorted(st.tried),
        )
        if item.pointer + 1 < len(item.stages):
            item.pointer += 1
        else:
            self.accept(item_id)

    @_journal_atomic
    def close(self, item_id: str, reason: str = "refuse") -> None:
        item = self._item(item_id)
        st = self._stage(item)
        if st.pc != "Running":
            raise ValueError("close requires pc=Running")
        st.pc = "Closed"
        st.pub = True
        st.fault = "F4" if reason == "death" else st.fault
        self._emit(
            type="decide", work_item_id=item_id,
            stage_id=f"{item_id}.{item.pointer}",
            result="fail_closed", fault=st.fault, next="ask",
            tried=sorted(st.tried),
        )

    def death_observed(self, item_id: str) -> None:
        """Watchdog entry point (A2). Maps an observed death to a
        published Close. The watchdog never accepts."""
        self.close(item_id, reason="death")

    @_journal_atomic
    def accept(self, item_id: str) -> None:
        """The only writer of the store. Requires every required stage
        Passed (I5, I8)."""
        item = self._item(item_id)
        if item.status != "open":
            raise ValueError("accept requires status=open")
        if not all(s.pc == "Passed" for s in item.stages):
            raise ValueError("accept requires all stages Passed")
        item.status = "accepted"
        self.store.add(item_id)
        self._emit(type="accept", work_item_id=item_id, store_id="S")

    def store_put(self, item_id: str) -> None:
        """Deliberately forbidden. Calling it is a bug, not a feature."""
        raise PermissionError("store admits only via Accept")

    # -- replay --------------------------------------------------------

    @classmethod
    def from_events(cls, journal: object, *policies: Policy,
                    clock: Callable[[], float] = lambda: 0.0) -> "Enforcer":
        """Deterministic rebuild from an append-only journal.

        A real deployment is event-sourced: the journal is the state.
        Re-drive every transition (state only), then restore the journal
        verbatim so no replayed transition emits a duplicate event.
        Requires every policy version referenced by an `open` event to be
        supplied; a version gap is an error, never a silent default.

        The re-driven events are compared field by field against the journal
        before the restore. Without that, this replay re-derived state and
        then accepted whatever the file said: a review demonstrated forged
        events of unknown type, a duplicated or deleted `accept`, and altered
        `on_bind` / `declared_model` / `tried` fields all rebuilding clean and
        then being served verbatim at /api/events. Only the fields a
        transition materially consumed were checked. `ts` is excluded — the
        clock is injected and a rebuild is not the original wall time.
        """
        if not policies:
            raise ValueError("from_events requires at least one Policy")
        events = normalize_journal(journal)
        # `*policies` is ordered oldest-first: the LAST supplied policy is the
        # live policy after rebuild. Historical `open` events temporarily
        # select their pinned version only during re-drive (below); the live
        # policy is restored before returning so new work after recovery opens
        # under the current version, not whatever the last historical Open pinned.
        e = cls(policies[0], clock=clock)
        for p in policies[1:]:
            e.install(p)
        current = e.policy
        sink: list[JournalEvent] = []
        real_emit, real_events = e._emit, e.events

        def quiet(**ev) -> None:
            sink.append(JournalEvent(ev))

        e._emit = quiet  # type: ignore[assignment]
        for ev in events:
            t = ev.get("type")
            iid = ev.get("work_item_id")
            if type(iid) is not str:
                raise ReplayError("replay refused: event identity must be a plain string")
            if t == "open":
                pv = ev.get("policy_version")
                if pv not in e._policies:
                    raise ValueError(f"journal references unknown policy version {pv!r}")
                if e.policy.version != pv:
                    e.install(e._policies[pv])
                e.open(iid, ev["class"], ev["body_hash"],
                       depends_on=tuple(ev.get("depends_on", ())))
            elif t == "stage":
                e.admit(iid, ev["assigned_specialist_id"])
            elif t == "bind":
                e.bind(iid, True)
            elif t == "call":
                # Belt-and-braces: tolerate pre-bind-event journals where
                # the first call of a stage implies bind(u=1).
                st = e._stage(e.items[iid])
                if st.pc == "Admitted":
                    e.bind(iid, True)
                e.observe(iid, ev["executed_model"])
            elif t == "decide":
                if ev.get("result") == "pass":
                    e.decide_pass(iid)
                elif ev.get("fault") == "F3":
                    e.bind(iid, False)
                elif ev.get("fault") == "F1":
                    e.decide_pass(iid)
                elif ev.get("fault") is None and ev.get("next") == "stop":
                    e.no_admit(iid)
                else:
                    e.close(iid, "death" if ev.get("fault") == "F4" else "refuse")
            elif t == "accept":
                # Non-empty classes emit Accept from final decide_pass. A class
                # with zero required stages has no Decide row, so its explicit
                # one-shot Accept must be re-driven here.
                if not e.items[iid].stages:
                    e.accept(iid)
        e._emit = real_emit  # type: ignore[assignment]
        e.policy = current   # restore the live policy; re-drive only borrowed pinned versions
        _compare_regenerated(sink, events)
        e._events = list(events)
        return e
