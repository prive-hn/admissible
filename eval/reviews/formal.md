# Formal review

Verdict: REVISE

Lens: formal methods / TLA-style. Artifact: `paper/DRAFT.md` at `c40db56`
(read-only; nothing in the paper was edited). Also consulted `metrics/SCHEMA.md`
and `paper/SECTIONS.md` as the telemetry contract and status ledger.

The core primitive — admit by class, bind one model, fail closed — is
formalizable and most of its safety slogans can be promoted to theorems with
small, local edits. The verdict is REVISE (not SURVIVES WITH CONDITIONS)
because two *central* claims are stated as if they hold but are false under the
definitions the draft actually gives: (a) declared/executed agreement is
asserted while the mechanism that would make it an invariant is "path only";
(b) separation of duties cannot be expressed by a class-indexed `π`, so the
self-review rule does not hold under the stated signature. One chapter also
contradicts another: fault F2 is unobservable under the metrics contract.
These are signature/axiom defects, not prose polish, so they gate the proof.

---

## State machine you would use

Model the **single stage** as the core automaton, and a work item as the
sequential composition of stage-automata joined by a pointer. This is the
smallest object on which every stated safety property is expressible; the
whole-item behavior is a fold over it.

### Constants (policy, fixed per run)
```
Classes        finite set of classes
Specialists    finite set of specialist identities
Models         finite set of data-plane (API-accepted) model identities
Pi(c)          allow set,  Pi : Classes -> SUBSET Specialists
Delta(c)       deny set,   Delta : Classes -> SUBSET Specialists
phi(a)         binding,    phi : Specialists -> Models        (see MD-1, MD-2)
u(m)           usability,  u : Models -> BOOLEAN               (see MD-4)
```

### Per-stage variables
```
pc       in { Open, Admitted, Running, Passed, Closed, Stopped }
c        in Classes           \* class of THIS stage; write-once at Open
body     frozen payload        \* write-once at Open
a        in Specialists U {_}  \* currently bound specialist
exec     in Models U {_}       \* what the DATA PLANE actually called
tried    SUBSET Specialists     \* specialists already attempted this stage
fault    in F1..F10 U {_}
pub      BOOLEAN                \* a closed failure has been published
```

### Transitions (guards → effect)
```
Open      : pc=Open, c and body set, a=exec=_, tried={}, pub=FALSE
Admit     : pc in {Open,Closed} /\ EXISTS x in (Pi(c) \ Delta(c) \ tried) :
              a' := x ; tried' := tried U {x} ; pc' := Admitted
NoAdmit   : pc in {Open,Closed} /\ (Pi(c)\Delta(c)\tried = {})
              -> pc' := Closed ; pub' := TRUE ; fault' := (F6-guard / F10)
Bind      : pc=Admitted /\ u(phi(a))       -> pc' := Running ; exec := phi(a)  [ENFORCED, see A1]
BindFail  : pc=Admitted /\ ~u(phi(a))       -> pc' := Closed ; pub' := TRUE     \* F3: no catalog search
Pass      : pc=Running                      -> pc' := Passed
Close     : pc=Running                      -> pc' := Closed ; pub' := TRUE ; fault' set
Retry     : pc=Closed                       -> Admit          \* same c, x notin tried
Ask       : pc=Closed                       -> operator event, then Admit or Stop
Stop      : pc=Closed                       -> pc' := Stopped  \* terminal
```

`Bind` is the only writer of `exec` and it writes `phi(a)` — but only because
of enforcer axiom **A1** below. Without A1, `exec` is an unconstrained
environment action and the safety theorem I3 fails. That gap is the paper's
central unproven point, so I make the axiom explicit rather than hide it in the
assignment.

### Work-item composition
An item is `<stages, ptr>` with `stages` a finite ordered list of stage-classes
(the **required stages**, currently undefined — see MD-3). The item advances
`ptr` only when the stage at `ptr` reaches `Passed`; it reaches the store only
when `ptr` runs off the end. `Accept` is the store-writing transition and its
guard is `ptr = Len(stages) /\ ALL passed`.

### Enforcer / environment axioms (must be stated to close the proofs)
```
A1 (executed == declared)  Every data-plane call observed while pc=Running
   satisfies exec = phi(a). This is the enforcer of §6.3 as a TOTAL guard.
A2 (exit trap)             Process/client exit while pc=Running is trapped and
   mapped to a Close transition (else F4 escapes the model).
A3 (policy well-formedness) FORALL c: Pi(c) INTERSECT Delta(c) = {}.
A4 (usability monotone within a stage) u(phi(a)) does not flip TRUE->...->TRUE
   in a way that lets a Running stage silently switch model (needed with A1).
```

---

## Invariants that hold (name, statement, proof sketch, assumptions)

**I1 — ClassFrozen.** `c` and `body` are constant from `Open` to the terminal
state. *Proof:* only `Open` writes them; no other transition mentions `c`/`body`
on the left of `:=`. *Assumptions:* none. This is the formal content of "does
not change class" and "the body does not move under a specialist's feet."

**I2 — NoBleed.** `pc in {Running, Passed}  =>  a in Pi(c) /\ a notin Delta(c)`.
*Proof by induction:* `a` is written only by `Admit`, whose guard is
`a in Pi(c)\Delta(c)\tried`; `Running`/`Passed` are reachable only through
`Admit; Bind`; `c` is frozen (I1). *Assumptions:* A3, and that `Admit` is the
sole writer of `a`. This is F6 ("Δ(c) is a wall") and the Bleed metric, as a
theorem.

**I3 — OnBind.** `pc in {Running, Passed}  =>  exec = phi(a)`. *Proof:* `Bind`
is the only transition to `Running` and sets `exec := phi(a)`; A1 forbids any
environment write of `exec != phi(a)` while `Running`; A4 blocks mid-run drift.
*Assumptions: A1, A4 — load-bearing.* Without them this is a slogan, not a
theorem (see "Claims that do NOT hold" #1). This is F1/F5 and the Misbind
metric.

**I4 — InClassBindingHistory.** Every specialist ever bound in this stage lies
in `Pi(c)\Delta(c)`; equivalently the transition relation has *no edge* that
binds outside `Pi(c)`. *Proof:* `tried` only grows via `Admit`; `Admit`'s
domain is `Pi(c)\Delta(c)`; `BindFail`/`Close` do not bind. *Assumptions:* A3.
This is F3 ("exhaustion is fail-closed; retry only inside π(c)") — the
structural difference from a router, which would have a bind edge into a global
fallback list.

**I5 — PublishedOnClose.** `pc = Closed  =>  pub = TRUE`. *Proof:* every
transition that sets `pc := Closed` (`NoAdmit`, `BindFail`, `Close`) sets
`pub := TRUE` in the same atomic step. *Assumptions: A2* (so that real client
death enters through `Close` rather than bypassing it). This is F4.

**I6 — NoUnboundModel.** `exec != _  =>  EXISTS a-bound : exec = phi(a)`.
*Proof:* corollary of I3 + "Bind is the sole writer of exec." *Assumptions:*
A1, A4. This is "does not pick an unbound model because it still has tokens."

**I7 — StageTermination.** Each stage automaton reaches `Passed` or `Stopped`
in `<= |Pi(c)\Delta(c)|` admit attempts. *Proof:* `Retry`/`Admit` require
`x notin tried` and grow `tried` by one; `Pi(c)` is finite; when
`Pi(c)\Delta(c)\tried = {}` only `NoAdmit -> Closed -> Stop` is enabled.
*Assumptions:* the `x notin tried` clause — **present in my machine, absent from
the draft** (see MD / "does not hold" #3). Without it, `Retry` may re-select the
failing specialist and livelock.

**I8 — StoreOnlyAccepted.** `x in store  =>  x traversed Passed for every
required stage`. *Proof:* `Accept` is the sole writer of `store` and its guard
is `ptr = Len(stages) /\ ALL passed`. *Assumptions:* MD-3 (a definition of
"required stages"). This is F9.

**I9 — RetryPreservesClass.** Across `Close; Retry; Admit`, `c` is unchanged.
*Proof:* I1; no retry edge writes `c`. This is the *half* of F10 that is a
theorem ("same item, same class, different allowed specialist"). The other half
does not hold — see below.

---

## Claims in the draft that do NOT hold

1. **"Two planes must agree … the process only exists if those are the same
   object" (§3) — asserted, not proven.** As written this is definitional
   circularity: it *names* the desired property (I3) and declares it true. The
   mechanism that would make it an invariant (the enforcer, §6.3) is "path only"
   per `SECTIONS.md`. Under the abstract machine, `exec` is an environment
   action; I3 holds *iff* axiom A1 is added as a total guard. Until A1 is
   stated, declared==executed is a slogan. This is the paper's headline safety
   property, so it gates the verdict.

2. **Separation of duties / self-review (§3, F7) does not hold under the stated
   signature of `π`.** The draft writes `π(c)` and `δ(c)` as functions of class
   *only*. F7 requires excluding "the author of a layer" and "a fallback that
   shares its weights" from the checking stage. A class-indexed `π` cannot
   express "exclude whoever authored the layer under review" — that predicate
   depends on the item's authorship history, not on `c`. So no stated invariant
   forbids self-review; the rule is currently unenforceable. Fix is a signature
   change (see MD-5), not prose.

3. **Retry termination (§2 "Retry", §3.5) is not guaranteed.** "Another
   specialist still in π(c)" does not say *a different, not-yet-tried* one.
   Nothing in the draft forbids `Retry` re-binding the same exhausted
   specialist, so an unbounded `Close -> Retry -> Close` livelock is consistent
   with the spec. I7 needs the explicit `x notin tried` clause; the draft omits
   it. Note "fail closed" prevents fail-*open* hopping but says nothing about
   liveness.

4. **F2 (shared runtime) is unobservable under the metrics contract — chapters
   contradict.** §4 says "isolation is part of φ," but `metrics/SCHEMA.md`'s
   `call` event carries only `executed_model` and `on_bind = (executed ==
   phi(specialist))`, i.e. it compares *model identity*, never *runtime
   instance*. Two specialists collapsing onto one process home (F2) produces
   identical `executed_model`/`on_bind` and is invisible. So the claim that F2
   is a measured fault is unsupported by the stated telemetry. Either `φ`'s
   codomain must become `(model, instance)` (MD-2) and the contract must gain a
   runtime/instance field, or §4 must drop F2's measurability claim.

5. **F10 "a new class is a new work item" is only half a theorem.** I9 gives
   "retry preserves class," which is real. But the *anti-reincarnation* content
   — the controller must not spawn a differently-classed sibling to launder
   failed work — is a property of the item-*creation* relation, not of the
   single-item automaton, which has no class-change edge to begin with. The
   draft states it as a rule about intent with no witness. It needs a global
   lineage invariant (e.g. "a fresh item whose charge/body descends from a
   Closed stage inherits that stage's class") or it is merely observable via a
   lineage metric the contract does not currently emit.

---

## Missing definitions that block a proof

- **MD-1 — `u(m)`.** Enumerated by signals (401/403/404/429/exhausted) but not
  defined as a predicate: domain, and temporal semantics (may `u` flip during a
  `Running` stage?). Blocks the `Bind`/`BindFail` guards and A4, hence I3/I7.
- **MD-2 — codomain of `φ` and the weight-sharing relation `~`.** F2 needs
  `φ : Specialists -> (Model x RuntimeInstance)`; F7 needs an equivalence `~`
  ("shares its weights") so the check stage can exclude the whole `~`-class of
  the author, not just one identity. Neither `~` nor the tuple is defined.
- **MD-3 — "required stages."** No definition of the required-stage set or its
  order. Blocks the `Accept` guard and I8; "accepted artifact" also collides
  with per-stage "Pass" naming.
- **MD-4 — identity equality `=`.** F5 (interface alias) hinges on when a
  declared string equals an executed API id. Needs a canonicalization function
  `norm(.)` and `=` defined as `norm(declared) = norm(executed)`; otherwise I3
  is unfalsifiable.
- **MD-5 — signature of `π`.** Must become `π : (Classes x AuthorHistory) ->
  SUBSET Specialists`, or a side constraint `authored(item, L) => author notin
  π(c_check(L))` closed under `~`. Blocks F7 / dual control (claim #2).
- **MD-6 — `well_formed`.** Appears in the `stage` event (SCHEMA) and F8 ("a
  stage starts only on a well-formed assignment") but is never defined. It is
  the guard on the `Open`/stage-start transition; without it F8 is
  unfalsifiable.
- **MD-7 — refinement mapping.** The invariants are about the abstract machine;
  the faults are about the running system. No abstraction map from
  implementation events to transitions is given, so "the invariants hold" does
  not transfer. Minimum needed: the exit-trap obligation A2 (exit -> `Close`)
  and the enforcer totality A1 (every call -> observed while `Running`).

---

## Smallest paper edits

1. **§2:** add axiom A3 as a well-formedness *hypothesis* on the policy (already
   half-stated) and add to "Retry": *"a specialist in `π(c) \ δ(c)` not tried in
   this stage."* (closes I7 / claim #3).
2. **§2/§4:** change `φ` to `φ : specialist -> (model identity, runtime
   instance)` and define `~` = "shares weights or runtime home"; state F2/F7 in
   terms of `~` (closes claim #2 at the signature level and MD-2).
3. **§2/§3:** give `π` the signature `π(c, author-history)` or add the
   side-constraint `author(L) ∉ π(c_check(L))` closed under `~` (closes claim
   #2 / MD-5).
4. **§3:** promote §6.3 to two stated invariants: **A1** "every executed call is
   observed while Running and satisfies `exec = φ(a)`" and **A2** "client/process
   exit maps to a published Close." Reframe "the process only exists if those are
   the same object" as *these are the enforcer's proof obligations* rather than a
   definition (closes claim #1).
5. **`metrics/SCHEMA.md` + §4:** add a `runtime_instance` field to the `call`
   event and redefine `on_bind` over `(model, instance)`; else delete F2's
   measurability claim (closes claim #4).
6. **§2:** define the required-stage list and restate `Accept`'s guard over it
   (closes MD-3 / I8); disambiguate per-stage "Pass" from item "accepted."
7. **§2/§4:** one sentence each defining `u(m)`, `norm(.)` for identity equality,
   and `well_formed` (closes MD-1, MD-4, MD-6).
8. **§8 (Limits):** add one line — "invariants I1–I9 are proved against the
   abstract stage machine under axioms A1–A4; the refinement map A1/A2 is the
   sole coupling to the running system" — so readers know what is a theorem and
   what is an obligation (closes MD-7).

With edits 1–4 the machine's *safety* invariants (I1–I6) become theorems and its
*liveness* invariant (I7) holds; the verdict would move to SURVIVES WITH
CONDITIONS. The edits are local and do not touch the thesis.
