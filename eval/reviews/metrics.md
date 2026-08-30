# Metrics review

Verdict: REVISE

Scope: measurement and counterexample review of the four rates (§5 of the draft;
line 39 of the telemetry contract) and faults F1–F10 (§4). Question for each rate:
is it a random variable with a defined sample space **after a named cut**, and is
the denominator gameable — in particular by silent abort? Question for each fault:
can it be written as a predicate over the four event types (`stage`, `call`,
`decide`, `accept`), and does a one-transition instance violate its stated rule?
Read-only; no artifact was edited.

## Rates (each: defined? / denominator trap / fix)

The draft names a "cut" but never defines it. A rate is only a random variable once
the cut fixes (a) an observation window `[t0, t1]`, (b) which event stream is the
sample space, and (c) the as-of versions of `π`, `δ`, `φ`. Treat every verdict below
as conditional on the cut being a closed interval that ends at least one window `W`
before the observation edge (otherwise every rate is right-censored at the boundary).

### 1. Misbind — `misbind calls / calls`

- **Defined?** Yes as written, over the `call` stream: indicator that
  `executed_model ≠ φ(assigned_specialist)` (available directly as `call.on_bind =
  false`) **or** `assigned_specialist ∉ π(class)`. Sample space = `call` events in
  the cut. It is a well-formed random variable *only over calls that were emitted*.
- **Denominator trap (two, both real):**
  1. **Silent-abort erasure.** If the client dies before emitting a `call`, the stage
     produces *no* denominator unit and *no* numerator unit. A fleet that fails by
     dying rather than by mis-calling drives this rate toward 0 while doing nothing
     right. This rate is **gameable by silent abort** — flag raised.
  2. **Per-stage dilution.** One stage can emit many `call`s (retries inside `π(c)`,
     provider 429 re-tries). Benign repeated correct calls inflate the denominator
     and dilute a single misbind. The rate mixes "calls" of different cardinality per
     stage, so it is not exchangeable across stages.
  - Secondary: the numerator fuses a call-level predicate (`on_bind`) with a
    stage-level predicate (`a ∉ π(c)`); the latter is a property of the `stage`
    event, not the `call`, so a call inherits it only by join.
- **Fix.** Denominate by **bind attempts per stage** (first call of each stage), not
  raw calls; and always report misbind *jointly* with silent-fail so an abort cannot
  launder a would-be misbind out of both numerator and denominator.

### 2. Silent fail — `silent fails / stages`

- **Defined?** Yes, and this is the well-designed one. Sample space = `stage`
  (assignment) events in the cut; numerator = stages with no *published* terminal
  event (`decide` or `accept` referencing `stage_id`) within window `W`. The draft
  explicitly denominates on assignments, "not calls" (line 119) — this is precisely
  what makes it **robust to silent abort**: the assignment fires before the client
  can die, so the abort lands in both the sample space and (correctly) the numerator.
  This is the one rate that *cannot* be gamed by silent abort; it is the abort
  detector.
- **Denominator trap:** Right-censoring. A legitimately in-flight stage whose true
  duration exceeds `W` is counted as a silent fail; and stages assigned within `W` of
  the observation edge have not had time to reply. Also "published reply" is
  undefined — a `decide(result=fail_closed)` **must** count as published (F4's own
  rule), else a correct fail-closed is miscounted as a silent fail.
- **Fix.** Set `W` per class from the observed reply-time distribution; exclude stages
  assigned after `t1 − W`; define "published" = existence of a `decide` OR `accept`
  row for the `stage_id`, and audit that fail-closed always writes a `decide`.

### 3. Bleed — `bleed / stages of that class`

- **Defined?** Yes, over `stage` events with `class = c`: numerator = stages whose
  `assigned_specialist_id ∈ δ(c)` or `∉ π(c)`. Checkable **at assignment time**, so it
  needs no `call` — therefore it is *not* erased by silent abort (assignment already
  emitted). Good.
- **Denominator trap:**
  - **Class mutability (couples to F10).** If a work item's class changes across
    stages, "stages of that class" is ambiguous — does a reincarnated stage count
    under its old or new class? The denominator is only well-defined if `class` is
    read per-`stage` event as-of `ts` (which the contract supports) and F10 is
    separately forbidden.
  - **Version drift.** `π/δ` must be evaluated as-of `stage.ts`; a later edit to the
    deny set silently rewrites history.
  - Note: bleed as defined catches *assigned*-specialist bleed. An *executed* hop
    into a denied model (F3 route) shows up as misbind, not bleed — so a denied model
    reached only via fallback, then aborted, hides. That residue rides on the misbind
    abort hole, not on bleed.
- **Fix.** Pin `π/δ` versions in the cut; compute bleed on the per-stage class; and
  add an executed-model bleed variant (`executed_model` resolves to a specialist in
  `δ(c)`) to close the fallback-hop path.

### 4. Time-to-stage — `well-formed stage → first reply`

- **Defined?** It is **not a rate** — it is a duration/distribution. As a random
  variable it is well-formed only over stages that *produced* a reply by the bound
  specialist. That conditioning is the trap.
- **Denominator trap:** **Survivorship / silent-abort censoring — flag raised.**
  Aborted stages have no reply and drop out of the sample entirely, so the mean or
  median time-to-stage *improves* when slow stages are killed. Reporting a bare
  central tendency rewards silent abort. Also "first reply by the bound specialist"
  must exclude a reply from a *non-bound* specialist (an F3 hop) or it credits the
  wrong worker.
- **Fix.** Report as a right-censored survival curve over *all* well-formed stages
  (aborts = censored at `W`, effectively `+∞`), always paired with the completion
  rate `(1 − silent-fail)`. Never publish a mean without the censoring denominator.

## Faults (each: formalizable? / counterexample)

Convention: a counterexample is a minimal event trace whose last transition violates
the fault's stated Rule. "Formalizable" = expressible as a predicate over the four
contract event types.

- **F1 Label lie — FORMALIZABLE.** Predicate: ∃ `call` with `executed_model ≠`
  its stage's `declared_model` (i.e. `on_bind = false`) and `decide.result = pass`.
  Counterexample: `stage(declared_model=A) → call(executed_model=B, on_bind=false) →
  decide(pass)`. The pass over a `false` bind violates "φ is the data-plane identity."
  Detected by misbind.

- **F2 Shared runtime — SYMPTOM FORMALIZABLE, ROOT INFORMAL.** The *symptom* (two
  specialists collapsing to one default) surfaces as misbind: `stage(a1,φ=A)` and
  `stage(a2,φ=B)` both yield `call(executed_model=A)`; the a2 call has `on_bind=false`.
  But the *cause* — shared process home / lack of isolation — has **no field** in the
  contract (no co-residency or PID/namespace attribute), so it is indistinguishable
  from a plain F1. Root cause is informal until an isolation attribute exists.

- **F3 Fail-open hop — FORMALIZABLE.** Predicate: within one `stage_id`, a `call`
  with `signal ∈ {401,403,404,429,exhausted}` is followed by another `call` (or an
  `executed_model` change) with no intervening `decide(result=fail_closed)`.
  Counterexample: `call(model=A, signal=exhausted) → call(model=B)` (same stage, no
  fail-closed between). Violates "exhaustion is fail-closed."

- **F4 Silent abort — FORMALIZABLE.** Predicate: ∃ `stage(well_formed=true)` with no
  `decide` or `accept` for its `stage_id` within `W`. Counterexample: a lone
  `stage(well_formed=true)` and silence. This *is* the silent-fail rate; it violates
  "a closed failure is published."

- **F5 Interface alias — SYMPTOM FORMALIZABLE, CAUSE INFORMAL.** Symptom: `call(signal
  = not_found | 404)`. Counterexample: `stage(declared_model="Pretty Display Name") →
  call(signal=404)`. But `404/not_found` cannot be attributed to a display-vs-API id
  rather than a dead endpoint or a wrong model — the *alias* cause is not observable in
  the contract; it overlaps F1/F5 at the signal level only.

- **F6 Class bleed — FORMALIZABLE.** Predicate: ∃ `stage` with `assigned_specialist_id
  ∈ δ(class)` (or `∉ π(class)`), `π/δ` as-of `ts`. Counterexample: a single
  `stage(class=c, assigned_specialist_id=a)` with `a ∈ δ(c)`. One transition, violates
  "δ(c) is a wall." This is the bleed rate.

- **F7 Self-review — INFORMAL (as contracted).** The rule references *authorship
  lineage* ("author of a layer is outside π for the check") and a *weight-equivalence*
  relation ("a fallback that shares its weights"). The contract has `work_item_id` and
  `stage_id` but **no edge** linking a review stage to the stage/specialist that
  produced the reviewed body, and **no** weight-sharing relation. The intended
  counterexample — `stage(class=implement, specialist=a)` then `stage(class=review,
  specialist=a)` on the same body — cannot be evaluated because "same body / same
  author" is not recorded. Fault is informal until an authorship edge and a
  specialist-equivalence class are added to `stage`.

- **F8 Prose assignment — FORMALIZABLE.** Predicate: ∃ `call` whose `stage_id` has no
  `stage` event with `well_formed=true`. Counterexample: `call(stage_id=S)` with no
  `stage(stage_id=S, well_formed=true)`. Violates "a stage starts only on a well-formed
  assignment." The `well_formed` flag exists for exactly this.

- **F9 Unstored accept — FORMALIZABLE.** Predicate: ∃ `work_item` with
  `decide(next=accept)` and no `accept` row for that `work_item_id`. Counterexample:
  `decide(result=pass, next=accept)` with no following `accept`. Violates "the process
  ends at the store."

- **F10 Retry as reincarnation — FORMALIZABLE.** Predicate: ∃ `work_item_id` with two
  `stage` events of differing `class`, the second following a `decide(next=retry)`.
  Counterexample: `stage(W, class=c1) → decide(fail_closed, next=retry) → stage(W,
  class=c2)` with `c2 ≠ c1`. Violates "retry is same item, same class." `class` is
  per-stage and `work_item_id` is stable, so this is checkable.

**Summary:** F1, F3, F4, F6, F8, F9, F10 are fully formalizable predicates over the
contract. F2 and F5 are formalizable only as *symptoms* (they collapse into misbind /
call-signal) — their distinguishing causes have no observable field. F7 is informal
under the current contract for lack of authorship-lineage and weight-equivalence
data.

## Silent-abort gaming — consolidated flag

- **Misbind** — gameable (abort removes the stage from both numerator and
  denominator).
- **Time-to-stage** — gameable (aborts are censored out of the reply-conditioned
  sample; killing slow stages improves the statistic).
- **Silent fail** — NOT gameable; it is the abort detector (stage-denominated).
- **Bleed** — assignment-level bleed is safe; only executed/fallback-hop bleed rides
  the misbind hole.
Therefore misbind and time-to-stage must never be reported without silent-fail beside
them; in isolation they reward the failure mode the process claims to forbid (F4).

## What would constitute a proof vs an estimate

**Estimate.** Any rate reconstructed from a partial or post-hoc stream — most acutely,
from `call` logs alone (the draft concedes, line 123, that call logs cannot produce
bleed, silent-fail, or time-to-stage). When event emission is *incidental* to the
action, the absence of an event is ambiguous between "did not happen" and "happened
but was not logged," so every numerator that keys on missing events (silent-fail) and
every denominator that keys on emitted calls (misbind) is biased by exactly the
silent-abort mode under study. That is an estimate, and a downward-biased one.

**Proof.** The rates become checkable invariants — not samples — when four conditions
hold in the cut:

1. **Write-ahead emission.** The `stage` event is a *precondition* of doing any work,
   and `decide`/`accept` are written atomically with the terminal action. Then absence
   of a terminal event provably implies a live-or-aborted stage, closing the
   silent-abort hole: silence is evidence, not a gap.
2. **Totality, no sampling.** Every call carries a `call` event and every assignment a
   `stage` event, so the enforcer compares declared vs executed on *every* call (draft
   §6.3). Rates are then computed over the population, not a draw from it.
3. **Versioned policy, evaluated as-of `ts`.** `π`, `δ`, `φ` are pinned per event so
   bleed and misbind are deterministic functions of the frozen log, not of today's
   roster.
4. **Contract completeness for F2/F5/F7.** Add an isolation attribute (F2), an
   API-identity-vs-display distinction (F5), and an authorship-lineage edge plus
   specialist weight-equivalence class (F7). Only then do those three faults have
   predicates rather than symptoms.

Under 1–3, `misbind = 0`, `bleed = 0`, `silent-fail = 0` over a named cut is a
**proof** that no corresponding fault fired in that window — a total check over a
complete, write-ahead log — rather than an estimate of how often it did. Absent 1–3,
all four numbers are estimates whose bias points in the direction that flatters the
system.
