# Metrics review r2

Reviewed head: 3e9d70fe6600348f063250d4f30114011355e916
Verdict: SURVIVES WITH CONDITIONS

Lens: measurement. Read only `paper/DRAFT.md`, `paper/INVARIANTS.md`,
`metrics/SCHEMA.md`. No paper files edited. No other review files read.

The measurement machinery is unusually honest for a draft: it names the abort
vector, pairs the gameable rates with a backstop, right-censors the cut edge,
and refuses a mean where a defective survival tail exists. It survives. The
conditions below are the difference between "these zeros are proofs" (the
paper's own bar, DRAFT §6 / INVARIANTS §6) and "these zeros are estimates
biased clean." Every condition is a contract obligation the schema states as a
*proof-side assumption* rather than an *emitter obligation*, plus two sample
spaces that are under-defined and one that is defined wrong for check stages.

---

## The named cut

A cut is `[t0, t1]`, a pinned `(π, δ, φ)` version, window `W`, excluding stages
with `ts > t1 − W` (SCHEMA top; DRAFT §6; INVARIANTS §6 — three consistent
statements).

Defined: yes for the right edge. The right-censor is correct and necessary — a
stage started near `t1` cannot be given its full `W` to resolve, so it must be
dropped rather than scored as silent-fail. Membership key is `stage.ts` (the
well-formed control-plane start, SCHEMA line 19), which is the right key.

Two defects in the cut definition:

1. **Pinned-version vs as-of-ts contradiction.** The cut "pins a `(π, δ, φ)`
   version" but SCHEMA line 3 says policy fields are "as-of `ts`," and bleed
   (below) is evaluated "policy as-of `ts`." These agree only if policy is
   guaranteed constant across `[t0, t1]`. If a policy version change can occur
   inside the interval, "pinned version" and "as-of ts" name different objects
   and bleed is ambiguous. **Fix:** state that a cut is well-defined only over a
   maximal interval of constant `(π, δ, φ)` version, OR drop "pinned version"
   and define the cut over a version *sequence* with bleed as-of ts. Pick one;
   do not carry both phrasings.

2. **`W` origin and meaning unstated.** DRAFT calls it "window," INVARIANTS
   "reply window," SCHEMA "window." Nowhere is it stated that `W` is measured
   forward from `stage.ts`. Silent-fail and time-to-stage both depend on this
   origin. **Fix:** "`W` is measured from the well-formed `stage` event `ts`";
   cross-cut comparison is invalid when `W` differs (see time-to-stage).

---

## Each rate: defined? gameable? remaining fix

### 1. Misbind

- **Sample space:** first-bind-attempt calls per stage — `call` events with
  `first_attempt = true` (SCHEMA line 30; DRAFT §6; INVARIANTS §6). Numerator:
  those with `on_bind = false`, i.e. `norm(executed) ≠ norm(φ(assigned))`
  (SCHEMA line 28).
- **Defined?** As an *A1-breach rate* (any executed model ≠ `φ(a)` while bound),
  yes — `on_bind` is a total per-call boolean and the denominator is countable.
  But the paper *names* this after fault F1, and F1 requires a **Pass** with the
  mismatch (DRAFT §5; INVARIANTS §7). A divergent call that then fails closed is
  the enforcer *working* (A1 caught it), not F1. As written the rate scores
  enforcer catches and integrity violations in the same numerator. It is a
  defensible A1-breach counter but a mislabeled F1 counter.
- **Gameable?** Two ways. (a) The paper's own flag: "Call-denominated misbind is
  gameable by abort" — kill the client after a bad bind but before the `call`
  event is durable and the misbind enters neither numerator nor denominator.
  This is why it is published "always beside silent-fail" (SCHEMA line 48). The
  pairing is the control and it is correct *if* silent-fail is itself
  non-gameable (it is not, yet — see below). (b) **`first_attempt` is a
  self-reported flag with no cross-check.** Nothing forces exactly one
  `first_attempt = true` call per stage. An emitter that never sets the flag
  collapses the denominator to zero and the rate to 0/undefined. This vector is
  not flagged in the paper.
- **Remaining fix:** (i) split the numerator into divergent-and-passed (F1) vs
  divergent-and-closed (A1 catch) by joining to the stage's terminal `decide`;
  report both. (ii) Derive `first_attempt` from the event stream (min-`ts`
  `call` per `stage_id`) instead of trusting the field, or add and validate an
  invariant that exactly one `call` per stage carries `first_attempt = true`.

### 2. Silent fail

- **Sample space:** well-formed stages with no `decide` and no `accept` within
  `W` of the stage start; fail-closed counts as published (SCHEMA line 48;
  DRAFT §6; INVARIANTS §6). This is the empirical A2 (exit-trap) / F4 measure and
  the declared backstop for the abort-gameable rates.
- **Defined?** Yes, conditionally: it is a proof of "no silent abort in the
  window" *only if* `stage` is write-ahead and `call`/`decide` are total (the
  paper says this itself — DRAFT §6 last para, INVARIANTS §6 last para).
- **Gameable? — this is the review's central finding.** The whole anti-gaming
  design leans on silent-fail as the incorruptible backstop, but silent-fail is
  corruptible by the *same* abort it is meant to catch, because its denominator
  is self-defined by the very `stage` events an abort suppresses:
  - **Write-ahead is asserted, not enforced.** SCHEMA line 19 ("well_formed true
    only if this event is the control-plane start") is a *semantic* claim about
    what the event means, not a *durability/ordering* obligation that the `stage`
    record is persisted before any `call` for that stage. An implementation that
    emits `stage` write-behind (only on success) satisfies every schema field
    yet drops every aborted stage out of the denominator. The gap between
    "biased clean" and "proof" lives entirely in a property the contract never
    requires of the emitter.
  - **No gap-detection.** `stage_id` has no stated monotonic/dense issuance, so a
    suppressed stage leaves no hole. A missing stage is invisible, not a signal.
  - **No work-item-level witness.** The four event types are `stage`, `call`,
    `decide`, `accept`. There is no `open` / work-item event, though DRAFT §3
    step 1 opens a work item. An item opened that dies before its first `stage`
    event leaves **zero trace** and is invisible to a stage-denominated
    silent-fail rate. This is the coarsest silent-abort escape and the contract
    has no external witness for it.
  - **`W` false positives (benign direction).** A legitimately slow `decide` at
    `stage.ts + W + ε` is scored silent-fail then later resolved — biased
    *dirty*, which is the safe direction, but it makes silent-fail sensitive to
    the free parameter `W`.
- **Remaining fix:** promote to emitter obligations in SCHEMA: (i) `stage` is
  durably logged before any `call` for that stage (write-ahead); (ii) `stage_id`
  is monotonic and gap-detectable so a suppressed stage is a hole; (iii)
  `call`/`decide` totality is a numbered contract obligation, not a proof aside;
  (iv) add a write-ahead work-item `open` event so item-level abort (die before
  first stage) is a dangling open = silent-fail at item granularity; (v) an
  external heartbeat/liveness witness, since whole-runtime death before any
  emit leaves no stage, no gap, and no signal.

### 3. Bleed

- **Sample space:** stages of class `c` whose `a ∈ δ(c)` or `a ∉ π(c)`, policy
  as-of `ts` (SCHEMA line 48; DRAFT §6; INVARIANTS §6). Empirical I2
  (class-admission) breach rate.
- **Defined?** Denominator "stages of class `c`" — read as admitted stages
  carrying a class and specialist, grouped by class. Countable given `stage`
  totality. But two definitional errors:
  1. **Wrong allow set on check stages.** Bleed tests `a ∉ π(c)`, but check
     stages admit against the *effective* set `π_chk(c, authors) = π(c) \ authors`
     (A6; F7; DRAFT §2). A self-review — check admit with `a ∈ authors` — has
     `a ∈ π(c)` and `a ∉ δ(c)`, so it is **not** caught by bleed. The
     dual-control breach (F7 / the I6 headline invariant) has **no rate**. Bleed
     as written measures I2 for writing stages but silently omits the check-stage
     integrity it should be measuring.
  2. **Same as-of-ts vs pinned-version tension** as the cut (above).
- **Gameable?** Yes, by the identical abort vector as misbind — a bleeding admit
  whose `stage` is not durable before the client dies never lands in the
  numerator. Yet the DRAFT pairs *only misbind* with silent-fail ("Never publish
  [misbind] without silent-fail"). Bleed carries the same hole and is granted no
  such pairing rule. This asymmetry is a defect: bleed's zero is as gameable as
  misbind's zero.
- **Remaining fix:** (i) on check stages evaluate membership against `π_chk`, so
  `a ∈ authors` is bleed — or add an explicit fifth dual-control rate for F7;
  (ii) apply the "never publish without silent-fail" pairing to bleed too;
  (iii) resolve the policy-version/as-of question once for both cut and bleed.

### 4. Time-to-stage

- **Sample space:** all well-formed stages, right-censored survival, paired with
  `1 − silent-fail`, explicitly "not a mean" (SCHEMA line 48; DRAFT §6;
  INVARIANTS §6).
- **Defined?** Partially. The clock *start* is clear (`stage.ts`) and the censor
  point (`t1`) is clear, but the **terminal event is unspecified.** "Time-to-
  stage" does not say whether the survival clock stops at this stage's terminal
  `decide` (stage duration) or at the next stage's well-formed event (time to
  advance). The hazard being estimated is therefore undefined. "Paired with
  `1 − silent-fail`" and "not a mean" are exactly right: the reported object is
  a *defective* survival function — `Ŝ(t)` among completing stages plus a point
  mass `silent-fail` at ∞ — for which a mean is undefined, so the pairing is the
  honest joint that prevents the classic "great latency by dropping slow stages
  into the abort bucket" game.
- **Gameable?** Only through silent-fail: aborting slow stages moves them from
  the survival numerator into the silent-fail mass, and the pairing closes that
  hole **iff silent-fail is non-gameable** — which loops back to the write-ahead
  / item-`open` conditions above. Time-to-stage inherits every silent-fail
  condition.
- **Remaining fix:** define the terminal event precisely (recommend: this
  stage's first terminal `decide`, with "advance" as a separate metric if
  wanted); state the reported object as an improper/defective survival function
  with the silent-fail point mass at ∞; forbid cross-cut comparison when `W`
  differs.

---

## Faults still informal under the contract

Measured against the four event types (`stage`, `call`, `decide`, `accept`) and
their fields, mapped to the fault table (DRAFT §5 / INVARIANTS §7):

- **F1** — partially formal. Approximated by misbind, but misbind's numerator is
  the A1-breach set, a *superset* of F1 (which needs a Pass). Not pinned to a
  pass-conditioned rate. **Fix:** join to terminal `decide.result = pass`.
- **F2** (two specialists, one runtime instance) — **informal by default.**
  Requires `runtime_instance`, which SCHEMA line 27 makes *optional*. Whenever
  the field is omitted, F2 is unmeasurable and indistinguishable from F1. No
  rate. **Fix:** require `runtime_instance` on `call`, or state plainly that F2
  is out of scope of the contract.
- **F3** (call after `u = 0` outside unused-allow with no fail-closed) —
  sequence-detectable via `call.signal ∈ {401,403,404,429,exhausted,not_found}`
  then a later `call` with no intervening `decide.result = fail_closed`, but
  **no rate is defined.** Informal.
- **F4** (Running exit, `pub = 0`) — approximated by silent-fail, but the
  contract has no explicit Running/exit event, so silent-fail cannot distinguish
  "exited while Running" from "still running slowly past `W`." F4-exact is
  informal.
- **F5** (`φ(a)` not an API identity) — detectable via `call.signal ∈
  {404, not_found}`, but folded into generic bind failure with no separate rate.
  Informal.
- **F6** (Pass with `a ∈ δ(c)`) — a subset of bleed *only if* bleed is
  pass-conditioned, which it is not (bleed scores admits). Pass-conditioning
  unstated. Partially formal.
- **F7** (check admit with `a ∈ authors`) — detectable via `stage.authors` vs
  `stage.assigned_specialist_id`, but **caught by no rate** (bleed misses it, per
  §Bleed). The dual-control / I6 breach has no numeric witness. Informal.
- **F8** (run with no well-formed stage) — detectable as a `call` whose
  `stage_id` has no well-formed `stage` event; but with `stage` write-behind this
  join is unreliable, and no rate is defined. Informal.
- **F9** (conversation end, status ≠ accepted) — the published `Stop` variant is
  detectable via `decide.next = stop` with no `accept` for the item, but the
  contract has **no conversation/session-end event**, so the *silent* variant
  (user leaves, nothing published) reduces to item-level silent abort — which,
  absent a work-item `open` event, is invisible. Materially informal.
- **F10** (same `id`, class changes; or retry of `a ∈ tried`) — sequence-
  detectable (two `stage` events, same `work_item_id`, differing `class`; or
  `decide.tried` vs a later admit's `assigned_specialist_id`), but **no rate.**
  Informal.

Net: F1/F4/F6 are partially formal (superset/approximation, not pinned).
F2 is informal by default (optional field). F3, F5, F7, F8, F9-silent, F10 have
no rate. Of these, **F7 and F9-silent are the substantive gaps** — F7 because it
is the dual-control invariant the paper foregrounds (I6) yet no rate touches it,
and F9-silent because it is invisible to a stage-denominated contract with no
work-item `open` event.

---

## Why SURVIVES WITH CONDITIONS, not REVISE

The four rates are individually defensible, the abort vector is named rather than
hidden, and the two anti-gaming moves that matter (pairing gameable rates with
silent-fail; reporting a defective survival function rather than a mean) are
present and correct in principle. None of the findings break a safety theorem —
that is the formal lens. What they break is the paper's *measurement* promise
that "zeros are proofs": that promise is conditional on write-ahead `stage`,
event totality, a work-item `open` witness, a corrected check-stage allow set in
bleed, a derived `first_attempt`, and a defined time-to-stage terminal event —
all of which the contract currently states as proof-side asides rather than
emitter obligations. Those are conditions, not a rewrite.

### Conditions for SURVIVES

1. Make write-ahead `stage`, `stage_id` gap-detectability, and `call`/`decide`
   totality numbered emitter obligations in SCHEMA, not proof asides.
2. Add a write-ahead work-item `open` event; recompute silent-fail with an
   item-level dangling-open term; add an external liveness witness for
   whole-runtime abort.
3. Bleed: evaluate check-stage membership against `π_chk` (catch F7) or add a
   dual-control rate; pair bleed with silent-fail as misbind is.
4. Misbind: split A1-catch vs F1-pass; derive `first_attempt` from the stream.
5. Time-to-stage: define the terminal event; state the defective survival object
   with the silent-fail point mass; forbid cross-`W` comparison.
6. Resolve pinned-version vs as-of-ts once, for both the cut and bleed; fix `W`'s
   origin.
