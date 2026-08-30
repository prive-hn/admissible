# Formal review r3

Reviewed head: 6b450a508fab00227ccc7da9028a314a955dc12e
Verdict: SURVIVES WITH CONDITIONS

Lens: formal methods. Scope: `paper/DRAFT.md`, `paper/INVARIANTS.md` only. The
question answered here is narrow: which of the claimed invariants I1–I9 are
theorems of the abstract transition system under axioms A0–A8, exactly as those
objects are written at this head. No implementation, no empirics, no quality
claim is in scope, and none is asserted by the draft.

The draft claims (DRAFT §4, §9): I1–I6, I8, I9 are inductive invariants; I7 is a
bound on Admit count, not liveness; "Not live" is a negative result; the
leftover-hop remark is a corollary about one selector class. The draft does not
overclaim liveness, does not call I7 termination, and honestly labels the hop a
corollary. The disagreement below is not about scope discipline — that is clean.
It is about whether the transition table as literally written gives the two
headline safety invariants (I1 bind integrity, I3 no unbound hop) any content.

## Theorems that close

These close as inductive safety invariants under A0–A8 as literally stated. Each
holds in the initial state (vacuously — pc=Open, `a`/`m_exec` unset, status=open,
S=∅) and is preserved by every transition whose source pc is pinned by its guard.

- **I4 (c, body frozen).** Strongest. Only Open writes `c`/`body`; Retry states
  "c unchanged"; Admit writes `a`/`tried`, not `c`. No other writer exists in the
  table, so the write-once frame condition is discharged by exhaustion. Closes
  unconditionally. F10 (same id, class changes) is excluded because the machine
  simply has no transition realizing it.

- **I8 (store only accepted).** Closes under A8. Accept is the sole writer of `S`
  and its guard forces `status=accepted` in the same step; `status=accepted` has
  no un-setter, and `S` is monotone. `id ∈ S ⇒ status=accepted` is preserved by
  every transition. Robust to the guard gaps below.

- **I5 (accept coverage).** Closes. Accept is the only writer of `status=accepted`
  and its guard requires every required stage Passed. `Passed` is stable: the only
  transitions reading `Running` as source (Pass, PassRefuse, Close) cannot fire
  from `Passed`, so no un-Pass exists. Preserved. Robust to the guard gaps.

- **I6 (dual control).** Closes directly from A6 and A4. On a check stage the
  Admit guard is `a ∈ π_chk(c,authors)\δ(c)\tried` with `π_chk = π(c)\authors`, so
  `a ∉ authors` at the Admit-time snapshot. This is a property of the Admit event
  itself and does not depend on later frame conditions. F7 excluded by construction.

- **I7 (bounded admits).** Closes as a finite bound, exactly as the draft frames
  it (not liveness). Admit requires `a ∉ tried` and adds `a` to `tried`; the map
  from Admit occurrences to `π*(c)\δ(c)` is injective; A0 makes the codomain
  finite. Within a single stage `authors` does not change (Pass, the only writer,
  is terminal), so `π*(c)\δ(c)` is a fixed finite set for that stage and the bound
  `|π*(c)\δ(c)|` is well-defined. Correctly does not assert Passed/Stopped.

- **I9 (retry preserves class).** Closes as a corollary of I4: Retry leaves `c`
  unchanged and the subsequent Admit writes `a`/`tried`, never `c`.

- **I2 (class admission) — closes modulo one guard fix.** `a` is written only by
  Admit, whose guard is `a ∈ π*(c)\δ(c)\tried ⊆ π*(c)\δ(c)`; A4 makes the authors
  snapshot well-defined and sequential. The one hole: preservation of
  `pc∈{Running,Passed} ⇒ a ∈ π*(c)\δ(c)` requires that `a` is not rewritten once
  the stage is Running/Passed, i.e. that Admit does not fire from Running/Passed.
  The table does not pin Admit's source pc (Gap 2). Under the intended reading
  (Admit fires only from Open or post-Retry), I2 is inductive. It is a theorem
  conditional on that guard being written down.

## Gaps that still block a proof

1. **m_exec conflation — the load-bearing gap (blocks non-vacuous I1, I3, F1).**
   The Bind transition sets `m_exec ← φ(a)`. Pass's guard is
   `norm(m_exec)=norm(φ(a))` and PassRefuse's is `norm(m_exec)≠norm(φ(a))`. Because
   Bind has just written `m_exec = φ(a)`, and no transition ever updates `m_exec`
   to the *observed executed* identity, the Pass guard is always true and the
   PassRefuse guard is unreachable on the machine. Consequences:
   - PassRefuse / F1 is dead code; the control-plane-vs-data-plane divergence that
     the whole draft exists to catch is not representable in the transition system.
   - I1 (`pc=Passed ⇒ norm(m_exec)=norm(φ(a))`) is a theorem only *vacuously*: no
     reachable state can falsify its antecedent's danger case, so it certifies
     nothing about a real divergent call. I3 inherits this vacuity through I1.
   The draft's own prose (DRAFT §3 line 55; INV A1) states the intent correctly —
   "declared binding is not evidence; A1 only requires the executed call is seen;
   whether it equals φ(a) is I1." But A1's `call` event carrying the observed
   `m_exec` is never wired into the state variable `m_exec` that Pass reads. The
   axiom and the machine disagree on what `m_exec` denotes: Bind makes it the
   declared identity; A1 and the I1 proof want it to be the observed one. Until an
   observation transition writes the observed executed model into the variable
   Pass compares, I1 and I3 are true but empty, and F1 cannot fire. This is why the
   verdict is CONDITIONS rather than SURVIVES: the two headline safety invariants
   carry no content as literally written.

2. **Missing source-pc preconditions on Admit, NoAdmit, Bind, BindFail.** Their
   guards constrain membership / `u` / exhaustion but not the source `pc`. The
   Effect column implies a source, but an inductive-invariant proof needs the
   transition relation to pin it. As written, nothing forbids Admit from firing in
   Running/Passed (rewriting `a`, breaking I2 preservation) or Bind from firing
   outside Admitted. F3-exclusion ("no Bind after Closed without re-admission")
   also rests on this. This is the frame condition that I2, I3, and F3 silently
   assume.

3. **Policy constancy is used but not axiomatized.** I2/I3 quantify over
   `π*(c)\δ(c)` as a fixed set and I6 over `π(c)\authors`; the proofs treat π, δ, φ
   as constant over a run. A0 asserts disjointness and finiteness but not
   constancy. §6 correctly defers versioning to measurement (as-of `ts`), so the
   machine wants a stated "π, δ, φ constant within a run" axiom to make the
   quantifiers well-formed. Small but load-bearing for I2/I3/I6.

4. **Under-specified item status and multi-call quantifier (soundness, not
   blocking).** (a) `status ∈ {open, failed, accepted}` but no transition writes
   `failed`; the failure half of the item lifecycle is absent. Does not affect the
   safety theorems but leaves the state space incomplete. (b) When A1 records
   several `call` events during one Running episode, which one does Pass read?
   For F1 to be sound, Pass must be refused if *any* observed call diverges;
   specify the quantifier (∀ observed calls) so I1 cannot be satisfied by cherry-
   picking a conforming call.

## Smallest remaining edits

1. Split the variable: `m_declared` written by Bind (`← φ(a)`), and `m_exec`
   written by a new **Observe** transition sourced from A1 (`m_exec ←` observed
   executed identity). Point Pass / PassRefuse at `m_exec`. This alone makes
   PassRefuse reachable, F1 a real forbidden step, and I1/I3 non-vacuous theorems.
2. Add explicit source pc to guards: Admit from `Open` (or post-Retry reset),
   Bind/BindFail from `Admitted`, Pass/PassRefuse/Close from `Running`. Closes the
   frame gap for I2/I3 and F3.
3. Add A9: "π, δ, φ are constant within a run; as-of versioning is a measurement
   concern (§6)." Makes the I2/I3/I6 quantifiers well-defined.
4. State Pass's comparison universally over observed calls in the Running episode;
   add a `failed` writer (BindFail/NoAdmit/Close on a required stage ⇒
   `status=failed`) to complete the lifecycle.

With edits 1–3 applied, I1–I6, I8, I9 are inductive invariants and I7 a finite
bound under A0–A9, and the draft's §4/§9 claims hold as written. Without edit 1,
I1 and I3 remain vacuous and the central "no unbound hop" guarantee is not a
substantive theorem — hence SURVIVES WITH CONDITIONS.
