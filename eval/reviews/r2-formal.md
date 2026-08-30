# Formal review r2

Reviewed head: 3e9d70fe6600348f063250d4f30114011355e916
Verdict: SURVIVES WITH CONDITIONS

Lens: formal methods. Scope: `paper/DRAFT.md` and `paper/INVARIANTS.md` only. I check
whether the claimed invariants I1–I9 are theorems of the transition system in
`INVARIANTS.md` §2 under axioms A0–A7, using the state in §1. "Closes" means the claim
is entailed by the transitions plus the cited axioms with no unstated premise. Read-only.

## Summary of the machine as modeled

Per-stage state: `pc ∈ {Open, Admitted, Running, Passed, Closed, Stopped}`, write-once
`c, body`, current `a`, `m_exec`, `tried ⊆ A`, `pub`. Item state: `authors ⊆ A`,
`required`, `status`. Sole writers, read off §2:

- `c, body` — Open only.
- `a` — Admit only.
- `m_exec` — Bind only (`m_exec ← φ(a)`).
- `tried` — Open (reset) and Admit (grow by one unused `a`).
- `authors` — Pass on a writing stage (grow only).
- `status=accepted` — Accept only.

These sole-writer facts are the backbone of the proofs and hold as read.

## Theorems that close

**I4 (class/body frozen) — closes, cleanly.** Open is the only writer of `c, body`,
which are write-once. No transition rewrites them. Pure sole-writer argument; no axiom
beyond the write-once tag. This is the strongest invariant in the set and several others
lean on it.

**I5 (accept coverage) — closes.** Accept's guard is "all required Passed" and, by A4,
Accept is enabled only when each `s ∈ required` has a pass record; Accept is the sole
writer of `status=accepted`. Passed has no outgoing transition in §2, so "Passed" is
monotone (no un-pass), which is what the coverage claim needs. Entailed by A4 + sole
writer. (Note it is close to a restatement of A4, but that is legitimate: A4 is the
premise, I5 is its consequence on `status`.)

**I9 (retry preserves class) — closes, given I4.** Retry's effect is "back to Admit,
`c` unchanged"; Admit does not write `c`. Direct corollary of I4.

**I1 (bind integrity) — closes, conditioned on A1.** Bind establishes
`m_exec = φ(a)` hence `norm(m_exec)=norm(φ(a))` at entry to Running; `a` cannot change
in Running (Admit sets `pc=Admitted`, and there is no Running→Admit edge), and `m_exec`
has no other writer. A1 is exactly the premise that no out-of-band data-plane call
violates the equality while Running; Pass propagates the equality into Passed without
touching either field. Honest status: the Running clause of I1 *is* A1 — the theorem is
"Bind establishes, A1 preserves, Pass propagates." It closes as a theorem-under-A1, not
as a fact derivable without A1. The draft already frames A1 as an obligation, so no
overclaim; I flag it only so the report is precise about what carries the weight.

**I3 (no unbound hop) — closes, given I1 and I2.** From I1,
`norm(m_exec)=norm(φ(a))`; from I2, `a ∈ π*(c)\δ(c)`; therefore
`norm(m_exec) ∈ {norm(φ(x)) : x ∈ π*(c)\δ(c)}`. Sound composition. It inherits every
condition attached to I1 (A1) and I2 (below).

**I6 (dual control) — closes at Admit, definitional from A6.** On a check stage
`π* = π_chk(c,authors) = π(c)\authors`, so the Admit guard `a ∈ π*(c)\δ(c)\tried`
forces `a ∉ authors` at Admit time. The theorem is scoped "at Admit," which is exactly
what A6 gives. It does not claim `a ∉ authors` throughout Running, and it should not.

**I2 (class admission) — closes only under a sequential-stage reading.** At Admit,
`a ∈ π*(c)\δ(c)\tried ⊆ π*(c)\δ(c)`; `a` is not rewritten and `c` is frozen (I4), so the
membership is carried to Running/Passed — *provided the set `π*(c)` is itself stable
between Admit and Passed.* On writing stages `π* = π(c)` is stable and I2 closes without
reservation. On check stages `π* = π_chk(c,authors)` depends on `authors`, which Pass
grows. If two stages of one item can be Running concurrently (the machine is written
per-stage but `authors` is item-global shared state), a specialist admitted while
`a ∉ authors` could later fall into `authors`, so "`a ∈ π*(c)\δ(c)` while pc∈{Running,
Passed}" is not invariant under interleaving. Under the implicit assumption that stages
of one item are totally ordered (no concurrent Running stages), or if I2 is read at
admit-time like I6, it closes. As literally quantified over `pc ∈ {Running, Passed}` with
a mutable `authors`, it needs that assumption made explicit.

## Gaps that still block a proof

**I8 (store only accepted) — does not close on A0–A7.** The transition system in §2 has
no store state variable and no store-write transition; the only field Accept writes is
`status`. The proof "sole writer" asserts a property of a component that is outside the
modeled machine. There is no axiom of the form "the artifact store is written only by
Accept." As stated, I8 is an enforcer obligation of the same kind as A1/A2, not a theorem
of the presented system. It closes the moment such an axiom is added, but today it is
claimed as a theorem while resting on an unmodeled interface.

**I7 (stage termination) — the admit bound closes; the "reaches Passed or Stopped"
clause overclaims, and finiteness is unstated.** Each Admit consumes one element of
`π*(c)\δ(c)` (guard `a ∉ tried`, effect `tried ← tried∪{a}`), so the number of Admits is
bounded by `|π*(c)\δ(c)|` — a clean well-founded-descent argument. Two defects in the
statement:
1. Finiteness of `π*(c)\δ(c)` (equivalently of `A` or `π(c)`) is used but not an axiom.
   A0–A7 never assert any set is finite.
2. "Reaches Passed or Stopped" is stronger than what the transitions give. From Closed,
   Ask ("wait; no pass") keeps the stage at Closed indefinitely; the machine can idle at
   Closed forever without ever reaching Stopped. The genuine theorem is *bounded Admits*
   (the admit loop cannot run forever), not *reaching a terminal Passed/Stopped state* —
   the latter is a liveness claim, and the paper itself disclaims liveness. As worded, I7
   asserts a terminal-state guarantee it does not have.

**I2/I6 shared-state quantification (see I2 above).** The per-stage transition system does
not model concurrency over the item-global `authors`. Either the sequential-stage
assumption or an admit-time snapshot of `authors` must be stated for the check-stage cases
of I2 to be unambiguous.

**Adjacent, not an invariant but load-bearing for the paper's separation claim
(§4 INVARIANTS):** "the unique maximizer binds `m`" needs a tie-breaking/strictness
premise (that the objective strictly prefers a served reply, and that `F` contains a
usable bind strictly beating BindFail). It is a one-step trace argument, not one of
I1–I9, so it does not affect the invariant verdict, but "unique" should be softened to
"a maximizer" or given the strictness premise.

## What is solid

The sole-writer discipline is real and the proofs that lean on it (I4, I5, I9, and the
Bind/Pass propagation in I1/I3) are valid. A0 keeps `π\δ` well-defined. A4 backs I5, A6
backs I6, A7 backs the descent in I7. Nothing here is circular. The defects are: one
invariant proved about an unmodeled component (I8), one invariant whose statement is
stronger than its proof (I7), and one quantification ambiguity under shared mutable state
(I2 check-stage). None of these are fatal; each has a one- or two-line fix.

## Smallest remaining edits

1. **I8:** Add an axiom (e.g. A8) "the artifact store's sole write path is the Accept
   transition; no other actor writes accepted artifacts," *or* add a store field to §1
   written only by Accept. Then I8 is one line by sole-writer. Without this, demote I8
   from "theorem" to "enforcer obligation" beside A1/A2.
2. **I7:** (a) Add a finiteness axiom: `A` finite (hence every `π(c)\δ(c)` finite).
   (b) Reword to the claim actually proved: "a stage executes at most `|π*(c)\δ(c)|`
   Admits; the admit loop cannot run forever." Drop or separately caveat "reaches Passed
   or Stopped," since Ask permits indefinite idling at Closed (consistent with the stated
   liveness disclaimer).
3. **I2 (and I6):** State that stages of one item are totally ordered (no two Running
   concurrently) *or* that `π_chk` reads an `authors` snapshot taken at the stage's Open,
   and restate I2's guarantee at Admit time to match I6's scoping. One sentence in A6 or a
   new A9 suffices.
4. **I1:** No edit required; optionally note in the proof line that the Running clause is
   discharged by A1 (already implied). Precision only.
5. **§4 separation:** Replace "the unique maximizer" with "a maximizer," or add the
   strictness/tie-break premise. Non-blocking for I1–I9.

With edits 1–3 applied, I1–I9 all close as theorems of the abstract machine under
A0–A8/A9. The verdict is SURVIVES WITH CONDITIONS because I8 and I7 are, as written,
overstated relative to A0–A7, and I2's check-stage case depends on an unstated
sequential-stage assumption.
