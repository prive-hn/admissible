# Refinement review r3

Reviewed head: 6b450a508fab00227ccc7da9028a314a955dc12e
Verdict: SURVIVES WITH CONDITIONS

Lens: refinement / proof obligations. Read-only; `DRAFT.md` and `INVARIANTS.md`
only. The question is not whether the invariants are *stated* correctly but
whether the abstract machine actually discharges them, or whether the work has
been quietly relocated from the axioms into an unstated obligation on the log.

Short answer:

- A1 and A2 no longer smuggle their conclusions **into the axioms**. The split
  (totality vs equality for A1; observability vs publication for A2) is the
  correct refinement discipline and is an honest improvement.
- A8 genuinely makes **I8 a machine theorem** — the cleanest result in the file.
- PassRefuse is *intended* to make **I1 a machine theorem**, and it supplies the
  branch, but as the transition table is written I1 is **vacuous**: nothing ever
  writes an `m_exec` that differs from `φ(a)`, so PassRefuse is unreachable and
  the substantive check has been relocated into A1-fidelity, which A1 explicitly
  disclaims. The smuggle is not eliminated; it is moved off the axiom and onto an
  *unstated* obligation about where `m_exec` comes from.
- F4-freedom is not a machine theorem in the sense I1/I8 are, and cannot be. It
  is the *absence* of a transition, not the *choice* of a guard; a real crash
  takes no transition at all.

That combination is why the verdict is SURVIVES WITH CONDITIONS rather than
SURVIVES: the safety claims are true on the machine, but two of the three load-
bearing ones (I1's content, F4's absence) transfer to a real log only under
obligations the paper has pushed outside the transition system without naming
them.

## Do A1 and A2 still smuggle I1 or F4

**A1 — no smuggle in the axiom, but I1 is vacuous as tabulated.**

A1 (`INVARIANTS.md:11`) now asserts only that every data-plane call while
`pc=Running` is *recorded* as a `call` event carrying `m_exec`, and explicitly
does **not** assert `m_exec = φ(a)`. That is the right shape: totality is an
observation obligation, equality is I1, and the axiom no longer presumes the
theorem. On that axis the conclusion is not smuggled. Good.

The problem is one layer down, in the transition table (`INVARIANTS.md:53,55,56`):

- `Bind` does `m_exec ← φ(a)`.
- `Pass` guard is `norm(m_exec)=norm(φ(a))`.
- `PassRefuse` guard is `norm(m_exec)≠norm(φ(a))`.

There is **no transition that writes `m_exec` from the recorded `call` event.**
`Bind` pre-commits `m_exec` to exactly the value `Pass` wants, and nothing
overwrites it. Therefore, on the machine as written:

1. `norm(m_exec)≠norm(φ(a))` is unsatisfiable — PassRefuse is dead code.
2. I1 (`Passed ⇒ norm(m_exec)=norm(φ(a))`, `:67`) holds *vacuously*: `m_exec`
   was set to `φ(a)` at Bind and never changed. The proof text at `:68` ("A later
   observed call with a different `m_exec` enables PassRefuse") describes an
   `m_exec` update that no transition performs.

So PassRefuse does **not** yet make I1 a *substantive* machine theorem. It makes
I1 true, but true the way `x = x` is true. The real discriminating work — does the
model the provider *actually executed* match the bound identity — has been moved
entirely into A1, and A1 disclaims exactly that equality. The conclusion I1 was
supposed to earn is now resting on an obligation ("the recorded `m_exec` is the
model that actually ran") that appears nowhere: not in A1 (totality only), not in
A5 (`norm` only), not in the table (Bind writes intent, not observation). That is
the residual smuggle: relocated from the axiom into an unnamed fidelity assumption
on the event source.

Draft §3 (`DRAFT.md:55`) says "Declared binding is not evidence... A1 only
requires that the executed call is **seen**. Whether it equals `φ(a)` is I1." The
intent is clearly that `m_exec` = the seen executed model. The table encodes the
opposite: `m_exec` = the declared model, frozen at Bind. Intent and encoding
disagree, and I1 is proved against the encoding.

**A2 — no smuggle, but F4-freedom is not recovered as a theorem.**

A2 (`:13`) asserts death while `pc=Running` is *recorded* and explicitly does not
assert that a `fail_closed` is published; publication is the Close transition and
its absence is F4. Again the correct split, no smuggled conclusion.

But note what this leaves. I1 and I8 are inductive invariants: the machine has a
guard (Pass / Accept) and, for the bad case, an explicit alternative transition
(PassRefuse / no-op). F4-freedom has no such shape. F4 (`:132`) is "Running exit
with `pub=0`" — i.e. the *absence* of a silent-death transition. The Close
transition (`:57`) sets `pub=1`, and there is no tabulated "die without Close."
So "no F4" is structurally true on the machine only because the bad transition
was never written down — and a real crash (SIGKILL, OOM, partition) does not
execute any transition, including Close. A2 gives you observability, but the
observer that turns a recorded death into a Close must *survive* the death, and
that survivor is outside the item's own transition system. Consequently "no F4"
is not inductive on this machine the way I1/I8 are; it is a liveness obligation on
an external monitor. The paper is honest that A2 is observation-only and F4 is a
fault, but it should not be read as implying the machine proves F4-freedom. It
does not, and cannot from inside the process.

**A8 / I8 — this one is a genuine machine theorem.**

A8 (`:25`) pins Accept as the sole writer of `S` with `S ← S ∪ {id}`. I8
(`id ∈ S ⇒ status=accepted`, `:88`) is properly inductive: base `S=∅` vacuous;
step — the only writer is Accept, whose guard is "all required Passed" and whose
effect sets `status=accepted`; and no transition ever moves `status` out of
`accepted` or removes an id from `S`, so the postcondition is stable. A8 does make
I8 a clean machine theorem, the strongest result here. Caveat: I8 certifies
`accepted`, and `accepted` transitively carries class integrity only through the
Passed stages, hence only as strong as I1. Because I1 is vacuous as tabulated
(above), I8 guarantees "accepted" but "accepted" witnesses only that recorded
`m_exec` (= `φ(a)` by Bind) equalled `φ(a)` — tautological. So A8/I8 are sound but
inherit I1's emptiness for the property that actually matters.

## What a real client must implement

The machine's safety content transfers only if the implementation supplies the
obligations the table left off. Concretely:

1. **Source `m_exec` from the provider's authoritative executed-model field**
   (the served / billed model id in the response), never by echoing the declared
   `φ(a)`. Add the missing transition: an `Observe`/`Call` step that writes
   `m_exec` from the recorded `call` event, and make `Pass`/`PassRefuse`
   evaluable *only after* that write. Until this exists, PassRefuse is
   unreachable, misbind is structurally zero, and the log proves nothing.

2. **An out-of-band watchdog that survives item/process death.** Lease/heartbeat
   on every `Running` stage; a reaper that detects Running-with-no-terminal past
   the lease and publishes `fail_closed` (Close, `pub=1`). This is the only thing
   that makes A2's "death is observed" actionable; without a survivor, A2 is an
   assertion about a row that the dead process cannot write.

3. **Artifact-store admission control coextensive with Accept.** The store must
   reject any write not carrying an Accept proof — no side-door INSERT, no
   credentialed direct write. A8 says "the only transition that adds to `S` is
   Accept" *on the machine*; that transfers only if the real store enforces the
   same sole-writer discipline (DRAFT §7 "store that rejects non-accepted
   writes"). Otherwise I8 is a theorem about a set nobody enforces.

4. **Write-ahead `stage` and total `call`/`decide` emission.** Per §6
   (`INVARIANTS.md:123`, `DRAFT.md:93`), zero misbind/bleed/silent-fail is a proof
   only if `stage` is write-ahead and `call`/`decide` are total; otherwise the
   zeros are estimates biased clean. Emit the stage event before the bind, and
   make call/decide unconditional.

5. **`u(m)` from real bind-time status**, not predicted (A3): treat
   401/403/404/429/exhausted/not_found as `u=0`, fail closed, and do **not** search
   the catalog (Process step 3, `DRAFT.md:48`; F3).

6. **Persist `tried` per stage** so Retry cannot re-admit `a ∈ tried` (A7/F10),
   and **snapshot `authors` at each Admit** so `π_chk` is well-defined (A4/A6/I6).

7. **One canonicalization table for `norm`**, applied to *both* the declared and
   the executed strings, and **as-of `(π, δ, φ)` resolution at event `ts`** (§6),
   so equality and policy checks are evaluated against the version in force at the
   event, not the current pin.

## What still cannot transfer from the machine to a log

Some obligations are implementable (above). These are not — they are the residue
that no event log can close, and they bound how much the machine's theorems mean.

1. **Provider execution fidelity.** Even with obligation (1) satisfied, the log
   records the provider's *claim* about which model ran. Whether that silicon
   actually executed `φ(a)` is unobservable to the client except through the
   provider's own attestation. I1's real-world meaning is capped by provider
   honesty; the machine can compare recorded strings, it cannot witness the
   compute. This is the hard floor under I1 and, transitively, under I8.

2. **Crash publication (F4) under adversarial or partition death.** A process that
   dies before emitting Close leaves `pub=0` and *no row*. A2 asserts death is
   observed, but observation needs a live observer; under total partition, or if
   the observer itself dies, the log simply lacks the Close, and its absence is
   indistinguishable from "no death occurred." Zero-F4 over a window is therefore
   an estimate that depends on call/decide totality — and totality cannot be
   self-certified from the same log it is meant to validate. This is the
   silent-fail bias §6 already names, restated as a transfer limit.

3. **Two-specialists-one-instance (F2).** F2 needs a runtime-instance field the
   machine marks optional (`:42`, `:130`). Without it, instance/weight sharing is
   unmeasurable; a log cannot exclude F2, so "we ran distinct specialists" is not
   witnessed by the event contract as it stands.

4. **Liveness / termination.** Item liveness is explicitly not a theorem; Ask may
   idle and Accept can be unreachable (`:94`). A log showing no Accept cannot
   distinguish "correctly fail-closed" from "stuck live" except through the
   right-censored survival apparatus of §6 — and that yields an estimate, never a
   proof of termination.

5. **The vacuity trap made concrete.** Because the tabulated machine freezes
   `m_exec = φ(a)` at Bind, a faithful implementation of *the table* produces a log
   that always shows `m_exec = φ(a)`, hence zero misbind and a spotless class-
   integrity record — while proving nothing. The log has discriminating power only
   if `m_exec` is drawn from the response, not the request (obligation 1). A
   reviewer handed such a clean log cannot, from the log alone, tell a correct
   enforcer from one that echoes its own intent. That indistinguishability is the
   sharpest thing that does not transfer, and it is the direct consequence of the
   missing `m_exec` writer.

Net: the axiom-level smuggle that earlier rounds flagged is genuinely gone — A1
and A2 are split honestly. But the work those axioms shed did not disappear; for
I1 it landed on an unstated `m_exec`-provenance obligation (currently making I1
vacuous), and for F4 it landed on an external survivor the machine cannot contain.
A8/I8 are clean. Fix the `m_exec`-writer gap (add the Observe transition; source
`m_exec` from the response) and name the watchdog obligation for A2, and this
moves to SURVIVES. As written, SURVIVES WITH CONDITIONS.
