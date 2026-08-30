# Proofs

Roque Briceño. Inductive proofs of I1–I17 on the machines in `INVARIANTS.md`.
No quality. No item liveness.

Notation. A **trace** is a finite sequence of transitions from the initial state
(`pc` unset, `S=∅`, no item). Each step applies exactly one enabled row.
`π*` at a step is the Admit-time snapshot (A4, A6).

## I1 Bind integrity

**Claim.** `pc=Passed ⇒ norm(m_exec)=norm(m_decl)=norm(φ(a))`.

**Proof.** Induction on trace length.

Base. Initial: `pc≠Passed`. Holds.

Inductive step. The only transition that sets `pc=Passed` is Pass.
Pass is enabled only if `m_exec≠none` and `norm(m_exec)=norm(m_decl)`.
`m_decl` is written only by Bind, which sets `m_decl=φ(a)`.
No transition after Bind overwrites `m_decl` until the next Admit, which
also clears `m_exec` and leaves `Passed`.
Hence at Pass, `norm(m_exec)=norm(m_decl)=norm(φ(a))`.

Observe may set `m_exec≠φ(a)`. Then Pass is disabled and PassRefuse is
enabled. That path never reaches `Passed`. □

**Remark.** If Bind wrote `m_exec`, the Pass guard would be tautological.
Observe is what makes I1 non-vacuous.

## I2 Class admission

**Claim.** `pc∈{Running,Passed} ⇒ a ∈ π*(c)\δ(c)`.

**Proof.** `a` is written only by Admit. Admit requires
`a ∈ π*\δ\tried`. Bind, Observe, Pass do not write `a`.
A4: stages sequential, so `π*` is the snapshot at that Admit. □

## I3 No unbound hop

**Claim.** No state with `pc=Passed` has
`norm(m_exec) ∉ {norm(φ(x)) | x ∈ π*(c)\δ(c)}`.

**Proof.** I1 gives `norm(m_exec)=norm(φ(a))`.
I2 gives `a ∈ π*\δ`. □

## I4 Frozen class and body

**Claim.** After Open, `c` and `body` are constant on that item.

**Proof.** Inspection: no other row writes `c` or `body`.
A class change is a new `id` by definition. □

## I5 Accept coverage

**Claim.** `status=accepted ⇒` every `s∈Required(c)` has `pc=Passed`.

**Proof.** Accept is the only writer of `status=accepted` and is enabled
only while `status=open` and every required stage has Passed. The status guard
also makes the row one-shot: an accepted item cannot emit a second Accept. □

## I6 Dual control

**Claim.** On a check-stage Admit, `a ∉ authors`.

**Proof.** A6: `π_chk=π(c)\authors`. Admit requires `a ∈ π*\δ\tried`.
A4: `authors` snapshotted at Admit. □

## I7 Bounded admits

**Claim.** A stage enables Admit at most `|π*(c)\δ(c)|` times.

**Proof.** A0: that set is finite. A7: Admit requires `a∉tried` and
adds `a` to `tried`. Each Admit strictly decreases the remainder.
Ask may idle; the bound is on Admit count, not on reaching Passed. □

## I8 Store only accepted

**Claim.** `id∈S ⇒ status=accepted`.

**Proof.** A8: Accept is the only writer of `S`. Accept sets
`status=accepted` in the same step. `status` is otherwise written only by
Open (fresh id) and NoAdmit; NoAdmit requires `pc∈{Open,Closed}`, and once
Accept has fired every stage is Passed, so no writer of `status` is enabled
on an accepted item and the implication holds of every later state. □

## I9 Retry preserves class

**Claim.** Retry does not change `c`.

**Proof.** Retry’s effect list does not write `c`. I4. □

## I10 Work and envelope pinning

**Claim.** A work item's `(P_v,K_v)` is write-once at Open. Within one gate attempt, the counter/nonce, base-envelope hash and `S0` remain constant until Close.

**Proof.** WorkOpen is the only transition that writes the work pin. EnvelopeAdmit reads that pin, creates a fresh counter/nonce, computes `X`, and freezes `S0`. BuildPackage, Receipt, AppendSteering and GatePass do not write those fields. AppendSteering writes a separate continuation chain. A base change requires Close and a new EnvelopeAdmit. □

## I11 Package/receipt compliance

**Claim.** GatePass implies the adapter-observed package hash equals the FCD expected hash for the current attempt/nonce.

**Proof.** BuildPackage deterministically writes the expected hash. Receipt is the only transition that writes a valid package acknowledgement and guards equality plus current attempt/nonce. GatePass requires that acknowledgement. ReceiptRefuse closes every mismatch. This proves receipt-level equality under A10; it does not prove physical model input without A10. □

## I12 Fresh-blind manifest exclusion

**Claim.** For `fresh_blind`, manifest categories are disjoint from the defined excluded author-context set and no continuity hint is admitted.

**Proof.** Canonical package categories are `include\exclude`; exclude wins. EnvelopeAdmit rejects `fresh_blind` unless continuity is `fresh`. BuildPackage cannot add a category outside the effective set. A10 is still required to rule out hidden executor prefix/session residue. □

## I13 Accepted-only serialized promotion

**Claim.** Project memory changes only by accepted knowledge delta under one successful CAS. A failed CAS cannot promote.

**Proof.** Promote is the sole memory writer. Its guard requires accepted item status and expected head equal to the current head. A13 serializes competing transitions, so at most one transition from one base succeeds. The winner advances the head; every loser observes a mismatch and takes PromoteRefuse, which has no write. □

## I14 No silent context drift

**Claim.** A work item cannot silently change its Open-pinned `(P_v,K_v)`.

**Proof.** I10 makes the pin write-once. ImpactReview records a decision against a newer head but does not rewrite the pin. `refresh` closes the old attempt and creates a new work revision/envelope. `continue_pinned` rebinds only the promotion CAS expectation to the exact reviewed head; another head advance invalidates the review. □

## I15 Steering scope and acknowledgement

**Claim.** Steering cannot write outside its declared scope or accepted state, and GatePass requires acknowledgement of the latest continuation hash.

**Proof.** AppendSteering guards scope membership in the same work item and rejects accepted targets. Its only write is an append plus chained continuation hash. Each append clears acknowledgement. Receipt records acknowledgement only for the latest hash. GatePass requires current acknowledgement. □

## I16 FCD cache identity

**Claim.** An FCD cache hit implies equality of the current attempt-local identity, including nonce, envelope, context mode, `S0` and latest continuation hash.

**Proof.** The FCD key is the hash of those fields. A11 assumes collisions do not occur — a colliding key here would produce a spurious *hit*, so this proof uses A11 in the fail-open direction and holds only under it. Admit/Close clear the cache. A differing field either changes the key or crosses a clear boundary, producing a miss. Executor/provider cache telemetry is not an FCD hit and has no Pass guard. □

## I17 Current-attempt receipt binding

**Claim.** GatePass cannot use a package, executor/run, steering or model receipt from another attempt.

**Proof.** Receipt requires the current attempt ID and nonce for every bound field. I10 fixes them within an attempt; EnvelopeAdmit creates a fresh nonce on retry. A11 is used in the fail-open direction here too: a colliding stale receipt would be *accepted*, so the theorem holds only under the assumption that collisions do not occur. Any stale field takes ReceiptRefuse, not GatePass. □

## What is not proved

- **Quality** of a Passed body.
- **Item liveness.** BindFail / empty remainder / Ask idle can make
  Accept unreachable.
- **F2** without a runtime-instance field.
- **A1/A2 on a partitioned host.** A9 says the watchdog emits
  `death_observed` in finite time if it can see the pid. If it cannot,
  F4 is an estimate on the log.
- **Provider fidelity.** Observe records what the client reports.
  If the provider lies about the model that ran, I1 holds of the
  report, not of physics.
- **Norm injectivity.** `norm` strips a bracketed display suffix only;
  vendor and namespace prefixes are significant (`fcd/core.py`). Distinct
  API ids can still collide if they differ only inside brackets. I1/I3
  hold up to that collision unless `norm` is injective on
  $\phi(\pi^*\setminus\delta)\cup\{\text{observed}\}$.
- **Re-observe.** Observe overwrites `m_exec`. I1 is the Pass-time
  value, not “no mismatched call ever occurred.” First-Observe mismatch
  is a misbind metric, not a Pass gate.
- **Body provenance.** Nothing ties `m_exec` to how `body` was produced.
- **Physical context isolation.** I11/I12 prove manifest/package/receipt properties. A10 is required to rule out hidden executor prefixes or session residue.
- **Adapter honesty.** A forged package/model/steering receipt can satisfy the abstract guards.
- **Executor/provider cache neutrality.** Internal cache/session behavior is telemetry and capability, not FCD authority.
- **Impact-review correctness.** `continue_pinned` promotion relative to a newer head relies on A12.
- **Instruction meaning.** Deterministic tool/authority conflicts block Admit; natural-language semantic contradiction is not generally decidable.

## Executable form

`tests/test_invariants.py`, `tests/test_core.py`, and `tests/test_context_envelope.py` drive the same transition guards. A failing test is a counterexample to the corresponding claim on the Python machine.
That is a proof about the core, not about an uninstrumented host.
