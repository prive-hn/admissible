# Formal review r4

Reviewed head: a8c7195b60f438f3f168d41e442d8d4d1bec3c64

Verdict: SURVIVES WITH CONDITIONS

Scope: read-only formal review of the fail-closed class dispatch machine. Sources
read at the exact head: `paper/DRAFT.md`, `paper/INVARIANTS.md`, `paper/PROOFS.md`,
`enforcer/machine.py`. Claims below were checked against the transition table and
re-derived on the executable machine. No paper or enforcer file was modified.

## Is I1 non-vacuous

**Yes.** I1 (`pc=Passed ⇒ norm(m_exec)=norm(m_decl)=norm(φ(a))`) is now a real
constraint rather than a tautology, in both senses that matter.

1. **The writers are split.** Bind writes the declared identity only. In the table,
   `Bind | Admitted ∧ u(φ(a))=1 | m_decl ← φ(a); pc=Running`, with the explicit line
   "Bind does not write `m_exec`." The machine agrees: `bind()` sets
   `st.m_decl = declared` and `st.m_exec = None`, then `pc="Running"`. The only writer
   of a non-None `m_exec` is `observe()`, guarded on `pc="Running"`, taking the value
   from its argument (the provider report). Admit clears both to `none`. So the value
   compared at Pass does not originate from the same write as the declared value.

2. **The Pass guard is a genuine filter with a live refusal path.** Because the observed
   value is supplied independently of `m_decl`, there exist reachable Running states with
   `norm(m_exec) ≠ norm(m_decl)`. In those states Pass is disabled and PassRefuse fires
   (F1, publish, Close). I reproduced both branches on the machine:
   - match → `pc=Passed`, item enters the store;
   - `observe` of a different identity → `pc=Closed`, `fault=F1`, not stored.
   PassRefuse is therefore live code, not a dead row. This is exactly the round-3 defect
   the head repairs: in round 3 Bind wrote `m_exec ← φ(a)`, so the guard held by
   construction and PassRefuse was unreachable. That path is gone.

3. **Passed is reachable**, so I1 is a non-empty claim (open → admit → bind(u=1) →
   observe(φ(a)) → Pass). The antecedent is satisfiable and the consequent is a filter
   that can and does fail; both conditions for non-vacuity hold.

The remark in `PROOFS.md` §I1 ("If Bind wrote `m_exec`, the Pass guard would be
tautological. Observe is what makes I1 non-vacuous.") is now faithful to the machine.

## Theorems that close

On the machine at this head, under A0–A9, the following are sound:

- **I1 (Bind integrity).** Pass is the only writer of `pc=Passed`; enabled only when
  `m_exec≠none` and `norm(m_exec)=norm(m_decl)`. `m_decl` is written only by Bind
  (`=φ(a)`) and is not overwritten before Pass: while Running, only `observe`
  (writes `m_exec`), `decide_pass`, and `close` are enabled, none touch `m_decl`; Admit,
  which would clear it, requires `pc∈{Open,Closed}` and cannot fire on a Running or
  Passed stage. A Passed stage is never re-admitted (the pointer only advances; retry
  acts on Closed stages). Induction closes. **Closes** — conditioned as noted below.
- **I2 (Class admission).** `a` is written only by Admit under `a∈π*\δ\tried`; Bind,
  Observe, Pass do not write `a`; A4 fixes the snapshot. **Closes.**
- **I3 (No unbound hop).** Immediate from I1 (`norm(m_exec)=norm(φ(a))`) and I2
  (`a∈π*\δ`). **Closes**, conditional on I1.
- **I4 (Frozen class/body).** Only `open()` writes `cls`/`body`; no other row does.
  **Closes.**
- **I5 (Accept coverage).** `accept()` is the only writer of `status=accepted` and
  re-checks `all(stage.pc=="Passed")` at the step, including on the internal call from
  `decide_pass`. **Closes.**
- **I6 (Dual control).** `pi_star` subtracts `authors` when `kind=="check"`; Admit
  requires `a∈π*\δ\tried`; A4 snapshots `authors` at Admit. **Closes.**
- **I8 (Store only accepted).** `self.store.add` occurs only inside `accept()`, in the
  same step that sets `status=accepted`; `store_put` raises. **Closes.**
- **I9 (Retry preserves class).** Retry is modeled as Admit from Closed; `admit()` does
  not write `cls`. **Closes.**
- **I7 (Bounded admits).** A bound, not termination: `tried` is monotone and Admit
  rejects `a∈tried`, so Admit fires at most `|π*\δ|` times per snapshot. **Closes as a
  bound**, with the paper's own caveat that it is not item liveness.

This matches DRAFT §4/§9: I1–I6, I8, I9 inductive; I7 a bound.

## Remaining proof gaps

None of these overturn I1's non-vacuity, but two bear directly on how much I1 actually
buys and should be stated as assumptions or scoped explicitly.

1. **`norm` is not injective — unstated assumption behind I1/I3.** Equality is defined as
   `norm(x)=norm(y)` (A5). But `norm` strips to the final `:`-segment and truncates at
   `[`, so distinct API identities can collapse to one string (verified:
   `norm("vendorA:gpt") = norm("vendorB:gpt") = "gpt"`). If φ maps two members of the
   relevant identity set — or an allowed and a denied member — to identifiers that collide
   under `norm`, PassRefuse can be bypassed and I3's "no unbound hop" weakens accordingly.
   I1/I3 are only as strong as `norm` being injective on `φ(π*\δ) ∪ {observed}`. That
   injectivity is neither assumed nor proved. **Condition:** add it as an assumption
   (norm injective on the in-scope identity set) or prove it for the deployed identity
   space; otherwise I1 is safety up to norm-collision.

2. **Repeated Observe means I1 guards only the Pass-time report, not the execution
   history.** The table's `Observe(m) | Running | m_exec ← m` has no write-once guard, and
   `observe()` overwrites on each call. A trace that Observes a mismatching identity, then
   Observes the declared one, then Passes is accepted (reproduced on the machine). So I1
   constrains the terminal recorded value at Pass, not "no execution ever occurred on an
   unbound model." The first-Observe mismatch is captured only by the misbind *metric*
   (INVARIANTS §5), not by the safety gate. This is defensible as stated — I1 is a property
   of the Passed state — but the paper should say so plainly, because the natural reading
   ("a pass record uses φ(a)") is stronger than what is proved. **Condition:** make explicit
   that I1 is over the Pass-time `m_exec`, or add a write-once/first-Observe-binds rule if
   the stronger property is intended.

3. **Provider fidelity ceiling (acknowledged).** `observe()` records what the client
   reports. I1 holds of the report, not of physics; a lying provider satisfies I1 while
   executing elsewhere. The paper scopes this out (PROOFS "Provider fidelity", DRAFT §9).
   No change required, but it caps the entire claim at report-integrity.

4. **A1 totality is assumed, not enforced (acknowledged).** `decide_pass` requires
   `m_exec≠None`, forcing some Observe, but nothing binds the observed value to the true
   data-plane call. A never-called Observe strands the stage in Running — item liveness
   (not claimed) and F4 (external watchdog) territory. Scoped out via A1/A2/A9.

5. **F2, item liveness, A2/A9 under partition (acknowledged).** F2 needs a runtime-instance
   field and is not modeled; item liveness is not claimed; under partition F4 is an estimate.
   All are declared limits, not defects.

Bottom line: the round-3 defect is genuinely closed at this head — Bind writes `m_decl`,
Observe writes `m_exec`, and PassRefuse is a live path — so I1 is non-vacuous and the
claimed theorems close on the machine. The verdict is conditioned on stating norm
injectivity and on scoping I1 to the Pass-time report value.
