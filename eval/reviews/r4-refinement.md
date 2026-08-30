# Refinement review r4
Reviewed head: a8c7195b60f438f3f168d41e442d8d4d1bec3c64
Verdict: SURVIVES WITH CONDITIONS

Scope: read-only refinement of the fail-closed class-dispatch machine.
Sources read: `paper/PROOFS.md`, `enforcer/machine.py` (both at the exact head).
Focus: does the `Observe` transition make invariant **I1** (bind integrity,
`pc=Passed ⇒ norm(m_exec)=norm(m_decl)=norm(φ(a))`) a *real* machine check
rather than a tautology, as the I1 remark claims.

## Does Observe close the vacuity hole

Yes. At the machine level the remark in `PROOFS.md` ("If Bind wrote `m_exec`,
the Pass guard would be tautological. Observe is what makes I1 non-vacuous.")
is faithful to the code. Verified writer-set facts:

1. **Bind never writes `m_exec`.** The only non-`None` writer of `m_exec` is
   `observe` (line 134, `st.m_exec = m_exec`, the externally supplied argument).
   `admit` (line 86) and `bind` (line 126) only *clear* it to `None`. So the
   executed-model value is never sourced from `φ(a)`; it is sourced from a
   report handed in from outside the guard.
2. **`m_decl` is the declared value and is sourced independently.** The only
   non-`None` writer of `m_decl` is `bind` (line 125, `declared = φ(st.a)`).
   The two sides of the equality therefore come from two different origins —
   policy (`φ(a)`) vs. the caller's report — which is exactly the condition a
   non-vacuous equality check needs.
3. **Observe is mandatory on the path to `Passed`.** `pc="Passed"` is set only
   in `decide_pass` (line 157), which is guarded by `pc=="Running"` **and**
   `m_exec is not None` (line 149). After `bind` sets `m_exec=None`, the only
   transition that can make it non-`None` is `observe`. Hence no trace can reach
   `Passed` without first executing `Observe`. The guard cannot be skipped.
4. **The guard can genuinely fail.** `observe` accepts an arbitrary string, so a
   reachable state with `norm(m_exec) != norm(m_decl)` exists; `decide_pass`
   routes it to `fail_closed / F1` (lines 151–156) instead of `Passed`. The
   check discriminates.

Together these make the I1 induction sound and non-trivial: the sole
`Passed`-setting branch requires the two independently-sourced normalized names
to be equal, and reaching that branch forces an `Observe`. The proof's claim
that "the only transition that sets `pc=Passed` is Pass" and that "Observe may
set `m_exec≠φ(a)`, then Pass is disabled" both hold against the code.

One proof-to-code fidelity note (not a defect): `PROOFS.md` describes a
two-row table (`Pass` enabled only on match; otherwise `PassRefuse`). The code
fuses these into a single `decide_pass` method that branches internally to
`F1` on mismatch. The invariant is preserved because the `Passed` branch still
requires the match, but the mapping is not row-for-row; a reader checking the
"enabled/disabled" framing against the source should expect a branch, not a
disabled row.

## What still cannot transfer to a real client

The vacuity hole is closed *for the machine*. The following gaps mean I1's
guarantee does not carry to an uninstrumented, real executing client. The first
is already disclosed in `PROOFS.md`; the rest are refinements this review adds.

- **Report trust (disclosed).** `m_exec` is whatever the caller passes to
  `observe`. If the executor misreports the model that actually ran, I1 holds of
  the *report*, not of the physical execution. The machine has no attestation
  binding the report to real compute. `PROOFS.md` states this under "Provider
  fidelity"; it remains the dominant transfer limit.
- **`norm()` collapses distinctions (not disclosed).** `norm` keeps only the
  segment after the last `:` and drops everything from `[` onward (lines 12–16).
  So a provider prefix and any bracketed parameters are erased before the
  equality. Two materially different real executions that share a bare name —
  different provider, or different sampling/params such as `name[temp=0]` vs
  `name[temp=1]` — normalize identically and pass. I1 therefore binds only the
  normalized short name, not the provider or the run configuration. A real
  client should not read I1 as pinning "the same model instance."
- **Re-observe-until-match (not disclosed).** `observe` is a last-writer-wins
  overwrite that stays in `Running` and triggers no fail-close by itself. A
  caller may `observe` a mismatching value and then `observe` again with a
  matching one before `decide_pass`; the machine passes cleanly and only the
  event log retains the earlier `call`. Nothing in the guard consumes the log's
  `on_bind`/`first_attempt` fields. I1 (the state at `Passed`) still literally
  holds, but the *intent* — that the reported execution matches the declaration
  on the run that produced the body — is not enforced across repeated reports.
- **No binding of report to artifact (not disclosed).** `body` is frozen at
  `Open` (I4), but `m_exec` is an independent later claim. Nothing ties the
  observed model to the content of `body`; a correct `m_exec` string alongside a
  body produced by something else satisfies I1.
- **Single-report abstraction (not disclosed).** One `m_exec` string represents
  the stage. A real client mixing models or issuing multiple sub-calls presents
  a single normalized name to the machine; per-call physical fidelity is outside
  I1's reach.

None of these are machine defects — the induction is valid on the Python
machine, and the executable table (`tests/test_invariants.py`) tests exactly
that. The conditions are scope/disclosure: `PROOFS.md` already fences quality,
liveness, F2, partitioned-host A1/A2, and provider fidelity, but the
`norm()`-collapse and re-observe-until-match gaps above are not surfaced in
"What is not proved." Adding them would make the transfer boundary honest.

## Verdict rationale

On the narrow question posed — does `Observe` make I1 a real machine check —
the answer is unambiguously **yes**, and the code backs the proof's remark.
The overall verdict is **SURVIVES WITH CONDITIONS** only because two real-client
transfer gaps (`norm()` collapse of provider/params, and re-observe-until-match)
are undisclosed in the "What is not proved" list. These are documentation/scope
conditions, not counterexamples to the invariant on the machine.
