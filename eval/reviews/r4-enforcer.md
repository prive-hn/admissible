# Enforcer review r4

Reviewed head: a8c7195b60f438f3f168d41e442d8d4d1bec3c64
Verdict: SURVIVES WITH CONDITIONS

Scope: read-only review of `enforcer/machine.py`, `enforcer/watchdog.py`,
`tests/test_invariants.py` against the theorem statements in
`paper/INVARIANTS.md` (I1–I9). Tests were executed via
`python -m unittest tests.test_invariants -v`: **11/11 pass**. The machine is
genuinely fail-closed and the round-3 defect (Bind writing `m_exec`) is fixed.
The conditions below concern test *coverage* and one under-specified equality
primitive — they are not safety-violation findings against the current traces.

## Observe vs Bind

The core round-3 fix is present and correct.

- `bind(u=True)` (machine.py:114–127) writes `m_decl ← φ(a)` and explicitly sets
  `m_exec = None`, then `pc = "Running"`. It does **not** write `m_exec`.
- `observe(m)` (129–144) is the sole writer of `m_exec`, guarded on
  `pc == "Running"` (raises otherwise, 132–133).
- `decide_pass` (146–164) compares `norm(m_exec)` vs `norm(m_decl)`; a `None`
  `m_exec` trips the guard at 149 and raises, so Pass cannot fire before an
  Observe. Mismatch → Closed/pub/F1 (152–156). Match → Passed (157).

Because Bind and Observe now write disjoint fields, PassRefuse (F1) is a
reachable state rather than dead code. This is witnessed two ways:
- `test_i1_pass_requires_observe_match` — bind True → observe `model-other` →
  decide_pass yields `pc=Closed`, `fault=F1`, `w ∉ store`.
- `test_i3_no_pass_on_foreign_model` — the strong case: `alice` bound
  (`m_decl=model-a`), executed `model-b`. `model-b = φ(bob)` **is** an allowed
  model in π*, yet Pass is refused because equality is against the *bound*
  model, not the allow-set. This correctly proves I3 as stated (exec must match
  the specific bind, not merely land inside `φ(π*\δ)`).

`test_bindfail_does_not_observe` confirms the BindFail→Closed path blocks a
subsequent Observe (guard raises). Observe/Bind separation holds.

## Tests vs claimed theorems

| Inv | Test(s) | Proven? | Note |
|-----|---------|---------|------|
| I1 | `test_i1_pass_requires_observe_match`, `test_i1_pass_when_exec_equals_decl` | Witnessed | Positive + negative trace. The `=norm(φ(a))` leg holds only transitively (m_decl is set to φ(a) in bind; test asserts `m_decl=="model-a"` and `norm(m_exec)==norm(m_decl)`). No trace asserts all three equal in one shot. |
| I2 | `test_i2_i6_check_excludes_author` | **Partial** | Only the author/δ leg is exercised. **No test admits a specialist outside π*** (e.g. a name not in `allow`) to confirm rejection, and **no test mutates policy after Admit** to prove the "Admit-time snapshot" clause. Membership-at-admit is enforced structurally (admit:81) but not independently tested. |
| I3 | `test_i3_no_pass_on_foreign_model` | Yes (strong) | See Observe-vs-Bind; foreign-but-allowed model refused. Best test in the suite. |
| I4 | `test_i4_class_frozen` | **Weak/vacuous** | Asserts `cls` unchanged, but no operation ever writes `cls`, so the test is trivially true. **`body` constancy is not asserted at all** despite I4 covering both `c` and `body`. |
| I5 | `test_i5_i8_accept_only_when_all_passed` | Yes | Accept before completion raises; full two-stage completion → `accepted` + in store. Guard `all(pc==Passed)` (182) confirmed. |
| I6 | `test_i2_i6_check_excludes_author` | Yes | After `alice` writes, `authors={alice}`; check-stage admit of `alice` raises, `carol` ok. Matches `pi_star` check branch (`base -= authors`, 29). |
| I7 | `test_i7_cannot_retry_tried` | **Partial** | Proves `a ∈ tried` is rejected (the mechanism that bounds admits). Does **not** exhaust π* and confirm the ≤|π*\δ| ceiling or the NoAdmit terminal. |
| I8 | `test_i5_i8_accept_only_when_all_passed`, `test_i8_bypass_forbidden` | Yes | `store.add` occurs only in `accept` (verified: sole writer at 185), immediately after `status="accepted"` (184). `store_put` raises PermissionError; `w ∉ store`. Structural + behavioral coverage. |
| I9 | `test_i9_retry_same_class` | Yes | bind False → Closed → re-Admit `bob`; `cls` unchanged. |

Overall: the suite consists of **single-trace witnesses**, not
universally-quantified proofs. Every I-statement in INVARIANTS.md is a `∀`
implication over reachable states; each test exercises one path. The file's
docstring ("Executable proofs of I1–I9") overstates this — they are executable
*examples*. No property-based / model-checking harness (e.g. exhaustive small
state exploration) is present, so regressions on untested branches would pass CI.

## Watchdog / store gaps

1. **`norm` equality primitive is untested.** All of I1/I3 rest on `norm`
   (strips `provider:` prefix and `[...]` suffix, machine.py:12–16). Every test
   uses bare names where `norm` is the identity, so the stripping logic — the
   thing that *defines* misbind equality (A5) — has zero coverage. A too-coarse
   `norm` (e.g. collapsing versions `model-a[v1]` vs `model-a[v2]`, or two
   providers sharing a model name) would let a real misbind Pass, and no test
   would catch it. **Condition:** add cases with prefixes/suffixes/versions.

2. **`no_admit` and `close(reason="refuse")` are untested.** `no_admit`
   (103–112) sets `status="failed"`, `pub`, and emits fail_closed — never
   invoked by any test. `close` is reached only via `death_observed`; the plain
   refuse path (fault=None, 173) is unexercised. F3 (BindFail) and F4 (death)
   fault labels are also never asserted, only their `pc`/`pub` effects.

3. **Watchdog is minimally tested and has a false-death edge.**
   `test_watchdog_close_on_dead_pid` covers the dead-pid→Close path only. There
   is **no test that a live pid leaves `pc` untouched** (the negative branch of
   poll:23). Separately, `pid_alive` treats *any* `OSError` as dead — including
   `EPERM` (pid alive but not owned by this process), which would trigger a
   spurious `death_observed`→Close. This is a *safe* failure direction for a
   fail-closed machine (it over-closes, never over-accepts), so it is not a
   safety-invariant break, but it is a liveness hazard and matches A9's own
   caveat that "F4 is then an estimate." Worth a comment/test.

4. **Store integrity verified structurally.** Grep confirms `self.store` is
   mutated only at accept:185 and `status="accepted"` set only at 184 (guarded).
   I8 therefore holds beyond the single bypass test; no hidden writer exists at
   this head.

### Why SURVIVES WITH CONDITIONS (not SURVIVES)
The machine is correct and fail-closed at this head; no counterexample was
found. But the test layer does not "prove" I1–I9 as claimed — I2, I4, and I7
are partial/vacuous, and the equality primitive underpinning I1/I3 is entirely
unexercised. Close these coverage gaps (norm cases, out-of-allow admit,
policy-mutation snapshot, body constancy, no_admit/refuse paths, live-pid
watchdog branch) and the verdict lifts to SURVIVES.
