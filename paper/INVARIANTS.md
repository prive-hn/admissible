# Invariants

Roque Briceño. Safety only. Companion to `DRAFT.md` and `PROOFS.md`.

Round 3: Bind wrote `m_exec ← φ(a)`, so PassRefuse was dead. Bind now writes **declared** only. **Observe** writes **executed** from the provider call.

## 0. Assumptions

A0. `π(c) ∩ δ(c) = ∅`. `A` and `π(c)` finite.

A1. **Observation totality.** Every data-plane call while `pc=Running` produces an Observe. A1 does not assert equality with φ(a).

A2. **Death observability.** A watchdog **outside** the worker process records death while `pc=Running`. A2 does not publish fail-closed. Close does.

A3. `u(m)=0` iff bind returns 401, 403, 404, 429, exhausted, or not_found.

A4. `Required(c)` finite ordered. Stages of one item sequential. `authors` snapshotted at Admit.

A5. `norm` to API identities. Equality is `norm(x)=norm(y)`.

A6. Check admit: `π_chk(c, authors)=π(c)\authors`. Write admit: `π(c)`.

A7. Retry only `a ∉ tried`.

A8. Store `S` written only by Accept: `S ← S ∪ {id}`.

A9. Watchdog liveness for A2: if the worker pid is gone and `pc=Running`, the watchdog emits `death_observed` in finite time. Partition can delay this; F4 is then an estimate.

A10. **Adapter attestation honesty.** The adapter computes the observed package hash from bytes it actually submits; reports executor/run, steering acknowledgement and executed model truthfully; and does not inject hidden context against its declared capability. This is a physical-boundary assumption, not an FCD theorem.

A11. Hash and attempt-nonce collision resistance. A collision here would fail toward *acceptance* — a stale receipt could match a new identity (I17) or a differing attempt could hit the cache (I16) — so A11 is an assumption that collisions do not occur, not a fail-closed property.

A12. A signed impact review correctly classifies non-interference for `continue_pinned`. If incorrect, promotion safety relative to the newer project is not proved.

A13. Accept/memory promotion is globally serialized by compare-and-swap on one exact `(P_v,K_v)` head.

## 1. State

Per stage: `pc ∈ {Open, Admitted, Running, Passed, Closed, Stopped}`
`c, body` write-once.
`a` or none.
`m_decl` (Bind) or none.
`m_exec` (Observe) or none.
`tried ⊆ A`.
`pub ∈ {0,1}`.

Item: `id`, `authors`, `required`, pointer, `status ∈ {open, failed, accepted}`.
Store `S`.

Project context: accepted project version `P_v`, accepted memory version `K_v`, policy version.

Per work item: Open-pinned `(P_v,K_v)`, contract revision.

Per gate attempt: monotonic counter, nonce, immutable base envelope `X`, expected canonical package hash, package categories, initial steering hash `S0`, latest continuation hash/sequence, adapter receipt or none, FCD cache identity, state `Running|Passed|Closed`.

Project memory changes only by accepted knowledge delta under CAS.

`π*` is `π_chk` on check stages else `π`.

## 2. Transitions

| Name | Guard | Effect |
|---|---|---|
| Open | well_formed; `id` fresh | `c, body`; `tried={}`; `pc=Open`; `status=open` |
| Admit(a) | `pc∈{Open,Closed}`; `a ∈ π* \ δ \ tried` | `a`; `tried ∪={a}`; `m_decl=m_exec=none`; `pc=Admitted` |
| NoAdmit | `pc∈{Open,Closed}`; allow remainder empty | `pc=Closed`; `pub=1`; `status=failed` |
| Bind | Admitted ∧ `u(φ(a))=1` | `m_decl ← φ(a)`; `pc=Running` |
| BindFail | Admitted ∧ `u(φ(a))=0` | `pc=Closed`; `pub=1` |
| Observe(m) | Running | `m_exec ← m` |
| Pass | Running ∧ `m_exec≠none` ∧ `norm(m_exec)=norm(m_decl)` | `pc=Passed`; write-stage: `authors ∪={a}` |
| PassRefuse | Running ∧ `m_exec≠none` ∧ `norm(m_exec)≠norm(m_decl)` | `pc=Closed`; `pub=1`; F1 |
| Close | Running ∧ (refuse ∨ death_observed) | `pc=Closed`; `pub=1` |
| Retry | Closed ∧ remainder nonempty | back toward Admit; `c` unchanged |
| Ask | Closed | idle |
| Stop | Closed | `pc=Stopped`; `status` may be `failed` |
| Accept | `status=open` and all required Passed | `status=accepted`; `S ∪={id}` |

Bind does **not** write `m_exec`.

Context-envelope transitions:

| Name | Guard | Effect |
|---|---|---|
| WorkOpen | verified project selected | pin current `(P_v,K_v)` and contract revision |
| EnvelopeAdmit | gate editable; context policy valid; declared executor capability available | increment attempt; fresh nonce; freeze `X` and `S0`; state Running |
| BuildPackage | attempt Running | canonical bytes from `include\exclude`; write expected hash |
| AppendSteering | Running; scope belongs to work and is not accepted state | append ordered event; advance continuation hash; clear acknowledgement |
| Receipt | current attempt/nonce; package hash, model, executor and latest continuation match | record valid receipt/acknowledgement |
| ReceiptRefuse | any receipt field stale/mismatched | Close; no Pass/Accept |
| GatePass | valid current receipt and class-stage Pass guard | state Passed |
| ImpactReview | work pin behind current head | bind signed classification/decision to that exact current head |
| Promote | item accepted; CAS head matches; no drift or valid `continue_pinned`/owner review | advance project/memory once; append accepted knowledge delta |
| PromoteRefuse | CAS mismatch; stale/missing review; `refresh` decision | no project/memory write |

`fresh_blind` also guards `continuity=fresh` and manifest categories disjoint from excluded author context. FCD cache is keyed to the current attempt, envelope and continuation; Admit/Close clears it. Executor cache/session reuse is telemetry outside this transition table.

## 3. Theorem statements

Proofs in `PROOFS.md`. Executable checks in `tests/test_invariants.py` and `tests/test_context_envelope.py`.

- **I1** `pc=Passed ⇒ norm(m_exec)=norm(m_decl)=norm(φ(a))`
- **I2** `pc∈{Running,Passed} ⇒ a ∈ π*(c)\δ(c)` (Admit-time snapshot)
- **I3** no Pass with `norm(m_exec) ∉ {norm(φ(x)) | x ∈ π*\δ}`
- **I4** `c` and `body` constant after Open
- **I5** `status=accepted ⇒` every required stage Passed
- **I6** check Admit ⇒ `a ∉ authors`
- **I7** ≤ `|π*\δ|` Admits per stage (not termination)
- **I8** `id∈S ⇒ status=accepted`
- **I9** Retry does not write `c`
- **I10** work `(P_v,K_v)` is write-once at Open; attempt base envelope, nonce and `S0` are immutable until Close
- **I11** Pass requires adapter-observed package hash equal to FCD expected hash for the current attempt/nonce
- **I12** `fresh_blind` manifest categories are disjoint from defined excluded author context and continuity is fresh
- **I13** project memory changes only through serialized Accept/CAS; failed CAS cannot promote
- **I14** a work pin cannot change silently; refresh is a new work revision/attempt and envelope
- **I15** steering cannot write outside scope or accepted state; Pass requires latest continuation acknowledgement
- **I16** an FCD cache hit implies full current attempt/envelope/continuation identity equality; otherwise miss and clear
- **I17** package, executor/run, steering and executed-model receipts all bind to the current attempt/nonce; prior-attempt receipts fail closed

**Not theorems:** quality, item liveness, F2 without instance field, hop-as-safety, physical prompt isolation, executor/provider cache neutrality, adapter honesty, or impact-review correctness.

## 4. Illustration (not a corollary)

A selector that may pick models outside `φ(π\δ)` can hop when every allowed bind is down. This table has no such edge. A selector confined to `π\δ` also fail-closes. A cost minimizer fail-closes. Do not cite this as a safety theorem.

## 5. Rates

Cut: `[t0,t1]`. `W` = class p95 of completed stage durations in the previous cut, or 12 minutes if n<30. Exclude `ts > t1−W`. Policy as-of `ts`.

Silent-fail includes: well-formed stage with no decide/accept in `W`, **and** `open` with no stage. Bleed uses `π*`. Misbind = first Observe per stage with `norm(m_exec)≠norm(m_decl)`; always with silent-fail. Time-to-stage = survival to decide/accept, paired with `1−silent-fail`.
