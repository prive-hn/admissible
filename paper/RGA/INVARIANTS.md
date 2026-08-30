# Invariants — Refutation-Gated Admission

Roque Briceño. Safety only. Companion to `PREMISE.md`, `PROOFS.md` and `DRAFT.md`. Machine: `rga/core.py`, composed over `fcd/core.py`. Round 1: an independent five-lens review found the defect-model author was a free label per record, the before-generation guard trusted a caller-supplied journal position, and replay could not rebuild a discord or underpower close; all three are repaired below and their traces are in `tests/`.

RGA extends fail-closed class dispatch. It writes no FCD field. The FCD theorems I1–I17 (`../INVARIANTS.md`) are premises here, cited, never re-derived. Where this file says *inherited*, the guard in `rga/core.py` reads an FCD state variable and the proof cites the FCD theorem that constrains it. Theorems are **R1–R13**; faults are **V1–V15** — separate namespaces, as FCD separates I from F.

## 0. Assumptions

B0. **FCD underneath.** A0–A13 hold. The FCD machine is `fcd/core.py`. Every RGA guard that mentions `pc`, `kind`, `a`, `m_decl`, `cls`, `body`, `policy_version` or `S` reads that machine's state. No RGA transition writes any of it (R11).

B1. **Harness honesty.** A trial verdict, witness hash, calibration ledger, package-category set and sampling configuration are reports from a harness that ran what it names on the bytes the kernel hashed. This is the A10 boundary moved to the refuter runner. A forged *survived* satisfies the abstract guards; a forged *survived* on a deterministic refuter is a replay divergence when a third party re-runs it (R5), which is more than FCD can say of a forged `m_exec`.

B2. **Pinned hermetic runtime.** A refuter runs under a pinned toolchain with no clock, no network, no environment, and a runtime-counted fuel budget — never a wall-clock deadline. Under B2 a trial's observable is a function of (refuter version, artifact bytes, seed, fuel). This is a physical-boundary assumption of A10's standing; binding a refuter *version string* to refuter *bytes* is part of it. The kernel checks it only by falsification (Replay). A refuter outside the deterministic subset of the runtime is the harness's obligation to refuse; the kernel has no static check.

B3. **Exhaustion is reported.** Fuel or harness exhaustion, refuter crash, and refuter death are reported as `inconclusive`, never as `survived`. Survival is a positive completed verdict.

B4. **Sample independence.** k samples under one bind key are k draws from the bind's output distribution at the declared sampling configuration. A whole-response cache replay is one draw presented k times; it is receipt-visible as a repeated run id under I17 and is outside this machine.

B5. **Defect model identity.** A defect-model hash names one finite set of seeded defects, each shipped with a killing witness so that none is equivalent to the original. A calibration ledger enumerates exactly that set. The kernel fixes the id-set and the author by the first record against the hash (V13); that the hash actually names those contents is part of B1.

B6. **Coupling.** Kill-rate on a defect model is read as power against the generator's actual defects only under the coupling-effect hypothesis (DeMillo, Lipton & Sayward 1978). That reading is empirical. The seal carries the defect-model identity so the reading is the reader's, not the kernel's.

B7. **Hash.** `sha256` is second-preimage resistant against an adversary who chooses the artifact bytes. A collision here fails toward *acceptance* — a refuted artifact could wear the seal of an unrefuted one — so B7 is an assumption, not a fail-closed property.

B8. **Claim language.** A class's claims are formal statements over a fixed artifact format. A refuter's witness is the canonical form of the claim-relevant observable it computed. Two witnesses agree iff their canonical forms are byte-equal. Inequality is discord; no canonicaliser launders a syntactic difference into agreement.

B9. **Nonce.** The sample nonce is drawn from an injected source after the artifact bytes are hashed and every Sample guard has passed, and is unpredictable to the generator at generation time. It is journaled, so replay reads it rather than redrawing it.

B10. **Seed discipline.** A seeded refuter uses exactly the seed the kernel derives (R10). A refuter that ignores its seed is a fixed-corpus refuter and is declared as one.

B11. **Author identity.** `Refuter.author` and `DefectModel.author` are declared strings in one namespace with the FCD specialist ids. The kernel compares them byte for byte and does not resolve, normalise or close them. R3 holds of the strings; that a string names the party that wrote the refuter or the defect model is assumed, as A10 assumes `m_exec` names the model that ran.

## 1. Objects

**Refuter** `r = (id, version, author, mode)`, `mode ∈ {ledger, bounded}`. Registry-level, write-once per `(id, version)`. Carries `declared_at` (journal position) and `refused ∈ {0,1}`, monotone. The version is a declared identity; binding it to bytes is B2.

**Defect model** `D = (hash, author)`. Named by content hash. Its ledger id-set **and its author** are fixed by the first power record written against the hash (V13), so no two records disagree about either.

**Power record** `P[(r, D)]`, write-once. Ledger mode: `(kills, size, killed_ids)` with `kills = |{e ∈ ledger : e.verdict = killed}|`, `size = |ledger|`, computed by the kernel; `inconclusive` entries count in `size` and not in `kills`; carried power is `kills/size`, exact on `D`. Bounded mode: a declared `(ε, N)`; carried power is `1 − (1−ε)^N`, computed by the kernel, with `ε` and `N` carried into the seal so the declaration is visible — the figure is as declared as `ε` is, and the seal labels the mode. No interval is carried: a binomial interval assumes i.i.d. draws from the population the seal speaks to, and a mutant set is not that.

**Claim spec** `(id, spec_hash, refuters ⊆ R, defect_model_hash)`. Fixed per class in the admission policy; ids unique per class; `refuters` nonempty. Claims are fully fixed at Open in this machine. Within-schema instantiation for discovery-shaped work — a claim whose instance is a sample-projected value with its own concordance — is *not modeled*; nothing in v1 represents it.

**Admission policy** per class: `claims(c)`, `k(c) ≥ 1`, `θ(c) ∈ (0,1]`, `p_min(c) ∈ [0,1]`, `excluded(c)` (package categories the generator must not receive: refuter source, version, results, defect model), `residual(c)` (intents not attacked, each with disposition `check_stage | unreviewed`; possibly empty). Versioned. Installing a version string that already exists with different content is refused.

**Line** = one FCD work item `id` plus: `generator` (the specialist `a`), `m_decl = φ(a)` under the item's pinned FCD policy, `sampling_hash`, `policy_version` (RGA), `claims` snapshot, `opened_at` (RGA journal position) and the FCD journal position recorded at Open, `samples`, `trials`, `pc ∈ {Open, Sealed, Closed}`, `pub`, `fault`.

**Bind key** of a line: `(cls, body, fcd_policy_version, generator, norm(m_decl), sampling_hash)`. This is the FCD-core form; a deployment that runs the context envelope additionally projects `ExecutionEnvelope` onto its non-attempt-local fields, which this kernel does not model. `sampling_hash` is a harness report equality-checked at Sample (B1), not an FCD field.

**Sample** `i` = FCD stage `i` of the item with `pc = Passed`, bound to the line's generator, plus `artifact_hash = sha256(bytes)` computed by the kernel, `nonce` drawn after every guard passed, `m_exec` copied from the stage. Write-kind and declared-model equality hold by construction (Open requires the first `k` stages to be write stages; both `m_decl` values come from `φ(generator)` under the pinned policy). Sample `i` must be registered before any later sample stage is attempted (V8), so bytes cannot be assigned to slots after seeing the batch. `samples[0]` is the **designated** sample; it is stage 0, fixed before any sample exists.

**Trial** `(r, claim, i, seed, inputs_hash, verdict, witness_hash, replays)`, `verdict ∈ {refuted, survived, inconclusive}`. At most one per `(r, claim, i)`; `0 ≤ i < |samples|`. `inputs_hash` is carried for audit and not compared by the kernel.

**Seal** = the record written to `S_R` (§4).

Store `S_R : id → Seal`. Written only by Seal (R8).

## 2. Transitions

Journal position is the index of the event a transition emits; "before" is strict order in that journal. The FCD journal positions recorded at Open and Sample are read by the kernel on the live path (`len(fcd.events)`) and from the journal on replay; no public transition accepts one from the caller.

| Name | Guard | Effect |
|---|---|---|
| Declare(r) | `(r.id, r.version) ∉ R`; `r.author ≠ ∅`; `r.mode ∈ {ledger, bounded}` | `R ∪= {r}`; `r.declared_at ← position`; `refused=0` |
| Measure(r, D, ledger) | `r ∈ R`, `r.mode=ledger`, `¬r.refused`; `(r,D) ∉ P`; `ledger ≠ ∅`, ids distinct, verdicts ∈ `{killed, survived, inconclusive}`; if the hash has a record: same id-set and same author; `D.author ≠ r.author` | `P[(r,D)] ← (kills, size, killed_ids)` computed from ledger; id-set and author fixed on first record |
| Bound(r, ε, N) | `r ∈ R`, `r.mode=bounded`, `¬r.refused`; `(r,⊥) ∉ P`; `0 < ε ≤ 1`; `N ≥ 1` | `P[(r,⊥)] ← (ε, N)`; power `1−(1−ε)^N` |
| Open(id, generator, sampling) | item `id` exists in FCD; line `id` not yet open; `cls(id) ∈ policy`; `generator ∈ π(c)\δ(c)` of the pinned FCD policy; `stages[0..k)` all `kind=write`; no FCD `stage` event for stages `0..k` of `id` precedes the FCD position the kernel reads here; every pinned `r`: `∈ R` (hence declared before this position — the journal is append-only), `¬refused`, `author ≠ generator`; every claim's `D` with a fixed author: `author ≠ generator` | line created; `claims ← policy.claims(c)`; `m_decl ← φ(generator)`; `pc=Open`; positions recorded |
| Sample(id, bytes, categories, sampling) | `pc=Open`; `i = |samples| < k`; FCD `stages[i]`: `pc=Passed ∧ a=generator`; `categories ∩ excluded(c) = ∅`; `sampling = line.sampling_hash`; no FCD `stage` event for stages `i+1..k` precedes the FCD position read here | `h ← sha256(bytes)`; `ν ← nonce()` (drawn after the guards); `samples ∪= (i, h, ν, m_exec)`; position recorded |
| Trial(id, r, claim, i, seed, inputs, verdict, witness) | `pc=Open`; `claim ∈ claims`; `r ∈ claim.refuters`; `0 ≤ i < |samples|`; `seed = H(ν_i ‖ h_i ‖ r.id ‖ r.version ‖ claim.id)`; no trial for `(r, claim, i)`; `verdict ∈ {refuted, survived, inconclusive}` | append trial; if `refuted` → Close(V1); if `inconclusive` → Close(V3) |
| Replay(id, t, verdict, witness) | trial `t` exists on line; `¬r_t.refused`. Enabled in any line state: a post-seal audit replay that diverges still refuses the refuter (see `tainted`) | if `(verdict, witness) ≠ (t.verdict, t.witness)` → `r_t.refused ← 1`, monotone; every Open line pinning `r_t` → Close(V4); else `t.replays += 1` (a counter outside every seal) |
| Seal(id) | `pc=Open`; `|samples| = k`; ∀ claim `j`, ∀ `r ∈ j.refuters`, ∀ `i<k`: trial `(r,j,i)` exists with `verdict=survived`; ∀ `r` used: some trial of `r` on this line has `replays ≥ 1`; ∀ ledger `r` of `j`: `P[(r, D_j)]` exists; ∀ bounded `r`: `P[(r,⊥)]` exists; ∀ `j`: `D_j`'s fixed author `≠ generator`; `id ∈ S` (FCD); a `residual` disposition of `check_stage` requires a Passed FCD check stage | compute `agreeing_j`, `composite_j`; if some `agreeing_j/k < θ` → Close(V2), naming in `miss_observed` exactly the refuters whose own witnesses differ from their sample-0 witness; elif `min_j composite_j < p_min` → Close(V5); else `S_R[id] ← Seal`; `pc=Sealed` |
| Close(id) | `pc=Open` | `pc=Closed`; `pub=1`; no fault (operator stop, published) |

A guard failure not listed as a Close raises and writes nothing (V6–V15). A Close is published: it emits `rga_close` with the fault code; the Seal attempt that observes V2 or V5 publishes the Close and then raises to its caller. A refuter refused while a line is Open closes that line in the same step; a refused refuter cannot be pinned (Open), measured (Measure/Bound) or replayed further. No Trial or Seal guard tests `refused`, because no trace reaches one with a refused refuter — a guard no trace can reach is dead code. For the same reason there is no write-kind or declared-model guard at Sample, no refuter-author clause at Seal (a record by a refuter whose author equals the model's author is refused at Measure, and Seal requires the record), and no separate `declared_at < opened_at` clause at Open (membership implies it in an append-only journal). Each removal is derived in `PROOFS.md`.

Concordance for claim `j`: `vec_i = sorted{(r, witness) : trial (r,j,i)}`; `agreeing_j = |{i : vec_i = vec_0}|`. Compared against the designated sample, never a plurality.

Composite power for claim `j`: let `L` be the ledger refuters of `j` with records against `D_j`, `B` the bounded refuters. If `|L| ≥ 2` their killed-id sets are unioned over the shared `D_j`: `u = |∪ killed|/size`. `composite_j = max(u, max_{b∈B} power_b)`, labelled `union` if only `L` contributed with `|L| ≥ 2`, `single` if one refuter, `max` otherwise. No product, no noisy-OR.

## 3. Theorem statements

Proofs in `PROOFS.md`. Executable checks in `tests/test_rga_invariants.py`; each guard has a deletion proof in `tests/test_rga_mutation.py`.

- **R1** `id ∈ S_R ⇒` every `(claim, refuter, sample)` cell has a trial with `verdict=survived`, and no trial on the line has `verdict ∈ {refuted, inconclusive}`.
- **R2** `id ∈ S_R ⇒` every power figure in `S_R[id]` equals a record `P[(r,D)]` written before Seal by Measure or Bound from a ledger or a declared `(ε,N)` the seal carries; no transition writes an existing key of `P`; hence no sealed power is raised after the fact.
- **R3** `id ∈ S_R ⇒` for every refuter `r` used: `r.author ≠ generator`; `r` was declared before the line opened; the line opened before any sample stage was attempted and each sample was registered before the next sample stage was attempted; the defect model's fixed author is neither the generator nor (for any record that exists) the recording refuter's author; and no sample's package contained a category in `excluded(c)`. All authorship clauses hold of declared strings (B11).
- **R4** `id ∈ S_R ⇒` for every claim `j`, `agreeing_j / k ≥ θ`, measured against stage 0; no transition writes a sealed artifact hash other than `samples[0].artifact_hash`.
- **R5** A replay divergence sets `refused=1` on that refuter; `refused` is monotone; after it, no line can pin, measure, bound or further replay it, and every line Open at refusal closes in the same step.
- **R6** `id ∈ S_R ⇒` every refuter used has at least one trial on that line with an identical replay.
- **R7** (inherited) every sample `i` of a sealed line is FCD stage `i` with `pc=Passed` and the line's bind key; hence `norm(m_exec_i) = norm(φ(generator))` (I1) and `generator ∈ π*(c)\δ(c)` (I2, I3).
- **R8** `id ∈ S_R ⇒ id ∈ S` (hence `status=accepted` by I8 and every required FCD stage Passed by I5, and neither can be unwritten: NoAdmit requires `pc∈{Open,Closed}` and Open requires a fresh id). `S_R` is written only by Seal.
- **R9** `id ∈ S_R ⇒` every trial on the line is bound, through its seed, to the artifact hash the kernel computed at Sample for that sample; the seal's artifact hash is sample 0's.
- **R10** every trial's seed is `H(ν_i ‖ h_i ‖ r ‖ claim)` where `ν_i` was drawn at Sample `i` after `h_i` was computed and after every Sample guard passed; no seed exists before its artifact hash.
- **R11** no RGA transition writes any field of the FCD machine. Non-interference lemma; it is what lets the FCD proofs carry to the combined machine.
- **R12** `claims`, `k`, `θ`, `p_min`, `generator`, `m_decl`, `sampling_hash`, `policy_version` are write-once at Open.
- **R13** a line has at most `k` samples and at most one trial per cell, hence at most `|claims| · max_j |refuters_j| · k` trials; a power record is written at most once per key; a defect model's id-set and author are fixed by its first record. Replays are unbounded (Ask-idle analogue).

**Not theorems:** quality; truth of a claim; relevance of `D` to the generator's defects (B6); refuter determinism beyond replayed inputs (B2); halting (B3); harness honesty (B1); sample independence (B4); claim fidelity to intent; refuter independence beyond a shared `D`; generator exposure to a public refuter through training; author identity beyond string equality (B11); that any consumer — the FCD DAG edge at `fcd/core.py` `open(depends_on=…)`, or a promotion predicate — reads `S_R` rather than `S`: the kernel exposes `check_dependencies`, `is_sealed`, `tainted` and `admissible`, and wiring them is a deployment obligation; that a retry after a refutation hides the refutation trace from the generator — `excluded(c)` refuses only the categories the harness reports (B1), and an adaptive retry is otherwise unlabelled. See `PROOFS.md` "What is not proved".

## 4. The seal

`S_R[id]` carries, and nothing else may be read as RGA authority:

- `artifact_hash` of the designated sample; `k`; `θ`; `p_min`; `sampling_hash`; RGA `policy_version`.
- FCD identity: `cls`, `body`, `generator`, `m_exec` of sample 0, FCD `policy_version`. (I1, I4.)
- Per claim: `claim_id`, `spec_hash`, each refuter as `(id, version, mode, power, D_hash | ⊥, kills | ⊥, size | ⊥, ε | ⊥, N | ⊥)`, `composite`, composition label, `(agreeing, k)`.
- `power_min = min_j composite_j`.
- `residual`: the class's declared not-attacked intents (possibly empty) with disposition; `check_stage` is refused unless an FCD check stage Passed on this item.
- `sealed_at` (journal position).

A seal is a record. A later refusal of a refuter (R5) does not rewrite it; `tainted(id)` is a pure query that reports whether a sealed line relied on a refuter refused after sealing, `admissible(id)` is `sealed ∧ ¬tainted`, and `check_dependencies(deps, floor)` — the power-aware DAG gate a deployment calls before `fcd.open(..., depends_on=deps)` — refuses an unsealed, underpowered or tainted dependency. With `k = 1`, `(agreeing, k) = (1, 1)`: nothing was measured and the record shows it.

## 5. Faults

Each is a forbidden step. V1–V5 are observed and publish a Close. V6–V15 are guard refusals that raise and write nothing. Every fault names the guard method(s) that enforce it; `tests/test_rga_mutation.py` deletes each method singly and proves the fault's forbidden state becomes reachable.

| Id | Forbidden step |
|---|---|
| V1 | Seal after a trial on the line returned `refuted` |
| V2 | Seal with `agreeing_j/k < θ` on any claim |
| V3 | Seal counting an `inconclusive` trial as survival |
| V4 | Agreement recorded for a replay that diverged; Measure, Bound or Replay on a refused refuter |
| V5 | Seal with `min_j composite_j < p_min` |
| V6 | Sample from a stage that is not Passed or is bound to a different specialist than the line |
| V7 | Sample whose generator package contained a category in `excluded(c)` |
| V8 | Open after a sample stage was attempted; Sample `i` after a later sample stage was attempted; Trial against a claim not in the line's snapshot or a refuter not pinned to it |
| V9 | Trial whose seed is not `H(ν_i ‖ h_i ‖ r ‖ claim)` |
| V10 | Seal without `k` samples or with a `(claim, refuter, sample)` cell lacking a surviving trial |
| V11 | Seal using a refuter with no identical replay on this line |
| V12 | Seal using a refuter with no power record |
| V13 | Measure or Bound on an existing key; a sample beyond `k`; a second trial in one cell; a ledger whose id-set, or a record whose author, differs from the defect model's first record |
| V14 | A pinned refuter authored by the generator; a defect model authored by its recording refuter's author, or whose fixed author is the generator |
| V15 | Seal of a line whose item is not in `S`; a residual that claims `check_stage` with no Passed check stage; any write to `S_R` other than Seal |

## 6. Rates

Defined as in `../INVARIANTS.md` §5, on a named cut `[t0,t1]` with window `W`. Policy as-of `ts`. None are theorems.

- **Refutation rate** per class and refuter version: trials with `refuted` over trials.
- **Discord rate** per class at declared `(k, sampling_hash)` (joined from `rga_close` to `rga_open` on the line id): lines closed V2 over lines reaching Seal.
- **Miss observed** per refuter version: V2 closes whose `miss_observed` names it — the refuter's own witnesses differed across samples it declared survived. For a claim whose witness is a function of the claim value, that is a detected miss: two claim-different samples both survived it. For other witness designs it is instability evidence only.
- **Replay divergence** per refuter version: Replays that diverged over Replays. The refuter analogue of misbind; always published with silent-fail.
- **Escape replay** per refuter version `v′`: of defects later found in artifacts sealed under `v`, the fraction `v′` kills on the pre-fix bytes. Requires a defect-report channel outside this machine (its numerator has no journal event); informative only for `v′ ≠ v` (a deterministic `v` reproduces its own miss); doubly selected. A journal-plus-reports rate keyed to the successor version, never a rewrite of any seal.

## 7. Illustration (not a corollary)

A generator that has seen a fixed public refuter can special-case it and survive at the refuter's full carried power. R3 forbids the refuter being shaped by the artifact; nothing in this table forbids the artifact being shaped by the refuter, except the post-artifact seed (R10) for seeded refuters and `excluded(c)` (R3) for fixed corpora the generator's package would otherwise carry. Pretraining exposure is outside both. A retry opened after a refutation, with the refutation trace in the generator's context, is the same picture one step later: the samples become adaptive, and this table neither forbids nor labels it beyond `excluded(c)`. Do not cite R3 as a theorem about Goodhart.

## 8. Calibration — the escape ledger

Machine: `rga/calibration.py`, composed over `Admission` the way `Admission` composes over FCD. Premise round: `eval/reviews/rga-calibration-premise-SYNTHESIS.md`; corrections to the first sketch are recorded there, including one authored adjudication between conflicting reviewer verdicts. Theorems are **C1–C7**; faults are **E1–E9**. "Calibration" is used in this repository's metrological, mode-3 sense — the reference corpus is ratcheted against verified real defects. The statistical sense is *not proved* and is filed as such: these theorems are about the ledger of found misses, never the distribution of real ones. What is proved is: forgetting is loud.

### 8.0 Assumptions

B12. **Post-seal byte availability.** Filing an escape requires the sealed bytes; whoever found the defect holds them, and any hash-matching copy suffices (B7). Loss of bytes censors the escape stream one-sidedly: it slows revocation and can never manufacture admission. This is the standing condition RGA's post-seal audit replay already carried, now load-bearing.

B13. **Governance visibility, not governance defeat.** Budget values, Seal-gate bits, exclusion decisions and tier-B adjudications are operator acts. The kernel makes each one a journaled, attributed, primary-carrying event; it does not and cannot make the operator honest. The operator is the trust root here as A10's adapter is FCD's.

B14. **Authenticated-publication trust boundary.** The composed receipt theorem assumes one authority stack with a stable registry namespace, atomic single-writer authority transitions, an honest signer whose key is not disclosed, and an external monotone registry that cannot be rolled back with the journal. Unrelated stacks use distinct namespaces; the registry serializes concurrent updates across them. Historical authenticity begins at a trusted first anchor or continuous publication: a first receipt cannot prove which coherent pre-anchor history actually ran. The computational claim assumes HMAC-SHA256 unforgeability and SHA-256 collision and second-preimage resistance. The bundled HMAC signer authenticates within that trust domain; it is not public-key non-repudiation. Compromise or coordinated rollback of signer/key and registry defeats currency and is not proved away.

### 8.1 Objects

**Escape** = a filed counterexample against a sealed line's claim: `(line_id ∈ S_R, claim_id, checker = (id, version), nonce, artifact bytes, witness_hash)`. Two tiers:
- **Tier A** — the checker is a refuter **pinned to that claim in the line's seal**. The finder authors nothing but the nonce and the bytes. The kernel computes `sha256(bytes)` and refuses unless it equals `seal.artifact_hash` (single-holder, the `sample()` pattern); derives `seed = H(nonce ‖ artifact_hash ‖ checker ‖ claim)` itself; records the reported verdict, which must be `refuted`. This is a counterfactual trial: the same pure function the seal's own trials evaluated (B2), at another point of its seed domain. It adds no assumption the seal did not already carry.
- **Tier B** — any other declared checker. A tier-B escape has **no effect of any kind** until a journaled adjudication event (named actor, decision, reason) accepts it. The adjudication is the per-escape claim-fidelity judgment (B8 of the checker), made visible instead of pretended away.

**Established** = the escape's run has one identical replay (verdict and witness equal). A divergent replay **discredits** the checker in this ledger, monotonically. **Valid** (read at query time, never stored): established ∧ checker not discredited ∧ checker not refused in the Admission registry ∧ (tier B ⇒ adjudicated accepted).

**Charge** = the journaled wrong-verdict cell `(line_id, claim_id, refuter_version)`: the pinned refuter returned `survived` on the designated sample and a valid escape exists against that cell. **Write-once per cell** — witness multiplicity and checker multiplicity never multiply charges; the refuter's chargeable error is its single journaled verdict.

**Corpus** per class: every valid escape contributes a derived seeded defect whose killing witness is the escape witness (B5 by construction), identified by the escape's journal position, carrying the finder as **journal-cited provenance metadata** — never fed into any author gate, never deriving any exclusion (the adjudicated decision of the premise round: an added entry is a monotone kill obligation and cannot advantage its finder).

**Exclusion** = a journaled operator decision `(class, escape ids, actor, reason)` releasing named corpus entries from the successor-coverage obligation. It waives nothing else: charges, impeachment, track records and the corpus itself stay monotone.

**Calibration policy** per class: `e_max ≥ 0` (charge budget per refuter version within the class) and `demotion_gate ∈ {seal, carry}`. Both explicit; no defaults.

### 8.2 Transitions

The authority wraps Open, Seal and Install the way the reference server wraps `decide_pass` (the GatePass interposition pattern): each Cal-row is a guard conjunction in front of the corresponding Admission row, driven through Admission's own guarded transition. A deployment that bypasses the wrapper has RGA's guarantees and not these — the consumer-redirection obligation, one layer up, stated. Seal- and claim-membership at filing are structural preconditions (an unknown line or claim cannot be named), not deletable predicates. Replay re-checks every filing guard and entailment before writing, and requires a diverged replay to be adjacent to its discredit event; `PROOFS.md`, *Replay of the ledger*, states its one-sided registry residue.

| Name | Guard | Effect |
|---|---|---|
| FileEscape | `line ∈ S_R`; claim in the seal; checker declared; `sha256(bytes) = seal.artifact_hash`; tier A: checker pinned to the claim in the seal and filed seed equals the kernel's derivation; verdict = `refuted` | escape recorded with tier, finder, position |
| ReplayEscape | escape exists; checker not discredited | equal `(verdict, witness)` → established; unequal → checker discredited, monotone; every unestablished escape of a discredited checker is void |
| Adjudicate | tier-B escape established; named actor | decision `accept` or `reject`, with reason, journaled; `accept` makes it valid |
| Exclude | class has the named valid escapes in its corpus; named actor; reason | exclusion recorded with primaries |
| CalInstall | every class of the incoming admission policy carries an explicit calibration policy, supplied with it and installed in the same step (E9); every **ledger** claim's defect-model hash has a kernel-fixed id-set (Measure before Install — always achievable: `measure` reads no policy state); each ledger claim's id-set ⊇ the class corpus's derived-defect ids minus excluded ids as of this position; no claim is bounded-only while the class corpus minus exclusions is nonempty; no class with a nonempty net corpus is absent from the incoming policy | drives `Admission.install`; emits the install event with coverage primaries (corpus size, excluded count, per-claim model map), the predecessor-policy diff of dropped defect ids, and any dropped classes |
| CalOpen | the class carries an explicit calibration policy (E9); no refuter pinned by the class is demoted here or refused in Admission | drives `Admission.open` |
| CalSeal | the class carries an explicit calibration policy (E9); the line is Open (checked before any emission — a close event for a line that stays Sealed would be a journaled step that never happened); if the class declares `demotion_gate = seal`: no pinned refuter demoted as of this position — else publish close, fault E5, carrying that refuter's primaries; always: stamp event with each pinned refuter's track-record primaries and the corpus finder-provenance split as of this position | drives `Admission.seal`; stamp emitted in the same step |
| Audit | `line ∈ S_R`; a checker pinned on the claim or the checker of a valid escape of the class, run against the sealed bytes (kernel hashes them; tier-A seed discipline applies to pinned checkers), verdict `survived`, replayed | audit event; exposure queryable |

Pure queries, never writes: `charges(refuter_version, class)` — the valid charge cells; `demoted(r, class)` = charges > `e_max`; `impeached(id)` = some valid escape against the seal; `suspect(id)` = some direct dependency impeached or tainted (transitive coverage is the consumer's fold over `depends_on`, RFC 5280 shape); `mediated(id)` = exactly one stamp bound to this seal's position, so a seal produced by calling `Admission.seal` directly is layer IR and distinguishable from IRC; `admissible` extended to `∧ mediated ∧ ¬impeached`; `check_dependencies` refuses impeached dependencies; `audit_exposure(id)`.

### 8.3 Theorem statements

- **C1 Established, never asserted.** A tier-A escape has effect only past kernel-checked preconditions — seal membership, byte-hash equality, pinned checker, kernel-derived seed, refuted verdict, identical replay — none of which is a declaration; a tier-B escape has effect only past a journaled, attributed adjudication. No other path to effect exists.
- **C2 Charge totality and unit.** The charges standing against a refuter version are exactly the valid wrong-verdict cells derivable from the journal — read, never declared — and at most one per `(line, claim, refuter_version)`.
- **C3 Impeachment is entailed and checkable.** `impeached(id)` is a pure query entailed by a valid escape; the seal is never rewritten; validity degrades (checker discredited or refused) by journal facts, never by discretion. Non-discretion is the property CRL/OCSP lack.
- **C4 The ratchet.** No policy installs unless every **ledger** claim's defect model is Measured and covers the class's valid corpus minus journaled exclusions as of the install position, no claim is bounded-only against a nonempty net corpus, and no class that owes coverage is dropped from the policy. The install event carries the coverage primaries, the per-claim model map, the dropped-id diff and any dropped classes. Hence: no successor forgets a valid escape without a named, attributed, journaled decision — forgetting is loud.
- **C5 Track record carried, and mediation provable.** Every CalSeal stamps the seal in the same step, and `mediated(id)` reads that stamp back: exactly one, bound to the seal's own position. A line sealed without passing through this authority has no stamp, so it is layer IR — `admissible` refuses it — and a consumer can tell the two apart. Re-pointing a stamp, duplicating one, or adding one out of seal order is refused on rebuild; adding one for the most recent unmediated seal is not — nothing earlier contradicts it — and removing one lowers the line to IR. Both residues are stated in PROOFS.md rather than claimed away.

- **C5a Primaries.** Every CalSeal stamps, in the same step as the seal, each pinned refuter's primaries as of that position — charged cells, seals participated in, corpus size and exclusions — and the class corpus's finder-provenance split for this seal's generator; never a rate; a zero is absence of filed evidence and the record says so.
- **C6 Demotion is a query with declared consequences.** `demoted` is a pure function of the valid charge set against the declared budget — rising as valid escapes accumulate, falling when a checker's discredit or refusal degrades their validity (refusal-shaped facts outrank the count: the fail-closed direction). It blocks new pins at CalOpen unconditionally; it gates CalSeal exactly where the class declared it, closing with a published fault that carries the primaries; it never cascades events and never touches an existing seal.
- **C7 Non-interference.** The calibration authority writes no Admission or FCD field directly; its only effect on the lower machines is through their own guarded transitions. Every R- and I-theorem holds on the combined trace.

**Authenticated publication (conditional on B14).** `issue_admissibility_receipt` accepts exactly one composed `Enforcer → Admission → CalibrationAuthority` stack and a stable namespace, snapshots its immutable journals, derives the subject's artifact and four predicates from that state, signs all three ordered heads plus the composed receipt, and advances the three registry heads atomically. Each successor head carries the new event digests; the registry recomputes a cumulative chain from its anchored head, so greater length without prefix extension is refused. It refuses if the journals or predicates move while signing. `verify_admissibility_receipt` authenticates the composed fields and requires every embedded head to equal the namespace's registry-current digest and the current journal body. Therefore, after a trusted anchor, a verified registry-current receipt cannot be produced by public rehashing, cross-wiring, truncation, coherent deletion, a longer fork, state-stale replay, namespace collision, or predicate substitution unless B14 fails. Here *stale* means not registry-current for the present journal state; composed `issued_at` is signed metadata, not an expiry or wall-clock-freshness theorem.

**Not theorems:** corpus representativeness — B6 is relocated to the corpus, not closed; the corpus is a selected, adversarially steerable subsample of real defects, and flooding it with true entries steers every aggregate built on it. Search intensity — zero charges is unreadable between sound and unsearched except through journaled audits, and those measure power against the corpus, never against undiscovered defects (B6 one level up). Audit-campaign scope honesty (B1 one level up). The residual disincentive to reveal defects only one's own instruments miss. Tier-B checker claim-fidelity — adjudicated, never kernel-checked. Statistical calibration — no bounded escape rate, no convergence of D to the generator's defect distribution, and none soundly statable under an adversarially censored escape channel (Gibbs & Candès 2021 is the shape such a theorem has, and why it does not fit here). Operator honesty (B13). Authenticated publication when the receipt path is bypassed, signer/key custody, registry durability, rollback of both key and registry, or concurrent writers outside the authority model (B14).

### 8.4 Faults

E5 publishes a close through CalSeal. E4, E6, E7 and E9 are guard refusals that raise and write nothing. E1–E3 are validity semantics read at query time: an invalid escape simply has no effect — there is nothing to publish or refuse — and `_check_valid` is the deletable method that holds them. E8 is the writer inspection, held by C7's proof and by replay re-guarding every write. Every fault names the method(s) that enforce it; `tests/test_rga_calibration.py` deletes each singly and proves the fault's forbidden state becomes reachable.

| Id | Forbidden step |
|---|---|
| E1 | Effect from an escape that is not established, or whose checker is discredited or refused |
| E2 | Effect from a tier-B escape with no accepted adjudication |
| E3 | A second charge in one `(line, claim, refuter_version)` cell |
| E4 | An install whose ledger defect models omit a valid, unexcluded corpus entry — or reference an unmeasured D, leave a claim bounded-only against a nonempty corpus, or drop a class that owes coverage |
| E5 | CalSeal under a demoted refuter where the class declared the gate |
| E6 | FileEscape whose bytes do not hash to the seal's artifact hash, whose checker is not pinned (tier A), or whose seed is not the kernel's derivation |
| E7 | Exclusion or adjudication without a named actor and reason; a second adjudication of one escape |
| E8 | Any write to charges, corpus, exclusions or stamps except through the named transitions |
| E9 | A CalOpen, CalSeal, budget query or install for a class carrying no explicit calibration policy — `e_max` and `demotion_gate` have no defaults, and an unconfigured class must never behave as an unlimited one |

### 8.5 Rates

All on named cuts; none theorems. Escape rate per class and tier; adjudication acceptance rate (tier B); exclusion load per install (primaries, already carried); charge accrual per refuter version; audit coverage per class (lines audited over lines sealed — one-sided, reads only with the audit events); the §6 escape-replay rate now has its journal numerator for tier-A escapes.

### 8.6 Ancestry

Eliminative argumentation and Assurance 2.0 defeater discipline (Goodenough, Weinstock & Klein 2015; Bloomfield & Rushby), mechanized: established escapes are replayed kills, not dispositioned prose, and the non-covering successor is refused by the kernel, not flagged for an assessor. Escape-to-test regression practice and mined-from-real-faults mutation (Tufano et al. 2018; Beller et al. 2021; Defects4J) for the corpus. Flaky-test quarantine and SRE error budgets for the budget-with-consequence shape — which lack the verified false-negative channel this layer creates. Browser root-program distrust of certificate authorities for the institutional precedent. CRL/OCSP/Sigstore for revocation-consulted-at-use, minus the two properties with no prior formalization found: non-discretion and charge totality. Mills 1972 for seeded audit controls.
