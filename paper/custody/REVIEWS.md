# Custody theory — review rounds

Two rounds of adversarial review. Round 1 took five branch formalizations written against the kernel (Fréchet Ledger, Polar Standing, Cut Custody, Refuser Calculus, Preimage Games), each refereed by three lenses — adversarial mathematical (soundness: circularity, vacuity, falsity, proof gaps), nearest-prior-art (novelty: the existing theory each object instantiates, audit of the branch's own novelty ledger), and kernel-adversarial (fidelity: non-claims, every `file:line` citation, feasibility of each proposed change under R11/C7 and fail-closed) — fifteen verdicts, followed by a completeness critic over the five. Round 2 took the unified paper (`DRAFT.md`, with `IMPROVEMENTS.md`, `custody.py`, `tests/test_custody.py`) through the same three lenses. Every referee had the repository and executed probes on the unmodified kernel (`rga/core.py`, `rga/calibration.py`, `fcd/core.py`, `fcd/head.py`) before ruling; a claim counts as a kernel fact below only where a referee re-drove it. Round-1 verdicts returned: repairable (9), broken (1), derivative (5) — no branch scored better than repairable on soundness or fidelity, every novelty verdict was derivative, Cut Custody's soundness verdict was broken. Round 2 returned a journal verdict: all three lenses, major revision. Severities are the referees' own; nothing was softened. Branch documents live only in the session scratchpad, not in the repository.

## Round 1 — five branch formalizations

Lens tags: [math] soundness, [lit] novelty, [kernel] fidelity. Ids `R1-<branch>-<n>` are referenced in the disposition table.

### Fréchet Ledger (quantitative)

A coproduct type for carried power (ledger / bounded / ⊥), Fréchet-interval semantics for union and max, an ideal-sum dependency bound along `depends_on`, and an e-value / existential partition of post-seal observations.
Verdicts: soundness repairable · novelty derivative · fidelity repairable.

- R1-FL-1 [math, kernel] T7 false: `charge_cells` (rga/calibration.py:384-385) charges every refuter pinned on the claim; RESULTS.md:63 charges spec-weak for spec-strong's escapes. A charge is co-liability, not a ρ>0 certificate.
- R1-FL-2 [math] T5 omits the seal's own committed survived trial at s_0 (rga/core.py:795-813): the identified set is always ⊂ [0,1); two of its four cases never occur.
- R1-FL-3 [math, lit, kernel] T6(b) misstated: the proof calls ∏(1−x_i) ≤ (1−x̄)^k false (it is AM–GM); the real obstacle is Jensen under exchangeability. Mixture counterexample: E[E_k] = 2^{k−1}. State under i.i.d.
- R1-FL-4 [math, lit, kernel] T4(ii) misidentifies the quantale: a (min,+) path fold gives 0.2727 < ideal 0.3636 (unsound, fail-open); 0.4545 is a sum over paths. Recompute the diamond.
- R1-FL-5 [math] T1/T2 mis-describe the kernel: `composition="max"` (rga/core.py:930-935) marks a cross-sort comparison; same-D ledger refuters are always unioned. The kernel never computes the Fréchet inf endpoint.
- R1-FL-6 [math] Cor 3.1: `check_dependencies` (rga/core.py:667-676) iterates direct deps at a caller-chosen floor; v has no `power_min` at gate time; Δ built from `power_min` is not assumption-free.
- R1-FL-7 [math, kernel] Novelty item 1 and I1/I2 are already in custody DRAFT §4 (T6, T6.1, T7, K3) and §8 (N4, N5, N6, N12); the ledger repeats them uncited.
- R1-FL-8 [math, kernel] T6(a) needs nonce unpredictability (B9), not journaled ordering; the kernel enforces ordering only, and harness/bench nonces (`nonce-{i}`, `finder-{iid}-{j}`) are predictable.
- R1-FL-9 [lit] Novelty #2 is risk-limiting audits (Stark; SHANGRLA) plus Hamlet 1987 / Miller 1992 zero-failure bounds and Fiat–Shamir; #1 is Cornell 1967 / Ditlevsen 1979 / Hailperin 1965.
- R1-FL-10 [kernel] I4's `e_frac` demotion is anti-monotone in `seals_participated` (an adversary raises n by honest sealing); custody DRAFT N12 already forbids the ratio.
- R1-FL-11 [kernel] T6(c)/I3 ignores selection among campaigns: open ~70 private campaigns of N=40, complete the one survivor, false e-value 67. Value incomplete campaigns 0; authority draws the nonces.
- R1-FL-12 [kernel] I5's premise false: `_guard_install_covers` (:653-674) requires only corpus ids ⊆ D'; `_dropped_ids` exists because successors drop ids; seed-roll losses are not kernel-computable.

Referee-confirmed kernel facts
- `_claim_seal`: union over `killed_ids` at rga/core.py:922-928, max at :929, labels :930-935; `bound()` accepts ε=1, N=1 at :423 (the sortless floor, later F6).
- Worked examples exact: union 0.8 vs independence 0.75; 10/11 vs 0.9339 — the product is neither a lower nor an upper bound.
- `check_dependencies` gates each edge at the comonotone endpoint (min ≥ floor) while the seal reports the union; a per-edge floor f along n edges carries max(0, 1−n(1−f)).
- RESULTS.md:92: wrap's refuters carry 0 charges and `demoted` False — three of four refuters demote, not four.
- `_file_run` (rga/calibration.py:267) accepts any nonce; `RefuterSeal.mode` is :217, not :216.

### Polar Standing (logical)

Types every journal fact by its polarity on each conjunct of `admissible`, derives an assumption's sign from the fact it licenses, and exhibits two verdict orders (artifact's, instrument's) on which one fact carries opposite signs.
Verdicts: soundness repairable · novelty derivative · fidelity repairable.

- R1-PS-1 [math] T4(ii) false; executed counterexample: delete w's highest-index escape and stamp x (its only witness), keep the `cal_exclude`; `from_events` accepts, `admissible(w)` True.
- R1-PS-2 [math] T1 and D10 mix polarity domains: `sealed`, `refused(pinned)`, `stamp` are mixed on P(𝔽) (two stamps → `mediated` False, rga/calibration.py:420-422); no support for `admissible` exists, T6 vacuous.
- R1-PS-3 [math] T1.2's residue omits `run_refuted(i)`: Probe 3a rewrites a run refuted→survived keeping `established`, un-impeaches, replays clean — a negative fact outside Neg_admissible.
- R1-PS-4 [math] D11/T5: schema-level base inclusion makes every run tier A (hawk carries B2 exactly as tests does); the proof switches to instance level for B2 by hand.
- R1-PS-5 [math] T3's headline "one instance, two sites, opposite signs" is ordinary branch polarity of a reproducibility check; what survives: the diverge branch is closed at rga/core.py:541, open at rga/calibration.py:293.
- R1-PS-6 [lit] D9's derived sign is one-hop QPN sign propagation (Wellman 1990); D8/D10 minimal supports are ATMS labels (de Kleer 1986); T1 is Doyle's out-list retraction (1979).
- R1-PS-7 [kernel] Improvement 1 gives an unestablished tier-A filing an effect (forbidden by E1/C1, INVARIANTS.md:195, :215): one finder with the bytes freezes every pin of the class. Alternative: discredit voids only unestablished runs (INVARIANTS.md:183).
- R1-PS-8 [math, kernel] D7 lists the install ratchet re-guard (rga/calibration.py:821-827) as a witness; it is not (Probe 4): `cal_install.coverage` is never recomputed on rebuild.

Referee-confirmed kernel facts
- Probe 1: one divergent `replay_run` report (rga/calibration.py:303-306) writes `discredited`; `_check_valid` (:347-348) voids every established escape of that checker; `admissible(w)` False→True, `demoted` True→False, `Admission.refused` empty. Probe 1b: a single actor does it alone (garbage tier-A escape, self-replayed divergently).
- T3.2: the discredited instrument then pins and seals a new line at power 0.9 (CalOpen checks `demoted` and `refused` only, :687-692).
- INVARIANTS.md:183 ("every unestablished escape … is void") contradicts :166 and the code, which void established ones too.
- X2 is overstated for calibration: `cal_exclude.corpus_size`, `cal_install.coverage`, `cal_run.finder` rewrite freely and replay clean; no standing query reads them.
- tests/test_rga_calibration.py:91-100 runs at default `e_max=2`, under which `demoted` never flips; the cited flip needs `e_max=0`.

### Cut Custody (record)

The record as three journals read at a cut; guards classified lax / oplax by monotonicity in the knowledge index; self-cuts as length anchors; a residue stratification; receipts as cuts.
Verdicts: soundness broken · novelty derivative · fidelity repairable.

- R1-CC-1 [math, fatal] T5 false: `_compare_regenerated` accepts any journaled value equal to the regenerated one, so renumbering a self-cut is the accepted coherent rewrite. E1: mid-journal stamp forgery with `track_records[*].as_of` renumbered replays clean, `admissible(x)` True.
- R1-CC-2 [math fatal, kernel major] `rga_seal.sealed_at` is not an event field (rga/core.py:606-620; SCHEMA.md); J_R has no compared self-cut. E2/A1: a refusal group before an IR seal deletes clean and un-taints.
- R1-CC-3 [math, fatal] T7's stratification false three ways: E1 (mid-journal insertion), E4 (refusal group deleted before a later mediated seal, cost zero), E3 (`cal_adjudicate.decision` rewritten accept→reject, un-impeaches).
- R1-CC-4 [math, kernel] T6(a): an `rga_measure` naming derived_defect_id(e) is not an anchor; `_guard_install_covers` (:664) only gets easier when e is deleted. E5 and probe B replay clean and un-impeach.
- R1-CC-5 [math] T8 vacuous: `verify_current` (fcd/head.py:491-495) requires the exact registry event_count and head, so any verified receipt pins the whole record; receipt-on-demonstration does no work.
- R1-CC-6 [math, kernel] §3.1 polarity labels wrong in three rows: install-covers corpus clause is ⊕ not ⊖; E5 `demoted(as_of)` is ⊖ not ±; `cal_stamp` is a recomputed equality, not a polar guard.
- R1-CC-7 [math] D4 self-cut does not type-check: `cal_run.run_index` (:757) and `rga_trial.trial_index` (:532) are sub-ledger counts, not strand positions; only `track_records[*].as_of` is a compared position.
- R1-CC-8 [lit] Ledger items 1–3 are CALM plus Dedalus stratified negation; Imieliński–Lipski / Dyreson–Snodgrass indeterminacy plus Instant Replay (LeBlanc–Mellor-Crummey 1987); sequence numbers and audit control totals.

Referee-confirmed kernel facts
- P1 (replay seam): an honest journal with an audit by a checker refused later is refused on rebuild — `_guard_audit_checker` (rga/calibration.py:608 via :777) reads `escapes(cls)` with `as_of=None`. x.sealed_at 37, filing cut 38, refused_at 42; final |J_R| is 44, not 43. No test covers it.
- E1–E6 all run green against the live `from_events`; E6: deleting FCD[10..12] is refused by FCD's own re-drive, never by `_guard_sample_order`.
- P6(b): a later same-class stamp anchors an earlier escape through `corpus_size` / `charged_cells` recomputation (:862-865) — CT T10(b) "every demonstration is recompute-free" is false.
- Only `cal_stamp.sealed_at` (compared at :852) anchors J_R length; IR seals anchor nothing (A2 refused, A1 clean).
- PROOFS.md:165 says the refused check is re-run on replay; replay (:768-771) checks `declared` and `discredited` only.
- §6 numbers correct: |J_F|=18, |J_R|=13, sealed_at 12/23/34, fcd_position 1/5/9/13; suites green (136 checks).

### Refuser Calculus (compositional)

Guarded machines at attempt granularity; stacking as stuttering simulation; read-channel stability typing; refuser sets (minimal guard cuts) per violation class; kill signatures in a free commutative monoid.
Verdicts: soundness repairable · novelty derivative · fidelity repairable.

- R1-RC-1 [math, kernel] K5 last row false: {`_guard_pinned_before_open`, `_guard_not_refused`} seals a line pinning a refuter refused before Open; refused_at < sealed_at so `tainted` (rga/core.py:659) is false and `admissible` True.
- R1-RC-2 [math, kernel] K5 rogue-trial row: {`_guard_trial_pinned`} alone seals when the rogue is tried on every sample (`_witness_vector`, :897); the V8∧V2 pair is one driver's refuser set, not a cut.
- R1-RC-3 [math, kernel] T2(iii) false: instability of φ somewhere in Reach(M) does not give an N-run reaching that state after β; counterexample `item.pointer == 0` after `status == failed`.
- R1-RC-4 [math, lit, kernel] T5(c) proof gapped: guard-path classes overlap as pair-sets, so weakening g "on exactly the pairs of C" alters registered drivers; the negative half of adequacy is unproved.
- R1-RC-5 [math] D10 does not type-check: `_check_refuted`, `_check_replay`, `_check_concordance`, `_check_power_floor` publish closes (rga/core.py:536-537, 851, 856), they do not refuse; the registry's replacements change effects, not enabling.
- R1-RC-6 [math] §8 "deleting the cal_run/cal_replay pair is the only move that raises it" false: a second filing replayed divergently discredits the checker; `admissible` True with nothing deleted.
- R1-RC-7 [math] D4/D6: `CalibrationAuthority.seal` steps Admission as seal or as close (E5, rga/calibration.py:531) depending on state; f_Att must map (state, attempt) pairs.
- R1-RC-8 [lit] Items 1–3 are Lipton reduction / Lamport–Schneider atomicity; UNITY stability plus CALM; Jia–Harman higher-order mutants with Budd–Angluin adequacy and Graf–Saïdi predicate abstraction.
- R1-RC-9 [kernel] Bookkeeping: the table has 6 singleton, 6 size-2 and 1 outside-G_A cuts; §8 says 9/4; §0 says two unregistered pairs.

Referee-confirmed kernel facts
- C7 rollback: driving `CalibrationAuthority.seal` with a raising clock takes the Admission journal 12→13→12; w unsealed, pc=Open, zero cal events. PROOFS.md:161 ("only assignments target self._events, self.runs, …") is false of rga/calibration.py:156-170; no test drives that branch (C7NonInterference covers successful transitions only). The `admission_policy` branch (:156-162) is the same defect for CalInstall.
- K6: 26×26 kill context, every diagonal red, exactly one off-diagonal red (`s_guard_not_refused` × `_check_replay`); the predicate fix `and TESTS in h.a.refused` verified.
- Pair cut {`_guard_seal_complete`, `_guard_sample_count`} for k+1 samples: neither single deletion reaches it.
- At p_min=0.5, {`_guard_seal_measured`} alone does not seal; {`_guard_seal_measured`, `_check_power_floor`} does — a second parameter-dependent cut beside the θ=0.6 one.
- K2's S/Q/G typing verified writer by writer; K7 numbers exact (C(66,22)=182183167981760400, C(24,22)=276, 298 cases).
- tests/test_rga_calibration.py:580 GUARDS has 17 entries (includes `_stamp`, an effect); `Enforcer.install` / `Admission.install` are unwrapped and append no event.

### Preimage Games (strategic)

The custody game with preimage-witnessed move order; the journal's published-evaluation set Π as the generator's leakage; a two-regime theorem for seed-invariant refuters; an ordered exposure type.
Verdicts: soundness repairable · novelty derivative · fidelity repairable.

- R1-PG-1 [math, kernel] T3's functionality step miscites R5: `_file_run` (rga/calibration.py:267-290) never checks nonce reuse; an escape filed at trial 0's exact seed is accepted and established, `refused` stays empty.
- R1-PG-2 [math, kernel] T3(ii) false: with σ = var, 𝔽_inv ∩ 𝔽(Π) = ∅ and O is empty, not a singleton; §5's own post-escape state is the counterexample.
- R1-PG-3 [math] Novelty item 1 contradicted by T2's own proof: freshness needs X2 (nonce unpredictability); a constant nonce source gives three samples one seed and nothing refuses.
- R1-PG-4 [math] T3(i)–(iii) and Cor 3.1 are vacuous: a finite set of graph points constrains an arbitrary function only at those points; nothing about the journal enters the proofs.
- R1-PG-5 [math] T5(b) false for |Π|: evaluated at sealed_at but ordered by opened_at; concurrent lines on one bind key give |Π| 6→3 along the order.
- R1-PG-6 [math, kernel] T4(a) is liveness and mis-cites I7: survival is not sealing (p_min > kills/size closes V5 every attempt); each attempt is a new item with a fresh `tried`.
- R1-PG-7 [math, kernel] "The stage move that fixed sample i's bytes" does not type-check: FCD holds no bytes; bytes enter at `rga_sample` (rga/core.py:479). N3's exactness needs body provenance (PROOFS.md:191).
- R1-PG-8 [math, kernel] N5 is not one transition: verdict and witness are arguments of the call that would draw the nonce; needs `audit_draw` / `audit_report`, unreported draws typed fail-closed.
- R1-PG-9 [kernel] D6's Π admits unestablished and discredited `cal_run`s: one unreplayed false refutation sets σ = var, the less-exposed reading — a fail-open channel.
- R1-PG-10 [lit] Items 1–3 are Σ-protocol / Fiat–Shamir commit-then-challenge plus version spaces (Mitchell 1982); Denning's 1976 lattice plus Lamport happens-before; metamorphic relations and the reusable holdout (Dwork et al. 2015).

Referee-confirmed kernel facts
- §5 worked example reproduces position by position: every scrutiny, FCD and standing position, hash prefix and seed.
- `trial` (rga/core.py:515-538) checks only index validity; `rga_trial` (:532-535) carries no `fcd_position` while `rga_sample` (:503) does; `run_to_seal_ready` (tests/test_rga_invariants.py:117-120) and the bench (bench.py:536-550) journal sample-0's trial before sample 1 registers.
- `file_audit` (rga/calibration.py:257-264) takes the caller's nonce; `_guard_run_seed` (:594-599) checks derivation only; the bench's finder files only refutations (:576-585).
- An unreplayed `refuted` `cal_run` is accepted with `_check_valid` False.
- The bench materialises all K samples before any FCD stage (bench.py:536); `ts` is excluded from replay comparison (fcd/core.py:145), so the shared clock orders nothing replay-checked.

### Completeness critic

Ranking: compositional 1 (load-bearing twice, all verdicts repairable, every computed claim confirmed), logical 2 (cleanest verdicts, one real bug, most derivative), quantitative 3 (highest-leverage gap, most findings: 19), strategic 4 (repeated game, narrow determined regime), record 5 (highest potential load, soundness broken).
Unification: a committed-support presheaf over the lattice of consistent cuts of the three journals — every queryable verdict carries cut(v), a minimal support supp(v) of recorded atoms (positions, assumption labels, guards, defect ids, refuter evaluations) and sign(v); two rules generate all five branches: fail-closed = infimum over worlds consistent with the support; commitment = every atom of the support pinned strictly before the observation it constrains. Each branch is supp projected onto one atom sort plus one rule.
Missing theorem: committed-support representation — (i) determination by supp, (ii) fail-closed = infimum (union, labelled max, `power_min`, K3, base-inclusion tiering as one rule), (iii) readable at a cut iff committed, else silence, (iv) loudness totality across all three layers, F5–F10 included.
Untouched by every branch: parameter derivation (k, θ, p_min, e_max), the concordance sampling model, subsumption-weighted D and B6 transfer, version-bump laundering of charges, liveness / dual-control covering, the ratchet coverage relation, norm injectivity, the instrument-validity meta-problem; `fcd/core.py` is never the subject of a theorem.

## Round 2 — the unified paper

Verdicts: soundness major revision · fidelity major revision · novelty major revision. Common ground across the three: 24/24 companion tests pass; every `file:symbol` citation in §8, §8a and IMPROVEMENTS.md resolves; the three prior-round corrections (T10(b) anchored/exposed, T10 connectedness, T5's two report-driven paths) each landed and each is incomplete; T6/T7/K3, T11, T12, T13's attempt-granularity caveat and K8's kill matrix survive re-execution; F1, F2, F3, F4 (first cut), F6, F8, F12 reproduce exactly.

### Fatal — R2-soundness-1 (D7 / X1 / T2 proof / T4(a), §3.1, §3.3)

D7 defines w ⊨ r as "the machine … produced exactly the record r". X1 then asserts w ⊨ r·e ⇒ w ⊨ r, which is false under that definition (a world producing exactly r·e does not produce exactly r; ⟦r⟧_B ∩ ⟦r·e⟧_B = ∅), so T2's proof ("By X1, ⟦r·e⟧_B ⊆ ⟦r⟧_B") rests on a contradiction. T4(a)'s proof then asserts ⟦r⟧_B ⊆ ⟦r'⟧_B for a scattered subword r' ⊂ r; no stated axiom gives this — X1, even repaired to a prefix reading, speaks only of prefixes, and under either reading the two world-sets are disjoint for a non-prefix subword. The conclusion is false for arbitrary world properties, which D8 allows: "take r = a·ρ·b with |a| = n−1, |b| ≥ 1, ρ an rga_refuse, r' = a·b ∈ L_rep, and P_n = 'the produced record's first n events contain no rga_refuse'. Then □P_n(r') = true and □P_n(r) = false, i.e. □P(r') > □P(r), contradicting clause (a) 'deletion lowers every necessity'." Clause (a)'s second sentence and T4.1 depend on it; T4 is the paper's declared centre and §9's first novelty item. The fidelity lens reached the same gap independently (R2-fidelity-1: three incompatible consistency relations — exactly / prefix / scattered subword). Repair: subsequence semantics for ⊨ (X1 and the inclusion then follow; T1–T3 unaffected); restrict the necessities T4/T11/T17 quantify over to a named class determined by the roots of retained events and monotone under sub-record; prove (a) for that class as a lemma with a hypothesis; state that `is_sealed` and `mediated` are of that class; add the line that for an arbitrary world property deletion can raise a necessity.

### Major

- R2-soundness-2 T4(b), §3.3, §3.5, T10(c): "genuinely holds" is definitional. P5 appends a stamp for an IR seal at equal cal length → `admissible(x)` True; P16 inserts a stamp mid-journal with nested `as_of` renumbered. ¬mediated has no witness and is repaired by a length-preserving move.
- R2-soundness-3 T10 (𝔊_n), T10(b), T17(iii): 𝔊_n as defined reaches every length-n record; P3 deletes an anchored escape together with its anchoring stamp, pads with three audits, replays clean, `admissible(w)` True. Anchoring must be recursive.
- R2-soundness-4 T4.1, §9 conjecture (iv), `custody.py:exposed`: two anchors missed — `cal_close(E5)` (`demoted(as_of)` re-checked at :874, P9a) and a later audit by a tier-B escape's checker (:777, P9b); `exposed()` says exposed where replay refuses. Derive anchoring from `from_events`.
- R2-soundness-5 T17(i), `custody.py:support`: deleting the diverged `cal_replay` + `cal_discredit` (outside the support) flips `admissible` True→False (P2); "any event inserted" is refuted by any escape. Definitional, or enlarge the negative atoms to validity degraders.
- R2-soundness-6 D6, `POLARITY['rga_refuse']`, §8a closing paragraph: `rga_refuse` is ± — a checker refused after a tier-B escape on a line it is not pinned on un-impeaches without tainting (P1, honest journal). §8a's "one row" sentence is false.
- R2-soundness-7 T9(c), N13: "the only such relation is membership" is false — covers(D,e) := |ids(D)| ≥ 2 is decidable, non-discretionary, monotone, not membership. Add equivariance, or weaken to "membership is the weakest".
- R2-soundness-8 §8a F1 "spec" direction, abstract, N28: INVARIANTS §8.1 Valid and C6 void established escapes; the code follows §8.1; the layer paper is inconsistent between its §8.2 row and §8.1/C6. Relabel fail-open; argue N28 on its merits and state its cost.
- R2-soundness-9 T17(iv) vs D28: under (iv) every tier-A escape is committed; D28 says filed escapes are selected. Restate with D28's two conditions; today no negative atom of `admissible` is committed.
- R2-soundness-10 T4.2, K5: minimality unproved (length is needed only because T11 counts); equal |r| does not identify a journal, so line-scoped certificates do not compose as claimed. Add a journal identity.
- R2-soundness-11 D3 "publishes", T5, T15: V1 appends [rga_trial, rga_close]; V4 appends [rga_replay, rga_refuse, rga_close] — the fault label is not first (P18). Define publishes as "no store write precedes the fault".
- R2-fidelity-1 D7 / X1 / T4(a) (DRAFT lines 82, 92, 133): three incompatible consistency relations; the central theorem's monotonicity clause has no proof under the stated semantics. Repair: subsequence semantics (see fatal).
- R2-fidelity-2 §8a F1, N28 (line 434), IMPROVEMENTS preamble: "back to what the transition table says" misreads an inconsistent spec; N28 must also rewrite §8.1, C3, C6. Sharper root cause: E1 attributes a divergence at an unestablished run to the checker, not the filer.
- R2-fidelity-3 T5 vs N28: `impeached()` calls `_check_valid` with `as_of=None` (:409, :349-355), so one divergent `Admission.replay` of a tier-B checker anywhere un-impeaches without taint; N28 repairs only the discredit path.
- R2-fidelity-4 T4.1, T10(b), N16, `custody.py:_anchors_of`: under D11 (scattered subword) every later `cal_run` anchors ("run index out of order", :757); under renumbering `cal_exclude` does not anchor (:816-820). Fix one move set.
- R2-fidelity-5 N1, `deletion_surface` taint branch, `test_a_tail_refusal_group_is_exposed`: deleting exactly the named pair is refused ("regenerated 16 events for a journal of 17"); the cascaded `rga_close(V4)` (rga/core.py:568-575) belongs to the group; the test never rebuilds.
- R2-fidelity-6 T10(a),(c) vs D18: a coherent root rewrite leaves the boolean unchanged, so (a)'s "all of them" holds only for root-parameterised necessities and (c) "by (a)" is invalid. Split value- from proposition-certifiability.
- R2-fidelity-7 N7: siting H(rga_open roots) in the FCD manifest makes the lower machine read the upper — the reverse of D21(ii)/R11. Move to an RGA-owned field, or re-tier with an added trust assumption.
- R2-fidelity-8 N18, F7: `open_mediated` is not a pure query over today's record (no cut orders cal events against rga positions); F7 reproduces only under `demotion_gate=carry` (gate=seal refuses E5).
- R2-fidelity-9 N17: evaluating `_guard_audit_checker` at the largest earlier recorded cut is below the live cut — accepts audits live refused; turns a fail-closed seam fail-open. Make it depend on N19.
- R2-fidelity-10 abstract, §8, §8a, §9 "fifteen reviews", IMPROVEMENTS N18/N22: eval/reviews/ held no branch or custody report; F5, F7, F9–F11, F13 and N22 have no test. Add the reports or relabel "asserted, untested".
- R2-novelty-1 §9 item 1, §3.6: roots / Δ / |r| is correctness / completeness / freshness of authenticated query processing over outsourced data (Devanbu 2003; Li 2006); valid = issued ∧ ¬revoked with the CRL number as length witness is X.509; PeerReview uncited. The sign is the ODB completeness obligation.
- R2-novelty-2 §9 item 2, K5, N2: "global heads do not compose" is contradicted by history-tree consistency proofs (Crosby–Wallach 2009; RFC 6962); N2 is OCSP-shaped (RFC 2560); the count is a degenerate accumulator.
- R2-novelty-3 §9 item 6, T7.2: composing bounds along a DAG with shared ancestors counted once is the fault-tree cut-set bound (NUREG-0492; Esary–Proschan 1963; Barlow–Proschan 1975). Keep F6 as the local finding.
- R2-novelty-4 T10(c), T10(a), K1: (c) does not follow from (a); `admissible`'s boolean survives a root rewrite; K1's gloss of `is_sealed` mentions no root and is certifiable by (a)'s own criterion. Define certifiability on (verdict, roots).

### Minor

Soundness — 12 T10 proof: τ_1 → τ_0 for connectedness. 13 T6(c): equality claim fails at p_ρ = 1 (P12). 14 T11 root list omits pinned refuters' registry records and `rga_replay`, which the companion hashes. 15 `custody.exposure` ignores the open(ℓ) cut (P10). 16 taint-surface test reads a flag, never deletes; V4 closes missing from the group (P4). 17 POLARITY test exercises one run; ± and − rows unchecked. 18 findings F1–F13 collide with faults F1–F10. 19 D26 before D12; §3.6 forward-references from a "self-contained" section. 20 citations: no §7.1 in the composed paper; `test_authenticated_receipt.py` names no certificate; `nonce-{i}` is the harness; the renumbered root is nested `track_records[*].as_of`. 21 abstract "most pure queries" (7 of 28). 22 N9 `derived_tier` is the pinned rule restated (P13). 23 T1 μ∘emit needs μ root-only. 24 K8 "predicts" → "names". 25 T18(b): product is 0 on any incomplete campaign; artifact selection breaks any family-wise reading.
Fidelity — 11 F4's second pair cut and the off-diagonal reproduce but are untested. 12 §1.1: unmarked elision in the §2 adversary quote; exempt the witness-source usage from "non-replayable". 13 τ_0. 14 D6 "enabling" vs companion "+"; `rga_close` absent from D6. 15 bench nonces are `n{i}` / `finder-{iid}-{j}` (bench.py:483, 577). 16 D27/T18(b): seed uniformity needs a PRF / random-oracle assumption B7 does not give. 17 N12 "no rate" → "no computed rate; a declared curve over two primaries". 18 F3 quotes PROOFS.md:161 inexactly. 19 "most pure queries" (12 of 28 carry the tier); D4 "total" vs `demoted` raising E9; N8 text vs companion. 20 §3.5 sentence contradicts the corrected T5.
Novelty — 5 Dedalus gives temporal stratification; "sealing" is Blazes 2014. 6 T14 is independence of postulates (Hilbert 1899; Huntington 1904), not Padoa. 7 frame rule: O'Hearn–Reynolds–Yang 2001, abstract form Calcagno–O'Hearn–Yang 2007. 8 anchoring is dependency provenance / lineage, not where-provenance. 9 T6/T7 are Boole–Fréchet (1935), attained at the Fréchet–Hoeffding upper copula. 10 D8 is runs-and-systems knowledge (Halpern–Moses 1990); T2 is Chandy–Misra 1986. 11 position vs preimage is the nonce-vs-timestamp dichotomy (Denning–Sacco 1981; Abadi–Needham 1996). 12 cite Pollock 1987; sharper item 4: C3's non-discretion holds for revocation and fails for reinstatement. 13 "custody" vs forensic chain of custody; "demonstration" vs the few-shot sense. 14 T18: cite Ville 1939, Shafer 2021, Vovk–Wang 2021, Grünwald et al. 2024. 15 conjecture (iv): state the enumeration method; derived_defect_id's position shift is N11's job.

## Round 3 — focused re-check of the repaired semantics

One referee (mathematical lens, kernel access, probes `probe_custody.py` P1–P6 and `probe2.py` Q1–Q4) re-checked D6–D11, D17–D18, D26, X1, T2–T5, T10, T11, T17 and §8a F1/F5 after round 2's repairs.

Verdicts: (1) D7/X1/T2/T4(a) **sound** — T4(a) now holds for every world property, no counterexample; (b), (c), T11 and T17 needed a named class of necessities (root-determined, D8′) — repairable. (2) The custodial reading of `is_sealed`/`mediated` **sound but under-stated**: certifiable necessities are presence claims; the guard content rides on A0; a vacuity hole (`⟦r⟧_B = ∅` records that replay accepts) with a new fail-open replay seam behind it (F14) — repairable. (3) T10(b) as a certifiability claim **broken**: every anchor is itself exposed, so anchoring prices a deletion and does not prevent it (P2 peeled an anchored escape by two single-event moves); (c) consistent with K4/T11 (P3, Q2 both caught on `roots`) — repairable. (4) T17(i) **holds for `admissible` under deletion**: an exhaustive search over single and pair deletions in seven scenarios found zero deletion sets disjoint from the support that change `admissible`; `cal_adjudicate(reject)` is not a degrader (P5) — repairable. (5) Notation: `cal_discredit` is strictly positive, not mixed (Q3); `cal_run` is neutral; `Σ_F` must include `rga_refuse`/`cal_discredit` (Q4); T11's root list omitted the registry records and `rga_replay`; ordering and wording minors.

All round-3 findings are applied in this revision: D8′ and the custodial premise with the vacuity clause; T4(b) restated with the degrader insertion; T10(b) restated as cost, T17(iii) aligned with T11; degraders without `reject`; D6/POLARITY relabelled; F14 added with a test; T11's root list corrected.

## Disposition

`applied` — taken into the next revision of DRAFT.md / IMPROVEMENTS.md / custody.py / tests. `open` — either a branch document's own theorem error (those documents are not in the repository; where the kernel fact behind it was carried into DRAFT.md the row says so) or a kernel code change (catalogued as N1–N28, not applied). Round-1 minors are not tabulated.

| finding | severity | disposition |
|---|---|---|
| R1-FL-1 | major | open — branch T7; kernel fact carried as F10, N12 |
| R1-FL-2 | major | open — branch T5 |
| R1-FL-3 | major | open — branch T6(b) |
| R1-FL-4 | major | open — branch T4(ii) |
| R1-FL-5 | major | open — branch T1/T2 |
| R1-FL-6 | major | open — branch Cor 3.1 |
| R1-FL-7 | major | open — branch ledger |
| R1-FL-8 | major | applied — D28, T18, N23 read B9 as unpredictability |
| R1-FL-9 | major | applied — §9 cites Stark, Hamlet/Miller, Cornell/Ditlevsen/Hailperin |
| R1-FL-10 | major | applied — N12 declares a step function, no ratio |
| R1-FL-11 | major | applied — N23 values incomplete campaigns 0, authority draws nonces |
| R1-FL-12 | major | applied — N24 restricts to D ∩ D′, drops the seed-roll bucket |
| R1-PS-1 | major | open — branch T4(ii); witness shape carried as N16 |
| R1-PS-2 | major | open — branch T1/D10 |
| R1-PS-3 | major | open — branch T1.2; Probe 3a carried |
| R1-PS-4 | major | open — branch D11/T5; DRAFT N9 inherits it (R2-soundness-22) |
| R1-PS-5 | major | open — branch T3; DRAFT T5 states the two paths |
| R1-PS-6 | major | applied — §9 cites de Kleer, Doyle |
| R1-PS-7 | major | open — kernel change; alternative catalogued as N28 |
| R1-PS-8 | major | applied — F5 |
| R1-CC-1 | fatal | open — branch T5; fact carried as K4, T10(b) anchored/exposed |
| R1-CC-2 | fatal | applied — F11; `rga_seal.fcd_position` catalogued as N19 |
| R1-CC-3 | fatal | open — branch T7; rewrite moves enter T10 via R2-soundness-3 |
| R1-CC-4 | major | applied — F5 |
| R1-CC-5 | major | open — branch T8; successor is N2 (R2-soundness-10) |
| R1-CC-6 | major | open — branch §3.1 table |
| R1-CC-7 | major | open — branch D4 |
| R1-CC-8 | major | applied — §9 cites Imieliński–Lipski, CALM; Dedalus slip via R2-novelty-5 |
| R1-RC-1 | major | applied — F4 second pair cut; N25 |
| R1-RC-2 | major | applied — F4 carries the two real cuts only |
| R1-RC-3 | major | open — branch T2(iii); kernel instance carried as T13, N26 |
| R1-RC-4 | major | open — branch T5(c); T14(b) states spanning by definition |
| R1-RC-5 | major | open — branch D10; DRAFT D3 fixed via R2-soundness-11 |
| R1-RC-6 | major | applied — T5, F1 |
| R1-RC-7 | major | open — branch D4/D6 |
| R1-RC-8 | major | applied — §9 cites Lipton; Jia–Harman, Budd–Angluin via R2-novelty-6 |
| R1-RC-9 | major | open — branch bookkeeping |
| R1-PG-1 | major | applied — F8 |
| R1-PG-2 | major | open — branch T3(ii) |
| R1-PG-3 | major | open — branch ledger; nonce predictability carried at T18, N23 |
| R1-PG-4 | major | open — branch T3 |
| R1-PG-5 | major | applied — D25 evaluates at open(ℓ); companion via R2-soundness-15 |
| R1-PG-6 | major | applied — N22 notes I7 gives no horizon across attempts |
| R1-PG-7 | major | applied — N19 declines `rga_trial.fcd_position` |
| R1-PG-8 | major | applied — N21 two-phase audit |
| R1-PG-9 | major | open — branch D6/σ; not carried into N8 |
| R1-PG-10 | major | applied — §9 (derivative on every branch) |
| R2-soundness-1 | fatal | applied |
| R2-soundness-2 | major | applied |
| R2-soundness-3 | major | applied |
| R2-soundness-4 | major | applied — companion re-drives `from_events`; red tests P9a/P9b |
| R2-soundness-5 | major | applied |
| R2-soundness-6 | major | applied — companion POLARITY and test |
| R2-soundness-7 | major | applied |
| R2-soundness-8 | major | applied (text); N28 itself stays catalogued, open |
| R2-soundness-9 | major | applied |
| R2-soundness-10 | major | applied |
| R2-soundness-11 | major | applied |
| R2-soundness-12–25 | minor | applied |
| R2-fidelity-1 | major | applied |
| R2-fidelity-2 | major | applied (text); the alternative discredit semantics is a kernel change, open |
| R2-fidelity-3 | major | applied — refusal path listed as residue beside N27 |
| R2-fidelity-4 | major | applied — one move set fixed; companion and test |
| R2-fidelity-5 | major | applied — companion group and rebuilding test |
| R2-fidelity-6 | major | applied |
| R2-fidelity-7 | major | applied — N7 re-tiered |
| R2-fidelity-8 | major | applied — N18 contingent on N19; F7 qualified |
| R2-fidelity-9 | major | applied — N17 contingent on N19; seam stays fail-closed |
| R2-fidelity-10 | major | applied — this file; untested rows relabelled |
| R2-fidelity-11–20 | minor | applied |
| R2-novelty-1 | major | applied |
| R2-novelty-2 | major | applied |
| R2-novelty-3 | major | applied |
| R2-novelty-4 | major | applied |
| R2-novelty-5–15 | minor | applied |
