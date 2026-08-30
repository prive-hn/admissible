# Premise

Roque Briceño. The attack on the RGA brief, written before the kernel. Companion to `INVARIANTS.md`, `PROOFS.md` and `DRAFT.md` in this directory.

The brief asked four questions and said: if the premise does not survive, the honest paper says why. This file is that report. It records what was attacked, what fell, what survived, and what the survivors force on the design.

## 0. Method

Five adversarial readings of the brief, one per question plus one whose only job was to argue that RGA is FCD with ceremony. Thirty-eight findings. Each finding was handed to an independent reviewer instructed to refute it, defaulting to *refuted* unless the argument survived a genuine attempt. All readers had `paper/INVARIANTS.md`, `paper/PROOFS.md`, `paper/DRAFT.md`, `fcd/core.py` and `eval/reviews/r4-formal.md`; several ran constructions on the unmodified machine.

| Question | Findings | Refuted | Survive, narrowed | Survive as stated |
|---|---|---|---|---|
| Power | 10 | 5 | 5 | 0 |
| Cheaper formulation | 6 | 2 | 4 | 0 |
| Boundary | 7 | 2 | 5 | 0 |
| Subsumption | 7 | 1 | 6 | 0 |
| Collapse | 8 | 4 | 4 | 0 |

Six findings were filed as *kills-premise*. None survived at that severity. Every one was either refuted or reduced to a design constraint. Nothing survived unchanged either: the brief as written over-claims in four places, listed in §6.

Positions I held before the attack are in the session scratchpad. Two were wrong and are marked below.

## 1. Is power measurable, or declared?

**Verdict: measurable, relative to a declared alternative. Never a measurement of the generator's actual defects. The kernel can make the bare number unrepresentable; it cannot make the alternative honest.**

The brief defines power as the probability the refuter would have caught the defect had it been there. That is Neyman–Pearson power: a function of the alternative hypothesis, not a number. The first attack said a scalar exists only after someone declares a prior over defects, so power collapses to a declaration. The refutation: a composite alternative is scalarised by *infimum over a declared class*, not by expectation over a prior. Every clinical power calculation is a scalar at a declared effect size. Nobody concludes power does not exist.

Three modes survive, and the kernel must carry which one it is:

1. **Exhaustive.** The refuter enumerates a finite domain. Power against any defect in that domain is 1 by construction. No sample size. This is the proof-carrying-code corner (Necula & Lee 1996): the seal still carries power 1 and the checker's identity, because a seal with no power field is the laundering channel the brief forbids.
2. **Bounded.** A seeded refuter draws N inputs from its declared distribution Q. Against any defect whose failure mass under Q is at least ε, the kill probability is at least 1−(1−ε)^N (Goldreich–Goldwasser–Ron 1998; Freivalds 1977; Miller–Rabin). The seal carries (ε, N); the seed rule is the kernel's (R10); Q is whatever the pinned refuter version samples from and is not a kernel field. ε is itself a declaration and the seal shows it (§9). The number is refuter-intrinsic and invariant to the generator by construction. The seed must be drawn *after* the artifact hash is frozen, or the generator can tailor to it; §5.
3. **Calibrated.** A refuter is run against a declared, content-addressed defect model D — a finite set of seeded defects, each with a killing witness so the denominator is exact. Power is kills/|D|, exact on D. The seal carries (D, kills, |D|, refuter version). Its transfer to the generator's real defects is the coupling-effect hypothesis (DeMillo, Lipton & Sayward 1978), which Just et al. (2014) found holds for roughly three quarters of real faults under common operators. That transfer is an empirical claim and goes under *What is not proved*, beside FCD's A10.

What fell:

- *The Wilson lower bound as the carried number.* I pre-registered this: carry kills, |D| and a 95% lower bound, threshold on the bound. Refuted. A binomial interval assumes i.i.d. draws from the population the seal speaks to; a mutant set is not that. A refuter killing 4900 of 5000 redundant operator mutants carries a lower bound of 0.976; a refuter killing 49 of 50 adversarial defects carries 0.895. The interval ranks the first above the second while the first has power near zero against the class it misses. A threshold on the interval does not remove laundering; it re-launders under a statistical badge. The coordinate that separates two seals at the same kill-rate is D, not n. So: |D| is derived from the content-addressed D, not carried as a free variable; the class policy names which D it certifies; the number is exact on D and the seal says so. `rga/core.py` carries kills and |D| and no interval.
- *Power composes by independence.* Refuted, and the repo's own ethos agrees (`fcd/core.py:254` recomputes `on_bind` rather than trusting a submitted boolean). Two refuters at 0.8 give 0.96 only if their blind spots are disjoint; Knight & Leveson (1986) measured correlated failure far above the independence prediction. Composite power is exact only as the union of kill vectors over one shared D. From scalars alone the sound bound is max(pᵢ). The kernel computes the union when D is shared and otherwise carries max, labelled.
- *A trivially weak refuter passes.* A refuter that always returns *survived* kills nothing: power 0/|D|, carried. A refuter weak in a targeted way — strong on D, blind to the defect class the generator actually emits — is not caught, and that is the Goodhart residue under *not proved*. Its oracle must derive from the Claim, never from the artifact (a golden-copy refuter needs information flow from the artifact into the check, which pinning the refuter before generation forbids), and the defect model must be authored by a party that is neither the generator nor the refuter's author. Three-way separation of duty.
- *Prose has no D.* Refuted by the factual-consistency literature: FactCC's perturbation family (entity, number, pronoun swap, negation), FRANK's error typology, and fixed-weight checkers (SummaC, AlignScore) that are bitwise replayable when pinned, with kill rates against human-labelled faithfulness errors in the 0.7–0.85 range. RGA scopes admission by *defect family with measured power*, not by medium. Omission and adequacy defects have near-zero measured power today and the seal shows that.

What the kernel can do: refuse a bare float; accept only a ledger of per-defect verdicts and count the kills itself; bind the record to a refuter version and a D hash; make the record write-once per (refuter version, D) so nothing raises it after the fact; compute the bounded-mode number from declared (ε, N) rather than accepting it, and carry (ε, N) in the seal so the declaration is visible. Two representations cover the three modes — the exhaustive mode is a ledger enumerating the whole domain — and the seal labels which. What the kernel cannot do: verify the ledger was produced by running anything. That is the same boundary as FCD's A10, and it is named as such.

**Is RGA then FCD with ceremony?** It is, exactly when power enters the seal as a scalar somebody wrote down. It is not when power enters as a replayable certification record a third party can falsify — the same move FCD makes with the package hash. The brief's phrase "measured doubt" must be read as *measured power against a declared alternative*, and the paper says so in its first paragraph.

## 2. Is there a cheaper formulation?

**Verdict: no candidate gives the same guarantee. Three are subcomponents, one is the power-1 corner, one is a different object. The name stays, with one sentence of DRAFT §9 discipline added.**

| Candidate | Gives | Lacks | Relation |
|---|---|---|---|
| Quorum of generators / N-version (Avizienis 1985) | Cross-model agreement; each sample inherits I1/I3 | No refuter, no power, no replay; Knight–Leveson correlation unmeasured | Subcomponent: concordance without refutation. Expressible as FCD stages with author exclusion on write stages. |
| Acceptance criteria fixed at Open (Meyer 1992; Nosek 2018) | Claim not authored by the generator | No power: Hypothesis at 100 vs 10 000 examples is the same green. No concordance. No determinism audit. | The skeleton RGA measures the strength of. Does not close the Goodhart hole; relocates it from "generator writes a weak claim after" to "generator writes an artifact after seeing a fixed public refuter". |
| Plain CI + hermetic builds + in-toto/SLSA provenance | T1, T3 provenance, T5 re-run, trial record | Concordance under a claim normaliser (in-toto thresholds are byte identity); a typed store read by the DAG gate; verdict replay from the journal | Residue is three guards, not one. Whether that is a paper or a section is a judgement the result must earn. |
| Proof-carrying code (Necula & Lee 1996) | Power 1 on the checked predicate | Nothing, where the predicate is human-authored. Where it is autoformalised by the generator, kernel power on the proof is 1 and power on the claim is not. | The exhaustive corner of mode 1. Cited. |
| Self-consistency / semantic entropy (Wang 2022; Kuhn, Gal & Farquhar 2023) | Disagreement detection, AUROC ≈ 0.7–0.8 as a confabulation signal | No refuter; a vote, not a fault | Inversion 3 *is* semantic entropy applied as a fail-closed gate with a threshold. The paper says so. |
| Conformal / selective prediction (Vovk; Mohri & Hashimoto 2024) | A marginal error rate with a theorem | Per-item refutation; a replayable verdict on one artifact; the best scorer is k-resample frequency, i.e. concordance, plus a labelled calibration set whose labeller is a refuter | A class-level rate that can sit beside the seal. Not a guard on Accept. |
| SPRT / statistical model checking (Younes & Simmons 2002) | Early-stopping bound on P(survive R) with declared α, β | Refuter-independent concordance | The formal home for a stamped survival rate with error bounds. Complementary. |

Two alternative names were proposed from the mathematics: *Seeded-Refutation Admission: Observed Power, Replayable Verdicts* and *Verdict-Bound Acceptance: a refutation stage for fail-closed class dispatch*. Both name mechanisms. *Refutation-Gated* names the shape of the guarantee: nothing is admitted except through a declared refutation that was given a fair chance and failed. The algorithm keeps its name. The subtitle *Integrity for Agents That Do Not Repeat* states the problem precisely and is kept; what it must not be read as is a theorem that the claim is true. §6.

The sentence the paper owes, in the voice of DRAFT §9: this is mutation analysis, hermetic replay and semantic entropy applied as guards on an FCD line, not a new integrity model. Clark and Wilson already had the integrity verification procedure and the certification rules; FCD modelled the enforcement half and listed body quality as unproved; RGA models the IVP and its certification record, and says which half is enforced and which is certified out of band.

## 3. Which claims can a deterministic refuter attack?

**Verdict: the boundary is intrinsic to a formal claim and sharp; what is relative is the gap between an intent and the formal claims that stand in for it. That gap is the engineering content, and the seal must carry it as an explicit field.**

Criterion. A claim C over a fixed artifact format is RGA-attackable iff its falsity has a finite witness that a total, fuel-bounded, hermetic, replay-stable checker accepts. Run the brief's list through it:

| Intent | Attackable shadow | Residual |
|---|---|---|
| "Passes tests T" / "type-checks" / "validates against schema S" | The claim itself; witness is the failing run | none |
| "∀x. P(x)" over an infinite domain | Kills (any counterexample); survivals only at bounded or calibrated power | absence, per Dijkstra |
| "f(x) = f(permute(x))", "decode(encode(x)) = x" | The relation; witness is the violating pair | that the relation is the right one |
| "Cites only files that exist; touches only the files the contract named; every number in the summary occurs in the anchored source span" | The claim itself | none |
| "This summary is faithful" | Anchored-span checks on entities, numbers, negations; pinned NLI checker at calibrated power | reversed causality, omission |
| "This is the correct fix" | Issue no longer reproduces; held-out tests pass; diff scope | that the held-out tests test the issue |
| "This design is good" | Named constraints: latency under a fixed load script, no dependency cycle, schema backward-compatible | everything else |

Every interesting intent has only an attackable shadow — necessary conditions, never the intent. A seal that attacked the shadow at power 1 must not read as a verdict on the intent. So the seal lists what was attacked, at what power, against which D, and carries an explicit **not-attacked** field for the residual with its disposition: reviewed by a non-author under I6, or unreviewed. FCD's check stage is where that residual is decided; it is inherited unchanged as a dispatch-integrity gate and is not asked to carry content trust.

Who authors the claim. A generator that authors the claim it must satisfy will author the weakest claim the refuter family can check, survive at power 1, and the seal will say 1. Not vacuous in the round-3 sense — refusal stays reachable — but worthless. So the claim schema and the refuter set are pinned by class at Open, by content hash, before any sample exists. The generator may instantiate a claim within the schema for discovery-shaped work; it may not select the schema or the refuters. `rga/core.py` v1 fixes claims at Open outright and treats within-schema instantiation as the documented extension.

What an LLM can do. Propose counterexamples. A checker-verified witness is a sound, replayable kill regardless of who proposed it. A survival under LLM-proposed attack carries power only if the proposer is pinned and its catch rate calibrated on a held-out seeded set — the same rule as any stochastic witness source (Miller–Rabin picks random bases). The LLM is never the refuter. It is a witness source with a calibration record or it is nothing.

Determinism. "Checkable" was over-claimed and was the one place the brief's theorem list had to be restated rather than narrowed. Re-running a refuter is a falsifier: a divergence is a sound refusal; an agreement is a sample. k agreeing re-runs bound the flake rate, never prove determinism. So:
- **A-det**, a physical-boundary assumption of A10's standing: a pinned runtime (toolchain hash, sealed clock, no network, runtime-counted fuel, not wall-clock — a 2M-iteration loop measured 86–91 ms across 25 idle runs, so any wall-clock deadline near the run time is a coin flip) makes a trial a function of (refuter, artifact, fuel).
- **Check 1**, static, is the harness's obligation under that assumption: the kernel never sees the refuter's text and cannot refuse one written outside the deterministic subset. The kernel's own check is the falsifier below.
- **Check 2**, dynamic: every refuter used on a line has at least one trial on that line replayed with an identical outcome; a divergence refuses the refuter, monotonically, for every line.
- **Exhaustion is a third outcome.** Fuel or harness exhaustion is neither kill nor survive. It closes the line with its own fault and never counts as survival. Lineage: A2, the watchdog's over-closing rule. Survival is a positive completed verdict, never the absence of a kill.
- The artifact runs inside the refuter's sandbox under the same denials and fuel; the refuter's parser is a trusted computing base against hostile input.

## 4. Does RGA subsume FCD?

**Verdict: by composition, not replacement. RGA writes no FCD field. I1–I6, I8 and I9 are inherited unchanged by the same no-other-writer inspection; I7, I10, I16 and I17 are restated per sample; A1, A2, A10 and A13 gain per-sample forms, and A11's collision clause is honestly *weakened* here (B7: toward acceptance — and FCD's own I16/I17 proofs use A11 fail-open, filed). The honest verb is *extends*.**

What "run the same bind k times" means on the machine. Not k Admits of one specialist on one stage (A7, I7 forbid it). Not k Observes in one Running stage (last-writer-wins, no artifact on the `call` event). A reviewer built both surviving constructions on the unmodified machine with the suite green:

- *k write stages of one class.* `Required(c) = [(write,s₀), …, (write,s_{k−1}), (check,…)]`. `tried` is per stage, so the same specialist is admitted on each; each stage gets its own Bind, Observe, Pass (I1 per sample), attempt, nonce and receipt (I10, I17 per sample); the item stays open until the check stage; one (P_v,K_v) pin, one policy version, one body hash; the check stage's π_chk excludes the generator automatically, so the residual's reviewer is not the generator (I6). The refuter itself is not an FCD stage; its author is a declared string, and the refuter-is-not-the-author rule is a new guard of I6's shape, only as strong as the author identities are honest (B11, added in round 1).
- *k sibling items* with one body hash. Works, but pins may differ across a promotion (A13) and a losing sibling has no terminal status.

I pre-registered sibling items. The first construction is stronger and is what `rga/core.py` composes over: a **Sample** is a Passed write stage of the line's FCD item whose bind key matches the line's. One item, one pin, one id in both stores.

What RGA reads from FCD, and never writes: `stages[i].pc`, `stages[i].kind`, `stages[i].a`, `stages[i].m_decl`, `item.cls`, `item.body`, `item.policy_version`, membership in S. The Sample guard is FCD's Passed state; the Seal guard is FCD's store membership. That is the literal form of inheriting I1, I3, I5 and I8 as premises.

Where the gate sits. There is no state between the last Pass and Accept on the Python machine (`decide_pass` calls `accept` in the same step). An RGA gate "after Accept" is post-store. A reviewer first argued the seal must therefore replace Accept; the refutation showed the third placement the repo already uses — the server interposes receipt refusal and drift review in state Running ∧ m_exec≠none, before `decide_pass` — and built a side authority with S_R ⊆ S × Power on the unchanged machine. RGA's seal is that refinement: `(id, p) ∈ S_R ⇒ id ∈ S ∧ a surviving trial at power p`. S stays a set of ids; Accept is untouched; every consumer that today reads S as a boolean — the DAG edge at `fcd/core.py:136-139`, Promote through the injected `is_accepted` — must be redirected to S_R with a power floor, or inversion 2 holds at the seal and fails at composition.

What FCD lacks that RGA must add. FCD has no output object. `Item.body` is the input hash; `AdapterReceipt` binds the package the executor *received* and the model that ran; S is a set of ids; the reference server keeps the produced artifact in a plain dict and flips it to accepted after the fact. A refuter that "ran against the accepted artifact" has nothing in FCD to cite. So the kernel content-addresses the candidate at Sample and every Trial carries that hash; the Seal records the hash of the bytes the surviving trials examined; a store that serves anything else is outside the theorem. This reuses A10 rather than widening it: the hash is computed by the authority over bytes it holds, as `compile_package` already is.

Why I1 and I3 are premises — corrected. The brief's reason was "you cannot measure a refuter's power without knowing what ran." For a script refuter, what ran is a content hash and I1 is irrelevant to it. The real reasons: (a) power is P over the bind's output distribution conditioned on a defect, so the number is meaningful only because I1 fixes which generator that is and I3 keeps it inside the calibrated allowed set; (b) concordance is a generator fault only if the k samples are draws from one distribution, which needs I1, I3, I10, I11 and I15 together plus a **bind key** FCD does not expose: `envelope_hash` includes attempt id, nonce, counter and channel, so it differs per attempt by construction. RGA defines the bind key as the envelope projected onto the fields that are not attempt-local, plus the sampling configuration, and guards Sample on equality.

Strengthened assumptions. One new trust assumption: the refuter runtime is honest and hermetic (A-det). The rest are design obligations: the `call` event and receipt need a sample identifier (the same species as `runtime_instance` for F2); k samples share one envelope and hence one pin by the definition of "same bind"; refuter death is no-admission by the watchdog's rule; the determinism check is a falsifier.

One reviewer reproduced a defect in the reference server while doing this: a steer between the write and check stages makes the served-as-accepted bytes differ from the bytes the reviewer's package hashed, with every guard green. And A11's clause "a collision fails toward refusal" is used fail-open by the I16 and I17 proofs. Both are FCD defects, out of RGA's scope, filed separately.

## 5. What the survivors force on the design

Each row is a constraint that was not in the brief and is now in `INVARIANTS.md` — as a guard, a seal field, a kernel query, or an entry under *Not theorems* naming it a deployment obligation. §9 records the round-1 corrections to these rows.

1. Power is a record, never a float: (mode, refuter version, D hash, kills, |D|) or (mode, Q, ε, N). Write-once per (refuter version, D). Kills counted by the kernel from a per-defect ledger.
2. Composite power per claim: union of kill vectors over a shared D, else max, labelled. Never a product.
3. Claim schema and refuter set pinned by class at Open — claims by content hash, refuters by declared (id, version) whose binding to bytes is the pinned-runtime assumption; a trial against an unpinned claim or refuter is refused, not scored.
4. Refuter author ≠ generator; defect-model author ∉ {generator, refuter author}; refuter version registered before the line opens.
5. Generator package excludes refuter source, version and results (I12 in the reverse direction); checked at Sample as a receipt field under A10.
6. Seeded refuters take a seed derived by the kernel from a nonce drawn *after* the artifact hash is recorded; the trial's seed is equality-checked. The envelope nonce predates generation and cannot serve.
7. Trial verdict ∈ {refuted, survived, inconclusive}; only *survived* counts; *inconclusive* and *refuted* close the line, published.
8. Every refuter used on a line has ≥1 trial on that line replayed with identical (verdict, witness); a divergence refuses the refuter for every line, monotonically.
9. Concordance is agreement with the designated sample (stage 0, fixed before any sample exists), not plurality; measured on the trial witness vector per claim; the seal carries (agreeing, k) so k = 1 is visibly trivial. Canonicalisation is conservative: inequality is discord.
10. Sampling configuration is part of the bind key and the seal, so the fault is relative to a declared regime; under deterministic decoding the discord row is dead and the seal says k, σ.
11. The seal carries: artifact hash; per claim (refuter versions, D, kills, |D|, composite power and its label, agreeing/k); min power over claims; the not-attacked residual and its disposition; the FCD identity (class, body, specialist, executed model, policy version).
12. S_R ⊆ S is a theorem. The kernel exposes the power-aware DAG gate (`check_dependencies`, which also refuses tainted seals) and the promotion predicates (`is_sealed`, `admissible`); that a deployment wires them in place of the FCD edge and `is_accepted` is an obligation listed under *Not theorems*, not a theorem. The reference server has since discharged it for promotion and state (`tests/test_server_admissibility.py`).
13. Discordance among surviving samples is a detected miss by every refuter on that claim; it is journaled against those refuters as a rate, not silently absorbed.
14. Retry after a refutation with the refutation trace visible to the generator makes the next sample adaptive. The kernel refuses only the categories `excluded(c)` names (B1); beyond that the flow is unlabelled, and `INVARIANTS.md` §7 and *Not theorems* say so. A retry that changes the claim is a new claim.

## 6. Where the brief over-claimed

1. "An accepted artifact is stamped with the power it survived." It is stamped with the calibrated power of the refuter version whose attested trial it survived, against a named alternative. The number is about the refuter, not the artifact; "negative on a test with sensitivity 0.98" is how a negative result is made informative about one patient, and no more than that.
2. "Determinism of the refuter is checkable." Falsifiable. A refuter that fails is refused; a refuter that passes is not proved deterministic.
3. "Integrity attaches to the test." Integrity attaches to the refutation *record*: that this refuter version, at this calibrated power, ran on these bytes under this fuel, and a third party can re-derive the verdict. It does not attach to the claim's truth, and the title must not be read that way, exactly as round 4 said "no leftover hop" must not be read as a theorem about fallback architectures.
4. "RGA subsumes FCD." Extends. Composes over. Writes no FCD field. Needs FCD underneath as a separate, cited layer.

The two inversions that survive cleanly are the first and third — the third as the zero-entropy special case of semantic entropy, exact agreement with a designated sample, applied as a gate. The second survives with the word *measured* relativised. "Fail-closed under measured doubt" is kept because every word in it is now defined: fail-closed on refutation, inconclusion, discord, nondeterminism and underpower; doubt measured against a declared alternative the seal names.

## 7. What goes under "What is not proved"

Written now, before the proofs, as the brief asked.

- Relevance of D to the generator's actual defects (coupling effect).
- Refuter over-fit to D; Goodhart outside span(D).
- Claim fidelity: a correct artifact for the wrong claim; the intent-to-claim gap per row.
- Harness honesty: a trial verdict is a report (A10 analogue); the ledger was produced by running something.
- Determinism beyond replayed inputs; behaviour under the harness equals behaviour in deployment.
- Halting: the fuel bound is enforced by the harness, not proved by the kernel.
- Sample independence: k draws from a provider that caches whole responses are one draw; receipt-visible as a repeated run id under I17, not proved.
- Refuter independence: combined power beyond a shared D.
- Generator exposure to a public refuter through pretraining (A10-class residue).
- Quality. Survival is not correctness. The brief did not claim it and neither does the paper.
- Body provenance is not closed; it is moved to the calibration record and still rests on I1 holding of the report.

## 8. Decision

The premise survives in the narrowed form above. Build it. The kernel is `rga/core.py`; the theorems are `INVARIANTS.md` R-invariants over the transition table there; the proofs inherit I1, I2, I3, I5 and I8 by citation; the check stage's dual control (I6) is inherited unchanged and no R-proof cites it.

## 9. Round-1 addendum

This file was written before the kernel, as the brief asked. An independent five-lens review of the finished kernel and papers (formal, enforcer, contrarian, attacker, document-versus-code; every finding handed to a skeptic) then broke parts of both, and the corrections are recorded here rather than silently absorbed.

Kernel defects, all reproduced, all repaired with tests: the defect model's author was a free label per record, so a second record on a clean first hash could carry the generator's authorship past both guards; Open accepted a caller-supplied journal position, bypassing the before-generation guard; replay could not rebuild a journal containing a discord or underpower close; a negative sample index slipped the range guard; the rebuilt machine's nonce source was a constant. Two FCD kernel defects surfaced the same way and are repaired in this branch because R7 and R8 lean on them: `no_admit` could write `status=failed` on an accepted item (no `pc` guard), and `open` silently replaced an existing id.

Corrections to this document: mode 2's seal contents are (ε, N), not (Q, ε, N, seed rule) — Q is the refuter's, the seed rule the kernel's; "Check 1, static" is the harness's obligation, not a kernel refusal; row 3's refuters are pinned by declared identity, not content hash; rows 12 and 14 are deployment obligations the kernel exposes as queries, not guards; §4's "A11 strengthened" was backwards — B7 states the collision direction honestly toward acceptance, weaker than A11's clause, which FCD's own I16/I17 proofs use fail-open (filed); "the refuter-is-not-the-author rule is I6 verbatim" over-claimed — it is I6's shape on declared strings (B11). The kernel has two power representations, not three; the exhaustive mode is a ledger over the whole domain. Fault codes were renamed V1–V15 so they never collide with theorem numbers R1–R13. And "measured doubt" required one more honesty note the review forced: with N = 1, a bounded refuter's carried figure equals its declared ε — the seal shows both, which is the whole defence.

## 10. The calibration round

RGA's own "What is not proved" names its successor gap the way FCD's named RGA's: B6 — whether D resembles the generator's real defects — is assumed, and nothing forces a found miss to have any consequence. A proposed escape-ledger layer (C1–C7: verified escapes, charge totality, a coverage ratchet, demotion, impeachment) went through the same premise discipline before any kernel: four adversaries, twenty-eight findings, each to a skeptic. Full record: `eval/reviews/rga-calibration-premise-SYNTHESIS.md`.

What survived changes the design: an escape is a **counterfactual trial of the pinned refuter at a finder-chosen nonce** — kernel-derived seed over the sealed bytes, refuted verdict, identical replay — adding no assumption the seal did not already carry; any other checker acts only through a journaled adjudication. Charges are write-once per wrong-verdict cell. The ratchet moves to Install with a Measure-first precondition, and `install` finally gets a journal event. Count-budget demotion was amputated to a pure query with a declared per-class Seal gate. The loop's ancestor is Bloomfield & Rushby's eliminative argumentation, mechanized. The honest sentence shrank again, as it should: not "the system cannot silently absorb evidence" but **forgetting is loud** — the theorems are about the ledger of found misses, never the distribution of real ones.
