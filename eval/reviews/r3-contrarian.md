# Contrarian review r3

Reviewed head: 6b450a508fab00227ccc7da9028a314a955dc12e
Lens: contrarian (steelman-first; attack novelty and the leftover-hop corollary)
Scope: `paper/DRAFT.md`, `paper/INVARIANTS.md`. Read-only. No product or stack names.

Verdict: **SURVIVES WITH CONDITIONS**

The formal safety content survives its strongest reasonable challenge: I1–I6, I8, I9 are correct on the stated machine and are stated with unusual restraint (no liveness, no quality theorem, no rates). What does **not** survive unconditioned is (a) the framing of the leftover-hop remark as a *corollary*, and (b) the abstract's opening checkability claim, which is load-bearing on assumptions A1/A2 that the paper cannot discharge and against prior art it does not situate. The paper pre-concedes most of the narrowness a contrarian would raise, which is a real defense and the reason the verdict is not "REJECT novelty" — you cannot reject a novelty claim the authors explicitly decline to make ("not a new access-control primitive," "not a new algebra"). But the conditions below are not cosmetic; two of them touch claims in the abstract and Section 9.

---

## Steelman

The strongest defensible version of this paper:

The sentence "we run specialists" is, in practice, unfalsifiable. A control plane can name one model identity while the data plane, after session restore or a provider-side fallback, executes a different one; a refusal (401/403/404/429/exhausted/not_found) can be indistinguishable from work-in-progress; and the entity that reviews a work item can be the entity that authored it. The paper's move is disciplined and correct in kind: model dispatch as the *smallest* transition system whose guards make each of those pathologies a forbidden transition rather than a low score. A work item is a constrained data item with a frozen body; a bound specialist is a transformation procedure; π/δ is a certification relation; check stages are integrity-verification procedures with mandatory separation of duty; Accept is the only validated write into the store. The genuinely articulated delta over the classical integrity model is narrow and honestly bounded: **φ is the *data-plane* identity the inference client actually called** (not the declared one), the closed-world reading of π means a **leftover fallback cannot override δ**, and the **event contract is claimed as the witness set** for that identity. The invariants are proved on the abstract machine; the two hard properties (that the executed call is *seen*, A1; that death is *seen*, A2) are cleanly separated out as *observation obligations on the enforcer*, and the paper repeatedly refuses to let those axioms smuggle in the equality they must not assert (A1 does not assert `m_exec = φ(a)`; that equality is I1, checked, and its failure is F1, not hidden). It declines to claim liveness, quality, or empirics, and it labels the leftover-hop remark as a corollary, not a theorem. A reasonable reader recognizes this as an integrity *configuration* stated with more restraint than the routing/cascade literature it critiques.

That steelman is fair, and a supporter would accept it. The contrarian case below does not deny it — it attacks where the paper reaches past it.

---

## Counter-thesis

**The paper's checkable-claim promise is downstream of exactly the assumption it cannot verify, and its safety theorems are true by construction of their own guards — so the load-bearing novelty is an *unattested* observation obligation, not a proved property.**

1. **The theorems are tautological relative to the guards; the risk lives entirely in A1/A2.** I1 ("Passed ⇒ norm(m_exec)=norm(φ(a))") holds because Pass is *enabled only* under that guard and PassRefuse fires otherwise. That is proof that the machine does what its transition table says — it is not evidence about any real system. Every non-trivial safety property the paper wants ("class integrity is checkable," abstract line 10; "a specialist fleet is a checkable claim only if…") reduces to whether `m_exec` is *faithfully observed*. That is A1. The paper itself concedes (INVARIANTS line 27) that if A1/A2 fail, "I1 and F4 become estimates on a partial log." So the abstract's strong opener is true only on the machine, and on the machine A1 is an axiom, not a result. The interesting, hard, real-world content is precisely the part assumed.

2. **Who watches the witness?** The "event contract is the witness set" is the claimed novelty, but the events are emitted by the same component that could misbind. There is no trusted path, no attestation, no independent mediator between the data-plane call and the log. A component that silently substitutes a model can also silently emit a conforming `call` event. Nothing in the machine detects a *coordinated* lie; A1 simply assumes it away ("every data-plane call while Running is recorded as a `call` event with `m_exec`"). This is a complete-mediation / trusted-path requirement dressed as an axiom. Until a mechanism binds `m_exec` to the real execution independently of the emitter, "checkable claim" is aspirational.
   - *Failure sequence:* provider-side or restore-path model substitution → emitter records the declared identity as `m_exec` (or omits the extra call) → guard sees norm-equality → Pass → F1 never fires, misbind rate reads zero. Detectability: silent. This is the paper's own "estimates biased clean" (DRAFT line 93) — but it is the *central* case, not an edge.

3. **The empirical checkability the title implies is conditional on instrumentation the paper does not specify or verify.** Zeros on misbind/bleed/silent-fail are proofs "only if `stage` is write-ahead and `call`/`decide` are total" (line 93); the misbind metric is admitted "gameable by abort" (INVARIANTS 118). These are honest, but they mean the paper's reason for existing — turning an unfalsifiable slogan into a checkable claim — is delivered only under write-ahead totality that is asserted, never demonstrated. The claim in the abstract is stronger than the results licence.

4. **The actual load-bearing novelty is an unstated closed-world assumption on π.** The Admit guard requires `a ∈ π*(c) \ δ(c) \ tried`. A model neither in π nor in δ is *unadmittable* — not because δ denies it, but because the world is closed. "No leftover hop" is therefore the enforcement of a closed-world π, which trades liveness for the guarantee. This is the real, interesting choice, and it is never named as such; it is smuggled in through the transition table and then defended by the leftover-hop remark (next section).

Disconfirmation of this counter-thesis: exhibit a mechanism in the artifact (attestation, dual-emitter reconciliation, provider-signed execution receipts) that makes `m_exec` observable *independently of the component that could lie*, and show write-ahead totality is enforced rather than assumed. If that exists, points 1–3 downgrade from "central hole" to "documented deployment obligation."

---

## Is the leftover-hop remark a theorem, a corollary, or rhetoric

**It is a definitional contrast, closest to rhetoric, and it should not carry the word "corollary."** The paper hedges it correctly as "not a safety theorem" (DRAFT 63, 113; INVARIANTS §4) — but "corollary" still overstates it. Three reasons:

1. **It is not entailed by the theorems; it is entailed by a definition, and it lives outside the machine.** A corollary follows from I1–I9 by a short derivation. This remark does not. INVARIANTS line 100 states the hop "is outside the transition table," and line 104 states "It is not extra information about safety." So it is not a corollary *of this system*; it is a statement about a *different, unmodeled* selector. It follows trivially from the *definition* of a reply-maximizer ("maximize P(published reply)"): give a selector that objective and a leftover bind with u=1 while all allowed binds have u=0, and by definition it takes the bind. A statement true by definition and admittedly carrying no safety information is rhetoric performing a framing function — it makes fail-closed look principled by contrast — not a derived result.

2. **The contrast is against a strawman selector.** The remark bites only a "reply-maximizer" whose fallback set F is defined disjoint from {φ(a) | a ∈ π\δ} (INVARIANTS 98). By construction that selector hops outside policy. A steelmanned competitor whose fallback set *equals* π(c)\δ(c) also fail-closes — and the paper concedes the pure cost minimizer fail-closes too (INVARIANTS 102). So the only selector that "hops" is one configured to hop outside its own allow set, i.e., a misconfiguration. The paper elsewhere is careful to call analogous things "extra config, not in I6" (weight-sharing, DRAFT 82). By its own standard, the leftover hop is a property of a badly-configured selector, not an inherent liveness/integrity tension — and "we forbid a misconfiguration" is not a process contribution.

3. **The liveness reframing is a values assertion, not a result.** "The hop happens in the same state where this process is already not live" neutralizes the obvious objection — that a routing system stays up while this one dies when the bound provider is down — by asserting the competitor's uptime is *illegitimate*. But whether the hop is a "violation" depends on whether the leftover model is in δ (explicit deny) or merely absent from π (policy incompleteness). If it is only absent from π, the hop violates nothing in the safety model; it violates only the closed-world reading of π. The remark thus hides the real trade (closed-world π sacrifices liveness) behind "the maximizer was non-live anyway."

*Required action:* demote the remark from "corollary" to an explicitly labelled *illustrative contrast under a named selector definition*, and state that its force is a function of the closed-world-π choice, not of I1–I9. This touches Section 4, Section 9, and INVARIANTS §4. Disconfirmation: show a derivation of the hop claim from I1–I9 that does not route through the definition of the reply-maximizer, or a real (non-strawman) selector class whose in-policy fallback still hops.

---

## Related-work remaining holes

The citation set (Clark–Wilson; Saltzer–Schroeder; Thomas–Sandhu TBAC; routing/cascade/MoE/MoA lit; one orchestration topology report) covers the integrity lineage and the objective-mismatch argument well. The holes are all on the side of the paper's *actual* novelty — data-plane identity, mediation, and the witness set — and each would sharpen or pressure a claim:

- **Reference monitor / complete mediation is the missing principle.** Saltzer–Schroeder is cited only for fail-safe defaults; the more load-bearing principle here is *complete mediation* — and A1 ("every data-plane call is recorded") is exactly a complete-mediation obligation. Naming it would expose that the paper's checkability rests on an unverified mediation assumption. Anderson's reference-monitor concept (tamperproof, always-invoked, verifiable) is the natural frame for "who watches the witness" and is absent.
- **Confused deputy is the classical name for F1/F2/F5.** The control-plane-names-one, data-plane-calls-another pathology is the confused-deputy / capability-confusion problem. The paper reaches for TOCTOU (correct but narrower); the confused-deputy framing is closer and uncited, and would strengthen the F-table's grounding.
- **Trusted path / attestation is the unaddressed core.** The claim "φ is the identity actually called" is an *attestation* claim, and "event contract is the witness set" is a *provenance* claim. The modern literature on binding a claimed artifact to its real producer (supply-chain provenance / attestation frameworks; remote attestation; signed execution receipts) is the direct prior art for the paper's one genuine delta — and it is entirely absent. This is the single most consequential hole: it is where a reviewer would ask "why is your unsigned log a witness rather than a claim?"
- **Admission-control prior art is the closest operational analogue and is unsituated.** Policy-driven admission controllers that fail-closed on an allow/deny set, evaluate policy *as-of* a version, and emit audit events are operationally near-identical to fail-closed dispatch. The paper never distinguishes itself from generic policy-as-admission-control. The delta ("the guarded identity is a data-plane model identity, not a control-plane label") is real but small; not naming this class lets the reader over-read the novelty.
- **LLM-as-judge self-preference is asserted without a source.** F7 is tied to "LLM-as-judge self-preference" (DRAFT 107) with no citation; the self-preference / judge-bias literature exists and should anchor the dual-control motivation.
- **Separation-of-duty predates TBAC.** Minor: transaction-control-expression / workflow-authorization work predating task-based authorization would round out the SoD lineage behind I6.

None of these are fatal individually. Collectively they show the paper cites heavily where it is *conservative* (integrity model, routing critique) and sparsely where it is *novel* (mediation, attestation, admission control) — the inverse of what a novelty defense needs.

---

## Conditions for the verdict to hold

1. **Reframe the abstract's checkability claim** (line 10 / opening) as conditional on A1/A2 and name the mechanism that discharges them, or downgrade "checkable claim" to "checkable *given complete, write-ahead, independently-attested observation*." As written it over-reaches the machine results.
2. **Demote the leftover-hop remark** from "corollary" to an explicitly labelled illustrative contrast, and state that its force derives from the closed-world-π choice, not from I1–I9 (Section 4, Section 9, INVARIANTS §4).
3. **Situate against reference-monitor/complete-mediation, attestation/provenance, and policy admission-control prior art**, since those bound the paper's only genuine delta; add the missing self-preference citation for F7.
4. **State the closed-world assumption on π explicitly** as the mechanism that trades liveness for integrity, rather than leaving it implicit in the Admit guard.

These are revisions to framing and related work, not to the proofs. The proofs survive.

---

## Assumption ledger (load-bearing only)

| Assumption | Type | If false | Confidence |
|---|---|---|---|
| A1 observation totality holds in a real stack (data-plane call faithfully recorded) | obligation asserted, not shown | I1/misbind become "estimates biased clean"; central novelty collapses to a claim | low |
| A2 death observability holds | obligation asserted, not shown | F4/silent-fail undercounted | low |
| Event emitter is not itself the misbinding component (implicit trusted path) | unstated | coordinated silent substitution defeats the witness set | low |
| π is intentionally closed-world (absence = unadmittable) | implicit in Admit guard | leftover-hop remark loses its force | medium |
| Novelty = application of an integrity model, not a new primitive | stated by authors | — (this is why "REJECT novelty" is not the verdict) | high |
