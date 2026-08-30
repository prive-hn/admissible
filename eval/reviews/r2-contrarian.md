# Contrarian review r2

Reviewed head: 3e9d70fe6600348f063250d4f30114011355e916

Verdict: SURVIVES WITH CONDITIONS

Posture: contrarian + adversarial overlay. Read-only. Scope limited to `paper/DRAFT.md`
and `paper/INVARIANTS.md` at the exact head above. The draft is scoped by its own authors
as a *safety-only specification* — no dataset, no rates, no quality theorem, no item
liveness. This review is judged against that modest claim, not against an inflated one.

---

## Steelman

The strongest defensible reading of the draft:

- The paper does not claim a new access-control primitive. It says so four times
  (DRAFT §Abstract, §8; INVARIANTS §5). It claims a *checkable integrity configuration*:
  the smallest transition system whose reachable pass records satisfy class integrity
  (`m_exec ∈ {φ(a) : a ∈ π(c)\δ(c)}`), with the model-down case treated as an **illegal**
  transition (fail-closed) rather than a **low-scoring** one.
- The Clark–Wilson embedding is clean and fair: work item = CDI, bound specialist = TP,
  π/δ = certification relation, review stage = IVP, dual control = SoD, Accept = validated
  write. This is a legitimate, load-bearing analogy, not decoration.
- The invariants I1–I9 are genuinely inductive on the stated machine, and the proofs are
  short because the machine is small. Admit is the sole writer of `a`; Bind the sole writer
  of `m_exec`; Accept the sole store writer. Single-writer discipline makes I1/I2/I4/I8
  near-mechanical. That is a feature: a small verified core.
- The paper is honest about its own limits with rare discipline. It names A1 (enforcer
  totality) and A2 (exit trap) as *assumptions*, states outright that without A1 "bind
  integrity is a slogan," and concedes non-liveness explicitly ("Not live"). It refuses to
  claim quality or empirics. A supporter would recognize all of this as a fair summary.
- The one operational stance with real teeth — *declared binding is not evidence; only the
  observed data-plane identity counts* (A1) — is the correct thing to insist on, and it is
  the thing most orchestration writeups elide.

On these terms the paper is largely defensible. The attack below is therefore aimed at the
two places where the draft reaches *beyond* the modest claim: its novelty framing and its
"objective conflict" separation.

---

## Counter-thesis

**Central counter-thesis:** the paper's two distinguishing moves — (a) the novelty delta
and (b) the objective-conflict separation — are both thinner than the prose implies. Once
A1 is read as an assumed oracle and the separation is read against its own preconditions,
what remains is an honest *specification/framing* contribution wrapped in theorem-grade
language it does not earn. Nothing here is wrong enough to reject; several things are
oversold enough to require revision.

### Assumption ledger (load-bearing only)

| Premise | Type | If false | Confidence |
|---|---|---|---|
| A1 is achievable in a real client (session restore, SDK-internal retries, provider fallback) | forecast / unknown | Every safety theorem describes a machine no implementation instantiates | medium |
| §4's "average-optimizing router with leftover fallback" is the relevant comparison class | inference | Separation is against a configuration choice, not an objective | medium |
| "minimize expected cost" maximizer binds `m` when all allowed are down | claim (false as written) | Cost branch of the separation does not hold | high |
| The novelty delta (φ = observed identity; fallback can't override δ; events as witness) is new rather than applied | inference | Contribution is application of CW + fail-safe defaults + TOCTOU, all cited as old | high |

### C1 — Novelty is application-level, and A1 hides the actual open problem

Strip the framing and the three claimed "added obligations" (DRAFT §Abstract, line 14) each
reduce to something the paper itself labels old:

- *"φ is the identity the inference client actually called."* This is the control-plane vs
  data-plane / TOCTOU concern the paper cites by name (Thomas–Sandhu; TOCTOU). Insisting you
  observe the real call is correct but is a *requirement statement*, not a mechanism.
- *"Leftover fallback cannot override δ."* This is deny-override MAC, which the draft
  concedes is standard (§8).
- *"The event contract is the witness set."* This is IVP + write-ahead logging as an
  auditing convention.

The one place with teeth, A1 (enforcer totality), is an **assumption, not a mechanism**.
INVARIANTS line 25 admits the theorems "do not describe that implementation" if A1 is false,
and §7 of the draft lists "Enforcer that implements A1" as future work with no design. So the
safety content is conditional in a near-vacuous direction: *if you can observe and constrain
every data-plane call, then the calls are constrained.* The genuinely hard part — realizing
A1 across session restore, in-SDK retries, and provider-side fallback that the *caller never
sees* — is assumed away. That is defensible for a spec paper, but it means the contribution
is "a precise statement of what must be witnessed," not any means of witnessing it. The draft
should say this in the abstract rather than let A1 read as settled.

- Disconfirmation: cite or sketch a concrete enforcer that achieves A1 against a client whose
  provider SDK performs opaque internal fallback. The draft does not; it defers to §7.

### C2 — The "objective conflict" collapses into the liveness concession the paper already made

INVARIANTS §4 and DRAFT §4 present the separation from leftover-fallback routers as the
distinguishing result. Its precondition is exactly `u(φ(a))=0` for **every** `a ∈ π(c)\δ(c)`
— i.e., all allowed binds are down. In that same state the machine's own "Not live" clause
(INVARIANTS §3) already says Accept is unreachable and the stage fails closed. So §4 and
"Not live" are two readings of one fact:

- Fail-closed dispatch sacrifices the reply guarantee when all allowed binds are down.
- Anything that *keeps* a reply guarantee in that state must bind something outside the
  allow-image, i.e., hop.

§4 therefore adds no information beyond (liveness concession) + (the transition table). It is a
corollary of a tradeoff the paper already booked, re-dressed as a "separation." Note also the
precondition is a boundary state: in every state where at least one allowed bind is up, an
optimizer whose fallback respects δ-except-when-all-down is behaviorally identical on I3. So
the "conflict" fires only on the degenerate all-down trace and says nothing about frequency or
harm — which the paper concedes it cannot (no rates).

- Disconfirmation: exhibit a router trace that violates I3 in a state where some allowed bind
  is **up**. §4 cannot, because its precondition is all-allowed-down. Finding stands unless the
  precondition is relaxed.

### C3 — The cost-minimization branch of the separation is false as written

INVARIANTS §4 (line 95) offers a disjunction: the selector "maximizes `P(published reply)` **or
minimizes expected cost**." The cost branch does not yield the claimed maximizer. Failing
closed spends nothing; binding `m ∈ F` spends tokens. A pure expected-cost minimizer therefore
*prefers fail-closed* and never binds `m`. The "unique maximizer binds `m`" claim holds only
under an unstated "must produce an acceptable reply" constraint (the FrugalGPT reading). Once
that constraint is made explicit, the conflict is precisely "must always reply" vs "may fail
closed" — which is again the safety/liveness tradeoff of C2, not an independent result. As
printed, the cost branch is either wrong or silently smuggles the very constraint that makes
the separation collapse.

- Disconfirmation: add an explicit reply/quality constraint to the cost objective. Then the
  branch is correct — but it also visibly reduces to the liveness tradeoff. Either way the
  current one-line disjunction is under-specified.

### C4 — "Router violates I3" is a category slip

I3 is an inductive invariant of *this* machine's runs. A foreign router does not execute this
machine, so "the router violates I3" (INVARIANTS §4 line 99) is only meaningful after embedding
the router's trace into this state space — at which point the honest statement is "different
transition relations reach different states." True and unremarkable. The phrasing borrows
theorem-weight from I3 to describe what is a definitional difference. Minor, but it is part of
how §4 reads heavier than it is.

### C5 — The §1 universal is a strawman of configurable routers

DRAFT §1 asserts "None of them forbid a hop to an unbound model." A router configured with an
empty leftover set, or with fallback ⊆ `{φ(a) : a ∈ π(c)\δ(c)}`, does not hop and is a direct
counterexample to the universal. The paper's fair rebuttal — such a router has *reimplemented*
π\δ and is therefore an instance of class dispatch — is actually the stronger argument and
should replace the universal claim. As written, the separation is against routers *configured
to be unsafe*, which is closer to a configuration conflict than an "objective conflict."

---

## Does the objective-conflict count as a theorem

Short answer: it is a **valid but trivial proposition — a corollary, not a theorem** — and one
branch of it is incorrect as printed.

- **Validity.** Given the precondition (all allowed binds down, some `m ∈ F` up) and an
  objective that strictly rewards a published reply, the maximizer is the hop transition, which
  is absent from the table. The reasoning is sound.
- **Triviality.** The proof (INVARIANTS §4) is one line and amounts to: "the hop is not in our
  table; the optimizer's maximizer is that hop; QED." It proves that two systems, one *built to
  lack* the hop and one *built to have* it, differ on exactly the transition where they were
  defined to differ. That is definitional. Combined with C2, it carries no information beyond
  the already-stated liveness concession.
- **Defects to fix before it can be called even a clean lemma.** (i) Delete or constrain the
  cost-minimization branch (C3). (ii) Quantify the router class precisely — "average-optimizing
  router *carrying a leftover set F ⊄ allow-image*," not "any average-optimizing router" (C5).
  (iii) Make the reply/quality constraint explicit, at which point label the result honestly as
  a corollary of "Not live." (iv) Restate "violates I3" as "reaches a state outside this
  machine's reachable set under embedding" (C4).

The paper's own hedges ("not an impossibility carnival," "not a new algebra") show the authors
sense this. The recommendation is to *match the language to the content*: demote "separation"
to "corollary of the liveness/optimality tradeoff," and keep it. It is honest and small; the
only fault is that the section's rhetoric outruns its logical weight. I1–I9 remain the real
theorems and are unaffected by this demotion.

---

## Related-work remaining holes

The related-work section (DRAFT §8) covers routing/MoE/MoA and Clark–Wilson/Saltzer–Schroeder/
TBAC well, but leaves these load-bearing neighbors uncited:

1. **Fail-closed as an operational pattern.** The core stance — "do not hop when the bound
   provider is down" — is the circuit-breaker / bulkhead / fail-stop literature. Saltzer–
   Schroeder is cited for the *principle*; the operational realization (which is what §7 wants
   to build) is uncited.
2. **Software-supply-chain provenance/attestation.** F1 ("declared ≠ executed") and A1 are a
   provenance problem: *this artifact was produced by the declared procedure.* Frameworks that
   formalize exactly this (build provenance, attestation/in-toto-style predicates, SLSA-style
   levels) are the closest formal analog to the witness-set claim and are absent.
3. **Trust boundary of the observation channel.** A1 assumes the enforcer observes `m_exec`
   *truthfully*. The adversarial case — a client or provider that misreports the executed model
   — is out of scope but should be named. Verifiable/attested computation and confidential-
   computing attestation are the relevant boundary; none are cited even to disclaim.
4. **LLM-as-judge self-preference.** F7 leans entirely on the self-preference phenomenon, yet
   no LLM-as-judge / self-preference evaluation work is cited. The claim is empirical and
   currently unsupported by reference.
5. **Separation-of-duty formalization.** I6/dual control cites TBAC only; the SoD and
   constraint-satisfaction literature (RBAC SoD, static/dynamic SoD formalizations) is the
   direct formal home for I6.
6. **Survival/reliability statistics.** §6's right-censored time-to-stage is standard survival
   analysis presented without citation, which weakens the measurement section's authority.
7. **Constrained decoding / guardrails distinction.** Worth one sentence distinguishing "which
   *model* may run" (this paper) from "which *content* may be emitted" (guardrails), since
   readers will conflate them.

None of these is fatal; each is a citation the draft should carry so that A1, F1, and F7 stop
resting on assertion.

---

## Recommendation

SURVIVES WITH CONDITIONS. The safety core (I1–I9 under A0–A7) is sound on its stated terms and
honestly scoped. Required conditions before the distinguishing claims can stand:

1. Fix or delete the cost-minimization branch of §4 (C3).
2. Demote the "objective conflict / separation" to a corollary of the liveness concession, with
   a precisely quantified router class (C2, C5), and correct the "violates I3" phrasing (C4).
3. Foreground A1 as an assumed oracle whose realization is the actual open problem, and move the
   universal "none of them forbid a hop" to the stronger "any router that avoids the hop has
   reimplemented π\δ" (C1, C5).
4. Add the missing related-work anchors, especially provenance/attestation (for F1/A1) and an
   LLM-as-judge self-preference citation (for F7).

Novelty is not rejected: read as a specification and framing contribution — "treat model-absent
as illegal, not low-scoring, and witness the data-plane identity" — it is defensible. It is
oversold wherever the prose reaches for theorem or separation weight it has not earned.
