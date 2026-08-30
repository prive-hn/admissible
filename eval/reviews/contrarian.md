# Contrarian review

Verdict: REVISE

Posture: contrarian + devil's-advocate novelty review. Read-only against `paper/DRAFT.md`
(working draft, 19 Aug 2026). Load-bearing question: *what is the non-trivial claim, and does
it survive the charge that this is RBAC + fail-closed retry + dual control renamed?*

Bottom line up front: the goal — making "we run a specialized fleet" a falsifiable sentence —
is sound and worth publishing. But the **novelty as stated does not survive**. Stripped of
vocabulary, the mechanism is deny-override access control + fail-secure bounded retry +
separation-of-duties, applied to model binding. There is a thin, genuinely non-trivial residue
(the declared-vs-executed *data-plane identity* problem and the metric-completeness claim), but
the draft neither isolates it, cites its nearest prior art, nor proves anything about it. Fixable,
hence REVISE rather than REJECT.

## Steelman

The strongest defensible reading: the contribution is not any single mechanism but a **checkable
specification for one invariant** — *a classed work item is still itself after each stage* — in a
setting where the field's existing names (routing, MoE, MoA, cascades, orchestration) all optimize
a *different* objective (average quality or spend) and therefore have no vocabulary for identity
preservation. Three moves carry real weight:

1. **φ is defined as the data-plane identity**, "the one the inference API accepts, not a display
   string" (§2, F1, F5). This targets a failure the routing literature structurally ignores:
   the model you *named* is empirically not the model that *ran*, after session restore, fallback
   lists, and display aliasing. That control-plane/data-plane divergence is the sharpest idea here.
2. **The deny set δ(c) is first-class and non-overridable by a leftover fallback list** (F3, F6,
   §6.3). "A model that refuses a class is not a weak assignee. It is forbidden." Deny is treated
   as a wall, not a low score — the opposite of a score-maximizing gate.
3. **Metrics are tied to assignment/reply events, not call logs** (§5). The observation that
   bleed, silent-fail, and time-to-stage are *unrecoverable* from call logs — and that the
   silent-fail denominator must be assignments, not calls — is a real measurement insight, not
   decoration.

A fair supporter would say: this is an operational standard (objects + fault taxonomy F1–F10 +
four metrics) that converts a marketing claim into an auditable contract. That is a legitimate
systems contribution even with zero theorems and "measurements defined and empty."

## Counter-thesis

Delete the coined terms and the primitive dissolves into three textbook parts:

- **Allow set π(c), deny set δ(c), disjointness π∩δ=∅, deny-is-a-wall.** This is mandatory access
  control with **deny-override** evaluation. NIST RBAC, Bell–LaPadula, and every ACL engine
  already give you allow lists, explicit deny, and precedence of deny over allow. "Deny set is
  first-class" is the deny-override rule with a new adjective.
- **Fail closed + retry only inside π(c).** This is Saltzer & Schroeder's **fail-safe defaults**
  (1975, design principle #2) composed with a bounded, set-constrained retry policy. "Exhaustion
  is fail-closed. Retry only inside π(c)" is a fail-secure error path — decades old.
- **"Author of a layer is outside π for the check on that layer" (§3, F7).** This is
  **separation of duties / dual control**, which the draft itself admits is "old in access
  control" (§7). Naming it "a stage, not a prompt" does not make the principle new.

The fault taxonomy, examined coldly, is mostly a **configuration-drift / TOCTOU checklist**, not a
theory. F1 (label lie), F2 (shared runtime collapsing bindings), F5 (interface alias) are all one
bug: *the running identity differs from the configured identity* — classic time-of-check/
time-of-use and control-vs-data-plane divergence. F8 (prose assignment) and F9 (unstored accept)
are workflow-plumbing hygiene, not properties of dispatch. F10 (retry-as-reincarnation) is a state-
machine/idempotency defect. So the charge lands: at the **mechanism** level this is RBAC
(deny-override) + fail-secure retry + SoD, with a good ops checklist bolted on. The claim that
"admit by class, bind one model, fail closed" is a *new primitive* distinct from routing is
overstated — it is a **policy configuration** layered on existing orchestration topology (which §7
concedes: "topology is not the process," but the process is still parameterized over that topology).

Disconfirmation of this counter-thesis: it would fail if the draft exhibited (a) a safety property
provably guaranteed by fail-closed class dispatch that no access-control + retry composition can
express, or (b) a separation result showing an average-optimizing router *cannot* preserve the
identity invariant. Neither is present.

## What is actually new vs restated

Restated (no novelty credit):
- Allow/deny sets + disjointness + deny precedence → RBAC / MAC deny-override.
- Fail-closed on exhaustion (401/403/404/429) → fail-safe defaults.
- Retry within the permitted set → constrained retry policy.
- Self-review prohibition (F7), "dual control is a stage" (§3) → separation of duties / Clark–Wilson.
- F1/F2/F5 → TOCTOU / control-plane vs data-plane divergence.
- F10 → idempotent state-machine / saga hygiene.

Plausibly new, but under-isolated and under-defended:
- **φ as the data-plane (inference-accepted) identity, with declared==executed as an explicit
  equivalence obligation** (§3 "Two planes must agree"). Applying an observational-equivalence
  requirement to *LLM model binding across session restore and fallback* is a fresh framing; the
  underlying idea (verify runtime == config) is not.
- **Metric completeness / denominator argument** (§5): that assignment+reply events are *necessary*
  witnesses for bleed and silent-fail and that call logs are provably insufficient. This is the
  most defensible original claim and is currently asserted, not proven.
- **The identity invariant itself** — "is a classed item still itself after each stage" — as the
  optimization target that routing/MoE/MoA lack. Novel as *framing*; not novel as *mechanism*, and
  never formalized.

Net: the non-trivial claim is not the primitive. It is the pairing of (i) a data-plane-identity
equivalence obligation with (ii) an event contract claimed to be a complete witness set for a fault
taxonomy. That is a narrower and more honest thesis than the abstract advertises.

## Related-work holes

The draft cites the routing/mixture literature it is *not* closest to, and omits the access-control
and systems literature it *is* closest to. Serious gaps:

- **Clark–Wilson integrity model (1987) — the nearest prior art, uncited.** It already formalizes
  exactly this shape: constrained data items (= work item / frozen body), transformation procedures
  (= specialist+bound model), a certification relation binding which TPs may act on which CDIs
  (= class policy π/δ), integrity verification procedures (= review stages), and *mandatory
  separation of duty*. "Accepted artifact only enters the store" is Clark–Wilson's validated-CDI
  transition. Not citing this is the single biggest novelty hole; a reviewer will read the paper
  as Clark–Wilson re-derived for LLM fleets.
- **Saltzer & Schroeder (1975), fail-safe defaults** — the origin of "fail closed." Uncited.
- **NIST RBAC / Bell–LaPadula / deny-override ACL semantics** — the origin of allow/deny/disjoint.
  Uncited.
- **Task-Based / Workflow authorization (Thomas & Sandhu; workflow SoD)** — authorization bound to
  a task instance and its state, which is precisely "dual control is a stage, not a prompt."
  Uncited.
- **TOCTOU and control-plane/data-plane divergence** (systems-security staple) — the actual name
  for F1/F2/F5. Uncited.
- **LLM-as-judge / self-preference bias** — the empirical justification for F7 (a model, or a
  fallback sharing its weights, checking its own output). Uncited; would strengthen, not weaken.
- **Idempotency / saga / exactly-once workflow literature** — the frame for F10. Uncited.

The related-work section (§7) engages MoMA, orchestrator-worker, and a one-line nod to
"separation of duties is old." That is the wrong comparison class. The paper must differentiate
against **integrity and access-control models**, because that is where a skeptic will say it already
lives.

## What a theorem would have to say to survive

Today the paper is a definitional + taxonomic artifact with "measurements defined and empty." To
defeat the restatement charge it needs at least one of the following, formally:

1. **Soundness / class-integrity theorem.** Define the invariant precisely — e.g. *no accepted
   artifact exists whose producing stage had executed-model ∉ π(class), or executed ≠ φ(a), or
   a ∈ δ(class)* — and prove the enforcer guarantees it under stated assumptions (published
   fail-closed on exhaustion; deny non-overridable; φ read at the data plane). This turns F1–F10
   from a checklist into "the ten violations of one named safety property," which is a real result.

2. **Separation / impossibility result (the decisive one).** Formalize "still itself after each
   stage" as an invariant and prove that **any average-optimizing router** (a gate selecting the
   argmax over a quality/cost score with a non-empty fallback set) *cannot* preserve it — i.e.
   exhibit a policy π/δ and a fault state where every score-maximizing selector admits a
   δ-forbidden or unbound model while fail-closed dispatch refuses. Without this, the claim that the
   primitive is categorically different from routing is rhetorical, not proven.

3. **Metric-completeness theorem.** Prove the four events (assignment, reply, executed-binding,
   fault) are a *complete and minimal witness set*: every fault F1–F10 is detectable from them, and
   at least one (bleed / silent-fail / time-to-stage) is provably *not* recoverable from call logs
   alone. This is the paper's most original claim (§5) and is currently only asserted.

Minimum bar to flip the verdict to SURVIVES WITH CONDITIONS: (a) reposition related work against
Clark–Wilson, fail-safe defaults, RBAC deny-override, and TBAC, explicitly stating the delta; and
(b) state and at least argue theorem (1), ideally (2). Bar to SURVIVES: prove (2) — a genuine
separation from average-optimizing routing — which is the only result that makes the primitive
non-reducible to "existing access control with new words."

### Disconfirmation of this review
This verdict downgrades if either is shown: (i) the draft already contains, or can add without new
machinery, a separation result of type (2) — in which case the primitive is novel and I am wrong to
call it restatement; or (ii) the intended contribution is explicitly *an operational standard, not a
new primitive*, in which case "novelty" is the wrong axis and the correct verdict is SURVIVES-as-a-
taxonomy, conditioned only on fixing the related-work omissions. The abstract's "This is not
mixture-of-experts… not mixture-of-agents… The primitive here is different" (§1) commits it to the
primitive-novelty claim, so I hold the review to that standard.
