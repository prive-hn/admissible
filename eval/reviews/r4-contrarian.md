# Contrarian review r4

Reviewed head: a8c7195b60f438f3f168d41e442d8d4d1bec3c64

Verdict: SURVIVES WITH CONDITIONS

Posture: contrarian + adversarial, read-only. Sources bound to this exact head:
`paper/DRAFT.md`, `paper/PROOFS.md`, and — as companions the two files reference —
`paper/INVARIANTS.md`, `enforcer/machine.py`, `tests/test_invariants.py`. No other
`eval/reviews/*` file was opened, per instruction. All 11 unittest checks in
`tests/test_invariants.py` were executed at this head and pass.

---

## Steelman

The strongest defensible reading: the draft turns an otherwise unfalsifiable slogan
("we run specialists") into a checkable safety property and delivers exactly that,
no more. A work item has a class `c` and a frozen body; a Passed stage is provably
constrained to a specialist `a ∈ π*(c)\δ(c)` whose executed model matches the bound
identity `φ(a)`. The load-bearing move is the Bind/Observe split: Bind writes only
`m_decl`, Observe writes `m_exec` from the provider report, and Pass is disabled
unless `norm(m_exec)=norm(m_decl)`. This is what makes I1 non-vacuous — a prior
round where Bind wrote `m_exec ← φ(a)` would have made the Pass guard tautological,
and the draft states this explicitly (PROOFS I1 Remark; INVARIANTS §0 preamble).
I3 ("no unbound hop") then follows honestly as I1 ∘ I2, not as an axiom.

The scope discipline is unusually good for a claim in this area. The draft refuses
the claims it cannot support and says so in four places: no quality theorem, no item
liveness, F2 unprovable without a runtime-instance field, and provider fidelity
(API-reported model vs. physics) explicitly out of scope. It correctly grounds
itself in prior art (Clark–Wilson CDI/TP/validated-write; Saltzer–Schroeder
fail-safe defaults; Thomas–Sandhu task-instance binding) rather than claiming a new
access-control algebra. The executable machine mirrors the transition table
row-for-row, the store is writable only through Accept (`store_put` raises), and the
tests exercise the non-vacuity path (`test_i1_pass_requires_observe_match` forces a
foreign `m_exec` and asserts F1 + no store write). A supporter would recognize this
summary as fair: the paper claims a small, checkable integrity property and proves
precisely that on the abstract machine under stated enforcer obligations.

---

## Counter-thesis

I could not break the safety claims within their stated obligations, so the honest
counter-thesis is about **adversary model** and **what the falsifiability reduces
to**, not about a proof error.

**C1 — The property closed is accidental/architectural hop, not adversarial
masquerade.** In `machine.py`, `observe(item_id, m_exec)` accepts `m_exec` as a
caller-supplied string; the enforcer trusts the witness. I1/I3 therefore hold "of
the report, not of physics" (PROOFS, Provider fidelity). Against a misconfigured
fallback selector, a cost minimizer that wanders, or a stale allow list, the machine
genuinely fail-closes. Against a worker that binds one model and *reports* the bound
name to Observe, Pass succeeds on a forged witness and F1 never fires. The word
"fail-closed" carries a security connotation (defends against an adversary); the
proofs deliver integrity against non-adversarial drift **plus a faithful witness
channel**. Condition → mechanism → consequence: worker forges `m_exec=φ(a)` →
Observe records the forgery → Pass and Accept succeed on a foreign runtime. This is
disclosed (A1 "does not assert equality with φ(a)"; Provider-fidelity limit), but it
is under-emphasized relative to the framing. Disconfirmation: an out-of-band
attestation of the executed model (independent of the worker) would upgrade the
claim from "integrity of a truthful report" to "integrity against a lying worker."

**C2 — The whole falsifiability claim reduces to event-contract faithfulness.** The
draft concedes this cleanly (DRAFT §6: zeros on misbind/bleed/silent-fail are a
proof only if `stage` is write-ahead and `call`/`decide` are total; otherwise
estimates "biased clean"). The contrarian point is that this is the *actual*
load-bearing assumption, larger than any single invariant: I1–I9 are safety on the
instrumented machine, and the machine's authority over a real host is exactly the
authority of A1/A2 and write-ahead logging. This is stated, not hidden — hence a
condition, not a defect.

**C3 — Motivation leans on the very picture the proofs disown.** §1 and the title
sell "the leftover hop to an unbound model when the provider is down" as the villain,
while INVARIANTS §4 and DRAFT §4/§9 insist hop-as-safety is *not* a theorem. The
paper wants the hop to be load-bearing for motivation and non-load-bearing for the
proofs. That is defensible and honestly flagged, but it is the one place a skimming
reader is invited to over-read (see next section).

None of C1–C3 is a proof error. Each is either explicitly disclosed or a
framing/emphasis issue. That is why the verdict is SURVIVES **WITH CONDITIONS**, not
REVISE: the safety claims hold exactly within the obligations the authors state; the
conditions are (i) scope the claims to a faithful Observe channel and a non-forging
worker, and (ii) keep the headline from being read as a general safety theorem about
fallback architectures.

---

## Hop remark: illustration or overclaim

**Finding: it is genuinely an illustration, not a smuggled corollary — with one
title-level blemish.**

There are two distinct "hop" objects, and the draft keeps them separate correctly:

- **I3 "No unbound hop"** is a real theorem, but tightly scoped: no Passed state has
  `norm(m_exec) ∉ {norm(φ(x)) | x ∈ π*(c)\δ(c)}`, derived from I1 (bind integrity)
  and I2 (Admit-time class membership). It is a statement about *this machine's
  Passed states*, verified by `test_i3_no_pass_on_foreign_model`. It does **not**
  claim that fallback-routing architectures in general are safe or unsafe.

- **The "leftover-hop picture"** — a selector reaching an unbound model when every
  allowed bind is down — is demoted to illustration in four independent places:
  DRAFT line 61 ("an illustration, not a corollary"), DRAFT line 109 ("The hop
  remark is an illustration"), INVARIANTS §3 ("Not theorems: … hop-as-safety"), and
  INVARIANTS §4, which is explicit: "This table has no such edge. A selector confined
  to π\δ also fail-closes. A cost minimizer fail-closes. Do not cite this as a safety
  theorem."

The §4 argument is the correct one and is the reason the illustration does not
over-reach: the machine's safety is **structural** (the transition table simply has
no edge that admits a model outside `π*\δ`), not **earned** by proving something
about the behaviour of leftover selectors. A confined selector and a cost minimizer
reach fail-closed by the same table; the leftover selector is merely one narrative
that motivates why the table is drawn this way. So the illustration explains *why*
leftover fallback is dangerous without the proofs having to quantify over selectors.
That is exactly the right relationship, and it is verified: the machine has no
"fallback-search" transition (Retry only re-enters Admit on `π*\δ\tried`; NoAdmit /
BindFail publish fail-closed).

**The blemish (actionable, cosmetic):** the *title* — "no leftover hop" — and the
abstract's obligation list ("leftover fallback cannot override δ") sit close enough
to a proved-guarantee reading that a reader who stops at the headline can mistake the
illustration for the theorem. The body repeatedly warns against precisely this, so
the fix is alignment, not retraction: qualify the headline (e.g. "this machine
admits no leftover-hop edge") or footnote it to INVARIANTS §4. Disconfirmation of
this finding would be any body passage that elevates the leftover-hop picture to a
corollary — I found none; every occurrence demotes it.

**Conclusion on the assigned check:** the leftover-hop is used correctly as an
illustration. The named theorem "no unbound hop" (I3) is real but scoped to the
machine and is not the same object as the illustration. The only overclaim risk is
rhetorical (title/abstract), not logical.

---

## Assumptions still unresolved

- **A1 fidelity / non-forging worker (C1):** the strongest claim requires an Observe
  channel independent of the worker; disclosed but the threat boundary should be
  stated where "fail-closed" is first used.
- **Write-ahead + total call/decide (C2):** the metric zeros are proofs only under
  these; DRAFT §6 says so — keep it adjacent to any published rate.
- **Provider fidelity:** I1 holds of the report, not of physics (PROOFS). Unchanged
  and correctly out of scope.

## Recommendation

Proceed. The safety contribution survives its strongest reasonable challenge on the
abstract machine, the Observe split makes the central invariant non-vacuous, and the
leftover-hop is disciplined as an illustration. Attach two conditions before the
"fail-closed" / "no leftover hop" language is read as more than it proves:
(1) state the adversary boundary (accidental/architectural hop + faithful witness,
not adversarial masquerade) at first use; (2) align the title/abstract with
INVARIANTS §4 so the illustration is not mistaken for a corollary. Both are wording
changes; neither touches a proof.
