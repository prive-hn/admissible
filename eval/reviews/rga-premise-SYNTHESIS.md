# RGA premise round — synthesis

Working tree, 2026-08-21, before any kernel code existed. Five adversarial readings of the RGA brief — power, cheaper formulation, boundary, subsumption, and a dedicated collapse steelman — produced 38 findings; each was handed to an independent reviewer instructed to refute it. Full structured results were consumed into `paper/RGA/PREMISE.md`; this file is the round's record.

| Question | Findings | Refuted | Survive narrowed | Survive as stated |
|---|---|---|---|---|
| Power | 10 | 5 | 5 | 0 |
| Cheaper | 6 | 2 | 4 | 0 |
| Boundary | 7 | 2 | 5 | 0 |
| Subsume | 7 | 1 | 6 | 0 |
| Collapse | 8 | 4 | 4 | 0 |

Verdict: the premise survives narrowed. All six *kills-premise* findings fell to refutation or narrowed to design constraints. The decisive refutations and narrowings:

- Power scalarises by **infimum over a declared alternative**, not expectation over an unknowable defect prior; three modes (exhaustive, bounded with a theorem, ledger-calibrated) — never a probability about the artifact.
- The **Wilson lower bound** the author pre-registered was killed: binomial intervals assume i.i.d. draws from the population the seal speaks to; a large redundant mutant set would outrank a small adversarial one. The coordinate is D, not n.
- A **sample is an FCD stage-attempt** (k write stages of one item), built and demonstrated on the unmodified machine — not k sibling items as pre-registered.
- The seal composes over FCD (`S_R ⊆ S`) at the third placement the repo already uses; "subsumes" became "extends by composition".
- Claims are pinned by class at Open; the generator never authors what it is measured against; concordance is agreement with the designated sample, never a plurality.
- "Determinism is checkable" was restated as an assumption (hermetic pinned runtime) plus a falsifier (replay refuses monotonically).

Two FCD defects surfaced in passing and were filed: the reference server stamps as accepted whatever the last stage's executor returned (`server/app.py` ~871–897, reproduced with a steer between stages), and A11's "collision fails toward refusal" is used fail-open by the I16/I17 proofs.
