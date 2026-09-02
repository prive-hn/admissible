# Section status

## Admissible (`paper/admissible/`)

| Piece | Status |
|---|---|
| Name | **Admissible** — the admissibility kernel. Argued from the code's top predicate `admissible(id) = sealed ∧ mediated ∧ ¬tainted ∧ ¬impeached` and the evidence-law/Daubert mapping (testability→refuters, known error rate→carried power, controlling standards→pinned policy, impeachment→escape ledger). Certifies procedure, never truth |
| Unified paper | `paper/admissible/DRAFT.md`: model, threat model, three layer summaries, Theorem 1 (soundness of the record) + Theorem 2 (loudness of deviation) as compositions by citation, methodology (delete-the-guard, citation binding, premise-first rounds), consolidated related work and limits. Adds framing and composition, not new mathematics, and says so |
| Counts (measured) | 586 checks green: 478 `tests/` + 37 atlas + 71 cockpit; 43 per-guard deletion proofs + 2 joint; 2 citation binders |
| Empirical (§9) | Three studies, none admissible evidence. Kernel bench (`eval/bench/`, Fig. 8) — machinery only; honest is the oracle, sloppy is drawn from D, and the figure says so; 7/7 latent-defect seals impeached, 3 unstable seals stand as misses. Real generator (`eval/generators/`) — 48 samples, 16/16 lines sealed, **zero defective**, ceiling structural. Real defects (`eval/realdefects/`, Fig. 9) — **8 hand-verified**, no defensible rate. Full account and every voided run: `eval/LOG.md` |

Canonical machine: `fcd/`. Round 4 conditions applied. Metrics empty until a named cut.

| Piece | Status |
|---|---|
| Name | Fail-closed class dispatch. Work item → accepted artifact |
| Observe vs Bind | `fcd/core.py`. Bind writes `m_decl`. Observe writes `m_exec` |
| Proofs I1–I17 | `paper/PROOFS.md` |
| Tests | 586 repository checks total: 478 Python kernel/server/context/RGA/calibration/paper/custody + 37 atlas/protocol + 71 cockpit |
| Context authority | `fcd/context.py`; attempt/nonce, package receipts, steering, CAS promotion |
| Execution boundary | `server/execution.py`; mature executor internals stay external |
| Watchdog | `fcd/watchdog.py` (injected `alive_fn`) |
| Stage cache | `fcd/cache.py` — same specialist + φ + prefix only |
| Store | Accept only |
| Rates | Defined in `fcd/metrics.py` + `metrics/SCHEMA.md`. No numbers |
| PDF | `paper/fail-closed-class-dispatch.pdf` |
| Hop | Illustration |
| Site collector | `eval/private/` only |

## Refutation-gated admission (`paper/RGA/`)

| Piece | Status |
|---|---|
| Premise | `paper/RGA/PREMISE.md`. 38 findings, five lenses; none of six "kills-premise" claims survived as such; two pre-registered positions fell; §9 records round 1 |
| Round 1 | Five-lens review of the finished kernel: five REVISE verdicts; 5 RGA kernel defects (3 of which invalidated published proofs) + 2 FCD kernel defects (`no_admit` pc guard, `open` fresh-id guard) repaired with tests; `eval/reviews/rga-r1-SYNTHESIS.md` |
| Name | Refutation-gated admission. Line → sealed artifact. Title kept; abstract scopes it to the refutation record |
| Kernel | `rga/core.py`, composed over `fcd/core.py`; writes no FCD field (R11) |
| Proofs R1–R13 | `paper/RGA/PROOFS.md`; cites `path:line:symbol`, move-detected by `tests/test_rga_citations.py` |
| Tests | 97: 65 invariant traces, 30 guard-deletion and coverage checks (26 per guard, 2 joint, 2 coverage — every guard method individually load-bearing), 2 citation checks |
| Faults | V1–V5 publish a close; V6–V15 raise. Own namespace so codes never collide with theorem numbers |
| Seal | `S_R ⊆ S`; carries power per claim with its defect model or `(ε, N)`, `(agreeing, k)`, sampling config, residual; `tainted`/`admissible`/`check_dependencies` are the consumer surface |
| Rates | `metrics/SCHEMA.md` RGA section. No numbers |
| Not proved | `PROOFS.md` "What is not proved", written first in `PREMISE.md` §7, extended by round 1 |
| Calibration | `rga/calibration.py` (C1–C7, faults E1–E9): escapes as counterfactual trials, charges per wrong-verdict cell, install ratchet (incl. class-drop refusal), demotion as query, provenance-stamped seals, re-guarded replay. Rounds: `rga-calibration-premise-SYNTHESIS.md`, `rga-calibration-r1-SYNTHESIS.md` (11 confirmed findings, all applied); 71 tests incl. 17 guard deletions and 7 repair traces |
