# Final full-stack review — synthesis

Five adversarial lenses over everything built after the layer reviews (the
bench, the journal schemas, the server's admissibility integration, the
cockpit surface, the papers), 36 agents total: each lens returned findings
with reproductions, and every finding went to a skeptic instructed to refute
it. 31 findings survived their skeptic; 0 were refuted. All 31 are applied
on this branch; the fixes carry red-first tests where they touch a kernel or
a server transition.

## Confirmed and applied

**Kernels (via the schemas lens).** Both replay paths accepted caller
verdicts outside their enums into the journal: `Admission.replay` and
`CalibrationAuthority.replay_run` now carry `_guard_replay_verdict`, each a
named method with a deletion proof (V4 / E1 rows in the mutation tables).
The conformance test additionally proves malformed events *fail* validation
(wrong types, missing required fields, out-of-enum values, unknown types).

**Server — critical.** On a class with more than one write gate, the k=1
RGA line bound the FIRST write's bytes while the store served the LAST
write's: an item could read "Sealed: survived the pinned refuter" for bytes
the refuter never attacked. The kernel binds sample i to FCD stage i, so
the reference server now refuses to open an RGA line on multi-write classes
— layer I, the reason stated, promotion refused
(`MultiWriteClassesRefuseTheSeal`, red-first). Also: project reload made
both-or-neither (the calibration ratchet runs before the FCD install, whose
only refusal is pre-checked); a V1-refuted line now surfaces the published
fault in state instead of "no admissibility claim is made"
(`RefutedLinesAreLoud`); `/discard` and `/fix` refuse accepted items, as
`steer` always did.

**Cockpit.** The failed-label-over-sealed-record cell renders the conflict
("trust the record") instead of "nothing was written"; the demo W4 record
now matches what the live server projects (power 1, not an invented 0.8);
the layer-badge and impeached glosses were rewritten (the old ones asserted
gates ran on lines where they had not, and claimed C1 entailment for tier-B
escapes that require adjudication); three formal references were
re-pointed at what the invariants actually say (residual → §4/V15,
admissible → C3/§8.5, tainted → §4 with R5 monotonicity); the "generated
from the same table" claim was replaced with the truth (mirrored by hand,
no generator) in both files, and the admissibility rows re-aligned
verbatim; `FaultStamp` no longer crashes on a fault code outside the F
table; the no-longer-admissible terminal now holds the broke frame the
docs promised, not only the label.

**Bench.** The published outcome and standing numbers are now derived from
the kernels' journals and run records (rga_seal/rga_close events, the
ledger's runs), not bench-side counters, and the record carries per-scenario
impeachment identity — so "every latent-defect seal was impeached, no
honest seal was" is computed from the record and prints only when true,
with an honest alternative branch that keeps the full data. The ratchet
line states what the successor is (the same checker re-versioned, measured
at fresh seeds over D ∪ corpus; charges do not carry across versions —
coverage, not improvement). The regeneration integrity check raises instead
of asserting (survives `-O`); dead `d2_entries` removed; the docstring's
determinism claim now matches the test, which compares journal hashes
carried in the results record; `test_bench` asserts honest-scenario
impeachments are zero *by identity*, not by a count inequality.

**Papers/README.** Stale counts measured and corrected (280 kernel/server/
context + 37 evidence-store + 70 cockpit; 44 per-guard deletion proofs);
Theorem 2's proof and §7's methodology claims scoped to where they hold
(per-guard deletion and line-level citation binding are R/C discipline; the
identity kernel's guards are driven by transition tests and its proofs
carry file-level citations); "three kernel defects" → five, matching the
cited record; the reference server's process-lifetime kernel state is now
stated in both README and §11 (a restart empties the escape ledger; C's
promises hold within one process).

## Accepted residual

- The conformance test exercises every enum member but not every variant
  *branch* (e.g. every optional field of every close); the negative-case
  suite covers the load-bearing constraints. Recorded, not closed.
- ~26 legacy FCD glossary rows in `docs/UI_GLOSSARY.md` paraphrase rather
  than mirror `glossary.ts` verbatim; both files now say "mirrored by hand"
  rather than claiming generation. The admissibility rows are verbatim.
- The citation move-detector fired during these fixes (the new kernel guard
  shifted line numbers); all citations re-derived, three of them re-pointed
  by hand where nearest-match landed on a call site rather than the
  enforcing line.

Zero findings were refused without a recorded reason; nothing here was
softened in the retelling.
