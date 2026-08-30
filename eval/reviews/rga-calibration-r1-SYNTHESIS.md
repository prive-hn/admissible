# Calibration round-1 synthesis

Working tree, 2026-08-21, on the first complete calibration kernel. Two lenses — formal (re-derive C1–C7 against `rga/calibration.py`, row-for-row table check, premise-constraint audit) and attacker (ten break targets, public methods only) — with every non-observation finding adversarially verified. Both: **REVISE**. Eleven findings confirmed; all applied in the same branch.

## The defect (both lenses, independently)

**`from_events` trusted the journal.** Unlike `rga/core`'s replay, which re-drives every event through the guarded public transitions, the first calibration rebuild wrote `runs`, `established`, `discredited`, `adjudication` and `exclusions` directly, re-checking almost nothing. Three reproduced traces: a `cal_run` tier tampered B→A gave an unadjudicated tier-B escape automatic effect on rebuild (impeachment and a charge live execution refuses — the E2 forbidden state through replay); a deleted `cal_discredit` silently un-discredited a checker while the event-count check saw nothing; a forged actorless `cal_exclude` was accepted, emptying a corpus. The writer inspection in PROOFS was false as written — it omitted five replay-path writers. Repair: replay now re-derives the tier from the seal and refuses a disagreeing journal, re-runs the seed, standing, verdict and audit-checker guards, requires a diverged replay to be adjacent to its discredit event (deletion detected), re-guards exclusions and adjudications, re-runs the ratchet at installs, and requires stamps and E5 closes to recompute from the rebuilt ledger. Four new tamper tests are red-first witnesses. One-sided residue stated in *Replay of the ledger*: registry membership is checked against the final Admission registry, a superset of the live one.

## The other confirmed findings, all applied

- **Spurious close**: `cal.seal` on an already-sealed line emitted a `cal_close` E5 event while the line stayed Sealed — a journaled step that never happened. The pc check now precedes any emission; test asserts no event.
- **Class-drop hole** (attacker): dropping a class from the successor policy released its whole corpus with no journal trace. The ratchet now refuses dropping any class that owes coverage; the named exit is exclusion, as everywhere else.
- **C6 over-claimed**: "demoted is monotone in the journal" was false — a discredit lowers valid charges and can un-demote. Restated as a pure function of the valid charge set, falling with validity degradation, which is the fail-closed direction (refusal-shaped facts outrank the count).
- **C5 promised what the code lacked**: the corpus finder-provenance split (a settled premise-round constraint) is now computed and stamped — `{finder_is_generator, independent}` — and replay recomputes it.
- **C4 statement vs code**: "every referenced defect model" scoped to ledger claims in §8.3, the table row, and the fault table; the bounded-only guard named as the reason.
- **§8.4 taxonomy**: E1–E3 are validity semantics read at query time, not published faults; only E5 publishes; E8 is the writer inspection. Rewritten. E7 gains the write-once adjudication clause.
- **Audit row** authorized "a measured refuter version" the code refuses — row fixed to the code (pinned or valid-escape checker).
- **Install event under-reported**: now carries the per-claim model map and dropped classes beside the dropped-id diff.
- **Two test bugs of the author's own**: a vacuous assertion (`impeached and False`) and an un-deepcopied `lines` component in the C7 snapshot — both real lapses of the round-4 standard, both fixed.

## State after the round

50 calibration tests (15 per-guard deletions including the stamp effect, 7 round-1 repair traces), 256 in `tests/`, 37 atlas, all green; every `path:line:symbol` citation resolves — the move-detector fired during the repairs exactly as designed and forced the re-cite.
