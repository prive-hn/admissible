# Exact-head review of PR #3 — synthesis

An independent reviewer read base `d943ea9` → head `062ac2e` and returned
REQUEST CHANGES with two P1 findings, one paper blocker and four non-blocking
follow-ups. Gates at that head were green (387/387 tests, 0 vulnerabilities,
clean build, both PDFs readable). Every finding was reproduced here before
anything was changed; none was refused. Chasing one of them uncovered a third
defect the review had not reached.

## P1 — `admissible()` did not prove the calibration authority mediated the seal

Reproduced exactly as filed: drive a line to a seal by calling
`Admission.seal` directly instead of `CalibrationAuthority.seal`, and the
ledger answered `admissible=True` with no stamp in existence. A consumer could
not tell an IRC seal from one that had bypassed layer C entirely, and
Theorem 1's same-step-stamp conjunct was a description of what usually
happened rather than a property the predicate enforced.

**Fixed.** `mediated(id)` is a new pure query: exactly one `cal_stamp`, bound
to that seal's own position. `admissible` conjoins it and
`check_dependencies` refuses an unmediated dependency, so a bypassed seal is
now visible as layer **IR** — sealed under scrutiny, never counter-signed —
and never answers admissible. Replay refuses an added, duplicated or
re-pointed stamp. The reference server derives the layer letters from the
record (`I` / `IR` / `IRC`) and the cockpit renders IR with its own label and
tone rather than as a lesser IRC. Six red-first tests, kernel through UI.

## P1 — a class with no calibration policy behaved as an unlimited one

Reproduced: with no `CalibrationClass` for a class, charges accrued but
`demoted()` returned `False` forever, and CalOpen/CalSeal continued. The
public route was project reload, which installed a successor admission policy
without evolving the calibration policy — the reviewer's trace showed a new
class accepted, sealed and `admissible=True` with no budget ever declared.

**Fixed** as fault **E9**: `e_max` and `demotion_gate` are explicit per class
with no defaults, enforced by a named guard at CalOpen, CalSeal and the budget
query, by a coverage check at construction, and by `install()`, which now
takes the successor calibration policy and swaps both atomically — a refused
ratchet leaves both standing. The server derives the calibration policy
wherever it derives the dispatch policy, so reload carries budgets for new
classes or refuses. The guard has a delete-the-guard proof; `demoted()` keeps
its old fallback *behind* the guard deliberately, so deleting the guard
exposes the defect instead of crashing.

## Paper blocker — Theorem 2's universal replay sentence was false

"No journal a live machine refuses is accepted by replay" was contradicted by
the residue `paper/RGA/PROOFS.md` already admitted, and by the deleted-stamp
counterexample. Both were real.

**Narrowed, not patched over.** Theorem 2 now claims what replay proves:
every event present is re-guarded, so alteration, forgery, duplication and
local reordering are refused, and every journal a live machine accepted
replays unchanged — but replay does not prove completeness. Two residues are
stated in the theorem, in `paper/RGA/PROOFS.md`, in §11's limitations and in
plain words in `docs/PROOFS_PLAIN.md`.

The sharper of the two was found while pinning the boundary: **truncating a
journal's tail is undetectable and is the one tamper that raises standing** —
drop the last escape and its line is no longer impeached. A middle deletion is
refused (later events stop recomputing), but a shorter history is
self-consistent. Closing this needs an anchor outside the journal — append-only
storage, or a signed head whose length is witnessed. The kernel implements
neither and now claims neither. The boundary is executable in both directions. *(Round 2 below refutes the "one tamper" half of this: at least four non-truncation tampers raise standing. The documents state the general deletion residue now, not this narrower one.)*

## Found while fixing: honest journals with two seals were refused on replay

Not in the review. Every stamp recomputed `seals_participated` against the
**final** rebuilt Admission, so any journal with more than one sealed line
failed rebuild — replay refusing an honest history, the one thing it must
never do. `track_record` now bounds the count to seals at or before the
stamp's own position, which is what the live stamp saw. A tampered index also
crashed with `IndexError` instead of refusing; it now raises a stated refusal.

## Non-blocking follow-ups

- `paper/SECTIONS.md` counts were stale; all counts across the papers and
  READMEs were re-measured (339 checks: 302 `tests/` + 37 atlas; 43 per-guard
  deletion proofs; 2 citation binders).
- The Daubert mapping now qualifies "known error rate" inline: carried power
  is exact on the named defect model, never the generator's real-world rate.
- PDF/figure regeneration is not byte-reproducible — acknowledged, not fixed;
  the figures are regenerated from code at every build by design.
- Detached-HEAD project load in `server/project.py` is a baseline defect this
  branch did not introduce and does not touch.

## What this round cost the documents

The corrections moved claims *down*, never the code up to meet them, except
where the code was genuinely wrong. Two theorem statements narrowed, one fault
family added, one predicate strengthened, and three documents that described
tamper-evidence in absolute terms now name the tamper they cannot catch.

---

# Round 2 — four agents over the repairs themselves

The repairs above were re-attacked by four independent reviewers (kernel
mediation and E9; server and cockpit surface; documents versus code; the PDF
volume and its build). Every finding below was reproduced before it was
changed, and the pattern is worth naming: **the first round's repairs were
correct and incomplete in the same direction.** Bounding one field of a
recomputed record left three unbounded; narrowing one theorem left its layer
paper unnarrowed; adding a mediation conjunct closed a live bypass and left
an equivalent one at replay.

## Critical — replay refused honest journals, four ways

`_check_valid` read the **final** Admission refused-set, so an ordinary
post-seal audit divergence retroactively invalidated escapes that a stamp,
an E5 close, an exclusion or an install had already recorded. Each of the
four is a journal the live machine produced that its own replay rejected —
the inverse of the property replay exists to provide, and the same bug class
as the two-seal defect round 1 fixed, one layer out.

Every event whose replay guard reads Admission state now carries the position
it was written at (`as_of` on E5 closes, exclusions and installs; `sealed_at`
already on stamps), and validity, charges, corpus and provenance are all read
as of that position. Four regression tests, one per route.

## High — the calibration policy was invisible to the record

`cal_install` journaled only the *admission* policy version. A budget raise
therefore changed what the authority admits, left no trace, and made the
journal replay silently under whichever budget the caller supplied. The event
now carries `calibration_policy_version` and the per-class budgets, and replay
**adopts** them rather than trusting a supplied policy — so a rebuild answers
`demoted()` under the budgets the record names. E9 coverage is re-checked at
each install on rebuild, not only live.

## High — forgery was accepted where the papers said it was refused

Two independent instances:

- **The identity kernel's replay had no integrity check at all.** It re-drove
  every transition into a discarded sink and then restored the journal
  verbatim, so forged events of unknown type, duplicated or deleted `accept`
  events, and altered `on_bind` / `declared_model` / `tried` fields all
  rebuilt clean — and were then served verbatim at `/api/events`. All three
  machines now compare re-driven transitions to the journal field by field
  (`ts` excluded). This also closes an RGA hole where a tampered `power_min`
  survived in the served record while the rebuilt seal carried the true value.
- **A first `cal_stamp` could be appended** to a never-mediated seal, buying
  IRC from a journal alone — defeating the mediation conjunct round 1 added.
  Stamps must now appear in seal order, which refuses a forgery for any but
  the most recent unmediated seal. That remaining case is stated, not claimed
  away: it is the append-side twin of the deletion residue.

## The residue, restated correctly

Round 1 said truncation was "the one tamper that raises standing". Four
counterexamples say otherwise: a forged first stamp, a deleted
highest-indexed run, a deleted adjudication, and a deleted
divergence/refuse/close triple that un-taints a seal. The documents now state
the general fact — **deletion of any coherent group no surviving event
recomputes against is undetectable, and deletion is the standing-raising
direction** — in the theorem, the proofs, §11, the README and the plain-language
companion.

## Also confirmed and fixed

- The reference server opened lines through `Admission.open`, leaving C6 and
  E9 dead in the only deployment shipped. It opens through the authority now.
- `Admission.from_events` ended on whichever policy the last opened line
  pinned, so the class-coverage check measured against the wrong one.
- `IR · impeached` matched no CSS tone rule and rendered *neutral* — better
  than plain IR. Tone is keyed on the state, not the layer letter, and the
  terminal's broke frame is driven by an explicit attribute rather than by a
  chip only some layers render.
- The IR sentence swallowed impeachment and taint and asserted "carries
  layer-R standing only" for a line whose layer-R seal was impeached.
- The demo state — the first frame every operator sees, and every
  disconnected frame — claimed IRC with no `mediated` in the record.
- A V4 close published an empty reason, rendering "Closed under scrutiny
  (V4):  —"; a discarded line read "Not sealed **yet**".
- The reference budget (`e_max = 3`) was a constant no document named.
- The volume build: a `|` inside a code span split table rows, destroying a
  normative Seal guard and emptying a bench column; `\|` did the same; two
  subscripts rendered as black boxes **that extract as the letter "I"**, so no
  text scan could find them; table cells carried markup the renderer prints
  literally; lists mixing a lead-in line folded into run-on prose; Figure 1
  was clipped by its own axis limit; the width bound was a character count
  wrong by more than 2× and is now measured in points from the font metrics.
- `tests/test_paper_build.py` was largely vacuous — one tautology, two tests
  sharing the subject's own bug, one blind past an unterminated fence. The
  width test now measures independently, the cell oracle uses a deliberately
  different splitting algorithm, and a new test renders a probe page through
  the real renderer so an unsupported glyph cannot ship silently again.

Counts re-measured after the round: 350 checks (313 `tests/` + 37 atlas), 43
per-guard deletion proofs, 2 citation binders, 71 cockpit tests.
