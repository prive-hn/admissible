# RGA round-1 synthesis

Working tree, 2026-08-21, on the first complete kernel + papers. Five lenses — formal (re-derive R1–R13 against the code), enforcer (are the mutation tests genuine; what is untested), contrarian (do the documents claim what the code does), attacker (public methods only, ten targets), docs (every sentence vs its enforcing line) — with every non-observation finding handed to an adversarial verifier. All five: **REVISE**. Every REVISE condition was applied in the same branch; this file records what broke and what changed.

## Kernel defects (reproduced, repaired, each with a test that was red first)

1. **Defect-model author was a free label per record** (formal, enforcer, attacker, docs — all four found it). `_guard_seal_independent` read only the *first* `rga_measure` for a hash, so a second record on a clean first hash could carry the generator's authorship past Open and Seal. Repair: the author is fixed by the first record (`defect_authors`, `_guard_model_author_fixed`, V13), and both guards read the one fixed value. Tests: `test_defect_model_author_is_fixed_by_first_record`, `test_defect_model_authored_by_generator_after_open_refused_at_seal`, mutation scenarios for `_guard_model_author_fixed` and `_guard_seal_independent`.
2. **`open()` accepted a caller-supplied `fcd_position`**, bypassing the before-generation guard (docs confirmed; attacker found independently). Repair: the public row reads its own journal position; replay supplies the recorded value through a private path and range-checks it. Test: `test_caller_cannot_supply_an_fcd_position`.
3. **`from_events` could not rebuild any journal containing a V2/V5 close** (formal, enforcer, attacker). A failed Seal emits a close but no seal event, so nothing re-drove it and the count check raised. Repair: replay re-drives the failed Seal attempt and requires it to reproduce the journaled fault; plus a policy cross-check against the `rga_open` record, position range checks, and a live nonce source after rebuild (the attacker found the rebuilt machine's nonce was a constant). Tests: `ReplayTests` ×4 new.
4. **Negative sample index passed the range guard** (formal), aliasing the one-trial-per-cell bound. Repair: `0 ≤ i <` range checks in `trial` and `seed_for`; test added.
5. **Harness could batch all k generations before registering any sample** (attacker near-miss), choosing byte-to-slot assignment after seeing the batch — converting a would-be discord close into a seal at θ < 1. Repair: interleaving guard `_guard_sample_order` (V8): sample i must be registered before any later sample stage is attempted.

## FCD kernel defects (repaired here because R7/R8 lean on them)

6. **`no_admit` had no `pc` guard** (formal): it could write `status="failed"` on a Passed stage of an accepted item while the id stayed in S — a second writer of `status` that broke I8 as a state invariant. Repair: the same `pc∈{Open,Closed}` guard Admit has; `paper/INVARIANTS.md` NoAdmit row and `paper/PROOFS.md` I8 updated; `KernelIdentityGuards` tests.
7. **`open` silently replaced an existing item id** (enforcer observation): a sealed id could come to refer to a different body while `is_sealed` stayed true, against I4's "a class change is a new id". Repair: fresh-id guard; row updated; test.

## Design gaps closed

- Bounded-mode seals carried a bare float; now carry `(ε, N)` with the mode labelled, and the documents say plainly that ε is a declaration the seal shows (with N = 1 the figure equals it).
- `miss_observed` named every refuter on a discordant claim; now names exactly the refuters whose own witnesses differ from their sample-0 witness.
- Seal gained `sampling_hash`; `check_dependencies` refuses tainted dependencies; `admissible = sealed ∧ ¬tainted`; duplicate claim ids refused at policy validation.
- Fault codes renamed **V1–V15** — they collided with theorem numbers R1–R13 and had confused both the author and the reviewers.
- Unreachable guard clauses removed and derived instead, per the file's own dead-code rule: the refused check at Trial/Seal, the write-kind and declared-model clauses at Sample, the `declared_at` ordering clause at Open, the refuter-author clause at Seal. Three inline fault-table checks promoted to named, deletion-tested methods (`_guard_bound_once`, `_guard_sample_count`, `_guard_trial_once`, plus `_guard_not_refused`).

## Document corrections (the round-4 lens: a document may not claim what the code does not do)

"No declared scalar is accepted" scoped to ledger mode; "every guard is a separate method" scoped to fault-table guards with shape preconditions named as inline; the citation test described as a move-detector, not a semantic check; PREMISE's (Q, ε, N) seal claim, "Check 1 static", "pinned by content hash", "I6 verbatim", "A11 strengthened", and rows 12/14 corrected, with a dated §9 addendum so the pre-registration stays honest; DRAFT's semantic-entropy line, kill-rate attribution (balanced accuracy, not recall), miss-observed qualifier, residual wording, inherited-theorem list, and B11 (author identities are declared strings) added; "What is not proved" gained ε honesty, ledger replay/replayer identity, consumer redirection, adaptive retries, and B11.

## Standing observations, not repaired

- FCD's reference server still reads `S`, not `S_R`, at the DAG edge and promotion — a deployment obligation listed under *Not theorems*.
- The premise-round FCD filings (server artifact overwrite; A11 wording) remain filed, not fixed here.
- 15 of 66 verifier agents died on a session limit mid-round; every finding they left unverified was independently confirmed by another lens or addressed as part of the same repair, and the re-verification run was stopped once the tree began changing under it.

Suite after the round: 243 Python tests green (206 in `tests/` including 95 RGA, 37 atlas), citations resolve, the README example executes as printed.
