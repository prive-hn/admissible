# Telemetry contract

Events for fail-closed class dispatch. Policy fields are as-of `ts`.

A **cut** is `[t0, t1]`. `W` is class p95 of completed stage durations in the previous cut, or 12 minutes if n<30. Exclude `ts > t1 − W`. Policy as-of `ts`.

Zeros are not yet gathered. Compute with `fcd.metrics.rates` / `survival` on a write-ahead journal after a named cut. Do not backfill mixed historical logs.

## `stage`

- `ts`
- `work_item_id`
- `class`
- `stage_id`
- `stage_kind` write | check
- `assigned_specialist_id`
- `declared_model` (Bind, pre-norm)
- `authors` specialist ids of prior writing stages
- `body_hash`
- `policy_version`
- `well_formed` true only if this event is the control-plane start
- `pi_star` allow set used at admit (`π` or `π_chk`)

## `open`

- `ts`
- `work_item_id`
- `class`
- `body_hash`
- `policy_version`
- `depends_on` item ids whose accepted artifacts this body builds on (DAG gate)

## `bind`

- `ts`
- `work_item_id`
- `stage_id`
- `declared_model` (φ(a), pre-norm)
- `policy_version`

Emitted on bind success. Durable: replay restores `Running` even if the process died before the first provider call.

## `call`

- `ts`
- `work_item_id`
- `stage_id`
- `declared_model` (Bind, pre-norm)
- `executed_model` (Observe, pre-norm)
- `runtime_instance` optional; required to distinguish F2 from F1
- `on_bind` recomputed as `norm(executed) == norm(declared)`
- `first_attempt` true on the first Observe of this stage
- `signal` none | 401 | 403 | 404 | 429 | exhausted | not_found

## `decide`

- `ts`
- `work_item_id`
- `stage_id`
- `result` pass | fail_closed
- `fault` F1..F10 or null
- `next` retry | ask | stop | accept
- `tried` specialists already attempted this stage

## `accept`

- `ts`
- `work_item_id`
- `store_id`

## Context-envelope events

These events support I10–I17 audits. They do not add empirical rates by themselves.

### `work_pin`

- `ts`, `project_id`, `work_item_id`
- `project_version`, `memory_version`, `contract_revision`

### `envelope_admit`

- `ts`, `work_item_id`, `gate_id`
- `attempt_counter`, unpredictable `nonce`, `envelope_hash`
- `agent_id`, `agent_revision`, `specialist`
- `executor_id`, `executor_revision`
- exact `model_provider`, `model_api_id`
- `context_mode`, `memory_scope`, `instruction_hash`, `tool_manifest_hash`
- `initial_steering_hash`, `steering_channel`

### `context_package`

- `ts`, `attempt_id`, `nonce`
- effective `categories` (`include minus exclude`)
- `package_hash_expected`

### `adapter_receipt`

- `ts`, `attempt_id`, `nonce`
- `executor_id`, `run_id`
- `package_hash_observed`
- latest `continuation_hash`
- exact `executed_provider`, `executed_model`
- optional `reported_reuse`, opaque executor cache/session ID; telemetry only

### `steering`

- `ts`, `attempt_id`, `sequence`
- `scope` project | work | gate | stage | artifact | evidence | failure
- `target_id`, `text_hash`, `continuation_hash`

### `impact_review`

- `ts`, `work_item_id`
- `classification` unaffected | reachable | direct_conflict | unknown
- `decision` continue_pinned | refresh | owner_override
- `actor`, `reviewed_project_version`, `reviewed_memory_version`, `signature`

### `memory_promote`

- `ts`, `work_item_id`
- expected and resulting project/memory versions
- accepted knowledge-delta hash and artifact/evidence references
- CAS result success | refuse

## Rates (empty)

| Rate | num / den | Notes |
|---|---|---|
| Misbind | — | first Observe / stage; publish only with silent-fail |
| Silent fail | — | stages + orphan opens; fail-closed = published |
| Bleed | — | `a ∉ π*` as-of `ts` |
| Time-to-stage | — | survival, not a mean; right-censor `ts > t1−W` |

## Refutation-gated admission events

Emitted by `rga/core.py`. They support the R1–R13 audits (fault codes V1–V15) in `paper/RGA/PROOFS.md`. Positions are indices into the RGA journal; `fcd_position` is an index into the FCD journal. None of these adds an empirical rate by itself.

### `rga_declare`

- `ts`, `refuter_id`, `refuter_version`, `author` (a declared identity string, B11), `mode` ledger | bounded

### `rga_measure`

- `ts`, `refuter_id`, `refuter_version`
- `defect_model_hash`, `defect_model_author`
- `ledger` list of `{defect_id, verdict}` with verdict killed | survived | inconclusive
- `kills`, `size`, `power` — computed by the kernel from `ledger`; `inconclusive` counts in `size` only

### `rga_bound`

- `ts`, `refuter_id`, `refuter_version`, `epsilon`, `n`, `power` = `1 − (1−epsilon)^n`, computed by the kernel

### `rga_open`

- `ts`, `work_item_id`, `class`, `body_hash`, `generator`, `declared_model`
- `fcd_policy_version`, `sampling_hash`, `policy_version` (RGA), `k`, `theta`, `p_min`
- `claims` ids pinned; `refuters` `(id, version)` pairs pinned
- `fcd_position` FCD journal length at Open, read by the kernel (never caller-supplied); no `stage` event for the item's first `k` stages precedes it. Replay cross-checks `(k, theta, p_min, claims, refuters)` against the rebuilt line

### `rga_sample`

- `ts`, `work_item_id`, `sample_index`, `stage_id`
- `artifact_hash` sha256 computed by the kernel over the bytes it was handed
- `nonce` drawn after the hash and after every Sample guard (B9); replay reads it
- `fcd_position` FCD journal length at Sample, read by the kernel; no `stage` event for a later sample stage precedes it
- `executed_model`, `declared_model` copied from the FCD stage (I1 holds of them)
- `package_categories` as reported; disjoint from the class's excluded set
- `sampling_hash` equal to the line's

### `rga_trial`

- `ts`, `work_item_id`, `trial_index`, `refuter_id`, `refuter_version`, `claim_id`, `sample_index`
- `seed` = `H(nonce ‖ artifact_hash ‖ refuter ‖ claim)`, equality-checked
- `inputs_hash` (carried for audit; not compared by the kernel), `verdict` refuted | survived | inconclusive, `witness_hash`

### `rga_replay`

- `ts`, `work_item_id`, `trial_index`, `refuter_id`, `refuter_version`, `verdict`, `witness_hash`, `diverged`

### `rga_refuse`

- `ts`, `refuter_id`, `refuter_version`, `reason`. Monotone: there is no un-refuse event.

### `rga_seal`

- `ts`, `work_item_id`, `class`, `body_hash`, `artifact_hash`, `k`, `theta`, `p_min`, `power_min`, `sampling_hash`, `policy_version` (RGA), `fcd_policy_version`, `generator`, `executed_model`
- `claims` list of `{claim_id, spec_hash, composite, composition single|union|max, agreeing, k, refuters: [{id, version, mode, power, defect_model_hash, kills, size, epsilon, n}]}` — ledger refuters carry `kills`/`size`, bounded refuters `epsilon`/`n`; the null fields mark the other mode
- `residual` list of `[intent, disposition]`; `check_stage` only if an FCD check stage Passed

### `rga_close`

- `ts`, `work_item_id`, `result` fail_closed, `fault` V1..V5 or null, `reason`, `next` ask
- V2 adds `concordance` `[{claim_id, agreeing, k}]` and `miss_observed` `[[refuter_id, version]]` — exactly the refuters whose own witnesses differ from their sample-0 witness
- V5 adds `power_min`

## RGA rates (empty)

| Rate | num / den | Notes |
|---|---|---|
| Refutation | — | `rga_trial.verdict=refuted` over trials, per class and refuter version |
| Discord | — | `rga_close.fault=V2` over lines reaching Seal, at declared `(k, sampling_hash)` joined from `rga_open` |
| Miss observed | — | per refuter version: V2 closes naming it in `miss_observed`; a detected miss only where the witness is a function of the claim value |
| Replay divergence | — | `rga_replay.diverged` over replays, per refuter version; publish only with silent-fail |
| Escape replay | — | per successor refuter version; numerator needs a defect-report channel outside the journal; informative only for a version other than the sealing one |

## Calibration events

Emitted by `rga/calibration.py` (`CalibrationAuthority`). They support the C1–C7 audits in `paper/RGA/PROOFS.md`; fault codes are E1–E9. Positions are indices into the calibration journal.

### `cal_run`

- `ts`, `run_index`, `line_id`, `class`, `claim_id`, `checker_id`, `checker_version`
- `tier` A (checker pinned to the claim in the seal; seed is the kernel's derivation over the sealed hash) | B (any other declared checker; consequences require adjudication)
- `nonce` finder-chosen; `artifact_hash` sha256 computed by the kernel over the filed bytes, equal to the seal's; `seed`
- `verdict` refuted (escape) | survived (audit), `witness_hash`, `finder` (journal-cited provenance; gates nothing)

### `cal_replay`

- `ts`, `run_index`, `verdict`, `witness_hash`, `diverged`. Equal outcome establishes the run; divergence discredits the checker.

### `cal_discredit`

- `ts`, `checker_id`, `checker_version`, `run_index`. Monotone: there is no un-discredit event; validity of every run by that checker degrades at query time.

### `cal_adjudicate`

- `ts`, `run_index`, `actor`, `decision` accept | reject, `reason`. Tier B escapes only; once.

### `cal_exclude`

- `ts`, `class`, `as_of` (the Admission position the corpus was read at), `run_indices`, `actor`, `reason`, `corpus_size`, `excluded_total`. Releases named corpus entries from successor coverage; waives nothing else.

### `cal_install`

- `ts`, `policy_version` (the **admission** policy), `calibration_policy_version`, `as_of` (the Admission position the ratchet was read at), `budgets` per class `{e_max, demotion_gate}`, `coverage` per class `{corpus_size, excluded, models: {claim_id: defect_model_hash}}`, `dropped_defect_ids` (the predecessor-diff), `dropped_classes` (classes leaving the policy; refused while they owe coverage). Emitted only past the ratchet guards (E4) and the class-coverage guard (E9); `rga/core.py install` itself emits nothing. The budgets are journaled because `demoted()` gates CalOpen and CalSeal: a budget nobody can read from the record is a gate nobody can audit, and replay refuses a supplied policy that disagrees with the one the journal installed.

### `cal_stamp`

- `ts`, `line_id`, `sealed_at`, `track_records` per pinned refuter: `{charged_cells, seals_participated, corpus_size, corpus_excluded, as_of}`, and `corpus_provenance` `{finder_is_generator, independent}` — the class corpus split by finder for this seal's generator. Primaries, never a rate; a zero `charged_cells` is absence of filed evidence, never measured power; the finder split is journal-cited provenance and gates nothing.

### `cal_close`

- `ts`, `line_id`, `fault` E5, `as_of` (the Admission position the demotion was read at), `refuter_id`, `refuter_version`, `primaries`. The demotion gate where the class declared it; the line closes through Admission's operator close in the same step. `as_of` is what makes the close replayable: without it, rebuild re-reads the demotion against final state and refuses honest journals.

## Calibration rates (empty)

| Rate | num / den | Notes |
|---|---|---|
| Escape rate | — | valid escapes over seals, per class and tier; doubly selected, one-sided |
| Adjudication acceptance | — | tier-B accepts over adjudications |
| Exclusion load | — | excluded over corpus size per install; primaries already on the event |
| Charge accrual | — | charged cells per refuter version; never read as quality without seals_participated |
| Audit coverage | — | lines with a valid audit over lines sealed; reads only with the audit events |
