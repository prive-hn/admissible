# Context, Memory, Model and Cache Envelope

**Status:** round-2 proposal for independent re-review. No implementation authority until all three reviewers pass this exact document.

**Owner:** Roque Briceño  
**Project:** Admissible — written when the project was still named `fail-closed-dispatch`, after its identity layer; the name is left as the record has it.

## 1. Decision

FCD is a work, evidence, steering and acceptance system. It is **not** a coding-agent implementation and **not** a sessions application.

Existing executors (Claude Code, Codex, Hermes, ACP, local/remote agents) keep their mature tool loops, provider clients, session behavior and internal optimizations. FCD treats an executor as a bounded black-box worker behind `ExecutionAdapter`.

FCD owns:

- project and accepted-state versions;
- work-item contracts and dependency DAG;
- gate policy;
- agent/profile and exact model selection per gate;
- context/memory/cache policy per gate;
- node-scoped steering and questions;
- evidence/artifact collection;
- Observe, Pass/PassRefuse and Accept authority.

Sessions, transcripts and executor-specific UI are inspectable evidence, not the product hierarchy.

## 2. Non-goals

FCD will not:

- recreate Claude Code/Codex/Hermes tool loops;
- implement provider inference, coding tools or ACP session internals;
- expose a left sidebar of model sessions as the primary UX;
- merge all project chat into one global prompt;
- treat cache as semantic memory;
- inject unaccepted sibling work into another line;
- claim mathematical proof of model intelligence, artifact quality or provider physics.

## 3. Terms

### Project snapshot `P_v`

Immutable accepted project state at version `v`: repository identities/heads, accepted capabilities/artifacts, constraints, policies, and accepted knowledge references.

### Project memory `K_v`

Versioned semantic knowledge promoted from accepted work only: decisions, interfaces, invariants, accepted limitations, capability changes and artifact/evidence references. Raw transcripts and model reasoning are not project memory.

### Work item `W`

One line opened against a pinned `(P_v, K_v)` with a visible contract and dependencies.

### Gate `G`

One bounded stage of work. A gate pins an execution envelope at Admit.

### Agent profile `A_r`

Versioned role, instructions, tools/authority claims and default model reference. Agent identity is independent of executor and model.

### Model reference `M_r`

Provider, provider-accepted API model ID, display label, context/reasoning profile and receipt-normalization policy. Display labels never substitute for API identity.

### Context

Material supplied to one gate invocation. Context is selected, not equal to all available history.

### Memory

Durable, semantic, versioned knowledge. Only accepted knowledge enters project memory.

### Cache

Executor/provider optimization for an equivalent input prefix. Cache has no semantic authority. A cache hit cannot alter the context manifest or skip Observe.

### Executor

An existing system behind `ExecutionAdapter`. It receives an envelope/context package, uses its own mature tools, and emits events/evidence/artifacts/receipts. It cannot Pass or Accept.

## 4. Work pin and attempt-scoped execution envelope

A work item pins `P_v` and `K_v` once at **Open**. Every gate inherits those exact versions. A later gate cannot choose a newer project/memory snapshot; refresh creates an explicit work revision and new attempt.

Each gate has a monotonic attempt counter and an unpredictable nonce:

```text
attempt_id = (work_item_id, gate_id, attempt_counter, nonce)
```

For attempt `a` of gate `g`:

\[
X_{g,a} = (attempt\_id, P_v, K_v, W_r, G_r, A_r, specialist, M_r, I_h, C_p, T_h, Q_c, S_0, steering\_channel)
\]

Where:

- `attempt_id`: exact attempt counter + nonce; prevents prior-attempt receipt replay;
- `P_v`, `K_v`: work-level snapshots pinned at Open and inherited unchanged;
- `W_r`, `G_r`, `A_r`: work, gate and agent/profile revisions;
- `specialist`: exact admitted worker identity, separate from reusable profile/model;
- `M_r`: exact provider/model reference;
- `I_h`: effective layered-instruction hash;
- `C_p`: FCD context-package policy;
- `T_h`: allowed tool-manifest hash or executor capability contract;
- `Q_c`: FCD attempt-local cache policy;
- `S_0`: steering-history snapshot frozen immediately before Admit;
- `steering_channel`: append-only channel ID for steering received after Admit.

At Admit:

\[
envelope\_hash_{g,a} = H(X_{g,a})
\]

The base envelope and `S_0` are immutable until Close. In-gate steering does **not** rewrite the base envelope. It appends to a separate ordered stream `J_{g,a}[n]`. Each accepted continuation receipt binds:

\[
continuation\_hash_n = H(envelope\_hash_{g,a}, continuation\_hash_{n-1}, J_{g,a}[n])
\]

A gate cannot Pass while a steering event is pending without an adapter receipt for the latest sequence. Any base-envelope change requires Close + Retry with a new attempt/nonce, or a new work item.

## 5. FCD context-package modes vs executor continuity

These are two different axes and must not be conflated.

### FCD-owned package modes (provable at manifest/package level)

#### `fresh_blind`

FCD constructs a new canonical package containing contract, immutable candidate artifact/diff, acceptance criteria, selected accepted project facts and explicit evidence. It excludes builder transcript/reasoning, prior reviewer verdicts and unaccepted memory.

#### `fresh_scoped`

FCD constructs a new package with selected accepted project knowledge, work contract, current artifact and allowed evidence. No full work transcript.

#### `project_shared`

FCD constructs accepted project memory plus work contract and gate-specific context. Normal implementation default. Sibling candidate content appears only when declared as dependency/evidence.

#### `contract_only`

FCD constructs only the contract and explicitly named input artifacts. No project memory or work transcript.

### Executor continuity hints (adapter capability, not FCD theorem)

#### `executor_continue`

Request that an executor continue an opaque existing session/checkpoint. FCD still supplies the current canonical context delta and steering stream. The executor must declare this capability. Hidden session residue is outside FCD proof; this mode cannot satisfy `fresh_blind`.

#### `executor_fork`

Request a provider/executor fork from a named opaque checkpoint. FCD does not claim the executor source is immutable. If the adapter cannot prove its declared fork capability, the gate fails closed or uses an explicitly policy-approved fresh package; it never silently downgrades.

FCD does not store/replay full executor sessions to manufacture continuity or forks. The executor owns those internals. FCD stores only opaque session/checkpoint IDs, capability declarations and receipts as evidence.

## 6. Canonical context package and independent attestation

Each gate records a language-neutral manifest:

```yaml
attempt_id: W42/review/2/nonce-8f2d
mode: fresh_blind
continuity: fresh
project_snapshot: P18
project_memory: K12
work_item: W42
contract_revision: 3
gate_revision: 2
agent_revision: 7
specialist: reviewer-2
model_ref: anthropic/claude-opus-4-8
include:
  - accepted_project_facts
  - candidate_diff
  - acceptance_criteria
exclude:
  - builder_transcript
  - builder_reasoning
  - previous_review_verdict
memory_scope: accepted_only
cache_scope: attempt
initial_steering_hash: sha256:...
steering_channel: steering/W42/review/2
continuation_sequence: 0
tool_manifest_hash: sha256:...
```

`exclude` always wins: `effective_categories = include − exclude`. `ExcludedAuthorContext(mode)` is a defined set from the context-mode policy; for `fresh_blind` it includes builder transcript/reasoning, prior reviewer verdicts and unaccepted memory.

FCD deterministically constructs canonical package bytes `B_{g,a}` from the effective manifest and records `package_hash_expected = H(B_{g,a})` before launch.

The adapter must independently compute `package_hash_observed` from the exact package bytes it submitted to the executor/model and return it with `attempt_id`, nonce, executor/session/run identity and executed-model receipt. FCD compares expected vs observed. The adapter may still lie; honest delivery is an explicit assumption, not a theorem. A simple echo unconnected to submitted bytes violates the adapter contract and is not accepted evidence.

## 7. Instruction layering

Prompts belong to semantic locations:

1. project instructions;
2. agent-profile instructions;
3. gate instructions;
4. work-item contract;
5. node-scoped steering events;
6. question answers.

Layers remain separate and versioned. They are not silent last-wins text concatenation.

Authority/precedence is:

1. project hard constraints and prohibitions;
2. agent authority/tool limits;
3. gate mission and context policy;
4. work-item contract;
5. node steering and question answers.

A lower layer cannot contradict or widen a higher layer. FCD detects a conflict while compiling the effective instruction manifest and blocks Admit with a visible question; it does not silently merge. The manifest preserves every source layer, conflict decision and final hash. New steering does not rewrite prior prompt history.

## 8. Agent/model/executor binding

A gate policy references all three separately:

```yaml
role: independent-review
agent: plan-reviewer@7
executor: claude-code@installed-profile
model:
  provider: anthropic
  api_id: claude-opus-4-8
  display: Claude Opus 4.8
context_mode: fresh_blind
memory_scope: accepted_only
cache_scope: attempt
```

The user may override before Admit. After Admit it is pinned. A running gate never hot-swaps agent, executor or model.

FCD requires adapters to emit:

- exact `attempt_id` and nonce;
- executor/session/run identity;
- independently computed `package_hash_observed` over bytes actually submitted;
- latest steering continuation sequence/hash acknowledged;
- declared model and provider route;
- executed-model receipt;
- tool/evidence/artifact events;
- terminal/death state.

Executor internals are outside the theorem. Receipt requirements and FCD transitions are inside it.

## 9. Cache boundary and telemetry

There are two distinct cache domains.

### FCD verified cache

The shipped `StageCache` remains **attempt-local**, one per stage runner, cleared on Admit/Close. It never reuses across gates, attempts, specialists or work items.

\[
fcd\_cache\_id = H(attempt\_id, executor, provider, model, P_v, K_v, W_r, G_r, A_r, specialist, I_h, C_p, T_h, S_0, continuation\_hash_n)
\]

A verified FCD cache hit requires full equality and cannot skip Observe or receipt checks. Any dimension change is a safe miss. This is I16.

### Executor/provider internal cache

Mature executors/providers may reuse their own project prefix, opaque session or provider cache. FCD does not implement, share or prove that cache. `executor_continue`/`executor_fork` are continuity hints under the adapter capability contract. The adapter may report reuse as **telemetry** (`reported_reuse`, opaque cache/session ID), but it is never a Pass authority and the UI must label it executor-reported, not FCD-verified.

FCD still sends the canonical package/delta required by policy, compares independent package receipt, records executed-model identity and applies Observe. An internal cache that injects hidden residue is a truthful-adapter/capability assumption failure, not an FCD cache hit.

Defaults:

- all FCD package modes: new attempt-local cache namespace;
- in-gate continuation: same attempt only, keyed by latest continuation hash;
- Close/Retry/new gate/new work item: FCD miss and clear;
- executor continuity: optional telemetry, never changes semantic manifest.

## 10. Project memory promotion and serialization

Only Accept may promote knowledge. Accept/promotion is globally serialized with compare-and-swap on expected `(P_v, K_v)`:

\[
CAS((P_v,K_v) \rightarrow (P_{v+1}, K_{v+1}))
\]

\[
K_{v+1} = K_v \oplus Promote(A_{accepted}, E, D)
\]

`Promote` is the sole writer of project memory and creates a reviewable knowledge delta containing accepted decisions, capability/interface changes, invariants, limitations, artifact references and evidence. It excludes hidden reasoning and raw transcript by default.

If two items Accept concurrently from the same base, one CAS wins. The other remains unpromoted, recomputes drift/impact against the new `(P,K)`, and must explicitly refresh/review before another promotion attempt. Version numbers therefore have one total order.

Candidate output, steering, questions and failed attempts remain work evidence but cannot become project truth.

## 11. Simultaneous work and time

If project state is `(P18, K12)` and A/B/C open, all pin `(P18, K12)`. FCD exposes sibling IDs/touched-capability summaries for collision detection, but does not inject raw sibling candidate context.

When A Accepts:

```text
P18 + accepted A → P19
K12 + accepted knowledge delta A → K13
```

B/C remain pinned to P18/K12. Every later gate inherits those Open-time versions. The impact engine classifies:

- unaffected: continue pinned;
- reachable impact: **block Accept** until a signed impact-review event approves continue-pinned or refresh;
- direct conflict/dependency: block and offer refresh/rebase/retry;
- unknown: block Accept in strict mode; a project policy may permit explicit owner override, but never automatic safety.

Refresh closes the current attempt and creates a new work revision/gate attempt/envelope against the newer `(P,K)`. A running gate cannot silently absorb P19/K13.

## 12. Node-scoped steering

Steering is an append-only event addressed to project, work item, gate, stage node, artifact or evidence/failure node. The selected scope is explicit in the UI and event.

Events present before Admit are summarized in frozen `S_0`. Events received during Running append to `J_{g,a}[n]`; they do not mutate the base envelope. The adapter must acknowledge the latest continuation sequence/hash before Pass. A contract/base-envelope-changing steering request cannot enter the running stream: it blocks and creates an explicit Close/Retry or new work item.

A steering event may affect only the permitted target/descendants within its work item. It cannot mutate accepted artifacts, siblings, project memory or another work item. Project-scoped steering changes project policy/instructions only through a new version and never rewrites in-flight envelopes.

## 13. Proposed invariants

### I10 — Base-envelope and work-snapshot pinning

`P_v`/`K_v` are write-once at Work Open. At Gate Admit, `envelope_hash_{g,a}`, attempt nonce and `S_0` are immutable until Close. Live steering is outside the base envelope and governed by I15.

### I11 — Manifest/package compliance

FCD deterministically computes `effective_categories = include − exclude` (exclude wins), canonical package bytes and `package_hash_expected`. Pass requires an adapter-computed `package_hash_observed` bound to the current attempt/nonce and equal to expected. Equality of physical model input is a truthful-adapter assumption, not this theorem.

### I12 — Independent-review manifest exclusion

For `fresh_blind`, define `ExcludedAuthorContext_g` from the mode policy. FCD proves:

\[
ManifestCategories_g \cap ExcludedAuthorContext_g = \emptyset
\]

and requires the independent package receipt of I11. Hidden executor-session residue/physical attention remains outside proof; `fresh_blind` forbids executor continuity hints.

### I13 — Accepted-knowledge promotion

Project memory changes only through globally serialized Accept/CAS and an accepted knowledge delta. A failed CAS cannot promote.

### I14 — No silent context drift

A work item cannot change Open-pinned `P_v`/`K_v` without explicit impact review, Close/refresh, a new work revision and new envelope.

### I15 — Steering scope

A scoped steering transition cannot write outside its allowed scope or write accepted state. A gate cannot Pass until an adapter receipt acknowledges the latest in-gate steering continuation hash.

### I16 — Cache identity

A verified FCD cache hit implies equality of the complete attempt-local cache identity including attempt nonce, context mode, `S_0` and latest continuation hash. Otherwise it is a miss and clear; executor/provider reported reuse is telemetry outside this theorem.

### I17 — Executor receipt binding

A gate cannot Pass unless independently computed package receipt, executor/run identity, latest steering continuation hash and executed-model receipt all carry the current `attempt_id`/nonce and bind to the current envelope. Prior/cross-attempt receipts fail closed.

## 14. Assumptions and proof limits

The extension assumes an honest adapter at the physical boundary: it computes the submitted-package digest from bytes it actually sends; truthfully reports opaque session/continuity state, executed-model identity and tool/artifact events; and does not inject hidden context contrary to its capability contract. A compromised adapter/provider may lie. FCD proves canonical package/manifest construction, receipt and attempt binding, state transitions and refusal behavior—not executor/model physics.

Executor/provider cache semantic neutrality and opaque session residue are assumptions/telemetry, not FCD theorems. `fresh_blind` therefore requires a capability that starts a fresh executor context and forbids continuity hints, but FCD still proves only the package and receipt boundary.

It does not prove model quality, tool correctness, complete test coverage or artifact usefulness. These remain evidence/acceptance questions.

Liveness is not claimed. A blocked executor, unavailable model, unanswered question, stale-memory impact review or required refresh may prevent Accept. Hash/model normalization collision resistance remains an assumption; collisions fail toward refusal.

## 15. Binding visual and interaction contract

The product remains three-pane and work-first:

```text
Project/capability atlas | Selected work line + bounded gate tray | Real artifact
```

It never introduces a primary sessions/transcripts route.

### 15.1 No-project / project entry

The same shell renders an explicit no-project state:

- top-left project switcher: `Open project…`;
- left pane: local path or GitHub owner/repo definition, verification status, recent projects;
- center composer disabled with `Load a project to start work`;
- right pane empty artifact explanation.

After verification, the top strip pins project ID, local/GitHub source, accepted `P_v`, memory `K_v`, policy, active lines, questions and drift count. Switching projects is explicit and never carries work/session context across projects.

### 15.2 Capability and sibling-line navigation

The left atlas organizes capabilities/components first. Expanding a component lists **every** work item (not only the first) with state, pinned `P/K`, question and drift badges. Selecting A/B/C changes the center line and artifact without opening a sessions page.

Top-strip counts are actions:

- active lines → filter/focus active work;
- questions → ordered list, select exact node;
- drift → filter affected lines, select required impact-review gate.

A drift line exposes `Impact review` with observed/reachable/unknown evidence and `continue pinned`, `refresh/rebase`, `retry`, or `discard` as policy-allowed actions. Reachable/direct conflict stays blocked until signed review; unknown follows project strict/owner-override policy.

### 15.3 Gate node density

Collapsed gate nodes show only:

1. state + one-sentence progress;
2. agent/profile;
3. exact provider/API model ID (display label secondary);
4. context mode.

Project/memory version, FCD cache, executor-reported reuse, executor/run and receipt status live in the gate tray. Semantic model comparison always uses provider-accepted API identity + executed-model receipt, never display-label prefix.

### 15.4 Pre-Admit editor vs post-Admit inspector

Clicking a selected gate opens a **bounded gate tray inside the center pane**, directly below the gate list, maximum 45% of center-pane height with internal scroll. Left atlas and right artifact remain visible. It never becomes a full-page session view or modal stack.

Before Admit, the tray is editable:

- agent/profile revision;
- executor capability/profile;
- provider + exact API model ID;
- FCD package mode;
- executor continuity hint (if capability permits);
- memory scope;
- FCD attempt-local cache policy;
- instruction layers/conflicts;
- tools/capability manifest;
- `Admit with this envelope` action.

The editor shows inherited project defaults and explicit overrides. Validation/conflict errors block Admit.

After Admit, the same tray becomes read-only and shows pinned attempt/nonce, package include/exclude, expected/observed package digests, instruction hash, tool manifest, steering sequence, executor/session/run receipts, declared/executed model, evidence and failure. Retry creates a new editable attempt; it never unlocks the old envelope.

### 15.5 Multi-scope steering

The bottom steering bar contains a required scope breadcrumb/chip:

```text
Project > Work W42 > Gate Review > Evidence E7
```

Clicking project, work item, gate/stage, artifact or evidence/failure changes the selected target. The input always states `Steering: <scope>` before submission. Commands unsupported for that scope are disabled/explained. Project steering creates a new project policy/instruction version; work/gate steering remains bounded by I15; accepted artifacts are never mutable.

### 15.6 Questions

A question pulses on its exact node. Clicking the top question count focuses the first unresolved node and provides next/previous navigation. The focused answer sheet is part of the gate tray or a small anchored popover; it does not replace the cockpit. Answer receipts and resulting steering sequence are visible.

### 15.7 Skins

Skins may alter composition/glyphs/motion within these surfaces but cannot hide state, exact API model identity, context mode, project/memory pin, cache authority label or receipt/failure. The no-project state, editable-vs-locked envelope distinction, sibling navigation, steering scope and impact actions are conformance requirements, not skin choices.

### 15.8 Binding user journeys

**J1 — First project and first line.** Empty shell shows Open project; composer disabled. Operator selects local/GitHub definition, verification pins project/P/K/policy, composer enables, prompt compiles contract, first gate tray opens editable, Admit locks it, artifact/evidence progress without a sessions page.

**J2 — Concurrent A/B/C and drift.** A/B/C appear as three selectable lines under one capability. A Accepts and advances P/K. B remains unaffected/pinned. C gets a drift badge; clicking drift count selects C and its impact-review tray. C cannot Accept until continue-pinned is signed or refresh creates a new work revision/attempt.

**J3 — Independent review model choice and receipt.** Operator selects an Open review gate, edits agent/executor/exact API model/package mode `fresh_blind`, sees inherited defaults/exclusions and admits. Tray locks. After run it shows expected/observed package hashes, attempt nonce and exact executed-model receipt. Any mismatch shows F1/receipt failure and no Accept.

**J4 — Scoped steering.** Operator selects artifact/evidence node, breadcrumb confirms scope, sends free steering or allowed slash command, event appears on that node. A contract-changing request blocks and offers new revision; sibling/accepted state stays unchanged.

## 16. Implementation cut after review

If this proposal passes all three reviews:

1. Add protocol schemas for project, agent, model, gate, attempt/envelope, FCD context package, adapter receipt, memory delta, impact review and steering scope.
2. Extend atlas with project/memory versions, every sibling work line, envelope/receipt nodes, questions and context-drift impact.
3. Extend FCD core with attempt identity/nonce, Open-time P/K pin, I10–I17 guards, serialized Accept/promotion CAS and deterministic tests.
4. Rename user-facing `HarnessAdapter` to `ExecutionAdapter`; preserve mature executor integrations; do not implement internal tools or session stores.
5. Add project loader/switcher (local/GitHub), model/agent/gate policy editors, FCD package-mode controls and executor continuity capability hints.
6. Add pre-Admit editable and post-Admit locked gate tray, multi-scope steering, sibling/drift/question navigation and exact model/receipt presentation.
7. Add deterministic mock adapters for FCD fresh modes plus declared-capability executor continue/fork tests; unsupported capabilities fail closed.
8. Update paper, invariants/proofs, metrics schema, README, PDF, wheel package data and screenshots.
9. Run full tests/audit/build/wheel/browser journeys at desktop and narrow viewport.
10. Freeze exact candidate, run at least three independent code/product/security reviews, fix/re-review, then open a PR. No merge.

## 17. Acceptance criteria for implementation

### Formal/authority

- [ ] Existing executor tool loops/session stores are not reimplemented.
- [ ] Work pins project/memory snapshot at Open; every gate inherits it.
- [ ] Every gate attempt has monotonic counter + nonce; prior/cross-attempt receipts fail closed.
- [ ] Agent, specialist, executor, exact provider/API model and instructions are separate versioned fields.
- [ ] Pre-Admit `S_0` is frozen; in-gate steering uses ordered continuation hashes and latest sequence must be acknowledged before Pass.
- [ ] FCD deterministically builds canonical package bytes and expected hash; mock adapter independently hashes submitted bytes.
- [ ] Fresh-blind manifest tests prove defined excluded categories absent; continuity hint is prohibited.
- [ ] Physical delivery/session residue is documented as honest-adapter assumption, not theorem.
- [ ] Accept/promotion CAS has one winner under concurrent Accept; failed CAS cannot promote.
- [ ] Context drift requires signed impact review; reachable/direct conflict blocks Accept; unknown follows explicit strict/owner-override policy.
- [ ] Instruction conflict test blocks Admit rather than silently last-wins.
- [ ] FCD cache is attempt-local, cleared on boundary, covers every identity dimension and never skips Observe.
- [ ] Executor/provider cache/session reuse is telemetry/capability only, never Pass authority.
- [ ] Node/project steering tests prove scope and no accepted-state/sibling mutation.

### Product/interaction

- [ ] No-project state gates composer and provides local/GitHub load + verification.
- [ ] Project switch cannot carry work/session context to another project.
- [ ] Atlas lists every sibling line under a component; A/B/C are independently selectable.
- [ ] Active/question/drift counts navigate to exact lines/nodes.
- [ ] Drift impact view exposes evidence and policy-allowed continue/refresh/retry/discard actions.
- [ ] Collapsed gate shows state, agent, exact API model and context mode without chip overload.
- [ ] Pre-Admit gate tray is editable; post-Admit same tray is locked and receipt-backed; left/right panes stay visible.
- [ ] Display model label is never used for semantic comparison.
- [ ] Steering scope breadcrumb supports project, work item, gate/stage, artifact and evidence/failure targets.
- [ ] Question navigation focuses exact node and preserves cockpit composition.
- [ ] UI remains project/work/artifact-first with no primary sessions/transcripts route.
- [ ] Skins cannot hide required semantic/authority surfaces or issue commands without explicit user action.

### Delivery

- [ ] Protocol schemas validate project/envelope/context/receipt/memory/impact/steering records.
- [ ] Adapter receipt mismatch, stale attempt receipt, stale steering sequence and executed-model mismatch each close fail-closed and cannot Accept.
- [ ] Paper clearly separates proved process properties from adapter/model/artifact assumptions.
- [ ] Full Python/atlas/UI tests, npm audit, production build, wheel install, browser journeys and screenshot matrix pass.
- [ ] Exact candidate receives three independent reviews before PR creation.

## 18. Round-1 review disposition

| Finding | Resolution |
|---|---|
| Steering hash vs immutable envelope | `S_0` frozen pre-Admit; live steering uses ordered continuation stream/receipt (Sections 4, 12, I10/I15). |
| Adapter receipt echo/vacuity | Canonical package bytes + expected hash; adapter independently hashes submitted bytes; truthful adapter remains assumption (Sections 6, 14, I11/I17). |
| Delivered-context claims mislabelled theorem | I11/I12 now prove manifest/package/receipt properties; physical delivery is explicit assumption. |
| Cross-attempt receipt replay | Attempt counter + nonce in envelope and every receipt; stale receipts fail closed. |
| Cache contradicts StageCache | FCD cache remains attempt-local; executor/provider cache is telemetry/capability only (Section 9). |
| Continue/fork reinvents sessions | Moved to executor continuity hints; FCD does not own/replay sessions and does not prove their residue/immutability (Section 5). |
| Stale-memory Accept ambiguity | Reachable/direct conflict blocks Accept; unknown strict/explicit-owner policy; signed impact review required (Section 11). |
| Instruction conflicts | Explicit precedence; lower layer cannot widen; conflict blocks Admit (Section 7). |
| P/K pin ambiguity | Work pins P/K at Open; all gates inherit; refresh creates new work revision (Sections 4, 11, I10/I14). |
| Concurrent memory promotion | Global Accept/CAS total order; loser cannot promote (Section 10/I13). |
| Missing project entry | Binding no-project state/project loader/switcher defined (15.1/J1). |
| Missing pre-Admit gate editor | Bounded center-pane gate tray editable before Admit and locked after (15.4/J3). |
| Sibling/drift navigation missing | Every sibling listed/selectable; actionable counts + impact review (15.2/J2). |
| Steering only stage-scoped | Explicit multi-scope breadcrumb and per-scope command authority (15.5/J4). |
| Model chip/display-label risk | Exact provider/API identity required; display secondary (15.3). |
| Chip density/inspector bound/questions | Collapsed priority defined; tray ≤45%; question count focuses exact nodes (15.3/15.4/15.6). |
