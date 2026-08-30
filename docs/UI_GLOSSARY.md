# UI glossary

Maps the paper's vocabulary to what the cockpit shows. An engineer should be
able to operate the instrument without reading `paper/DRAFT.md`; this file is
the bridge. The UI ships its own copy of these readings in
`apps/cockpit/src/domain/glossary.ts`; the two are mirrored by hand and kept
aligned in review — where they differ, the glossary in the code is what the
cockpit actually shows.

Sources of truth: `paper/INVARIANTS.md` (assumptions A0–A13, transitions,
theorems I1–I17), `paper/DRAFT.md` (fault table), `fcd/core.py`,
`fcd/context.py`.

Implementation: `apps/cockpit/src/domain/glossary.ts` holds the UI's table and
feeds both the inline hover cards (`Gloss`) and the **Legend** panel in the
command rail. Change one, change the other — by hand; there is no generator.

## Rules for this vocabulary

1. **Plain phrase first, exact term kept.** The machine's words are
   load-bearing and appear in the journal, the schemas and the proofs. The UI
   keeps them and attaches a plain reading, rather than renaming them into
   something friendlier that no longer matches the record.
2. **No softening.** A gloss may not weaken a guarantee. "Reachable" never
   becomes "affected", "unknown" never becomes "safe", "candidate" never
   becomes "done".
3. **Derived, not invented.** Every plain sentence restates something the
   transition table, an invariant or the code already says.

## Objects

| Paper / code | UI shows | Plain reading |
|---|---|---|
| work item, `status ∈ {open, failed, accepted}` | **Line** — centre pane title, atlas rows | One unit of work taking form through its required gates. It ends as an accepted artifact, or it stays closed. |
| stage, `Required(c)` | **Gate** — a card on the load path | One required stage of a line. Each gate binds an agent, one exact model and a context policy. |
| write stage | `WRITE` tag | Produces the work. Whoever passes it is recorded as an author of the line. |
| check stage, `π_chk` (A6, I6) | `CHECK` tag | Reviews the work. It cannot admit anyone who authored this line. |
| `c` (I4) | `class` in the line header | What kind of work this is. It decides the allow set and the required gates, and it is fixed the moment the line opens. |
| candidate | `CANDIDATE` seal, artifact pane | Produced but not accepted. It sits outside the store and can still be retried or discarded. |
| `id ∈ S` (I8) | `ACCEPTED` seal | Accepted and immutable. A fix is a new line, never an edit of this one. Accepted is the identity layer's word; sealed is the scrutiny layer's, and it is stronger. |

## Lifecycle

| Paper / code | UI shows | Plain reading |
|---|---|---|
| Open (I4) | gate state `open` | The line starts. Its class and body are fixed here and can never be rewritten. |
| `Admit(a)`, `a ∈ π*(c) \ δ(c) \ tried` | "Admit and run this gate"; the envelope reads "Editable before Admit", "Retryable", "No specialists left to try", or "Locked at Admit" | The machine takes one specialist from the allow set. Admitting freezes the envelope: agent, exact model, context package and steering base stop being editable. |
| Bind, `m_decl ← φ(a)` | `declared …` in the route row | The machine writes down which exact model it intends to use. Intent only, never what ran. |
| Observe, `m_exec ← m` (A1) | `executed …` in the route row | The provider reports which model actually ran. The only place executed identity is written. |
| Pass, `norm(m_exec)=norm(m_decl)` (I1) | gate state `held`, green load-path segment, `MATCH` | The gate holds. Allowed only when the model that ran matches the model that was bound. |
| PassRefuse / Close, `pub=1` | gate state `broke`, the **shear** in the load path, `F…` stamp | The gate broke and the break was published. Nothing downstream runs. |
| (no hop transition) | "The line never hops out of it" under Recovery | Silently continuing on a different model after a break. This machine has no such transition. |
| Retry (I9, A7) | "Run this gate again" in the envelope, "Retry inside allow set" in recovery | Reopen the same gate with a different allowed specialist. The contract is never rewritten, and a specialist already tried is not offered again. |
| Accept (A8, I5) | Accepted seal, "Accept is the only writer" | The only writer of the store. Every required gate must have held first. |
| `pc=Open` below a `Closed` stage, line finished | **not reached** badge, dashed rail and card | This gate never ran. Not queued work — work that did not happen. |
| `pc=Open` below a `Closed` stage, line still open | **not started** badge | An earlier gate broke, but the line is still open. This gate runs only if that gate is retried and holds. |
| watchdog (A2, A9) | — (server side) | Runs outside the worker and reports its death. It can only close a line, never accept one. |

## Route

| Paper / code | UI shows | Plain reading |
|---|---|---|
| `π*(c)`, `π_chk` (A6) | "allow set" in the contract card and recovery hint | The specialists this gate may admit. On a check gate it excludes everyone who authored the line. |
| `δ(c)` (A0) | deny set (settings/policy) | Specialists this class may never admit. Deny always overrides allow. |
| `φ` | `provider / api_id` in the route row | Which exact provider model each specialist resolves to. |
| `norm(x)=norm(y)` (A5) | `MATCH` / `MISMATCH` verdict | Two model names match only as API identities. Vendor prefixes count; a display suffix is not an identity. |
| policy version | `policy …` chip | The identity of the rules this line runs under. A line finishes under the version it opened with. |
| `ExecutionAdapter` | "Execution adapter" field | The outside worker that runs the gate. It produces candidates and receipts; it can never pass or accept. |
| `execution-readiness.schema.json` | "Route ready" / "Route not ready" with the failing checks named | Explicit checks that this exact provider route can run now. Any failed check blocks Admit rather than degrading quietly. |

## Context envelope

| Paper / code | UI shows | Plain reading |
|---|---|---|
| `X`, nonce (I10) | the gate envelope panel | The frozen record of one attempt: agent, exact model, context package and the steering it started from. |
| `ContextPackage` (I11) | `package` receipt row | The exact bytes handed to the executor. A pass requires the executor to report back the same hash the machine expects. |
| `AdapterReceipt` (I17) | `receipt valid` / `receipt missing` | The executor's statement of what it ran and what context it received. A stale or mismatched receipt refuses the pass. |
| steering continuation (I15) | steering readout in the command bar | Steering is evidence the run must acknowledge; it cannot rewrite the contract. |
| `project_shared` \| `fresh_scoped` \| `fresh_blind` \| `contract_only` | Context select, each with its own sentence | What the executor is given. `fresh_blind` (I12) excludes the author's transcript, reasoning and prior verdicts, and forces a fresh session. |
| `fresh` \| `executor_continue` \| `executor_fork` | Continuity select | Whether the executor starts a new session, resumes its own, or forks it. The last two need declared adapter capability. |
| current `(P_v, K_v)` | `project … · memory …` in the command rail | The versions accepted **right now**. A line pins these when it opens and finishes against the pin even after the head moves on. |
| `(P_v, K_v)` write-once at Open (I10, I14) | `project pin` on the gate receipt | The versions this line opened against. They never change underneath it. |
| ImpactReview (A12, I13) | **drift** flag and the impact-review banner | The accepted project moved on after this line opened. The line keeps its pin; the impact must be reviewed before Accept. |
| telemetry outside the transition table | `executor cache` receipt row | What the executor says it reused. Its own report, unchecked, and **no guarantee rests on it**. |
| FCD cache (I16) | — (not yet surfaced) | The machine's own cache identity, tied to one attempt, envelope and continuation. Distinct from the row above. |

## Admissibility (layers R and C)

The scrutiny and standing layers (`rga/core.py`, `rga/calibration.py`; papers
`paper/RGA/DRAFT.md`, `paper/admissible/DRAFT.md`). The terminal on an
accepted line repeats the server's admissibility sentence verbatim, and its
tone may never outrun the record: amber for accepted-without-seal, the broke
tone once a line is no longer admissible.

| Paper / code | UI shows | Plain reading |
|---|---|---|
| `admissible(id) := id ∈ S_R ∧ mediated ∧ ¬tainted ∧ ¬impeached` | **layer** chip `I` / `IR` / `IRC` in the line header | Which layers' guarantees govern this line. I: the identity layer alone — nothing beyond class dispatch is claimed, and the line's own state says how far it got. IR: it also sealed under scrutiny, but the calibration authority never counter-signed the seal, so its standing is not tracked. IRC: all three. A missing letter is a smaller claim, never a weaker version of the next one. |
| `mediated(id)`: one `cal_stamp` bound to `seal.sealed_at` (C5) | terminal label **Sealed — layer IR, not mediated** when absent | The calibration authority counter-signed this seal: exactly one track-record stamp, bound to this seal and no other. Without it the line sealed at the scrutiny layer only — it reads IR, and it is not admissible. |
| Seal, `id ∈ S_R ⊆ S` (R1, R8) | terminal label **Sealed** | The scrutiny layer's acceptance. A line seals only after its samples survived every pinned refuter, and the seal carries the measured strength of that scrutiny. Write-once; nothing on it can be raised later. |
| accepted, not sealed | terminal label **Accepted — layer I**, with the refusal reason | The identity layer accepted it, the scrutiny layer could not. The reason is stated, never a smaller green. |
| `admissible(id)` = sealed ∧ mediated ∧ ¬tainted ∧ ¬impeached — pure queries (C3, §8.2) | `admissible` / `not admissible` chip | Counter-signed, not tainted, not impeached — right now. A live query against the escape ledger, never a stored flag: recomputed on every read, so it cannot be set. What the ledger cannot see is an entry deleted from its own record. |
| impeached(id) entailed by a valid escape (C3); tier A past kernel checks, tier B past adjudication (C1) | terminal label **Impeached** | A valid escape stands against a sealed claim: either the seal's own pinned refuter, re-run at an input a finder chose, killed the artifact (automatic once replayed), or another checker did and an adjudicator accepted the claim-match. The seal never rewrites; the record of the find stands beside it, and it lapses only by journal facts — a discredited checker — never by discretion. |
| tainted(id): sealed line relied on a refuter refused after sealing (§4; refusal is R5-monotone) | terminal label **Tainted** | A refuter this seal relied on was later caught giving different answers on replay. Everything that trusted it is marked, monotonically — the mark never comes off. |
| power = kills/\|D\| or 1−(1−ε)^N (R2) | `power …` chip | How hard the refuters actually tried, as a number the kernel counted: kills over a named defect set, or a bound computed from declared trial parameters. Never a scalar anyone wrote down. |
| witness agreement at θ (R4) | `concordance (agreeing, k)` chip | Whether independent samples agreed on the claim's observable behaviour. At k=1 it is visibly unmeasured, not silently perfect. |
| `seal.residual` — check_stage requires a Passed check stage (§4, V15) | `residual` chips on the terminal | What the seal does not cover: every claim that was not attacked by any refuter, named on the seal with how it was left — reviewed at a check gate, or not reviewed at all. |

## Certainty bands

`docs/EVIDENCE_MODEL.md` requires these three to stay disjoint. The UI prints
each definition next to its band, every time.

| Band | Plain reading | Rendering |
|---|---|---|
| **Observed** | It happened, and the journal shows it. | Oxide top rule |
| **Reachable** | Analysis proves it may be affected. It has not been seen. | Amber top rule |
| **Unknown** | The evidence does not bound it. Not a list of safe things. | Neutral top rule, hatched ground |

## Fault codes

Stamped on a gate that broke. Hovering the stamp shows the plain reading.

Each code is shown on screen with its complete name, because a bare `F1` is as
unreadable as a bare `P2 · K2`.

| Code | Name shown on screen | Plain reading | Formal |
|---|---|---|---|
| F1 | executed model did not match the bind | The model that ran was not the model that was bound. | Pass with `norm(m_exec) ≠ norm(φ(a))` |
| F2 | two specialists shared one runtime instance | Two specialists shared one runtime instance. | needs a runtime-instance field to measure |
| F3 | the bound model was unusable | The bound model was unusable, or a call continued outside the unused allow set instead of failing closed. | after `u = 0`, another call without fail-closed |
| F4 | the worker died with no published close | The worker exited while the gate was running and no close was published. | Running exit with no published close |
| F5 | the mapped model is not an API identity | The mapped model is not a real API identity. | `φ(a)` not an API identity |
| F6 | passed on a denied specialist | A gate passed on a denied specialist. | Pass with `a ∈ δ(c)` |
| F7 | a check gate admitted an author of this line | A check gate admitted someone who authored this line. | check admit with `a ∈ authors` |
| F8 | ran without a well-formed gate | Something ran without a well-formed stage. | run without a well-formed stage |
| F9 | stopped while not accepted | The line was stopped in conversation while it was not accepted. | Stop in chat with status not accepted |
| F10 | the class changed, or a tried specialist was retried | The same id came back with a different class, or a specialist already tried was retried. | same id, class changes; or retry of `a ∈ tried` |

## Gate states

The label at the right of every gate card.

| `pc` | UI label | Meaning |
|---|---|---|
| `Open` | `open` | Declared, not yet admitted. |
| `Admitted` | `admitted` | A specialist is taken; the envelope is frozen. |
| `Running` | `running` | Bound and executing. |
| `Passed` | `held` | Executed identity matched the bind. |
| `Closed` | `broke` | Broke and published. Nothing downstream ran. |
| `Stopped` | `stopped` | Closed and deliberately ended. |

## Surfaces

| Question an operator asks | Where the cockpit answers it |
|---|---|
| What will this prompt actually enforce? | The contract card, compiled by the authority before anything opens |
| Which models can this project run, and can they run now? | **Models** in the command rail — every route, the gate that uses it, and each readiness check |
| What does this term mean? | Hover any dotted term, or **Legend** in the command rail |
| What did this attempt actually bind and execute? | The gate receipt: route configured, bound this attempt, executed |
| Why did it break, and what is still safe? | The failure card: what happened, what remains safe, three certainty bands, evidence, recovery |
| What did the authority refuse? | The refusal strip, which does not time out |

## Where the vocabulary is enforced

- `apps/cockpit/src/domain/glossary.ts` — the table, typed.
- `apps/cockpit/src/components/Gloss.tsx` — inline hover/focus cards.
- `apps/cockpit/src/components/LegendPanel.tsx` — the searchable legend, opened
  from **Legend** in the command rail.
- `server/app.py` `_event_label` — evidence rows read as sentences, with the
  exact payload one click away.
