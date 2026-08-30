# Interaction layer

Status: implemented in `apps/cockpit/` and `server/`.

## Product hierarchy

FCD is not a sessions application. The visible hierarchy is:

```text
Project → capability/component → work item → gate → evidence/artifact
```

Executor sessions and cache IDs appear only as receipt evidence inside a gate tray.

## Reading the system before opening work

Two surfaces answer questions an operator has before any line exists, both in
the command rail:

- **Models** — every exact provider model the project can bind, which gate uses
  it, which adapter runs it, and each readiness check with the reason it
  matters. A route with any declared check false cannot Admit, and an adapter
  that reports nothing is shown as unknown rather than assumed available.
- **Legend** — every term the instrument uses, in plain words, next to the rule
  it comes from.

## Vocabulary

The instrument keeps the paper's words — they are the words in the journal, the
schemas and the proofs — and attaches a plain reading to each. Every machine
term carries a hover/focus card, and **Legend** in the command rail opens the
full searchable mapping. `docs/UI_GLOSSARY.md` is the same table in prose, and
`apps/cockpit/src/domain/glossary.ts` is the single source both read from. A
gloss may never soften a guarantee: reachable does not become affected, unknown
does not become safe, candidate does not become done.

## Project entry

The composer is disabled until a project is verified. `Open project…` accepts:

- local Git repository path;
- GitHub `owner/repo` identity;
- base branch.

The loader verifies `.git`, `origin`, and base-branch existence. A feature branch is allowed. The project strip shows current branch, accepted project version `P`, memory version `K`, policy, active lines, questions and drift. Switching projects changes the whole runtime; work/session context does not cross projects.

## Composition

The reference view puts three panes side by side. That is the default, not the
product: a skin may replace the whole main region (see `SKIN_PROTOCOL.md`), and
`Focus` ships as a single-column example with no panes at all.

What "locked composition" actually means is narrower, and it survives any
skin: the atlas, the live line and the artifact stay **reachable together**
without navigating away, and the shell's spine — rail, refusal strip, steering
bar, settings — cannot be removed by a skin.

In the reference view all three panes remain visible:

1. capability/outcome atlas with every sibling work line;
2. selected work item rendered as a load path, with each gate's envelope inline
   beneath it and an item-scoped impact banner above;
3. runnable artifact and evidence.

The centre pane is one scroll column. A gate's envelope belongs to that gate and
renders under it rather than in a separate tray competing for the same space.

Pane widths belong to the operator: the dividers are `separator` controls with
arrow-key, Home/End and Enter-to-reset support, either side pane collapses to a
stub, and both survive a reload. Text size and density are operator settings
too — text scales `--type-rem` alone, so gaps, controls and radii keep their
size and the layout does not stretch with the type.

## The load path

A line is drawn as a load path, because that is what the machine's semantics
already say: each gate holds or shears.

- **held** — filled marker, continuous rail;
- **holding** — lit marker, the only motion on the instrument;
- **broke** — the rail *shears*: two offset bars at the break, a dashed rail
  below it, and the published fault stamped on the gate;
- **not reached** — hollow marker, dashed rail, dashed card. A fail-closed break
  means downstream gates did not run, so they are never drawn as merely queued;
- **terminal** — a finished line ends in a cap: sealed, or closed for good.

## Gate interaction

A collapsed gate shows:

- state and one-sentence progress;
- agent/profile;
- exact provider/API model identity;
- context mode.

Before Admit, the tray edits agent, execution adapter, exact model, FCD context mode and executor continuity hint. It shows the selected agent instructions, tools and authority. Each exact model carries explicit readiness checks: installed, authenticated, model resolves, project access, tools available, canary, receipt support and death observability. A route with any required check false cannot Admit. Project defaults remain visible. `fresh_blind` forces fresh continuity.

After Admit, the same tray is locked. It shows attempt ID/nonce, project and memory pin, package status, receipt status, exact executed model and executor-reported cache telemetry. A closed attempt remains inspectable. Retry creates a new editable attempt; the old one never unlocks.

## Context drift

Concurrent lines pin the project/memory head at Open. If another accepted line advances the head, active stale lines get a drift badge. The impact tray separates:

- observed: the accepted head changed;
- reachable: declared dependency/capability paths may intersect;
- unknown: untraced paths are not asserted safe.

Reachable drift blocks final Accept until a signed `continue_pinned` review. `refresh` does not authorize the stale final gate. Failed and accepted lines do not enter active drift navigation.

## Questions and steering

Questions pulse on the exact node. The answer sheet is anchored and non-modal, so the cockpit stays visible.

The bottom input has an explicit scope selector:

```text
project → work → gate → stage → artifact → evidence/failure
```

Plain text emits a steering event. Commands are `/inspect`, `/why`, `/impact`,
`/fix`, `/run`, `/retry`, `/pause`, `/discard`, `/accept`. `/run` and `/retry`
do the same work under two honest names: a gate that has never run is being
started, not retried.

Steering is not the only way to run a gate, and it should not be the first one
an operator finds. The envelope carries an explicit **Admit and run this gate**
control, and when holding that gate would accept the whole line the control
says so on its face, because Accept writes the store. Unsupported actions stay bounded by scope. Accepted artifacts are immutable.

## Contract compilation

The authority compiles the contract, not the cockpit. `POST /api/work-items/compile`
returns the class, required gates, allow set, acceptance mode and policy version
straight off the live policy, and opens nothing. The composer shows exactly that
and commits it. A locally guessed contract is only ever shown on the labelled
disconnected surface, and the card says so and refuses to commit.

## Authority

- The cockpit submits intents. It never writes accepted state.
- Execution adapters produce candidates, evidence and receipts. They cannot Pass or Accept.
- `fcd` performs Admit, Bind, Observe, Pass/PassRefuse and Accept.
- `ContextAuthority` pins envelopes, validates receipts, scopes steering and serializes accepted-only memory promotion.
- Skins are read-only projections.

## API

- `GET /api/state`
- `GET /api/state/stream` (SSE; one frame per revision, polling is the fallback)
- `GET /api/events`
- `GET /api/projects`
- `POST /api/projects/load`
- `POST /api/projects/{id}/select`
- `POST /api/work-items/compile` (contract preview; opens nothing)
- `POST /api/work-items/{id}/action` accepts `run` alongside `retry`
- `POST /api/work-items`
- `POST /api/work-items/{id}/gates/{gate}/configure`
- `POST /api/work-items/{id}/impact-review`
- `POST /api/work-items/{id}/steer`
- `POST /api/work-items/{id}/action`
- `POST /api/questions/{id}/answer`

The server accepts snake_case and typed-client camelCase at the boundary.

## Reference flow

`DemoExecutionAdapter` produces runnable HTML and independently reports executed model identity. Seed data contains one accepted line and one real F1 refusal. The real Chrome journey in `paper/figures/context-cockpit-gate.png` creates a third line, answers its question, runs implementation, admits a `fresh_blind` review, validates the receipt, and accepts the artifact without opening a sessions view.
