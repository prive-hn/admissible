# Context/memory/model envelope implementation receipt

Reviewed proposal: `docs/CONTEXT_MEMORY_MODEL_PROPOSAL.md` at commit `6de94ac30735150e058973cf56ef9ed20b32e67b`.

Proposal review result: three independent PASS verdicts covering formal methods, architecture/context/cache, and product/UX.

This receipt describes the implementation candidate before its final exact-tree reviews. It does not authorize merge.

## Authority core

`fcd/context.py` implements I10–I17:

- project/memory pin at Work Open;
- monotonic gate-attempt counter and unpredictable nonce;
- immutable base envelope and pre-Admit steering hash;
- canonical context package with exclude-overrides-include;
- adapter-observed package hash and exact executed model receipt;
- stale/cross-attempt receipt refusal;
- ordered scoped steering continuation chain;
- attempt-local FCD cache identity;
- signed drift impact review;
- serialized accepted-only project-memory CAS;
- append-only context journal.

The core proves FCD-owned state/manifest/receipt properties. Adapter honesty, physical prompt isolation, hidden executor residue, provider cache neutrality, model quality and impact-review correctness remain explicit assumptions or limits.

## Project and execution boundary

`server/project.py` verifies local Git repository, GitHub origin and base-branch existence. Project definitions separate:

- provider/API model identity;
- agent role, instructions, tools and authority;
- gate agent/executor/model/context/continuity assignments.

`server/execution.py` replaces the former harness boundary. Existing executors retain their tools, provider clients, sessions and internal caches. They return evidence and receipts but cannot Pass, Accept or promote memory.

Exact-route readiness is explicit and fail-closed: installed, authenticated, model resolves, project access, tools available, harmless canary, receipt support, death observability and declared-executor connectivity. An unavailable route cannot Admit and does not consume the open question.

## Protocol and atlas

New packaged schemas cover project, agent, model, gate, readiness, execution envelope, context package, adapter receipt, context journal, steering, impact review and memory delta. `protocol.schema_path()` provides traversal-safe lookup in the installed wheel.

`atlas/context.py` projects immutable project head, every sibling work line, locked attempts and active drift. Failed and accepted lines do not enter active drift navigation.

## Interaction layer

The cockpit remains project/work/artifact first. It has no sessions route.

Implemented surfaces:

- verified project load/switch; composer disabled without a project;
- every sibling line independently selectable;
- actionable active/question/drift counts;
- compact gate identity: agent, exact provider/API model, context mode;
- bounded gate tray, editable before Admit and locked after;
- visible agent instructions, tools and authority;
- model/executor readiness and unavailable-route refusal;
- package/model/steering receipts;
- anchored non-modal question sheet;
- observed/reachable/unknown drift review;
- project/work/gate/stage/artifact/evidence/failure steering scope;
- read-only skin conformance.

## Verification receipts

Canonical tests:

- 83 kernel/server/context/project tests;
- 37 atlas/protocol tests;
- 23 cockpit tests;
- 143 total, zero failures.

Additional receipts:

- TypeScript clean;
- Vite production build green;
- `npm audit`: 0 vulnerabilities;
- `fcd 0.4.0` wheel and sdist build cleanly;
- fresh wheel install contains public Context Authority API, bundled schemas and cockpit static files;
- installed server binds in the no-project state outside a Git checkout;
- research PDF: 9 pages, text layer present, no scanned pages;
- real isolated Chrome journey passed: load project, create W3, inspect pre-Admit instructions/readiness, answer anchored question, implement, run `fresh_blind` review, validate receipt, accept artifact;
- final steering target was `stage:W3.1`;
- no sessions navigation appeared and all three panes remained visible.

Figures:

- `paper/figures/context-cockpit-live.png`
- `paper/figures/context-cockpit-gate.png`

## Remaining admission gate

Freeze the complete candidate tree, run three independent read-only reviews on that exact tree, reconcile/fix any P0/P1 findings, then commit the reviewed tree and create a PR. No merge is authorized by this receipt.
