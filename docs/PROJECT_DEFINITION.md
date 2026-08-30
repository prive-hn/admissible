# Project definition

FCD work starts inside a verified project. It does not start in a global prompt or executor session.

## Source identity

`POST /api/projects/load` requires:

```json
{
  "id": "example",
  "name": "Example project",
  "local_path": "/absolute/path/to/repo",
  "github": "owner/repo",
  "base_branch": "main"
}
```

The server verifies:

- the local path is a Git repository;
- `origin` matches `owner/repo`;
- the declared base branch exists locally or on `origin`;
- the current feature branch and exact HEAD are recorded.

The simple cockpit loader submits these fields and installs the reference model/agent/gate defaults. A full project definition may supply all three arrays below. Supplying only one or two fails closed.

## Models

Models use provider-accepted API identity. Display labels are presentation only.

```json
"models": [
  {
    "id": "build-model",
    "revision": 1,
    "provider": "provider-a",
    "api_id": "exact-build-api-id",
    "display": "Build model",
    "context_profile": "128k",
    "reasoning": "high"
  },
  {
    "id": "review-model",
    "revision": 1,
    "provider": "provider-b",
    "api_id": "exact-review-api-id",
    "display": "Review model",
    "context_profile": "1m",
    "reasoning": "high"
  }
]
```

Each loaded model receives an execution-readiness receipt bound to executor, provider and API ID. `ready=true` is the conjunction of installed, authenticated, model resolves, project access, tools available, harmless canary, receipt support and death observability. An unavailable route cannot Admit.

## Agents

An agent definition is role, instructions, tools and authority. It is not an executor or model.

```json
"agents": [
  {
    "id": "builder",
    "revision": 1,
    "name": "Builder",
    "instructions": "Implement the visible contract.",
    "default_model_id": "build-model",
    "tools": ["read", "write", "test", "build"],
    "authority": ["implement"]
  },
  {
    "id": "reviewer",
    "revision": 1,
    "name": "Independent reviewer",
    "instructions": "Review independently. Do not implement.",
    "default_model_id": "review-model",
    "tools": ["read", "test"],
    "authority": ["review"]
  }
]
```

The pre-Admit gate tray shows the selected instructions, tools and authority. Changing the profile changes the compiled instruction manifest for the new attempt. It never rewrites an admitted envelope.

## Finding a project

An operator should not have to recall an absolute path to open work, and the
browser cannot read a filesystem, so the server discovers repositories:

```text
GET /api/projects/discover?q=<filter>
  -> { roots: [...], candidates: [{ local_path, name, github, base_branch, current_branch }] }
```

The client sends a filter, never a directory, so discovery stays confined to
the server's own roots. Those are `FCD_PROJECT_ROOTS` (colon-separated) when
set, otherwise the conventional folders under `$HOME` that exist — `repos`,
`src`, `code`, `Projects`, `dev`, `git`, `work`, `Developer`. The walk is
bounded to three levels and treats a repository as a leaf.

Each candidate carries its own `origin` remote and base branch, read with git.
That is the point: picking a repository fills the GitHub identity from the
repository itself rather than from memory, which removes the "local origin does
not match GitHub definition" refusal as a class. A repository with no origin
remote is offered but not loaded — the cockpit will not invent an identity for
it, and says so.

The searched roots are shown in the picker, and typing a path by hand remains
available for anything outside them.

## Classes: kinds of work

`Required(c)` is a function of the class (A4), so the class is where "which
specialists must touch this" is decided. A class is an ordered list of declared
gates:

```json
"classes": [
  {"id": "investigate", "name": "Investigate",
   "summary": "Answer a question about the repository. One specialist answers; nothing is built.",
   "gate_ids": ["answer"], "hints": ["investigate", "why", "explain", "audit"]},
  {"id": "feature", "name": "Feature or fix",
   "summary": "Build the work, then have a specialist who did not build it review it.",
   "gate_ids": ["implement", "review"], "hints": ["add", "build", "fix", "refactor"]}
]
```

**A class is a promise, not a tier.** `investigate` promises provenance: an
admitted specialist on a bound model answered, and nothing is sealed unless the
model matched. `feature` promises that *and* dual control. Nothing in A4
requires two gates — a one-gate class is fully sound and simply makes a
narrower promise.

Gate ids must be unique project-wide. A specialist is `agent:gate` and `phi` is
keyed by specialist, so two gates sharing an id would collapse to one model
binding — a wrong bind with no error. Load refuses it.

## Intake: proposing a class

The class is write-once at Open (I4), so choosing it chooses how much scrutiny
the work gets. A wrong choice accepted silently would be a hop in requirement
space rather than model space. So intake **proposes and never decides**:

- `class-inferred` (default) reads `hints` from the prompt. If nothing matches
  it falls back to the class with the **most** gates, never the fewest, and the
  contract says it did.
- `explicit-class` — the operator names it.
- `guarded` — an unreadable prompt refuses intake instead of guessing.

The compiled contract carries `classChosenBy` (`intake` / `operator` /
`default`), and the composer lets the operator switch to any declared class and
recompile. All of that happens before Open, where nothing is committed yet.

Needing a class that does not exist is a **policy change**: a new version, with
in-flight lines untouched by construction.

## Gates

A gate binds agent, execution adapter, exact model and context policy:

```json
"gates": [
  {
    "id": "implement",
    "revision": 1,
    "name": "Implement",
    "agent_id": "builder",
    "executor_id": "configured-adapter",
    "model_id": "build-model",
    "context_mode": "project_shared",
    "continuity": "fresh",
    "kind": "write"
  },
  {
    "id": "review",
    "revision": 1,
    "name": "Independent review",
    "agent_id": "reviewer",
    "executor_id": "configured-adapter",
    "model_id": "review-model",
    "context_mode": "fresh_blind",
    "continuity": "fresh",
    "kind": "check"
  }
]
```

`kind` is `write` or `check` and is **declared, not derived from position**.
Only a check gate excludes the authors of the line (A6, I6), so inferring it
from list order made dual control an accident of ordering.

Valid FCD package modes are `project_shared`, `fresh_scoped`, `fresh_blind`, and `contract_only`. Executor continuity is `fresh`, `executor_continue`, or `executor_fork`; the latter two require declared adapter capability. `fresh_blind` always requires `fresh`.

## Inheritance and lock

Instruction sources remain separate:

1. project hard constraints;
2. agent authority/instructions;
3. gate mission/context policy;
4. work contract;
5. scoped steering and question answers.

A lower layer cannot widen a higher prohibition. A deterministic conflict blocks Admit. Before Admit, agent/model/context defaults can be overridden for that work/gate. After Admit, attempt ID, nonce, model, package, instruction hash and steering base are locked. Retry creates a new attempt.

Schemas:

- `project-definition.schema.json`
- `model-definition.schema.json`
- `agent-definition.schema.json`
- `gate-definition.schema.json`
- `execution-readiness.schema.json`
