# Admissible Ready — implementation contract

Status: **shipped** in the private predecessor as Admissible Ready v0.7.
This file is the historical implementation contract, not live operator guidance.
Current operator docs: `docs/READY.md`, `docs/DEVELOPER_WORKFLOW.md`, `docs/GITHUB_ACTIONS.md`.

The original baseline and branch identities are deliberately absent from the
clean public repository history.

## Outcome

Admissible gives a person and a connected coding agent one shared answer for one exact Git commit:

1. what was checked;
2. what passed or failed;
3. what remains;
4. who or what can perform the next action;
5. whether the exact commit is admitted and current.

The normal loop is:

`change → check → fix the next item → recheck → ready`

The deterministic admission system remains the authority. Friendly labels are a presentation layer over existing canonical decisions and never replace them.

## Release cut

### Human surface

- `admissible check` evaluates `HEAD` by default with no signing credential and prints a concise, friendly result.
- `admissible check --json` emits the same versioned Ready document used by the UI and agent tools.
- `admissible ui` starts a loopback-only local application for the selected repository.
- The main UI answers: current outcome, whether the user is needed, what happens next, check progress, exact commit, and advanced evidence.
- A Connect agent flow asks only for agent name, day-to-day purpose, and runtime. It generates provider-specific setup for Claude Code, Codex, Hermes, or a custom MCP client.
- The UI can verify that an MCP session for that agent has actually connected; generated setup alone is not reported as connected.

### Agent surface

- `admissible mcp` is a dependency-free MCP 2025-06-18 stdio server.
- It exposes only:
  - `admissible_get_state` — latest Ready state for exact `HEAD`;
  - `admissible_get_work_package` — exact identity, task, policy class, capability boundary, and completion contract;
  - `admissible_check` — run the same deterministic preview checks as the human command;
  - `admissible_get_remediation` — ordered machine-readable next actions.
- Every tool returns `structuredContent` conforming to a declared output schema and also returns serialized JSON as text for compatibility.
- The agent never parses terminal prose.
- A new commit invalidates prior state naturally because every document binds repository, full commit SHA, tree SHA, policy digest, and attempt ID.
- Agent connection/session records are operational presence only. They grant no reviewer, observer, policy, signing, finalization, merge, or deployment authority.

### Local API

- `GET /api/v1/state` reads the latest Ready state and never runs checks.
- `POST /api/v1/check` runs the deterministic preview checks and returns Ready state.
- `GET /api/v1/agents` returns live, recently recorded MCP sessions for this exact repository.
- `POST /api/v1/connect` validates name, purpose, and runtime, then returns setup instructions; it does not edit provider configuration or claim a connection occurred.
- The server binds to `127.0.0.1` by default, validates `Origin` on mutations, bounds request bodies, serializes check execution per repository, and refuses to start while any Admissible signing/review/evaluation credential is present.

## Friendly state contract

Schema: `admissible/v0.7/ready-state`

| Friendly status | Canonical source | Default message |
| --- | --- | --- |
| `checking` | transient UI state | Checking this exact commit… |
| `needs_attention` | `REFUSED` / `NOT_READY` | A check needs attention. |
| `waiting_for_review` | `REFUSED` / `AWAITING_REVIEW` | Checks passed. Independent review is still needed. |
| `checks_complete` | `CHECKS_PASSED` / `READY_FOR_ATTESTATION` | Checks passed. Secure confirmation is next. |
| `ready` | authentic `CURRENT` admission for exact commit | This exact commit is ready. |
| `unable_to_check` | `BLOCKED`, malformed/unavailable state | Admissible could not safely check this commit. |

Every document includes the untouched canonical state/readiness/standing under `canonical`.

## Next-action contract

Each next action has stable fields:

```json
{
  "id": "fix_check",
  "title": "Fix unit tests",
  "detail": "The unit check failed for this commit.",
  "owner": "agent_or_human",
  "kind": "repair",
  "reason_codes": ["failed_check"],
  "command": "python -m unittest ...",
  "retryable": true
}
```

Allowed owners are `agent_or_human`, `human`, `reviewer`, and `trusted_infrastructure`. Agents must stop when no action is owned by `agent_or_human`.

## Security invariants

1. `check`, `ui`, and `mcp` execute or can trigger candidate-controlled commands; they refuse to run while any admission, reviewer, or evaluation signing credential is present.
2. No Ready endpoint or MCP tool can trust/revoke policy, sign reviews, attest evaluations, finalize, issue receipts, merge, deploy, or impeach.
3. UI and agent results never translate preview success into `ADMITTED` or authentic `CURRENT` standing.
4. Connector configuration stores no secrets and never implies review independence.
5. All repository paths are canonicalized; selected repositories must remain Git repositories with `.admissible.json` under the root.
6. HTTP is loopback-only by default; mutation requests require a matching local Origin and bounded JSON object.
7. Stdio stdout contains JSON-RPC messages only. Diagnostics go to stderr.
8. Tool inputs are closed and bounded. Unknown keys, oversized text, relative/short SHA repair attempts, hostile JSON, symlinks, and stale identities fail closed.
9. Existing eight profiles, Python 3.10+, zero mandatory dependencies, SQLite receipts, standing, and all v0.6 canonical state strings remain unchanged.
10. The deterministic path makes zero LLM calls. Agent execution remains external.

## Acceptance tests

### Ready document

- passing checks map to `checks_complete`, not `ready`;
- missing independent review maps to `waiting_for_review` and a reviewer-owned action;
- failed required check maps to `needs_attention` and ordered repair action with stable reason code;
- blocked identity/config maps to `unable_to_check`;
- an authentic current receipt maps to `ready`;
- a stale/dirty/new commit cannot inherit the prior attempt or Ready label;
- JSON validates against the packaged Ready schema.

### Friendly CLI

- `admissible check --repo REPO` defaults to full `HEAD` and runs real configured checks;
- plain output leads with one friendly sentence and one next action, with canonical details behind a technical section;
- JSON is stable and contains no logs or credentials;
- existing `run`, `explain`, `status`, and exit semantics do not change.

### MCP

- official initialization lifecycle, `tools/list`, and `tools/call` work over newline-delimited UTF-8 JSON-RPC;
- requests before initialization, unsupported protocol versions, unknown tools, malformed arguments, batch/oversized input, and non-object messages fail without traceback or stdout contamination;
- all four tools bind output to exact repository/commit/tree/policy;
- check tool strips no secret silently: server startup refuses a signing-bearing environment;
- read tools never execute checks;
- one live session becomes visible to the UI API and disappears after its process is gone or its bounded lease expires.

### UI/API

- production build is packaged and served by `admissible ui`;
- disconnected/empty/failure states are honest and useful;
- Connect agent returns provider-specific copyable configuration and never says connected until a live MCP session exists;
- main viewport shows only the outcome, progress, next action, and activity; hashes/evidence/trust internals are under Advanced details;
- keyboard navigation, visible focus, semantic headings, status text, 44px targets, responsive layout, reduced-motion support, and non-color status cues are covered;
- real browser can run a check and render the returned exact attempt.

## Implementation sequence

1. Add RED Python contracts for Ready mapping, `check`, MCP, session registry, and HTTP API.
2. Implement `admissible.ready`, the packaged schema, and friendly CLI.
3. Implement private agent session registry, connection-instruction generator, and MCP stdio server.
4. Implement loopback HTTP server and API.
5. Add `apps/ready`, frontend tests, production build, and package static assets.
6. Run a real temporary-repository canary through CLI, MCP, API, and browser.
7. Run focused, full, compatibility, packaging, actionlint/shell, audit/build, secret scan, and sabotage gates.
8. Freeze exact commit/tree and obtain independent read-only security/protocol, UX/accessibility, and compatibility reviews. Any source repair invalidates the review batch.
9. Only after exact-head convergence: push, open the PR, read back its identity, request final review, and merge only if separately authorized.

## Explicit non-goals for v0.7

- Admissible does not become an agent runner or model router.
- It does not write Claude/Codex/Hermes configuration automatically.
- It does not grant agents merge/deploy/signing authority.
- It does not duplicate CI, tests, scanners, or external review systems.
- It does not replace the research cockpit or expose kernel research concepts in the default Ready interface.
- It does not implement remote multi-tenant hosting; the first UI/API is local and loopback-only.
