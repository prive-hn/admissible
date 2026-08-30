# Admissible Runtime and Authority Separation Implementation Plan

> **For Hermes:** Use `subagent-driven-development` to implement this plan task-by-task. This document is plan-only; it does not authorize implementation, publication, merge, or release.

> **Status:** Historical implementation plan. The runtime/authority split, artifact gates, exact-candidate reviews, PR, and merge were completed before the 0.8.0 public release. The proposal below remains in future tense as a decision record and is not operator guidance. For the built tree, read `README.md`, `packages/{core,ready,trust,umbrella}/README.md`, `docs/READY.md`, and `docs/DEVELOPER_WORKFLOW.md`. Branch, issue, and commit references in this plan belong to the private predecessor history and are not part of the clean public repository history.

**Goal:** Keep Admissible in one repository while separating candidate-executing Ready surfaces from trusted review, finalization, signing, and standing authority at the installable-package and process boundaries.

**Architecture:** Preserve one monorepo and one shared protocol, but produce distinct Core, Ready, and Trust distributions. Ready may execute candidate-controlled checks but cannot import or install Trust. Trust may authenticate reviews and issue or inspect authenticated receipts but cannot import or install Ready. An optional umbrella distribution preserves the existing `admissible` user experience on ordinary developer machines without being permitted in trusted infrastructure.

**Tech Stack:** Python 3.10+, setuptools/build, SQLite, HMAC-SHA256 authenticated receipts and heads, JSON Schema Draft 2020-12, dependency-free MCP 2025-06-18 over stdio, loopback HTTP, packaged static UI, `unittest`, existing sabotage harness, npm/Vitest for the existing cockpit.

---

## 1. Executive Decision

### Decision

The change belongs in:

```text
/path/to/admissible
```

It does **not** belong in `red-admissible`, and it does not require a new repository.

### Recommended end state

```text
One GitHub repository: prive-hn/admissible

├── admissible-core      shared deterministic contracts and non-authoritative mechanisms
├── admissible-ready     candidate execution, Ready projection, MCP, UI, local API
├── admissible-trust     review/observer/finalizer/signing/standing authority
└── admissible           optional compatibility/umbrella distribution for developer machines
```

### The important distinction

| Boundary | Recommendation | Reason |
|---|---|---|
| Git repository | Keep together | Atomic schema changes, one review artifact, no cross-repository version drift |
| Python distribution/wheel | Separate | Trusted infrastructure should not install candidate-executing code |
| Process/environment | Separate | Candidate commands and signing credentials must never coexist |
| Persistence | Preserve initially; tighten interfaces | Avoid an unrelated database migration while package boundaries are established |
| Mathematical corpus | Do not change in this refactor | Package separation does not convert P0–P3 into theorems |
| Red Admissible | No change | Red consumes a separately verified projection only in a later, separately scoped change |

### Verdict on the current design

The existing Ready implementation is not architecturally wrong. It correctly builds a product layer over canonical decisions and prevents passing checks from becoming `ADMITTED`. The weakness is narrower: candidate execution, local presentation, and trusted receipt machinery are shipped adjacent in one Python distribution and one large CLI implementation. Runtime credential refusal is a strong control, but separate distributions would make the intended authority boundary harder to violate accidentally and easier to inspect.

---

## 2. Frozen Baseline

This plan was prepared against:

| Item | Value |
|---|---|
| Repository | `prive-hn/admissible` |
| Local path | `/path/to/admissible` |
| Branch | `main` |
| Commit | `76ad2950c53c82e105aabe2be345f5ce1ef5e910` |
| Tree | `67a63b597d670cc9f66b9169ac92d90deb7b8ee7` |
| Package version | `0.7.0` |
| Worktree at inspection | Clean and aligned with `origin/main` |
| Ready implementation contract | `docs/plans/ADMISSIBLE_READY_V07.md` |
| Ready process addendum | `paper/READY/{PREMISE,INVARIANTS,LEMMAS}.md` |

The baseline already implements, at least partially:

- exact repository/commit/tree/policy identity in Ready documents;
- single-use, connection-local MCP work packages;
- fail-closed opening/closing identity checks for authenticated projection;
- exact review candidate binding over `(base, head, tree, patch SHA-256)`;
- startup refusal when candidate execution sees signing/review/evaluation credentials;
- loopback-only Ready UI/API;
- no MCP verb for review, finalization, policy trust, signing, merge, or deploy.

The baseline also states honest limitations:

- P0–P3 are unproved process lemmas, not I18 and not citation-bound theorems;
- direct library bypass is outside the mediated claim;
- UI `POST /api/v1/check` is not a package-authorized MCP check;
- package issuance is refillable and not a finite budget;
- endpoint equality does not prove continuous non-movement or exclude ABA;
- package/process separation is not a system sandbox or distributed-consensus proof.

---

## 3. Why Separate Packages but Not Repositories

### Strongest case for the current one-repository approach

Ready, MCP, CLI, schemas, receipt state, and tests evolve together. A new Ready field can be added to the schema, serializer, MCP output schema, UI renderer, CLI JSON, tests, and docs in one atomic candidate. Splitting repositories would create coordinated-release debt and make it easier for agent and human surfaces to interpret the same canonical decision differently.

### Strongest case against the current single-distribution approach

`admissible.cli` currently exposes both candidate-executing and trusted operations. The same installable distribution includes:

- `check`, `run`, MCP, UI, local API, and runner code;
- review/evaluation attestation code;
- policy trust/revocation;
- finalization and receipt issuance;
- authenticated standing and impeachment operations.

The design relies on runtime credential refusal and disciplined invocation to keep these capabilities apart. That is defensible, but it enlarges the trusted computing base and permits future internal imports to silently reconnect domains that the prose says are separate.

### Chosen compromise

Keep one repository and one coordinated version line, but build separate wheels and entry points. This preserves atomic source review while letting trusted infrastructure install a smaller artifact that physically lacks MCP, UI, and candidate runner modules.

---

## 4. Terminology

Use these terms consistently throughout implementation and documentation:

### Core

Data contracts and deterministic mechanisms that carry no candidate execution entry point and no signing/finalization entry point by themselves. Core is shared code, not authority.

### Ready domain

The untrusted/candidate-facing domain. It may inspect a repository, execute configured deterministic checks, record attempts and private logs, issue local work packages, expose MCP, and render local Ready state. It must hold no review, observer, policy, admission, or signing credentials.

### Trust domain

The reviewer/observer/finalizer/status domain. It authenticates review and evaluation evidence, verifies policy and receipts, anchors authenticated state, files authenticated defects, and computes trusted standing. It must never execute candidate-owned commands.

### Umbrella distribution

A convenience package for an ordinary developer machine that installs and dispatches both Ready and Trust commands. It is explicitly forbidden in trusted infrastructure and does not weaken the process rules simply because both packages exist on a developer machine.

### Repository separation

Moving source to a different GitHub repository. This plan rejects that option.

### Distribution separation

Producing separate wheels/installable packages from one source repository. This plan requires it.

### Process separation

Running Ready and Trust in distinct processes/environments with different installed packages and credentials. This plan requires it for any trusted claim.

---

## 5. Current Surface Inventory

### Current CLI command catalogue

The current monolithic `admissible` CLI exposes:

```text
profiles
init
run
check
mcp
connect
ui
ready-status
attest-review
attest-evaluation
policy trust
policy revoke
policy list
finalize
verify
explain
export
import
impeach
status
```

### Provisional module classification

This is the starting classification, not permission to move files blindly. Task 1 must mechanically verify all static and dynamic imports before extraction.

| Current path | Proposed owner | Notes |
|---|---|---|
| `admissible/fsutil.py` | Core | Permission-checked file primitives; must not load secrets unless called by Trust |
| `admissible/identity.py` | Core | Exact repository identity |
| `admissible/config.py` | Core | Configuration parsing and policy digest selection |
| `admissible/profiles.py` | Core | Built-in deterministic profiles |
| `admissible/evidence.py` | Core | Closed evidence records; no authentication authority |
| `admissible/decision.py` | Core | Canonical decision types and deterministic mapping |
| `admissible/schema.py` | Core | Shared schema resource loader |
| `admissible/store.py` | Core mechanism with capability facades | Candidate attempts and trusted receipts currently share persistence; expose role-specific interfaces |
| `admissible/runner.py` | Ready | Executes candidate-configured commands; must never enter Trust wheel |
| `admissible/github.py` | Ready/evaluate-only | Candidate CI projection; no finalization |
| `admissible/ready.py` | Split | Unsigned Ready mapping/inspection/check belongs to Ready; authenticated Ready projection belongs to Trust |
| `admissible/agent_connection.py` | Ready | Local operational presence only |
| `admissible/agent_mcp.py` | Ready | Candidate-facing MCP surface |
| `admissible/ready_server.py` | Ready | Loopback UI/API server |
| `admissible/ready_static/` | Ready | Packaged UI assets |
| `admissible/review.py` | Trust | Review attestation verification/signing boundary |
| `admissible/attestation.py` | Trust | Evaluation/observer attestation boundary |
| `admissible/receipt.py` | Trust | Receipt issuance and authenticated head operations |
| `admissible/standing.py` | Split | Pure/unsigned query portions may be Core; authenticated projection and defect filing belong to Trust |
| `admissible/cli.py` | Split | Current 2,600+ line mixed command surface must become Ready CLI, Trust CLI, and thin umbrella dispatcher |
| `fcd/`, `rga/`, `atlas/`, `protocol/` | Core/research distribution | Keep source together; do not reinterpret their theorem status during this refactor |
| `server/`, `apps/cockpit/` | Existing research cockpit | Do not conflate with Ready UI; classify and preserve separately |

### Critical mixed boundary in `ready.py`

`ready.inspect(repo, signer=None, ...)` currently accepts a signer parameter so the same module can produce authenticated `ready` status in a trusted context. MCP and UI intentionally call it without a signer, but the function signature keeps trusted projection adjacent to candidate-facing code.

The target must split this behavior:

```text
Ready package:
  inspect_unsigned(...)
  run_check(...)
  from_evaluation(...)
  from_problem(...)

Trust package:
  inspect_authenticated(..., verifier)
  ready_status(..., verifier)
```

Ready must have no callable parameter through which a signer/verifier credential can be passed to promote local state to authenticated `ready`.

---

## 6. Target Package Architecture

### Proposed source layout

```text
/path/to/admissible/
├── packages/
│   ├── core/
│   │   ├── pyproject.toml
│   │   └── src/admissible_core/
│   │       ├── config.py
│   │       ├── decision.py
│   │       ├── evidence.py
│   │       ├── fsutil.py
│   │       ├── identity.py
│   │       ├── profiles.py
│   │       ├── schema.py
│   │       ├── store_base.py
│   │       ├── store_candidate.py
│   │       ├── store_read.py
│   │       └── protocol/*.schema.json
│   ├── ready/
│   │   ├── pyproject.toml
│   │   └── src/admissible_ready/
│   │       ├── __main__.py
│   │       ├── cli.py
│   │       ├── runner.py
│   │       ├── github.py
│   │       ├── ready.py
│   │       ├── agent_connection.py
│   │       ├── agent_mcp.py
│   │       ├── ready_server.py
│   │       └── ready_static/*
│   ├── trust/
│   │   ├── pyproject.toml
│   │   └── src/admissible_trust/
│   │       ├── __main__.py
│   │       ├── cli.py
│   │       ├── review.py
│   │       ├── attestation.py
│   │       ├── receipt.py
│   │       ├── standing.py
│   │       ├── defects.py
│   │       └── ready_status.py
│   └── umbrella/
│       ├── pyproject.toml
│       └── src/admissible/
│           ├── __init__.py
│           ├── __main__.py
│           ├── cli.py
│           └── compatibility facades for the declared migration window
├── tests/
│   ├── architecture/
│   ├── core/
│   ├── ready/
│   ├── trust/
│   └── compatibility/
├── fcd/
├── rga/
├── atlas/
├── server/
├── apps/
├── paper/
└── docs/
```

The exact filesystem move should occur only after the import census proves the dependency graph. Unique import namespaces are preferred over splitting one `admissible` namespace across multiple wheels; implicit/partial namespace-package ownership would make installation order and missing-file behavior harder to reason about.

### Distribution contracts

#### `admissible-core`

Allowed:

- canonical data types and serialization;
- exact identity capture;
- configuration and schema loading;
- evidence and decision shapes;
- persistence primitives and read-only queries;
- cryptographic verification primitives only if they take an already-constructed verifier and cannot load credentials or issue state.

Forbidden:

- `subprocess` candidate execution;
- MCP and HTTP servers;
- packaged Ready static assets;
- environment credential loading;
- policy trust/revoke writes;
- review/evaluation signing;
- receipt issuance/finalization;
- deployment, merge, or network agent execution.

#### `admissible-ready`

Allowed:

- repository selection and exact identity;
- profile initialization;
- deterministic preview checks;
- attempt/log persistence through a candidate-specific store facade;
- Ready state that remains unsigned unless presented as an externally authenticated document;
- MCP work package issuance and one-time spending;
- remediation projection;
- loopback UI/API;
- evaluate-only GitHub integration.

Forbidden:

- importing `admissible_trust`;
- loading HMAC/review/observer/finalizer keys;
- authenticating a self-supplied receipt into `ready`;
- policy trust/revocation;
- review/evaluation attestation issuance;
- receipt issuance, finalization, impeachment, merge, or deploy;
- writing trusted standing fields.

#### `admissible-trust`

Allowed:

- authenticate reviewer identity and review evidence;
- authenticate observer/evaluation evidence;
- trust and revoke policies;
- consume retained preview artifacts;
- finalize and issue authenticated receipts;
- verify authenticated receipts and current standing;
- file authenticated defects/impeachment events;
- export/import authenticated state under existing closed contracts.

Forbidden:

- importing `admissible_ready`;
- executing repository-configured commands;
- launching MCP or HTTP servers;
- importing packaged Ready assets;
- invoking candidate GitHub workflows;
- cloning, building, or running the candidate under finalizer credentials.

#### `admissible` umbrella

Allowed only on ordinary developer/operator machines. It may depend on all coordinated sibling packages and preserve the existing command syntax.

Forbidden in:

- finalizer environments;
- reviewer key environments;
- observer key environments;
- policy signing/trust environments;
- any documented minimal trusted deployment.

---

## 7. Command Ownership Matrix

### Recommended command allocation

| Existing command | Ready CLI | Trust CLI | Umbrella behavior |
|---|---:|---:|---|
| `profiles` | Yes | No | Dispatch Ready |
| `init` | Yes | No | Dispatch Ready |
| `run --preview` | Yes | No | Dispatch Ready |
| `run` without `--preview` | No | Transitional Trust compatibility only | Warn and dispatch Trust during one release window; prefer `finalize` |
| `check` | Yes | No | Dispatch Ready |
| `mcp` | Yes | No | Dispatch Ready |
| `connect` | Yes | No | Dispatch Ready |
| `ui` | Yes | No | Dispatch Ready |
| `ready-status` | No | Yes | Dispatch Trust; requires authenticated verifier domain |
| `attest-review` | No | Yes | Dispatch Trust |
| `attest-evaluation` | No | Yes | Dispatch Trust |
| `policy trust` | No | Yes | Dispatch Trust |
| `policy revoke` | No | Yes | Dispatch Trust |
| `policy list` | No | Yes | Dispatch Trust to avoid exposing policy-home internals in Ready |
| `finalize` | No | Yes | Dispatch Trust |
| `verify` | No | Yes | Dispatch Trust |
| `explain` | Read-only unsigned explanation | Authenticated explanation variant | Umbrella selects based on explicit mode, never ambient credential guessing |
| `export` | Candidate-attempt export only if separately named | Authenticated journal export | Avoid one ambiguous verb long-term |
| `import` | Candidate-attempt import only if separately named | Authenticated journal import | Avoid one ambiguous verb long-term |
| `impeach` | No | Yes | Dispatch Trust |
| `status` | Unsigned check/attempt status | Authenticated standing status | Umbrella requires an explicit submode if both are retained |

### Entry points

Proposed console scripts:

```toml
# admissible-ready
[project.scripts]
admissible-ready = "admissible_ready.cli:main"

# admissible-trust
[project.scripts]
admissible-trust = "admissible_trust.cli:main"

# umbrella only
[project.scripts]
admissible = "admissible.cli:main"
```

Do not choose a domain based only on whether a signing environment variable happens to be present. Command ownership must be explicit. Ambient credentials remain a fail-closed guard, not a router.

---

## 8. Authority and Data-Flow Contract

### Candidate check flow

```text
Repository HEAD
  → Ready exact identity capture
  → candidate-specific policy/config selection
  → deterministic runner
  → command evidence + attempt record
  → Ready state/checks/remediation
  → retained preview artifact
```

No step above may load or receive:

- admission HMAC key;
- reviewer keyring;
- observer/evaluation key;
- finalizer credential;
- policy trust/revocation credential.

### Trusted finalization flow

```text
Retained preview artifact
  + exact repository/commit/tree/policy identity
  + authenticated review evidence
  + authenticated observer/evaluation evidence
  + trusted policy state
  → Trust verification
  → receipt proposal
  → authenticated monotone head
  → persisted workflow receipt
  → current-standing query
```

No step above may execute a command from `.admissible.json`, launch a candidate process, start MCP, or expose the Ready HTTP server.

### Ready status after separation

Ready without a verifier may report:

- `needs_attention`;
- `waiting_for_review`;
- `checks_complete`;
- `unable_to_check`;
- authenticated status supplied by a trusted domain only if the authentication has already been performed outside Ready and the data contract explicitly proves that fact.

Because the current receipt authentication is HMAC-SHA256, verification and signing share secret material. Ready must **not** receive that key merely to display `ready`. The conservative behavior remains: only `admissible-trust ready-status` may emit authenticated `ready`. Introducing public-key verification would be a separate cryptographic design change and is out of scope.

### Persistence

For the first separation release:

- preserve the current SQLite schema and migration history;
- introduce role-specific store facades;
- keep candidate writes limited to attempts/logs/work-package operational records;
- keep trusted writes limited to policies, authenticated receipts/heads, attestations, and defects;
- require authenticated reads before trusted rows affect standing;
- open every home under one authority-neutral protocol in `admissible_core.store_open`: a cross-process lock keyed by the canonical absolute database path and kept outside the home, held from before the existence check until the schema and recorded version are final; an immutable read-only look before any read-write connection exists; and a second version check through the writing connection before the first pragma. Ready takes it now and Trust takes the same lock on the same home;
- refuse a home that has a `-wal`, `-shm` or `-journal` beside it, because its committed contents are in that file and reading them means replaying it. This is a deliberate **denial of service**: a process holding the store open locks every other opener out until it closes or checkpoints, so two Admissible processes cannot share one home concurrently;
- document that the schema lock is advisory and binds only the distributions that take it — arbitrary same-user SQL against the database file is outside every claim made here;
- document that same-user filesystem access can still corrupt or delete local state and cause fail-closed denial of service.

Package separation is **not** a filesystem sandbox. A future hardening phase may split candidate and trusted stores or move trusted persistence to an external owner, but that must not be smuggled into this package refactor.

---

## 9. Security Invariants for the New Boundary

Create an executable architecture contract with stable identifiers, for example `SEP1`–`SEP12`. These are implementation guards, not additions to `paper/PROOFS.md`.

| ID | Required invariant |
|---|---|
| SEP1 | The Ready wheel contains no `admissible_trust` module or Trust console script. |
| SEP2 | The Trust wheel contains no Ready runner, MCP, HTTP server, or static UI asset. |
| SEP3 | Ready source imports Core only; it never imports Trust directly or dynamically. |
| SEP4 | Trust source imports Core only; it never imports Ready directly or dynamically. |
| SEP5 | Every Ready entry point refuses before repository mutation or command execution if any signing/review/observer/finalizer credential is present. |
| SEP6 | Every Trust entry point has no reachable candidate-command executor. |
| SEP7 | Passing Ready checks cannot write or emit `ADMITTED` or authenticated `CURRENT`. |
| SEP8 | Authenticated `ready` requires Trust verification of an exact current receipt. |
| SEP9 | The umbrella package is not a documented or tested trusted deployment artifact. |
| SEP10 | Shared schemas have one owning distribution and identical bytes across all consumers. |
| SEP11 | Legacy CLI compatibility cannot route a candidate command into Trust or a trust mutation into Ready. |
| SEP12 | Removing any package/import/credential guard makes a named architecture test fail. |

### What these invariants do not prove

- OS-level isolation;
- protection from a hostile process under the same Unix account;
- reviewer honesty or completeness;
- public non-repudiation from HMAC;
- no database deletion or corruption;
- distributed consensus;
- that P0–P3 are mathematical theorems;
- that an agent patch is correct;
- that a candidate cannot bypass Admissible entirely.

---

## 10. Compatibility Strategy

### Versioning

Recommended first separated release: a coordinated minor release such as `0.8.0`, not a silent patch to `0.7.0`.

All sibling packages must share one version and exact dependency pins:

```toml
admissible-ready==0.8.0  → admissible-core==0.8.0
admissible-trust==0.8.0  → admissible-core==0.8.0
admissible==0.8.0        → core==0.8.0, ready==0.8.0, trust==0.8.0
```

Do not permit mixed sibling minor versions. Protocol schema identifiers remain their existing versioned domains unless their JSON contracts actually change.

### Import compatibility

The umbrella package may provide temporary facades for documented imports such as:

```python
from admissible.evidence import ReviewEvidence
from admissible.receipt import WorkflowReceipt
```

The facades should emit deprecation warnings only where they do not break machine JSON/stdout contracts. No warning may contaminate MCP stdout or JSON output. The migration window should be finite and written in `docs/DEVELOPER_WORKFLOW.md`.

Trusted infrastructure must not use compatibility facades, because installing them installs the umbrella surface.

### CLI compatibility

During one release window:

- keep `admissible check`, `admissible mcp`, and `admissible ui` working through umbrella dispatch;
- keep trusted commands working through umbrella dispatch on developer machines;
- add explicit `admissible-ready` and `admissible-trust` entry points;
- ensure machine-readable stdout remains byte-compatible where promised;
- never auto-select a domain from ambient credentials;
- deprecate ambiguous non-preview `admissible run` in favor of explicit `admissible-trust finalize`.

### Data compatibility

Do not reset or rewrite the local store. Existing attempts, receipts, heads, policies, evidence rows, and standing must remain readable. Any schema migration must be additive, transactional, replayable, and tested against a v0.7 store fixture.

---

## 11. Detailed Implementation Plan

### Task 1: Freeze the candidate and produce a complete dependency census

**Objective:** Establish exact source identity and a mechanically complete static/dynamic dependency map before moving any code.

**Files:**
- Create: `docs/plans/ADMISSIBLE_RUNTIME_AUTHORITY_SEPARATION.md`
- Create: `tests/architecture/test_import_census.py`
- Create: `tests/architecture/expected_module_owners.json`

**Steps:**

1. Create an isolated worktree from current `origin/main`; do not edit the canonical checkout.
2. Record base commit/tree and clean status in the plan document.
3. Parse every Python AST under `admissible/`, `fcd/`, `rga/`, `atlas/`, `server/`, and tests.
4. Record static imports, relative imports with `module=None`, dynamic `importlib` calls, and imports inside functions.
5. Search CLI handlers for local imports that a top-level graph misses.
6. Record package-data access through `importlib.resources`.
7. Enumerate all console commands and their call graphs.
8. Classify each module as Core, Ready, Trust, Umbrella, or Existing Research Surface.
9. Fail the census test when an unclassified module or a new cross-domain edge appears.
10. Run the census test and preserve the JSON manifest as the reviewable boundary.

**Verification:**

```bash
.venv/bin/python -m unittest tests.architecture.test_import_census -v
```

Expected: all modules classified; zero Ready→Trust and zero Trust→Ready edges in the target manifest.

**Commit:**

```text
test: define admissible authority separation map
```

---

### Task 2: Write RED wheel-content and isolated-install tests

**Objective:** Prove the present monolith fails the desired physical package boundary before implementation.

**Files:**
- Create: `tests/architecture/test_distribution_separation.py`
- Create: `tests/architecture/inspect_wheel.py`
- Modify: `pyproject.toml` dev dependencies only if the existing `build` dependency is insufficient

**Steps:**

1. Define expected wheel names and exact owned module prefixes.
2. Build each proposed wheel into a temporary directory.
3. Inspect wheel ZIP members directly; do not trust build exit status alone.
4. Assert Ready wheel has no Trust modules, credential loaders, or Trust entry point.
5. Assert Trust wheel has no runner, MCP, Ready server, or static assets.
6. Assert Core wheel has neither command family.
7. Create three temporary virtual environments: Ready-only, Trust-only, umbrella.
8. In Ready-only, require `find_spec("admissible_trust") is None`.
9. In Trust-only, require `find_spec("admissible_ready") is None`.
10. In umbrella, require both explicit command families and the compatibility dispatcher.
11. Verify schema resource hashes are identical to the source-owned canonical files.
12. Run tests and confirm they fail on the current monolithic packaging for the intended reason.

**Verification:**

```bash
.venv/bin/python -m unittest tests.architecture.test_distribution_separation -v
```

Expected before implementation: FAIL because the distributions do not yet exist.

**Commit:**

```text
test: require physically separate ready and trust wheels
```

---

### Task 3: Extract the Core distribution without behavior changes

**Objective:** Establish one shared, authority-neutral dependency layer.

**Files:**
- Create: `packages/core/pyproject.toml`
- Create/move: `packages/core/src/admissible_core/*`
- Modify: schema resource paths and imports
- Modify: root test bootstrap/import paths
- Test: `tests/core/*`

**Steps:**

1. Move the smallest leaf modules first: `identity`, `schema`, `profiles`, and pure validation helpers.
2. Run their focused tests after each move.
3. Move evidence and deterministic decision shapes.
4. Run evidence/decision/schema tests.
5. Move configuration parsing without any command execution.
6. Introduce `store_read`, `store_candidate`, and `store_base` facades while preserving the underlying SQLite schema.
7. Keep credential loading and receipt issuance out of Core.
8. Package protocol JSON under one canonical resource owner.
9. Add tests proving Core imports do not load `subprocess`, MCP, HTTP server, Ready static, or Trust credential loaders as a package side effect.
10. Build the Core wheel and verify member hashes.
11. Run all pre-existing Python tests through compatibility imports before proceeding.

**Verification:**

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
.venv/bin/python -m unittest discover -s atlas/tests -p 'test_*.py' -q
```

Expected: existing behavior remains green; new Core isolation tests pass.

**Commit:**

```text
refactor: extract authority-neutral admissible core
```

---

### Task 4: Extract the Ready distribution

**Objective:** Move candidate execution and local presentation into a package that physically lacks Trust.

**Files:**
- Create: `packages/ready/pyproject.toml`
- Create/move: `packages/ready/src/admissible_ready/{runner,github,ready,agent_connection,agent_mcp,ready_server}.py`
- Move: `admissible/ready_static/` → Ready package data
- Create: `packages/ready/src/admissible_ready/cli.py`
- Test: `tests/ready/*`

**Steps:**

1. Move runner/evaluate-only code and preserve exact command evidence behavior.
2. Move unsigned Ready mapping (`from_evaluation`, `from_problem`, rendering).
3. Remove the signer/verifier argument from the Ready inspection API.
4. Move authenticated projection code out of Ready; leave a failing test until Trust owns it.
5. Move MCP and connection-local package store.
6. Preserve package single-use semantics: first check attempt spends, success or refusal.
7. Move loopback server and static assets.
8. Create a Ready CLI containing only Ready-owned commands.
9. Add a credential canary matrix covering every known admission/review/observer/finalizer variable.
10. Prove refusal occurs before repository write, store write, attempt creation, or candidate command launch.
11. Add a dynamic-import guard test so local imports cannot bypass the static import rule.
12. Build/install Ready-only and run its CLI/MCP/UI API canaries.

**Focused verification:**

```bash
.venv/bin/python -m unittest \
  tests.test_admissible_ready \
  tests.test_admissible_ready_server \
  tests.test_admissible_ready_e2e \
  tests.test_admissible_review_candidate -q
```

Expected: Ready behavior remains stable; Ready-only environment cannot import Trust.

**Commit:**

```text
refactor: isolate admissible ready candidate domain
```

---

### Task 5: Extract the Trust distribution

**Objective:** Move all credentialed authority into a package that physically lacks candidate execution.

**Files:**
- Create: `packages/trust/pyproject.toml`
- Create/move: `packages/trust/src/admissible_trust/{review,attestation,receipt,standing,defects,ready_status}.py`
- Create: `packages/trust/src/admissible_trust/cli.py`
- Test: `tests/trust/*`

**Steps:**

1. Move review attestation parsing/signing and keyring verification.
2. Move evaluation/observer attestation logic.
3. Move policy trust/revoke/list operations.
4. Move receipt issuance, authenticated head anchoring, and finalization.
5. Split standing query from defect-filing mutation where necessary.
6. Implement authenticated Ready projection in `admissible_trust.ready_status`.
7. Ensure finalization consumes retained preview/evidence files only.
8. Add static and runtime tests proving Trust has no candidate executor import.
9. Add a trap module in tests that raises if `subprocess` candidate execution, Ready runner, MCP, or Ready server is imported or called.
10. Build/install Trust-only and verify Ready package is absent.
11. Run receipt, authority, standing, finalization, policy, and durability suites.

**Focused verification:**

```bash
.venv/bin/python -m unittest \
  tests.test_admissible_receipt \
  tests.test_authenticated_receipt \
  tests.test_admissible_authority \
  tests.test_admissible_standing \
  tests.test_admissible_final_closure \
  tests.test_admissible_final_repair \
  tests.test_admissible_release_closure -q
```

Expected: authenticated behavior remains stable; Trust-only environment cannot import Ready.

**Commit:**

```text
refactor: isolate admissible trusted authority domain
```

---

### Task 6: Build the umbrella compatibility distribution

**Objective:** Preserve the familiar `admissible` command and declared import compatibility without using the umbrella in trusted deployments.

**Files:**
- Create: `packages/umbrella/pyproject.toml`
- Create: `packages/umbrella/src/admissible/{__init__,__main__,cli}.py`
- Create only necessary compatibility facade modules
- Test: `tests/compatibility/test_legacy_cli.py`
- Test: `tests/compatibility/test_legacy_imports.py`

**Steps:**

1. Implement explicit command-to-domain dispatch table.
2. Refuse unknown or ambiguous commands.
3. Never route based on ambient credentials.
4. Preserve machine JSON and MCP stdout contracts.
5. Add explicit warnings only to human stderr paths.
6. Preserve documented imports for one finite migration window.
7. Verify the umbrella package pins exact sibling versions.
8. Add tests that an attempted Ready command with credentials refuses in Ready rather than falling through to Trust.
9. Add tests that a Trust command cannot invoke Ready as a helper.
10. Document that umbrella installation is forbidden in trusted infrastructure.

**Verification:**

```bash
.venv/bin/python -m unittest discover -s tests/compatibility -p 'test_*.py' -v
```

Expected: current public commands remain usable; domain ownership is explicit.

**Commit:**

```text
feat: preserve admissible cli through explicit domain dispatch
```

---

### Task 7: Add architecture sabotage and negative controls

**Objective:** Prove the separation guards are load-bearing rather than decorative.

**Files:**
- Modify: `scripts/sabotage_admissible.py`
- Create: `tests/architecture/test_separation_sabotage.py`
- Create: architecture guard registry/manifest

**Steps:**

1. Register every SEP guard site by stable identifier.
2. Add a sabotage case deleting the Ready→Trust import prohibition.
3. Add a sabotage case deleting the Trust→Ready import prohibition.
4. Add a sabotage case placing a Trust module in the Ready wheel.
5. Add a sabotage case placing runner/MCP assets in the Trust wheel.
6. Add a sabotage case removing Ready credential refusal.
7. Add a sabotage case allowing unsigned Ready projection to emit `ready`.
8. Add a sabotage case routing by ambient credential.
9. Require each deletion/mutation to make one named test fail.
10. Restore every file byte-for-byte and verify the tree after sabotage.

**Verification:**

```bash
.venv/bin/python scripts/sabotage_admissible.py
```

Expected: every registered separation mutant is killed; zero residue; original tree restored byte-for-byte.

**Commit:**

```text
test: prove admissible package separation guards load-bearing
```

Do not promote P0–P3 to proved theorems in this task. A future proof/citation change is Lane 3 and must be separately scoped.

---

### Task 8: Update documentation and operator guidance

**Objective:** Make installation and authority ownership unambiguous without rewriting historical plans as current behavior.

**Files likely to change:**

- `README.md`
- `docs/READY.md`
- `docs/DEVELOPER_WORKFLOW.md`
- `docs/GITHUB_ACTIONS.md`
- `docs/plans/ADMISSIBLE_RUNTIME_AUTHORITY_SEPARATION.md`
- `paper/READY/PREMISE.md`
- `paper/READY/INVARIANTS.md`
- `paper/READY/LEMMAS.md`
- package-specific READMEs under `packages/*/`
- `CHANGELOG.md` if present/current

**Required documentation statements:**

1. One repository, separate distributions and processes.
2. Exact commands installed by each package.
3. Ready environment holds no trust credential or Trust package.
4. Trust environment holds no Ready package and executes no candidate command.
5. Umbrella is convenience-only and forbidden in trusted deployments.
6. HMAC means Ready cannot safely verify `ready` without entering the Trust domain.
7. Package separation reduces accidental capability adjacency but is not OS isolation.
8. Store compatibility and local-denial-of-service limitations remain honest.
9. P0–P3 remain unproved unless a separate formal admission changes that status.
10. Red Admissible is unchanged and no new Red composition claim is made.

Also resolve the predecessor repository's issue #13 by correcting the P1 plain sentence. The public release tree must carry the correction without depending on the private issue history.

**Verification:**

- validate every documented command in isolated Ready-only, Trust-only, and umbrella environments;
- check local Markdown links;
- run documentation contract tests;
- run `git diff --check`;
- inspect all changed prose against executable package content.

**Commit:**

```text
docs: define admissible runtime and trust installation boundaries
```

---

### Task 9: Run full repository and artifact gates

**Objective:** Prove the split preserves existing behavior and produces the intended artifact contents.

**Canonical repository commands:**

```bash
make test
make audit
make build
.venv/bin/python scripts/sabotage_admissible.py
```

`make test` currently runs:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
.venv/bin/python -m unittest discover -s atlas/tests -p 'test_*.py' -q
npm --prefix apps/cockpit test -- --run
```

Additional required gates:

1. Build all wheels and sdists from a clean checkout.
2. Inspect every archive member and recompute hashes.
3. Install Ready-only, Trust-only, Core-only, and umbrella into fresh virtual environments.
4. Run import-absence assertions in each environment.
5. Run CLI help and representative command canaries.
6. Run MCP initialization/tools-list/tools-call canaries in Ready-only.
7. Run retained-preview → Trust-finalize canary across two separate processes/environments.
8. Run credential canaries and prove Ready refuses before side effects.
9. Run a dirty-tree/stale-head/work-package-spent matrix.
10. Run receipt authenticity/current-standing/impeachment matrix in Trust-only.
11. Scan built artifacts for secrets and unexpected package members.
12. Run `git diff --check` and final clean-status verification after artifact cleanup.

No test count should be copied into release prose until computed from the final exact candidate.

---

### Task 10: Freeze, review, and publish within Lane 2

**Objective:** Admit one exact package-separation candidate under proportionate review.

This change is Lane 2 because it changes Admissible Ready and signing/finalization boundaries. Two reviewers are justified because signing/finalization authority changes; commission them together on one exact frozen candidate.

**Review mandates:**

- Reviewer A: package/import/process separation and candidate-execution reachability.
- Reviewer B: trusted receipt/finalization behavior, compatibility, schemas, and artifact contents.

**Freeze receipt:**

- exact base commit;
- exact head commit;
- exact tree;
- complete patch SHA-256;
- source/sdist/wheel SHA-256 for every distribution;
- test commands and exits;
- sabotage result;
- Ready-only/Trust-only import-absence receipts.

Use the existing generation budget. Initial review plus one consolidated remediation generation is the default. A source-byte change invalidates prior candidate review. Do not open a third generation without Roque explicitly authorizing generation 3 and its reason. No generation four.

**Publication sequence:**

1. Push the exact reviewed branch.
2. Open one focused PR unless repository policy requires coordinated package PRs.
3. Read back PR head SHA and file list.
4. Wait for deterministic CI on the exact head.
5. Answer every review comment directly.
6. Merge only with current-head required checks green, zero unresolved P0/P1, and zero unresolved material threads.
7. Publish packages only through a separately authorized release action.
8. Verify registry artifacts by downloading and inspecting them.
9. Do not move an existing tag.
10. Keep the worktree until the branch is merged and clean.

---

## 12. Acceptance Criteria

The change is complete only when all of the following are true:

### Source and import boundaries

- [ ] Ready imports Core and never Trust.
- [ ] Trust imports Core and never Ready.
- [ ] Core imports neither Ready nor Trust.
- [ ] Dynamic/local imports are included in enforcement.
- [ ] The source ownership manifest has no unclassified module.

### Built artifacts

- [ ] Ready wheel physically contains no Trust package or entry point.
- [ ] Trust wheel physically contains no runner, MCP, Ready HTTP, or Ready assets.
- [ ] Core wheel contains no Ready or Trust entry point.
- [ ] Umbrella pins exact sibling versions.
- [ ] All schema resources have one canonical owner and verified hashes.

### Runtime behavior

- [ ] Ready refuses credential-bearing environments before any side effect.
- [ ] Trust cannot execute candidate commands by import or reachable call graph.
- [ ] Passing checks never produces authenticated `ready`.
- [ ] Authenticated `ready` remains exact-receipt + `CURRENT` standing only.
- [ ] Work package issuance/check/spending semantics remain unchanged.
- [ ] Exact review candidate binding remains unchanged.

### Compatibility

- [ ] Existing documented CLI commands work through umbrella dispatch during the migration window.
- [ ] Machine JSON and MCP stdout remain uncontaminated.
- [ ] Existing v0.7 stores remain readable without destructive migration.
- [ ] Existing receipt, head, evidence, and policy schema domains remain honest.
- [ ] External consumer packaging tests pass.

### Verification

- [ ] Full Python, Atlas, and cockpit suites pass.
- [ ] npm audit/build gates pass according to repository policy.
- [ ] Every separation mutant is killed.
- [ ] Built artifacts are inspected by content.
- [ ] Two exact-candidate reviews close with no P0/P1.
- [ ] PR head and required CI are re-read after final push.

### Documentation

- [ ] Current docs explain repository vs distribution vs process separation.
- [ ] Trusted installation instructions never install the umbrella or Ready.
- [ ] Ready installation instructions never install Trust.
- [ ] Limitations are explicit; package separation is not described as sandboxing.
- [ ] P0–P3 theorem status is not overstated.
- [ ] The predecessor issue #13 receives a direct fix receipt/reply.

---

## 13. Risks and Controls

| Risk | Failure mode | Control |
|---|---|---|
| Import breakage | Existing consumers import `admissible.*` directly | Finite umbrella facade window + external consumer tests |
| Namespace-package fragility | Multiple wheels partially own `admissible` | Use unique `admissible_core`, `admissible_ready`, `admissible_trust` namespaces |
| Schema drift | Ready and Trust ship divergent JSON schemas | One Core-owned schema resource + byte-hash tests |
| CLI ambiguity | `status`, `run`, `export`, or `import` crosses domains | Explicit command matrix; no ambient-credential routing |
| False security claim | Separate wheels are described as sandboxing | Explicit non-theorem/limitation section and adversarial docs review |
| Ready promotion | UI/MCP gains verifier and emits `ready` | Remove signer argument from Ready; Trust-only authenticated projection |
| Candidate execution in Trust | Finalizer imports runner through helper | Wheel absence + AST/import census + runtime trap + sabotage mutant |
| Credential leakage into Ready | Environment accidentally carries HMAC/reviewer key | Refuse before repository/store/check activity; canary every entry point |
| Store damage | Candidate process edits shared local SQLite state | Authenticated rows fail closed; role-specific facade; document local DoS boundary |
| Migration scope explosion | Refactor also changes crypto, schema, DB, theorem status | Explicit non-goals and split follow-up issues |
| Release skew | Core/Ready/Trust versions mismatch | Exact coordinated pins and isolated install tests |
| UI regression | Package-data move omits assets | Wheel-member assertions + real loopback/browser canary |
| MCP regression | stderr/stdout or schema behavior changes | Existing MCP contract tests + isolated Ready-only protocol canary |
| Review drift | Reviewer approves pre-repair bytes | Candidate tuple binding and review-generation fence |

---

## 14. Non-Goals

This plan does not authorize or include:

- creating a second Admissible repository;
- renaming the repository to Green Admissible now;
- changing Red Admissible;
- changing Red’s B1 base-receipt contract;
- promoting P0–P3 into `paper/PROOFS.md`;
- adding I18;
- changing HMAC-SHA256 to asymmetric signatures;
- remote multi-tenant Ready hosting;
- an agent runner/model router;
- merge or deploy authority for MCP;
- automatic provider configuration edits;
- a new trusted database service;
- OS sandboxing or container isolation;
- rewriting FCD/RGA theorem families;
- moving the existing research cockpit as part of this change;
- changing GitHub evaluate-only workflows into finalizers.

Any of these requires a separate decision and scope.

---

## 15. Rollback Plan

### Before merge

- Keep the implementation in an isolated worktree.
- Never delete an unmerged branch.
- Preserve the v0.7 clean baseline and exact commit/tree receipts.
- Do not rewrite existing tags or package releases.

### After merge but before package publication

- Revert the focused merge commit if the default branch gate exposes a regression.
- Existing published `0.7.0` remains the stable artifact.
- No database rollback should be needed if schema changes are avoided/additive.

### After package publication

- Do not overwrite or yank silently.
- Publish a corrected coordinated patch release only after exact-head verification.
- Trusted operators remain pinned to the last verified Trust/Core pair.
- Developer machines may temporarily return to `admissible==0.7.0` if their local store remains schema-compatible.
- Record the package hashes and reason for rollback.

Rollback is package/version rollback, not deletion of authenticated history. Existing receipts and heads remain immutable evidence.

---

## 16. Open Decisions for Roque

These decisions should be made before implementation, but none requires a new repository:

1. **Package names:** accept `admissible-core`, `admissible-ready`, `admissible-trust`, and `admissible` umbrella, or choose another naming scheme.
2. **First release version:** recommended coordinated `0.8.0` because packaging changes materially.
3. **Compatibility window:** recommended one minor release for legacy Python imports and the mixed umbrella CLI.
4. **Ambiguous commands:** decide whether `run` without `--preview`, `status`, `export`, and `import` remain umbrella aliases or are removed immediately in favor of explicit domain commands.
5. **Trusted Ready display:** retain HMAC and Trust-only `ready` status, or separately design public-key verification later. This plan recommends retaining HMAC and not expanding scope.
6. **Store separation:** keep one compatible local SQLite schema with role facades now, or fund a separate trusted-store phase later. This plan recommends facades now and no storage rewrite.
7. **Proof status:** keep P0–P3 unproved after package separation, or commission a separate Lane 3 citation/mutation/proof project later. This plan recommends keeping them unproved in this release.

---

## 17. Recommended Decisions

For the least risky path:

```text
Repository:          keep prive-hn/admissible
Package names:       core / ready / trust / umbrella
Version:             coordinated 0.8.0
Compatibility:       one minor release
Crypto:              unchanged HMAC-SHA256
Ready “ready” label: Trust-only authenticated command
Persistence:         existing schema + role facades
Proof status:        P0–P3 remain unproved
Red Admissible:      unchanged
Review:              two reviewers together because signing/finalization moves
```

This achieves the real objective—removing candidate execution from the trusted installation—without fragmenting the source repository, changing cryptography, rewriting persistence, or making a proof claim the implementation has not yet earned.

---

## 18. Final Completion Receipt Format

When implementation is eventually complete, report exactly:

```text
LANE: 2 — Admissible Ready/signing boundary
BASE: <full SHA> / <tree>
HEAD: <full SHA> / <tree>
PATCH_SHA256: <digest>
PACKAGES:
  admissible-core <version> <wheel SHA256>
  admissible-ready <version> <wheel SHA256>
  admissible-trust <version> <wheel SHA256>
  admissible <version> <wheel SHA256>
IMPORT BOUNDARIES:
  Ready→Trust: absent
  Trust→Ready: absent
  Core→Ready/Trust: absent
TESTS: <commands and exact results>
SABOTAGE: <killed>/<discovered>, zero survivors
REVIEWS:
  Reviewer A: <verdict bound to HEAD>
  Reviewer B: <verdict bound to HEAD>
PR: <URL and live head>
CI: <required checks on live head>
MERGE: <state>
PUBLICATION: <state; registry read-back if published>
OPEN FOLLOW-UPS: <P2/P3 or explicitly none>
```

A plan, green local suite, or merged PR alone is not publication. A published package is not proof that any trusted machine installed it. Those remain separate receipts.
