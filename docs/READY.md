# Admissible Ready

Admissible Ready is the product layer over the deterministic admission engine. It gives people and connected coding agents one shared loop:

**change → check → fix the next item → recheck → ready**

The friendly labels do not replace the trust model. When identity is known,
every result binds repository, full commit SHA, tree, and policy.
`applies_to_current_commit` is authoritative. Blocked results and some legacy
authenticated receipts may omit an attempt ID. Exact canonical state is always
available under technical details.

## Where Ready is installed, and what is not installed beside it

Since 0.8.0 the boundary below is a packaging fact and not only a rule.
`pip install admissible-ready` installs the candidate side and
`admissible-core==0.8.0`; it **does not install `admissible-trust`**, under any
extra or environment marker, and the Ready wheel does not contain Trust's
modules, so nothing on that machine can import a receipt signer, a keyring
reader or a verifier even by a path no census walks.

The reverse holds too. `pip install admissible-trust` installs the signing side
and the same kernel; it does not install `admissible-ready`, and the Trust wheel
contains no runner, no MCP server, no HTTP server and no browser asset. A trust
environment therefore **executes no candidate command**: its only subprocess is
a fixed vocabulary of `git` identity queries, run with hooks, fsmonitor and
system configuration disabled.

The `admissible` umbrella installs both and is a developer convenience only. It
is forbidden anywhere a trusted claim is made — see the README's installation
section and `packages/umbrella/README.md`.

A Ready environment also holds **no trust credential**. Every entry point that
can read the repository, open the store, bind a socket or start a subprocess
refuses *first* when any of these is set:

```text
ADMISSIBLE_HMAC_KEY        ADMISSIBLE_HMAC_KEY_FILE        ADMISSIBLE_HMAC_KEY_ID
ADMISSIBLE_REVIEW_KEY      ADMISSIBLE_REVIEW_KEY_FILE      ADMISSIBLE_REVIEW_KEY_ID
ADMISSIBLE_REVIEW_KEYRING
ADMISSIBLE_EVALUATION_KEY  ADMISSIBLE_EVALUATION_KEY_FILE  ADMISSIBLE_EVALUATION_KEY_ID
ADMISSIBLE_EVALUATION_KEYRING
```

A **present but empty** variable refuses as well. The name being set means
something intended a signing identity to be in this process; the value can
change under a long-lived MCP or UI process and the intent that set the name
does not. `--help` still answers, because it reads nothing about this machine.

## Start here

Inside a committed Git repository with `.admissible.json`:

```bash
admissible check
```

The command chooses exact `HEAD`, refuses a dirty worktree, runs the configured deterministic checks, records one attempt, and answers four questions:

1. What was checked?
2. What passed?
3. What remains?
4. What should happen next?

It does not sign or admit anything. The explicit `admissible-ready run --preview` command remains available for trusted pipelines and advanced handoffs.

Open the local product with:

```bash
admissible ui
```

The server binds only to `127.0.0.1`. It uses the same Ready document as the CLI and MCP server, serves no remote assets, accepts only same-origin bounded JSON writes, and refuses to start if the process contains a signing, review, observer, or admission credential.

## Friendly status and exact meaning

| Friendly label | Machine status | Canonical meaning |
| --- | --- | --- |
| **Needs attention** | `needs_attention` | A check or bounded requirement failed. The next action may be handled by an agent or person. |
| **Waiting for review** | `waiting_for_review` | Deterministic checks passed; independent review remains. The connected builder must stop. |
| **Checks complete** | `checks_complete` | Evaluation reached `CHECKS_PASSED`. This is not an admission. |
| **Ready** | `ready` | A separate trusted status domain authenticated `ADMITTED` with `CURRENT` standing for this exact commit. |
| **Unable to check** | `unable_to_check` | Identity, configuration, credentials, or an operational boundary prevented a trustworthy evaluation. |

The machine document is `admissible/v0.7/ready-state`, validated by `protocol/ready-state.schema.json`. It includes:

- exact identity and `applies_to_current_commit`;
- friendly status and summary;
- canonical `state`, `readiness`, `standing`, and exit code;
- check counts and structured reasons;
- ordered `next_actions` with stable IDs and reason codes;
- an owner for each action: `agent_or_human`, `reviewer`, `trusted_infrastructure`, or `human`;
- `agent_can_continue`, which is false when authority must change hands.

Agents should call `admissible check --json` or MCP. They must never scrape the human prose.

## Connect an agent

The UI has **Connect agent**. The equivalent CLI is:

```bash
admissible connect \
  --name Builder \
  --purpose "Implement the requested change and stop at review" \
  --runtime hermes
```

Supported setup renderers are:

- Claude Code
- Codex
- Hermes
- local
- custom

The output is copyable provider configuration. It contains the repository path, agent name, purpose, runtime, and the dependency-free stdio command. It contains no credential.

For Hermes, add the generated entry under `mcp_servers` in `~/.hermes/config.yaml`, restart Hermes, and confirm the agent appears in the Ready UI. Live-session files are owner-only, local, and removed when the MCP process exits. A live session proves connection only; it grants no admission authority.

## Agent protocol

Admissible implements MCP `2025-06-18` over stdio without a mandatory SDK dependency. A connected client receives four bounded tools:

| Tool | Purpose | Side effect |
| --- | --- | --- |
| `admissible_get_state` | Read the latest exact-HEAD Ready state | may initialize or migrate the local Admissible store; never runs checks |
| `admissible_get_work_package` | Receive a task bound to repository, commit, tree, policy, limits, and capabilities | may initialize or migrate the local Admissible store; never runs checks |
| `admissible_check` | Run the same deterministic check as the human command; optionally attach an existing bounded evidence JSON object | records an attempt and private logs |
| `admissible_get_remediation` | Receive stable reason codes and ordered next actions | may initialize or migrate the local Admissible store; never runs checks |

The work package allows `read`, `edit`, `test`, `commit`, and `request_check`. It explicitly forbids signing, finalizing, policy trust/revocation, review attestation, evaluation attestation, impeachment, merge, and deploy.

A connected agent follows this loop:

1. Call `admissible_get_work_package` for the task.
2. Confirm the exact base identity.
3. Make and commit the bounded change.
4. Call `admissible_get_work_package` again for the new exact HEAD, then `admissible_check` with that package's `package_id`, `class_id`, `policy_digest`, and `config_path`.
5. If the first action owner is `agent_or_human` and `agent_can_continue` is true, fix that item and recheck.
6. Stop when the owner is `reviewer`, `trusted_infrastructure`, or `human`.
7. Never lower policy, create an attestation, reuse stale evidence, or infer admission from checks passing.

The MCP process never receives signing, reviewer, observer, or finalizer credentials. It refuses to start if one is present.

## Evidence attachment

An agent may attach an **existing** evidence JSON object to `admissible_check`. The server applies the MCP message ceiling, serializes it into an owner-only temporary file, gives that file to the existing evidence parser, and removes it in `finally`.

Attachment is transport, not authentication. The untrusted check domain cannot authenticate reviews, and attaching a signed-looking object cannot produce `Ready`. Reviewer and finalizer keyrings remain elsewhere.

## Trusted Ready status

After the external observer and finalizer issue a durable receipt, authenticate the user-facing Ready projection with the admission verification key:

```bash
ADMISSIBLE_HMAC_KEY=... admissible-trust ready-status --json
```

`ready-status` never runs candidate-owned checks. It verifies standing and emits `ready` only when the exact commit is authentically `CURRENT`. The local UI and MCP process never receive that key and therefore cannot promote stored rows to Ready themselves.

That separation is deliberate:

- **UI/MCP/check domain:** may execute candidate commands; holds no trust credential.
- **Reviewer domain:** signs an independent review; never builds the change.
- **Observer domain:** authenticates provider/isolation evidence after candidate execution ends.
- **Finalizer/status domain:** verifies and anchors; never executes candidate commands.

Receipt authentication is HMAC-SHA256, which is a **shared secret**. Because
verification and signing share that secret, there is no key Ready could be given
that would let it *display* `ready` without also letting it mint what it
displays. So Ready cannot safely verify an authenticated `ready` at all: it says
`checks_complete`, which is the honest answer without the key, and entering the
Trust domain — a different process, a different installed distribution — is what
produces `ready`.

On a developer machine the umbrella still accepts `admissible ready-status` and
the other trust verbs for one release window; the explicit `admissible-trust`
command is what a trusted environment installs and what these documents run.

## Store compatibility and the limits that are real

The 0.8.0 split changed no schema and no stored row. An existing **v0.7** home —
`admissible.sqlite3`, the trusted policy baselines and the private logs under
`$ADMISSIBLE_HOME` — continues to **open and migrate in place**, with no
destructive step, and a home written by a *newer* schema is refused before the
journal mode is set and before any migration runs.

What that costs, said plainly rather than left to be discovered:

- **Live sidecars refuse.** A home with a `-wal`, `-shm` or `-journal` file
  beside it is refused outright. Those files mean the database's current
  contents are in the sidecar rather than in the main file, and reading them
  honestly would mean replaying them — a write to a home this process has not
  yet decided it may use. A plausible answer read out of a stale main file would
  be worse than a refusal.
- **Concurrent same-home processes are unsupported.** Two Admissible processes
  cannot share one home at the same time: the second is told to wait for the
  owner. A process that holds the store open, or one killed without closing it,
  locks every other opener out until it lets go or somebody checkpoints the
  home. That is a **denial of service by design**, and it is the deliberate
  trade.
- **Advisory locks bind only cooperative packages.** The cross-process schema
  lock binds the processes that agree to take it, which is every Admissible
  distribution and nothing else.
- **Same-user filesystem and SQL tampering is outside the claim.** A hand-run
  `sqlite3`, or anything else under this Unix account, can create, migrate,
  corrupt or delete the home between any two steps, and can read this process's
  environment and remove the private logs. The fail-closed reads then produce a
  **denial of service** rather than a false answer, and that denial is real.
  Nothing here is a defence against arbitrary same-user SQL.

Separate distributions are **not an operating-system sandbox** and are not
offered as one. What the split removes is **accidental capability adjacency**: a
signing key is no longer one import away from a process that runs whatever
`.admissible.json` says. Isolation from code that is already hostile and already
running in the account is an operating-system problem, and it stays one.

## GitHub pull requests

The reusable evaluate-only workflow writes an **Admissible Ready** card to the GitHub job summary. It leads with the friendly label, says whether the result applies to the exact commit, shows one next action, and keeps canonical state/readiness under technical details.

A green card still means only that deterministic checks passed. The workflow has no secrets, reviewer keyring, observer key, finalizer, or signing job.

The automated observer/finalizer bridge does not exist yet. Today the retained preview and SHA-256 handoff must cross to external trusted infrastructure manually or through operator-owned automation. See [GitHub Actions](GITHUB_ACTIONS.md) for the exact boundary.

## Process lemmas (unproved)

Family **P** — fail-closed work projection — lives in `paper/READY/`. It is an addendum, not I18. P0/P1/P2 bind agent checks to domain-separated task, package, and artifact identities, and refuse Ready if HEAD moved mid-inspect. P3 binds a review verdict to one `(base, head, tree, patch)` candidate so a large agent build cannot hop approval onto a later tree. These are lemmas to implement, not theorems to cite, until the guards are named, citation-bound, and mutation-killed.

The 0.8.0 distribution split does not change that status. Separating the wheels makes P0's guard obligation harder to violate by accident — the surface that must not hold a credential is now in a distribution that ships no credential loader — and it proves nothing. P0–P3 remain **unproved** process lemmas.

## What Admissible does not do

Admissible is not an agent runner and makes zero mandatory model calls. Claude Code, Codex, Hermes, local models, CI, scanners, and reviewers do their own work. Admissible coordinates identity, policy, evidence, readiness, next actions, receipts, standing, and impeachment.

It also does not:

- let a builder approve itself;
- expose trust credentials to pull-request code;
- call subscription agents from untrusted GitHub jobs;
- treat preview success as admission;
- merge or deploy through the Ready protocol;
- silently retry paid model work;
- weaken an enforceable profile floor.

The strict system is progressive disclosure, not removed security.
