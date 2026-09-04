# admissible-ready

The candidate side of [Admissible](https://github.com/prive-hn/admissible): the
half that runs on a developer's machine and inside a hosted evaluate job.

```bash
pip install admissible-ready      # pulls admissible-core==0.8.1, and nothing else
admissible-ready init --profile python-library
admissible-ready check
```

| module | what it does |
| --- | --- |
| `admissible_ready.cli` | the seven candidate-side commands, and only those |
| `admissible_ready.git_reader` | the one place this product runs `git`, with a fixed argv and a sanitized environment |
| `admissible_ready.runner` | argv-only execution with hashed, bounded, owner-only output — and the closed credential list |
| `admissible_ready.store` | the durable home's schema, its reads, and the writes that only record an observation |
| `admissible_ready.ready` | unsigned Ready state: `inspect_unsigned`, `run_check`, `from_evaluation`, `from_problem`, `work_package`, `render_plain` |
| `admissible_ready.github` | the evaluate half of the CI boundary and the unsigned preview handover |
| `admissible_ready.agent_mcp` | the dependency-free MCP 2025-06-18 stdio surface |
| `admissible_ready.agent_connection` | copyable MCP client setup and the local live-session registry |
| `admissible_ready.ready_server` | the loopback-only HTTP service and its packaged browser assets |

## Commands

```text
profiles   init   run --preview   check   mcp   connect   ui
```

That is the whole surface. `ready-status`, `attest-review`,
`attest-evaluation`, `policy trust|revoke|list`, `finalize`, `verify`,
`explain`, `export`, `import` and `impeach` are **not** here — not hidden
behind a flag or a missing key, but absent from the wheel, because they need a
credential and this is the process that starts the candidate's commands. They
live in `admissible-trust`, which installs no runner, no MCP server and no HTTP
server.

`run` without `--preview` is a refusal with migration guidance. One command
cannot both evaluate and sign: the evaluating process starts code the
repository chose, and a signing key in that process is a key the candidate's
code can reach.

## What it deliberately cannot do

- **It cannot import Trust.** `admissible_ready` imports the standard library,
  `admissible_core`, and `fcd.journal` for the one canonical serialisation Core
  itself uses. The wheel declares exactly one dependency,
  `admissible-core==0.8.1`, with no extras and no environment markers.
- **It cannot load a signing credential.** There is no key loader, no keyring
  reader and no verifier in the distribution. Instead every entry point that
  can read the repository, open the store, bind a socket or start a subprocess
  refuses *first* when any of these is set — empty or not:

  ```text
  ADMISSIBLE_HMAC_KEY        ADMISSIBLE_HMAC_KEY_FILE        ADMISSIBLE_HMAC_KEY_ID
  ADMISSIBLE_REVIEW_KEY      ADMISSIBLE_REVIEW_KEY_FILE      ADMISSIBLE_REVIEW_KEY_ID
  ADMISSIBLE_REVIEW_KEYRING
  ADMISSIBLE_EVALUATION_KEY  ADMISSIBLE_EVALUATION_KEY_FILE  ADMISSIBLE_EVALUATION_KEY_ID
  ADMISSIBLE_EVALUATION_KEYRING
  ```

  Refusing on a *present but empty* variable is deliberate. The name being set
  means something intended a signing identity to be in this process; the value
  can change under a long-lived MCP or UI process, and the intent that put the
  name there does not. `--help` still answers, because it is metadata: it reads
  nothing about this machine.

- **It cannot say `ready`.** The unsigned statuses are `needs_attention`,
  `waiting_for_review`, `checks_complete` and `unable_to_check`. There is no
  signer or verifier parameter on any callable here — removed, not defaulted to
  `None`. Because receipt authentication is HMAC-SHA256, verification and
  signing share secret material, so handing Ready a key to *display* `ready`
  would hand it the ability to mint what it displays. `admissible-trust
  ready-status` is where an authenticated `ready` comes from.

- **It cannot write trusted state.** Its store backend implements the reads and
  the observation-writes — attempts, evidence, the evidence cache, dependency
  edges — and does not implement `trust_policy`, `revoke_policy`,
  `accept_head`, receipt or defect insertion, journal import, or journal
  verification. The `CandidateStore` facade proves the reachable set; the
  absence proves there is nothing behind it. The raw SQLite connection is not
  reachable either: `admissible_ready.store` exports `open_store` and the
  facade it returns, the backend class behind them is module-private, and the
  connection is held in module state rather than as an attribute of either
  object — so no supported name leads from a store to something that could
  drop the schema's append-only triggers. Existing v0.7 homes open and migrate
  in place with no destructive step, and a home written by a *newer* schema is
  refused before the journal mode is set, before the schema script runs and
  before any migration: it comes back byte for byte as it was, with no `-wal`
  or `-journal` beside it.

## Opening a home

Creating and initialising a home happens under a cross-process lock
(`admissible_core.store_open.schema_lock`), keyed by the canonical absolute
path of the database file and kept in a private directory of this user's
temporary space — never inside the home it guards. The lock is taken *before*
the existence check and released only once the schema and the recorded version
are final, so two openers cannot both create a fresh file or both migrate one.
An opener that waits too long says which lock it waited for and which process
held it, rather than hanging.

The decision about whether this build may open a home at all is made on an
immutable read-only connection, before any read-write connection exists. It
cannot create a `-wal`, cannot replay a journal and cannot be talked into a
write. The version is then read *once more* through the read-write connection
before the first pragma, because the lock only binds processes that agree to
take it.

A home with a `-wal`, `-shm` or `-journal` beside it is **refused outright**.
Those files mean the store is open in another process, or that one stopped
without closing it, and either way the database's current contents are in the
sidecar rather than in the main file. Reading them honestly means replaying
them, which is a write to a home this build has not yet decided it may use.

## Honest limits

Separate distributions are **not** a sandbox, and this document does not claim
they are.

- Anything running under the same Unix account can read this process's
  environment, delete or corrupt the SQLite home, and remove the private check
  logs. The fail-closed reads then produce a **denial of service**, not a false
  answer — but the denial is real and package separation does not prevent it.
- Refusing a home that has a sidecar beside it is a **denial of service by
  design**. A process that holds the store open — a long-running one, or one
  that was killed without closing — locks every other opener out until it lets
  go or somebody checkpoints the home. Two Admissible processes therefore
  cannot share one home concurrently: the second is told to wait for the owner.
  That is the deliberate trade. A plausible answer read out of a stale main
  file, while the committed contents sit unread in a `-wal`, would be worse
  than a refusal, and there is no third option that does not write to the home
  first.
- The schema lock binds the processes that take it, which is every Admissible
  distribution, and nothing else. A hand-run `sqlite3` under the same account
  can create, migrate or corrupt the home between any two of these steps. The
  second version check narrows the window; it does not close it, and **nothing
  here is a defence against arbitrary same-user SQL**.
- A check that escapes its process group with `setsid()` survives the
  group kill. That is why an evaluation *records* which boundary confined it
  (`ADMISSIBLE_ISOLATION`) instead of claiming one, and why a preview declaring
  `none` is never finalisable.
- `POST /api/v1/check` on the loopback UI is the local operator pressing a
  button. It is not a package-authorized MCP check and does not pretend to be.
- MCP work packages are single-use per connection and **refillable**. This is a
  use-once token, not a finite budget.
- What this split buys is the removal of *accidental capability adjacency*: a
  signing key is no longer one import away from a process that runs whatever
  `.admissible.json` says. Isolation from code that is already hostile and
  already running in the account is an operating-system problem.

## License

Apache-2.0. The distribution includes the canonical repository `LICENSE` and
`NOTICE`; see the root `LICENSE.md` for scope.
