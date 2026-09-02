# Admissible

Author: **Roque Briceño**. Isolated research + core. Not a product diary.

**A fail-closed admissibility kernel for agents that do not repeat.** Three layers, three proof families, one predicate:

| Layer | Question | Proofs | Kernel |
|---|---|---|---|
| **I** — identity (fail-closed class dispatch) | who actually did the work? | I1–I17 | `fcd/core.py` |
| **R** — scrutiny (refutation-gated admission) | what tried to kill it, and how hard? | R1–R13 | `rga/core.py` |
| **C** — standing (the escape ledger) | what has been found against it since? | C1–C7 | `rga/calibration.py` |

`admissible(id) = sealed ∧ mediated ∧ ¬tainted ∧ ¬impeached` — the union of all three families is the soundness of that one query, and the loudness of its complement. The name is evidence law's, and it is honest exactly where the theorems are: admissibility certifies provenance, known error rate, controlling procedure and exposure to impeachment — never truth. Unified paper: `paper/admissible/DRAFT.md`. Each layer's paper stands on its own.

## Layer I: fail-closed class dispatch

Process: **fail-closed class dispatch**  
Live object: **work item**  
Finished object: **accepted artifact**

Admit by class. Bind one model. Observe what actually ran. Pass only if they match. If the bind is dead, **fail closed** — publish, then ask, retry inside the allow set, or stop. Do not hop.

This is Clark–Wilson integrity applied to LLM binds, not a new algebra.

## Layout

| Path | What |
|---|---|
| `paper/admissible/DRAFT.md` | The unified paper: the admissibility kernel, all three layers |
| `paper/DRAFT.md` | Layer I paper |
| `paper/INVARIANTS.md` | A0–A13, transition tables, I1–I17 |
| `paper/PROOFS.md` | Inductive proofs + explicit adapter/model/impact assumptions |
| `paper/fail-closed-class-dispatch.pdf` | Research PDF, structural and live cockpit figures only |
| `paper/VISUAL.md` | Author interpretation. Not the name, not a 3D task |
| `paper/RGA/` | Refutation-gated admission: `PREMISE.md` (the attack on the brief + round-1 addendum), `INVARIANTS.md` (B0–B11, transitions, R1–R13, faults V1–V15), `PROOFS.md`, `DRAFT.md` |
| `packages/core/` | `admissible-core` 0.8.0: the authority-neutral kernel — identity, policy, evidence, decision, schemas. No console command, no dependencies |
| `packages/ready/` | `admissible-ready` 0.8.0: the candidate side. Runs checks, serves the loopback UI and MCP, holds no key. Depends on `admissible-core==0.8.0` and nothing else |
| `packages/trust/` | `admissible-trust` 0.8.0: the signing side. Reviews, attestations, policy trust, finalization, standing. Starts no candidate command. Depends on `admissible-core==0.8.0` and nothing else |
| `packages/umbrella/` | `admissible` 0.8.0: the developer-convenience dispatcher that keeps the legacy `admissible` command working. Pins all three siblings at `==0.8.0`, installs both authorities, and is forbidden in trusted infrastructure |
| `admissible/` | The **pre-split monolith**, still at 0.7.0 and kept only for the one-release migration window — it is what the source-checkout CI gate runs and what the legacy suites are written against. 18 CLI commands, eight risk-shaped starter profiles, Python 3.10+. It is history with a window, not the current split architecture: that is `packages/` |
| `admissible/templates/` | The workflow/action files `admissible init --ci github` scaffolds, byte-identical to this repository's own copies. Only `consumer-workflow.yml` also ships inside the `admissible-ready` wheel |
| `.github/workflows/admissible-gate.yml` | The reusable `workflow_call` gate a consumer pins by commit. It is **evaluate-only**: it runs candidate commands, holds no signing key and no reviewer keyring, and contains no finalize job at all. `admissible-trust finalize` runs elsewhere, on a trusted machine that has no candidate executor installed, and is the only place ADMITTED is ever issued |
| `.github/actions/admissible/action.yml` | Evaluate-only composite action, deliberately with no finalize mode: a repository-local action inside the candidate cannot promise the finalizer's separation |
| `scripts/sabotage_admissible.py` | Deletes each product trust boundary in turn and proves the contract suite goes red; restores every target and verifies it byte for byte. Then breaks each package-separation invariant `SEP1`–`SEP12` in a disposable clone and prints a receipt per invariant |
| `tests/architecture/separation_guards.py` | The separation guard registry: `SEP1`–`SEP12`, the concrete guard site each one lives at, the named test every mutant must kill, and the exact failures — signature and count — that test must report |
| `tests/architecture/separation_observer.py` | The trusted observer that watches one mutated test run from outside it and authenticates what it saw, so that the process being tested cannot author the evidence the harness reads |
| `fcd/` | Portable acceptance kernel (Python 3.10+, zero runtime deps) |
| `rga/` | Refutation-gated admission kernel + calibration escape ledger, composed over `fcd`; writes no FCD field |
| `atlas/` | Immutable evidence/capability reducer |
| `paper/` | Three papers with their invariants and proofs. The standalone PDFs and `admissible-volume.pdf` are regenerated from the release-candidate Markdown with the repository-contained renderer |
| `eval/bench/` | Deterministic three-layer kernel bench over stdlib-specified targets (stdlib as differential oracle, seeded AST mutants); `RESULTS.md` is generated, freshness-tested |
| `protocol/` | JSON Schemas for project, agent/model/gate, envelope, package, receipt, memory, impact, steering, snapshots and all three journals (fcd, rga, calibration) — conformance-tested against live emissions |
| `server/` | Verified project registry, `ExecutionAdapter` boundary and HTTP authority server |
| `apps/cockpit/` | React/Vite project/work/artifact interaction layer |
| `docs/` | Interaction, evidence, skin, execution and artifact contracts |
| `docs/UI_GLOSSARY.md` | Paper vocabulary mapped to what the cockpit shows, in plain words |
| `docs/DEVELOPER_WORKFLOW.md` | The developer gate: commands, exit codes, what a receipt is and is not |
| `docs/READY.md` | The human + agent Ready product: local UI, MCP tools, stable status/actions, credential boundaries |
| `docs/GITHUB_ACTIONS.md` | The evaluate-only CI gate: what it pins, what it publishes, and what it deliberately cannot do |
| `docs/COST_AND_LATENCY.md` | Cost units, ceilings, cheapest-first ordering; no model calls anywhere |
| `docs/IMPEACHMENT.md` | Filing defects, observed vs reachable vs unknown impact, raw miss counts |
| `examples/developer-workflow/demo.sh` | Offline end-to-end walk-through in a throwaway repository: init, an evaluation, a cache hit, the four-step admission path, a refusal, the signed-review handoff, an impeachment |
| `docs/PROOFS_PLAIN.md` | Every theorem of both papers — FCD I1–I17 and RGA R1–R13 — in one plain sentence each, plus what neither proves |
| `tests/` | 2916 kernel/server/context/project/class/RGA/calibration/bench/schema/paper/custody tests, including 2442 for the developer product |
| `atlas/tests/` | 37 atlas/immutability/impact/schema tests |
| `apps/cockpit/tests/` | 71 UI/steering/context/receipt/readiness/instrument/skin-contract/skin-authority tests |
| `metrics/SCHEMA.md` | Event contract. Rates stay empty until a named cut |
| `data/` | Local collector output. Not committed |
| `eval/` | Deterministic benchmark and historical review material. Private provider-routing records are excluded from the public release tree |
| `enforcer/` | Thin shim → `fcd`. Do not add logic here |

## Installing Admissible

Admissible is **one repository** and **four coordinated 0.8.0 distributions**,
built from `packages/`, meant to be installed into **separate processes**. The
separation is physical rather than conventional: the Ready wheel does not
contain Trust's modules, the Trust wheel does not contain Ready's, and neither
declares the other as a dependency under any extra or environment marker.

| distribution | console command | commands it installs |
| --- | --- | --- |
| `admissible-core` | none | nothing — it is a library, and the only one of the four with no dependencies |
| `admissible-ready` | `admissible-ready` | `profiles` `init` `run` `check` `mcp` `connect` `ui` |
| `admissible-trust` | `admissible-trust` | `ready-status` `verify` `explain` `status` `impeach` `attest-review` `attest-evaluation` `policy` (`trust`, `revoke`, `list`) `finalize` `run` `export` `import` |
| `admissible` | `admissible` | none of its own: static compatibility dispatch of the legacy verb to whichever sibling owns it |

```bash
pip install admissible-core==0.8.0   # kernel alone; no dependencies
pip install admissible-ready==0.8.0  # + exact Core; candidate execution
pip install admissible-trust==0.8.0  # + exact Core; trusted finalization
pip install admissible==0.8.0        # developer umbrella; all three siblings
```

Those index commands become valid only after all four artifacts exist in the
canonical registry and their hashes have been read back. Before publication,
build from this exact checkout with
`.venv/bin/python scripts/build_release_artifacts.py` and install the verified
local artifacts from `dist/`.

Every sibling edge is an **exact** `==0.8.0` pin, never a range. The four agree
about what a policy digest is, what an evidence record hashes to and what a
decision means; a range would let a Ready wheel evaluate against a kernel that
computes one of those differently, and the disagreement would surface as a
check that passed here and a receipt that refused there.

**A trusted machine installs exactly one authority.** `admissible-ready` where
candidate code runs; `admissible-trust` where a credential is held. Installing
`admissible` puts *both* on one machine, which is exactly what makes it a
developer convenience and exactly why it is forbidden in trusted
infrastructure — not in a finalizer environment, not in a reviewer or observer
key environment, not in a policy signing or policy trust environment, not in
any documented minimal trusted deployment, and not as a dependency of anything
that runs in one.

The Ready environment holds **no Trust package and no trust credential**: every
Ready entry point that can read the repository, open the store, bind a socket
or start a subprocess refuses first when a signing, review or observer variable
is set — present but empty counts as set. The Trust environment holds **no
Ready package and executes no candidate command**: its only subprocess is a
fixed vocabulary of `git` identity queries.

Receipt authentication is HMAC-SHA256, which is a **shared secret**: because
verification and signing share that secret, a Ready process handed a key to
*display* `ready` would be a Ready process able to mint what it displays. So
Ready cannot safely verify an authenticated `ready` without becoming Trust; it
reports `checks_complete`, and `admissible-trust ready-status` is where an
authenticated `ready` comes from.

What the split buys is the removal of **accidental capability adjacency**: a
signing key is no longer one import away from a process that runs whatever
`.admissible.json` says. It is **not an operating-system sandbox** and is not
offered as one. Anything already running under the same Unix account can read
this process's environment, delete or corrupt the store and remove the private
logs; the fail-closed reads then produce a denial of service rather than a
false answer, and that denial is real. See `docs/READY.md` and
`docs/DEVELOPER_WORKFLOW.md` for the store and local-denial-of-service limits
in full, and `packages/ready/README.md`, `packages/trust/README.md`,
`packages/core/README.md` and `packages/umbrella/README.md` for each wheel's
own contract.

## Admissible Ready (`admissible` v0.7.0)

The default product loop is deliberately short:

**change → check → fix the next item → recheck → ready**

```bash
pip install admissible                         # or admissible-ready alone
admissible profiles                            # the eight starters
admissible init --profile python-library       # policy + ignores
$EDITOR .admissible.json
git add -A && git commit -m "adopt the gate"

admissible check                               # exact HEAD, friendly result
```

Open the local product or generate copyable agent setup when you want either
surface:

```bash
admissible ui                                  # local Ready product
admissible connect --name Builder --purpose "Implement this change" --runtime hermes
```

People see **Needs attention**, **Waiting for review**, **Checks complete**, and
**Ready**. Agents receive the same exact repository/commit/tree/policy state as
`admissible/v0.7/ready-state`, plus stable reason codes and ordered actions over
MCP. Neither surface can sign or finalize. See `docs/READY.md`.

The explicit evaluator remains available for advanced handoffs and trusted
automation:

```bash
admissible-ready run --preview --sha "$(git rev-parse HEAD)"   # evaluate; never signs
admissible-trust explain "$(git rev-parse HEAD)"               # what is known, and why
admissible-trust verify "$(git rev-parse HEAD)"                # standing + authenticity
admissible-trust status                                        # repository at a glance
admissible-trust impeach "$(git rev-parse HEAD)" --evidence defect.json --test unit
admissible-trust export --out journal.json
admissible-trust import --in journal.json
```

Those are the explicit commands, and they are what a trusted environment
installs. On a developer machine with the umbrella, `admissible run --preview`,
`admissible explain`, `admissible status`, `admissible export` and `admissible
import` still work for **one release window** as transitional aliases: the
dispatcher hands each to whichever sibling owns it, statically, from the words
typed and **never by ambient credentials**, and a human — not a `--json`
caller — gets a line on stderr naming the explicit replacement.

`check` runs the same deterministic preview evaluation as `run --preview`; it
does not issue a receipt. A result can say **Ready** only after a separate
trusted status command authenticates an `ADMITTED` receipt with
`CURRENT` standing:

```bash
ADMISSIBLE_HMAC_KEY=... admissible-trust ready-status --json
```

The advanced admission flow still belongs to separate trust domains — and, now,
to separate installs — and is described under **Running the checks and admitting
the result** below:

```bash
admissible-ready init --profile python-library --ci github --tool-sha FULL_SHA
export ADMISSIBLE_HOME=/var/lib/admissible
export ADMISSIBLE_DURABLE_HOME=1
admissible-trust policy trust                                        # the operator
admissible-trust attest-review --review r.json --out attested.json   # a reviewer
admissible-trust attest-evaluation --preview p.json --out e.json \
    --source-receipt receipt.json --isolation single-use-vm          # the observer
admissible-trust finalize --preview p.json --sha "$SHA" \
    --policy-root DIR --evaluation-attestation e.json \
    --reviews /trusted/out-of-band/reviews.json                       # the finalizer
```

Each of those four lines runs in a different environment. Only the first has
`admissible-ready` installed; none of the other three does, and the machine that
runs the last one has no candidate executor on it at all.

Eight risk-shaped starter profiles, chosen by the risk of the change rather than
only by language: `python-library`, `typescript-application`, `rest-api`,
`database-migration`, `authentication-change`, `payment-change`,
`infrastructure-change`, `documentation-only`. `init` also adds what the chosen
profile's own checks write (`__pycache__/`, `dist/`, …) to `.gitignore`: an
exact-SHA run refuses a dirty worktree, so without that the first run would
block on output the policy itself asked for. Profiles whose checks are your own
`make` targets add nothing and say so — nothing here can know what those write.

`run` is the one verb both distributions implement, so it is the one verb whose
owner is decided by shape rather than by a table. **Ready owns preview
evaluation**: `admissible-ready run --preview` issues no receipt, appends
nothing to the journal, and reads no key. **Trust retains bare `admissible-trust run`
for one release window**, as a transitional alias for `finalize`, which
consumes a preview somebody else already produced and executes no check. The
umbrella dispatches between them explicitly — `--preview` as a bare flag is
Ready's evaluation, `--preview FILE` or no `--preview` at all is Trust's alias —
and never by ambient credentials. **Preview is not "no
I/O"** — it still runs the checks and still writes their exact output to
owner-only private logs under `$ADMISSIBLE_HOME/logs/`, and it records the
attempt and its evidence so `explain` can describe them afterwards. `--no-cache`
re-runs everything and still records; `--no-store` records nothing and says so.

Exit codes are stable and command-specific: `0` from `admissible-ready run
--preview` means only that the checks passed; `0` from `finalize` — and from
the bare `admissible-trust run` alias for it — means the exact receipt is
admitted; and `0` from `verify` or `status` means authenticated current
standing. `1` means refused or not current, and `2` means blocked by
configuration, identity, a key, a ceiling, or an operational problem.
`admissible-ready run --preview` signs nothing, so its zero can never mean
admitted; the Trust alias is the one spelling of `run` whose zero can.

### Cost is declared; a language model is never called

Admissible makes **zero** model calls, in every profile, on every path — the
`test_admissible_makes_no_model_call` contract walks the package and fails on so
much as an `http.client` import. Cost units are integers your team defines, and
ceilings are checked against the *plan* before a single child process is
spawned. A profile that requires independent review declares that in
`required_independent_reviews`, `reviewer_key_ids` and `author_key_ids` — all
three, because "independent" needs both lists and they must be disjoint, and a
class missing either is refused where policies are parsed. Whoever produces the
review — a person, or a tool you run yourself — decides what it costs. See
`docs/COST_AND_LATENCY.md`.

The five high-risk profiles (`rest-api`, `database-migration`,
`authentication-change`, `payment-change`, `infrastructure-change`) also carry a
floor taken from the shipped profile itself: a repository may add checks and
raise the review count, and may never require fewer reviews or drop one of the
profile's required checks. The argv stays yours — the floor is about which
checks exist, never which commands they run. The policy travels inside the tree
it governs, so without a floor a change to payment code could also lower the bar
for payment changes.

### Running the checks and admitting the result are different jobs

`admissible-ready run` evaluates. It never signs, it reads no key, and
`--preview` is required — without it the command refuses. The reason is not
caution: a run starts commands the repository under evaluation controls, and a
process holding a signing key while it does that has already lost the boundary
the key was protecting. Since 0.8.0 that is also a packaging fact: there is no
key loader in the Ready wheel to reach for.

The consequence is that the records a run produces are a *description* of what
happened, not a proof of it. A check can leave a descendant behind that edits
what the run later reports, so recomputing a decision from those records proves
the arithmetic and nothing else. Turning an evaluation into a receipt therefore
takes three more parties, each doing something the others must not be able to:

| Party | Does | Key |
| ----- | ---- | --- |
| the **operator** | records once, in a trusted context, which policy is enforceable for a class (`admissible-trust policy trust`) | none |
| an external **observer** | after the run is over and its process group is gone, validates external infrastructure evidence, independently asserts isolation, and signs exactly which records that evaluation produced (`admissible-trust attest-evaluation --isolation MODE`) | `ADMISSIBLE_EVALUATION_KEY` |
| the **finalizer** | verifies that attestation and the reviews, re-derives repository, tree and policy from its own checkout, recomputes the whole decision, anchors the receipt (`admissible-trust finalize`) | `ADMISSIBLE_HMAC_KEY` |

**No evaluation attestation, no receipt.** There is no default and no fallback.

A class that requires independent review can never be `ADMITTED` by a run: it
holds no reviewer keyring, because a keyring given to a process that runs
candidate-owned commands is a keyring given to the candidate. The decision says
so rather than routing around it, in a `readiness` field beside `state`:

| `readiness` | meaning |
| ----------- | ------- |
| `READY_FOR_ATTESTATION` | every required check passed and nothing is outstanding that this evaluation could resolve; it is ready for an observer to attest and a finalizer to admit, and it is **not** an admission |
| `AWAITING_REVIEW` | every deterministic required check passed and the evidence is valid; only independent review is outstanding, and nothing here can authenticate it |
| `NOT_READY` | something else refused or blocked it |

The public action and reusable workflow also output `state`, whose evaluation
values are exactly `CHECKS_PASSED`, `REFUSED` and `BLOCKED`. `ADMITTED` is a
signed receipt state only. Once the observer has authenticated the provider's
record, the provider-conclusion matrix is exact:

```text
READY_FOR_ATTESTATION -> success only
AWAITING_REVIEW -> success or failure
NOT_READY -> no provider conclusion is admissible
```

`cancelled` and `timed_out` are never admissible. The `failure` exception is
only for a genuine `AWAITING_REVIEW`: the hosted gate is deliberately red when
all deterministic checks passed but authenticated review remains out-of-band.
The matrix is applied to the readiness the finalizer recomputes from evidence
and its trusted policy. Observer-bound or preview-reported readiness cannot
widen the provider conclusions that recomputation permits.

`ADMITTED` is not among them, and it never was a `readiness` value: `readiness`
describes an evaluation, and an evaluation admits nothing. `ADMITTED` appears in
exactly one place — the `state` of a signed durable receipt.

`AWAITING_REVIEW` is never called an admission, and in CI it is always **red**.
An earlier design reported it as green whenever a finalize job was enabled — and
skipped that job on every pull request, so review-gated pull requests went green
with zero authenticated reviews. The shipped reusable workflow has no signing
job at all now, so the answer no longer depends on anything.

The hosted preview always records evaluator isolation as `none`; there is no
caller isolation input. Later, the **observer independently asserts isolation**
with required `attest-evaluation --isolation MODE`, after checking evidence in
the observer's own trust domain. The preview's candidate-adjacent claim never
authorizes finalization.

Signed reviews, signed authorship claims, and the evaluation observer are
**separate authenticated roles**. Reviews and authorship travel out-of-band to
`finalize --reviews`; adding or replacing them requires **no observer re-sign**,
because the finalizer authenticates and binds those records independently.

### Durability: a receipt is not an anchor

`finalize` refuses a home inside `GITHUB_WORKSPACE` or `RUNNER_TEMP`, and on a
hosted runner refuses any home not declared durable with
`ADMISSIBLE_DURABLE_HOME=1`. The reason is a bootstrap caveat that no amount of
signing removes: **a first anchor cannot prove its own past.** A journal that is
destroyed with the job bootstraps a fresh one every run, so no rollback is ever
detectable and "current" means nothing. Historical authenticity begins at a
trusted first anchor or continuous publication; restoring an older database is a
deliberate trust decision, not a backup restore. A receipt on its own is
authentic history and cannot show that its head is still the current one.

### What is not built

The shipped GitHub workflow publishes its preview both as a bounded base64 job
output and as a retained run artifact named with the full evaluated SHA and run
attempt. The artifact includes `preview.sha256`, and it is uploaded even when
`AWAITING_REVIEW` makes the gate red. Getting from that artifact to a receipt —
having the observer independently authenticate the provider run and isolation,
then driving the durable finalizer — is a manual step or your own script today.
A service that watches for completed runs, authenticates them against the
GitHub API and drives the finalizer would be reasonable; it is not in this
repository, and the workflow should not be read as if it were.

### Versions and compatibility

The split distributions — `admissible-core`, `admissible-ready`,
`admissible-trust` and the `admissible` umbrella under `packages/` — are all
**0.8.0**, versioned and built together and pinned to each other with `==`.
That is a coordinated version and a coordinated build in this repository, and
nothing more: no distribution here has been published anywhere. The root
project is still the pre-split monolith at **0.7.0**; it is retained for the
one-release migration window and for the source checkout the hosted gate runs,
and it is not the current architecture.

Nothing about the wire formats moved. The friendly, unsigned product
contracts are `admissible/v0.7/{ready-state,agent-work-package,remediation,agent-connection}`.
Existing admission, receipt and signature domains remain on
`admissible/v0.6/{workflow-policy,workflow-decision,workflow-evidence,
workflow-receipt,workflow-preview,review-attestation,evaluation-attestation,
workflow-journal-export,evidence-cache,environment-fingerprint,attempt,
developer-workflow-admission}` deliberately: changing a signed domain string
would make authentic historical material stop verifying.

The research kernel is a separate layer at **0.5.0**, and its signing domains
stay `admissible/v0.5/{journal-head,journal-chain,composed-receipt}` for the same
reason. v0.7 adds presentation, local HTTP, MCP and trusted authenticated status over
the existing admission engine; it does not silently rewrite a v0.6 receipt. The
0.8.0 split moves where code is installed and which process may hold a key; it
changes no schema, no domain string and no stored row, and an existing v0.7 home
opens and migrates in place.

See `docs/READY.md` for the normal human/agent workflow;
`docs/DEVELOPER_WORKFLOW.md` for what `run` actually does, how attempts and
the exact-identity cache work, how signed review attestations block a merge, and
the three-party admission path; `docs/GITHUB_ACTIONS.md` for the evaluate-only
CI boundary, the `tool-sha` pin and what is deliberately not built there;
`docs/COST_AND_LATENCY.md` for ceilings, cache keys and the model-call boundary;
`docs/IMPEACHMENT.md` for filing defects and carrying standing between machines.

## Cockpit

The reference product is a three-pane authority surface, not a decorative graph:

```text
Project/capability atlas | Selected work line + bounded gate tray | Real runnable artifact
```

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
npm --prefix apps/cockpit install
make test
make audit
make cockpit
# http://127.0.0.1:8791
```

A verified local/GitHub project comes first. **Open project…** searches the repository folders the server can see (`FCD_PROJECT_ROOTS`, or the conventional ones under `$HOME`); picking one fills its path, origin and base branch from the repository itself. The composer is disabled until load. A prompt then compiles into a visible contract and node-scoped question — the **authority** compiles it (`POST /api/work-items/compile`), so the terms an operator approves are the terms the machine enforces, never a locally guessed shape. Every gate chooses an agent/profile, execution adapter, exact provider/API model, context mode and continuity hint before Admit. Agent instructions/tools/authority and exact-route readiness are visible in the envelope under that gate; an unavailable route cannot Admit. After Admit the envelope locks and shows package/model/steering receipts. The bottom input steers project, work, gate, stage, artifact or evidence scopes and accepts `/inspect`, `/why`, `/impact`, `/fix`, `/retry`, `/pause`, `/discard`, `/accept`.

The cockpit is the layer above `fcd` and below the skins: it carries structure, function and meaning, never mood. Pane widths, collapse, text size and density belong to the operator and survive a reload. A skin may repaint by answering the token contract, or **re-represent** by supplying its own view of the same snapshot — a city, a processor die, a room of avatars — while the shell keeps a spine no skin can remove: the rail, the refusal strip, the steering bar and the way back to settings. `Focus` ships as a worked single-column example. `apps/cockpit/src/styles.css` holds no colour literal at all — every value comes from the token contract in `src/skins/contract.ts`, and `tests/skin-contract.test.ts` fails the build on a stray hex, an unanswered token, an `-ink` colour under 4.5:1 against any ground it can be painted on, or a `--focus` ring under 3:1. Mood belongs to skins; `instrument` and `nocturne` are deliberately quiet references. See `docs/SKIN_PROTOCOL.md`.

The centre pane renders a line as a **load path**: each gate holds or shears, and everything under a fail-closed break is drawn as work that never ran, not work that is queued. **Models** in the command rail lists every exact provider model the project can bind, the gate that uses it and its readiness checks. Every machine term carries its plain reading on hover, and **Legend** opens the full searchable mapping — the same table as `docs/UI_GLOSSARY.md`. State arrives over SSE (`GET /api/state/stream`); polling is only the fallback when a server does not expose it.

Concurrent lines pin project `P` and memory `K` at Open. Only accepted work promotes memory through serialized CAS. Active stale lines get an impact review; failed/accepted lines do not pollute drift navigation. `fresh_blind` reviews prohibit executor continuity. Existing executor tool/session loops remain external behind `ExecutionAdapter`.

See `docs/PROJECT_DEFINITION.md`, `docs/INTERACTION_LAYER.md`, `docs/EVIDENCE_MODEL.md`, `docs/SKIN_PROTOCOL.md`, `docs/EXECUTION_ADAPTER.md`, and `docs/ARTIFACT_ADAPTER.md`.

## Core (`fcd`)

```python
from fcd import Enforcer, Policy, StageCache
from fcd.metrics import rates, survival
from fcd.watchdog import poll

policy = Policy(
    allow={"impl": {"alice", "carol"}},
    deny={"impl": set()},
    phi={"alice": "vendorA:model-a", "carol": "vendorC:model-c"},
    required={"impl": [("write", "w1"), ("check", "c1")]},
)
e = Enforcer(policy)          # optional clock= for tests
e.open("w", "impl", "bodyhash")
e.admit("w", "alice")
e.bind("w", True)             # u(phi(a)); False => BindFail, published
e.observe("w", "vendorA:model-a")
e.decide_pass("w")            # mismatch => F1, Closed, no hop
```

Cache is **stage-scoped only**. Key = `(specialist, norm(φ(a)), prefix_hash)`. A hit never skips Observe. Clear on Admit/Close. Sharing a cache across specialists is F2.

Watchdog: `poll(pc, alive_fn, on_death)`. Inject liveness (macOS: `os.kill`; iOS: heartbeat). It only closes. It cannot accept.

## Refutation-gated admission (`rga`)

FCD verifies the die, not the roll: with a stochastic generator, knowing which model ran says nothing about the artifact, and `paper/PROOFS.md` lists body quality and provenance as unproved. `rga` moves the gate to the claim. A class pins, before any artifact exists, the formal claims an artifact must satisfy and the deterministic refuters that attack them; each refuter carries a power as a labelled record — a kill-rate the kernel **counts** from a ledger of seeded defects, or `1-(1-eps)^N` from a declared `(eps, N)` the seal carries; the same bind is sampled `k` times, each sample registered before the next stage runs; every refuter is tried on every sample; admission requires every cell survived, every refuter replayed once with the same outcome, concordance with the designated sample, and power above a floor. The seal says what was attacked, at what power, against which defect model, and what was not.

```python
import hashlib
from fcd import Enforcer, Policy
from rga import Admission, AdmissionPolicy, ClaimSpec, ClassAdmission, DefectModel, LedgerEntry, Refuter

artifact_bytes = [b"sample-0", b"sample-1", b"sample-2"]
witness_hash = hashlib.sha256(b"tests: 12 passed").hexdigest()

fcd = Enforcer(Policy(allow={"impl": {"gen", "rev"}}, deny={"impl": set()},
                      phi={"gen": "vendorA:model-g", "rev": "vendorC:model-r"},
                      required={"impl": [("write", "s0"), ("write", "s1"), ("write", "s2"), ("check", "c1")]}))
rga = Admission(fcd, AdmissionPolicy({"impl": ClassAdmission(
    claims=(ClaimSpec("tests_pass", "spec-hash", frozenset({("tests", "v1")}), "D-hash"),),
    k=3, theta=1.0, p_min=0.8, excluded=frozenset({"refuter_source"}),
    residual=(("correct fix", "check_stage"),))}))

rga.declare(Refuter("tests", "v1", author="tester", mode="ledger"))
rga.measure("tests", "v1", DefectModel("D-hash", author="mutator"),
            [LedgerEntry(f"m{i}", "killed" if i < 9 else "survived") for i in range(10)])   # power 0.9, counted
fcd.open("w", "impl", "bodyhash")
rga.open("w", generator="gen", sampling_hash="temp=0.7")      # before any sample stage runs
for i in range(3):
    fcd.admit("w", "gen"); fcd.bind("w", True); fcd.observe("w", "vendorA:model-g"); fcd.decide_pass("w")
    rga.sample("w", artifact_bytes[i], package_categories={"contract"}, sampling_hash="temp=0.7")
    seed = rga.seed_for("w", i, "tests", "v1", "tests_pass")     # exists only after the artifact
    rga.trial("w", "tests", "v1", "tests_pass", i, seed, "inputs", "survived", witness_hash)
rga.replay("w", 0, "survived", witness_hash)                   # divergence refuses the refuter everywhere
fcd.admit("w", "rev"); fcd.bind("w", True); fcd.observe("w", "vendorC:model-r"); fcd.decide_pass("w")  # Accept -> S
seal = rga.seal("w")                                           # S_R, a subset of S
```

On top of the seal sits the **escape ledger** (`rga/calibration.py`, C1–C7): a defect found in a *sealed* artifact is filed as a counterfactual trial — the pinned refuter at a finder-chosen nonce, kernel-derived seed, refuted verdict, one identical replay — and from that one checkable object the loop follows mechanically: the seal is impeached (a pure query; the record never rewrites), every vouching refuter is charged (write-once per wrong-verdict cell), no successor defect model installs without covering the escape or naming its exclusion, and an instrument past its declared miss budget cannot be pinned again. Every seal the authority issues is counter-signed with its instruments' track record in the same step, and `mediated(id)` reads that stamp back — so a seal that reached the scrutiny layer without passing this authority is visible as **IR**, not IRC, and never answers admissible. Every class states its miss budget explicitly: a class nobody configured is refused, never treated as one with an unlimited budget. Forgetting is loud; what was never found, the ledger says it cannot see — and one thing more replay alone cannot see: a coherent rewrite of root transition inputs, a journal shortened at the tail, or a journal shortened by a coherent group of events no surviving event recomputes against, each reads as another honest history. Deletion is the direction that raises standing. v0.5 closes that residue only on the authenticated publication path: immutable authority-owned journals, externally anchored monotone heads, and a signed composed receipt derived from the current I/R/C state. A deployment that does not issue and verify that receipt retains the replay-only limitation. Premise round for this layer: `eval/reviews/rga-calibration-premise-SYNTHESIS.md`.

`rga` reads `fcd` state and writes none of it (R11), so I1–I6, I8 and I9 hold on the combined machine by citation. Every guard the fault table (V1–V15) names is a named method, and `tests/test_rga_mutation.py` replaces each with a no-op — one at a time — and proves the forbidden state becomes reachable; `tests/test_rga_citations.py` fails if a proof cites a line that no longer contains the cited symbol (a move-detector — the proofs' sentences claim enforcement, the test keeps them pointed at live lines). `paper/RGA/PREMISE.md` records the attack on the brief — 38 findings, none of the six "kills-premise" claims survived as such — plus two of the author's pre-registered positions that fell, and its §9 records what an independent five-lens review of the finished kernel then broke: five kernel defects, two FCD kernel defects (`no_admit` could fail an accepted item; `open` silently replaced an existing id — both repaired here with tests), and a set of over-claims in these documents.

### Authenticated composed receipts (v0.5)

`fcd/journal.py` stores each I/R/C event as a deeply immutable mapping and each authority exposes its journal as a tuple snapshot. Legacy plain-dictionary journals still replay after exact canonical-JSON normalization. `fcd/head.py` signs ordered journal heads and advances three heads atomically in an external monotone registry. `rga/attestation.py` derives `sealed`, `mediated`, `tainted`, `impeached`, artifact identity, and the exact three current heads from one composed authority stack; callers cannot supply those predicates.

```python
from fcd import HMACSHA256Signer, MonotoneHeadRegistry
from rga import issue_admissibility_receipt, verify_admissibility_receipt

signer = HMACSHA256Signer("issuer-1", key_bytes)
registry = MonotoneHeadRegistry()  # persist outside the journals in production
receipt = issue_admissibility_receipt(
    "w", fcd, rga, calibration, registry, signer,
    journal_namespace="project-or-deployment-id", issued_at=clock())
verify_admissibility_receipt(
    receipt, fcd, rga, calibration, registry, signer)
```

The journal namespace is a stable identity for one authority stack; unrelated projects or deployments must use different namespaces when sharing a registry. The registry serializes concurrent updates across namespaces. Successor receipts carry only new event digests, and the registry recomputes the cumulative hash chain from its current head before accepting them, so a longer fork cannot replace an anchored prefix. Historical authenticity begins at a trusted first anchor or continuous publication; a first receipt cannot identify which coherent pre-anchor history actually ran. A receipt is *stale* when it is not registry-current for the present journal state; composed `issued_at` is signed metadata, not expiry. The receipt schema defines the wire shape, while semantic validation must also require each head ID to equal `admissible/{journal_namespace}/{role}`. The bundled HMAC signer is the dependency-free reference, not public-key non-repudiation. The computational boundary assumes HMAC-SHA256 unforgeability and SHA-256 collision/second-preimage resistance. Journal-head and composed-receipt signatures use distinct domain tags; signer/keyring objects refuse copy, deepcopy, and pickle to prevent accidental key persistence. Compromise or rollback of both signer/key and registry, dishonest key custody, and concurrent mutation outside an authority's atomic single-writer model remain explicit non-theorems.

## Scale: lines, stacks, time

One work item is a line (a trace). A project is many lines, possibly dependent on each other. Time is policy evolution. All three are now in the core:

**1. Replay.** `Enforcer.from_events(journal, *policies)` rebuilds state deterministically from the append-only journal — the enforcer itself is event-sourced (as are `Admission` and the calibration authority, each with re-guarded replay). The reference server, however, persists none of these journals: its kernel state is process-lifetime, and a restart empties the escape ledger — durability of the *record* is a kernel capability the demo deployment does not yet exercise. Bind success is durable (`bind` event), so a crash between Bind and the first call still replays to `Running`. Replaying never emits duplicate events. Unknown policy version in the journal is an error, never a silent default.

```python
rebuilt = Enforcer.from_events(journal, policy_v1, policy_v2)
```

**2. Version pinning.** `install(new_policy)` swaps the live policy. Items **pin** the version at Open and finish under it; new items get the new version. Re-using a version string with different content is rejected — a version is an identity, not a slot. This is how "add/remove specialists, change φ" stays inside the theorems: in-flight lines are untouched by construction.

**3. DAG gate.** `open(..., depends_on=("a",))` refuses unless every dependency is already an **accepted artifact** in the store. Lines stack; nothing opens on top of an unaccepted line.

```python
e.open("a", "impl", "hash-a")
# ... a accepted ...
e.open("b", "impl", "hash-b", depends_on=("a",))
```

What is still out of scope: scheduling/priority across lines (any order is legal), cross-item cache reuse (still F2), and quality.

## Metrics (empty on purpose)

Four rates, forward log, after a **named cut** `[t0, t1]` with window `W` = class p95 of prior completes, or 12 minutes if n < 30.

| Rate | Sample | Event |
|---|---|---|
| Misbind | first Observe / stage | `norm(exec) ≠ norm(decl)` — always beside silent-fail |
| Silent fail | well-formed stages + orphan opens | no decide/accept in `W` (fail-closed counts published) |
| Bleed | stages of class `c` | `a ∉ π*(c)` as-of `ts` (check stages use `π_chk`) |
| Time-to-stage | well-formed stages | survival to decide/accept, right-censored. Not a mean |

```python
from fcd.metrics import rates, survival
r = rates(e.events, t0=0, t1=10, W=2, policy=None)
s = survival(e.events, t0=0, t1=10, W=2)
```

No numbers in the paper until those calls run on a write-ahead journal after a named cut. Mixed historical logs are not rates.

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

3024 checks green in this repository, in two scopes that are counted
separately because they prove different things:

| Scope | Checks | Where |
| ----- | -----: | ----- |
| Research kernel — the number the paper cites | 582 | 474 in `tests/` + 37 `atlas/tests/` + 71 `apps/cockpit/tests/` |
| Developer product (`admissible/`) | 2442 | `tests/test_admissible_*.py` + the split suites under `tests/architecture/`, `tests/core/`, `tests/ready/`, `tests/trust/` and `tests/compatibility/` |
| **Total** | **3024** | 2916 under `tests/`, 37 atlas, 71 cockpit |

The research-kernel number moves when kernel-scope checks are added, and the
cockpit server's are: `tests/test_server.py` carries neither the
`test_admissible_` prefix nor a product directory, so its checks are counted
against the number the paper cites and the paper moves with them. The runtime
split puts new product checks in per-wheel directories rather than under the
`test_admissible_` prefix, so the scope split is by directory as well as by
filename and a new split suite cannot drift into the kernel scope unnoticed.

The paper artifact gate is deliberately fail-closed: the complete pinned build
closure is mirrored in the `dev` extra and `paper/requirements.txt`, so a clean
`pip install -e '.[dev]'` can rebuild and byte-check every committed PDF and
generated figure. The JSON Schema dependency remains optional for runtime-only
installs; schema-only tests skip when that extra is absent.

```bash
make test        # both Python suites, then the cockpit suite
make audit       # npm audit; dev-server packages are part of the threat surface
make build
```

The developer product's trust boundaries are covered by a mutation harness
rather than by assertion alone:

```bash
python3 scripts/sabotage_admissible.py
```

It deletes each guard in turn — 298 cases across 29 files, including the
workflow YAML — runs the one suite that should notice, and fails if any deletion
goes undetected. It restores every target from a pre-run capture through an exit
hook and signal handlers, then verifies each one byte for byte and scans the
package and workflows for live sabotage residue, so a killed run cannot leave a
deleted guard behind.

A second phase attacks the architecture rather than the product: 24 mutants
across the 12 package-separation invariants `SEP1`–`SEP12`, registered in
`tests/architecture/separation_guards.py`. Each one breaks the split somewhere
it actually lives — a Trust module planted in the Ready wheel, a schema forked
out of Core, a router that reads a credential, an umbrella namespace inside a
trusted install — and names the single test that must go red. These are applied
to a complete disposable copy of the checkout in a temporary directory, never in
place, so that phase has nothing to restore; a negative control proves every
named test is green on an unmutated clone first, and a mutation that moved no
bytes is reported as an error rather than counted as a kill.

A kill there is a narrower claim than a red suite: it is the *complete* outcome
the mutant registered in advance — the exception, the message and the exact
number of failures — so a run that goes red because a module stopped importing,
because a fixture raised, because an unrelated assertion disagreed, or because
the intended failure arrived with an unrelated one beside it, is an error and
never a kill.

Nor is that outcome taken from the process under test. The mutated code and the
tests judging it run with no descriptor on the harness's channel, no key, no
nonce and no path — an argv of test ids and nothing else — while a sealed
observer outside the disposable clone watches from the far side of that
boundary and signs one authenticated frame per run with a per-run key. A record
the tested process invents cannot be delivered as the harness's evidence, and
one it adds makes the run ambiguous rather than a kill. And because a mutated
build backend is arbitrary code running on a developer's machine, observer and
tests alike run behind the platform's network boundary — verified by probing
it at both depths, not assumed — with an environment built from an allowlist
and a private home inside the workspace that is about to be deleted. Where that
boundary cannot be enforced, the harness reports an error rather than claiming
an isolation it does not have.

Undetected sabotage is treated as a test defect, not as a harness quirk: where a
second guard happened to catch what the first one was supposed to, the test was
tightened to name which guard refused. Defence in depth is worth having and it
makes a suite easy to fool, and only one of those two facts is obvious.

```bash
bash examples/developer-workflow/demo.sh   # offline, throwaway repo, exits 0
```

## The system, run on itself

`scripts/self_admit.py` drives the composed kernel over this repository's own
change. Everything else here evaluates the kernel against something else —
stdlib reference implementations, generated code, historical defects. This is
the one subject it can be fully honest about.

```
subject   the tracked tree at HEAD, as a content-addressed manifest
claim     every guard in the defect model is individually load-bearing
D         the 298 sabotage cases in scripts/sabotage_admissible.py, each a
          source mutation paired with the test that must catch it
refuter   the sabotage harness: apply each mutation, run its named test,
          require the test to go red
```

**The measurement.** Every one of the 298 mutations was applied and caught:
298/298, with the harness's own integrity check confirming every target file
byte-identical to pre-run and no residue. That is a real fact about this
repository's guards.

**The result: the kernel refuses to certify it.**

```
measured detection: 298/298 = 1.0000
REFUSED at measure — fault V14: defect model authored by the refuter's author
```

V14 forbids a refuter carrying power against a defect model its own author
wrote. Here that is simply true: the same project wrote the guards, the tests
that catch their deletion, and the mutation set that deletes them. There is no
seal, no receipt and no stamp, and manufacturing one would take nothing more
than giving the two authors different labels — which is precisely the
claim-shaping the threat model names.

So the honest reading is the refusal, not the 1.0. **298/298 is a fact about
this repository and is not admissible evidence about it.** This is the
**coupling** assumption of `paper/admissible/DRAFT.md` §11 — that power against
a defect model predicts real faults — enforced mechanically instead of noted in
prose, and it lands on the authors of the kernel first.

What would close it is an independently authored defect model for this code.
The real-defect study (`eval/realdefects/`) is the same problem approached from
the other side, and reaches the same place: eight defects verified by hand, no
defensible rate. The full outcome, including the artifact hash and the fault, is
`eval/self/receipt.json`; re-run it from a clean checkout of the exact current
HEAD with

```bash
python3 scripts/self_admit.py
```

The command always executes the sabotage model freshly, verifies that the commit
and tree did not move, and refuses unauthenticated replay logs.

## What is not here

No quality theorem. No item liveness. No leftover-hop “corollary.” I1 is Pass-time `m_exec`, not execution history. I10–I17 prove envelope/package/receipt/state properties, not physical model input. Provider physics, hidden executor residue, a lying adapter and incorrect impact review are explicit assumptions. `norm` keeps vendor prefixes. Site names do not belong in `paper/`.

## Port

`fcd` has no `os.kill`, signals, or filesystem. macOS and iOS hosts wrap `alive_fn` and a dumb UI that cannot choose φ. The control plane is this machine, not the host.

## Review record

Historical frozen-head research reviews live in `eval/reviews/`; they are
evidence about the commits they name, not approval of a later release. The
public 0.8.0 release record will bind its reviews, tests, artifacts, and tag to
one accepted commit.

## Community and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development and architecture
rules, [`SECURITY.md`](SECURITY.md) for private vulnerability reporting, and
[`RELEASING.md`](RELEASING.md) for the source and package publication boundary.

## Citation

Use [`CITATION.cff`](CITATION.cff) and the paper-specific guidance in
[`paper/README.md`](paper/README.md). Version 0.8.0 is a technical-report and
software release; no DOI, journal acceptance, or peer-review status is claimed.

## License

Software, tests, schemas, build systems, examples, and repository documentation
are Apache-2.0. Research manuscripts and generated research PDFs under
`paper/` are CC BY 4.0. See [`LICENSE.md`](LICENSE.md), [`NOTICE`](NOTICE), and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
