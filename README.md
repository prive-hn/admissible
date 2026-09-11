# Admissible

Admissible answers one question about one exact commit:

> **May this artifact be admitted under this repository's own policy?**

It is a deterministic gate. It runs the checks your repository already has, binds
what they observed to one exact commit, tree and policy, and then refuses to call
that result an admission until a separate trusted party signs it. Nothing here
calls a language model, in any profile, on any path.

The name is evidence law's, and the guarantee is honest exactly where the
theorems are: admissibility certifies provenance, known error rate, controlling
procedure and exposure to impeachment — **never truth**.

Author: **Roque Briceño**. Isolated research and core; not a product diary.

## Start here

| If you want to… | Read |
| --- | --- |
| use the gate on your own repository | [Admissible Ready](#admissible-ready-admissible-v070) below, then [`docs/READY.md`](docs/READY.md) |
| understand what a receipt proves | [Evaluation is not admission](#evaluation-is-not-admission) below |
| install it on a trusted machine | [Installing Admissible](#installing-admissible) below |
| read the theory | [`paper/admissible/DRAFT.md`](paper/admissible/DRAFT.md), or [`docs/PROOFS_PLAIN.md`](docs/PROOFS_PLAIN.md) for one plain sentence per theorem |
| contribute | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

## The predicate

Three layers, three proof families, one predicate:

| Layer | Question it answers | Proofs | Kernel |
| --- | --- | --- | --- |
| **I** — identity | who actually did the work? | I1–I17 | `fcd/core.py` |
| **R** — scrutiny | what tried to kill it, and how hard? | R1–R13 | `rga/core.py` |
| **C** — standing | what has been found against it since? | C1–C7 | `rga/calibration.py` |

`admissible(id) = sealed ∧ mediated ∧ ¬tainted ∧ ¬impeached`

Layer **I** is Clark–Wilson integrity applied to model binds: admit by class,
bind one model, observe what actually ran, pass only if they match, and **fail
closed** when the bind is dead rather than silently hopping to another model.
Layer **R** moves the gate from the die to the roll — knowing which model ran
says nothing about the artifact, so a class pins the claims an artifact must
satisfy and the deterministic refuters that attack them, before any artifact
exists. Layer **C** is the escape ledger: what was filed against an artifact
after it was admitted.

Each layer's paper stands on its own; the unified paper is
[`paper/admissible/DRAFT.md`](paper/admissible/DRAFT.md).

## Admissible Ready (`admissible` v0.7.0)

The product loop is deliberately short:

**change → check → fix the next item → recheck → ready**

> **Nothing here has been published yet.** The install line below is what
> adopting the gate will look like, not something you can run today. Build the
> four artifacts from this checkout first with
> `.venv/bin/python scripts/build_release_artifacts.py`, then install the
> verified local ones from `dist/` — see
> [Installing Admissible](#installing-admissible). Everything after that line
> is the loop itself, and works against a local install.

```bash
pip install admissible                     # or admissible-ready alone
admissible profiles                        # the eight starter profiles
admissible init --profile python-library   # writes .admissible.json
$EDITOR .admissible.json
git add -A && git commit -m "adopt the gate"

admissible check                           # evaluate this exact HEAD
```

`check` is the normal human command: it evaluates the exact commit you are on
and prints a friendly result. Two other surfaces read the same state:

```bash
admissible ui                              # local Ready product, loopback only
admissible connect --name Builder --purpose "Implement this change" --runtime hermes
```

People see **Needs attention**, **Waiting for review**, **Checks complete** and
**Ready**. Agents receive the same repository/commit/tree/policy state over MCP
as `admissible/v0.7/ready-state`, plus stable reason codes and ordered actions.
Neither surface can sign or finalize anything. See
[`docs/READY.md`](docs/READY.md).

Cost units are integers your team defines, and ceilings are checked against the
*plan* before a single child process is spawned. The five high-risk profiles
(`rest-api`, `database-migration`, `authentication-change`, `payment-change`,
`infrastructure-change`) carry a floor: a repository may add checks and raise the
review count, and may never require fewer reviews or drop a required check —
because the policy travels inside the tree it governs. See
[`docs/COST_AND_LATENCY.md`](docs/COST_AND_LATENCY.md).

## Installing Admissible

Admissible is **one repository** and **four coordinated 0.8.1 distributions**,
built from `packages/` and meant to be installed into **separate processes**.
The separation is physical rather than conventional: the Ready wheel does not
contain Trust's modules, the Trust wheel does not contain Ready's, and neither
declares the other as a dependency under any extra or environment marker.

| distribution | console command | commands it installs |
| --- | --- | --- |
| `admissible-core` | none | nothing — it is a library, and the only one of the four with no dependencies |
| `admissible-ready` | `admissible-ready` | `profiles` `init` `run` `check` `mcp` `connect` `ui` |
| `admissible-trust` | `admissible-trust` | `ready-status` `verify` `explain` `status` `impeach` `attest-review` `attest-evaluation` `policy` (`trust`, `revoke`, `list`) `finalize` `run` `export` `import` |
| `admissible` | `admissible` | none of its own: static compatibility dispatch of the legacy verb to whichever sibling owns it |

```bash
pip install admissible-core==0.8.1   # kernel alone; no dependencies
pip install admissible-ready==0.8.1  # + exact Core; candidate execution
pip install admissible-trust==0.8.1  # + exact Core; trusted finalization
pip install admissible==0.8.1        # developer umbrella; all three siblings
```

The four are **0.8.1**, versioned and built together and pinned to each other.
That is a coordinated version and a coordinated build in this repository, and
nothing more: no distribution here has been published anywhere. Those index
commands become valid only once all four artifacts exist in the canonical
registry and their hashes have been read back; until then, build from this
checkout with `.venv/bin/python scripts/build_release_artifacts.py` and install
the verified local artifacts from `dist/`.

Every sibling edge is an **exact** `==0.8.1` pin, never a range. The four agree
about what a policy digest is, what an evidence record hashes to and what a
decision means; a range would let a Ready wheel evaluate against a kernel that
computes one of those differently, and the disagreement would surface as a check
that passed here and a receipt that refused there.

**A trusted machine installs exactly one authority.** `admissible-ready` where
candidate code runs; `admissible-trust` where a credential is held. Installing
`admissible` puts *both* on one machine, which is what makes it a developer
convenience and why it is forbidden in trusted infrastructure — not in a
finalizer environment, not in a reviewer or observer key environment, not in a
policy signing or policy trust environment, and not as a dependency of anything
that runs in one.

The Ready environment holds **no Trust package and no trust credential**: every
Ready entry point that can read the repository, open the store, bind a socket or
start a subprocess refuses first when a signing, review or observer variable is
set — present but empty counts as set. The Trust environment holds **no Ready
package and executes no candidate command**: its only subprocess is a fixed
vocabulary of `git` identity queries.

Receipt authentication is HMAC-SHA256, which is a **shared secret**: because
verification and signing share that secret, a Ready process handed a key to
*display* `ready` would be a Ready process able to mint what it displays. So
Ready reports `checks_complete`, and `admissible-trust ready-status` is where an
authenticated `ready` comes from.

What the split buys is the removal of **accidental capability adjacency**: a
signing key is no longer one import away from a process that runs whatever
`.admissible.json` says. It is **not an operating-system sandbox** and is not
offered as one. Anything already running under the same Unix account can read
this process's environment, delete or corrupt the store and remove the private
logs; the fail-closed reads then produce a denial of service rather than a false
answer, and that denial is real.

Per-wheel contracts: [`packages/core/README.md`](packages/core/README.md),
[`packages/ready/README.md`](packages/ready/README.md),
[`packages/trust/README.md`](packages/trust/README.md),
[`packages/umbrella/README.md`](packages/umbrella/README.md).

## Evaluation is not admission

This is the central idea of the whole system, and the one worth reading twice.

`admissible-ready run --preview` evaluates. It never signs, it reads no key, and
`--preview` is required. The reason is not caution: an evaluation starts commands
that the repository under evaluation controls, and a process holding a signing
key while it does that has already lost the boundary the key was protecting.
Since 0.8.0 that is also a packaging fact — there is no key loader in the Ready
wheel to reach for.

So the records an evaluation produces are a *description* of what happened, not a
proof of it. Turning one into a receipt takes three parties, each doing something
the others must not be able to:

| Party | Does | Key |
| --- | --- | --- |
| the **operator** | records once, in a trusted context, which policy is enforceable for a class (`admissible-trust policy trust`) | none |
| an external **observer** | after the evaluation is over and its process group is gone, validates infrastructure evidence, independently asserts isolation, and signs which records that evaluation produced (`admissible-trust attest-evaluation --isolation MODE`) | `ADMISSIBLE_EVALUATION_KEY` |
| the **finalizer** | verifies that attestation and the reviews, re-derives repository, tree and policy from its own checkout, recomputes the decision, anchors the receipt (`admissible-trust finalize`) | `ADMISSIBLE_HMAC_KEY` |

**No evaluation attestation, no receipt.** There is no default and no fallback.

A class that requires independent review can never be admitted by an evaluation:
it holds no reviewer keyring, because a keyring given to a process that runs
candidate-owned commands is a keyring given to the candidate. The decision says
so rather than routing around it, in a `readiness` field beside `state`:

| `readiness` | meaning |
| --- | --- |
| `READY_FOR_ATTESTATION` | every required check passed and nothing outstanding could be resolved here; ready for an observer to attest and a finalizer to admit — and **not** an admission |
| `AWAITING_REVIEW` | every deterministic required check passed and the evidence is valid; only independent review is outstanding, and nothing here can authenticate it |
| `NOT_READY` | something else refused or blocked it |

`ADMITTED` never was a `readiness` value — `readiness` describes an evaluation,
and an evaluation admits nothing. It appears in exactly one place: the `state` of
a signed durable receipt.

`AWAITING_REVIEW` is never called an admission, and in CI it is always **red**.
An earlier design reported it green whenever a finalize job was enabled, and
skipped that job on every pull request — so review-gated pull requests went green
with zero authenticated reviews. The shipped reusable workflow has no signing job
at all now, so the answer no longer depends on anything.

The public action and reusable workflow also output `state`, whose evaluation
values are exactly `CHECKS_PASSED`, `REFUSED` and `BLOCKED`. Once the observer
has authenticated the provider's record, the provider-conclusion matrix is
exact:

```text
READY_FOR_ATTESTATION -> success only
AWAITING_REVIEW -> success or failure
NOT_READY -> no provider conclusion is admissible
```

`cancelled` and `timed_out` are never admissible. The `failure` exception is
only for a genuine `AWAITING_REVIEW`, and the matrix is applied to the
readiness the finalizer recomputes from evidence and its own trusted policy:
an observer-bound or preview-reported readiness cannot widen the provider
conclusions that recomputation permits.

The hosted preview always records evaluator isolation as `none`, and there is no
caller isolation input. Later, the **observer independently asserts isolation**
with a required `attest-evaluation --isolation MODE`, after checking evidence in
the observer's own trust domain. Signed reviews, signed authorship claims and the
evaluation observer are **separate authenticated roles**: reviews and authorship
travel out-of-band to `finalize --reviews`, and adding or replacing them requires
**no observer re-sign**, because the finalizer authenticates and binds those
records independently.

### The admission path, one environment per line

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
    --reviews /trusted/out-of-band/reviews.json                      # the finalizer
```

Each of those lines runs in a different environment. Only the first has
`admissible-ready` installed; none of the other three does, and the machine that
runs the last one has no candidate executor on it at all.

The CI gate is therefore **evaluate-only**: it runs candidate commands, holds no
signing key and no reviewer keyring, and contains no finalize job.
`admissible-trust finalize` runs elsewhere, on a trusted machine with no
candidate executor installed, and is the only place `ADMITTED` is ever issued.
See [`docs/GITHUB_ACTIONS.md`](docs/GITHUB_ACTIONS.md).

A receipt is also **not an anchor**: `finalize` refuses a home inside
`GITHUB_WORKSPACE` or `RUNNER_TEMP`, because a first anchor cannot prove its own
past. A journal destroyed with the job bootstraps a fresh one every run, so no
rollback is ever detectable and "current" means nothing.

### Which `run` is which

`run` is the one verb both distributions implement, so its owner is decided by
shape rather than by name:

```bash
admissible-ready run --preview --sha "$(git rev-parse HEAD)"   # evaluate; never signs
admissible-trust explain "$(git rev-parse HEAD)"               # what is known, and why
admissible-trust verify "$(git rev-parse HEAD)"                # standing + authenticity
admissible-trust status                                        # repository at a glance
admissible-trust impeach "$(git rev-parse HEAD)" --evidence defect.json --test unit
```

`admissible-trust run` is a transitional alias for `finalize`. On a developer
machine with the umbrella, `admissible run --preview`, `admissible explain`,
`admissible status`, `admissible export` and `admissible import` keep working for
**one release window** as transitional aliases: the dispatcher hands each to
whichever sibling owns it, statically, from the words typed and
**never by ambient credentials**. A human — not a `--json` caller — gets a line
on stderr naming the explicit replacement.

See [`docs/DEVELOPER_WORKFLOW.md`](docs/DEVELOPER_WORKFLOW.md) for attempts, the
exact-identity cache, signed review attestations and the full admission path, and
[`docs/IMPEACHMENT.md`](docs/IMPEACHMENT.md) for filing defects and carrying
standing between machines.

## The research kernel

`fcd` is the portable acceptance kernel — Python 3.10+, no runtime dependencies:

```python
from fcd import Enforcer, Policy

policy = Policy(
    allow={"impl": {"alice", "carol"}},
    deny={"impl": set()},
    phi={"alice": "vendorA:model-a", "carol": "vendorC:model-c"},
    required={"impl": [("write", "w1"), ("check", "c1")]},
)
e = Enforcer(policy)
e.open("w", "impl", "bodyhash")
e.admit("w", "alice")
e.bind("w", True)             # False => BindFail, published
e.observe("w", "vendorA:model-a")
e.decide_pass("w")            # mismatch => F1, Closed, no hop
```

Cache is **stage-scoped only**; a hit never skips Observe, and sharing a cache
across specialists is a fault. Three properties make it usable at scale:
`Enforcer.from_events(...)` replays state deterministically from the append-only
journal; `install(new_policy)` swaps the live policy while in-flight items stay
pinned to the version they opened under; and `open(..., depends_on=("a",))`
refuses unless every dependency is already an accepted artifact.

`rga` composes over `fcd` and writes no `fcd` field. A class pins its claims and
refuters in advance; each refuter carries a power as a labelled record; the same
bind is sampled `k` times; admission requires every cell to have survived, every
refuter replayed once with the same outcome, concordance with the designated
sample, and power above a floor. The seal says what was attacked, at what power,
against which defect model — and what was not.

Metrics are **empty on purpose**. Four rates (misbind, silent fail, bleed,
time-to-stage) are defined in [`metrics/SCHEMA.md`](metrics/SCHEMA.md) and stay
empty until they are computed on a write-ahead journal after a named cut. Mixed
historical logs are not rates.

## Cockpit

The reference product is a three-pane authority surface:

```text
Project/capability atlas | Selected work line + bounded gate tray | Real runnable artifact
```

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
npm --prefix apps/cockpit install
make cockpit          # http://127.0.0.1:8791
```

The **authority** compiles a prompt into a visible contract, so the terms an
operator approves are the terms the machine enforces. Every gate chooses an
agent/profile, execution adapter, exact provider model, context mode and
continuity hint before Admit; an unavailable route cannot Admit. The centre pane
draws a line as a load path, so everything under a fail-closed break is shown as
work that never ran rather than work that is queued. Skins may repaint or
re-represent, but cannot remove the rail, the refusal strip or the steering bar.

See [`docs/INTERACTION_LAYER.md`](docs/INTERACTION_LAYER.md),
[`docs/EVIDENCE_MODEL.md`](docs/EVIDENCE_MODEL.md),
[`docs/SKIN_PROTOCOL.md`](docs/SKIN_PROTOCOL.md) and
[`docs/UI_GLOSSARY.md`](docs/UI_GLOSSARY.md), which maps every machine term to
plain words.

## Layout

| Path | What |
| --- | --- |
| `packages/core/` | `admissible-core`: the authority-neutral kernel — identity, policy, evidence, decision, schemas. No console command, no dependencies |
| `packages/ready/` | `admissible-ready`: the candidate side. Runs checks, serves the loopback UI and MCP, holds no key |
| `packages/trust/` | `admissible-trust`: the signing side. Reviews, attestations, policy trust, finalization, standing. Starts no candidate command |
| `packages/umbrella/` | `admissible`: the developer-convenience dispatcher that keeps the legacy `admissible` command working |
| `admissible/` | The **pre-split monolith**, still at 0.7.0 and kept only for the one-release migration window — 18 CLI commands, eight risk-shaped starter profiles, Python 3.10+. It is what the source-checkout CI gate runs and what the legacy suites are written against: history with a window, not the current architecture |
| `fcd/` | Layer I: the portable acceptance kernel, zero runtime dependencies |
| `rga/` | Layers R and C: refutation-gated admission and the calibration escape ledger, composed over `fcd` |
| `atlas/` | Immutable evidence/capability reducer |
| `paper/` | The three papers with their invariants, proofs and regenerated PDFs |
| `protocol/` | JSON Schemas for every document the system emits, conformance-tested against live emissions |
| `server/` | Verified project registry, `ExecutionAdapter` boundary and HTTP authority server |
| `apps/cockpit/` | React/Vite project/work/artifact interaction layer |
| `docs/` | Interaction, evidence, skin, execution and artifact contracts |
| `eval/` | Deterministic three-layer kernel bench and historical review material |
| `examples/developer-workflow/demo.sh` | Offline end-to-end walk-through in a throwaway repository |
| `scripts/sabotage_admissible.py` | Mutation harness: deletes each trust boundary in turn and proves the contract suite goes red |
| `tests/` | Kernel, server, project, class, RGA, calibration, bench, schema, paper and custody suites, including 2452 for the developer product |
| `.github/workflows/admissible-gate.yml` | The reusable `workflow_call` gate a consumer pins by commit — evaluate-only, with no finalize job |
| `metrics/`, `data/`, `enforcer/` | Event contract; local collector output (not committed); thin shim to `fcd` — add no logic there |

## Tests

```bash
make test                                  # both Python suites, then the cockpit suite
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Two prerequisites, both worth stating because a run without them fails in a way
that reads as broken code rather than a missing tool:

- **`build`, `setuptools` and `wheel` must be importable *system-wide*.** The
  packaging suites launch every subprocess with `PYTHONNOUSERSITE=1` on purpose,
  so an import canary reports what the wheel ships rather than what the
  developer's shell happens to have. A `pip install --user build` is invisible to
  them and roughly 290 checks fail with `No module named build`.
- **A `.venv/` at the repository root**, because one check runs the demo through
  `.venv/bin/python` to prove a relative interpreter path is resolved before the
  script changes directory.

The counts are derived from collection, not typed — a suite that grows and a
README that does not is a red test rather than a stale claim:

| Scope | Checks | Where |
| ----- | -----: | ----- |
| Research kernel — the number the paper cites | 733 | 625 in `tests/` + 37 `atlas/tests/` + 71 `apps/cockpit/tests/` |
| Developer product (`admissible/`) | 2452 | `tests/test_admissible_*.py` + the split suites under `tests/architecture/`, `tests/core/`, `tests/ready/`, `tests/trust/` and `tests/compatibility/` |
| **Total** | **3185** | 3077 under `tests/`, 37 atlas, 71 cockpit |

Trust boundaries are covered by a mutation harness rather than by assertion
alone:

```bash
python3 scripts/sabotage_admissible.py
bash examples/developer-workflow/demo.sh   # offline, throwaway repo, exits 0
```

It deletes each guard in turn — 298 cases across 29 files, including the workflow
YAML — runs the one suite that should notice, and fails if any deletion goes
undetected, restoring every target and verifying it byte for byte. A second phase
attacks the architecture rather than the product: 24 mutants across the 12
package-separation invariants `SEP1`–`SEP12`, applied to a disposable clone, each
naming in advance the single test that must go red and the exact failure it must
report. A run that goes red for another reason is an error, never a kill — and
the verdict is signed by an observer outside the clone, so the process under test
cannot author the evidence the harness reads.

## The system, run on itself

`scripts/self_admit.py` drives the composed kernel over this repository's own
change — the one subject it can be fully honest about.

Every one of the 298 mutations was applied and caught: **298/298**, with the
harness's integrity check confirming every target byte-identical to pre-run. And
the kernel **refuses to certify it**:

```text
measured detection: 298/298 = 1.0000
REFUSED at measure — fault V14: defect model authored by the refuter's author
```

V14 forbids a refuter carrying power against a defect model its own author wrote.
Here that is simply true: the same project wrote the guards, the tests that catch
their deletion, and the mutation set that deletes them. So the honest reading is
the refusal, not the 1.0 — **298/298 is a fact about this repository and is not
admissible evidence about it.** Manufacturing a seal would take nothing more than
giving the two authors different labels, which is precisely the claim-shaping the
threat model names.

What would close it is an independently authored defect model for this code. The
real-defect study in `eval/realdefects/` approaches the same problem from the
other side and reaches the same place: eight defects verified by hand, no
defensible rate.

```bash
python3 scripts/self_admit.py
```

The command always executes the sabotage model freshly, verifies that the commit
and tree did not move, and refuses unauthenticated replay logs.

## What is not proved

Stated plainly, because the gaps are load-bearing:

- **No quality theorem.** Admissibility is about procedure and provenance. I1 is
  pass-time `m_exec`, not execution history; I10–I17 prove envelope, package,
  receipt and state properties, not physical model input.
- **No item liveness**, and no leftover-hop corollary.
- **Explicit assumptions:** provider physics, hidden executor residue, a lying
  adapter, and incorrect impact review.
- **Not built:** the service that would watch completed CI runs, authenticate
  them against the GitHub API and drive the durable finalizer. Getting from the
  published preview artifact to a receipt is a manual step or your own script
  today, and the workflow should not be read as if it were automatic.
- **Bootstrap caveat:** a receipt is authentic history and cannot show that its
  head is still the current one.

`fcd` has no `os.kill`, signals or filesystem; macOS and iOS hosts wrap
`alive_fn` behind a UI that cannot choose φ. The control plane is this machine,
not the host.

## Versions

| Layer | Version | Notes |
| --- | --- | --- |
| Split distributions (`packages/`) | 0.8.1 | The current architecture |
| Root monolith (`admissible/`) | 0.7.0 | Retained for the one-release migration window |
| Research kernel | 0.5.0 | Signing domains stay `admissible/v0.5/…` |

Wire formats did not move with the split. Product contracts are
`admissible/v0.7/{ready-state,agent-work-package,remediation,agent-connection}`;
admission, receipt and signature domains remain on `admissible/v0.6/…`
deliberately, because changing a signed domain string would make authentic
historical material stop verifying. The 0.8.0 split changed where code is
installed and which process may hold a key — no schema, no domain string and no
stored row.

## Community, citation and license

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development setup and architecture rules
- [`SECURITY.md`](SECURITY.md) — private vulnerability reporting
- [`RELEASING.md`](RELEASING.md) — the source and package publication boundary
- [`CHANGELOG.md`](CHANGELOG.md) — what changed, and when
- [`CITATION.cff`](CITATION.cff) — with paper-specific guidance in
  [`paper/README.md`](paper/README.md)

Historical frozen-head research reviews live in `eval/reviews/`; they are
evidence about the commits they name, not approval of a later version. Version
0.8.1 is a technical-report and software artifact; no DOI, journal acceptance or
peer-review status is claimed.

Software, tests, schemas, build systems, examples and repository documentation
are Apache-2.0. Research manuscripts and generated research PDFs under `paper/`
are CC BY 4.0. See [`LICENSE.md`](LICENSE.md), [`NOTICE`](NOTICE) and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
