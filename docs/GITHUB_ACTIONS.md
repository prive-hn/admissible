# Admissible on GitHub Actions

The gate ships as a **reusable workflow** you pin by commit:
`.github/workflows/admissible-gate.yml`. `admissible-ready init --profile NAME
--ci github --tool-sha FULL_SHA` writes a caller into your repository.

Be precise about where each of those files comes from, because the split made
the answer different for each:

| file | where it comes from |
| ---- | ------------------- |
| `consumer-workflow.yml` | the **only** template inside the `admissible-ready` wheel; it is the caller `init --ci github` writes into your repository |
| `reusable-workflow.yml` | the **repository checkout**, as `.github/workflows/admissible-gate.yml`; it is not in any wheel |
| `action.yml` | the **repository checkout**, as `.github/actions/admissible/action.yml`; it is not in any wheel |

The repository's own copies under `admissible/templates/` are byte-identical to
the two it publishes, and they travel with the source, not with a distribution.
Pinning `uses: …@<commit>` is what fetches them; there is no `pip install` that
puts them on a runner.

```yaml
jobs:
  gate:
    uses: prive-hn/admissible/.github/workflows/admissible-gate.yml@<commit>
    with:
      tool-sha: <the same commit>
```

## This workflow evaluates. It does not sign.

That is the shape of the whole document, so it is worth stating before anything
else, and worth saying why rather than leaving it to be inferred.

`evaluate` runs candidate-owned commands. A command runs as the same user as the
job, on the same filesystem, and can leave a process behind that outlives it. So
every artefact this workflow produces — the preview, the decision document, the
command records inside them — is **candidate-adjacent data**. It describes what
happened; it does not prove it. Handing a signing key to a later job in the same
run, on the strength of that data, signs the description.

An earlier version of this file did exactly that, behind a `finalize-enabled`
flag. The flag is gone, along with the job, the secrets and the environment. The
safe configuration has to be the only configuration the file can express.

So the boundary is drawn where a workflow cannot fake it:

| Where | What it does | Keys it holds |
| ----- | ------------ | ------------- |
| this workflow | evaluates the exact head commit, publishes the preview as a job output and retained SHA-256-receipted artifact | none |
| an external observer | authenticates the preview after this run is over, independently asserts isolation, and signs an evaluation attestation | `ADMISSIBLE_EVALUATION_KEY` |
| a trusted finalizer | verifies that attestation, re-derives everything, recomputes the decision, anchors the receipt | `ADMISSIBLE_HMAC_KEY`, the reviewer keyring |

A green run of this workflow means **the deterministic checks passed for this
commit**. It never means the commit was admitted.

### The `evaluate` job is the Ready domain, whatever the command line says

The job runs `python3 -m admissible` out of the pinned `admissible-tool/`
checkout. Read that as the **migration window**, not as an authority: during
this window the gate runs from a source checkout of the pre-split 0.7.0
monolith, because a workflow pinned by commit must run the program at that
commit, and a `pip install` from an index would pin nothing.

What the job *does* is entirely Ready-domain work — evaluate the exact head
commit, publish a preview — and it is executed with no signing key, no reviewer
keyring and no observer key anywhere in the environment. The exact spelling
matters, so here it is: the step's command line is unchanged and still reads
`python3 -m admissible run --preview --preview-out FILE`. Nothing in
`.github/workflows/admissible-gate.yml` has been rewritten to say
`admissible-ready`, and this document is not describing a workflow edit that
has happened.

What those words resolve to is unchanged too, including on a commit whose
checkout is the split tree. The step runs the module from the checkout root, so
Python resolves the `admissible/` package the repository root still carries —
the retained 0.7.0 monolith. It does not resolve
`packages/umbrella/compat/admissible/`, which is not at that root and which no
step installs, so this command line reaches no umbrella dispatcher and is
handed to no `admissible-ready` console script. What `run --preview` *does* is
Ready-domain work, as above; the executable performing it, for as long as this
migration window lasts, is the legacy source-tree monolith. The authority a job
holds is decided by which credentials reach it and which work it does, and on
both counts this one is the candidate side.

### The two dotted names this document mentions

| what applies the rule | owner after the split |
| --------------------- | --------------------- |
| deriving what a workflow may do from named environment inputs | `admissible_ready.github.evaluation_context` |
| refusing a `--policy-root` that ships its own `admissible` package | `admissible_trust.github.assert_trusted_tool` |

The legacy spellings `admissible.github.evaluation_context()` and
`admissible.github.assert_trusted_tool()` still resolve, and they resolve
**umbrella-only**: they are compatibility facades in the `admissible`
distribution, which no trusted environment installs. That facade is also
**fail-closed** — importing it imports neither half, reading each name imports
exactly its own owner, and the two names both halves happen to define
(`GitHubError`, `PREVIEW_SCHEMA`) raise rather than pick an authority for you.

### The Admissible Ready card

Every evaluation writes an **Admissible Ready** card to the GitHub job summary.
It leads with the same friendly label as the CLI and local UI, states whether
the result applies to the exact commit, and answers **What should happen next**
with one ordered action. Canonical state, canonical readiness, attempt, policy
anchor, and the absence of a receipt remain under technical details.

The presentation does not change the gate colour or authority. **Checks
complete** can be green because the deterministic checks passed;
**Waiting for review** remains red; only `admissible-trust ready-status` with
the admission verification key can authenticate `ADMITTED` with `CURRENT`
standing as **Ready**.

### The bridge is external, and it does not exist yet

Getting from "this workflow produced a preview" to "a receipt exists" means
fetching the retained preview artifact, verifying its `preview.sha256`, having
the observer validate external provider and isolation evidence and sign it with
`admissible-trust attest-evaluation --isolation MODE`, and running
`admissible-trust finalize` on the finalizer. Today that is a manual step, or
your own script.

An automated bridge — a service that watches for completed runs, authenticates
them against the GitHub API, and drives the finalizer — is a reasonable thing to
build. It is not in this repository. Do not read the workflow as if it were.

## Pinning: one commit, written twice

```yaml
    uses: prive-hn/admissible/.github/workflows/admissible-gate.yml@<commit>
    with:
      tool-sha: <the same commit>
```

`tool-sha` is required, has no default, and must be a full 40-character
lowercase hex commit. The gate checks it out and runs `python3 -m admissible`
from that checkout, and nothing else.

The second copy is not redundancy. An earlier version resolved the tool
reference from `github.workflow_ref`, which for an external consumer names the
*caller's* workflow, not the gate's — so an exact-SHA pin on the `uses:` line
fell through to a movable tag for the program that actually ran. Pinning the
workflow by commit while its program came out of a tag pinned nothing that
mattered.

At run time the gate compares `tool-sha` against `github.job_workflow_sha` —
the commit GitHub resolved your `uses:` reference to, which is the one value
that tells the callee which revision of itself you pinned. If they disagree, or
if GitHub leaves `job_workflow_sha` empty, the job fails with exit 2. An empty
value is a refusal, not a skip: otherwise a PR can keep `uses:` pinned and
point `tool-sha` at candidate-owned code. There is no fallback tag anywhere in
the file.

`admissible-ready init --ci github` refuses without `--tool-sha`, because a
guessed pin would run and would run whatever the tool repository happened to
hold that day. `--ci-placeholder` is the deliberate alternative: it scaffolds a caller
with an explicit `REPLACE-WITH-…` in both places, which is a workflow that
cannot start until somebody chooses a commit.

## What the job actually does

Two checkouts, in two paths:

* `admissible-tool/` — the Admissible package at `tool-sha`. This is the program
  that runs.
* `candidate/` — the commit under evaluation. It supplies the policy and the
  checks. It never supplies the program.

Then:

1. **Bind to the head commit, not the merge commit.** On `pull_request`, GitHub
   sets `GITHUB_SHA` to a synthetic merge commit that does not exist in your
   history; evidence bound to it can never be verified again. The workflow
   checks out `${{ github.event.pull_request.head.sha || github.sha }}` and then
   *proves* the checkout is at that SHA before doing anything else.
   `admissible_ready.github.evaluation_context` applies the same rule in code,
   refuses anything that is not a full 40-character lowercase SHA, and refuses
   `pull_request_target` outright — that event grants repository write scope to
   a workflow evaluating a fork's changes.
2. **Refuse a missing policy.** If `config-path` is absent at the evaluated
   commit the gate exits 1 and says so. It does not skip. A gate that goes green
   when its policy is deleted is worse than no gate, because the green tick
   still reads as approval. The same path is checked for existence, passed to
   the CLI as `--config`, and named in the preview, so all three are talking
   about one file.
3. **Evaluate**, in a private scratch directory made with `mktemp -d` and
   `chmod 700`. The candidate's checks never see `RUNNER_TEMP` — the runner
   strips the whole `GITHUB_*`/`RUNNER_*`/`ACTIONS_*`/`ADMISSIBLE_*` namespace
   from their environment — so a surviving descendant has no name to guess at
   for the preview it would like to rewrite.
4. **Publish the preview** as a base64 job output and a retained run artifact,
   along with `sha`, `state`, `readiness`, `fork`, `preview-sha256` and
   `artifact-name`. The artifact name binds the full evaluated SHA and
   `github.run_attempt`; it contains the preview plus `preview.sha256`, and the
   pinned upload step runs for every produced preview, including a red
   `AWAITING_REVIEW`. All outputs are declared under `on.workflow_call.outputs`,
   so an external caller can consume them; internal job outputs that no
   consumer can reach are not a portability contract.

## Readiness is not a decision state

`evaluate` holds no reviewer keyring, for the same reason it holds no signing
key: a keyring given to a job that runs candidate-owned commands is a keyring
given to the candidate. That has a consequence, and the honest thing is to name
it — **nothing here can ever be `ADMITTED`, and a class that requires
independent review cannot even reach `READY_FOR_ATTESTATION`.** Nothing in this
job can authenticate a signature, and nothing in it signs anything, so the
strongest thing it can truthfully report is that the checks passed.

So the decision carries a second field beside `state`:

| `readiness` | What this evaluation established |
| ----------- | -------------------------------- |
| `READY_FOR_ATTESTATION` | every required check passed and nothing is outstanding that this job could ever resolve. Not an admission: it is ready for an observer to attest and a finalizer to admit |
| `AWAITING_REVIEW` | every deterministic required check passed and the evidence is valid; the only blocker left is independent review, which no job here can authenticate |
| `NOT_READY` | anything else refused or blocked it |

The decision `state` beside it is `CHECKS_PASSED`, `REFUSED` or `BLOCKED`.
`ADMITTED` is not among them and never was earned here: an evaluation signs
nothing and anchors nothing, so only a signed durable receipt records an
admission. A preview that calls its own decision `ADMITTED` is refused by
`finalize` on that alone.

`AWAITING_REVIEW` is deliberately narrow. It requires a plain refusal — never a
block — with every required check actually **passed**, and every refusal code one
that only a keyring holder could ever clear. One failed check, one timeout, one
rejecting review, one reviewer key the policy does not pin, one author-signed
approval, one future-dated review, and the answer is `NOT_READY`: there is
nobody for that preview to be waiting on.

**`AWAITING_REVIEW` is red.** Always, on every event, for every repository and
every fork. The previous version reported it as success whenever a finalize job
was enabled, reasoning that the finalizer would complete the review — and the
finalizer was skipped outright on `pull_request`, which is precisely where a
review requirement matters. Every review-gated pull request went green with zero
authenticated reviews. There is no finalize job now, so the answer no longer
depends on anything: a review this run cannot authenticate is a red gate.

Exit codes stay `0`/`1`/`2`; readiness is never a fourth state.

The provider-conclusion matrix is exact:

```text
READY_FOR_ATTESTATION -> success only
AWAITING_REVIEW -> success or failure
NOT_READY -> no provider conclusion is admissible
```

`cancelled` and `timed_out` are refused for every readiness.

## Review bundles cannot travel in the candidate tree

An earlier version of this document recommended committing the bundle of signed
attestations into the candidate tree. That recommendation was impossible, and
this section replaces it.

A review binds the exact repository, commit, **tree** and policy it approves.
Committing the bundle changes the commit and the tree, so the reviews inside it
no longer describe the artefact they are now part of. Signing *after* the commit
that contains them does not help either: the commit that contains the signatures
is a different commit from the one they would have to bind. The hash would have
to contain itself. There is no ordering that closes it.

So **review bundles reach a finalizer out-of-band**, alongside the preview, and
this workflow implements no transport for either. That is an explicit, named
boundary rather than an omission: see "the out-of-band boundary" below.

`evidence-path` remains, and it is for evidence that legitimately predates the
commit — imported command records from another system, advisory reviews that
count for nothing here. An absolute path is accepted for callers that place a
file on the runner by some other means.

This job authenticates none of it. It carries what it is given into the preview,
reports signed reviews as `unauthenticated_review`, counts them for nothing, and
says so. **The five review-required profiles therefore stay red on the hosted
path**, and that is the honest colour: this job cannot authenticate a review and
must not appear to have.

## Isolation: what confined the candidate's commands

The gate starts commands the repository under evaluation controls, and kills
the process group of each one when it is over. That is real and it is not
enough. A descendant that calls `setsid()` leaves the group, keeps running as
the same user after the evaluation believes the check has finished, and can
rewrite the preview and the decision document before the next step reads them.
No portable call finds such a process again, so this is not a hole the
evaluator can close — and it is not one that is claimed shut.

The generic reusable workflow cannot prove such a boundary, and a caller is not
an observer. It therefore has **no `isolation` input** and forces its diagnostic
preview field to `none`. That candidate-adjacent field authorizes nothing.

After the hosted run and its process group are gone, the **observer
independently asserts isolation** with the required `admissible-trust
attest-evaluation --isolation MODE` option. The supported assertions are
`none`, `pid-namespace`, `single-use-vm` and `separate-uid`. The observer checks
external infrastructure evidence before signing; `none` remains honest but is
not finalizable.

The observer independently asserts isolation; the workflow never does.

Each means the same thing: every process the checks started is destroyed, by
something outside this evaluation, before anything reads what this evaluation
produced. A bare hosted runner does not satisfy that — the step that reads the
preview runs on the same machine as the survivor. Satisfying it means running
the checks inside a container whose PID namespace is torn down before the
preview is read, or on a machine created for this evaluation and destroyed
before it is read, or as a separate unprivileged user that cannot write any
file the evaluator, the observer or the finalizer reads.

The observer's signature says who asserted the boundary; a candidate changing
the preview cannot change that signed fact. Admissible still does not inspect a
hypervisor or namespace itself, so the observer's infrastructure check remains
an explicit trust boundary, just like its provider-receipt check.

## A red gate and a `success`-only receipt

`AWAITING_REVIEW` is red, and a provider records a red run as `failure`. If
finalization accepted only `success`, the two rules together would mean no
review-required class could ever be admitted through this path: the gate's own
honesty would make its output unusable.

So the accepted set depends only on the readiness the finalizer recomputes from
the evidence and its trusted policy. At `READY_FOR_ATTESTATION` only `success`
completes an admission. At genuine `AWAITING_REVIEW`, `failure` is accepted as
well — and only there. The observer binds the evaluator's reported readiness,
but that report cannot widen the accepted provider conclusions: the finalizer
must independently derive `AWAITING_REVIEW` after every required check passed
and the sole remaining blocker is a review this job could not authenticate. A
failing required check re-derives as `NOT_READY` instead. `cancelled` and
`timed_out` are refused at every readiness: they say the run did not finish,
and an unfinished run establishes nothing to be waiting on.

## The out-of-band boundary

Between "this workflow produced a preview" and "a receipt exists" there is a
boundary this workflow does not cross, and nothing shipped here crosses it for
you. Crossing it takes three things that happen elsewhere:

1. fetch the `admissible-preview-FULL_SHA-attempt-N` artifact after the run
   finishes and verify the included `preview.sha256` receipt;
2. read the provider's own record of that run — its immutable run id, the head
   sha it ran on, and the conclusion it reported — and hand it to
   `admissible-trust attest-evaluation --source-receipt ... --isolation MODE`,
   in the observer's trust domain, with a key that never enters this workflow.
   The observer validates external isolation evidence before choosing `MODE`;
3. run `admissible-trust finalize` on the finalizer, with the preview, the
   attestation, and any review bundle — the bundle arrives through
   `--reviews FILE`, which accepts signed reviews and signed authorship claims
   and refuses command records.

Reviews, authorship and evaluation observation are **separate authenticated roles**.
A finalizer authenticates the out-of-band `--reviews` bundle against
its review keyring and binds it during recomputation; adding it requires **no observer re-sign**
because it cannot add or replace the command evidence the
observer witnessed.

Step 2 carries the assumption named in `docs/DEVELOPER_WORKFLOW.md`: whoever
runs it says they read the provider's record. Admissible does not fetch it and
cannot verify it, so a dishonest adapter produces an attestation that verifies.
A service that queries the GitHub API from the observer's trust domain would
narrow that to "the adapter is honest". It is a reasonable thing to build and it
does not exist here.

## Policy is unanchored here, and the preview says so

The gate reads the policy out of the candidate checkout and holds no durable
baseline to compare it against, so the preview reports `policy_anchor:
unanchored` and the step summary says it in words. That is the true answer for a
hosted evaluation, not a soft yes.

The finalizer re-derives the same question from its own durable store, where an
operator has recorded which policy is enforceable for a class with
`admissible-trust policy trust`. Without a baseline it refuses; with one, a
change to the checks,
the review count or the key ids blocks until an operator approves it too. That
is what stops a change to payment code from also changing the file that says
what a payment change must satisfy.

Select that durable store before the first policy bootstrap and keep the same
home for finalization:

```bash
export ADMISSIBLE_HOME=/var/lib/admissible
export ADMISSIBLE_DURABLE_HOME=1
admissible-trust policy trust --repo /trusted/checkout
admissible-trust finalize --preview preview.json --sha "$SHA" \
  --policy-root /trusted/checkout \
  --evaluation-attestation evaluation.json \
  --reviews /trusted/out-of-band/reviews.json
```

## Forks

A fork can evaluate. A fork can never be finalized. The preview carries a `fork`
flag, and `admissible-trust finalize` refuses a fork preview before it does anything
else. If the CI context cannot be identified at all, the preview is marked as a
fork: an unidentifiable context is treated as untrusted, not as trusted.

## What `finalize` may do — elsewhere

`finalize` runs outside this workflow, on a machine with durable storage. It
reads data only:

* it starts no subprocess except `git`, reading the trusted checkout's identity;
* it imports no candidate module and runs no package script (no `npm install`,
  no `pip install -e .`, no `make`);
* it **requires an evaluation attestation** from an external observer, verified
  against `ADMISSIBLE_EVALUATION_KEYRING`, binding repository, commit, tree,
  policy, class, attempt, decision digest, command-record digests and advisory
  review-record digests observed in the preview — checked in both directions,
  so a record the observer did not watch cannot be counted and a record it
  watched cannot be dropped afterwards. Signed review and authorship
  attestations retain their own out-of-band authority; the observer does not
  re-sign them. No evaluation attestation, no receipt;
* it re-derives repository, commit, tree and cleanliness from its own trusted
  checkout and compares them with the preview, rather than believing it;
* it reads the policy file the preview names, from that checkout, confirms the
  policy digest, and checks it against the trusted baseline;
* it **recomputes** the decision from the imported evidence, comparing every
  command's `argv_digest` with the argv the policy configures;
* it verifies every review attestation against `ADMISSIBLE_REVIEW_KEYRING` and
  counts blocking reviews by distinct authenticated key id — an attestation it
  cannot authenticate is an error here, never a shrug: `finalize` *is* the
  authenticator;
* it refuses a preview whose readiness is `NOT_READY`, one whose readiness and
  state contradict each other, and one that names no attempt;
* it refuses to issue anything unless its own recomputation says
  `CHECKS_PASSED`, and it records the resulting receipt as `ADMITTED` — the
  only place that word is ever written.

The preview's own `state` and `readiness` decide only whether the work is worth
doing. Nothing in it is believed.

`admissible_trust.github.assert_trusted_tool` refuses a `--policy-root` that
ships its own `admissible` package: once the module Python imported came out of
the commit under evaluation, the candidate's code has already run with the key
and nothing later can help.

### Durable storage is not optional there

`admissible-trust finalize` refuses a home inside `GITHUB_WORKSPACE` or `RUNNER_TEMP`,
and refuses to sign on a hosted runner unless `ADMISSIBLE_DURABLE_HOME=1`
declares the home deliberately durable. A signed journal is a claim about
history; on a hosted runner the database is deleted with the job, so every run
would bootstrap a new journal, no rollback could be detected, and "current"
would mean nothing.

**Restoring an old database loses rollback protection.** Monotone standing works
because the store refuses a head that does not extend the one it already has. If
you restore an older snapshot of `admissible.sqlite3`, the store no longer knows
about the events that came after it, and a head it would have refused an hour
ago becomes acceptable. Back the home up, but treat a restore as a deliberate
trust decision: re-import the newest export you have (`admissible-trust import` refuses
to shorten a journal) before you sign anything else.

## Preview handover

The preview travels in two forms. The bounded base64 job output remains useful
to small callers: GitHub caps a job's outputs at 1 MiB counted over UTF-16 code
units, so the gate refuses raw previews over **262,144 bytes**. Independently,
every produced preview is retained by the pinned `actions/upload-artifact`
step, even when `AWAITING_REVIEW` makes the final reporting step red. Its name
is `admissible-preview-FULL_SHA-attempt-N`, and it contains both `preview.json`
and a `preview.sha256` receipt. Both are unsigned candidate-adjacent data; the
receipt detects transfer corruption and does not replace observer authentication.

## Runners

The job defaults to GitHub-hosted `ubuntu-latest`, which is fine: it anchors
nothing and holds nothing. `evaluate-runs-on` takes JSON (`'"ubuntu-latest"'` or
`'["self-hosted","linux","x64","label"]'`) so a label list can never be assembled
by string concatenation.

If you run it on a self-hosted runner, remember that anything which ever runs
there can read the workspace and the runner token. That is your decision to
make, and it no longer risks a signing key, because there is no signing key in
this workflow.

## Pinning third-party actions

Every third-party action is pinned by full commit SHA:
`actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` (v4.2.2) and
`actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`.
Re-pin deliberately when you upgrade; a floating tag is a supply-chain
decision, not a convenience.

## The composite action

`.github/actions/admissible/action.yml` is the same evaluation as a composite
action, for callers assembling their own job. It takes `tool-root` (the trusted
checkout to run from), `repo`, `sha`, and optionally `class`, `config` and
`evidence`. Its optional `isolation` value is evaluator-owned diagnostic data,
not finalization authority; the observer still supplies the independent signed
assertion. It unsets every Admissible key variable before it starts, uses its
own `mktemp -d` scratch directory, and has no finalize mode at all. Its public
outputs are `state` (`CHECKS_PASSED`, `REFUSED`, `BLOCKED`) and `readiness`
(`READY_FOR_ATTESTATION`, `AWAITING_REVIEW`, `NOT_READY`), with the exact
provider-conclusion matrix above.

## Caching

Successful, untruncated command evidence is cached on exact identity:
repository, commit, tree, policy digest, check id, check version, the digest of
the configured argv, and a fingerprint of the machine — which covers the exact
filtered environment the child would see, the executables the checks resolve to
through that `PATH`, the repository's lockfiles, and the interpreter and
platform. Every one is part of the key and every one is re-validated before
reuse; a record that fails any of them is a miss, not a repair. A failure is
never cached but *is* recorded as an invalidation of that key, ordered by the
store's monotone write sequence rather than by any clock, so a failure observed
after a pass always outranks it even when the two attempts overlapped.
`cache_max_age_seconds` bounds how long a pass may stand in; `cacheable: false`
means never — the `infrastructure-change` profile marks its live-state checks
that way. `--no-cache` bypasses reuse and still records the attempt.

**On this hosted path the cache saves nothing across runs, and the workflow
does not pretend otherwise.** `ADMISSIBLE_HOME` points inside the per-run
`mktemp -d` scratch directory, which is created fresh for every run and
destroyed with the runner, so there is **no cross-run cache** here: every check
executes every time. Reuse within a run still applies, and that is all. A
self-hosted runner with a persistent `ADMISSIBLE_HOME` outside the workspace
would keep one — at the cost of a store that candidate commands run beside,
which is a trade to make deliberately rather than by accident.

Reuse is reported: each check carries `provenance` of `executed`, `reused`,
`imported`, `missing` or `not_run`, and a reused check also carries
`reused_from_attempt` naming the attempt the command actually ran in.
