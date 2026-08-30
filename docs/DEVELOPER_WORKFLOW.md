# The Admissible developer workflow

Admissible is a deterministic gate. It runs the commands your repository already
has, binds what they observed to one exact commit, and answers one question:
**may this exact artefact be admitted under this repository's own policy?**

It is not an LLM runner. Nothing in this workflow calls a language model. If a
profile requires independent review, you import that review as a **signed
attestation**; the gate checks that a reviewer key it was told to trust signed
it, that it is bound to this exact commit, and that it is fresh.

## Install

Admissible is one repository and four coordinated 0.8.0 distributions, built
from `packages/` and meant to run in separate processes. Which one you install
is a decision about what that machine is allowed to do.

| distribution | console command | commands it installs |
| --- | --- | --- |
| `admissible-core` | none | nothing — it is a library, and the only one of the four with no dependencies |
| `admissible-ready` | `admissible-ready` | `profiles` `init` `run` `check` `mcp` `connect` `ui` |
| `admissible-trust` | `admissible-trust` | `ready-status` `verify` `explain` `status` `impeach` `attest-review` `attest-evaluation` `policy` (`trust`, `revoke`, `list`) `finalize` `run` `export` `import` |
| `admissible` | `admissible` | none of its own: static compatibility dispatch to whichever sibling owns the verb |

```bash
pip install admissible-core       # the kernel alone; it has no dependencies
pip install admissible-ready      # + admissible-core==0.8.0; Python 3.10+
pip install admissible-trust      # + admissible-core==0.8.0; Python 3.10+
pip install admissible            # developer convenience; pins all three siblings
admissible-ready profiles         # see the eight starter profiles
```

Only `admissible-core` has no dependencies. Each of the other three declares at
least one, pinned exactly at `==0.8.0`, and the umbrella declares all three.

A trusted machine installs exactly one authority: `admissible-ready` where
candidate code runs, `admissible-trust` where a key is held. The `admissible`
umbrella installs **both**, which is what makes it a developer convenience and
what makes it forbidden in a finalizer environment, a reviewer or observer key
environment, a policy signing or policy trust environment, any documented
minimal trusted deployment, and as a dependency of anything that runs in one.

On a developer machine with the umbrella, the legacy verbs keep working as
**transitional** aliases for **one release window**: `admissible run --preview`,
`admissible ready-status`, `admissible explain`, `admissible status`,
`admissible export` and `admissible import` are each handed to the sibling that
owns them. The dispatcher reads the command you typed and consults a static
table; it reads no credential, variable or keyring, so the same words dispatch
the same way on every machine, and a verb in neither table is refused rather
than guessed at.

Every trust-side example below is written as `admissible-trust`, because that is
the command the machine running it actually has installed.

## Quickstart

Every line below runs as written, in order, in a git repository with at least
one commit. Nothing is elided.

```bash
admissible init --profile python-library        # writes .admissible.json
$EDITOR .admissible.json                        # point each check at your
                                                # real command; the generated
                                                # argv are a template
git add .admissible.json .gitignore
git commit -m "adopt the admissible gate"       # an uncommitted policy cannot
                                                # be evaluated: the gate refuses
                                                # a dirty worktree
admissible check                                  # one friendly exact-HEAD result
admissible ui                                     # optional local product
```

Expect the first run to refuse and name something. A starter profile describes
the tools its profile *expects*, not the tools you have, and a first run telling
you which command is missing is the gate working.

`check` is the normal human command. It runs the same deterministic preview
evaluation as `admissible-ready run --preview`, records the attempt, and
translates the exact decision into **Needs attention**, **Waiting for review**,
**Checks complete**, or **Unable to check** with one ordered next action. It
never signs.

`admissible check --json` emits `admissible/v0.7/ready-state`. Stable machine
statuses include `needs_attention`, `waiting_for_review`, and `checks_complete`;
agents consume the schema and reason/action codes rather than terminal prose.
See `READY.md` for MCP and the local UI.

`admissible-ready run --preview` is the explicit evaluator for advanced
automation. It never signs, and it takes no key: it starts commands your
repository controls, and a process holding a signing key while it does that has
already lost the boundary the key was protecting. Issuing a receipt is a
separate flow, in a separate trust domain — see **Admission** below.

**`run` names two commands now, and this page always says which.** Ready's
`admissible-ready run --preview` is the evaluation above. The signing wheel
installs a `run` of its own: bare `admissible-trust run` — and `admissible run`
without a bare `--preview`, which the umbrella hands to it — is a transitional
alias for `finalize`, retained for **one release window**. That one consumes a
preview somebody else already produced, executes no check, and does sign, issue
a receipt and anchor it. The two are told apart by the argument list and never
by what credential the machine happens to hold. Prefer the explicit verbs:
`admissible-ready run --preview` to evaluate, `admissible-trust finalize` to
admit.

## The commands you will actually use

```bash
admissible init --profile python-library    # write .admissible.json
admissible check                            # friendly result for exact HEAD
admissible ui                               # local Ready product
admissible connect --name Builder \
  --purpose "Implement this change" --runtime hermes
admissible-ready run --preview --sha "$(git rev-parse HEAD)"
admissible-trust explain "$(git rev-parse HEAD)"
admissible-trust verify "$(git rev-parse HEAD)"
admissible-trust status
```

and, when reality disagrees with an earlier approval:

```bash
admissible-trust impeach "$(git rev-parse HEAD)" --evidence defect.json --test unit
```

Two exist for moving state between machines:

```bash
admissible-trust export --out journal.json      # this repository's signed journal
admissible-trust import --in journal.json       # extend a journal; rollback refused
```

and one for scaffolding CI, which needs the exact Admissible commit you pin:

```bash
admissible init --profile python-library --ci github --tool-sha FULL_SHA
```

The rest are the advanced flow that turns an evaluation into a receipt. They
belong to three different people on three different machines, and they are
described under **Admission**:

```bash
export ADMISSIBLE_HOME=/var/lib/admissible
export ADMISSIBLE_DURABLE_HOME=1
admissible-trust policy trust                                      # the operator
admissible-trust attest-review --review r.json --out attested.json # a reviewer
admissible-trust attest-evaluation --preview p.json --out e.json \
    --source-receipt receipt.json --isolation single-use-vm        # the observer
admissible-trust finalize --preview p.json --sha "$SHA" \
    --policy-root . --evaluation-attestation e.json \
    --reviews /trusted/out-of-band/reviews.json                    # the finalizer
admissible-trust ready-status --json                               # authenticated Ready
```

## Exit codes

| Code | Meaning | Typical cause |
| ---- | ------- | ------------- |
| `0` | command-specific success | `admissible-ready run --preview`: checks passed only; `finalize`, and the bare `admissible-trust run` alias for it: receipt admitted; `verify`/`status`: authenticated current standing |
| `1` | refused, or not current | a required check failed or is missing, a review is missing or stale, the artefact is unknown, or a defect has impeached it |
| `2` | blocked | dirty worktree, wrong or partial `--sha`, missing `.admissible.json`, missing signing key, cost/time ceiling, locked store |

`admissible-ready run --preview` exits `0`, `1` or `2`, and its zero is never
admission. Bare `admissible-trust run` is the `finalize` alias, so its zero
*is* one — that is the whole reason the two spellings are kept apart here.
`admissible-trust verify` exits `0` only when the artefact is current and
authentic, and `1` otherwise. Scripts can branch on these codes; they are part
of the contract.

A `--json` caller gets JSON on stdout for every one of them, including a usage
error. The envelope is narrower than it once claimed to be, and it is worth
stating exactly rather than generously:

* **`admissible-ready run --preview` emits a decision document.** On refusal it
  carries `scope`, `state`, `readiness`, `exit_code`, `reasons` and
  `remediation`. It does not promise a `message`: the structured reason codes
  are the account of the decision.
* **`verify`, `status` and `explain` emit a human summary on nonzero exits.**
  Their JSON includes `message`, readiness `NOT_READY`, and non-empty
  `remediation`, in addition to each command's own structured fields.
* **usage and operational envelopes carry** `scope`, `state`, `readiness`,
  `exit_code`, `message` and `remediation`, so a consumer need not parse stderr
  for those failures.
* **the other commands emit their own shapes** — `finalize` and `verify` emit
  a receipt or a standing document, `init` and `profiles` emit what they wrote
  or listed. Each is documented with its command, and none of them promises
  the failure envelope on success.

A consumer that wants one rule can use this one: on a nonzero exit from any
command, the document carries `state`, `readiness`, `exit_code` and
`remediation`. `message` is **not** in that universal rule because an
`admissible-ready run --preview` decision explains itself through `reasons`.
A consumer that wants one human-readable line should read `message` when
present and otherwise render the first structured reason.

## What `admissible-ready run --preview` actually does

The Ready evaluation is an evaluation and only an evaluation. `--preview` is
required, and without it `admissible-ready run` refuses with exit `2` rather
than doing anything. The bare `run` the signing wheel retains is a different
command in a different distribution — the `finalize` alias described under
**Admission** — and none of the seven steps below happens there.

1. **Identify the artefact exactly.** Full 40-character lowercase SHA only. A
   dirty or untracked worktree is refused, because evidence produced there would
   not describe the commit you name. An abbreviated SHA is refused; a stale
   `--sha` is refused and the observed head is printed.
2. **Load the closed policy.** `.admissible.json` is parsed with exact types.
   Unknown keys are refused. A `shell` key does not exist: commands are argv
   lists and are never passed through a shell.
3. **Check the budget before spending it.** If the class plans more cost units
   or more seconds than its own ceilings allow, the run is `BLOCKED` and *no
   command is spawned*. A ceiling you only discover after paying is not a
   ceiling.
4. **Run the checks, cheapest first, and stop at the first decisive failure.**
   Each check runs with its own timeout in a new process group; on timeout the
   whole group is killed. stdout and stderr are drained by bounded readers
   *while the child runs*, so a noisy check cannot fill the disk before anyone
   truncates it; the retained bytes are hashed once and those same bytes are
   written to an owner-only private log under `$ADMISSIBLE_HOME/logs/`. When a
   required check fails, the remaining checks are reported `not_run` rather than
   executed — set `collect_all_checks: true` on the class if you would rather
   see everything.

   The child environment has the whole `GITHUB_*`, `RUNNER_*`, `ACTIONS_*` and
   `ADMISSIBLE_*` namespace removed, plus every secret-shaped name. Not a list
   of variables: the namespaces. `RUNNER_TEMP` and `GITHUB_WORKSPACE` tell a
   check exactly where the trusted job's files are going to be, which is
   everything a surviving descendant needs to rewrite one. `ADMISSIBLE_IN_CHECK`
   is the single variable put back, so your tooling can tell it is inside the
   gate; it carries no path and no secret.

   When a check finishes — normally, on timeout, on error, or on Ctrl-C — its
   entire process group is killed. Exiting zero tells the runner nothing about
   what a check forked, and a descendant that closed its pipes looks finished
   while it keeps running as the same user.
5. **Re-check the artefact, and the gate, after every check.** If a check
   repairs a tracked file, stages something, or leaves an untracked artefact
   behind, the run is `BLOCKED`: no evidence gathered there describes the
   commit you named. The Admissible source tree is measured before the checks
   start and again after they finish; a check that edited it would be rewriting
   the program about to judge it, so that is `BLOCKED` too.
6. **Decide.** Required checks must pass, and each one must be matched by
   evidence carrying the digest of the argv this policy configures. Optional
   checks are reported but never refuse. Reviews must be signed by a pinned
   reviewer key, approving, bound to this exact commit and tree, and fresher
   than `review_max_age_seconds`.
7. **Record, and hand over.** The attempt, its evidence and the decision it
   reached are written to `$ADMISSIBLE_HOME`, whatever the decision was, so
   `explain` can answer about it later. With `--preview-out FILE` the run also
   writes the unsigned preview artefact a finalizer consumes. It is written
   last, owner-only, and atomically: last because every check's process group
   is dead by then, atomically so no reader can catch it half-written.

No `admissible-ready run --preview` produces a receipt, ever: there is
**no signer** in the Ready wheel to reach for, and no key is read. It is not a
quiet run either — every check's output goes to an owner-only private log under
`$ADMISSIBLE_HOME/logs/`, which is the only place raw bytes are kept.

`--no-cache` re-runs every check and still
records the attempt — not reusing evidence was never a reason not to write it
down. `--no-store` records nothing at all, and the output says so, because a
run that leaves no trace should never be something you have to infer.

## Attempts

Every run is one **attempt**, with its own id, carried by the evidence it
produces and by the decision and receipt that quote it.

Attempts never merge, and the decision enforces it: a record belonging to
another attempt is refused with `attempt_mismatch`, and a decision that names no
attempt at all may still not span two of them. Inside one attempt, several
records may describe one check — a locally executed run and an imported one, say
— and they resolve to the *worst* outcome, so a passing record can never paper
over an observed failure. Across attempts they do not mix: yesterday's failed
attempt stays on record as history, and a clean rerun today is admitted on its
own evidence.

Reusing an earlier observation is therefore an explicit act with its own record.
A reused result is *derived* into the current attempt: the derived record
carries this attempt so it can count, and `reused_from_attempt` naming the
attempt the command actually ran in, so nobody reading it later can mistake it
for a command that ran just now.

`admissible explain` reports the latest attempt and names it, so standing and
explanation can never disagree about the same observation. When a receipt on
record belongs to an earlier attempt, `explain` says so rather than re-judging
it.

## Caching

Successful, untruncated command evidence is reused when — and only when — every
one of these matches: repository, commit, tree, policy digest, check id, check
version, the digest of the configured argv, and a fingerprint of the machine.
All eight are in the cache key and all eight are re-validated before reuse. A
command observes the machine as well as the tree, so a result from another one
answers a question nobody asked; cheap over-invalidation is the right error
here.

The machine fingerprint is the part worth spelling out, because a fingerprint
that covers less than the command can see is a reuse that is not exact:

* **the exact environment the child would see**, every name and every value,
  after the runner's filtering. `PATH` decides which program runs; `LANG`,
  `TZ`, `CFLAGS` and their kind decide what it does;
* **the executables the checks name**, resolved through that same `PATH` and
  identified by content where the file is small enough to hash, and by
  device/inode/size/mtime where it is not;
* **the dependency manifests the repository commits** — `poetry.lock`,
  `uv.lock`, `Pipfile.lock`, `requirements.txt`, `package-lock.json`,
  `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, `Gemfile.lock`,
  `composer.lock`;
* the interpreter, implementation, architecture and platform.

Three further rules bound it:

* **A failure is never cached** — a failing check must run again so a repair
  can be observed. But it is not dropped either: it is recorded as an
  *invalidation* of that exact cache key, so no earlier success under the same
  key may be reused after it. Without that, a pass, then a known failure, then
  an ordinary run would quietly resurrect the pass.

  "After" is the store's own monotone write order, never a wall clock. Two
  attempts overlap in CI all the time, and the slow one that started first can
  fail last: its attempt-start timestamp is *lower* than the pass it has to
  invalidate, so ordering by clock would let that pass survive news that
  contradicts it. Ordering by the sequence the store assigned when each fact
  was committed is ordering by when it became known, which is the only order
  that answers "what do we know now?".
* **`cache_max_age_seconds`** bounds how long a pass may stand in for a fresh
  observation. The shipped tree-only profiles set a day.
* **`cacheable: false`** means never reusable at all. It is for checks whose
  subject is live state rather than the committed tree — the
  `infrastructure-change` profile marks its plan, policy and drift checks this
  way, because a reused pass would answer about a world that has moved on.

Reuse is reported as `provenance: reused`, with `reused_from_attempt` naming
where it came from. `--no-cache` re-runs everything and still records the
attempt.

## Reviews that block

A review that blocks a merge is an authority claim, so it must be authenticated.

```bash
export ADMISSIBLE_REVIEW_KEY_ID=alice
export ADMISSIBLE_REVIEW_KEY='…'          # deliberately NOT the signing key
admissible-trust attest-review --review review.json --out attested.json
```

Put the attestation in the `attestations` array of an evidence bundle, list the
reviewer key ids allowed to approve the class in `reviewer_key_ids`, and point
`ADMISSIBLE_REVIEW_KEYRING` at a permission-checked JSON file mapping key id to
secret **on the finalizer**.

The bundle reaches the finalizer beside the preview, never inside the tree:

```bash
admissible-trust finalize --preview preview.json --sha "$SHA" \
    --policy-root . --evaluation-attestation evaluation.json \
    --reviews reviews.json
```

An earlier version of this page said committing the bundle into the candidate
tree was a supported transport. It is not, and it never could have been: a
review binds the exact repository, commit, **tree** and policy it approves, so
committing it changes the tree it signs, and signing after that commit binds a
different commit again. The hash would have to contain itself.

A signed attestation is still nonsecret data — its authenticity is the
signature, not the path it arrived by — which is why `--reviews` can accept a
file from anywhere. The file is authenticated against the same pinned keyring
and bound to the same exact repository, commit, tree and policy as everything
else, and it may carry **only** signed reviews and signed authorship claims:
command records are refused there, because those are exactly what the external
observer exists to witness and a side channel that could add one could
fabricate a pass.

Reviews, authorship and evaluation observation are **separate authenticated roles**.
The observer signs the command-evaluation boundary; the finalizer separately
authenticates the out-of-band review and authorship bundle. Supplying or
updating `--reviews` needs **no observer re-sign** and cannot replace a command
record the observer witnessed.

Counting is by **distinct authenticated key id**, not by the `reviewer_id`
string: two reviews signed by one key are one reviewer. `author_key_ids` names
identities that may never count, so nobody reviews their own change.

Both lists are required, and they must be disjoint. A class that requires review
and names no `reviewer_key_ids`, or no `author_key_ids`, or the same key in
both, is refused where policies are parsed — before a single check is spawned.
"Independent" is only a real requirement when the policy can tell a reviewer
from an author; without the author list, a change's own author can sign it twice
with two keys and the gate would report two independent reviews. The generated
high-risk profiles ship explicit `REPLACE-WITH-…` placeholders in both lists, so
a policy nobody has configured is BLOCKED rather than lenient.

An unsigned review is advisory. It is displayed, and it is heeded when it
*rejects* — refusing on an unauthenticated objection is the safe direction — but
it can never satisfy a required review. A class that requires reviews but pins
no `reviewer_key_ids` refuses and says so, rather than appearing to enforce
something it cannot authenticate.

### Who authenticates is a property of the job, not of the bundle

Whether an attestation can be authenticated depends entirely on whether *this*
process holds a reviewer keyring, and the two cases are deliberately different:

* **`finalize` holds the keyring.** It is the authenticator. Every attestation
  must verify against it; one that does not is an error, not a shrug.
* **`admissible-ready run --preview` never holds one.** It starts
  candidate-owned commands, so it does not read a reviewer keyring even when
  one is configured in its environment — that would make the boundary a
  property of the environment rather than of the
  program. The attestations are carried through untouched, reported as
  `unauthenticated_review`, and count for nothing. The decision is `REFUSED`
  with readiness `AWAITING_REVIEW`, and the preview it writes is a handoff to
  whoever does hold the keyring.

The same keyring authenticates one more thing: **who wrote the change**. A
class requiring independent review admits nothing without an authenticated
authorship attestation signed by a key the policy pins in `author_key_ids`.
"Nobody reviews their own change" is a rule about a key, and until a key claims
authorship there is nothing to exclude — the `author_id` string inside a review
document is populated by whoever wrote the file and establishes nothing. Sign
one with `admissible attest-review --authorship` and carry it in the bundle's
`author_attestations` array. Without one the decision reports
`missing_author_attestation` and no finalizer will complete it.

The claimed `key_id` is still screened while unauthenticated, because that check
costs nothing and can only ever refuse: a key the policy names as an author, or
one it does not pin, is rejected there and then rather than travelling on. A
claim that survives still has to survive the signature check wherever the keyring
lives.

`readiness` is reported beside `state` in `--json` and in the plain output, and
is never a fourth decision state: exit codes stay `0`/`1`/`2`. Evaluation
`state` is exactly `CHECKS_PASSED`, `REFUSED` or `BLOCKED`; `ADMITTED` belongs
only to a signed receipt. For an authenticated provider receipt, the matrix is:

```text
READY_FOR_ATTESTATION -> success only
AWAITING_REVIEW -> success or failure
NOT_READY -> no provider conclusion is admissible
```

`cancelled` and `timed_out` are never admissible. See
`docs/GITHUB_ACTIONS.md` for the CI handoff this exists for.

Evidence dated more than **300 seconds** ahead of this clock is refused
(`future_dated_evidence`, `future_dated_review`). That allowance is ordinary
skew between two machines; beyond it, a max-age rule cannot bound anything,
because the review claims to come from a future that has not happened.

## What `explain` tells you

`admissible explain SHA` never runs a command. It reads what is on record and
answers three questions: what happened, what is known, and what to do next.

It answers twice, deliberately. First from **what the attempt recorded at the
time** — the tree, the policy and the decision as they were then — because an
attempt is history and the checkout has moved on since; judging yesterday's
evidence against today's tree produces stale-tree and missing-check complaints
that describe nothing that ever happened. Then from **this repository's current
policy**, which is the "what would happen if I re-ran this now?" answer.

It covers every refusal shape you will actually hit:

| Situation | What `explain` shows |
| --------- | -------------------- |
| stale evidence | `stale_evidence_sha` / `stale_evidence_tree`, plus the `missing_check` that follows |
| a check never ran | `missing_check` with the exact command to run |
| a check failed | `failed_check` with its exit code |
| a check timed out | `check_timeout` with the timeout it exceeded |
| no independent review | `missing_independent_review` with how many are still needed |
| a forged or mismatched command | `argv_mismatch`, naming the argv the policy configures |
| a check that mutated the worktree | a `BLOCKED` run naming what changed |
| a budget ceiling | `cost_ceiling` / `time_ceiling`, and that nothing was run |
| a check skipped after a decisive failure | `check_not_run` |
| evidence from a different attempt | `attempt_mismatch`, naming both |
| an unsigned or unpinned review | `missing_independent_review`, `unpinned_reviewer_key`, `unpinned_reviewer_keyring` |
| a signature no keyring here can check | `unauthenticated_review`, and readiness `AWAITING_REVIEW` |
| no authenticated authorship claim | `missing_author_attestation`, naming the key list that may sign one |
| an authorship claim by an unpinned key | `unpinned_author_key` |
| a review dated in the future | `future_dated_review` |
| a receipt that will not verify | the signature problem, with the key id to check |
| a receipt whose head was superseded | "authentic, but its journal head is no longer the current head" |
| an impeached artefact | the defect, the checks that missed it, and the reachable dependents |

Because it evaluates the stored evidence against the *current* policy, it also
answers "what would happen if I re-ran this now?" after you tighten a profile.

## Moving state between machines

`admissible export` writes the repository's journal: its events, the full signed
head chain, the workflow receipts, the evidence records they bind, and the
defects that were anchored. It carries no key material and no raw logs.

`admissible import` replays that chain, and believes exactly what a signed head
covers. Events trailing past the last signed head's `event_count` are covered
by no signature at all, so a bundle carrying any is refused rather than
truncated — otherwise a forged defect appended after the last head arrives
looking anchored and impeaches an artefact nobody signed an impeachment for.
Every head is authenticated against the events it claims to cover, including on
a same-head re-import, where a shortcut would let a second bundle arrive with
the same head and different events.

A full export is capped at **64 MiB** and refuses before creating or replacing
`--out` when the authenticated bundle would exceed that bound. The supported
bounded selection is a signed journal prefix, never an arbitrary row limit:

```bash
admissible-trust export --through-head HEAD_HASH --out journal-prefix.json
admissible-trust import --in journal-prefix.json
```

A selected prefix is a historical cut, not a path around the ceiling. Every
selection is cumulative from the journal's first event, so after current
history exceeds 64 MiB no sequence of later prefix imports can bring a
destination to the source's current head. Importing an earlier cut
intentionally omits every later event, including a later defect, so `CURRENT`
on that destination means current only as of the selected authenticated cut.
Use `--through-head` only for deliberate historical reconstruction; the present
single-file format does not support complete current-history transfer above the
ceiling. Import still authenticates the complete selected prefix and refuses
rollback.

Three correspondences are then checked in **both** directions, because a one-way
check lets an omission through and an omission is the quiet forgery:

| Signed event | ↔ | Attachment |
| ------------ | - | ---------- |
| `workflow-admission` | ↔ | its workflow receipt, by body digest |
| a receipt's `evidence_digests` | ↔ | the evidence records supplied |
| `defect-filed` | ↔ | its defect record |

Dropping a defect erases an impeachment and restores `CURRENT`; dropping a
receipt leaves an admission nobody can read; dropping evidence leaves an
artefact current on the strength of records that are not there. All three are
refusals. Dependency edges are rebuilt from the signed receipt bodies, so
impeachment reachability survives the move.

The whole bundle lands in **one** `BEGIN IMMEDIATE` transaction. Heads committed
one at a time could be interrupted with the earlier ones durable and their
attachments missing, which is indistinguishable from an export that omitted
them: an invalid last head therefore leaves nothing at all behind.

An import may extend a journal; it may never shorten one. Both machines need the
same signing key.

## What a receipt is, and is not

A workflow receipt authenticates: repository, commit, tree, policy digest,
class, decision, attempt, evidence digests, which reviewer key authenticated
each counted review, declared dependencies, issuance time, and one monotone
journal head.

That last-but-three matters for attribution. `explain` reports which reviewer
*keys* carried an artefact that later showed a defect, and it takes them from
the signed receipt, never from the `reviewer_id` string inside a review record —
which is chosen by whoever produced the record. Naming a person is a claim, so
it is only ever made from the identity that signed.

It is **not** the composed identity/scrutiny/standing receipt of the Admissible
research kernel, and its schema says so (`scope:
developer-workflow-admission`). It never claims that the code is correct — only
that the checks you declared passed on this exact artefact.

Authenticity is HMAC-SHA256: it proves that a holder of the shared key issued
the receipt. That is not public non-repudiation. Anyone with the key can issue
receipts and can verify them.

## Admission

`admissible-ready run --preview` produces an evaluation. Turning one into a
receipt takes three more parties, and they are separate because each one is a
thing the others must not be able to do. Bare `admissible-trust run` is the
third party's `finalize` under its transitional name, not a shortcut past the
first two.

First select the finalizer's durable store. Do this before the operator trusts
a policy and keep the same home for finalization:

```bash
export ADMISSIBLE_HOME=/var/lib/admissible
export ADMISSIBLE_DURABLE_HOME=1
admissible-trust policy trust --repo /trusted/checkout
```

**1. The operator anchors the policy — once.**

```bash
admissible-trust policy trust                   # in a trusted checkout, on the
                                          # machine that will finalize
```

The policy travels inside the tree the policy governs. A change to payment code
can also change the file that says what a payment change must satisfy, so a
gate that reads only that file lets the change set its own bar. The baseline
breaks the circle: after it, descriptions may change freely — the enforcement
digest ignores prose — and any change to the checks, the review counts or the
key ids blocks until an operator approves it the same way. A finalizer holding
no baseline for a class refuses everything for that class, because it cannot
tell a tightened policy from a weakened one. The first policy is an explicit
bootstrap and never an implicit one: "trust whatever arrives first" is the rule
an attacker would choose.

**2. An external observer attests the evaluation — after it is over.**

```bash
export ADMISSIBLE_EVALUATION_KEY_ID=observer-1
export ADMISSIBLE_EVALUATION_KEY='…'      # a third key, see below
admissible-trust attest-evaluation --preview preview.json \
    --source-receipt source-receipt.json --isolation single-use-vm \
    --out evaluation.json
```

This is the part that makes any of the rest worth doing. Recomputing a decision
from evidence proves the arithmetic, not the evidence: the records were written
by the same process that ran candidate-owned commands, and a command can leave
a descendant behind that edits what that process later reports. The observer
runs after the evaluating job's process group is gone, holds a key that job
never sees, and signs for the exact repository, commit, tree, policy, class,
attempt, state, readiness, config path, fork flag, dependency edges, decision
digest, and the digest of every command record and advisory review record in
the preview it observed. Those digests are checked in both directions: a
record the observer did not watch cannot be counted, and a record it watched
cannot be dropped afterwards. Signed reviews and signed authorship claims
arrive independently through the authenticated out-of-band `--reviews` bundle;
they keep their own authority and require no observer re-sign. Every field the
observer does bind is compared by `finalize` against what it independently
derived — a field that is read but not compared is a field a candidate may
change after the observer looked at it. In particular,
the **observer independently asserts isolation** after checking external
infrastructure evidence; preview isolation is evaluator-reported diagnostic
data and never supplies the signed assertion. `none` is a valid honest
observation and remains non-finalizable.

### The source receipt, and what it does not prove

`--source-receipt` is required, and it is the difference between an attestation
and a signature over the candidate's own account of itself. Every other field
in the body comes out of the artefact under evaluation; without an external
one, a self-consistent fabricated pass and a real run are the same document
with the same signature on it.

The receipt is closed and exactly typed:

```json
{
  "schema": "admissible/v0.6/external-source-receipt",
  "provider": "github-actions",
  "run_id": "17825349901",
  "commit_sha": "…40 hex…",
  "conclusion": "success",
  "receipt_digest": "…64 hex…"
}
```

`receipt_digest` is the digest of the receipt document the observer read. If it
is easier to hand over the document itself, put it under `source_document`
instead and the digest is computed canonically here; supplying both is fine as
long as they agree. `run_id` must be immutable at that provider — a value that
can be reused names nothing. `finalize` refuses a receipt for another commit.
Its conclusion rule uses only the readiness the finalizer recomputes from the
evidence and its trusted policy: `READY_FOR_ATTESTATION` accepts only `success`;
genuine `AWAITING_REVIEW` accepts `success` or the red gate's `failure`;
`NOT_READY`, `cancelled` and `timed_out` never complete an admission. The
readiness in the observer's signed statement is bound and checked, but it does
not grant a provider conclusion the recomputation would refuse.

**The adapter-honesty assumption is retained deliberately, and it is this.**
Signing a source receipt establishes that an operator, or an adapter they run,
reported having read that receipt from the named provider. Admissible does not
fetch it, does not call the provider, and cannot verify it. An adapter that
lies — or an operator who signs a receipt they never read — produces an
attestation that verifies. What the source receipt buys is a bound on *who* can
be wrong: the fabrication now has to happen in the observer's trust domain,
outside the job the candidate's commands ran in, rather than inside it. It does
not remove the possibility, and no wording here should be read as if it did.

**3. The finalizer signs.**

```bash
export ADMISSIBLE_HMAC_KEY='…'
export ADMISSIBLE_EVALUATION_KEYRING=~/.admissible/observers.json
export ADMISSIBLE_REVIEW_KEYRING=~/.admissible/reviewers.json
export ADMISSIBLE_HOME=/var/lib/admissible
export ADMISSIBLE_DURABLE_HOME=1
admissible-trust finalize --preview preview.json --sha "$SHA" \
    --policy-root /trusted/checkout --evaluation-attestation evaluation.json \
    --reviews /trusted/out-of-band/reviews.json --out receipt.json
```

It re-derives repository, tree and policy from its own trusted checkout,
authenticates the observer and the reviewers against keyrings it pins,
re-checks the policy against the baseline, recomputes the whole decision, and
only then anchors. **No evaluation attestation, no receipt** — there is no
default and no fallback.

If writing `--out` fails after the admission is anchored, the message says the
receipt exists and names it. Reporting BLOCKED for an admission that is already
durable is the one lie an automated caller cannot recover from.

## Keys

There are three, and none of them substitutes for another.

| Variable | Signs | Held by |
| -------- | ----- | ------- |
| `ADMISSIBLE_HMAC_KEY` | admissions (receipts, defects) | the finalizer |
| `ADMISSIBLE_REVIEW_KEY` | reviews, and authorship claims | a reviewer, or an author |
| `ADMISSIBLE_EVALUATION_KEY` | evaluation attestations | an external observer |

Holding the finalizer's key must not let anyone mint the reviews it honours, or
the attestation that says an external source receipt was read. Each has a `_KEY_ID` and a
`_KEY_FILE` form; the finalizer verifies the other two against
`ADMISSIBLE_REVIEW_KEYRING` and `ADMISSIBLE_EVALUATION_KEYRING`, which are the
pins.

```bash
export ADMISSIBLE_HMAC_KEY='…'            # or
export ADMISSIBLE_HMAC_KEY_FILE=~/.admissible/key   # chmod 600, checked
export ADMISSIBLE_HMAC_KEY_ID=team-a      # optional, default "local"
```

No key is ever accepted as a command-line argument, stored in the database,
written into a receipt, or printed. A key file readable by group or others is
refused. `admissible-ready run --preview` reads none of them; bare
`admissible-trust run` is `finalize`, and reads `ADMISSIBLE_HMAC_KEY` like it.

## Where state lives

`$ADMISSIBLE_HOME` (default `~/.admissible`) holds `admissible.sqlite3`, the
trusted policy baselines, and the private logs. The database is created `0600` in a `0700` directory, runs in WAL
with foreign keys on, and refuses to open a database written by a newer
schema. Evidence, journal events, receipts and defects are append-only, enforced
by triggers as well as by the API.

The 0.8.0 split changed no schema and no stored row. An existing **v0.7** home
opens and migrates in place, from either distribution, with no destructive step.

### What that home cannot promise

- **Live sidecars refuse.** A home with a `-wal`, `-shm` or `-journal` file
  beside it is refused outright, because the database's current contents are
  then in the sidecar and reading them honestly would mean replaying them —
  a write to a home this process has not yet decided it may use.
- **Concurrent same-home processes are unsupported.** Two Admissible processes
  cannot share one home at once; the second is told to wait for the owner. A
  process that holds the store open, or one killed without closing it, locks
  every other opener out until it lets go or somebody checkpoints the home.
  That is a **denial of service by design** and the deliberate trade.
- **The schema lock is advisory.** It binds the processes that agree to take
  it, which is every Admissible distribution and nothing else.
- **Same-user filesystem and SQL tampering is outside the claim.** A hand-run
  `sqlite3`, or anything else under this Unix account, can create, migrate,
  corrupt or delete the home between any two steps, read this process's
  environment, and remove the private logs. The fail-closed reads then produce a
  **denial of service** rather than a false answer — and that denial is real.

Separate distributions are **not an operating-system sandbox**. What the split
removes is **accidental capability adjacency**: a signing key is no longer one
import away from a process that runs whatever `.admissible.json` says. Isolation
from code already running hostile in this account remains an operating-system
problem.

## Tightening a profile

The starter profiles are conservative and deliberately incomplete. Each one
lists what it does **not** cover and how to tighten it (`admissible profiles`).
Replace the placeholder commands with the ones your repository really runs,
then raise `required_independent_reviews`, shorten `review_max_age_seconds`, or
add checks as the risk of the change class justifies it.

Changing any enforcement-relevant field changes the policy digest, and evidence
is never reused across a policy boundary. Descriptions and residual-risk notes
are not part of the digest, so you can improve the prose without invalidating
yesterday's evidence — and not part of the *enforcement* digest either, so
improving the prose does not need a fresh `admissible policy trust`.

Tightening is always allowed. Weakening a **high-risk** profile is not: the
`rest-api`, `database-migration`, `authentication-change`, `payment-change` and
`infrastructure-change` profiles carry a floor taken from the shipped profile
itself. A class under one of them may add checks and raise the review count, and
may never require fewer reviews or drop one of the profile's required checks.
The argv stays yours — the floor is about which checks exist, never about which
commands they run. If a class is not that kind of change, choose a different
profile rather than lowering the bar of this one.

Selecting a different policy file is `--config PATH`, relative to the repository
root and contained inside it. That exact file is what is checked for existence,
evaluated, digested, named in the preview, and re-read by `finalize`. An option
that is advertised, existence-checked and then ignored is worse than no option:
it lets a caller believe it picked the strict policy while the default one
decides.

See also: [GITHUB_ACTIONS.md](GITHUB_ACTIONS.md),
[COST_AND_LATENCY.md](COST_AND_LATENCY.md), [IMPEACHMENT.md](IMPEACHMENT.md).
