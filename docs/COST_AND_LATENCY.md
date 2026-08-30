# Cost and latency

Admissible makes the price of a gate explicit *before* it runs, and refuses a
policy that cannot afford itself.

## The two ceilings

Every artifact class declares:

* `max_cost_units` — an abstract budget you define. A check costs
  `cost_units`; the class plans the sum of its checks.
* `max_wall_seconds` — the wall-clock ceiling. The class plans the sum of its
  check timeouts, and the decision also accounts for the wall time actually
  observed.

If the plan exceeds either ceiling, the decision is `BLOCKED` (exit `2`) with
`cost_ceiling` or `time_ceiling` — not `REFUSED`. The distinction matters: the
artefact was never evaluated, so nothing is known about it. Raise the ceiling
deliberately or make the class cheaper.

**The ceiling is checked before anything is spawned.** A budget you only
discover you have exceeded after paying is not a budget. `admissible run`
computes the plan first, and a class that cannot fit inside its own ceilings is
blocked without a single child process starting.

## Cost units are yours to define

A cost unit is whatever your team decides: CI minutes, dollars, reviewer
attention. Admissible does not convert units into money and does not estimate
anything. It adds integers and compares them to a ceiling you wrote down.

The starter profiles use a rough convention: `1` for a fast static check, `3–4`
for a full test suite, `4–5` for a suite that touches money or schema.

## Cheapest first, and stop at the first decisive failure

Checks run in `(cost_units, id)` order, and the run **stops** when a required
check fails. The remaining checks are reported as `not_run`, not as missing
evidence that someone forgot to gather. A refusal therefore costs the cheapest
check that could produce it, not the whole plan.

Set `collect_all_checks: true` on a class when you would rather see every
failure in one pass — useful while tightening a policy, expensive as a default.

## Reuse is exact or it does not happen

A successful, untruncated check result is cached against eight things:
repository, commit, tree, policy digest, check id, check version, the digest of
the configured argv, and a fingerprint of the machine (platform, architecture,
interpreter). Re-running the same commit under the same policy on the same
machine therefore costs nothing and spawns nothing; the decision reports those
checks as `provenance: reused`, with `reused_from_attempt` naming the attempt
the command actually ran in.

A miss on any one of the eight is a miss, not a repair. The machine is in the
key because a command observes it as well as the tree, and cheap
over-invalidation is the right error there: a needless re-run costs seconds, a
wrong reuse costs the guarantee.

Three rules bound it further:

* **A failure is never cached**, and never merely dropped either. It is
  recorded as an *invalidation* of that exact cache key, so no earlier success
  under the same key may be reused afterwards. Without that, a pass, then a
  known failure, then an ordinary run would resurrect the pass.
* **`cache_max_age_seconds`** bounds how long a pass may stand in for a fresh
  observation. The shipped tree-only profiles set a day.
* **`cacheable: false`** means never reusable. It is for checks whose subject is
  live state rather than the committed tree; `infrastructure-change` marks its
  plan, policy and drift checks that way, because a reused pass would answer
  about a world that has moved on.

Truncated output is never cached either, because its digest describes only the
bytes that were kept. `--no-cache` re-runs everything — and still records the
attempt, because not reusing evidence was never a reason not to write it down.

## Latency you should expect

The gate itself is arithmetic over digests: parsing, hashing and the SQLite
commit are microseconds-to-milliseconds. Essentially all wall time is your own
checks. The overhead Admissible adds is:

* one `git rev-parse`/`git status` per run, plus one `git status` after each
  check and one more before the preview is written;
* one SHA-256 pass over each check's retained output (bounded, 1 MiB per stream
  by default);
* two passes over the Admissible source tree — one before the checks, one after
  — so a check that rewrote the program judging it cannot go unnoticed;
* one `killpg` per check, always, because a check that exits zero has told the
  runner nothing about what it forked;
* one `BEGIN IMMEDIATE` transaction per anchored decision, in `finalize`.

## Language-model cost is declared, never spent

Admissible makes **zero** model calls, in every profile, on every path. A
profile that requires independent review declares that requirement in
`required_independent_reviews`, `reviewer_key_ids`, `author_key_ids` and
`review_max_age_seconds`; whoever produces that review — a person or a tool you
run yourself — decides what it costs. The gate only checks that a reviewer key
it was told to trust signed the review, that it is bound to this exact artefact,
that it is fresh, and that its key is not one of the configured author keys.
Both key lists are required and must be disjoint: a class that names one and not
the other, or the same key in both, is refused where policies are parsed.

`documentation-only` requires zero reviews and must never require a model call.

## Timeouts are a cost control, not a safety net

A check that exceeds `timeout_seconds` has its whole process group killed and is
recorded as `check_timeout`. A timed-out required check refuses the artefact: an
unfinished check is not a passing check.

## Output is bounded while the child is still running

Output is drained by bounded reader threads *as it arrives*. Bytes past the
limit (1 MiB per stream by default) are counted as truncation and discarded
immediately: they are never written to disk and never held in memory. A check
that prints a gigabyte cannot exhaust the runner's storage before anyone gets
round to truncating it, and it cannot stall on a full pipe either.

The retained bytes are exactly the bytes that are hashed and exactly the bytes
in the private log, so `stdout_sha256` always describes something you can read
back. Receipts carry digests and byte counts, never the bytes themselves.
