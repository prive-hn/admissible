# Developer Admission Product — implementation plan

> **Historical record.** The v0.7 product described here shipped before the
> v0.8 package split. Use `docs/READY.md` and `docs/DEVELOPER_WORKFLOW.md` for
> current guidance; branch, issue, and commit references below belong to the
> private predecessor history and do not exist in the clean public history.

Date: 24/08/2026
Issue: predecessor repository issue #7
Base: `496b4e74f2dd92de45bd13d3b91876881c58242d`
Branch: `feat/developer-admission-product`

## Outcome

Turn the existing Admissible I/R/C research kernel into a practical, zero-dependency developer gate that consumes exact-artifact evidence, explains refusal, persists authenticated decisions, and updates current standing when later defects impeach prior approvals.

The product is not an LLM runner. Existing commands and optional reviewer tools produce evidence; Admissible evaluates and authenticates it deterministically.

## Non-negotiable boundaries

- Python 3.10+ and zero mandatory runtime dependencies.
- Closed JSON inputs/outputs; exact types at trust boundaries.
- No shell interpolation for configured commands.
- No raw stdout/stderr or secrets in receipts by default; store hashes and bounded private artifact paths.
- No reuse across repository/SHA/tree/policy/check-version boundaries.
- No workflow receipt may claim the full I/R/C predicate unless a real composed authority stack produced it.
- HMAC is shared-secret authenticity, never described as public non-repudiation.
- First registry anchor remains a bootstrap trust assumption.
- GitHub candidate execution is secret-free; signing/finalization is isolated from arbitrary candidate commands.
- Evidence and defects are append-only. A later defect changes current standing by query; it never rewrites the old signed decision.

## Architecture

Create a new `admissible/` stdlib package and keep `fcd/`, `rga/`, and `atlas/` unchanged unless a narrowly proven reusable primitive is required.

Suggested modules:

- `admissible/config.py` — closed `.admissible.json`, class selection, profile expansion, policy digest.
- `admissible/profiles.py` — eight built-in conservative profile documents.
- `admissible/identity.py` — repository remote/full SHA/tree/worktree identity.
- `admissible/evidence.py` — closed command/review/defect records, canonical serialization.
- `admissible/runner.py` — argv-only subprocess execution, timeout/process cleanup, output hashing/private logs, cheap-first sequencing.
- `admissible/decision.py` — ADMITTED/REFUSED/BLOCKED, independence/staleness/cost/time checks, plain remediation and stable JSON.
- `admissible/store.py` — SQLite schema/transactions/locking for evidence, journal events, workflow receipts, monotone current heads, dependencies and defects.
- `admissible/receipt.py` — signed workflow receipts and durable head anchoring built on `fcd.journal`/`fcd.head`; distinct domain and schema from composed I/R/C receipt.
- `admissible/standing.py` — current standing, impeachment, transitive dependents, missed-check accounting without unsupported rate claims.
- `admissible/cli.py` / `admissible/__main__.py` — init, profiles, run, verify, explain, status, impeach, export/import as needed.

Add:

- `protocol/workflow-evidence.schema.json`
- `protocol/workflow-receipt.schema.json`
- `protocol/defect-record.schema.json`
- `.github/actions/admissible/action.yml` local composite action
- `.github/workflows/admissible-reusable.yml` reusable workflow or a safe documented template if reusable-workflow self-reference would be misleading
- `examples/` end-to-end fixture/demo
- `docs/DEVELOPER_WORKFLOW.md`, `docs/GITHUB_ACTIONS.md`, `docs/COST_AND_LATENCY.md`, `docs/IMPEACHMENT.md`

## Phase 1 — RED contracts

Write failing tests before production code for:

1. profile enumeration and `init` non-overwrite;
2. closed config and profile/class selection;
3. exact repository identity and dirty/stale/partial-SHA refusal;
4. argv-only command execution, timeout, hashes and no raw log leakage;
5. closed review evidence, exact-SHA and independence checks;
6. plain actionable decision output and stable JSON;
7. restart-durable SQLite receipt/current-head behavior;
8. concurrent writer and transaction rollback;
9. signed workflow receipt issue/verify/stale/fork/truncation;
10. dependency and impeachment propagation;
11. CLI e2e in real temporary Git repositories;
12. GitHub environment exact-head/fork-preview/finalize boundaries;
13. wheel/entrypoint/schema/package-data contracts.

Each test must fail for missing behavior, not syntax/setup. Record RED commands/results in the commit message or a test-development log.

## Phase 2 — core CLI and decision

Implement profiles, config, identity, evidence, runner and decision with minimal code to turn phase-1 tests green. Commands:

- `admissible profiles [--json]`
- `admissible init --profile NAME [--force]`
- `admissible run [--class ID] [--sha FULL_SHA] [--preview] [--json]`
- `admissible verify TARGET [--json]`
- `admissible explain TARGET [--json]`
- `admissible status [--json]`
- `admissible impeach TARGET --evidence FILE [--test ID] [--json]`

Exit codes must be documented and stable: 0 admitted/current, 1 refused/not current, 2 blocked/config/operational error.

## Phase 3 — durable authenticated workflow receipts

Implement stdlib SQLite persistence under `ADMISSIBLE_HOME` with:

- schema versioning;
- WAL, foreign keys, busy timeout;
- append-only evidence/events/receipts/defects;
- atomic monotone-head + receipt commit;
- process-safe concurrent writers;
- deterministic lookup by receipt hash, full SHA, and current repository namespace;
- restart proof;
- key loading from `ADMISSIBLE_HMAC_KEY` or a permission-checked external file;
- signer key material never stored in SQLite or output;
- safe export/import that rejects rollback.

The workflow receipt should authenticate exact repository, SHA, tree, artifact, policy digest, decision, evidence digests, dependencies, issuance time, and one monotone workflow journal head. It is explicitly not `rga.AdmissibilityReceipt`.

## Phase 4 — impeachment and developer value

Implement append-only defect filing and standing queries:

- prior receipt remains authentic historical evidence;
- current standing becomes impeached;
- direct/transitive dependents are returned cycle-safely;
- output distinguishes observed defect, reachable dependent impact, and unknown scope;
- list checks/reviewers that approved the defective receipt and their raw miss counts only;
- exact remediation for affected artifacts and future regression requirement.

Add `admissible explain` scenarios for stale SHA, missing check, failed check, missing independent review, budget ceiling, timeout, invalid signature, current-head rollback, and impeachment.

## Phase 5 — GitHub Actions

Provide a simple two-boundary workflow:

1. `evaluate` — no signing secret; exact checkout; clean status; run commands/import optional review evidence; produce unsigned preview/evidence artifact and step summary.
2. `finalize` — protected branch/environment only; download immutable evidence artifact; verify SHA/tree/policy identity; execute no candidate command/package script; sign and persist receipt.

Do not assume Privé runner labels. Document `[self-hosted, linux, x64, <label>]` as caller configuration. Forks can evaluate but never finalize. Include cache identity contract and explicit LLM cost/time fields without making calls.

## Phase 6 — full verification and review

- Sabotage each critical test against old/disabled behavior.
- Existing `make test`, `make audit`, `make build`.
- Python 3.10/3.11/3.12 focused and full Python tests where available.
- actionlint or structural workflow validator; no unpinned external actions without rationale.
- build sdist/wheel; isolated install and CLI demo.
- assert wheel has no required dependencies and includes profiles/schemas/action templates.
- secret-pattern scan and permission checks.
- freeze exact commit; independent spec, security, compatibility/package, and UX review; repair and repeat until no valid P0/P1.
- open PR linked to issue #7 only after local gates pass.

## Done means

A developer can clone a small fixture repository, run:

```bash
admissible init --profile python-library
admissible run --preview --sha "$(git rev-parse HEAD)"
admissible explain "$(git rev-parse HEAD)"
admissible verify "$(git rev-parse HEAD)"
admissible impeach "$(git rev-parse HEAD)" --evidence defect.json --test unit
admissible status
```

and observe an exact-SHA admission, a restart-stable authenticated receipt, an actionable refusal when evidence is stale/missing, and an append-only impeachment that identifies affected dependents and missed checks—all without any LLM call unless the selected profile explicitly requires imported independent review evidence.


## Addendum — the security cut, after review

Recorded here because this file is the plan the branch was built from, and the
finished branch does something different in one important place. It is not
edited above: a plan that quietly matches the outcome stops being a record of
what was decided when.

Five external reviews of the finished branch converged on one finding, in
several shapes: **the CI gate signed on the strength of data the candidate could
reach.** The `evaluate` job runs candidate-owned commands; a command can leave a
descendant behind that edits what that job later reports; and a `finalize` job
in the same run, gated on that job's own output, was handed the signing key.
Recomputing the decision there proved the arithmetic and not the evidence.

The plan above says "signing/finalization is isolated from arbitrary candidate
commands". Two checkouts in one workflow run turned out not to be that. So:

- the reusable workflow **evaluates only**. It has no finalize job, takes no
  secret, and publishes its preview as a job output. A green run means the
  deterministic checks passed for that commit, and never that it was admitted;
- a new closed domain, `admissible/v0.6/evaluation-attestation`, carries an
  **external observer's** signature over exactly which records an evaluation
  produced — signed after the candidate's process group is gone, with a key the
  evaluating job never sees. `finalize` requires and verifies one. No
  attestation, no receipt;
- `admissible run` is preview-only and loads no key of any kind;
- a **trusted policy baseline** (`admissible policy trust`) breaks the circle
  where a change could edit the file that says what that change must satisfy;
- the whole executable boundary is pinned by a required `tool-sha` input, and
  the gate refuses at run time if it disagrees with `github.job_workflow_sha`.

The bridge from a finished GitHub run to a receipt is external and manual today.
That is a real gap and it is documented as one; it is not a workflow feature
that exists.
