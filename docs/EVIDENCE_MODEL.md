# Evidence model

Status: atlas/context reducers and schemas implemented. External executor/code-index adapters remain integration work.

## Claim chain

```text
operator intent → visible contract → pinned envelope/package → adapter/model/steering receipts → fcd decision → artifact → accepted memory delta
```

Evidence records never impersonate authority events. `Enforcer` owns `open|stage|bind|call|decide|accept`. `ContextAuthority` owns `work_pin|envelope_admit|context_package|steering|adapter_receipt|receipt_refuse|impact_review|memory_promote`. Plans, questions and artifacts are declared records consumed alongside those journals.

## Certainty bands

A failure/impact view must keep three disjoint meanings:

- **Observed** — happened in journal/runtime evidence.
- **Reachable** — dependency/static analysis proves it may be affected; not observed.
- **Unknown** — evidence does not bound it.

Never render reachable as observed or unknown as safe.

## Provenance

Every evidence row has an ID, kind, label, optional source URI/hash, journal index and timestamp. Visual marks resolve to those IDs. Questions attach to one exact node. An unresolved question sets only that node `blocked=true`; DAG dependents remain gated by normal dependency policy.

## Artifact evidence

An artifact record states `present` and `runnable` as observed facts. The reference server supplies sandboxed HTML with candidate/accepted state. Future adapters may supply web previews, documents, API responses, mobile builds, test runs or deployment receipts.

## Failure detail

Required fields:

- what happened,
- what remains safe,
- fault or fail-closed label,
- observed/reachable/unknown impact,
- evidence records,
- recovery intents.

No free-form agent summary can override these fields.
