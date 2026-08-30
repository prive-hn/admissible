# Execution adapter

FCD is the authority surface. An execution adapter is a bounded bridge to an existing worker such as a coding CLI, ACP agent, remote service, or local model runner.

FCD does not recreate the worker's tools, provider client, context store, or internal agent loop.

## Interface

Implemented in `server/execution.py`:

```python
ExecutionAdapter.run(request: ExecutionRequest) -> ExecutionResult
```

`ExecutionRequest` contains:

- immutable `ExecutionEnvelope` with attempt counter and nonce;
- canonical `ContextPackage` and expected package hash;
- admitted specialist, contract, steering stream and latest continuation hash;
- context mode plus an optional executor continuity hint.

`ExecutionResult` contains:

- `AdapterReceipt` computed over the package bytes the adapter submitted;
- exact executed provider/API model identity;
- executor/run identity and latest steering continuation hash;
- candidate artifact, evidence or question;
- optional executor-reported session/cache reuse telemetry.

An adapter cannot Pass, Accept, promote memory or write the store. It also reports readiness for an exact provider/API route: installed, authenticated, model resolves, project access, tools available, harmless canary, receipt support and death observability. FCD blocks Admit if the selected route is not ready; it does not wait for a later model-mismatch failure.

## FCD-owned guarantees

FCD validates:

1. current attempt ID and unpredictable nonce;
2. expected versus adapter-observed package digest;
3. latest steering continuation receipt;
4. declared versus executed provider/API model identity;
5. FCD attempt-local cache identity;
6. Pass/PassRefuse, store admission and accepted-only memory promotion.

Prior-attempt receipts, stale steering receipts, package mismatch and model mismatch fail closed.

## Executor-owned behavior

The executor may keep its mature:

- file, Git, test, build and browser tools;
- session/checkpoint implementation;
- provider prompt caching;
- tool loop and streaming protocol.

`executor_continue` and `executor_fork` are capability hints. FCD stores opaque IDs and receipts, not full sessions. `fresh_blind` forbids continuity. An adapter that cannot satisfy a required capability fails closed; it never silently downgrades.

Executor/provider cache reuse is telemetry only. It has no Pass authority and is labeled `executor-reported` in the cockpit. FCD's verified cache remains attempt-local and clears on Admit/Close.

## Trust boundary

FCD proves canonical package construction and receipt binding. Unsigned
`AdapterReceipt` values are **route identity**: Observe records what the
adapter reported. Provider physics and hidden executor residue remain
outside the theorem (A10).

`fcd/adapter_attestation.py` is a separate witness. `AttestingGateway`
holds the HMAC key. The transport returns a `ProviderObservation` and
cannot supply the signature. A verified receipt is bound to attempt id,
nonce, package hash, continuation hash, immutable `model_revision`, and
`provider_request_id`. Replay of those bindings fails closed. A worker
that changes `executed_model` without the gateway key fails verification.
This does not prove the provider told the truth. It proves the worker did
not author the executed-model field.

`observe_attested` is the only helper that writes `m_exec` from a verified
receipt. Direct `observe` still exists for the record kernel and for
route-identity demos.

`InferenceGateway` is the non-bypassable path: it holds `ProviderCredentials`
and never exports them. Only `infer` may call the provider. `ExecutionFence(require_attested=True)` refuses route identity. An optional `audit_ref` is signed when the provider supplies a billing or request-audit id.

Human review is a separate record (`fcd/human_review.py`). `ReviewConclusions.as_view()` always returns `automation` and `human` and never a single `green` flag. `admitted(require_human=True)` stays false until a signed human accept exists; a human reject blocks even if automation passed.

## Reference adapter

`DemoExecutionAdapter` is deterministic. It produces self-contained HTML and independently maps agent roles to executed models so mismatches reach Observe. `ProcessExecutionAdapter` accepts an injected mature executor runner; it does not implement a CLI or session store. Neither issues attested receipts. Use `AttestingGateway` when the executed model must be gateway-signed.
