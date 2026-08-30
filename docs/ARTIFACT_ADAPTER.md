# Artifact adapter

The artifact pane shows the result an owner can evaluate, not a generated picture of it.

## Contract

A runnable artifact record contains:

- `workItemId`, stable artifact ID and title,
- kind (`html`, `document`, `api`, `test`, mobile/build adapter names),
- state (`candidate` or `accepted`),
- addressable content (`srcDoc`, URI or platform handle),
- optional before-version,
- provenance/evidence IDs.

## Rules

- Candidate artifacts remain outside the accepted store.
- Accepted is derived from fcd Accept only.
- Before/after compares immutable versions.
- Embedded web content is sandboxed and cannot call cockpit authority APIs.
- Missing artifact is explicit; the UI may render deterministic stage evidence but labels it as fallback.
- A visual smoke is evidence only for behavior actually exercised.

## Implemented

`DemoExecutionAdapter` returns self-contained HTML; the right pane renders it in a sandboxed iframe and exposes candidate/accepted/before-after views plus evidence overlay.

## Future adapters

- local/remote web server preview,
- iOS Simulator/device build,
- API collection/result,
- document/PDF renderer,
- test/coverage report,
- deployment and live-smoke receipt.

Each adapter remains read-only with respect to fcd authority.
