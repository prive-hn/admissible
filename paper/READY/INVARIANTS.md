# Invariants — fail-closed work projection

Roque Briceño. Safety only. Companion to `PREMISE.md` and `LEMMAS.md`.

Status: **unproved process lemmas**. No citation binder row. No mutation receipt. Do not fold into `paper/PROOFS.md`.

## 0. Assumptions

A10 remains: adapter attestation honesty.

**Ap1 Connection-local packages.** Package issuance and check share one connection-scoped store. A `package_id` minted on another connection is out of claim unless that store is authenticated.

**Ap2 Hash.** SHA-256 collision and second-preimage resistance, same fail-open direction as A11: a colliding package or candidate digest would *admit*.

**Ap3 Single-process inspect window.** Opening and closing identity captures of one status query run in one process. A concurrent checkout swap mid-window is P2’s job, not a distributed lock theorem.

**Ap4 Mediated review path.** Verdicts that bind `(base, head, tree, patch digest)` are the only verdicts in claim. Informal chat approval, truncated logs, and “it was green earlier” are outside proof, the way Red’s runner proves only `InterposingRunner`.

**Ap5 Finite generation budget.** The allow set of review generations is finite and named in advance. Exhaustion is Closed, not a hop.

## 1. Identities

Three domain-separated digests. No API accepts one in another’s field. Distinct domain tags.

| Digest | Role | Binds |
|---|---|---|
| `task_hash` | comparison | bounded edit issued to the agent (paths, purpose, forbidden verbs) |
| `package_id` | authorization | issued package, class, policy digest, config path, principal |
| `artifact_id` | wire | repository, full commit, tree |

A **candidate** for review is a fourth tuple, not a fourth digest family: `(base, head, tree, patch digest)`. A verdict names that tuple or it names nothing.

## 2. State

Work package: `Issued` (write-once identities) or `Spent` (a check consumed it, success or refuse).

Projection query: `Open` (opening identity captured) → `Closed` (closing identity captured) → `Projected` or `Unable`.

Review generation: `Issued` → `InFlight` → `Accepted` | `Rejected` | `Invalidated`. Invalidated on any source byte change. Accepted transfers to no successor.

## 3. Forbidden hops

- Check without an issued `package_id` on this connection (I3).
- Check whose `artifact_id` differs from the package’s (I9 / I17).
- Caller-asserted class, policy, or config in place of the package’s (I10).
- Status `ready` after a failed or divergent closing identity capture (P2).
- Presentation writing an admission receipt or standing field (P0 / R11).
- Review verdict reused on a different head, tree, or patch digest (P3).
- Opening generation *n+1* after budget exhaustion without a new explicit admit (Ap5).
