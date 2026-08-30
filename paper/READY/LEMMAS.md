# Lemmas — fail-closed work projection

Roque Briceño. 27 August 2026. Companion to `PREMISE.md` and `INVARIANTS.md`.

Not theorems. Not I18. Family **P**, composed over I/R/C the way Red F sits over the base.

Fable (2026-08-27): analogical I/R citations are not derivations. Sketches below no longer claim □ from I3/I7/I9/I10/I17/R11. Motivation only. The theorem is the guards.

## Lemma P0 — Projection non-interference

A projection surface (status query, local presentation, stdio agent surface) writes no FCD field, no RGA field, and no admission receipt.

**Sketch.** Each is a query or an evaluation trigger. The friendly label `ready` is emitted only by authenticating an already-issued `ADMITTED` receipt with `CURRENT` standing. Passing checks never writes standing. This is the same *inspection method* as R11, on Ready files, not a citation of R11.

**Guard obligation.** Named methods: refuse to start a presentation or agent surface in a process that holds admission, review, observer, or signing credentials; refuse any tool that finalizes, trusts policy, attests, impeaches, merges, or deploys.

## Lemma P1 — Work-identity factorization

A connected-agent check is admissible only if:

1. `package_id` was issued on this connection, for this principal, and is still `Issued` (not `Spent`);
2. `artifact_id` at issue equals `artifact_id` at check;
3. evaluation uses the package’s class, policy digest, and config path, not caller-asserted stand-ins.

Otherwise refuse. Do not evaluate. The first check attempt, success or refuse, marks the package `Spent`.

**Sketch.** Instantiate Red F on `(task, package_id, artifact_id)`. I-theorems are motivation, not premises. The connection store is not writable by the agent.

**Corollary P1′.** Two agents on the same tree still need two packages. Sharing `artifact_id` does not share `package_id`.

**Guard obligation.** `package_id` required on MCP check; principal and issue nonce in the preimage; spend on first check; packaged identity compared before any candidate command runs; `run_check` re-checks when given `package=`.

## Lemma P2 — Query-time identity stability

An authenticated projection may say `ready` only if identity at the start of the query equals identity at the end, under the same verifier. If the closing capture fails, the answer is unable-to-check. Never reuse the opening capture.

**Sketch.** `ready` claims the projection applies to the current commit after the journal read. Substituting the opening identity when the closing read fails is a silent hop. The claim is **endpoint equality**, not continuous non-movement (ABA is out of claim without a generation counter).

**Guard obligation.** Closing `IdentityError` and authenticated store failure both terminate as unable-to-check with a nonempty reason; neither falls back to unsigned preview.

## Lemma P3 — Candidate identity (no review hop)

A review verdict authorizes only the exact `(base, head, tree, patch digest)` it named. A later byte change is a different candidate. Transferring accept or reject across candidates is an unbound hop.

The allow set of generations is a **named operator fence**, not a kernel machine. Exhaustion is Closed. Override **replaces** the finite budget (`--new-budget` > used) and records an admit id. Truncation is `Unable` and consumes the slot.

**Sketch.** Tuple-binding is Red F on review evidence. Budget is I7-shaped only after a tried-set exists; until then it is the fence. Do not cite I7 as a premise.

**Corollary P3′.** Truncation, quota exhaustion, and a missing report are not accept. They are Unable and spend the generation.

**Guard obligation.** `verify_review_candidate` requires `base_sha` and `patch_sha256`; fence override requires `--new-budget`; `unable` closes in-flight as Unable.

## Assumptions (fail toward admission if false)

A10, Ap1–Ap5 as in `INVARIANTS.md`. Plus: the agent cannot write the connection package store (Ap1 strengthened). Analogical citation is not inheritance.

## Not theorems

- The agent’s patch is good.
- The model that wrote the patch is the model named in a prompt.
- Global uniqueness of `package_id` across machines.
- Liveness of an agent session.
- Library bypass of the mediated CLI (Red A2 analogue).
- Loopback HTTP `POST /api/v1/check` (Ready UI; not a package permit).
- Unbounded MCP package issuance (Spent is not a budget).
- Reviewer honesty or completeness.
- Continuous non-movement of HEAD during inspect (ABA).
- Distributed consensus across builders.

## Plain sentences

P0. Presentation cannot mint admission.

P1. An agent's check is admissible only under a work package issued for this connection and not yet spent; the first check — passing or refused — spends it. Issuance is refillable.

P2. Ready only if opening identity equals closing identity.

P3. A verdict names one candidate. Override is a new allow set. Truncation spends the slot.

## Implementation status (v0.7.0 baseline, v0.8.0 separation)

The guard sites below were implemented in the **v0.7.0** product and are
unchanged by the **v0.8.0** runtime separation. The split moved code between
installable distributions — `admissible-ready` runs candidate commands and ships
no credential loader; `admissible-trust` holds the keys and ships no runner — so
P0's obligation is now harder to violate by accident. That is a packaging fact.
It is not a proof, and it promotes nothing: P0–P3 remain **unproved** process
lemmas, and only a separate formal admission — named guards, citation binding
and a mutation receipt — would change that status.

- **P0** — present as credential refuse on `run_check` plus forbidden MCP verbs. Not an R11 inspection test of every write.
- **P1** — MCP requires `package_id`; packages bind principal + issue nonce; first check spends; mismatch refuses before evaluation; `run_check(..., package=)` re-checks opening identity and the completed document's repository/commit/tree/class/policy.
- **P2** — present in `inspect` (endpoint equality).
- **P3** — named reviews bind only against independently supplied `(base, patch)` on `evaluate`; unpaired fields refuse at parse. Generation budget remains the operator fence.
