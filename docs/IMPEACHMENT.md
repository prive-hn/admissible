# Impeachment: when reality disagrees with an approval

An admitted artefact is not a correct artefact. It is one that passed the checks
you declared. When a defect shows up later, Admissible records that fact without
pretending the past was different.

## Nothing is rewritten

Filing a defect **never** edits the receipt that was issued earlier. That
receipt stays authentic historical evidence of what was known at the time.
What changes is the answer to a *query*: "is this artefact current now?"

```bash
admissible verify "$SHA"     # exit 0, CURRENT
admissible impeach "$SHA" --evidence defect.json --test unit
admissible verify "$SHA"     # exit 1, IMPEACHED — same receipt, still authentic
```

`admissible verify --json` reports `state: IMPEACHED` together with
`signature_valid: true`. Both facts are true at once, and both matter.

## Filing a defect

A defect record is a closed document (`protocol/defect-record.schema.json`):

```json
{
  "kind": "defect",
  "defect_id": "PAY-1043",
  "repository": "github.com/acme/widget",
  "commit_sha": "…40 hex…",
  "severity": "high",
  "summary": "refunds rounded towards the house on split payments",
  "missed_check_ids": ["payment-tests"],
  "regression_test_id": "payment-tests",
  "discovered_at": 1756000000
}
```

Defects are append-only and idempotent by content digest: filing the same defect
twice records it once. Each filing is anchored in the repository's monotone
workflow journal, so the ledger of "what we later learned" is as tamper-evident
as the ledger of "what we admitted".

You may file a defect against a commit that has no receipt. Standing becomes
`IMPEACHED` with `unknown_scope: true` — the defect is real, but the approving
evidence is unknown here.

## Three registers: observed, reachable, unknown

`admissible explain "$SHA"` separates what it can prove from what it cannot:

* **observed** — defects actually filed against this artefact;
* **reachable** — consumers reachable through dependency edges you recorded
  (`admissible run --preview --depends-on REPOSITORY@SHA`). The fold is cycle-safe;
* **unknown** — consumers with no recorded edge, and any behaviour no check or
  reviewer examined. Admissible cannot bound this set and says so.

Standing itself stays **direct**, exactly as the kernel's semantics require: a
dependent is *reported* as reachable, not silently impeached. Deciding whether a
dependent is affected is a human judgement, and the report tells you which ones
to look at.

## Missed checks: raw counts, from the receipt only

The report names the checks and the reviewer *keys* that approved the defective
artefact, with two integers each:

* `approved_artifacts` — how many artefacts in this repository that check or key
  approved;
* `missed_defects` — how many of those later had a defect filed.

Both are read from the admitted receipt and from nowhere else. A check counts
only when its evidence digest is one the receipt binds, so an evidence record
dropped beside the real ones — through `--evidence`, or left over from another
attempt — is not an approval. A reviewer counts only through the receipt's
`authenticated_reviews`, which records which key the finalizer's keyring
actually authenticated for each counted review.

That is why the report says `key <id>` and not a person's name. The
`reviewer_id` inside a review record is a string whoever produced the record
chose; the key id is what a keyring verified. Naming somebody as having approved
a change that later broke is a claim about a person, so it is only ever made
from the identity that signed.

These are raw counts. Admissible deliberately does **not** turn them into a
rate, a probability, or a confidence score: the denominator is "artefacts we
happened to gate", the numerator is "defects someone happened to file", and
neither is a sample of anything. Use the counts to decide where to strengthen a
check, not to score a reviewer.

## Carrying standing to another machine

`admissible export` / `admissible import` move the whole authenticated story —
receipts, the evidence they bind, the dependency edges they declare, *and* the
defects that impeached them — between stores.

Defects are checked in **both** directions, and the second direction is the one
that matters most:

* a defect that no signed event anchors cannot be smuggled *in*, so nobody can
  hand you a file that quietly impeaches a competitor's artefact;
* a defect the journal *did* sign cannot be left *out*. An export whose
  `defects` array omits an anchored defect is rejected outright. Without that
  rule, deleting one array from an otherwise authentic bundle would erase an
  impeachment and restore `CURRENT` — and deletion is always the direction that
  raises standing.

Dependency edges are rebuilt from the verified receipts that declare them, so
reachability survives a move. Before this was enforced, a three-deep chain of
consumers became invisible the moment a journal changed machines: the receipts
still said who depended on what, and nothing read them back.

Evidence is checked in both directions too. An evidence array with no signed
correspondence is unverifiable on the far side, so it is neither exported nor
accepted — and a receipt whose evidence did *not* travel is refused as well,
because an artefact cannot be current on the strength of records that are not
there. The same holds for admissions: a signed `workflow-admission` event
without its receipt, or a receipt without its event, is a refusal.

Two structural rules make those bijections mean something:

* **Only what a signed head covers is imported.** Events trailing past the last
  head's `event_count` carry no signature at all, so a bundle with any is
  refused rather than truncated. A forged defect appended after the last head
  would otherwise arrive looking anchored.
* **The bundle lands in one transaction.** Heads committed one at a time could
  be interrupted with the earlier ones durable and their attachments missing —
  which is indistinguishable from an export that omitted them, and would leave
  an anchored defect invisible while the artefact read `CURRENT`.

Re-importing the same head is a full heal-and-verify pass rather than a no-op:
every head and event is authenticated again, every bijection is re-checked, any
row a partial earlier import left out is restored, and an incomplete bundle is
refused.

A journal that carries nothing but defects is a supported shape and exports
completely: repositories are discovered from the signed events, not only from
the workflow receipts a defect-only journal does not have.

## What to do next

The report always ends with concrete steps: fix the defect in a new commit and
admit that commit; add a failing-first regression case to the named check so the
same defect cannot pass the gate again; re-evaluate each reachable dependent;
and treat everything outside the observed and reachable sets as unknown rather
than safe.
