"""Signed developer-workflow receipts anchored in a monotone journal.

A workflow receipt authenticates *one developer workflow admission*: this exact
repository, commit, tree, policy, class, decision, and evidence set, anchored at
one position of one monotone journal. It is deliberately a different domain and
schema from :class:`rga.AdmissibilityReceipt`: it makes no claim about the
composed identity/scrutiny/standing predicate, and it must never be presented as
one.

Authenticity here is HMAC-SHA256: a shared secret proves that a holder of the
key issued the receipt. That is *not* public non-repudiation, and the first
anchor of a journal remains a bootstrap trust assumption.

One thing changed at the split, and it is worth naming.  The monolith's
attachment path handed SQL to the store: ``attach`` returned ``(statement,
parameters)`` pairs and the anchoring transaction executed them through
``store.connection``.  That was an arbitrary-write channel into the one
transaction that matters, and a caller who could reach it could drop an
append-only trigger and write a receipt row by hand.  Here ``attach`` returns a
*thunk* instead: a callable that performs its writes through the store's own
named authority methods, and there is no connection for it to reach.  What is
written is decided by the store; when it is written is decided here.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Callable

from fcd import head as fcd_head
from fcd.journal import canonical_json

from admissible_core import evidence as evidence_module
from admissible_core import fsutil
from admissible_core.decision import (ADMITTED, CHECKS_PASSED, Decision,
                                      decision_digest, decision_to_dict)
from admissible_core.store_base import HeadConflict

__all__ = [
    "AnchorError",
    "Proposal",
    "RECEIPT_DOMAIN",
    "RECEIPT_SCHEMA",
    "RECEIPT_SCOPE",
    "ReceiptError",
    "SigningError",
    "WorkflowReceipt",
    "anchor",
    "anchor_event",
    "expected_receipt_body",
    "expected_receipt_body_digest",
    "issue_receipt",
    "issue_receipt_from_parts",
    "journal_id_for",
    "load_signer",
    "propose_next",
    "receipt_from_dict",
    "receipt_to_dict",
    "signer_from_secret",
    "verify_current",
    "verify_receipt",
]

RECEIPT_SCHEMA = "admissible/v0.6/workflow-receipt"
RECEIPT_DOMAIN = "admissible/v0.6/developer-workflow-admission"
RECEIPT_SCOPE = "developer-workflow-admission"
JOURNAL_PREFIX = "admissible/workflow"
EVENT_WORKFLOW_ADMISSION = "workflow-admission"
EVENT_DEFECT = "defect-filed"
_MAX_KEY_BYTES = 4096
_DEFAULT_KEY_ID = "local"
_RECEIPT_KEYS = (
    "schema", "scope", "journal_id", "repository", "commit_sha", "tree_sha",
    "policy_digest", "class_id", "state", "attempt_id", "decision_digest",
    "evidence_digests", "authenticated_reviews", "dependencies", "issued_at",
    "body_digest", "receipt_hash", "head",
)


class ReceiptError(ValueError):
    """A workflow receipt is not authentic, not current, or not well formed."""


class SigningError(ValueError):
    """No usable signing key was provided."""


class AnchorError(ValueError):
    """A journal event could not be anchored after repeated attempts."""


class _AlreadyIssued(Exception):
    """A writer that started first already stored this exact receipt body."""

    def __init__(self, receipt) -> None:
        super().__init__("this receipt body is already stored")
        self.receipt = receipt


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def journal_id_for(repository: str) -> str:
    """The monotone workflow journal that owns one repository's admissions."""

    if type(repository) is not str or not repository.strip():
        raise ValueError("repository namespace must be a non-empty string")
    return f"{JOURNAL_PREFIX}/{repository}"


def signer_from_secret(key_id: str, secret: bytes):
    """Build an HMAC signer; the secret never leaves this object."""

    if type(secret) is not bytes or not secret:
        raise SigningError("signing secret must be non-empty bytes")
    return fcd_head.HMACSHA256Signer(key_id, secret)


def _read_key_file(path_text: str) -> bytes:
    try:
        material = fsutil.read_secret_file(
            path_text, "ADMISSIBLE_HMAC_KEY_FILE",
            max_bytes=_MAX_KEY_BYTES).strip()
    except fsutil.SecretFileError as error:
        raise SigningError(str(error)) from None
    if not material:
        raise SigningError(f"ADMISSIBLE_HMAC_KEY_FILE {path_text} is empty")
    return material


def load_signer(environment: dict[str, str] | None = None):
    """Load the signer from the environment or a permission-checked file.

    Key material is accepted from ``ADMISSIBLE_HMAC_KEY`` or from the file named
    by ``ADMISSIBLE_HMAC_KEY_FILE`` only. It is never accepted from a command
    line argument, never written to the database, and never printed.
    """

    source = os.environ if environment is None else environment
    key_id = (source.get("ADMISSIBLE_HMAC_KEY_ID") or _DEFAULT_KEY_ID).strip()
    if not key_id:
        raise SigningError("ADMISSIBLE_HMAC_KEY_ID must not be empty")
    inline = source.get("ADMISSIBLE_HMAC_KEY")
    if inline is not None:
        material = inline.strip().encode("utf-8")
        if not material:
            raise SigningError(
                "ADMISSIBLE_HMAC_KEY is set but empty; unset it or provide a "
                "real key")
        return signer_from_secret(key_id, material)
    key_file = source.get("ADMISSIBLE_HMAC_KEY_FILE")
    if key_file:
        return signer_from_secret(key_id, _read_key_file(key_file))
    raise SigningError(
        "no signing key: set ADMISSIBLE_HMAC_KEY, or point "
        "ADMISSIBLE_HMAC_KEY_FILE at a file that only you can read. Evaluate "
        "without issuing a receipt with 'admissible-ready run --preview'.")


@dataclass(frozen=True)
class Proposal:
    """A candidate successor head that has not yet been durably accepted."""

    journal_id: str
    events: tuple[dict, ...]
    event: dict
    head_receipt: fcd_head.HeadReceipt


def propose_next(store, journal_id: str, event: dict, *, signer,
                 now: int) -> Proposal:
    """Build the signed successor head that appends ``event`` to the journal."""

    if signer is None:
        raise SigningError("a signer is required to anchor a journal event")
    current = store.current_head(journal_id)
    events = tuple(store.journal_events(journal_id)) + (event,)
    head = fcd_head.compute_journal_head(journal_id, list(events))
    issued_at = now if current is None else max(now, current.issued_at)
    previous_hash = "" if current is None else current.receipt_hash
    head_receipt = fcd_head.make_receipt(
        head, previous_hash, issued_at, signer, previous=current)
    return Proposal(journal_id=journal_id, events=events, event=event,
                    head_receipt=head_receipt)


def anchor(store, journal_id: str, event: dict, *, signer, now: int,
           attempts: int = 8,
           attach: Callable[[Proposal], Callable[[], None] | None] | None = None,
           preflight: Callable[[], None] | None = None,
           precondition: Callable[[], None] | None = None,
           busy_timeout_ms: int | None = None) -> Proposal:
    """Append ``event`` to the durable journal, retrying only on CAS conflict.

    ``preflight`` runs inside the compare-and-set transaction before the
    proposed event is materialized. ``precondition`` runs later, immediately
    before the attachment writes, so callers such as defect idempotency may
    inspect that proposed event. Both are rollback-protected. An idempotency
    check belongs inside this transaction: run before it, the loser can append
    a second event for a receipt row that is then silently dropped.

    ``attach`` is handed the proposal and returns the thunk that writes this
    event's attachments, or ``None`` when there are none. It returns a callable
    rather than SQL because the store no longer offers a way to run a statement
    a caller chose: the thunk reaches the store's named authority methods and
    nothing else.
    """

    if type(attempts) is not int or attempts < 1:
        raise AnchorError("attempts must be a positive integer")
    last: Exception | None = None
    for _ in range(attempts):
        proposal = propose_next(store, journal_id, event, signer=signer, now=now)
        writer = None if attach is None else attach(proposal)

        def builder(write=writer):
            if precondition is not None:
                precondition()
            if write is not None:
                write()

        try:
            store.accept_head(proposal.head_receipt, proposal.events, signer,
                              before_extend=preflight,
                              attachments_builder=builder,
                              busy_timeout_ms=busy_timeout_ms)
        except HeadConflict as error:
            last = error
            continue
        return proposal
    raise AnchorError(
        f"could not anchor an event in {journal_id!r} after {attempts} "
        f"attempts because other writers kept winning: {last}")


def anchor_event(store, journal_id: str, event: dict, *, signer, now: int,
                 attempts: int = 8,
                 busy_timeout_ms: int | None = None) -> fcd_head.HeadReceipt:
    """Anchor one event and return the accepted head receipt."""

    return anchor(store, journal_id, event, signer=signer, now=now,
                  attempts=attempts,
                  busy_timeout_ms=busy_timeout_ms).head_receipt


@dataclass(frozen=True)
class WorkflowReceipt:
    """An authenticated developer workflow admission — not an I/R/C receipt."""

    schema: str
    scope: str
    journal_id: str
    repository: str
    commit_sha: str
    tree_sha: str
    policy_digest: str
    class_id: str
    state: str
    attempt_id: str
    decision_digest: str
    evidence_digests: tuple[str, ...]
    # Which review record each authenticated reviewer key actually signed, as
    # (evidence digest, key id) pairs. Attribution has to come from here and
    # nowhere else: the ``reviewer_id`` inside a review record is a string the
    # submitter chose, so reporting it as "who approved this" would name
    # whoever the document says rather than whoever signed.
    authenticated_reviews: tuple[tuple[str, str], ...]
    dependencies: tuple[tuple[str, str], ...]
    issued_at: int
    body_digest: str
    receipt_hash: str
    head: fcd_head.HeadReceipt


def _body(*, journal_id: str, repository: str, commit_sha: str, tree_sha: str,
          policy_digest: str, class_id: str, state: str, attempt_id: str,
          decision_digest_value: str, evidence_digests: tuple[str, ...],
          authenticated_reviews: tuple[tuple[str, str], ...],
          dependencies: tuple[tuple[str, str], ...], issued_at: int) -> dict:
    return {
        "domain": RECEIPT_DOMAIN,
        "schema": RECEIPT_SCHEMA,
        "scope": RECEIPT_SCOPE,
        "journal_id": journal_id,
        "repository": repository,
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
        "policy_digest": policy_digest,
        "class_id": class_id,
        "state": state,
        "attempt_id": attempt_id,
        "decision_digest": decision_digest_value,
        "evidence_digests": list(evidence_digests),
        "authenticated_reviews": [
            {"evidence_digest": item[0], "key_id": item[1]}
            for item in sorted(authenticated_reviews)],
        "dependencies": [{"repository": item[0], "commit_sha": item[1]}
                         for item in dependencies],
        "issued_at": issued_at,
    }


def expected_receipt_body(*, repository: str, commit_sha: str, tree_sha: str,
                          class_id: str, policy_digest: str, state: str,
                          decision_digest_value: str,
                          evidence_digests: tuple[str, ...],
                          attempt_id: str = "",
                          authenticated_reviews: tuple = (),
                          dependencies: tuple = (),
                          issued_at: int) -> dict[str, Any]:
    """Derive the exact receipt body issuance would persist, without writing.

    Interrupt recovery and issuance must ask the same identity question. This
    helper is therefore the one public construction boundary for that body;
    callers hash its canonical result rather than approximating a receipt with
    a subset such as repository, commit and attempt.
    """

    if state != ADMITTED:
        raise ReceiptError(
            f"a workflow receipt only ever records an admission; refusing to "
            f"derive a body for state {state!r}")
    normalized_dependencies = tuple(
        (item[0], item[1]) for item in dependencies)
    normalized_reviews = tuple(sorted(
        (item[0], item[1]) for item in authenticated_reviews))
    return _body(
        journal_id=journal_id_for(repository), repository=repository,
        commit_sha=commit_sha, tree_sha=tree_sha,
        policy_digest=policy_digest, class_id=class_id, state=state,
        attempt_id=attempt_id, decision_digest_value=decision_digest_value,
        evidence_digests=tuple(evidence_digests),
        authenticated_reviews=normalized_reviews,
        dependencies=normalized_dependencies, issued_at=issued_at)


def expected_receipt_body_digest(
        *, repository: str, commit_sha: str, tree_sha: str, class_id: str,
        policy_digest: str, state: str, decision_digest_value: str,
        evidence_digests: tuple[str, ...], attempt_id: str = "",
        authenticated_reviews: tuple = (), dependencies: tuple = (),
        issued_at: int) -> str:
    """Canonical digest of :func:`expected_receipt_body`, without writing."""

    return _digest(expected_receipt_body(
        repository=repository, commit_sha=commit_sha, tree_sha=tree_sha,
        class_id=class_id, policy_digest=policy_digest, state=state,
        attempt_id=attempt_id,
        decision_digest_value=decision_digest_value,
        evidence_digests=evidence_digests,
        authenticated_reviews=authenticated_reviews,
        dependencies=dependencies, issued_at=issued_at))


def _body_of(receipt: WorkflowReceipt) -> dict:
    return _body(journal_id=receipt.journal_id, repository=receipt.repository,
                 commit_sha=receipt.commit_sha, tree_sha=receipt.tree_sha,
                 policy_digest=receipt.policy_digest,
                 class_id=receipt.class_id, state=receipt.state,
                 attempt_id=receipt.attempt_id,
                 decision_digest_value=receipt.decision_digest,
                 evidence_digests=receipt.evidence_digests,
                 authenticated_reviews=receipt.authenticated_reviews,
                 dependencies=receipt.dependencies,
                 issued_at=receipt.issued_at)


def _event_for(body: dict, body_digest: str) -> dict:
    return {
        "domain": RECEIPT_DOMAIN,
        "type": EVENT_WORKFLOW_ADMISSION,
        "body_digest": body_digest,
        "repository": body["repository"],
        "commit_sha": body["commit_sha"],
        "tree_sha": body["tree_sha"],
        "policy_digest": body["policy_digest"],
        "class_id": body["class_id"],
        "state": body["state"],
        "attempt_id": body["attempt_id"],
        "issued_at": body["issued_at"],
    }


def _receipt_hash(body_digest: str, head_receipt_hash: str) -> str:
    return _digest({"domain": RECEIPT_DOMAIN, "body_digest": body_digest,
                    "head_receipt_hash": head_receipt_hash})


def receipt_to_dict(receipt: WorkflowReceipt) -> dict[str, Any]:
    if type(receipt) is not WorkflowReceipt:
        raise ReceiptError("receipt must be a WorkflowReceipt")
    return {
        "schema": receipt.schema,
        "scope": receipt.scope,
        "journal_id": receipt.journal_id,
        "repository": receipt.repository,
        "commit_sha": receipt.commit_sha,
        "tree_sha": receipt.tree_sha,
        "policy_digest": receipt.policy_digest,
        "class_id": receipt.class_id,
        "state": receipt.state,
        "attempt_id": receipt.attempt_id,
        "decision_digest": receipt.decision_digest,
        "evidence_digests": list(receipt.evidence_digests),
        "authenticated_reviews": [
            {"evidence_digest": item[0], "key_id": item[1]}
            for item in receipt.authenticated_reviews],
        "dependencies": [{"repository": item[0], "commit_sha": item[1]}
                         for item in receipt.dependencies],
        "issued_at": receipt.issued_at,
        "body_digest": receipt.body_digest,
        "receipt_hash": receipt.receipt_hash,
        "head": fcd_head.head_receipt_to_dict(receipt.head),
    }


def receipt_from_dict(document: object) -> WorkflowReceipt:
    if type(document) is not dict or set(document) != set(_RECEIPT_KEYS):
        raise ReceiptError("workflow receipt must be a closed JSON object")
    dependencies = document["dependencies"]
    if type(dependencies) is not list:
        raise ReceiptError("workflow receipt dependencies must be a list")
    parsed_dependencies = []
    for item in dependencies:
        if type(item) is not dict or set(item) != {"repository", "commit_sha"}:
            raise ReceiptError("workflow receipt dependency is not closed")
        parsed_dependencies.append((item["repository"], item["commit_sha"]))
    digests = document["evidence_digests"]
    if type(digests) is not list or any(type(item) is not str for item in digests):
        raise ReceiptError("workflow receipt evidence digests must be strings")
    attributed = document["authenticated_reviews"]
    if type(attributed) is not list:
        raise ReceiptError(
            "workflow receipt authenticated_reviews must be a list")
    parsed_reviews = []
    for item in attributed:
        if type(item) is not dict or set(item) != {"evidence_digest", "key_id"}:
            raise ReceiptError(
                "workflow receipt authenticated review is not closed")
        parsed_reviews.append((item["evidence_digest"], item["key_id"]))
    try:
        head = fcd_head.head_receipt_from_dict(document["head"])
    except (TypeError, ValueError) as error:
        raise ReceiptError(f"workflow receipt head is invalid: {error}") from None
    return WorkflowReceipt(
        schema=document["schema"],
        scope=document["scope"],
        journal_id=document["journal_id"],
        repository=document["repository"],
        commit_sha=document["commit_sha"],
        tree_sha=document["tree_sha"],
        policy_digest=document["policy_digest"],
        class_id=document["class_id"],
        state=document["state"],
        attempt_id=document["attempt_id"],
        decision_digest=document["decision_digest"],
        evidence_digests=tuple(digests),
        authenticated_reviews=tuple(parsed_reviews),
        dependencies=tuple(parsed_dependencies),
        issued_at=document["issued_at"],
        body_digest=document["body_digest"],
        receipt_hash=document["receipt_hash"],
        head=head,
    )


def verify_receipt(receipt: WorkflowReceipt, verifier) -> bool:
    """Verify body integrity, journal binding, and head authenticity."""

    if type(receipt) is not WorkflowReceipt:
        raise ReceiptError("receipt must be a WorkflowReceipt")
    if receipt.schema != RECEIPT_SCHEMA or receipt.scope != RECEIPT_SCOPE:
        raise ReceiptError("receipt is not a developer workflow admission")
    body = _body_of(receipt)
    body_digest = _digest(body)
    if body_digest != receipt.body_digest:
        raise ReceiptError(
            "receipt body does not match its own digest: it was modified after "
            "issuance")
    try:
        fcd_head.verify_receipt(receipt.head, verifier)
    except fcd_head.HeadVerificationError:
        raise ReceiptError(
            "receipt head signature is not authentic under this key") from None
    event_digest = _digest(_event_for(body, body_digest))
    if event_digest not in receipt.head.extension_digests:
        raise ReceiptError(
            "receipt body is not the event covered by its signed head")
    if _receipt_hash(body_digest, receipt.head.receipt_hash) != receipt.receipt_hash:
        raise ReceiptError("receipt hash does not bind this body and head")
    return True


def verify_current(store, receipt: WorkflowReceipt, verifier) -> bool:
    """Verify the receipt *and* that its head is still the current head."""

    verify_receipt(receipt, verifier)
    current = store.current_head(receipt.journal_id)
    if current is None or current.receipt_hash != receipt.head.receipt_hash:
        raise ReceiptError(
            "this receipt is authentic but its journal head is no longer "
            "current; later events exist for this repository")
    return True


def issue_receipt(store, *, repository: str, commit_sha: str, tree_sha: str,
                  class_id: str, policy_digest: str, result: Decision,
                  commands: tuple = (), reviews: tuple = (),
                  authorships: tuple = (),
                  authenticated_reviews: tuple = (),
                  dependencies: tuple = (), signer=None,
                  now: int) -> WorkflowReceipt:
    """Persist evidence and anchor one authenticated workflow admission.

    Only an ADMITTED decision may be issued, and the decision must be *about*
    the artefact the caller names. A receipt that could be minted from a
    refusal, or from a decision about some other tree, would make standing
    meaningless.
    """

    if type(result) is not Decision:
        raise ReceiptError("issue_receipt needs a Decision")
    if result.state != CHECKS_PASSED:
        raise ReceiptError(
            f"only a decision whose required checks all passed can be issued "
            f"as a receipt; this one is {result.state}. Nothing was anchored.")
    if not result.attempt_id.strip():
        raise ReceiptError(
            "the decision names no attempt. A receipt records one observation "
            "of one artefact at one moment, and a decision that belongs to no "
            "attempt cannot be that. Nothing was anchored.")
    mismatched = [
        name for name, expected, actual in (
            ("repository", repository, result.repository),
            ("commit_sha", commit_sha, result.commit_sha),
            ("tree_sha", tree_sha, result.tree_sha),
            ("policy_digest", policy_digest, result.policy_digest),
            ("class_id", class_id, result.class_id),
        ) if expected != actual]
    if mismatched:
        raise ReceiptError(
            "the receipt would name a different artefact than the decision it "
            f"quotes ({', '.join(mismatched)} differ); nothing was anchored")
    return issue_receipt_from_parts(
        store, repository=repository, commit_sha=commit_sha,
        tree_sha=tree_sha, class_id=class_id, policy_digest=policy_digest,
        state=ADMITTED, attempt_id=result.attempt_id,
        decision_digest_value=decision_digest(result),
        evidence_digests=tuple(result.evidence_digests), commands=commands,
        reviews=reviews, authorships=authorships,
        authenticated_reviews=authenticated_reviews,
        dependencies=dependencies, signer=signer, now=now)


def _prove_evidence_set(evidence_digests, commands, reviews,
                        authorships=()) -> None:
    """The records handed over are exactly the records the decision used.

    A receipt binds a set of evidence digests and the store keeps the records
    those digests name. If the caller may pass fewer records than the decision
    counted, a receipt can be minted whose claimed evidence is simply absent --
    authentic, ``CURRENT``, and unable to survive an authenticated import. If
    it may pass more, the store gains records no decision ever weighed.

    So neither direction is allowed, and duplicates are refused too: a record
    supplied twice is a record the digest set cannot account for.
    """

    try:
        claimed_items = tuple(evidence_digests)
    except TypeError:
        raise ReceiptError(
            "receipt evidence_digests must be an iterable of exact digests; "
            "nothing was anchored") from None
    if any(type(digest) is not str or len(digest) != 64
           or any(character not in "0123456789abcdef"
                  for character in digest)
           for digest in claimed_items):
        raise ReceiptError(
            "receipt evidence_digests must be lowercase 64-character hex "
            "strings; nothing was anchored")
    if len(claimed_items) != len(set(claimed_items)):
        raise ReceiptError(
            "a workflow receipt cannot bind the same evidence digest more "
            "than once; nothing was anchored")

    supplied: list[str] = []
    for record in tuple(commands) + tuple(reviews) + tuple(authorships):
        try:
            supplied.append(evidence_module.evidence_digest(record))
        except evidence_module.EvidenceError as error:
            raise ReceiptError(
                f"receipt evidence is not a closed record: {error}. Nothing "
                "was anchored.") from None
    duplicates = sorted({digest for digest in supplied
                         if supplied.count(digest) > 1})
    if duplicates:
        raise ReceiptError(
            f"the same evidence record was supplied more than once "
            f"({duplicates[0]}); nothing was anchored")
    claimed = set(claimed_items)
    present = set(supplied)
    missing = sorted(claimed - present)
    extra = sorted(present - claimed)
    if missing:
        raise ReceiptError(
            f"this receipt would bind {len(claimed)} evidence digest(s) but "
            f"{len(missing)} of the record(s) they name were not supplied "
            f"(first: {missing[0]}). A receipt whose evidence is not stored "
            "cannot survive an authenticated import; nothing was anchored.")
    if extra:
        raise ReceiptError(
            f"{len(extra)} evidence record(s) were supplied that this "
            f"decision did not weigh (first: {extra[0]}); nothing was "
            "anchored")


def _evidence_attachments(*, repository: str, commit_sha: str, tree_sha: str,
                          policy_digest: str, commands, reviews, authorships
                          ) -> dict[str, dict[str, Any]]:
    """Closed, exact evidence rows this receipt is entitled to attach."""

    prepared: dict[str, dict[str, Any]] = {}
    for record in tuple(commands) + tuple(reviews) + tuple(authorships):
        try:
            document = evidence_module.evidence_to_dict(record)
            digest = evidence_module.evidence_digest(record)
        except evidence_module.EvidenceError as error:
            raise ReceiptError(
                f"receipt evidence is not a closed record: {error}. Nothing "
                "was anchored.") from None
        if (document.get("repository") != repository
                or document.get("commit_sha") != commit_sha
                or document.get("tree_sha") != tree_sha
                or document.get("policy_digest") != policy_digest):
            raise ReceiptError(
                f"receipt-bound evidence {digest} does not describe this "
                "exact repository, commit, tree and policy; nothing was "
                "anchored")
        if digest in prepared:
            # _prove_evidence_set reports this first in ordinary calls. Keep
            # the construction boundary independently closed as well.
            raise ReceiptError(
                f"evidence digest {digest} resolves to more than one supplied "
                "record; nothing was anchored")
        prepared[digest] = {
            "digest": digest,
            "kind": document["kind"],
            "repository": document["repository"],
            "commit_sha": document["commit_sha"],
            "tree_sha": document["tree_sha"],
            "policy_digest": document["policy_digest"],
            "record_json": canonical_json(document),
            "record": record,
        }
    return prepared


def _normalized_authenticated_reviews(value, evidence_rows
                                      ) -> tuple[tuple[str, str], ...]:
    """Prove every attribution names one supplied approving review."""

    try:
        items = tuple(value)
    except TypeError:
        raise ReceiptError(
            "authenticated_reviews must be an iterable of digest/key pairs; "
            "nothing was anchored") from None
    normalized: list[tuple[str, str]] = []
    for item in items:
        if type(item) not in (tuple, list) or len(item) != 2:
            raise ReceiptError(
                "each authenticated review must be exactly one digest/key-id "
                "pair; nothing was anchored")
        digest, key_id = item
        if (type(digest) is not str or len(digest) != 64
                or any(character not in "0123456789abcdef"
                       for character in digest)):
            raise ReceiptError(
                "an authenticated review digest must be a lowercase "
                "64-character hex string; nothing was anchored")
        if type(key_id) is not str or not key_id.strip():
            raise ReceiptError(
                "an authenticated reviewer key id must be non-empty text; "
                "nothing was anchored")
        row = evidence_rows.get(digest)
        if row is None:
            raise ReceiptError(
                f"authenticated reviewer {key_id!r} names evidence {digest} "
                "that is not supplied and bound by this receipt; nothing was "
                "anchored")
        record = row["record"]
        if (type(record) is not evidence_module.ReviewEvidence
                or record.verdict != "approve"):
            raise ReceiptError(
                f"authenticated reviewer {key_id!r} does not resolve to one "
                "supplied, receipt-bound approving review; nothing was "
                "anchored")
        normalized.append((digest, key_id))
    if len(normalized) != len(set(normalized)):
        raise ReceiptError(
            "a workflow receipt cannot repeat one authenticated review "
            "attribution; nothing was anchored")
    return tuple(sorted(normalized))


def _normalized_dependencies(value) -> tuple[tuple[str, str], ...]:
    try:
        items = tuple(value)
    except TypeError:
        raise ReceiptError(
            "receipt dependencies must be an iterable of repository/SHA "
            "pairs; nothing was anchored") from None
    normalized: list[tuple[str, str]] = []
    for item in items:
        if type(item) not in (tuple, list) or len(item) != 2:
            raise ReceiptError(
                "each receipt dependency must be exactly one repository/SHA "
                "pair; nothing was anchored")
        dependency_repository, dependency_sha = item
        if (type(dependency_repository) is not str
                or not dependency_repository.strip()):
            raise ReceiptError(
                "a dependency repository must be non-empty text; nothing was "
                "anchored")
        if (type(dependency_sha) is not str or len(dependency_sha) != 40
                or any(character not in "0123456789abcdef"
                       for character in dependency_sha)):
            raise ReceiptError(
                "a dependency commit must be a full lowercase 40-character "
                "hex SHA; nothing was anchored")
        normalized.append((dependency_repository, dependency_sha))
    if len(normalized) != len(set(normalized)):
        raise ReceiptError(
            "a workflow receipt cannot bind the same dependency edge more "
            "than once; nothing was anchored")
    return tuple(normalized)


def issue_receipt_from_parts(store, *, repository: str, commit_sha: str,
                             tree_sha: str, class_id: str, policy_digest: str,
                             state: str, decision_digest_value: str,
                             evidence_digests: tuple[str, ...],
                             attempt_id: str = "",
                             commands: tuple = (), reviews: tuple = (),
                             authorships: tuple = (),
                             authenticated_reviews: tuple = (),
                             dependencies: tuple = (), signer=None,
                             _require_current_policy: bool = False,
                             now: int) -> WorkflowReceipt:
    """Anchor an admission from already-validated parts (used by finalize)."""

    if signer is None:
        raise SigningError(
            "issuing a receipt needs a signing key; set ADMISSIBLE_HMAC_KEY")
    if state != ADMITTED:
        raise ReceiptError(
            f"a workflow receipt only ever records an admission; refusing to "
            f"anchor state {state!r}")
    if type(_require_current_policy) is not bool:
        raise ReceiptError(
            "the current-policy issuance guard must be exactly true or false; "
            "nothing was anchored")
    try:
        commands = tuple(commands)
        reviews = tuple(reviews)
        authorships = tuple(authorships)
        evidence_digests = tuple(evidence_digests)
    except TypeError:
        raise ReceiptError(
            "receipt evidence inputs must be finite iterables; nothing was "
            "anchored") from None
    _prove_evidence_set(evidence_digests, commands, reviews, authorships)
    evidence_rows = _evidence_attachments(
        repository=repository, commit_sha=commit_sha, tree_sha=tree_sha,
        policy_digest=policy_digest, commands=commands, reviews=reviews,
        authorships=authorships)
    normalized_dependencies = _normalized_dependencies(dependencies)
    normalized_reviews = _normalized_authenticated_reviews(
        authenticated_reviews, evidence_rows)
    body = expected_receipt_body(
        repository=repository, commit_sha=commit_sha, tree_sha=tree_sha,
        class_id=class_id, policy_digest=policy_digest, state=state,
        attempt_id=attempt_id,
        decision_digest_value=decision_digest_value,
        evidence_digests=tuple(evidence_digests),
        authenticated_reviews=normalized_reviews,
        dependencies=normalized_dependencies, issued_at=now)
    journal_id = body["journal_id"]
    body_digest = _digest(body)

    _EVIDENCE_COLUMNS = ("kind", "repository", "commit_sha", "tree_sha",
                         "policy_digest", "record_json")

    def authenticated_expected(stored: WorkflowReceipt,
                               *, where: str) -> WorkflowReceipt:
        """Authenticate and compare every body field before trusting a hit."""

        try:
            verify_receipt(stored, signer)
        except ReceiptError as error:
            raise ReceiptError(
                f"{where} receipt for expected body {body_digest} is not "
                f"authentic: {error}. Nothing was anchored.") from None
        actual = _body_of(stored)
        if stored.body_digest != body_digest or actual != body:
            raise ReceiptError(
                f"{where} receipt conflicts with the complete expected body "
                f"{body_digest}; a cached row is not an idempotent retry merely "
                "because a lookup returned it. Nothing was anchored.")
        return stored

    # This is a fail-fast hint only, never an idempotency return. The same row
    # is read and authenticated again under the write transaction below, where
    # another writer cannot race the decision.
    hinted = store.workflow_receipt_by_body(body_digest)
    if hinted is not None:
        authenticated_expected(hinted, where="cached")

    event = _event_for(body, body_digest)
    built: dict[str, WorkflowReceipt] = {}

    def attachment_history() -> tuple[
            dict[str, list[WorkflowReceipt]],
            dict[tuple[str, str], int]]:
        """Authenticate prior binders needed to interpret shared rows."""

        bound_evidence: dict[str, list[WorkflowReceipt]] = {}
        dependency_times: dict[tuple[str, str], int] = {}
        try:
            prior_receipts = store.receipts_for(repository, commit_sha)
        except (ReceiptError, TypeError, ValueError) as error:
            raise ReceiptError(
                f"stored receipt attachment history is not readable: {error}. "
                "Nothing was anchored.") from None
        for prior in prior_receipts:
            try:
                verify_receipt(prior, signer)
            except ReceiptError as error:
                raise ReceiptError(
                    "stored receipt attachment history is not authentic: "
                    f"{error}. Nothing was anchored.") from None
            if (prior.repository != repository
                    or prior.commit_sha != commit_sha):
                raise ReceiptError(
                    "a stored receipt row conflicts with the artifact whose "
                    "attachments it would authorize; nothing was anchored")
            if (len(prior.evidence_digests)
                    != len(set(prior.evidence_digests))
                    or len(prior.dependencies) != len(set(prior.dependencies))
                    or len(prior.authenticated_reviews)
                    != len(set(prior.authenticated_reviews))):
                raise ReceiptError(
                    "stored receipt attachment history contains duplicate "
                    "signed body entries; nothing was anchored")
            for digest in prior.evidence_digests:
                bound_evidence.setdefault(digest, []).append(prior)
            for edge in prior.dependencies:
                previous = dependency_times.get(edge)
                dependency_times[edge] = (prior.issued_at if previous is None
                                          else min(previous, prior.issued_at))
        return bound_evidence, dependency_times

    def validate_prior_evidence(
            binders: dict[str, list[WorkflowReceipt]]) -> None:
        """Require every older receipt's evidence to remain exact."""

        parsed: dict[str, object] = {}
        for digest, receipts in binders.items():
            row = store.receipt_evidence_row(digest)
            if row is None:
                raise ReceiptError(
                    f"receipt-bound evidence attachment {digest} is missing "
                    "from existing signed history; nothing was anchored")
            try:
                document = json.loads(row["record_json"])
                if row["kind"] == "command":
                    record = evidence_module.command_evidence_from_dict(
                        document)
                elif row["kind"] == "review":
                    record = evidence_module.review_evidence_from_dict(
                        document)
                elif row["kind"] == "authorship":
                    record = evidence_module.authorship_evidence_from_dict(
                        document)
                else:
                    raise evidence_module.EvidenceError(
                        "receipt-bound evidence has an unknown kind")
            except (TypeError, ValueError,
                    evidence_module.EvidenceError) as error:
                raise ReceiptError(
                    f"receipt-bound evidence attachment {digest} is invalid: "
                    f"{error}. Nothing was anchored.") from None
            actual = tuple(row[key] for key in _EVIDENCE_COLUMNS)
            wanted = (document["kind"], record.repository,
                      record.commit_sha, record.tree_sha,
                      record.policy_digest, canonical_json(document))
            if (actual != wanted
                    or evidence_module.evidence_digest(record) != digest
                    or any(record.repository != binder.repository
                           or record.commit_sha != binder.commit_sha
                           or record.tree_sha != binder.tree_sha
                           or record.policy_digest != binder.policy_digest
                           for binder in receipts)):
                raise ReceiptError(
                    f"receipt-bound evidence attachment {digest} conflicts "
                    "with its signed receipt history; nothing was anchored")
            parsed[digest] = record
        for receipts in binders.values():
            for prior in receipts:
                for digest, key_id in prior.authenticated_reviews:
                    record = parsed.get(digest)
                    if (digest not in prior.evidence_digests
                            or type(record) is not evidence_module.ReviewEvidence
                            or record.verdict != "approve"):
                        raise ReceiptError(
                            f"stored reviewer attribution {key_id!r} lacks "
                            "receipt-bound approving evidence; nothing was "
                            "anchored")

    def ensure_attachment_correspondence(*, require_present: bool) -> None:
        """Compare or insert every attachment under the head transaction."""

        prior_evidence, prior_dependencies = attachment_history()
        # Validating only this call's records would let a missing or corrupted
        # attachment from an older authentic receipt survive a second
        # ADMITTED return.  Check the whole prior evidence namespace inside the
        # same receipt transaction, before any new attachment can commit.
        validate_prior_evidence(prior_evidence)
        expected_dependency_rows = dict(prior_dependencies)
        for digest, expected in evidence_rows.items():
            stored = store.receipt_evidence_row(digest)
            if stored is None:
                if require_present or digest in prior_evidence:
                    raise ReceiptError(
                        f"receipt-bound evidence attachment {digest} is "
                        "missing from existing signed history; nothing was "
                        "anchored")
                store.insert_receipt_evidence(
                    digest=digest, kind=expected["kind"],
                    repository=expected["repository"],
                    commit_sha=expected["commit_sha"],
                    tree_sha=expected["tree_sha"],
                    policy_digest=expected["policy_digest"],
                    record_json=expected["record_json"])
                stored = store.receipt_evidence_row(digest)
            actual = None if stored is None else tuple(
                stored[key] for key in _EVIDENCE_COLUMNS)
            wanted = tuple(expected[key] for key in _EVIDENCE_COLUMNS)
            if actual != wanted:
                raise ReceiptError(
                    f"pre-existing evidence attachment {digest} conflicts "
                    "with the complete receipt-bound record; nothing was "
                    "anchored")

        for dependency_repository, dependency_sha in normalized_dependencies:
            edge = (dependency_repository, dependency_sha)
            prior_time = prior_dependencies.get(edge)
            expected_time = (now if prior_time is None
                             else min(now, prior_time))
            expected_dependency_rows[edge] = expected_time
            locator = {
                "consumer_repository": repository,
                "consumer_commit_sha": commit_sha,
                "dependency_repository": dependency_repository,
                "dependency_commit_sha": dependency_sha,
            }
            stored = store.dependency_recorded_at(**locator)
            if stored is None:
                if require_present or prior_time is not None:
                    raise ReceiptError(
                        "a receipt-bound dependency attachment is missing "
                        "from existing signed history; nothing was anchored")
                store.insert_dependency_edge(recorded_at=expected_time,
                                             **locator)
                stored = store.dependency_recorded_at(**locator)
            elif (prior_time is not None and stored == prior_time
                  and expected_time < prior_time):
                # Dependency rows are a derived projection, not an authority
                # separate from their authentic receipt bodies.  When an
                # older signed cut arrives after a newer one, canonical time
                # is the minimum issued_at regardless of arrival order.  The
                # schema permits only this monotone lowering and never an edge
                # identity change.
                store.lower_dependency_recorded_at(
                    recorded_at=expected_time,
                    previous_recorded_at=prior_time, **locator)
                stored = store.dependency_recorded_at(**locator)
            if stored is None or stored != expected_time:
                raise ReceiptError(
                    "a pre-existing dependency attachment conflicts with the "
                    "complete receipt-bound edge and recording time; nothing "
                    "was anchored")

        # Compare the whole consumer namespace, not only the edges this call
        # expects.  Otherwise an unrelated unsigned row can survive beside an
        # authentic receipt: issuance reports ADMITTED, while authenticated
        # standing immediately rejects the extra edge and reports UNKNOWN.
        # No receipt may be returned from a state its own verifier refuses.
        actual_dependency_rows = {
            (edge[2], edge[3]): recorded_at
            for edge, recorded_at in store.consumer_dependency_rows(
                repository, commit_sha).items()}
        if actual_dependency_rows != expected_dependency_rows:
            raise ReceiptError(
                "stored dependency attachments are not exactly the edges "
                "bound by authentic receipts for this artifact; an unsigned "
                "extra edge cannot accompany an admission. Nothing was "
                "anchored")

    def authenticated_repository_preflight() -> None:
        """Refuse issuance from a repository standing would call UNKNOWN.

        Standing authenticates one complete repository journal, not only the
        commit being finalized.  This check runs under the same BEGIN
        IMMEDIATE as issuance but before the proposed admission event exists,
        so a damaged attachment on commit A cannot accompany an ADMITTED
        return for commit B and cached retries cannot bypass the check.
        """

        try:
            current = store.current_head(journal_id)
            if current is None:
                if store.has_repository_authority(journal_id, repository):
                    raise ReceiptError(
                        "repository attachment history exists without one "
                        "authentic current journal head; nothing was anchored")
                # A dependency row is derivable rather than independently
                # authoritative.  Before the first head, allow only an exact
                # row that this very receipt is about to bind; the public API
                # historically supports compare-or-insert of that row.  An
                # edge for another commit, another dependency, or another
                # timestamp remains an unsigned repository attachment and is
                # refused.
                expected = {
                    (repository, commit_sha, dependency_repository,
                     dependency_sha): now
                    for dependency_repository, dependency_sha
                    in normalized_dependencies}
                stored_rows = store.consumer_dependency_rows(repository)
                for edge, recorded_at in stored_rows.items():
                    if expected.get(edge) != recorded_at:
                        raise ReceiptError(
                            "repository dependency history exists without an "
                            "authentic receipt or an exact edge this first "
                            "receipt will bind; nothing was anchored")
                return
            store.authenticated_repository_projection(repository, signer)
        except ReceiptError:
            raise
        except Exception as error:
            raise ReceiptError(
                "existing repository receipt history is not one exact "
                f"authenticated namespace: {error}. Nothing was anchored."
            ) from None

    def already_issued() -> None:
        """Authenticate receipt and attachments inside one transaction."""

        stored = store.workflow_receipt_by_body(body_digest)
        if stored is not None:
            authenticated = authenticated_expected(
                stored, where="transaction-cached")
            ensure_attachment_correspondence(require_present=True)
            raise _AlreadyIssued(authenticated)
        if hinted is not None:
            raise ReceiptError(
                "a cached receipt disappeared before the transactional "
                "idempotency check. Append-only admission state cannot do "
                "that, so the store is conflicting and nothing was anchored.")
        if _require_current_policy:
            try:
                trusted = store.trusted_policies(repository, class_id)
            except (TypeError, ValueError) as error:
                raise ReceiptError(
                    f"the trusted policy baseline is not readable inside "
                    f"receipt issuance: {error}. Nothing was anchored."
                ) from None
            if not any(item["policy_digest"] == policy_digest
                       for item in trusted):
                raise ReceiptError(
                    f"policy {policy_digest} for class {class_id!r} is no "
                    "longer current and unrevoked inside the receipt write "
                    "transaction. Policy authority changed after validation; "
                    "nothing was anchored.")
        ensure_attachment_correspondence(require_present=False)

    def receipt_transaction_preflight() -> None:
        # Both checks must precede the store's exact-head idempotency return.
        # Two writers can precompute the same proposal; after the winner
        # commits, repository attachments or policy authority can change before
        # the loser acquires the lock. Returning merely because the signed head
        # now matches would skip cached receipt authentication and could report
        # ADMITTED from a namespace standing calls UNKNOWN.
        authenticated_repository_preflight()
        already_issued()

    def attach(proposal: Proposal):
        receipt = WorkflowReceipt(
            schema=RECEIPT_SCHEMA, scope=RECEIPT_SCOPE, journal_id=journal_id,
            repository=repository, commit_sha=commit_sha, tree_sha=tree_sha,
            policy_digest=policy_digest, class_id=class_id, state=state,
            attempt_id=attempt_id,
            decision_digest=body["decision_digest"],
            evidence_digests=tuple(evidence_digests),
            authenticated_reviews=normalized_reviews,
            dependencies=normalized_dependencies, issued_at=now,
            body_digest=body_digest,
            receipt_hash=_receipt_hash(
                body_digest, proposal.head_receipt.receipt_hash),
            head=proposal.head_receipt)
        built["receipt"] = receipt
        return lambda: store.insert_workflow_receipt(receipt)

    try:
        anchor(store, journal_id, event, signer=signer, now=now, attach=attach,
               preflight=receipt_transaction_preflight)
    except _AlreadyIssued as duplicate:
        return authenticated_expected(duplicate.receipt,
                                      where="transaction-cached")
    issued = built["receipt"]
    stored = store.workflow_receipt(issued.receipt_hash)
    if stored is None:
        raise ReceiptError(
            "the receipt was not stored by its own commit; nothing is claimed")
    return authenticated_expected(stored, where="newly stored")


def decision_document(result: Decision) -> dict:
    """The plain decision document a receipt commits to by digest."""

    return decision_to_dict(result)
