"""Filing a defect and recording a dependency: the two signed mutations.

Standing is a *query* and lives next door in :mod:`admissible_trust.standing`.
This module holds the two acts that change what that query will answer, and
they are separated for the reason every separation in this distribution
exists: a caller who only wants to ask whether an artefact is current should be
holding a module that cannot file an impeachment.

Filing a defect never touches a receipt. The receipt issued yesterday stays
authentic historical evidence of what was known then; what changes is the
answer to "is this artefact current now?". So there is no update path here and
no delete path -- only an append, anchored by a signed journal event, inside
the same compare-and-set transaction that writes the row it corresponds to.
"""
from __future__ import annotations

from admissible_core import evidence as evidence_module
from admissible_core.store_base import StoreError

from . import receipt as receipt_module

__all__ = ["file_defect", "record_dependency"]


class _AlreadyFiled(Exception):
    """This exact defect is already anchored; the caller's work is done."""


def file_defect(store, document: object, *, signer, now: int) -> dict:
    """Append one defect and anchor it; prior receipts are never touched.

    Filing the same defect twice is one filing. The check that makes it so runs
    *inside* the compare-and-set transaction, because outside it the check is a
    hint and two callers both pass it: the loser then appends a second signed
    event whose defect row is silently dropped, and the journal ends up with
    two events for one record -- which an authenticated import can only read as
    a forgery. Inside the transaction there is one winner and the other caller
    learns, truthfully, that the defect is already filed.
    """

    record = evidence_module.defect_from_dict(document)
    plain = evidence_module.defect_to_dict(record)
    digest = evidence_module.evidence_digest(record)
    journal_id = receipt_module.journal_id_for(record.repository)
    event = {
        "domain": receipt_module.RECEIPT_DOMAIN,
        "type": receipt_module.EVENT_DEFECT,
        "defect_digest": digest,
        "defect_id": record.defect_id,
        "repository": record.repository,
        "commit_sha": record.commit_sha,
        "severity": record.severity,
        "discovered_at": record.discovered_at,
        "filed_at": now,
    }

    def require_bijection() -> None:
        """Classify the row/event pair under the signing write lock.

        The proposed event is already visible in this transaction when the
        attachment builder runs.  Therefore ``(1, no row)`` is a first filing
        and ``(2, row)`` is an idempotent retry whose proposed second event is
        rolled back.  Either orphan shape is corruption, not success.
        """

        store.verify_journal(journal_id, signer)
        event_count = store.defect_event_count(journal_id, digest)
        has_row = store.has_defect(digest)
        if event_count == 1 and not has_row:
            return
        if event_count == 2 and has_row:
            raise _AlreadyFiled
        raise StoreError(
            "defect filing requires exactly one authentic signed event and "
            "one attachment; an orphan or duplicate was found")

    def attach(proposal):
        """The thunk that writes this defect's row inside the head commit.

        The monolith returned SQL here and the anchoring transaction executed
        it. What comes back now is a callable that reaches one named store
        method, because the store no longer offers a way to run a statement a
        caller chose.
        """

        return lambda: store.insert_defect(
            digest=digest, defect_id=record.defect_id,
            repository=record.repository, commit_sha=record.commit_sha,
            filed_at=now, record=plain)

    try:
        receipt_module.anchor(
            store, journal_id, event,
            signer=signer, now=now, attach=attach,
            precondition=require_bijection)
    except _AlreadyFiled:
        return plain
    return plain


def record_dependency(store, *, consumer: tuple[str, str],
                      dependency: tuple[str, str], now: int) -> bool:
    """Record that ``consumer`` depends on ``dependency``."""

    return store.put_dependency(
        consumer_repository=consumer[0], consumer_commit_sha=consumer[1],
        dependency_repository=dependency[0], dependency_commit_sha=dependency[1],
        recorded_at=now)
