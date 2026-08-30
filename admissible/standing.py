"""Current standing: impeachment, dependents, and missed-check accounting.

Standing is a *query*, never a rewrite. A defect filed today does not touch the
receipt that was issued yesterday: that receipt stays authentic historical
evidence of what was known then. What changes is the answer to "is this artefact
current now?".

Impact is reported in three explicitly separated registers:

* **observed** — defects that were actually filed;
* **reachable** — consumers reachable through recorded dependency edges;
* **unknown** — everything outside both, which this tool cannot bound.

Counts are raw counts. This module never converts them into a rate, a
probability, or a confidence claim.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from fcd.journal import canonical_json

from . import evidence as evidence_module
from . import receipt as receipt_module
from . import store as store_module
from .decision import ADMITTED

__all__ = [
    "CURRENT",
    "Dependent",
    "IMPEACHED",
    "MissedCheck",
    "Report",
    "Standing",
    "UNKNOWN",
    "current_standing",
    "dependents",
    "file_defect",
    "impact_report",
    "record_dependency",
    "render_plain",
    "report_to_dict",
    "standing_to_dict",
]

CURRENT = "CURRENT"
IMPEACHED = "IMPEACHED"
UNKNOWN = "UNKNOWN"

_EXIT_CODES = {CURRENT: 0, IMPEACHED: 1, UNKNOWN: 1}
_MAX_DEPENDENT_NODES = 10_000


@dataclass(frozen=True)
class Standing:
    """The current answer for one artefact."""

    state: str
    repository: str
    commit_sha: str
    receipts: tuple
    defects: tuple
    unknown_scope: bool
    # Rows that say ADMITTED and whose signature this home could not
    # authenticate. They are reported and never counted: a database row is a
    # claim about a signature, and standing is the one question where "a row
    # exists" and "a keyholder signed it" must not be the same answer.
    unauthenticated: tuple = ()
    # Authentic historical receipts that cannot confer authority while the
    # surrounding journal/attachment projection is incoherent.
    historical_receipts: tuple = ()
    integrity_problem: str = ""

    @property
    def exit_code(self) -> int:
        return _EXIT_CODES[self.state]


@dataclass(frozen=True)
class Dependent:
    repository: str
    commit_sha: str
    direct: bool
    distance: int


@dataclass(frozen=True)
class MissedCheck:
    check_id: str
    approved_artifacts: int
    missed_defects: int


@dataclass(frozen=True)
class MissedReviewer:
    """An authenticated reviewer key that approved an artefact that failed.

    Keyed by ``key_id`` and never by ``reviewer_id``. The reviewer id inside a
    review record is a string whoever produced the record chose; the key id is
    what a reviewer keyring actually authenticated at the moment the receipt
    was issued, and it is carried in the signed receipt body for exactly this
    reason. Attribution is a claim about a person, so it is only ever made from
    the identity that signed.
    """

    key_id: str
    approved_artifacts: int
    missed_defects: int


@dataclass(frozen=True)
class Report:
    repository: str
    commit_sha: str
    state: str
    defects: tuple
    receipts: tuple
    dependents: tuple[Dependent, ...]
    missed_checks: tuple[MissedCheck, ...]
    missed_reviewers: tuple[MissedReviewer, ...]
    reachable_dependent_impact: bool
    unknown_scope: bool
    remediation: tuple[str, ...]
    unauthenticated: tuple = ()
    historical_receipts: tuple = ()
    integrity_problem: str = ""


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def current_standing(store, repository: str, commit_sha: str, *,
                     verifier=None) -> Standing:
    """Answer "is this exact artefact current?" from durable records only.

    ``verifier`` is mandatory for authority.  Without it the answer is UNKNOWN;
    a SQL row that says ADMITTED is only an unauthenticated claim.  With it,
    heads, events, receipts, evidence, defects, and dependencies are validated
    together in one consistent store transaction before any CURRENT or
    IMPEACHED answer is possible.
    """

    if verifier is None:
        return Standing(
            state=UNKNOWN, repository=repository, commit_sha=commit_sha,
            receipts=(), defects=(), unknown_scope=True,
            unauthenticated=(), historical_receipts=(),
            integrity_problem="a verifier is required for standing")
    try:
        projections, invalid = store.authenticated_workflow_state(verifier)
    except store_module.StoreError as error:
        detail = str(error) or "authenticated journal could not be read"
        return Standing(
            state=UNKNOWN, repository=repository, commit_sha=commit_sha,
            receipts=(), defects=(), unknown_scope=True,
            unauthenticated=(), historical_receipts=(),
            integrity_problem=detail)
    return _current_from_state(
        projections, invalid, repository, commit_sha)


def _current_from_state(projections: dict, invalid: frozenset,
                        repository: str, commit_sha: str) -> Standing:
    if repository in invalid:
        projection = projections.get(repository, {})
        historical = tuple(
            item for item in projection.get("historical_claims", ())
            if item.commit_sha == commit_sha and item.state == ADMITTED)
        unauthenticated = tuple(
            item for item in projection.get("unauthenticated_claims", ())
            if item.commit_sha == commit_sha and item.state == ADMITTED)
        return Standing(
            state=UNKNOWN, repository=repository, commit_sha=commit_sha,
            receipts=(), defects=(), unknown_scope=True,
            unauthenticated=unauthenticated,
            historical_receipts=historical,
            integrity_problem=projection.get("integrity_error", ""))
    projection = projections.get(repository, {})
    receipts = tuple(
        item for item in projection.get("receipts", ())
        if item.commit_sha == commit_sha and item.state == ADMITTED)
    defects = tuple(
        item for item in projection.get("defects", ())
        if item["commit_sha"] == commit_sha)
    if defects:
        state = IMPEACHED
    elif receipts:
        state = CURRENT
    else:
        state = UNKNOWN
    return Standing(state=state, repository=repository, commit_sha=commit_sha,
                    receipts=receipts, defects=defects,
                    unknown_scope=not receipts,
                    unauthenticated=(), historical_receipts=(),
                    integrity_problem="")


def standing_to_dict(found: Standing) -> dict[str, Any]:
    return {
        "scope": receipt_module.RECEIPT_SCOPE,
        "state": found.state,
        "exit_code": found.exit_code,
        "repository": found.repository,
        "commit_sha": found.commit_sha,
        "receipts": len(found.receipts),
        "defects": len(found.defects),
        "unknown_scope": found.unknown_scope,
        "unauthenticated_receipts": [item.receipt_hash
                                     for item in found.unauthenticated],
        "historical_receipts": [item.receipt_hash
                                for item in found.historical_receipts],
        "integrity_problem": found.integrity_problem,
    }


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
        raise store_module.StoreError(
            "defect filing requires exactly one authentic signed event and "
            "one attachment; an orphan or duplicate was found")

    def attach(proposal):
        return [store.defect_row(
            digest=digest, defect_id=record.defect_id,
            repository=record.repository, commit_sha=record.commit_sha,
            filed_at=now, record=plain)]

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


def _dependents_from_state(projections: dict, repository: str,
                           commit_sha: str) -> tuple[Dependent, ...]:
    edges: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for projection in projections.values():
        for (consumer_repository, consumer_sha,
             dependency_repository, dependency_sha) in projection.get(
                 "dependencies", ()):
            edges.setdefault(
                (dependency_repository, dependency_sha), []).append(
                    (consumer_repository, consumer_sha))

    seen: set[tuple[str, str]] = set()
    found: list[Dependent] = []
    frontier = [(repository, commit_sha)]
    distance = 0
    while frontier and len(seen) < _MAX_DEPENDENT_NODES:
        distance += 1
        following: list[tuple[str, str]] = []
        for node in frontier:
            for consumer in sorted(edges.get(node, ())):
                if consumer in seen:
                    continue
                seen.add(consumer)
                found.append(Dependent(repository=consumer[0],
                                       commit_sha=consumer[1],
                                       direct=distance == 1,
                                       distance=distance))
                following.append(consumer)
        frontier = following
    return tuple(found)


def dependents(store, repository: str, commit_sha: str, *,
               verifier=None) -> tuple[Dependent, ...]:
    """Authenticated receipt-bound consumers, folded cycle-safely."""

    if verifier is None:
        return ()
    try:
        projections, _invalid = store.authenticated_workflow_state(verifier)
    except store_module.StoreError:
        return ()
    return _dependents_from_state(projections, repository, commit_sha)


def _missed(projections: dict, repository: str, defective_sha: str
            ) -> tuple[tuple[MissedCheck, ...], tuple[MissedReviewer, ...]]:
    """What approved this artefact, attributed only to what a receipt binds.

    Scanning every evidence record for the commit was the wrong scope twice
    over. It counted records no receipt ever bound -- an advisory review file
    dropped next to the real ones would appear as an approval -- and it named
    reviewers by the ``reviewer_id`` string in the document rather than by the
    key that signed. Both start from the admitted receipt instead: its
    ``evidence_digests`` say which records carried the admission, and its
    ``authenticated_reviews`` say which key each counted review was signed by.
    """

    projection = projections.get(repository, {})
    admitted = [item for item in projection.get("receipts", ())
                if item.state == ADMITTED]
    defective = frozenset(
        item["commit_sha"] for item in projection.get("defects", ()))
    evidence = projection.get("evidence", {})
    approvals_by_key: dict[str, set[str]] = {}
    approvals_by_check: dict[str, set[str]] = {}
    for item in admitted:
        for digest in item.evidence_digests:
            row = evidence.get(digest)
            if row is None or row["kind"] != "command":
                continue
            record = row["record"]
            if record.passed:
                approvals_by_check.setdefault(
                    record.check_id, set()).add(item.commit_sha)
        # Store projection construction already proved that every attribution
        # names a receipt-bound, stored approving review record.
        for digest, key_id in item.authenticated_reviews:
            row = evidence.get(digest)
            if (row is not None and row["kind"] == "review"
                    and row["record"].verdict == "approve"):
                approvals_by_key.setdefault(key_id, set()).add(item.commit_sha)
    checks = tuple(sorted(
        (MissedCheck(check_id=check_id,
                     approved_artifacts=len(shas),
                     missed_defects=len(shas & defective))
         for check_id, shas in approvals_by_check.items()
         if defective_sha in shas),
        key=lambda item: item.check_id))
    reviewers = tuple(sorted(
        (MissedReviewer(key_id=key_id,
                        approved_artifacts=len(shas),
                        missed_defects=len(shas & defective))
         for key_id, shas in approvals_by_key.items()
         if defective_sha in shas),
        key=lambda item: item.key_id))
    return checks, reviewers


def impact_report(store, repository: str, commit_sha: str, *,
                  verifier=None) -> Report:
    """Everything known about one defective artefact and what it reached."""

    if verifier is None:
        projections, invalid = {}, frozenset({repository})
    else:
        try:
            projections, invalid = store.authenticated_workflow_state(verifier)
        except store_module.StoreError:
            projections, invalid = {}, frozenset({repository})
    found = _current_from_state(
        projections, invalid, repository, commit_sha)
    reachable = _dependents_from_state(
        projections, repository, commit_sha)
    checks, reviewers = _missed(projections, repository, commit_sha)
    remediation: list[str] = []
    regression_ids = sorted({
        defect["regression_test_id"] for defect in found.defects
        if defect["regression_test_id"]})
    if found.state == IMPEACHED:
        remediation.append(
            f"fix {commit_sha} in a new commit and admit that commit; the old "
            "receipt stays authentic history and is never edited")
        for check_id in regression_ids:
            remediation.append(
                f"add a failing-first regression case to check {check_id!r} so "
                "this defect cannot pass the gate again")
        if not regression_ids:
            remediation.append(
                "name the check that must carry a new regression case, then "
                "re-file with --test CHECK_ID")
        for item in checks:
            remediation.append(
                f"check {item.check_id!r} passed this artefact and did not "
                f"catch the defect ({item.missed_defects} of "
                f"{item.approved_artifacts} artefacts it approved later showed "
                "a defect); decide whether to strengthen it")
        for item in reachable:
            remediation.append(
                f"re-evaluate dependent {item.repository}@{item.commit_sha}; "
                "standing is direct, so a dependent is not impeached "
                "automatically")
        remediation.append(
            "treat anything no check or reviewer examined as unknown, not safe")
    elif found.state == UNKNOWN:
        if found.integrity_problem and found.historical_receipts:
            remediation.append(
                f"{len(found.historical_receipts)} authentic historical "
                f"receipt(s) for {commit_sha} still exist, but exact durable "
                "correspondence failed, so they confer no CURRENT standing: "
                f"{found.integrity_problem}")
            remediation.append(
                "if this exact evaluation attempt is finalizable, finalize "
                "it; otherwise export the authenticated signed journal "
                "prefix and import it into a clean durable home "
                "(attempt-only, unbound evidence deliberately does not "
                "travel). Never repair this by deleting or editing store "
                "rows")
        if found.unauthenticated:
            remediation.append(
                f"{len(found.unauthenticated)} row(s) for {commit_sha} say "
                "ADMITTED and do not verify under this home's key: they are "
                "reported and counted for nothing. Either this is not the key "
                "that issued them, or the database has been edited")
            remediation.append(
                "export ADMISSIBLE_HMAC_KEY for the domain that issued these "
                "receipts, then ask again")
        if not found.historical_receipts:
            remediation.append(
                f"no authenticated receipt exists for {commit_sha}; evaluate "
                "it with 'admissible run --preview --preview-out preview.json "
                f"--sha {commit_sha}' in a clean checkout of that commit, "
                "have an external observer attest it, then run 'admissible "
                "finalize'")
    else:
        remediation.append(
            "nothing: this artefact is current and no defect has been filed "
            "against it")
    return Report(
        repository=repository, commit_sha=commit_sha, state=found.state,
        defects=found.defects, receipts=found.receipts, dependents=reachable,
        missed_checks=checks, missed_reviewers=reviewers,
        reachable_dependent_impact=bool(reachable),
        unknown_scope=found.unknown_scope,
        remediation=tuple(remediation),
        unauthenticated=found.unauthenticated,
        historical_receipts=found.historical_receipts,
        integrity_problem=found.integrity_problem)


def report_to_dict(report: Report) -> dict[str, Any]:
    return {
        "scope": receipt_module.RECEIPT_SCOPE,
        "state": report.state,
        "repository": report.repository,
        "commit_sha": report.commit_sha,
        "observed_defects": [dict(defect) for defect in report.defects],
        "receipts": [item.receipt_hash for item in report.receipts],
        "unauthenticated_receipts": [item.receipt_hash
                                     for item in report.unauthenticated],
        "historical_receipts": [item.receipt_hash
                                for item in report.historical_receipts],
        "integrity_problem": report.integrity_problem,
        "reachable_dependents": [
            {"repository": item.repository, "commit_sha": item.commit_sha,
             "direct": item.direct, "distance": item.distance}
            for item in report.dependents],
        "reachable_dependent_impact": report.reachable_dependent_impact,
        "unknown_scope": report.unknown_scope,
        "missed_checks": [
            {"check_id": item.check_id,
             "approved_artifacts": item.approved_artifacts,
             "missed_defects": item.missed_defects}
            for item in report.missed_checks],
        "missed_reviewers": [
            {"key_id": item.key_id,
             "approved_artifacts": item.approved_artifacts,
             "missed_defects": item.missed_defects}
            for item in report.missed_reviewers],
        "remediation": list(report.remediation),
    }


def render_plain(report: Report) -> str:
    """Plain impact output: observed, reachable, unknown, and next steps."""

    lines = [
        f"What happened: standing for {report.commit_sha} in "
        f"{report.repository} is {report.state}.",
        "",
        "What is known:",
        f"  observed defects ({len(report.defects)}):",
    ]
    if report.defects:
        for defect in report.defects:
            lines.append(
                f"    - {defect['defect_id']} [{defect['severity']}] "
                f"{defect['summary']}")
    else:
        lines.append("    - none filed")
    if report.unauthenticated:
        lines.append(
            f"  rows saying ADMITTED that this key cannot authenticate "
            f"({len(report.unauthenticated)}):")
        for item in report.unauthenticated:
            lines.append(f"    - {item.receipt_hash} (counted for nothing)")
    if report.historical_receipts:
        lines.append(
            "  authentic historical receipts blocked by an integrity "
            f"mismatch ({len(report.historical_receipts)}):")
        for item in report.historical_receipts:
            lines.append(f"    - {item.receipt_hash} (history, not CURRENT)")
        if report.integrity_problem:
            lines.append(f"    - integrity problem: {report.integrity_problem}")
    lines.append(f"  checks that approved this artefact and missed the defect "
                 f"({len(report.missed_checks)}):")
    if report.missed_checks:
        for item in report.missed_checks:
            lines.append(
                f"    - {item.check_id}: approved {item.approved_artifacts} "
                f"artefact(s), {item.missed_defects} later showed a defect")
    else:
        lines.append("    - none recorded")
    if report.missed_reviewers:
        lines.append(
            "  reviewer keys whose authenticated approval carried this "
            "artefact:")
        for item in report.missed_reviewers:
            lines.append(
                f"    - key {item.key_id}: approved "
                f"{item.approved_artifacts} artefact(s), "
                f"{item.missed_defects} later showed a defect")
    lines.append(f"  reachable dependents through recorded edges "
                 f"({len(report.dependents)}):")
    if report.dependents:
        for item in report.dependents:
            kind = "direct" if item.direct else f"distance {item.distance}"
            lines.append(f"    - {item.repository}@{item.commit_sha} ({kind})")
    else:
        lines.append("    - none recorded")
    lines.append(
        "  unknown: consumers with no recorded dependency edge, and any "
        "behaviour no check or reviewer examined. This tool cannot bound that "
        "set.")
    if report.unknown_scope:
        lines.append(
            "  unknown: no admission receipt exists for this exact commit, so "
            "the approving evidence is unknown here.")
    lines.append("")
    lines.append("What to do next:")
    for line in report.remediation:
        lines.append(f"  - {line}")
    return "\n".join(lines) + "\n"
