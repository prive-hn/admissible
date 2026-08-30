"""The deterministic decision: admitted, refused, or blocked — and why.

A decision is a pure function of the artefact identity, the policy, and the
bound evidence. It says what happened, what remains known, and exactly what to
do next. It describes a *developer workflow admission* only; it never claims the
composed identity/scrutiny/standing predicate of the research kernel.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from fcd.journal import canonical_json

from .config import ArtifactClass
from .evidence import (AttestedAuthorship, CommandEvidence, ReviewEvidence,
                       EvidenceError, UnverifiedAuthorship, UnverifiedReview,
                       VerifiedReview, evidence_digest, verify_review_candidate)

__all__ = [
    "ADMITTED",
    "BLOCKED",
    "CHECKS_PASSED",
    "DECISION_SCOPE",
    "Decision",
    "MAX_CLOCK_SKEW_SECONDS",
    "READINESS",
    "READINESS_AWAITING_REVIEW",
    "READINESS_NOT_READY",
    "READINESS_READY_FOR_ATTESTATION",
    "REFUSED",
    "Reason",
    "decision_digest",
    "digest_of_document",
    "decision_to_dict",
    "evaluate",
    "plan_budget",
    "preview_readiness",
    "render_plain",
]

# What a *decision* can be. ``ADMITTED`` is deliberately not among them: a
# decision is arithmetic over evidence, and admission is an act performed by a
# keyholder against durable storage. An unsigned evaluation that reaches the
# end of its policy has passed its checks and nothing more, so that is what it
# says, and only :mod:`admissible.receipt` ever writes ``ADMITTED``.
CHECKS_PASSED = "CHECKS_PASSED"
REFUSED = "REFUSED"
BLOCKED = "BLOCKED"
# The state a signed durable workflow receipt records. It is here because the
# receipt layer and the standing layer both need the word, and nowhere in this
# module produces it.
ADMITTED = "ADMITTED"
DECISION_SCOPE = "developer-workflow-admission"
_DECISION_DOMAIN = "admissible/v0.6/workflow-decision"

_EXIT_CODES = {CHECKS_PASSED: 0, REFUSED: 1, BLOCKED: 2}

# Evidence dated slightly ahead of this clock is ordinary skew between two
# machines. Evidence dated far ahead is a claim about a future that has not
# happened, and staleness rules cannot bound it, so it is refused.
MAX_CLOCK_SKEW_SECONDS = 300

# Preview readiness: what an *evaluation* has established, as distinct from what
# has been admitted. Evaluation and admission are different jobs in different
# trust domains, and conflating them is how a gate ends up calling something
# ADMITTED that no keyholder ever signed.
#
#   READY_FOR_ATTESTATION  every required check passed and nothing is
#                    outstanding that this evaluation could ever resolve. It is
#                    ready for an external observer to attest and a finalizer to
#                    admit. It is *not* an admission and never says ADMITTED.
#   AWAITING_REVIEW  every deterministic required check passed and the evidence
#                    is valid, and the only outstanding blocker is independent
#                    review or an authorship claim, which this job holds no
#                    keyring to authenticate. Not an admission either, and a
#                    hosted gate reporting it is red.
#   NOT_READY        anything else: a failed, timed-out or missing check, a
#                    ceiling, a rejection, a review this policy can never count.
READINESS_READY_FOR_ATTESTATION = "READY_FOR_ATTESTATION"
READINESS_AWAITING_REVIEW = "AWAITING_REVIEW"
READINESS_NOT_READY = "NOT_READY"
READINESS = (READINESS_READY_FOR_ATTESTATION, READINESS_AWAITING_REVIEW,
             READINESS_NOT_READY)

# The only refusal codes a trusted finalizer holding the reviewer keyring could
# still resolve. Every other code describes something the finalizer would hit
# again, so a preview carrying one is not waiting for anybody.
_REVIEW_PENDING_CODES = frozenset({
    "missing_independent_review",
    "unauthenticated_review",
    "missing_author_attestation",
    "unauthenticated_authorship",
})


@dataclass(frozen=True)
class Reason:
    """One machine-stable refusal or block code with its plain detail."""

    code: str
    subject: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "subject": self.subject,
                "detail": self.detail}


@dataclass(frozen=True)
class CheckOutcome:
    check_id: str
    required: bool
    status: str
    exit_code: int | None
    duration_ms: int
    provenance: str = "recorded"
    attempt_id: str = ""
    reused_from_attempt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"check_id": self.check_id, "required": self.required,
                "status": self.status, "exit_code": self.exit_code,
                "duration_ms": self.duration_ms,
                "provenance": self.provenance,
                "attempt_id": self.attempt_id,
                "reused_from_attempt": self.reused_from_attempt}


@dataclass(frozen=True)
class Decision:
    """The complete, stable answer for one artefact under one policy."""

    state: str
    repository: str
    commit_sha: str
    tree_sha: str
    policy_digest: str
    class_id: str
    reasons: tuple[Reason, ...]
    remediation: tuple[str, ...]
    checks: tuple[CheckOutcome, ...]
    independent_reviews: int
    required_independent_reviews: int
    cost_units: int
    max_cost_units: int
    wall_seconds: int
    max_wall_seconds: int
    evidence_digests: tuple[str, ...]
    evaluated_at: int
    attempt_id: str = ""
    # Distinct reviewer keys that *claim* an approving signature nothing here
    # could authenticate. Never added to ``independent_reviews``: it is what is
    # outstanding, not what has been established.
    pending_reviews: int = 0

    @property
    def exit_code(self) -> int:
        return _EXIT_CODES[self.state]

    @property
    def readiness(self) -> str:
        return preview_readiness(self)


def _status_of(record: CommandEvidence) -> str:
    if record.timed_out:
        return "timeout"
    if record.launch_failed:
        return "launch_failed"
    if record.exit_code != 0:
        return "failed"
    return "passed"


_SEVERITY_ORDER = {"timeout": 0, "launch_failed": 1, "failed": 2, "passed": 3}


def _severity(record: CommandEvidence) -> tuple[int, int]:
    """Order records worst-first; ties break on the earliest observation."""

    return (_SEVERITY_ORDER[_status_of(record)], record.started_at)


def _bound(record, repository: str, commit_sha: str, tree_sha: str,
           policy_digest: str, *, expected_base_sha: str = "",
           expected_patch_sha256: str = "") -> tuple[bool, str]:
    if record.repository != repository:
        return False, "cross_repository_evidence"
    if record.commit_sha != commit_sha:
        return False, "stale_evidence_sha"
    if record.tree_sha != tree_sha:
        return False, "stale_evidence_tree"
    if record.policy_digest != policy_digest:
        return False, "policy_mismatch"
    if type(record) is ReviewEvidence and (
            expected_base_sha or expected_patch_sha256
            or record.base_sha or record.patch_sha256):
        if not expected_base_sha or not expected_patch_sha256:
            return False, "review_candidate_mismatch"
        try:
            verify_review_candidate(
                record, base_sha=expected_base_sha, commit_sha=commit_sha,
                tree_sha=tree_sha, patch_sha256=expected_patch_sha256)
        except EvidenceError:
            return False, "review_candidate_mismatch"
    return True, ""


def _in_attempt(record, attempt_id: str) -> bool:
    """Does this record belong to the attempt the decision is about?

    An attempt is one observation of one artefact at one moment. Two attempts
    never jointly satisfy one decision: a record kept from an earlier attempt
    has to be *derived* into this one first (see
    :func:`admissible.evidence.reuse_in_attempt`), which leaves the reuse
    visible in the record instead of hiding it.

    A review carries no attempt when it is signed -- a reviewer approves an
    artefact, not a run -- so an empty attempt on a review is not a mismatch.
    A command always carries one.
    """

    return not record.attempt_id or record.attempt_id == attempt_id


_UNBOUND_DETAIL = {
    "cross_repository_evidence":
        "evidence describes a different repository and cannot be reused here",
    "stale_evidence_sha":
        "evidence describes a different commit than the one being admitted",
    "stale_evidence_tree":
        "evidence describes a different tree than the one being admitted",
    "policy_mismatch":
        "evidence was produced under a different policy digest",
    "review_candidate_mismatch":
        "review evidence names a different candidate than this artefact",
}

def plan_budget(artifact_class: ArtifactClass) -> tuple[int, int, tuple[Reason, ...],
                                                        tuple[str, ...]]:
    """What this class would cost *before* anything is spawned.

    Ceilings are a promise about spend, so they are evaluated against the plan
    and not against the bill. A class that cannot fit inside its own ceilings
    is blocked without running a single command.
    """

    cost_units = artifact_class.planned_cost_units
    wall_seconds = artifact_class.planned_wall_seconds
    reasons: list[Reason] = []
    remediation: list[str] = []
    if cost_units > artifact_class.max_cost_units:
        reasons.append(Reason(
            "cost_ceiling", artifact_class.id,
            f"this class plans {cost_units} cost units but its ceiling is "
            f"{artifact_class.max_cost_units}"))
        remediation.append(
            "raise max_cost_units deliberately, or remove/cheapen checks in "
            f"class {artifact_class.id!r}")
    if wall_seconds > artifact_class.max_wall_seconds:
        reasons.append(Reason(
            "time_ceiling", artifact_class.id,
            f"this class needs up to {wall_seconds}s but its ceiling is "
            f"{artifact_class.max_wall_seconds}s"))
        remediation.append(
            "raise max_wall_seconds deliberately, or shorten the checks in "
            f"class {artifact_class.id!r}")
    return cost_units, wall_seconds, tuple(reasons), tuple(remediation)


def _split_reviews(reviews):
    """Separate what a reviewer key authenticated from what merely claims to be."""

    advisory: list[ReviewEvidence] = []
    verified: list[VerifiedReview] = []
    unverified: list[UnverifiedReview] = []
    for item in reviews:
        if type(item) is VerifiedReview:
            verified.append(item)
        elif type(item) is UnverifiedReview:
            unverified.append(item)
        elif type(item) is ReviewEvidence:
            advisory.append(item)
        else:
            raise TypeError(
                "reviews must be ReviewEvidence, VerifiedReview or "
                "UnverifiedReview records")
    return tuple(advisory), tuple(verified), tuple(unverified)


def _split_authorships(authorships):
    """Separate an authenticated authorship claim from one nobody checked."""

    attested: list[AttestedAuthorship] = []
    unverified: list[UnverifiedAuthorship] = []
    for item in authorships:
        if type(item) is AttestedAuthorship:
            attested.append(item)
        elif type(item) is UnverifiedAuthorship:
            unverified.append(item)
        else:
            raise TypeError(
                "authorships must be AttestedAuthorship or "
                "UnverifiedAuthorship records")
    return tuple(attested), tuple(unverified)


def evaluate(*, artifact_class: ArtifactClass, repository: str,
             commit_sha: str, tree_sha: str, policy_digest: str,
             commands: tuple[CommandEvidence, ...],
             reviews: tuple, now: int, attempt_id: str,
             authorships: tuple = (),
             provenance: dict[str, str] | None = None,
             not_run: frozenset[str] | tuple[str, ...] = (),
             base_sha: str = "", patch_sha256: str = "") -> Decision:
    """Decide admissibility for one artefact from bound evidence only.

    Every record must describe *this* repository, commit, tree and policy, and
    every command must carry the digest of the argv this policy configures. A
    review only counts towards a required independent review when an external
    reviewer keyring authenticated the key that signed it.

    ``attempt_id`` is required and must be non-empty. A decision is about one
    observation of one artefact at one moment; a decision that belongs to no
    attempt while its evidence belongs to one is a claim nobody made. Every
    command record must name exactly this attempt, or be a record deliberately
    derived into it by :func:`admissible.evidence.reuse_in_attempt`, which
    leaves the reuse visible. A review names this attempt or no attempt at all
    -- a reviewer approves an artefact, not a run -- and a review naming some
    *other* attempt is refused like any other mismatch.
    """

    if type(attempt_id) is not str or not attempt_id.strip():
        raise ValueError(
            "evaluate needs a non-empty attempt_id: a decision is one "
            "observation of one artefact at one moment, and a decision that "
            "belongs to no attempt cannot be that")
    reasons: list[Reason] = []
    remediation: list[str] = []
    provenance = dict(provenance or {})
    not_run = frozenset(not_run)
    advisory_reviews, verified_reviews, unverified_reviews = _split_reviews(
        reviews)
    attested_authorships, claimed_authorships = _split_authorships(authorships)

    bound_commands: list[CommandEvidence] = []
    for record in commands:
        ok, code = _bound(record, repository, commit_sha, tree_sha, policy_digest)
        if not ok:
            reasons.append(Reason(
                code, record.check_id,
                f"check {record.check_id!r}: {_UNBOUND_DETAIL[code]}"))
            remediation.append(
                f"re-run check {record.check_id!r} against {commit_sha} under "
                "this policy; evidence is never reused across repository, "
                "commit, tree or policy boundaries")
            continue
        if not _in_attempt(record, attempt_id) or not record.attempt_id:
            reasons.append(Reason(
                "attempt_mismatch", record.check_id,
                f"evidence for check {record.check_id!r} belongs to attempt "
                f"{record.attempt_id or 'nothing'!r}, and this decision is "
                f"about attempt {attempt_id!r}; two attempts are two "
                "observations and never satisfy one decision together"))
            remediation.append(
                f"re-run check {record.check_id!r} in this attempt, or reuse "
                "the earlier observation deliberately so the record says it "
                "was reused and names the attempt it came from")
            continue
        bound_commands.append(record)
    def bind_review(record, subject: str) -> bool:
        ok, code = _bound(
            record, repository, commit_sha, tree_sha, policy_digest,
            expected_base_sha=base_sha, expected_patch_sha256=patch_sha256)
        if not ok:
            reasons.append(Reason(
                code, subject, f"review {subject!r}: {_UNBOUND_DETAIL[code]}"))
            remediation.append(
                f"obtain review {subject!r} for {commit_sha} under this policy")
            return False
        if not _in_attempt(record, attempt_id):
            reasons.append(Reason(
                "attempt_mismatch", subject,
                f"review {subject!r} names attempt {record.attempt_id!r}, and "
                f"this decision is about attempt {attempt_id!r}"))
            remediation.append(
                f"obtain review {subject!r} for this attempt, or have it name "
                "no attempt at all: a reviewer approves an artefact, not a run")
            return False
        return True

    bound_advisory = tuple(record for record in advisory_reviews
                           if bind_review(record, record.review_id))
    bound_verified = tuple(item for item in verified_reviews
                           if bind_review(item.record, item.record.review_id))
    bound_unverified = tuple(item for item in unverified_reviews
                             if bind_review(item.record, item.record.review_id))

    outcomes: list[CheckOutcome] = []
    observed_ms = 0
    for check in artifact_class.checks:
        candidates = [record for record in bound_commands
                      if record.check_id == check.id
                      and record.check_version == check.version]
        matches = []
        for record in candidates:
            if record.argv_digest != check.argv_digest:
                reasons.append(Reason(
                    "argv_mismatch", check.id,
                    f"evidence for check {check.id!r} names a different command "
                    "than this policy configures, so it proves nothing about "
                    "the configured command"))
                remediation.append(
                    f"run check {check.id!r} exactly as configured: "
                    f"{' '.join(check.argv)}")
                continue
            if record.started_at > now + MAX_CLOCK_SKEW_SECONDS:
                reasons.append(Reason(
                    "future_dated_evidence", check.id,
                    f"evidence for check {check.id!r} is dated "
                    f"{record.started_at - now}s in the future, beyond the "
                    f"{MAX_CLOCK_SKEW_SECONDS}s clock-skew allowance"))
                remediation.append(
                    f"fix the clock on the machine that ran check {check.id!r} "
                    "and produce the evidence again")
                continue
            matches.append(record)
        if not matches:
            if check.id in not_run:
                outcomes.append(CheckOutcome(check.id, check.required,
                                             "not_run", None, 0,
                                             provenance.get(check.id, "not_run")))
                if check.required:
                    reasons.append(Reason(
                        "check_not_run", check.id,
                        f"required check {check.id!r} was not run: an earlier "
                        "required check already decided this commit"))
                    remediation.append(
                        "fix the failing check above, then re-run; the gate "
                        "stops at the first decisive required failure so a "
                        "refusal costs the cheapest check, not all of them")
                continue
            outcomes.append(CheckOutcome(check.id, check.required, "missing",
                                         None, 0,
                                         provenance.get(check.id, "missing")))
            if check.required:
                reasons.append(Reason(
                    "missing_check", check.id,
                    f"required check {check.id!r} (version {check.version}) has "
                    "no evidence for this exact commit"))
                remediation.append(
                    f"run check {check.id!r}: {' '.join(check.argv)}")
            continue
        # Several records may describe one check within a single attempt: a
        # locally executed run and an imported one, for instance. They resolve
        # to the *worst* outcome, so a later passing record can never paper over
        # an observed failure inside the same attempt. Across attempts they do
        # not mix at all: an attempt is evaluated on its own evidence.
        observed_ms += max(record.duration_ms for record in matches)
        record = min(matches, key=_severity)
        status = _status_of(record)
        outcomes.append(CheckOutcome(
            check.id, check.required, status, record.exit_code,
            record.duration_ms, provenance.get(check.id, "recorded"),
            record.attempt_id, record.reused_from_attempt))
        if status == "passed":
            continue
        if not check.required:
            continue
        if status == "timeout":
            reasons.append(Reason(
                "check_timeout", check.id,
                f"required check {check.id!r} exceeded its "
                f"{check.timeout_seconds}s timeout"))
            remediation.append(
                f"make check {check.id!r} finish inside {check.timeout_seconds}s "
                "or raise its timeout_seconds deliberately")
        elif status == "launch_failed":
            reasons.append(Reason(
                "check_launch_failed", check.id,
                f"required check {check.id!r} could not be executed at all"))
            remediation.append(
                f"install or fix the command for check {check.id!r}: "
                f"{' '.join(check.argv)}")
        else:
            reasons.append(Reason(
                "failed_check", check.id,
                f"required check {check.id!r} exited {record.exit_code}"))
            remediation.append(
                f"fix what check {check.id!r} reports, then re-run: "
                f"{' '.join(check.argv)}")

    def review_is_fresh(record, subject: str) -> bool:
        if record.issued_at > now + MAX_CLOCK_SKEW_SECONDS:
            reasons.append(Reason(
                "future_dated_review", subject,
                f"review {subject!r} is dated {record.issued_at - now}s in the "
                f"future, beyond the {MAX_CLOCK_SKEW_SECONDS}s clock-skew "
                "allowance; a max-age rule cannot bound it"))
            remediation.append(
                f"fix the clock on the machine that signed {subject!r} and "
                "obtain the review again")
            return False
        if now - record.issued_at > artifact_class.review_max_age_seconds:
            reasons.append(Reason(
                "expired_review", subject,
                f"review {subject!r} is older than "
                f"{artifact_class.review_max_age_seconds}s"))
            remediation.append(
                f"obtain a fresh review from {record.reviewer_id!r}")
            return False
        return True

    pinned = frozenset(artifact_class.reviewer_key_ids)
    authors = frozenset(artifact_class.author_key_ids)

    def rejected(record, who: str) -> None:
        reasons.append(Reason(
            "rejecting_review", record.review_id,
            f"{who} rejected this commit"))
        remediation.append(
            f"resolve the findings raised by {record.reviewer_id!r} and "
            "obtain a new review")

    def key_can_never_count(subject: str, key_id: str, *,
                            authenticated: bool) -> bool:
        """Reasons a key is disqualified whether or not it really signed.

        Both checks are made against the key id the document *names*, which is
        free and can only ever refuse: a claim that survives here still has to
        survive the signature check wherever the keyring lives.

        ``authenticated`` only changes how the refusal is worded, so an
        unverified claim is never described as an established fact.
        """

        signed = "is signed by" if authenticated else "claims a signature by"
        if key_id in authors:
            reasons.append(Reason(
                "author_signed_review", subject,
                f"review {subject!r} {signed} {key_id!r}, which this policy "
                "names as an author identity; nobody reviews their own change"))
            remediation.append(
                "obtain an approving review signed by a reviewer key that is "
                f"not one of: {', '.join(sorted(authors))}")
            return True
        if pinned and key_id not in pinned:
            reasons.append(Reason(
                "unpinned_reviewer_key", subject,
                f"review {subject!r} {signed} {key_id!r}, which class "
                f"{artifact_class.id!r} does not pin as a reviewer key"))
            remediation.append(
                f"add {key_id!r} to reviewer_key_ids in class "
                f"{artifact_class.id!r}, or have a pinned reviewer sign it")
            return True
        return False

    # An unsigned review is a claim by whoever wrote the file. It is heeded
    # when it *rejects* -- refusing on an unauthenticated objection is the safe
    # direction -- and never counted when it approves.
    for record in bound_advisory:
        if not review_is_fresh(record, record.review_id):
            continue
        if record.verdict == "reject":
            rejected(record, f"reviewer {record.reviewer_id!r}")

    # An attestation nobody here could authenticate is the same claim with a
    # signature attached. It never counts, and it is reported by its own code so
    # a caller can tell "waiting for the authenticator" apart from "refused".
    pending_keys: set[str] = set()
    for item in bound_unverified:
        record, key_id = item.record, item.key_id
        if not review_is_fresh(record, record.review_id):
            continue
        if record.verdict == "reject":
            # An objection is heeded whoever signed it: refusing on an
            # unauthenticated rejection is the safe direction.
            rejected(record, f"a review claiming the key {key_id!r}")
            continue
        if record.verdict != "approve":
            continue
        if key_can_never_count(record.review_id, key_id, authenticated=False):
            continue
        pending_keys.add(key_id)
        reasons.append(Reason(
            "unauthenticated_review", record.review_id,
            f"review {record.review_id!r} claims a signature by {key_id!r}, "
            "and this evaluation holds no reviewer keyring, so nothing here "
            "can authenticate it and it counts for nothing"))
        remediation.append(
            "hand this preview to the trusted finalizer: it holds the pinned "
            "reviewer keyring and is the only place an independent review can "
            "be authenticated")

    approving_keys: set[str] = set()
    for item in bound_verified:
        record, key_id = item.record, item.key_id
        if not review_is_fresh(record, record.review_id):
            continue
        if record.verdict == "reject":
            rejected(record, f"reviewer key {key_id!r}")
            continue
        if record.verdict != "approve":
            continue
        if key_can_never_count(record.review_id, key_id, authenticated=True):
            continue
        # Counted by authenticated key identity: two reviews signed by one key
        # are one reviewer, whatever their reviewer_id strings say.
        approving_keys.add(key_id)

    # Author identity, established by a key rather than by a string in a
    # document the submitter wrote. It matters exactly where independent review
    # matters: "nobody reviews their own change" is a rule about who the author
    # is, and until something authenticates that, the rule is decoration. So a
    # class that requires independent review requires an authenticated
    # authorship attestation too, and admits nothing without one.
    if artifact_class.required_independent_reviews > 0:
        authenticated_authors: set[str] = set()
        for item in attested_authorships:
            record = item.record
            ok, code = _bound(record, repository, commit_sha, tree_sha,
                              policy_digest)
            if not ok:
                reasons.append(Reason(
                    code, record.author_id,
                    f"authorship claim by {record.author_id!r}: "
                    f"{_UNBOUND_DETAIL[code]}"))
                remediation.append(
                    "have the author sign an authorship attestation for "
                    f"{commit_sha} under this policy")
                continue
            if item.key_id not in authors:
                reasons.append(Reason(
                    "unpinned_author_key", record.author_id,
                    f"an authorship claim for this commit is signed by "
                    f"{item.key_id!r}, which class {artifact_class.id!r} does "
                    "not pin as an author key"))
                remediation.append(
                    f"add {item.key_id!r} to author_key_ids in class "
                    f"{artifact_class.id!r}, or have a pinned author sign it")
                continue
            authenticated_authors.add(item.key_id)
        for item in claimed_authorships:
            # An empty key id is not a key id nobody typed: it is a record read
            # back from durable storage, where the signature and the key that
            # made it are not part of what a receipt binds. Saying "names key
            # ''" would read as a malformed claim rather than as the true
            # answer, which is that this process has the claim and nothing to
            # check it with.
            names = (f"names key {item.key_id!r}" if item.key_id
                     else "was read back from storage, which retains the "
                          "record and not the key that signed it")
            reasons.append(Reason(
                "unauthenticated_authorship", item.record.author_id,
                f"an authorship claim for this commit {names}, and this "
                "evaluation holds no keyring, so nothing here can "
                "authenticate it and it counts for nothing"))
            remediation.append(
                "hand this preview to the trusted finalizer: it holds the "
                "pinned keyring and is the only place an authorship claim can "
                "be authenticated")
        if not authenticated_authors:
            reasons.append(Reason(
                "missing_author_attestation", artifact_class.id,
                f"class {artifact_class.id!r} requires independent review, and "
                "no authenticated authorship attestation names who wrote this "
                "commit. Excluding the author from reviewing their own change "
                "is a rule about a key, and no key has claimed authorship "
                "here"))
            remediation.append(
                "have the author sign an authorship attestation with "
                "'admissible attest-review --authorship' using a key this "
                "policy pins in author_key_ids, and carry it in the evidence "
                "bundle")
        # An approving review signed by a key that also authenticated
        # authorship is the author approving themselves. The pinned-key lists
        # are disjoint, so this is already refused above; it is asserted here
        # too because the two rules must never be able to drift apart.
        overlapping = sorted(authenticated_authors & approving_keys)
        if overlapping:
            reasons.append(Reason(
                "author_signed_review", artifact_class.id,
                "the key(s) " + ", ".join(overlapping) + " both attested "
                "authorship of this commit and signed an approving review of "
                "it; nobody reviews their own change"))
            remediation.append(
                "obtain an approving review signed by a reviewer key that did "
                "not attest authorship of this commit")
            approving_keys -= set(overlapping)

    independent = len(approving_keys)
    if artifact_class.required_independent_reviews > 0 and not pinned:
        reasons.append(Reason(
            "unpinned_reviewer_keyring", artifact_class.id,
            f"class {artifact_class.id!r} requires "
            f"{artifact_class.required_independent_reviews} independent "
            "review(s) but pins no reviewer_key_ids, so no review can be "
            "authenticated and none can block"))
        remediation.append(
            f"list the reviewer key ids allowed to approve class "
            f"{artifact_class.id!r} in reviewer_key_ids, then have each "
            "reviewer sign with 'admissible attest-review'")
    if independent < artifact_class.required_independent_reviews:
        reasons.append(Reason(
            "missing_independent_review", artifact_class.id,
            f"{independent} of {artifact_class.required_independent_reviews} "
            "required independent approving reviews are present for this exact "
            "commit, counted by authenticated reviewer key"))
        remediation.append(
            "obtain "
            f"{artifact_class.required_independent_reviews - independent} more "
            "approving review(s), each signed by a distinct pinned reviewer "
            "key, recorded against this exact commit, tree and policy")

    cost_units, planned_wall, ceiling_reasons, ceiling_remediation = plan_budget(
        artifact_class)
    wall_seconds = max(planned_wall, (observed_ms + 999) // 1000)
    blocked = bool(ceiling_reasons)
    reasons.extend(ceiling_reasons)
    remediation.extend(ceiling_remediation)
    if not blocked and wall_seconds > artifact_class.max_wall_seconds:
        blocked = True
        reasons.append(Reason(
            "time_ceiling", artifact_class.id,
            f"this class needs up to {wall_seconds}s but its ceiling is "
            f"{artifact_class.max_wall_seconds}s"))
        remediation.append(
            "raise max_wall_seconds deliberately, or shorten the checks in "
            f"class {artifact_class.id!r}")

    if blocked:
        state = BLOCKED
    elif reasons:
        state = REFUSED
    else:
        state = CHECKS_PASSED

    if state == CHECKS_PASSED and not remediation:
        remediation.append(
            "have an external observer attest this evaluation with "
            "'admissible attest-evaluation', then run 'admissible finalize' in "
            "the trust domain that holds the signing key; no receipt exists "
            "until it does")

    digests = tuple(sorted(
        {evidence_digest(record) for record in bound_commands}
        | {evidence_digest(record) for record in bound_advisory}
        | {evidence_digest(item.record) for item in bound_verified}
        | {evidence_digest(item.record) for item in bound_unverified}
        | {evidence_digest(item.record)
           for item in attested_authorships + claimed_authorships}))
    seen: set[str] = set()
    unique_remediation = tuple(
        line for line in remediation
        if not (line in seen or seen.add(line)))
    return Decision(
        state=state,
        repository=repository,
        commit_sha=commit_sha,
        tree_sha=tree_sha,
        policy_digest=policy_digest,
        class_id=artifact_class.id,
        reasons=tuple(reasons),
        remediation=unique_remediation,
        checks=tuple(outcomes),
        independent_reviews=independent,
        required_independent_reviews=artifact_class.required_independent_reviews,
        cost_units=cost_units,
        max_cost_units=artifact_class.max_cost_units,
        wall_seconds=wall_seconds,
        max_wall_seconds=artifact_class.max_wall_seconds,
        evidence_digests=digests,
        evaluated_at=now,
        attempt_id=attempt_id,
        pending_reviews=len(pending_keys - approving_keys),
    )


def preview_readiness(result: Decision) -> str:
    """What this evaluation established, as opposed to what it admitted.

    ``AWAITING_REVIEW`` is deliberately narrow. It requires a plain refusal --
    never a block -- with every required check actually passed and *every*
    refusal code one that only a keyring holder could clear. One failed check,
    one rejection, one reviewer key this policy can never count, and the answer
    is ``NOT_READY``: there is nobody for this preview to be waiting on.
    """

    if type(result) is not Decision:
        raise TypeError("result must be a Decision")
    if result.state == CHECKS_PASSED:
        return READINESS_READY_FOR_ATTESTATION
    if result.state != REFUSED or not result.reasons:
        return READINESS_NOT_READY
    if any(outcome.required and outcome.status != "passed"
           for outcome in result.checks):
        return READINESS_NOT_READY
    if any(reason.code not in _REVIEW_PENDING_CODES
           for reason in result.reasons):
        return READINESS_NOT_READY
    return READINESS_AWAITING_REVIEW


def decision_to_dict(result: Decision) -> dict[str, Any]:
    """A stable plain-JSON view of the decision."""

    if type(result) is not Decision:
        raise TypeError("result must be a Decision")
    return {
        "scope": DECISION_SCOPE,
        "state": result.state,
        "readiness": preview_readiness(result),
        "exit_code": result.exit_code,
        "repository": result.repository,
        "commit_sha": result.commit_sha,
        "tree_sha": result.tree_sha,
        "policy_digest": result.policy_digest,
        "class_id": result.class_id,
        "attempt_id": result.attempt_id,
        "reasons": [reason.to_dict() for reason in result.reasons],
        "remediation": list(result.remediation),
        "checks": [outcome.to_dict() for outcome in result.checks],
        "reviews": {
            "independent_approving": result.independent_reviews,
            "pending_authentication": result.pending_reviews,
            "required": result.required_independent_reviews,
        },
        "budget": {
            "cost_units": result.cost_units,
            "max_cost_units": result.max_cost_units,
            "wall_seconds": result.wall_seconds,
            "max_wall_seconds": result.max_wall_seconds,
        },
        "evidence_digests": list(result.evidence_digests),
        "evaluated_at": result.evaluated_at,
    }


def digest_of_document(document: dict) -> str:
    """The decision digest of an already-serialised decision document."""

    if type(document) is not dict:
        raise TypeError("decision document must be a JSON object")
    return hashlib.sha256(canonical_json({
        "domain": _DECISION_DOMAIN,
        "decision": document,
    }).encode("utf-8")).hexdigest()


def decision_digest(result: Decision) -> str:
    """A content digest binding the decision into a receipt."""

    return digest_of_document(decision_to_dict(result))


_HEADLINE = {
    CHECKS_PASSED: (
        "CHECKS_PASSED: every required check passed for this exact commit. "
        "This is an evaluation, not an admission."),
    REFUSED: "REFUSED: this commit does not meet its own policy yet.",
    BLOCKED: "BLOCKED: the policy or environment cannot be evaluated as written.",
}


def render_plain(result: Decision) -> str:
    """Plain output: what happened, what is known, what to do next."""

    readiness = preview_readiness(result)
    lines = [f"What happened: {_HEADLINE[result.state]}"]
    if readiness == READINESS_READY_FOR_ATTESTATION:
        lines.append(
            "  READY_FOR_ATTESTATION: nothing is outstanding that this "
            "evaluation could resolve.")
        lines.append(
            "  It is not an admission: only a signed durable receipt is.")
    if readiness == READINESS_AWAITING_REVIEW:
        lines.append(
            "  AWAITING_REVIEW: every required check passed and the only "
            "blocker left is")
        lines.append(
            "  independent review, which only a keyring holder can "
            "authenticate. This is")
        lines.append("  not an admission.")
    lines += [
        f"  repository {result.repository}",
        f"  commit     {result.commit_sha}",
        f"  attempt    {result.attempt_id or 'not recorded'}",
        f"  tree       {result.tree_sha}",
        f"  class      {result.class_id} (policy {result.policy_digest[:12]})",
    ]
    if result.reasons:
        lines.append("")
        for reason in result.reasons:
            lines.append(f"  - [{reason.code}] {reason.detail}")
    lines.append("")
    lines.append("What is known:")
    for outcome in result.checks:
        marker = "required" if outcome.required else "optional"
        detail = "" if outcome.exit_code is None else f" (exit {outcome.exit_code})"
        lines.append(f"  - check {outcome.check_id}: {outcome.status} "
                     f"[{marker}, {outcome.provenance}]{detail}")
    lines.append(
        f"  - independent approving reviews: {result.independent_reviews} of "
        f"{result.required_independent_reviews} required, counted by "
        "authenticated reviewer key")
    if result.pending_reviews:
        lines.append(
            f"  - {result.pending_reviews} further review(s) carry a signature "
            "this evaluation holds no key for; they count for nothing here")
    lines.append(
        f"  - budget: {result.cost_units}/{result.max_cost_units} cost units, "
        f"up to {result.wall_seconds}/{result.max_wall_seconds} seconds")
    lines.append(
        "  - not known: anything no check or reviewer examined; this is a "
        "developer workflow admission, not a proof of correctness")
    lines.append("")
    lines.append("What to do next:")
    for line in result.remediation:
        lines.append(f"  - {line}")
    return "\n".join(lines) + "\n"
