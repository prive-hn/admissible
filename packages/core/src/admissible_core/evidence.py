"""Closed evidence records: commands, reviews, defects, and bundles.

Evidence is non-authoritative. It describes what a command or reviewer observed
about an exact repository, commit, tree, and policy. It can never forge a kernel
journal event and it never carries raw output or secrets: only digests, sizes,
and exact identities.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from fcd.journal import canonical_json

__all__ = [
    "ATTESTATION_KEYS",
    "ATTESTATION_SCHEMA",
    "AUTHORSHIP_ATTESTATION_SCHEMA",
    "AttestedAuthorship",
    "AuthorshipEvidence",
    "Bundle",
    "CommandEvidence",
    "DefectRecord",
    "EVIDENCE_SCHEMA",
    "EvidenceError",
    "MAX_EVIDENCE_BYTES",
    "ReviewEvidence",
    "VERDICTS",
    "command_evidence_from_dict",
    "command_evidence_from_result",
    "command_evidence_to_dict",
    "defect_from_dict",
    "defect_to_dict",
    "evidence_digest",
    "evidence_to_dict",
    "file_digest",
    "load_evidence_file",
    "bundle_to_dict",
    "parse_bundle",
    "UnverifiedAuthorship",
    "UnverifiedReview",
    "VerifiedReview",
    "attestation_digest",
    "authorship_attestation_shape",
    "authorship_evidence_from_dict",
    "authorship_evidence_to_dict",
    "parse_attestation_shape",
    "review_evidence_from_dict",
    "review_evidence_to_dict",
    "verify_review_candidate",
    "reuse_in_attempt",
]

EVIDENCE_SCHEMA = "admissible/v0.6/workflow-evidence"
ATTESTATION_SCHEMA = "admissible/v0.6/review-attestation"
ATTESTATION_KEYS = ("schema", "algorithm", "key_id", "review", "signature")
AUTHORSHIP_ATTESTATION_SCHEMA = "admissible/v0.6/authorship-attestation"
AUTHORSHIP_ATTESTATION_KEYS = ("schema", "algorithm", "key_id", "authorship",
                               "signature")
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
VERDICTS = ("approve", "reject", "abstain")
SEVERITIES = ("low", "medium", "high", "critical")
# Absent means "observed in its own attempt". Older records predate the field
# and say nothing about reuse, which is exactly what an empty string means, so
# the key is accepted as absent and always written back present.
_COMMAND_OPTIONAL = ("reused_from_attempt",)
_BUNDLE_KEYS = {"schema", "commands", "reviews", "defects", "attestations"}
# Authorship attestations arrived after the bundle shape was fixed, and an
# absent list means "none supplied" rather than a malformed bundle. It is
# always written back present, so a bundle that round-trips gains the key once
# and never loses it.
_BUNDLE_OPTIONAL = ("author_attestations",)


class EvidenceError(ValueError):
    """An evidence document is not a closed, exactly typed record."""


@dataclass(frozen=True)
class CommandEvidence:
    kind: str
    check_id: str
    check_version: str
    repository: str
    commit_sha: str
    tree_sha: str
    policy_digest: str
    argv_digest: str
    exit_code: int
    timed_out: bool
    launch_failed: bool
    duration_ms: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    output_truncated: bool
    started_at: int
    finished_at: int
    attempt_id: str
    # The attempt this observation was *originally* made in, when this record
    # is a reuse of an earlier one. Empty means the observation belongs to
    # ``attempt_id`` itself. Reuse never rewrites history in place: it derives a
    # new record for the current attempt and keeps naming where it came from,
    # so a receipt can be read back to the moment the command actually ran.
    reused_from_attempt: str = ""

    @property
    def passed(self) -> bool:
        return (self.exit_code == 0 and not self.timed_out
                and not self.launch_failed)


@dataclass(frozen=True)
class ReviewEvidence:
    kind: str
    review_id: str
    reviewer_id: str
    reviewer_version: str
    author_id: str
    verdict: str
    repository: str
    commit_sha: str
    tree_sha: str
    policy_digest: str
    findings_digest: str
    issued_at: int
    attempt_id: str
    base_sha: str = ""
    patch_sha256: str = ""

    @property
    def independent(self) -> bool:
        """Unequal identity strings only.

        This is a *hint*, never an authority. Independence that blocks a merge
        is established by an authenticated reviewer key id, never by a string
        the submitter chose; see :class:`VerifiedReview`.
        """

        return self.reviewer_id != self.author_id


@dataclass(frozen=True)
class VerifiedReview:
    """One review whose signature an external reviewer keyring authenticated.

    ``key_id`` is the identity that actually signed. Blocking review counts are
    taken over distinct ``key_id`` values, so two reviews signed by one key are
    one reviewer however their ``reviewer_id`` strings read.
    """

    record: ReviewEvidence
    key_id: str


@dataclass(frozen=True)
class UnverifiedReview:
    """One attestation whose signature *this* job cannot authenticate.

    The evaluate job holds no reviewer keyring by design: it runs
    candidate-owned commands, so handing it reviewer secrets would hand them to
    the candidate. It is therefore not the authenticator, and an attestation it
    carries is exactly a claim -- ``key_id`` is what the document *says* signed
    it, never what did.

    Keeping the claim in its own type makes the honest thing the easy thing: it
    can be reported and handed on, and there is no code path that counts it
    towards a required independent review.
    """

    record: ReviewEvidence
    key_id: str


@dataclass(frozen=True)
class DefectRecord:
    kind: str
    defect_id: str
    repository: str
    commit_sha: str
    severity: str
    summary: str
    missed_check_ids: tuple[str, ...]
    regression_test_id: str
    discovered_at: int


@dataclass(frozen=True)
class AuthorshipEvidence:
    """Who authored one exact artefact, as a record a key can sign.

    ``author_id`` is a label. What blocks or permits anything is the key that
    signed this record: a policy names author key ids, an authenticated
    authorship attestation establishes that one of them claims this commit, and
    "nobody reviews their own change" is then a statement about keys rather
    than about strings the submitter chose.
    """

    kind: str
    author_id: str
    repository: str
    commit_sha: str
    tree_sha: str
    policy_digest: str
    issued_at: int


@dataclass(frozen=True)
class AttestedAuthorship:
    """One authorship record whose signature a keyring authenticated."""

    record: AuthorshipEvidence
    key_id: str


@dataclass(frozen=True)
class UnverifiedAuthorship:
    """One authorship claim *this* job holds no key to authenticate."""

    record: AuthorshipEvidence
    key_id: str


@dataclass(frozen=True)
class Bundle:
    commands: tuple[CommandEvidence, ...]
    reviews: tuple[ReviewEvidence, ...]
    defects: tuple[DefectRecord, ...]
    attestations: tuple[dict, ...] = ()
    author_attestations: tuple[dict, ...] = ()
    source_sha256: str = ""


def _closed(document: object, expected: tuple[str, ...], where: str, *,
            optional: tuple[str, ...] = ()) -> dict:
    if type(document) is not dict:
        raise EvidenceError(f"{where} must be a JSON object")
    present = set(document)
    wanted = set(expected)
    unknown = present - wanted
    if unknown:
        raise EvidenceError(
            f"{where} has unknown key(s): {', '.join(sorted(unknown))}")
    missing = wanted - present - set(optional)
    if missing:
        raise EvidenceError(
            f"{where} is missing key(s): {', '.join(sorted(missing))}")
    return document


def _text(value: object, where: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise EvidenceError(f"{where} must be a string")
    if not allow_empty and not value.strip():
        raise EvidenceError(f"{where} must not be empty")
    if len(value) > 4096:
        raise EvidenceError(f"{where} is too long")
    return value


def _hex(value: object, length: int, where: str) -> str:
    text = _text(value, where)
    if len(text) != length or any(
            character not in "0123456789abcdef" for character in text):
        raise EvidenceError(
            f"{where} must be a lowercase {length}-character hex digest")
    return text


def _integer(value: object, where: str, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        raise EvidenceError(f"{where} must be a plain integer")
    if minimum is not None and value < minimum:
        raise EvidenceError(f"{where} must be at least {minimum}")
    return value


def _boolean(value: object, where: str) -> bool:
    if type(value) is not bool:
        raise EvidenceError(f"{where} must be true or false")
    return value


def _member(value: object, allowed: tuple[str, ...], where: str) -> str:
    text = _text(value, where)
    if text not in allowed:
        raise EvidenceError(f"{where} must be one of {', '.join(allowed)}")
    return text


def _keys(record_type) -> tuple[str, ...]:
    return tuple(field.name for field in fields(record_type))


def command_evidence_from_dict(document: object) -> CommandEvidence:
    document = _closed(document, _keys(CommandEvidence), "command evidence",
                       optional=_COMMAND_OPTIONAL)
    return CommandEvidence(
        kind=_member(document["kind"], ("command",), "command evidence kind"),
        check_id=_text(document["check_id"], "check_id"),
        check_version=_text(document["check_version"], "check_version"),
        repository=_text(document["repository"], "repository"),
        commit_sha=_hex(document["commit_sha"], 40, "commit_sha"),
        tree_sha=_hex(document["tree_sha"], 40, "tree_sha"),
        policy_digest=_hex(document["policy_digest"], 64, "policy_digest"),
        argv_digest=_hex(document["argv_digest"], 64, "argv_digest"),
        exit_code=_integer(document["exit_code"], "exit_code"),
        timed_out=_boolean(document["timed_out"], "timed_out"),
        launch_failed=_boolean(document["launch_failed"], "launch_failed"),
        duration_ms=_integer(document["duration_ms"], "duration_ms", minimum=0),
        stdout_sha256=_hex(document["stdout_sha256"], 64, "stdout_sha256"),
        stderr_sha256=_hex(document["stderr_sha256"], 64, "stderr_sha256"),
        stdout_bytes=_integer(document["stdout_bytes"], "stdout_bytes", minimum=0),
        stderr_bytes=_integer(document["stderr_bytes"], "stderr_bytes", minimum=0),
        output_truncated=_boolean(document["output_truncated"], "output_truncated"),
        started_at=_integer(document["started_at"], "started_at", minimum=0),
        finished_at=_integer(document["finished_at"], "finished_at", minimum=0),
        attempt_id=_text(document["attempt_id"], "attempt_id"),
        reused_from_attempt=_text(document.get("reused_from_attempt", ""),
                                  "reused_from_attempt", allow_empty=True),
    )


def command_evidence_to_dict(record: CommandEvidence) -> dict[str, Any]:
    if type(record) is not CommandEvidence:
        raise EvidenceError("record must be CommandEvidence")
    return {name: getattr(record, name) for name in _keys(CommandEvidence)}


def review_evidence_from_dict(document: object) -> ReviewEvidence:
    document = _closed(document, _keys(ReviewEvidence), "review evidence",
                       optional=("base_sha", "patch_sha256"))
    named = "base_sha" in document
    if named != ("patch_sha256" in document):
        raise EvidenceError("review candidate fields must be paired")
    if named:
        base_sha = _hex(document["base_sha"], 40, "base_sha")
        patch_sha256 = _hex(document["patch_sha256"], 64, "patch_sha256")
    else:
        base_sha = ""
        patch_sha256 = ""
    return ReviewEvidence(
        kind=_member(document["kind"], ("review",), "review evidence kind"),
        review_id=_text(document["review_id"], "review_id"),
        reviewer_id=_text(document["reviewer_id"], "reviewer_id"),
        reviewer_version=_text(document["reviewer_version"], "reviewer_version"),
        author_id=_text(document["author_id"], "author_id"),
        verdict=_member(document["verdict"], VERDICTS, "verdict"),
        repository=_text(document["repository"], "repository"),
        commit_sha=_hex(document["commit_sha"], 40, "commit_sha"),
        tree_sha=_hex(document["tree_sha"], 40, "tree_sha"),
        policy_digest=_hex(document["policy_digest"], 64, "policy_digest"),
        findings_digest=_hex(document["findings_digest"], 64, "findings_digest"),
        issued_at=_integer(document["issued_at"], "issued_at", minimum=0),
        attempt_id=_text(document["attempt_id"], "attempt_id", allow_empty=True),
        base_sha=base_sha,
        patch_sha256=patch_sha256,
    )


def review_evidence_to_dict(record: ReviewEvidence) -> dict[str, Any]:
    if type(record) is not ReviewEvidence:
        raise EvidenceError("record must be ReviewEvidence")
    return {name: getattr(record, name) for name in _keys(ReviewEvidence)
            if not (name in {"base_sha", "patch_sha256"} and not getattr(record, name))}


def verify_review_candidate(record: ReviewEvidence, *, base_sha: str,
                            commit_sha: str, tree_sha: str,
                            patch_sha256: str) -> None:
    """Refuse a verdict that does not name this exact candidate tuple."""

    if type(record) is not ReviewEvidence:
        raise EvidenceError("record must be ReviewEvidence")
    if not record.base_sha or not record.patch_sha256:
        raise EvidenceError("review evidence does not name a candidate")
    if (record.base_sha != base_sha or record.commit_sha != commit_sha
            or record.tree_sha != tree_sha
            or record.patch_sha256 != patch_sha256):
        raise EvidenceError("review evidence names a different candidate")


def authorship_evidence_from_dict(document: object) -> AuthorshipEvidence:
    document = _closed(document, _keys(AuthorshipEvidence),
                       "authorship evidence")
    return AuthorshipEvidence(
        kind=_member(document["kind"], ("authorship",),
                     "authorship evidence kind"),
        author_id=_text(document["author_id"], "author_id"),
        repository=_text(document["repository"], "repository"),
        commit_sha=_hex(document["commit_sha"], 40, "commit_sha"),
        tree_sha=_hex(document["tree_sha"], 40, "tree_sha"),
        policy_digest=_hex(document["policy_digest"], 64, "policy_digest"),
        issued_at=_integer(document["issued_at"], "issued_at", minimum=0),
    )


def authorship_evidence_to_dict(record: AuthorshipEvidence) -> dict[str, Any]:
    if type(record) is not AuthorshipEvidence:
        raise EvidenceError("record must be AuthorshipEvidence")
    return {name: getattr(record, name) for name in _keys(AuthorshipEvidence)}


def defect_from_dict(document: object) -> DefectRecord:
    document = _closed(document, _keys(DefectRecord), "defect record")
    missed = document["missed_check_ids"]
    if type(missed) is not list:
        raise EvidenceError("missed_check_ids must be a list of check ids")
    return DefectRecord(
        kind=_member(document["kind"], ("defect",), "defect record kind"),
        defect_id=_text(document["defect_id"], "defect_id"),
        repository=_text(document["repository"], "repository"),
        commit_sha=_hex(document["commit_sha"], 40, "commit_sha"),
        severity=_member(document["severity"], SEVERITIES, "severity"),
        summary=_text(document["summary"], "summary"),
        missed_check_ids=tuple(
            _text(item, "missed_check_ids entry") for item in missed),
        regression_test_id=_text(document["regression_test_id"],
                                 "regression_test_id", allow_empty=True),
        discovered_at=_integer(document["discovered_at"], "discovered_at",
                               minimum=0),
    )


def defect_to_dict(record: DefectRecord) -> dict[str, Any]:
    if type(record) is not DefectRecord:
        raise EvidenceError("record must be a DefectRecord")
    document = {name: getattr(record, name) for name in _keys(DefectRecord)}
    document["missed_check_ids"] = list(record.missed_check_ids)
    return document


def evidence_to_dict(record: object) -> dict[str, Any]:
    if type(record) is CommandEvidence:
        return command_evidence_to_dict(record)
    if type(record) is ReviewEvidence:
        return review_evidence_to_dict(record)
    if type(record) is AuthorshipEvidence:
        return authorship_evidence_to_dict(record)
    if type(record) is DefectRecord:
        return defect_to_dict(record)
    raise EvidenceError("unknown evidence record type")


def attestation_digest(document: object) -> str:
    """A stable digest over one signed attestation document.

    The signature is part of it. Two attestations over the same review, signed
    by two keys, are two records: an observer that watched one of them did not
    watch the other, and collapsing them would let a signature be swapped for
    another after the observer looked.
    """

    if type(document) is not dict:
        raise EvidenceError("an attestation must be a JSON object")
    return hashlib.sha256(
        canonical_json(dict(document)).encode("utf-8")).hexdigest()


def evidence_digest(record: object) -> str:
    """A stable content digest over the exact evidence record."""

    return hashlib.sha256(
        canonical_json(evidence_to_dict(record)).encode("utf-8")).hexdigest()


def command_evidence_from_result(result, *, repository: str, commit_sha: str,
                                 tree_sha: str, policy_digest: str,
                                 attempt_id: str) -> CommandEvidence:
    """Bind a runner's ``CommandResult`` to an exact artefact.

    ``result`` is read by attribute, never imported: running the command is the
    executing distribution's capability, and a kernel that imported the runner
    to describe its output would carry that capability into every process.
    """

    return command_evidence_from_dict({
        "kind": "command",
        "check_id": result.check_id,
        "check_version": result.check_version,
        "repository": repository,
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
        "policy_digest": policy_digest,
        "argv_digest": result.argv_digest,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "launch_failed": result.launch_failed,
        "duration_ms": result.duration_ms,
        "stdout_sha256": result.stdout_sha256,
        "stderr_sha256": result.stderr_sha256,
        "stdout_bytes": result.stdout_bytes,
        "stderr_bytes": result.stderr_bytes,
        "output_truncated": result.output_truncated,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "attempt_id": attempt_id,
        "reused_from_attempt": "",
    })


def reuse_in_attempt(record: CommandEvidence, *,
                     attempt_id: str) -> CommandEvidence:
    """Derive ``record`` into ``attempt_id`` without losing where it came from.

    A decision is about one attempt. Reusing an earlier observation is
    therefore an explicit act with its own record: the derived record carries
    the current attempt so it can count, and ``reused_from_attempt`` so nobody
    reading it later can mistake it for a command that ran just now. Deriving a
    record that already belongs to this attempt is a no-op, and a record that
    was itself derived keeps naming the original observation rather than the
    intermediate copy.
    """

    if type(record) is not CommandEvidence:
        raise EvidenceError("only command evidence is reused across attempts")
    if type(attempt_id) is not str or not attempt_id.strip():
        raise EvidenceError("a derived record needs a non-empty attempt id")
    if record.attempt_id == attempt_id:
        return record
    source = record.reused_from_attempt or record.attempt_id
    return CommandEvidence(
        **{**command_evidence_to_dict(record), "attempt_id": attempt_id,
           "reused_from_attempt": source})


def file_digest(path: Path | str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def load_evidence_file(path: Path | str) -> Bundle:
    """Load an imported evidence bundle, refusing anything but the closed shape."""

    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError:
        raise EvidenceError(f"cannot read evidence file {path}") from None
    if size > MAX_EVIDENCE_BYTES:
        raise EvidenceError(
            f"evidence file {path} is larger than {MAX_EVIDENCE_BYTES} bytes")
    source_sha256 = file_digest(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{path} is not valid JSON: {error}") from None
    return parse_bundle(document, source_sha256=source_sha256)


def parse_bundle(document: object, *, source_sha256: str = "") -> Bundle:
    """Parse an in-memory evidence bundle document."""

    document = _closed(document, tuple(_BUNDLE_KEYS) + _BUNDLE_OPTIONAL,
                       "evidence bundle", optional=_BUNDLE_OPTIONAL)
    if document["schema"] != EVIDENCE_SCHEMA:
        raise EvidenceError(
            f"evidence bundle schema must be {EVIDENCE_SCHEMA!r}")
    author_attestations = document.get("author_attestations", [])
    for key, value in (("commands", document["commands"]),
                       ("reviews", document["reviews"]),
                       ("defects", document["defects"]),
                       ("attestations", document["attestations"]),
                       ("author_attestations", author_attestations)):
        if type(value) is not list:
            raise EvidenceError(f"evidence bundle {key} must be a list")
    return Bundle(
        commands=tuple(command_evidence_from_dict(item)
                       for item in document["commands"]),
        reviews=tuple(review_evidence_from_dict(item)
                      for item in document["reviews"]),
        defects=tuple(defect_from_dict(item) for item in document["defects"]),
        attestations=tuple(parse_attestation_shape(item)
                           for item in document["attestations"]),
        author_attestations=tuple(authorship_attestation_shape(item)
                                  for item in author_attestations),
        source_sha256=source_sha256,
    )


def parse_attestation_shape(document: object) -> dict[str, Any]:
    """Structural validation only; the signing authority verifies the mark.

    Checking the shape of an attestation is arithmetic on a document.
    Deciding that its mark is genuine needs a keyring, which is exactly
    what an authority-neutral kernel does not hold.
    """

    document = _closed(document, ATTESTATION_KEYS, "review attestation")
    if document["schema"] != ATTESTATION_SCHEMA:
        raise EvidenceError(
            f"review attestation schema must be {ATTESTATION_SCHEMA!r}")
    if document["algorithm"] != "hmac-sha256":
        raise EvidenceError(
            "review attestation algorithm must be 'hmac-sha256'; this is "
            "shared-secret authenticity, not public non-repudiation")
    _text(document["key_id"], "review attestation key_id")
    _hex(document["signature"], 64, "review attestation signature")
    review_evidence_from_dict(document["review"])
    return {name: document[name] for name in ATTESTATION_KEYS}


def authorship_attestation_shape(document: object) -> dict[str, Any]:
    """Structural validation only; the signing authority verifies the mark.

    Checking the shape of an attestation is arithmetic on a document.
    Deciding that its mark is genuine needs a keyring, which is exactly
    what an authority-neutral kernel does not hold.
    """

    document = _closed(document, AUTHORSHIP_ATTESTATION_KEYS,
                       "authorship attestation")
    if document["schema"] != AUTHORSHIP_ATTESTATION_SCHEMA:
        raise EvidenceError(
            "authorship attestation schema must be "
            f"{AUTHORSHIP_ATTESTATION_SCHEMA!r}")
    if document["algorithm"] != "hmac-sha256":
        raise EvidenceError(
            "authorship attestation algorithm must be 'hmac-sha256'; this is "
            "shared-secret authenticity, not public non-repudiation")
    _text(document["key_id"], "authorship attestation key_id")
    _hex(document["signature"], 64, "authorship attestation signature")
    authorship_evidence_from_dict(document["authorship"])
    return {name: document[name] for name in AUTHORSHIP_ATTESTATION_KEYS}


def bundle_to_dict(bundle: Bundle) -> dict[str, Any]:
    """Serialise a bundle back to its closed document shape."""

    return {
        "schema": EVIDENCE_SCHEMA,
        "commands": [command_evidence_to_dict(item) for item in bundle.commands],
        "reviews": [review_evidence_to_dict(item) for item in bundle.reviews],
        "defects": [defect_to_dict(item) for item in bundle.defects],
        "attestations": [dict(item) for item in bundle.attestations],
        "author_attestations": [dict(item)
                                for item in bundle.author_attestations],
    }
