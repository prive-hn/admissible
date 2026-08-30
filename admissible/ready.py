"""Friendly, machine-stable readiness presentation over canonical decisions.

This module is deliberately a presentation boundary.  It never evaluates policy,
authenticates evidence, or issues an admission.  Canonical state stays visible in
every document so a friendly label cannot weaken the underlying claim.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
from typing import Any, Mapping, Sequence

from . import evidence as evidence_module
from . import identity as identity_module
from . import runner as runner_module
from . import standing as standing_module
from . import store as store_module
from .config import CONFIG_FILENAME, config_file, load_config
from .decision import (BLOCKED, CHECKS_PASSED, READINESS_AWAITING_REVIEW,
                       READINESS_NOT_READY, READINESS_READY_FOR_ATTESTATION,
                       REFUSED)

__all__ = [
    "READY_SCHEMA",
    "ReadyError",
    "from_evaluation",
    "from_problem",
    "inspect",
    "render_plain",
    "run_check",
    "work_package",
]

READY_SCHEMA = "admissible/v0.7/ready-state"
_ALLOWED_STATES = frozenset({CHECKS_PASSED, REFUSED, BLOCKED})
_ALLOWED_READINESS = frozenset({READINESS_READY_FOR_ATTESTATION,
                                READINESS_AWAITING_REVIEW,
                                READINESS_NOT_READY})


class ReadyError(ValueError):
    """A canonical document could not be presented without guessing."""


def _text(document: Mapping[str, Any], key: str, *, lengths: tuple[int, ...] = ()) -> str:
    value = document.get(key)
    if type(value) is not str or not value:
        raise ReadyError(f"{key} must be a non-empty string")
    if lengths and len(value) not in lengths:
        raise ReadyError(f"{key} has an invalid length")
    return value


def _optional_attempt_id(document: Mapping[str, Any]) -> str | None:
    value = document.get("attempt_id")
    if value is None or value == "":
        return None
    if type(value) is not str:
        raise ReadyError("attempt_id must be a string or null")
    return value


def _unsigned_identities_match(found: Any, attempt: Mapping[str, Any],
                               decision: Mapping[str, Any]) -> bool:
    for key in ("repository", "commit_sha", "tree_sha"):
        query = getattr(found, key)
        nested = decision.get(key)
        if nested != query:
            return False
        row = attempt.get(key)
        if row is not None and row != query:
            return False
    row_attempt = attempt.get("attempt_id")
    nested_attempt = decision.get("attempt_id")
    return (type(row_attempt) is str and bool(row_attempt)
            and row_attempt == nested_attempt)


def _objects(value: Any, key: str) -> list[dict[str, Any]]:
    if type(value) is not list:
        raise ReadyError(f"{key} must be a list")
    if any(type(item) is not dict for item in value):
        raise ReadyError(f"every {key} item must be an object")
    return [dict(item) for item in value]


def _strings(value: Any, key: str) -> list[str]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ReadyError(f"{key} must be a list of strings")
    return list(value)


def _reason_codes(reasons: Sequence[Mapping[str, Any]]) -> list[str]:
    codes: list[str] = []
    for reason in reasons:
        code = reason.get("code")
        if type(code) is not str or not code:
            raise ReadyError("every reason code must be a non-empty string")
        if code not in codes:
            codes.append(code)
    return codes


def _action(*, action_id: str, title: str, detail: str, owner: str,
            kind: str, reason_codes: Sequence[str], command: str = "",
            retryable: bool = False) -> dict[str, Any]:
    return {
        "id": action_id,
        "title": title,
        "detail": detail,
        "owner": owner,
        "kind": kind,
        "reason_codes": list(reason_codes),
        "command": command,
        "retryable": retryable,
    }


def _status_and_summary(state: str, readiness: str) -> tuple[str, str]:
    if state == BLOCKED:
        return "unable_to_check", "Admissible could not safely check this commit."
    if state == REFUSED and readiness == READINESS_AWAITING_REVIEW:
        return "waiting_for_review", (
            "Checks passed. Independent review is still needed.")
    if state == CHECKS_PASSED and readiness == READINESS_READY_FOR_ATTESTATION:
        return "checks_complete", (
            "Checks passed. Secure confirmation is next.")
    return "needs_attention", "A check or requirement needs attention."


def _next_actions(status: str, reasons: Sequence[Mapping[str, Any]],
                  remediation: Sequence[str]) -> list[dict[str, Any]]:
    codes = _reason_codes(reasons)
    detail = remediation[0] if remediation else "Review the technical details."
    if status == "waiting_for_review":
        return [_action(
            action_id="request_review", title="Request independent review",
            detail=detail, owner="reviewer", kind="review",
            reason_codes=codes or ["missing_independent_review"])]
    if status == "checks_complete":
        return [_action(
            action_id="await_secure_confirmation",
            title="Wait for secure confirmation", detail=detail,
            owner="trusted_infrastructure", kind="confirmation",
            reason_codes=codes, retryable=False)]
    if status == "unable_to_check":
        return [_action(
            action_id="make_checkable", title="Make this commit checkable",
            detail=detail, owner="human", kind="precondition",
            reason_codes=codes, retryable=True)]
    failed = "failed_check" in codes
    return [_action(
        action_id="fix_check" if failed else "resolve_requirement",
        title="Fix the failing check" if failed else "Resolve the next requirement",
        detail=detail, owner="agent_or_human", kind="repair",
        reason_codes=codes, retryable=True)]


def from_evaluation(document: Mapping[str, Any], *,
                    standing: str = "UNKNOWN") -> dict[str, Any]:
    """Translate one canonical evaluation document into Ready v0.7.

    The translation is strict and deterministic.  It cannot produce ``ready``:
    an evaluation has no authority to claim an authentic current admission.
    """

    if type(document) is not dict:
        raise ReadyError("an evaluation must be a JSON object")
    state = _text(document, "state")
    readiness = _text(document, "readiness")
    if state not in _ALLOWED_STATES:
        raise ReadyError(f"unsupported canonical state {state!r}")
    if readiness not in _ALLOWED_READINESS:
        raise ReadyError(f"unsupported canonical readiness {readiness!r}")
    if standing not in {"UNKNOWN", "CURRENT", "IMPEACHED", "UNVERIFIED"}:
        raise ReadyError(f"unsupported canonical standing {standing!r}")

    repository = _text(document, "repository")
    commit_sha = _text(document, "commit_sha", lengths=(40,))
    tree_sha = _text(document, "tree_sha", lengths=(40,))
    policy_digest = _text(document, "policy_digest", lengths=(64,))
    class_id = _text(document, "class_id")
    attempt_id = _optional_attempt_id(document)
    reasons = _objects(document.get("reasons", []), "reasons")
    remediation = _strings(document.get("remediation", []), "remediation")
    checks = _objects(document.get("checks", []), "checks")
    status, summary = _status_and_summary(state, readiness)
    optional_failed = sum(
        1 for item in checks
        if item.get("required") is False
        and item.get("status") in {"failed", "timeout", "launch_failed"})
    if status == "checks_complete" and optional_failed:
        noun = "check" if optional_failed == 1 else "checks"
        summary = (
            f"All required checks passed. {optional_failed} optional {noun} failed.")

    passed = sum(1 for item in checks if item.get("status") == "passed")
    failed = sum(1 for item in checks if item.get("status") in {
        "failed", "timeout", "launch_failed"})
    required = sum(1 for item in checks if item.get("required") is True)
    if "required_independent_reviews" in document:
        required_reviews = document.get("required_independent_reviews")
        if required_reviews is not None and type(required_reviews) is not int:
            raise ReadyError(
                "required_independent_reviews must be an integer or null")
        if type(required_reviews) is bool:
            raise ReadyError(
                "required_independent_reviews must be an integer or null")
    else:
        required_reviews = 0

    return {
        "schema": READY_SCHEMA,
        "status": status,
        "summary": summary,
        "identity": {
            "repository": repository,
            "commit_sha": commit_sha,
            "tree_sha": tree_sha,
            "policy_digest": policy_digest,
            "class_id": class_id,
            "attempt_id": attempt_id,
            "applies_to_current_commit": True,
        },
        "canonical": {
            "state": state,
            "readiness": readiness,
            "standing": standing,
            "scope": document.get("scope", "developer-workflow-admission"),
            "exit_code": document.get("exit_code", 2),
        },
        "progress": {
            "checks_total": len(checks),
            "checks_required": required,
            "checks_passed": passed,
            "checks_failed": failed,
        },
        "checks": checks,
        "reasons": reasons,
        "next_actions": _next_actions(status, reasons, remediation),
        "agent_can_continue": status == "needs_attention",
        "advanced": {
            "remediation": remediation,
            "independent_reviews": document.get("independent_reviews", 0),
            "required_independent_reviews": required_reviews,
        },
    }


def from_problem(message: str, remediation: Sequence[str] = (), *,
                 reason_code: str = "operational_block",
                 summary: str = "Admissible could not safely check this commit.") \
        -> dict[str, Any]:
    """Return the same Ready envelope when exact identity is unavailable."""

    if type(message) is not str or not message:
        raise ReadyError("a blocked message must be a non-empty string")
    if type(summary) is not str or not summary:
        raise ReadyError("a blocked summary must be a non-empty string")
    steps = list(remediation)
    if any(type(item) is not str for item in steps):
        raise ReadyError("blocked remediation must contain only strings")
    reason = {"code": reason_code, "subject": "admissible",
              "detail": message}
    return {
        "schema": READY_SCHEMA,
        "status": "unable_to_check",
        "summary": summary,
        "identity": {
            "repository": None, "commit_sha": None, "tree_sha": None,
            "policy_digest": None, "class_id": None, "attempt_id": None,
            "applies_to_current_commit": False,
        },
        "canonical": {
            "state": BLOCKED, "readiness": READINESS_NOT_READY,
            "standing": "UNKNOWN", "scope": "developer-workflow-admission",
            "exit_code": 2,
        },
        "progress": {
            "checks_total": 0, "checks_required": 0,
            "checks_passed": 0, "checks_failed": 0,
        },
        "checks": [],
        "reasons": [reason],
        "next_actions": _next_actions("unable_to_check", [reason], steps),
        "agent_can_continue": False,
        "advanced": {"remediation": steps, "message": message,
                     "independent_reviews": 0,
                     "required_independent_reviews": 0},
    }


def render_plain(document: Mapping[str, Any]) -> str:
    """Render one concise human view with technical facts one level down."""

    if type(document) is not dict or document.get("schema") != READY_SCHEMA:
        raise ReadyError("render_plain requires a Ready v0.7 document")
    status = document.get("status", "unable_to_check")
    labels = {
        "needs_attention": "Needs attention",
        "waiting_for_review": "Waiting for review",
        "checks_complete": "Checks complete",
        "ready": "Ready",
        "unable_to_check": "Unable to check",
    }
    lines = [f"{labels.get(status, 'Unable to check')}: "
             f"{document.get('summary', '')}", ""]
    actions = document.get("next_actions", [])
    if type(actions) is list and actions:
        action = actions[0]
        lines.extend([f"Next: {action.get('title', 'Review details')}",
                      f"  {action.get('detail', '')}", ""])
    identity = document.get("identity", {})
    canonical = document.get("canonical", {})
    lines.append("Technical details:")
    if type(identity) is dict and identity.get("commit_sha"):
        lines.append(f"  Commit: {identity['commit_sha']}")
    lines.append(f"  State: {canonical.get('state', BLOCKED)}")
    lines.append(f"  Readiness: {canonical.get('readiness', READINESS_NOT_READY)}")
    return "\n".join(lines) + "\n"


def inspect(repo: str, *, signer: Any | None = None,
            identity: Any | None = None) -> dict[str, Any]:
    """Read exact-HEAD state without running checks.

    ``signer`` is accepted only for a separate trusted read-only status domain.
    MCP and the Ready UI never pass one, so they cannot turn stored rows into an
    authenticated Ready claim.
    """

    if identity is None:
        try:
            found = identity_module.repository_identity(repo, allow_dirty=True)
        except identity_module.IdentityError as error:
            return from_problem(str(error))
    elif type(identity) is not identity_module.Identity:
        raise ReadyError("identity must be an exact repository Identity")
    else:
        found = identity
    if found.dirty:
        document = from_problem(
            "the worktree has uncommitted changes, so no recorded attempt "
            "describes the complete change now on disk",
            ("commit or stash the changes, then run Admissible again",),
            reason_code="dirty_worktree",
            summary="Commit or stash the current changes before checking.")
        document["identity"].update({
            "repository": found.repository,
            "commit_sha": found.commit_sha,
            "tree_sha": found.tree_sha,
        })
        return document
    try:
        opened = store_module.open_store(store_module.default_home())
    except store_module.StoreError as error:
        return from_problem(str(error))
    try:
        authenticated_receipt = None
        authenticated_problem = ""
        authenticated_defect = None
        standing = standing_module.current_standing(
            opened, found.repository, found.commit_sha, verifier=signer)
        reported_standing = standing.state
        if (signer is not None
                and (standing.integrity_problem
                     or standing.historical_receipts)):
            authenticated_problem = standing.integrity_problem or (
                "authenticated historical receipts cannot establish current "
                "standing because their durable projection is incomplete")
            attempt = None
        elif (signer is not None
                and reported_standing == standing_module.IMPEACHED
                and not standing.receipts):
            authenticated_defect = standing
            attempt = None
        elif (reported_standing in (
                standing_module.CURRENT, standing_module.IMPEACHED)
                and standing.receipts):
            receipt = max(
                standing.receipts,
                key=lambda item: (item.issued_at, item.receipt_hash))
            if (receipt.repository == found.repository
                    and receipt.commit_sha == found.commit_sha
                    and receipt.tree_sha == found.tree_sha):
                authenticated_receipt = receipt
                attempt = None
            else:
                attempt = None
                reported_standing = standing_module.UNKNOWN
        else:
            attempt = opened.latest_attempt(found.repository, found.commit_sha)
        if (not authenticated_problem
                and reported_standing == standing_module.UNKNOWN
                and opened.receipts_for(found.repository, found.commit_sha)):
            reported_standing = "UNVERIFIED"
    finally:
        opened.close()
    try:
        closing = identity_module.repository_identity(repo, allow_dirty=True)
    except identity_module.IdentityError:
        document = from_problem(
            "repository identity could not be re-read while Ready was inspecting standing",
            ("re-run the status command against the commit that should be checked",),
            reason_code="identity_changed",
            summary="HEAD could not be confirmed while Ready was inspecting this commit.")
        document["identity"].update({
            "repository": found.repository,
            "commit_sha": found.commit_sha,
            "tree_sha": found.tree_sha,
            "applies_to_current_commit": False,
        })
        return document
    if (closing.repository != found.repository
            or closing.commit_sha != found.commit_sha
            or closing.tree_sha != found.tree_sha
            or bool(closing.dirty) != bool(found.dirty)):
        document = from_problem(
            "repository identity changed while Ready was inspecting standing",
            ("re-run the status command against the commit that should be checked",),
            reason_code="identity_changed",
            summary="HEAD moved while Ready was inspecting this commit.")
        document["identity"].update({
            "repository": found.repository,
            "commit_sha": found.commit_sha,
            "tree_sha": found.tree_sha,
            "applies_to_current_commit": False,
        })
        return document
    if authenticated_problem:
        document = from_problem(
            authenticated_problem,
            ("inspect and repair the authenticated admission journal before "
             "relying on standing",),
            reason_code="authenticated_journal_integrity",
            summary=(
                "Authenticated admission history is internally inconsistent."))
        document["identity"].update({
            "repository": found.repository,
            "commit_sha": found.commit_sha,
            "tree_sha": found.tree_sha,
            "applies_to_current_commit": True,
        })
        return document
    if authenticated_defect is not None:
        reasons = [{
            "code": "impeached",
            "subject": item.get("defect_id") or "authenticated defect",
            "detail": item.get("summary") or (
                "Authenticated later evidence impeached this commit."),
        } for item in authenticated_defect.defects]
        if not reasons:
            reasons = [{
                "code": "impeached",
                "subject": "authenticated standing",
                "detail": "Authenticated later evidence impeached this commit.",
            }]
        document = from_problem(
            reasons[0]["detail"],
            ("inspect the authenticated defect before changing code",),
            reason_code="impeached",
            summary="This commit has authenticated defects and no admission receipt.")
        document["status"] = "needs_attention"
        document["identity"].update({
            "repository": found.repository,
            "commit_sha": found.commit_sha,
            "tree_sha": found.tree_sha,
            "applies_to_current_commit": True,
        })
        document["canonical"]["standing"] = standing_module.IMPEACHED
        document["reasons"] = reasons
        document["next_actions"] = [_action(
            action_id="inspect_impeachment", title="Inspect the new defect",
            detail=(
                "Review the authenticated defect and dependency impact "
                "before changing code."),
            owner="human", kind="inspect", reason_codes=["impeached"],
            command=f"admissible explain {found.commit_sha}",
            retryable=False)]
        document["agent_can_continue"] = False
        return document
    if authenticated_receipt is not None:
        receipt = authenticated_receipt
        impeached = reported_standing == standing_module.IMPEACHED
        reasons = []
        if impeached:
            reasons = [{
                "code": "impeached",
                "subject": item.get("defect_id") or "authenticated defect",
                "detail": item.get("summary") or (
                    "Authenticated later evidence impeached this admission."),
            } for item in standing.defects]
            if not reasons:
                reasons = [{
                    "code": "impeached",
                    "subject": "authenticated standing",
                    "detail": (
                        "Authenticated later evidence impeached this admission."),
                }]
        canonical = {
            "scope": "developer-workflow-admission",
            "state": CHECKS_PASSED,
            "readiness": READINESS_READY_FOR_ATTESTATION,
            "repository": receipt.repository,
            "commit_sha": receipt.commit_sha,
            "tree_sha": receipt.tree_sha,
            "policy_digest": receipt.policy_digest,
            "class_id": receipt.class_id,
            "attempt_id": receipt.attempt_id or None,
            "reasons": reasons, "remediation": [], "checks": [],
            "independent_reviews": len(receipt.authenticated_reviews),
            "required_independent_reviews": None,
            "exit_code": 0,
        }
        document = from_evaluation(canonical, standing=reported_standing)
        document["canonical"].update({
            "state": "ADMITTED",
            "readiness": READINESS_READY_FOR_ATTESTATION,
            "standing": reported_standing,
            "exit_code": 1 if impeached else 0,
        })
        document["agent_can_continue"] = False
        document["advanced"].update({
            "receipt_hash": receipt.receipt_hash,
            "decision_digest": receipt.decision_digest,
            "check_evidence": "unavailable",
        })
        if impeached:
            document["status"] = "needs_attention"
            document["summary"] = (
                "This commit was admitted, but later evidence impeached it.")
            document["next_actions"] = [_action(
                action_id="inspect_impeachment", title="Inspect the new defect",
                detail=(
                    "Review the authenticated defect and dependency impact "
                    "before changing code."),
                owner="human", kind="inspect", reason_codes=["impeached"],
                command=f"admissible explain {found.commit_sha}",
                retryable=False)]
        else:
            document["status"] = "ready"
            document["summary"] = (
                "This exact commit is admitted, authenticated, and current.")
            document["next_actions"] = []
        return document
    if attempt is None or type(attempt.get("decision")) is not dict:
        document = from_problem(
            "no recorded evaluation exists for this exact commit",
            ("run 'admissible check' for this commit",),
            reason_code="not_checked",
            summary="This exact commit has not been checked yet.")
        document["status"] = "needs_attention"
        document["identity"].update({
            "repository": found.repository,
            "commit_sha": found.commit_sha,
            "tree_sha": found.tree_sha,
        })
        document["next_actions"] = [_action(
            action_id="run_check", title="Check this commit",
            detail="Run the configured deterministic checks for exact HEAD.",
            owner="agent_or_human", kind="check",
            reason_codes=["not_checked"], command="admissible check",
            retryable=True)]
        document["agent_can_continue"] = True
        return document
    decision = attempt["decision"]
    if not _unsigned_identities_match(found, attempt, decision):
        document = from_problem(
            "stored attempt identity does not match this exact commit",
            ("run 'admissible check' for the current exact HEAD",),
            reason_code="stored_attempt_identity_mismatch",
            summary="The stored attempt does not describe this exact commit.")
        document["identity"].update({
            "repository": found.repository,
            "commit_sha": found.commit_sha,
            "tree_sha": found.tree_sha,
            "applies_to_current_commit": False,
        })
        return document
    canonical = dict(decision)
    canonical.setdefault("repository", found.repository)
    canonical.setdefault("commit_sha", found.commit_sha)
    canonical.setdefault("tree_sha", attempt.get("tree_sha") or found.tree_sha)
    canonical.setdefault("policy_digest", attempt.get("policy_digest"))
    canonical.setdefault("class_id", attempt.get("class_id"))
    canonical["attempt_id"] = attempt["attempt_id"]
    document = from_evaluation(canonical, standing=reported_standing)
    if reported_standing == standing_module.CURRENT:
        document["status"] = "ready"
        document["summary"] = (
            "This exact commit is admitted, authenticated, and current.")
        document["canonical"].update({
            "state": "ADMITTED",
            "readiness": READINESS_READY_FOR_ATTESTATION,
            "standing": standing_module.CURRENT,
            "exit_code": 0,
        })
        document["next_actions"] = []
        document["agent_can_continue"] = False
    elif reported_standing == standing_module.IMPEACHED:
        document["status"] = "needs_attention"
        document["summary"] = (
            "This commit was admitted, but later evidence impeached it.")
        document["canonical"].update({
            "state": "ADMITTED",
            "standing": standing_module.IMPEACHED,
            "exit_code": 1,
        })
        document["next_actions"] = [_action(
            action_id="inspect_impeachment", title="Inspect the new defect",
            detail="Review the defect and dependency impact before changing code.",
            owner="human", kind="inspect", reason_codes=["impeached"],
            command=f"admissible explain {found.commit_sha}", retryable=False)]
        document["agent_can_continue"] = False
    return document


def run_check(repo: str, *, no_cache: bool = False,
              evidence: Mapping[str, Any] | None = None,
              class_id: str | None = None,
              config_path: str | None = None,
              expected_policy_digest: str | None = None,
              package: Mapping[str, Any] | None = None,
              ) -> tuple[int, dict[str, Any]]:
    """Invoke the public check command in-process and return its JSON contract."""

    if package is not None:
        if type(package) is not dict:
            raise ReadyError("package must be a JSON object")
        try:
            found = identity_module.repository_identity(repo)
        except identity_module.IdentityError as error:
            raise ReadyError(str(error)) from None
        if (package.get("repository") != found.repository
                or package.get("commit_sha") != found.commit_sha
                or package.get("tree_sha") != found.tree_sha
                or package.get("class_id") != class_id
                or package.get("policy_digest") != expected_policy_digest
                or package.get("config_path") != config_path):
            return 2, from_problem(
                "work package does not match this exact repository HEAD",
                ("request a new work package for the current HEAD, then recheck",),
                reason_code="work_package_identity_mismatch",
                summary="The packaged artifact identity is not the current HEAD.")

    ambient = runner_module.ambient_signing_credentials()
    if ambient:
        return 2, from_problem(
            "a process that can start candidate checks must not hold "
            "admission, review, or evaluation credentials",
            ("unset the signing credentials and run the check again",),
            reason_code="signing_credential_present",
            summary="A signing credential is present, so no check was run.")
    from . import cli as cli_module

    argv = ["check", "--repo", repo, "--json"]
    if class_id is not None:
        if type(class_id) is not str or not class_id.strip():
            raise ReadyError("class_id must be a non-empty string")
        argv.extend(("--class", class_id))
    if config_path is not None:
        if type(config_path) is not str or not config_path.strip():
            raise ReadyError("config_path must be a non-empty string")
        argv.extend(("--config", config_path))
    if expected_policy_digest is not None:
        if (type(expected_policy_digest) is not str
                or len(expected_policy_digest) != 64
                or any(item not in "0123456789abcdef"
                       for item in expected_policy_digest)):
            raise ReadyError("policy_digest must be a lowercase SHA-256 digest")
    if no_cache:
        argv.append("--no-cache")
    evidence_path: str | None = None
    if evidence is not None:
        if type(evidence) is not dict:
            raise ReadyError("evidence must be a JSON object")
        try:
            encoded = (json.dumps(evidence, separators=(",", ":"),
                                  sort_keys=True, ensure_ascii=True)
                       + "\n").encode("utf-8")
        except (TypeError, ValueError) as error:
            raise ReadyError(f"evidence is not JSON-serializable: {error}") from None
        if len(encoded) > evidence_module.MAX_EVIDENCE_BYTES:
            raise ReadyError(
                f"evidence is above the {evidence_module.MAX_EVIDENCE_BYTES}-byte ceiling")
        descriptor, evidence_path = tempfile.mkstemp(
            prefix="admissible-ready-evidence-", suffix=".json")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
        except BaseException:
            try:
                os.unlink(evidence_path)
            except OSError:
                pass
            raise
        argv.extend(("--evidence", evidence_path))
    out, err = io.StringIO(), io.StringIO()
    try:
        code = cli_module.main(argv, stdout=out, stderr=err)
    finally:
        if evidence_path is not None:
            try:
                os.unlink(evidence_path)
            except OSError:
                pass
    try:
        document = json.loads(out.getvalue())
    except json.JSONDecodeError as error:
        return 2, from_problem(
            f"the check returned no valid Ready document: {error}")
    if type(document) is not dict or document.get("schema") != READY_SCHEMA:
        return 2, from_problem("the check returned an unsupported document")
    checked_identity = document.get("identity")
    if package is not None and (
            type(checked_identity) is not dict
            or checked_identity.get("repository") != package.get("repository")
            or checked_identity.get("commit_sha") != package.get("commit_sha")
            or checked_identity.get("tree_sha") != package.get("tree_sha")
            or checked_identity.get("class_id") != package.get("class_id")
            or checked_identity.get("policy_digest") != package.get("policy_digest")):
        refused = from_problem(
            "the completed check does not match the work package identity",
            ("request a new work package for the current HEAD, then recheck",),
            reason_code="work_package_identity_mismatch",
            summary="The check ran against a different artefact than the work package.")
        if type(checked_identity) is dict:
            for key in ("repository", "commit_sha", "tree_sha", "class_id",
                        "policy_digest", "attempt_id"):
                refused["identity"][key] = checked_identity.get(key)
        return 2, refused
    if expected_policy_digest is not None and (
            type(checked_identity) is not dict
            or checked_identity.get("class_id") != class_id
            or checked_identity.get("policy_digest") != expected_policy_digest):
        refused = from_problem(
            "the completed check does not match the work package policy",
            ("request a new work package for the current policy, then recheck",),
            reason_code="work_package_identity_mismatch",
            summary="The check used a different class or policy than the work package.")
        if type(checked_identity) is dict:
            for key in ("repository", "commit_sha", "tree_sha", "class_id",
                        "policy_digest", "attempt_id"):
                refused["identity"][key] = checked_identity.get(key)
        return 2, refused
    return code, document


def work_package(repo: str, task: str, *, class_id: str | None = None,
                 config_path: str | None = None,
                 principal: str | None = None,
                 issue_nonce: str | None = None) -> dict[str, Any]:
    """Build a bounded agent contract for exact HEAD without launching an agent."""

    if type(task) is not str or not task.strip() or len(task) > 8000:
        raise ReadyError("task must be a non-empty string of at most 8000 characters")
    try:
        found = identity_module.repository_identity(repo)
    except identity_module.IdentityError as error:
        raise ReadyError(str(error)) from None
    state = inspect(repo, identity=found)
    state_identity = state.get("identity", {})
    if type(state_identity) is not dict:
        raise ReadyError("Ready state did not contain an exact identity")
    if (state_identity.get("repository") not in (None, found.repository)
            or state_identity.get("commit_sha") not in (None, found.commit_sha)
            or state_identity.get("tree_sha") not in (None, found.tree_sha)):
        raise ReadyError("Ready state does not describe this exact repository HEAD")
    selected_class = class_id or state_identity.get("class_id")
    selected_config = config_path or CONFIG_FILENAME
    try:
        resolved_config = config_file(found.root, selected_config)
        parsed = load_config(found.root, selected_config)
        artifact_class = parsed.select_class(selected_class)
    except ValueError as error:
        raise ReadyError(str(error)) from None
    recorded_class = state_identity.get("class_id")
    recorded_policy = state_identity.get("policy_digest")
    if recorded_class is not None and recorded_class != artifact_class.id:
        raise ReadyError(
            "the requested class does not match the latest exact-HEAD attempt")
    if (recorded_policy is not None
            and recorded_policy != artifact_class.policy_digest):
        raise ReadyError(
            "the requested policy does not match the latest exact-HEAD attempt")
    relative_config = resolved_config.relative_to(found.root).as_posix()
    policy_digest = recorded_policy or artifact_class.policy_digest
    bound_class = recorded_class or artifact_class.id
    if principal is not None and (
            type(principal) is not str or not principal.strip()
            or len(principal) > 120):
        raise ReadyError("principal must be a non-empty bounded string")
    if issue_nonce is not None and (
            type(issue_nonce) is not str or not issue_nonce.strip()
            or len(issue_nonce) > 200):
        raise ReadyError("issue_nonce must be a non-empty bounded string")
    package_id = hashlib.sha256(json.dumps({
        "repository": found.repository,
        "commit_sha": found.commit_sha,
        "tree_sha": found.tree_sha,
        "policy_digest": policy_digest,
        "class_id": bound_class,
        "config_path": relative_config,
        "task": task.strip(),
        "principal": (principal or "").strip(),
        "issue_nonce": (issue_nonce or "").strip(),
    }, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "schema": "admissible/v0.7/agent-work-package",
        "package_id": package_id,
        "task": task.strip(),
        "identity": {
            "repository": found.repository,
            "commit_sha": found.commit_sha,
            "tree_sha": found.tree_sha,
            "policy_digest": policy_digest,
            "class_id": bound_class,
            "config_path": relative_config,
        },
        "readiness": state,
        "capabilities": {
            "allowed": ["read", "edit", "test", "commit", "request_check"],
            "forbidden": [
                "sign", "finalize", "trust_policy", "revoke_policy",
                "attest_review", "attest_evaluation", "impeach", "merge",
                "deploy",
            ],
        },
        "completion": {
            "requires_clean_tree": True,
            "requires_new_commit_after_edits": True,
            "requires_admissible_check": True,
            "check_arguments": {
                "package_id": package_id,
                "class_id": bound_class,
                "policy_digest": policy_digest,
                "config_path": relative_config,
            },
            "stop_when_action_owner_is_not": "agent_or_human",
        },
    }
