"""Signed human-review evidence, kept apart from automation.

A green automated check and a human verdict are two records. This module
never folds them into one boolean. Admission that requires a human still
reads the human receipt; automation remains visible either way.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .head import HMACSHA256Signer
from .journal import canonical_json

__all__ = [
    "HumanReviewError",
    "HumanReviewReceipt",
    "ReviewConclusions",
    "issue_human_review",
    "verify_human_review",
]

_ALGORITHM = "hmac-sha256"
_DOMAIN = "admissible/v0.8/human-review"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_VERDICTS = frozenset({"accept", "reject", "abstain"})


class HumanReviewError(ValueError):
    """A human-review receipt is not well formed, independent, or authentic."""


def _identity(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise HumanReviewError(f"{label} must be a non-empty plain string")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise HumanReviewError(f"{label} must be a non-negative plain integer")
    return value


def _hex64(value: object, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise HumanReviewError(f"{label} must be a lowercase 64-hex string")
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _same_secret(signer: HMACSHA256Signer, secret: bytes) -> bool:
    probe = b"admissible/v0.8/human-review/secret-probe"
    expected = hmac.new(secret, probe, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signer.sign(probe), expected)


@dataclass(frozen=True)
class HumanReviewReceipt:
    artifact_hash: str
    reviewer_id: str
    independent_of: tuple[str, ...]
    scope: str
    verdict: str
    reviewed_at: int
    algorithm: str
    key_id: str
    signature: str
    receipt_hash: str


def _unsigned_payload(
    *,
    artifact_hash: str,
    reviewer_id: str,
    independent_of: tuple[str, ...],
    scope: str,
    verdict: str,
    reviewed_at: int,
    algorithm: str,
    key_id: str,
) -> dict:
    return {
        "domain": _DOMAIN,
        "artifact_hash": artifact_hash,
        "reviewer_id": reviewer_id,
        "independent_of": list(independent_of),
        "scope": scope,
        "verdict": verdict,
        "reviewed_at": reviewed_at,
        "algorithm": algorithm,
        "key_id": key_id,
    }


def issue_human_review(
    *,
    signer: HMACSHA256Signer,
    artifact_hash: str,
    reviewer_id: str,
    independent_of: tuple[str, ...] | list[str],
    scope: str,
    verdict: str,
    reviewed_at: int,
    peer_secrets: Mapping[str, bytes] | None = None,
) -> HumanReviewReceipt:
    if type(signer) is not HMACSHA256Signer:
        raise HumanReviewError("human reviews are issued by HMACSHA256Signer")
    reviewer_id = _identity(reviewer_id, "reviewer_id")
    if signer.key_id != reviewer_id:
        raise HumanReviewError("reviewer_id must match the signing key")
    artifact_hash = _hex64(artifact_hash, "artifact_hash")
    scope = _identity(scope, "scope")
    verdict = _identity(verdict, "verdict")
    if verdict not in _VERDICTS:
        raise HumanReviewError("verdict must be accept, reject, or abstain")
    at = _nonnegative_int(reviewed_at, "reviewed_at")
    if type(independent_of) not in (tuple, list):
        raise HumanReviewError("independent_of must be a tuple of key ids")
    peers = tuple(_identity(item, "independent_of") for item in independent_of)
    if reviewer_id in peers:
        raise HumanReviewError("a reviewer cannot be independent of itself")
    if peer_secrets:
        if type(peer_secrets) is not dict:
            raise HumanReviewError("peer_secrets must be a plain dictionary")
        for peer_id, secret in dict.items(peer_secrets):
            _identity(peer_id, "peer_secrets")
            if type(secret) is not bytes or not secret:
                raise HumanReviewError("peer secrets must be non-empty plain bytes")
            if _same_secret(signer, secret):
                raise HumanReviewError(
                    "reviewer secret matches a generator or gateway secret")
    algorithm = signer.algorithm
    if algorithm != _ALGORITHM:
        raise HumanReviewError("unsupported human-review signature algorithm")
    unsigned = _unsigned_payload(
        artifact_hash=artifact_hash,
        reviewer_id=reviewer_id,
        independent_of=peers,
        scope=scope,
        verdict=verdict,
        reviewed_at=at,
        algorithm=algorithm,
        key_id=signer.key_id,
    )
    try:
        signature = signer.sign(canonical_json(unsigned).encode("utf-8"))
    except Exception as exc:
        raise HumanReviewError("human-review signing failed") from exc
    core = dict(unsigned, signature=signature)
    return HumanReviewReceipt(
        artifact_hash=artifact_hash,
        reviewer_id=reviewer_id,
        independent_of=peers,
        scope=scope,
        verdict=verdict,
        reviewed_at=at,
        algorithm=algorithm,
        key_id=signer.key_id,
        signature=signature,
        receipt_hash=_digest(core),
    )


def verify_human_review(receipt: HumanReviewReceipt, verifier: Any) -> bool:
    if type(receipt) is not HumanReviewReceipt:
        raise HumanReviewError("not a human-review receipt")
    unsigned = _unsigned_payload(
        artifact_hash=receipt.artifact_hash,
        reviewer_id=receipt.reviewer_id,
        independent_of=receipt.independent_of,
        scope=receipt.scope,
        verdict=receipt.verdict,
        reviewed_at=receipt.reviewed_at,
        algorithm=receipt.algorithm,
        key_id=receipt.key_id,
    )
    payload = canonical_json(unsigned).encode("utf-8")
    try:
        ok = verifier.verify_signature(
            payload, receipt.key_id, receipt.algorithm, receipt.signature)
    except Exception:
        ok = False
    if not ok:
        raise HumanReviewError("human-review signature is invalid")
    expected = _digest(dict(unsigned, signature=receipt.signature))
    if not hmac.compare_digest(expected, receipt.receipt_hash):
        raise HumanReviewError("human-review receipt hash is invalid")
    return True


@dataclass(frozen=True)
class ReviewConclusions:
    automation: dict[str, Any]
    human: HumanReviewReceipt | None

    def as_view(self) -> dict[str, Any]:
        if type(self.automation) is not dict:
            raise HumanReviewError("automation conclusions must be a plain dict")
        human_view = None
        if self.human is not None:
            if type(self.human) is not HumanReviewReceipt:
                raise HumanReviewError("human conclusion must be a HumanReviewReceipt")
            human_view = {
                "reviewer_id": self.human.reviewer_id,
                "artifact_hash": self.human.artifact_hash,
                "scope": self.human.scope,
                "verdict": self.human.verdict,
                "reviewed_at": self.human.reviewed_at,
            }
        return {
            "automation": dict(self.automation),
            "human": human_view,
            "unexamined": None if self.human is not None else "human",
        }

    def admitted(self, require_human: bool) -> bool:
        if type(self.automation) is not dict:
            raise HumanReviewError("automation conclusions must be a plain dict")
        automation_ok = self.automation.get("passed") is True
        if not require_human:
            return automation_ok
        if type(self.human) is not HumanReviewReceipt:
            return False
        return automation_ok and self.human.verdict == "accept"
