"""Kernel-issued authentication for the composed I/R/C admissibility result."""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

from fcd import __version__ as BASE_VERSION
from fcd.core import Enforcer
from fcd.head import (
    HeadReceipt,
    HeadRefused,
    HeadSigner,
    HeadVerifier,
    JournalHead,
    MonotoneHeadRegistry,
    compute_journal_head,
    head_receipt_from_dict,
    head_receipt_to_dict,
    make_receipt,
    verify_current,
)
from fcd.journal import canonical_json

from .calibration import CalibrationAuthority
from .core import Admission

__all__ = [
    "AdmissibilityReceipt",
    "ReceiptIssueError",
    "ReceiptVerificationError",
    "admissibility_receipt_from_dict",
    "admissibility_receipt_to_dict",
    "issue_admissibility_receipt",
    "verify_admissibility_receipt",
]

_HEX64 = re.compile(r"[0-9a-f]{64}")
_NAMESPACE_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_RECEIPT_KEYS = frozenset({
    "base_version", "journal_namespace", "subject_id", "artifact_hash",
    "sealed", "mediated", "tainted", "impeached", "fcd_head", "rga_head",
    "calibration_head", "issued_at", "algorithm", "key_id", "signature",
    "receipt_hash",
})


def _namespace(value: object) -> str:
    if type(value) is not str or _NAMESPACE_RE.fullmatch(value) is None:
        raise ValueError("journal namespace must match [A-Za-z0-9._-]{1,64}")
    return value


def _journal_ids(namespace: str) -> tuple[str, str, str]:
    safe = _namespace(namespace)
    return (
        f"admissible/{safe}/fcd",
        f"admissible/{safe}/rga",
        f"admissible/{safe}/calibration",
    )


class ReceiptIssueError(ValueError):
    """The kernel could not issue and anchor a composed receipt."""


class ReceiptVerificationError(ValueError):
    """A composed receipt is unauthenticated, stale, or cross-wired."""


def _identity(value: object, *, optional: bool = False) -> str:
    if optional and type(value) is str and value == "":
        return ""
    if type(value) is not str or not value:
        raise ValueError("receipt identities must be non-empty plain strings")
    return value


def _flag(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError("receipt predicates must be plain booleans")
    return value


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise ValueError("receipt digests must be lowercase 64-hex strings")
    return value


def _nonnegative_int(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("receipt issued_at must be a non-negative plain integer")
    return value


def _head_payload(receipt: HeadReceipt) -> dict:
    return head_receipt_to_dict(receipt)


@dataclass(frozen=True)
class AdmissibilityReceipt:
    base_version: str
    journal_namespace: str
    subject_id: str
    artifact_hash: str
    sealed: bool
    mediated: bool
    tainted: bool
    impeached: bool
    fcd_head: HeadReceipt
    rga_head: HeadReceipt
    calibration_head: HeadReceipt
    issued_at: int
    algorithm: str
    key_id: str
    signature: str
    receipt_hash: str

    def __post_init__(self) -> None:
        _identity(self.base_version)
        journal_ids = _journal_ids(self.journal_namespace)
        _identity(self.subject_id)
        _identity(self.artifact_hash, optional=True)
        for value in (self.sealed, self.mediated, self.tainted, self.impeached):
            _flag(value)
        if ((self.sealed and _HEX64.fullmatch(self.artifact_hash) is None)
                or (not self.sealed and self.artifact_hash != "")):
            raise ValueError("receipt artifact identity disagrees with sealed")
        for head, journal_id in zip(
            (self.fcd_head, self.rga_head, self.calibration_head), journal_ids
        ):
            if type(head) is not HeadReceipt or head.journal_id != journal_id:
                raise ValueError("receipt heads do not match the composed journal set")
        _nonnegative_int(self.issued_at)
        if _identity(self.algorithm) != "hmac-sha256":
            raise ValueError("unsupported receipt signature algorithm")
        _identity(self.key_id)
        _hex64(self.signature)
        _hex64(self.receipt_hash)

    def predicates_ok(self) -> bool:
        return (self.sealed and self.mediated
                and not self.tainted and not self.impeached)


def admissibility_receipt_to_dict(receipt: AdmissibilityReceipt) -> dict:
    if type(receipt) is not AdmissibilityReceipt:
        raise TypeError("receipt must be an AdmissibilityReceipt")
    return {
        "base_version": receipt.base_version,
        "journal_namespace": receipt.journal_namespace,
        "subject_id": receipt.subject_id,
        "artifact_hash": receipt.artifact_hash,
        "sealed": receipt.sealed,
        "mediated": receipt.mediated,
        "tainted": receipt.tainted,
        "impeached": receipt.impeached,
        "fcd_head": head_receipt_to_dict(receipt.fcd_head),
        "rga_head": head_receipt_to_dict(receipt.rga_head),
        "calibration_head": head_receipt_to_dict(receipt.calibration_head),
        "issued_at": receipt.issued_at,
        "algorithm": receipt.algorithm,
        "key_id": receipt.key_id,
        "signature": receipt.signature,
        "receipt_hash": receipt.receipt_hash,
    }


def admissibility_receipt_from_dict(value: dict) -> AdmissibilityReceipt:
    if type(value) is not dict or frozenset(value) != _RECEIPT_KEYS:
        raise ValueError("admissibility receipt must be a closed plain JSON object")
    try:
        fields = dict(value)
        fields["fcd_head"] = head_receipt_from_dict(fields["fcd_head"])
        fields["rga_head"] = head_receipt_from_dict(fields["rga_head"])
        fields["calibration_head"] = head_receipt_from_dict(
            fields["calibration_head"])
        return AdmissibilityReceipt(**fields)
    except (TypeError, ValueError):
        raise ValueError(
            "admissibility receipt must be a closed plain JSON object") from None


def _unsigned_payload(
    *, base_version: str, journal_namespace: str, subject_id: str,
    artifact_hash: str,
    sealed: bool, mediated: bool, tainted: bool, impeached: bool,
    fcd_head: HeadReceipt, rga_head: HeadReceipt,
    calibration_head: HeadReceipt, issued_at: int,
    algorithm: str, key_id: str,
) -> dict:
    return {
        # Pinned to the kernel version this receipt reports in base_version.
        # Bumping it would make every composed receipt already issued fail to
        # verify, which is exactly the silence this layer exists to remove.
        "domain": "admissible/v0.5/composed-receipt",
        "base_version": base_version,
        "journal_namespace": journal_namespace,
        "subject_id": subject_id,
        "artifact_hash": artifact_hash,
        "sealed": sealed,
        "mediated": mediated,
        "tainted": tainted,
        "impeached": impeached,
        "heads": {
            "fcd": _head_payload(fcd_head),
            "rga": _head_payload(rga_head),
            "calibration": _head_payload(calibration_head),
        },
        "issued_at": issued_at,
        "algorithm": algorithm,
        "key_id": key_id,
    }


def _receipt_unsigned(receipt: AdmissibilityReceipt) -> dict:
    return _unsigned_payload(
        base_version=receipt.base_version,
        journal_namespace=receipt.journal_namespace,
        subject_id=receipt.subject_id,
        artifact_hash=receipt.artifact_hash,
        sealed=receipt.sealed,
        mediated=receipt.mediated,
        tainted=receipt.tainted,
        impeached=receipt.impeached,
        fcd_head=receipt.fcd_head,
        rga_head=receipt.rga_head,
        calibration_head=receipt.calibration_head,
        issued_at=receipt.issued_at,
        algorithm=receipt.algorithm,
        key_id=receipt.key_id,
    )


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _require_stack(enforcer: Enforcer, admission: Admission,
                   calibration: CalibrationAuthority) -> None:
    if (type(enforcer) is not Enforcer or type(admission) is not Admission
            or type(calibration) is not CalibrationAuthority
            or admission.fcd is not enforcer or calibration.adm is not admission):
        raise ValueError(
            "admissibility receipt requires one composed authority stack")


def _next_head_receipt(head: JournalHead, registry: MonotoneHeadRegistry,
                       signer: HeadSigner, issued_at: int) -> HeadReceipt:
    current = registry.current(head.journal_id)
    if (current is not None and current.event_count == head.event_count
            and hmac.compare_digest(current.head_digest, head.head_digest)):
        return current
    previous_hash = "" if current is None else current.receipt_hash
    return make_receipt(
        head, previous_hash, issued_at, signer, previous=current)


def _state_fields(subject_id: str, admission: Admission,
                  calibration: CalibrationAuthority) -> dict:
    seal = admission.sealed.get(subject_id)
    return {
        "artifact_hash": "" if seal is None else seal.artifact_hash,
        "sealed": seal is not None,
        "mediated": calibration.mediated(subject_id),
        "tainted": admission.tainted(subject_id),
        "impeached": calibration.impeached(subject_id),
    }


def issue_admissibility_receipt(
    subject_id: str,
    enforcer: Enforcer,
    admission: Admission,
    calibration: CalibrationAuthority,
    registry: MonotoneHeadRegistry,
    signer: HeadSigner,
    *,
    journal_namespace: str,
    issued_at: int,
    verifier: HeadVerifier | None = None,
) -> AdmissibilityReceipt:
    """Derive, sign, and atomically anchor the current composed kernel result."""

    _identity(subject_id)
    journal_ids = _journal_ids(journal_namespace)
    _require_stack(enforcer, admission, calibration)
    if type(registry) is not MonotoneHeadRegistry:
        raise TypeError("registry must be a MonotoneHeadRegistry")
    at = _nonnegative_int(issued_at)
    chosen: HeadVerifier = verifier if verifier is not None else signer  # type: ignore[assignment]
    if not hasattr(chosen, "verify_signature"):
        raise TypeError("receipt issuance requires a verifier")

    fcd_events = tuple(enforcer.events)
    rga_events = tuple(admission.events)
    calibration_events = tuple(calibration.events)
    heads = (
        compute_journal_head(journal_ids[0], fcd_events),
        compute_journal_head(journal_ids[1], rga_events),
        compute_journal_head(journal_ids[2], calibration_events),
    )
    head_receipts = tuple(
        _next_head_receipt(head, registry, signer, at) for head in heads)

    fields = {
        "base_version": BASE_VERSION,
        "journal_namespace": journal_namespace,
        "subject_id": subject_id,
        **_state_fields(subject_id, admission, calibration),
        "fcd_head": head_receipts[0],
        "rga_head": head_receipts[1],
        "calibration_head": head_receipts[2],
        "issued_at": at,
    }
    try:
        algorithm = _identity(signer.algorithm)
        key_id = _identity(signer.key_id)
        unsigned = _unsigned_payload(
            **fields, algorithm=algorithm, key_id=key_id)
        signature = signer.sign(canonical_json(unsigned).encode("utf-8"))
        _hex64(signature)
        receipt_hash = _digest(dict(unsigned, signature=signature))
        candidate = AdmissibilityReceipt(
            **fields, algorithm=algorithm, key_id=key_id,
            signature=signature, receipt_hash=receipt_hash)
    except Exception:
        raise ReceiptIssueError("admissibility receipt signing failed") from None

    if (tuple(enforcer.events) != fcd_events
            or tuple(admission.events) != rga_events
            or tuple(calibration.events) != calibration_events
            or _state_fields(subject_id, admission, calibration) != {
                key: fields[key] for key in (
                    "artifact_hash", "sealed", "mediated", "tainted", "impeached")
            }):
        raise ReceiptIssueError(
            "kernel changed while issuing admissibility receipt")

    try:
        registry.accept_batch(head_receipts, chosen)
    except HeadRefused:
        raise ReceiptIssueError("admissibility journal heads were not accepted") from None
    try:
        verify_admissibility_receipt(
            candidate, enforcer, admission, calibration, registry, chosen)
    except ReceiptVerificationError:
        raise ReceiptIssueError(
            "kernel changed while issuing admissibility receipt") from None
    return candidate


def verify_admissibility_receipt(
    receipt: AdmissibilityReceipt,
    enforcer: Enforcer,
    admission: Admission,
    calibration: CalibrationAuthority,
    registry: MonotoneHeadRegistry,
    verifier: HeadVerifier,
) -> bool:
    """Authenticate the receipt and bind it to the exact current I/R/C state."""

    if type(receipt) is not AdmissibilityReceipt:
        raise ReceiptVerificationError("receipt authentication failed")
    try:
        unsigned = _receipt_unsigned(receipt)
        signature_ok = verifier.verify_signature(
            canonical_json(unsigned).encode("utf-8"), receipt.key_id,
            receipt.algorithm, receipt.signature)
        hash_ok = hmac.compare_digest(
            _digest(dict(unsigned, signature=receipt.signature)),
            receipt.receipt_hash)
    except Exception:
        signature_ok = hash_ok = False
    if not signature_ok or not hash_ok:
        raise ReceiptVerificationError("receipt authentication failed")

    try:
        _require_stack(enforcer, admission, calibration)
        if receipt.base_version != BASE_VERSION:
            raise ValueError
        journal_ids = _journal_ids(receipt.journal_namespace)
        verify_current(journal_ids[0], tuple(enforcer.events),
                       receipt.fcd_head, registry, verifier)
        verify_current(journal_ids[1], tuple(admission.events),
                       receipt.rga_head, registry, verifier)
        verify_current(journal_ids[2], tuple(calibration.events),
                       receipt.calibration_head, registry, verifier)
        seal = admission.sealed.get(receipt.subject_id)
        expected = (
            "" if seal is None else seal.artifact_hash,
            seal is not None,
            calibration.mediated(receipt.subject_id),
            admission.tainted(receipt.subject_id),
            calibration.impeached(receipt.subject_id),
        )
        observed = (
            receipt.artifact_hash, receipt.sealed, receipt.mediated,
            receipt.tainted, receipt.impeached,
        )
        if observed != expected:
            raise ValueError
    except Exception:
        raise ReceiptVerificationError(
            "receipt does not describe current kernel state") from None
    return True
