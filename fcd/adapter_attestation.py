"""Authenticated execution-adapter receipts.

Observe still writes m_exec from a report. This module is the independent
witness for that report: a gateway key, not the worker, signs attempt, nonce,
package hash, model revision, and provider request id. Replay of those
bindings fails closed. An unsigned observation is labeled route identity and
is not this witness.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any, Callable

from .core import Enforcer
from .head import HMACSHA256Signer
from .journal import canonical_json

__all__ = [
    "AdapterIssueError",
    "AdapterReplayError",
    "AdapterReplayLog",
    "AdapterVerificationError",
    "AttestingGateway",
    "AuthenticatedAdapterReceipt",
    "ExecutionFence",
    "InferenceGateway",
    "ProviderCredentials",
    "ProviderObservation",
    "issue_adapter_receipt",
    "observe_attested",
    "route_identity",
    "verify_adapter_receipt",
]

_ALGORITHM = "hmac-sha256"
_DOMAIN = "admissible/v0.8/adapter-receipt"
_HEX64 = re.compile(r"[0-9a-f]{64}")


class AdapterIssueError(ValueError):
    """The gateway refused to issue an adapter receipt."""


class AdapterVerificationError(ValueError):
    """A signed adapter receipt failed authentication or binding."""


class AdapterReplayError(ValueError):
    """An adapter receipt reused a spent attempt, nonce, or provider request."""


def _identity(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise AdapterIssueError(f"{label} must be a non-empty plain string")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise AdapterIssueError(f"{label} must be a non-negative plain integer")
    return value


def _hex64(value: object, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise AdapterIssueError(f"{label} must be a lowercase 64-hex string")
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ProviderObservation:
    executor_id: str
    run_id: str
    package_hash_observed: str
    continuation_hash: str
    executed_provider: str
    executed_model: str
    model_revision: str
    provider_request_id: str
    audit_ref: str = ""


@dataclass(frozen=True)
class AuthenticatedAdapterReceipt:
    attempt_id: str
    nonce: str
    executor_id: str
    run_id: str
    package_hash_observed: str
    continuation_hash: str
    executed_provider: str
    executed_model: str
    model_revision: str
    provider_request_id: str
    issued_at: int
    algorithm: str
    key_id: str
    signature: str
    receipt_hash: str
    identity_kind: str
    audit_ref: str = ""


class AdapterReplayLog:
    """Process-local spent-binding log. Not a durable registry."""

    def __init__(self) -> None:
        self._attempt_ids: set[str] = set()
        self._nonces: set[str] = set()
        self._requests: set[str] = set()

    def remember(self, attempt_id: str, nonce: str, provider_request_id: str) -> None:
        if (attempt_id in self._attempt_ids or nonce in self._nonces
                or provider_request_id in self._requests):
            raise AdapterReplayError("adapter receipt replay")
        self._attempt_ids.add(attempt_id)
        self._nonces.add(nonce)
        self._requests.add(provider_request_id)


def _unsigned_payload(
    *,
    attempt_id: str,
    nonce: str,
    executor_id: str,
    run_id: str,
    package_hash_observed: str,
    continuation_hash: str,
    executed_provider: str,
    executed_model: str,
    model_revision: str,
    provider_request_id: str,
    issued_at: int,
    algorithm: str,
    key_id: str,
    audit_ref: str = "",
) -> dict:
    return {
        "domain": _DOMAIN,
        "attempt_id": attempt_id,
        "nonce": nonce,
        "executor_id": executor_id,
        "run_id": run_id,
        "package_hash_observed": package_hash_observed,
        "continuation_hash": continuation_hash,
        "executed_provider": executed_provider,
        "executed_model": executed_model,
        "model_revision": model_revision,
        "provider_request_id": provider_request_id,
        "issued_at": issued_at,
        "algorithm": algorithm,
        "key_id": key_id,
        "audit_ref": audit_ref,
    }


def issue_adapter_receipt(
    *,
    attempt_id: str,
    nonce: str,
    observation: ProviderObservation,
    signer: HMACSHA256Signer,
    issued_at: int,
) -> AuthenticatedAdapterReceipt:
    if type(observation) is not ProviderObservation:
        raise AdapterIssueError("observation must be a ProviderObservation")
    if type(signer) is not HMACSHA256Signer:
        raise AdapterIssueError("adapter receipts are issued by HMACSHA256Signer")
    attempt_id = _identity(attempt_id, "attempt_id")
    nonce = _identity(nonce, "nonce")
    model_revision = _identity(observation.model_revision, "model_revision")
    provider_request_id = _identity(
        observation.provider_request_id, "provider_request_id")
    executed_provider = _identity(observation.executed_provider, "executed_provider")
    executed_model = _identity(observation.executed_model, "executed_model")
    run_id = _identity(observation.run_id, "run_id")
    package_hash = _hex64(observation.package_hash_observed, "package_hash_observed")
    continuation = _hex64(observation.continuation_hash, "continuation_hash")
    audit_ref = observation.audit_ref if type(observation.audit_ref) is str else ""
    at = _nonnegative_int(issued_at, "issued_at")
    algorithm = signer.algorithm
    if algorithm != _ALGORITHM:
        raise AdapterIssueError("unsupported adapter signature algorithm")
    key_id = _identity(signer.key_id, "key_id")
    unsigned = _unsigned_payload(
        attempt_id=attempt_id,
        nonce=nonce,
        executor_id=key_id,
        run_id=run_id,
        package_hash_observed=package_hash,
        continuation_hash=continuation,
        executed_provider=executed_provider,
        executed_model=executed_model,
        model_revision=model_revision,
        provider_request_id=provider_request_id,
        issued_at=at,
        algorithm=algorithm,
        key_id=key_id,
        audit_ref=audit_ref,
    )
    try:
        signature = signer.sign(canonical_json(unsigned).encode("utf-8"))
    except Exception as exc:
        raise AdapterIssueError("adapter receipt signing failed") from exc
    if _HEX64.fullmatch(signature) is None:
        raise AdapterIssueError("adapter signature must be lowercase 64-hex")
    core = dict(unsigned, signature=signature)
    return AuthenticatedAdapterReceipt(
        attempt_id=attempt_id,
        nonce=nonce,
        executor_id=key_id,
        run_id=run_id,
        package_hash_observed=package_hash,
        continuation_hash=continuation,
        executed_provider=executed_provider,
        executed_model=executed_model,
        model_revision=model_revision,
        provider_request_id=provider_request_id,
        issued_at=at,
        algorithm=algorithm,
        key_id=key_id,
        signature=signature,
        receipt_hash=_digest(core),
        identity_kind="attested",
        audit_ref=audit_ref,
    )


def route_identity(observation: ProviderObservation) -> AuthenticatedAdapterReceipt:
    if type(observation) is not ProviderObservation:
        raise AdapterIssueError("observation must be a ProviderObservation")
    return AuthenticatedAdapterReceipt(
        attempt_id="",
        nonce="",
        executor_id=observation.executor_id if type(observation.executor_id) is str else "",
        run_id=observation.run_id if type(observation.run_id) is str else "",
        package_hash_observed=observation.package_hash_observed
        if type(observation.package_hash_observed) is str else "",
        continuation_hash=observation.continuation_hash
        if type(observation.continuation_hash) is str else "",
        executed_provider=observation.executed_provider
        if type(observation.executed_provider) is str else "",
        executed_model=observation.executed_model
        if type(observation.executed_model) is str else "",
        model_revision=observation.model_revision
        if type(observation.model_revision) is str else "",
        provider_request_id=observation.provider_request_id
        if type(observation.provider_request_id) is str else "",
        issued_at=0,
        algorithm="",
        key_id="",
        signature="",
        receipt_hash="",
        identity_kind="route",
        audit_ref=observation.audit_ref if type(observation.audit_ref) is str else "",
    )


def verify_adapter_receipt(
    receipt: AuthenticatedAdapterReceipt,
    verifier: Any,
    replay: AdapterReplayLog,
    *,
    attempt_id: str,
    nonce: str,
    package_hash_observed: str,
    continuation_hash: str,
) -> bool:
    if type(receipt) is not AuthenticatedAdapterReceipt:
        raise AdapterVerificationError("not an authenticated adapter receipt")
    if receipt.identity_kind != "attested":
        raise AdapterVerificationError("adapter receipt is not attested")
    if type(replay) is not AdapterReplayLog:
        raise AdapterVerificationError("adapter replay log is required")
    unsigned = _unsigned_payload(
        attempt_id=receipt.attempt_id,
        nonce=receipt.nonce,
        executor_id=receipt.executor_id,
        run_id=receipt.run_id,
        package_hash_observed=receipt.package_hash_observed,
        continuation_hash=receipt.continuation_hash,
        executed_provider=receipt.executed_provider,
        executed_model=receipt.executed_model,
        model_revision=receipt.model_revision,
        provider_request_id=receipt.provider_request_id,
        issued_at=receipt.issued_at,
        algorithm=receipt.algorithm,
        key_id=receipt.key_id,
        audit_ref=receipt.audit_ref,
    )
    payload = canonical_json(unsigned).encode("utf-8")
    try:
        ok = verifier.verify_signature(
            payload, receipt.key_id, receipt.algorithm, receipt.signature)
    except Exception:
        ok = False
    if not ok:
        raise AdapterVerificationError("adapter receipt signature is invalid")
    expected_hash = _digest(dict(unsigned, signature=receipt.signature))
    if not hmac.compare_digest(expected_hash, receipt.receipt_hash):
        raise AdapterVerificationError("adapter receipt hash is invalid")
    if (receipt.attempt_id != attempt_id or receipt.nonce != nonce
            or receipt.package_hash_observed != package_hash_observed
            or receipt.continuation_hash != continuation_hash):
        raise AdapterVerificationError("adapter receipt is not bound to this attempt")
    if receipt.executor_id != receipt.key_id:
        raise AdapterVerificationError("adapter executor_id is not the signing key")
    replay.remember(receipt.attempt_id, receipt.nonce, receipt.provider_request_id)
    return True


def observe_attested(
    enforcer: Enforcer,
    item_id: str,
    receipt: AuthenticatedAdapterReceipt,
    verifier: Any,
    replay: AdapterReplayLog,
    *,
    package_hash_observed: str,
    continuation_hash: str,
    attempt_id: str,
    nonce: str,
) -> None:
    if type(enforcer) is not Enforcer:
        raise AdapterVerificationError("observe_attested requires an Enforcer")
    verify_adapter_receipt(
        receipt, verifier, replay,
        attempt_id=attempt_id,
        nonce=nonce,
        package_hash_observed=package_hash_observed,
        continuation_hash=continuation_hash,
    )
    enforcer.observe(
        item_id, f"{receipt.executed_provider}:{receipt.executed_model}")


class AttestingGateway:
    """Signs provider observations. The transport never holds the key."""

    def __init__(
        self,
        transport: Callable[[Any], ProviderObservation],
        signer: HMACSHA256Signer,
    ) -> None:
        if not callable(transport):
            raise AdapterIssueError("gateway transport must be callable")
        if type(signer) is not HMACSHA256Signer:
            raise AdapterIssueError("gateway signer must be HMACSHA256Signer")
        self._transport = transport
        self._signer = signer

    def run(
        self,
        *,
        attempt_id: str,
        nonce: str,
        issued_at: int,
        request: Any,
    ) -> AuthenticatedAdapterReceipt:
        observation = self._transport(request)
        if type(observation) is not ProviderObservation:
            raise AdapterIssueError("transport must return a ProviderObservation")
        return issue_adapter_receipt(
            attempt_id=attempt_id,
            nonce=nonce,
            observation=observation,
            signer=self._signer,
            issued_at=issued_at,
        )


class ProviderCredentials:
    """Provider secret held only by InferenceGateway."""

    __slots__ = ("provider", "_secret")

    def __init__(self, provider: str, secret: bytes) -> None:
        if type(provider) is not str or not provider:
            raise AdapterIssueError("provider must be a non-empty plain string")
        if type(secret) is not bytes or not secret:
            raise TypeError("provider secret must be non-empty plain bytes")
        self.provider = provider
        self._secret = bytes(secret)

    @property
    def secret(self) -> bytes:
        return self._secret

    def __repr__(self) -> str:
        return f"ProviderCredentials(provider={self.provider!r}, secret=<hidden>)"

    def __copy__(self):
        raise TypeError("secret material is not copyable")

    def __deepcopy__(self, memo):
        raise TypeError("secret material is not copyable")

    def __reduce_ex__(self, protocol):
        raise TypeError("secret material is not serializable")

    def __reduce__(self):
        raise TypeError("secret material is not serializable")

    def __getstate__(self):
        raise TypeError("secret material is not serializable")


class InferenceGateway:
    """The only caller allowed to hold provider credentials."""

    __slots__ = ("_signer", "_credentials", "_provider_call")

    def __init__(
        self,
        *,
        signer: HMACSHA256Signer,
        credentials: ProviderCredentials,
        provider_call: Callable[[ProviderCredentials, Any], ProviderObservation],
    ) -> None:
        if type(signer) is not HMACSHA256Signer:
            raise AdapterIssueError("gateway signer must be HMACSHA256Signer")
        if type(credentials) is not ProviderCredentials:
            raise AdapterIssueError("gateway credentials must be ProviderCredentials")
        if not callable(provider_call):
            raise AdapterIssueError("provider_call must be callable")
        self._signer = signer
        self._credentials = credentials
        self._provider_call = provider_call

    def __repr__(self) -> str:
        return (
            f"InferenceGateway(provider={self._credentials.provider!r}, "
            "secret=<hidden>)"
        )

    def export_credentials(self) -> None:
        raise AdapterIssueError("workers do not possess provider credentials")

    def infer(
        self,
        *,
        attempt_id: str,
        nonce: str,
        issued_at: int,
        request: Any,
    ) -> AuthenticatedAdapterReceipt:
        observation = self._provider_call(self._credentials, request)
        if type(observation) is not ProviderObservation:
            raise AdapterIssueError("provider_call must return a ProviderObservation")
        return issue_adapter_receipt(
            attempt_id=attempt_id,
            nonce=nonce,
            observation=observation,
            signer=self._signer,
            issued_at=issued_at,
        )


class ExecutionFence:
    """Unsigned observations are route identity unless attestation is required."""

    def __init__(self, require_attested: bool) -> None:
        if type(require_attested) is not bool:
            raise AdapterIssueError("require_attested must be a plain bool")
        self.require_attested = require_attested

    def accept(
        self, receipt: AuthenticatedAdapterReceipt,
    ) -> AuthenticatedAdapterReceipt:
        if type(receipt) is not AuthenticatedAdapterReceipt:
            raise AdapterVerificationError("not an authenticated adapter receipt")
        if self.require_attested and receipt.identity_kind != "attested":
            raise AdapterVerificationError("unattested provider is refused")
        return receipt
