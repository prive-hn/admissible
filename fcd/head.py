"""Authenticated monotone heads for Admissible's JSON-shaped journals.

The reference implementation is dependency-free HMAC-SHA256.  It authenticates
ordered journal bytes and prevents rollback only when the registry is external,
trusted, and itself monotone.  Signer/key and registry compromise remain explicit
non-theorems.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import threading
from dataclasses import dataclass
from typing import Mapping, Protocol

from .journal import JournalEvent, canonical_json, normalize_journal, to_plain_json

__all__ = [
    "HeadReceipt",
    "HeadRefused",
    "HeadVerificationError",
    "HMACSHA256Keyring",
    "HMACSHA256Signer",
    "JournalHead",
    "MonotoneHeadRegistry",
    "compute_journal_head",
    "head_receipt_from_dict",
    "head_receipt_to_dict",
    "make_receipt",
    "verify_current",
    "verify_receipt",
]

_HEX64 = re.compile(r"[0-9a-f]{64}")
_ALGORITHM = "hmac-sha256"
# The signing domain is part of every head signature, so moving it silently
# invalidates every head receipt already issued: the same journal, the same key
# and the same events stop verifying. It therefore tracks the *kernel's* own
# version (fcd.__version__), not the product package's, and the product's
# v0.6 workflow domains live beside it without disturbing it.
_HEAD_DOMAIN = "admissible/v0.5/journal-head"
_CHAIN_DOMAIN = "admissible/v0.5/journal-chain"
_HEAD_RECEIPT_KEYS = frozenset({
    "journal_id", "event_count", "head_digest", "previous_receipt_hash",
    "extension_digests", "issued_at", "algorithm", "key_id", "signature",
    "receipt_hash",
})


class HeadVerificationError(ValueError):
    """A signed head failed authentication, currency, or body verification."""


class HeadRefused(ValueError):
    """The trusted monotone registry refused a proposed successor head."""


def _identity(value: object) -> str:
    if type(value) is not str or not value:
        raise ValueError("head identities must be non-empty plain strings")
    return value


def _nonnegative_int(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("head counters must be non-negative plain integers")
    return value


def _hex64(value: object, *, optional: bool = False) -> str:
    if optional and type(value) is str and value == "":
        return ""
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise ValueError("head digests must be lowercase 64-hex strings")
    return value


@dataclass(frozen=True)
class JournalHead:
    journal_id: str
    event_count: int
    head_digest: str
    event_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        _identity(self.journal_id)
        _nonnegative_int(self.event_count)
        _hex64(self.head_digest)
        if (type(self.event_digests) is not tuple
                or len(self.event_digests) != self.event_count):
            raise ValueError("head event digests must match event_count")
        for digest in self.event_digests:
            _hex64(digest)


@dataclass(frozen=True)
class HeadReceipt:
    journal_id: str
    event_count: int
    head_digest: str
    previous_receipt_hash: str
    extension_digests: tuple[str, ...]
    issued_at: int
    algorithm: str
    key_id: str
    signature: str
    receipt_hash: str

    def __post_init__(self) -> None:
        _identity(self.journal_id)
        _nonnegative_int(self.event_count)
        _hex64(self.head_digest)
        _hex64(self.previous_receipt_hash, optional=True)
        if type(self.extension_digests) is not tuple:
            raise ValueError("head extension digests must be a tuple")
        for digest in self.extension_digests:
            _hex64(digest)
        _nonnegative_int(self.issued_at)
        if _identity(self.algorithm) != _ALGORITHM:
            raise ValueError("unsupported head signature algorithm")
        _identity(self.key_id)
        _hex64(self.signature)
        _hex64(self.receipt_hash)


def head_receipt_to_dict(receipt: HeadReceipt) -> dict:
    if type(receipt) is not HeadReceipt:
        raise TypeError("receipt must be a HeadReceipt")
    return {
        "journal_id": receipt.journal_id,
        "event_count": receipt.event_count,
        "head_digest": receipt.head_digest,
        "previous_receipt_hash": receipt.previous_receipt_hash,
        "extension_digests": list(receipt.extension_digests),
        "issued_at": receipt.issued_at,
        "algorithm": receipt.algorithm,
        "key_id": receipt.key_id,
        "signature": receipt.signature,
        "receipt_hash": receipt.receipt_hash,
    }


def head_receipt_from_dict(value: dict) -> HeadReceipt:
    if type(value) is not dict or frozenset(value) != _HEAD_RECEIPT_KEYS:
        raise ValueError("head receipt must be a closed plain JSON object")
    try:
        fields = dict(value)
        if type(fields["extension_digests"]) is not list:
            raise ValueError
        fields["extension_digests"] = tuple(fields["extension_digests"])
        return HeadReceipt(**fields)
    except (TypeError, ValueError):
        raise ValueError("head receipt must be a closed plain JSON object") from None


class HeadSigner(Protocol):
    @property
    def algorithm(self) -> str: ...

    @property
    def key_id(self) -> str: ...

    def sign(self, payload: bytes) -> str: ...


class HeadVerifier(Protocol):
    def verify_signature(self, payload: bytes, key_id: str,
                         algorithm: str, signature: str) -> bool: ...


class HMACSHA256Signer:
    algorithm = _ALGORITHM
    __slots__ = ("_key_id", "_secret")

    def __init__(self, key_id: str, secret: bytes) -> None:
        self._key_id = _identity(key_id)
        if type(secret) is not bytes or not secret:
            raise TypeError("HMAC secret must be non-empty plain bytes")
        self._secret = bytes(secret)

    @property
    def key_id(self) -> str:
        return self._key_id

    def __repr__(self) -> str:
        return (f"HMACSHA256Signer(key_id={self._key_id!r}, "
                f"algorithm={self.algorithm!r}, secret=<hidden>)")

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

    def sign(self, payload: bytes) -> str:
        if type(payload) is not bytes:
            raise TypeError("signed payload must be plain bytes")
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def verify_signature(self, payload: bytes, key_id: str,
                         algorithm: str, signature: str) -> bool:
        if (type(payload) is not bytes or type(key_id) is not str
                or type(algorithm) is not str or type(signature) is not str):
            return False
        if key_id != self._key_id or algorithm != self.algorithm:
            return False
        try:
            expected = self.sign(payload)
        except Exception:
            return False
        return hmac.compare_digest(expected, signature)


class HMACSHA256Keyring:
    __slots__ = ("_keys",)

    def __init__(self, keys: Mapping[str, bytes]) -> None:
        if type(keys) is not dict:
            raise TypeError("HMAC keyring must be a plain dictionary")
        clean: dict[str, bytes] = {}
        for key_id, secret in dict.items(keys):
            clean[_identity(key_id)] = bytes(secret) if type(secret) is bytes and secret else b""
            if not clean[key_id]:
                raise TypeError("HMAC keyring secrets must be non-empty plain bytes")
        self._keys = clean

    def __repr__(self) -> str:
        return f"HMACSHA256Keyring(key_ids={sorted(self._keys)!r}, secrets=<hidden>)"

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

    def verify_signature(self, payload: bytes, key_id: str,
                         algorithm: str, signature: str) -> bool:
        if (type(payload) is not bytes or type(key_id) is not str
                or type(algorithm) is not str or type(signature) is not str
                or algorithm != _ALGORITHM):
            return False
        secret = self._keys.get(key_id)
        if secret is None:
            return False
        expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _chain_genesis(journal_id: str) -> str:
    return _digest({"domain": _CHAIN_DOMAIN, "journal_id": journal_id,
                    "position": -1, "event_digest": ""})


def _extend_chain(journal_id: str, prior: str, start: int,
                  extension: tuple[str, ...]) -> str:
    current = prior
    for offset, event_digest in enumerate(extension):
        current = _digest({
            "domain": _CHAIN_DOMAIN,
            "journal_id": journal_id,
            "position": start + offset,
            "previous": current,
            "event_digest": event_digest,
        })
    return current


def compute_journal_head(journal_id: str, events: object) -> JournalHead:
    journal_id = _identity(journal_id)
    normalized = normalize_journal(events)
    event_digests = tuple(_digest(to_plain_json(event)) for event in normalized)
    head_digest = _extend_chain(
        journal_id, _chain_genesis(journal_id), 0, event_digests)
    return JournalHead(journal_id, len(normalized), head_digest, event_digests)


def _unsigned_head_payload(journal_id: str, event_count: int,
                           head_digest: str, previous: str,
                           extension_digests: tuple[str, ...], issued_at: int,
                           algorithm: str, key_id: str) -> dict:
    return {
        "domain": _HEAD_DOMAIN,
        "journal_id": journal_id,
        "event_count": event_count,
        "head_digest": head_digest,
        "previous_receipt_hash": previous,
        "extension_digests": list(extension_digests),
        "issued_at": issued_at,
        "algorithm": algorithm,
        "key_id": key_id,
    }


def _receipt_core(receipt: HeadReceipt) -> dict:
    return {
        "domain": _HEAD_DOMAIN,
        "journal_id": receipt.journal_id,
        "event_count": receipt.event_count,
        "head_digest": receipt.head_digest,
        "previous_receipt_hash": receipt.previous_receipt_hash,
        "extension_digests": list(receipt.extension_digests),
        "issued_at": receipt.issued_at,
        "algorithm": receipt.algorithm,
        "key_id": receipt.key_id,
        "signature": receipt.signature,
    }


def make_receipt(head: JournalHead, previous_receipt_hash: str,
                 issued_at: int, signer: HeadSigner, *,
                 previous: HeadReceipt | None = None) -> HeadReceipt:
    if type(head) is not JournalHead:
        raise TypeError("head must be a JournalHead")
    previous_hash = _hex64(previous_receipt_hash, optional=True)
    at = _nonnegative_int(issued_at)
    expected_head = _extend_chain(
        head.journal_id, _chain_genesis(head.journal_id), 0,
        head.event_digests)
    if not hmac.compare_digest(expected_head, head.head_digest):
        raise HeadRefused("journal head does not match its event chain")
    if previous is None:
        if previous_hash != "":
            raise HeadRefused("successor head requires the previous receipt")
        extension = head.event_digests
    else:
        if (type(previous) is not HeadReceipt
                or previous.receipt_hash != previous_hash
                or previous.journal_id != head.journal_id
                or not hmac.compare_digest(
                    _digest(_receipt_core(previous)), previous.receipt_hash)
                or previous.event_count >= head.event_count
                or at < previous.issued_at):
            raise HeadRefused("successor head does not identify its prefix")
        prefix = head.event_digests[:previous.event_count]
        prefix_digest = _extend_chain(
            head.journal_id, _chain_genesis(head.journal_id), 0, prefix)
        if not hmac.compare_digest(prefix_digest, previous.head_digest):
            raise HeadRefused("successor journal does not extend current head")
        extension = head.event_digests[previous.event_count:]
    try:
        algorithm = _identity(signer.algorithm)
        if algorithm != _ALGORITHM:
            raise ValueError("unsupported head signature algorithm")
        key_id = _identity(signer.key_id)
        unsigned = _unsigned_head_payload(
            head.journal_id, head.event_count, head.head_digest,
            previous_hash, extension, at, algorithm, key_id)
        signature = signer.sign(canonical_json(unsigned).encode("utf-8"))
    except Exception:
        raise HeadRefused("head signing failed") from None
    _hex64(signature)
    core = dict(unsigned, signature=signature)
    return HeadReceipt(
        journal_id=head.journal_id,
        event_count=head.event_count,
        head_digest=head.head_digest,
        previous_receipt_hash=previous_hash,
        extension_digests=extension,
        issued_at=at,
        algorithm=algorithm,
        key_id=key_id,
        signature=signature,
        receipt_hash=_digest(core),
    )


def verify_receipt(receipt: HeadReceipt, verifier: HeadVerifier) -> bool:
    if type(receipt) is not HeadReceipt:
        raise HeadVerificationError("head authentication failed")
    unsigned = _unsigned_head_payload(
        receipt.journal_id, receipt.event_count, receipt.head_digest,
        receipt.previous_receipt_hash, receipt.extension_digests,
        receipt.issued_at, receipt.algorithm, receipt.key_id,
    )
    try:
        valid = verifier.verify_signature(
            canonical_json(unsigned).encode("utf-8"), receipt.key_id,
            receipt.algorithm, receipt.signature)
    except Exception:
        valid = False
    if not valid or not hmac.compare_digest(_digest(_receipt_core(receipt)),
                                             receipt.receipt_hash):
        raise HeadVerificationError("head authentication failed")
    return True


class MonotoneHeadRegistry:
    """Trusted latest head per journal; batch acceptance commits all or none."""

    __slots__ = ("_current", "_lock")

    def __init__(self) -> None:
        self._current: dict[str, HeadReceipt] = {}
        self._lock = threading.RLock()

    def current(self, journal_id: str) -> HeadReceipt | None:
        identity = _identity(journal_id)
        with self._lock:
            return self._current.get(identity)

    @staticmethod
    def _validate_next(receipt: HeadReceipt,
                       current: HeadReceipt | None) -> None:
        if current is None:
            if receipt.previous_receipt_hash != "":
                raise HeadRefused("first head requires an empty predecessor")
            if receipt.event_count != len(receipt.extension_digests):
                raise HeadRefused("first head extension count mismatch")
            expected = _extend_chain(
                receipt.journal_id, _chain_genesis(receipt.journal_id),
                0, receipt.extension_digests)
            if not hmac.compare_digest(expected, receipt.head_digest):
                raise HeadRefused("first head does not prove its journal chain")
            return
        if receipt == current:
            return
        if receipt.previous_receipt_hash != current.receipt_hash:
            raise HeadRefused("head predecessor is not registry current")
        if (not receipt.extension_digests
                or receipt.event_count != current.event_count + len(receipt.extension_digests)):
            raise HeadRefused("head extension count mismatch")
        expected = _extend_chain(
            receipt.journal_id, current.head_digest, current.event_count,
            receipt.extension_digests)
        if not hmac.compare_digest(expected, receipt.head_digest):
            raise HeadRefused("successor head does not extend current journal")
        if receipt.issued_at < current.issued_at:
            raise HeadRefused("head time rollback refused")

    def accept_batch(self, receipts: tuple[HeadReceipt, ...],
                     verifier: HeadVerifier) -> tuple[HeadReceipt, ...]:
        if type(receipts) is not tuple or not receipts:
            raise HeadRefused("head batch must be a non-empty tuple")
        seen: set[str] = set()
        for receipt in receipts:
            if type(receipt) is not HeadReceipt or receipt.journal_id in seen:
                raise HeadRefused("head batch contains an invalid or duplicate journal")
            seen.add(receipt.journal_id)
            try:
                verify_receipt(receipt, verifier)
            except HeadVerificationError:
                raise HeadRefused("head batch refused") from None
        with self._lock:
            staged = dict(self._current)
            for receipt in receipts:
                try:
                    self._validate_next(receipt, staged.get(receipt.journal_id))
                except HeadRefused:
                    raise HeadRefused("head batch refused") from None
                staged[receipt.journal_id] = receipt
            self._current = staged
        return receipts

    def accept(self, receipt: HeadReceipt,
               verifier: HeadVerifier) -> HeadReceipt:
        return self.accept_batch((receipt,), verifier)[0]


def verify_current(journal_id: str, events: object,
                   receipt: HeadReceipt, registry: MonotoneHeadRegistry,
                   verifier: HeadVerifier) -> bool:
    try:
        verify_receipt(receipt, verifier)
        current = registry.current(journal_id)
        head = compute_journal_head(journal_id, events)
    except Exception:
        raise HeadVerificationError("journal head is not current") from None
    if (current is None
            or not hmac.compare_digest(current.receipt_hash, receipt.receipt_hash)
            or head.event_count != receipt.event_count
            or not hmac.compare_digest(head.head_digest, receipt.head_digest)):
        raise HeadVerificationError("journal head is not current")
    return True
