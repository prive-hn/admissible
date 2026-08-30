"""Signed review attestations from a trust domain Admissible does not own.

A review that *blocks* a merge is an authority claim, so it must be
authenticated. An unsigned JSON file is a claim by whoever wrote the file, and
this module keeps those two things apart:

* :func:`attest` marks a closed review record with a reviewer key. The key
  lives in ``ADMISSIBLE_REVIEW_KEY`` / ``ADMISSIBLE_REVIEW_KEY_FILE`` and is
  deliberately *not* the workflow signing key: a compromised finalizer must not
  be able to mint the reviews it then honours.
* :func:`verify_attestation` checks the mark against an external reviewer
  keyring supplied by the operator, and returns the review it authenticated.

The algorithm is HMAC-SHA256. That is shared-secret authenticity — a holder of
the key issued this — and never public non-repudiation. Admissible makes no
model call anywhere: a reviewer is a person or a tool the operator runs, and
Admissible only authenticates what they signed.

This module lives in the signing distribution because both halves of it need a
credential: :func:`attest` loads the reviewer's own key, and
:func:`verify_attestation` needs the keyring a finalizer pinned. Since the
algorithm is symmetric, a distribution that could verify a review could mint
one, so there is no half of this that the candidate side could safely hold —
which is why the candidate side holds none of it.
"""
from __future__ import annotations

import hmac
import json
import os
from hashlib import sha256
from typing import Any, Mapping

from fcd.journal import canonical_json

from admissible_core import evidence as evidence_module
from admissible_core.fsutil import SecretFileError, read_secret_file

__all__ = [
    "ATTESTATION_DOMAIN",
    "AUTHORSHIP_DOMAIN",
    "ReviewError",
    "assert_distinct_secrets",
    "attest",
    "attest_authorship",
    "carry_bundle_attestations",
    "carry_bundle_authorship",
    "load_keyring",
    "load_review_signer",
    "parse_attestation",
    "verify_attestation",
    "verify_authorship_attestation",
    "verify_bundle_attestations",
    "verify_bundle_authorship",
]

ATTESTATION_DOMAIN = "admissible/v0.6/review-attestation"
# A separate domain, so a signature over a review can never be replayed as a
# signature over an authorship claim, or the other way round.
AUTHORSHIP_DOMAIN = "admissible/v0.6/authorship-attestation"
_MAX_KEY_BYTES = 4096
_MAX_KEYRING_BYTES = 256 * 1024


class ReviewError(ValueError):
    """A review attestation is not well formed or not authentic."""


def assert_distinct_secrets(keyring: Mapping[str, bytes], *, where: str,
                            error=None) -> None:
    """Refuse a keyring in which two ids name one physical credential.

    A policy that requires two independent reviews is counting people, and it
    counts them by the key id that signed. That only means anything while two
    ids are two secrets. Map one secret as ``reviewer-a`` and ``reviewer-b``
    and one holder produces both approvals, satisfies "two distinct reviewer
    keys", and never involves a second person -- and the same secret mapped as
    an author id would let that holder attest authorship and review it too.

    Nothing downstream can notice: a signature carries the key id it was made
    under, not the bytes behind it. This is the only place that can see both,
    so it is the place that refuses.
    """

    failure = ReviewError if error is None else error
    seen: dict[bytes, str] = {}
    for key_id in sorted(keyring):
        secret = keyring[key_id]
        first = seen.get(secret)
        if first is not None:
            raise failure(
                f"{where} maps {first!r} and {key_id!r} to the same secret. "
                "Two ids sharing one credential is one holder wearing two "
                "names: it satisfies a two-reviewer rule with one person, and "
                "no signature downstream can tell the difference because a "
                "signature carries the id, not the bytes. Give each identity "
                "its own secret.")
        seen[secret] = key_id


def _signature(review: Mapping[str, Any], secret: bytes, key_id: str) -> str:
    payload = canonical_json({
        "domain": ATTESTATION_DOMAIN,
        "key_id": key_id,
        "review": dict(review),
    }).encode("utf-8")
    return hmac.new(secret, payload, sha256).hexdigest()


def attest(review: object, *, key_id: str, secret: bytes) -> dict[str, Any]:
    """Sign one closed review record and return the attestation document."""

    if type(key_id) is not str or not key_id.strip():
        raise ReviewError("a reviewer key id must be a non-empty string")
    if type(secret) is not bytes or not secret:
        raise ReviewError("a reviewer signing secret must be non-empty bytes")
    try:
        record = evidence_module.review_evidence_from_dict(review)
    except evidence_module.EvidenceError as error:
        raise ReviewError(f"the review record is not closed: {error}") from None
    document = evidence_module.review_evidence_to_dict(record)
    return {
        "schema": evidence_module.ATTESTATION_SCHEMA,
        "algorithm": "hmac-sha256",
        "key_id": key_id,
        "review": document,
        "signature": _signature(document, secret, key_id),
    }


def parse_attestation(document: object) -> dict[str, Any]:
    try:
        return evidence_module.parse_attestation_shape(document)
    except evidence_module.EvidenceError as error:
        raise ReviewError(str(error)) from None


def verify_attestation(document: object, keyring: Mapping[str, bytes]):
    """Authenticate one attestation against an external reviewer keyring."""

    parsed = parse_attestation(document)
    key_id = parsed["key_id"]
    secret = keyring.get(key_id) if isinstance(keyring, Mapping) else None
    if secret is None:
        raise ReviewError(
            f"no reviewer key {key_id!r} in this keyring; a review can only "
            "block when the finalizer can authenticate who signed it")
    if type(secret) is not bytes or not secret:
        raise ReviewError(f"reviewer key {key_id!r} is not usable key material")
    expected = _signature(parsed["review"], secret, key_id)
    if not hmac.compare_digest(expected, parsed["signature"]):
        raise ReviewError(
            f"review attestation signed by {key_id!r} is not authentic; it was "
            "modified after signing or signed by a different key")
    return evidence_module.review_evidence_from_dict(parsed["review"])


def verify_bundle_attestations(bundle, keyring: Mapping[str, bytes]
                               ) -> tuple[evidence_module.VerifiedReview, ...]:
    """Every attestation in a bundle, authenticated, as verified reviews."""

    verified = []
    for document in bundle.attestations:
        record = verify_attestation(document, keyring)
        verified.append(evidence_module.VerifiedReview(
            record=record, key_id=document["key_id"]))
    return tuple(verified)


def _authorship_signature(record: Mapping[str, Any], secret: bytes,
                           key_id: str) -> str:
    payload = canonical_json({
        "domain": AUTHORSHIP_DOMAIN,
        "key_id": key_id,
        "authorship": dict(record),
    }).encode("utf-8")
    return hmac.new(secret, payload, sha256).hexdigest()


def attest_authorship(record: object, *, key_id: str,
                      secret: bytes) -> dict[str, Any]:
    """Sign one closed authorship record with the author's own key.

    The author signs. That is the whole point: a policy naming author key ids
    can only exclude an author from reviewing their own change if something
    other than a string in the submitted document says who the author is.
    """

    if type(key_id) is not str or not key_id.strip():
        raise ReviewError("an author key id must be a non-empty string")
    if type(secret) is not bytes or not secret:
        raise ReviewError("an author signing secret must be non-empty bytes")
    try:
        parsed = evidence_module.authorship_evidence_from_dict(record)
    except evidence_module.EvidenceError as error:
        raise ReviewError(
            f"the authorship record is not closed: {error}") from None
    document = evidence_module.authorship_evidence_to_dict(parsed)
    return {
        "schema": evidence_module.AUTHORSHIP_ATTESTATION_SCHEMA,
        "algorithm": "hmac-sha256",
        "key_id": key_id,
        "authorship": document,
        "signature": _authorship_signature(document, secret, key_id),
    }


def verify_authorship_attestation(document: object,
                                  keyring: Mapping[str, bytes]):
    """Authenticate one authorship attestation against a pinned keyring."""

    try:
        parsed = evidence_module.authorship_attestation_shape(document)
    except evidence_module.EvidenceError as error:
        raise ReviewError(str(error)) from None
    key_id = parsed["key_id"]
    secret = keyring.get(key_id) if isinstance(keyring, Mapping) else None
    if secret is None:
        raise ReviewError(
            f"no key {key_id!r} in this keyring; an authorship claim only "
            "counts when the finalizer can authenticate who signed it")
    if type(secret) is not bytes or not secret:
        raise ReviewError(f"key {key_id!r} is not usable key material")
    expected = _authorship_signature(parsed["authorship"], secret, key_id)
    if not hmac.compare_digest(expected, parsed["signature"]):
        raise ReviewError(
            f"authorship attestation signed by {key_id!r} is not authentic; "
            "it was modified after signing or signed by a different key")
    return evidence_module.authorship_evidence_from_dict(parsed["authorship"])


def verify_bundle_authorship(bundle, keyring: Mapping[str, bytes]
                             ) -> tuple[evidence_module.AttestedAuthorship, ...]:
    """Every authorship attestation in a bundle, authenticated."""

    return tuple(
        evidence_module.AttestedAuthorship(
            record=verify_authorship_attestation(document, keyring),
            key_id=document["key_id"])
        for document in bundle.author_attestations)


def carry_bundle_authorship(
        bundle) -> tuple[evidence_module.UnverifiedAuthorship, ...]:
    """Every authorship claim, carried on without authenticating it."""

    return tuple(
        evidence_module.UnverifiedAuthorship(
            record=evidence_module.authorship_evidence_from_dict(
                document["authorship"]),
            key_id=document["key_id"])
        for document in bundle.author_attestations)


def carry_bundle_attestations(
        bundle) -> tuple[evidence_module.UnverifiedReview, ...]:
    """Every attestation in a bundle, carried on without authenticating it.

    This is what a job that holds *no* reviewer keyring may honestly do with a
    signature: keep it, name the key it claims, hand it to whoever can check it,
    and count it for nothing. It is not a fallback for a keyring that rejected a
    key -- a job that holds a keyring is the authenticator and must use
    :func:`verify_bundle_attestations`, which refuses.
    """

    return tuple(
        evidence_module.UnverifiedReview(
            record=evidence_module.review_evidence_from_dict(
                document["review"]),
            key_id=document["key_id"])
        for document in bundle.attestations)


def _read_secret_file(path_text: str, variable: str) -> bytes:
    try:
        return read_secret_file(path_text, variable,
                                max_bytes=_MAX_KEYRING_BYTES)
    except SecretFileError as error:
        raise ReviewError(str(error)) from None


def load_review_signer(environment: Mapping[str, str] | None = None
                       ) -> tuple[str, bytes]:
    """The reviewer key id and secret this machine signs reviews with."""

    source = os.environ if environment is None else environment
    key_id = (source.get("ADMISSIBLE_REVIEW_KEY_ID") or "").strip()
    if not key_id:
        raise ReviewError(
            "set ADMISSIBLE_REVIEW_KEY_ID to the identity this review is "
            "signed by; blocking reviews are counted by key id")
    inline = source.get("ADMISSIBLE_REVIEW_KEY")
    if inline is not None:
        material = inline.strip().encode("utf-8")
        if not material:
            raise ReviewError("ADMISSIBLE_REVIEW_KEY is set but empty")
        if len(material) > _MAX_KEY_BYTES:
            raise ReviewError("ADMISSIBLE_REVIEW_KEY is implausibly large")
        return key_id, material
    key_file = source.get("ADMISSIBLE_REVIEW_KEY_FILE")
    if key_file:
        material = _read_secret_file(key_file, "ADMISSIBLE_REVIEW_KEY_FILE"
                                     ).strip()
        if not material:
            raise ReviewError(f"ADMISSIBLE_REVIEW_KEY_FILE {key_file} is empty")
        return key_id, material
    raise ReviewError(
        "no reviewer key: set ADMISSIBLE_REVIEW_KEY, or point "
        "ADMISSIBLE_REVIEW_KEY_FILE at a file only you can read. This key is "
        "deliberately separate from ADMISSIBLE_HMAC_KEY.")


def load_keyring(environment: Mapping[str, str] | None = None
                 ) -> dict[str, bytes]:
    """The external reviewer keyring a finalizer verifies blocking reviews with.

    ``ADMISSIBLE_REVIEW_KEYRING`` names a permission-checked JSON file mapping
    reviewer key id to secret. An absent keyring is not an error: it means no
    review can block, and the decision will say so.
    """

    source = os.environ if environment is None else environment
    path_text = (source.get("ADMISSIBLE_REVIEW_KEYRING") or "").strip()
    if not path_text:
        return {}
    raw = _read_secret_file(path_text, "ADMISSIBLE_REVIEW_KEYRING")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReviewError(
            f"the reviewer keyring {path_text} is not valid JSON: {error}"
        ) from None
    if type(document) is not dict:
        raise ReviewError("the reviewer keyring must be a JSON object")
    keyring: dict[str, bytes] = {}
    for key_id, secret in document.items():
        if type(key_id) is not str or not key_id.strip():
            raise ReviewError("reviewer keyring ids must be non-empty strings")
        if type(secret) is not str or not secret.strip():
            raise ReviewError(
                f"reviewer keyring entry {key_id!r} must be a non-empty string")
        keyring[key_id] = secret.strip().encode("utf-8")
    assert_distinct_secrets(keyring, where=f"the reviewer keyring {path_text}")
    return keyring
