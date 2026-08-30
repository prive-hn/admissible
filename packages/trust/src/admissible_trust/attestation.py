"""Evaluation attestations: an external observer's statement, not a proof.

Command evidence is a description of what a process did, written by the same
job that ran candidate-owned commands. That job cannot be its own witness. A
check can leave a descendant behind, a descendant can rewrite a file, and every
downstream verification would then be checking a forgery against itself very
carefully.

An **evaluation attestation** narrows that hole by moving the witness out of
the candidate's reach. It is signed by an external observer that:

* runs after the candidate job is over and its process group is gone;
* holds a key the evaluating job never sees, in a trust domain the candidate
  cannot reach;
* names the exact repository, commit, tree, policy, class, attempt, state,
  readiness, config path, fork flag, observer-validated isolation boundary,
  dependency edges and the digest of every command and review record it
  observed;
* names a **closed external source receipt** -- a provider, an immutable run or
  job id, the exact commit, the conclusion that provider reported, and the
  digest of the receipt document itself -- that the observer read from a system
  outside this evaluation.

The source receipt is the part that stops this being proof by re-signing the
preview. Without it an observer would only be restating what the artefact says
about itself, and a self-consistent fabricated pass would be indistinguishable
from a real one.

What it is *not*: a proof that the checks ran. Signing the source receipt
establishes that an operator or an adapter reported having read that receipt
from the named provider. **Admissible does not fetch it and cannot verify it.**
That is the adapter-honesty assumption, and it is retained deliberately and
stated wherever this feature is documented: an adapter that lies, or an
operator who signs a receipt they never read, produces an attestation that
verifies. The attestation bounds *who* can be wrong; it does not remove the
possibility.

Independently signed reviews and authorship claims are separate authorities.
They travel out of band to ``finalize --reviews``, are authenticated there
against their own keyring and exact artefact identity, and are bound by the
final receipt. The observer neither re-signs nor subsumes those human roles.

``finalize`` requires one and verifies it against a keyring the operator pins,
then compares every field in it against what it independently derived. No
evaluation attestation, no receipt -- there is no default, no fallback, and no
"the workflow said so" path.

Three distinct keys exist in this product and none of them substitutes for
another:

* ``ADMISSIBLE_HMAC_KEY``       -- signs admissions
  (:mod:`admissible_trust.receipt`);
* ``ADMISSIBLE_REVIEW_KEY``     -- signs reviews
  (:mod:`admissible_trust.review`);
* ``ADMISSIBLE_EVALUATION_KEY`` -- signs evaluation attestations, here.

The algorithm is HMAC-SHA256: shared-secret authenticity, never public
non-repudiation.
"""
from __future__ import annotations

import hmac
import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from fcd.journal import canonical_json

from admissible_core import evidence as evidence_module
from admissible_core.fsutil import SecretFileError, read_secret_file

__all__ = [
    "ADMISSIBLE_SOURCE_CONCLUSIONS",
    "AWAITING_REVIEW_SOURCE_CONCLUSIONS",
    "admissible_source_conclusions",
    "EVALUATION_BODY_KEYS",
    "EVALUATION_DOMAIN",
    "EVALUATION_KEYS",
    "EVALUATION_SCHEMA",
    "EVALUATION_STATES",
    "EvaluationError",
    "SOURCE_RECEIPT_DOMAIN",
    "SOURCE_RECEIPT_KEYS",
    "SOURCE_RECEIPT_SCHEMA",
    "attest",
    "attest_preview",
    "evaluation_body",
    "evaluation_state_readiness",
    "load_evaluation_keyring",
    "load_evaluation_signer",
    "parse_evaluation",
    "read_attestation_file",
    "read_source_receipt_file",
    "source_document_digest",
    "source_receipt",
    "verify_evaluation",
]

EVALUATION_SCHEMA = "admissible/v0.6/evaluation-attestation"
EVALUATION_DOMAIN = "admissible/v0.6/evaluation-attestation"
EVALUATION_KEYS = ("schema", "algorithm", "key_id", "evaluation", "signature")
# Every field a finalizer reads out of a preview is in here. The rule is not
# "sign the interesting parts": a field that decides something and is outside
# the signature is a field a candidate may change after the observer looked.
_BODY_KEYS = (
    "schema", "preview_schema", "issued_at", "repository", "commit_sha",
    "tree_sha", "policy_digest",
    "class_id", "attempt_id", "state", "readiness", "config_path", "fork",
    "isolation", "dependencies", "command_digests", "review_digests",
    "decision_digest", "source_receipt", "observed_at",
)
# The same tuple, exported. A caller that needs to know what is inside the
# signature must be able to read it here rather than infer it, because "which
# fields are signed" is the whole question this module answers.
EVALUATION_BODY_KEYS = _BODY_KEYS
_MAX_ATTESTATION_BYTES = 1024 * 1024
_MAX_KEY_BYTES = 4096
_MAX_SOURCE_RECEIPT_BYTES = 1024 * 1024
_PREVIEW_SCHEMA = "admissible/v0.6/workflow-preview"

SOURCE_RECEIPT_SCHEMA = "admissible/v0.6/external-source-receipt"
SOURCE_RECEIPT_DOMAIN = "admissible/v0.6/external-source-receipt"
SOURCE_RECEIPT_KEYS = ("provider", "run_id", "commit_sha", "conclusion",
                       "receipt_digest")
_SOURCE_FILE_OPTIONAL = ("schema", "source_document")
# The conclusions a finalizer will complete an admission on. Anything else --
# `cancelled`, `timed_out`, `neutral`, a provider-specific word nobody here
# knows -- is reported and refused rather than interpreted.
ADMISSIBLE_SOURCE_CONCLUSIONS = frozenset({"success"})
# ...and the set for an evaluation whose only outstanding blocker is a review.
#
# A review-required class is red on the hosted gate by design, on every event
# and every repository: the evaluate job holds no reviewer keyring, so it
# cannot authenticate a review and must not appear to have. The provider
# therefore records that run as `failure`, and demanding `success` here meant
# the five review-required profiles had no path to admission at all -- the
# gate's own honesty made its output unusable.
#
# `failure` is accepted only against readiness AWAITING_REVIEW, and that is a
# narrow window rather than a hole. Readiness is inside the observer's
# signature, and `preview_readiness` returns AWAITING_REVIEW only when every
# required check passed and the sole remaining reason is a review this job
# could not authenticate; a failing required check yields NOT_READY. So the
# pair "conclusion failure, readiness AWAITING_REVIEW" says exactly one thing:
# the provider ran it, the checks are green, and the missing element is the one
# the finalizer is about to supply from its own keyring and recompute.
#
# `cancelled` and `timed_out` stay refused in both cases: they say the run did
# not finish, and an unfinished run establishes nothing to be waiting on.
AWAITING_REVIEW_SOURCE_CONCLUSIONS = frozenset({"success", "failure"})

# Evaluation and admission are disjoint state machines. These are the only
# decision states an unsigned evaluation can report. ``ADMITTED`` deliberately
# does not appear: it is an act recorded by a durable receipt, never a result a
# candidate-adjacent preview or an observer can manufacture.
EVALUATION_STATES = ("CHECKS_PASSED", "REFUSED", "BLOCKED")


def admissible_source_conclusions(readiness: object) -> frozenset[str]:
    """Which provider conclusions may complete an admission at this readiness."""

    from admissible_core.decision import (READINESS_AWAITING_REVIEW,
                                          READINESS_NOT_READY,
                                          READINESS_READY_FOR_ATTESTATION)

    if readiness == READINESS_AWAITING_REVIEW:
        return AWAITING_REVIEW_SOURCE_CONCLUSIONS
    if readiness == READINESS_READY_FOR_ATTESTATION:
        return ADMISSIBLE_SOURCE_CONCLUSIONS
    if readiness == READINESS_NOT_READY:
        return frozenset()
    raise EvaluationError(
        f"evaluation readiness must be one of "
        f"{READINESS_READY_FOR_ATTESTATION}, {READINESS_AWAITING_REVIEW}, "
        f"{READINESS_NOT_READY}; got {readiness!r}")


class EvaluationError(ValueError):
    """An evaluation attestation is not well formed, or not authentic."""


def evaluation_state_readiness(state: object, readiness: object
                               ) -> tuple[str, str]:
    """Validate the closed, coherent state/readiness pair of an evaluation.

    A readiness is not a second spelling of state. The two valid exceptional
    pairs are a plain refusal that is genuinely waiting on review, and a plain
    refusal that is not finalizable. A block is never review-completable.
    """

    from admissible_core.decision import (BLOCKED, CHECKS_PASSED, READINESS,
                                          READINESS_AWAITING_REVIEW,
                                          READINESS_NOT_READY,
                                          READINESS_READY_FOR_ATTESTATION,
                                          REFUSED)

    if type(state) is not str or state not in EVALUATION_STATES:
        raise EvaluationError(
            "evaluation state must be exactly one of "
            + ", ".join(EVALUATION_STATES)
            + f"; got {state!r}. ADMITTED belongs only to a durable receipt")
    if type(readiness) is not str or readiness not in READINESS:
        raise EvaluationError(
            "evaluation readiness must be exactly one of "
            + ", ".join(READINESS)
            + f"; got {readiness!r}")
    coherent = {
        CHECKS_PASSED: frozenset({READINESS_READY_FOR_ATTESTATION}),
        REFUSED: frozenset({READINESS_AWAITING_REVIEW, READINESS_NOT_READY}),
        BLOCKED: frozenset({READINESS_NOT_READY}),
    }
    if readiness not in coherent[state]:
        raise EvaluationError(
            f"evaluation state {state!r} and readiness {readiness!r} "
            "contradict each other")
    return state, readiness


def _text(value: object, where: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise EvaluationError(f"{where} must be a string")
    if not allow_empty and not value.strip():
        raise EvaluationError(f"{where} must not be empty")
    if len(value) > 4096:
        raise EvaluationError(f"{where} is too long")
    return value


def _hex(value: object, length: int, where: str) -> str:
    text = _text(value, where)
    if len(text) != length or any(
            character not in "0123456789abcdef" for character in text):
        raise EvaluationError(
            f"{where} must be a lowercase {length}-character hex digest")
    return text


def _digest_list(value: object, where: str) -> tuple[str, ...]:
    if type(value) is not list:
        raise EvaluationError(f"{where} must be a list of digests")
    return tuple(sorted(_hex(item, 64, f"{where} entry") for item in value))


def _signature(body: Mapping[str, Any], secret: bytes, key_id: str) -> str:
    payload = canonical_json({
        "domain": EVALUATION_DOMAIN,
        "key_id": key_id,
        "evaluation": dict(body),
    }).encode("utf-8")
    return hmac.new(secret, payload, sha256).hexdigest()


def source_document_digest(document: object) -> str:
    """The canonical digest of a source document the observer actually read."""

    return sha256(canonical_json({
        "domain": SOURCE_RECEIPT_DOMAIN,
        "document": document,
    }).encode("utf-8")).hexdigest()


def source_receipt(document: object) -> dict[str, Any]:
    """The closed external receipt an observer says it read, or a refusal.

    Closed on purpose. A receipt with room for extra keys is a receipt whose
    meaning depends on which reader looks at it, and this one has to mean the
    same thing to the observer that signs it and the finalizer that compares
    it. Either the digest of the receipt document is supplied, or the document
    itself is and the digest is computed here -- never both saying different
    things.
    """

    if type(document) is not dict:
        raise EvaluationError("a source receipt must be a JSON object")
    unknown = set(document) - set(SOURCE_RECEIPT_KEYS) - set(
        _SOURCE_FILE_OPTIONAL)
    if unknown:
        raise EvaluationError(
            "the source receipt has unknown key(s): "
            + ", ".join(sorted(unknown)))
    schema = document.get("schema")
    if schema is not None and schema != SOURCE_RECEIPT_SCHEMA:
        raise EvaluationError(
            f"a source receipt schema must be {SOURCE_RECEIPT_SCHEMA!r}")
    supplied = document.get("source_document")
    computed = None if supplied is None else source_document_digest(supplied)
    stated = document.get("receipt_digest")
    if stated is None:
        if computed is None:
            raise EvaluationError(
                "the source receipt is missing key(s): receipt_digest. Supply "
                "the digest of the receipt document, or the document itself "
                "as 'source_document' so the digest can be taken here")
        digest = computed
    else:
        digest = _hex(stated, 64, "source receipt receipt_digest")
        if computed is not None and computed != digest:
            raise EvaluationError(
                "the source receipt names a receipt_digest that is not the "
                "digest of the source_document beside it")
    missing = {"provider", "run_id", "commit_sha", "conclusion"} - set(document)
    if missing:
        raise EvaluationError(
            "the source receipt is missing key(s): "
            + ", ".join(sorted(missing)))
    return {
        "provider": _text(document["provider"], "source receipt provider"),
        "run_id": _text(document["run_id"], "source receipt run_id"),
        "commit_sha": _hex(document["commit_sha"], 40,
                           "source receipt commit_sha"),
        "conclusion": _text(document["conclusion"],
                            "source receipt conclusion"),
        "receipt_digest": digest,
    }


# Bound once so a keyword argument named ``source_receipt`` cannot shadow the
# function that validates it.
_normalize_source_receipt = source_receipt


def read_source_receipt_file(path: Path | str) -> dict[str, Any]:
    """Load the receipt an observer read from the provider, refusing junk."""

    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError:
        raise EvaluationError(
            f"cannot read the source receipt {path}") from None
    if size > _MAX_SOURCE_RECEIPT_BYTES:
        raise EvaluationError(f"the source receipt {path} is implausibly large")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvaluationError(
            f"the source receipt {path} is not valid JSON: {error}") from None
    return source_receipt(document)


def _isolation(value: object) -> str:
    """The declared boundary, checked against the runner's closed set.

    Inside the signature because it decides whether a finalizer will admit at
    all, and a field that decides something and sits outside the signature is a
    field a candidate may set for itself after the observer looked.
    """

    from admissible_core.isolation import ISOLATION_MODES

    text = _text(value, "isolation")
    if text not in ISOLATION_MODES:
        raise EvaluationError(
            f"isolation must be one of {', '.join(ISOLATION_MODES)}; "
            f"got {text!r}")
    return text


def _dependency_list(value: object, where: str) -> list[dict[str, str]]:
    if type(value) is not list:
        raise EvaluationError(f"{where} must be a list of dependency edges")
    edges = []
    for item in value:
        if type(item) is not dict or set(item) != {"repository", "commit_sha"}:
            raise EvaluationError(
                f"{where} entries must be closed "
                "{repository, commit_sha} objects")
        edges.append({
            "repository": _text(item["repository"], f"{where} repository"),
            "commit_sha": _hex(item["commit_sha"], 40, f"{where} commit_sha"),
        })
    return sorted(edges, key=lambda edge: (edge["repository"],
                                           edge["commit_sha"]))


def evaluation_body(*, preview_schema: str, issued_at: int,
                    repository: str, commit_sha: str, tree_sha: str,
                    policy_digest: str, class_id: str, attempt_id: str,
                    state: str, readiness: str, config_path: str, fork: bool,
                    isolation: str, dependencies, command_digests,
                    review_digests, decision_digest: str, source_receipt,
                    observed_at: int) -> dict[str, Any]:
    """The closed statement an external observer signs.

    Digest lists are sorted here rather than trusted in the order they arrive,
    so two observers watching one evaluation produce byte-identical bodies.
    """

    if preview_schema != _PREVIEW_SCHEMA:
        raise EvaluationError(
            f"preview_schema must be {_PREVIEW_SCHEMA!r}")
    if type(issued_at) is not int or issued_at < 0:
        raise EvaluationError("issued_at must be a non-negative integer")
    if type(observed_at) is not int or observed_at < 0:
        raise EvaluationError("observed_at must be a non-negative integer")
    if type(fork) is not bool:
        raise EvaluationError(
            "fork must be exactly true or false; a fork flag that can be "
            "null, 0 or absent is a prohibition that fails open")
    normalized_state, normalized_readiness = evaluation_state_readiness(
        state, readiness)
    return {
        "schema": EVALUATION_SCHEMA,
        "preview_schema": preview_schema,
        "issued_at": issued_at,
        "repository": _text(repository, "repository"),
        "commit_sha": _hex(commit_sha, 40, "commit_sha"),
        "tree_sha": _hex(tree_sha, 40, "tree_sha"),
        "policy_digest": _hex(policy_digest, 64, "policy_digest"),
        "class_id": _text(class_id, "class_id"),
        "attempt_id": _text(attempt_id, "attempt_id", allow_empty=True),
        "state": normalized_state,
        "readiness": normalized_readiness,
        "config_path": _text(config_path, "config_path"),
        "fork": fork,
        "isolation": _isolation(isolation),
        "dependencies": _dependency_list(dependencies, "dependencies"),
        "command_digests": list(_digest_list(command_digests,
                                             "command_digests")),
        "review_digests": list(_digest_list(review_digests, "review_digests")),
        "decision_digest": _hex(decision_digest, 64, "decision_digest"),
        "source_receipt": _normalize_source_receipt(source_receipt),
        "observed_at": observed_at,
    }


def parse_evaluation(document: object) -> dict[str, Any]:
    """Structural validation of a whole attestation document."""

    if type(document) is not dict:
        raise EvaluationError("an evaluation attestation must be a JSON object")
    unknown = set(document) - set(EVALUATION_KEYS)
    if unknown:
        raise EvaluationError(
            "evaluation attestation has unknown key(s): "
            + ", ".join(sorted(unknown)))
    missing = set(EVALUATION_KEYS) - set(document)
    if missing:
        raise EvaluationError(
            "evaluation attestation is missing key(s): "
            + ", ".join(sorted(missing)))
    if document["schema"] != EVALUATION_SCHEMA:
        raise EvaluationError(
            f"evaluation attestation schema must be {EVALUATION_SCHEMA!r}")
    if document["algorithm"] != "hmac-sha256":
        raise EvaluationError(
            "evaluation attestation algorithm must be 'hmac-sha256'; this is "
            "shared-secret authenticity, not public non-repudiation")
    _text(document["key_id"], "evaluation attestation key_id")
    _hex(document["signature"], 64, "evaluation attestation signature")
    body = document["evaluation"]
    if type(body) is not dict:
        raise EvaluationError("the evaluation statement must be a JSON object")
    unknown = set(body) - set(_BODY_KEYS)
    if unknown:
        raise EvaluationError(
            "evaluation statement has unknown key(s): "
            + ", ".join(sorted(unknown)))
    missing = set(_BODY_KEYS) - set(body)
    if missing:
        raise EvaluationError(
            "evaluation statement is missing key(s): "
            + ", ".join(sorted(missing)))
    normalized = evaluation_body(
        preview_schema=body["preview_schema"], issued_at=body["issued_at"],
        repository=body["repository"], commit_sha=body["commit_sha"],
        tree_sha=body["tree_sha"], policy_digest=body["policy_digest"],
        class_id=body["class_id"], attempt_id=body["attempt_id"],
        state=body["state"], readiness=body["readiness"],
        config_path=body["config_path"], fork=body["fork"],
        isolation=body["isolation"],
        dependencies=body["dependencies"],
        command_digests=body["command_digests"],
        review_digests=body["review_digests"],
        decision_digest=body["decision_digest"],
        source_receipt=body["source_receipt"],
        observed_at=body["observed_at"])
    return {"schema": document["schema"], "algorithm": document["algorithm"],
            "key_id": document["key_id"], "evaluation": normalized,
            "signature": document["signature"]}


def attest(body: Mapping[str, Any], *, key_id: str,
           secret: bytes) -> dict[str, Any]:
    """Sign one closed evaluation statement."""

    if type(key_id) is not str or not key_id.strip():
        raise EvaluationError("an evaluation key id must be a non-empty string")
    if type(secret) is not bytes or not secret:
        raise EvaluationError(
            "an evaluation signing secret must be non-empty bytes")
    normalized = evaluation_body(
        preview_schema=body["preview_schema"], issued_at=body["issued_at"],
        repository=body["repository"], commit_sha=body["commit_sha"],
        tree_sha=body["tree_sha"], policy_digest=body["policy_digest"],
        class_id=body["class_id"], attempt_id=body.get("attempt_id", ""),
        state=body["state"], readiness=body["readiness"],
        config_path=body["config_path"], fork=body["fork"],
        isolation=body["isolation"],
        dependencies=body["dependencies"],
        command_digests=body["command_digests"],
        review_digests=body["review_digests"],
        decision_digest=body["decision_digest"],
        source_receipt=body["source_receipt"],
        observed_at=body["observed_at"])
    return {
        "schema": EVALUATION_SCHEMA,
        "algorithm": "hmac-sha256",
        "key_id": key_id,
        "evaluation": normalized,
        "signature": _signature(normalized, secret, key_id),
    }


def attest_preview(preview: object, *, key_id: str, secret: bytes,
                   isolation: str | None = None, source_receipt=None,
                   observed_at: int = 0,
                   **overrides) -> dict[str, Any]:
    """Sign the evaluation a preview document describes.

    The digests are recomputed from the preview's own evidence rather than read
    off any field the preview supplies, so an observer signs what is in the
    artefact and not what the artefact claims about itself.

    ``source_receipt`` has no default. Everything else in this body comes out
    of the artefact under evaluation, so an attestation without it would be a
    signature over the candidate's own account of itself -- exactly the shape
    this module exists to refuse.
    """

    if type(preview) is not dict:
        raise EvaluationError("a preview document must be a JSON object")
    if source_receipt is None:
        raise EvaluationError(
            "no external source receipt. An attestation over the preview "
            "alone re-signs the candidate's own account of itself: every "
            "field in it comes out of the artefact under evaluation. Supply "
            "the closed receipt the observer read from the provider -- "
            "provider, immutable run or job id, exact commit, conclusion, and "
            "the digest of the receipt document. Nothing was signed.")
    if isolation is None:
        raise EvaluationError(
            "no observer isolation assertion. The preview's isolation field "
            "is candidate-adjacent data and cannot assert the boundary that "
            "made observation safe. Supply isolation explicitly from the "
            "observer's trust domain. Nothing was signed.")
    for key in ("schema", "issued_at", "repository", "commit_sha", "tree_sha",
                "policy_digest",
                "class_id", "decision", "evidence", "state", "readiness",
                "config_path", "fork", "dependencies"):
        if key not in preview:
            raise EvaluationError(f"the preview has no {key!r} to attest")
    try:
        bundle = evidence_module.parse_bundle(preview["evidence"])
    except evidence_module.EvidenceError as error:
        raise EvaluationError(
            f"the preview evidence cannot be attested: {error}") from None
    decision_document = preview["decision"]
    if type(decision_document) is not dict:
        raise EvaluationError("the preview decision must be a JSON object")
    receipt = _normalize_source_receipt(source_receipt)
    if receipt["commit_sha"] != preview["commit_sha"]:
        raise EvaluationError(
            f"the source receipt is for commit {receipt['commit_sha']} and "
            f"this preview describes {preview['commit_sha']}; an observer "
            "cannot attest one run with another run's receipt")

    from admissible_core.decision import digest_of_document

    body = {
        "preview_schema": preview["schema"],
        "issued_at": preview["issued_at"],
        "repository": preview["repository"],
        "commit_sha": preview["commit_sha"],
        "tree_sha": preview["tree_sha"],
        "policy_digest": preview["policy_digest"],
        "class_id": preview["class_id"],
        "attempt_id": decision_document.get("attempt_id", ""),
        "state": preview["state"],
        "readiness": preview["readiness"],
        "config_path": preview["config_path"],
        "fork": preview["fork"],
        # This is an observer assertion supplied independently. It is never
        # copied from the candidate-adjacent preview.
        "isolation": isolation,
        "dependencies": preview["dependencies"],
        "command_digests": [evidence_module.evidence_digest(record)
                            for record in bundle.commands],
        "review_digests": [evidence_module.evidence_digest(record)
                           for record in bundle.reviews],
        # Signed review and authorship documents are authenticated by their own
        # independent keyring. Requiring the observer to re-sign them would
        # collapse two authorities into one and would make the documented OOB
        # review transport impossible after observation.
        "decision_digest": digest_of_document(decision_document),
        "source_receipt": receipt,
        "observed_at": observed_at,
    }
    body.update(overrides)
    return attest(body, key_id=key_id, secret=secret)


def verify_evaluation(document: object,
                      keyring: Mapping[str, bytes]) -> dict[str, Any]:
    """Authenticate one attestation against a keyring the operator pinned.

    A key id that is not in the keyring is a refusal, never a warning: the
    keyring *is* the pin, and an observer nobody named observed nothing that
    can complete an admission here.
    """

    parsed = parse_evaluation(document)
    key_id = parsed["key_id"]
    secret = keyring.get(key_id) if isinstance(keyring, Mapping) else None
    if secret is None:
        raise EvaluationError(
            f"no evaluation key {key_id!r} in this keyring; an evaluation can "
            "only complete an admission when the finalizer can authenticate "
            "which external observer signed it")
    if type(secret) is not bytes or not secret:
        raise EvaluationError(
            f"evaluation key {key_id!r} is not usable key material")
    expected = _signature(parsed["evaluation"], secret, key_id)
    if not hmac.compare_digest(expected, parsed["signature"]):
        raise EvaluationError(
            f"the evaluation attestation signed by {key_id!r} is not "
            "authentic; it was modified after signing or signed by a "
            "different key")
    return parsed


def read_attestation_file(path: Path | str) -> dict[str, Any]:
    """Load an attestation document from disk, refusing anything oversized."""

    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError:
        raise EvaluationError(
            f"cannot read the evaluation attestation {path}") from None
    if size > _MAX_ATTESTATION_BYTES:
        raise EvaluationError(
            f"the evaluation attestation {path} is implausibly large")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvaluationError(
            f"the evaluation attestation {path} is not valid JSON: {error}"
        ) from None


def load_evaluation_signer(environment: Mapping[str, str] | None = None
                           ) -> tuple[str, bytes]:
    """The observer identity and secret this machine signs evaluations with."""

    import os as os_module

    source = os_module.environ if environment is None else environment
    key_id = (source.get("ADMISSIBLE_EVALUATION_KEY_ID") or "").strip()
    if not key_id:
        raise EvaluationError(
            "set ADMISSIBLE_EVALUATION_KEY_ID to the external observer this "
            "attestation is signed by; a finalizer counts observers by key id")
    inline = source.get("ADMISSIBLE_EVALUATION_KEY")
    if inline is not None:
        material = inline.strip().encode("utf-8")
        if not material:
            raise EvaluationError("ADMISSIBLE_EVALUATION_KEY is set but empty")
        if len(material) > _MAX_KEY_BYTES:
            raise EvaluationError(
                "ADMISSIBLE_EVALUATION_KEY is implausibly large")
        return key_id, material
    key_file = source.get("ADMISSIBLE_EVALUATION_KEY_FILE")
    if key_file:
        try:
            material = read_secret_file(
                key_file, "ADMISSIBLE_EVALUATION_KEY_FILE",
                max_bytes=_MAX_KEY_BYTES).strip()
        except SecretFileError as error:
            raise EvaluationError(str(error)) from None
        if not material:
            raise EvaluationError(
                f"ADMISSIBLE_EVALUATION_KEY_FILE {key_file} is empty")
        return key_id, material
    raise EvaluationError(
        "no evaluation key: set ADMISSIBLE_EVALUATION_KEY, or point "
        "ADMISSIBLE_EVALUATION_KEY_FILE at a file only you can read. This key "
        "belongs to the external observer and is deliberately separate from "
        "both ADMISSIBLE_HMAC_KEY and ADMISSIBLE_REVIEW_KEY.")


def load_evaluation_keyring(environment: Mapping[str, str] | None = None
                            ) -> dict[str, bytes]:
    """The observer keyring a finalizer authenticates evaluations against.

    An absent keyring is not an empty allowance: ``finalize`` refuses when it
    cannot authenticate the observer, so an empty mapping means nothing can be
    signed here, and the refusal says so.
    """

    import os as os_module

    source = os_module.environ if environment is None else environment
    path_text = (source.get("ADMISSIBLE_EVALUATION_KEYRING") or "").strip()
    if not path_text:
        return {}
    try:
        raw = read_secret_file(path_text, "ADMISSIBLE_EVALUATION_KEYRING")
    except SecretFileError as error:
        raise EvaluationError(str(error)) from None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvaluationError(
            f"the evaluation keyring {path_text} is not valid JSON: {error}"
        ) from None
    if type(document) is not dict:
        raise EvaluationError("the evaluation keyring must be a JSON object")
    keyring: dict[str, bytes] = {}
    for key_id, secret in document.items():
        if type(key_id) is not str or not key_id.strip():
            raise EvaluationError(
                "evaluation keyring ids must be non-empty strings")
        if type(secret) is not str or not secret.strip():
            raise EvaluationError(
                f"evaluation keyring entry {key_id!r} must be a non-empty "
                "string")
        keyring[key_id] = secret.strip().encode("utf-8")
    from .review import assert_distinct_secrets

    assert_distinct_secrets(
        keyring, where=f"the evaluation keyring {path_text}",
        error=EvaluationError)
    return keyring
