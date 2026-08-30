"""The evaluate half of the GitHub Actions boundary, and only that half.

Two rules make a hosted evaluation safe enough to describe honestly:

1. **Bind to the head commit, never to the synthetic merge commit.** On
   ``pull_request`` GitHub sets ``GITHUB_SHA`` to an ephemeral merge commit that
   does not exist in the repository history. Evidence bound to it can never be
   verified again, so this module reads ``event.pull_request.head.sha`` and
   refuses anything that is not a full lowercase 40-hex SHA.

2. **Separate trust domains.** The ``evaluate`` job runs candidate-owned
   commands and therefore never receives a signing secret. The ``finalize`` job
   holds the secret, consumes only validated data, and executes no
   candidate-owned command or package script. A fork can evaluate and can never
   finalize.

``pull_request_target`` is refused outright: it grants a write-scoped token to a
workflow evaluating a fork's changes.

What is *here* is the first rule and the untrusted side of the second: which
artefact this run is about, whether it came from a fork, what a durable baseline
would say about the policy that was used, and the unsigned preview document the
evaluate job hands over.  What is deliberately not here is everything a
finalizer does -- reading a preview back, authenticating an observer
attestation, counting authenticated reviews, requiring a trusted policy,
refusing an untrusted tool checkout, and issuing a receipt.  None of it was
copied, weakened, or left behind a flag; a wheel that contains a finalizer is a
wheel from which one can be called.

:func:`preview_document` is the handover, and it is unsigned by construction.
It carries the decision, the evidence bundle, the policy anchor and the
declared isolation, and it asserts nothing: a finalizer re-derives the whole
decision from the evidence in a different process holding a different key.
``policy_anchor`` in particular is reported as data and decides nothing here --
a hosted evaluate job has no durable home, so ``unanchored`` is the true answer
there rather than a soft yes.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from admissible_core.decision import (BLOCKED, CHECKS_PASSED, DECISION_SCOPE,
                                      READINESS, READINESS_AWAITING_REVIEW,
                                      READINESS_NOT_READY,
                                      READINESS_READY_FOR_ATTESTATION, REFUSED)
from admissible_core.identity import normalize_remote

__all__ = [
    "GITHUB_JOB_OUTPUT_LIMIT_BYTES",
    "MAX_PREVIEW_HANDOVER_BYTES",
    "POLICY_ANCHOR_CHANGED",
    "POLICY_ANCHOR_TRUSTED",
    "POLICY_ANCHOR_UNANCHORED",
    "PREVIEW_SCHEMA",
    "Context",
    "GitHubError",
    "context_to_dict",
    "evaluation_context",
    "fork_from_environment",
    "policy_anchor",
    "preview_document",
]

PREVIEW_SCHEMA = "admissible/v0.6/workflow-preview"
MAX_PREVIEW_BYTES = 4 * 1024 * 1024

# GitHub caps the total size of one job's outputs at 1 MiB, counted over UTF-16
# code units -- two bytes per base64 character. A preview travels base64-encoded
# (4 characters per 3 raw bytes), so the raw ceiling that fits is:
#
#     2 * 4 * ceil(raw / 3) <= 1 MiB   ->   raw <= 393216
#
# 256 KiB is chosen below that, leaving room for the other outputs in the job.
GITHUB_JOB_OUTPUT_LIMIT_BYTES = 1024 * 1024
MAX_PREVIEW_HANDOVER_BYTES = 256 * 1024

# What an evaluating context could establish about the policy it just used.
#
#   TRUSTED     this context holds a durable baseline and the policy matches it.
#   CHANGED     it holds a baseline and this policy enforces something else.
#   UNANCHORED  it holds no baseline at all, which is the ordinary state of a
#               hosted evaluate job: it reads the policy out of the candidate
#               checkout and has nothing to compare it against. An unanchored
#               evaluation is a real evaluation and never an admission.
POLICY_ANCHOR_TRUSTED = "trusted"
POLICY_ANCHOR_CHANGED = "changed"
POLICY_ANCHOR_UNANCHORED = "unanchored"

# The states an evaluation may report. ``ADMITTED`` is absent on purpose: it
# belongs only to a durable receipt, and this distribution issues none.
_EVALUATION_STATES = (CHECKS_PASSED, REFUSED, BLOCKED)


class GitHubError(ValueError):
    """A CI context or preview artefact is unsafe or not exactly identified."""


@dataclass(frozen=True)
class Context:
    """What the workflow may do, derived only from named environment inputs."""

    event_name: str
    repository: str
    base_repository: str
    commit_sha: str
    ref: str
    is_fork: bool

    @property
    def can_sign(self) -> bool:
        return not self.is_fork

    @property
    def preview_only(self) -> bool:
        return self.is_fork


def _full_sha(value: object) -> str:
    if (type(value) is not str or len(value) != 40
            or any(character not in "0123456789abcdef" for character in value)):
        raise GitHubError(
            "a commit SHA must be a full 40-character lowercase hex string; "
            f"got {value!r}")
    return value


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if type(value) is not str or not value.strip():
        raise GitHubError(f"{name} is not set in this environment")
    return value


def _event_payload(environment: Mapping[str, str]) -> dict:
    path = Path(_required(environment, "GITHUB_EVENT_PATH"))
    try:
        raw = path.read_bytes()
    except OSError:
        raise GitHubError(
            f"GITHUB_EVENT_PATH {path} cannot be read; the head commit cannot "
            "be identified and nothing is guessed") from None
    if len(raw) > MAX_PREVIEW_BYTES:
        raise GitHubError("the event payload is implausibly large")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GitHubError(f"the event payload is not valid JSON: {error}") from None
    if type(document) is not dict:
        raise GitHubError("the event payload must be a JSON object")
    return document


def evaluation_context(environment: Mapping[str, str]) -> Context:
    """Derive the exact artefact and signing capability of this workflow run."""

    if not isinstance(environment, Mapping):
        raise GitHubError("environment must be a mapping")
    event_name = _required(environment, "GITHUB_EVENT_NAME")
    if event_name == "pull_request_target":
        raise GitHubError(
            "pull_request_target is refused: it runs with repository write "
            "scope while evaluating a fork's changes. Use pull_request for "
            "evaluation and a separate protected job for finalisation.")
    slug = _required(environment, "GITHUB_REPOSITORY")
    server = environment.get("GITHUB_SERVER_URL") or "https://github.com"
    repository = normalize_remote(f"{server.rstrip('/')}/{slug}")
    ref = environment.get("GITHUB_REF", "")
    if event_name == "pull_request":
        payload = _event_payload(environment)
        pull_request = payload.get("pull_request")
        if type(pull_request) is not dict:
            raise GitHubError("the event payload has no pull_request object")
        head = pull_request.get("head")
        base = pull_request.get("base")
        if type(head) is not dict or type(base) is not dict:
            raise GitHubError("the pull request payload has no head/base object")
        commit_sha = _full_sha(head.get("sha"))
        head_repository = (head.get("repo") or {}).get("full_name")
        base_repository = (base.get("repo") or {}).get("full_name") or slug
        if type(head_repository) is not str or not head_repository:
            raise GitHubError("the pull request head names no repository")
        return Context(
            event_name=event_name,
            repository=normalize_remote(f"{server.rstrip('/')}/{head_repository}"),
            base_repository=normalize_remote(
                f"{server.rstrip('/')}/{base_repository}"),
            commit_sha=commit_sha, ref=ref,
            is_fork=head_repository != slug)
    return Context(event_name=event_name, repository=repository,
                   base_repository=repository,
                   commit_sha=_full_sha(environment.get("GITHUB_SHA")),
                   ref=ref, is_fork=False)


def context_to_dict(context: Context) -> dict[str, Any]:
    """A closed description of the context; never an environment dump."""

    if type(context) is not Context:
        raise GitHubError("context must be a Context")
    return {
        "event_name": context.event_name,
        "repository": context.repository,
        "base_repository": context.base_repository,
        "commit_sha": context.commit_sha,
        "ref": context.ref,
        "is_fork": context.is_fork,
        "can_sign": context.can_sign,
        "preview_only": context.preview_only,
    }


def fork_from_environment(source: Mapping[str, str] | None = None) -> bool:
    """Mark a preview produced by a fork so no finalizer can ever sign it."""

    environment = os.environ if source is None else source
    if not environment.get("GITHUB_EVENT_NAME"):
        return False
    try:
        return evaluation_context(environment).is_fork
    except GitHubError:
        # An unidentifiable CI context is treated as untrusted, not as trusted.
        return True


def policy_anchor(store, *, repository: str, class_id: str,
                  policy_digest: str, enforcement_digest: str) -> str:
    """What a durable baseline says about the policy that was just used.

    Answered from a store or not at all. A hosted evaluate job has no durable
    home, so it has no baseline, and ``UNANCHORED`` is the true answer there --
    not a soft yes. It is reported as data and decides nothing: the finalizer
    re-derives the same question from *its* store, which is the only one that
    outlives a job.

    Reading the baseline is all this does. The candidate-side store facade has
    no ``trust_policy``, so an evaluation cannot answer the question by making
    the answer true.
    """

    if store is None:
        return POLICY_ANCHOR_UNANCHORED
    trusted = store.trusted_policies(repository, class_id)
    if not trusted:
        return POLICY_ANCHOR_UNANCHORED
    if any(item["policy_digest"] == policy_digest for item in trusted):
        return POLICY_ANCHOR_TRUSTED
    if any(item["enforcement_digest"] == enforcement_digest
           for item in trusted):
        return POLICY_ANCHOR_TRUSTED
    return POLICY_ANCHOR_CHANGED


def _state_readiness(state: object, readiness: object) -> tuple[str, str]:
    """Validate the closed, coherent state/readiness pair of an evaluation.

    A readiness is not a second spelling of state. The two valid exceptional
    pairs are a plain refusal that is genuinely waiting on review, and a plain
    refusal that is not finalizable. A block is never review-completable.

    The finalizer applies the same rule from its own module. Duplicating four
    lines of arithmetic is the cost of not shipping the signing distribution's
    code here; a shared helper for it would have to live in the kernel, and the
    kernel is not where an evaluation's shape belongs.
    """

    if type(state) is not str or state not in _EVALUATION_STATES:
        raise GitHubError(
            "evaluation state must be exactly one of "
            + ", ".join(_EVALUATION_STATES)
            + f"; got {state!r}. ADMITTED belongs only to a durable receipt")
    if type(readiness) is not str or readiness not in READINESS:
        raise GitHubError(
            "evaluation readiness must be exactly one of "
            + ", ".join(READINESS)
            + f"; got {readiness!r}")
    coherent = {
        CHECKS_PASSED: frozenset({READINESS_READY_FOR_ATTESTATION}),
        REFUSED: frozenset({READINESS_AWAITING_REVIEW, READINESS_NOT_READY}),
        BLOCKED: frozenset({READINESS_NOT_READY}),
    }
    if readiness not in coherent[state]:
        raise GitHubError(
            f"evaluation state {state!r} and readiness {readiness!r} "
            "contradict each other")
    return state, readiness


def preview_document(*, repository: str, commit_sha: str, tree_sha: str,
                     policy_digest: str, class_id: str, state: str,
                     readiness: str, decision: dict, evidence: dict,
                     dependencies: tuple, issued_at: int, fork: bool,
                     isolation: str,
                     config_path: str = ".admissible.json",
                     policy_anchor: str = POLICY_ANCHOR_UNANCHORED,
                     ) -> dict[str, Any]:
    """The unsigned artefact the evaluate job hands to the finalize job.

    ``readiness``, ``fork`` and ``isolation`` have no defaults on purpose.
    Every default here would be a guess -- about how far an evaluation got,
    about whose branch it ran on, or about what confined the commands it
    started -- and the safe-looking guesses are exactly the ones that hand a
    finalizer a preview nobody claimed was finished, clear a fork prohibition
    by omission, or invent a sandbox that was never there.
    """

    from .runner import ISOLATION_MODES

    if isolation not in ISOLATION_MODES:
        raise GitHubError(
            f"preview isolation must be one of {', '.join(ISOLATION_MODES)}")
    _state_readiness(state, readiness)
    if type(fork) is not bool:
        raise GitHubError("preview fork must be exactly true or false")
    if policy_anchor not in (POLICY_ANCHOR_TRUSTED, POLICY_ANCHOR_CHANGED,
                             POLICY_ANCHOR_UNANCHORED):
        raise GitHubError(f"unknown policy anchor state {policy_anchor!r}")
    document = {
        "schema": PREVIEW_SCHEMA,
        "repository": repository,
        "config_path": config_path,
        "policy_anchor": policy_anchor,
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
        "policy_digest": policy_digest,
        "class_id": class_id,
        "state": state,
        "readiness": readiness,
        "isolation": isolation,
        "decision": decision,
        "evidence": evidence,
        "dependencies": [{"repository": item[0], "commit_sha": item[1]}
                         for item in dependencies],
        "issued_at": issued_at,
        "fork": fork,
    }
    _preview_decision(document)
    return document


def _preview_decision(document: dict) -> dict:
    """Return the embedded decision after every duplicated field agrees.

    The evaluate job checks this when it *writes* the preview, so a handover
    that describes one evaluation two ways is caught here rather than at the
    finalizer. The finalizer checks it again on read, because a file that
    travelled through a job output is not the file that was written until
    something says so.
    """

    decision_document = document["decision"]
    if (type(decision_document) is not dict
            or decision_document.get("scope") != DECISION_SCOPE):
        raise GitHubError(
            "the preview decision must be a developer-workflow-admission "
            "document")
    duplicated = (
        ("state", "state"),
        ("readiness", "readiness"),
        ("repository", "repository"),
        ("commit_sha", "commit_sha"),
        ("tree_sha", "tree_sha"),
        ("policy_digest", "policy_digest"),
        ("class_id", "class_id"),
        ("issued_at", "evaluated_at"),
    )
    for preview_key, decision_key in duplicated:
        if decision_key not in decision_document:
            raise GitHubError(
                f"the embedded decision is missing {decision_key!r}, so it "
                f"cannot be matched to the preview's {preview_key!r}")
        if document[preview_key] != decision_document[decision_key]:
            raise GitHubError(
                f"the preview {preview_key} is {document[preview_key]!r} but "
                f"its embedded decision says {decision_key}="
                f"{decision_document[decision_key]!r}; the two descriptions "
                "of one evaluation do not match and nothing was signed")
    _state_readiness(document["state"], document["readiness"])
    _state_readiness(decision_document["state"], decision_document["readiness"])
    return decision_document
