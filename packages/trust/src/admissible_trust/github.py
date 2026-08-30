"""Finalization: the trusted half of the CI boundary, and nothing else.

Two rules made the hosted gate safe enough to describe honestly, and the split
turns the second one from a convention into a property of the installed wheel:

1. **Bind to the head commit, never to the synthetic merge commit.** On
   ``pull_request`` GitHub sets ``GITHUB_SHA`` to an ephemeral merge commit that
   does not exist in the repository history. Evidence bound to it can never be
   verified again, so the evaluating side reads ``event.pull_request.head.sha``
   and this side refuses anything that is not a full lowercase 40-hex SHA.

2. **Separate trust domains.** The ``evaluate`` job runs candidate-owned
   commands and therefore never receives a signing secret. The ``finalize`` job
   holds the secret, consumes only validated data, and executes no
   candidate-owned command or package script. A fork can evaluate and can never
   finalize.

What is here is the finalizer. What is *not* here is the evaluate half: there
is no ``evaluation_context``, no ``preview_document`` and no ``policy_anchor``,
because writing a preview is something the process that ran the checks does.
Those live in ``admissible_ready.github``, in the distribution that has a
runner. This module only ever reads one.

Reading is the whole of it. :func:`finalize` opens files, re-derives identity
through the fixed Git adapter, recomputes a decision with the kernel, and
issues a receipt. It starts no subprocess but that adapter, imports no
candidate module, runs no package script, and calls no provider API -- it does
not fetch the source receipt an observer says it read, which is the
adapter-honesty assumption stated where it is relied upon rather than hidden.
"""
from __future__ import annotations

import errno
import hmac
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from admissible_core import evidence as evidence_module
from admissible_core.decision import (ADMITTED, CHECKS_PASSED, DECISION_SCOPE,
                                      MAX_CLOCK_SKEW_SECONDS,
                                      READINESS_AWAITING_REVIEW,
                                      READINESS_READY_FOR_ATTESTATION,
                                      digest_of_document, evaluate)
from admissible_core.identity import IdentityError, normalize_remote

from . import attestation as attestation_module
from . import git_reader
from . import receipt as receipt_module
from . import review as review_module

__all__ = [
    "GitHubError",
    "MAX_PREVIEW_BYTES",
    "PREVIEW_SCHEMA",
    "approving_reviews",
    "assert_trusted_tool",
    "expected_finalization_receipt_body_digest",
    "finalize",
    "require_trusted_policy",
]

PREVIEW_SCHEMA = "admissible/v0.6/workflow-preview"
MAX_PREVIEW_BYTES = 4 * 1024 * 1024

_PREVIEW_REQUIRED = {
    "schema", "repository", "commit_sha", "tree_sha", "policy_digest",
    "class_id", "state", "readiness", "decision", "evidence", "dependencies",
    "issued_at", "config_path", "policy_anchor", "fork", "isolation",
}

# The only readiness values a finalizer will look at twice.
# ``READY_FOR_ATTESTATION`` means the evaluating job reached the end of its
# policy with nothing outstanding it could ever resolve; ``AWAITING_REVIEW``
# means it did everything it could and the independent reviews and authorship
# claims are for the keyring holder to authenticate. Neither is an admission:
# both are re-derived here from evidence, and the field only selects which
# previews are worth the work.
_FINALIZABLE_READINESS = (READINESS_READY_FOR_ATTESTATION,
                          READINESS_AWAITING_REVIEW)

# Nothing. Every key a finalizer reads is required and signed; an optional key
# is a key a candidate can remove after the observer looked at it.
_PREVIEW_OPTIONAL: set[str] = set()



class GitHubError(ValueError):
    """A CI context or preview artefact is unsafe or not exactly identified."""



@dataclass(frozen=True)
class _Finalization:
    """The exact validated parts one finalize invocation may persist."""

    repository: str
    commit_sha: str
    tree_sha: str
    class_id: str
    policy_digest: str
    attempt_id: str
    decision_digest_value: str
    evidence_digests: tuple[str, ...]
    commands: tuple
    reviews: tuple
    authorships: tuple
    authenticated_reviews: tuple
    dependencies: tuple
    issued_at: int



def _full_sha(value: object) -> str:
    if (type(value) is not str or len(value) != 40
            or any(character not in "0123456789abcdef" for character in value)):
        raise GitHubError(
            "a commit SHA must be a full 40-character lowercase hex string; "
            f"got {value!r}")
    return value



def require_trusted_policy(store, *, repository: str, class_id: str,
                           artifact_class, now: int) -> str:
    """Refuse to sign against a policy this home has not deliberately trusted.

    The policy travels inside the tree the policy governs. A change to payment
    code can also change the file that says what a payment change must satisfy,
    so a gate that reads only that file lets the change set its own bar.

    The baseline is what breaks that circle: an operator, in a trusted context,
    records which policy is enforceable for a class. After that a candidate may
    edit descriptions freely -- the enforcement digest ignores prose -- and any
    change to what is actually enforced blocks until an operator approves it
    the same way. The first policy for a class is an explicit bootstrap and
    never an implicit one, because "trust whatever arrives first" is exactly
    the rule an attacker would choose.
    """

    from admissible_core.config import enforcement_digest

    enforcement = enforcement_digest(artifact_class)
    trusted = store.trusted_policies(repository, class_id)
    if not trusted:
        raise GitHubError(
            f"no trusted policy baseline for class {class_id!r} in "
            f"{repository}. This home has never been told which policy is "
            "enforceable here, so it cannot tell a tightened policy from a "
            "weakened one, and it will not sign against either. Bootstrap it "
            "deliberately with 'admissible policy trust --class "
            f"{class_id}' in a trusted checkout.")
    if any(item["policy_digest"] == artifact_class.policy_digest
           for item in trusted):
        return artifact_class.policy_digest
    if any(item["enforcement_digest"] == enforcement for item in trusted):
        # Same enforcement, different words. Record the new digest so the next
        # run matches directly, and carry on: nothing about the gate changed.
        store.trust_policy(
            repository=repository, class_id=class_id,
            policy_digest=artifact_class.policy_digest,
            enforcement_digest=enforcement, trusted_at=now)
        return artifact_class.policy_digest
    superseded = [
        item for item in store.trusted_policies(repository, class_id,
                                                include_superseded=True)
        if item["policy_digest"] == artifact_class.policy_digest
        or item["enforcement_digest"] == enforcement]
    if superseded:
        raise GitHubError(
            f"the policy for class {class_id!r} in {repository} was trusted "
            "here once and is not trusted now: a later baseline superseded it, "
            "or an operator revoked it. Trust is a current fact and not an "
            "accumulating list -- otherwise raising a class from no reviews to "
            "two would leave the zero-review policy permanently valid, and "
            "reverting one file would restore the weaker gate. Nothing was "
            "signed. If this policy really is the one that should enforce "
            f"here, run 'admissible policy trust --class {class_id}' in a "
            "trusted checkout and say so deliberately.")
    raise GitHubError(
        f"the policy for class {class_id!r} in {repository} enforces something "
        "different from the baseline this home trusts: the checks, the review "
        "requirement or the reviewer and author keys have changed. That is a "
        "change to the gate, not a change under it, so it is approved "
        "separately or not at all. Review the diff and run 'admissible policy "
        f"trust --class {class_id}' in a trusted checkout to accept it.")


#: Namespaces a candidate checkout could ship to become the finalizer.
#:
#: The split multiplied the shapes rather than removing them: before, only
#: ``admissible`` could shadow the tool; now ``admissible_trust`` is the
#: program that signs, ``admissible_core`` is the kernel it computes with, and
#: the compatibility namespace is still a name Python will import. All three
#: are refused, because a checkout that ships any of them is one ``cd`` away
#: from deciding what the signing process runs.
_SHADOWED_NAMESPACES = ("admissible_trust", "admissible_core", "admissible")


def assert_trusted_tool(policy_root: Path | str | None) -> bool:
    """Refuse to finalize a checkout that could supply the finalizer.

    The finalizer holds the signing key. Once the Python package this process
    imported came out of the checkout under evaluation, no code of ours gets a
    turn: the candidate's module already ran. The real repair is architectural
    -- the reusable workflow puts the tool and the candidate in separate
    checkouts and runs the tool from its own directory -- and this is the same
    rule stated in code, so a hand-run finalize cannot drift from it.

    Two shapes are refused:

    * the executing package lives inside the candidate checkout;
    * the candidate checkout ships a top-level package or module of its own
      under any of :data:`_SHADOWED_NAMESPACES`, each of which is one ``cd``
      away from being the program that signs.
    """

    if policy_root is None:
        return True
    package = Path(__file__).resolve().parent
    try:
        root = Path(policy_root).resolve()
    except OSError:
        return True
    if package == root or root in package.parents:
        raise GitHubError(
            f"refusing to finalize: the Admissible package being executed "
            f"({package}) lives inside the checkout under evaluation ({root}). "
            "Check the tool out separately, at a trusted revision, and run "
            "finalize from there.")
    for namespace in _SHADOWED_NAMESPACES:
        for shadow in (root / namespace / "__init__.py",
                       root / f"{namespace}.py"):
            if shadow.exists():
                raise GitHubError(
                    f"refusing to finalize: the checkout under evaluation "
                    f"({root}) ships its own {shadow.name} at {shadow.parent}. "
                    "Running the finalizer from that directory would hand the "
                    "signing key to the candidate's code before any check of "
                    "ours could run. Keep the tool checkout and the candidate "
                    "checkout separate, and point --policy-root at a checkout "
                    "that carries policy and data only.")
    return True


def _assert_separate_domains(reviewer_keyring: Mapping[str, bytes],
                             source: Mapping[str, str],
                             evaluation_keyring: Mapping[str, bytes] | None
                             = None, *, signer=None) -> None:
    """Refuse an admission key that is also a reviewer, author or observer key.

    Three keys exist in this product and none substitutes for another. If the
    finalizer's own admission secret is also in the reviewer keyring, then the
    process that signs receipts can mint the reviews it then honours -- and a
    compromise of one domain is a compromise of all three. Only this job holds
    both, so only this job can notice.
    """

    inline = source.get("ADMISSIBLE_HMAC_KEY")
    material = None
    if inline is not None and inline.strip():
        material = inline.strip().encode("utf-8")
    else:
        key_file = source.get("ADMISSIBLE_HMAC_KEY_FILE")
        if key_file:
            try:
                material = receipt_module._read_key_file(key_file)
            except receipt_module.SigningError:
                material = None
    observers = evaluation_keyring
    if observers is None:
        # The finalizer usually reads this from its own environment, and this
        # check runs before the attestation is opened. A keyring that cannot be
        # loaded is not this function's error to report -- verification below
        # says so far better -- so an unreadable one simply contributes no ids.
        try:
            observers = attestation_module.load_evaluation_keyring(source)
        except attestation_module.EvaluationError:
            observers = {}

    review_module.assert_distinct_secrets(
        observers, where="the evaluation keyring")
    overlaps = []
    for reviewer_id, reviewer_secret in reviewer_keyring.items():
        for observer_id, observer_secret in observers.items():
            if reviewer_secret == observer_secret:
                overlaps.append((reviewer_id, observer_id))
    if overlaps:
        pairs = ", ".join(
            f"reviewer {reviewer!r} / observer {observer!r}"
            for reviewer, observer in sorted(overlaps))
        raise review_module.ReviewError(
            "the reviewer keyring and the evaluation keyring map the same "
            f"secret to {pairs}. A reviewer and observer sharing one physical "
            "credential are not independent trust roles. Give every reviewer "
            "and observer separate secret material.")

    signer_signature = None
    challenge = b"admissible/v0.6/trust-domain-separation"
    if signer is not None:
        try:
            signer_signature = signer.sign(challenge)
        except Exception as error:
            raise review_module.ReviewError(
                "the supplied admission signer could not prove its trust "
                f"domain: {error}") from None
    elif material is None:
        return
    for where, other in (("the reviewer keyring", reviewer_keyring),
                         ("the evaluation keyring", observers)):
        if signer_signature is None:
            shared = sorted(key_id for key_id, secret in other.items()
                            if secret == material)
        else:
            shared = sorted(
                key_id for key_id, secret in other.items()
                if hmac.compare_digest(
                    signer_signature,
                    receipt_module.signer_from_secret(
                        "domain-separation-probe", secret).sign(challenge)))
        if shared:
            raise review_module.ReviewError(
                "the admission key this finalizer signs with is also mapped "
                f"in {where} as " + ", ".join(repr(k) for k in shared)
                + ". A finalizer that can mint the reviews it honours, or "
                "attest the evaluation it admits, is not a second party to "
                "anything, and one stolen secret would then be every "
                "authority in this product at once. Give the admission key, "
                "the reviewer keys and the observer keys separate material.")



def _dependency_edges(value: object) -> list[dict[str, str]]:
    """The closed, sorted dependency edges a preview declares.

    Every field is typed before any of them is used, because both uses are
    unsafe on a value a candidate wrote. The edges are ordered by
    ``(repository, commit_sha)``, and two repositories that are not both
    strings make that comparison raise ``TypeError`` -- an exception no caller
    here declares, so it leaves a credentialed finalizer as a traceback where a
    refusal belongs. The surviving edges are then recorded in a signed receipt
    body exactly as they arrived, which is not something a value of any type at
    all may become.
    """

    if type(value) is not list:
        raise GitHubError("preview dependencies must be a list")
    edges = []
    for item in value:
        if type(item) is not dict or set(item) != {"repository", "commit_sha"}:
            raise GitHubError("preview dependencies must be closed objects")
        repository = item["repository"]
        if type(repository) is not str or not repository:
            raise GitHubError(
                "a preview dependency repository must be a non-empty string; "
                f"got {repository!r}")
        edges.append({"repository": repository,
                      "commit_sha": _full_sha(item["commit_sha"])})
    return sorted(edges,
                  key=lambda edge: (edge["repository"], edge["commit_sha"]))


def _preview_bytes(path: Path) -> bytes:
    """Every byte this finalizer will parse, from one descriptor.

    The ceiling is on bytes read, never on what metadata said they would be.
    Asking the path how large it is and then reading the path again asks two
    questions of two filesystem objects that need not be the same one: whoever
    can write the containing directory answers the first with a small file and
    the second with an unbounded one, and this process holds the admission key
    while it reads whatever arrives into memory. A file that simply grows
    between the two calls does the same thing without anybody intending it.

    So the file is opened once and every question is asked of that open
    descriptor: ``O_NOFOLLOW`` refuses a symbolic link at the final component
    in the same syscall that opens it, ``fstat`` describes the object actually
    opened rather than whatever the path names now, and the read stops one byte
    past the ceiling so an object with no size at all -- a pipe, a device --
    is bounded by the same rule as a regular file rather than by trust.
    """

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NOCTTY", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as error:
        if getattr(error, "errno", None) in (errno.ELOOP, errno.EMLINK):
            raise GitHubError(
                f"the preview artefact {path} is a symbolic link. Evidence is "
                "read from the file it names, never through a link: the link "
                "is one rename away from naming something else, and this "
                "process would follow it") from None
        raise GitHubError(f"cannot read the preview artefact {path}") from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise GitHubError(
                f"the preview artefact {path} is not a regular file")
        body = bytearray()
        while len(body) <= MAX_PREVIEW_BYTES:
            try:
                block = os.read(descriptor, MAX_PREVIEW_BYTES + 1 - len(body))
            except OSError:
                raise GitHubError(
                    f"cannot read the preview artefact {path}") from None
            if not block:
                break
            body.extend(block)
        if len(body) > MAX_PREVIEW_BYTES:
            raise GitHubError(f"the preview artefact {path} is too large")
        return bytes(body)
    finally:
        os.close(descriptor)


def _load_preview(path: Path | str) -> dict:
    path = Path(path)
    raw = _preview_bytes(path)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GitHubError(
            f"the preview artefact {path} is not valid JSON: {error}") from None
    if type(document) is not dict:
        raise GitHubError("the preview artefact must be a JSON object")
    present = set(document)
    unknown = present - _PREVIEW_REQUIRED - _PREVIEW_OPTIONAL
    if unknown:
        raise GitHubError(
            "the preview artefact has unknown key(s): "
            + ", ".join(sorted(unknown)))
    missing = _PREVIEW_REQUIRED - present
    if missing:
        raise GitHubError(
            "the preview artefact is missing key(s): "
            + ", ".join(sorted(missing)))
    return document


def _preview_decision(document: dict) -> dict:
    """Return the embedded decision after every duplicated field agrees."""

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
    try:
        attestation_module.evaluation_state_readiness(
            document["state"], document["readiness"])
        attestation_module.evaluation_state_readiness(
            decision_document["state"], decision_document["readiness"])
    except attestation_module.EvaluationError as error:
        raise GitHubError(str(error)) from None
    return decision_document


def approving_reviews(verified) -> tuple[tuple[str, str], ...]:
    """The (digest, key id) pairs of reviews that actually *approved*.

    A receipt's ``authenticated_reviews`` is read later as "these keys approved
    this artefact": impeachment attributes a missed defect to them, and
    standing counts them. Recording every authenticated review there -- an
    abstention, a review whose verdict was something else -- blames a reviewer
    for approving something they explicitly did not.
    """

    return tuple(sorted(
        (evidence_module.evidence_digest(item.record), item.key_id)
        for item in verified if item.record.verdict == "approve"))


def _verified_evaluation(attestation_path, keyring, source, *, repository: str,
                         commit_sha: str, tree_sha: str, policy_digest: str,
                         class_id: str, attempt_id: str, bundle,
                         document: dict, decision_document: dict,
                         now: int) -> dict:
    """Authenticate the external observer's statement about this evaluation.

    Everything the attestation names is compared against what this job has
    independently derived, and *everything* means everything: a field a
    finalizer reads but does not compare is a field a candidate may change
    after the observer looked at it, and the signature still verifies.

    Observed record digests are checked in both directions -- a command or
    plain review record the observer did not watch cannot be counted, and one
    it watched cannot be dropped afterwards. Independently signed review and
    authorship attestations remain separate authorities authenticated by the
    finalizer; the observer does not re-sign them.
    """

    if attestation_path is None:
        raise GitHubError(
            "no evaluation attestation. The command records in a preview were "
            "written by the same job that ran candidate-owned commands, so "
            "they are a description and not a proof. An external observer -- "
            "running after that job's process group is gone, holding a key it "
            "never sees -- must sign for this exact repository, commit, tree, "
            "policy, attempt, record digests and the external source receipt "
            "it read. Produce one with 'admissible attest-evaluation' in the "
            "observer's trust domain. Nothing was signed.")
    if keyring is None:
        try:
            keyring = attestation_module.load_evaluation_keyring(source)
        except attestation_module.EvaluationError as error:
            raise GitHubError(str(error)) from None
    if not keyring:
        raise GitHubError(
            "an evaluation attestation was supplied but this job pins no "
            "evaluation keyring, so it cannot tell which observer signed it. "
            "Point ADMISSIBLE_EVALUATION_KEYRING at the observers this "
            "finalizer trusts. Nothing was signed.")
    try:
        attestation = attestation_module.read_attestation_file(attestation_path)
        verified = attestation_module.verify_evaluation(attestation, keyring)
    except attestation_module.EvaluationError as error:
        raise GitHubError(
            f"the evaluation attestation is not usable: {error}") from None
    statement = verified["evaluation"]
    for label, observed, expected in (
            ("preview schema", statement["preview_schema"],
             document["schema"]),
            ("preview issued_at", statement["issued_at"],
             document["issued_at"]),
            ("repository", statement["repository"], repository),
            ("commit", statement["commit_sha"], commit_sha),
            ("tree", statement["tree_sha"], tree_sha),
            ("policy", statement["policy_digest"], policy_digest),
            ("class", statement["class_id"], class_id),
            ("attempt", statement["attempt_id"], attempt_id),
            ("state", statement["state"], document["state"]),
            ("readiness", statement["readiness"], document["readiness"]),
            ("config path", statement["config_path"],
             document["config_path"])):
        if observed != expected:
            raise GitHubError(
                f"the evaluation attestation names {label} {observed!r} and "
                f"this job is finalising {expected!r}; nothing was signed")
    if statement["fork"] is not document["fork"]:
        raise GitHubError(
            f"the evaluation attestation was signed with fork="
            f"{statement['fork']!r} and this preview now says "
            f"{document['fork']!r}. A fork prohibition outside the signature "
            "is a prohibition that fails open; nothing was signed")
    declared = _dependency_edges(document["dependencies"])
    if statement["dependencies"] != declared:
        raise GitHubError(
            f"the evaluation attestation covers "
            f"{len(statement['dependencies'])} dependency edge(s) and this "
            f"preview declares {len(declared)}; the dependency graph a receipt "
            "records is not something a candidate may edit after the observer "
            "signed it, and nothing was signed")
    expected_decision = digest_of_document(decision_document)
    if statement["decision_digest"] != expected_decision:
        raise GitHubError(
            "the evaluation attestation was signed over a different decision "
            "document than the one in this preview; nothing was signed")
    for label, observed, present in (
            ("command", statement["command_digests"],
             sorted(evidence_module.evidence_digest(record)
                    for record in bundle.commands)),
            ("review", statement["review_digests"],
             sorted(evidence_module.evidence_digest(record)
                    for record in bundle.reviews))):
        if sorted(observed) != present:
            raise GitHubError(
                f"the evaluation attestation covers {len(observed)} {label} "
                f"record(s) and this preview carries {len(present)}; the "
                "observer signed for a different set of records than the one "
                "presented here, and nothing was signed")
    receipt = statement["source_receipt"]
    if receipt["commit_sha"] != commit_sha:
        raise GitHubError(
            f"the evaluation attestation carries a source receipt for commit "
            f"{receipt['commit_sha']} and this job is finalising {commit_sha}; "
            "an observer cannot vouch for one run with another run's receipt, "
            "and nothing was signed")
    observed_at = statement["observed_at"]
    if observed_at > now + MAX_CLOCK_SKEW_SECONDS:
        raise GitHubError(
            f"the evaluation attestation says it was observed {observed_at}, "
            f"which is {observed_at - now}s in the future of this job's clock. "
            "A receipt is issued at the moment of observation, so an "
            "observation nobody has reached yet cannot issue one; nothing was "
            "signed")
    if statement["issued_at"] > observed_at + MAX_CLOCK_SKEW_SECONDS:
        raise GitHubError(
            f"the preview was issued at {statement['issued_at']} and the "
            f"observer says it looked at {observed_at}, before the evaluation "
            "it claims to have observed had finished; nothing was signed")
    return verified


def _validated_finalization(
        store, preview_path: Path | str, *, expected_sha: str, now: int,
        policy_root: Path | str | None = None,
        evaluation_attestation: Path | str | None = None,
        evaluation_keyring: Mapping[str, bytes] | None = None,
        reviews: Path | str | None = None,
        environment: Mapping[str, str] | None = None,
        keyring: Mapping[str, bytes] | None = None,
        admission_signer=None) -> _Finalization:
    """Authenticate a preview and return exact receipt parts without writing.

    This function reads data only. It starts no subprocess, imports no
    candidate module, and runs no package script.

    ``policy_root`` is a *trusted* checkout of the same commit, made by the
    trusted workflow with a pinned checkout action. It is required: repository,
    commit, tree, cleanliness and policy are all re-derived from what this job
    can actually see, and the preview's own assertions about them are only ever
    compared, never believed. The decision is recomputed here too, so the
    finalizer trusts the evaluate job's *evidence* and none of its arithmetic.

    ``reviews`` is the out-of-band transport for signed reviews and authorship
    claims, and it exists because there is no in-band one that could work. A
    review binds the commit and tree it approves, so committing it into that
    tree changes both values it signs: the hash would have to contain itself.
    An evaluate job therefore cannot carry a review of the commit it is
    evaluating, and without this input a class requiring independent review had
    no path to admission at all on the hosted gate.

    Nothing about that transport is trusted. The bundle carries *signed*
    records only -- no command evidence, no unsigned reviews, no defects -- and
    each one is authenticated here against the same pinned keyring, bound to
    the same exact repository, commit, tree and policy, and counted by the key
    that actually signed. Command records are deliberately excluded: those are
    the records an external observer exists to witness, and a side channel that
    could add one would be a side channel that could fabricate a pass.

    ``evaluation_attestation`` is required, and it is the reason any of the
    above is worth doing. Recomputing a decision from evidence proves the
    arithmetic, not the evidence: the job that produced those records ran
    candidate-owned commands, and a command can leave a process behind that
    edits what the job later reports. So the records only count when an
    external observer -- running after the candidate's process group is gone,
    holding a key that job never sees -- has signed for the exact repository,
    commit, tree, policy, attempt, and record digests. Without one, no receipt
    is issued and nothing is written.
    """

    source = os.environ if environment is None else environment
    if policy_root is None:
        raise GitHubError(
            "finalize needs --policy-root: a trusted checkout of the exact "
            "commit, so repository, tree and policy can be re-derived here "
            "instead of taken from the preview's word for it")
    assert_trusted_tool(policy_root)

    document = _load_preview(preview_path)
    if document["schema"] != PREVIEW_SCHEMA:
        raise GitHubError(f"the preview schema must be {PREVIEW_SCHEMA!r}")
    decision_document = _preview_decision(document)
    # Exactly ``False``, never "not true". ``null``, ``0`` and ``"false"`` all
    # failed the old test and all mean "somebody edited this field".
    if document["fork"] is not False:
        raise GitHubError(
            f"this preview says fork={document['fork']!r}. A fork can evaluate "
            "and can never be finalised, and a fork flag that is anything but "
            "exactly false is a prohibition somebody has been editing. Re-run "
            "the gate on a branch of this repository.")
    commit_sha = _full_sha(document["commit_sha"])
    tree_sha = _full_sha(document["tree_sha"])
    if commit_sha != _full_sha(expected_sha):
        raise GitHubError(
            f"the preview describes {commit_sha} but this job was asked to "
            f"finalise {expected_sha}; nothing was signed")
    # An evaluate job holds no reviewer keyring, so a class that requires
    # independent review can never be ADMITTED there. Refusing every such
    # preview would mean high-risk classes could never be admitted at all, and
    # calling them ADMITTED in the evaluate job would be a lie. The third answer
    # is the honest one: accept the preview that says the deterministic work is
    # done and the reviews are still to be authenticated, then authenticate them
    # here and recompute the entire decision below. Nothing about this preview
    # is believed; it only decides whether the work is worth doing.
    readiness = document["readiness"]
    if readiness not in _FINALIZABLE_READINESS:
        raise GitHubError(
            f"this preview is {readiness!r}: the evaluation that produced it "
            "did not establish the deterministic evidence a review could ever "
            "complete. Only READY_FOR_ATTESTATION or AWAITING_REVIEW is worth "
            f"finalising. Its decision state is {document['state']!r}")
    for key in ("repository", "class_id", "policy_digest"):
        if type(document[key]) is not str or not document[key]:
            raise GitHubError(f"the preview {key} must be a non-empty string")
    if type(document["issued_at"]) is not int:
        raise GitHubError("the preview issued_at must be a plain integer")

    # What this job can actually see, from the trusted checkout.
    try:
        observed = git_reader.repository_identity(
            policy_root, expected_sha=commit_sha)
    except IdentityError as error:
        raise GitHubError(
            f"the trusted checkout at {policy_root} is not the exact artefact "
            f"this preview describes: {error}") from None
    if observed.tree_sha != tree_sha:
        raise GitHubError(
            f"the preview claims tree {tree_sha}, but commit {commit_sha} in "
            f"the trusted checkout has tree {observed.tree_sha}; nothing was "
            "signed")
    if observed.repository != document["repository"]:
        raise GitHubError(
            f"the preview claims repository {document['repository']!r}, but "
            f"the trusted checkout is {observed.repository!r}; nothing was "
            "signed")
    slug = source.get("GITHUB_REPOSITORY") or ""
    if slug.strip():
        server = (source.get("GITHUB_SERVER_URL") or "https://github.com").rstrip("/")
        running_in = normalize_remote(f"{server}/{slug}")
        if running_in != observed.repository:
            raise GitHubError(
                f"this job runs for {running_in!r} but the checkout it was "
                f"given is {observed.repository!r}; nothing was signed")

    try:
        bundle = evidence_module.parse_bundle(document["evidence"])
    except evidence_module.EvidenceError as error:
        raise GitHubError(f"the preview evidence is not valid: {error}") from None
    repository = observed.repository
    policy_digest = document["policy_digest"]
    for record in bundle.commands + bundle.reviews:
        if (record.repository != repository or record.commit_sha != commit_sha
                or record.tree_sha != tree_sha
                or record.policy_digest != policy_digest):
            raise GitHubError(
                "the preview carries evidence that is not bound to this exact "
                "repository, commit, tree and policy")
    if bundle.defects:
        raise GitHubError("a preview must not carry defect records")

    # Blocking reviews are authenticated here, against a keyring this job owns.
    try:
        reviewer_keyring = (review_module.load_keyring(source)
                            if keyring is None else dict(keyring))
        # Whether it came from the environment or from a caller, two ids in it
        # must be two secrets. A class requiring two independent reviews counts
        # distinct key ids, and one secret mapped twice satisfies that count
        # with one holder.
        review_module.assert_distinct_secrets(
            reviewer_keyring, where="the reviewer keyring")
        _assert_separate_domains(reviewer_keyring, source,
                                 evaluation_keyring,
                                 signer=admission_signer)
        verified = review_module.verify_bundle_attestations(
            bundle, reviewer_keyring)
    except review_module.ReviewError as error:
        raise GitHubError(
            f"a review attestation in this preview is not usable: {error}"
        ) from None
    for item in verified:
        record = item.record
        if (record.repository != repository or record.commit_sha != commit_sha
                or record.tree_sha != tree_sha
                or record.policy_digest != policy_digest):
            raise GitHubError(
                "a signed review in this preview is not bound to this exact "
                "repository, commit, tree and policy")
    # Authorship claims are authenticated against the same keyring of human
    # identities. Which of those ids may review and which may author is the
    # policy's business, and the two lists are disjoint by construction.
    try:
        authorships = review_module.verify_bundle_authorship(
            bundle, reviewer_keyring)
    except review_module.ReviewError as error:
        raise GitHubError(
            f"an authorship attestation in this preview is not usable: {error}"
        ) from None
    for item in authorships:
        record = item.record
        if (record.repository != repository or record.commit_sha != commit_sha
                or record.tree_sha != tree_sha
                or record.policy_digest != policy_digest):
            raise GitHubError(
                "a signed authorship claim in this preview is not bound to "
                "this exact repository, commit, tree and policy")

    if reviews is not None:
        try:
            supplied = evidence_module.load_evidence_file(reviews)
        except evidence_module.EvidenceError as error:
            raise GitHubError(
                f"the signed review bundle is not usable: {error}") from None
        for label, present in (("command", supplied.commands),
                               ("defect", supplied.defects),
                               ("unsigned review", supplied.reviews)):
            if present:
                raise GitHubError(
                    f"the signed review bundle carries {len(present)} "
                    f"{label} record(s). This transport carries signed reviews "
                    "and signed authorship claims and nothing else: a command "
                    "record is exactly what the external observer exists to "
                    "witness, and an unsigned review is a claim by whoever "
                    "wrote the file. Nothing was signed.")
        try:
            extra_reviews = review_module.verify_bundle_attestations(
                supplied, reviewer_keyring)
            extra_authorships = review_module.verify_bundle_authorship(
                supplied, reviewer_keyring)
        except review_module.ReviewError as error:
            raise GitHubError(
                f"a record in the signed review bundle is not usable: {error}"
            ) from None
        for item in extra_reviews + extra_authorships:
            record = item.record
            if (record.repository != repository
                    or record.commit_sha != commit_sha
                    or record.tree_sha != tree_sha
                    or record.policy_digest != policy_digest):
                raise GitHubError(
                    "a record in the signed review bundle is not bound to "
                    "this exact repository, commit, tree and policy")
        verified = verified + extra_reviews
        authorships = authorships + extra_authorships

    from admissible_core.config import ConfigError, load_config
    from admissible_core.decision import decision_to_dict

    config_relative = document["config_path"]
    if type(config_relative) is not str or not config_relative.strip():
        raise GitHubError(
            "the preview must name the exact policy file it was evaluated "
            "under; a preview that does not say which file decided it cannot "
            "be re-checked against that file")

    attempt_id = decision_document.get("attempt_id")
    if type(attempt_id) is not str or not attempt_id.strip():
        raise GitHubError(
            "the preview decision names no attempt. A receipt records one "
            "observation of one artefact at one moment, and a decision that "
            "belongs to no attempt cannot be that")

    # The external observer's statement, verified before anything else is read
    # off the preview. It comes first because everything after it uses fields
    # this is what authenticates: the policy file to open is one of them, and
    # opening whichever file the preview happens to name would report a missing
    # file where the real answer is "this preview was edited after signing".
    verified_evaluation = _verified_evaluation(
        evaluation_attestation, evaluation_keyring, source,
        repository=repository, commit_sha=commit_sha, tree_sha=tree_sha,
        policy_digest=policy_digest, class_id=document["class_id"],
        attempt_id=attempt_id, bundle=bundle, document=document,
        decision_document=decision_document, now=now)

    # Isolation is an assertion made by the external observer from evidence in
    # its own trust domain. The preview's field is candidate-adjacent and is
    # deliberately never consulted here.
    from admissible_core.isolation import ISOLATION_MODES, ISOLATION_NONE

    observer_isolation = verified_evaluation["evaluation"]["isolation"]
    if observer_isolation not in ISOLATION_MODES:
        raise GitHubError(
            f"the observer asserted isolation {observer_isolation!r}, which "
            "names no boundary this product knows. Nothing was signed.")
    if observer_isolation == ISOLATION_NONE:
        raise GitHubError(
            "the observer asserted no isolation boundary. Candidate-owned "
            "commands can leave descendants behind to rewrite a preview after "
            "evaluation, so only an observer that independently verified a "
            "destroyed PID namespace, single-use machine, or separate uid may "
            "complete an admission. Nothing was signed.")

    try:
        parsed = load_config(policy_root, config_relative)
        artifact_class = parsed.select_class(document["class_id"])
    except ConfigError as error:
        raise GitHubError(
            f"cannot re-check the policy at {policy_root}/{config_relative}: "
            f"{error}") from None
    if artifact_class.policy_digest != policy_digest:
        raise GitHubError(
            "the policy in this checkout does not match the policy the "
            "preview was evaluated under")
    # A candidate may propose a policy. Only an operator makes one enforceable.
    require_trusted_policy(store, repository=repository,
                           class_id=document["class_id"],
                           artifact_class=artifact_class, now=now)

    # Reconstruct what the untrusted evaluator itself was entitled to know.
    # Signed review/authorship documents remain claims at that boundary: their
    # independent keyring is intentionally held only by this finalizer. This
    # re-derivation happens before the provider conclusion matrix, so a forged
    # AWAITING_REVIEW label can never broaden `failure` into an admissible run.
    try:
        pending_reviews = review_module.carry_bundle_attestations(bundle)
        pending_authorships = review_module.carry_bundle_authorship(bundle)
    except (review_module.ReviewError,
            evidence_module.EvidenceError) as error:
        raise GitHubError(
            f"the preview cannot be re-derived as evaluator evidence: {error}"
        ) from None
    evaluation_time = verified_evaluation["evaluation"]["issued_at"]
    evaluator_result = evaluate(
        artifact_class=artifact_class, repository=repository,
        commit_sha=commit_sha, tree_sha=tree_sha,
        policy_digest=policy_digest, commands=bundle.commands,
        reviews=bundle.reviews + pending_reviews,
        authorships=pending_authorships, now=evaluation_time,
        attempt_id=attempt_id)
    evaluator_readiness = evaluator_result.readiness
    if (document["state"] != evaluator_result.state
            or document["readiness"] != evaluator_readiness):
        raise GitHubError(
            "the trusted policy and bound preview evidence re-derived "
            f"evaluation state/readiness {evaluator_result.state}/"
            f"{evaluator_readiness}, but the top-level preview and its embedded "
            f"decision say {document['state']}/{document['readiness']}. "
            "Provider conclusions are interpreted only against the re-derived "
            "pair; nothing was signed")

    source_receipt = verified_evaluation["evaluation"]["source_receipt"]
    acceptable = attestation_module.admissible_source_conclusions(
        evaluator_readiness)
    if source_receipt["conclusion"] not in acceptable:
        allowed = (", ".join(sorted(acceptable))
                   if acceptable else "no conclusion")
        raise GitHubError(
            f"the external source receipt from "
            f"{source_receipt['provider']!r} for run "
            f"{source_receipt['run_id']!r} reports conclusion "
            f"{source_receipt['conclusion']!r}, and the trusted policy plus "
            f"bound evidence re-derived readiness {evaluator_readiness!r}. "
            f"Only {allowed} completes an admission at that readiness; "
            "cancelled and timed_out runs never do. Nothing was signed")

    # The observer closes candidate-controlled evidence at observed_at. Human
    # authorities are deliberately separate and may be signed later without
    # asking the observer to re-sign.  Use the latest authenticated authority
    # timestamp as the deterministic cut at which those independent inputs
    # meet.  This remains stable across retries, while evaluating at the older
    # observer time would incorrectly call every review arriving more than the
    # ordinary clock-skew allowance "future dated".
    observed_at = verified_evaluation["evaluation"]["observed_at"]
    authority_time = max(
        (observed_at,
         *(item.record.issued_at for item in verified),
         *(item.record.issued_at for item in authorships)))
    if authority_time > now + MAX_CLOCK_SKEW_SECONDS:
        raise GitHubError(
            f"a signed review or authorship authority is dated "
            f"{authority_time - now}s in the future of this finalizer's "
            "clock. Independent authorities may arrive after observation, "
            "but they cannot claim a time nobody has reached; nothing was "
            "signed")
    recomputed = evaluate(
        artifact_class=artifact_class, repository=repository,
        commit_sha=commit_sha, tree_sha=tree_sha,
        policy_digest=policy_digest, commands=bundle.commands,
        reviews=bundle.reviews + verified,
        authorships=authorships, now=authority_time, attempt_id=attempt_id)
    if recomputed.state != CHECKS_PASSED:
        raise GitHubError(
            "re-checking the preview evidence here does not admit this "
            f"commit ({recomputed.state}); nothing was signed. "
            + "; ".join(f"[{reason.code}] {reason.detail}"
                        for reason in recomputed.reasons))
    decision_digest_value = digest_of_document(decision_to_dict(recomputed))
    evidence_digests = tuple(recomputed.evidence_digests)

    declared = tuple(
        (edge["repository"], edge["commit_sha"])
        for edge in _dependency_edges(document["dependencies"]))
    return _Finalization(
        repository=repository, commit_sha=commit_sha, tree_sha=tree_sha,
        class_id=document["class_id"], policy_digest=policy_digest,
        attempt_id=attempt_id, decision_digest_value=decision_digest_value,
        evidence_digests=evidence_digests, commands=bundle.commands,
        reviews=tuple(item.record for item in verified) + bundle.reviews,
        authorships=tuple(item.record for item in authorships),
        authenticated_reviews=approving_reviews(verified),
        dependencies=declared, issued_at=authority_time)


def _receipt_body_arguments(parts: _Finalization) -> dict[str, Any]:
    return {
        "repository": parts.repository,
        "commit_sha": parts.commit_sha,
        "tree_sha": parts.tree_sha,
        "class_id": parts.class_id,
        "policy_digest": parts.policy_digest,
        "state": ADMITTED,
        "attempt_id": parts.attempt_id,
        "decision_digest_value": parts.decision_digest_value,
        "evidence_digests": parts.evidence_digests,
        "authenticated_reviews": parts.authenticated_reviews,
        "dependencies": parts.dependencies,
        "issued_at": parts.issued_at,
    }


def expected_finalization_receipt_body_digest(
        store, preview_path: Path | str, *, expected_sha: str, now: int,
        policy_root: Path | str | None = None,
        evaluation_attestation: Path | str | None = None,
        evaluation_keyring: Mapping[str, bytes] | None = None,
        reviews: Path | str | None = None,
        environment: Mapping[str, str] | None = None,
        keyring: Mapping[str, bytes] | None = None) -> str:
    """Validate exactly as finalize and derive its body digest without writes."""

    parts = _validated_finalization(
        store, preview_path, expected_sha=expected_sha, now=now,
        policy_root=policy_root,
        evaluation_attestation=evaluation_attestation,
        evaluation_keyring=evaluation_keyring, reviews=reviews,
        environment=environment, keyring=keyring)
    return receipt_module.expected_receipt_body_digest(
        **_receipt_body_arguments(parts))


def finalize(store, preview_path: Path | str, *, signer, expected_sha: str,
             now: int, policy_root: Path | str | None = None,
             evaluation_attestation: Path | str | None = None,
             evaluation_keyring: Mapping[str, bytes] | None = None,
             reviews: Path | str | None = None,
             environment: Mapping[str, str] | None = None,
             keyring: Mapping[str, bytes] | None = None,
             expected_body_digest: str | None = None):
    """Authenticate a validated preview and atomically issue its exact receipt.

    Dependency edges come only from the observer-bound preview. There is no
    public dependency-injection parameter: callers cannot append authority to
    the signed graph while finalizing it.
    """

    parts = _validated_finalization(
        store, preview_path, expected_sha=expected_sha, now=now,
        policy_root=policy_root,
        evaluation_attestation=evaluation_attestation,
        evaluation_keyring=evaluation_keyring, reviews=reviews,
        environment=environment, keyring=keyring,
        admission_signer=signer)
    body_arguments = _receipt_body_arguments(parts)
    actual_body_digest = receipt_module.expected_receipt_body_digest(
        **body_arguments)
    if expected_body_digest is not None:
        if (type(expected_body_digest) is not str
                or len(expected_body_digest) != 64
                or any(character not in "0123456789abcdef"
                       for character in expected_body_digest)):
            raise GitHubError(
                "the expected receipt body digest must be a lowercase "
                "64-character hex string; nothing was signed")
        if actual_body_digest != expected_body_digest:
            raise GitHubError(
                "revalidating finalization produced expected receipt body "
                f"{actual_body_digest}, but interrupt recovery is guarding "
                f"the previously validated body {expected_body_digest}. "
                "A mutable preview, authority bundle, or policy input changed "
                "between preparation and issuance; nothing was signed")
    body_arguments.pop("issued_at")
    return receipt_module.issue_receipt_from_parts(
        store, commands=parts.commands, reviews=parts.reviews,
        authorships=parts.authorships, signer=signer, now=parts.issued_at,
        _require_current_policy=True,
        **body_arguments)
