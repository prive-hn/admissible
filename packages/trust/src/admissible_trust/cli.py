"""``admissible-trust`` — the commands that hold a key, and only those.

Every verb here needs a credential to mean anything, and each one loads exactly
the credential its own role names: ``attest-review`` reads the reviewer key,
``attest-evaluation`` reads the observer key, and the rest read the admission
key. None of them guesses. A command is never selected by which secret happens
to be in the environment -- ambient credentials are a fail-closed guard, not a
router -- and no key material is ever accepted from a command-line argument,
written to the database, or printed to a stream.

What is absent is the point. There is no ``profiles``, ``init``, ``run
--preview``, ``check``, ``mcp``, ``connect`` or ``ui``: each of those starts a
process the repository under evaluation chose, and this is the process holding
the key. They live in ``admissible-ready``, and they are not hidden here behind
a flag -- the wheel does not contain a runner, an MCP server or an HTTP server
at all.

``run`` is retained for one release window as an explicit alias for
``finalize`` over a retained preview. It consumes files; it never executes a
check. Invoked without a preview it refuses and says where each half of the old
verb went.

Exit codes are stable within each command. ``finalize`` returning zero means a
receipt was issued (or the exact receipt was already present), while ``verify``
and ``status`` return zero only for authenticated ``CURRENT`` standing. Nonzero
means refused/not current, or an operationally blocked invocation as the
command's JSON envelope describes.

Every command prints what happened, what is known, and what to do next. A
``--json`` caller gets that as a document on stdout and never has to parse
prose; warnings and refusals for a human go to stderr.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any, TextIO

from admissible_core import evidence as evidence_module
from admissible_core import identity as identity_module
from admissible_core.config import (CONFIG_FILENAME, ConfigError,
                                    enforcement_digest, load_config)
from admissible_core.decision import (BLOCKED, READINESS_NOT_READY,
                                      READINESS_READY_FOR_ATTESTATION,
                                      decision_to_dict, evaluate)
from admissible_core.isolation import ISOLATION_MODES

from . import attestation as attestation_module
from . import defects as defects_module
from . import git_reader
from . import github as github_module
from . import ready_status
from . import receipt as receipt_module
from . import review as review_module
from . import standing as standing_module
from . import store as store_module

__all__ = ["main"]

EXIT_OK = 0
EXIT_NOT_CURRENT = 1
EXIT_BLOCKED = 2

_FULL_SHA_LENGTH = 40
_RECEIPT_HASH_LENGTH = 64


class _Usage(Exception):
    """argparse wanted to exit; the CLI decides what to print and return."""

    def __init__(self, message: str, code: int = EXIT_BLOCKED) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # pragma: no cover - argparse plumbing
        raise _Usage(f"admissible-trust: {message}\n{self.format_usage()}")

    def exit(self, status: int = 0, message: str | None = None):
        raise _Usage(message or "", EXIT_BLOCKED if status else EXIT_OK)


def _build_parser() -> _Parser:
    parser = _Parser(prog="admissible-trust", add_help=False,
                     description="The credentialed half of the Admissible gate.")
    parser.add_argument("--help", "-h", action="store_true", dest="help")
    commands = parser.add_subparsers(dest="command")

    def with_repo(sub):
        sub.add_argument("--repo", default=".",
                         help="repository root (default: current directory)")
        sub.add_argument("--json", action="store_true",
                         help="print a stable JSON document instead of prose")
        return sub

    ready_status_command = commands.add_parser("ready-status", add_help=False)
    with_repo(ready_status_command)

    attest = commands.add_parser("attest-review", add_help=False)
    attest.add_argument("--review", required=True, metavar="FILE")
    attest.add_argument("--out", required=True, metavar="FILE")
    attest.add_argument("--authorship", action="store_true",
                        help="sign an authorship record instead of a review: "
                             "this is how an author's identity becomes a key "
                             "rather than a string somebody typed")
    with_repo(attest)

    attest_evaluation = commands.add_parser("attest-evaluation",
                                            add_help=False)
    attest_evaluation.add_argument("--preview", required=True, metavar="FILE")
    attest_evaluation.add_argument("--out", required=True, metavar="FILE")
    attest_evaluation.add_argument("--source-receipt", required=True,
                                   dest="source_receipt", metavar="FILE",
                                   help="the closed receipt this observer read "
                                        "from the provider outside this run: "
                                        "provider, immutable run or job id, "
                                        "exact commit, conclusion, and the "
                                        "digest of the receipt document")
    attest_evaluation.add_argument(
        "--isolation", required=True, choices=ISOLATION_MODES,
        help="the isolation boundary this trusted observer independently "
             "validated from external infrastructure evidence; the preview's "
             "own isolation text is never authority")
    with_repo(attest_evaluation)

    policy = commands.add_parser("policy", add_help=False)
    policy_commands = policy.add_subparsers(dest="policy_command")
    trust = policy_commands.add_parser("trust", add_help=False)
    trust.add_argument("--class", dest="class_id", default=None)
    trust.add_argument("--config", dest="config_path", default=None,
                       metavar="FILE")
    with_repo(trust)
    revoke = policy_commands.add_parser("revoke", add_help=False)
    revoke.add_argument("--class", dest="class_id", required=True)
    revoke.add_argument("--digest", dest="policy_digest", required=True,
                        metavar="SHA256",
                        help="the policy digest to withdraw; read it from "
                             "'admissible-trust policy list --json'")
    with_repo(revoke)
    policy_listing = policy_commands.add_parser("list", add_help=False)
    policy_listing.add_argument("--class", dest="class_id", default=None)
    policy_listing.add_argument("--config", dest="config_path", default=None,
                                metavar="FILE")
    policy_listing.add_argument("--all", dest="include_superseded",
                                action="store_true",
                                help="include superseded generations, which "
                                     "are history and not authority")
    with_repo(policy_listing)

    def finalize_arguments(sub, *, required: bool):
        sub.add_argument("--preview", required=required, default=None,
                         metavar="FILE")
        sub.add_argument("--sha", required=required, default=None)
        sub.add_argument("--policy-root", required=required, default=None,
                         metavar="DIR",
                         help="trusted read-only checkout of the same commit; "
                              "repository, tree and policy are re-derived "
                              "there and the decision is recomputed")
        sub.add_argument("--evaluation-attestation", required=required,
                         default=None, dest="evaluation_attestation",
                         metavar="FILE",
                         help="the external observer's signed statement about "
                              "the evaluation that produced this preview")
        sub.add_argument("--reviews", default=None, metavar="FILE",
                         help="signed reviews and authorship claims that "
                              "reached this finalizer out of band; a review "
                              "binds the tree it approves and so can never "
                              "travel inside it")
        sub.add_argument("--out", default=None, metavar="FILE",
                         help="write the receipt here; written and validated "
                              "before the admission is anchored")
        return with_repo(sub)

    finalize_arguments(commands.add_parser("finalize", add_help=False),
                       required=True)
    # The transitional verb. Every argument is optional so that a bare `run`
    # reaches its handler and can say where each half of the old command went,
    # rather than dying in argparse with a message about missing flags.
    finalize_arguments(commands.add_parser("run", add_help=False),
                       required=False)

    verify = commands.add_parser("verify", add_help=False)
    verify.add_argument("target")
    with_repo(verify)

    explain = commands.add_parser("explain", add_help=False)
    explain.add_argument("target")
    explain.add_argument("--class", dest="class_id", default=None)
    with_repo(explain)

    export = commands.add_parser("export", add_help=False)
    export.add_argument("--out", required=True, metavar="FILE")
    export.add_argument(
        "--through-head", dest="through_head", default=None, metavar="HASH",
        help="export an explicit historical journal cut ending at this "
             "stored signed head; it is cumulative from genesis, may omit "
             "later defects, and is not an incremental path around the "
             "import ceiling")
    with_repo(export)

    importer = commands.add_parser("import", add_help=False)
    importer.add_argument("--in", dest="source", required=True, metavar="FILE")
    with_repo(importer)

    with_repo(commands.add_parser("status", add_help=False))

    impeach = commands.add_parser("impeach", add_help=False)
    impeach.add_argument("target")
    impeach.add_argument("--evidence", required=True)
    impeach.add_argument("--test", dest="test_id", default=None)
    with_repo(impeach)
    return parser


_HELP = """usage: admissible-trust COMMAND [options]

Commands:
  ready-status [--repo DIR]               authenticated Ready projection; the
                                          only place 'ready' is ever said
  attest-review --review FILE --out FILE  sign a review with a reviewer key
      [--authorship]                      ...or an authorship record
  attest-evaluation --preview FILE        sign, as the external observer, the
      --source-receipt FILE               evaluation and the external receipt
      --isolation MODE --out FILE         the observer independently validated
  policy trust [--class ID]               record the enforceable policy
      [--config FILE]                     baseline for this repository
  policy list [--class ID] [--all]        show what may enforce here now
  policy revoke --class ID                withdraw one trusted policy
      --digest SHA256                     without rewriting the record of it
  finalize --preview FILE --sha SHA       sign a validated preview artefact
      --policy-root DIR                   (a trusted checkout of that commit)
      --evaluation-attestation FILE       (the observer's signed statement)
      [--reviews FILE] [--out FILE]
  verify TARGET                           check standing and authenticity
  explain TARGET                          explain what is known about TARGET
  status                                  summarise this repository
  export --out FILE                       export this repository's journal
      [--through-head HASH]               ...or an explicit historical cut
  import --in FILE                        import a journal, refusing rollback
  impeach TARGET --evidence FILE          file a defect against TARGET
      [--test CHECK_ID]
  run ...                                 transitional alias for 'finalize';
                                          it consumes a retained preview and
                                          never runs a check

Common options: --repo DIR, --json

Not here, and not hidden: profiles, init, run --preview, check, mcp, connect
and ui all start a process the repository chose, and this is the process that
holds the key. They are in 'admissible-ready', which ships no key loader.

Three separate keys, and none of them substitutes for another:
  ADMISSIBLE_HMAC_KEY        signs admissions        (finalize, impeach, import)
  ADMISSIBLE_REVIEW_KEY      signs reviews           (a reviewer)
  ADMISSIBLE_EVALUATION_KEY  signs evaluations       (an external observer)

Exit codes are command-specific:
  finalize: 0 = an authenticated receipt is ADMITTED
  verify/status/ready-status: 0 = authenticated CURRENT standing
  nonzero: refused/not current, or blocked as the command output explains.
"""


def _fail(stream: TextIO, message: str, *, next_steps: tuple[str, ...] = (),
          json_mode: bool = False) -> int:
    """Report a blocked invocation on the stream the caller is reading."""

    steps = tuple(next_steps) or ("fix the problem above and re-run",)
    if json_mode:
        # A --json caller must never have to parse prose off stdout.
        _dump(stream, {
            "scope": receipt_module.RECEIPT_SCOPE,
            "state": BLOCKED,
            # An operational failure establishes nothing, so it carries the
            # same readiness key a decision does. A consumer reading `readiness`
            # must never have to special-case the shape it gets back.
            "readiness": READINESS_NOT_READY,
            "exit_code": EXIT_BLOCKED,
            "message": message,
            "remediation": list(steps),
        })
        return EXIT_BLOCKED
    stream.write(f"What happened: BLOCKED. {message}\n")
    stream.write("What is known: nothing was recorded for this invocation.\n")
    stream.write("What to do next:\n")
    for line in steps:
        stream.write(f"  - {line}\n")
    return EXIT_BLOCKED


def _dump(stdout: TextIO, document: dict[str, Any]) -> None:
    stdout.write(json.dumps(document, indent=2, sort_keys=True) + "\n")


def _full_sha(value: str) -> bool:
    return (len(value) == _FULL_SHA_LENGTH
            and all(character in "0123456789abcdef" for character in value))


def _open_store(stderr: TextIO):
    return store_module.open_store()


def _json_mode(options) -> bool:
    return bool(getattr(options, "json", False))


def _identity(root: str, *, expected_sha: str | None = None,
              allow_dirty: bool = False):
    """Exact identity, through this distribution's fixed Git adapter."""

    return git_reader.repository_identity(
        root, expected_sha=expected_sha, allow_dirty=allow_dirty)


def _command_attest_review(options, stdout: TextIO, stderr: TextIO) -> int:
    """Sign a closed review record with a reviewer key.

    This is the only way an imported review can block a merge. The key is
    deliberately separate from the workflow signing key, so holding the
    finalizer's secret does not let anyone mint the reviews it then honours.
    """

    stream = stdout if options.json else stderr
    try:
        key_id, secret = review_module.load_review_signer()
        raw = Path(options.review).read_bytes()
        if len(raw) > evidence_module.MAX_EVIDENCE_BYTES:
            raise ValueError(f"{options.review} is too large")
        document = json.loads(raw.decode("utf-8"))
        if options.authorship:
            attestation = review_module.attest_authorship(
                document, key_id=key_id, secret=secret)
        else:
            attestation = review_module.attest(document, key_id=key_id,
                                               secret=secret)
        Path(options.out).write_text(
            json.dumps(attestation, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
    except (review_module.ReviewError, OSError, ValueError,
            json.JSONDecodeError) as error:
        return _fail(stream, str(error), json_mode=options.json, next_steps=(
            "set ADMISSIBLE_REVIEW_KEY_ID and ADMISSIBLE_REVIEW_KEY (or "
            "ADMISSIBLE_REVIEW_KEY_FILE) for the reviewer identity",
            "pass --review a closed review-evidence record for one exact "
            "commit, tree and policy",
        ))
    role = "authorship" if options.authorship else "review"
    array = "author_attestations" if options.authorship else "attestations"
    pinned = "author_key_ids" if options.authorship else "reviewer_key_ids"
    if options.json:
        _dump(stdout, {"path": options.out, "key_id": key_id,
                       "algorithm": "hmac-sha256", "role": role})
        return EXIT_OK
    stdout.write(f"What happened: signed {options.review} as a {role} "
                 f"attestation by key {key_id!r} and wrote {options.out}.\n\n")
    stdout.write("What is known:\n")
    stdout.write("  - HMAC-SHA256 proves a holder of this key signed it; it is "
                 "not public non-repudiation\n")
    if options.authorship:
        stdout.write("  - a class requiring independent review admits nothing "
                     "without an authenticated authorship claim: excluding an "
                     "author from reviewing their own change is a rule about "
                     "a key, never about a string in a document\n\n")
    else:
        stdout.write("  - a finalizer counts blocking reviews by distinct "
                     "authenticated key id, not by the reviewer_id string\n\n")
    stdout.write("What to do next:\n")
    stdout.write(f"  - put the attestation in the {array!r} array of an "
                 "evidence bundle and pass it with 'admissible-ready run "
                 "--preview --evidence', or hand it to 'admissible-trust "
                 "finalize --reviews' out of band\n")
    stdout.write(f"  - pin this key id in {pinned} for the class it applies "
                 "to\n")
    return EXIT_OK


def _command_ready_status(options, stdout: TextIO, stderr: TextIO) -> int:
    """Authenticate standing without executing candidate-owned checks."""

    stream = stdout if options.json else stderr
    try:
        found = _identity(options.repo, allow_dirty=True)
    except identity_module.IdentityError as error:
        return _fail(stream, str(error), json_mode=options.json)
    try:
        signer = receipt_module.load_signer()
    except receipt_module.SigningError as error:
        return _fail(
            stream, str(error), json_mode=options.json, next_steps=(
                "run ready-status in the trusted status domain that "
                "holds ADMISSIBLE_HMAC_KEY",
                "never place that key in a process that runs candidate "
                "checks; the Ready UI and MCP server refuse to start "
                "beside one",
            ))
    document = ready_status.inspect_authenticated(
        options.repo, verifier=signer, identity=found)
    if options.json:
        _dump(stdout, document)
    else:
        stdout.write(ready_status.render_plain(document))
    return EXIT_OK if document["status"] == "ready" else EXIT_NOT_CURRENT


def _resolve_target(options, stream: TextIO):
    found = _identity(options.repo, allow_dirty=True)
    target = options.target
    if not _full_sha(target) and len(target) != _RECEIPT_HASH_LENGTH:
        raise identity_module.IdentityError(
            f"TARGET must be a full 40-character commit SHA (or a 64-character "
            f"receipt hash), got {target!r}")
    return found, target


def _receipt_rows(opened, repository: str, target: str) -> tuple:
    if len(target) == _RECEIPT_HASH_LENGTH:
        found = opened.workflow_receipt(target)
        return () if found is None else (found,)
    return opened.receipts_for(repository, target)


def _command_verify(options, stdout: TextIO, stderr: TextIO) -> int:
    stream = stdout if options.json else stderr
    try:
        found, target = _resolve_target(options, stream)
        opened = _open_store(stream)
    except (identity_module.IdentityError, store_module.StoreError) as error:
        return _fail(stream, str(error), json_mode=options.json)
    try:
        receipts = _receipt_rows(opened, found.repository, target)
        # A receipt hash may name an artefact from another repository; standing
        # is then answered in that receipt's namespace, not this checkout's.
        repository = receipts[0].repository if receipts else found.repository
        commit_sha = receipts[0].commit_sha if receipts else target
        signer = None
        if receipts:
            # A key is only needed to authenticate receipts that actually exist.
            try:
                signer = receipt_module.load_signer()
            except receipt_module.SigningError as error:
                return _fail(stream, str(error), json_mode=options.json, next_steps=(
                    "export the ADMISSIBLE_HMAC_KEY that issued these receipts",
                    "until then this artefact cannot be shown to be current",
                ))
        state = standing_module.current_standing(opened, repository,
                                                 commit_sha, verifier=signer)
        signature_valid = bool(receipts)
        signature_detail = []
        for item in receipts:
            try:
                receipt_module.verify_receipt(item, signer)
            except receipt_module.ReceiptError as error:
                signature_valid = False
                signature_detail.append(f"{item.receipt_hash}: {error}")
        reported = state.state if signature_valid or not receipts else "UNVERIFIED"
        exit_code = EXIT_OK if reported == standing_module.CURRENT else EXIT_NOT_CURRENT
        if reported == standing_module.CURRENT:
            remediation = ("nothing; keep the authenticated receipt with the "
                           "artefact",)
        elif reported == "UNVERIFIED":
            remediation = (
                "check ADMISSIBLE_HMAC_KEY_ID and use the key domain that "
                "issued this receipt",
                "treat this artefact as not admitted until the receipt and "
                "journal verify",
            )
        elif reported == standing_module.IMPEACHED:
            remediation = (
                f"run 'admissible-trust explain {commit_sha}' to inspect the signed "
                "defect and its reachable dependents",
            )
        else:
            remediation = (
                f"run 'admissible-ready run --preview --preview-out preview.json "
                f"--sha {commit_sha}' in a clean checkout of that commit",
                "have a trusted observer attest that preview, then run "
                "'admissible-trust finalize' in the durable signing domain",
            )
        if options.json:
            document = standing_module.standing_to_dict(state)
            document["state"] = reported
            document["readiness"] = (
                READINESS_READY_FOR_ATTESTATION
                if reported == standing_module.CURRENT else READINESS_NOT_READY)
            document["exit_code"] = exit_code
            document["message"] = (
                "" if reported == standing_module.CURRENT else
                f"{commit_sha} in {repository} is {reported}")
            document["remediation"] = list(remediation)
            document["signature_valid"] = signature_valid
            document["receipt_hashes"] = [item.receipt_hash for item in receipts]
            document["signature_problems"] = signature_detail
            _dump(stdout, document)
            return exit_code
        stdout.write(
            f"What happened: {commit_sha} in {repository} is {reported}.\n\n")
        stdout.write("What is known:\n")
        stdout.write(f"  - receipts: {len(receipts)}\n")
        stdout.write(f"  - defects filed: {len(state.defects)}\n")
        stdout.write(
            f"  - receipt signature: "
            f"{'authentic under this key' if signature_valid else 'NOT authentic under this key'}\n")
        for line in signature_detail:
            stdout.write(f"    {line}\n")
        stdout.write("  - this is a developer workflow admission, not a proof "
                     "of correctness\n\n")
        stdout.write("What to do next:\n")
        for line in remediation:
            stdout.write(f"  - {line}\n")
        return exit_code
    finally:
        opened.close()


def _attempt_scope(opened, repository: str, commit_sha: str, receipts: tuple):
    """The evidence of one attempt, which attempt it is, and what it recorded.

    Attempts do not mix. The latest attempt is what "would this pass now?"
    means; when a receipt exists but its attempt was recorded elsewhere, the
    receipt's own bound evidence is used instead, so standing and explanation
    always describe the same observation.

    The attempt row is returned with it, because an attempt is history: it
    holds the tree and the decision that were recorded at the time, and asking
    later what a refused attempt said must be answered from those and not from
    whatever the checkout happens to hold today.
    """

    attempt = opened.latest_attempt(repository, commit_sha)
    if attempt is not None:
        return (attempt["attempt_id"], attempt.get("class_id") or "",
                opened.evidence_in_attempt(attempt["attempt_id"]), attempt)
    if receipts:
        latest = receipts[-1]
        anchored = frozenset(latest.evidence_digests)
        return (latest.attempt_id, latest.class_id,
                tuple(row for row in opened.evidence_for(repository, commit_sha)
                      if row["digest"] in anchored), None)
    return "", "", opened.evidence_for(repository, commit_sha), None


def _stored_evidence(rows):
    """Rebuild typed evidence records from durable rows.

    Authorship is rebuilt too. Dropping it silently was not a smaller answer,
    it was a wrong one: a class that requires independent review requires an
    authenticated authorship claim, so re-judging an attempt without the
    authorship it actually recorded reported a missing-authorship refusal for
    evidence that was sitting in the store.
    """

    commands, reviews, authorships = [], [], []
    for row in rows:
        try:
            if row["kind"] == "command":
                commands.append(
                    evidence_module.command_evidence_from_dict(row["record"]))
            elif row["kind"] == "review":
                reviews.append(
                    evidence_module.review_evidence_from_dict(row["record"]))
            elif row["kind"] == "authorship":
                # Carried as a claim, never as an authenticated one. A durable
                # row is the record, not the signature over it: the key id that
                # signed lives in the attestation the finalizer authenticated
                # and is not part of what the receipt binds, so this process
                # has the claim and no way to check it. Saying that is the
                # honest answer, and it is the same answer `explain` already
                # gives about reviews. Dropping the record instead reported a
                # bare "no authorship attestation names who wrote this" for
                # evidence sitting in the store, and passing the bare record on
                # raised TypeError out of the decision layer.
                authorships.append(evidence_module.UnverifiedAuthorship(
                    record=evidence_module.authorship_evidence_from_dict(
                        row["record"]),
                    key_id=""))
        except evidence_module.EvidenceError:
            # A record that no longer parses is reported as absent rather than
            # trusted; the decision below will say what is missing.
            continue
    return tuple(commands), tuple(reviews), tuple(authorships)


def _command_explain(options, stdout: TextIO, stderr: TextIO) -> int:
    stream = stdout if options.json else stderr
    try:
        found, target = _resolve_target(options, stream)
        opened = _open_store(stream)
    except (identity_module.IdentityError, store_module.StoreError) as error:
        return _fail(stream, str(error), json_mode=options.json)
    try:
        receipts = _receipt_rows(opened, found.repository, target)
        repository = receipts[0].repository if receipts else found.repository
        commit_sha = receipts[0].commit_sha if receipts else target
        signature_problems = []
        try:
            signer = receipt_module.load_signer()
        except receipt_module.SigningError as error:
            signer = None
            if receipts:
                signature_problems.append(str(error))
        # Standing is computed from the receipts this key can authenticate, so
        # the state reported here and the signature problems listed below can
        # never disagree: a row nothing could verify used to leave CURRENT in
        # the document and "nothing" in the remediation while the signature
        # failure was reported in a separate field nobody had to read.
        report = standing_module.impact_report(opened, repository, commit_sha,
                                               verifier=signer)
        attempt_id, attempt_class, rows, attempt = _attempt_scope(
            opened, repository, commit_sha, receipts)

        # What this attempt actually decided, as recorded at the time. An
        # attempt is a moment, and the checkout has moved on since: judging
        # yesterday's evidence against today's tree produces stale-tree and
        # missing-check complaints that describe nothing that ever happened.
        recorded = attempt.get("decision") if attempt else None

        # And, separately, what this repository's *current* policy would say
        # about that same evidence. Nothing is executed here.
        result = None
        policy_note = ""
        if not attempt_id:
            # There is no attempt to re-judge. Evaluating this commit's stored
            # records "as if" they were one observation would invent an
            # attempt that never happened, and a decision has to be about one.
            policy_note = (
                "no attempt is recorded for this commit here, and a decision "
                "is about one attempt; there is nothing to re-judge. Run "
                "'admissible-ready run --preview' against this commit, or "
                "import a journal that carries its attempt.")
        else:
            try:
                parsed = load_config(found.root)
                class_id = options.class_id or attempt_class or None
                if class_id is None and receipts:
                    class_id = receipts[0].class_id
                artifact_class = parsed.select_class(class_id)
                commands, reviews, authorships = _stored_evidence(rows)
                # The tree the evidence describes, taken from what was recorded
                # then, then from the receipt, and only then from this checkout.
                tree_sha = ((attempt or {}).get("tree_sha")
                            or (receipts[0].tree_sha if receipts else "")
                            or found.tree_sha)
                # And the moment it was recorded at. Judging yesterday's
                # reviews against today's clock reports them expired for no
                # reason anybody observed: history is answered as of when it
                # happened.
                moment = ((attempt or {}).get("started_at")
                          or (receipts[0].issued_at if receipts else 0)
                          or int(time.time()))
                # The clock-skew guard measures evidence against the moment the
                # decision was made -- when the checks finished -- not against
                # the attempt's start. A check that legitimately ran longer than
                # the allowance finished after ``moment``; anchoring the guard
                # there would re-report its evidence as future-dated and
                # disagree with the decision this run already recorded. ``now``
                # stays at ``moment`` so review max-age is still answered as of
                # when the run happened.
                decided_at = max(
                    (record.finished_at for record in commands),
                    default=moment)
                if decided_at < moment:
                    decided_at = moment
                result = evaluate(
                    artifact_class=artifact_class, repository=repository,
                    commit_sha=commit_sha, tree_sha=tree_sha,
                    policy_digest=artifact_class.policy_digest,
                    commands=commands, reviews=reviews,
                    authorships=authorships, now=moment,
                    decided_at=decided_at,
                    attempt_id=attempt_id)
            except (ConfigError, ValueError) as error:
                policy_note = str(error)

        stale_heads = []
        for item in receipts:
            if signer is None:
                continue
            try:
                receipt_module.verify_receipt(item, signer)
            except receipt_module.ReceiptError as error:
                signature_problems.append(f"{item.receipt_hash}: {error}")
                continue
            current_head = opened.current_head(item.journal_id)
            if (current_head is None
                    or current_head.receipt_hash != item.head.receipt_hash):
                stale_heads.append(item.receipt_hash)

        current = (report.state == standing_module.CURRENT
                   and not signature_problems)
        exit_code = EXIT_OK if current else EXIT_NOT_CURRENT
        if options.json:
            document = standing_module.report_to_dict(report)
            reported = (report.state if not signature_problems
                        else "UNVERIFIED")
            document["state"] = reported
            document["readiness"] = (
                READINESS_READY_FOR_ATTESTATION
                if reported == standing_module.CURRENT else READINESS_NOT_READY)
            document["exit_code"] = exit_code
            document["message"] = (
                "" if reported == standing_module.CURRENT else
                f"{commit_sha} in {repository} is {reported}; inspect the "
                "recorded decision and remediation below")
            document["decision"] = (None if result is None
                                    else decision_to_dict(result))
            document["recorded_decision"] = recorded
            document["decision_attempt_id"] = attempt_id
            document["receipt_attempt_ids"] = sorted(
                {item.attempt_id for item in receipts if item.attempt_id})
            document["policy_note"] = policy_note
            document["signature_problems"] = signature_problems
            document["superseded_receipts"] = stale_heads
            document["evidence"] = [
                {"digest": row["digest"], "kind": row["kind"],
                 "subject": (row["record"].get("check_id")
                             or row["record"].get("reviewer_id")
                             or row["record"].get("author_id", ""))}
                for row in rows]
            _dump(stdout, document)
            return exit_code

        stdout.write(standing_module.render_plain(report))
        if recorded is not None:
            stdout.write(
                f"\nWhat attempt {attempt_id} recorded at the time: "
                f"{recorded.get('state', 'unknown')}\n")
            for reason in recorded.get("reasons", []):
                stdout.write(f"  - [{reason['code']}] {reason['detail']}\n")
            if not recorded.get("reasons"):
                stdout.write("  - no unmet requirement\n")
        if result is not None:
            stdout.write(
                "\nAgainst this repository's current policy, the evidence of "
                f"attempt {attempt_id} would be: {result.state}\n")
            others = sorted({item.attempt_id for item in receipts
                             if item.attempt_id and item.attempt_id != attempt_id})
            if others:
                stdout.write(
                    "  - note: the receipt on record is for attempt "
                    f"{', '.join(others)}, a different observation; it stays "
                    "authentic history and is not re-judged here\n")
            for reason in result.reasons:
                stdout.write(f"  - [{reason.code}] {reason.detail}\n")
            if not result.reasons:
                stdout.write("  - no unmet requirement\n")
            if result.remediation:
                # The decision knows what to do about each of those reasons.
                # Printing the reasons and dropping the remediation left a
                # developer with a refusal and no next step, which is the one
                # thing this output exists to avoid.
                stdout.write("\nWhat to do next about that decision:\n")
                for line in result.remediation:
                    stdout.write(f"  - {line}\n")
        elif policy_note:
            stdout.write(f"\nThe current policy could not be applied: "
                         f"{policy_note}\n")
        if signature_problems:
            stdout.write("\nReceipt signature problems:\n")
            for line in signature_problems:
                stdout.write(f"  - {line}\n")
        for receipt_hash in stale_heads:
            stdout.write(
                f"\nReceipt {receipt_hash} is authentic, but its journal head "
                "is no longer the current head: later events exist for this "
                "repository.\n")
        if rows:
            stdout.write("\nEvidence recorded for this commit:\n")
            for row in rows:
                record = row["record"]
                if row["kind"] == "command":
                    stdout.write(
                        f"  - check {record['check_id']} "
                        f"(version {record['check_version']}) exit "
                        f"{record['exit_code']}, {record['duration_ms']}ms, "
                        f"stdout {record['stdout_bytes']} bytes "
                        f"[{record['stdout_sha256'][:12]}]\n")
                elif row["kind"] == "review":
                    stdout.write(
                        f"  - review {record['review_id']} by "
                        f"{record['reviewer_id']}: {record['verdict']}\n")
                elif row["kind"] == "authorship":
                    stdout.write(
                        f"  - authorship claimed by {record['author_id']} "
                        f"for {record['commit_sha'][:12]}\n")
                else:
                    stdout.write(f"  - {row['kind']} record {row['digest'][:12]}"
                                 "\n")
        else:
            stdout.write("\nNo evidence is recorded for this commit.\n")
        return exit_code
    finally:
        opened.close()


def _command_export(options, stdout: TextIO, stderr: TextIO) -> int:
    stream = stdout if options.json else stderr
    try:
        found = _identity(options.repo, allow_dirty=True)
        opened = _open_store(stream)
    except (identity_module.IdentityError, store_module.StoreError) as error:
        return _fail(stream, str(error), json_mode=options.json)
    try:
        journal_id = receipt_module.journal_id_for(found.repository)
        through_head = getattr(options, "through_head", None)
        bundle = opened.export_journal(
            journal_id, through_head=through_head)
    except store_module.StoreError as error:
        steps = [
            "run 'admissible-ready run --preview' and then 'admissible-trust "
            "finalize' at least once, so there is a journal to export",
        ]
        if "through_head" in str(error):
            steps = [
                "choose a stored signed head and retry with 'admissible-trust "
                "export --through-head HEAD_HASH --out FILE' only for a "
                "deliberate historical reconstruction",
                "treat CURRENT after importing that historical cut as "
                "current only as of the selected authenticated head; later "
                "events, including defects, are intentionally absent",
            ]
        opened.close()
        return _fail(stream, str(error), json_mode=options.json,
                     next_steps=tuple(steps))
    body = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    encoded = body.encode("utf-8")
    try:
        if len(encoded) > store_module.MAX_JOURNAL_BYTES:
            # Refused here rather than written and then found unreadable. An
            # export nobody can import is worse than no export: it looks like a
            # backup right up to the moment it is needed.
            return _fail(stream, (
                f"this journal serialises to {len(encoded)} bytes, above the "
                f"{store_module.MAX_JOURNAL_BYTES}-byte ceiling 'admissible-trust "
                "import' will read. Nothing was written."),
                json_mode=options.json, next_steps=(
                    "retry with 'admissible-trust export --through-head HEAD_HASH "
                    "--out FILE' only to select an explicit historical cut",
                    "a historical cut is cumulative from genesis and cannot "
                    "transfer current history around this ceiling; it may "
                    "omit later events, including defects",
                ))
        Path(options.out).write_text(body, encoding="utf-8")
    except OSError as error:
        return _fail(stream, f"cannot write {options.out}: {error}",
                     json_mode=options.json)
    finally:
        opened.close()
    if options.json:
        _dump(stdout, {"path": options.out, "journal_id": journal_id,
                       "events": len(bundle["events"]),
                       "receipts": len(bundle["receipts"]),
                       "through_head": through_head or "",
                       "selection_scope": (
                           "historical-cut" if through_head
                           else "complete-at-export")})
        return EXIT_OK
    stdout.write(f"What happened: exported {journal_id} to {options.out}.\n\n")
    stdout.write("What is known:\n")
    stdout.write(f"  - {len(bundle['events'])} events and "
                 f"{len(bundle['receipts'])} signed heads\n")
    if through_head:
        stdout.write(f"  - explicit historical cut through signed head "
                     f"{through_head}\n"
                     "  - later events, including later defects, are absent; "
                     "CURRENT after import means current only as of this "
                     "authenticated cut\n"
                     "  - this cumulative cut is not an incremental part and "
                     "cannot move current history around the 64 MiB ceiling\n")
    stdout.write("  - the export carries no key material and no raw logs\n\n")
    stdout.write("What to do next:\n")
    stdout.write("  - run 'admissible-trust import --in FILE' on the other machine, "
                 "with the same signing key\n")
    return EXIT_OK


def _command_import(options, stdout: TextIO, stderr: TextIO) -> int:
    stream = stdout if options.json else stderr
    try:
        signer = receipt_module.load_signer()
        opened = _open_store(stream)
    except (receipt_module.SigningError, store_module.StoreError) as error:
        return _fail(stream, str(error), json_mode=options.json)
    try:
        source = Path(options.source)
        size = source.stat().st_size
        if size > store_module.MAX_JOURNAL_BYTES:
            raise ValueError(
                f"{options.source} is {size} bytes, above the "
                f"{store_module.MAX_JOURNAL_BYTES}-byte journal ceiling")
        # The stat is an early refusal, not the bound: the file can be replaced
        # or grow between stat and open.  Read at most one byte beyond the
        # contract and reject that byte, so an input path never causes an
        # unbounded allocation before the ceiling is enforced.
        with source.open("rb") as handle:
            raw = handle.read(store_module.MAX_JOURNAL_BYTES + 1)
        if len(raw) > store_module.MAX_JOURNAL_BYTES:
            raise ValueError(
                f"{options.source} grew above the "
                f"{store_module.MAX_JOURNAL_BYTES}-byte journal ceiling while "
                "it was being read")
        bundle = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        opened.close()
        return _fail(stream, f"cannot read {options.source}: {error}",
                     json_mode=options.json)
    try:
        head = opened.import_journal(bundle, signer)
    except store_module.StoreError as error:
        return _fail(stream, str(error), json_mode=options.json, next_steps=(
            "export again from the machine that has the longer journal",
            "an import may extend a journal, never shorten it",
        ))
    finally:
        opened.close()
    if options.json:
        _dump(stdout, {"journal_id": head.journal_id,
                       "event_count": head.event_count,
                       "receipt_hash": head.receipt_hash})
        return EXIT_OK
    stdout.write(f"What happened: imported {head.journal_id}.\n\n")
    stdout.write("What is known:\n")
    stdout.write(f"  - the journal now holds {head.event_count} events\n")
    stdout.write(f"  - every signed head in the chain verified under key "
                 f"{head.key_id}\n\n")
    stdout.write("What to do next:\n")
    stdout.write("  - run 'admissible-trust verify SHA' for any commit you care "
                 "about\n")
    return EXIT_OK


def _command_status(options, stdout: TextIO, stderr: TextIO) -> int:
    stream = stdout if options.json else stderr
    try:
        found = _identity(options.repo, allow_dirty=True)
        opened = _open_store(stream)
    except (identity_module.IdentityError, store_module.StoreError) as error:
        return _fail(stream, str(error), json_mode=options.json)
    try:
        journal_id = receipt_module.journal_id_for(found.repository)
        head = opened.current_head(journal_id)
        # Standing is answered with the key in hand or not at all. `status`
        # used to read the ADMITTED rows and report CURRENT without ever
        # checking a signature, which turned "a row exists in this database"
        # into "a keyholder admitted this commit" -- and those are different
        # claims wherever anything but this finalizer can write the file.
        signer = None
        key_problem = ""
        try:
            signer = receipt_module.load_signer()
        except receipt_module.SigningError as error:
            key_problem = str(error)
        state = standing_module.current_standing(
            opened, found.repository, found.commit_sha, verifier=signer)
        reported = state.state
        if signer is None and opened.receipts_for(found.repository,
                                                  found.commit_sha):
            # Receipts exist and nothing here can authenticate them. That is
            # not CURRENT and it is not UNKNOWN either; it is the honest third
            # answer, and it is the same word `verify` uses.
            reported = "UNVERIFIED"
        exit_code = (EXIT_OK if reported == standing_module.CURRENT
                     else EXIT_NOT_CURRENT)
        document = {
            "scope": receipt_module.RECEIPT_SCOPE,
            "repository": found.repository,
            "current_sha": found.commit_sha,
            "dirty": found.dirty,
            "receipts": opened.receipt_count(found.repository),
            "defects": opened.defect_count(found.repository),
            "state": reported,
            "readiness": (READINESS_READY_FOR_ATTESTATION
                          if reported == standing_module.CURRENT
                          else READINESS_NOT_READY),
            "exit_code": exit_code,
            "authenticated_receipts": [item.receipt_hash
                                       for item in state.receipts],
            "unauthenticated_receipts": [item.receipt_hash
                                         for item in state.unauthenticated],
            "signature_problem": key_problem,
            "message": (
                "" if reported == standing_module.CURRENT else
                f"{found.commit_sha} in {found.repository} is {reported}"),
            "remediation": [],
            "home": str(store_module.default_home()),
            "head": None if head is None else {
                "journal_id": journal_id,
                "event_count": head.event_count,
                "receipt_hash": head.receipt_hash,
                "key_id": head.key_id,
                "algorithm": head.algorithm,
            },
        }
        document["remediation"] = list(_status_next_steps(
            reported, found.commit_sha, key_problem))
        if options.json:
            _dump(stdout, document)
            return exit_code
        stdout.write(f"What happened: status for {found.repository}.\n\n")
        stdout.write("What is known:\n")
        stdout.write(f"  - current checkout: {found.commit_sha}"
                     f"{' (dirty)' if found.dirty else ''}\n")
        stdout.write(f"  - standing of this commit: {reported}\n")
        if state.unauthenticated:
            stdout.write(
                f"  - {len(state.unauthenticated)} row(s) say ADMITTED and do "
                "not verify under this key; they count for nothing\n")
        if key_problem:
            stdout.write(f"  - no signing key here, so no receipt could be "
                         f"authenticated: {key_problem}\n")
        stdout.write(f"  - receipts: {document['receipts']}, defects: "
                     f"{document['defects']}\n")
        if head is None:
            stdout.write("  - workflow journal: empty\n")
        else:
            stdout.write(
                f"  - workflow journal: {head.event_count} events, head "
                f"{head.receipt_hash[:12]} signed by key {head.key_id}\n")
        stdout.write(f"  - store: {document['home']}\n\n")
        stdout.write("What to do next:\n")
        for line in document["remediation"]:
            stdout.write(f"  - {line}\n")
        return exit_code
    finally:
        opened.close()


def _status_next_steps(reported: str, commit_sha: str,
                       key_problem: str) -> tuple[str, ...]:
    if reported == standing_module.CURRENT:
        return ("nothing; this commit is admitted, authenticated here, and "
                "not impeached",)
    if reported == standing_module.IMPEACHED:
        return (f"run 'admissible-trust explain {commit_sha}'",)
    if reported == "UNVERIFIED":
        return (
            "receipts exist for this commit and nothing here can authenticate "
            "them, so this commit is not shown to be admitted"
            + (f": {key_problem}" if key_problem else ""),
            "export the ADMISSIBLE_HMAC_KEY of the domain that issued them, "
            f"then run 'admissible-trust verify {commit_sha}'",
        )
    return (
        "run 'admissible-ready run --preview --preview-out preview.json' "
        "to evaluate this commit; nothing in that distribution signs",
        "have the external observer sign it with 'admissible-trust "
        "attest-evaluation --preview preview.json --source-receipt "
        "receipt.json --isolation MODE --out evaluation.json' after "
        "independently validating that boundary from external evidence",
        "then 'admissible-trust finalize --preview preview.json --sha "
        f"{commit_sha} --policy-root DIR --evaluation-attestation "
        "evaluation.json' in the trust domain that holds the signing key; "
        "only that issues a receipt",
    )


def _load_defect_document(path_text: str, repository: str, target: str,
                          test_id: str | None) -> dict:
    path = Path(path_text)
    try:
        raw = path.read_bytes()
    except OSError:
        raise ConfigError(
            f"cannot read defect evidence file {path}; pass --evidence with a "
            "readable defect record") from None
    if len(raw) > evidence_module.MAX_EVIDENCE_BYTES:
        raise ConfigError(f"defect evidence file {path} is too large")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConfigError(
            f"defect evidence file {path} is not valid JSON: {error}") from None
    if type(document) is dict and "schema" in document:
        bundle = evidence_module.load_evidence_file(path)
        if len(bundle.defects) != 1:
            raise ConfigError(
                "the evidence bundle must contain exactly one defect record")
        document = evidence_module.defect_to_dict(bundle.defects[0])
    if type(document) is not dict:
        raise ConfigError("a defect record must be a JSON object")
    document = dict(document)
    if test_id is not None:
        document["regression_test_id"] = test_id
    if document.get("repository") != repository:
        raise ConfigError(
            f"the defect record names repository "
            f"{document.get('repository')!r}, but this working tree is "
            f"{repository!r}")
    if document.get("commit_sha") != target:
        raise ConfigError(
            f"the defect record names commit {document.get('commit_sha')!r}, "
            f"but you asked to impeach {target!r}")
    return document


def _command_impeach(options, stdout: TextIO, stderr: TextIO) -> int:
    stream = stdout if options.json else stderr
    try:
        found, target = _resolve_target(options, stream)
        document = _load_defect_document(
            options.evidence, found.repository, target, options.test_id)
        signer = receipt_module.load_signer()
        # Impeachment is the authoritative revocation path, and it signs. A
        # defect anchored on a disposable runner disappears at teardown while
        # the canonical store keeps reporting the old receipt as CURRENT -- so
        # this needs the same durable home finalize does, for the same reason.
        home = store_module.require_durable_home()
        opened = store_module.open_store(home)
    except (identity_module.IdentityError, ConfigError,
            evidence_module.EvidenceError, receipt_module.SigningError,
            store_module.StoreError) as error:
        return _fail(stream, str(error), json_mode=options.json, next_steps=(
            "pass --evidence FILE with a defect record for this exact commit",
            "set ADMISSIBLE_HMAC_KEY so the defect can be anchored",
            "point ADMISSIBLE_HOME at durable storage and set "
            "ADMISSIBLE_DURABLE_HOME=1 to declare it deliberately; a defect "
            "filed on a disposable runner revokes nothing",
        ))
    try:
        defects_module.file_defect(opened, document, signer=signer,
                                    now=int(time.time()))
        report = standing_module.impact_report(
            opened, found.repository, target, verifier=signer)
        if options.json:
            _dump(stdout, standing_module.report_to_dict(report))
            return EXIT_OK
        stdout.write(standing_module.render_plain(report))
        return EXIT_OK
    except (evidence_module.EvidenceError, store_module.StoreError,
            receipt_module.AnchorError, receipt_module.SigningError) as error:
        return _fail(stream, str(error), json_mode=options.json)
    finally:
        opened.close()


def _write_private(path: Path, body: bytes) -> None:
    """Create ``path`` owner-only and replace it in one step."""

    scratch = path.parent / f".{path.name}.{secrets.token_hex(8)}"
    descriptor = os.open(str(scratch), os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(scratch, path)
    except BaseException:
        try:
            os.unlink(scratch)
        except OSError:
            pass
        raise


def _command_attest_evaluation(options, stdout: TextIO,
                               stderr: TextIO) -> int:
    """Sign, as an external observer, what an evaluation actually produced.

    This runs in the observer's trust domain, after the evaluating job and its
    whole process group are gone. It reads the preview and recomputes every
    digest from the evidence in it, so the statement is about what the artefact
    contains rather than about what it claims.

    It also requires ``--source-receipt``: the closed receipt this observer
    read from the provider that ran the evaluation. Without it, every field
    being signed would come out of the artefact under evaluation, and the
    signature would say only that the candidate's account of itself is
    internally consistent.

    What the source receipt establishes is bounded, and the command says so in
    its own output. An operator or an adapter reported reading it. Admissible
    does not fetch it and cannot verify it, so an adapter that lies -- or an
    operator who signs a receipt they never read -- produces an attestation
    that verifies. That is the adapter-honesty assumption, and it is retained
    deliberately rather than papered over.
    """

    stream = stdout if options.json else stderr
    try:
        key_id, secret = attestation_module.load_evaluation_signer()
        source = attestation_module.read_source_receipt_file(
            options.source_receipt)
        raw = Path(options.preview).read_bytes()
        if len(raw) > github_module.MAX_PREVIEW_BYTES:
            raise ValueError(f"{options.preview} is too large")
        preview = json.loads(raw.decode("utf-8"))
        document = attestation_module.attest_preview(
            preview, key_id=key_id, secret=secret, source_receipt=source,
            observed_at=int(time.time()), isolation=options.isolation)
        _write_private(
            Path(options.out),
            (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"))
    except (attestation_module.EvaluationError, OSError, ValueError,
            json.JSONDecodeError) as error:
        return _fail(stream, str(error), json_mode=options.json, next_steps=(
            "set ADMISSIBLE_EVALUATION_KEY_ID and ADMISSIBLE_EVALUATION_KEY "
            "(or ADMISSIBLE_EVALUATION_KEY_FILE) for this observer",
            "pass --source-receipt a closed receipt you read from the "
            "provider: provider, immutable run or job id, exact commit, "
            "conclusion, and the digest of the receipt document",
            "pass --isolation only for the boundary this observer "
            "independently validated; candidate preview text is not "
            "authority, and none can never finalize",
            "sign only after the evaluating job has finished and its "
            "processes are gone; an attestation signed while the candidate is "
            "still running attests to nothing",
        ))
    statement = document["evaluation"]
    receipt = statement["source_receipt"]
    if options.json:
        _dump(stdout, {"path": options.out, "key_id": key_id,
                       "algorithm": "hmac-sha256",
                       "commit_sha": statement["commit_sha"],
                       "attempt_id": statement["attempt_id"],
                       "state": statement["state"],
                       "readiness": statement["readiness"],
                       "preview_schema": statement["preview_schema"],
                       "issued_at": statement["issued_at"],
                       "fork": statement["fork"],
                       "isolation": statement["isolation"],
                       "command_digests": len(statement["command_digests"]),
                       "review_digests": len(statement["review_digests"]),
                       "source_receipt": receipt})
        return EXIT_OK
    stdout.write(f"What happened: signed the evaluation of "
                 f"{statement['commit_sha']} as observer key {key_id!r} and "
                 f"wrote {options.out}.\n\n")
    stdout.write("What is known:\n")
    stdout.write(f"  - attempt {statement['attempt_id']}, state "
                 f"{statement['state']}, readiness {statement['readiness']}, "
                 f"fork {str(statement['fork']).lower()}, observer-validated "
                 f"isolation {statement['isolation']}\n")
    stdout.write(f"  - {len(statement['command_digests'])} command, "
                 f"{len(statement['review_digests'])} preview review "
                 "record(s) named by digest; no observed record can be "
                 "substituted or dropped afterwards\n")
    stdout.write("  - independently signed out-of-band reviews and authorship "
                 "remain separate authorities: finalize authenticates and "
                 "binds them in its receipt; the observer does not re-sign "
                 "them\n")
    stdout.write(f"  - external source receipt: {receipt['provider']} run "
                 f"{receipt['run_id']}, conclusion {receipt['conclusion']}, "
                 f"document digest {receipt['receipt_digest'][:12]}\n")
    stdout.write("  - HMAC-SHA256 proves a holder of this observer key signed "
                 "it; it is not public non-repudiation\n\n")
    stdout.write("What is not known:\n")
    stdout.write("  - that the checks actually ran. This attests that an "
                 "operator or an adapter observed that source receipt; "
                 "Admissible does not fetch it and cannot verify it, so an "
                 "adapter that lies produces an attestation that verifies\n")
    stdout.write("  - that the checks were the right checks\n\n")
    stdout.write("What to do next:\n")
    stdout.write("  - pass it to 'admissible-trust finalize --evaluation-attestation "
                 "FILE'\n")
    stdout.write("  - list this key id in the finalizer's "
                 "ADMISSIBLE_EVALUATION_KEYRING\n")
    return EXIT_OK


def _command_policy_revoke(options, stdout: TextIO, stderr: TextIO) -> int:
    """Withdraw one trusted policy. History is kept; authority is not."""

    stream = stdout if options.json else stderr
    digest = (options.policy_digest or "").strip()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        return _fail(stream, (
            "--digest must be a full 64-character lowercase policy digest; "
            f"got {options.policy_digest!r}"), json_mode=options.json,
            next_steps=("read the digest from 'admissible-trust policy list "
                        "--json'",))
    try:
        found = _identity(options.repo, allow_dirty=True)
        opened = _open_store(stream)
    except (identity_module.IdentityError, store_module.StoreError) as error:
        return _fail(stream, str(error), json_mode=options.json)
    try:
        withdrawn = opened.revoke_policy(
            repository=found.repository, class_id=options.class_id,
            policy_digest=digest, revoked_at=int(time.time()))
        remaining = opened.trusted_policies(found.repository, options.class_id)
    except store_module.StoreError as error:
        return _fail(stream, str(error), json_mode=options.json)
    finally:
        opened.close()
    if options.json:
        _dump(stdout, {
            "repository": found.repository, "class_id": options.class_id,
            "policy_digest": digest, "revoked": withdrawn,
            "enforceable": [item["policy_digest"] for item in remaining]})
        return EXIT_OK
    stdout.write(f"What happened: revoked a trusted policy for class "
                 f"{options.class_id} in {found.repository}.\n\n")
    stdout.write("What is known:\n")
    stdout.write(f"  - policy {digest[:12]} is no longer enforceable here"
                 f"{'' if withdrawn else ' (it already was not)'}\n")
    stdout.write(f"  - {len(remaining)} policy(ies) may still enforce this "
                 "class\n")
    stdout.write("  - nothing was deleted: the baseline is still readable "
                 "with 'admissible-trust policy list --all'\n\n")
    stdout.write("What to do next:\n")
    if not remaining:
        stdout.write("  - this class can now admit nothing; run 'admissible-trust "
                     "policy trust' on the policy that should enforce it\n")
    else:
        stdout.write("  - run 'admissible-trust policy list' and confirm what is "
                     "left is what you meant to leave\n")
    return EXIT_OK


def _command_policy_list(options, stdout: TextIO, stderr: TextIO) -> int:
    stream = stdout if options.json else stderr
    try:
        found = _identity(options.repo, allow_dirty=True)
        relative = options.config_path or CONFIG_FILENAME
        parsed = load_config(found.root, relative)
        classes = (parsed.classes if options.class_id is None
                   else (parsed.select_class(options.class_id),))
        opened = _open_store(stream)
    except (identity_module.IdentityError, ConfigError,
            store_module.StoreError) as error:
        return _fail(stream, str(error), json_mode=options.json)
    try:
        rows = []
        for artifact_class in classes:
            current = opened.policy_generation(found.repository,
                                               artifact_class.id)
            revoked = opened.revoked_policies(found.repository,
                                              artifact_class.id)
            for item in opened.trusted_policies(
                    found.repository, artifact_class.id,
                    include_superseded=options.include_superseded):
                rows.append({
                    "class_id": artifact_class.id,
                    "policy_digest": item["policy_digest"],
                    "enforcement_digest": item["enforcement_digest"],
                    "trusted_at": item["trusted_at"],
                    "generation": item.get("generation", 1),
                    "enforceable": (item.get("generation", 1) == current
                                    and item["policy_digest"] not in revoked),
                })
    except store_module.StoreError as error:
        return _fail(stream, str(error), json_mode=options.json)
    finally:
        opened.close()
    if options.json:
        _dump(stdout, {"repository": found.repository, "policies": rows})
        return EXIT_OK
    stdout.write(f"What happened: read the policy baseline for "
                 f"{found.repository}.\n\n")
    stdout.write("What is known:\n")
    if not rows:
        stdout.write("  - no policy has ever been trusted here, so this home "
                     "can admit nothing\n")
    for item in rows:
        mark = "enforceable" if item["enforceable"] else "superseded/revoked"
        stdout.write(f"  - class {item['class_id']}: policy "
                     f"{item['policy_digest'][:12]} generation "
                     f"{item['generation']} ({mark})\n")
    stdout.write("\nWhat to do next:\n")
    stdout.write("  - trust is a current fact, not an accumulating list: a "
                 "superseded policy stays readable and can never enforce "
                 "again until it is trusted deliberately\n")
    return EXIT_OK


def _command_policy(options, stdout: TextIO, stderr: TextIO) -> int:
    stream = stdout if options.json else stderr
    sub = getattr(options, "policy_command", None)
    if sub == "revoke":
        return _command_policy_revoke(options, stdout, stderr)
    if sub == "list":
        return _command_policy_list(options, stdout, stderr)
    if sub != "trust":
        return _fail(stream, (
            "usage: admissible-trust policy trust [--class ID] | policy list "
            "[--class ID] [--all] | policy revoke --class ID --digest SHA256"),
            json_mode=options.json, next_steps=(
            "run 'admissible-trust policy trust' in a trusted checkout to record "
            "which policy is enforceable for this repository",))
    try:
        found = _identity(options.repo, allow_dirty=True)
        relative = options.config_path or CONFIG_FILENAME
        parsed = load_config(found.root, relative)
        classes = (parsed.classes if options.class_id is None
                   else (parsed.select_class(options.class_id),))
        opened = _open_store(stream)
    except (identity_module.IdentityError, ConfigError,
            store_module.StoreError) as error:
        return _fail(stream, str(error), json_mode=options.json)
    try:
        now = int(time.time())
        trusted = []
        for artifact_class in classes:
            opened.trust_policy(
                repository=found.repository, class_id=artifact_class.id,
                policy_digest=artifact_class.policy_digest,
                enforcement_digest=enforcement_digest(artifact_class),
                trusted_at=now)
            trusted.append({"class_id": artifact_class.id,
                            "policy_digest": artifact_class.policy_digest})
    except store_module.StoreError as error:
        return _fail(stream, str(error), json_mode=options.json)
    finally:
        opened.close()
    if options.json:
        _dump(stdout, {"repository": found.repository, "trusted": trusted})
        return EXIT_OK
    stdout.write(f"What happened: recorded a trusted policy baseline for "
                 f"{found.repository}.\n\n")
    stdout.write("What is known:\n")
    for item in trusted:
        stdout.write(f"  - class {item['class_id']}: policy "
                     f"{item['policy_digest'][:12]}\n")
    stdout.write("  - a finalizer using this home will now sign against this "
                 "policy, and refuse a policy that enforces something else "
                 "until you approve that change here too\n")
    stdout.write("  - editorial changes to descriptions do not need approving; "
                 "changes to checks, review counts or key ids do\n\n")
    stdout.write("What to do next:\n")
    stdout.write("  - read the policy you just trusted before trusting it, not "
                 "after: this command is the whole reason a candidate cannot "
                 "set its own bar\n")
    return EXIT_OK

_UNKNOWN_COMMIT_OUTCOME = "UNKNOWN_COMMIT_OUTCOME"


def _report_interrupted_finalize(options, stdout: TextIO, stream: TextIO,
                                 opened,
                                 expected_body_digest: str | None) -> int:
    """Answer whether this exact prepared receipt committed, never a cousin."""

    opened.close()
    issued = None
    try:
        reopened = store_module.open_store(store_module.default_home())
    except store_module.StoreError:
        reopened = None
    if (reopened is not None and type(expected_body_digest) is str
            and len(expected_body_digest) == 64):
        try:
            signer = receipt_module.load_signer()
            candidate = reopened.workflow_receipt_by_body(expected_body_digest)
            if candidate is not None:
                receipt_module.verify_receipt(candidate, signer)
                if candidate.body_digest != expected_body_digest:
                    raise receipt_module.ReceiptError(
                        "the receipt indexed by the expected body carries a "
                        "different body digest")
                standing = standing_module.current_standing(
                    reopened, candidate.repository, candidate.commit_sha,
                    verifier=signer)
                if (standing.state == standing_module.CURRENT
                        and any(item.receipt_hash == candidate.receipt_hash
                                for item in standing.receipts)):
                    issued = candidate
        except (store_module.StoreError, receipt_module.ReceiptError,
                receipt_module.SigningError):
            issued = None
        finally:
            reopened.close()
    elif reopened is not None:
        reopened.close()
    if issued is not None:
        if options.json:
            document = receipt_module.receipt_to_dict(issued)
            document["path"] = ""
            document["interrupted"] = True
            _dump(stdout, document)
            return EXIT_OK
        stdout.write(
            "\nInterrupted -- but the admission for "
            f"{issued.commit_sha} IS anchored as receipt "
            f"{issued.receipt_hash} at journal position "
            f"{issued.head.event_count}.\n\nWhat to do next:\n"
            f"  - read it back with 'admissible-trust verify {issued.commit_sha}'\n"
            "  - do not re-run finalize expecting a different answer: the "
            "admission is already recorded\n")
        return EXIT_OK
    steps = (
        f"run 'admissible-trust verify {options.sha}' to see whether a receipt "
        "exists for this commit",
        "run 'admissible-trust status' to see whether the journal advanced",
        "only re-run finalize once verify says no receipt exists; re-running "
        "over an anchored admission is safe but the answer above is the one "
        "to act on",
    )
    if options.json:
        _dump(stdout, {
            "scope": receipt_module.RECEIPT_SCOPE,
            "state": _UNKNOWN_COMMIT_OUTCOME,
            "readiness": READINESS_NOT_READY,
            "exit_code": EXIT_BLOCKED,
            "message": (
                "finalize was interrupted and no authentic CURRENT receipt "
                "with this invocation's exact expected body can be read back "
                f"for {options.sha}. The durable commit may or may not have "
                "happened; this process cannot tell, and will not guess."),
            "remediation": list(steps),
        })
        return EXIT_BLOCKED
    stream.write(
        f"What happened: {_UNKNOWN_COMMIT_OUTCOME}. finalize was interrupted "
        "and no authentic CURRENT receipt with this invocation's exact "
        "expected body can be read back for\n"
        f"{options.sha}.\n")
    stream.write(
        "What is known: the durable commit may or may not have happened. This "
        "process\ncannot tell, and will not guess.\n")
    stream.write("What to do next:\n")
    for line in steps:
        stream.write(f"  - {line}\n")
    return EXIT_BLOCKED


def _command_finalize(options, stdout: TextIO, stderr: TextIO) -> int:
    stream = stdout if options.json else stderr
    try:
        signer = receipt_module.load_signer()
        # Anchoring only means something on storage that outlives the job.
        home = store_module.require_durable_home()
        opened = store_module.open_store(home)
    except (receipt_module.SigningError, store_module.StoreError) as error:
        return _fail(stream, str(error), json_mode=options.json, next_steps=(
            "give the finalize job ADMISSIBLE_HMAC_KEY from a protected "
            "environment secret",
            "never give that secret to a job that runs candidate commands",
            "point ADMISSIBLE_HOME at durable storage and set "
            "ADMISSIBLE_DURABLE_HOME=1 to declare it deliberately",
        ))
    expected_body_digest = None
    try:
        finalize_now = int(time.time())
        expected_body_digest = (
            github_module.expected_finalization_receipt_body_digest(
                opened, options.preview, expected_sha=options.sha,
                now=finalize_now, policy_root=options.policy_root,
                evaluation_attestation=options.evaluation_attestation,
                reviews=options.reviews))
        issued = github_module.finalize(
            opened, options.preview, signer=signer, expected_sha=options.sha,
            now=finalize_now, policy_root=options.policy_root,
            evaluation_attestation=options.evaluation_attestation,
            reviews=options.reviews,
            expected_body_digest=expected_body_digest)
    except (github_module.GitHubError, receipt_module.ReceiptError,
            receipt_module.SigningError, receipt_module.AnchorError,
            attestation_module.EvaluationError,
            store_module.StoreError) as error:
        opened.close()
        return _fail(stream, str(error), json_mode=options.json, next_steps=(
            "re-run the evaluate job for the exact head commit",
            "have the external observer sign the evaluation with 'admissible-trust "
            "attest-evaluation', and pin its key id in "
            "ADMISSIBLE_EVALUATION_KEYRING",
            "a fork preview can never be finalised",
        ))
    except KeyboardInterrupt:
        # The one place an interrupt cannot be answered with "nothing was
        # recorded". The durable commit may already have happened -- the
        # transaction commits, and the signal arrives before the return -- and
        # telling an automated caller that no receipt exists is the single lie
        # it cannot recover from: it re-runs, or it reports a failure over an
        # admission that is on record.
        #
        # So the store is closed first, then reopened, and the question is put
        # to the durable state rather than guessed from the traceback.
        return _report_interrupted_finalize(
            options, stdout, stream, opened, expected_body_digest)
    try:
        if options.out:
            # Written before anything is reported and after the admission is
            # anchored, and the locator is reported either way. The old order
            # -- anchor, then write, then fail -- could report BLOCKED for an
            # admission that was already durable, which is the one lie an
            # automated caller cannot recover from.
            try:
                _write_private(
                    Path(options.out),
                    (json.dumps(receipt_module.receipt_to_dict(issued),
                                indent=2, sort_keys=True) + "\n").encode(
                                    "utf-8"))
            except OSError as error:
                # The admission is durable. Only the copy failed, and the one
                # thing this must never report is "nothing was recorded": a
                # caller that believes that re-runs, or reports a failure over
                # an admission that is on record. So the receipt is reported in
                # full -- state, hash, journal position -- and the exit code
                # says the invocation did not do everything it was asked.
                steps = (
                    f"read it back with 'admissible-trust verify "
                    f"{issued.receipt_hash}'",
                    "do not re-run finalize expecting a different answer: the "
                    "admission is already recorded",
                    f"copy the receipt to {options.out} by hand if that file "
                    "is needed",
                )
                message = (
                    f"the admission for {issued.commit_sha} IS anchored as "
                    f"receipt {issued.receipt_hash} at journal position "
                    f"{issued.head.event_count}, but it could not be written "
                    f"to {options.out}: {error}. The receipt exists; only "
                    "this copy of it does not.")
                if options.json:
                    document = receipt_module.receipt_to_dict(issued)
                    document["path"] = ""
                    document["exit_code"] = EXIT_BLOCKED
                    document["readiness"] = READINESS_NOT_READY
                    document["message"] = message
                    document["output_error"] = str(error)
                    document["remediation"] = list(steps)
                    _dump(stdout, document)
                    return EXIT_BLOCKED
                stream.write(f"What happened: {message}\n")
                stream.write(
                    "What is known: the admission is on record; the "
                    "requested copy is not.\n")
                stream.write("What to do next:\n")
                for line in steps:
                    stream.write(f"  - {line}\n")
                return EXIT_BLOCKED
        if options.json:
            document = receipt_module.receipt_to_dict(issued)
            document["path"] = options.out or ""
            _dump(stdout, document)
            return EXIT_OK
        stdout.write(
            f"What happened: signed a developer workflow admission for "
            f"{issued.commit_sha} in {issued.repository}.\n\n")
        stdout.write("What is known:\n")
        stdout.write(f"  - receipt {issued.receipt_hash}\n")
        stdout.write(f"  - journal position {issued.head.event_count}, key "
                     f"{issued.head.key_id}\n")
        stdout.write(f"  - evidence records: {len(issued.evidence_digests)}\n")
        stdout.write("  - this authenticates a developer workflow admission, "
                     "not the composed kernel predicate\n\n")
        stdout.write("What to do next:\n")
        stdout.write(f"  - run 'admissible-trust verify {issued.commit_sha}' from any "
                     "machine with the same key\n")
        stdout.write("  - file a defect with 'admissible-trust impeach' if reality "
                     "later disagrees\n")
        return EXIT_OK
    finally:
        opened.close()


def _command_run(options, stdout: TextIO, stderr: TextIO) -> int:
    """The transitional verb: an explicit alias for ``finalize``, or a refusal.

    ``run`` used to mean two things at once -- evaluate the candidate, and sign
    the result if a key happened to be present. The split makes that impossible
    to spell, because the two halves are now two distributions, so the old name
    is kept for one release window bound to exactly one of them.

    What it will never do is execute a check. There is no runner in this wheel
    and no code path here that could reach one; ``run`` reads a retained
    preview and hands it to :func:`_command_finalize` unchanged. Invoked
    without one, it refuses and says where each half went.
    """

    stream = stdout if options.json else stderr
    missing = [name for name, value in (
        ("--preview", options.preview), ("--sha", options.sha),
        ("--policy-root", options.policy_root),
        ("--evaluation-attestation", options.evaluation_attestation),
    ) if not value]
    if missing:
        return _fail(stream, (
            "'run' is a transitional alias for 'finalize' in this "
            "distribution and consumes a preview that has already been "
            "produced; it never evaluates anything. This invocation is "
            "missing " + ", ".join(missing) + "."),
            json_mode=options.json, next_steps=(
                "evaluate with 'admissible-ready run --preview --preview-out "
                "preview.json' in the distribution that has a runner",
                "have an external observer sign that preview with "
                "'admissible-trust attest-evaluation'",
                "then run 'admissible-trust finalize --preview preview.json "
                "--sha SHA --policy-root DIR --evaluation-attestation "
                "evaluation.json'; prefer 'finalize' directly, because 'run' "
                "is removed after this release window",
            ))
    # Human-readable, on stderr, and never on the machine stream: a --json
    # caller's stdout carries the receipt and nothing else.
    stderr.write(
        "Warning: 'admissible-trust run' is a transitional alias for "
        "'finalize' and will be removed. It consumes the retained preview you "
        "passed and runs no check.\n")
    return _command_finalize(options, stdout, stderr)


# What an interrupt leaves behind, per command. The default is the careful
# answer, because a command that anchors is a command whose durable commit may
# already have happened when the signal arrived.
_INTERRUPTED = {
    "ready-status": ("INTERRUPTED",
                     "Nothing was written; ready-status only reads.",
                     ("re-run the command",)),
    "attest-review": (
        "INTERRUPTED",
        "No receipt was issued and no journal was touched: signing a review "
        "writes one file and anchors nothing.",
        ("re-run the command",)),
    "attest-evaluation": (
        "INTERRUPTED",
        "No receipt was issued and no journal was touched: an attestation is "
        "one file, created owner-only under a private name and renamed into "
        "place, so a reader sees the old file or the whole new one.",
        ("re-run the command",)),
    "verify": ("INTERRUPTED", "Nothing was written; verify only reads.",
               ("re-run the command",)),
    "explain": ("INTERRUPTED", "Nothing was written; explain only reads.",
                ("re-run the command",)),
    "status": ("INTERRUPTED", "Nothing was written; status only reads.",
               ("re-run the command",)),
    "export": ("INTERRUPTED",
               "Nothing durable was written; export only reads the journal.",
               ("re-run the command",)),
    None: (
        _UNKNOWN_COMMIT_OUTCOME,
        "This command can write durably, and the interrupt arrived without a "
        "chance to read the store back. Whether the durable commit happened "
        "is not known here, and it will not be guessed.",
        ("run 'admissible-trust verify SHA' to see whether a receipt exists",
         "run 'admissible-trust status' to see whether the journal advanced")),
}

_COMMANDS = {
    "ready-status": _command_ready_status,
    "verify": _command_verify,
    "explain": _command_explain,
    "status": _command_status,
    "impeach": _command_impeach,
    "attest-review": _command_attest_review,
    "attest-evaluation": _command_attest_evaluation,
    "policy": _command_policy,
    "finalize": _command_finalize,
    "run": _command_run,
    "export": _command_export,
    "import": _command_import,
}


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    """Run one Admissible Trust command and return its exit code."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    # A usage error happens before the options exist, so --json cannot be read
    # off them. It is read off the raw argument list instead: a caller that
    # asked for JSON is owed JSON on stdout even when the thing that went wrong
    # is the command line itself. Prose on stderr and an empty stdout is a
    # parse failure for them, and they cannot tell it from a crash.
    json_requested = "--json" in arguments
    if not arguments or arguments[0] in ("-h", "--help", "help"):
        # Help is metadata: it names commands and variables and reads nothing
        # about this machine or this repository, so it is answered before any
        # credential is looked for.
        out.write(_HELP)
        return EXIT_OK if arguments else EXIT_BLOCKED
    parser = _build_parser()
    try:
        options = parser.parse_args(arguments)
    except _Usage as usage:
        if usage.code == EXIT_OK:
            out.write(usage.message or _HELP)
            return EXIT_OK
        message = usage.message.strip() or "this is not a usable command line"
        return _fail(out if json_requested else err, message,
                     json_mode=json_requested, next_steps=(
                         "run 'admissible-trust --help' for the exact command "
                         "list",
                         "profiles, init, run --preview, check, mcp, connect "
                         "and ui belong to 'admissible-ready'",))
    if getattr(options, "help", False) or options.command is None:
        if json_requested:
            return _fail(out, "no command given", json_mode=True, next_steps=(
                "run 'admissible-trust --help' for the exact command list",))
        out.write(_HELP)
        return EXIT_BLOCKED
    handler = _COMMANDS.get(options.command)
    if handler is None:
        if json_requested:
            return _fail(out, f"unknown command {options.command!r}",
                         json_mode=True, next_steps=(
                             "run 'admissible-trust --help' for the exact "
                             "command list",))
        err.write(_HELP)
        return EXIT_BLOCKED
    try:
        return handler(options, out, err)
    except KeyboardInterrupt:
        # Deliberately never "nothing was recorded". What an interrupt leaves
        # behind depends on which command was running, so the answer does too,
        # and a --json caller is owed it as a document rather than as prose on
        # stderr they cannot parse.
        #
        # `finalize` answers this itself, from the store, before the exception
        # reaches here: it is the one command whose durable commit may already
        # have happened. If its own handler was bypassed the honest answer is
        # still that the outcome is unknown, which is what the table above
        # says.
        json_mode = _json_mode(options)
        state, message, steps = _INTERRUPTED.get(
            options.command, _INTERRUPTED[None])
        if json_mode:
            _dump(out, {
                "scope": receipt_module.RECEIPT_SCOPE,
                "state": state,
                "readiness": READINESS_NOT_READY,
                "exit_code": EXIT_BLOCKED,
                "message": message,
                "remediation": list(steps),
            })
            return EXIT_BLOCKED
        err.write(f"\nWhat happened: {state}. {message}\n")
        err.write("What to do next:\n")
        for line in steps:
            err.write(f"  - {line}\n")
        return EXIT_BLOCKED
    except (OSError, store_module.StoreError, receipt_module.ReceiptError,
            receipt_module.SigningError, receipt_module.AnchorError,
            evidence_module.EvidenceError, review_module.ReviewError,
            attestation_module.EvaluationError,
            identity_module.IdentityError, ConfigError,
            json.JSONDecodeError) as error:
        # Anything that reached here is still an operational problem, and the
        # caller is owed the documented exit-2 contract rather than a traceback
        # on stderr and an empty document on stdout.
        detail = getattr(error, "strerror", None) or str(error)
        where = getattr(error, "filename", None)
        message = f"{detail} ({where})" if where else detail
        json_mode = _json_mode(options)
        return _fail(out if json_mode else err, message, json_mode=json_mode)
