"""``admissible`` — a deterministic developer gate you can run in one command.

Exit codes are stable within each command.  In particular, ``run`` returning
zero means only ``CHECKS_PASSED``; an evaluation never admits anything.
``finalize`` returning zero means a receipt was issued (or the exact receipt
was already present), while ``verify`` and ``status`` return zero only for
authenticated ``CURRENT`` standing.  Nonzero means refused/not current or an
operationally blocked invocation as the command's JSON envelope describes.

Every command prints what happened, what is known, and what to do next.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any, TextIO

from . import attestation as attestation_module
from . import evidence as evidence_module
from . import identity as identity_module
from . import profiles as profiles_module
from . import ready as ready_module
from . import receipt as receipt_module
from . import review as review_module
from . import runner as runner_module
from . import standing as standing_module
from . import store as store_module
from .config import (CI_PROVIDERS, CONFIG_FILENAME, ConfigError, apply_init,
                     enforcement_digest, load_config, preflight_init)
from .decision import (ADMITTED, BLOCKED, CHECKS_PASSED,
                       READINESS_AWAITING_REVIEW, READINESS_NOT_READY,
                       READINESS_READY_FOR_ATTESTATION, REFUSED,
                       decision_to_dict, evaluate, plan_budget,
                       preview_readiness, render_plain)

__all__ = ["main"]

EXIT_OK = 0
EXIT_NOT_CURRENT = 1
EXIT_BLOCKED = 2

_FULL_SHA_LENGTH = 40
_RECEIPT_HASH_LENGTH = 64
_ANCHOR_UNANCHORED = "unanchored"
_ANCHOR_CHANGED = "changed"


class _Usage(Exception):
    """argparse wanted to exit; the CLI decides what to print and return."""

    def __init__(self, message: str, code: int = EXIT_BLOCKED) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # pragma: no cover - argparse plumbing
        raise _Usage(f"admissible: {message}\n{self.format_usage()}")

    def exit(self, status: int = 0, message: str | None = None):
        raise _Usage(message or "", EXIT_BLOCKED if status else EXIT_OK)


def _build_parser() -> _Parser:
    parser = _Parser(prog="admissible", add_help=False,
                     description="Deterministic developer admission gate.")
    parser.add_argument("--help", "-h", action="store_true", dest="help")
    commands = parser.add_subparsers(dest="command")

    def with_repo(sub):
        sub.add_argument("--repo", default=".",
                         help="repository root (default: current directory)")
        sub.add_argument("--json", action="store_true",
                         help="print a stable JSON document instead of prose")
        return sub

    listing = commands.add_parser("profiles", add_help=False)
    listing.add_argument("--json", action="store_true")

    initialise = commands.add_parser("init", add_help=False)
    initialise.add_argument("--profile", required=True)
    initialise.add_argument("--force", action="store_true")
    initialise.add_argument("--ci", default=None, choices=sorted(CI_PROVIDERS),
                            help="also scaffold a CI caller workflow")
    initialise.add_argument("--tool-sha", dest="tool_sha", default=None,
                            metavar="FULL_SHA",
                            help="the exact Admissible commit the generated CI "
                                 "caller pins, in both its 'uses' reference "
                                 "and its tool-sha input")
    initialise.add_argument("--ci-placeholder", dest="ci_placeholder",
                            action="store_true",
                            help="scaffold the CI caller with an explicit "
                                 "unrunnable placeholder instead of a pinned "
                                 "--tool-sha")
    initialise.add_argument("--trust-policy", dest="trust_policy",
                            action="store_true",
                            help="also record this policy as the trusted "
                                 "baseline for its classes in this home")
    initialise.add_argument("--no-gitignore", action="store_true",
                            help="do not add this profile's build output to "
                                 ".gitignore")
    with_repo(initialise)

    run = commands.add_parser("run", add_help=False)
    run.add_argument("--class", dest="class_id", default=None)
    run.add_argument("--sha", default=None)
    run.add_argument("--preview", action="store_true")
    run.add_argument("--config", dest="config_path", default=None,
                     metavar="FILE",
                     help="policy file relative to the repository root "
                          "(default: .admissible.json)")
    run.add_argument("--evidence", default=None)
    run.add_argument("--depends-on", action="append", default=[],
                     metavar="REPOSITORY@SHA")
    run.add_argument("--preview-out", default=None, metavar="FILE",
                     help="write the unsigned preview artefact for a trusted "
                          "finalize job")
    run.add_argument("--no-cache", action="store_true",
                     help="re-run every check even when exact-identity "
                          "evidence is already on record")
    run.add_argument("--no-store", action="store_true",
                     help="record nothing durably; the run leaves no audit "
                          "trail and says so")
    with_repo(run)

    check = commands.add_parser("check", add_help=False)
    check.add_argument("--class", dest="class_id", default=None)
    check.add_argument("--sha", default=None)
    check.add_argument("--config", dest="config_path", default=None,
                       metavar="FILE")
    check.add_argument("--evidence", default=None)
    check.add_argument("--depends-on", action="append", default=[],
                       metavar="REPOSITORY@SHA")
    check.add_argument("--no-cache", action="store_true")
    with_repo(check)

    mcp = commands.add_parser("mcp", add_help=False)
    mcp.add_argument("--repo", default=".")
    mcp.add_argument("--agent-name", required=True)
    mcp.add_argument("--purpose", required=True)
    mcp.add_argument("--runtime", required=True,
                     choices=("claude-code", "codex", "hermes", "local",
                              "custom"))

    connect = commands.add_parser("connect", add_help=False)
    connect.add_argument("--name", required=True)
    connect.add_argument("--purpose", required=True)
    connect.add_argument("--runtime", required=True,
                         choices=("claude-code", "codex", "hermes", "local",
                                  "custom"))
    with_repo(connect)

    ui = commands.add_parser("ui", add_help=False)
    ui.add_argument("--repo", default=".")
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--no-open", action="store_true")

    ready_status = commands.add_parser("ready-status", add_help=False)
    with_repo(ready_status)

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
        "--isolation", required=True, choices=runner_module.ISOLATION_MODES,
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
                             "'admissible policy list --json'")
    with_repo(revoke)
    listing = policy_commands.add_parser("list", add_help=False)
    listing.add_argument("--class", dest="class_id", default=None)
    listing.add_argument("--config", dest="config_path", default=None,
                         metavar="FILE")
    listing.add_argument("--all", dest="include_superseded",
                         action="store_true",
                         help="include superseded generations, which are "
                              "history and not authority")
    with_repo(listing)

    finalize = commands.add_parser("finalize", add_help=False)
    finalize.add_argument("--preview", required=True, metavar="FILE")
    finalize.add_argument("--sha", required=True)
    finalize.add_argument("--policy-root", required=True, metavar="DIR",
                          help="trusted read-only checkout of the same commit; "
                               "repository, tree and policy are re-derived "
                               "there and the decision is recomputed")
    finalize.add_argument("--evaluation-attestation", required=True,
                          dest="evaluation_attestation", metavar="FILE",
                          help="the external observer's signed statement about "
                               "the evaluation that produced this preview")
    finalize.add_argument("--reviews", default=None, metavar="FILE",
                          help="signed reviews and authorship claims that "
                               "reached this finalizer out of band; a review "
                               "binds the tree it approves and so can never "
                               "travel inside it")
    finalize.add_argument("--out", default=None, metavar="FILE",
                          help="write the receipt here; written and validated "
                               "before the admission is anchored")
    with_repo(finalize)

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


_HELP = """usage: admissible COMMAND [options]

Commands:
  profiles [--json]                       list the built-in starter profiles
  init --profile NAME [--force]           write .admissible.json
      [--ci github]                       ...and a CI caller workflow
      [--no-gitignore]                    ...without ignoring check output
  init --profile NAME --ci github        ...pinning the tool by commit
      --tool-sha FULL_SHA
      [--ci-placeholder] [--trust-policy]
  run --preview [--class ID]              evaluate this exact commit;
      [--sha FULL_SHA] [--config FILE]    'run' never signs anything
      [--evidence FILE] [--no-cache]
      [--depends-on REPOSITORY@SHA]
      [--preview-out FILE] [--no-store]
  check [--class ID] [--sha FULL_SHA]     check HEAD and show the friendly
      [--config FILE] [--evidence FILE]   Ready result; never signs anything
      [--no-cache]
  mcp --agent-name NAME --purpose TEXT    connect an agent to the same Ready
      --runtime RUNTIME [--repo DIR]      workflow over MCP stdio
  connect --name NAME --purpose TEXT      print copyable setup for Claude Code,
      --runtime RUNTIME [--repo DIR]      Codex, Hermes, or another MCP client
  ui [--repo DIR] [--port PORT]           open the local Ready product; loopback
      [--no-open]                         only and never holds signing keys
  ready-status [--repo DIR]               trusted authenticated Ready projection;
                                          requires the admission verification key
  policy trust [--class ID]               record the enforceable policy
      [--config FILE]                     baseline for this repository
  policy list [--class ID] [--all]        show what may enforce here now
  policy revoke --class ID                withdraw one trusted policy
      --digest SHA256                     without rewriting the record of it
  attest-review --review FILE --out FILE  sign a review with a reviewer key
      [--authorship]                      ...or an authorship record
  attest-evaluation --preview FILE        sign, as the external observer, the
      --source-receipt FILE               evaluation and the external receipt
      --isolation MODE --out FILE         the observer independently validated
  verify TARGET                           check standing and authenticity
  explain TARGET                          explain what is known about TARGET
  status                                  summarise this repository
  impeach TARGET --evidence FILE          file a defect against TARGET
      [--test CHECK_ID]
  finalize --preview FILE --sha SHA       sign a validated preview artefact
      --policy-root DIR                   (a trusted checkout of that commit)
      --evaluation-attestation FILE       (the observer's signed statement)
      [--out FILE]
  export --out FILE                       export this repository's journal
      [--through-head HASH]               ...or an explicit historical cut
  import --in FILE                        import a journal, refusing rollback

Common options: --repo DIR, --json

Three separate keys, and none of them substitutes for another:
  ADMISSIBLE_HMAC_KEY        signs admissions        (finalize only)
  ADMISSIBLE_REVIEW_KEY      signs reviews           (a reviewer)
  ADMISSIBLE_EVALUATION_KEY  signs evaluations       (an external observer)

Exit codes are command-specific:
  run:      0 = CHECKS_PASSED only; never admission
  finalize: 0 = an authenticated receipt is ADMITTED
  verify/status: 0 = authenticated CURRENT standing
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
    return identity_module.repository_identity(
        root, expected_sha=expected_sha, allow_dirty=allow_dirty)


def _command_profiles(options, stdout: TextIO, stderr: TextIO) -> int:
    rows = profiles_module.profile_summaries()
    if options.json:
        _dump(stdout, {"profiles": [dict(row) for row in rows]})
        return EXIT_OK
    stdout.write("What happened: listing the built-in starter profiles.\n\n")
    stdout.write("What is known:\n")
    for row in rows:
        stdout.write(f"  {row['name']}\n")
        stdout.write(f"    {row['summary']}\n")
        stdout.write(f"    checks: {', '.join(row['checks'])}\n")
        stdout.write(
            f"    independent reviews required: "
            f"{row['required_independent_reviews']} — "
            f"{row['review_requirement']}\n")
        stdout.write(
            f"    ceilings: {row['max_cost_units']} cost units, "
            f"{row['max_wall_seconds']}s\n")
        stdout.write("    not covered: "
                     f"{row['residual_risks'][0]}\n")
    stdout.write("\nWhat to do next:\n")
    stdout.write("  - pick the profile that matches the risk of the change, "
                 "not only the language\n")
    stdout.write("  - run 'admissible init --profile NAME'\n")
    stdout.write("  - edit .admissible.json to match your real commands, then "
                 "tighten it over time\n")
    return EXIT_OK


def _command_init(options, stdout: TextIO, stderr: TextIO) -> int:
    """Scaffold a policy, and a CI caller that pins the tool by commit.

    Nothing is written until every file this invocation would write has been
    checked. Writing the policy, then discovering the workflow already exists,
    then reporting failure leaves the repository in a state the operator did
    not ask for and the message does not describe.
    """

    stream = stdout if options.json else stderr
    written: list = []
    ignored: tuple[str, ...] = ()
    trusted: list[dict] = []
    try:
        plan = preflight_init(
            options.repo, options.profile, ci=options.ci, force=options.force,
            tool_sha=options.tool_sha,
            allow_placeholder=options.ci_placeholder,
            gitignore=not options.no_gitignore)
        written = list(apply_init(plan))
        ignored = tuple(
            pattern for item in plan for pattern in item.added)
    except (ConfigError, profiles_module.UnknownProfile) as error:
        return _fail(stream, str(error), json_mode=options.json, next_steps=(
            "choose one of: " + ", ".join(profiles_module.PROFILE_NAMES),
            "pass --tool-sha with the full 40-character commit of the "
            "Admissible release you reviewed",
            "re-run with --force to replace an existing file",
        ))
    if options.trust_policy:
        trusted_or_error = _trust_initial_policy(options, stream)
        if type(trusted_or_error) is int:
            return trusted_or_error
        trusted = trusted_or_error
    if options.json:
        _dump(stdout, {"path": str(written[0]), "profile": options.profile,
                       "written": [str(item) for item in written],
                       "ignored": list(ignored),
                       "trusted": trusted,
                       "tool_sha": options.tool_sha or "",
                       "ci": options.ci or ""})
        return EXIT_OK
    stdout.write(f"What happened: wrote {written[0]} for profile "
                 f"{options.profile!r}.\n")
    for extra in written[1:]:
        if extra.name == ".gitignore":
            stdout.write("                and added " + ", ".join(ignored)
                         + " to .gitignore.\n")
        else:
            stdout.write(f"                and {extra}, which calls the pinned "
                         "Admissible reusable workflow.\n")
    stdout.write("\nWhat is known:\n")
    if ignored:
        stdout.write("  - those ignore patterns are what this profile's own "
                     "checks write; an exact-SHA run refuses a dirty worktree, "
                     "so without them the first run would block on output the "
                     "policy itself asked for\n")
    elif not profiles_module.profile_ignores(options.profile):
        stdout.write("  - this profile's checks are your own commands, so "
                     "nothing here can know what they write; if a run blocks "
                     "with 'the worktree is no longer clean', add those paths "
                     "to .gitignore or have the command write outside the "
                     "repository\n")
    stdout.write("  - the generated check commands are a starting template, "
                 "not a description of this repository; they name the tools "
                 "the profile expects, which may not be installed here\n")
    stdout.write("  - nothing has been evaluated yet, and no receipt exists\n")
    stdout.write("  - 'run --preview' issues no receipt and touches no journal, "
                 "but it does execute the checks and write their output to "
                 "owner-only logs under $ADMISSIBLE_HOME/logs\n")
    stdout.write("\nWhat to do next:\n")
    stdout.write("  - replace each check argv with the command your repository "
                 "really runs, and tighten the ceilings and review "
                 "requirements to match the risk of the change\n")
    stdout.write("  - commit the generated file(s): an exact-SHA run refuses a "
                 "worktree with uncommitted or untracked changes, so an "
                 "uncommitted policy cannot be evaluated\n")
    stdout.write("  - then run 'admissible run --preview' and expect to fix "
                 "what it reports; a first run naming missing tools is the "
                 "normal starting point, not a failure of the gate\n")
    return EXIT_OK


def _trust_initial_policy(options, stream: TextIO):
    """Bootstrap the trusted baseline for a policy this operator just wrote."""

    try:
        found = _identity(options.repo, allow_dirty=True)
        parsed = load_config(found.root)
        opened = _open_store(stream)
    except (identity_module.IdentityError, ConfigError,
            store_module.StoreError) as error:
        return _fail(stream, (
            f"the policy was written, but it could not be trusted as a "
            f"baseline: {error}"), json_mode=options.json, next_steps=(
                "commit the generated files, then run 'admissible policy "
                "trust' in this checkout",))
    try:
        now = int(time.time())
        trusted = []
        for artifact_class in parsed.classes:
            opened.trust_policy(
                repository=found.repository, class_id=artifact_class.id,
                policy_digest=artifact_class.policy_digest,
                enforcement_digest=enforcement_digest(artifact_class),
                trusted_at=now)
            trusted.append({"class_id": artifact_class.id,
                            "policy_digest": artifact_class.policy_digest})
        return trusted
    except store_module.StoreError as error:
        return _fail(stream, str(error), json_mode=options.json)
    finally:
        opened.close()


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
                 "evidence bundle and pass it with 'run --evidence'\n")
    stdout.write(f"  - pin this key id in {pinned} for the class it applies "
                 "to\n")
    return EXIT_OK


def _parse_dependency(text: str) -> tuple[str, str]:
    repository, separator, commit_sha = text.rpartition("@")
    if not separator or not repository or not _full_sha(commit_sha):
        raise ConfigError(
            f"--depends-on must look like REPOSITORY@FULL_SHA, got {text!r}")
    return repository, commit_sha

def _new_attempt_id(found, artifact_class, now: int) -> str:
    """A fresh identity for this run of this policy against this artefact.

    Attempts never merge. Worst-evidence resolution is what keeps a passing
    record from papering over a failure *inside* one attempt; a later attempt
    is a separate observation of a separate moment, so a clean rerun may admit
    while yesterday's failure stays on record as history.
    """

    return hashlib.sha256(("|".join((
        "admissible/v0.6/attempt", found.repository, found.commit_sha,
        found.tree_sha, artifact_class.policy_digest, artifact_class.id,
        str(now), secrets.token_hex(16)))).encode("utf-8")).hexdigest()[:32]


def _mutation_report(before, after) -> tuple[str, ...]:
    """What a check changed about the artefact under evaluation."""

    problems = []
    if after.commit_sha != before.commit_sha:
        problems.append(
            f"HEAD moved from {before.commit_sha} to {after.commit_sha}")
    if after.tree_sha != before.tree_sha:
        problems.append(
            f"the committed tree changed from {before.tree_sha} to "
            f"{after.tree_sha}")
    if after.repository != before.repository:
        problems.append(
            f"the repository identity changed from {before.repository} to "
            f"{after.repository}")
    if after.dirty and not before.dirty:
        problems.append("the worktree is no longer clean: "
                        + "; ".join(after.status) if after.status
                        else "the worktree is no longer clean")
    return tuple(problems)


def _command_run(options, stdout: TextIO, stderr: TextIO) -> int:
    """Evaluate this exact commit and hand the result on. Never sign it.

    ``run`` executes candidate-owned commands, so this process must never hold
    a key while it does. That used to be a matter of not passing ``--preview``;
    it is now the only thing ``run`` does. Issuing a receipt is ``finalize``'s
    job, in a different process, with a different trust domain, after an
    external observer has attested that the evaluation happened as described.
    """

    from . import github as github_module

    stream = stdout if options.json else stderr
    if not options.preview:
        return _fail(stream, (
            "'run' evaluates and never signs, so it needs --preview. It starts "
            "candidate-owned commands, and a process that holds a signing key "
            "while it does that has already lost the boundary the key was "
            "protecting: a check runs as this user and can reach anything this "
            "process can. Run 'admissible run --preview --preview-out FILE', "
            "then hand FILE to 'admissible finalize' in the trusted domain "
            "that holds the key."), json_mode=options.json, next_steps=(
                "re-run with --preview to evaluate this commit",
                "add --preview-out FILE to produce the artefact finalize "
                "consumes",
            ))
    # Before anything else: this process is about to start commands the
    # repository under evaluation controls. A check runs as this user, and a
    # descendant that escapes the process group runs as this user after the
    # evaluation believes it is over. Holding a signing credential while that
    # happens has already lost the boundary the credential was protecting, and
    # stripping the names from the *child* environment does not take the file
    # those names point at out of the candidate's reach.
    ambient = runner_module.ambient_signing_credentials()
    if ambient:
        return _fail(stream, (
            "'run' starts candidate-owned commands and this process holds "
            + ", ".join(ambient)
            + ". A check runs as this user and can read what that names, so "
            "the boundary is gone before the first command starts. Nothing "
            "was evaluated."), json_mode=options.json, next_steps=(
                "unset " + " ".join(ambient) + " and re-run",
                "keep signing keys in the finalizer's trust domain, which "
                "never runs a candidate command",
            ))
    try:
        isolation = runner_module.declared_isolation()
    except runner_module.RunnerError as error:
        return _fail(stream, str(error), json_mode=options.json, next_steps=(
            "set ADMISSIBLE_ISOLATION to the boundary that actually confined "
            "these commands, or leave it unset and accept that the preview "
            "cannot be finalised",))
    try:
        found = _identity(options.repo, expected_sha=options.sha)
        config_relative = options.config_path or CONFIG_FILENAME
        parsed = load_config(found.root, config_relative)
        artifact_class = parsed.select_class(options.class_id)
        dependencies = tuple(_parse_dependency(item)
                             for item in options.depends_on)
    except (identity_module.IdentityError, ConfigError) as error:
        return _fail(stream, str(error), json_mode=options.json, next_steps=(
            "run 'admissible init --profile NAME' if this repository has no "
            "policy yet",
            "commit or remove local changes so evidence describes a real "
            "commit",
        ))

    now = int(time.time())
    attempt_id = _new_attempt_id(found, artifact_class, now)
    policy_digest = artifact_class.policy_digest

    # Ceilings are enforced against the plan, before anything is spawned. A
    # class that cannot fit inside its own budget must cost nothing to refuse.
    _, _, ceiling_reasons, _ = plan_budget(artifact_class)
    if ceiling_reasons:
        blocked = evaluate(
            artifact_class=artifact_class, repository=found.repository,
            commit_sha=found.commit_sha, tree_sha=found.tree_sha,
            policy_digest=policy_digest, commands=(), reviews=(), now=now,
            attempt_id=attempt_id,
            not_run=frozenset(check.id for check in artifact_class.checks))
        return _emit_decision(options, stdout, blocked, log_dir=None,
                              attempt_id=attempt_id, recorded=False,
                              anchor=github_module.POLICY_ANCHOR_UNANCHORED)

    # Before anything is written: our own store and logs must not be what makes
    # this worktree dirty.
    try:
        home = store_module.require_home_outside(found.root)
    except store_module.StoreError as error:
        return _fail(stream, str(error), json_mode=options.json, next_steps=(
            "unset ADMISSIBLE_HOME to use the default ~/.admissible",
            "or point it at a directory outside the repository being "
            "evaluated",
        ))
    log_dir = home / "logs" / found.commit_sha[:12]
    # The fingerprint covers every executable this class could start, resolved
    # through the same filtered PATH the children will get, plus the repository
    # lockfiles. A change to any of them invalidates every cached result for
    # this attempt: over-invalidation costs seconds, a wrong reuse costs the
    # guarantee.
    fingerprint = runner_module.environment_fingerprint(
        executables=tuple(check.argv[0] for check in artifact_class.checks),
        root=found.root)

    # The gate's own code lives on the same filesystem, under the same user, as
    # every check it is about to start. Take its measure now.
    try:
        tool_before = runner_module.tool_tree_digest()
    except runner_module.RunnerError as error:
        return _fail(stream, str(error), json_mode=options.json)

    opened = None
    if not options.no_store:
        try:
            opened = _open_store(stream)
        except store_module.StoreError as error:
            return _fail(stream, str(error), json_mode=options.json)
    bundle = None
    try:
        commands: list = []
        provenance: dict[str, str] = {}
        not_run: set[str] = set()
        stop = False
        for check in runner_module.order_checks(artifact_class.checks):
            if stop:
                not_run.add(check.id)
                continue
            cached = None
            if opened is not None and not options.no_cache and check.cacheable:
                cached = opened.cached_command_evidence(
                    repository=found.repository, commit_sha=found.commit_sha,
                    tree_sha=found.tree_sha, policy_digest=policy_digest,
                    check_id=check.id, check_version=check.version,
                    argv_digest=check.argv_digest,
                    environment_fingerprint=fingerprint, now=now,
                    max_age_seconds=check.cache_max_age_seconds)
            if cached is not None:
                # Reuse is an act with its own record. The derived record
                # belongs to this attempt so it can count, and still names the
                # attempt the command actually ran in.
                commands.append(evidence_module.reuse_in_attempt(
                    cached, attempt_id=attempt_id))
                provenance[check.id] = "reused"
                continue
            try:
                result = runner_module.run_check(check, cwd=found.root,
                                                 log_dir=log_dir)
            except runner_module.RunnerError as error:
                return _fail(stream, str(error), json_mode=options.json,
                             next_steps=(
                    "make $ADMISSIBLE_HOME writable, or point ADMISSIBLE_HOME "
                    "at a directory you own",))
            record = evidence_module.command_evidence_from_result(
                result, repository=found.repository,
                commit_sha=found.commit_sha, tree_sha=found.tree_sha,
                policy_digest=policy_digest, attempt_id=attempt_id)
            commands.append(record)
            provenance[check.id] = "executed"
            # A check that edits the artefact invalidates every observation
            # made about it, including its own.
            try:
                after = _identity(found.root, allow_dirty=True)
            except identity_module.IdentityError as error:
                return _fail(stream, str(error), json_mode=options.json)
            problems = _mutation_report(found, after)
            if problems:
                return _fail(stream, (
                    f"check {check.id!r} mutated the repository under "
                    f"evaluation, so no evidence here describes commit "
                    f"{found.commit_sha}: " + "; ".join(problems)),
                    json_mode=options.json, next_steps=(
                        f"make check {check.id!r} read-only, or have it write "
                        "only outside the repository",
                        "commit the repair as its own commit and evaluate that "
                        "commit instead",
                    ))
            if opened is not None:
                opened.cache_command_evidence(
                    record, recorded_at=now,
                    environment_fingerprint=fingerprint,
                    cacheable=check.cacheable)
            if check.required and not record.passed \
                    and not artifact_class.collect_all_checks:
                # Cheapest first, and stop at the first decisive refusal: a
                # refusal should cost one cheap check, not the whole plan.
                stop = True

        reviews: list = []
        carried: list = []
        authorships: list = []
        if options.evidence:
            try:
                bundle = evidence_module.load_evidence_file(options.evidence)
            except evidence_module.EvidenceError as error:
                return _fail(stream, str(error), json_mode=options.json,
                             next_steps=(
                    "produce the bundle with the documented workflow-evidence "
                    "schema",))
            if bundle.defects:
                return _fail(stream, (
                    f"the evidence bundle {options.evidence} carries "
                    f"{len(bundle.defects)} defect record(s); a run must not "
                    "file defects"), json_mode=options.json, next_steps=(
                        "file defects with 'admissible impeach TARGET "
                        "--evidence FILE'",
                        "remove the defects from the bundle and re-run",
                    ))
            for record in bundle.commands:
                commands.append(evidence_module.reuse_in_attempt(
                    record, attempt_id=attempt_id))
                provenance.setdefault(record.check_id, "imported")
            reviews.extend(bundle.reviews)
            authorships.extend(review_module.carry_bundle_authorship(bundle))
            # This process runs candidate-owned commands, so it holds no
            # reviewer keyring and never loads one. An attestation here is
            # exactly a claim: it is carried on, named, counted for nothing,
            # and authenticated where the keyring actually lives.
            try:
                carried.extend(review_module.carry_bundle_attestations(bundle))
            except (review_module.ReviewError,
                    evidence_module.EvidenceError) as error:
                return _fail(stream, str(error), json_mode=options.json,
                             next_steps=(
                    "produce the attestation with 'admissible attest-review'",
                    "or remove the malformed attestation from the bundle",
                ))

        decision_now = int(time.time())
        result = evaluate(
            artifact_class=artifact_class, repository=found.repository,
            commit_sha=found.commit_sha, tree_sha=found.tree_sha,
            policy_digest=policy_digest, commands=tuple(commands),
            reviews=tuple(reviews) + tuple(carried),
            authorships=tuple(authorships), now=decision_now,
            attempt_id=attempt_id, provenance=provenance,
            not_run=frozenset(not_run))

        # Last word before anything is written: is this still the artefact the
        # evidence describes, and is this still the program that judged it?
        try:
            final = _identity(found.root, allow_dirty=True)
        except identity_module.IdentityError as error:
            return _fail(stream, str(error), json_mode=options.json)
        problems = _mutation_report(found, final)
        if problems:
            return _fail(stream, (
                "the repository was mutated during evaluation, so nothing "
                f"here describes commit {found.commit_sha}: "
                + "; ".join(problems)), json_mode=options.json)
        try:
            tool_after = runner_module.tool_tree_digest()
        except runner_module.RunnerError as error:
            return _fail(stream, str(error), json_mode=options.json)
        if tool_after != tool_before:
            return _fail(stream, (
                "the Admissible source tree changed while the checks were "
                "running, so the program that judged this commit is not the "
                "program that started. Nothing here describes anything."),
                json_mode=options.json, next_steps=(
                    "run the gate from a checkout the candidate's checks "
                    "cannot write to",
                    "re-install Admissible and evaluate this commit again",
                ))

        review_records = (tuple(reviews)
                          + tuple(item.record for item in carried)
                          + tuple(item.record for item in authorships))
        anchor = github_module.POLICY_ANCHOR_UNANCHORED
        if opened is not None:
            try:
                anchor = github_module.policy_anchor(
                    opened, repository=found.repository,
                    class_id=artifact_class.id, policy_digest=policy_digest,
                    enforcement_digest=enforcement_digest(artifact_class))
                # An evaluation records what it observed whatever it decided,
                # and whatever --no-cache asked for. Not caching is a statement
                # about reuse; it was never a statement about the audit trail.
                for record in tuple(commands) + review_records:
                    document = evidence_module.evidence_to_dict(record)
                    opened.put_evidence(
                        digest=evidence_module.evidence_digest(record),
                        kind=document["kind"],
                        repository=document["repository"],
                        commit_sha=document["commit_sha"],
                        tree_sha=document["tree_sha"],
                        policy_digest=document["policy_digest"],
                        record=document)
                opened.record_attempt(
                    attempt_id=attempt_id, repository=found.repository,
                    commit_sha=found.commit_sha, class_id=artifact_class.id,
                    policy_digest=policy_digest, state=result.state,
                    started_at=now, tree_sha=found.tree_sha,
                    decision=decision_to_dict(result),
                    digests=[evidence_module.evidence_digest(record)
                             for record in tuple(commands) + review_records])
            except store_module.StoreError as error:
                return _fail(stream, str(error), json_mode=options.json)
    finally:
        if opened is not None:
            opened.close()

    if options.preview_out:
        try:
            _write_preview(options.preview_out, found=found,
                           artifact_class=artifact_class, result=result,
                           commands=tuple(commands), reviews=tuple(reviews),
                           attestations=(
                               bundle.attestations if bundle is not None
                               else ()),
                           author_attestations=(
                               bundle.author_attestations if bundle is not None
                               else ()),
                           dependencies=dependencies, now=decision_now,
                           config_path=config_relative, policy_anchor=anchor,
                           isolation=isolation)
        except (OSError, ValueError) as error:
            return _fail(stream, f"cannot write the preview artefact: {error}",
                         json_mode=options.json)

    return _emit_decision(options, stdout, result, log_dir=log_dir,
                          attempt_id=attempt_id, recorded=opened is not None,
                          anchor=anchor)


def _command_check(options, stdout: TextIO, stderr: TextIO) -> int:
    """Run the preview evaluator and present its answer as Ready v0.7."""

    ambient = runner_module.ambient_signing_credentials()
    if ambient:
        document = ready_module.from_problem(
            "a process that can start candidate checks must not hold "
            "admission, review, or evaluation credentials",
            ("unset " + " ".join(ambient) + " and run the check again",
             "keep every signing credential in its separate trusted domain"),
            reason_code="signing_credential_present",
            summary="A signing credential is present, so no check was run.")
        if options.json:
            _dump(stdout, document)
        else:
            stdout.write(ready_module.render_plain(document))
        return EXIT_BLOCKED

    captured_out, captured_err = io.StringIO(), io.StringIO()
    run_options = argparse.Namespace(**vars(options))
    run_options.command = "run"
    run_options.preview = True
    run_options.preview_out = None
    run_options.no_store = False
    run_options.json = True
    exit_code = _command_run(run_options, captured_out, captured_err)
    raw = captured_out.getvalue()
    try:
        canonical = json.loads(raw)
    except json.JSONDecodeError:
        canonical = {
            "message": captured_err.getvalue().strip()
                       or "the evaluator returned no usable result",
            "remediation": [],
        }
        exit_code = EXIT_BLOCKED
    try:
        if (canonical.get("state") in (CHECKS_PASSED, REFUSED, BLOCKED)
                and type(canonical.get("repository")) is str
                and type(canonical.get("commit_sha")) is str
                and type(canonical.get("tree_sha")) is str
                and type(canonical.get("policy_digest")) is str
                and type(canonical.get("class_id")) is str
                and type(canonical.get("attempt_id")) is str):
            document = ready_module.from_evaluation(canonical)
        else:
            document = ready_module.from_problem(
                canonical.get("message") or "the evaluator was blocked",
                canonical.get("remediation") or ())
    except ready_module.ReadyError as error:
        document = ready_module.from_problem(str(error))
        exit_code = EXIT_BLOCKED
    if options.json:
        _dump(stdout, document)
    else:
        stdout.write(ready_module.render_plain(document))
    return exit_code


def _command_mcp(options, stdout: TextIO, stderr: TextIO) -> int:
    """Serve bounded Ready tools without carrying signing authority."""

    from . import agent_mcp as agent_mcp_module

    ambient = runner_module.ambient_signing_credentials()
    if ambient:
        stderr.write(
            "Unable to connect agent: this process contains a signing "
            "credential. MCP can run candidate checks, so unset "
            + " ".join(ambient)
            + " and keep those credentials in their separate trusted "
              "domains.\n")
        return EXIT_BLOCKED
    try:
        server = agent_mcp_module.Server(
            repo=options.repo, agent_name=options.agent_name,
            purpose=options.purpose, runtime=options.runtime)
    except ValueError as error:
        stderr.write(f"Unable to connect agent: {error}\n")
        return EXIT_BLOCKED
    return agent_mcp_module.serve_stdio(
        server, stdout=stdout, stderr=stderr)


def _command_connect(options, stdout: TextIO, stderr: TextIO) -> int:
    """Print provider-specific setup for the bounded local MCP server."""

    from . import agent_connection as connection_module

    stream = stdout if options.json else stderr
    try:
        document = connection_module.instructions(
            options.repo, name=options.name, purpose=options.purpose,
            runtime=options.runtime)
    except connection_module.ConnectionError as error:
        return _fail(stream, str(error), json_mode=options.json)
    if options.json:
        _dump(stdout, document)
    else:
        stdout.write(
            f"Agent setup ready: {document['name']} ({document['runtime']})\n"
            f"Repository: {document['repository']}\n\n"
            f"{document['instructions']}\n\n"
            f"{document['snippet'].rstrip()}\n\n"
            f"{document['verification']}\n")
    return EXIT_OK


def _command_ui(options, stdout: TextIO, stderr: TextIO) -> int:
    """Run the loopback Ready product without any trusted credential."""

    from . import ready_server as ready_server_module

    ambient = runner_module.ambient_signing_credentials()
    if ambient:
        stderr.write(
            "Unable to start Ready UI: this process contains a signing "
            "credential. The UI can run candidate checks, so unset "
            + " ".join(ambient)
            + " and keep trusted credentials in their separate domains.\n")
        return EXIT_BLOCKED
    try:
        _identity(options.repo, allow_dirty=True)
        server = ready_server_module.make_server(
            options.repo, host="127.0.0.1", port=options.port)
    except (identity_module.IdentityError, ValueError, OSError) as error:
        stderr.write(f"Unable to start Ready UI: {error}\n")
        return EXIT_BLOCKED
    host, port = server.server_address[:2]
    url = f"http://{host}:{port}/"
    stdout.write(f"Admissible Ready: {url}\n")
    stdout.flush()
    if not options.no_open:
        import webbrowser
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
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
                "never place that key in the Ready UI or MCP process",
            ))
    document = ready_module.inspect(options.repo, signer=signer, identity=found)
    if options.json:
        _dump(stdout, document)
    else:
        stdout.write(ready_module.render_plain(document))
    return EXIT_OK if document["status"] == "ready" else EXIT_NOT_CURRENT


def _emit_decision(options, stdout: TextIO, result, *, log_dir,
                   attempt_id: str, recorded: bool, anchor: str) -> int:
    if options.json:
        document = decision_to_dict(result)
        document["preview"] = True
        document["attempt_id"] = attempt_id
        document["receipt"] = None
        document["recorded"] = recorded
        document["policy_anchor"] = anchor
        document["log_directory"] = "" if log_dir is None else str(log_dir)
        _dump(stdout, document)
        return result.exit_code
    stdout.write(render_plain(result))
    stdout.write(
        "\nThis is an evaluation, not an admission: no receipt was issued and "
        "no journal\nwas touched. Only 'admissible finalize', in the trust "
        "domain that holds the\nsigning key, can anchor one.\n")
    if not recorded:
        stdout.write(
            "\n--no-store was given, so nothing here was recorded: no attempt, "
            "no evidence,\nand nothing 'admissible explain' will be able to "
            "answer about later.\n")
    if anchor == _ANCHOR_UNANCHORED:
        stdout.write(
            "\nPolicy: unanchored. This context holds no trusted baseline for "
            "this class, so\nit read the policy out of the checkout and had "
            "nothing to compare it against.\nA finalizer with a baseline is "
            "what decides whether that policy may enforce.\n")
    elif anchor == _ANCHOR_CHANGED:
        stdout.write(
            "\nPolicy: changed. This policy enforces something different from "
            "the baseline\nthis home trusts. A finalizer will refuse it until "
            "an operator approves the\nchange with 'admissible policy "
            "trust'.\n")
    if preview_readiness(result) == READINESS_AWAITING_REVIEW:
        stdout.write(
            "\nEvery required check passed and no keyring here could "
            "authenticate the reviews.\nThat is a handoff, not an admission: "
            "give this to a finalizer holding the pinned\nreviewer keyring "
            "and it will recompute the whole decision there.\n")
    return result.exit_code


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
                f"run 'admissible explain {commit_sha}' to inspect the signed "
                "defect and its reachable dependents",
            )
        else:
            remediation = (
                f"run 'admissible run --preview --preview-out preview.json "
                f"--sha {commit_sha}' in a clean checkout of that commit",
                "have a trusted observer attest that preview, then run "
                "'admissible finalize' in the durable signing domain",
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
                "'admissible run --preview' against this commit, or import a "
                "journal that carries its attempt.")
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
                # Re-judge at the recorded decision moment. An attempt starts
                # before its checks complete, so using started_at would treat
                # valid long-run evidence as future-dated after a successful
                # completion-time evaluation. Historical attempts without a
                # stored decision retain the older receipt/start fallback.
                moment = (((attempt or {}).get("decision") or {}).get("evaluated_at")
                          or (attempt or {}).get("started_at")
                          or (receipts[0].issued_at if receipts else 0)
                          or int(time.time()))
                result = evaluate(
                    artifact_class=artifact_class, repository=repository,
                    commit_sha=commit_sha, tree_sha=tree_sha,
                    policy_digest=artifact_class.policy_digest,
                    commands=commands, reviews=reviews,
                    authorships=authorships, now=moment,
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
            "run 'admissible run' at least once so there is a journal to "
            "export",
        ]
        if "through_head" in str(error):
            steps = [
                "choose a stored signed head and retry with 'admissible "
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
                f"{store_module.MAX_JOURNAL_BYTES}-byte ceiling 'admissible "
                "import' will read. Nothing was written."),
                json_mode=options.json, next_steps=(
                    "retry with 'admissible export --through-head HEAD_HASH "
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
    stdout.write("  - run 'admissible import --in FILE' on the other machine, "
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
    stdout.write("  - run 'admissible verify SHA' for any commit you care "
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
        return (f"run 'admissible explain {commit_sha}'",)
    if reported == "UNVERIFIED":
        return (
            "receipts exist for this commit and nothing here can authenticate "
            "them, so this commit is not shown to be admitted"
            + (f": {key_problem}" if key_problem else ""),
            "export the ADMISSIBLE_HMAC_KEY of the domain that issued them, "
            f"then run 'admissible verify {commit_sha}'",
        )
    return (
        "run 'admissible run --preview --preview-out preview.json' to "
        "evaluate this commit; 'run' never signs",
        "have the external observer sign it with 'admissible "
        "attest-evaluation --preview preview.json --source-receipt "
        "receipt.json --isolation MODE --out evaluation.json' after "
        "independently validating that boundary from external evidence",
        "then 'admissible finalize --preview preview.json --sha "
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
        standing_module.file_defect(opened, document, signer=signer,
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


def _write_preview(path_text: str, *, found, artifact_class, result,
                   commands: tuple, reviews: tuple, dependencies: tuple,
                   now: int, config_path: str, policy_anchor: str,
                   isolation: str, attestations: tuple = (),
                   author_attestations: tuple = ()) -> None:
    """Write the unsigned artefact the trusted finalize job consumes.

    Written last, owner-only, and in one step. Last because every check has
    finished and its whole process group has been killed by then, so nothing
    the candidate started is still around to rewrite it. Owner-only and atomic
    because a file that appears empty, then partial, then complete is a file
    another process can catch halfway: it is created ``0600`` under a private
    temporary name and renamed into place, so a reader sees the old file or the
    whole new one and never something in between.
    """

    from . import github as github_module

    bundle = evidence_module.Bundle(
        commands=commands, reviews=reviews, defects=(),
        attestations=attestations, author_attestations=author_attestations)
    document = github_module.preview_document(
        repository=found.repository, commit_sha=found.commit_sha,
        tree_sha=found.tree_sha, policy_digest=artifact_class.policy_digest,
        class_id=artifact_class.id, state=result.state,
        readiness=preview_readiness(result),
        decision=decision_to_dict(result),
        evidence=evidence_module.bundle_to_dict(bundle),
        dependencies=dependencies, issued_at=now,
        config_path=config_path, policy_anchor=policy_anchor,
        isolation=isolation, fork=_fork_from_environment())
    body = json.dumps(document, indent=2, sort_keys=True) + "\n"
    encoded = body.encode("utf-8")
    if len(encoded) > github_module.MAX_PREVIEW_HANDOVER_BYTES:
        raise ValueError(
            f"the preview is {len(encoded)} bytes, above the "
            f"{github_module.MAX_PREVIEW_HANDOVER_BYTES}-byte ceiling that "
            "still fits a GitHub job output once base64 and UTF-16 accounting "
            "are applied. Reduce the number of checks or reviews in this "
            "class, or hand the preview over as a pinned artefact instead.")
    _write_private(Path(path_text), encoded)


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

    from . import github as github_module

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
    stdout.write("  - pass it to 'admissible finalize --evaluation-attestation "
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
            next_steps=("read the digest from 'admissible policy list "
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
                 "with 'admissible policy list --all'\n\n")
    stdout.write("What to do next:\n")
    if not remaining:
        stdout.write("  - this class can now admit nothing; run 'admissible "
                     "policy trust' on the policy that should enforce it\n")
    else:
        stdout.write("  - run 'admissible policy list' and confirm what is "
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
            "usage: admissible policy trust [--class ID] | policy list "
            "[--class ID] [--all] | policy revoke --class ID --digest SHA256"),
            json_mode=options.json, next_steps=(
            "run 'admissible policy trust' in a trusted checkout to record "
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


def _fork_from_environment() -> bool:
    """Mark a preview produced by a fork so no finalizer can ever sign it."""

    from . import github as github_module

    import os

    if not os.environ.get("GITHUB_EVENT_NAME"):
        return False
    try:
        return github_module.evaluation_context(os.environ).is_fork
    except github_module.GitHubError:
        # An unidentifiable CI context is treated as untrusted, not as trusted.
        return True


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
            f"  - read it back with 'admissible verify {issued.commit_sha}'\n"
            "  - do not re-run finalize expecting a different answer: the "
            "admission is already recorded\n")
        return EXIT_OK
    steps = (
        f"run 'admissible verify {options.sha}' to see whether a receipt "
        "exists for this commit",
        "run 'admissible status' to see whether the journal advanced",
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
    from . import github as github_module

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
            "have the external observer sign the evaluation with 'admissible "
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
                    f"read it back with 'admissible verify "
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
        stdout.write(f"  - run 'admissible verify {issued.commit_sha}' from any "
                     "machine with the same key\n")
        stdout.write("  - file a defect with 'admissible impeach' if reality "
                     "later disagrees\n")
        return EXIT_OK
    finally:
        opened.close()


# What an interrupt leaves behind, per command. The default is the careful
# answer, because a command that anchors is a command whose durable commit may
# already have happened when the signal arrived.
_INTERRUPTED = {
    "run": (
        "INTERRUPTED",
        "No receipt was issued and no journal was touched: 'run' never issues "
        "one. Evidence from checks that had already finished may be on "
        "record. Nothing the checks started is still running -- the runner "
        "kills each process group in a 'finally'.",
        ("run 'admissible explain SHA' to see what was recorded",
         "re-run when ready; an evaluation is repeatable by construction")),
    "profiles": ("INTERRUPTED", "Nothing was read and nothing was written.",
                 ("re-run the command",)),
    "init": ("INTERRUPTED",
             "'init' writes every file it plans or none of them, and puts back "
             "anything it had already written.",
             ("re-run 'admissible init'",
              "check 'git status' to confirm the tree is as you left it")),
    "verify": ("INTERRUPTED", "Nothing was written; verify only reads.",
               ("re-run the command",)),
    "explain": ("INTERRUPTED", "Nothing was written; explain only reads.",
                ("re-run the command",)),
    "status": ("INTERRUPTED", "Nothing was written; status only reads.",
               ("re-run the command",)),
    None: (
        _UNKNOWN_COMMIT_OUTCOME,
        "This command can write durably, and the interrupt arrived without a "
        "chance to read the store back. Whether the durable commit happened "
        "is not known here, and it will not be guessed.",
        ("run 'admissible verify SHA' to see whether a receipt exists",
         "run 'admissible status' to see whether the journal advanced")),
}

_COMMANDS = {
    "profiles": _command_profiles,
    "init": _command_init,
    "run": _command_run,
    "check": _command_check,
    "mcp": _command_mcp,
    "connect": _command_connect,
    "ui": _command_ui,
    "ready-status": _command_ready_status,
    "verify": _command_verify,
    "explain": _command_explain,
    "status": _command_status,
    "impeach": _command_impeach,
    "attest-review": _command_attest_review,
    "attest-evaluation": _command_attest_evaluation,
    "policy": _command_policy,
    "finalize": _command_finalize,
    "export": _command_export,
    "import": _command_import,
}


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    """Run one Admissible command and return its exit code."""

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
                         "run 'admissible --help' for the exact command list",))
    if getattr(options, "help", False) or options.command is None:
        if json_requested:
            return _fail(out, "no command given", json_mode=True, next_steps=(
                "run 'admissible --help' for the exact command list",))
        out.write(_HELP)
        return EXIT_BLOCKED
    handler = _COMMANDS.get(options.command)
    if handler is None:
        if json_requested:
            return _fail(out, f"unknown command {options.command!r}",
                         json_mode=True, next_steps=(
                             "run 'admissible --help' for the exact command "
                             "list",))
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
        # still that the outcome is unknown, which is what the table below
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
