"""``admissible-ready`` — the candidate-side command surface, and only that.

Seven commands: ``profiles``, ``init``, ``run --preview``, ``check``, ``mcp``,
``connect`` and ``ui``.  Every one of them can start a command the repository
under evaluation chose, so every one of them refuses before its first side
effect if this process holds an admission, review or observer credential.

What is *not* here is the other half of the monolith's CLI: ``ready-status``,
``attest-review``, ``attest-evaluation``, ``policy trust``/``revoke``/``list``,
``finalize``, ``verify``, ``export``, ``import`` and ``impeach``.  They are not
hidden behind a flag or a missing key -- the code that implements them is in a
distribution this wheel does not contain and does not depend on, so
``admissible-ready finalize`` is an unknown command rather than a refused one.

``run`` without ``--preview`` is a refusal with migration guidance, because
that is the shape the mistake actually takes: somebody expects one command to
evaluate and then sign.  It cannot, and it should not want to -- a process that
starts a candidate's command while holding a signing key has already lost the
boundary the key was protecting.

Exit codes are stable within each command.  ``run --preview`` and ``check``
return zero only for ``CHECKS_PASSED``, which is an evaluation and never an
admission; nonzero means refused or operationally blocked as the command's JSON
envelope describes.
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

from admissible_core import evidence as evidence_module
from admissible_core import identity as identity_module
from admissible_core import profiles as profiles_module
from admissible_core.config import (CI_PROVIDERS, CONFIG_FILENAME, ConfigError,
                                    apply_init, enforcement_digest,
                                    load_config, preflight_init)
from admissible_core.decision import (BLOCKED, CHECKS_PASSED, DECISION_SCOPE,
                                      READINESS_AWAITING_REVIEW,
                                      READINESS_NOT_READY, REFUSED,
                                      decision_to_dict, evaluate, plan_budget,
                                      preview_readiness, render_plain)

from . import git_reader
from . import ready as ready_module
from . import runner as runner_module
from . import store as store_module

__all__ = ["main"]

EXIT_OK = 0
EXIT_BLOCKED = 2

_FULL_SHA_LENGTH = 40
_ANCHOR_UNANCHORED = "unanchored"
_ANCHOR_CHANGED = "changed"

#: Where this distribution keeps the CI caller template ``init --ci`` writes.
#: The kernel plans the write and this distribution owns the bytes: a workflow
#: that runs ``admissible run --preview`` is candidate-side scaffolding, and a
#: kernel that shipped it would be shipping an execution surface.
TEMPLATE_ROOT = Path(__file__).resolve().parent / "templates"


class _Usage(Exception):
    """argparse wanted to exit; the CLI decides what to print and return."""

    def __init__(self, message: str, code: int = EXIT_BLOCKED) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # pragma: no cover - argparse plumbing
        raise _Usage(f"admissible-ready: {message}\n{self.format_usage()}")

    def exit(self, status: int = 0, message: str | None = None):
        raise _Usage(message or "", EXIT_BLOCKED if status else EXIT_OK)


def _build_parser() -> _Parser:
    parser = _Parser(prog="admissible-ready", add_help=False,
                     description="Candidate-side Admissible readiness gate.")
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
    return parser


_HELP = """usage: admissible-ready COMMAND [options]

The candidate side of Admissible: it evaluates this exact commit and shows
what is known. It signs nothing, and it holds no key.

Commands:
  profiles [--json]                       list the built-in starter profiles
  init --profile NAME [--force]           write .admissible.json
      [--ci github]                       ...and a CI caller workflow
      [--no-gitignore]                    ...without ignoring check output
  init --profile NAME --ci github        ...pinning the tool by commit
      --tool-sha FULL_SHA
      [--ci-placeholder]
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

Common options: --repo DIR, --json

Not here, and not by accident. Reviewing, trusting a policy, finalising,
verifying a receipt, filing a defect and reading authenticated standing all
need a key, and a process that starts a candidate's commands must not hold
one. They live in `admissible-trust`, which is a separate installation with no
runner, no MCP server and no HTTP server in it:

  admissible-trust attest-review        sign a review with a reviewer key
  admissible-trust attest-evaluation    sign an evaluation as the observer
  admissible-trust policy trust|revoke|list
  admissible-trust finalize             sign a validated preview artefact
  admissible-trust verify|status|explain|ready-status
  admissible-trust export|import|impeach

This command refuses to start at all while any of these is in its environment:
  ADMISSIBLE_HMAC_KEY[_FILE|_ID]        signs admissions        (finalize only)
  ADMISSIBLE_REVIEW_KEY[_FILE|_ID], ADMISSIBLE_REVIEW_KEYRING     (a reviewer)
  ADMISSIBLE_EVALUATION_KEY[_FILE|_ID], ADMISSIBLE_EVALUATION_KEYRING
                                        signs evaluations (an external observer)

Exit codes are command-specific:
  run --preview: 0 = CHECKS_PASSED only; never admission
  check:         0 = CHECKS_PASSED only; never admission
  nonzero: refused, or blocked as the command output explains.
"""


def _fail(stream: TextIO, message: str, *, next_steps: tuple[str, ...] = (),
          json_mode: bool = False) -> int:
    """Report a blocked invocation on the stream the caller is reading."""

    steps = tuple(next_steps) or ("fix the problem above and re-run",)
    if json_mode:
        # A --json caller must never have to parse prose off stdout.
        _dump(stream, {
            "scope": DECISION_SCOPE,
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
    return git_reader.repository_identity(
        root, expected_sha=expected_sha, allow_dirty=allow_dirty)


# -- the credential canary ---------------------------------------------------
def _credential_refusal(stream: TextIO, verb: str, *,
                        json_mode: bool = False) -> int | None:
    """Refuse before any side effect while a signing credential is present.

    Called first in every command that can read the repository, open the
    store, bind a socket or start a subprocess -- before all four, not between
    them.  ``present_signing_credentials`` reports a variable that is *set*,
    empty or not, because the fact that matters is that something arranged for
    a signing identity to be in this process.
    """

    present = runner_module.present_signing_credentials()
    if not present:
        return None
    return _fail(stream, (
        f"{verb!r} starts candidate-owned commands and this process holds "
        + ", ".join(present)
        + ". A check runs as this user and can read what that names, so "
        "the boundary is gone before the first command starts. Nothing "
        "was evaluated."), json_mode=json_mode, next_steps=(
            "unset " + " ".join(present) + " and re-run",
            "keep signing keys in the finalizer's trust domain, which "
            "never runs a candidate command",
        ))


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

    ``--trust-policy`` is not accepted here. Recording which policy may enforce
    is an operator's act in a trusted context, and this distribution has no
    ``trust_policy`` to call: the candidate store facade withholds it and the
    backend does not implement it. ``admissible-trust policy trust`` is where
    it lives, and the JSON below reports an empty ``trusted`` list rather than
    dropping the key, so a consumer of the old shape still parses.
    """

    stream = stdout if options.json else stderr
    refusal = _credential_refusal(stream, "init", json_mode=options.json)
    if refusal is not None:
        return refusal
    written: list = []
    ignored: tuple[str, ...] = ()
    try:
        plan = preflight_init(
            options.repo, options.profile, ci=options.ci, force=options.force,
            tool_sha=options.tool_sha,
            allow_placeholder=options.ci_placeholder,
            gitignore=not options.no_gitignore,
            template_root=TEMPLATE_ROOT)
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
    if options.json:
        _dump(stdout, {"path": str(written[0]), "profile": options.profile,
                       "written": [str(item) for item in written],
                       "ignored": list(ignored),
                       "trusted": [],
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


def _carry_bundle_attestations(bundle) -> tuple:
    """Every review attestation in a bundle, carried without authenticating it.

    This is what a job that holds *no* reviewer keyring may honestly do with a
    signature: keep it, name the key it claims, hand it on to whoever can check
    it, and count it for nothing.  It is not a weaker verification -- there is
    no keyring in this distribution to verify against, and
    :func:`admissible_core.decision.evaluate` counts an ``UnverifiedReview``
    towards no review requirement.

    Deliberately not imported from the signing distribution.  The function
    there is three lines of shape-checking beside the verification it exists to
    be distinguished from, and importing it would put the verifier one
    attribute away from a process that runs candidate commands.
    """

    return tuple(
        evidence_module.UnverifiedReview(
            record=evidence_module.review_evidence_from_dict(
                document["review"]),
            key_id=document["key_id"])
        for document in bundle.attestations)


def _carry_bundle_authorship(bundle) -> tuple:
    """Every authorship claim in a bundle, carried without authenticating it."""

    return tuple(
        evidence_module.UnverifiedAuthorship(
            record=evidence_module.authorship_evidence_from_dict(
                document["authorship"]),
            key_id=document["key_id"])
        for document in bundle.author_attestations)


def _command_run(options, stdout: TextIO, stderr: TextIO) -> int:
    """Evaluate this exact commit and hand the result on. Never sign it.

    ``run`` executes candidate-owned commands, so this process must never hold
    a key while it does. That used to be a matter of not passing ``--preview``;
    it is now the only thing ``run`` does, and in this distribution there is no
    signing code left for it to reach. Issuing a receipt is
    ``admissible-trust finalize``'s job, in a different process, in a different
    installation, after an external observer has attested that the evaluation
    happened as described.
    """

    from . import github as github_module

    stream = stdout if options.json else stderr
    if not options.preview:
        return _fail(stream, (
            "'run' evaluates and never signs, so it needs --preview. It starts "
            "candidate-owned commands, and a process that holds a signing key "
            "while it does that has already lost the boundary the key was "
            "protecting: a check runs as this user and can reach anything this "
            "process can. This distribution has no finalizer in it at all -- "
            "run 'admissible-ready run --preview --preview-out FILE', then "
            "hand FILE to 'admissible-trust finalize' in the trusted domain "
            "that holds the key."), json_mode=options.json, next_steps=(
                "re-run with --preview to evaluate this commit",
                "add --preview-out FILE to produce the artefact finalize "
                "consumes",
                "install admissible-trust in a separate environment and run "
                "'admissible-trust finalize --preview FILE' there",
            ))
    # Before anything else: this process is about to start commands the
    # repository under evaluation controls. A check runs as this user, and a
    # descendant that escapes the process group runs as this user after the
    # evaluation believes it is over. Holding a signing credential while that
    # happens has already lost the boundary the credential was protecting, and
    # stripping the names from the *child* environment does not take the file
    # those names point at out of the candidate's reach.
    refusal = _credential_refusal(stream, "run", json_mode=options.json)
    if refusal is not None:
        return refusal
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
                        "file defects with 'admissible-trust impeach TARGET "
                        "--evidence FILE'",
                        "remove the defects from the bundle and re-run",
                    ))
            for record in bundle.commands:
                commands.append(evidence_module.reuse_in_attempt(
                    record, attempt_id=attempt_id))
                provenance.setdefault(record.check_id, "imported")
            reviews.extend(bundle.reviews)
            # This process runs candidate-owned commands, so it holds no
            # reviewer keyring and never loads one. An attestation here is
            # exactly a claim: it is carried on, named, counted for nothing,
            # and authenticated where the keyring actually lives.
            try:
                authorships.extend(_carry_bundle_authorship(bundle))
                carried.extend(_carry_bundle_attestations(bundle))
            except (KeyError, TypeError,
                    evidence_module.EvidenceError) as error:
                return _fail(stream, str(error), json_mode=options.json,
                             next_steps=(
                    "produce the attestation with "
                    "'admissible-trust attest-review'",
                    "or remove the malformed attestation from the bundle",
                ))

        result = evaluate(
            artifact_class=artifact_class, repository=found.repository,
            commit_sha=found.commit_sha, tree_sha=found.tree_sha,
            policy_digest=policy_digest, commands=tuple(commands),
            reviews=tuple(reviews) + tuple(carried),
            authorships=tuple(authorships), now=now,
            # The checks have just run; judge against the clock now, not the
            # attempt's start, so a check that ran longer than the clock-skew
            # allowance is not mistaken for future-dated evidence.
            decided_at=int(time.time()),
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
                           dependencies=dependencies, now=now,
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

    present = runner_module.present_signing_credentials()
    if present:
        document = ready_module.from_problem(
            "a process that can start candidate checks must not hold "
            "admission, review, or evaluation credentials",
            ("unset " + " ".join(present) + " and run the check again",
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

    present = runner_module.present_signing_credentials()
    if present:
        stderr.write(
            "Unable to connect agent: this process contains a signing "
            "credential. MCP can run candidate checks, so unset "
            + " ".join(present)
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
    # `connect` reads the repository through git, which starts a process, and
    # the setup it prints is how an agent will later run checks here. Both are
    # reasons to refuse before the first subprocess rather than after it.
    refusal = _credential_refusal(stream, "connect", json_mode=options.json)
    if refusal is not None:
        return refusal
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

    present = runner_module.present_signing_credentials()
    if present:
        stderr.write(
            "Unable to start Ready UI: this process contains a signing "
            "credential. The UI can run candidate checks, so unset "
            + " ".join(present)
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
        isolation=isolation, fork=github_module.fork_from_environment())
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


_INTERRUPTED = {
    "run": (
        "INTERRUPTED",
        "No receipt was issued and no journal was touched: 'run' never issues "
        "one. Evidence from checks that had already finished may be on "
        "record. Nothing the checks started is still running -- the runner "
        "kills each process group in a 'finally'.",
        ("run 'admissible explain SHA' to see what was recorded",
         "re-run when ready; an evaluation is repeatable by construction")),
    "check": (
        "INTERRUPTED",
        "No receipt was issued and no journal was touched: a check never "
        "issues one. Evidence from checks that had already finished may be on "
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
    "connect": ("INTERRUPTED", "Nothing was written; connect only reads.",
                ("re-run the command",)),
    "mcp": ("INTERRUPTED",
            "The connection registration, if any, was removed with the "
            "process. Evidence from checks an agent had already requested may "
            "be on record.",
            ("re-run the command",)),
    "ui": ("INTERRUPTED",
           "The server stopped. Evidence from checks it had already started "
           "may be on record.",
           ("re-run the command",)),
    None: (
        "INTERRUPTED",
        "Nothing in this distribution issues a receipt or anchors a journal, "
        "so no authenticated state can be half-written. Evidence and attempts "
        "from work that had already finished may be on record.",
        ("re-run the command",
         "run 'admissible-trust status' in the trusted domain to see whether "
         "any authenticated state exists")),
}

_COMMANDS = {
    "profiles": _command_profiles,
    "init": _command_init,
    "run": _command_run,
    "check": _command_check,
    "mcp": _command_mcp,
    "connect": _command_connect,
    "ui": _command_ui,
}


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    """Run one Admissible Ready command and return its exit code."""

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
        # about this machine, so it is answered even beside a credential. A
        # `--help` that refused would be a `--help` nobody could use to find
        # out why.
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
                         "run 'admissible-ready --help' for the exact command "
                         "list",))
    if getattr(options, "help", False) or options.command is None:
        if json_requested:
            return _fail(out, "no command given", json_mode=True, next_steps=(
                "run 'admissible-ready --help' for the exact command list",))
        out.write(_HELP)
        return EXIT_BLOCKED
    handler = _COMMANDS.get(options.command)
    if handler is None:
        if json_requested:
            return _fail(out, f"unknown command {options.command!r}",
                         json_mode=True, next_steps=(
                             "run 'admissible-ready --help' for the exact "
                             "command list",))
        err.write(_HELP)
        return EXIT_BLOCKED
    try:
        return handler(options, out, err)
    except KeyboardInterrupt:
        # Deliberately never a bare "nothing was recorded". What an interrupt
        # leaves behind depends on which command was running, so the answer
        # does too, and a --json caller is owed it as a document rather than as
        # prose on stderr they cannot parse.
        json_mode = _json_mode(options)
        state, message, steps = _INTERRUPTED.get(
            options.command, _INTERRUPTED[None])
        if json_mode:
            _dump(out, {
                "scope": DECISION_SCOPE,
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
    except (OSError, store_module.StoreError, evidence_module.EvidenceError,
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
