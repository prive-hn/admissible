"""``admissible`` — the legacy command, and the table that says where it goes.

The monolith's command surface was one program that could evaluate a candidate
and sign the result.  The split made those two programs, in two distributions,
that cannot import each other.  This module keeps the old name usable on a
developer machine by doing exactly one thing: deciding, from the words typed,
which of the two owns the invocation, and handing the whole argument list to
that one's ``main``.

Three properties, and they are the reasons this file is as boring as it is:

*Ownership is static.*  ``READY_COMMANDS`` and ``TRUST_COMMANDS`` are written
down here.  Nothing in this module reads the environment -- not a credential,
not a keyring path, not a home directory -- so the same words dispatch the same
way on every machine.  Choosing a domain by noticing that a signing key happens
to be set is the failure this split exists to make impossible: it would mean
the meaning of a command depends on what the machine holds, and the one machine
that holds everything is the one where it matters most.

*One verb needs a rule.*  ``run`` is implemented by both distributions, so a
row cannot say who owns it.  ``--preview`` on its own is Ready's evaluation;
``--preview FILE``, or no ``--preview`` at all, is Trust's transitional alias
for ``finalize``.  Ready's ``run`` takes no positional argument, so a value
after ``--preview`` cannot be a Ready invocation -- the two shapes are told
apart by the argument list and by nothing else.

*Everything else fails closed.*  A command that is in neither table is refused,
with both explicit commands named, before anything is imported.  Guessing would
mean sending an unknown verb to whichever distribution seemed likelier, and the
cost of guessing wrong is a candidate's command running in the process that
holds a key.

*An import that fails is two different facts.*  Either the distribution that
owns the command is not installed -- ``pip install --no-deps admissible`` is a
real thing people do -- or it is installed and its code raised.  The two get
two refusals, because they send a reader to two different places: one to an
install, the other to a defect in a release that is already on the machine.
Reporting the second as the first makes a genuine fault inside
``admissible_ready`` unreportable, so the distinction is drawn from the
exception's own ``name`` and from whether the top-level package can be located
at all, and never from the fact that *an* ``ImportError`` happened.

The two refusals also differ in what they claim about this process.  Nothing at
all ran for an absent owner, and nothing ran for a command that was never
routed, so both say so.  A broken owner is the other case: its import was
attempted, its package ``__init__`` may have finished, a submodule of it may
still be in ``sys.modules``, and anything that code did before raising has
already happened.  Saying "nothing was imported" there would be false, and
false in the direction that costs a reader the most -- it sends them to look
for the fault in a process they have been told never started.

Only the resolved distribution is imported.  A Ready command never loads
``admissible_trust``, so a Ready refusal cannot fall through to Trust and be
tried again there; a Trust command never loads ``admissible_ready``, so nothing
signing-side can reach a runner even by accident.  That holds for a failed
import too: a broken owner is refused where it broke, not retried elsewhere.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from typing import Any, TextIO

from admissible_core.decision import (BLOCKED, DECISION_SCOPE,
                                      READINESS_NOT_READY)

__all__ = ["main", "resolve"]

EXIT_OK = 0
EXIT_BLOCKED = 2

#: The two modules an invocation can be handed to.
READY_TARGET = "admissible_ready.cli"
TRUST_TARGET = "admissible_trust.cli"

#: Commands the candidate-side distribution implements and this one routes to
#: it.  Every one of them can start a process the repository under evaluation
#: chose, which is why they live in the distribution that holds no key.
READY_COMMANDS = frozenset({
    "profiles", "init", "check", "mcp", "connect", "ui",
})

#: Commands the signing distribution implements.  ``explain``, ``status``,
#: ``export`` and ``import`` are here because the split gave them to Trust
#: outright: the candidate side implements no version of them at all, so there
#: is nothing for a submode to choose between.
TRUST_COMMANDS = frozenset({
    "ready-status", "attest-review", "attest-evaluation", "policy",
    "finalize", "verify", "explain", "status", "export", "import", "impeach",
})

#: The verbs both distributions implement, and therefore the verbs that need a
#: rule.  Every one of them must appear in :data:`SUBMODES`.
SHARED_COMMANDS = frozenset({"run"})

#: The verbs the split made ambiguous.  They still work for one release window;
#: a human gets a line on stderr naming what replaces them, and a machine gets
#: nothing at all, because its stdout is a wire format.
TRANSITIONAL_COMMANDS = frozenset({
    "run", "explain", "status", "export", "import",
})

_OWNERS = {
    **{command: READY_TARGET for command in READY_COMMANDS},
    **{command: TRUST_TARGET for command in TRUST_COMMANDS},
}

# The two module names are spelled out at the call site rather than passed
# through as a variable, so that the complete set of modules this file can
# reach is readable in the file itself -- by a person and by the import census.
_LOADERS = {
    READY_TARGET: lambda: importlib.import_module("admissible_ready.cli"),
    TRUST_TARGET: lambda: importlib.import_module("admissible_trust.cli"),
}

_PREVIEW = "--preview"


def _top_level_is_absent(module: str) -> bool:
    """Is this top-level name genuinely not on the import path?

    ``find_spec`` locates a module without executing it, which is exactly the
    question here: whether the distribution is *installed*, separately from
    whether its code runs.  Absence is only ever claimed when it has been
    established: a finder that raises, or a name already in ``sys.modules``
    with no spec, has proved that the environment is not answering rather than
    that the distribution is missing, so both answer "not absent" and the
    caller reports the breakage instead.
    """
    try:
        return importlib.util.find_spec(module) is None
    except (ImportError, ValueError):
        return False


def _owner_is_absent(target: str, error: ImportError) -> bool:
    """Did this ``ImportError`` mean "that distribution is not installed"?

    Two conditions, and both are needed.  The exception must be a
    ``ModuleNotFoundError`` naming the owning distribution's top-level package
    or something inside it -- a failure to find ``admissible_core.decision``
    while loading ``admissible_ready.cli`` is a Core problem, not an absent
    Ready -- and that top-level package must then actually be unfindable, so
    that a missing ``admissible_ready.cli`` inside a present
    ``admissible_ready`` is read as the broken install it is.

    Everything else is code that is present and raised.  Calling that "absent"
    sends a reader to reinstall a distribution that is already installed, while
    the defect that stopped their command stays exactly where it was.
    """
    if not isinstance(error, ModuleNotFoundError):
        return False
    name = getattr(error, "name", None)
    if not name:
        return False
    top = target.partition(".")[0]
    if name != top and not name.startswith(f"{top}."):
        return False
    return _top_level_is_absent(top)


def _resolve_run(arguments: list[str]) -> str:
    """Which distribution owns this ``run``, from its arguments alone.

    ``--preview`` as a bare flag is Ready evaluating this commit.  A value
    after it -- ``--preview FILE`` or ``--preview=FILE`` -- is the retained
    artefact Trust's transitional alias consumes, and no ``--preview`` at all
    is that same alias invoked without the artefact, which refuses and says
    where each half went.
    """
    for index, argument in enumerate(arguments):
        if argument.startswith(f"{_PREVIEW}="):
            return TRUST_TARGET
        if argument == _PREVIEW:
            following = arguments[index + 1:index + 2]
            if not following or following[0].startswith("-"):
                return READY_TARGET
            return TRUST_TARGET
    return TRUST_TARGET


#: ``command -> rule``, for the commands a row cannot decide.
SUBMODES = {"run": _resolve_run}


def resolve(arguments: list[str]) -> str | None:
    """The module that owns this invocation, or ``None`` to refuse it.

    Pure, and deliberately so: it reads the argument list, consults two written
    tables, and returns.  Nothing here opens a file, reads a variable or
    imports a distribution, so the answer is a property of what was typed.
    """
    if not arguments:
        return None
    command = arguments[0]
    if command.startswith("-"):
        return None
    rule = SUBMODES.get(command)
    if rule is not None:
        return rule(list(arguments[1:]))
    return _OWNERS.get(command)


def _warning(command: str, target: str) -> str:
    """The migration line a human gets, on stderr, for a transitional verb."""
    if command == "run":
        if target == READY_TARGET:
            return (
                "Warning: 'admissible run --preview' is a compatibility alias "
                "handled here by 'admissible-ready run --preview'. It "
                "evaluates and never signs; issuing a receipt is "
                "'admissible-trust finalize', in a separate process holding "
                "the key.\n")
        return (
            "Warning: 'admissible run' without --preview is a transitional "
            "alias handled here by 'admissible-trust finalize', which consumes "
            "a preview that has already been produced. Evaluate with "
            "'admissible-ready run --preview --preview-out FILE' first; prefer "
            "'admissible-trust finalize' directly, because this alias is "
            "removed after this release window.\n")
    return (
        f"Warning: 'admissible {command}' is a transitional alias handled here "
        f"by 'admissible-trust {command}'. The candidate-side distribution "
        f"implements no '{command}', so this verb belongs to the trusted "
        "domain; use the explicit command, because the alias is removed after "
        "this release window.\n")


#: The "What is known" line for a refusal decided before anything was loaded:
#: an unroutable command, and an owner the import system could not find at all.
#: Both are literally true there, and nowhere else.
NOTHING_RAN = "nothing was dispatched and nothing was imported"

#: The same line for an owner that is installed and raised.  Its import was
#: attempted, so its ``__init__`` may have finished, a submodule of it may
#: still be in ``sys.modules``, and whatever that code did before raising has
#: already happened -- a reader told "nothing was imported" would be looking
#: for the fault in a process they have been told never started.  What must
#: still be said, and is said here directly rather than left to follow from a
#: sentence about imports, is that the other distribution was not reached for.
OWNER_IMPORT_FAILED = (
    "the owning distribution's import was attempted and raised part-way "
    "through, so some of its code may already have run; nothing was "
    "dispatched, and no fallback to the opposite authority was attempted")


def _fail(stream: TextIO, message: str, *, next_steps: tuple[str, ...] = (),
          json_mode: bool = False, known: str = NOTHING_RAN) -> int:
    """Report an invocation this dispatcher will not route.

    ``known`` is the state of the process at the moment of the refusal, and it
    is a parameter because there is more than one such state.  A ``--json``
    caller reads it as part of ``message`` rather than as a seventh key: the
    document's shape is a contract that a change of wording does not get to
    move.
    """
    steps = tuple(next_steps) or ("fix the problem above and re-run",)
    if json_mode:
        # A --json caller must never have to parse prose off stdout, and must
        # never be handed a document by one distribution and prose by another.
        _dump(stream, {
            "scope": DECISION_SCOPE,
            "state": BLOCKED,
            "readiness": READINESS_NOT_READY,
            "exit_code": EXIT_BLOCKED,
            "message": f"{message} What is known: {known}.",
            "remediation": list(steps),
        })
        return EXIT_BLOCKED
    stream.write(f"What happened: BLOCKED. {message}\n")
    stream.write(f"What is known: {known}.\n")
    stream.write("What to do next:\n")
    for line in steps:
        stream.write(f"  - {line}\n")
    return EXIT_BLOCKED


def _dump(stdout: TextIO, document: dict[str, Any]) -> None:
    stdout.write(json.dumps(document, indent=2, sort_keys=True) + "\n")


_HELP = """usage: admissible COMMAND [options]

'admissible' is a compatibility dispatcher for developer machines. It decides
nothing: each command below is handed to the distribution that owns it,
unchanged, and that distribution's answer is what you get.

Handled by admissible-ready -- the candidate side, which runs checks and holds
no key:
  profiles                      list the shipped policy profiles
  init --profile NAME           scaffold a policy, and optionally a CI caller
  run --preview                 evaluate this exact commit; never signs
  check                         evaluate this exact commit without an attempt
  mcp                           speak MCP over stdio to a coding agent
  connect                       register a local agent connection
  ui                            serve the loopback Ready view

Handled by admissible-trust -- the signing side, which holds a key and runs no
candidate command:
  ready-status                  the authenticated Ready projection
  attest-review --review FILE   sign a review with a reviewer key
  attest-evaluation             sign an evaluation as the external observer
  policy trust|revoke|list      manage the enforceable policy baseline
  finalize --preview FILE       sign a validated preview artefact
  verify TARGET                 check standing and authenticity
  explain TARGET                explain what is known about TARGET
  status                        summarise this repository
  export --out FILE             export this repository's journal
  import --in FILE              import a journal, refusing rollback
  impeach TARGET                file a defect against TARGET
  run (without --preview)       transitional alias for finalize

Ownership is static: it is read off the command you typed and nothing else. No
credential, variable or installed key ever selects a domain, and a command in
neither table is refused rather than guessed at.

The two explicit commands are always available, and they are what a trusted
environment installs: 'admissible-ready' where candidate code runs,
'admissible-trust' where a key is held. This umbrella installs both, which is
exactly why it is a developer convenience and is forbidden in trusted
infrastructure.

Run 'admissible-ready --help' or 'admissible-trust --help' for a command's own
options, exit codes and required keys.
"""


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    """Route one legacy invocation to the distribution that owns it."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    # Read off the raw argument list, because a caller who asked for JSON is
    # owed JSON even when what went wrong is the command line itself -- and
    # because it is the flag that says "this stream is a wire format", which is
    # what suppresses the migration notice below.
    json_requested = "--json" in arguments
    if not arguments or arguments[0] in ("-h", "--help", "help"):
        # Help is metadata: it names commands and distributions and reads
        # nothing about this machine, so it is answered unconditionally.
        out.write(_HELP)
        return EXIT_OK if arguments else EXIT_BLOCKED
    command = arguments[0]
    target = resolve(arguments)
    if target is None:
        return _fail(
            out if json_requested else err,
            f"'admissible {command}' names no command this dispatcher owns, so "
            "it was not routed anywhere. Guessing a domain for an unknown verb "
            "is how a candidate's command ends up in the process that holds a "
            "key.", json_mode=json_requested, next_steps=(
                "run 'admissible --help' for the exact command list and who "
                "owns each one",
                "run 'admissible-ready --help' for the candidate-side commands",
                "run 'admissible-trust --help' for the credentialed commands",
            ))
    try:
        owner = _LOADERS[target]()
    except ImportError as error:
        distribution = target.partition(".")[0].replace("_", "-")
        if _owner_is_absent(target, error):
            # `pip install --no-deps admissible` is a real thing people do, and
            # so is an environment where one sibling was removed. Either way
            # the distribution that owns this command is not here, and saying
            # so is more useful than a traceback -- and better than reaching
            # for the other one, which is installed and is the wrong authority.
            return _fail(
                out if json_requested else err,
                f"'admissible {command}' belongs to {distribution}, which is "
                f"not importable in this environment ({error}). This "
                "dispatcher does not substitute one distribution for another.",
                json_mode=json_requested, next_steps=(
                    "reinstall 'admissible', which pins all three sibling "
                    "distributions at exactly one version",
                    f"or run the command as '{distribution} {command}' in the "
                    "environment that has that distribution",
                ))
        # The distribution is here and its code raised. That is a defect in the
        # installed release, and it is reported as one: quoting the exception
        # rather than restating it as an absence is what keeps a broken
        # `admissible_ready` from reading, in every log, as one nobody
        # installed. Nothing is retried in the other domain -- an import that
        # failed is not a reason to hand a candidate's command to the process
        # that holds a key -- and the refusal says that outright, because the
        # import it reports is one that partly ran.
        return _fail(
            out if json_requested else err,
            f"'admissible {command}' belongs to {distribution}, which is "
            f"installed in this environment but failed to import: "
            f"{type(error).__name__}: {error}. The fault is inside that "
            "distribution, not an absent one.",
            known=OWNER_IMPORT_FAILED,
            json_mode=json_requested, next_steps=(
                f"run '{distribution} {command}' directly: it raises the same "
                "import with a full traceback",
                f"treat this as a defect in the installed {distribution}, not "
                "as a missing install; reinstalling the same release "
                "reproduces it",
                "check that all three sibling distributions are at one "
                "version, which 'admissible' pins them to",
            ))
    if command in TRANSITIONAL_COMMANDS and not json_requested:
        # Human prose, on stderr, and never on the stream a machine reads.
        # MCP is not in this set at all: its stdout is a JSON-RPC session and
        # its stderr belongs to the agent that started it.
        err.write(_warning(command, target))
    return owner.main(arguments, stdout=out, stderr=err)
