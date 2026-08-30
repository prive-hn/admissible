"""Closed ``.admissible.json`` parsing, class selection, and policy identity.

The configuration document is intentionally small and closed: unknown keys,
inexact types, and shell-shaped commands are refused at the ingress boundary so
a repository can never widen the gate by accident.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from fcd.journal import canonical_json

from .fsutil import PathError, resolve_within, resolve_write_target
from .profiles import (HIGH_RISK_PROFILES, PLACEHOLDER_AUTHOR_KEY_ID,
                       PLACEHOLDER_REVIEWER_KEY_ID, UnknownProfile,
                       profile_document, profile_floor, profile_ignores)

__all__ = [
    "ArtifactClass",
    "CI_PROVIDERS",
    "CONFIG_FILENAME",
    "Check",
    "Config",
    "ConfigError",
    "POLICY_DOMAIN",
    "PLACEHOLDER_MARKER",
    "TOOL_SHA_PLACEHOLDER",
    "config_file",
    "enforcement_digest",
    "normalize_tool_sha",
    "InitWrite",
    "apply_init",
    "init_targets",
    "plan_init",
    "preflight_init",
    "init_config",
    "load_config",
    "parse_config",
    "scaffold_ci",
    "scaffold_ignores",
]

CONFIG_FILENAME = ".admissible.json"
CI_PROVIDERS = {"github": (".github/workflows/admissible.yml",
                          "consumer-workflow.yml")}
POLICY_DOMAIN = "admissible/v0.6/workflow-policy"
MAX_CONFIG_BYTES = 256 * 1024
CONFIG_VERSION = 1

_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_MAX_TIMEOUT_SECONDS = 24 * 60 * 60
_MAX_COST_UNITS = 1_000_000

_CONFIG_KEYS = {"version", "profile", "classes"}
_CONFIG_OPTIONAL = {"title", "summary", "residual_risks", "tightening"}
_CLASS_KEYS = {"id", "checks", "required_independent_reviews",
               "review_max_age_seconds", "max_cost_units", "max_wall_seconds"}
_CLASS_OPTIONAL = {"description", "residual_risks", "tightening",
                   "review_requirement", "reviewer_key_ids", "author_key_ids",
                   "collect_all_checks"}
_CHECK_KEYS = {"id", "argv", "timeout_seconds", "cost_units", "required",
               "version"}
_CHECK_OPTIONAL = {"description", "cacheable", "cache_max_age_seconds"}

# A generated placeholder is refused by name. Anything carrying this marker is
# a slot somebody was supposed to fill, and treating it as a configured value
# would turn "nobody has set this up" into "this is set up".
PLACEHOLDER_MARKER = "REPLACE-WITH-"
_MAX_CACHE_MAX_AGE = 365 * 24 * 60 * 60


class ConfigError(ValueError):
    """The configuration document is not a closed, exactly typed policy."""


def _object(value: object, where: str) -> dict:
    if type(value) is not dict:
        raise ConfigError(f"{where} must be a JSON object")
    for key in value:
        if type(key) is not str:
            raise ConfigError(f"{where} keys must be strings")
    return value


def _closed(document: dict, required: set[str], optional: set[str],
            where: str) -> None:
    present = set(document)
    unknown = present - required - optional
    if unknown:
        raise ConfigError(
            f"{where} has unknown key(s): {', '.join(sorted(unknown))}")
    missing = required - present
    if missing:
        raise ConfigError(
            f"{where} is missing key(s): {', '.join(sorted(missing))}")


def _exact_int(value: object, where: str, *, minimum: int,
               maximum: int) -> int:
    if type(value) is not int:  # bool is deliberately not an int here
        raise ConfigError(f"{where} must be a plain integer")
    if value < minimum or value > maximum:
        raise ConfigError(f"{where} must be between {minimum} and {maximum}")
    return value


def _exact_bool(value: object, where: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"{where} must be true or false")
    return value


def _exact_str(value: object, where: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise ConfigError(f"{where} must be a string")
    if not allow_empty and not value.strip():
        raise ConfigError(f"{where} must not be empty")
    return value


def _identifier(value: object, where: str) -> str:
    text = _exact_str(value, where)
    if _IDENTIFIER.fullmatch(text) is None:
        raise ConfigError(
            f"{where} must be a lowercase identifier of letters, digits, "
            "'.', '_' or '-'")
    return text


def _string_tuple(value: object, where: str) -> tuple[str, ...]:
    if type(value) is not list:
        raise ConfigError(f"{where} must be a list of strings")
    return tuple(_exact_str(item, f"{where} entry") for item in value)


@dataclass(frozen=True)
class Check:
    """One deterministic command the gate may execute."""

    id: str
    argv: tuple[str, ...]
    timeout_seconds: int
    cost_units: int
    required: bool
    version: str
    description: str = ""
    # Whether an identical earlier pass may stand in for running this again,
    # and for how long. A check whose subject is live state -- a drift check, a
    # plan against a real account -- is not reusable at all: its answer is about
    # a world that keeps moving, and an indefinite cache would let it answer
    # about a world that is gone.
    #
    # Both default to the answer that runs the check. A policy that says
    # nothing about reuse has not authorised any: the fingerprint that guards a
    # cached pass covers the environment, the executables a check names and the
    # committed lockfiles, and not the transitive packages those executables
    # import, so "reusable forever unless told otherwise" was a claim about a
    # machine nobody had bounded. Over-running costs seconds; wrong reuse costs
    # the guarantee.
    cacheable: bool = False
    cache_max_age_seconds: int = 0

    @property
    def argv_digest(self) -> str:
        """The digest of the argv this policy configures, and only that argv.

        Command evidence carries the digest of the argv that actually ran.
        Comparing the two is what stops a forged record for ``["true"]`` from
        satisfying a required ``["false"]``.
        """

        return _digest(list(self.argv))

    def core(self) -> dict:
        """The enforcement-relevant projection bound by the policy digest."""

        return {
            "id": self.id,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "cost_units": self.cost_units,
            "required": self.required,
            "version": self.version,
            "cacheable": self.cacheable,
            "cache_max_age_seconds": self.cache_max_age_seconds,
        }


@dataclass(frozen=True)
class ArtifactClass:
    """A named risk class: what must pass, who must review, what it may cost."""

    id: str
    checks: tuple[Check, ...]
    required_independent_reviews: int
    review_max_age_seconds: int
    max_cost_units: int
    max_wall_seconds: int
    description: str = ""
    residual_risks: tuple[str, ...] = ()
    tightening: tuple[str, ...] = ()
    review_requirement: str = ""
    reviewer_key_ids: tuple[str, ...] = ()
    author_key_ids: tuple[str, ...] = ()
    collect_all_checks: bool = False
    # The profile this class was parsed under. It is not part of the *policy*
    # digest -- that is the class exactly as written -- but it is part of what
    # the class enforces, because a high-risk profile imposes a floor the class
    # cannot go below and swapping the profile silently moves that floor.
    profile: str = ""

    @property
    def policy_digest(self) -> str:
        return _digest({"domain": POLICY_DOMAIN, "class": self.core()})

    def core(self) -> dict:
        return {
            "id": self.id,
            "checks": [check.core() for check in
                       sorted(self.checks, key=lambda item: item.id)],
            "required_independent_reviews": self.required_independent_reviews,
            "review_max_age_seconds": self.review_max_age_seconds,
            "max_cost_units": self.max_cost_units,
            "max_wall_seconds": self.max_wall_seconds,
            "reviewer_key_ids": sorted(self.reviewer_key_ids),
            "author_key_ids": sorted(self.author_key_ids),
            "collect_all_checks": self.collect_all_checks,
        }

    def check(self, check_id: str) -> Check | None:
        for candidate in self.checks:
            if candidate.id == check_id:
                return candidate
        return None

    @property
    def planned_cost_units(self) -> int:
        return sum(check.cost_units for check in self.checks)

    @property
    def planned_wall_seconds(self) -> int:
        return sum(check.timeout_seconds for check in self.checks)


@dataclass(frozen=True)
class Config:
    """A parsed, closed repository policy."""

    version: int
    profile: str
    classes: tuple[ArtifactClass, ...]
    title: str = ""
    summary: str = ""
    residual_risks: tuple[str, ...] = ()
    tightening: tuple[str, ...] = ()

    @property
    def policy_digest(self) -> str:
        return _digest({
            "domain": POLICY_DOMAIN,
            "version": self.version,
            "classes": [artifact_class.core() for artifact_class in
                        sorted(self.classes, key=lambda item: item.id)],
        })

    def select_class(self, class_id: object = None) -> ArtifactClass:
        if class_id is None:
            if len(self.classes) == 1:
                return self.classes[0]
            for candidate in self.classes:
                if candidate.id == "default":
                    return candidate
            raise ConfigError(
                "this policy has several classes; choose one with --class "
                f"({', '.join(sorted(item.id for item in self.classes))})")
        if type(class_id) is not str:
            raise ConfigError("class id must be a string")
        for candidate in self.classes:
            if candidate.id == class_id:
                return candidate
        raise ConfigError(
            f"unknown class {class_id!r}; this policy defines "
            f"{', '.join(sorted(item.id for item in self.classes))}")


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _parse_check(document: object) -> Check:
    document = _object(document, "check")
    _closed(document, _CHECK_KEYS, _CHECK_OPTIONAL, "check")
    argv = document["argv"]
    if type(argv) is not list or not argv:
        raise ConfigError("check argv must be a non-empty list of strings")
    words = tuple(_exact_str(word, "check argv word") for word in argv)
    cacheable = _exact_bool(document.get("cacheable", False), "check cacheable")
    max_age = _exact_int(document.get("cache_max_age_seconds", 0),
                         "check cache_max_age_seconds", minimum=0,
                         maximum=_MAX_CACHE_MAX_AGE)
    if cacheable and max_age <= 0:
        raise ConfigError(
            f"check {document['id']!r} says cacheable: true and names no "
            "cache_max_age_seconds. 'Reusable' without 'for how long' is "
            "'forever', and nothing here can support that: the fingerprint "
            "that guards a reused pass covers this machine's environment, the "
            "executables the check names and the repository's committed "
            "lockfiles -- not the packages those executables import, and not "
            "anything the repository ignores. Give it a bound, or leave "
            "cacheable out and have the check run.")
    return Check(
        id=_identifier(document["id"], "check id"),
        argv=words,
        timeout_seconds=_exact_int(document["timeout_seconds"],
                                   "check timeout_seconds", minimum=1,
                                   maximum=_MAX_TIMEOUT_SECONDS),
        cost_units=_exact_int(document["cost_units"], "check cost_units",
                              minimum=0, maximum=_MAX_COST_UNITS),
        required=_exact_bool(document["required"], "check required"),
        version=_exact_str(document["version"], "check version"),
        description=_exact_str(document.get("description", ""),
                               "check description", allow_empty=True),
        cacheable=cacheable,
        cache_max_age_seconds=max_age,
    )


def _validate_review_keys(artifact_class: ArtifactClass, *,
                          allow_placeholders: bool) -> None:
    """A class that requires review must say who may review and who authors.

    "Two independent reviews" is only a real requirement when the policy can
    tell a reviewer from an author. Counting by authenticated key id gives the
    first half; naming the author keys gives the second. Without both, a
    change's own author can sign it twice with two keys and the gate reports
    two independent reviews -- which is the promise the profile makes, broken
    exactly where it matters most.

    An empty list is refused rather than defaulted, and a generated placeholder
    is refused by name: a policy nobody has configured is BLOCKED, not lenient.
    """

    if artifact_class.required_independent_reviews <= 0:
        return
    where = f"class {artifact_class.id!r}"
    for label, values in (("reviewer_key_ids", artifact_class.reviewer_key_ids),
                          ("author_key_ids", artifact_class.author_key_ids)):
        if not values:
            raise ConfigError(
                f"{where} requires "
                f"{artifact_class.required_independent_reviews} independent "
                f"review(s) but lists no {label}. Independent review is "
                "counted by authenticated key id, and an author is excluded by "
                "key id, so both lists must name real keys before this class "
                "can decide anything.")
        placeholders = sorted(
            item for item in values if PLACEHOLDER_MARKER in item)
        if placeholders and not allow_placeholders:
            raise ConfigError(
                f"{where} still carries the generated {label} placeholder(s) "
                f"{', '.join(placeholders)}. Replace them with the real key "
                "ids; until then this class is BLOCKED and evaluates nothing.")
    overlap = sorted(set(artifact_class.reviewer_key_ids)
                     & set(artifact_class.author_key_ids))
    if overlap:
        raise ConfigError(
            f"{where} names {', '.join(overlap)} as both a reviewer key and an "
            "author key. A key that authors a change can never be an "
            "independent review of it, so the two lists must be disjoint.")


def _apply_profile_floor(parsed: "Config") -> None:
    """A high-risk profile may be tightened locally and never weakened.

    The floor exists because the policy travels in the tree the policy governs.
    A change that alters payment code can also alter the file that says what a
    payment change must satisfy, and a gate that reads only that file would let
    the change set its own bar. This is the part a candidate commit cannot move.
    """

    floor = profile_floor(parsed.profile)
    if floor is None:
        return
    minimum_reviews, required_checks = floor
    for artifact_class in parsed.classes:
        if artifact_class.required_independent_reviews < minimum_reviews:
            raise ConfigError(
                f"profile {parsed.profile!r} requires at least "
                f"{minimum_reviews} independent review(s), but class "
                f"{artifact_class.id!r} asks for "
                f"{artifact_class.required_independent_reviews}. A high-risk "
                "profile can be tightened here and never weakened; choose a "
                "different profile if this class is not that kind of change.")
        present = {check.id for check in artifact_class.checks if check.required}
        missing = sorted(required_checks - present)
        if missing:
            raise ConfigError(
                f"profile {parsed.profile!r} requires the check(s) "
                f"{', '.join(missing)}, and class {artifact_class.id!r} does "
                "not require them. A high-risk profile can gain checks here "
                "and never lose them; change the argv to the command your "
                "repository really runs, but keep the check.")


def enforcement_digest(artifact_class: ArtifactClass) -> str:
    """The digest of what a class *enforces*, ignoring how it is described.

    Two policies with the same enforcement digest ask for the same evidence,
    from the same people, under the same limits, and re-trusting one after an
    editorial change is not a new decision. Anything that can change what a
    decision comes out as is therefore inside this digest: the argv, the
    versions, whether a check is required, its timeout and cost, whether it may
    be cached and for how long, the ceilings, ``collect_all_checks``, the
    review requirement, the pinned reviewer and author keys, and the profile
    floor the class cannot go below.

    What stays outside is editorial prose only -- descriptions, residual-risk
    notes, tightening notes, the human wording of a review requirement. A
    candidate may rewrite those freely; a change to anything else is a change
    to the gate and blocks until an operator approves it.
    """

    floor = profile_floor(artifact_class.profile)
    return _digest({
        "domain": POLICY_DOMAIN,
        "enforcement": {
            "id": artifact_class.id,
            "checks": [
                {"id": check.id, "argv": list(check.argv),
                 "required": check.required, "version": check.version,
                 "cacheable": check.cacheable,
                 "timeout_seconds": check.timeout_seconds,
                 "cost_units": check.cost_units,
                 "cache_max_age_seconds": check.cache_max_age_seconds}
                for check in sorted(artifact_class.checks,
                                    key=lambda item: item.id)],
            "required_independent_reviews":
                artifact_class.required_independent_reviews,
            "review_max_age_seconds": artifact_class.review_max_age_seconds,
            "reviewer_key_ids": sorted(artifact_class.reviewer_key_ids),
            "author_key_ids": sorted(artifact_class.author_key_ids),
            "max_cost_units": artifact_class.max_cost_units,
            "max_wall_seconds": artifact_class.max_wall_seconds,
            "collect_all_checks": artifact_class.collect_all_checks,
            "profile": artifact_class.profile,
            "profile_floor": None if floor is None else {
                "minimum_independent_reviews": floor[0],
                "required_check_ids": sorted(floor[1]),
            },
        },
    })


def _parse_class(document: object) -> ArtifactClass:
    document = _object(document, "class")
    _closed(document, _CLASS_KEYS, _CLASS_OPTIONAL, "class")
    checks_document = document["checks"]
    if type(checks_document) is not list or not checks_document:
        raise ConfigError("class checks must be a non-empty list")
    checks = tuple(_parse_check(entry) for entry in checks_document)
    seen: set[str] = set()
    for check in checks:
        if check.id in seen:
            raise ConfigError(f"duplicate check id {check.id!r}")
        seen.add(check.id)
    return ArtifactClass(
        id=_identifier(document["id"], "class id"),
        checks=checks,
        required_independent_reviews=_exact_int(
            document["required_independent_reviews"],
            "class required_independent_reviews", minimum=0, maximum=16),
        review_max_age_seconds=_exact_int(
            document["review_max_age_seconds"], "class review_max_age_seconds",
            minimum=1, maximum=365 * 24 * 60 * 60),
        max_cost_units=_exact_int(document["max_cost_units"],
                                  "class max_cost_units", minimum=0,
                                  maximum=_MAX_COST_UNITS),
        max_wall_seconds=_exact_int(document["max_wall_seconds"],
                                    "class max_wall_seconds", minimum=1,
                                    maximum=_MAX_TIMEOUT_SECONDS),
        description=_exact_str(document.get("description", ""),
                               "class description", allow_empty=True),
        residual_risks=_string_tuple(document.get("residual_risks", []),
                                     "class residual_risks"),
        tightening=_string_tuple(document.get("tightening", []),
                                 "class tightening"),
        review_requirement=_exact_str(document.get("review_requirement", ""),
                                      "class review_requirement",
                                      allow_empty=True),
        reviewer_key_ids=_string_tuple(document.get("reviewer_key_ids", []),
                                       "class reviewer_key_ids"),
        author_key_ids=_string_tuple(document.get("author_key_ids", []),
                                     "class author_key_ids"),
        collect_all_checks=_exact_bool(document.get("collect_all_checks", False),
                                       "class collect_all_checks"),
    )


def parse_config(document: object, *,
                 allow_placeholders: bool = False) -> Config:
    """Parse a closed policy document into an exactly typed :class:`Config`.

    ``allow_placeholders`` exists for exactly one caller: ``init``, which has to
    check that the document it is about to write is otherwise a valid policy
    *before* an operator has filled in the key ids. Nothing that evaluates,
    signs or verifies ever passes it.
    """

    document = _object(document, "configuration")
    _closed(document, _CONFIG_KEYS, _CONFIG_OPTIONAL, "configuration")
    version = _exact_int(document["version"], "configuration version",
                         minimum=1, maximum=1)
    classes_document = document["classes"]
    if type(classes_document) is not list or not classes_document:
        raise ConfigError("configuration classes must be a non-empty list")
    classes = tuple(_parse_class(entry) for entry in classes_document)
    seen: set[str] = set()
    for artifact_class in classes:
        if artifact_class.id in seen:
            raise ConfigError(f"duplicate class id {artifact_class.id!r}")
        seen.add(artifact_class.id)
    profile = _identifier(document["profile"], "configuration profile")
    # Each class carries the profile it was parsed under, so a later question
    # about what it enforces can be answered from the class alone.
    classes = tuple(
        replace(artifact_class, profile=profile) for artifact_class in classes)
    parsed = Config(
        version=version,
        profile=profile,
        classes=classes,
        title=_exact_str(document.get("title", ""), "configuration title",
                         allow_empty=True),
        summary=_exact_str(document.get("summary", ""),
                           "configuration summary", allow_empty=True),
        residual_risks=_string_tuple(document.get("residual_risks", []),
                                     "configuration residual_risks"),
        tightening=_string_tuple(document.get("tightening", []),
                                 "configuration tightening"),
    )
    for artifact_class in parsed.classes:
        _validate_review_keys(artifact_class,
                              allow_placeholders=allow_placeholders)
    _apply_profile_floor(parsed)
    return parsed


def config_file(root: Path | str, relative: str | None = None) -> Path:
    """The exact policy file to read, resolved strictly inside ``root``.

    A caller may select a policy other than the default one, and the file it
    selects has to be the file that is read, digested and re-checked at every
    later boundary. A path that is advertised, checked for existence and then
    quietly ignored is worse than no option at all: it lets a caller believe it
    picked the strict policy while the default one decides.
    """

    selected = CONFIG_FILENAME if relative is None else relative
    try:
        return resolve_within(root, selected)
    except PathError as error:
        raise ConfigError(
            f"--config {selected!r} must name a file inside the repository "
            f"root: {error}") from None


def config_path(root: Path | str) -> Path:
    return Path(root) / CONFIG_FILENAME


@dataclass(frozen=True)
class InitWrite:
    """One file ``init`` would create, and exactly what would be in it."""

    path: Path
    relative: str
    body: str
    # For `.gitignore`, the patterns this write appends. Empty everywhere else.
    added: tuple[str, ...] = ()


def _init_target(root: Path, relative: str) -> Path:
    try:
        return resolve_write_target(root, relative)
    except PathError as error:
        raise ConfigError(
            f"cannot write {relative} in {root}: {error}") from None


def _writable_target(path: Path, relative: str) -> None:
    """Refuse now what would otherwise fail half-way through the writing."""

    if path.exists() and not path.is_file():
        raise ConfigError(
            f"{path} exists and is not a regular file, so {relative} cannot be "
            "written there. Nothing was written.")
    parent = path.parent
    walked = parent
    missing = []
    while not walked.exists():
        missing.append(walked)
        walked = walked.parent
    if not walked.is_dir():
        raise ConfigError(f"{walked} is not a directory. Nothing was written.")
    if not os.access(walked, os.W_OK):
        raise ConfigError(
            f"{walked} is not writable, so {relative} cannot be created there. "
            "Nothing was written.")


def _gitignore_body(root: Path, profile_name: str) -> tuple[str, tuple[str, ...]]:
    """The `.gitignore` this profile needs, and the lines it would add.

    Only lines that are missing are appended, nothing is ever removed, and a
    profile whose checks are the operator's own ``make`` targets contributes
    nothing -- what those write is not knowable here, and a guess presented as
    a guarantee would be worse than the honest empty answer.
    """

    wanted = profile_ignores(profile_name)
    if not wanted:
        return "", ()
    path = _init_target(root, ".gitignore")
    try:
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
    except OSError as error:
        raise ConfigError(f"cannot read {path}: {error.strerror}") from None
    present = {line.strip() for line in existing.splitlines()}
    missing = tuple(pattern for pattern in wanted if pattern not in present)
    if not missing:
        return "", ()
    block = [
        f"# Added by 'admissible init --profile {profile_name}'.",
        "# The gate refuses a dirty worktree; these are what this profile's",
        "# own checks write.",
    ]
    body = existing
    if body and not body.endswith("\n"):
        body += "\n"
    if body:
        body += "\n"
    body += "\n".join(block + list(missing)) + "\n"
    return body, missing


def _ci_body(provider: str, tool_sha: object, allow_placeholder: bool,
             template_root: Path | str | None = None) -> str:
    """The CI caller a scaffold would write, pinned to an exact tool commit.

    ``template_root`` is where the caller keeps its templates.  It is a
    parameter rather than a constant because a CI caller is *candidate-side
    scaffolding*: the workflow it writes runs the deterministic checks a
    repository configured, so the bytes belong to the distribution that has an
    execution surface, not to this kernel.  Core plans the write, checks for
    collisions and applies it atomically; it does not ship the file.

    The default is this package's own directory, which ships no templates, so
    a caller that supplies none gets the honest "missing from this
    installation" refusal rather than a workflow nobody meant to be here.
    """

    if provider not in CI_PROVIDERS:
        raise ConfigError(
            f"unknown --ci provider {provider!r}; this build knows "
            f"{', '.join(sorted(CI_PROVIDERS))}")
    pinned = normalize_tool_sha(tool_sha, allow_placeholder=allow_placeholder)
    root = (Path(__file__).resolve().parent / "templates"
            if template_root is None else Path(template_root))
    template = root / CI_PROVIDERS[provider][1]
    try:
        body = template.read_text(encoding="utf-8")
    except OSError:
        raise ConfigError(
            f"the packaged {provider} template is missing from this "
            "installation") from None
    return body.replace(TOOL_SHA_PLACEHOLDER, pinned)


def plan_init(root: Path | str, profile_name: str, *, ci: str | None = None,
              force: bool = False, tool_sha: object = None,
              allow_placeholder: bool = False,
              gitignore: bool = True,
              template_root: Path | str | None = None
              ) -> tuple[InitWrite, ...]:
    """Everything ``init`` would write, decided before anything is written.

    ``init`` is all-or-nothing or it is nothing. Checking one target at a time
    meant the policy could land, the workflow could collide, and the operator
    would be told the command failed while a file they did not ask for sat in
    their tree. Every target is resolved inside the repository -- no absolute
    path, no ``..``, no symlink anywhere along it -- every collision is found,
    and every parent is checked for writability, before a single byte moves.
    """

    try:
        document = profile_document(profile_name)
    except UnknownProfile as error:
        raise ConfigError(str(error)) from None
    # A shipped profile must always be a valid policy apart from the key ids
    # only the operator can supply.
    parse_config(document, allow_placeholders=True)
    root_path = Path(root)
    if not root_path.is_dir():
        raise ConfigError(f"{root_path} is not a directory")

    writes: list[InitWrite] = []
    writes.append(InitWrite(
        path=_init_target(root_path, CONFIG_FILENAME),
        relative=CONFIG_FILENAME,
        body=json.dumps(document, indent=2, sort_keys=False) + "\n"))
    if ci is not None:
        relative = CI_PROVIDERS[ci][0] if ci in CI_PROVIDERS else ""
        body = _ci_body(ci, tool_sha, allow_placeholder, template_root)
        writes.append(InitWrite(path=_init_target(root_path, relative),
                                relative=relative, body=body))
    collisions = [str(item.path) for item in writes if item.path.exists()]
    if collisions and not force:
        raise ConfigError(
            f"{', '.join(collisions)} already exist(s); re-run with --force to "
            "replace them. Nothing was written.")
    if gitignore:
        body, added = _gitignore_body(root_path, profile_name)
        if added:
            writes.append(InitWrite(
                path=_init_target(root_path, ".gitignore"),
                relative=".gitignore", body=body, added=added))
    for item in writes:
        _writable_target(item.path, item.relative)
    return tuple(writes)


def _atomic_write(path: Path, body: bytes) -> None:
    """Create ``path`` and replace it in one step, or leave it as it was."""

    scratch = path.parent / f".{path.name}.{secrets.token_hex(8)}"
    descriptor = os.open(str(scratch), os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o644)
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


def _undo(originals: list[tuple[Path, bytes | None]],
          created: list[Path]) -> tuple[str, ...]:
    """Put the tree back, and report every place that could not be.

    The return value is the point. An undo that cannot finish is exactly the
    situation a caller must not be told "nothing was written" about, and the
    old shape swallowed each failure and then said so anyway.
    """

    unrestored: list[str] = []
    for path, before in reversed(originals):
        try:
            if before is None:
                if path.exists():
                    path.unlink()
            else:
                _atomic_write(path, before)
        except OSError as error:
            unrestored.append(f"{path} ({error.strerror or error})")
    for directory in reversed(created):
        try:
            directory.rmdir()
        except OSError:
            # A directory this command created and could not remove is empty
            # scaffolding, not lost content: it is not reported as unrestored.
            pass
    return tuple(unrestored)


def apply_init(writes: tuple[InitWrite, ...]) -> tuple[Path, ...]:
    """Perform a plan, or undo whatever part of it landed.

    Preflight makes a partial write unlikely; it cannot make it impossible --
    a disk fills, a permission changes between the check and the write. So the
    prior content of every target is kept until the last one succeeds, and any
    failure puts the tree back exactly as it was found.

    "Any failure" means any: an interrupt between two writes leaves the same
    half-applied tree a full disk does, and catching only OSError and
    ValueError meant Ctrl-C was the one way to get one. And when the undo
    itself cannot finish, that is said rather than swallowed -- a message
    promising a restored tree over a tree that is not restored is worse than
    the partial write, because it stops anybody looking.
    """

    originals: list[tuple[Path, bytes | None]] = []
    created: list[Path] = []
    try:
        for item in writes:
            parent = item.path.parent
            missing = []
            walked = parent
            while not walked.exists():
                missing.append(walked)
                walked = walked.parent
            for directory in reversed(missing):
                directory.mkdir()
                created.append(directory)
            originals.append(
                (item.path,
                 item.path.read_bytes() if item.path.exists() else None))
            _atomic_write(item.path, item.body.encode("utf-8"))
    except BaseException as error:
        unrestored = _undo(originals, created)
        if unrestored:
            raise ConfigError(
                f"{type(error).__name__} interrupted 'init', and putting the "
                "tree back did not finish. These paths are NOT as this "
                "command found them: " + "; ".join(unrestored)
                + ". Restore them from version control before running "
                "anything else here; do not assume this command left the "
                "repository alone.") from error
        if isinstance(error, (OSError, ValueError)):
            detail = getattr(error, "strerror", None) or str(error)
            raise ConfigError(
                f"cannot write {getattr(error, 'filename', '')}: {detail}. "
                "Nothing was written: every file this command had already "
                "created was put back as it was found.") from None
        # An interrupt stays an interrupt. The tree is verified clean above,
        # so there is nothing this layer needs to add to it.
        raise
    return tuple(item.path for item in writes)


def init_targets(root: Path | str, profile_name: str, *, ci: str | None = None,
                 tool_sha: object = None, allow_placeholder: bool = False,
                 gitignore: bool = True) -> tuple[str, ...]:
    """The exact files ``init`` would touch, for a caller that wants to look."""

    return tuple(str(item.path) for item in plan_init(
        root, profile_name, ci=ci, force=True, tool_sha=tool_sha,
        allow_placeholder=allow_placeholder, gitignore=gitignore))


def init_config(root: Path | str, profile_name: str, *,
                force: bool = False) -> Path:
    """Write ``.admissible.json`` for ``profile_name`` without clobbering."""

    writes = plan_init(root, profile_name, force=force, gitignore=False)
    return apply_init(writes)[0]


def scaffold_ignores(root: Path | str, profile_name: str) -> tuple[str, ...]:
    """Make sure this profile's own check output cannot dirty the worktree.

    An exact-SHA run refuses a worktree with uncommitted or untracked changes,
    because evidence gathered against a modified tree describes no commit. That
    rule collides with the profiles whose checks legitimately write build
    output: byte-compiling a package leaves ``__pycache__``, building an sdist
    leaves ``dist/``, and the very first run would then block on artefacts the
    policy itself asked for.

    Returns the patterns that were actually added.
    """

    root_path = Path(root)
    body, added = _gitignore_body(root_path, profile_name)
    if not added:
        return ()
    write = InitWrite(path=_init_target(root_path, ".gitignore"),
                      relative=".gitignore", body=body, added=added)
    _writable_target(write.path, write.relative)
    apply_init((write,))
    return added


_FULL_SHA = re.compile(r"[0-9a-f]{40}")
TOOL_SHA_PLACEHOLDER = "REPLACE-WITH-FULL-40-HEX-ADMISSIBLE-COMMIT-SHA"


def normalize_tool_sha(value: object, *,
                      allow_placeholder: bool = False) -> str:
    """The exact Admissible commit a generated caller pins, or a refusal.

    Pinning the reusable workflow by commit is only worth something if the
    *program* is pinned too, and the program is named by a separate input. A
    partial or abbreviated sha is refused rather than resolved: this value has
    to be comparable, byte for byte, against the commit the workflow is running
    from, and nothing here can resolve an abbreviation anyway.

    With no sha at all, the answer is a refusal by default. A caller written
    with a guess would run, and would run whatever the tool repository happens
    to hold that day. ``allow_placeholder`` is the deliberate second option:
    the caller is written with a placeholder in both places, which is a
    workflow that cannot start until somebody chooses a commit.
    """

    if value is None:
        if allow_placeholder:
            return TOOL_SHA_PLACEHOLDER
        raise ConfigError(
            "--ci needs --tool-sha FULL_SHA: the exact Admissible commit this "
            "caller pins. The workflow reference and the tool-sha input must "
            "name the same commit, and the gate refuses at run time if they "
            "do not, so there is nothing sensible to default to. Pass "
            "--ci-placeholder instead to scaffold a caller that is explicitly "
            "unrunnable until you choose one.")
    if type(value) is not str or _FULL_SHA.fullmatch(value) is None:
        raise ConfigError(
            f"--tool-sha must be a full 40-character lowercase commit SHA, "
            f"got {value!r}. A tag or a short sha cannot be checked against "
            "the commit the workflow actually runs, so it would pin nothing.")
    return value


def scaffold_ci(root: Path | str, provider: str, *, force: bool = False,
                tool_sha: object = None,
                allow_placeholder: bool = False) -> Path:
    """Write the CI workflow that *calls* the pinned Admissible reusable gate.

    The scaffold is deliberately a caller, not a copy: the trust boundary lives
    in the reusable workflow the consumer pins by commit, so a consumer never
    has to vendor -- or keep up with -- the finalizer's internals.

    The same commit is written twice, into the ``uses:`` reference and into the
    ``tool-sha`` input, because the gate refuses at run time unless they agree.
    With ``allow_placeholder`` and no sha, the caller is generated with a
    placeholder in both places: a workflow that cannot run, which is the honest
    shape for a pin nobody has chosen yet.
    """

    if provider not in CI_PROVIDERS:
        raise ConfigError(
            f"unknown --ci provider {provider!r}; this build knows "
            f"{', '.join(sorted(CI_PROVIDERS))}")
    relative = CI_PROVIDERS[provider][0]
    root_path = Path(root)
    path = _init_target(root_path, relative)
    if path.exists() and not force:
        raise ConfigError(
            f"{path} already exists; re-run with --force to replace it")
    write = InitWrite(
        path=path, relative=relative,
        body=_ci_body(provider, tool_sha, allow_placeholder))
    _writable_target(path, relative)
    return apply_init((write,))[0]


def preflight_init(root: Path | str, profile_name: str, *,
                   ci: str | None = None, force: bool = False,
                   tool_sha: object = None,
                   allow_placeholder: bool = False,
                   gitignore: bool = True,
                   template_root: Path | str | None = None
                   ) -> tuple[InitWrite, ...]:
    """Refuse before writing anything, not after writing half of it."""

    return plan_init(root, profile_name, ci=ci, force=force,
                     tool_sha=tool_sha, allow_placeholder=allow_placeholder,
                     gitignore=gitignore, template_root=template_root)


def load_config(root: Path | str, relative: str | None = None) -> Config:
    """Read and parse the repository policy at ``root``."""

    path = config_file(root, relative)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise ConfigError(
            f"no {path.name} in {Path(root)}; run 'admissible init "
            "--profile NAME' to create one") from None
    except OSError as error:
        raise ConfigError(f"cannot read {path}: {error.strerror}") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(
            f"{path.name} is larger than {MAX_CONFIG_BYTES} bytes")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConfigError(f"{path} is not valid JSON: {error}") from None
    return parse_config(document)
