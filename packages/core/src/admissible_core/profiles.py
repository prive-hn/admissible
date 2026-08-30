"""The eight built-in conservative starter profiles.

The catalog is deliberately organised by *risk of change*, not by programming
language: a payment change and a documentation change need different evidence
even in the same repository. Every profile states what it actually verifies,
what it explicitly does not, and how to tighten it.

Command-shaped checks are argv only. Profiles that cannot assume a language
toolchain drive ``make`` targets so the repository owns the command body; the
gate owns the identity, ceilings, and review requirements.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

__all__ = [
    "HIGH_RISK_PROFILES",
    "PLACEHOLDER_AUTHOR_KEY_ID",
    "PLACEHOLDER_REVIEWER_KEY_ID",
    "PROFILE_NAMES",
    "Profile",
    "UnknownProfile",
    "get_profile",
    "profile_document",
    "profile_floor",
    "profile_ignores",
    "profile_summaries",
]

# A generated policy for a high-risk change ships these rather than an empty
# list. An empty list reads as "nothing required here" and parses cleanly; a
# named placeholder cannot be mistaken for a decision, and validation refuses it
# by name until somebody replaces it with a real key id.
PLACEHOLDER_REVIEWER_KEY_ID = "REPLACE-WITH-REVIEWER-KEY-ID"
PLACEHOLDER_AUTHOR_KEY_ID = "REPLACE-WITH-AUTHOR-KEY-ID"


# How long a cached pass may stand in for a fresh observation. A check whose
# whole subject is the committed tree could in principle be reused forever, but
# the machine it ran on is part of what it observed, and a day is long enough to
# make an identical re-run cheap without letting last month's toolchain answer
# for this one.
_DEFAULT_CACHE_MAX_AGE = 24 * 60 * 60


class UnknownProfile(ValueError):
    """The requested profile is not part of the built-in catalog."""


@dataclass(frozen=True)
class Profile:
    """A named starter policy with its plain-language description."""

    name: str
    title: str
    summary: str
    review_requirement: str
    document: dict
    # Paths this profile's own checks are known to write. The gate refuses a
    # dirty worktree, so a profile whose checks leave build output behind would
    # block on evidence it asked for. `admissible init` adds these to
    # .gitignore. It is deliberately empty for the profiles whose checks are
    # the operator's own `make` targets: nothing here can know what those write,
    # and guessing would be worse than saying so.
    ignores: tuple[str, ...] = ()


def _check(check_id: str, argv: list[str], *, timeout: int, cost: int,
           required: bool, description: str, cacheable: bool = True,
           cache_max_age_seconds: int = _DEFAULT_CACHE_MAX_AGE) -> dict:
    document = {
        "id": check_id,
        "argv": argv,
        "timeout_seconds": timeout,
        "cost_units": cost,
        "required": required,
        "version": "1",
        "description": description,
    }
    # Always written, never left to a default. A reader of a policy file has
    # to be able to see whether a check may be reused without knowing what this
    # program would have assumed, and the assumption is deliberately the
    # cautious one -- so a profile that means "reusable" has to say so.
    document["cacheable"] = bool(cacheable)
    if cacheable:
        document["cache_max_age_seconds"] = cache_max_age_seconds
    return document


def _document(name: str, title: str, summary: str, checks: list[dict], *,
              reviews: int, review_requirement: str, review_max_age: int,
              max_cost: int, max_wall: int, residual_risks: list[str],
              tightening: list[str], class_description: str) -> dict:
    if reviews:
        tightening = list(tightening) + [
            "Replace the reviewer_key_ids placeholder with the reviewer key "
            "ids allowed to approve this class, and have each reviewer sign "
            "with 'admissible attest-review'.",
            "Replace the author_key_ids placeholder with the key ids that "
            "author changes to this class. A key in that list can never count "
            "as an independent review of its own change. Until both are "
            "replaced, this class is BLOCKED and evaluates nothing.",
        ]
    artifact_class = {
        "id": "default",
        "description": class_description,
        "checks": checks,
        "required_independent_reviews": reviews,
        "review_requirement": review_requirement,
        "review_max_age_seconds": review_max_age,
        "max_cost_units": max_cost,
        "max_wall_seconds": max_wall,
        "residual_risks": list(residual_risks),
        "tightening": list(tightening),
    }
    if reviews:
        # A required review is an authority claim, so it is counted by the
        # reviewer key that signed it, and it only means "independent" if the
        # policy also names who the authors are. Both lists ship as explicit
        # placeholders: the class is BLOCKED until an operator replaces them,
        # which is the honest state for a policy nobody has configured yet.
        artifact_class["reviewer_key_ids"] = [PLACEHOLDER_REVIEWER_KEY_ID]
        artifact_class["author_key_ids"] = [PLACEHOLDER_AUTHOR_KEY_ID]
    return {
        "version": 1,
        "profile": name,
        "title": title,
        "summary": summary,
        "residual_risks": list(residual_risks),
        "tightening": list(tightening),
        "classes": [artifact_class],
    }


_PYTHON_LIBRARY = _document(
    "python-library",
    "Python library",
    "Importable Python package changes verified by tests, byte-compilation "
    "and a packaging check.",
    [
        _check("compile", ["python3", "-m", "compileall", "-q", "."],
               timeout=300, cost=1, required=True,
               description="Every module byte-compiles on this interpreter."),
        _check("unit", ["python3", "-m", "pytest", "-q"],
               timeout=1800, cost=4, required=True,
               description="The project's own test suite passes."),
        _check("packaging", ["python3", "-m", "build", "--sdist", "--wheel",
                             "--outdir", "dist"],
               timeout=900, cost=3, required=True,
               description="An sdist and wheel still build. Required: this "
                           "profile's summary promises a packaging check, and "
                           "an optional check cannot keep that promise."),
    ],
    reviews=0,
    review_requirement="No independent review required; deterministic checks "
                       "carry this class.",
    review_max_age=7 * 24 * 60 * 60,
    max_cost=12,
    max_wall=3600,
    residual_risks=[
        "Runtime behaviour on Python versions the suite does not exercise.",
        "Dependency resolution and transitive supply-chain risk.",
        "Performance, memory, and concurrency regressions.",
        "Public API compatibility for downstream consumers.",
    ],
    tightening=[
        "Add a matrix check per supported interpreter version.",
        "Add an API-compatibility check against the last released version.",
        "Raise required_independent_reviews to 1 before a major release.",
    ],
    class_description="Library source and tests.",
)

_TYPESCRIPT_APPLICATION = _document(
    "typescript-application",
    "TypeScript application",
    "Application changes verified by type checking, unit tests and a "
    "production build.",
    [
        _check("typecheck", ["npm", "run", "--silent", "typecheck"],
               timeout=900, cost=2, required=True,
               description="tsc reports no type errors."),
        _check("unit", ["npm", "test", "--silent", "--", "--run"],
               timeout=1800, cost=4, required=True,
               description="The application test suite passes."),
        _check("build", ["npm", "run", "--silent", "build"],
               timeout=1800, cost=3, required=True,
               description="The production bundle builds."),
        _check("audit", ["npm", "audit", "--audit-level=high"],
               timeout=600, cost=1, required=False,
               description="No known high-severity advisories (optional)."),
    ],
    reviews=0,
    review_requirement="No independent review required; add one for changes "
                       "that touch authentication or payment surfaces.",
    review_max_age=7 * 24 * 60 * 60,
    max_cost=14,
    max_wall=5400,
    residual_risks=[
        "Runtime behaviour in browsers or Node versions not exercised here.",
        "Visual regressions and accessibility defects.",
        "Bundle size and load-time regressions.",
        "Server-side behaviour behind the application boundary.",
    ],
    tightening=[
        "Add an end-to-end check against a running build.",
        "Add a bundle-size budget check with a hard ceiling.",
        "Make the audit check required once the advisory backlog is clear.",
    ],
    class_description="Application source, tests, and build configuration.",
)

_REST_API = _document(
    "rest-api",
    "REST API service",
    "Service changes verified by tests plus an explicit contract and schema "
    "check, with one independent review.",
    [
        _check("unit", ["make", "test"],
               timeout=1800, cost=4, required=True,
               description="Service unit and integration tests pass."),
        _check("contract", ["make", "contract-test"],
               timeout=1200, cost=3, required=True,
               description="Published request/response contracts still hold."),
        _check("schema-lint", ["make", "openapi-lint"],
               timeout=600, cost=1, required=True,
               description="The API description document is valid and "
                           "backward compatible."),
    ],
    reviews=1,
    review_requirement="One independent review, signed by a reviewer key you "
                       "list in reviewer_key_ids. Until that list is filled "
                       "in, this class refuses: an unsigned approval is a "
                       "claim by whoever wrote the file.",
    review_max_age=3 * 24 * 60 * 60,
    max_cost=12,
    max_wall=4200,
    residual_risks=[
        "Client behaviour of consumers that are not covered by contract tests.",
        "Load, latency, and rate-limit behaviour under production traffic.",
        "Authorisation rules that the contract tests do not assert.",
        "Data migrations shipped alongside the interface change.",
    ],
    tightening=[
        "Register consumer repositories as dependencies so impeachment can "
        "name them.",
        "Add a replay check against recorded production request shapes.",
        "Raise required_independent_reviews to 2 for breaking changes.",
    ],
    class_description="Service handlers, contracts, and API descriptions.",
)

_DATABASE_MIGRATION = _document(
    "database-migration",
    "Database migration",
    "Schema changes verified by a dry run, a proven rollback, and the service "
    "test suite, with one independent review.",
    [
        _check("migrate-dry-run", ["make", "migrate-dry-run"],
               timeout=1800, cost=4, required=True,
               description="The migration applies cleanly to a scratch copy."),
        _check("migrate-rollback", ["make", "migrate-rollback-test"],
               timeout=1800, cost=4, required=True,
               description="The down migration restores the previous schema."),
        _check("unit", ["make", "test"],
               timeout=1800, cost=4, required=True,
               description="Application tests pass against the new schema."),
    ],
    reviews=1,
    review_requirement="One independent review, signed by a reviewer key you "
                       "list in reviewer_key_ids; a database owner is strongly "
                       "advised.",
    review_max_age=2 * 24 * 60 * 60,
    max_cost=16,
    max_wall=5400,
    residual_risks=[
        "Lock duration and table-rewrite cost at production data volume.",
        "Replica lag and failover behaviour during the migration window.",
        "Backfill correctness for rows written during deployment.",
        "Irreversible data loss that a rollback cannot undo.",
    ],
    tightening=[
        "Add a check that runs the migration against a production-sized "
        "restored snapshot.",
        "Add an explicit lock-time ceiling check.",
        "Require a second independent review for destructive statements.",
    ],
    class_description="Migration files and the code that depends on them.",
)

_AUTHENTICATION_CHANGE = _document(
    "authentication-change",
    "Authentication or authorisation change",
    "Identity and access changes verified by dedicated auth tests and a "
    "secret scan, with one independent review.",
    [
        _check("unit", ["make", "test"],
               timeout=1800, cost=4, required=True,
               description="The full test suite passes."),
        _check("auth-tests", ["make", "test-auth"],
               timeout=1200, cost=4, required=True,
               description="Authentication and authorisation cases pass, "
                           "including negative cases."),
        _check("secret-scan", ["make", "secret-scan"],
               timeout=600, cost=2, required=True,
               description="No credential material is committed."),
    ],
    reviews=1,
    review_requirement="One independent review, signed by a reviewer key you "
                       "list in reviewer_key_ids; a security owner is strongly "
                       "advised.",
    review_max_age=2 * 24 * 60 * 60,
    max_cost=14,
    max_wall=4200,
    residual_risks=[
        "Session, token lifetime, and revocation behaviour in production.",
        "Privilege escalation paths that the negative tests do not model.",
        "Identity-provider configuration that lives outside this repository.",
        "Logging or telemetry that may now carry identity material.",
    ],
    tightening=[
        "Add an explicit deny-by-default authorisation matrix check.",
        "Raise required_independent_reviews to 2 for privilege boundaries.",
        "Register dependent services so impeachment reaches them.",
    ],
    class_description="Authentication, authorisation, and session code.",
)

_PAYMENT_CHANGE = _document(
    "payment-change",
    "Payment or money-movement change",
    "Money-touching changes verified by payment and ledger invariant tests, "
    "with two independent reviews.",
    [
        _check("unit", ["make", "test"],
               timeout=1800, cost=4, required=True,
               description="The full test suite passes."),
        _check("payment-tests", ["make", "test-payments"],
               timeout=1800, cost=5, required=True,
               description="Payment flows pass, including failure and "
                           "retry paths."),
        _check("ledger-invariants", ["make", "test-ledger"],
               timeout=1200, cost=4, required=True,
               description="Balances, rounding, and idempotency invariants "
                           "hold."),
    ],
    reviews=2,
    review_requirement="Two independent reviews, signed by two distinct "
                       "reviewer keys you list in reviewer_key_ids, by people "
                       "other than the change author.",
    review_max_age=2 * 24 * 60 * 60,
    max_cost=18,
    max_wall=5400,
    residual_risks=[
        "Provider-side behaviour, fees, and settlement timing.",
        "Currency, rounding, and tax rules not covered by the invariants.",
        "Reconciliation against external statements.",
        "Partial-failure states created by real network timeouts.",
    ],
    tightening=[
        "Add a sandbox end-to-end payment check against the provider.",
        "Add a reconciliation check over recorded ledger fixtures.",
        "Shorten review_max_age_seconds so approvals cannot go stale.",
    ],
    class_description="Payment, billing, and ledger code.",
)

_INFRASTRUCTURE_CHANGE = _document(
    "infrastructure-change",
    "Infrastructure change",
    "Infrastructure-as-code changes verified by a plan, a policy check and a "
    "drift check, with one independent review.",
    [
        _check("plan", ["make", "infra-plan"],
               timeout=1800, cost=4, required=True, cacheable=False,
               description="A plan is produced without errors. Never cached: a "
                           "plan is a statement about live state, not about "
                           "the committed tree alone."),
        _check("policy", ["make", "infra-policy"],
               timeout=900, cost=3, required=True, cacheable=False,
               description="The plan satisfies organisational policy rules. "
                           "Never cached: it judges the plan above."),
        _check("drift", ["make", "infra-drift"],
               timeout=900, cost=3, required=True, cacheable=False,
               description="Live state matches the committed configuration "
                           "before the change. Never cached: its subject is "
                           "the account as it is right now, and a reused pass "
                           "would answer about a world that has moved on."),
    ],
    reviews=1,
    review_requirement="One independent review, signed by a reviewer key you "
                       "list in reviewer_key_ids; an infrastructure owner is "
                       "strongly advised.",
    review_max_age=2 * 24 * 60 * 60,
    max_cost=14,
    max_wall=4200,
    residual_risks=[
        "Blast radius of apply-time failures and partially applied changes.",
        "Cost impact of the planned resources.",
        "Secrets, IAM, and network reachability changes in the live account.",
        "State-file locking and concurrent operators.",
    ],
    tightening=[
        "Add a cost-estimate check with an explicit ceiling.",
        "Add an IAM-diff check that refuses privilege widening.",
        "Require two independent reviews for production accounts.",
    ],
    class_description="Infrastructure definitions and their policy rules.",
)

_DOCUMENTATION_ONLY = _document(
    "documentation-only",
    "Documentation only",
    "Prose-only changes verified by a link check and a documentation build. "
    "No language model review is required or expected.",
    [
        _check("docs-build", ["make", "docs-build"],
               timeout=600, cost=1, required=True,
               description="The documentation set builds."),
        _check("docs-links", ["make", "docs-links"],
               timeout=600, cost=1, required=True,
               description="Internal links and anchors resolve."),
        _check("no-code-change", ["make", "docs-only-diff"],
               timeout=300, cost=1, required=True,
               description="The change really is documentation only."),
    ],
    reviews=0,
    review_requirement="Zero independent reviews and zero language-model "
                       "review: this class must never require an LLM call.",
    review_max_age=7 * 24 * 60 * 60,
    max_cost=6,
    max_wall=1800,
    residual_risks=[
        "Factual accuracy of the prose itself.",
        "Documentation that describes behaviour the code does not have.",
        "Translated or generated copies that are not rebuilt here.",
    ],
    tightening=[
        "Add an external link check on a schedule rather than per change.",
        "Add a doc-to-code example check that executes the samples.",
        "Move the change to a code profile as soon as any source file "
        "changes.",
    ],
    class_description="Documentation sources only.",
)

_PROFILES: tuple[Profile, ...] = (
    Profile("python-library", "Python library",
            _PYTHON_LIBRARY["summary"],
            _PYTHON_LIBRARY["classes"][0]["review_requirement"],
            _PYTHON_LIBRARY,
            # compileall writes __pycache__, pytest writes .pytest_cache, and
            # `python -m build` writes dist/, build/ and *.egg-info.
            ("__pycache__/", "*.py[cod]", ".pytest_cache/", "dist/", "build/",
             "*.egg-info/")),
    Profile("typescript-application", "TypeScript application",
            _TYPESCRIPT_APPLICATION["summary"],
            _TYPESCRIPT_APPLICATION["classes"][0]["review_requirement"],
            _TYPESCRIPT_APPLICATION,
            ("node_modules/", "dist/", "build/", ".vite/", "*.tsbuildinfo")),
    Profile("rest-api", "REST API service",
            _REST_API["summary"],
            _REST_API["classes"][0]["review_requirement"], _REST_API),
    Profile("database-migration", "Database migration",
            _DATABASE_MIGRATION["summary"],
            _DATABASE_MIGRATION["classes"][0]["review_requirement"],
            _DATABASE_MIGRATION),
    Profile("authentication-change", "Authentication or authorisation change",
            _AUTHENTICATION_CHANGE["summary"],
            _AUTHENTICATION_CHANGE["classes"][0]["review_requirement"],
            _AUTHENTICATION_CHANGE),
    Profile("payment-change", "Payment or money-movement change",
            _PAYMENT_CHANGE["summary"],
            _PAYMENT_CHANGE["classes"][0]["review_requirement"],
            _PAYMENT_CHANGE),
    Profile("infrastructure-change", "Infrastructure change",
            _INFRASTRUCTURE_CHANGE["summary"],
            _INFRASTRUCTURE_CHANGE["classes"][0]["review_requirement"],
            _INFRASTRUCTURE_CHANGE),
    Profile("documentation-only", "Documentation only",
            _DOCUMENTATION_ONLY["summary"],
            _DOCUMENTATION_ONLY["classes"][0]["review_requirement"],
            _DOCUMENTATION_ONLY),
)

PROFILE_NAMES: tuple[str, ...] = tuple(profile.name for profile in _PROFILES)

_BY_NAME = {profile.name: profile for profile in _PROFILES}


def get_profile(name: object) -> Profile:
    """Return the named built-in profile."""

    if type(name) is not str or name not in _BY_NAME:
        raise UnknownProfile(
            f"unknown profile {name!r}; built-in profiles are "
            f"{', '.join(PROFILE_NAMES)}")
    return _BY_NAME[name]


# The classes of change where a weakened policy is not a local matter. For
# these, a repository may tighten what the built-in profile asks for and may
# never go below it.
HIGH_RISK_PROFILES: tuple[str, ...] = (
    "rest-api", "database-migration", "authentication-change",
    "payment-change", "infrastructure-change",
)


def profile_floor(name: object) -> tuple[int, frozenset[str]] | None:
    """The minimum a high-risk profile's policy may ever require.

    Derived from the shipped profile itself rather than restated, so the floor
    cannot drift away from the catalog it is supposed to be the floor of.
    """

    if type(name) is not str or name not in HIGH_RISK_PROFILES:
        return None
    artifact_class = get_profile(name).document["classes"][0]
    return (artifact_class["required_independent_reviews"],
            frozenset(check["id"] for check in artifact_class["checks"]
                      if check["required"]))


def profile_ignores(name: object) -> tuple[str, ...]:
    """Paths this profile's own checks are known to write.

    Empty is a real answer, not a gap: a profile whose checks are the
    operator's own ``make`` targets writes whatever those targets write, and
    inventing a list would be a guess dressed as a guarantee.
    """

    return get_profile(name).ignores


def profile_document(name: object) -> dict[str, Any]:
    """A detached plain-JSON copy of the profile's policy document."""

    return copy.deepcopy(get_profile(name).document)


def profile_summaries() -> tuple[dict[str, Any], ...]:
    """Plain rows for ``admissible profiles``."""

    rows = []
    for profile in _PROFILES:
        artifact_class = profile.document["classes"][0]
        rows.append({
            "name": profile.name,
            "title": profile.title,
            "summary": profile.summary,
            "required_independent_reviews":
                artifact_class["required_independent_reviews"],
            "review_requirement": profile.review_requirement,
            "checks": [check["id"] for check in artifact_class["checks"]],
            "max_cost_units": artifact_class["max_cost_units"],
            "max_wall_seconds": artifact_class["max_wall_seconds"],
            "residual_risks": list(profile.document["residual_risks"]),
            "tightening": list(profile.document["tightening"]),
        })
    return tuple(rows)
