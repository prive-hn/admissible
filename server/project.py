"""Verified project, model, agent and gate definitions for the cockpit."""
from __future__ import annotations

import os
import subprocess
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ModelDefinition:
    id: str
    revision: int
    provider: str
    api_id: str
    display: str
    context_profile: str
    reasoning: str


@dataclass(frozen=True)
class AgentDefinition:
    id: str
    revision: int
    name: str
    instructions: str
    default_model_id: str
    tools: tuple[str, ...]
    authority: tuple[str, ...]


@dataclass(frozen=True)
class GateDefinition:
    """One required step, and what it is for.

    `kind` is declared, not inferred. Only a check gate excludes the authors of
    the line (A6, I6), so deriving it from list position made dual control an
    accident of ordering.
    """
    id: str
    revision: int
    name: str
    agent_id: str
    executor_id: str
    model_id: str
    context_mode: str
    continuity: str = "fresh"
    kind: str = "write"


@dataclass(frozen=True)
class ClassDefinition:
    """A kind of work, and the promise the machine makes about it.

    `Required(c)` is a function of the class (A4), so the class is where
    "which specialists must touch this" is decided. A class with one write gate
    promises provenance; a class with a check gate promises dual control on top
    of it. Both are honest — they are different promises, not different
    strengths of the same one.
    """
    id: str
    name: str
    summary: str
    gate_ids: tuple[str, ...]
    #  Words that make this class the obvious reading of a prompt. Intake
    #  proposes; it never decides (the class is write-once at Open, I4).
    hints: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProjectDefinition:
    id: str
    name: str
    revision: int
    local_path: str
    github: str
    base_branch: str
    project_version: int
    memory_version: int
    policy_version: str
    strict_unknown: bool
    skin: str
    models: tuple[ModelDefinition, ...]
    agents: tuple[AgentDefinition, ...]
    gates: tuple[GateDefinition, ...]
    classes: tuple[ClassDefinition, ...] = ()


@dataclass
class LoadedProject:
    definition: ProjectDefinition
    verified: bool
    head: str
    remote: str
    current_branch: str
    runtime_data: dict[str, Any] = field(default_factory=dict)

    def model(self, model_id: str) -> ModelDefinition:
        return next(m for m in self.definition.models if m.id == model_id)

    def agent(self, agent_id: str) -> AgentDefinition:
        return next(a for a in self.definition.agents if a.id == agent_id)

    def gate(self, gate_id: str) -> GateDefinition:
        return next(g for g in self.definition.gates if g.id == gate_id)

    def klass(self, class_id: str) -> ClassDefinition:
        return next(c for c in self.definition.classes if c.id == class_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self.definition), "verified": self.verified,
            "head": self.head, "remote": self.remote,
            "current_branch": self.current_branch,
        }


def _git(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True)
    if p.returncode != 0:
        raise ValueError(p.stderr.strip() or f"git {' '.join(args)} failed")
    return p.stdout.strip()


def _normalize_remote(value: str) -> str:
    v = value.strip().removesuffix(".git")
    if v.startswith("git@github.com:"):
        return v.split(":", 1)[1]
    marker = "github.com/"
    if marker in v:
        return v.split(marker, 1)[1]
    return v


# Where repositories conventionally live. An operator should not have to
# remember a path to open work, and the browser cannot read a filesystem, so
# discovery happens here.
CONVENTIONAL_ROOTS = ("repos", "src", "code", "Projects", "dev", "git", "work", "Developer")
MAX_DEPTH = 3
MAX_CANDIDATES = 200


def default_roots() -> tuple[Path, ...]:
    """Roots to search, in order.

    `FCD_PROJECT_ROOTS` (colon-separated) wins outright so an operator whose
    repositories live somewhere unconventional can say so once. Otherwise the
    conventional folders under home that actually exist.
    """
    env = os.environ.get("FCD_PROJECT_ROOTS", "").strip()
    if env:
        return tuple(
            p for raw in env.split(os.pathsep)
            if (p := Path(raw).expanduser()).is_dir()
        )
    home = Path.home()
    return tuple(p for name in CONVENTIONAL_ROOTS if (p := home / name).is_dir())


@dataclass(frozen=True)
class ProjectCandidate:
    """A git repository found on disk, with what the loader needs prefilled."""
    local_path: str
    name: str
    github: str
    base_branch: str
    current_branch: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _quiet_git(repo: Path, *args: str) -> str:
    """Git for discovery: a repository that cannot answer is skipped, not fatal."""
    try:
        p = subprocess.run(["git", *args], cwd=repo, text=True,
                           capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return ""
    return p.stdout.strip() if p.returncode == 0 else ""


def _walk_repositories(root: Path, depth: int = 0) -> list[Path]:
    """Directories containing .git, bounded so a deep tree cannot stall a scan."""
    if depth > MAX_DEPTH:
        return []
    found: list[Path] = []
    try:
        entries = sorted(p for p in root.iterdir() if p.is_dir())
    except (PermissionError, OSError):
        return []
    for entry in entries:
        if entry.name.startswith(".") or entry.name in {"node_modules", "venv", "__pycache__"}:
            continue
        if (entry / ".git").exists():
            found.append(entry)
            continue  # a repository is a leaf; its subdirectories are its own
        found.extend(_walk_repositories(entry, depth + 1))
        if len(found) >= MAX_CANDIDATES:
            break
    return found


def discover_projects(query: str = "", roots: tuple[Path, ...] | None = None,
                      limit: int = 25) -> tuple[ProjectCandidate, ...]:
    """Repositories matching `query`, with origin and base branch already read.

    Reading the remote here is what removes the "local origin does not match
    GitHub definition" class of failure: the operator picks a repository and
    the identity comes from the repository itself rather than from memory.

    The client never supplies a path to scan — only a filter — so this cannot
    be pointed at an arbitrary directory.
    """
    needle = query.strip().lower()
    seen: set[str] = set()
    out: list[ProjectCandidate] = []
    for root in (roots if roots is not None else default_roots()):
        for repo in _walk_repositories(root):
            key = str(repo)
            if key in seen:
                continue
            seen.add(key)
            if needle and needle not in repo.name.lower() and needle not in key.lower():
                continue
            remote = _normalize_remote(_quiet_git(repo, "remote", "get-url", "origin"))
            branch = _quiet_git(repo, "symbolic-ref", "--short", "HEAD")
            head = _quiet_git(repo, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
            base = head.split("/", 1)[1] if "/" in head else (branch or "main")
            out.append(ProjectCandidate(
                local_path=key, name=repo.name, github=remote,
                base_branch=base, current_branch=branch,
            ))
            if len(out) >= limit:
                return tuple(out)
    return tuple(out)


class ProjectRegistry:
    def __init__(self) -> None:
        self._projects: dict[str, LoadedProject] = {}
        self._current_id: str | None = None

    @property
    def current(self) -> LoadedProject | None:
        return self._projects.get(self._current_id) if self._current_id else None

    def list(self) -> tuple[LoadedProject, ...]:
        return tuple(self._projects.values())

    def load(self, definition: ProjectDefinition) -> LoadedProject:
        repo = Path(definition.local_path).expanduser().resolve()
        if not repo.is_dir() or not (repo / ".git").exists():
            raise ValueError("local_path is not a Git repository")
        remote = _git(repo, "remote", "get-url", "origin")
        if _normalize_remote(remote) != _normalize_remote(definition.github):
            raise ValueError("local origin does not match GitHub definition")
        branch = _git(repo, "symbolic-ref", "--short", "HEAD")
        # The working branch may be a feature branch; only the declared base
        # must exist (or be the unborn branch for a new repository).
        base = subprocess.run(
            ["git", "rev-parse", "--verify", definition.base_branch],
            cwd=repo, text=True, capture_output=True,
        )
        remote_base = subprocess.run(
            ["git", "rev-parse", "--verify", f"origin/{definition.base_branch}"],
            cwd=repo, text=True, capture_output=True,
        )
        if base.returncode != 0 and remote_base.returncode != 0 and branch != definition.base_branch:
            raise ValueError(f"base_branch {definition.base_branch!r} does not exist")
        inside = _git(repo, "rev-parse", "--is-inside-work-tree") == "true"
        if inside:
            p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True)
            head = p.stdout.strip() if p.returncode == 0 else f"UNBORN:{branch}"
        else:
            head = ""

        model_ids = {m.id for m in definition.models}
        agent_ids = {a.id for a in definition.agents}
        if len(model_ids) != len(definition.models) or len(agent_ids) != len(definition.agents):
            raise ValueError("duplicate model/agent id")
        for m in definition.models:
            if not m.provider or not m.api_id:
                raise ValueError("model requires provider and provider-accepted api_id")
        for a in definition.agents:
            if a.default_model_id not in model_ids:
                raise ValueError(f"agent {a.id!r} references unknown model")
        gate_ids: set[str] = set()
        for g in definition.gates:
            if g.agent_id not in agent_ids or g.model_id not in model_ids:
                raise ValueError(f"gate {g.id!r} references unknown agent/model")
            if g.context_mode == "fresh_blind" and g.continuity != "fresh":
                raise ValueError("fresh_blind gate cannot request executor continuity")
            if g.kind not in ("write", "check"):
                raise ValueError(f"gate {g.id!r} kind must be write or check")
            # A specialist is agent:gate and phi is keyed by specialist, so two
            # gates sharing an id would silently collapse to one model binding.
            # That is a wrong bind with no error, so it is refused at load.
            if g.id in gate_ids:
                raise ValueError(f"duplicate gate id {g.id!r}: gate ids must be unique in a project")
            gate_ids.add(g.id)
        by_id = {g.id: g for g in definition.gates}

        if not definition.classes:
            # A project that declares gates but no classes has exactly one kind
            # of work: all of them, in order. Deriving it here keeps a single
            # rule rather than letting callers each invent their own.
            definition = replace(definition, classes=(ClassDefinition(
                "feature", "Feature or fix",
                "Every declared gate, in the order the project declares them.",
                tuple(g.id for g in definition.gates),
            ),))
        class_ids: set[str] = set()
        for c in definition.classes:
            if c.id in class_ids:
                raise ValueError(f"duplicate class id {c.id!r}")
            class_ids.add(c.id)
            if not c.gate_ids:
                raise ValueError(f"class {c.id!r} declares no gates")
            seen_in_class: set[str] = set()
            for gid in c.gate_ids:
                if gid not in gate_ids:
                    raise ValueError(f"class {c.id!r} references unknown gate {gid!r}")
                # The same gate twice is two stages sharing one specialist, so
                # the second stage's allow set is already exhausted by the first.
                if gid in seen_in_class:
                    raise ValueError(f"class {c.id!r} lists gate {gid!r} twice")
                seen_in_class.add(gid)
            # `authors` is written only by a passing write stage (I6 keys the
            # check exclusion off it), so a class whose first gate is a check
            # excludes nobody, and a class with no write gate excludes nobody
            # ever. Both promise dual control the machine cannot deliver, so
            # they are refused at load rather than passing vacuously.
            kinds = [by_id[gid].kind for gid in c.gate_ids]
            if kinds[0] != "write":
                raise ValueError(
                    f"class {c.id!r} starts with a check gate: a check excludes the "
                    "authors of the line, and nothing has authored it yet")
            if "write" not in kinds:
                raise ValueError(f"class {c.id!r} declares no write gate")

        loaded = LoadedProject(definition, True, head, _normalize_remote(remote), branch)
        self._projects[definition.id] = loaded
        self._current_id = definition.id
        return loaded

    def select(self, project_id: str) -> LoadedProject:
        if project_id not in self._projects:
            raise ValueError("project not loaded")
        self._current_id = project_id
        return self._projects[project_id]
