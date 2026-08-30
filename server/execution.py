"""Execution boundary for mature black-box workers.

FCD owns project/work/context/evidence/acceptance. An ExecutionAdapter may use
Claude Code, Codex, Hermes, ACP, or another existing executor internally. FCD
does not reimplement those tools or session stores. The adapter cannot Pass or
Accept; it returns receipts/evidence/artifacts for FCD to validate.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from fcd.context import AdapterReceipt, ContextPackage, ExecutionEnvelope, hash_bytes


@dataclass(frozen=True)
class ExecutionRequest:
    envelope: ExecutionEnvelope
    package: ContextPackage
    specialist: str
    contract: dict[str, Any]
    steering: tuple[dict[str, Any], ...]
    latest_continuation_hash: str
    continuity_hint: str = "fresh"
    opaque_checkpoint_id: str | None = None


@dataclass(frozen=True)
class ExecutionResult:
    receipt: AdapterReceipt
    artifact: dict[str, Any] | None = None
    evidence: tuple[dict[str, Any], ...] = ()
    question: dict[str, Any] | None = None
    reported_reuse: bool | None = None
    opaque_cache_id: str | None = None


class ExecutionAdapter(ABC):
    id: str
    capabilities: frozenset[str]

    def readiness(self, *, provider: str, model_api_id: str, project_path: str) -> dict[str, Any]:
        """Return explicit connection checks. Unknown adapters fail closed."""
        return {
            "installed": False, "authenticated": False, "model_resolves": False,
            "project_access": False, "tools_available": False, "canary": False,
            "receipt_available": False, "death_observable": False, "ready": False,
        }

    @abstractmethod
    def run(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute one stage. No authority to Pass, Accept, or write memory."""


class DemoExecutionAdapter(ExecutionAdapter):
    """Deterministic reference adapter for tests and the bundled demo.

    Its specialist→model map is independent from FCD policy. A policy/adapter
    mismatch reaches Observe and correctly closes F1.
    """

    id = "demo"
    capabilities = frozenset({"continue", "fork"})
    #  Keyed by agent id. An agent the adapter cannot run resolves to
    #  "unknown", which reaches Observe and closes F1 — correct behaviour, but
    #  it means every agent the demo project declares must appear here or its
    #  class can never pass. `analyst` was missing, so the one-gate
    #  `investigate` class closed F1 on every line.
    models = {"builder": ("demo", "builder"), "reviewer": ("demo", "reviewer"),
              "analyst": ("demo", "reviewer")}

    def readiness(self, *, provider: str, model_api_id: str, project_path: str) -> dict[str, Any]:
        resolves = (provider, model_api_id) in set(self.models.values())
        project_access = Path(project_path).is_dir()
        ready = resolves and project_access
        return {
            "installed": True, "authenticated": True, "model_resolves": resolves,
            "project_access": project_access, "tools_available": True,
            "canary": resolves, "receipt_available": True,
            "death_observable": True, "ready": ready,
        }

    def run(self, request: ExecutionRequest) -> ExecutionResult:
        import html

        title = html.escape(request.contract["title"])
        summary = html.escape(request.contract["summary"])
        steer = html.escape(request.steering[-1]["text"]) if request.steering else "No steering overrides"
        src = f"""<!doctype html><html><head><meta charset='utf-8'><style>
body{{font:15px system-ui;margin:0;background:#f7f5ef;color:#17202a}}
main{{padding:32px;max-width:720px;margin:auto}} .card{{background:white;border:1px solid #d7d3c8;border-radius:12px;padding:24px;box-shadow:0 8px 30px #0001}}
small{{color:#667085}} button{{border:0;background:#1f4d2a;color:white;padding:10px 15px;border-radius:8px}}</style></head>
<body><main><div class='card'><small>Runnable candidate · {html.escape(request.envelope.work_item_id)}</small><h1>{title}</h1><p>{summary}</p><p><strong>Steering:</strong> {steer}</p><button type='button'>Candidate action</button></div></main></body></html>"""
        provider, model = self.models.get(request.specialist, ("demo", "unknown"))
        receipt = AdapterReceipt(
            attempt_id=request.envelope.attempt_id,
            nonce=request.envelope.nonce,
            executor_id=self.id,
            run_id=f"demo-{request.envelope.attempt_counter}",
            package_hash_observed=hash_bytes(request.package.payload),
            continuation_hash=request.latest_continuation_hash,
            executed_provider=provider,
            executed_model=model,
        )
        return ExecutionResult(
            receipt=receipt,
            artifact={"kind": "html", "srcDoc": src, "title": request.contract["title"]},
            evidence=({"kind": "execution", "label": "Demo adapter produced runnable HTML",
                       "detail": request.envelope.gate_id},),
        )


class ProcessExecutionAdapter(ExecutionAdapter):
    """Compatibility boundary for an existing CLI/ACP executor.

    The injected runner keeps its mature tool/session behavior. FCD supplies a
    canonical request and validates its result. No shell/process implementation
    is embedded here.
    """

    def __init__(self, adapter_id: str, capabilities: frozenset[str],
                 runner: Callable[[ExecutionRequest], ExecutionResult]) -> None:
        self.id = adapter_id
        self.capabilities = capabilities
        self._runner = runner

    def run(self, request: ExecutionRequest) -> ExecutionResult:
        return self._runner(request)
