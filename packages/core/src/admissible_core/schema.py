"""Access to the shipped JSON Schema documents for the workflow contracts."""
from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

__all__ = [
    "DEFECT_SCHEMA_FILE",
    "EVALUATION_SCHEMA_FILE",
    "EVIDENCE_SCHEMA_FILE",
    "RECEIPT_SCHEMA_FILE",
    "READY_SCHEMA_FILE",
    "REMEDIATION_SCHEMA_FILE",
    "WORK_PACKAGE_SCHEMA_FILE",
    "defect_schema",
    "evaluation_schema",
    "evidence_schema",
    "load_schema",
    "receipt_schema",
    "ready_schema",
    "remediation_schema",
    "work_package_schema",
]

EVIDENCE_SCHEMA_FILE = "workflow-evidence.schema.json"
RECEIPT_SCHEMA_FILE = "workflow-receipt.schema.json"
DEFECT_SCHEMA_FILE = "defect-record.schema.json"
EVALUATION_SCHEMA_FILE = "evaluation-attestation.schema.json"
READY_SCHEMA_FILE = "ready-state.schema.json"
WORK_PACKAGE_SCHEMA_FILE = "agent-work-package.schema.json"
REMEDIATION_SCHEMA_FILE = "remediation.schema.json"
_KNOWN = (
    EVIDENCE_SCHEMA_FILE,
    RECEIPT_SCHEMA_FILE,
    DEFECT_SCHEMA_FILE,
    EVALUATION_SCHEMA_FILE,
    READY_SCHEMA_FILE,
    WORK_PACKAGE_SCHEMA_FILE,
    REMEDIATION_SCHEMA_FILE,
)


@lru_cache(maxsize=16)
def _read(name: str) -> str:
    return resources.files("protocol").joinpath(name).read_text(encoding="utf-8")


def load_schema(name: str) -> dict[str, Any]:
    """Load one shipped schema document by file name."""

    if name not in _KNOWN:
        raise KeyError(f"unknown schema document {name!r}")
    return json.loads(_read(name))


def evidence_schema() -> dict[str, Any]:
    return load_schema(EVIDENCE_SCHEMA_FILE)


def receipt_schema() -> dict[str, Any]:
    return load_schema(RECEIPT_SCHEMA_FILE)


def defect_schema() -> dict[str, Any]:
    return load_schema(DEFECT_SCHEMA_FILE)


def evaluation_schema() -> dict[str, Any]:
    return load_schema(EVALUATION_SCHEMA_FILE)


def ready_schema() -> dict[str, Any]:
    return load_schema(READY_SCHEMA_FILE)


def work_package_schema() -> dict[str, Any]:
    return load_schema(WORK_PACKAGE_SCHEMA_FILE)


def remediation_schema() -> dict[str, Any]:
    return load_schema(REMEDIATION_SCHEMA_FILE)
