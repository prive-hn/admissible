"""fcd — fail-closed class dispatch, portable core.

Zero dependencies. Python 3.10+ (dataclasses, generics). Runs on
CPython and PyPy; suitable for macOS / iOS (PythonKit, a-Shell) hosts
because it never touches os.kill, signals, or the filesystem.
"""
from .core import Enforcer, Policy, Stage, Item, norm
from .cache import StageCache
from .watchdog import poll
from .journal import JournalEvent, ReplayError, to_plain_json
from .head import (
    HeadReceipt,
    HeadRefused,
    HeadVerificationError,
    HMACSHA256Keyring,
    HMACSHA256Signer,
    JournalHead,
    MonotoneHeadRegistry,
    compute_journal_head,
    verify_current,
)
from .adapter_attestation import (
    AdapterIssueError,
    AdapterReplayError,
    AdapterReplayLog,
    AdapterVerificationError,
    AttestingGateway,
    AuthenticatedAdapterReceipt,
    ExecutionFence,
    InferenceGateway,
    ProviderCredentials,
    ProviderObservation,
    issue_adapter_receipt,
    observe_attested,
    route_identity,
    verify_adapter_receipt,
)
from .human_review import (
    HumanReviewError,
    HumanReviewReceipt,
    ReviewConclusions,
    issue_human_review,
    verify_human_review,
)
from .context import (
    AdapterReceipt,
    AgentRef,
    ContextAuthority,
    ContextPackage,
    ContextPolicy,
    ExecutionAdapterRef,
    ExecutionEnvelope,
    GateSpec,
    ImpactReview,
    KnowledgeDelta,
    ModelRef,
    ProjectState,
    SteeringEvent,
    WorkPin,
    compile_instruction_manifest,
    hash_bytes,
)

__version__ = "0.5.0"

__all__ = [
    "Enforcer", "Policy", "Stage", "Item", "norm", "StageCache", "poll",
    "JournalEvent", "ReplayError", "to_plain_json", "HeadReceipt",
    "HeadRefused", "HeadVerificationError", "HMACSHA256Keyring",
    "HMACSHA256Signer", "JournalHead", "MonotoneHeadRegistry",
    "compute_journal_head", "verify_current",
    "AdapterIssueError", "AdapterReplayError", "AdapterReplayLog",
    "AdapterVerificationError", "AttestingGateway",
    "AuthenticatedAdapterReceipt", "ProviderObservation",
    "ExecutionFence", "InferenceGateway", "ProviderCredentials",
    "issue_adapter_receipt", "observe_attested", "route_identity",
    "verify_adapter_receipt",
    "HumanReviewError", "HumanReviewReceipt", "ReviewConclusions",
    "issue_human_review", "verify_human_review",
    "ContextAuthority", "ProjectState", "WorkPin", "AgentRef",
    "ExecutionAdapterRef", "ModelRef", "ContextPolicy", "GateSpec",
    "ExecutionEnvelope", "ContextPackage", "AdapterReceipt", "SteeringEvent",
    "KnowledgeDelta", "ImpactReview", "compile_instruction_manifest", "hash_bytes",
    "__version__",
]
