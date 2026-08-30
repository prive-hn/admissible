"""rga — refutation-gated admission, portable core.

Zero dependencies beyond fcd. Python 3.10+. Composes over fcd.core.Enforcer
and writes none of its state (paper/RGA/PROOFS.md R11).
"""
from .calibration import (
    CalibrationAuthority,
    CalibrationClass,
    CalibrationPolicy,
    Run,
)
from .core import (
    Admission,
    AdmissionPolicy,
    ClaimSeal,
    ClaimSpec,
    ClassAdmission,
    DefectModel,
    LedgerEntry,
    Line,
    PowerRecord,
    Refuter,
    RefuterSeal,
    Sample,
    Seal,
    Trial,
    derive_seed,
    sha256,
)
from .attestation import (
    AdmissibilityReceipt,
    ReceiptIssueError,
    ReceiptVerificationError,
    admissibility_receipt_from_dict,
    admissibility_receipt_to_dict,
    issue_admissibility_receipt,
    verify_admissibility_receipt,
)

__version__ = "0.5.0"

__all__ = [
    "Admission", "AdmissionPolicy", "CalibrationAuthority", "CalibrationClass",
    "CalibrationPolicy", "ClaimSeal", "ClaimSpec", "ClassAdmission",
    "DefectModel", "LedgerEntry", "Line", "PowerRecord", "Refuter", "RefuterSeal",
    "Run", "Sample", "Seal", "Trial", "derive_seed", "sha256", "__version__",
    "AdmissibilityReceipt", "ReceiptIssueError", "ReceiptVerificationError",
    "admissibility_receipt_from_dict", "admissibility_receipt_to_dict",
    "issue_admissibility_receipt", "verify_admissibility_receipt",
]
