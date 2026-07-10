"""Data model and persistence for security findings.

`schema` defines the plain data objects that flow through the whole
pipeline (Finding -> FixAttempt -> VerificationResult). `store` persists
them in SQLite so a run can be inspected, resumed, or re-scored without
re-running CodeChecker or the LLMs.
"""

from sectool.findings.schema import (
    BugPathEvent,
    Finding,
    FindingStatus,
    FixAttempt,
    VerificationResult,
    VerificationStage,
)
from sectool.findings.store import FindingStore

__all__ = [
    "BugPathEvent",
    "Finding",
    "FindingStatus",
    "FixAttempt",
    "VerificationResult",
    "VerificationStage",
    "FindingStore",
]
