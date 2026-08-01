"""TrustGate — a control and audit layer for AI agents.

TrustGate decides, deterministically, whether a proposed agent action is allowed
— allow, block, modify, or escalate to a human — and records every decision in a
tamper-evident log. Policy is written once as a plain-English constitution; thin
adapters connect the engine to specific agent surfaces.

The engine is surface-agnostic. Only adapters know what a "tool call" looks like.
"""

from trustgate.core.models import (
    Action,
    ActionRequest,
    ActionType,
    AuditEntry,
    Context,
    Decision,
    Effect,
    GuardResult,
    Principal,
    Reason,
    Verdict,
)

__version__ = "0.1.0"

__all__ = [
    "Action",
    "ActionRequest",
    "ActionType",
    "AuditEntry",
    "Context",
    "Decision",
    "Effect",
    "GuardResult",
    "Principal",
    "Reason",
    "Verdict",
    "__version__",
]
