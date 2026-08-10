"""Voice-agent adapter.

Intercepts at the function-call boundary, which every voice stack (LiveKit,
Pipecat, Vapi, Twilio, custom) eventually passes through.

    from trustgate.adapters.voice import VoiceContext, guard_tool, set_call_context

    @guard_tool()
    def issue_refund(amount: float, order_id: str) -> str:
        ...

Spec: Master Build Document v3.0, Part I.
"""

from trustgate.adapters.voice.client import (
    DecisionClient,
    HTTPClient,
    InProcessClient,
    build_default_client,
)
from trustgate.adapters.voice.guard import (
    ActionBlocked,
    GuardError,
    NeedsHumanApproval,
    VoiceContext,
    build_request,
    evaluate,
    guard_tool,
    guarded_dispatch,
    reset_call_context,
    safe_refusal,
    set_call_context,
    set_client,
)

__all__ = [
    "ActionBlocked",
    "DecisionClient",
    "GuardError",
    "HTTPClient",
    "InProcessClient",
    "NeedsHumanApproval",
    "VoiceContext",
    "build_default_client",
    "build_request",
    "evaluate",
    "guard_tool",
    "guarded_dispatch",
    "reset_call_context",
    "safe_refusal",
    "set_call_context",
    "set_client",
]
