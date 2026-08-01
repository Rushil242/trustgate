"""Context Guard — scan ingested content for injected instructions.

Reads `context.ingested_content`: file text, a fetched web page, an MCP tool
description, or a voice transcript. All of it is data. None of it is authority.

Deliberate design choice: on a hit this guard returns `uncertain`, not `block`.
Injection heuristics are keyword-shaped and fire on innocent prose ("ignore the
previous section" in a README), so a hard block here would blow the
zero-false-positive requirement. Uncertain routes the call to the LLM judge,
which can read intent.

Spec: Master Build Document v3.0, Part E.4.

R0 status: stubbed. Heuristics land in R1.
"""

from __future__ import annotations

from trustgate.core.guards import BaseGuard
from trustgate.core.models import ActionRequest, GuardResult, Verdict

# Seed set for R1. Kept here so the red-team suite and the guard evolve together.
OVERRIDE_PHRASES: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard the system prompt",
    "disregard your instructions",
    "you are now",
    "forget the verification step",
    "forget your rules",
    "new instructions:",
    "system override",
)


class ContextGuard(BaseGuard):
    name = "context"

    def check(self, req: ActionRequest) -> GuardResult:
        """R0: stub. Injection heuristics land in R1."""
        return GuardResult(verdict=Verdict.allow)
