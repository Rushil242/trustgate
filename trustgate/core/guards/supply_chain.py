"""Supply-Chain Guard — verify hooks, skills and MCP servers before they run.

An agent's extension points are executable code that arrives from outside the
review process. This guard hashes the files that define them and compares
against a locally approved manifest (`.trustgate/approved.json`); anything
unknown or changed escalates to a human rather than executing.

This is the control that answers the hook-CVE and package-hook-worm class of
attack, where the compromise is a config file the agent trusts implicitly.

Spec: Master Build Document v3.0, Part E.5.

R0 status: stubbed. Hashing and the approval manifest land in R1.
"""

from __future__ import annotations

from trustgate.core.guards import BaseGuard
from trustgate.core.models import ActionRequest, GuardResult, Verdict

# Files whose modification changes what the agent will execute.
WATCHED_CONFIGS: tuple[str, ...] = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
    ".claude/hooks",
    ".claude/skills",
)

APPROVAL_MANIFEST = ".trustgate/approved.json"


class SupplyChainGuard(BaseGuard):
    name = "supply_chain"

    def check(self, req: ActionRequest) -> GuardResult:
        """R0: stub. Hash comparison against the approval manifest lands in R1."""
        return GuardResult(verdict=Verdict.allow)
