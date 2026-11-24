"""Context Guard — scan ingested content for injected instructions.

Reads `context.ingested_content`: file text, a fetched web page, an MCP tool
description, or a voice transcript. All of it is data. None of it is authority.

**This guard never blocks.** On a hit it returns `uncertain`, which asks the
engine for a model judgment. That is a deliberate design choice, not a
limitation: injection heuristics are keyword-shaped and fire on innocent prose —
a README documenting prompt-injection, a changelog entry saying "ignore previous
defaults", a test fixture containing an attack string. Hard-blocking on those
would break the zero-false-positive requirement and train people to disable the
gate. Uncertainty routes to something that can read intent.

Spec: Master Build Document v3.0, Part E.4.
"""

from __future__ import annotations

import re
import time

from trustgate.core.guards import BaseGuard
from trustgate.core.models import ActionRequest, GuardResult, Reason, Verdict

# Phrases that attempt to override the agent's operating instructions.
OVERRIDE_PHRASES: tuple[str, ...] = (
    r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above)\s+instructions",
    r"disregard\s+(?:the\s+)?(?:system\s+prompt|previous|prior|your)\s*\w*",
    r"forget\s+(?:the\s+|your\s+)?(?:verification|rules|instructions|guidelines)",
    r"you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|different|new|DAN|jailbroken)",
    r"new\s+instructions\s*:",
    r"system\s+(?:override|prompt)\s*:",
    r"do\s+not\s+(?:mention|tell|inform|report)\s+(?:this|it)\s+to\s+the\s+user",
    r"without\s+(?:asking|telling|notifying)\s+the\s+user",
    r"act\s+as\s+(?:if\s+you\s+are\s+)?(?:root|admin|administrator|a\s+different)",
    r"</?(?:system|instructions?)>",
    r"\[\[?\s*(?:system|admin)\s*\]?\]",
)

# Hidden-instruction carriers: text the human reviewer will not see.
# HTML comments are scanned by `_hidden_comment` below, not by a regex: the old
# pattern `<!--.*?(...).*?-->` was quadratic, and 80,000 characters of `<!--`
# stalled the hook for 15 seconds.
HIDDEN_MARKERS: tuple[str, ...] = (
    r"\u200b|\u200c|\u200d|\ufeff",  # zero-width characters
)
_COMMENT_WORDS = re.compile(r"ignore|instruction|you\s+must|execute", re.IGNORECASE)

SCAN_BUDGET_SECONDS = 0.05
"""The whole scan stops after this long and reports `uncertain`. A slow scan is
treated as a reason for a person to look, never as a pass."""

_COMPILED_OVERRIDE = [re.compile(p, re.IGNORECASE) for p in OVERRIDE_PHRASES]
_COMPILED_HIDDEN = [re.compile(p) for p in HIDDEN_MARKERS]


def _hidden_comment(text: str) -> bool:
    """Whether any HTML comment carries instruction words. Linear time.

    Each comment is looked at once: find `<!--`, find the next `-->` after it,
    search only that slice, then continue after the close. An unclosed comment
    hides everything after it in a browser, so it runs to the end of the text.
    """
    pos = 0
    while True:
        start = text.find("<!--", pos)
        if start < 0:
            return False
        end = text.find("-->", start + 4)
        body = text[start + 4 : end if end >= 0 else len(text)]
        if _COMMENT_WORDS.search(body):
            return True
        if end < 0:
            return False
        pos = end + 3

MAX_SCAN_CHARS = 200_000
"""Cap the scan so a huge ingested file cannot stall the hot path."""


class ContextGuard(BaseGuard):
    name = "context"

    def check(self, req: ActionRequest) -> GuardResult:
        content = req.context.ingested_content
        if not content:
            return GuardResult(verdict=Verdict.allow)

        excerpt = content[:MAX_SCAN_CHARS]
        reasons: list[Reason] = []
        deadline = time.perf_counter() + SCAN_BUDGET_SECONDS

        for pattern in _COMPILED_OVERRIDE:
            if time.perf_counter() > deadline:
                return _over_budget(self.name)
            match = pattern.search(excerpt)
            if match:
                reasons.append(
                    Reason(
                        guard=self.name,
                        rule_id="context-injection",
                        message=(
                            "Ingested content contains an instruction-override phrase: "
                            f"{_quote(match.group(0))}"
                        ),
                        severity="medium",
                    )
                )
                break

        hidden = _hidden_comment(excerpt) or any(p.search(excerpt) for p in _COMPILED_HIDDEN)
        if time.perf_counter() > deadline and not reasons and not hidden:
            return _over_budget(self.name)
        if hidden:
            reasons.append(
                Reason(
                    guard=self.name,
                    rule_id="context-hidden-instruction",
                    message=(
                        "Ingested content contains hidden or invisible text, which "
                        "is a common carrier for instructions a reviewer cannot see"
                    ),
                    severity="medium",
                )
            )

        if not reasons:
            return GuardResult(verdict=Verdict.allow)

        # Uncertain, never block. See the module docstring.
        return GuardResult(verdict=Verdict.uncertain, reasons=reasons)


def _over_budget(guard: str) -> GuardResult:
    return GuardResult(
        verdict=Verdict.uncertain,
        reasons=[
            Reason(
                guard=guard,
                rule_id="context-scan-budget",
                message="Ingested content was too large or slow to scan in time",
                severity="medium",
            )
        ],
    )


def _quote(text: str, limit: int = 80) -> str:
    """Quote matched text for an audit line without letting it run away."""
    flattened = " ".join(text.split())
    if len(flattened) > limit:
        flattened = flattened[:limit] + "…"
    return repr(flattened)
