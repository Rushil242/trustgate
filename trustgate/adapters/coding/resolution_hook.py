"""Records how an escalation was answered, for coding agents.

`PreToolUse` can only ever write half a compliance record. It says "a human must
decide this" and then hands control to Claude Code, which prompts the developer.
Without this module the ledger contains the question and never the answer, and
"escalated" is not something anyone can hand an auditor.

We do not own that prompt, so we cannot be told the answer directly. We infer it
from the events that follow, keyed on `tool_use_id`:

| Event                  | What it proves                    | Outcome    |
|------------------------|-----------------------------------|------------|
| `PostToolUse`          | the tool ran, so it was permitted | `approved` |
| `PermissionDenied`     | Claude Code refused it            | `denied`   |
| `PostToolUseFailure`   | it did not run, reason is text    | see below  |

`PostToolUseFailure` is the awkward one: it fires both when a user declines and
when a permitted command simply errored, and the payload does not distinguish
them. We match a short list of Claude Code's own refusal phrasings and record
`unknown` for anything else, with the error text kept verbatim.

The direction of that default is the whole point. A wrong `unknown` costs an
auditor one question. A wrong `approved` puts a person's name against a decision
they never made, which is worse than having no record at all.

Registered by `trustgate init` on all three events. Writes nothing for actions
that were never escalated, which is almost all of them.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from trustgate.core.models import Approver, Outcome

HOOK_EVENTS = ("PostToolUse", "PostToolUseFailure", "PermissionDenied")

# Claude Code's wording when a person declines a permission prompt. Matched
# case-insensitively as substrings. Anything unmatched becomes `unknown`, so a
# phrasing change here degrades the record's precision and never its honesty.
#
# Every phrase must name the user, or name the tool use as rejected. That rule
# is not stylistic. The obvious candidate "permission denied" is the POSIX
# EACCES string, so `EACCES: permission denied, open '.claude/settings.json'`
# would be filed as a human refusal that never happened — a fabricated approval
# decision, which is the one error this module exists to avoid. A phrase that
# an operating system could emit on its own does not belong here.
DENIAL_PHRASES: tuple[str, ...] = (
    "user doesn't want to proceed",
    "user does not want to proceed",
    "user rejected",
    "rejected by the user",
    "denied by the user",
    "tool use was rejected",
)

# How each outcome was established, recorded alongside it. An auditor reading
# the ledger can tell direct evidence from inference without leaving the line.
METHODS: dict[str, str] = {
    "PostToolUse": "inferred: claude-code executed the tool, so permission was granted",
    "PermissionDenied": "observed: claude-code reported the permission was denied",
    "PostToolUseFailure": "inferred: claude-code reported the tool did not succeed",
}


def classify(event: str, payload: dict[str, Any]) -> tuple[Outcome, str]:
    """Map a post-action event onto an outcome and the text that justifies it."""
    if event == "PostToolUse":
        return Outcome.approved, ""

    if event == "PermissionDenied":
        return Outcome.denied, str(payload.get("denial_reason") or "")

    error = str(payload.get("tool_error") or "")
    lowered = error.lower()
    if any(phrase in lowered for phrase in DENIAL_PHRASES):
        return Outcome.denied, error

    # It ran and failed, or it was refused in wording we do not recognize.
    # Both are honestly `unknown`; the text is preserved so a human can settle it.
    return Outcome.unknown, error


def principal_id(payload: dict[str, Any]) -> str:
    """Who we can credibly say answered.

    Claude Code does not tell a hook which human is at the keyboard, so naming
    one would be a fabrication. We record the machine account instead, which is
    true and checkable. A named approver is what the hosted console adds, and it
    is the reason that console is worth paying for.
    """
    import getpass

    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser consults the environment and can fail
        return "local-user"


def record(payload: dict[str, Any], ledger=None) -> dict[str, Any]:
    """Full cycle for one post-action event. Never raises.

    Returns a small report for tests and `--debug`; Claude Code ignores the
    stdout of these events, so the return value is not a hook response.
    """
    event = str(payload.get("hook_event_name") or "")
    if event not in HOOK_EVENTS:
        return {"recorded": False, "why": f"not a resolution event: {event!r}"}

    correlation_id = str(payload.get("tool_use_id") or "")
    if not correlation_id:
        return {"recorded": False, "why": "no tool_use_id to match on"}

    try:
        if ledger is None:
            ledger = _build_ledger()
        escalation = ledger.find_open_escalation(correlation_id)
    except Exception as exc:  # noqa: BLE001 - a broken ledger must not break the session
        return {"recorded": False, "why": f"could not read the ledger: {exc}"}

    if escalation is None:
        # The overwhelmingly common case: the action was allowed outright and
        # there is no question for this event to answer. Writing anything here
        # would double the size of every ledger to no purpose.
        return {"recorded": False, "why": "no open escalation for this action"}

    outcome, detail = classify(event, payload)

    try:
        entry = ledger.write_resolution(
            request_id=escalation.get("request_id", ""),
            outcome=outcome,
            approver=Approver(id=principal_id(payload), method=METHODS.get(event, event)),
            correlation_id=correlation_id,
            detail=detail,
            # Claude Code held the tool call at its own prompt until someone
            # answered, so this answer did gate the action even though we only
            # observed the result rather than serving the prompt ourselves.
            gated=True,
        )
    except Exception as exc:  # noqa: BLE001
        return {"recorded": False, "why": f"could not append the resolution: {exc}"}

    return {
        "recorded": True,
        "outcome": outcome.value,
        "seq": entry.seq,
        "request_id": entry.request_id,
    }


def _build_ledger():
    from trustgate.core.audit import AuditLedger
    from trustgate.core.config import Config

    return AuditLedger(Config.load().audit_path)


def main() -> int:
    """Entry point for the installed shim.

    Always exits 0. These events are informational to Claude Code, and a
    non-zero exit from a bookkeeping hook would surface to the developer as a
    broken tool for no benefit.
    """
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    if not isinstance(payload, dict):
        return 0

    try:
        record(payload)
    except Exception:  # noqa: BLE001 - defence in depth; record() already catches
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
