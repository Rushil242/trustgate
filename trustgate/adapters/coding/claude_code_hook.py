"""Claude Code adapter — the Policy Enforcement Point for coding agents.

Claude Code fires a `PreToolUse` hook with the proposed tool call as JSON on
stdin, before the tool runs. This module maps that call onto the universal
`ActionRequest`, asks the engine, and translates the `Decision` back into the
hook response schema.

Two details that decide whether this works at all:

* **The response schema.** `PreToolUse` reads
  `hookSpecificOutput.permissionDecision`; the flat top-level `decision`/`reason`
  fields are not used for this event. Emitting the flat form means the hook is
  ignored and every action is allowed — a gate that fails open silently. The
  v3.0 build document specifies the flat form; see DEVIATIONS.md #4.

* **Failing safe on our own errors.** If this adapter crashes, Claude Code
  proceeds with the tool call. So every failure path is caught and converted
  into an explicit decision rather than allowed to raise.

Spec: Master Build Document v3.0, Part H.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from trustgate.core.models import Action, ActionRequest, ActionType, Context, Decision, Effect

HOOK_EVENT = "PreToolUse"

# Claude Code tool name -> normalized action type. Anything unlisted falls back
# to `tool_call`, which is correct for MCP tools (`mcp__server__tool`) and for
# tools added after this mapping was written.
TOOL_TYPES: dict[str, ActionType] = {
    "Bash": ActionType.shell,
    "BashOutput": ActionType.shell,
    "Read": ActionType.file_read,
    "NotebookRead": ActionType.file_read,
    "Glob": ActionType.file_read,
    "Grep": ActionType.file_read,
    "Write": ActionType.file_write,
    "Edit": ActionType.file_write,
    "MultiEdit": ActionType.file_write,
    "NotebookEdit": ActionType.file_write,
    "WebFetch": ActionType.network,
    "WebSearch": ActionType.network,
}

# Where each tool keeps the text worth pattern-matching. `raw` must always be
# populated: the secret-read normalizer and every `any_pattern` read it, so an
# empty raw quietly weakens enforcement rather than failing loudly.
RAW_KEYS: tuple[str, ...] = (
    "command",
    "file_path",
    "path",
    "notebook_path",
    "pattern",
    "url",
    "query",
)


def to_action_request(payload: dict[str, Any]) -> ActionRequest:
    """Map a PreToolUse payload onto the universal contract."""
    tool_name = payload.get("tool_name") or "unknown"
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    action_type = TOOL_TYPES.get(tool_name, ActionType.tool_call)

    return ActionRequest(
        surface="coding",
        action=Action(
            type=action_type,
            tool=tool_name,
            params=tool_input,
            raw=_raw_text(tool_input),
        ),
        context=Context(
            ingested_content=_ingested_content(tool_input),
            session_id=payload.get("session_id"),
            correlation_id=payload.get("tool_use_id"),
        ),
    )


def _raw_text(tool_input: dict[str, Any]) -> str:
    """The action's text form, for patterns and the secret-read normalizer."""
    for key in RAW_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    # No known key: fall back to a stable serialization rather than nothing.
    return json.dumps(tool_input, sort_keys=True) if tool_input else ""


def _ingested_content(tool_input: dict[str, Any]) -> str | None:
    """Content this call would introduce into the agent's context.

    For a write, the text being written is attacker-influenced material worth
    scanning — a poisoned file lands here before it is ever read back.
    """
    for key in ("content", "new_string", "prompt"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def to_hook_response(decision: Decision) -> dict[str, Any]:
    """Translate a Decision into the PreToolUse response schema."""
    permission, reason = _permission_for(decision)
    return {
        "hookSpecificOutput": {
            "hookEventName": HOOK_EVENT,
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        }
    }


def _permission_for(decision: Decision) -> tuple[str, str]:
    if decision.effect is Effect.allow:
        return "allow", "TrustGate: no policy violation."

    if decision.effect is Effect.block:
        return "deny", f"Blocked by TrustGate. {summarize(decision)}"

    if decision.effect is Effect.escalate:
        return "ask", f"TrustGate requires human approval. {summarize(decision)}"

    # modify: V1 refuses rather than rewriting. Silently altering a command the
    # agent believes it ran is its own kind of unsafe, and the agent would
    # reason about output that came from a different command than it issued.
    return (
        "deny",
        "Blocked by TrustGate: this action carries data that must be redacted "
        f"before it can run. {summarize(decision)}",
    )


def summarize(decision: Decision) -> str:
    """A one-line explanation the model can act on.

    Names the principle that fired. The agent is told *which rule* it hit so it
    can choose a different approach instead of retrying variations of the same
    blocked action.
    """
    if not decision.reasons:
        return "No specific rule was recorded."

    parts = [f"[{r.rule_id}] {r.message}" for r in decision.reasons[:3]]
    if len(decision.reasons) > 3:
        parts.append(f"(+{len(decision.reasons) - 3} more)")
    return " ".join(parts)


def decide(payload: dict[str, Any], engine=None) -> dict[str, Any]:
    """Full hook cycle for one payload. Never raises."""
    try:
        request = to_action_request(payload)
    except Exception as exc:  # noqa: BLE001
        return _fail_safe(f"could not interpret the tool call: {exc}")

    try:
        if engine is None:
            engine = _build_engine()
        decision = engine.decide(request)
    except Exception as exc:  # noqa: BLE001
        return _fail_safe(f"policy engine error: {exc}")

    return to_hook_response(decision)


def _build_engine():
    from trustgate.core.audit import AuditLedger
    from trustgate.core.config import Config
    from trustgate.core.constitution import Constitution
    from trustgate.core.engine import Engine

    cfg = Config.load()
    constitution = Constitution.from_file(cfg.constitution_path)

    judge = None
    if cfg.judge.enabled:
        from trustgate.core.guards.constitution_llm import ConstitutionGuard
        from trustgate.core.llm import build_llm

        judge = ConstitutionGuard(constitution, build_llm(cfg.judge))

    return Engine(
        constitution=constitution, audit=AuditLedger(cfg.audit_path), judge=judge
    )


def _fail_safe(detail: str) -> dict[str, Any]:
    """Ask the human when TrustGate itself is broken.

    Not `deny`: a misconfigured gate that blocks every tool call makes the agent
    unusable and gets uninstalled. Not `allow`: that is silent failure open.
    `ask` puts a person in the loop and makes the breakage visible.
    """
    return {
        "hookSpecificOutput": {
            "hookEventName": HOOK_EVENT,
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                f"TrustGate could not evaluate this action ({detail}). "
                "Approve only if you are confident it is safe."
            ),
        }
    }


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError) as exc:
        print(json.dumps(_fail_safe(f"invalid hook payload: {exc}")))
        return 0

    print(json.dumps(decide(payload)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
