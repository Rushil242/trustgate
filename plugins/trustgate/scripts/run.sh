#!/usr/bin/env bash
# Runs a TrustGate hook from the plugin's own install.
#   run.sh pretooluse   the gate: allow, deny or ask before a tool runs
#   run.sh resolution   bookkeeping after a tool runs; never blocks
#
# Policy: the project's own trustgate.constitution.yaml if it has one, otherwise
# the shipped starter policy. TRUSTGATE_CONSTITUTION overrides both.
set -uo pipefail

MODE="${1:-pretooluse}"
DATA="${CLAUDE_PLUGIN_DATA:-$HOME/.claude/plugins/data/trustgate}"
PY="$DATA/venv/bin/python"

if [ ! -x "$PY" ] || ! "$PY" -c 'import trustgate' 2>/dev/null; then
    # Not installed (yet). Never fail open: ask the user instead of allowing.
    if [ "$MODE" = "pretooluse" ]; then
        printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"TrustGate is not installed yet, so it could not check this action. It installs when a session starts; restart Claude Code if this persists. Approve only if you are confident this is safe."}}'
    fi
    exit 0
fi

if [ -z "${TRUSTGATE_CONSTITUTION:-}" ]; then
    PROJECT_POLICY="${CLAUDE_PROJECT_DIR:-$PWD}/trustgate.constitution.yaml"
    if [ -f "$PROJECT_POLICY" ]; then
        export TRUSTGATE_CONSTITUTION="$PROJECT_POLICY"
    else
        TRUSTGATE_CONSTITUTION="$("$PY" -c 'import pathlib, trustgate; print(pathlib.Path(trustgate.__file__).parent / "policies" / "starter.coding.yaml")')"
        export TRUSTGATE_CONSTITUTION
    fi
fi

case "$MODE" in
    pretooluse) exec "$PY" -m trustgate.adapters.coding.claude_code_hook ;;
    resolution) exec "$PY" -m trustgate.adapters.coding.resolution_hook ;;
    *) echo "unknown mode: $MODE" >&2; exit 0 ;;
esac
