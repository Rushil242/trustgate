#!/usr/bin/env bash
# SessionStart: make sure the TrustGate engine is installed in the plugin's own
# data folder. Runs at every session start and returns at once when it is
# already installed. Never fails the session: errors go to stderr, exit is 0,
# and run.sh asks the user about every action until the install works.
set -uo pipefail

DATA="${CLAUDE_PLUGIN_DATA:-$HOME/.claude/plugins/data/trustgate}"
VENV="$DATA/venv"
STAMP="$DATA/installed-from"
SPEC="${TRUSTGATE_PLUGIN_SOURCE:-trustgate @ git+https://github.com/Rushil242/trustgate@v0.2.0}"

if [ -x "$VENV/bin/python" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$SPEC" ]; then
    exit 0
fi

mkdir -p "$DATA"
rm -rf "$VENV"

if command -v uv >/dev/null 2>&1; then
    uv venv -q --python ">=3.11" "$VENV" >&2 && uv pip install -q --python "$VENV/bin/python" "$SPEC" >&2
else
    PY=""
    for candidate in python3.13 python3.12 python3.11 python3; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
            PY="$candidate"
            break
        fi
    done
    if [ -z "$PY" ]; then
        echo "TrustGate needs Python 3.11 or newer (or uv). Until then every action asks for approval." >&2
        exit 0
    fi
    "$PY" -m venv "$VENV" >&2 && "$VENV/bin/pip" install -q "$SPEC" >&2
fi

if [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c 'import trustgate' 2>/dev/null; then
    printf '%s' "$SPEC" > "$STAMP"
else
    echo "TrustGate install failed. Until it works, every action asks for approval." >&2
    rm -f "$STAMP"
fi
exit 0
