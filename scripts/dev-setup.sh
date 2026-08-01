#!/usr/bin/env bash
# Development environment setup: `uv sync --all-extras`, with a macOS workaround.
#
# THE PROBLEM
# On some macOS systems, files created under ~/Documents or ~/Desktop get the
# UF_HIDDEN file flag applied automatically — iCloud Drive sync and several
# endpoint-security agents both do this. CPython's `site.addpackage` skips
# hidden .pth files outright, so an editable install's path entry is silently
# ignored and `import trustgate` fails.
#
# The symptom is confusing: `uv run pytest` passes (pytest injects its own
# pythonpath) while `uv run trustgate` raises ModuleNotFoundError. Clearing the
# flag with chflags does not stick — the agent re-applies it within seconds.
#
# THE FIX
# Put the virtualenv outside the affected directory tree. The source stays where
# it is; only the .venv moves. This script detects the condition and does that
# automatically, then prints the one line you need for your shell.
#
# On Linux, Windows, and unaffected macOS setups this is a plain `uv sync` into
# the usual ./.venv.

set -euo pipefail

cd "$(dirname "$0")/.."
PROJECT_ROOT="$(pwd)"

hides_files() {
    # Probe: create a file and see whether something flags it hidden.
    command -v chflags >/dev/null 2>&1 || return 1
    local probe=".trustgate-hidden-probe"
    : > "$probe"
    sleep 1
    local flagged=1
    if ls -lO "$probe" 2>/dev/null | grep -q hidden; then
        flagged=0
    fi
    rm -f "$probe"
    return $flagged
}

if [ -n "${UV_PROJECT_ENVIRONMENT:-}" ]; then
    echo "using UV_PROJECT_ENVIRONMENT=$UV_PROJECT_ENVIRONMENT"
elif hides_files; then
    export UV_PROJECT_ENVIRONMENT="${TRUSTGATE_VENV:-$HOME/.venvs/trustgate}"
    cat <<EOF

NOTE: this directory is under a path where macOS auto-hides new files, which
      breaks Python's .pth handling and therefore editable installs.

      Placing the virtualenv outside it instead:
        $UV_PROJECT_ENVIRONMENT

      Add this to your shell profile (or prefix every uv command with it):
        export UV_PROJECT_ENVIRONMENT="$UV_PROJECT_ENVIRONMENT"

      Alternatively, move this repository somewhere outside ~/Documents and
      ~/Desktop, and the problem disappears entirely.

EOF
    rm -rf "$PROJECT_ROOT/.venv"
fi

uv sync --all-extras "$@"

VENV="${UV_PROJECT_ENVIRONMENT:-$PROJECT_ROOT/.venv}"
echo
echo "ready. verify with:"
echo "  \"$VENV/bin/trustgate\" --version"
echo "  \"$VENV/bin/pytest\" -q"
