#!/usr/bin/env bash
# Install the TrustGate guard room as its own OS user (macOS or Linux).
#
#   sudo deploy/install-guardroom.sh [--source SPEC] [--python PATH]
#   deploy/install-guardroom.sh --dry-run        # print every step, change nothing
#   sudo deploy/install-guardroom.sh --uninstall # stop and remove; keeps the log
#
# What it does, in order:
#   1. checks that nobody but root can change the Python the daemon and the
#      hook run on (--lock-python makes it so for a python.org install)
#   2. creates the _trustgate user (trustgate on Linux)
#   3. creates the daemon's folders: state 0700 and run 0755, owned by that user
#   4. installs TrustGate into a root-owned venv in /usr/local/lib/trustgate
#   5. writes the thin hook there, and a Claude Code managed-settings drop-in
#   6. starts the daemon (LaunchDaemon or systemd) and checks it answers you
#      with protection level 1
#
# Nothing here deletes the audit log. Uninstall leaves the state folder.
set -euo pipefail

DRY_RUN=0
UNINSTALL=0
MANAGED_HOOKS_ONLY=1
LOCK_PYTHON=0
SOURCE=""
PY=""
HOOK_PY=""
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --source) SOURCE="$2"; shift ;;
        --python) PY="$2"; shift ;;
        --hook-python) HOOK_PY="$2"; shift ;;
        --allow-other-hooks) MANAGED_HOOKS_ONLY=0 ;;
        --lock-python) LOCK_PYTHON=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

OS="$(uname -s)"
# For tests only: preview the other OS's steps. Ignored unless --dry-run.
if [ "$DRY_RUN" -eq 1 ] && [ -n "${TG_PREVIEW_OS:-}" ]; then OS="$TG_PREVIEW_OS"; fi
LIB=/usr/local/lib/trustgate
VENV="$LIB/venv"
if [ "$OS" = "Darwin" ]; then
    TG_USER=_trustgate
    BASE="/Library/Application Support/TrustGate"
    STATE="$BASE/state"
    RUN="$BASE/run"
    LOGS=/Library/Logs/TrustGate
    MANAGED_DIR="/Library/Application Support/ClaudeCode/managed-settings.d"
    ROOT_GROUP=wheel
elif [ "$OS" = "Linux" ]; then
    TG_USER=trustgate
    STATE=/var/lib/trustgate
    RUN=/run/trustgate
    MANAGED_DIR=/etc/claude-code/managed-settings.d
    ROOT_GROUP=root
else
    echo "unsupported OS: $OS" >&2
    exit 2
fi
SOURCE="${SOURCE:-$REPO}"

say() { printf '\n== %s\n' "$*"; }
run() {
    # Print the command; run it unless this is a dry run.
    printf '+'; printf ' %q' "$@"; printf '\n'
    if [ "$DRY_RUN" -eq 0 ]; then "$@"; fi
}

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo (or use --dry-run to see the steps)" >&2
    exit 1
fi

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" -eq 1 ]; then
    say "stopping the daemon"
    if [ "$OS" = "Darwin" ]; then
        run launchctl bootout system/com.trustgate.guardroom || true
        run rm -f /Library/LaunchDaemons/com.trustgate.guardroom.plist
    else
        run systemctl disable --now trustgated || true
        run rm -f /etc/systemd/system/trustgated.service
        run systemctl daemon-reload
    fi
    say "removing the hook, the managed-settings drop-in and the venv"
    run rm -f "$MANAGED_DIR/50-trustgate.json"
    run rm -rf "$LIB"
    run rm -f /usr/local/bin/trustgate-admin
    echo
    echo "Kept: $STATE (the policy, the signed log and the machine key are evidence)."
    echo "Kept: the $TG_USER user. Remove both yourself if you are sure."
    exit 0
fi

# ---------------------------------------------------------------- 1. python
say "1. choosing a root-owned Python 3.11+ for the daemon"
if [ -z "$PY" ]; then
    for c in /usr/local/bin/python3.13 /usr/local/bin/python3.12 /usr/local/bin/python3.11 \
             /Library/Frameworks/Python.framework/Versions/Current/bin/python3 \
             /usr/bin/python3.13 /usr/bin/python3.12 /usr/bin/python3.11 /usr/bin/python3; do
        if [ -x "$c" ] && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
            PY="$c"; break
        fi
    done
fi
if [ -z "$PY" ]; then
    echo "no Python 3.11+ found in a system location. Install one from python.org (macOS)" >&2
    echo "or your package manager (Linux), or pass --python PATH." >&2
    [ "$DRY_RUN" -eq 1 ] && PY=/usr/local/bin/python3.12 || exit 1
fi

owner_of() { if [ "$OS" = "Darwin" ]; then stat -f %u "$1"; else stat -c %u "$1"; fi; }
mode_of() { if [ "$OS" = "Darwin" ]; then stat -f %Lp "$1"; else stat -c %a "$1"; fi; }

# The daemon runs this interpreter and its whole install as _trustgate, and the
# hook runs it as you. If anything in it is writable by your user, directly or
# through a group such as `admin`, the agent can change the code the gate
# runs. Owner alone is not enough: python.org installs are owned by root but
# group-writable by `admin`, which every macOS administrator account is in.
others_can_write() {
    # Prints the first few paths that are not root-owned or that group/other
    # can write, in the prefix and in every folder above it.
    local prefix="$1" dir
    find "$prefix" \( ! -user root -o -perm -g+w -o -perm -o+w \) ! -type l 2>/dev/null | head -5
    dir="$prefix"
    while [ "$dir" != "/" ]; do
        dir="$(dirname "$dir")"
        if [ "$(owner_of "$dir")" != "0" ] || [ $(( 0$(mode_of "$dir") & 022 )) -ne 0 ]; then
            # /tmp-style sticky folders are not on this path; anything here is a problem.
            echo "$dir"
        fi
    done
}

if [ -x "$PY" ]; then
    REAL_PY="$("$PY" -I -c 'import os,sys; print(os.path.realpath(sys.executable))')"
    PREFIX="$("$PY" -I -c 'import sys; print(sys.base_prefix)')"
    PY="$REAL_PY"   # never a symlink that a writable folder could swap
    BAD="$(others_can_write "$PREFIX")"
    if [ -n "$BAD" ] && [ "$LOCK_PYTHON" -eq 1 ]; then
        echo "locking $PREFIX: removing group and other write access (owner root)"
        run chown -R root "$PREFIX"
        run chmod -R go-w "$PREFIX"
        case "$PREFIX" in
            /Library/Frameworks/Python.framework/*)
                run chmod go-w /Library/Frameworks/Python.framework/Versions ;;
        esac
        [ "$DRY_RUN" -eq 0 ] && BAD="$(others_can_write "$PREFIX")"
    fi
    if [ -n "$BAD" ] && [ "$DRY_RUN" -eq 0 ] || { [ -n "$BAD" ] && [ "$LOCK_PYTHON" -eq 0 ]; }; then
        echo "REFUSED: users other than root can change this Python ($PREFIX):" >&2
        echo "$BAD" | sed 's/^/  /' >&2
        echo "Fix: rerun with --lock-python (removes group write from that install; use" >&2
        echo "venvs for your own packages), or pass --python for a root-only interpreter." >&2
        [ "$DRY_RUN" -eq 1 ] || exit 1
    elif [ -z "$BAD" ]; then
        echo "ok: only root can change $PREFIX"
    else
        echo "(dry run: would lock $PREFIX, then check again)"
    fi
else
    echo "(dry run: $PY not present, checks skipped)"
fi
HOOK_PY="${HOOK_PY:-$PY}"

# ---------------------------------------------------------------- 2. user
say "2. creating the $TG_USER user"
if id "$TG_USER" >/dev/null 2>&1; then
    echo "exists: $TG_USER"
elif [ "$OS" = "Darwin" ]; then
    NEXT_ID=300
    while dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$NEXT_ID" ||
          dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | grep -qx "$NEXT_ID"; do
        NEXT_ID=$((NEXT_ID + 1))
    done
    run dscl . -create "/Groups/$TG_USER"
    run dscl . -create "/Groups/$TG_USER" PrimaryGroupID "$NEXT_ID"
    run dscl . -create "/Users/$TG_USER"
    run dscl . -create "/Users/$TG_USER" UniqueID "$NEXT_ID"
    run dscl . -create "/Users/$TG_USER" PrimaryGroupID "$NEXT_ID"
    run dscl . -create "/Users/$TG_USER" UserShell /usr/bin/false
    run dscl . -create "/Users/$TG_USER" NFSHomeDirectory /var/empty
    run dscl . -create "/Users/$TG_USER" RealName "TrustGate guard room"
    run dscl . -create "/Users/$TG_USER" IsHidden 1
else
    run useradd --system --user-group --no-create-home --home-dir "$STATE" \
        --shell /usr/sbin/nologin "$TG_USER"
fi

# ---------------------------------------------------------------- 3. folders
say "3. folders: state 0700 and run 0755, owned by $TG_USER"
if [ "$OS" = "Darwin" ]; then
    run mkdir -p "$STATE" "$RUN" "$LOGS"
    run chown root:"$ROOT_GROUP" "$BASE"
    run chmod 0755 "$BASE"
    run chown "$TG_USER:$TG_USER" "$STATE" "$RUN" "$LOGS"
    run chmod 0700 "$STATE"
    run chmod 0755 "$RUN"
    run chmod 0750 "$LOGS"
else
    echo "(systemd creates $STATE and $RUN itself, from StateDirectory and RuntimeDirectory)"
fi

# ---------------------------------------------------------------- 4. venv
say "4. installing TrustGate into a root-owned venv"
run mkdir -p "$LIB"
run chown root:"$ROOT_GROUP" "$LIB"
run chmod 0755 "$LIB"
run "$PY" -m venv "$VENV"
# Not editable: a copy, so later edits to your checkout do not change the gate.
run "$VENV/bin/pip" install --no-cache-dir --quiet "$SOURCE[guardroom]"
run chown -R root:"$ROOT_GROUP" "$VENV"
run chmod -R go-w "$VENV"
run ln -sf "$VENV/bin/trustgate" /usr/local/bin/trustgate-admin

# ---------------------------------------------------------------- 5. hook
say "5. thin hook and Claude Code managed settings"
TMP_JSON="$(mktemp)"
run "$VENV/bin/trustgate" guardroom install-hook --prod --dest "$LIB/hook.py" \
    --python "$HOOK_PY" --settings-out "$TMP_JSON"
run chown root:"$ROOT_GROUP" "$LIB/hook.py"
run chmod 0755 "$LIB/hook.py"
if [ "$MANAGED_HOOKS_ONLY" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    "$VENV/bin/python" -I -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d.pop("allowManagedHooksOnly", None); json.dump(d, open(p, "w"), indent=2)' "$TMP_JSON"
fi
# A managed settings file that is not valid JSON stops Claude Code starting.
if [ "$DRY_RUN" -eq 0 ]; then
    "$VENV/bin/python" -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$TMP_JSON"
fi
run mkdir -p "$MANAGED_DIR"
# 0644, not 0600: a root-only file is silently skipped by Claude Code.
run install -o root -g "$ROOT_GROUP" -m 0644 "$TMP_JSON" "$MANAGED_DIR/50-trustgate.json"
rm -f "$TMP_JSON"

# ---------------------------------------------------------------- 6. service
say "6. starting the daemon"
if [ "$OS" = "Darwin" ]; then
    run install -o root -g wheel -m 0644 "$HERE/macos/com.trustgate.guardroom.plist" \
        /Library/LaunchDaemons/com.trustgate.guardroom.plist
    run launchctl bootout system/com.trustgate.guardroom 2>/dev/null || true
    run launchctl bootstrap system /Library/LaunchDaemons/com.trustgate.guardroom.plist
else
    run install -o root -g root -m 0644 "$HERE/linux/trustgated.service" \
        /etc/systemd/system/trustgated.service
    run systemctl daemon-reload
    run systemctl enable --now trustgated
fi

say "checking it answers you, as a different user"
if [ "$DRY_RUN" -eq 0 ]; then
    for _ in $(seq 1 50); do [ -S "$RUN/agent.sock" ] && break; sleep 0.2; done
    ASK_AS="${SUDO_USER:-nobody}"
    STATUS="$(sudo -u "$ASK_AS" "$VENV/bin/trustgate" guardroom status --prod)"
    echo "$STATUS"
    echo "$STATUS" | grep -q '"protection_level": 1' || {
        echo "WARNING: the daemon did not report protection level 1 to $ASK_AS" >&2; exit 1; }
fi

cat <<EOF

Done. The guard room runs as $TG_USER. Next:
  * Restart Claude Code. Check /status lists the managed settings.
  * Install your own policy (asks for your password, recorded with your name):
      sudo trustgate-admin guardroom policy-install --prod --policy FILE --by "Your Name"
  * Approve a held action:
      sudo trustgate-admin guardroom resolve --prod REQUEST_ID approved --approver "Your Name"
  * Make sudo ask every time, so an agent cannot reuse your recent password:
      add 'Defaults timestamp_timeout=0' with visudo.
  * Public key, to check signatures with 'trustgate verify-audit --pubkey':
      trustgate-admin guardroom status --prod
EOF
