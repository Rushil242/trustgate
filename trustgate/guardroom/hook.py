"""TrustGate thin hook. Standard library only. Run with `python3 -I`.

The installer copies this file and replaces SOCKET and FALLBACK below. In
production the copy is owned by root and named in Claude Code's managed
settings, so the agent can neither edit it nor point it somewhere else.

The socket path is a constant on purpose, not an environment variable: the
agent can write `~/.zshrc`, and an environment variable read here would let it
aim the next session at a fake daemon that says yes to everything.

    python3 -I hook.py pretooluse   decide; prints the PreToolUse answer
    python3 -I hook.py observe      after a tool ran or was refused; never blocks
"""

import json
import socket
import sys
import time

SOCKET = "/var/run/trustgate/agent.sock"
FALLBACK = "deny"  # "ask" only in dev mode; never "allow"


def _answer(permission, reason):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": permission,
                                   "permissionDecisionReason": reason}}


def _ask_daemon(op, payload):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.settimeout(5)
        for attempt in range(5):  # a busy daemon can refuse for a moment
            try:
                conn.connect(SOCKET)
                break
            except (BlockingIOError, ConnectionRefusedError):
                if attempt == 4:
                    raise
                conn.close()
                time.sleep(0.05 * (attempt + 1))
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                conn.settimeout(5)
        conn.settimeout(None)  # a decision may wait for a person
        conn.sendall(json.dumps({"op": op, "payload": payload}).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        return json.loads(data)
    finally:
        conn.close()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "pretooluse"
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = None
    if mode != "pretooluse":
        try:
            _ask_daemon("observe", payload)
        except (OSError, ValueError):
            pass
        return 0
    try:
        reply = _ask_daemon("decide", payload)
        out = reply["response"]["hookSpecificOutput"]
        if out["permissionDecision"] not in ("allow", "deny", "ask"):
            raise ValueError("unknown decision")
        print(json.dumps(reply["response"]))
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps(_answer(FALLBACK, "TrustGate guard room did not answer, so this "
                                 "action was not checked. It is refused until it answers.")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
