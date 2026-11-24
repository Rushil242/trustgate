"""Phase 1, part A: the guard room daemon and the thin hook.

A real daemon on real Unix sockets, and the real thin hook run as a separate
`python3 -I` process, exactly as Claude Code would run it. These tests run in
dev mode (daemon and caller are the same OS user, protection level 0); the
separate-user case needs root and is covered by the install script's checks.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from trustgate.core.audit import AuditLedger
from trustgate.core.config import Config
from trustgate.guardroom import daemon
from trustgate.guardroom import hook as thin

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def room(tmp_path):
    """Start a daemon; yield (state, run, cfg, servers). Sockets need short paths."""
    run = Path(tempfile.mkdtemp(prefix="tg-", dir="/tmp"))
    state = tmp_path / "state"
    cfg = Config()
    servers = daemon.serve(state, run, cfg)
    yield state, run, cfg, servers
    for server in servers:
        server.shutdown()
        server.server_close()
    shutil.rmtree(run, ignore_errors=True)


def _thin_copy(tmp_path, run, fallback="deny"):
    text = Path(thin.__file__).read_text()
    text = text.replace('SOCKET = "/var/run/trustgate/agent.sock"',
                        f"SOCKET = {str(run / 'agent.sock')!r}")
    text = text.replace('FALLBACK = "deny"', f"FALLBACK = {fallback!r}")
    path = tmp_path / "hook.py"
    path.write_text(text)
    return path


def _run_hook(hook_path, tool, tool_input, mode="pretooluse", env=None, cwd=None, tid="t1"):
    payload = json.dumps({"tool_name": tool, "tool_input": tool_input, "tool_use_id": tid})
    out = subprocess.run([sys.executable, "-I", str(hook_path), mode], input=payload,
                         capture_output=True, text=True, timeout=60, env=env, cwd=cwd)
    if mode != "pretooluse":
        return None
    return json.loads(out.stdout)["hookSpecificOutput"]


def test_status_reports_dev_mode(room):
    state, run, _cfg, _ = room
    reply = daemon.request(run / "agent.sock", {"op": "status"})
    assert reply["ok"] and reply["protection_level"] == 0
    assert reply["caller_uid"] == os.geteuid() == reply["daemon_uid"]
    assert reply["policy_digest"].startswith("sha256:")


def test_file_and_socket_modes(room):
    state, run, _cfg, _ = room
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE((run / "agent.sock").stat().st_mode) == 0o666
    assert stat.S_IMODE((run / "admin.sock").stat().st_mode) == 0o600
    assert stat.S_IMODE((state / "policy.yaml").stat().st_mode) == 0o600


def test_thin_hook_decides_through_the_daemon(room, tmp_path):
    state, run, _cfg, _ = room
    hook = _thin_copy(tmp_path, run)
    assert _run_hook(hook, "Bash", {"command": "cat .env"})["permissionDecision"] == "deny"
    assert _run_hook(hook, "Bash", {"command": "npm test"})["permissionDecision"] == "allow"
    all_entries = AuditLedger(state / "audit.jsonl").read_all()
    assert all_entries[0]["kind"] == "policy_change"  # recorded at daemon start
    entries = [e for e in all_entries if e["kind"] == "decision"]
    assert [e["effect"] for e in entries] == ["block", "allow"]
    assert entries[0]["principal"]["id"] == f"unix:{os.geteuid()}"
    assert entries[0]["protection_level"] == 0
    assert AuditLedger(state / "audit.jsonl").verify().ok


def test_agent_socket_cannot_approve(room):
    _state, run, _cfg, _ = room
    reply = daemon.request(run / "agent.sock", {"op": "resolve", "request_id": "r",
                                                "outcome": "approved", "approver": "me"})
    assert not reply["ok"] and "not allowed on this socket" in reply["error"]
    reply = daemon.request(run / "agent.sock", {"op": "policy-install"})
    assert not reply["ok"]


def test_no_daemon_means_the_fallback_never_allow(tmp_path):
    run = Path(tempfile.mkdtemp(prefix="tg-", dir="/tmp"))
    try:
        prod = _thin_copy(tmp_path, run, "deny")
        assert _run_hook(prod, "Bash", {"command": "npm test"})["permissionDecision"] == "deny"
        dev = _thin_copy(tmp_path, run, "ask")
        assert _run_hook(dev, "Bash", {"command": "npm test"})["permissionDecision"] == "ask"
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_environment_cannot_redirect_the_hook(room, tmp_path):
    _state, run, _cfg, _ = room
    hook = _thin_copy(tmp_path, run)
    env = {**os.environ, "TRUSTGATE_SOCKET": "/tmp/fake.sock", "PYTHONPATH": "/tmp/evil"}
    assert _run_hook(hook, "Bash", {"command": "cat .env"}, env=env)["permissionDecision"] == "deny"


def test_a_planted_json_module_in_cwd_is_not_imported(room, tmp_path):
    _state, run, _cfg, _ = room
    hook = _thin_copy(tmp_path, run)
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "json.py").write_text("raise SystemExit('planted module ran')\n")
    shutil.copy(hook, evil / "hook.py")  # even next to the script itself
    out = _run_hook(evil / "hook.py", "Bash", {"command": "cat .env"}, cwd=evil)
    # -I (which implies -P) keeps both the cwd and the script's own folder off
    # sys.path, so the planted json.py is never imported.
    assert out["permissionDecision"] == "deny"


def test_forged_line_in_the_file_is_not_an_answer(room, tmp_path):
    state, run, cfg, servers = room
    cfg.approval.mode, cfg.approval.timeout, cfg.approval.poll_interval = "remote", 1.5, 0.05
    hook = _thin_copy(tmp_path, run)

    def forge():
        time.sleep(0.3)
        ledger = AuditLedger(state / "audit.jsonl")
        esc = [e for e in ledger.read_all() if e.get("effect") == "escalate"][-1]
        # A properly chained line, written with the public function. In dev
        # mode the agent's user can do this; the daemon must still not care.
        from trustgate.core.models import Approver, Outcome

        ledger.write_resolution(esc["request_id"], Outcome.approved,
                                Approver(id="priya", method="forged"), gated=True)

    threading.Thread(target=forge).start()
    out = _run_hook(hook, "Bash", {"command": "terraform destroy"})
    assert out["permissionDecision"] == "deny"


def test_admin_socket_approval_releases_the_wait(room, tmp_path):
    state, run, cfg, _ = room
    cfg.approval.mode, cfg.approval.timeout, cfg.approval.poll_interval = "remote", 10, 0.05
    hook = _thin_copy(tmp_path, run)

    def approve():
        for _ in range(100):
            time.sleep(0.05)
            escalations = [e for e in AuditLedger(state / "audit.jsonl").read_all()
                           if e.get("effect") == "escalate"]
            if escalations:
                reply = daemon.request(run / "admin.sock", {
                    "op": "resolve", "request_id": escalations[-1]["request_id"],
                    "outcome": "approved", "approver": "priya", "note": "CHG-1"})
                assert reply["ok"], reply
                return

    threading.Thread(target=approve).start()
    out = _run_hook(hook, "Bash", {"command": "terraform destroy"})
    assert out["permissionDecision"] == "allow" and "priya" in out["permissionDecisionReason"]
    last = AuditLedger(state / "audit.jsonl").read_all()[-1]
    assert last["approver"]["method"].startswith("guard room admin socket, OS user unix:")


def test_resolve_needs_a_name_and_a_real_outcome(room):
    _state, run, _cfg, _ = room
    bad = daemon.request(run / "admin.sock", {"op": "resolve", "request_id": "r",
                                              "outcome": "approved", "approver": " "})
    assert not bad["ok"]
    bad = daemon.request(run / "admin.sock", {"op": "resolve", "request_id": "r",
                                              "outcome": "maybe", "approver": "p"})
    assert not bad["ok"]


def test_parallel_hook_processes_keep_one_chain(room, tmp_path):
    state, run, _cfg, _ = room
    hook = _thin_copy(tmp_path, run)
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "npm test"}})
    procs = [subprocess.Popen([sys.executable, "-I", str(hook)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True) for _ in range(24)]
    for p in procs:
        p.stdin.write(payload)
        p.stdin.close()
    assert all(p.wait(timeout=60) == 0 for p in procs)
    result = AuditLedger(state / "audit.jsonl").verify()
    assert result.ok and result.entries_checked == 25  # 24 decisions + start-up policy line


def test_decision_through_the_socket_is_fast(room):
    _state, run, _cfg, _ = room
    msg = {"op": "decide", "payload": {"tool_name": "Bash", "tool_input": {"command": "ls"}}}
    daemon.request(run / "agent.sock", msg)  # warm up
    times = []
    for _ in range(40):
        t = time.perf_counter()
        daemon.request(run / "agent.sock", msg)
        times.append((time.perf_counter() - t) * 1000)
    times.sort()
    assert times[len(times) // 2] < 5, times


def test_observe_records_how_a_local_prompt_ended(room, tmp_path):
    state, run, _cfg, _ = room
    hook = _thin_copy(tmp_path, run)
    out = _run_hook(hook, "Bash", {"command": "terraform destroy"}, tid="tu-9")
    assert out["permissionDecision"] == "ask"
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "tu-9",
               "tool_input": {"command": "terraform destroy"}}
    subprocess.run([sys.executable, "-I", str(hook), "observe"], input=json.dumps(payload),
                   text=True, timeout=60, check=True)
    last = AuditLedger(state / "audit.jsonl").read_all()[-1]
    assert last["kind"] == "resolution" and last["correlation_id"] == "tu-9"


def test_bad_requests_get_an_answer_not_a_crash(room):
    _state, run, _cfg, _ = room
    import socket

    with socket.socket(socket.AF_UNIX) as conn:
        conn.connect(str(run / "agent.sock"))
        conn.sendall(b"this is not json\n")
        assert b'"ok": false' in conn.recv(4096)
    assert daemon.request(run / "agent.sock", {"op": "status"})["ok"]


def test_install_hook_bakes_the_path(tmp_path, capsys):
    from trustgate.api import cli

    dest = tmp_path / "h.py"
    assert cli.main(["guardroom", "install-hook", "--run", "/tmp/tg-run", "--dest",
                     str(dest)]) == 0
    text = dest.read_text()
    assert "SOCKET = '/tmp/tg-run/agent.sock'" in text and "FALLBACK = 'ask'" in text
    assert "os.environ" not in text
    assert "-I" in capsys.readouterr().out


def test_a_fake_observe_event_cannot_release_a_waiting_action(room, tmp_path):
    state, run, cfg, _ = room
    cfg.approval.mode, cfg.approval.timeout, cfg.approval.poll_interval = "remote", 1.5, 0.05
    hook = _thin_copy(tmp_path, run)

    def fake_observe():
        time.sleep(0.3)
        # The agent talks to agent.sock itself: "the tool ran, so it was approved".
        for event in ("PostToolUse", "PermissionRequest"):
            daemon.request(run / "agent.sock", {"op": "observe", "payload": {
                "hook_event_name": event, "tool_name": "Bash", "tool_use_id": "wait-1",
                "tool_input": {"command": "terraform destroy"}}})

    threading.Thread(target=fake_observe).start()
    out = _run_hook(hook, "Bash", {"command": "terraform destroy"}, tid="wait-1")
    assert out["permissionDecision"] == "deny", out


def test_resolve_needs_a_real_escalation(room):
    _state, run, _cfg, _ = room
    reply = daemon.request(run / "admin.sock", {"op": "resolve", "request_id": "made-up",
                                                "outcome": "approved", "approver": "p"})
    assert not reply["ok"] and "no escalation" in reply["error"]


@pytest.mark.parametrize("argv", [
    ["guardroom", "resolve", "--prod", "r1", "approved", "--approver", "p"],
    ["guardroom", "resolve", "r1", "approved", "--approver", "p", "--prod"],
    ["guardroom", "policy-install", "--prod", "--policy", "x.yaml", "--by", "p"],
    ["guardroom", "status", "--prod"],
])
def test_guardroom_cli_accepts_the_printed_orders(argv):
    # The installer prints `resolve --prod REQUEST_ID approved`; argparse used
    # to reject that order. Parse only, so no daemon is needed.
    from trustgate.api import cli

    args = cli.build_parser().parse_args(argv)
    assert args.prod and args.func is cli.cmd_guardroom


def test_resolve_needs_an_approver_name():
    from trustgate.api import cli

    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["guardroom", "resolve", "r1", "approved"])
