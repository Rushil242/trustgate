"""Phase 1, part D: installing the guard room as its own OS user.

The real install needs root, so these tests check everything that can be
checked without it: the service files are valid and agree with the paths the
code uses, the installer's every step (dry run, both OSes), the managed
settings it writes, and that the production hook refuses when no daemon answers.
"""

from __future__ import annotations

import json
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from trustgate.api import cli

REPO = Path(__file__).resolve().parents[1]
DEPLOY = REPO / "deploy"
SCRIPT = DEPLOY / "install-guardroom.sh"


def _dry(*args, os_name=None):
    env = {**os.environ}
    if os_name:
        env["TG_PREVIEW_OS"] = os_name
    out = subprocess.run(["bash", str(SCRIPT), "--dry-run", *args], capture_output=True,
                         text=True, env=env, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout


def test_script_syntax():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


@pytest.mark.skipif(shutil.which("plutil") is None, reason="macOS only")
def test_plist_is_valid():
    subprocess.run(["plutil", "-lint", str(DEPLOY / "macos/com.trustgate.guardroom.plist")],
                   check=True, capture_output=True)


def test_plist_matches_the_code():
    plist = plistlib.loads((DEPLOY / "macos/com.trustgate.guardroom.plist").read_bytes())
    state, _run = cli.prod_dirs("darwin")
    assert plist["UserName"] == "_trustgate"
    assert plist["ProgramArguments"][1:] == ["guardroom", "serve", "--prod"]
    assert plist["EnvironmentVariables"]["TRUSTGATE_HOME"] == str(state)
    assert plist["Umask"] == 0o077 and plist["KeepAlive"] is True


def test_systemd_unit_matches_the_code():
    unit = (DEPLOY / "linux/trustgated.service").read_text()
    state, run = cli.prod_dirs("linux")
    assert "User=trustgate" in unit and "NoNewPrivileges=yes" in unit
    assert f"ReadWritePaths={state} {run}" in unit
    assert f"Environment=TRUSTGATE_HOME={state}" in unit
    assert "StateDirectoryMode=0700" in unit and "RuntimeDirectoryMode=0755" in unit
    assert "guardroom serve --prod" in unit


def test_macos_dry_run_steps():
    out = _dry(os_name="Darwin")
    state, run = cli.prod_dirs("darwin")
    flat = out.replace("\\ ", " ")
    assert "dscl . -create /Users/_trustgate" in flat or "exists: _trustgate" in flat
    for step in ("chmod 0700", "launchctl bootstrap system",
                 "managed-settings.d/50-trustgate.json", "-m 0644", "--settings-out",
                 "guardroom install-hook --prod"):
        assert step in out.replace("\\ ", " "), step


def test_linux_dry_run_steps():
    out = _dry(os_name="Linux")
    for step in ("useradd --system", "systemctl enable --now trustgated",
                 "/etc/claude-code/managed-settings.d/50-trustgate.json",
                 "trustgated.service"):
        assert step in out, step


def test_uninstall_never_deletes_the_log():
    for os_name in ("Darwin", "Linux"):
        out = _dry("--uninstall", os_name=os_name)
        state, _ = cli.prod_dirs(os_name.lower())
        removed = [line for line in out.splitlines() if line.startswith("+ rm")]
        assert removed and not any("state" in r or "/var/lib/trustgate" in r for r in removed)
        assert "Kept:" in out


def test_installer_refuses_without_root_unless_dry_run():
    if os.geteuid() == 0:
        pytest.skip("running as root")
    out = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 1 and "sudo" in out.stderr


def test_prod_hook_and_managed_settings(tmp_path):
    dest, settings = tmp_path / "hook.py", tmp_path / "managed.json"
    assert cli.main(["guardroom", "install-hook", "--prod", "--dest", str(dest),
                     "--python", "/usr/bin/python3", "--settings-out", str(settings)]) == 0
    data = json.loads(settings.read_text())
    assert data["allowManagedHooksOnly"] is True
    assert data["permissions"]["disableBypassPermissionsMode"] == "disable"
    pre = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert pre == f"/usr/bin/python3 -I {dest} pretooluse"
    assert set(data["hooks"]) == {"PreToolUse", "PostToolUse", "PostToolUseFailure",
                                  "PermissionDenied"}
    _state, run = cli.prod_dirs()
    text = dest.read_text()
    assert f"SOCKET = {str(run / 'agent.sock')!r}" in text and "FALLBACK = 'deny'" in text

    # No daemon is running at that path in this test: the production hook refuses.
    out = subprocess.run([sys.executable, "-I", str(dest), "pretooluse"],
                         input=json.dumps({"tool_name": "Bash",
                                           "tool_input": {"command": "ls"}}),
                         capture_output=True, text=True, timeout=30)
    if not (run / "agent.sock").exists():
        assert json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_the_agent_cannot_run_guardroom_commands_itself(tmp_path, monkeypatch):
    from trustgate.adapters.coding.claude_code_hook import decide
    from trustgate.core.config import Config

    monkeypatch.setenv("TRUSTGATE_HOME", str(tmp_path / "home"))
    cfg = Config()
    cfg.constitution_path = str(REPO / "trustgate/policies/starter.coding.yaml")
    cfg.audit_path = str(tmp_path / "a.jsonl")
    for command in ("sudo trustgate-admin guardroom resolve --prod r1 approved --approver me",
                    "trustgate guardroom policy-install --prod --policy p.yaml --by me",
                    "cat '/Library/Application Support/ClaudeCode/managed-settings.json'",
                    "rm /etc/claude-code/managed-settings.d/50-trustgate.json"):
        out = decide({"tool_name": "Bash", "tool_input": {"command": command}}, config=cfg)
        assert out["hookSpecificOutput"]["permissionDecision"] in ("ask", "deny"), command


def test_installer_checks_who_can_write_not_just_the_owner():
    text = SCRIPT.read_text()
    # python.org installs are root-owned but admin-writable; the owner test alone passed them.
    assert "-perm -g+w" in text and "--lock-python" in text
    assert 'PY="$REAL_PY"' in text  # never build the venv through a swappable symlink
    assert 'HOOK_PY="${HOOK_PY:-$PY}"' in text  # the hook runs on the same checked Python


def test_lock_python_dry_run_shows_the_lock_steps():
    out = _dry("--lock-python", os_name="Darwin")
    if "checks skipped" in out:
        pytest.skip("no Python 3.11+ in a system location on this machine")
    assert "chmod -R go-w" in out or "ok: only root can change" in out
