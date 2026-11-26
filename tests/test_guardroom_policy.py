"""Phase 1, part C: policy changes are log entries, and the pack says how isolated the gate was.

The outside review's pack row "Who can change the policy, and is that change
recorded?" said "not evidenced". With the guard room it can be.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from trustgate.core import evidence
from trustgate.core.audit import AuditLedger
from trustgate.core.config import Config
from trustgate.core.constitution import Constitution
from trustgate.guardroom import daemon

REPO = Path(__file__).resolve().parents[1]
STARTER = (REPO / "trustgate" / "policies" / "starter.coding.yaml").read_text()
EMPTY = "version: 1\nmetadata: {name: open}\nprinciples: []\n"


def _start(state):
    run = Path(tempfile.mkdtemp(prefix="tg-", dir="/tmp"))
    return run, daemon.serve(state, run, Config())


def _stop(run, servers):
    for server in servers:
        server.shutdown()
        server.server_close()
    shutil.rmtree(run, ignore_errors=True)


@pytest.fixture
def room(tmp_path):
    state = tmp_path / "state"
    run, servers = _start(state)
    yield state, run
    _stop(run, servers)


def _changes(state):
    return [e for e in AuditLedger(state / "audit.jsonl").read_all()
            if e["kind"] == "policy_change"]


def _decide(run, command):
    reply = daemon.request(run / "agent.sock", {"op": "decide", "payload": {
        "tool_name": "Bash", "tool_input": {"command": command}}})
    return reply["response"]["hookSpecificOutput"]["permissionDecision"]


def test_first_start_records_the_policy(room):
    state, _run = room
    (change,) = _changes(state)
    assert change["old_digest"] == "" and change["note"] == "first start"
    assert change["new_digest"] == Constitution.from_yaml(STARTER).digest


def test_restart_with_the_same_policy_adds_nothing(tmp_path):
    state = tmp_path / "state"
    _stop(*_start(state))
    _stop(*_start(state))
    assert len(_changes(state)) == 1


def test_an_edit_while_stopped_is_recorded_at_start(tmp_path):
    state = tmp_path / "state"
    _stop(*_start(state))
    (state / "policy.yaml").write_text(EMPTY)  # someone edits the file offline
    _stop(*_start(state))
    changes = _changes(state)
    assert len(changes) == 2 and "edited while stopped" in changes[1]["note"]


def test_policy_install_through_the_admin_socket(room):
    state, run = room
    assert _decide(run, "cat .env") == "deny"
    reply = daemon.request(run / "admin.sock", {
        "op": "policy-install", "policy_text": EMPTY, "by": "priya", "note": "CHG-7"})
    assert reply["ok"], reply
    assert _decide(run, "cat .env") == "allow"  # the new policy is in force
    change = _changes(state)[-1]
    assert change["by"] == "priya" and change["note"] == "CHG-7"
    assert change["os_uid"] is not None and change["new_digest"] == reply["new_digest"]
    assert (state / "policy.yaml").read_text() == EMPTY


def test_the_agent_socket_cannot_install_a_policy(room):
    _state, run = room
    reply = daemon.request(run / "agent.sock", {"op": "policy-install", "policy_text": EMPTY,
                                                "by": "agent"})
    assert not reply["ok"]
    assert _decide(run, "cat .env") == "deny"


@pytest.mark.parametrize(
    "message,why",
    [
        ({"policy_text": EMPTY, "by": " "}, "name the person"),
        ({"policy_text": "principles: [", "by": "p"}, "not installed"),
        ({"policy_text": "version: 1\nprinciples:\n  - id: x\n", "by": "p"}, "not installed"),
        ({"by": "p"}, "policy_text is required"),
    ],
)
def test_bad_installs_are_refused_and_the_old_policy_stays(room, message, why):
    state, run = room
    reply = daemon.request(run / "admin.sock", {"op": "policy-install", **message})
    assert not reply["ok"] and why in reply["error"]
    assert _decide(run, "cat .env") == "deny"
    assert len(_changes(state)) == 1


def test_installing_the_same_policy_writes_nothing(room):
    state, run = room
    reply = daemon.request(run / "admin.sock", {"op": "policy-install",
                                                "policy_text": STARTER, "by": "p"})
    assert reply["ok"] and reply["unchanged"]
    assert len(_changes(state)) == 1


def test_the_pack_shows_changes_and_isolation(room):
    state, run = room
    _decide(run, "npm test")
    daemon.request(run / "admin.sock", {"op": "policy-install", "policy_text": EMPTY,
                                        "by": "priya"})
    _decide(run, "npm test")

    pack = evidence.build(AuditLedger(state / "audit.jsonl"), Constitution.from_yaml(EMPTY))
    assert pack.decisions == 2  # policy lines are not counted as decisions
    assert len(pack.policy_changes) == 2
    # The change mid-period is explained by a recorded change, so no alarm about it.
    assert not any("no recorded policy change" in w for w in pack.warnings)
    assert any("protection level 0" in w for w in pack.warnings)  # dev mode is said plainly

    md = evidence.to_markdown(pack)
    assert "## Policy changes" in md and "priya" in md
    assert "same OS user, dev mode (level 0): 2" in md
    row = next(line for line in md.splitlines() if line.startswith("| Who can change"))
    assert "| evidenced |" in row
    html = evidence.to_html(pack)
    assert "Policy changes" in html and "Gate isolation" in html


def test_an_unrecorded_policy_change_is_still_flagged(tmp_path):
    from trustgate.core.engine import Engine
    from trustgate.core.models import Action, ActionRequest, ActionType

    ledger = AuditLedger(tmp_path / "a.jsonl")
    for text in (STARTER, EMPTY):
        Engine(Constitution.from_yaml(text), audit=ledger).decide(ActionRequest(
            surface="coding", action=Action(type=ActionType.shell, tool="Bash", raw="ls")))
    pack = evidence.build(ledger, Constitution.from_yaml(EMPTY))
    assert any("no recorded policy change" in w for w in pack.warnings)


def test_cli_policy_install(room, tmp_path, capsys):
    from trustgate.api import cli

    state, run = room
    new = tmp_path / "new.yaml"
    new.write_text(EMPTY)
    assert cli.main(["guardroom", "policy-install", "--run", str(run), "--policy", str(new),
                     "--by", "priya"]) == 0
    assert _changes(state)[-1]["by"] == "priya"
