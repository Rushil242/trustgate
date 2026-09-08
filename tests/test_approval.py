"""Holding an action until a named person answers.

One property matters more than the rest and every test here is arranged around
it: silence never becomes approval. A wait that ends without an answer must
refuse, and it must leave a record saying so.
"""

from __future__ import annotations

import pytest

from trustgate.adapters.coding import claude_code_hook
from trustgate.adapters.coding.install import (
    DEFAULT_HOOK_TIMEOUT,
    TIMEOUT_MARGIN,
    gate_timeout,
    merge_settings,
)
from trustgate.core.approval import ApprovalResult, wait_for_decision
from trustgate.core.audit import AuditLedger
from trustgate.core.config import Config
from trustgate.core.models import Approver, Outcome

POLICY = (
    __import__("pathlib").Path(__file__).resolve().parents[1]
    / "trustgate" / "policies" / "starter.coding.yaml"
)
ESCALATING_COMMAND = "terraform destroy -auto-approve"


@pytest.fixture
def ledger(tmp_path):
    return AuditLedger(tmp_path / "audit.jsonl")


@pytest.fixture
def remote_config(tmp_path):
    cfg = Config()
    cfg.constitution_path = str(POLICY)
    cfg.audit_path = str(tmp_path / "audit.jsonl")
    cfg.judge.enabled = False
    cfg.approval.mode = "remote"
    cfg.approval.timeout = 30.0
    cfg.approval.poll_interval = 0.5
    return cfg


class FakeClock:
    """A clock the test drives, so a 3 minute wait takes no real time."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


# --------------------------------------------------------------------------
# The wait itself
# --------------------------------------------------------------------------


class TestWaitForDecision:
    def test_an_answer_already_present_returns_at_once(self, ledger):
        ledger.write_resolution(
            "req-1", Outcome.approved, Approver(id="priya", method="console")
        )
        clock = FakeClock()

        result = wait_for_decision(
            ledger, "req-1", timeout=60, _clock=clock, _sleep=clock.sleep
        )

        assert result.approved
        assert result.approver == "priya"
        assert not result.timed_out
        assert clock.now == 0.0  # never slept

    def test_an_answer_arriving_later_is_picked_up(self, ledger):
        clock = FakeClock()
        calls = {"n": 0}

        def sleep(seconds):
            clock.sleep(seconds)
            calls["n"] += 1
            if calls["n"] == 3:
                ledger.write_resolution(
                    "req-1", Outcome.denied, Approver(id="sam", method="console")
                )

        result = wait_for_decision(
            ledger, "req-1", timeout=60, poll_interval=1, _clock=clock, _sleep=sleep
        )

        assert result.outcome is Outcome.denied
        assert result.approver == "sam"
        assert not result.approved
        assert not result.timed_out

    def test_nobody_answering_times_out_and_is_not_an_approval(self, ledger):
        clock = FakeClock()

        result = wait_for_decision(
            ledger, "req-1", timeout=10, poll_interval=1, _clock=clock, _sleep=clock.sleep
        )

        assert result.timed_out
        assert result.outcome is Outcome.expired
        assert not result.approved

    def test_a_timeout_leaves_a_record(self, ledger):
        clock = FakeClock()
        wait_for_decision(
            ledger, "req-1", timeout=10, poll_interval=1, _clock=clock, _sleep=clock.sleep
        )

        entry = ledger.read_all()[-1]
        assert entry["kind"] == "resolution"
        assert entry["outcome"] == "expired"
        assert entry["approver"]["id"] == "nobody"
        # It did hold the action, and the answer was that nobody gave one.
        assert entry["gated"] is True
        assert ledger.verify().ok

    def test_the_expiry_record_can_be_suppressed(self, ledger):
        clock = FakeClock()
        wait_for_decision(
            ledger,
            "req-1",
            timeout=10,
            poll_interval=1,
            record_expiry=False,
            _clock=clock,
            _sleep=clock.sleep,
        )
        assert ledger.read_all() == []

    def test_an_unreadable_outcome_is_not_an_approval(self, ledger, tmp_path):
        ledger.write_resolution("req-1", Outcome.approved, Approver(id="priya"))
        path = tmp_path / "audit.jsonl"
        path.write_text(
            path.read_text(encoding="utf-8").replace('"approved"', '"yes-go-ahead"'),
            encoding="utf-8",
        )

        result = wait_for_decision(ledger, "req-1", timeout=1)
        assert result.outcome is Outcome.unknown
        assert not result.approved

    @pytest.mark.parametrize(
        "outcome,expected",
        [
            (Outcome.approved, True),
            (Outcome.denied, False),
            (Outcome.expired, False),
            (Outcome.unknown, False),
        ],
    )
    def test_only_an_explicit_approval_counts_as_approved(self, outcome, expected):
        assert ApprovalResult(outcome=outcome).approved is expected


# --------------------------------------------------------------------------
# The hook, in remote mode
# --------------------------------------------------------------------------


def _payload(command=ESCALATING_COMMAND, tool_use_id="tu-1"):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": tool_use_id,
    }


def _permission(response):
    return response["hookSpecificOutput"]["permissionDecision"]


class TestHookRemoteMode:
    def test_local_mode_still_delegates_to_the_local_prompt(self, remote_config):
        remote_config.approval.mode = "local"
        response = claude_code_hook.decide(_payload(), config=remote_config)
        assert _permission(response) == "ask"

    def test_an_approval_in_the_console_lets_the_action_run(self, remote_config, monkeypatch):
        monkeypatch.setattr(
            claude_code_hook,
            "_await_remote_decision",
            lambda decision, cfg: claude_code_hook._response("allow", "approved by priya"),
        )
        response = claude_code_hook.decide(_payload(), config=remote_config)
        assert _permission(response) == "allow"

    def test_a_denial_in_the_console_blocks_it(self, remote_config, monkeypatch):
        from trustgate.core.approval import ApprovalResult as R

        monkeypatch.setattr(
            "trustgate.core.approval.wait_for_decision",
            lambda *a, **k: R(outcome=Outcome.denied, approver="priya"),
        )
        response = claude_code_hook.decide(_payload(), config=remote_config)
        assert _permission(response) == "deny"
        assert "priya" in response["hookSpecificOutput"]["permissionDecisionReason"]

    def test_nobody_answering_blocks_by_default(self, remote_config, monkeypatch):
        from trustgate.core.approval import ApprovalResult as R

        monkeypatch.setattr(
            "trustgate.core.approval.wait_for_decision",
            lambda *a, **k: R(outcome=Outcome.expired, timed_out=True),
        )
        response = claude_code_hook.decide(_payload(), config=remote_config)
        assert _permission(response) == "deny"
        assert "Silence is not approval" in (
            response["hookSpecificOutput"]["permissionDecisionReason"]
        )

    def test_falling_back_to_the_local_prompt_is_opt_in(self, remote_config, monkeypatch):
        from trustgate.core.approval import ApprovalResult as R

        remote_config.approval.on_timeout = "ask"
        monkeypatch.setattr(
            "trustgate.core.approval.wait_for_decision",
            lambda *a, **k: R(outcome=Outcome.expired, timed_out=True),
        )
        response = claude_code_hook.decide(_payload(), config=remote_config)
        assert _permission(response) == "ask"

    def test_a_broken_approval_queue_blocks_rather_than_passes(
        self, remote_config, monkeypatch
    ):
        def explode(*a, **k):
            raise OSError("queue unreachable")

        monkeypatch.setattr("trustgate.core.approval.wait_for_decision", explode)
        response = claude_code_hook.decide(_payload(), config=remote_config)
        assert _permission(response) == "deny"

    def test_an_allowed_action_never_waits(self, remote_config, monkeypatch):
        def explode(*a, **k):
            raise AssertionError("must not wait on an action nobody escalated")

        monkeypatch.setattr("trustgate.core.approval.wait_for_decision", explode)
        response = claude_code_hook.decide(_payload(command="npm test"), config=remote_config)
        assert _permission(response) == "allow"

    def test_a_blocked_action_never_waits(self, remote_config, monkeypatch):
        def explode(*a, **k):
            raise AssertionError("must not wait on an action that is already refused")

        monkeypatch.setattr("trustgate.core.approval.wait_for_decision", explode)
        response = claude_code_hook.decide(_payload(command="rm -rf /"), config=remote_config)
        assert _permission(response) == "deny"


# --------------------------------------------------------------------------
# The installer has to give the hook room to wait
# --------------------------------------------------------------------------


class TestGateTimeout:
    def test_local_mode_keeps_the_short_budget(self, remote_config):
        remote_config.approval.mode = "local"
        assert gate_timeout(remote_config) == DEFAULT_HOOK_TIMEOUT

    def test_remote_mode_outlasts_the_approval_window(self, remote_config):
        remote_config.approval.timeout = 180.0
        assert gate_timeout(remote_config) == 180 + TIMEOUT_MARGIN

    def test_the_gate_gets_the_long_budget_and_bookkeeping_does_not(
        self, tmp_path, remote_config
    ):
        remote_config.approval.timeout = 120.0
        merged, _ = merge_settings({}, tmp_path, remote_config)

        gate = merged["hooks"]["PreToolUse"][0]["hooks"][0]
        bookkeeping = merged["hooks"]["PostToolUse"][0]["hooks"][0]

        assert gate["timeout"] == 120 + TIMEOUT_MARGIN
        assert bookkeeping["timeout"] == DEFAULT_HOOK_TIMEOUT


# --------------------------------------------------------------------------
# Config plumbing
# --------------------------------------------------------------------------


class TestApprovalConfig:
    def test_local_is_the_default(self):
        assert Config().approval.mode == "local"
        assert Config().approval.is_remote is False

    def test_deny_is_the_default_on_timeout(self):
        assert Config().approval.on_timeout == "deny"

    def test_environment_can_switch_it_on(self, monkeypatch):
        monkeypatch.setenv("TRUSTGATE_APPROVAL_MODE", "remote")
        monkeypatch.setenv("TRUSTGATE_APPROVAL_TIMEOUT", "45")
        cfg = Config.load()
        assert cfg.approval.is_remote
        assert cfg.approval.timeout == 45.0

    def test_a_junk_timeout_is_ignored_rather_than_crashing_the_hook(self, monkeypatch):
        monkeypatch.setenv("TRUSTGATE_APPROVAL_TIMEOUT", "soon")
        assert Config.load().approval.timeout == 180.0
