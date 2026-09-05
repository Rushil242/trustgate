"""Recording how an escalation was answered.

The property under test throughout: the ledger must never claim a human
approved something unless that is actually established. Every ambiguous path
here is asserted to land on `unknown`, not on `approved`.
"""

from __future__ import annotations

import pytest

from trustgate.adapters.coding import resolution_hook
from trustgate.adapters.coding.claude_code_hook import to_action_request
from trustgate.core.audit import AuditLedger
from trustgate.core.models import (
    Action,
    ActionRequest,
    ActionType,
    Approver,
    Context,
    Decision,
    Effect,
    Outcome,
)

TOOL_USE_ID = "toolu_01ABC123"


@pytest.fixture
def ledger(tmp_path):
    return AuditLedger(tmp_path / "audit.jsonl")


def _escalate(ledger, correlation_id=TOOL_USE_ID, raw="terraform destroy"):
    req = ActionRequest(
        surface="coding",
        action=Action(type=ActionType.shell, tool="Bash", raw=raw),
        context=Context(correlation_id=correlation_id),
    )
    dec = Decision(request_id=req.request_id, effect=Effect.escalate)
    return ledger.write(req, dec)


def _payload(event, **extra):
    return {"hook_event_name": event, "tool_use_id": TOOL_USE_ID, **extra}


# --------------------------------------------------------------------------
# The ledger side
# --------------------------------------------------------------------------


class TestLedgerResolutions:
    def test_resolution_continues_the_same_chain(self, ledger):
        escalation = _escalate(ledger)
        resolution = ledger.write_resolution(
            escalation.request_id, Outcome.approved, Approver(id="priya")
        )

        assert resolution.seq == escalation.seq + 1
        assert resolution.prev_hash == escalation.entry_hash
        assert ledger.verify().ok

    def test_editing_a_resolution_breaks_verification(self, ledger, tmp_path):
        escalation = _escalate(ledger)
        ledger.write_resolution(
            escalation.request_id, Outcome.denied, Approver(id="priya")
        )

        path = tmp_path / "audit.jsonl"
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace('"denied"', '"approved"'), encoding="utf-8")

        result = ledger.verify()
        assert not result.ok
        assert "modified" in result.detail

    def test_escalation_is_open_until_answered(self, ledger):
        escalation = _escalate(ledger)
        assert len(ledger.open_escalations()) == 1

        ledger.write_resolution(
            escalation.request_id, Outcome.approved, Approver(id="priya")
        )
        assert ledger.open_escalations() == []

    def test_allowed_actions_are_never_open(self, ledger):
        req = ActionRequest(
            surface="coding", action=Action(type=ActionType.shell, tool="Bash", raw="ls")
        )
        ledger.write(req, Decision(request_id=req.request_id, effect=Effect.allow))
        assert ledger.open_escalations() == []

    def test_find_open_escalation_matches_on_correlation_id(self, ledger):
        escalation = _escalate(ledger)
        found = ledger.find_open_escalation(TOOL_USE_ID)
        assert found is not None
        assert found["request_id"] == escalation.request_id

    def test_find_open_escalation_ignores_answered_ones(self, ledger):
        escalation = _escalate(ledger)
        ledger.write_resolution(
            escalation.request_id, Outcome.approved, Approver(id="priya"), TOOL_USE_ID
        )
        assert ledger.find_open_escalation(TOOL_USE_ID) is None

    def test_blank_correlation_id_never_matches(self, ledger):
        _escalate(ledger, correlation_id="")
        assert ledger.find_open_escalation("") is None

    def test_resolution_detail_is_redacted(self, ledger):
        escalation = _escalate(ledger)
        resolution = ledger.write_resolution(
            escalation.request_id,
            Outcome.denied,
            Approver(id="priya"),
            detail="refused: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        )
        assert "AKIAIOSFODNN7EXAMPLE" not in resolution.detail
        assert "<REDACTED:aws_key>" in resolution.detail


# --------------------------------------------------------------------------
# Classifying what the surface told us
# --------------------------------------------------------------------------


class TestClassify:
    def test_execution_proves_approval(self):
        outcome, _ = resolution_hook.classify("PostToolUse", {})
        assert outcome is Outcome.approved

    def test_permission_denied_is_a_denial(self):
        outcome, detail = resolution_hook.classify(
            "PermissionDenied", {"denial_reason": "blocked by policy"}
        )
        assert outcome is Outcome.denied
        assert detail == "blocked by policy"

    @pytest.mark.parametrize(
        "error",
        [
            "The user doesn't want to proceed with this tool use.",
            "user rejected the tool call",
            "Rejected by the user",
            "TOOL USE WAS REJECTED",
        ],
    )
    def test_recognized_refusal_wording_is_a_denial(self, error):
        outcome, _ = resolution_hook.classify(
            "PostToolUseFailure", {"tool_error": error}
        )
        assert outcome is Outcome.denied

    @pytest.mark.parametrize(
        "error",
        [
            # EACCES and EPERM. The operating system says these on its own, with
            # no human involved, so filing them as a refusal would invent an
            # approval decision. Caught in an end-to-end run, not by review.
            "EACCES: permission denied, open '.claude/settings.json'",
            "Permission denied",
            "operation not permitted",
            "command not found: terrafrom",
            "exit status 1",
            "",
            "connection reset by peer",
        ],
    )
    def test_an_ordinary_failure_is_unknown_not_approved(self, error):
        outcome, detail = resolution_hook.classify(
            "PostToolUseFailure", {"tool_error": error}
        )
        assert outcome is Outcome.unknown
        assert detail == error

    def test_unfamiliar_refusal_wording_degrades_to_unknown(self):
        outcome, _ = resolution_hook.classify(
            "PostToolUseFailure", {"tool_error": "nope, not doing that"}
        )
        assert outcome is Outcome.unknown


# --------------------------------------------------------------------------
# The hook end to end
# --------------------------------------------------------------------------


class TestResolutionHook:
    def test_records_approval_against_the_escalation(self, ledger):
        escalation = _escalate(ledger)

        report = resolution_hook.record(_payload("PostToolUse"), ledger=ledger)

        assert report["recorded"] is True
        assert report["outcome"] == "approved"
        assert report["request_id"] == escalation.request_id
        assert ledger.open_escalations() == []
        assert ledger.verify().ok

    def test_records_a_denial(self, ledger):
        _escalate(ledger)
        report = resolution_hook.record(
            _payload("PermissionDenied", denial_reason="not allowed in prod"),
            ledger=ledger,
        )
        assert report["outcome"] == "denied"

    def test_writes_nothing_when_the_action_was_never_escalated(self, ledger):
        req = ActionRequest(
            surface="coding",
            action=Action(type=ActionType.shell, tool="Bash", raw="ls"),
            context=Context(correlation_id=TOOL_USE_ID),
        )
        ledger.write(req, Decision(request_id=req.request_id, effect=Effect.allow))

        before = len(ledger.read_all())
        report = resolution_hook.record(_payload("PostToolUse"), ledger=ledger)

        assert report["recorded"] is False
        assert len(ledger.read_all()) == before

    def test_ignores_events_it_does_not_handle(self, ledger):
        _escalate(ledger)
        report = resolution_hook.record(_payload("PreToolUse"), ledger=ledger)
        assert report["recorded"] is False
        assert len(ledger.open_escalations()) == 1

    def test_ignores_a_payload_with_no_tool_use_id(self, ledger):
        _escalate(ledger)
        report = resolution_hook.record({"hook_event_name": "PostToolUse"}, ledger=ledger)
        assert report["recorded"] is False

    def test_an_answer_is_recorded_only_once(self, ledger):
        _escalate(ledger)
        resolution_hook.record(_payload("PostToolUse"), ledger=ledger)
        second = resolution_hook.record(_payload("PostToolUse"), ledger=ledger)

        assert second["recorded"] is False
        kinds = [e.get("kind") for e in ledger.read_all()]
        assert kinds.count("resolution") == 1

    def test_a_broken_ledger_never_raises(self, ledger, monkeypatch):
        _escalate(ledger)
        monkeypatch.setattr(
            ledger, "find_open_escalation", lambda _: (_ for _ in ()).throw(OSError("disk"))
        )
        report = resolution_hook.record(_payload("PostToolUse"), ledger=ledger)
        assert report["recorded"] is False
        assert "disk" in report["why"]

    def test_the_method_records_how_we_know(self, ledger):
        _escalate(ledger)
        resolution_hook.record(_payload("PostToolUse"), ledger=ledger)

        resolution = ledger.read_all()[-1]
        assert "inferred" in resolution["approver"]["method"]


# --------------------------------------------------------------------------
# The join key has to survive the adapter
# --------------------------------------------------------------------------


class TestCorrelationId:
    def test_the_adapter_carries_tool_use_id_through(self):
        request = to_action_request(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "terraform destroy"},
                "tool_use_id": TOOL_USE_ID,
                "session_id": "s-1",
            }
        )
        assert request.context.correlation_id == TOOL_USE_ID

    def test_a_payload_without_one_is_still_accepted(self):
        request = to_action_request({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        assert request.context.correlation_id is None

    def test_the_ledger_persists_it(self, ledger):
        _escalate(ledger)
        assert ledger.read_all()[0]["correlation_id"] == TOOL_USE_ID


# --------------------------------------------------------------------------
# Deciding from the console
# --------------------------------------------------------------------------

fastapi = pytest.importorskip("fastapi", reason="server extra not installed")
from fastapi.testclient import TestClient  # noqa: E402

from trustgate.api.server import build_app  # noqa: E402
from trustgate.core.config import Config  # noqa: E402

POLICY = (
    __import__("pathlib").Path(__file__).resolve().parents[1]
    / "trustgate" / "policies" / "starter.coding.yaml"
)


@pytest.fixture
def api(tmp_path):
    cfg = Config()
    cfg.constitution_path = str(POLICY)
    cfg.audit_path = str(tmp_path / "audit.jsonl")
    cfg.judge.provider = "fake"
    ledger = AuditLedger(cfg.audit_path)
    with TestClient(build_app(cfg)) as client:
        yield client, ledger


class TestResolveEndpoint:
    def test_a_named_person_can_approve(self, api):
        client, ledger = api
        escalation = _escalate(ledger)

        res = client.post(
            f"/v1/escalations/{escalation.request_id}/resolve",
            json={"outcome": "approved", "approver": "priya@acme.com", "note": "planned teardown"},
        )

        assert res.status_code == 200
        body = res.json()
        assert body["outcome"] == "approved"
        assert body["approver"]["id"] == "priya@acme.com"
        assert body["detail"] == "planned teardown"
        assert ledger.open_escalations() == []
        assert ledger.verify().ok

    def test_a_console_decision_did_not_hold_the_action(self, api):
        client, ledger = api
        escalation = _escalate(ledger)
        res = client.post(
            f"/v1/escalations/{escalation.request_id}/resolve",
            json={"outcome": "denied", "approver": "priya"},
        )
        assert res.json()["gated"] is False

    def test_an_observed_answer_did_hold_the_action(self, ledger):
        _escalate(ledger)
        resolution_hook.record(_payload("PostToolUse"), ledger=ledger)
        assert ledger.read_all()[-1]["gated"] is True

    def test_an_unsigned_decision_is_refused(self, api):
        client, ledger = api
        escalation = _escalate(ledger)
        res = client.post(
            f"/v1/escalations/{escalation.request_id}/resolve",
            json={"outcome": "approved", "approver": "   "},
        )
        assert res.status_code == 422
        assert len(ledger.open_escalations()) == 1

    @pytest.mark.parametrize("outcome", ["unknown", "expired"])
    def test_a_person_may_only_approve_or_deny(self, api, outcome):
        client, ledger = api
        escalation = _escalate(ledger)
        res = client.post(
            f"/v1/escalations/{escalation.request_id}/resolve",
            json={"outcome": outcome, "approver": "priya"},
        )
        assert res.status_code == 422
        assert len(ledger.open_escalations()) == 1

    def test_answering_twice_conflicts(self, api):
        client, ledger = api
        escalation = _escalate(ledger)
        payload = {"outcome": "approved", "approver": "priya"}
        url = f"/v1/escalations/{escalation.request_id}/resolve"
        assert client.post(url, json=payload).status_code == 200
        assert client.post(url, json=payload).status_code == 409

    def test_an_unknown_escalation_is_not_found(self, api):
        client, _ = api
        res = client.post(
            "/v1/escalations/no-such-request/resolve",
            json={"outcome": "approved", "approver": "priya"},
        )
        assert res.status_code == 404
