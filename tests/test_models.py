"""Contract tests.

These pin the wire format. If a change here needs a test edit, it is a breaking
change to every adapter and belongs in a major version.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from trustgate.core.models import (
    Action,
    ActionRequest,
    ActionType,
    Context,
    Decision,
    Effect,
    GuardResult,
    Principal,
    Reason,
    Verdict,
    combine_verdicts,
    verdict_to_effect,
)


def test_minimal_action_request_fills_defaults():
    req = ActionRequest(surface="coding", action=Action(type=ActionType.shell, tool="Bash"))

    assert req.request_id
    assert req.timestamp > 0
    assert req.principal.id == "local-user"
    assert req.principal.roles == ["developer"]
    assert req.action.params == {}
    assert req.action.raw == ""
    assert req.context.ingested_content is None
    assert req.context.turn == 0


def test_principal_defaults_are_not_shared_between_instances():
    a, b = Principal(), Principal()
    a.roles.append("admin")
    assert b.roles == ["developer"]


def test_action_request_rejects_unknown_fields():
    # Adapters must not smuggle surface-specific fields through the contract;
    # anything a guard needs belongs in `params` or `context`.
    with pytest.raises(ValidationError):
        ActionRequest(
            surface="coding",
            action=Action(type=ActionType.shell, tool="Bash"),
            sudo=True,
        )


def test_action_request_round_trips_through_json():
    req = ActionRequest(
        surface="voice",
        principal=Principal(id="agent-7", roles=["support"]),
        action=Action(
            type=ActionType.tool_call,
            tool="issue_refund",
            params={"amount": 250, "order_id": "A-1"},
            raw="issue_refund(amount=250)",
        ),
        context=Context(ingested_content="caller transcript", session_id="call-99", turn=3),
    )
    assert ActionRequest.model_validate_json(req.model_dump_json()) == req


def test_decision_round_trips_through_json():
    dec = Decision(
        request_id="r1",
        effect=Effect.escalate,
        reasons=[Reason(guard="action", rule_id="refund-limit", message="over $100")],
        obligations=["require_human_approval"],
        latency_ms=12.5,
    )
    assert Decision.model_validate_json(dec.model_dump_json()) == dec


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (Verdict.allow, Verdict.block, Verdict.block),
        (Verdict.block, Verdict.allow, Verdict.block),
        (Verdict.modify, Verdict.escalate, Verdict.escalate),
        (Verdict.escalate, Verdict.modify, Verdict.escalate),
        (Verdict.escalate, Verdict.block, Verdict.block),
        (Verdict.allow, Verdict.modify, Verdict.modify),
    ],
)
def test_precedence_is_block_escalate_modify_allow(a, b, expected):
    assert combine_verdicts(a, b) is expected


def test_uncertain_never_raises_the_verdict_on_its_own():
    # `uncertain` asks for a judgment; it must not become an enforcement outcome,
    # or a low-confidence heuristic could escalate by itself.
    assert combine_verdicts(Verdict.allow, Verdict.uncertain) is Verdict.allow
    assert combine_verdicts(Verdict.uncertain, Verdict.allow) is Verdict.allow
    assert combine_verdicts(Verdict.modify, Verdict.uncertain) is Verdict.modify
    assert verdict_to_effect(Verdict.uncertain) is Effect.allow


def test_every_verdict_maps_to_an_effect():
    for verdict in Verdict:
        assert isinstance(verdict_to_effect(verdict), Effect)


def test_guard_result_defaults_to_no_reasons():
    assert GuardResult(verdict=Verdict.allow).reasons == []
