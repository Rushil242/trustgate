"""The evidence pack.

This is the document a customer hands to someone else's security team, so the
tests here are mostly about honesty rather than formatting: the pack must
disclose what went wrong, must not round anything up, and must never quietly
drop an escalation nobody answered.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trustgate.core import evidence
from trustgate.core.audit import AuditLedger
from trustgate.core.constitution import Constitution
from trustgate.core.models import (
    Action,
    ActionRequest,
    ActionType,
    Approver,
    Context,
    Decision,
    Effect,
    Outcome,
    Reason,
)

POLICY = Path(__file__).resolve().parents[1] / "trustgate" / "policies" / "starter.coding.yaml"


@pytest.fixture
def ledger(tmp_path):
    return AuditLedger(tmp_path / "audit.jsonl")


def _decide(ledger, effect, raw="npm test", rule="", ts=None):
    req = ActionRequest(
        surface="coding",
        action=Action(type=ActionType.shell, tool="Bash", raw=raw),
        context=Context(correlation_id=raw),
    )
    if ts is not None:
        req.timestamp = ts
    reasons = [Reason(guard="action", rule_id=rule, message=f"{rule} fired")] if rule else []
    dec = Decision(request_id=req.request_id, effect=effect, reasons=reasons)
    return ledger.write(req, dec)


class TestCounts:
    def test_counts_every_verdict_separately(self, ledger):
        _decide(ledger, Effect.allow)
        _decide(ledger, Effect.allow)
        _decide(ledger, Effect.block, "cat .env", "protect-secrets")
        _decide(ledger, Effect.escalate, "terraform destroy", "prod-changes")

        pack = evidence.build(ledger)

        assert pack.decisions == 4
        assert pack.effects["allow"] == 2
        assert pack.effects["block"] == 1
        assert pack.effects["escalate"] == 1
        assert len(pack.blocked) == 1
        assert len(pack.escalations) == 1

    def test_resolutions_are_not_counted_as_actions(self, ledger):
        d = _decide(ledger, Effect.escalate, "terraform destroy", "prod-changes")
        ledger.write_resolution(d.request_id, Outcome.approved, Approver(id="priya"))

        pack = evidence.build(ledger)

        assert pack.decisions == 1
        assert pack.answered == 1

    def test_an_answer_outside_the_window_still_counts(self, ledger):
        """An escalation on Monday answered on Tuesday is answered, not abandoned."""
        d = _decide(ledger, Effect.escalate, "terraform destroy", "prod-changes", ts=1000)
        ledger.write_resolution(d.request_id, Outcome.approved, Approver(id="priya"))

        pack = evidence.build(ledger, start=500, end=1500)

        assert len(pack.escalations) == 1
        assert pack.answered == 1
        assert pack.open_escalations == []

    def test_actions_outside_the_window_are_excluded(self, ledger):
        _decide(ledger, Effect.allow, ts=100)
        _decide(ledger, Effect.allow, ts=5000)

        pack = evidence.build(ledger, start=1000, end=9000)
        assert pack.decisions == 1


class TestHonesty:
    def test_an_unanswered_escalation_is_disclosed(self, ledger):
        _decide(ledger, Effect.escalate, "helm rollback", "prod-changes")

        pack = evidence.build(ledger)
        assert len(pack.open_escalations) == 1

        page = evidence.to_html(pack)
        assert "Read this first" in page
        assert "never answered" in page

    def test_an_unclear_answer_is_disclosed(self, ledger):
        d = _decide(ledger, Effect.escalate, "write settings", "no-untrusted-hooks")
        ledger.write_resolution(d.request_id, Outcome.unknown, Approver(id="rushil"))

        pack = evidence.build(ledger)
        assert len(pack.unclear) == 1
        assert "could not establish" in evidence.to_html(pack)

    def test_a_broken_chain_is_shouted_about(self, ledger, tmp_path):
        _decide(ledger, Effect.allow, "npm test")
        _decide(ledger, Effect.allow, "npm build")
        path = tmp_path / "audit.jsonl"
        path.write_text(
            path.read_text(encoding="utf-8").replace("npm test", "rm -rf /"),
            encoding="utf-8",
        )

        pack = evidence.build(ledger)
        page = evidence.to_html(pack)

        assert pack.chain_ok is False
        assert "FAILED" in page
        assert "failed its integrity check" in page

    def test_the_pack_states_what_it_does_not_prove(self, ledger):
        _decide(ledger, Effect.allow)
        page = evidence.to_html(evidence.build(ledger))

        assert "What this does not prove" in page
        assert "tamper evident, not tamper proof" in page
        assert "no adapter installed" in page

    def test_authority_distinguishes_gating_from_reviewing(self, ledger):
        held = _decide(ledger, Effect.escalate, "terraform destroy", "prod-changes")
        after = _decide(ledger, Effect.escalate, "kubectl delete", "prod-changes")
        ledger.write_resolution(
            held.request_id, Outcome.approved, Approver(id="a"), gated=True
        )
        ledger.write_resolution(
            after.request_id, Outcome.approved, Approver(id="b"), gated=False
        )

        page = evidence.to_html(evidence.build(ledger))
        assert "held the action" in page
        assert "recorded afterwards" in page


class TestRendering:
    def test_html_is_self_contained(self, ledger):
        _decide(ledger, Effect.allow)
        page = evidence.to_html(evidence.build(ledger))

        # Anything fetched at open time can fail, leak a request, or be blocked
        # by the mail gateway of the company we are trying to reassure.
        assert "<script" not in page.lower()
        assert "http://" not in page.replace("http://localhost", "")
        assert "https://" not in page

    def test_action_text_is_escaped(self, ledger):
        _decide(ledger, Effect.block, "<script>alert(1)</script>", "no-destructive-shell")
        page = evidence.to_html(evidence.build(ledger))

        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;" in page

    def test_no_dates_reads_as_a_sentence_not_two_blanks(self, ledger):
        _decide(ledger, Effect.allow)
        page = evidence.to_html(evidence.build(ledger))

        assert "all recorded activity" in page
        assert "Period — to —" not in page

    def test_the_policy_rules_appear_in_full(self, ledger):
        _decide(ledger, Effect.allow)
        constitution = Constitution.from_file(POLICY)
        page = evidence.to_html(evidence.build(ledger, constitution))

        for principle in constitution.principles:
            assert principle.id in page
            # The plain English statement is the point: it explains the block to
            # a reviewer who will never read the YAML.
            assert principle.statement[:40] in page

    def test_markdown_form_carries_the_same_facts(self, ledger):
        d = _decide(ledger, Effect.escalate, "terraform destroy", "prod-changes")
        ledger.write_resolution(d.request_id, Outcome.denied, Approver(id="priya"))
        text = evidence.to_markdown(evidence.build(ledger))

        assert "terraform destroy" in text
        assert "priya" in text
        assert "denied" in text
        assert "What this does not prove" in text
        assert "Escalated: 1" in text and "Escalateed" not in text

    def test_json_form_is_machine_readable(self, ledger):
        import json

        _decide(ledger, Effect.block, "cat .env", "protect-secrets")
        data = json.loads(evidence.to_json(evidence.build(ledger)))

        assert data["decisions"] == 1
        assert data["effects"]["block"] == 1
        assert data["chain"]["ok"] is True

    def test_write_creates_the_file(self, ledger, tmp_path):
        _decide(ledger, Effect.allow)
        out = evidence.write(evidence.build(ledger), tmp_path / "sub" / "pack.html")

        assert out.is_file()
        assert out.read_text(encoding="utf-8").startswith("<!doctype html>")

    def test_an_empty_ledger_still_produces_a_valid_pack(self, ledger):
        page = evidence.to_html(evidence.build(ledger))
        assert "Nothing was blocked in this period" in page
        assert "Nothing was escalated in this period" in page
