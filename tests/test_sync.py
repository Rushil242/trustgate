"""The sync client, without a cloud.

The cloud side is tested in the private TrustGate Cloud project against these
same functions. These tests pin down the promises the client makes on its own:
it never raises, never blocks the agent, and never mistakes a refusal for a
network blip.
"""

from __future__ import annotations

from trustgate.core import sync
from trustgate.core.audit import AuditLedger
from trustgate.core.config import CloudConfig, Config
from trustgate.core.models import Action, ActionRequest, ActionType, Decision, Effect


def _write(ledger, raw="npm test"):
    req = ActionRequest(
        surface="coding", action=Action(type=ActionType.shell, tool="Bash", raw=raw)
    )
    return ledger.write(req, Decision(request_id=req.request_id, effect=Effect.allow))


def test_nothing_to_send_makes_no_request(tmp_path):
    calls = []
    res = sync.push(AuditLedger(tmp_path / "a.jsonl"), "http://x", "k", "m",
                    transport=lambda *a: calls.append(a) or (200, {}))
    assert res.ok and res.sent == 0 and calls == []


def test_an_unreachable_cloud_is_an_error_not_an_exception(tmp_path):
    ledger = AuditLedger(tmp_path / "a.jsonl")
    _write(ledger)
    res = sync.push(ledger, "http://x", "k", "m",
                    transport=lambda *a: (0, {"detail": "connection refused"}))
    assert not res.ok and not res.rejected
    assert "connection refused" in res.error


def test_a_failed_send_does_not_move_the_cursor(tmp_path):
    ledger = AuditLedger(tmp_path / "a.jsonl")
    _write(ledger)
    sync.push(ledger, "http://x", "k", "m", transport=lambda *a: (0, {}))
    assert sync.Cursor.for_ledger(ledger).seq == -1


def test_a_success_moves_the_cursor(tmp_path):
    ledger = AuditLedger(tmp_path / "a.jsonl")
    entry = _write(ledger)
    res = sync.push(ledger, "http://x", "k", "m", transport=lambda *a: (
        200, {"accepted": 1, "last_seq": 0, "last_hash": entry.entry_hash}))
    assert res.sent == 1
    assert sync.Cursor.for_ledger(ledger).seq == 0


def test_a_rewritten_history_is_reported_as_a_refusal(tmp_path):
    ledger = AuditLedger(tmp_path / "a.jsonl")
    _write(ledger)
    res = sync.push(ledger, "http://x", "k", "m", transport=lambda *a: (
        409, {"detail": "history rewritten", "expected_seq": 3, "rewritten": True}))
    assert res.rejected and "rewritten" in res.error


def test_the_key_is_sent_as_a_bearer_token(tmp_path):
    ledger = AuditLedger(tmp_path / "a.jsonl")
    _write(ledger)
    seen = {}
    sync.push(ledger, "http://x", "tgk_secret", "m",
              transport=lambda m, u, p, h, t: seen.update(h) or (0, {}))
    assert seen["Authorization"] == "Bearer tgk_secret"


def test_cloud_is_off_unless_url_and_key_are_both_set():
    assert not CloudConfig().enabled
    assert not CloudConfig(url="http://x").enabled
    assert CloudConfig(url="http://x", api_key="k").enabled


def test_the_key_comes_only_from_the_environment(tmp_path, monkeypatch):
    toml = tmp_path / "config.toml"
    toml.write_text('[cloud]\nurl = "http://cloud.test/"\napi_key = "tgk_in_a_file"\n')
    monkeypatch.delenv("TRUSTGATE_CLOUD_KEY", raising=False)
    cfg = Config.load(toml)
    assert cfg.cloud.url == "http://cloud.test"
    assert cfg.cloud.api_key == ""  # never read from the file

    monkeypatch.setenv("TRUSTGATE_CLOUD_KEY", "tgk_from_env")
    assert Config.load(toml).cloud.api_key == "tgk_from_env"
