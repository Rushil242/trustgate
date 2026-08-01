"""Audit ledger: hash chaining, tamper detection, and the redaction invariant."""

from __future__ import annotations

import json

import pytest

from trustgate.core.audit import AuditLedger
from trustgate.core.guards.secret import redact
from trustgate.core.models import Action, ActionRequest, ActionType, Decision, Effect, Reason


@pytest.fixture
def ledger(tmp_path):
    return AuditLedger(tmp_path / "audit.jsonl")


def _write(ledger, raw="ls -la", effect=Effect.allow):
    req = ActionRequest(
        surface="coding",
        action=Action(type=ActionType.shell, tool="Bash", raw=raw),
    )
    dec = Decision(request_id=req.request_id, effect=effect)
    return ledger.write(req, dec)


def test_empty_ledger_verifies():
    result = AuditLedger("/nonexistent/audit.jsonl").verify()
    assert result.ok
    assert result.entries_checked == 0


def test_first_entry_is_genesis(ledger):
    entry = _write(ledger)
    assert entry.seq == 0
    assert entry.prev_hash == ""
    assert entry.entry_hash


def test_entries_chain_and_sequence(ledger):
    entries = [_write(ledger, raw=f"echo {i}") for i in range(5)]

    assert [e.seq for e in entries] == [0, 1, 2, 3, 4]
    for prev, current in zip(entries, entries[1:], strict=False):  # offset pairing
        assert current.prev_hash == prev.entry_hash

    result = ledger.verify()
    assert result.ok
    assert result.entries_checked == 5


def test_chain_survives_a_reopened_ledger(tmp_path):
    # The hook is a fresh process per tool call, so the chain has to continue
    # correctly when the ledger is re-read from disk rather than held in memory.
    path = tmp_path / "audit.jsonl"
    first = _write(AuditLedger(path))
    second = _write(AuditLedger(path))

    assert second.seq == 1
    assert second.prev_hash == first.entry_hash
    assert AuditLedger(path).verify().ok


def test_modified_entry_is_detected(ledger):
    for i in range(3):
        _write(ledger, raw=f"echo {i}")

    lines = ledger.path.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["effect"] = "allow" if tampered["effect"] != "allow" else "block"
    lines[1] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    ledger.path.write_text("\n".join(lines) + "\n")

    result = ledger.verify()
    assert not result.ok
    assert result.broken_seq == 1
    assert "modified" in result.detail


def test_removed_entry_is_detected(ledger):
    for i in range(4):
        _write(ledger, raw=f"echo {i}")

    lines = ledger.path.read_text().splitlines()
    del lines[2]
    ledger.path.write_text("\n".join(lines) + "\n")

    result = ledger.verify()
    assert not result.ok
    assert result.broken_seq == 2


def test_appended_forgery_is_detected(ledger):
    _write(ledger)

    forged = {
        "seq": 1,
        "request_id": "forged",
        "ts": 0.0,
        "surface": "coding",
        "principal": {},
        "action_redacted": "rm -rf /",
        "effect": "allow",
        "reasons": [],
        "prev_hash": "0" * 64,
        "entry_hash": "f" * 64,
    }
    with ledger.path.open("a") as fh:
        fh.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")

    assert not ledger.verify().ok


def test_secrets_never_reach_disk(ledger):
    # The ledger is append-only and often exported; a credential written here is
    # unrecallable. This invariant is why redact() ships in R0.
    secret = "AKIAIOSFODNN7EXAMPLE"
    _write(ledger, raw=f"aws configure set aws_access_key_id {secret}")

    on_disk = ledger.path.read_text()
    assert secret not in on_disk
    assert "<REDACTED:aws_key>" in on_disk


def test_allows_are_recorded_too(ledger):
    # "What did this agent do on Tuesday" is the question auditors actually ask,
    # and a block-only log cannot answer it.
    _write(ledger, effect=Effect.allow)
    entries = ledger.read_all()
    assert len(entries) == 1
    assert entries[0]["effect"] == "allow"


def test_reasons_are_persisted(ledger):
    req = ActionRequest(
        surface="coding",
        action=Action(type=ActionType.shell, tool="Bash", raw="rm -rf /"),
    )
    dec = Decision(
        request_id=req.request_id,
        effect=Effect.block,
        reasons=[
            Reason(
                guard="action",
                rule_id="no-destructive-shell",
                message="Never run destructive shell commands.",
                severity="critical",
            )
        ],
    )
    ledger.write(req, dec)

    entry = ledger.read_all()[0]
    assert entry["reasons"][0]["rule_id"] == "no-destructive-shell"


def test_hash_is_stable_across_key_ordering(ledger):
    from trustgate.core.audit import compute_hash

    a = {"seq": 0, "effect": "allow", "surface": "coding"}
    b = {"surface": "coding", "seq": 0, "effect": "allow"}
    assert compute_hash(a, "") == compute_hash(b, "")


class TestRedact:
    @pytest.mark.parametrize(
        ("text", "marker"),
        [
            ("key=AKIAIOSFODNN7EXAMPLE", "<REDACTED:aws_key>"),
            ("token ghp_" + "a" * 36, "<REDACTED:github_pat>"),
            ("stripe sk_live_" + "b" * 24, "<REDACTED:stripe>"),
            ("psql postgres://user:pw@host/db", "<REDACTED:conn_string>"),
            ("mail alice@example.com now", "<REDACTED:email>"),
            ("ssn 123-45-6789", "<REDACTED:ssn>"),
            ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij", "<REDACTED:jwt>"),
        ],
    )
    def test_detects_known_secret_shapes(self, text, marker):
        assert marker in redact(text)

    def test_redacts_a_luhn_valid_card(self):
        assert "<REDACTED:card>" in redact("card 4111 1111 1111 1111")

    @pytest.mark.parametrize(
        "text",
        [
            "call +1 415 555 0132 today",
            "order 1234567890123456789012",
            "epoch 1735689600000",
            "commit 1234567890123456",
            "version 1.2.3-4567890123456",
        ],
    )
    def test_leaves_non_card_digit_runs_alone(self, text):
        # The v3.0 draft regex matched any 13-16 digit run, which redacts phone
        # numbers and ids. See DEVIATIONS.md #3.
        assert "<REDACTED:card>" not in redact(text)

    def test_is_a_noop_on_clean_text(self):
        clean = "npm test && git status"
        assert redact(clean) == clean

    def test_handles_empty_input(self):
        assert redact("") == ""
