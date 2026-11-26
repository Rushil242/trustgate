"""Phase 1, part B: signed ledger entries (version 2).

The review's exp3-5: a chain needs no secret, so a line written with the
public function verified fine. With a machine key, it no longer does.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from trustgate.core.audit import AuditLedger, check_canonical, compute_hash, hashed_body
from trustgate.core.evidence import build
from trustgate.core.models import (
    Action,
    ActionRequest,
    ActionType,
    Approver,
    AuditEntry,
    Decision,
    Effect,
    Outcome,
)
from trustgate.core.signing import Signer, check_signature, key_id_for

VECTORS = json.loads((Path(__file__).parent / "vectors" / "ledger_v2.json").read_text())


def _req(raw="npm test"):
    return ActionRequest(surface="coding",
                         action=Action(type=ActionType.shell, tool="Bash", raw=raw))


def _write(ledger, raw="npm test", effect=Effect.allow):
    req = _req(raw)
    return ledger.write(req, Decision(request_id=req.request_id, effect=effect))


@pytest.fixture
def signer(tmp_path):
    return Signer.load_or_create(tmp_path / "machine.key")


def _keys(signer):
    return {signer.key_id: signer.public_b64}


# -- the format, pinned by fixed vectors --------------------------------------


def test_vectors_reproduce_exactly():
    signer = Signer.from_seed(bytes.fromhex(VECTORS["seed_hex"]))
    assert signer.public_b64 == VECTORS["public_key_b64"]
    assert key_id_for(base64.b64decode(VECTORS["public_key_b64"])) == VECTORS["key_id"]

    prev = ""
    for entry in VECTORS["entries"]:
        assert compute_hash(hashed_body(entry), prev) == entry["entry_hash"]
        assert check_signature(VECTORS["public_key_b64"], entry["entry_hash"], entry["sig"])
        prev = entry["entry_hash"]

    canonical = VECTORS["canonical_bytes_of_entry_0"]
    first = VECTORS["entries"][0]
    assert json.dumps(hashed_body(first), sort_keys=True, separators=(",", ":")) == canonical
    assert "\\u00e9" in canonical  # non-ASCII is escaped, as the spec says
    digest = hashlib.sha256((canonical + "").encode("utf-8")).hexdigest()
    assert digest == first["entry_hash"]


def test_vector_file_is_a_valid_signed_ledger(tmp_path):
    path = tmp_path / "v.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in VECTORS["entries"]))
    keys = {VECTORS["key_id"]: VECTORS["public_key_b64"]}
    assert AuditLedger(path).verify(public_keys=keys).ok


# -- writing ------------------------------------------------------------------


def test_signed_entries_are_integers_only_and_verify(tmp_path, signer):
    ledger = AuditLedger(tmp_path / "a.jsonl", signer=signer)
    _write(ledger)
    req = _req("terraform destroy")
    ledger.write(req, Decision(request_id=req.request_id, effect=Effect.escalate))
    ledger.write_resolution(req.request_id, Outcome.denied, Approver(id="p", method="m"))

    for entry in ledger.read_all():
        assert entry["v"] == 2 and entry["key_id"] == signer.key_id and entry["sig"]
        assert "ts" not in entry and isinstance(entry["ts_ms"], int)
        check_canonical(hashed_body(entry))
    result = ledger.verify(public_keys=_keys(signer))
    assert result.ok and "3 signatures verified" in result.detail
    assert "not checked" in ledger.verify().detail


def test_models_read_version_2_times():
    entry = dict(VECTORS["entries"][0])
    assert AuditEntry.model_validate(entry).ts == 1764000000.0


def test_key_file_is_private_and_reused(tmp_path):
    first = Signer.load_or_create(tmp_path / "k.pem")
    assert oct((tmp_path / "k.pem").stat().st_mode & 0o777) == "0o600"
    assert Signer.load_or_create(tmp_path / "k.pem").key_id == first.key_id


def test_a_float_in_a_signed_entry_is_refused(tmp_path, signer):
    ledger = AuditLedger(tmp_path / "a.jsonl", signer=signer)
    req = _req()
    with pytest.raises(ValueError, match="float"):
        ledger.write(req, Decision(request_id=req.request_id, effect=Effect.allow),
                     stamps={"score": 0.5})


# -- attacks -----------------------------------------------------------------


def test_exp3_5_a_chained_forgery_without_the_key_fails(tmp_path, signer):
    path = tmp_path / "a.jsonl"
    ledger = AuditLedger(path, signer=signer)
    req = _req("terraform destroy")
    ledger.write(req, Decision(request_id=req.request_id, effect=Effect.escalate))

    # The attacker uses the public function, with no key: an unsigned line.
    AuditLedger(path).write_resolution(req.request_id, Outcome.approved,
                                       Approver(id="priya", method="forged"))
    result = AuditLedger(path).verify()
    assert not result.ok and "unsigned entry after signed entries" in result.detail


def test_a_forgery_signed_with_another_key_fails(tmp_path, signer):
    path = tmp_path / "a.jsonl"
    AuditLedger(path, signer=signer)
    _write(AuditLedger(path, signer=signer))
    attacker = Signer.load_or_create(tmp_path / "attacker.key")
    _write(AuditLedger(path, signer=attacker))
    assert AuditLedger(path).verify().ok  # without keys, only the chain is checked
    result = AuditLedger(path).verify(public_keys=_keys(signer))
    assert not result.ok and "unknown key" in result.detail


def test_an_edited_signed_entry_fails(tmp_path, signer):
    path = tmp_path / "a.jsonl"
    ledger = AuditLedger(path, signer=signer)
    _write(ledger, "cat .env", Effect.block)
    entry = json.loads(path.read_text())
    entry["effect"] = "allow"
    entry["entry_hash"] = compute_hash(hashed_body(entry), "")  # re-hash, cannot re-sign
    path.write_text(json.dumps(entry) + "\n")
    result = AuditLedger(path).verify(public_keys=_keys(signer))
    assert not result.ok and "signature does not match" in result.detail


def test_a_stripped_signature_fails(tmp_path, signer):
    path = tmp_path / "a.jsonl"
    _write(AuditLedger(path, signer=signer))
    entry = json.loads(path.read_text())
    del entry["sig"]
    path.write_text(json.dumps(entry) + "\n")
    assert "without a signature" in AuditLedger(path).verify().detail


def test_evidence_pack_reads_version_2(tmp_path, signer):
    ledger = AuditLedger(tmp_path / "a.jsonl", signer=signer)
    _write(ledger, "cat .env", Effect.block)
    pack = build(ledger)
    assert pack.decisions == 1 and pack.blocked
    from trustgate.core.evidence import to_markdown

    assert "1970" not in to_markdown(pack)  # the time is read from ts_ms


def test_verify_audit_cli_with_a_public_key(tmp_path, signer, capsys):
    from trustgate.api import cli

    path = tmp_path / "a.jsonl"
    _write(AuditLedger(path, signer=signer))
    assert cli.main(["verify-audit", "-a", str(path), "--pubkey", signer.public_b64]) == 0
    assert "1 signatures verified" in capsys.readouterr().out
    other = Signer.load_or_create(tmp_path / "o.key")
    assert cli.main(["verify-audit", "-a", str(path), "--pubkey", other.public_b64]) == 2


def test_verify_with_a_key_reports_unsigned_entries(tmp_path, signer):
    path = tmp_path / "a.jsonl"
    _write(AuditLedger(path))  # written before signing began
    _write(AuditLedger(path, signer=signer))
    result = AuditLedger(path).verify(public_keys=_keys(signer))
    assert result.ok and "1 unsigned entries" in result.detail
