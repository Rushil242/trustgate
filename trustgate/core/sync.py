"""Shipping the local ledger to TrustGate Cloud.

The local ledger proves a record was not *edited*. It cannot prove a record was
not *deleted*: truncate the file and the shorter chain still verifies. A copy
held by someone other than the person being audited closes that gap, because
the cloud already has the lines that went missing and will refuse a history
that disagrees with them.

Sync reads the ledger file rather than hooking the engine, on purpose. The
engine runs on every agent action and must never wait on a network. Reading the
file afterwards means a slow or absent cloud costs the agent nothing: entries
queue up on disk, exactly as they always have, and go out when they can.

Stdlib only (urllib), so the core stays free of HTTP dependencies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trustgate.core.audit import AuditLedger

# (method, url, payload or None, headers, timeout) -> (status, parsed body)
Transport = Callable[[str, str, dict | None, dict, float], tuple[int, dict]]


def urllib_transport(
    method: str, url: str, payload: dict | None, headers: dict, timeout: float
) -> tuple[int, dict]:
    """Default transport. Turns every failure into a status code, never raises."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read().decode("utf-8") or "{}"
            return resp.status, json.loads(body)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8") or "{}")
        except (ValueError, OSError):
            return exc.code, {}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return 0, {"detail": f"could not reach the cloud: {exc}"}


@dataclass
class Cursor:
    """How far this machine has already shipped. Stored next to the ledger.

    Losing it is harmless: the cloud reports where it is up to and sync resumes
    from there. Its only job is to avoid re-sending the whole file every time.
    """

    path: Path
    seq: int = -1
    entry_hash: str = ""

    @classmethod
    def for_ledger(cls, ledger: AuditLedger) -> Cursor:
        path = ledger.path.with_name(ledger.path.name + ".sync-cursor.json")
        cur = cls(path=path)
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                cur.seq = int(data.get("seq", -1))
                cur.entry_hash = str(data.get("entry_hash", ""))
            except (ValueError, OSError):
                pass
        return cur

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"seq": self.seq, "entry_hash": self.entry_hash}), encoding="utf-8"
        )


@dataclass
class SyncResult:
    sent: int = 0
    up_to_seq: int = -1
    error: str = ""
    rejected: bool = False
    """The cloud refused this machine's history. Not a network blip: it means
    the local ledger disagrees with lines the cloud already holds."""

    @property
    def ok(self) -> bool:
        return not self.error


def push(
    ledger: AuditLedger,
    url: str,
    api_key: str,
    machine: str,
    batch_size: int = 200,
    timeout: float = 5.0,
    transport: Transport = urllib_transport,
    _resynced: bool = False,
) -> SyncResult:
    """Send every entry the cloud does not have yet. Never raises."""
    result = SyncResult()
    cursor = Cursor.for_ledger(ledger)
    result.up_to_seq = cursor.seq

    try:
        entries = ledger.read_all()
    except (OSError, ValueError) as exc:
        result.error = f"could not read the ledger: {exc}"
        return result

    pending = [e for e in entries if int(e.get("seq", -1)) > cursor.seq]
    if not pending:
        return result

    headers = {"Authorization": f"Bearer {api_key}"}
    endpoint = url.rstrip("/") + "/v1/ingest"

    for start in range(0, len(pending), max(batch_size, 1)):
        batch = pending[start : start + batch_size]
        status, body = transport(
            "POST", endpoint, {"machine": machine, "entries": batch}, headers, timeout
        )

        if status == 200:
            cursor.seq = int(body.get("last_seq", batch[-1]["seq"]))
            cursor.entry_hash = str(body.get("last_hash", batch[-1].get("entry_hash", "")))
            cursor.save()
            result.sent += int(body.get("accepted", len(batch)))
            result.up_to_seq = cursor.seq
            continue

        expected = body.get("expected_seq")
        if status == 409 and expected is not None and not _resynced and not body.get("rewritten"):
            # The cloud is somewhere other than our cursor thinks: usually a
            # lost cursor file or a lost response. Move to where it is, once.
            cursor.seq = int(expected) - 1
            cursor.entry_hash = str(body.get("last_hash", ""))
            cursor.save()
            again = push(
                ledger, url, api_key, machine, batch_size, timeout, transport, _resynced=True
            )
            again.sent += result.sent
            return again

        result.error = str(body.get("detail") or f"cloud returned HTTP {status}")
        result.rejected = status == 409
        return result

    return result


class CloudResolutions:
    """Asks the cloud whether a reviewer has answered an escalation.

    Shaped like the part of `AuditLedger` that `wait_for_decision` uses, so the
    wait can poll a fleet-wide inbox instead of a local file without the wait
    itself knowing the difference. Every network failure reads as "no answer
    yet", which keeps waiting, and a wait that never gets an answer expires
    into a refusal. Nothing here can turn an outage into an approval.
    """

    def __init__(self, cfg_cloud, ledger: AuditLedger, transport: Transport = urllib_transport):
        self.cloud = cfg_cloud
        self.ledger = ledger
        self.transport = transport
        self.uploaded = False

    def _ensure_uploaded(self) -> None:
        # A reviewer cannot answer an escalation the cloud has never seen.
        if self.uploaded:
            return
        res = push(
            self.ledger,
            self.cloud.url,
            self.cloud.api_key,
            self.cloud.machine_id,
            self.cloud.batch_size,
            self.cloud.timeout,
            self.transport,
        )
        self.uploaded = res.ok

    def find_resolution(self, request_id: str) -> dict[str, Any] | None:
        local = self.ledger.find_resolution(request_id)
        if local is not None:
            return local

        self._ensure_uploaded()
        url = f"{self.cloud.url.rstrip('/')}/v1/escalations/{request_id}/resolution"
        status, body = self.transport(
            "GET", url, None, {"Authorization": f"Bearer {self.cloud.api_key}"},
            self.cloud.timeout,
        )
        if status != 200 or not body.get("outcome"):
            return None

        return {
            "kind": "resolution",
            "request_id": request_id,
            "outcome": body.get("outcome"),
            "approver": {
                "id": body.get("approver", ""),
                "method": "cloud console: a named reviewer answered while the agent waited",
            },
            "detail": body.get("note", ""),
            "gated": True,
            "_from_cloud": True,
        }

    def write_resolution(self, *args, **kwargs):
        return self.ledger.write_resolution(*args, **kwargs)
