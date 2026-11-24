"""Tamper-evident audit ledger.

Append-only JSONL where each line carries the hash of the line before it. Any
edit to a past entry breaks every hash after it, so tampering is detectable
without a database, a server, or trust in the operator. This is the compliance
artifact, and it is the piece a regulator can be handed.

Two invariants:

* Every decision is written, including allows. A ledger that only records blocks
  cannot answer "what did this agent do on Tuesday", which is the question an
  auditor actually asks.
* Nothing reaches disk unredacted. `action_redacted` runs through the secret
  redactor first — a leaked credential in an append-only file is unrecallable.

Spec: Master Build Document v3.0, Part F.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from trustgate.core.guards.secret import redact
from trustgate.core.models import (
    ActionRequest,
    Approver,
    AuditEntry,
    Decision,
    Effect,
    Outcome,
    ResolutionEntry,
)

GENESIS_HASH = ""

ENGINE_VERSION = "0.3.0.dev0"
"""Stamped on every entry. Kept here, not imported, so the ledger has no
dependency on package metadata being installed."""


def compute_hash(entry: dict, prev_hash: str) -> str:
    """SHA-256 over the canonical entry body plus the previous link.

    `sort_keys` makes the digest independent of dict ordering, so a ledger stays
    verifiable across Python versions and re-serializations.
    """
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":")) + prev_hash
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def action_digest(req: ActionRequest) -> str:
    """`sha256:<hex>` of the full action: type, tool and every parameter.

    The stored `action_redacted` is a short, redacted summary (for a file write
    it is only the path). This digest commits to everything the tool received,
    content included, without storing any of it.
    """
    canonical = json.dumps(
        {"type": req.action.type.value, "tool": req.action.tool, "params": req.action.params},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@contextmanager
def _file_lock(path: Path):
    """Exclusive advisory lock across processes. No-op where flock is missing."""
    try:
        import fcntl
    except ImportError:  # Windows: one process at a time is the caller's job
        yield
        return
    with path.open("a") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _lines_from_end(path: Path, block: int = 65536):
    """Yield the file's non-empty lines, last line first."""
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        pos = fh.tell()
        rest = b""
        while pos > 0:
            step = min(block, pos)
            pos -= step
            fh.seek(pos)
            chunk = fh.read(step) + rest
            parts = chunk.split(b"\n")
            rest = parts[0]
            for raw in reversed(parts[1:]):
                text = raw.decode("utf-8", errors="replace").strip()
                if text:
                    yield text
        text = rest.decode("utf-8", errors="replace").strip()
        if text:
            yield text


@dataclass
class VerifyResult:
    """Outcome of a chain verification."""

    ok: bool
    entries_checked: int
    broken_seq: int | None = None
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ok


class AuditLedger:
    """Hash-chained append-only ledger backed by a local JSONL file.

    Every hook call is a new process, so the in-process lock alone is not
    enough: two hooks fired together would both read the same tail and both
    write the same `seq`, which breaks the chain for good. Each append
    therefore takes an exclusive `flock` on a sidecar lock file, re-reads the
    tail from disk while holding it, and only then writes.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    @property
    def lock_path(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    # -- writing ----------------------------------------------------------

    def write(
        self, req: ActionRequest, dec: Decision, policy_digest: str = ""
    ) -> AuditEntry:
        """Append one decision and return it.

        `policy_digest` names the exact policy bytes the decision was made
        under; `action_digest` is a hash of the full tool input, content
        included, so an approval or a report can be tied to the exact action
        even though only a redacted summary is stored in the clear.
        """

        def build(seq: int, prev_hash: str) -> dict:
            return {
                "seq": seq,
                "kind": "decision",
                "request_id": req.request_id,
                "correlation_id": req.context.correlation_id or "",
                "ts": req.timestamp,
                "surface": req.surface,
                "principal": req.principal.model_dump(),
                "action_redacted": redact(req.action.raw or str(req.action.params)),
                "action_digest": action_digest(req),
                "policy_digest": policy_digest,
                "engine_version": ENGINE_VERSION,
                "effect": dec.effect.value,
                "reasons": [r.model_dump() for r in dec.reasons],
                "prev_hash": prev_hash,
            }

        return AuditEntry.model_validate(self._append(build))

    def write_resolution(
        self,
        request_id: str,
        outcome: Outcome,
        approver: Approver,
        correlation_id: str = "",
        detail: str = "",
        gated: bool = False,
    ) -> ResolutionEntry:
        """Append the answer to an earlier escalation.

        Deliberately does not check that the escalation exists. The ledger
        records what happened; refusing to write an answer because the question
        is missing would lose the more interesting of the two facts. Callers
        that need the pairing use `open_escalations`.
        """

        def build(seq: int, prev_hash: str) -> dict:
            return {
                "seq": seq,
                "kind": "resolution",
                "request_id": request_id,
                "correlation_id": correlation_id,
                "ts": time.time(),
                "outcome": outcome.value,
                "approver": approver.model_dump(),
                # Denial reasons are surface text and can quote the command.
                "detail": redact(detail),
                "gated": gated,
                "engine_version": ENGINE_VERSION,
                "prev_hash": prev_hash,
            }

        return ResolutionEntry.model_validate(self._append(build))

    def _append(self, build) -> dict:
        """Read the tail and append one line, as one step across processes."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, _file_lock(self.lock_path):
            prev_hash, seq = self._tail()
            body = build(seq, prev_hash)
            body["entry_hash"] = compute_hash(body, prev_hash)
            self._append_line(body)
        return body

    def _tail(self) -> tuple[str, int]:
        """Previous hash and next sequence number, read from the end of the file.

        Always read from disk, never cached: another process may have appended
        since we last looked. Reads backwards in blocks, so the cost does not
        grow with the size of the ledger. Lines that are not valid entries are
        skipped, as before; `verify` is what reports them.
        """
        if not self.path.is_file():
            return GENESIS_HASH, 0
        for line in _lines_from_end(self.path):
            try:
                entry = json.loads(line)
                return str(entry["entry_hash"]), int(entry["seq"]) + 1
            except (ValueError, KeyError, TypeError):
                continue
        return GENESIS_HASH, 0

    def _append_line(self, body: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n"
        # Open-append-flush-fsync per entry: a crash must not be able to lose the
        # record of an action that already executed.
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

    # -- reading and verification ----------------------------------------

    def read_all(self) -> list[dict]:
        if not self.path.is_file():
            return []
        entries = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def open_escalations(self) -> list[dict]:
        """Escalated decisions that no resolution has answered yet.

        This is the queue a human is supposed to be working through, and the
        list an evidence pack has to disclose rather than quietly omit. An
        escalation nobody ever answered is a real compliance finding: the system
        asked for a decision and did not get one.
        """
        answered: set[str] = set()
        escalations: list[dict] = []

        for entry in self.read_all():
            if entry.get("kind") == "resolution":
                answered.add(entry.get("request_id", ""))
            elif entry.get("effect") == Effect.escalate.value:
                escalations.append(entry)

        return [e for e in escalations if e.get("request_id") not in answered]

    def find_resolution(self, request_id: str) -> dict | None:
        """The answer to one escalation, or None if nobody has answered.

        Scans from the end, because a waiter polling for an answer is looking
        for something that was just appended, and the cheap substring test
        skips JSON parsing on the overwhelming majority of lines.
        """
        if not self.path.is_file() or not request_id:
            return None

        needle = f'"{request_id}"'
        with self.path.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()

        for line in reversed(lines):
            if needle not in line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("kind") == "resolution" and entry.get("request_id") == request_id:
                return entry if self._is_chained(entry) else None
        return None

    def _is_chained(self, entry: dict) -> bool:
        """Whether an answer is a real, chained entry in an intact ledger.

        A line appended by hand, without a valid place in the chain, is not an
        answer. Neither is anything in a ledger whose chain is broken: once the
        record has been tampered with, no line in it can approve an action.

        This raises the cost of forging an approval; it does not remove it.
        Any process running as the same OS user can still compute a valid
        hash. Only the guard room (a separate OS user) closes that.
        """
        if not entry.get("entry_hash") or "seq" not in entry:
            return False
        return bool(self.verify())

    def find_open_escalation(self, correlation_id: str) -> dict | None:
        """The unanswered escalation matching a surface-native id, if any.

        Adapters observing a later event know the surface's own id, never our
        `request_id`, so this is how an answer finds its question. Returns the
        most recent match: a correlation id can legitimately repeat across
        sessions, and the newest open one is the only one still waiting.
        """
        if not correlation_id:
            return None
        matches = [
            e for e in self.open_escalations() if e.get("correlation_id") == correlation_id
        ]
        return matches[-1] if matches else None

    def verify(self) -> VerifyResult:
        """Recompute the chain and report the first broken link.

        This is what `trustgate verify-audit` calls, and what proves in a demo
        that an edited log is detectable rather than merely discouraged.
        """
        if not self.path.is_file():
            return VerifyResult(ok=True, entries_checked=0, detail="no ledger yet")

        prev_hash = GENESIS_HASH
        checked = 0
        expected_seq = 0

        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    return VerifyResult(
                        ok=False,
                        entries_checked=checked,
                        broken_seq=expected_seq,
                        detail=f"line {lineno} is not valid JSON: {exc}",
                    )

                seq = entry.get("seq")
                if seq != expected_seq:
                    return VerifyResult(
                        ok=False,
                        entries_checked=checked,
                        broken_seq=expected_seq,
                        detail=f"line {lineno}: expected seq {expected_seq}, found {seq} "
                        "(an entry was removed or reordered)",
                    )

                if entry.get("prev_hash") != prev_hash:
                    return VerifyResult(
                        ok=False,
                        entries_checked=checked,
                        broken_seq=seq,
                        detail=f"line {lineno}: prev_hash does not match the preceding entry",
                    )

                stated = entry.get("entry_hash", "")
                body = {k: v for k, v in entry.items() if k != "entry_hash"}
                if compute_hash(body, prev_hash) != stated:
                    return VerifyResult(
                        ok=False,
                        entries_checked=checked,
                        broken_seq=seq,
                        detail=f"line {lineno}: entry contents do not match entry_hash "
                        "(this entry was modified after it was written)",
                    )

                prev_hash = stated
                checked += 1
                expected_seq += 1

        return VerifyResult(ok=True, entries_checked=checked, detail="chain intact")
