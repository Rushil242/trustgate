"""Holding an action until a named person answers.

This is the difference between a record and a control. Everything before this
module observed a decision somebody else made, or filed a judgment after the
fact. Here the action stops and does not proceed until an answer exists.

The mechanism is deliberately dull. The engine has already written the
escalation to the ledger, and the console writes the resolution to the same
ledger, so waiting is just watching for a line to appear. No socket, no queue,
no broker. When the ledger moves to a hosted store, the same function grows an
HTTP implementation behind the same signature and nothing above it changes.

Three ways a wait can end, and only one of them lets the action run:

* **answered** — a person approved or denied. Their name is already in the
  chain, written by whoever served them the question.
* **timed out** — nobody answered inside the budget. Recorded as `expired`,
  and `expired` is not consent.
* **interrupted** — the process died or the developer hit Ctrl+C. Nothing is
  written, because we did not learn anything.

Silence never becomes approval. That is the single rule this file exists to
enforce, and every branch below is arranged so that the permissive outcome
requires an actual answer rather than the absence of one.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from trustgate.core.audit import AuditLedger
from trustgate.core.models import Approver, Outcome

EXPIRY_METHOD = "nobody answered before the approval window closed"


@dataclass
class ApprovalResult:
    """How the wait ended."""

    outcome: Outcome
    approver: str = ""
    note: str = ""
    waited: float = 0.0
    timed_out: bool = False

    @property
    def approved(self) -> bool:
        """True only for an explicit approval. Never for silence or an error."""
        return self.outcome is Outcome.approved


def wait_for_decision(
    ledger: AuditLedger,
    request_id: str,
    timeout: float = 180.0,
    poll_interval: float = 1.0,
    *,
    record_expiry: bool = True,
    _clock=time.monotonic,
    _sleep=time.sleep,
) -> ApprovalResult:
    """Block until this escalation is answered, or the budget runs out.

    Polls rather than watches the filesystem: a poll is a few milliseconds
    against a file that is already open elsewhere, and it behaves identically
    on macOS, Linux, a container bind mount and a network share, none of which
    agree about change notifications.
    """
    deadline = _clock() + max(timeout, 0.0)
    interval = max(poll_interval, 0.05)
    started = _clock()

    while True:
        entry = ledger.find_resolution(request_id)
        if entry is not None:
            if entry.get("_from_cloud"):
                _record_cloud_answer(ledger, request_id, entry)
            return _from_entry(entry, _clock() - started)

        remaining = deadline - _clock()
        if remaining <= 0:
            break
        _sleep(min(interval, remaining))

    waited = _clock() - started
    if record_expiry:
        # Write the expiry before returning. The agent is about to be told no,
        # and a refusal with no corresponding ledger line is exactly the sort of
        # gap that makes an audit trail worthless.
        try:
            ledger.write_resolution(
                request_id=request_id,
                outcome=Outcome.expired,
                approver=Approver(id="nobody", method=EXPIRY_METHOD),
                detail=f"no answer within {timeout:.0f}s",
                gated=True,
            )
        except OSError:
            # Losing the record is bad; failing open because we could not write
            # it would be worse. The refusal still stands.
            pass

    return ApprovalResult(outcome=Outcome.expired, waited=waited, timed_out=True)


def _record_cloud_answer(ledger, request_id: str, entry: dict) -> None:
    """Copy a reviewer's cloud answer into this machine's own chain.

    The local ledger should be complete on its own: a reader of this machine's
    file must be able to see that the escalation was answered, by whom, and that
    the answer held the action. The line then syncs back up like any other.
    """
    try:
        outcome = Outcome(entry.get("outcome", ""))
    except ValueError:
        outcome = Outcome.unknown
    approver = entry.get("approver") or {}
    try:
        ledger.write_resolution(
            request_id=request_id,
            outcome=outcome,
            approver=Approver(
                id=str(approver.get("id", "")), method=str(approver.get("method", ""))
            ),
            detail=str(entry.get("detail", "")),
            gated=True,
        )
    except OSError:
        pass


def _from_entry(entry: dict, waited: float) -> ApprovalResult:
    raw = entry.get("outcome", "")
    try:
        outcome = Outcome(raw)
    except ValueError:
        # An outcome this build does not recognize is not an approval.
        outcome = Outcome.unknown

    approver = entry.get("approver") or {}
    return ApprovalResult(
        outcome=outcome,
        approver=str(approver.get("id", "")),
        note=str(entry.get("detail", "")),
        waited=waited,
    )
