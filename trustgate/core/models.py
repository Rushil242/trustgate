"""The TrustGate wire contract.

Every adapter (PEP) and every guard depends on these schemas. They are the seam
that lets one engine serve many agent surfaces, so they are deliberately small
and deliberately stable: additive changes only within a major version.

Spec: Master Build Document v3.0, Part C.
"""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

CONTRACT_VERSION = "1.0"


# --------------------------------------------------------------------------
# Input side: what an adapter sends to the engine
# --------------------------------------------------------------------------


class ActionType(StrEnum):
    """The normalized shape of a proposed action, independent of surface.

    Adapters map their surface's vocabulary onto these: a Claude Code `Bash`
    tool call and a shell command issued by some future CI agent are both
    `shell`, so one policy covers both.
    """

    shell = "shell"
    file_read = "file_read"
    file_write = "file_write"
    tool_call = "tool_call"
    network = "network"
    other = "other"


class Principal(BaseModel):
    """Who is proposing the action.

    Roles come from the authenticated session, never from model output or
    prompt text — a caller claiming to be an admin is data, not authorization.
    """

    id: str = "local-user"
    roles: list[str] = Field(default_factory=lambda: ["developer"])


class Action(BaseModel):
    """The proposed action itself."""

    type: ActionType
    tool: str
    """Surface-native tool name: "Bash", "Read", "issue_refund", ..."""

    params: dict[str, Any] = Field(default_factory=dict)
    """Structured arguments, e.g. {"command": "cat .env"} or {"amount": 250}."""

    raw: str = ""
    """Original text form of the action.

    Adapters must populate this whenever a text form exists. Pattern matching
    and the secret-read normalizer both read `raw`; leaving it empty silently
    weakens enforcement rather than failing loudly, so adapter tests assert it.
    """


class Context(BaseModel):
    """Surrounding material the guards may need to inspect.

    `ingested_content` is always treated as data, never as instructions — it is
    exactly where injected text arrives (file contents, fetched web pages, tool
    descriptions, voice transcripts).
    """

    ingested_content: str | None = None
    session_id: str | None = None
    turn: int = 0

    correlation_id: str | None = None
    """The surface's own id for this action, when it has one.

    Claude Code supplies `tool_use_id`; a voice platform supplies a call and turn
    reference. It exists so a later event about the *same* action can be matched
    back to the decision that escalated it — `request_id` is minted by us and the
    surface never sees it, so it cannot be the join key.
    """


class ActionRequest(BaseModel):
    """The universal input. One shape for every surface."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    surface: str
    """"coding" | "voice" | ... — informational routing, not a trust boundary."""

    principal: Principal = Field(default_factory=Principal)
    action: Action
    context: Context = Field(default_factory=Context)


# --------------------------------------------------------------------------
# Output side: what the engine returns to an adapter
# --------------------------------------------------------------------------


class Effect(StrEnum):
    """The enforceable outcome. Adapters must handle all four."""

    allow = "allow"
    block = "block"
    modify = "modify"
    escalate = "escalate"


class Reason(BaseModel):
    """Why a decision came out the way it did.

    One entry per triggered rule. `rule_id` is a constitution principle id or a
    built-in rule id, and it is what makes an audit line traceable to a specific
    written principle rather than a vague "something was wrong".
    """

    guard: str
    rule_id: str
    message: str
    severity: str = "high"


class Decision(BaseModel):
    """The universal output."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    effect: Effect
    reasons: list[Reason] = Field(default_factory=list)
    modifications: dict[str, Any] = Field(default_factory=dict)
    """Replacement values when effect is `modify`, e.g. {"params": {...redacted}}."""

    obligations: list[str] = Field(default_factory=list)
    """Side conditions the adapter must satisfy, e.g. ["require_human_approval"]."""

    latency_ms: float = 0.0


# --------------------------------------------------------------------------
# Internal: how guards report to the engine
# --------------------------------------------------------------------------


class Verdict(StrEnum):
    """A single guard's opinion.

    `uncertain` is not an outcome — it is a request for the LLM judge. It never
    raises the combined verdict on its own; see `combine_verdicts`.
    """

    allow = "allow"
    block = "block"
    escalate = "escalate"
    modify = "modify"
    uncertain = "uncertain"


class GuardResult(BaseModel):
    """What every guard returns."""

    verdict: Verdict
    reasons: list[Reason] = Field(default_factory=list)
    modifications: dict[str, Any] = Field(default_factory=dict)


# Precedence: block > escalate > modify > allow.
# `uncertain` sits at allow level because it carries no enforcement opinion; the
# engine tracks it separately as a flag to invoke the judge. Ranking it any
# higher would let a low-confidence heuristic escalate on its own, which is the
# false-positive failure mode the Context Guard is explicitly designed to avoid.
_PRECEDENCE: dict[Verdict, int] = {
    Verdict.allow: 0,
    Verdict.uncertain: 0,
    Verdict.modify: 1,
    Verdict.escalate: 2,
    Verdict.block: 3,
}

_VERDICT_TO_EFFECT: dict[Verdict, Effect] = {
    Verdict.allow: Effect.allow,
    Verdict.uncertain: Effect.allow,
    Verdict.modify: Effect.modify,
    Verdict.escalate: Effect.escalate,
    Verdict.block: Effect.block,
}


def combine_verdicts(current: Verdict, incoming: Verdict) -> Verdict:
    """Fold a guard's verdict into the running verdict, most severe wins.

    `uncertain` is normalized to `allow` on both sides so it can never survive
    the fold and become the engine's final verdict. The engine records the need
    for a judgment in a separate flag; letting `uncertain` linger here would
    make the running verdict mean two different things at once.
    """
    current = Verdict.allow if current is Verdict.uncertain else current
    incoming = Verdict.allow if incoming is Verdict.uncertain else incoming
    return incoming if _PRECEDENCE[incoming] > _PRECEDENCE[current] else current


def verdict_to_effect(verdict: Verdict) -> Effect:
    """Project an internal verdict onto the enforceable output enum."""
    return _VERDICT_TO_EFFECT[verdict]


_EFFECT_TO_VERDICT: dict[Effect, Verdict] = {
    Effect.allow: Verdict.allow,
    Effect.block: Verdict.block,
    Effect.modify: Verdict.modify,
    Effect.escalate: Verdict.escalate,
}


def effect_to_verdict(effect: Effect) -> Verdict:
    """Lift a principle's declared effect into a guard verdict."""
    return _EFFECT_TO_VERDICT[effect]


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------


class AuditEntry(BaseModel):
    """One line of the hash-chained ledger.

    `action_redacted` is the only place action text is persisted, and it is
    always passed through the secret redactor first — the ledger is a compliance
    artifact, so a leaked key in it is worse than no ledger at all.

    Spec: Master Build Document v3.0, Part F.1.
    """

    seq: int
    request_id: str
    ts: float
    surface: str
    principal: dict[str, Any]
    action_redacted: str
    effect: Effect
    reasons: list[Reason] = Field(default_factory=list)
    prev_hash: str
    entry_hash: str = ""

    kind: str = "decision"
    """Discriminator. A ledger now carries two shapes; see `ResolutionEntry`."""

    correlation_id: str = ""
    """Copied from the request's context, so a resolution can find this entry."""


class Outcome(StrEnum):
    """How an escalation ended.

    `unknown` is a real, reportable state, not a placeholder. We observe the
    human's answer through the surface's own events rather than owning the
    prompt, and an observation we cannot classify must not be recorded as
    approval. Guessing in the permissive direction is how a gate ends up
    certifying something nobody agreed to.
    """

    approved = "approved"
    denied = "denied"
    expired = "expired"
    unknown = "unknown"


class Approver(BaseModel):
    """Who answered, and how we came to know it.

    `method` matters as much as `id`. "a person clicked approve in the TrustGate
    console" and "the tool subsequently executed, so permission must have been
    granted locally" are both evidence, and they are not equally strong. An
    auditor is entitled to see which one they are looking at.
    """

    id: str = "local-user"
    method: str = "unspecified"


class ResolutionEntry(BaseModel):
    """One ledger line recording how an earlier escalation was answered.

    Appended into the same hash chain as decisions, so an answer cannot be
    removed or back-dated without breaking verification the same way a decision
    would. It is a separate line rather than an edit to the original entry
    because the ledger is append-only by construction: rewriting the escalation
    in place would defeat the chain it sits in.
    """

    seq: int
    kind: str = "resolution"
    request_id: str
    """The escalated decision this answers."""

    correlation_id: str = ""
    ts: float
    outcome: Outcome
    approver: dict[str, Any]
    detail: str = ""
    """Verbatim text from the surface, e.g. a denial reason. Redacted on write."""

    gated: bool = False
    """Whether this answer actually held the action, or only judged it after.

    Two very different facts, and collapsing them would make the ledger lie in
    the most damaging way available to it. `true` means the action could not
    proceed until someone answered. `false` means the action already resolved
    on its own and a reviewer recorded a judgment afterwards, which is a real
    and useful compliance record but is not authorization.

    Defaults to `false` because that is the weaker claim.
    """

    prev_hash: str
    entry_hash: str = ""
