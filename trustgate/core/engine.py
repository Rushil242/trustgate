"""The Policy Decision Point.

The engine owns the outcome. Guards report; the engine folds their verdicts by
precedence, decides whether the LLM judge is worth consulting, attaches
obligations, and writes the audit entry. Adapters then enforce what it returns.

Ordering and short-circuiting are the whole performance story: the deterministic
guards run first and target under 50 ms combined, and a hard block skips the
judge entirely. There is no point paying a model call to confirm that `rm -rf /`
is bad.

Spec: Master Build Document v3.0, Part E.1.
"""

from __future__ import annotations

import time

from trustgate.core.audit import AuditLedger
from trustgate.core.constitution import Constitution
from trustgate.core.guards import Guard
from trustgate.core.guards.action import ActionGuard
from trustgate.core.guards.constitution_llm import ConstitutionGuard
from trustgate.core.guards.context import ContextGuard
from trustgate.core.guards.secret import SecretGuard
from trustgate.core.guards.supply_chain import SupplyChainGuard
from trustgate.core.models import (
    ActionRequest,
    Decision,
    Effect,
    Reason,
    Verdict,
    combine_verdicts,
    verdict_to_effect,
)


class Engine:
    """Runs the guard pipeline and produces a Decision."""

    def __init__(
        self,
        constitution: Constitution,
        audit: AuditLedger | None = None,
        judge: ConstitutionGuard | None = None,
        guards: list[Guard] | None = None,
    ) -> None:
        self.c = constitution
        self.audit = audit
        self.judge = judge
        self.det_guards: list[Guard] = guards if guards is not None else [
            ContextGuard(constitution),
            ActionGuard(constitution),
            SecretGuard(constitution),
            SupplyChainGuard(constitution),
        ]

    def decide(self, req: ActionRequest) -> Decision:
        t0 = time.perf_counter()

        reasons: list[Reason] = []
        modifications: dict = {}
        obligations: list[str] = []
        verdict = Verdict.allow
        needs_judge = False

        for guard in self.det_guards:
            result = self._run_guard(guard, req)
            reasons.extend(result.reasons)
            if result.modifications:
                modifications.update(result.modifications)
            if result.verdict is Verdict.uncertain:
                needs_judge = True
            verdict = combine_verdicts(verdict, result.verdict)
            if verdict is Verdict.block:
                break  # nothing a later guard says can make this more blocked

        # Consult the judge only when this specific request warrants it: a
        # deterministic guard was unsure, or a reasoning principle's prefilter
        # fired. Merely *having* reasoning principles in the file is a property
        # of the config, not of the request, and gating on it would put a model
        # call on every tool call. See DEVIATIONS.md #2.
        if verdict is not Verdict.block:
            in_scope = self.c.principles_needing_judge(req)

            if self.judge is not None and (needs_judge or in_scope):
                # An uncertain guard means "someone should reason about this",
                # so fall back to all reasoning principles when no prefilter hit.
                principles = in_scope or self.c.reasoning_principles
                jr = self.judge.evaluate(req, principles)
                reasons.extend(jr.reasons)
                if jr.modifications:
                    modifications.update(jr.modifications)
                verdict = combine_verdicts(verdict, jr.verdict)

            elif needs_judge or in_scope:
                # Something asked for a judgment and there is no judge to give
                # one: either a guard was uncertain, or a reasoning principle's
                # prefilter fired. Allowing here would mean the answer to "is
                # this safe?" is "nobody knows", which is the one answer that
                # must never read as yes. Same rule as a judge that times out.
                verdict = combine_verdicts(verdict, Verdict.escalate)
                reasons.append(
                    Reason(
                        guard="engine",
                        rule_id="unresolved-uncertainty",
                        message=_unresolved_message(needs_judge, in_scope),
                        severity="medium",
                    )
                )

        effect = verdict_to_effect(verdict)
        if effect is Effect.escalate:
            obligations.append("require_human_approval")

        decision = Decision(
            request_id=req.request_id,
            effect=effect,
            reasons=reasons,
            modifications=modifications,
            obligations=obligations,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )

        if self.audit is not None:
            self.audit.write(req, decision)

        return decision

    def _run_guard(self, guard: Guard, req: ActionRequest):
        """Run one guard, converting a crash into an escalation.

        A guard that throws is a guard whose opinion we do not have. Treating
        that as `allow` would mean a bug in a detector silently disables it,
        which is the failure mode most likely to go unnoticed in production.
        """
        from trustgate.core.models import GuardResult

        try:
            return guard.check(req)
        except Exception as exc:  # noqa: BLE001
            return GuardResult(
                verdict=Verdict.escalate,
                reasons=[
                    Reason(
                        guard=getattr(guard, "name", guard.__class__.__name__),
                        rule_id="guard-error",
                        message=f"Guard raised {type(exc).__name__}: {exc}; escalating",
                        severity="high",
                    )
                ],
            )


def _unresolved_message(needs_judge: bool, in_scope: list) -> str:
    """Say which thing wanted a judgment, so the escalation is actionable."""
    if in_scope:
        named = ", ".join(p.id for p in in_scope[:3])
        return (
            f"Reasoning principle(s) apply here ({named}) but no judge is "
            "configured to evaluate them; escalating rather than allowing"
        )
    if needs_judge:
        return (
            "A guard was uncertain and no judge is configured to resolve it; "
            "escalating rather than allowing"
        )
    return "Unresolved judgment; escalating rather than allowing"


def build_engine(
    constitution: Constitution,
    audit_path: str | None = None,
    judge: ConstitutionGuard | None = None,
) -> Engine:
    """Convenience wiring used by the CLI and the HTTP server."""
    ledger = AuditLedger(audit_path) if audit_path else None
    return Engine(constitution=constitution, audit=ledger, judge=judge)
