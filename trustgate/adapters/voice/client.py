"""How a voice adapter reaches the engine.

Two modes, one interface:

* **In-process** — the engine runs inside the voice application. Fastest, no
  network hop, and the right default for a single process.
* **HTTP** — the engine runs as a daemon (`trustgate serve`). The right choice
  when several workers share one policy and one audit ledger, which is the
  normal shape for a call platform.

The distinction matters here more than on the coding surface: a voice agent is
inside a live conversation, and a decision that takes 400 ms is a decision the
caller hears as silence.

Spec: Master Build Document v3.0, Part I.2.
"""

from __future__ import annotations

from typing import Protocol

from trustgate.core.models import ActionRequest, Decision, Effect, Reason


class DecisionClient(Protocol):
    def decide(self, req: ActionRequest) -> Decision: ...


class InProcessClient:
    """Calls the engine directly."""

    def __init__(self, engine) -> None:
        self.engine = engine

    def decide(self, req: ActionRequest) -> Decision:
        return self.engine.decide(req)


class HTTPClient:
    """Calls a `trustgate serve` daemon over POST /v1/decide.

    On a transport failure this fails safe to `escalate` rather than raising or
    allowing. A voice agent that crashes mid-call is a worse outcome than one
    that routes a refund to a human, and an unreachable policy engine must never
    read as approval.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8000", timeout: float = 1.5) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def decide(self, req: ActionRequest) -> Decision:
        import httpx

        try:
            response = httpx.post(
                f"{self.base_url}/v1/decide",
                json=req.model_dump(mode="json"),
                timeout=self.timeout,
            )
            response.raise_for_status()
            return Decision.model_validate(response.json())
        except Exception as exc:  # noqa: BLE001
            return Decision(
                request_id=req.request_id,
                effect=Effect.escalate,
                reasons=[
                    Reason(
                        guard="client",
                        rule_id="engine-unreachable",
                        message=(
                            f"Policy engine unreachable ({exc}); escalating rather "
                            "than allowing"
                        ),
                        severity="critical",
                    )
                ],
                obligations=["require_human_approval"],
            )


def build_default_client() -> DecisionClient:
    """In-process client using the configured constitution."""
    from trustgate.core.audit import AuditLedger
    from trustgate.core.config import Config
    from trustgate.core.constitution import Constitution
    from trustgate.core.engine import Engine

    cfg = Config.load()
    constitution = Constitution.from_file(cfg.constitution_path)

    judge = None
    if cfg.judge.enabled:
        from trustgate.core.guards.constitution_llm import ConstitutionGuard
        from trustgate.core.llm import build_llm

        judge = ConstitutionGuard(constitution, build_llm(cfg.judge))

    return InProcessClient(
        Engine(constitution=constitution, audit=AuditLedger(cfg.audit_path), judge=judge)
    )
