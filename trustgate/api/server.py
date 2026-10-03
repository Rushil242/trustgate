"""HTTP Decision API.

Daemon mode, used by the voice adapter and optionally by coding adapters that
prefer a warm process to a per-call CLI invocation. The constitution is loaded
once at startup so the hot path never touches disk.

Binds to 127.0.0.1 by default. This endpoint decides whether privileged actions
may run; exposing it on a public interface would let anyone on the network
approve their own actions.

Spec: Master Build Document v3.0, Part G.1.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from trustgate import __version__
from trustgate.core.audit import AuditLedger
from trustgate.core.config import Config
from trustgate.core.constitution import Constitution, ConstitutionError
from trustgate.core.engine import Engine
from trustgate.core.guards.constitution_llm import ConstitutionGuard
from trustgate.core.llm import build_llm
from trustgate.core.models import ActionRequest, Approver, Decision, Outcome

_state: dict = {}

CONSOLE_METHOD = "console: a named person reviewed this and recorded a decision"


class ResolveRequest(BaseModel):
    """A human's answer to an escalation, submitted from the console."""

    outcome: Outcome
    approver: str = Field(min_length=1, max_length=200)
    note: str = ""


def build_app(config: Config | None = None) -> FastAPI:
    cfg = config or Config.load()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            constitution = Constitution.from_file(cfg.constitution_path)
        except ConstitutionError as exc:
            # Refuse to start rather than serve with no policy: a gate that
            # allows everything is worse than an obviously absent gate.
            raise RuntimeError(f"cannot start without a valid constitution: {exc}") from exc

        judge = (
            ConstitutionGuard(constitution, build_llm(cfg.judge)) if cfg.judge.enabled else None
        )
        _state["config"] = cfg
        _state["constitution"] = constitution
        _state["engine"] = Engine(
            constitution=constitution,
            audit=AuditLedger(cfg.audit_path),
            judge=judge,
        )
        yield
        _state.clear()

    app = FastAPI(
        title="TrustGate Decision API",
        version=__version__,
        description="Policy Decision Point for AI agent actions.",
        lifespan=lifespan,
    )

    @app.get("/health")
    def health() -> dict:
        constitution: Constitution = _state["constitution"]
        cfg: Config = _state["config"]
        return {
            "status": "ok",
            "constitution": constitution.metadata.name,
            "principles": len(constitution.principles),
            "deterministic": len(constitution.deterministic_principles),
            "reasoning": len(constitution.reasoning_principles),
            "judge": cfg.judge.provider if cfg.judge.enabled else "disabled",
        }

    @app.post("/v1/decide", response_model=Decision)
    def decide(req: ActionRequest) -> Decision:
        engine: Engine | None = _state.get("engine")
        if engine is None:
            raise HTTPException(status_code=503, detail="engine not initialized")
        return engine.decide(req)

    @app.get("/v1/audit")
    def audit_entries(limit: int = 200, effect: str | None = None) -> dict:
        """Recent audit entries, newest first, for the dashboard.

        Read-only and local: the ledger itself is the source of truth. This
        just paginates it for a browser instead of a human tailing a file.
        """
        engine: Engine | None = _state.get("engine")
        if engine is None or engine.audit is None:
            raise HTTPException(status_code=503, detail="no audit ledger configured")
        all_entries = engine.audit.read_all()
        entries = all_entries
        if effect:
            entries = [e for e in entries if e.get("effect") == effect]
        entries = list(reversed(entries))[: max(1, min(limit, 2000))]
        return {"entries": entries, "total": len(all_entries)}

    @app.post("/v1/escalations/{request_id}/resolve")
    def resolve_escalation(request_id: str, body: ResolveRequest) -> dict:
        """Record a named person's decision on an escalation.

        This writes a judgment; it does not run or cancel anything. By the time
        a reviewer opens the console the action has already been allowed or
        refused at the surface, so the entry is stored with `gated: false`. The
        distinction is the point: a sign-off recorded afterwards is a genuine
        compliance record and is not the same thing as having held the action.
        Live gating needs the adapter to wait on this endpoint, which is a
        separate piece of work.
        """
        cfg: Config = _state["config"]
        ledger = AuditLedger(cfg.audit_path)

        if body.outcome not in (Outcome.approved, Outcome.denied):
            # `unknown` and `expired` describe what we failed to learn. A person
            # sitting in front of the action is never in that position.
            raise HTTPException(422, "a person may only approve or deny")

        approver = body.approver.strip()
        if not approver:
            # Refuse rather than fill in a placeholder. The entire value of this
            # record is that a specific person's name is attached to it.
            raise HTTPException(422, "an approver name is required")

        open_items = [e for e in ledger.open_escalations() if e.get("request_id") == request_id]
        if not open_items:
            already = any(
                e.get("kind") == "resolution" and e.get("request_id") == request_id
                for e in ledger.read_all()
            )
            raise HTTPException(
                409 if already else 404,
                "this escalation has already been answered"
                if already
                else "no open escalation with that request id",
            )

        entry = ledger.write_resolution(
            request_id=request_id,
            outcome=body.outcome,
            approver=Approver(id=approver, method=CONSOLE_METHOD),
            correlation_id=open_items[-1].get("correlation_id", ""),
            detail=body.note,
            gated=False,
        )
        return entry.model_dump()

    @app.get("/v1/audit/verify")
    def audit_verify() -> dict:
        engine: Engine | None = _state.get("engine")
        if engine is None or engine.audit is None:
            raise HTTPException(status_code=503, detail="no audit ledger configured")
        result = engine.audit.verify()
        return {
            "ok": result.ok,
            "entries_checked": result.entries_checked,
            "broken_seq": result.broken_seq,
            "detail": result.detail,
        }

    _mount_dashboard(app)
    return app


def _mount_dashboard(app: FastAPI) -> None:
    """Serve the static dashboard at / if it's present alongside the package.

    Optional by design: the API and CLI work with no dashboard installed, and a
    minimal deployment (e.g. the Docker image) must not fail to serve decisions
    just because dashboard/ was not copied in.
    """
    from pathlib import Path

    from fastapi.responses import FileResponse

    dashboard_dir = Path(__file__).resolve().parents[2] / "dashboard"
    if not dashboard_dir.is_dir():
        return

    @app.get("/")
    def dashboard_index() -> FileResponse:
        return FileResponse(dashboard_dir / "index.html")


app = build_app() if os.environ.get("TRUSTGATE_AUTOLOAD_APP") else None


def serve(host: str = "127.0.0.1", port: int = 8000, config: Config | None = None) -> None:
    import uvicorn

    uvicorn.run(build_app(config), host=host, port=port)
