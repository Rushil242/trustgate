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

from trustgate.core.audit import AuditLedger
from trustgate.core.config import Config
from trustgate.core.constitution import Constitution, ConstitutionError
from trustgate.core.engine import Engine
from trustgate.core.guards.constitution_llm import ConstitutionGuard
from trustgate.core.llm import build_llm
from trustgate.core.models import ActionRequest, Decision

_state: dict = {}


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
        version="0.1.0",
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
