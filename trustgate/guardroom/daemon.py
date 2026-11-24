"""`trustgated`: the gate as a long-lived process that owns its own files.

    trustgate guardroom serve --state DIR --run DIR

What lives in the state folder (mode 0700, owned by the daemon's user):

    policy.yaml     the only policy the daemon uses; changed via admin.sock
    audit.jsonl     the ledger; this process is its only writer
    machine.key     the signing key (Part 1B)

What lives in the run folder:

    agent.sock      0666: decide, observe, status
    admin.sock      0600: resolve, policy-install, plus everything above

Run as your own user this is "dev mode": the same code, but the agent's user
can still reach the files, and every entry says `protection_level: 0`. Run as
a separate user (`_trustgate`) the operating system keeps the agent out, and
entries from other users' calls say `protection_level: 1`. The level is worked
out per call from the kernel's answer about the caller, not from config.
"""

from __future__ import annotations

import json
import os
import shutil
import socketserver
import threading
from pathlib import Path
from typing import Any

from trustgate.adapters.coding import claude_code_hook as hook_mod
from trustgate.adapters.coding import resolution_hook
from trustgate.core.audit import AuditLedger
from trustgate.core.config import Config
from trustgate.core.constitution import Constitution
from trustgate.core.engine import Engine
from trustgate.guardroom.peer import peer_uid

MAX_REQUEST_BYTES = 2 * 1024 * 1024
AGENT_OPS = frozenset({"decide", "observe", "status"})
ADMIN_OPS = AGENT_OPS | {"resolve", "policy-install"}


ADMIN_METHOD = "guard room admin socket"


class IndexedLedger(AuditLedger):
    """The daemon's ledger: one writer, and answers found in memory.

    `find_resolution` reads an index, never the file. Only two kinds of line
    can answer a waiting action: an approval given on the admin socket, and an
    expiry written by the wait itself. A line someone else appended to the
    file is not an answer, and neither is a resolution recorded from an
    `observe` event, because anyone who can reach agent.sock can send one.
    """

    def __init__(self, path: str | Path, signer=None) -> None:
        super().__init__(path, signer=signer)
        self._answers: dict[str, dict] = {}
        self.escalations: set[str] = set()
        check = self.verify()
        self.chain_ok_at_start = bool(check.ok)
        if check.ok:
            for entry in self.read_all():
                if entry.get("effect") == "escalate":
                    self.escalations.add(entry.get("request_id", ""))
                method = str((entry.get("approver") or {}).get("method", ""))
                if entry.get("kind") == "resolution" and method.startswith(ADMIN_METHOD):
                    self._answers[entry.get("request_id", "")] = entry

    def write(self, req, dec, *args, **kwargs):
        entry = super().write(req, dec, *args, **kwargs)
        if dec.effect.value == "escalate":
            self.escalations.add(entry.request_id)
        return entry

    def write_resolution(self, *args, counts_as_answer: bool = True, **kwargs):
        entry = super().write_resolution(*args, **kwargs)
        if counts_as_answer:
            self._answers[entry.request_id] = entry.model_dump(mode="json")
        return entry

    def find_resolution(self, request_id: str) -> dict | None:
        return self._answers.get(request_id)


class _RecordOnly:
    """The ledger as `observe` sees it: it can record, but never answer."""

    def __init__(self, ledger: IndexedLedger) -> None:
        self._ledger = ledger

    def write_resolution(self, *args, **kwargs):
        return self._ledger.write_resolution(*args, counts_as_answer=False, **kwargs)

    def __getattr__(self, name):
        return getattr(self._ledger, name)


class GuardRoom:
    """Everything the daemon decides. Sockets are a thin layer on top."""

    def __init__(self, state_dir: str | Path, config: Config | None = None) -> None:
        self.state = Path(state_dir)
        self.state.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state, 0o700)
        self.uid = os.geteuid()
        self.cfg = config or Config()
        self.policy_path = self.state / "policy.yaml"
        if not self.policy_path.exists():
            starter = Path(hook_mod.__file__).resolve().parents[2] / "policies"
            shutil.copyfile(starter / "starter.coding.yaml", self.policy_path)
            os.chmod(self.policy_path, 0o600)
        self.cfg.constitution_path = str(self.policy_path)
        self.cfg.audit_path = str(self.state / "audit.jsonl")
        self.ledger = IndexedLedger(self.cfg.audit_path, signer=self._signer())
        self._lock = threading.Lock()
        self.engine = self._build_engine()
        self._record_policy_at_start()

    # -- building ---------------------------------------------------------

    def _signer(self):
        """The machine key, made on first start. None if `cryptography` is missing."""
        try:
            from trustgate.core.signing import Signer

            return Signer.load_or_create(self.state / "machine.key")
        except RuntimeError:
            return None

    def _build_engine(self) -> Engine:
        constitution = Constitution.from_file(self.policy_path)
        judge = None
        if self.cfg.judge.active:
            from trustgate.core.guards.constitution_llm import ConstitutionGuard
            from trustgate.core.llm import build_llm

            judge = ConstitutionGuard(constitution, build_llm(self.cfg.judge))
        # The daemon's own policy file is trusted by where it lives: only the
        # admin socket can change it. Pins are for the in-project hook.
        return Engine(constitution=constitution, audit=self.ledger, judge=judge)

    def _record_policy_at_start(self) -> None:
        """Make the log say which policy is in force from now on.

        If the file differs from the last recorded change, it was installed
        for the first time or edited while the daemon was not running. Either
        way the log gets a line, so the change is never silent.
        """
        current, last = self.engine.c.digest, self.ledger.last_policy_digest()
        if current != last:
            self.ledger.write_policy_change(
                last, current, by="(found at daemon start)", os_uid=self.uid,
                note="first start" if not last else
                "policy file differs from the last recorded change; edited while stopped",
            )

    def protection_level(self, caller_uid: int | None) -> int:
        """1 when the caller is a different OS user than the daemon, else 0."""
        return 1 if caller_uid is not None and caller_uid != self.uid else 0

    # -- operations ---------------------------------------------------------

    def handle(self, request: dict, caller_uid: int | None, admin: bool) -> dict:
        op = request.get("op")
        allowed = ADMIN_OPS if admin else AGENT_OPS
        if op not in allowed:
            return {"ok": False, "error": f"operation {op!r} is not allowed on this socket"}
        try:
            return getattr(self, "op_" + op.replace("-", "_"))(request, caller_uid)
        except Exception as exc:  # noqa: BLE001 - the daemon must keep running
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def op_status(self, request: dict, caller_uid: int | None) -> dict:
        return {
            "ok": True,
            "policy_digest": self.engine.c.digest,
            "policy_name": self.engine.c.metadata.name,
            "daemon_uid": self.uid,
            "caller_uid": caller_uid,
            "protection_level": self.protection_level(caller_uid),
            "chain_ok_at_start": self.ledger.chain_ok_at_start,
            "signing": self.ledger.signer is not None,
            "key_id": getattr(self.ledger.signer, "key_id", ""),
            "public_key": getattr(self.ledger.signer, "public_b64", ""),
        }

    def op_decide(self, request: dict, caller_uid: int | None) -> dict:
        payload = request.get("payload")
        if not isinstance(payload, dict):
            return {"ok": True, "response": hook_mod._fail_safe("invalid hook payload")}
        try:
            req = hook_mod.to_action_request(payload)
        except Exception as exc:  # noqa: BLE001
            return {"ok": True, "response": hook_mod._fail_safe(f"bad tool call: {exc}")}
        req.principal.id = f"unix:{caller_uid}" if caller_uid is not None else "unix:unknown"

        decision = self.engine.decide(
            req, stamps={"protection_level": self.protection_level(caller_uid)}
        )
        if decision.effect.value == "escalate" and self.cfg.approval.is_remote:
            source = self.ledger
            if self.cfg.cloud.enabled:
                from trustgate.core.sync import CloudResolutions

                source = CloudResolutions(self.cfg.cloud, self.ledger)
            return {"ok": True, "response": hook_mod._await_remote_decision(
                decision, self.cfg, source=source)}
        return {"ok": True, "response": hook_mod.to_hook_response(decision)}

    def op_observe(self, request: dict, caller_uid: int | None) -> dict:
        payload = request.get("payload")
        if isinstance(payload, dict):
            resolution_hook.record(payload, ledger=_RecordOnly(self.ledger))
        return {"ok": True}

    def op_resolve(self, request: dict, caller_uid: int | None) -> dict:
        from trustgate.core.models import Approver, Outcome

        request_id = str(request.get("request_id", ""))
        outcome = Outcome(request.get("outcome", ""))
        if outcome not in (Outcome.approved, Outcome.denied):
            return {"ok": False, "error": "outcome must be approved or denied"}
        if request_id not in self.ledger.escalations:
            return {"ok": False, "error": "no escalation with that request id"}
        if self.ledger.find_resolution(request_id) is not None:
            return {"ok": False, "error": "this escalation has already been answered"}
        name = str(request.get("approver", "")).strip()
        if not name:
            return {"ok": False, "error": "an approval must name the person giving it"}
        entry = self.ledger.write_resolution(
            request_id=request_id,
            outcome=outcome,
            approver=Approver(
                id=name,
                method=f"{ADMIN_METHOD}, OS user unix:{caller_uid}",
            ),
            detail=str(request.get("note", "")),
            gated=True,
        )
        return {"ok": True, "entry": entry.model_dump(mode="json")}

    def op_policy_install(self, request: dict, caller_uid: int | None) -> dict:
        """Replace the policy. Admin socket only. Recorded with who did it."""
        text = request.get("policy_text")
        by = str(request.get("by", "")).strip()
        if not isinstance(text, str) or not text.strip():
            return {"ok": False, "error": "policy_text is required"}
        if not by:
            return {"ok": False, "error": "a policy change must name the person making it"}
        try:
            new = Constitution.from_yaml(text, source="policy-install")
        except Exception as exc:  # noqa: BLE001 - ConstitutionError and friends
            return {"ok": False, "error": f"policy not installed: {exc}"}
        with self._lock:
            old = self.engine.c.digest
            if new.digest == old:
                return {"ok": True, "unchanged": True, "digest": old}
            tmp = self.policy_path.with_name("policy.yaml.new")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.replace(tmp, self.policy_path)
            self.engine = self._build_engine()
            entry = self.ledger.write_policy_change(
                old, self.engine.c.digest, by=by, os_uid=caller_uid,
                note=str(request.get("note", "")),
            )
        return {"ok": True, "old_digest": old, "new_digest": self.engine.c.digest,
                "seq": entry.seq}


# -- sockets ----------------------------------------------------------------


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        line = self.rfile.readline(MAX_REQUEST_BYTES + 1)
        if len(line) > MAX_REQUEST_BYTES:
            reply = {"ok": False, "error": "request too large"}
        else:
            try:
                request = json.loads(line)
                if not isinstance(request, dict):
                    raise ValueError("request must be a JSON object")
            except ValueError as exc:
                reply = {"ok": False, "error": f"bad request: {exc}"}
            else:
                reply = self.server.room.handle(
                    request, peer_uid(self.connection), self.server.admin
                )
        self.wfile.write(json.dumps(reply).encode("utf-8") + b"\n")


class _Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    # The default queue is 5 pending connections. Claude Code runs tool calls
    # in parallel, and a refused connection means the hook falls back to deny.
    request_queue_size = 256

    def __init__(self, path: Path, room: GuardRoom, admin: bool, mode: int) -> None:
        if path.exists() or path.is_symlink():
            path.unlink()
        old = os.umask(0o177)  # never exists, even briefly, with wider access
        try:
            super().__init__(str(path), _Handler)
        finally:
            os.umask(old)
        os.chmod(path, mode)
        self.room, self.admin = room, admin


def serve(state_dir: str | Path, run_dir: str | Path, config: Config | None = None,
          ready: threading.Event | None = None) -> tuple[_Server, _Server]:
    """Start both sockets in background threads and return the servers."""
    room = GuardRoom(state_dir, config)
    run = Path(run_dir)
    run.mkdir(parents=True, exist_ok=True)
    os.chmod(run, 0o755)
    agent = _Server(run / "agent.sock", room, admin=False, mode=0o666)
    admin = _Server(run / "admin.sock", room, admin=True, mode=0o600)
    for server in (agent, admin):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    if ready is not None:
        ready.set()
    return agent, admin


def request(socket_path: str | Path, message: dict[str, Any], timeout: float = 30.0) -> dict:
    """Send one request to a guard room socket. For the CLI and tests."""
    import socket

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(str(socket_path))
        conn.sendall(json.dumps(message).encode("utf-8") + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data or b"{}")
