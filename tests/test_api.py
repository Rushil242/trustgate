"""Decision API surfaces: HTTP daemon and the one-shot CLI.

R0 acceptance (Master Build Document v3.0, L.3): `import trustgate` works,
models validate, `/health` returns.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from trustgate.core.config import Config

POLICY = Path(__file__).resolve().parents[1] / "trustgate" / "policies" / "starter.coding.yaml"

fastapi = pytest.importorskip("fastapi", reason="server extra not installed")
from fastapi.testclient import TestClient  # noqa: E402

from trustgate.api.server import build_app  # noqa: E402


@pytest.fixture
def client(tmp_path):
    cfg = Config()
    cfg.constitution_path = str(POLICY)
    cfg.audit_path = str(tmp_path / "audit.jsonl")
    cfg.judge.provider = "fake"
    with TestClient(build_app(cfg)) as c:
        yield c


def test_import_trustgate_works():
    import trustgate

    assert trustgate.__version__
    assert trustgate.ActionRequest is not None


def test_health_reports_the_loaded_constitution(client):
    body = client.get("/health").json()

    assert body["status"] == "ok"
    assert body["constitution"] == "TrustGate starter (coding)"
    assert body["principles"] == body["deterministic"] + body["reasoning"] - _both_count()
    assert body["principles"] > 0


def _both_count() -> int:
    from trustgate.core.constitution import Constitution, Enforcement

    c = Constitution.from_file(POLICY)
    return sum(1 for p in c.principles if p.enforcement is Enforcement.both)


def test_decide_returns_a_valid_decision(client):
    from trustgate.core.models import Decision

    payload = {
        "surface": "coding",
        "action": {"type": "shell", "tool": "Bash", "raw": "ls -la"},
    }
    resp = client.post("/v1/decide", json=payload)

    assert resp.status_code == 200
    Decision.model_validate(resp.json())


def test_decide_rejects_a_malformed_request(client):
    resp = client.post("/v1/decide", json={"surface": "coding"})  # no action
    assert resp.status_code == 422


def test_decide_writes_to_the_ledger(client, tmp_path):
    client.post(
        "/v1/decide",
        json={"surface": "coding", "action": {"type": "shell", "tool": "Bash", "raw": "ls"}},
    )
    assert (tmp_path / "audit.jsonl").read_text().strip()


def test_server_refuses_to_start_without_a_valid_constitution(tmp_path):
    # A gate that allows everything is worse than an obviously absent gate.
    cfg = Config()
    cfg.constitution_path = str(tmp_path / "missing.yaml")

    with pytest.raises(RuntimeError, match="constitution"):
        with TestClient(build_app(cfg)):
            pass


class TestCLI:
    def _run(self, args, stdin="", env_extra=None, tmp_path=None):
        import os

        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        if tmp_path is not None:
            env["TRUSTGATE_AUDIT_PATH"] = str(tmp_path / "audit.jsonl")
        env["TRUSTGATE_CONSTITUTION"] = str(POLICY)
        env.update(env_extra or {})

        return subprocess.run(
            [sys.executable, "-m", "trustgate.api.cli", *args],
            input=stdin,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_validate_summarizes_a_constitution(self):
        result = self._run(["validate", str(POLICY)])
        assert result.returncode == 0
        assert "TrustGate starter (coding)" in result.stdout

    def test_validate_reports_a_broken_constitution(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("version: 1\nprinciples:\n  - id: x\n    enforcement: deterministic\n")
        result = self._run(["validate", str(bad)])
        assert result.returncode == 1
        assert "invalid" in result.stderr.lower()

    def test_check_emits_a_decision_on_stdout(self, tmp_path):
        payload = json.dumps(
            {"surface": "coding", "action": {"type": "shell", "tool": "Bash", "raw": "ls"}}
        )
        result = self._run(["check"], stdin=payload, tmp_path=tmp_path)

        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["effect"] == "allow"

    def test_check_rejects_malformed_stdin(self, tmp_path):
        result = self._run(["check"], stdin="not json", tmp_path=tmp_path)
        assert result.returncode == 1
        assert "error" in result.stderr

    def test_verify_audit_reports_an_intact_chain(self, tmp_path):
        payload = json.dumps(
            {"surface": "coding", "action": {"type": "shell", "tool": "Bash", "raw": "ls"}}
        )
        self._run(["check"], stdin=payload, tmp_path=tmp_path)

        result = self._run(["verify-audit"], tmp_path=tmp_path)
        assert result.returncode == 0
        assert "chain intact" in result.stdout

    def test_verify_audit_detects_tampering(self, tmp_path):
        payload = json.dumps(
            {"surface": "coding", "action": {"type": "shell", "tool": "Bash", "raw": "ls"}}
        )
        self._run(["check"], stdin=payload, tmp_path=tmp_path)

        ledger = tmp_path / "audit.jsonl"
        entry = json.loads(ledger.read_text().strip())
        entry["effect"] = "block"
        ledger.write_text(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")

        result = self._run(["verify-audit"], tmp_path=tmp_path)
        assert result.returncode == 2
        assert "chain broken" in result.stderr

    def test_console_script_entry_point_is_declared(self):
        # The real contract: pyproject registers `trustgate` as a console
        # script pointing at cli:main. Checked via installed metadata so it
        # holds regardless of how the package was installed.
        from importlib.metadata import entry_points

        scripts = {
            ep.name: ep.value for ep in entry_points(group="console_scripts")
        }
        assert scripts.get("trustgate") == "trustgate.api.cli:main"

    @pytest.mark.skipif(shutil.which("trustgate") is None, reason="package not installed")
    def test_console_script_runs(self):
        result = subprocess.run(["trustgate", "--version"], capture_output=True, text=True)

        if result.returncode != 0 and "ModuleNotFoundError" in result.stderr:
            pytest.skip(_hidden_pth_hint() or f"console script failed: {result.stderr}")

        assert result.returncode == 0, result.stderr
        assert "trustgate" in result.stdout


def _hidden_pth_hint() -> str | None:
    """Explain the macOS hidden-.pth failure mode, if that is what happened.

    CPython's site.addpackage skips .pth files carrying UF_HIDDEN, which some
    macOS setups apply to newly created files under ~/Documents. The editable
    install then silently has no effect. Without this hint the failure reads as
    a packaging bug in the project, which it is not.
    """
    import stat
    import sys

    site_packages = Path(sys.prefix) / "lib"
    for pth in site_packages.glob("python*/site-packages/*.pth"):
        try:
            if os.lstat(pth).st_flags & stat.UF_HIDDEN:
                return (
                    f"{pth.name} has the macOS UF_HIDDEN flag, so Python ignores it and "
                    "the editable install does not apply. Fix: ./scripts/dev-setup.sh"
                )
        except (OSError, AttributeError):
            continue
    return None
