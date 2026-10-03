"""Runtime configuration.

Resolution order, lowest priority first: built-in defaults, then
`~/.trustgate/config.toml`, then environment variables. Environment wins so a
hook or CI job can override without editing a file.

Secrets (API keys) are read from the environment only — they are never accepted
from the TOML file, so a config file is safe to commit or share.

Spec: Master Build Document v3.0, Part K.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_HOME = Path(os.environ.get("TRUSTGATE_HOME", Path.home() / ".trustgate"))
CONFIG_FILENAME = "config.toml"


@dataclass
class JudgeConfig:
    """Which model backs the Constitution Guard, and how patient we are.

    `fake` is the default on purpose: the engine must be runnable, testable and
    red-teamable with no key and no network. A judge is an enhancement to the
    deterministic floor, never a prerequisite for it.
    """

    provider: str = "fake"
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    timeout: float = 4.0
    enabled: bool = True

    # OpenRouter and Groq are OpenAI-compatible, so they differ only by URL.
    PRESETS: dict[str, dict[str, str]] = field(
        default_factory=lambda: {
            "openrouter": {
                "base_url": "https://openrouter.ai/api/v1",
                "model": "meta-llama/llama-3.3-70b-instruct:free",
                "key_env": "OPENROUTER_API_KEY",
            },
            "groq": {
                "base_url": "https://api.groq.com/openai/v1",
                "model": "llama-3.3-70b-versatile",
                "key_env": "GROQ_API_KEY",
            },
            "anthropic": {
                "base_url": "https://api.anthropic.com/v1",
                "model": "claude-sonnet-5",
                "key_env": "ANTHROPIC_API_KEY",
            },
            "local": {
                "base_url": "http://localhost:11434/v1",
                "model": "llama3.3",
                "key_env": "TRUSTGATE_LOCAL_API_KEY",
            },
        },
        repr=False,
    )


@dataclass
class ApprovalConfig:
    """Who answers an escalation, and how long the agent waits for them.

    `local` is the default and preserves the existing behaviour: the escalation
    is handed to the agent's own permission prompt, so the person at the
    keyboard decides. That is fine for one developer and useless for an audit,
    because the person being controlled is also the approver.

    `remote` holds the action and waits for a named person to answer in the
    console. It is the only mode where the approval is a control rather than a
    record, and it is opt-in because it makes an unattended agent stop dead.
    """

    mode: str = "local"
    timeout: float = 180.0
    poll_interval: float = 1.0

    on_timeout: str = "deny"
    """What an unanswered escalation becomes.

    `deny` is the default because "nobody answered" is not consent, and a gate
    that resolves silence into approval is not a gate. `ask` falls back to the
    agent's local prompt, which keeps work moving and gives up the separation
    between the person acting and the person approving. Choose knowingly.
    """

    @property
    def is_remote(self) -> bool:
        return self.mode.lower() == "remote"


@dataclass
class CloudConfig:
    """Where this machine ships its decisions, if anywhere.

    Empty `url` means local only, which is the default and stays fully
    functional. The API key is read from `TRUSTGATE_CLOUD_KEY` and never from
    the TOML file, for the same reason judge keys are not: a config file gets
    committed and shared, and a key in it is a key leaked.
    """

    url: str = ""
    machine: str = ""
    api_key: str = ""
    batch_size: int = 200
    timeout: float = 5.0

    @property
    def enabled(self) -> bool:
        return bool(self.url and self.api_key)

    @property
    def machine_id(self) -> str:
        if self.machine:
            return self.machine
        import socket

        return socket.gethostname() or "unknown-machine"


@dataclass
class Config:
    constitution_path: str = "trustgate.constitution.yaml"
    audit_path: str = field(default_factory=lambda: str(DEFAULT_HOME / "audit.jsonl"))
    judge: JudgeConfig = field(default_factory=JudgeConfig)
    approval: ApprovalConfig = field(default_factory=ApprovalConfig)
    cloud: CloudConfig = field(default_factory=CloudConfig)
    verbose: bool = False

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        cfg = cls()
        cfg._apply_toml(Path(path) if path else DEFAULT_HOME / CONFIG_FILENAME)
        cfg._apply_env()
        cfg._resolve_judge_preset()
        return cfg

    def _apply_toml(self, path: Path) -> None:
        if not path.is_file():
            return
        try:
            with path.open("rb") as fh:
                data: dict[str, Any] = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError):
            # A broken config file must not take the hook offline; defaults and
            # environment still apply, and `trustgate check` keeps working.
            return

        self.constitution_path = data.get("constitution", self.constitution_path)
        self.audit_path = data.get("audit_path", self.audit_path)
        self.verbose = bool(data.get("verbose", self.verbose))

        judge = data.get("judge", {})
        if isinstance(judge, dict):
            self.judge.provider = judge.get("provider", self.judge.provider)
            self.judge.model = judge.get("model", self.judge.model)
            self.judge.base_url = judge.get("base_url", self.judge.base_url)
            self.judge.timeout = float(judge.get("timeout", self.judge.timeout))
            self.judge.enabled = bool(judge.get("enabled", self.judge.enabled))

        cloud = data.get("cloud", {})
        if isinstance(cloud, dict):
            self.cloud.url = str(cloud.get("url", self.cloud.url)).rstrip("/")
            self.cloud.machine = str(cloud.get("machine", self.cloud.machine))
            try:
                self.cloud.batch_size = int(cloud.get("batch_size", self.cloud.batch_size))
                self.cloud.timeout = float(cloud.get("timeout", self.cloud.timeout))
            except (TypeError, ValueError):
                pass

        approval = data.get("approval", {})
        if isinstance(approval, dict):
            self.approval.mode = approval.get("mode", self.approval.mode)
            self.approval.timeout = float(approval.get("timeout", self.approval.timeout))
            self.approval.poll_interval = float(
                approval.get("poll_interval", self.approval.poll_interval)
            )
            self.approval.on_timeout = approval.get("on_timeout", self.approval.on_timeout)

    def _apply_env(self) -> None:
        env = os.environ
        self.constitution_path = env.get("TRUSTGATE_CONSTITUTION", self.constitution_path)
        self.audit_path = env.get("TRUSTGATE_AUDIT_PATH", self.audit_path)
        self.judge.provider = env.get("TRUSTGATE_JUDGE_PROVIDER", self.judge.provider)
        if "TRUSTGATE_JUDGE_TIMEOUT" in env:
            try:
                self.judge.timeout = float(env["TRUSTGATE_JUDGE_TIMEOUT"])
            except ValueError:
                pass
        if env.get("TRUSTGATE_JUDGE_ENABLED", "").lower() in ("0", "false", "no"):
            self.judge.enabled = False
        if env.get("TRUSTGATE_VERBOSE", "").lower() in ("1", "true", "yes"):
            self.verbose = True

        self.cloud.url = env.get("TRUSTGATE_CLOUD_URL", self.cloud.url).rstrip("/")
        self.cloud.machine = env.get("TRUSTGATE_CLOUD_MACHINE", self.cloud.machine)
        self.cloud.api_key = env.get("TRUSTGATE_CLOUD_KEY", "")

        self.approval.mode = env.get("TRUSTGATE_APPROVAL_MODE", self.approval.mode)
        self.approval.on_timeout = env.get(
            "TRUSTGATE_APPROVAL_ON_TIMEOUT", self.approval.on_timeout
        )
        for var, attr in (
            ("TRUSTGATE_APPROVAL_TIMEOUT", "timeout"),
            ("TRUSTGATE_APPROVAL_POLL_INTERVAL", "poll_interval"),
        ):
            if var in env:
                try:
                    setattr(self.approval, attr, float(env[var]))
                except ValueError:
                    pass

    def _resolve_judge_preset(self) -> None:
        """Fill blank judge fields from the provider preset and environment."""
        provider = self.judge.provider.lower()
        preset = self.judge.PRESETS.get(provider)
        if preset is None:
            return

        env = os.environ
        per_provider_model = env.get(f"TRUSTGATE_{provider.upper()}_MODEL", "")
        per_provider_url = env.get(f"TRUSTGATE_{provider.upper()}_BASE_URL", "")

        self.judge.model = self.judge.model or per_provider_model or preset["model"]
        self.judge.base_url = self.judge.base_url or per_provider_url or preset["base_url"]
        self.judge.api_key = env.get(preset["key_env"], "")
