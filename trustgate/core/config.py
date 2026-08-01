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
class Config:
    constitution_path: str = "trustgate.constitution.yaml"
    audit_path: str = field(default_factory=lambda: str(DEFAULT_HOME / "audit.jsonl"))
    judge: JudgeConfig = field(default_factory=JudgeConfig)
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
