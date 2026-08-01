"""Provider-agnostic LLM connector for the Constitution Guard.

The judge is the one place TrustGate calls a model, and the engine must never
depend on a specific vendor being reachable. Three backends share one interface:

* `FakeLLM`   — deterministic, offline, free. The default, and what the test
                suite and red-team runner use so results are reproducible.
* `OpenAICompatLLM` — OpenRouter, Groq, and any local OpenAI-compatible server
                (Ollama, vLLM, llama.cpp). These differ only by base URL, model
                id and key, so one client covers all of them.
* `AnthropicLLM`    — the Messages API, whose request shape differs enough to
                warrant its own small client.

`httpx` is imported lazily: `trustgate check` runs on every agent tool call and
must not pay an HTTP library's import cost when the judge is not consulted.

Spec: Master Build Document v3.0, Appendix 2.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from trustgate.core.config import JudgeConfig


class LLMError(Exception):
    """Any judge failure: transport, auth, timeout, or unparseable output.

    The engine catches this and fails safe. It is a distinct type precisely so
    that "the judge was unreachable" can never be mistaken for "the judge
    approved this".
    """


class LLM(Protocol):
    def complete(self, prompt: str) -> str: ...


class FakeLLM:
    """Offline judge stand-in.

    Returns a well-formed "no violations" verdict, so an engine with no API key
    behaves exactly like one whose judge found nothing — the deterministic
    guards still do their job. Tests that need a violating judge inject their
    own canned response via `scripted`.
    """

    def __init__(self, scripted: str | None = None) -> None:
        self.scripted = scripted
        self.calls: list[str] = []

    def complete(self, prompt: str) -> str:
        self.calls.append(prompt)
        if self.scripted is not None:
            return self.scripted
        return json.dumps({"violations": [], "verdict": "allow"})


class OpenAICompatLLM:
    """Chat-completions client for OpenRouter, Groq and local servers."""

    def __init__(self, cfg: JudgeConfig) -> None:
        if not cfg.base_url:
            raise LLMError(f"no base_url configured for provider {cfg.provider!r}")
        self.cfg = cfg

    def complete(self, prompt: str) -> str:
        import httpx  # lazy: keeps the hook's hot path free of HTTP imports

        headers = {"Content-Type": "application/json"}
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"
        if "openrouter" in self.cfg.base_url:
            # OpenRouter attributes traffic via these; harmless elsewhere.
            headers["HTTP-Referer"] = "https://github.com/trustgate/trustgate"
            headers["X-Title"] = "TrustGate"

        payload: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "max_tokens": 512,
        }

        try:
            resp = httpx.post(
                f"{self.cfg.base_url.rstrip('/')}/chat/completions",
                headers=headers,
                json=payload,
                timeout=self.cfg.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"] or ""
        except Exception as exc:  # noqa: BLE001 — all failures collapse to fail-safe
            raise LLMError(f"{self.cfg.provider} judge call failed: {exc}") from exc


class AnthropicLLM:
    """Messages API client."""

    def __init__(self, cfg: JudgeConfig) -> None:
        self.cfg = cfg

    def complete(self, prompt: str) -> str:
        import httpx

        if not self.cfg.api_key:
            raise LLMError("ANTHROPIC_API_KEY is not set")

        try:
            resp = httpx.post(
                f"{self.cfg.base_url.rstrip('/')}/messages",
                headers={
                    "x-api-key": self.cfg.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.cfg.model,
                    "max_tokens": 512,
                    "temperature": 0,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=self.cfg.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return "".join(
                block.get("text", "") for block in data.get("content", [])
                if block.get("type") == "text"
            )
        except LLMError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise LLMError(f"anthropic judge call failed: {exc}") from exc


def build_llm(cfg: JudgeConfig) -> LLM:
    """Instantiate the configured backend.

    An unknown provider name falls back to `FakeLLM` rather than raising: a typo
    in a config file should degrade to "deterministic guards only", not take the
    agent's tool calls offline.
    """
    provider = cfg.provider.lower()
    if provider in ("fake", "none", "off"):
        return FakeLLM()
    if provider == "anthropic":
        return AnthropicLLM(cfg)
    if provider in ("openrouter", "groq", "local", "openai"):
        return OpenAICompatLLM(cfg)
    return FakeLLM()


def parse_judge_json(text: str) -> dict[str, Any]:
    """Extract the judge's JSON verdict defensively.

    Models wrap JSON in prose or code fences even when told not to, so this
    strips fences and falls back to the outermost brace-balanced span. An
    unparseable reply raises LLMError, which the engine treats as a judge
    failure and fails safe on — never as an approval.
    """
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1] if "```" in cleaned[3:] else cleaned[3:]
        if cleaned.lstrip().lower().startswith("json"):
            cleaned = cleaned.lstrip()[4:]
        cleaned = cleaned.strip("`").strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    start, depth = cleaned.find("{"), 0
    if start != -1:
        for i in range(start, len(cleaned)):
            if cleaned[i] == "{":
                depth += 1
            elif cleaned[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(cleaned[start : i + 1])
                    except json.JSONDecodeError:
                        break

    raise LLMError(f"judge returned unparseable output: {text[:200]!r}")
