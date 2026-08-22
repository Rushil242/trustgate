# Changelog

All notable changes to this project are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — first public release

The first version where TrustGate actually enforces policy end to end.

### Added

- **Core engine (PDP)** — guard pipeline with precedence, short-circuit on hard
  block, and fail-safe on every unresolved path.
- **Constitution** — YAML policy language with plain-English statements and
  three enforcement modes (`deterministic`, `reasoning`, `both`). Compiled
  matchers for surface, action type, tool, regex patterns, path globs, and
  numeric thresholds.
- **Five guards** — Context (injection heuristics), Action (destructive
  commands + secret-file access), Secret (literal credentials), Supply-chain
  (hook/MCP digest manifest), Constitution (LLM judge).
- **Tamper-evident audit ledger** — hash-chained JSONL with `verify-audit`
  detecting modification, deletion, reordering, and forged appends.
- **Claude Code adapter** — `PreToolUse` hook plus `trustgate init` installer
  that merges into `settings.json` and backs up before writing.
- **Voice adapter** — `guard_tool` decorator and `guarded_dispatch` gateway,
  with in-process and HTTP decision clients.
- **Red-team suite** — 41 adversarial payloads and 24 controls across both
  surfaces, CI-gated on zero misses and zero false positives.
- **CLI** — `init`, `check`, `approve`, `validate`, `test`, `serve`,
  `verify-audit`. HTTP Decision API and Docker image.
- Provider-agnostic LLM judge: `fake` (default, offline), OpenRouter, Groq,
  Anthropic, or any OpenAI-compatible local server.

### Notable design decisions

- **Recursive deletes are judged by target, not pattern.** A bare `rm -rf` rule
  also blocks `rm -rf node_modules`; a gate that blocks routine work gets
  switched off.
- **The Context Guard never hard-blocks.** Injection heuristics fire on innocent
  prose, so a hit returns `uncertain` and routes to a judgment.
- **Unresolved uncertainty escalates.** If a guard is unsure and no judge is
  available, the action goes to a human rather than through.

Sixteen documented departures from the original build specification are recorded
in [`DEVIATIONS.md`](DEVIATIONS.md), including one where the specified hook
response format would have made the gate report success while enforcing nothing.
