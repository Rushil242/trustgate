# Changelog

All notable changes to this project are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Escalations now record their answer.** The ledger previously held the
  question ("a human must decide this") and never the outcome, so it could not
  answer the thing an auditor actually asks. A new `resolution` entry is
  appended into the same hash chain carrying the outcome, who answered, and how
  that was established.
- **Resolution hook for Claude Code** — registered by `trustgate init` on
  `PostToolUse`, `PostToolUseFailure` and `PermissionDenied`, matched to the
  original decision by `tool_use_id`. Writes nothing for actions that were never
  escalated. Never blocks and always exits 0.
- **`trustgate pending`** — lists escalations nobody answered, and exits
  non-zero when any are open. An unanswered escalation is a finding: the system
  asked for a decision and did not get one.
- `Context.correlation_id` carries the surface's own id for an action, so a
  later event can be matched back to the decision that escalated it.

### Notable design decisions

- **An unclassifiable answer is recorded as `unknown`, never as `approved`.**
  We observe the human's answer through Claude Code's events rather than owning
  the prompt, and `PostToolUseFailure` does not distinguish a refusal from an
  ordinary error. A wrong `unknown` costs an auditor one question; a wrong
  `approved` puts a person's name against a decision they never made.
- **Denial phrases must name the user.** An end-to-end run caught
  `EACCES: permission denied` being filed as a human refusal, because
  "permission denied" is the POSIX error string. Any phrase an operating system
  can emit on its own is excluded by rule.
- **Approver `method` is recorded next to the outcome.** "the tool subsequently
  ran, so permission was granted" is weaker evidence than "a named person
  clicked approve", and an auditor is entitled to see which one they have.

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
