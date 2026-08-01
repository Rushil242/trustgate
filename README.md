# TrustGate

**A control and audit layer for AI agents.**

TrustGate sits between an AI agent and the actions it takes, decides
deterministically whether each proposed action is allowed — **allow / block /
modify / escalate to a human** — and records every decision in a tamper-evident,
exportable log.

You write the rules once, in plain English. TrustGate enforces them.

```yaml
- id: protect-secrets
  statement: "Never read, print, or transmit the contents of secret files."
  enforcement: deterministic
  severity: critical
  match:
    touches_paths: ["**/.env", "**/*.pem", "**/id_rsa"]
  effect: block
```

The engine is surface-agnostic; thin adapters connect it to specific agents.
V1 ships the engine plus a coding-agent adapter for Claude Code. A voice-agent
adapter is the immediate fast-follow.

---

## Status: R0 — contracts and skeleton

This repository is at milestone **R0**. What that means, precisely:

| Component | State |
|---|---|
| Wire contract (`ActionRequest` / `Decision` / `GuardResult`) | **Frozen** — additive changes only |
| Constitution format, parser, validation | **Complete** |
| Engine orchestration, precedence, short-circuiting, fail-safe | **Complete** |
| Tamper-evident audit ledger + `verify-audit` | **Complete** |
| Constitution Guard (LLM judge) + provider connector | **Complete** |
| Context / Action / Secret / Supply-Chain detection logic | **Stubbed — returns allow** |
| Claude Code adapter, `trustgate init`, `trustgate test` | **Not started** (R2 / F1) |

> **TrustGate does not block anything yet.** The four deterministic guards are
> structural stubs. The pipeline that runs them, the ledger that records them,
> and the contract they speak are real and tested; the detection patterns land
> in R1. Do not deploy this as a control.

## Why this exists

Better models get more autonomy and a bigger blast radius, so a layer that
bounds what an agent *may do* becomes more valuable as models improve, not less.
The durable parts are the boring, provable ones:

- **Deterministic enforcement** — reproducible controls that do not depend on a
  model's judgment, and cannot be talked out of a decision.
- **Tamper-evident audit** — a compliance artifact you can hand a regulator.
- **Cross-tool neutrality** — one policy across every agent a team runs. A
  platform vendor only ever secures its own tool.

The constitution and self-critique framing is the product's UX. The moat is the
audit trail and the deterministic floor beneath it.

## Architecture

```
Coding agent  ──hook────▶  ┌──────────────────────────┐  ──▶ Decision
(Claude Code)              │      TrustGate Core      │      (allow/block/
                           │  Policy Decision Point   │       modify/escalate)
Voice agent  ──gateway──▶  │  + guard pipeline        │
(any stack)                │  + audit ledger          │  ──▶ Tamper-evident log
                           └──────────────────────────┘
```

Adapters are **Policy Enforcement Points**: they intercept a proposed action,
package it as an `ActionRequest`, ask the engine, and enforce the answer. The
engine is the **Policy Decision Point**: it runs the guard pipeline and writes
the audit entry. Adapters stay small and surface-specific; the valuable logic is
centralized, tested once, and reused.

Guards run in a fixed order and short-circuit on a hard block:

```
Context → Action → Secret → Supply-Chain → (LLM judge, only when needed)
```

The deterministic guards target **under 50 ms combined**. The LLM judge is
consulted only when a guard is uncertain or a reasoning principle's prefilter
fires — most actions never reach a model.

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
./scripts/dev-setup.sh
```

That is `uv sync --all-extras` plus a macOS workaround (see
[Troubleshooting](#troubleshooting)). On Linux and Windows, plain
`uv sync --all-extras` is equivalent.

## Try it

```bash
uv run trustgate validate trustgate/policies/starter.coding.yaml
```

Decide on a single action:

```bash
echo '{"surface":"coding","action":{"type":"shell","tool":"Bash","raw":"ls -la"}}' | uv run trustgate check
```

Verify the audit chain is intact:

```bash
uv run trustgate verify-audit
```

Run the HTTP Decision API:

```bash
uv run trustgate serve --port 8000
```

## The constitution

A constitution is a YAML file of principles. Each has a stable `id`, a
plain-English `statement`, and an `enforcement` mode:

- `deterministic` — a compiled matcher. Fast, reproducible, no model call.
- `reasoning` — evaluated by the LLM judge. Catches phrasing no pattern
  anticipated, at the cost of latency and non-determinism.
- `both` — matched deterministically *and* reviewed by the judge.

The `statement` is what a human reads, what the judge is shown, and what appears
in the audit line — one sentence explains a block to a developer, an agent, and
an auditor.

Reasoning principles may carry a `match` block used purely as a cheap
**prefilter**: it enforces nothing, it only decides whether the principle is
worth a model call. This is what keeps the hot path free.

Starter policies: [`trustgate/policies/`](trustgate/policies/).

## The LLM judge

Provider-agnostic and **off by default**. `fake` is the default provider — the
engine must be runnable, testable and red-teamable with no key and no network.

| Provider | Notes |
|---|---|
| `fake` | Deterministic, offline, free. Used by the test suite. |
| `openrouter` | OpenAI-compatible. Free-tier models available. |
| `groq` | OpenAI-compatible. |
| `anthropic` | Messages API. |
| `local` | Any OpenAI-compatible server (Ollama, vLLM, llama.cpp). |

Configure via `.env` (see [`.env.example`](.env.example)) or
`~/.trustgate/config.toml`. Keys are read from the environment only, never from
the config file, so a config file is safe to share.

**A judge that fails is never a judge that approved.** Timeouts, transport
errors and unparseable output all fail safe: escalate when a critical principle
was in scope.

## Audit

Append-only JSONL where each line carries the hash of the line before it. Edit
any past entry and every hash after it breaks.

```bash
uv run trustgate verify-audit
# OK  chain intact — 41 entries verified
```

Two invariants: every decision is written including allows (a block-only log
cannot answer "what did this agent do on Tuesday"), and nothing reaches disk
unredacted.

## Development

```bash
uv run pytest
uv run ruff check .
```

## Troubleshooting

**`ModuleNotFoundError: No module named 'trustgate'` when the tests pass**

On some macOS setups, files created under `~/Documents` or `~/Desktop` get the
`UF_HIDDEN` file flag applied automatically — iCloud Drive sync and several
endpoint-security agents both do this. CPython's `site.addpackage` skips hidden
`.pth` files outright, so the editable install's path entry is silently ignored.

The symptom is confusing: `uv run pytest` passes (pytest injects its own
`pythonpath`) while `uv run trustgate` fails. Clearing the flag with `chflags
nohidden` does not stick; the agent re-applies it within seconds.

Check for it:

```bash
ls -lO .venv/lib/python*/site-packages/*.pth
```

If the listing says `hidden`, run `./scripts/dev-setup.sh`. It detects the
condition and places the virtualenv outside the affected tree, then prints the
`UV_PROJECT_ENVIRONMENT` line to add to your shell profile. Moving the
repository outside `~/Documents` and `~/Desktop` also resolves it permanently.

## Open core

Free and open source: the engine, all six guards, the constitution format, the
coding and voice adapters, local tamper-evident audit, the CLI, the HTTP daemon,
and the red-team suite. Anything that helps one developer.

Paid (TrustGate Cloud, not in this repository): fleet policy management across
repos and agents, dashboards and alerting, SSO/RBAC, immutable cloud audit with
SIEM export, compliance reporting, a hosted judge, and industry constitution
packs. Anything that helps a team prove and manage agent behaviour at scale.

## Documentation

- [`DEVIATIONS.md`](DEVIATIONS.md) — where this implementation departs from the
  v3.0 build document, and why.

## License

MIT — see [`LICENSE`](LICENSE).
