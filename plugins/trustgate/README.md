# TrustGate plugin for Claude Code

Installs TrustGate's hooks so every tool call is checked against plain-English rules before it runs.

```text
/plugin install trustgate --marketplace Rushil242/trustgate
```

| Hook | Script | What it does |
|---|---|---|
| SessionStart | `scripts/setup.sh` | Installs the engine into `${CLAUDE_PLUGIN_DATA}/venv` the first time, then returns at once |
| PreToolUse | `scripts/run.sh pretooluse` | Allow, deny or ask, with the rule that fired |
| PostToolUse, PostToolUseFailure, PermissionDenied | `scripts/run.sh resolution` | Records how an escalation ended. Never blocks |

- Policy: the project's `trustgate.constitution.yaml` if present, otherwise the shipped starter policy. `TRUSTGATE_CONSTITUTION` overrides both.
- Log: `~/.trustgate/audit.jsonl`, or `TRUSTGATE_AUDIT_PATH`. Check it with `trustgate verify-audit`.
- If the engine is not installed or cannot load, every action asks for approval. It never fails open.
- `trustgate init` still works if you prefer per-project hooks in `.claude/settings.json`. Use one or the other, not both, or each tool call is checked twice.
