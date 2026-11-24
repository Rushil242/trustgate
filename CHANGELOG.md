# Changelog

All notable changes to this project are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (guard room)

- **`trustgated`, the guard room** (`trustgate guardroom serve`): the gate as its
  own process, owning the policy, the log and a signing key. Two Unix sockets;
  the OS file mode decides who may approve. See `docs/GUARDROOM.md`.
- **Thin hook**: standard library only, run with `python -I`, socket path baked
  in, refuses when the daemon does not answer. A full hook call drops from
  about 160 ms to about 17 ms.
- **Signed ledger, version 2**: Ed25519 machine key, integer-only entries, a
  one-page format (`docs/LEDGER-FORMAT.md`) with fixed test vectors.
  `trustgate verify-audit --pubkey` checks signatures.
- **Policy changes are log entries**, with who made them, and the evidence
  pack lists them. Every decision records its protection level.
- **Installer for a separate OS user** (`deploy/install-guardroom.sh`) with a
  LaunchDaemon, a systemd unit and Claude Code managed settings.

### Security

- **Parallel hooks no longer break the log.** Each write takes a file lock and
  reads the end of the file, so the chain stays intact and the hook no longer
  slows down as the log grows.
- **Approvals are harder to fake.** With TrustGate Cloud configured, only the
  Cloud's answer counts, never a line in the local file. Locally, an answer
  must sit in an intact chain.
- **Pinned policy.** The hook trusts a policy file only if its hash was pinned
  with `trustgate pin-policy`, or it is an unchanged shipped starter. An
  unpinned policy still blocks; anything else goes to a person.
- **TrustGate protects its own files.** A built-in rule that no policy can
  remove sends actions on the policy, `~/.trustgate`, the hooks, `.claude`
  settings and the install to a person, as well as self-approving CLI commands.
- **Hook scripts run Python with `-P`,** so a `trustgate/` folder in a project
  cannot stand in for the real package.
- **The fake judge counts as no judge.** The shipped config now behaves exactly
  like the red-team suite: uncertainty goes to a person instead of being allowed.
- **No regex stall.** HTML comments are scanned in linear time, with a 50 ms
  budget for the whole Context Guard.
- **Money rules fail closed.** A threshold field that is not a plain number, or
  is missing on a named tool, goes to a person. Policies can say
  `unknown_tools: escalate`; the voice starter does.
- **More spellings covered:** case-insensitive paths, shell globs such as
  `.en*`, `rm -r` without `-f`, `$HOME` forms, force pushes in every spelling,
  `| /bin/sh`, `sh -c "$(curl ...)"`, `bash <(curl ...)`, lower-case SQL.
- **More secrets redacted in the log:** `-p<password>`, `Bearer` tokens,
  `--password`, and `NAME_PASSWORD=` style values.

### Changed

- Every decision records `policy_digest`, `action_digest` and `engine_version`.
  The evidence pack shows a policy history and warns when the policy changed
  during the period or was not the one applied.
- In a fleet pack, a reviewer's name comes only from the Cloud's own record.
- Fewer false alarms: README text, `.gitignore` edits, `.env.example`, commit
  messages and requests to localhost no longer ask for approval.
- README, threat model and pack wording now state the current limits plainly.

### Added

- **Break TrustGate challenge** (`CHALLENGE.md`): rules, scope, Hall of Fame
  and scoreboard for outside attempts to get an action past the default rules.
- **One-file community attacks** in `redteam/community/`. `trustgate test`
  loads every file for the surface being tested, lists an outside attack that
  gets through under "BYPASS FOUND" with its author, and marks it as a
  "Bypass found" error on GitHub pull requests. A malformed file is reported by
  name instead of crashing. New flags: `--community-dir`, `--no-community`.
- **"I broke it" issue form** for bypass reports.
- **Claude Code plugin** in `plugins/trustgate/`, with a marketplace file at
  `.claude-plugin/marketplace.json`. Installs the engine on first session start
  and asks about every action until the install works, so it never fails open.

### Changed

- `SECURITY.md` now separates public findings (gaps in the default rules, via
  the challenge) from private ones (failing open, crashes, secrets in the log,
  undetected log edits).
- Every mention of the 41/41 red-team result says it is self-measured.
- The CHANGELOG and README no longer describe TrustGate Cloud as hosted. It is
  built and runs locally, and is set up directly with each team in early access.

### Fixed

- The README claimed `echo ".env" >> .gitignore` is allowed. It is blocked by
  the starter `protect-secrets` rule; the README now says so as a known false
  positive.

## [0.2.0] — 2026-10-03

The release where TrustGate stops being only a gate and starts producing the
proof. Built around one situation: a deal sitting in procurement while a
customer's security team asks what your AI agent is allowed to do.

### Added

- **`trustgate sync`** — ships the local ledger to TrustGate Cloud, a separate
  store for a copy of the log. The cloud is built and runs locally today; it is
  not a hosted service yet, and is set up directly with each team in early
  access. Reads the ledger file rather than hooking the engine, so a
  slow or unreachable cloud never slows an agent; entries queue on disk. Stdlib
  only. The API key is read from `TRUSTGATE_CLOUD_KEY` and never from a config
  file. A refused history exits 2 and is never retried blindly.
- **Fleet approval** — with a cloud configured, remote approval waits on the
  fleet inbox, and the reviewer's answer is also written into the machine's own
  chain as a gated resolution.
- **Sample evidence pack** in `docs/sample/`, generated by the real command.
- **Evidence pack** — `trustgate evidence` turns the ledger into a document you
  can hand to a customer's security team. Self-contained HTML (prints to PDF),
  Markdown for pasting into a questionnaire reply, or JSON. Lists the controls
  in force with their plain-English statements, every blocked action, every
  escalation with who answered and whether that answer held the action, the
  chain verification result, and a mapping of common review questions to what
  the ledger can and cannot evidence.
- **Remote approval mode** — `approval.mode = "remote"` makes the gate wait for
  a named person to answer in the console before the action proceeds. Off by
  default. `trustgate init` now sizes the `PreToolUse` hook timeout above the
  approval window, since Claude Code kills a hook at its configured timeout and
  a short budget turns a waiting gate into a silent fallback to the local prompt.

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
- **Evidence pack summary said "Escalateed".** Fixed before it reached anyone.
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
