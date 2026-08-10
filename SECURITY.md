# Security policy

TrustGate is a security control. A bypass in it is more serious than an ordinary
bug, because someone is relying on it to stop something.

## Reporting a vulnerability

**Do not open a public issue for a bypass.**

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**), which opens a private advisory visible
only to maintainers.

Useful to include:

- The action that should have been stopped and was not, ideally as an
  `ActionRequest` JSON or a red-team payload case
- The constitution you were running (redact anything sensitive)
- The version or commit
- What you expected, and what happened

You will get an acknowledgement within **3 working days** and an assessment
within **10**. This is a small project run by two people, not a vendor with an
on-call rota — those are honest targets, not an SLA.

## What counts as a vulnerability

**In scope:**

- **A bypass.** Any action the shipped starter constitution should block,
  escalate, or redact, and does not. New spellings of a known attack are very
  much in scope — that is the whole `.env` bypass problem.
- **A false negative in redaction.** A credential shape that reaches the audit
  log or a model prompt in the clear.
- **Audit tampering that verification does not catch.** A ledger edit that
  `trustgate verify-audit` reports as intact.
- **A fail-open path.** Any error, timeout, or malformed input that results in
  `allow` where the tables in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §4
  say it should escalate.
- **Injection into TrustGate itself.** Content that causes the engine to execute
  it rather than inspect it, or that manipulates the judge into approving an
  action.
- **Anything in the installer that damages a user's configuration**, especially
  loss of existing hooks in `settings.json`.

**Out of scope** — these are documented limits, not bugs. See
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §5:

- Anything requiring write access to TrustGate's own code, constitution, or
  ledger. A compromised host is out of the trust model.
- The operator disabling or uninstalling their own gate.
- The LLM judge reaching a different conclusion than you would. It is
  probabilistic by design; if a rule matters, make it `deterministic`.
- Denial of service. There is no rate limiting and that is known.
- Multi-turn attacks that build state across many turns. Not modeled in V1.
- A secret in a file whose name matches no glob in your policy. Denylists are
  incomplete by construction — extend `touches_paths`.

## Disclosure

Coordinated. We will agree a date with you, and default to publishing within
**90 days** of the report or immediately after a fix ships, whichever is sooner.
Credit is given unless you would rather not be named.

If a bypass is already public or being exploited, we will prioritize shipping the
fix over the timeline.

## Fixes come with a payload

Every accepted bypass is added to `redteam/payloads.coding.json` or
`payloads.voice.json` as a permanent regression case before the fix is merged.
The suite is CI-gated on zero missed attacks and zero false positives, so a
reported bypass cannot silently return.

## Supported versions

Pre-1.0. Only the latest release gets fixes.

## A note on the block rate

The published block rate is measured against payloads written by the same people
who wrote the defenses, which biases it upward. It means the known attack classes
are covered — not that the gate is unbypassable. Independent red-teaming is
welcome and is the most useful contribution you can make to this project.
