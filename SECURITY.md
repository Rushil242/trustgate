# Security policy

TrustGate is a security control. A bypass in it is more serious than an ordinary
bug, because someone is relying on it to stop something.

## Public or private?

There are two kinds of finding, and they go to different places.

**Public: a gap in the default rules.** A new way to get an action past the
shipped starter policies (a new spelling of `cat .env`, a disguised destructive
command, a refund that skips the escalation). These are part of the
[Break TrustGate](CHALLENGE.md) challenge. Submit them as a pull request adding
one file to `redteam/community/`, or with the "I broke it" issue form. They are
fixed in public and credited.

**Private: a flaw that hurts everyone who runs TrustGate.** Report these
privately, as described below:

- The gate fails open: an error, timeout or malformed input results in `allow`.
- TrustGate crashes, or executes content instead of inspecting it.
- A credential reaches the audit log or a model prompt in the clear.
- A ledger edit that `trustgate verify-audit` reports as intact.
- The installer damages a user's configuration.

If you are not sure which kind you have, report it privately.

## Reporting a vulnerability privately

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
within **10**. This is a small project run by one person, not a vendor with an
on-call rota. Those are honest targets, not an SLA.

## What counts as a vulnerability

**In scope:**

- **A bypass.** Any action the shipped starter constitution should block,
  escalate, or redact, and does not. New spellings of a known attack are very
  much in scope. That is the whole `.env` bypass problem. Submit these publicly
  through the [challenge](CHALLENGE.md).
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

Every accepted bypass stays in the suite as a permanent regression case before
the fix is merged: as its own file in `redteam/community/`, or in
`redteam/payloads.coding.json` or `payloads.voice.json`.
The suite is CI-gated on zero missed attacks and zero false positives, so a
reported bypass cannot silently return.

## Supported versions

Pre-1.0. Only the latest release gets fixes.

## A note on the block rate

The published block rate is measured against payloads written by the same people
who wrote the defenses, which biases it upward. It means the known attack classes
are covered — not that the gate is unbypassable. Independent red-teaming is
welcome and is the most useful contribution you can make to this project.
