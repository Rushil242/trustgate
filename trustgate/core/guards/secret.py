"""Secret/Data Guard — detect and redact secrets and PII.

Two responsibilities, deliberately separable:

* `redact()` is a pure function used by the audit ledger on every write and by
  the judge before any content reaches a model. A ledger that persists raw
  credentials is worse than no ledger at all.
* `SecretGuard.check()` catches a *literal* secret being carried by an action —
  a key pasted into a command line, a token in a tool parameter. That is a
  different failure from `cat .env`, which never contains the secret in its own
  text and is the Action Guard's job.

V1 uses high-precision patterns rather than a trained model: every redaction
traces to a named rule, which is what makes the audit log defensible. Presidio
or NER for free-form names is a later upgrade.

Spec: Master Build Document v3.0, Part E.3.
"""

from __future__ import annotations

import re
from typing import Any

from trustgate.core.guards import BaseGuard
from trustgate.core.models import ActionRequest, GuardResult, Reason, Verdict

# Ordered: the most specific patterns run first so a token inside a connection
# string is labelled as the token, not as the surrounding URI.
PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_pat": re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    "stripe": re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "anthropic_key": re.compile(r"\bsk-ant-[0-9A-Za-z_-]{20,}\b"),
    "openai_key": re.compile(r"\bsk-(?:proj-)?[0-9A-Za-z_-]{20,}\b"),
    "google_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END "
        r"(?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        re.DOTALL,
    ),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "conn_string": re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@]+@\S+"
    ),
    "ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]*[A-Za-z]\b"),
}

# Payment cards get their own pass: a bare digit-run regex is far too eager
# (it matches phone numbers, order ids, epoch timestamps), so candidates are
# length-checked against real card lengths and Luhn-verified.
# See DEVIATIONS.md #3.
_CARD_CANDIDATE = re.compile(r"(?<![\d.-])(?:\d[ -]?){12,18}\d(?![\d.-])")

# Secret kinds that are credentials rather than personal data. Only these make
# the guard act on an action; an email address in a commit message is not a
# reason to interfere with the commit.
CREDENTIAL_KINDS: frozenset[str] = frozenset(
    {
        "aws_key", "github_pat", "slack_token", "stripe", "anthropic_key",
        "openai_key", "google_key", "private_key", "jwt", "conn_string",
    }
)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _redact_cards(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        digits = re.sub(r"[ -]", "", m.group(0))
        if not (13 <= len(digits) <= 19) or not _luhn_ok(digits):
            return m.group(0)
        return "<REDACTED:card>"

    return _CARD_CANDIDATE.sub(repl, text)


def redact(text: str) -> str:
    """Replace detected secrets with `<REDACTED:kind>` markers."""
    if not text:
        return text
    for name, pattern in PATTERNS.items():
        text = pattern.sub(f"<REDACTED:{name}>", text)
    return _redact_cards(text)


def detect(text: str) -> list[str]:
    """Kinds of secret present in `text`, without redacting it."""
    if not text:
        return []
    found = [name for name, pattern in PATTERNS.items() if pattern.search(text)]
    if "<REDACTED:card>" in _redact_cards(text):
        found.append("card")
    return found


def redact_value(value: Any) -> Any:
    """Recursively redact strings inside a JSON-shaped value."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    return value


class SecretGuard(BaseGuard):
    name = "secret"

    def check(self, req: ActionRequest) -> GuardResult:
        action_text = "\n".join(
            [req.action.raw, *(f"{k}={v}" for k, v in (req.action.params or {}).items())]
        )
        kinds = detect(action_text)
        credential_kinds = [k for k in kinds if k in CREDENTIAL_KINDS]

        if not credential_kinds:
            return GuardResult(verdict=Verdict.allow)

        # Hand back redacted copies. The engine surfaces these as
        # Decision.modifications; a V1 coding adapter refuses rather than
        # rewriting a command, because silently altering a command the agent
        # believes it ran is its own kind of unsafe.
        return GuardResult(
            verdict=Verdict.modify,
            reasons=[
                Reason(
                    guard=self.name,
                    rule_id="secret-in-action",
                    message=(
                        "Action carries a literal credential ("
                        + ", ".join(sorted(set(credential_kinds)))
                        + "); it must not be sent onward or logged in the clear"
                    ),
                    severity="critical",
                )
            ],
            modifications={
                "params": redact_value(req.action.params or {}),
                "raw": redact(req.action.raw),
            },
        )
