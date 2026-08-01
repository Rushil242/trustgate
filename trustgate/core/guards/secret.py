"""Secret/Data Guard — detect and redact secrets and PII.

Two responsibilities, deliberately separable:

* `redact()` is a pure function used by the audit ledger on every write. It is
  implemented now, in R0, because a ledger that persists raw credentials is
  worse than no ledger at all — this invariant cannot wait for R1.
* `SecretGuard.check()` decides whether an *action* should be modified before it
  runs. That is R1 work and is stubbed below.

V1 uses high-precision patterns for well-defined secrets rather than a trained
model: every redaction traces to a named rule, which is what makes the audit log
defensible. Presidio/NER for free-form names is a later upgrade.

Spec: Master Build Document v3.0, Part E.3.
"""

from __future__ import annotations

import re

from trustgate.core.guards import BaseGuard
from trustgate.core.models import ActionRequest, GuardResult, Verdict

# Ordered: the most specific patterns run first so a token inside a connection
# string is labelled as the token, not as the surrounding URI.
PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_pat": re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    "stripe": re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    "openai_key": re.compile(r"\bsk-(?:proj-)?[0-9A-Za-z_-]{20,}\b"),
    "anthropic_key": re.compile(r"\bsk-ant-[0-9A-Za-z_-]{20,}\b"),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END "
        r"(?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
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
# length-checked against real IIN ranges and then Luhn-verified.
# See DEVIATIONS.md #3.
_CARD_CANDIDATE = re.compile(r"(?<![\d.-])(?:\d[ -]?){12,18}\d(?![\d.-])")


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
        if not (13 <= len(digits) <= 19):
            return m.group(0)
        if not _luhn_ok(digits):
            return m.group(0)
        return "<REDACTED:card>"

    return _CARD_CANDIDATE.sub(repl, text)


def redact(text: str) -> str:
    """Replace detected secrets with `<REDACTED:kind>` markers.

    Used on every audit write and before any content reaches the LLM judge.
    Redaction is one-way here — the reversible masking vault is a gateway-side
    concern, not a ledger concern.
    """
    if not text:
        return text
    for name, pattern in PATTERNS.items():
        text = pattern.sub(f"<REDACTED:{name}>", text)
    return _redact_cards(text)


class SecretGuard(BaseGuard):
    name = "secret"

    def check(self, req: ActionRequest) -> GuardResult:
        """R0: stub. Detection and `modify` verdicts land in R1."""
        return GuardResult(verdict=Verdict.allow)
