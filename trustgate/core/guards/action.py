"""Action Guard — deterministic enforcement. The star of V1.

Two jobs:

1. Run every deterministic principle's compiled matcher against the request.
2. Normalize the action before matching, so a rule survives paraphrase. This is
   the `.env`-bypass defense: policy says "never read secret files", not "never
   run `cat .env`", so `echo $(cat .env)`, `grep KEY .env` and `while read < .env`
   all have to fall to the same rule.

Spec: Master Build Document v3.0, Part E.2.

R0 status: stubbed. This is the guard the red-team suite exists to attack, so it
is built in R1 against `redteam/payloads.coding.json` rather than written blind
here — a matcher with no adversarial tests behind it is a false sense of safety.
"""

from __future__ import annotations

from trustgate.core.guards import BaseGuard
from trustgate.core.models import ActionRequest, GuardResult, Verdict

# Utilities that can disclose a file's contents. R1 parses the command and
# checks whether any of these touch a protected path, rather than pattern
# matching on one spelling of one tool.
SECRET_READERS: tuple[str, ...] = (
    "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "awk", "sed",
    "nl", "od", "xxd", "strings", "base64", "cp", "mv", "scp", "rsync", "curl", "tee",
)

SECRET_PATH_GLOBS: tuple[str, ...] = (
    "**/.env", "**/.env.*", "**/credentials", "**/credentials.*", "**/*.pem",
    "**/id_rsa", "**/id_ed25519", "**/*.key", "**/.aws/*", "**/.ssh/*",
    "**/.netrc", "**/*.p12", "**/*.pfx",
)


class ActionGuard(BaseGuard):
    name = "action"

    def check(self, req: ActionRequest) -> GuardResult:
        """R0: stub. Compiled matchers + secret-read normalization land in R1."""
        return GuardResult(verdict=Verdict.allow)
