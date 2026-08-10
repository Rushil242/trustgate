"""Action Guard — deterministic enforcement. The star of V1.

Two jobs, in order:

1. Run every deterministic principle's compiled matcher against the request.
2. Apply two built-in normalizers that are too important to leave to regexes in
   a policy file:

   * **Secret-file access.** Policy says "never read secret files", not "never
     run `cat .env`". `echo $(cat .env)`, `grep KEY .env.production`,
     `base64 .env`, `cp .env /tmp/x` and `... done < .env` are the same act, and
     all of them must fall to the same rule.
   * **Recursive deletes, judged by target.** `rm -rf /` is unrecoverable;
     `rm -rf node_modules` is a build artifact `npm install` restores. Blocking
     both — which a bare `rm -rf` pattern does — teaches developers to switch
     the gate off, so the target decides.

Both are attributed to the constitution principle they enforce, so an audit line
still points at a sentence a human wrote.

Spec: Master Build Document v3.0, Part E.2.
"""

from __future__ import annotations

import re

from trustgate.core.guards import BaseGuard
from trustgate.core.models import (
    ActionRequest,
    ActionType,
    GuardResult,
    Reason,
    Verdict,
    combine_verdicts,
    effect_to_verdict,
)
from trustgate.core.normalize import (
    extract_paths,
    invoked_utilities,
    is_dangerous_delete,
    path_matches_glob,
    shell_tokens,
)

# Programs that can disclose, copy, or transmit a file's contents. Intersected
# against the command's tokens, so a protected path alone is not enough — the
# command has to actually do something with it. That keeps
# `echo ".env" >> .gitignore` allowed.
SECRET_READERS: frozenset[str] = frozenset(
    {
        "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg",
        "awk", "sed", "nl", "od", "xxd", "strings", "base64", "hexdump",
        "cp", "mv", "scp", "rsync", "tee", "install",
        "curl", "wget", "nc", "netcat", "ftp", "sftp",
        "python", "python3", "node", "ruby", "perl", "php",
        "source", ".", "read", "export", "env", "printenv",
        "tar", "zip", "gzip", "openssl", "git", "docker",
    }
)

SECRET_PATH_GLOBS: tuple[str, ...] = (
    "**/.env",
    "**/.env.*",
    "**/credentials",
    "**/credentials.*",
    "**/*.pem",
    "**/id_rsa",
    "**/id_dsa",
    "**/id_ecdsa",
    "**/id_ed25519",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/.aws/**",
    "**/.ssh/**",
    "**/.netrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/secrets.*",
    "**/service-account*.json",
)

# A read redirection: `... done < .env`. The token is already flattened out by
# shell_tokens, but matching the operator directly catches the case where the
# consuming program is a shell builtin we do not list.
_READ_REDIRECT = re.compile(r"<\s*([^\s;|&<>()]+)")


def _is_protected(candidate: str) -> bool:
    return any(path_matches_glob(candidate, g) for g in SECRET_PATH_GLOBS)


def protected_paths(action_type: str, tool: str, params: dict, raw: str) -> list[str]:
    """Paths in this action that match a protected-secret glob."""
    return [p for p in extract_paths(action_type, tool, params, raw) if _is_protected(p)]


def protected_tokens(command: str) -> list[str]:
    """Protected paths named anywhere in a shell command.

    Works off raw tokens rather than `extract_paths` because some of the most
    sensitive names are neither dotfiles nor extensioned — `id_rsa`,
    `credentials` — and a general-purpose path heuristic will not classify them
    as paths. Here the glob list is the authority.

    Leading sigils are stripped before comparison: `curl --data @.env` carries
    the filename as `@.env`, and an attacker should not get to smuggle a path
    past a glob by using the syntax the tool documents.
    """
    hits: list[str] = []
    for token in shell_tokens(command):
        if token.startswith("-"):
            continue
        for candidate in {token, token.lstrip("@<>=&")}:
            if candidate and _is_protected(candidate):
                hits.append(candidate)
                break
    return hits


def reads_secret_file(command: str) -> tuple[bool, str]:
    """Whether a shell command discloses a protected file. Returns (hit, path).

    The bypass defense: detection keys on *a protected path plus something that
    consumes it*, not on any particular spelling of any particular utility.
    Requiring a consumer is what keeps `echo ".env" >> .gitignore` allowed.
    """
    if not command:
        return False, ""

    hits = protected_tokens(command)
    if not hits:
        return False, ""

    if invoked_utilities(command) & SECRET_READERS:
        return True, hits[0]

    # Redirected into a shell builtin (`while read ... < .env`).
    for redirect_target in _READ_REDIRECT.findall(command):
        if _is_protected(redirect_target):
            return True, redirect_target

    # Command substitution around a protected path always resolves its contents.
    if re.search(r"\$\([^)]*\)|`[^`]*`", command):
        return True, hits[0]

    return False, ""


def _match_detail(principle, req: ActionRequest) -> str:
    """Name the concrete thing that tripped a path rule.

    "Never read secret files" tells an auditor the rule; "(this action touches
    .env)" tells them what happened. The first question asked of any blocked
    action is which file, so the answer belongs in the audit line.
    """
    globs = principle.match.touches_paths if principle.match else None
    if not globs:
        return ""

    paths = extract_paths(
        req.action.type.value, req.action.tool, req.action.params, req.action.raw
    )
    hits = [p for p in paths if any(path_matches_glob(p, g) for g in globs)]
    return f" (this action touches {hits[0]})" if hits else ""


class ActionGuard(BaseGuard):
    name = "action"

    def check(self, req: ActionRequest) -> GuardResult:
        reasons: list[Reason] = []
        verdict = Verdict.allow

        for principle in self.c.deterministic_principles:
            if principle.matches(req):
                reasons.append(
                    Reason(
                        guard=self.name,
                        rule_id=principle.id,
                        message=principle.statement + _match_detail(principle, req),
                        severity=principle.severity.value,
                    )
                )
                verdict = combine_verdicts(verdict, effect_to_verdict(principle.effect))

        verdict, reasons = self._apply_builtins(req, verdict, reasons)
        return GuardResult(verdict=verdict, reasons=reasons)

    def _apply_builtins(
        self, req: ActionRequest, verdict: Verdict, reasons: list[Reason]
    ) -> tuple[Verdict, list[Reason]]:
        """Normalizers that back a principle but are not expressible as a regex.

        Each only fires if the constitution actually contains the principle it
        enforces. TrustGate must not invent policy the operator did not write —
        a rule that is not in the file cannot appear in the audit log, and an
        unexplainable block is worse than a missed one.
        """
        already = {r.rule_id for r in reasons}

        secrets_principle = self.c.by_id("protect-secrets")
        if secrets_principle is not None and "protect-secrets" not in already:
            hit_path = self._secret_access(req)
            if hit_path:
                reasons.append(
                    Reason(
                        guard=self.name,
                        rule_id=secrets_principle.id,
                        message=(
                            f"{secrets_principle.statement} "
                            f"(this action reads {hit_path})"
                        ),
                        severity=secrets_principle.severity.value,
                    )
                )
                verdict = combine_verdicts(
                    verdict, effect_to_verdict(secrets_principle.effect)
                )

        destructive = self.c.by_id("no-destructive-shell")
        if destructive is not None and req.action.type is ActionType.shell:
            command = req.action.raw or str(req.action.params.get("command", ""))
            dangerous, target = is_dangerous_delete(command)
            if dangerous and "no-destructive-shell" not in already:
                reasons.append(
                    Reason(
                        guard=self.name,
                        rule_id=destructive.id,
                        message=(
                            f"{destructive.statement} "
                            f"(recursive force delete of {target})"
                        ),
                        severity=destructive.severity.value,
                    )
                )
                verdict = combine_verdicts(verdict, effect_to_verdict(destructive.effect))

        return verdict, reasons

    def _secret_access(self, req: ActionRequest) -> str:
        """Protected path this action touches, by whichever route it arrives."""
        if req.action.type is ActionType.shell:
            command = req.action.raw or str(req.action.params.get("command", ""))
            hit, path = reads_secret_file(command)
            return path if hit else ""

        # Structured file tools name their target directly, so there is no
        # command to parse: touching a protected path at all is the violation.
        if req.action.type in (ActionType.file_read, ActionType.file_write):
            hits = protected_paths(
                req.action.type.value, req.action.tool, req.action.params, req.action.raw
            )
            return hits[0] if hits else ""

        return ""
