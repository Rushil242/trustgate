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

import os
import re
import sys
from pathlib import Path

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
    PATH_PARAM_KEYS,
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


# TrustGate's own files. Text markers rather than globs, matched
# case-insensitively anywhere in the action, because the attacks on these files
# arrive in every spelling: `cd .claude/hooks && printf ... > x`, a Python
# one-liner that opens `~/.trustgate/config.toml`, a `mv` of settings.json.
SELF_MARKERS: tuple[str, ...] = (
    ".trustgate",               # ~/.trustgate/ (config, ledger, pins) and project .trustgate/
    "trustgate.constitution",   # the policy file
    "trustgate-pretooluse",     # the hook scripts
    "trustgate-resolution",
    "pinned-policies",
    "plugins/data/trustgate",   # the plugin's own venv
    ".claude/settings",         # what decides whether the hook runs at all
    ".claude/hooks",
)

# CLI subcommands that change what the gate trusts. A person runs these; an
# agent running them is approving itself.
SELF_APPROVING_COMMANDS: frozenset[str] = frozenset({"approve", "pin-policy", "init"})


def _self_markers(policy_source: str) -> list[str]:
    markers = list(SELF_MARKERS)
    home = os.environ.get("TRUSTGATE_HOME")
    if home:
        markers.append(home)
    if policy_source:
        markers += [policy_source, Path(policy_source).name]
    if sys.prefix != sys.base_prefix:  # running from a venv: its files are the gate
        markers.append(sys.prefix)
    return [m.lower() for m in markers if m]


def touches_trustgate(req: ActionRequest, policy_source: str = "") -> str:
    """What part of TrustGate itself this action could change, or "".

    Built in, not policy: a gate whose own files are writable by the thing it
    gates is only a suggestion, and the policy file is one of those files. So
    no policy can switch this off. Reads by structured file tools are allowed
    (reading the ledger is how a person checks it); everything else that names
    these files goes to a person. This is a speed bump until Phase 1 moves the
    gate to its own OS user, where the operating system enforces it instead.
    """
    if req.action.type is ActionType.file_read:
        return ""

    if req.action.type is ActionType.shell:
        text = req.action.raw or str(req.action.params.get("command", ""))
    else:
        # Paths only. The content of a file being written may mention these
        # names (a README about installing hooks) without touching them.
        text = "\n".join(
            str(v) for k, v in (req.action.params or {}).items()
            if k.lower() in PATH_PARAM_KEYS and isinstance(v, str)
        )
        if req.action.type is ActionType.file_write:
            text += "\n" + (req.action.raw or "")  # the hook puts the target path here
    text = text.lower()
    for marker in _self_markers(policy_source):
        if marker in text:
            return marker

    if req.action.type is ActionType.shell:
        tokens = shell_tokens(req.action.raw or str(req.action.params.get("command", "")))
        for i, token in enumerate(tokens):
            name = token.rstrip("/").rsplit("/", 1)[-1].lower()
            if name == ".claude":
                # `cd .claude && mv settings.json x`: the folder that decides
                # whether this hook runs, reached in two steps.
                return ".claude"
            if name == "trustgate" and i + 1 < len(tokens):
                if tokens[i + 1].lower() in SELF_APPROVING_COMMANDS:
                    return f"trustgate {tokens[i + 1]}"
            if name in ("kill", "pkill", "killall") and any(
                "trustgate" in t.lower() for t in tokens[i + 1 :]
            ):
                return "a TrustGate process"
    return ""


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

        hit = touches_trustgate(req, getattr(self.c, "source", ""))
        if hit:
            reasons.append(
                Reason(
                    guard=self.name,
                    rule_id="protect-trustgate",
                    message=(
                        "Built-in rule: actions that could change TrustGate itself (its "
                        f"policy, log, hooks, settings or install) need a person ({hit})"
                    ),
                    severity="critical",
                )
            )
            verdict = combine_verdicts(verdict, Verdict.escalate)
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
