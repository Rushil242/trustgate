"""Action normalization — the layer that makes policy survive paraphrase.

The central insight of the Action Guard is that a rule must be written about
*what an action does*, not about how it happens to be spelled. "Never read secret
files" has to catch `cat .env`, `echo $(cat .env)`, `grep KEY .env`,
`while read < .env` and `base64 .env` — all of which are the same act wearing
different syntax.

So before any matching happens, an action is reduced to structured facts:

* `shell_tokens`  — the words of a command, with shell operators removed so that
  redirect targets and subshell contents become ordinary tokens.
* `extract_paths` — every filesystem path the action plausibly touches, from
  both shell text and structured tool parameters.
* `invoked_utilities` — which programs the command runs, by name.
* `rm_targets` / `is_dangerous_delete` — recursive-force deletes, judged by
  target rather than by the presence of `-rf`.

Nothing here makes policy decisions. It produces facts; the guards judge them.

Spec: Master Build Document v3.0, Part E.2.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex

# Shell metacharacters that separate words. Replacing them with whitespace turns
# `echo $(cat .env)` and `... done < .env` into flat token lists, which is what
# lets one rule cover both spellings.
_OPERATORS = re.compile(
    r"""
    \$\( | \) | `        |   # command substitution
    \|\| | \| | && | ;   |   # pipelines and separators
    >> | > | << | <      |   # redirections
    \n | \r                  # line breaks in multi-line commands
    """,
    re.VERBOSE,
)

# Keys whose values are paths in the tool schemas adapters map from.
_PATH_PARAM_KEYS = frozenset(
    {
        "file_path",
        "filepath",
        "path",
        "notebook_path",
        "target_file",
        "old_path",
        "new_path",
        "source",
        "destination",
        "dest",
        "output",
        "output_path",
        "config",
        "config_path",
    }
)

# A token that looks like a filesystem path rather than a flag or a URL.
# The dotfile alternative is load-bearing: `.env` has no extension and no
# separator, so an extension-or-slash heuristic misses the single most important
# path in the whole threat model.
_PATH_LIKE = re.compile(
    r"""
      ^(?: ~ | / | \.{1,2}/ )      # home-relative, absolute, or explicitly relative
    | /                            # contains a separator anywhere
    | ^\.[A-Za-z0-9][\w.-]*$       # dotfile: .env, .npmrc, .env.production
    | \.[A-Za-z0-9]{1,8}$          # ordinary file extension
    """,
    re.VERBOSE,
)

_URL_LIKE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def shell_tokens(command: str) -> list[str]:
    """Split a shell command into words, discarding operators.

    Falls back to whitespace splitting when the command is not lexically valid
    (unbalanced quotes, for example). Failing open on tokenization would be a
    bypass: an attacker could hide a payload behind a stray quote, so the
    fallback still yields tokens rather than an empty list.
    """
    if not command:
        return []

    flattened = _OPERATORS.sub(" ", command)
    try:
        tokens = shlex.split(flattened, posix=True)
    except ValueError:
        # Unbalanced quotes. Strip quote characters and split on whitespace so
        # the tokens are still inspectable.
        tokens = flattened.replace('"', " ").replace("'", " ").split()

    return [t for t in tokens if t]


def invoked_utilities(command: str) -> set[str]:
    """Program names the command runs, normalized to bare names.

    `/usr/bin/cat`, `cat` and `sudo cat` all yield "cat". Every token is
    considered, not just the first, because command substitution puts the
    interesting program in the middle: `echo $(cat .env)`.
    """
    utilities: set[str] = set()
    for token in shell_tokens(command):
        if token.startswith("-") or _URL_LIKE.match(token):
            continue
        name = posixpath.basename(token)
        if name and re.fullmatch(r"[\w.+-]+", name):
            utilities.add(name.lower())
    return utilities


def normalize_path(path: str) -> str:
    """Collapse a path to a comparable form without touching the filesystem.

    Deliberately does not resolve symlinks or call `realpath`: a policy decision
    must not depend on the state of the disk at decision time, and resolving
    user-supplied paths would be a way to probe it.
    """
    p = path.strip().strip("'\"")
    if p.startswith("~"):
        p = "~" + p[1:]  # keep the marker; expansion is the shell's business
    # Strip a leading ./ but preserve a leading / or ~
    while p.startswith("./"):
        p = p[2:]
    return p or path


def extract_paths(action_type: str, tool: str, params: dict, raw: str) -> list[str]:
    """Every filesystem path this action plausibly touches.

    Union of two sources, because adapters vary in what they populate:
    structured parameters (`Read` with `file_path`) and free shell text
    (`Bash` with a command). Over-collecting is the safe direction — a path that
    is not really a path costs a glob comparison, whereas a missed one is a
    bypass.
    """
    paths: list[str] = []

    for key, value in (params or {}).items():
        if not isinstance(value, str) or not value:
            continue
        if key.lower() in _PATH_PARAM_KEYS or _looks_like_path(value):
            paths.append(normalize_path(value))

    if action_type == "shell" or tool.lower() in ("bash", "shell", "sh", "run"):
        command = raw or str(params.get("command", ""))
        for token in shell_tokens(command):
            if token.startswith("-") or _URL_LIKE.match(token):
                continue
            if _looks_like_path(token):
                paths.append(normalize_path(token))
    elif raw and _looks_like_path(raw):
        paths.append(normalize_path(raw))

    # Preserve order, drop duplicates.
    seen: set[str] = set()
    return [p for p in paths if not (p in seen or seen.add(p))]


def _looks_like_path(token: str) -> bool:
    if not token or _URL_LIKE.match(token):
        return False
    if token in ("/", "~", "."):
        return True
    return bool(_PATH_LIKE.search(token))


def path_matches_glob(path: str, pattern: str) -> bool:
    """Match a path against a policy glob.

    Policy authors write `**/.env` meaning "a file called .env anywhere,
    including right here". Plain fnmatch would not match a bare `.env` against
    that pattern because `**/` demands a separator, so the `**/` prefix is also
    tried stripped, and the basename is tried as well. Being generous here is
    correct: these globs name things that must never be touched.
    """
    candidates = {path, normalize_path(path), posixpath.basename(path)}
    if path.startswith("~/"):
        candidates.add(path[2:])

    patterns = {pattern}
    if pattern.startswith("**/"):
        patterns.add(pattern[3:])

    return any(
        fnmatch.fnmatch(candidate, pat)
        for candidate in candidates
        if candidate
        for pat in patterns
    )


# --------------------------------------------------------------------------
# Recursive deletes, judged by target
# --------------------------------------------------------------------------

# Paths where a recursive force delete is catastrophic and unrecoverable.
_PROTECTED_DELETE_TARGETS = (
    "/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "..", "../", "*",
    "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/opt", "/boot", "/dev",
    "/System", "/Library", "/Applications", "/Users", "/home", "/root", "/srv",
)

_RM_RECURSIVE_FLAGS = ("r", "R")
_RM_FORCE_FLAG = "f"


def rm_targets(command: str) -> list[str]:
    """Non-flag operands of an `rm` invocation."""
    tokens = shell_tokens(command)
    targets: list[str] = []
    in_rm = False
    for token in tokens:
        name = posixpath.basename(token).lower()
        if name == "rm":
            in_rm = True
            continue
        if not in_rm:
            continue
        if token.startswith("-"):
            continue
        # A second command in a pipeline ends the rm's operand list.
        if name in ("sudo", "xargs", "find", "&&", "||"):
            continue
        targets.append(token)
    return targets


def is_recursive_force_delete(command: str) -> bool:
    """Whether the command is an `rm` with both recursive and force set.

    Handles `-rf`, `-fr`, `-r -f`, `-Rf`, and the long forms. Flag bundling is
    exactly the kind of spelling difference a naive `"rm -rf"` substring misses.
    """
    tokens = shell_tokens(command)
    if not any(posixpath.basename(t).lower() == "rm" for t in tokens):
        return False

    recursive = force = False
    for token in tokens:
        if not token.startswith("-"):
            continue
        if token.startswith("--"):
            flag = token[2:].lower()
            if flag == "recursive":
                recursive = True
            elif flag == "force":
                force = True
            continue
        letters = token[1:]
        if any(ch in letters for ch in _RM_RECURSIVE_FLAGS):
            recursive = True
        if _RM_FORCE_FLAG in letters:
            force = True

    return recursive and force


def is_dangerous_delete(command: str) -> tuple[bool, str]:
    """Whether a delete would hit a path that must never be recursively removed.

    Returns (dangerous, offending_target).

    `rm -rf /` and `rm -rf node_modules` are not the same act. The first is
    unrecoverable; the second is a build artifact that `npm install` restores.
    Blocking both — which a bare `rm -rf` pattern does — trains developers to
    disable the gate, so the target is what decides.
    """
    if not is_recursive_force_delete(command):
        return False, ""

    for target in rm_targets(command):
        normalized = target.rstrip("/") or "/"
        if target in _PROTECTED_DELETE_TARGETS or normalized in _PROTECTED_DELETE_TARGETS:
            return True, target
        # An absolute path outside the working tree, or any escape upward.
        if target.startswith(("/", "~")) or normalized.startswith(".."):
            return True, target
        # A bare glob deletes everything in the current directory.
        if normalized in ("*", ".*"):
            return True, target

    return False, ""
