"""Installer for the coding adapter, behind `trustgate init`.

Writes three things into a project:

1. `trustgate.constitution.yaml` — the starter policy, copied so it is yours to
   edit rather than hidden inside the package.
2. `.claude/hooks/trustgate-pretooluse.sh` — a small shell shim that pipes the
   hook payload into this Python package.
3. A `PreToolUse` entry in `.claude/settings.json`.

Every step is idempotent and backs up before it writes. Editing a user's
`settings.json` is the single most intrusive thing this project does — that file
controls what runs automatically in every future session — so it is merged, never
overwritten, and a timestamped backup is always left behind.

Spec: Master Build Document v3.0, Part H.2.
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

CONSTITUTION_FILENAME = "trustgate.constitution.yaml"
HOOK_RELATIVE_PATH = ".claude/hooks/trustgate-pretooluse.sh"
RESOLUTION_HOOK_RELATIVE_PATH = ".claude/hooks/trustgate-resolution.sh"
SETTINGS_RELATIVE_PATH = ".claude/settings.json"

# Marks our entries so re-running init updates them instead of adding duplicates.
HOOK_MARKER = "trustgate-pretooluse"
RESOLUTION_HOOK_MARKER = "trustgate-resolution"

# The events that tell us how an escalation was answered. Registered together
# because any one of them alone leaves a gap: PostToolUse never sees a refusal,
# and the failure events never see a success.
RESOLUTION_EVENTS: tuple[str, ...] = (
    "PostToolUse",
    "PostToolUseFailure",
    "PermissionDenied",
)

HOOK_SCRIPT = """#!/usr/bin/env bash
# TrustGate PreToolUse hook. Installed by `trustgate init`.
#
# Reads the proposed tool call as JSON on stdin and emits a PreToolUse decision.
# Exits 0 even on failure: the Python side converts every error into an explicit
# "ask" decision, which is more useful than a non-zero exit that Claude Code
# would report as a broken hook.
set -uo pipefail

TRUSTGATE_PYTHON="${TRUSTGATE_PYTHON:-%(python)s}"

if [ ! -x "$TRUSTGATE_PYTHON" ]; then
    TRUSTGATE_PYTHON="$(command -v python3 || command -v python)"
fi

exec "$TRUSTGATE_PYTHON" -m trustgate.adapters.coding.claude_code_hook
"""

RESOLUTION_HOOK_SCRIPT = """#!/usr/bin/env bash
# TrustGate resolution hook. Installed by `trustgate init`.
#
# Runs after a tool call finishes, fails, or is denied, and records how an
# earlier escalation was answered. Bookkeeping only: it never blocks anything,
# writes nothing for actions that were not escalated, and always exits 0.
set -uo pipefail

TRUSTGATE_PYTHON="${TRUSTGATE_PYTHON:-%(python)s}"

if [ ! -x "$TRUSTGATE_PYTHON" ]; then
    TRUSTGATE_PYTHON="$(command -v python3 || command -v python)"
fi

exec "$TRUSTGATE_PYTHON" -m trustgate.adapters.coding.resolution_hook
"""


@dataclass
class InstallResult:
    project_root: Path
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    backups: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines: list[str] = []
        for label, items in (
            ("created", self.created),
            ("updated", self.updated),
            ("unchanged", self.skipped),
        ):
            for item in items:
                lines.append(f"  {label:<10} {item}")
        for backup in self.backups:
            lines.append(f"  backup     {backup}")
        return "\n".join(lines)


def backup_file(path: Path) -> Path:
    """Copy a file next to itself with a timestamp suffix."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    destination = path.with_name(f"{path.name}.trustgate-backup-{stamp}")
    shutil.copy2(path, destination)
    return destination


DEFAULT_HOOK_TIMEOUT = 15

# Slack between the approval window closing and Claude Code killing the hook.
# Without it the two race, Claude Code wins, and the wait never gets to record
# the expiry it was about to write.
TIMEOUT_MARGIN = 20


def gate_timeout(config=None) -> int:
    """Seconds Claude Code should allow the gate to run.

    In remote approval mode the hook blocks for as long as the approval window,
    so the hook's own timeout has to be the larger of the two. Getting this
    wrong is not a slow gate, it is a broken one: Claude Code terminates the
    hook and the tool call falls back to the normal permission flow, which is
    the local prompt we were trying to take out of the loop.
    """
    if config is None:
        from trustgate.core.config import Config

        config = Config.load()

    if not config.approval.is_remote:
        return DEFAULT_HOOK_TIMEOUT
    return int(config.approval.timeout) + TIMEOUT_MARGIN


def hook_entry(
    project_root: Path,
    relative_path: str = HOOK_RELATIVE_PATH,
    timeout: int = DEFAULT_HOOK_TIMEOUT,
) -> dict:
    """The settings.json fragment registering one of our hooks.

    No `matcher`, deliberately: a matcher restricts the hook to named tools, and
    a policy engine that only sees `Bash` cannot enforce a rule about `Read`,
    `Write`, or an MCP tool added next week. Filtering belongs in the
    constitution, where it is visible and auditable.
    """
    return {
        "hooks": [
            {
                "type": "command",
                "command": f"{project_root / relative_path}",
                "timeout": timeout,
            }
        ]
    }


def _is_trustgate_entry(entry: dict, marker: str = HOOK_MARKER) -> bool:
    for hook in entry.get("hooks", []) or []:
        if marker in str(hook.get("command", "")):
            return True
    return False


def _merge_event(
    hooks: dict, event: str, desired: dict, marker: str
) -> bool:
    """Add or refresh one entry under one event. Returns whether it changed."""
    entries = hooks.setdefault(event, [])

    if not isinstance(entries, list):
        raise ValueError(
            f"hooks.{event} in settings.json is not a list; refusing to modify it"
        )

    for index, entry in enumerate(entries):
        if isinstance(entry, dict) and _is_trustgate_entry(entry, marker):
            if entry == desired:
                return False
            entries[index] = desired
            return True

    entries.append(desired)
    return True


def merge_settings(settings: dict, project_root: Path, config=None) -> tuple[dict, bool]:
    """Add or refresh every TrustGate hook entry. Returns (settings, changed).

    Registers the gate on `PreToolUse` and the bookkeeping hook on the three
    events that reveal how an escalation ended. Existing entries for other tools
    are left exactly as they are.
    """
    merged = json.loads(json.dumps(settings))  # deep copy, JSON-shaped by definition
    hooks = merged.setdefault("hooks", {})

    changed = _merge_event(
        hooks,
        "PreToolUse",
        hook_entry(project_root, HOOK_RELATIVE_PATH, gate_timeout(config)),
        HOOK_MARKER,
    )

    # The bookkeeping hook never waits on a human, so it keeps the short budget.
    resolution = hook_entry(
        project_root, RESOLUTION_HOOK_RELATIVE_PATH, DEFAULT_HOOK_TIMEOUT
    )
    for event in RESOLUTION_EVENTS:
        if _merge_event(hooks, event, resolution, RESOLUTION_HOOK_MARKER):
            changed = True

    return merged, changed


def starter_policy_path(surface: str = "coding") -> Path:
    return Path(__file__).resolve().parents[2] / "policies" / f"starter.{surface}.yaml"


def install(
    project_root: Path | str | None = None,
    surface: str = "coding",
    python_executable: str | None = None,
    force: bool = False,
    config=None,
) -> InstallResult:
    """Install the constitution, hook scripts, and settings entries."""
    import sys

    root = Path(project_root) if project_root else Path.cwd()
    result = InstallResult(project_root=root)

    # 1. Constitution — never clobber an edited policy without --force.
    constitution_path = root / CONSTITUTION_FILENAME
    source_policy = starter_policy_path(surface)
    if not source_policy.is_file():
        raise FileNotFoundError(f"no starter policy for surface {surface!r}")

    if constitution_path.exists() and not force:
        result.skipped.append(str(constitution_path))
    else:
        if constitution_path.exists():
            result.backups.append(str(backup_file(constitution_path)))
            result.updated.append(str(constitution_path))
        else:
            result.created.append(str(constitution_path))
        shutil.copyfile(source_policy, constitution_path)

    # 2. Hook scripts: the gate, and the one that records how escalations ended.
    interpreter = python_executable or sys.executable
    for relative_path, template in (
        (HOOK_RELATIVE_PATH, HOOK_SCRIPT),
        (RESOLUTION_HOOK_RELATIVE_PATH, RESOLUTION_HOOK_SCRIPT),
    ):
        hook_path = root / relative_path
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        script = template % {"python": interpreter}
        existed = hook_path.exists()
        if existed and hook_path.read_text(encoding="utf-8") == script:
            result.skipped.append(str(hook_path))
        else:
            if existed:
                result.backups.append(str(backup_file(hook_path)))
                result.updated.append(str(hook_path))
            else:
                result.created.append(str(hook_path))
            hook_path.write_text(script, encoding="utf-8")
        hook_path.chmod(0o755)

    # 3. settings.json — merge, back up, never overwrite.
    settings_path = root / SETTINGS_RELATIVE_PATH
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    if settings_path.exists():
        raw = settings_path.read_text(encoding="utf-8").strip()
        try:
            existing = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{settings_path} is not valid JSON ({exc}); fix or move it before "
                "running init, so your existing hooks are not lost"
            ) from exc
    else:
        existing = {}

    merged, changed = merge_settings(existing, root, config)

    if not changed:
        result.skipped.append(str(settings_path))
    else:
        if settings_path.exists():
            result.backups.append(str(backup_file(settings_path)))
            result.updated.append(str(settings_path))
        else:
            result.created.append(str(settings_path))
        settings_path.write_text(
            json.dumps(merged, indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )

    return result


def next_steps(result: InstallResult) -> str:
    root = result.project_root
    return f"""
TrustGate is installed for Claude Code.

{result.summary()}

Next:
  1. Read and edit the policy:  {root / CONSTITUTION_FILENAME}
  2. Approve your extension files (hooks, MCP servers):
       trustgate approve
  3. Check the suite passes against your policy:
       trustgate test
  4. Start a new Claude Code session. Hooks are read at session start,
     so an already-running session will not pick this up.

Verify it works by asking Claude Code to run `cat .env` — it should be
refused, and the decision recorded:

    trustgate verify-audit
"""
