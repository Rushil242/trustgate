"""Supply-Chain Guard — verify hooks, skills and MCP servers before they run.

An agent's extension points are executable code that arrives from outside the
review process: a `settings.json` hook, an MCP server definition, a skill file.
Compromising one of those is more valuable than compromising any single command,
because it runs on every future session — this is the hook-CVE and the
package-hook-worm class of attack.

The control is deliberately dull: hash the files that decide what runs, compare
against a manifest the operator approved, and escalate on anything unknown or
changed. No heuristics, no model, nothing to argue with.

The check is scoped to actions that actually invoke an extension (MCP tool
calls), and results are cached against file mtime, so the common case costs no
disk I/O. *Writes* to those same files are caught separately by the
`no-untrusted-hooks` principle in the constitution.

Spec: Master Build Document v3.0, Part E.5.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from trustgate.core.guards import BaseGuard
from trustgate.core.models import ActionRequest, ActionType, GuardResult, Reason, Verdict

# Files whose contents decide what the agent will execute.
WATCHED_CONFIGS: tuple[str, ...] = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
)

WATCHED_DIRS: tuple[str, ...] = (
    ".claude/hooks",
    ".claude/skills",
)

APPROVAL_MANIFEST = ".trustgate/approved.json"

MCP_TOOL_PREFIX = "mcp__"


def file_digest(path: Path) -> str:
    """SHA-256 of a file's bytes."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_extension_files(root: Path) -> dict[str, str]:
    """Path → digest for every extension-defining file under `root`."""
    digests: dict[str, str] = {}

    for rel in WATCHED_CONFIGS:
        candidate = root / rel
        if candidate.is_file():
            digests[rel] = file_digest(candidate)

    for rel in WATCHED_DIRS:
        directory = root / rel
        if not directory.is_dir():
            continue
        for entry in sorted(directory.rglob("*")):
            if entry.is_file():
                digests[str(entry.relative_to(root))] = file_digest(entry)

    return digests


def load_manifest(root: Path) -> dict[str, str]:
    manifest_path = root / APPROVAL_MANIFEST
    if not manifest_path.is_file():
        return {}
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # An unreadable manifest means nothing is approved, which escalates.
        # Treating it as "everything is fine" would make corrupting the manifest
        # a way to disable the control.
        return {}
    approved = data.get("approved")
    return approved if isinstance(approved, dict) else {}


def write_manifest(root: Path, digests: dict[str, str]) -> Path:
    """Record the current extension files as approved."""
    manifest_path = root / APPROVAL_MANIFEST
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps({"version": 1, "approved": digests}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def diff_against_manifest(root: Path) -> list[tuple[str, str]]:
    """Extension files that are unapproved or changed. Returns (path, why)."""
    approved = load_manifest(root)
    current = collect_extension_files(root)

    problems: list[tuple[str, str]] = []
    for rel, digest in sorted(current.items()):
        if rel not in approved:
            problems.append((rel, "not in the approved manifest"))
        elif approved[rel] != digest:
            problems.append((rel, "changed since it was approved"))
    return problems


class SupplyChainGuard(BaseGuard):
    name = "supply_chain"

    def __init__(self, constitution, root: Path | str | None = None) -> None:
        super().__init__(constitution)
        self.root = Path(root) if root is not None else Path.cwd()
        self._cache: tuple[frozenset[tuple[str, float]], list[tuple[str, str]]] | None = None

    def check(self, req: ActionRequest) -> GuardResult:
        if not self._invokes_extension(req):
            return GuardResult(verdict=Verdict.allow)

        problems = self._problems()
        if not problems:
            return GuardResult(verdict=Verdict.allow)

        rel, why = problems[0]
        extra = f" (and {len(problems) - 1} more)" if len(problems) > 1 else ""
        return GuardResult(
            verdict=Verdict.escalate,
            reasons=[
                Reason(
                    guard=self.name,
                    rule_id="unverified-extension",
                    message=(
                        f"{rel} is {why}{extra}. An extension file decides what runs "
                        "automatically in every future session; approve it with "
                        "`trustgate approve` after reviewing the diff."
                    ),
                    severity="high",
                )
            ],
        )

    def _invokes_extension(self, req: ActionRequest) -> bool:
        return req.action.type is ActionType.tool_call and req.action.tool.startswith(
            MCP_TOOL_PREFIX
        )

    def _problems(self) -> list[tuple[str, str]]:
        """Cached against the mtimes of the watched files."""
        signature = self._mtime_signature()
        if self._cache is not None and self._cache[0] == signature:
            return self._cache[1]

        problems = diff_against_manifest(self.root)
        self._cache = (signature, problems)
        return problems

    def _mtime_signature(self) -> frozenset[tuple[str, float]]:
        entries: list[tuple[str, float]] = []
        for rel in (*WATCHED_CONFIGS, APPROVAL_MANIFEST):
            candidate = self.root / rel
            if candidate.is_file():
                entries.append((rel, candidate.stat().st_mtime))
        for rel in WATCHED_DIRS:
            directory = self.root / rel
            if directory.is_dir():
                for entry in sorted(directory.rglob("*")):
                    if entry.is_file():
                        entries.append((str(entry), entry.stat().st_mtime))
        return frozenset(entries)
