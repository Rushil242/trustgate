"""Pinned policies: the hook only trusts a policy file whose hash you approved.

The policy file lives in the project, and the agent can write files in the
project. Without a pin, an agent (or a repo cloned from the internet) can
replace the policy with an empty rule list, and the very next tool call is
judged by rules nobody wrote. With a pin, a policy file is trusted only if
its exact bytes were approved by a person running `trustgate pin-policy`, or
it is byte-for-byte one of the starter policies shipped inside the package.

An unpinned policy is still evaluated, so a block in it still blocks. Anything
it would allow or escalate goes to a person instead. The gate never silently
runs on rules it has not been told to trust.

This is a speed bump, not a wall, until the guard room (Phase 1): the pin file
sits in `~/.trustgate/`, which the agent's own OS user can write. The Action
Guard escalates any tool call that touches that folder, so the agent cannot
quietly re-pin a policy through its normal tools.
"""

from __future__ import annotations

import json
import os
import time
from functools import cache
from pathlib import Path

from trustgate.core.constitution import policy_digest

PINS_FILENAME = "pinned-policies.json"
EMPTY_DIGEST = policy_digest(b"")


def trustgate_home() -> Path:
    """Read at call time, so tests and tools that set TRUSTGATE_HOME are honoured."""
    return Path(os.environ.get("TRUSTGATE_HOME", Path.home() / ".trustgate"))


def pins_path() -> Path:
    return trustgate_home() / PINS_FILENAME


@cache
def shipped_digests() -> frozenset[str]:
    """Digests of the starter policies inside this package. Trusted as shipped."""
    folder = Path(__file__).resolve().parents[1] / "policies"
    digests = {policy_digest(p.read_bytes()) for p in folder.glob("*.yaml")}
    previous = folder / "previous-starters.txt"
    if previous.is_file():
        for line in previous.read_text(encoding="utf-8").splitlines():
            word = line.split("#", 1)[0].strip().split(" ", 1)[0]
            if word.startswith("sha256:") and word != EMPTY_DIGEST:
                digests.add(word)
    return frozenset(digests)


def load_pins(path: Path | None = None) -> dict[str, dict]:
    path = path or pins_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    pins = data.get("pins") if isinstance(data, dict) else None
    return pins if isinstance(pins, dict) else {}


def is_trusted(digest: str, path: Path | None = None) -> bool:
    if not digest:
        return False
    return digest in shipped_digests() or digest in load_pins(path)


def pin(policy_file: str | Path, path: Path | None = None, note: str = "") -> str:
    """Approve the current bytes of `policy_file`. Returns the digest."""
    policy_file = Path(policy_file)
    digest = policy_digest(policy_file.read_bytes())
    path = path or pins_path()
    pins = load_pins(path)
    pins[digest] = {
        "path": str(policy_file.resolve()),
        "pinned_at": time.time(),
        "by": os.environ.get("USER", ""),
        "note": note,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({"version": 1, "pins": pins}, indent=2), encoding="utf-8")
    tmp.replace(path)
    return digest
