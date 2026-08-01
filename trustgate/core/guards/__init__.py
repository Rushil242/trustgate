"""The guard pipeline.

Each guard inspects an ActionRequest and returns a GuardResult. The engine runs
them in a fixed order, folds their verdicts by precedence, and short-circuits on
a hard block. Guards never enforce anything themselves and never mutate the
request — they report, the engine decides.

Order matters: Context runs first because injected instructions in ingested
content are what make an otherwise-innocent action suspicious; Supply-Chain runs
last of the deterministic set because it is the only one that touches disk.

Spec: Master Build Document v3.0, Part E.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from trustgate.core.constitution import Constitution
from trustgate.core.models import ActionRequest, GuardResult


@runtime_checkable
class Guard(Protocol):
    """The interface every guard implements."""

    name: str

    def check(self, req: ActionRequest) -> GuardResult:
        """Inspect a request. Must not raise; must not mutate `req`.

        A guard that cannot reach a confident conclusion returns
        `Verdict.uncertain`, which asks the engine for an LLM judgment rather
        than guessing. Guarding is advisory — the engine owns the outcome.
        """
        ...


class BaseGuard:
    """Shared construction so guards can be swapped freely in tests."""

    name: str = "base"

    def __init__(self, constitution: Constitution) -> None:
        self.c = constitution


__all__ = ["Guard", "BaseGuard"]
