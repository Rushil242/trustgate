"""The constitution: TrustGate's policy language.

A constitution is a YAML file of plain-English principles, each optionally bound
to a deterministic matcher. One format governs every surface. The plain-English
`statement` is what a human reads, what the LLM judge is shown, and what appears
in the audit line — so the same sentence explains a block to a developer, a
regulator, and the model.

Spec: Master Build Document v3.0, Part D.

R0 status: schema, loading and validation are complete. Matcher compilation is
stubbed (see `Principle.matches`) and lands in R1 with the Action Guard.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from trustgate.core.models import ActionRequest, ActionType, Effect


class ConstitutionError(Exception):
    """Raised when a constitution file is malformed. Message is user-facing."""


class Enforcement(StrEnum):
    deterministic = "deterministic"
    """Matched by a compiled rule. Fast, reproducible, no model call."""

    reasoning = "reasoning"
    """Evaluated by the LLM judge. Catches phrasings no pattern anticipated."""

    both = "both"
    """Deterministic match, with the judge consulted as well."""


class Severity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Match(BaseModel):
    """The deterministic trigger for a principle.

    All populated fields must hold for the principle to fire (AND across fields,
    OR within a list). Every field is optional; an empty Match matches nothing,
    which is caught during validation rather than silently disabling a rule.
    """

    model_config = ConfigDict(extra="forbid")

    surface: list[str] | None = None
    action_type: list[ActionType] | None = None
    tool: list[str] | None = None
    any_pattern: list[str] | None = None
    """Regexes tested against `action.raw` and stringified params."""

    touches_paths: list[str] | None = None
    """Globs tested against any filesystem path mentioned by the action."""

    param_gt: dict[str, float] | None = None
    """Numeric thresholds, e.g. {"amount": 100} fires when params["amount"] > 100."""

    def is_empty(self) -> bool:
        return all(
            getattr(self, f) is None
            for f in ("surface", "action_type", "tool", "any_pattern", "touches_paths", "param_gt")
        )


# The constitution schema spells this field `redact` (Part D.1) while the wire
# contract calls the outcome `modify` (Part C.2). `redact` is the author-facing
# word and stays; it compiles to Effect.modify. See DEVIATIONS.md #5.
_EFFECT_ALIASES: dict[str, Effect] = {
    "allow": Effect.allow,
    "block": Effect.block,
    "escalate": Effect.escalate,
    "modify": Effect.modify,
    "redact": Effect.modify,
}


class Principle(BaseModel):
    """One rule. Stable `id`, human `statement`, optional machine `match`."""

    model_config = ConfigDict(extra="forbid")

    id: str
    statement: str
    enforcement: Enforcement
    severity: Severity = Severity.high
    match: Match | None = None
    effect: Effect = Effect.block

    @model_validator(mode="before")
    @classmethod
    def _normalize_effect(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("effect"), str):
            raw = data["effect"].strip().lower()
            if raw not in _EFFECT_ALIASES:
                allowed = ", ".join(sorted(_EFFECT_ALIASES))
                raise ValueError(f"effect must be one of: {allowed} (got {data['effect']!r})")
            data = {**data, "effect": _EFFECT_ALIASES[raw].value}
        return data

    @model_validator(mode="after")
    def _check_match_present(self) -> Principle:
        needs_match = self.enforcement in (Enforcement.deterministic, Enforcement.both)
        if needs_match and (self.match is None or self.match.is_empty()):
            raise ValueError(
                f"principle {self.id!r} is {self.enforcement.value} but has no usable "
                "`match` block, so it could never fire"
            )
        return self

    @property
    def is_deterministic(self) -> bool:
        return self.enforcement in (Enforcement.deterministic, Enforcement.both)

    @property
    def is_reasoning(self) -> bool:
        return self.enforcement in (Enforcement.reasoning, Enforcement.both)

    def matches(self, req: ActionRequest) -> bool:
        """Whether this principle's deterministic trigger fires on `req`.

        R0: stub. Compiled matchers land in R1 alongside the Action Guard, which
        is where the patterns are exercised and red-teamed. Returning False here
        means an R0 engine allows everything, which is the intended skeleton
        behaviour — enforcement is not claimed until R1.
        """
        return False

    def triggers_judge(self, req: ActionRequest) -> bool:
        """Whether the LLM judge should evaluate this principle for `req`.

        A reasoning principle with no `match` block is always-on (evaluated on
        every request). One *with* a `match` block uses it as a cheap prefilter:
        the block does not enforce anything, it just decides whether this
        principle is worth a model call. This is what keeps the hot path free
        when a constitution contains reasoning principles. See DEVIATIONS.md #2.
        """
        if not self.is_reasoning:
            return False
        if self.match is None or self.match.is_empty():
            return True
        return self.matches(req)


class Metadata(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str = "unnamed constitution"
    surface: str | None = None
    """Informational. A constitution may deliberately be surface-agnostic."""


class Constitution(BaseModel):
    """A parsed, validated policy file."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    metadata: Metadata = Field(default_factory=Metadata)
    principles: list[Principle] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_unique_ids(self) -> Constitution:
        seen: set[str] = set()
        for p in self.principles:
            if p.id in seen:
                raise ValueError(
                    f"duplicate principle id {p.id!r}; ids appear in audit lines "
                    "and must be unique"
                )
            seen.add(p.id)
        return self

    # -- accessors (Part D.4) ---------------------------------------------

    @property
    def deterministic_principles(self) -> list[Principle]:
        return [p for p in self.principles if p.is_deterministic]

    @property
    def reasoning_principles(self) -> list[Principle]:
        return [p for p in self.principles if p.is_reasoning]

    def by_id(self, principle_id: str) -> Principle | None:
        return next((p for p in self.principles if p.id == principle_id), None)

    def principles_needing_judge(self, req: ActionRequest) -> list[Principle]:
        """Reasoning principles whose prefilter fires for this request."""
        return [p for p in self.principles if p.triggers_judge(req)]

    def render_for_judge(self, principles: list[Principle] | None = None) -> str:
        """The numbered plain-English list shown to the LLM judge."""
        subset = self.reasoning_principles if principles is None else principles
        return "\n".join(f"{i}. [{p.id}] {p.statement}" for i, p in enumerate(subset, start=1))

    # -- loading ----------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> Constitution:
        path = Path(path)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConstitutionError(f"cannot read constitution at {path}: {exc}") from exc
        return cls.from_yaml(text, source=str(path))

    @classmethod
    def from_yaml(cls, text: str, source: str = "<string>") -> Constitution:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConstitutionError(f"{source}: invalid YAML: {exc}") from exc

        if not isinstance(data, dict):
            raise ConstitutionError(
                f"{source}: top level must be a mapping, got {type(data).__name__}"
            )

        try:
            return cls.model_validate(data)
        except ValidationError as exc:
            raise ConstitutionError(_format_errors(source, data, exc)) from exc


def _format_errors(source: str, data: dict[str, Any], exc: ValidationError) -> str:
    """Turn a Pydantic error dump into something a policy author can act on."""
    lines = [f"{source}: constitution is invalid:"]
    raw_principles = data.get("principles") or []
    for err in exc.errors():
        loc = list(err["loc"])
        label = ".".join(str(p) for p in loc) or "<root>"
        # Name the offending principle by id rather than by list index.
        if len(loc) >= 2 and loc[0] == "principles" and isinstance(loc[1], int):
            idx = loc[1]
            pid = None
            if idx < len(raw_principles) and isinstance(raw_principles[idx], dict):
                pid = raw_principles[idx].get("id")
            where = f"principle {pid!r}" if pid else f"principles[{idx}]"
            field = ".".join(str(p) for p in loc[2:])
            label = f"{where}{'.' + field if field else ''}"
        lines.append(f"  - {label}: {err['msg']}")
    return "\n".join(lines)
