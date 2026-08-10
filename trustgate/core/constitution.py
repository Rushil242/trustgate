"""The constitution: TrustGate's policy language.

A constitution is a YAML file of plain-English principles, each optionally bound
to a deterministic matcher. One format governs every surface. The plain-English
`statement` is what a human reads, what the LLM judge is shown, and what appears
in the audit line — so the same sentence explains a block to a developer, a
regulator, and the model.

Spec: Master Build Document v3.0, Part D.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from trustgate.core.models import ActionRequest, ActionType, Effect
from trustgate.core.normalize import extract_paths, path_matches_glob


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
        # Compile eagerly so a malformed regex is a load-time error naming the
        # principle, not a surprise on the first action that reaches it.
        if self.match is not None and self.match.any_pattern:
            self.compiled_patterns()
        return self

    @property
    def is_deterministic(self) -> bool:
        return self.enforcement in (Enforcement.deterministic, Enforcement.both)

    @property
    def is_reasoning(self) -> bool:
        return self.enforcement in (Enforcement.reasoning, Enforcement.both)

    def matches(self, req: ActionRequest) -> bool:
        """Whether this principle's deterministic trigger fires on `req`.

        Populated fields are ANDed; values within a field are ORed. An empty
        `match` never fires, and validation rejects it at load time so a rule
        cannot silently enforce nothing.
        """
        m = self.match
        if m is None or m.is_empty():
            return False

        if m.surface is not None and req.surface not in m.surface:
            return False
        if m.action_type is not None and req.action.type not in m.action_type:
            return False
        if m.tool is not None and req.action.tool not in m.tool:
            return False
        if m.param_gt is not None and not self._param_gt_fires(req):
            return False
        if m.any_pattern is not None and not self._pattern_fires(req):
            return False
        if m.touches_paths is not None and not self._path_fires(req):
            return False

        return True

    def _pattern_fires(self, req: ActionRequest) -> bool:
        haystack = searchable_text(req)
        return any(rx.search(haystack) for rx in self.compiled_patterns())

    def _path_fires(self, req: ActionRequest) -> bool:
        paths = extract_paths(
            req.action.type.value, req.action.tool, req.action.params, req.action.raw
        )
        globs = self.match.touches_paths or []
        return any(path_matches_glob(p, g) for p in paths for g in globs)

    def _param_gt_fires(self, req: ActionRequest) -> bool:
        """Strictly greater-than: "refunds over $100" leaves exactly $100 allowed.

        A missing or non-numeric parameter does not fire. A threshold rule
        describes a value that is present and too large; an absent value is the
        Action Guard's problem, not a numeric bound's.
        """
        for key, threshold in (self.match.param_gt or {}).items():
            value = req.action.params.get(key)
            if isinstance(value, bool) or not isinstance(value, int | float | str):
                continue
            try:
                if float(value) > threshold:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    def compiled_patterns(self) -> list[re.Pattern[str]]:
        """Compile once, cache on the instance.

        Every deterministic principle is tested against every action, so
        recompiling per request would dominate the sub-50ms budget.
        """
        cached = self.__dict__.get("_pattern_cache")
        if cached is None:
            cached = compile_patterns(self.match.any_pattern or [], self.id)
            self.__dict__["_pattern_cache"] = cached
        return cached

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


def compile_patterns(patterns: list[str], principle_id: str) -> list[re.Pattern[str]]:
    """Compile a principle's regexes, naming the principle on failure."""
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error as exc:
            raise ValueError(
                f"principle {principle_id!r} has an invalid regex {pattern!r}: {exc}"
            ) from exc
    return compiled


def searchable_text(req: ActionRequest) -> str:
    """The text a principle's `any_pattern` is tested against.

    Deliberately excludes `context.ingested_content`. Ingested content is
    untrusted data that the agent happens to have read — a README that documents
    `rm -rf /` must not block a deploy, and a web page containing "terraform
    destroy" must not escalate an unrelated action. Scanning that content is the
    Context Guard's job, and it reports `uncertain` rather than enforcing.
    """
    parts = [req.action.raw, req.action.tool]
    for key, value in (req.action.params or {}).items():
        parts.append(f"{key}={value}")
    return "\n".join(p for p in parts if p)


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
