"""Constitution parsing, validation, and judge prefiltering."""

from __future__ import annotations

from pathlib import Path

import pytest

from trustgate.core.constitution import Constitution, ConstitutionError, Enforcement
from trustgate.core.models import Action, ActionRequest, ActionType, Effect

POLICY_DIR = Path(__file__).resolve().parents[1] / "trustgate" / "policies"


def _req(raw: str = "ls") -> ActionRequest:
    return ActionRequest(
        surface="coding",
        action=Action(type=ActionType.shell, tool="Bash", raw=raw),
    )


@pytest.mark.parametrize("name", ["starter.coding.yaml", "starter.voice.yaml"])
def test_shipped_starter_policies_parse(name):
    c = Constitution.from_file(POLICY_DIR / name)
    assert c.principles
    assert c.metadata.name


def test_accessors_partition_by_enforcement():
    c = Constitution.from_yaml(
        """
        version: 1
        principles:
          - id: det
            statement: deterministic one
            enforcement: deterministic
            match: { action_type: [shell] }
            effect: block
          - id: reason
            statement: reasoning one
            enforcement: reasoning
            effect: block
          - id: both
            statement: both one
            enforcement: both
            match: { tool: [Bash] }
            effect: escalate
        """
    )
    assert [p.id for p in c.deterministic_principles] == ["det", "both"]
    assert [p.id for p in c.reasoning_principles] == ["reason", "both"]
    assert c.by_id("reason").enforcement is Enforcement.reasoning
    assert c.by_id("missing") is None


def test_redact_effect_is_an_alias_for_modify():
    # The policy language says `redact`; the wire contract says `modify`.
    c = Constitution.from_yaml(
        """
        version: 1
        principles:
          - id: r
            statement: redact things
            enforcement: deterministic
            match: { action_type: [tool_call] }
            effect: redact
        """
    )
    assert c.by_id("r").effect is Effect.modify


def test_deterministic_principle_without_match_is_rejected():
    # Such a rule can never fire, so accepting it would mean shipping a policy
    # that silently enforces nothing.
    with pytest.raises(ConstitutionError) as exc:
        Constitution.from_yaml(
            """
            version: 1
            principles:
              - id: unfireable
                statement: never fires
                enforcement: deterministic
                effect: block
            """
        )
    assert "unfireable" in str(exc.value)


def test_empty_match_block_is_rejected():
    with pytest.raises(ConstitutionError):
        Constitution.from_yaml(
            """
            version: 1
            principles:
              - id: hollow
                statement: hollow match
                enforcement: deterministic
                match: {}
                effect: block
            """
        )


def test_duplicate_principle_ids_are_rejected():
    with pytest.raises(ConstitutionError) as exc:
        Constitution.from_yaml(
            """
            version: 1
            principles:
              - id: dup
                statement: first
                enforcement: reasoning
                effect: block
              - id: dup
                statement: second
                enforcement: reasoning
                effect: block
            """
        )
    assert "duplicate" in str(exc.value)


def test_unknown_effect_is_rejected():
    with pytest.raises(ConstitutionError):
        Constitution.from_yaml(
            """
            version: 1
            principles:
              - id: bad
                statement: bad effect
                enforcement: reasoning
                effect: incinerate
            """
        )


def test_unknown_match_key_is_rejected():
    # A typo'd key must fail loudly rather than widening the rule to match all.
    with pytest.raises(ConstitutionError):
        Constitution.from_yaml(
            """
            version: 1
            principles:
              - id: typo
                statement: typo'd key
                enforcement: deterministic
                match: { action_types: [shell] }
                effect: block
            """
        )


def test_errors_name_the_principle_not_the_index():
    with pytest.raises(ConstitutionError) as exc:
        Constitution.from_yaml(
            """
            version: 1
            principles:
              - id: fine
                statement: ok
                enforcement: reasoning
                effect: block
              - id: broken
                statement: bad severity
                enforcement: reasoning
                severity: catastrophic
                effect: block
            """
        )
    assert "'broken'" in str(exc.value)


def test_invalid_yaml_raises_constitution_error():
    with pytest.raises(ConstitutionError):
        Constitution.from_yaml("version: 1\nprinciples: [unclosed")


def test_missing_file_raises_constitution_error():
    with pytest.raises(ConstitutionError):
        Constitution.from_file("/nonexistent/trustgate.yaml")


def test_always_on_reasoning_principle_triggers_the_judge():
    c = Constitution.from_yaml(
        """
        version: 1
        principles:
          - id: always
            statement: evaluated every time
            enforcement: reasoning
            effect: block
        """
    )
    assert [p.id for p in c.principles_needing_judge(_req())] == ["always"]


def test_prefiltered_reasoning_principle_stays_off_the_hot_path():
    # R0 stubs matcher compilation, so a prefiltered principle does not fire.
    # This is what keeps a constitution containing reasoning principles from
    # putting a model call on every single action. See DEVIATIONS.md #2.
    c = Constitution.from_yaml(
        """
        version: 1
        principles:
          - id: prefiltered
            statement: only when the prefilter hits
            enforcement: reasoning
            match: { any_pattern: ["manager said"] }
            effect: block
        """
    )
    assert c.principles_needing_judge(_req()) == []


def test_render_for_judge_numbers_and_labels_principles():
    c = Constitution.from_file(POLICY_DIR / "starter.coding.yaml")
    rendered = c.render_for_judge()
    assert rendered.startswith("1. [")
    for p in c.reasoning_principles:
        assert f"[{p.id}]" in rendered
