# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import io
import tarfile
from pathlib import Path
from typing import cast

import pytest

from hub.core.errors import SkillValidationError
from hub.core.validation import (
    MAX_HISTORY_PLACEHOLDERS,
    validate_skill_metadata,
    validate_skill_metadata_shape,
)
from hub.storage.tarball import extract_skill_yaml


def _valid_skill() -> dict[str, object]:
    return {
        "name": "temperature-guard",
        "version": "1.2.3",
        "author": "test-author",
        "license": "Apache-2.0",
        "description": "Alerts an operator when temperature is elevated.",
        "signature": "bundled",
        "sensors_required": [{"type": "temperature", "protocol": "i2c"}],
        "triggers": [
            {
                "name": "temperature_high",
                "condition": "value > warning_threshold",
                "action_tier": "A",
                "cooldown_seconds": 60,
                "escalate_to": "local_slm",
                "bypass_llm": False,
                "requires_approval": False,
                "approval_timeout_seconds": 300,
                "safe_default_action": "log_to_dashboard",
            }
        ],
        "prompts": {"temperature_high": "Current reading: {value}{unit}"},
        "actions": {
            "available": [{"name": "alert_operator", "tier": "A"}],
            "defaults": {"temperature_high": ["alert_operator"]},
        },
        "config": {"warning_threshold": 30.0},
    }


def _triggers(skill: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], skill["triggers"])


def _actions(skill: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], skill["actions"])


def _available(skill: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], _actions(skill)["available"])


def _defaults(skill: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], _actions(skill)["defaults"])


def _tarball_with_hook(skill_yaml: bytes, hook: bytes) -> bytes:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
        for name, payload in (("skill.yaml", skill_yaml), ("hooks.py", hook)):
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return archive_bytes.getvalue()


def test_validates_current_package_shape_without_mutating_input() -> None:
    skill = _valid_skill()
    original = copy.deepcopy(skill)

    result = validate_skill_metadata(skill)

    assert result.name == "temperature-guard"
    assert result.version == "1.2.3"
    assert result.author == "test-author"
    assert result.trigger_names == ("temperature_high",)
    assert result.action_names == ("alert_operator",)
    assert result.declared_tiers == frozenset({"A"})
    assert result.declares_tier_cd is False
    assert skill == original


def test_legacy_shape_entry_point_runs_full_validation() -> None:
    skill = _valid_skill()
    validate_skill_metadata_shape(skill)

    _triggers(skill)[0]["action_tier"] = "Z"
    with pytest.raises(SkillValidationError, match="action_tier"):
        validate_skill_metadata_shape(skill)


def test_unknown_top_level_runtime_metadata_remains_allowed() -> None:
    skill = _valid_skill()
    skill["requirements"] = {"python": [">=3.11"], "hardware": None}
    skill["future_contract_extension"] = {"enabled": True}

    result = validate_skill_metadata(skill)

    assert result.name == "temperature-guard"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", None),
        ("name", ""),
        ("name", " temperature-guard"),
        ("version", 1),
        ("version", " "),
        ("author", []),
        ("author", "test-author "),
    ],
)
def test_rejects_invalid_required_identity_fields(field: str, value: object) -> None:
    skill = _valid_skill()
    skill[field] = value

    with pytest.raises(SkillValidationError, match=field):
        validate_skill_metadata(skill)


def test_signature_is_optional_but_must_be_a_non_empty_string_when_present() -> None:
    skill = _valid_skill()
    del skill["signature"]
    validate_skill_metadata(skill)

    skill["signature"] = 123
    with pytest.raises(SkillValidationError, match="signature must be a string"):
        validate_skill_metadata(skill)

    skill["signature"] = " "
    with pytest.raises(SkillValidationError, match="non-empty"):
        validate_skill_metadata(skill)


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("temperature", "sensors_required must be an array"),
        ([42], r"sensors_required\[0\] must be a mapping"),
        ([{}], r"sensors_required\[0\]\.type"),
        ([{"type": ""}], r"sensors_required\[0\]\.type"),
        (
            [{"type": "temperature", "protocol": 1}],
            r"sensors_required\[0\]\.protocol",
        ),
    ],
)
def test_rejects_malformed_sensor_requirements(
    value: object,
    match: str,
) -> None:
    skill = _valid_skill()
    skill["sensors_required"] = value

    with pytest.raises(SkillValidationError, match=match):
        validate_skill_metadata(skill)


def test_rejects_duplicate_sensor_subscription_types() -> None:
    skill = _valid_skill()
    skill["sensors_required"] = [
        {"type": "temperature", "protocol": "i2c"},
        {"type": "temperature", "protocol": "modbus"},
    ]

    with pytest.raises(SkillValidationError, match="duplicate sensor type"):
        validate_skill_metadata(skill)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("condition", 1, "condition must be a string"),
        ("action_tier", None, "action_tier must be a string"),
        ("action_tier", "Z", "action_tier must be one of"),
        ("cooldown_seconds", "60", "cooldown_seconds must be an integer"),
        ("cooldown_seconds", True, "cooldown_seconds must be an integer"),
        ("escalate_to", "cloud", "escalate_to must be"),
        ("escalate_to", "LOCAL_SLM", "escalate_to must be"),
        ("bypass_llm", 1, "bypass_llm must be a boolean"),
        ("requires_approval", "false", "requires_approval must be a boolean"),
        (
            "approval_timeout_seconds",
            30.0,
            "approval_timeout_seconds must be an integer",
        ),
        (
            "safe_default_action",
            None,
            "safe_default_action must be a string",
        ),
    ],
)
def test_rejects_malformed_trigger_fields(
    field: str,
    value: object,
    match: str,
) -> None:
    skill = _valid_skill()
    _triggers(skill)[0][field] = value

    with pytest.raises(SkillValidationError, match=match):
        validate_skill_metadata(skill)


@pytest.mark.parametrize(
    "name",
    ["", " temperature_high", "temperature high", "_temperature", "temp.c"],
)
def test_rejects_invalid_trigger_names(name: str) -> None:
    skill = _valid_skill()
    _triggers(skill)[0]["name"] = name

    with pytest.raises(SkillValidationError, match="name"):
        validate_skill_metadata(skill)


def test_rejects_duplicate_trigger_names() -> None:
    skill = _valid_skill()
    duplicate = copy.deepcopy(_triggers(skill)[0])
    _triggers(skill).append(duplicate)

    with pytest.raises(SkillValidationError, match="duplicate trigger name"):
        validate_skill_metadata(skill)


def test_rejects_bypass_llm_outside_tier_d() -> None:
    skill = _valid_skill()
    _triggers(skill)[0]["bypass_llm"] = True

    with pytest.raises(SkillValidationError, match="outside Tier D"):
        validate_skill_metadata(skill)


def test_tier_d_is_rule_only_and_defaults_to_rule() -> None:
    skill = _valid_skill()
    trigger = _triggers(skill)[0]
    trigger["action_tier"] = "D"
    trigger["bypass_llm"] = True
    del trigger["escalate_to"]

    result = validate_skill_metadata(skill)
    assert result.declares_tier_cd is True

    trigger["escalate_to"] = "gateway"
    with pytest.raises(SkillValidationError, match="must use escalate_to='rule'"):
        validate_skill_metadata(skill)


@pytest.mark.parametrize("tier", ["A", "C", "D"])
def test_post_action_is_rejected_outside_tier_b(tier: str) -> None:
    skill = _valid_skill()
    trigger = _triggers(skill)[0]
    trigger["action_tier"] = tier
    trigger["reasoning_policy"] = "post_action"
    if tier == "D":
        trigger["escalate_to"] = "rule"
        trigger["bypass_llm"] = True

    with pytest.raises(SkillValidationError, match="outside Tier B"):
        validate_skill_metadata(skill)


def test_rejects_unknown_reasoning_policy() -> None:
    skill = _valid_skill()
    trigger = _triggers(skill)[0]
    trigger["action_tier"] = "B"
    trigger["reasoning_policy"] = "before_action"

    with pytest.raises(SkillValidationError, match="unsupported reasoning_policy"):
        validate_skill_metadata(skill)


def test_physical_tier_b_requires_explicit_execution_policy() -> None:
    skill = _valid_skill()
    _triggers(skill)[0]["action_tier"] = "B"
    _available(skill)[0]["tier"] = "B"

    with pytest.raises(SkillValidationError, match="physical Tier B trigger"):
        validate_skill_metadata(skill)

    _triggers(skill)[0]["requires_approval"] = True
    validate_skill_metadata(skill)


def test_tier_b_post_action_requires_tier_a_notification_default() -> None:
    skill = _valid_skill()
    trigger = _triggers(skill)[0]
    trigger["action_tier"] = "B"
    trigger["reasoning_policy"] = "post_action"
    _available(skill)[0]["name"] = "switch_load"
    _available(skill)[0]["tier"] = "B"
    _defaults(skill)["temperature_high"] = ["switch_load"]

    with pytest.raises(SkillValidationError, match="Tier A default action"):
        validate_skill_metadata(skill)

    _available(skill).append({"name": "alert_operator", "tier": "A"})
    _defaults(skill)["temperature_high"] = ["switch_load", "switch_load"]
    with pytest.raises(SkillValidationError, match="duplicate action reference"):
        validate_skill_metadata(skill)

    _defaults(skill)["temperature_high"] = ["switch_load", "alert_operator"]
    validate_skill_metadata(skill)


def test_non_physical_tier_b_does_not_require_execution_policy() -> None:
    skill = _valid_skill()
    _triggers(skill)[0]["action_tier"] = "B"

    validate_skill_metadata(skill)


def test_tier_c_requires_non_empty_safe_default_action() -> None:
    skill = _valid_skill()
    trigger = _triggers(skill)[0]
    trigger["action_tier"] = "C"
    trigger["safe_default_action"] = ""

    with pytest.raises(SkillValidationError, match="safe_default_action"):
        validate_skill_metadata(skill)

    trigger["safe_default_action"] = "log_to_dashboard"
    assert validate_skill_metadata(skill).declares_tier_cd is True


def test_tier_c_safe_default_must_be_a_declared_tier_a_action() -> None:
    skill = _valid_skill()
    trigger = _triggers(skill)[0]
    trigger["action_tier"] = "C"
    trigger["safe_default_action"] = "missing_action"

    with pytest.raises(SkillValidationError, match="not declared"):
        validate_skill_metadata(skill)

    trigger["safe_default_action"] = "alert_operator"
    _available(skill)[0]["tier"] = "B"
    with pytest.raises(SkillValidationError, match="must be a Tier A action"):
        validate_skill_metadata(skill)

    _available(skill)[0]["tier"] = "A"
    validate_skill_metadata(skill)


@pytest.mark.parametrize(
    "trigger_tier",
    ["A", "B", "C"],
)
def test_tier_d_action_cannot_hide_behind_lower_trigger_authority(
    trigger_tier: str,
) -> None:
    skill = _valid_skill()
    _triggers(skill)[0]["action_tier"] = trigger_tier
    _available(skill)[0]["tier"] = "D"

    with pytest.raises(SkillValidationError, match="non-Tier-D trigger"):
        validate_skill_metadata(skill)


def test_tier_c_action_escalation_is_valid_but_review_classified() -> None:
    skill = _valid_skill()
    _available(skill)[0]["tier"] = "C"

    result = validate_skill_metadata(skill)

    assert result.declares_tier_cd is True


def test_tier_b_action_escalation_requires_explicit_approval() -> None:
    skill = _valid_skill()
    _available(skill)[0]["tier"] = "B"

    with pytest.raises(SkillValidationError, match="physical Tier B trigger"):
        validate_skill_metadata(skill)

    _triggers(skill)[0]["requires_approval"] = True
    validate_skill_metadata(skill)


@pytest.mark.parametrize(
    ("available", "match"),
    [
        ("alert_operator", "actions.available must be an array"),
        ([], "actions.available must be a non-empty array"),
        ([42], r"actions.available\[0\] must be a mapping"),
        ([{"tier": "A"}], r"actions.available\[0\]\.name"),
        ([{"name": "alert_operator"}], r"actions.available\[0\]\.tier"),
        (
            [{"name": "alert_operator", "tier": "E"}],
            r"actions.available\[0\]\.tier",
        ),
    ],
)
def test_rejects_malformed_available_actions(
    available: object,
    match: str,
) -> None:
    skill = _valid_skill()
    _actions(skill)["available"] = available

    with pytest.raises(SkillValidationError, match=match):
        validate_skill_metadata(skill)


def test_rejects_duplicate_action_declarations() -> None:
    skill = _valid_skill()
    _available(skill).append({"name": "alert_operator", "tier": "B"})

    with pytest.raises(SkillValidationError, match="duplicate action name"):
        validate_skill_metadata(skill)


@pytest.mark.parametrize(
    ("defaults", "match"),
    [
        ([], "actions.defaults must be a mapping"),
        ({}, "missing actions.defaults"),
        (
            {"temperature_high": [], "unknown": ["alert_operator"]},
            "unknown trigger",
        ),
        (
            {"temperature_high": "alert_operator"},
            "actions.defaults.temperature_high must be an array",
        ),
        (
            {"temperature_high": []},
            "actions.defaults.temperature_high must be a non-empty array",
        ),
        (
            {"temperature_high": [1]},
            r"actions.defaults.temperature_high\[0\] must be a string",
        ),
        (
            {"temperature_high": ["missing_action"]},
            "references undeclared action",
        ),
        (
            {"temperature_high": ["alert_operator", "alert_operator"]},
            "duplicate action reference",
        ),
    ],
)
def test_rejects_malformed_or_ambiguous_action_defaults(
    defaults: object,
    match: str,
) -> None:
    skill = _valid_skill()
    _actions(skill)["defaults"] = defaults

    with pytest.raises(SkillValidationError, match=match):
        validate_skill_metadata(skill)


def test_declared_tiers_include_trigger_and_unused_action_authority() -> None:
    skill = _valid_skill()
    _available(skill).append({"name": "trip_relay", "tier": "C"})

    result = validate_skill_metadata(skill)

    assert result.declared_tiers == frozenset({"A", "C"})
    assert result.declares_tier_cd is True


def test_rejects_more_than_sixteen_history_placeholders() -> None:
    skill = _valid_skill()
    prompts = cast(dict[str, object], skill["prompts"])
    prompts["temperature_high"] = " ".join(
        "{history.last_value('sensor')}" for _ in range(MAX_HISTORY_PLACEHOLDERS + 1)
    )

    with pytest.raises(SkillValidationError, match="maximum allowed is 16"):
        validate_skill_metadata(skill)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("prompts", [], "prompts must be a mapping"),
        ("prompts", {"temperature_high": 1}, "must be a string"),
        ("config", [], "config must be a mapping"),
    ],
)
def test_rejects_invalid_optional_mapping_shapes(
    field: str,
    value: object,
    match: str,
) -> None:
    skill = _valid_skill()
    skill[field] = value

    with pytest.raises(SkillValidationError, match=match):
        validate_skill_metadata(skill)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), object()])
def test_rejects_non_json_manifest_values(value: object) -> None:
    skill = _valid_skill()
    skill["extension"] = value

    with pytest.raises(SkillValidationError, match="JSON-compatible|finite"):
        validate_skill_metadata(skill)


def test_rejects_cyclic_manifest_values() -> None:
    skill = _valid_skill()
    cycle: list[object] = []
    cycle.append(cycle)
    skill["extension"] = cycle

    with pytest.raises(SkillValidationError, match="cyclic reference"):
        validate_skill_metadata(skill)


def test_validation_never_executes_packaged_hooks(tmp_path: Path) -> None:
    marker = tmp_path / "hook-executed"
    skill_yaml = b"""\
name: inert-hook-test
version: 1.0.0
author: test-author
triggers:
  - name: threshold
    condition: "value > 1"
    action_tier: A
actions:
  available:
    - name: alert_operator
      tier: A
  defaults:
    threshold: [alert_operator]
"""
    hook = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
    ).encode()
    archive = _tarball_with_hook(skill_yaml, hook)

    document = extract_skill_yaml(archive)
    validate_skill_metadata(document.mapping)

    assert not marker.exists()
