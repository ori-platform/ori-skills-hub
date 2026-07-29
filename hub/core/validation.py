# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Pure validation for the Ori skill package v1 contract.

This module mirrors the contract implemented by runtime v2 without importing
runtime or SDK internals. Validation operates only on already-decoded metadata;
it never opens, imports, or executes package files such as ``hooks.py``.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, cast

from hub.core.errors import SkillValidationError

ActionTier = Literal["A", "B", "C", "D"]

VALID_ACTION_TIERS: Final = frozenset({"A", "B", "C", "D"})
VALID_ESCALATION_TIERS: Final = frozenset({"rule", "local_slm", "gateway"})
MAX_HISTORY_PLACEHOLDERS: Final = 16

_TRIGGER_NAME_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_HISTORY_PLACEHOLDER_RE: Final = re.compile(r"\{history\.[^{}]+\}")
_MANUAL_REVIEW_TIERS: Final = frozenset({"C", "D"})


@dataclass(frozen=True, slots=True)
class SkillValidationResult:
    """Identity and authority facts derived from a valid skill package."""

    name: str
    version: str
    author: str
    trigger_names: tuple[str, ...]
    action_names: tuple[str, ...]
    declared_tiers: frozenset[ActionTier]

    @property
    def declares_tier_cd(self) -> bool:
        """Return whether any trigger or action declares Tier C/D authority."""

        return bool(self.declared_tiers.intersection(_MANUAL_REVIEW_TIERS))


@dataclass(frozen=True, slots=True)
class _TriggerPolicy:
    name: str
    action_tier: ActionTier
    requires_approval: bool
    reasoning_policy: str | None
    safe_default_action: str


def _invalid(message: str) -> SkillValidationError:
    return SkillValidationError(message)


def _require_mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _invalid(f"{field} must be a mapping")
    for key in value:
        if not isinstance(key, str):
            raise _invalid(f"{field} keys must be strings")
    return cast(Mapping[str, object], value)


def _require_array(
    value: object,
    field: str,
    *,
    non_empty: bool = False,
) -> list[object]:
    if not isinstance(value, list):
        raise _invalid(f"{field} must be an array")
    if non_empty and not value:
        raise _invalid(f"{field} must be a non-empty array")
    return cast(list[object], value)


def _require_string(
    value: object,
    field: str,
    *,
    non_empty: bool = True,
    identifier: bool = False,
) -> str:
    if not isinstance(value, str):
        raise _invalid(f"{field} must be a string")
    if non_empty and not value.strip():
        raise _invalid(f"{field} must be a non-empty string")
    if identifier and value != value.strip():
        raise _invalid(f"{field} must not contain surrounding whitespace")
    return value


def _require_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise _invalid(f"{field} must be a boolean")
    return value


def _require_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _invalid(f"{field} must be an integer")
    return value


def _validate_json_value(
    value: object,
    field: str,
    *,
    ancestors: set[int],
) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _invalid(f"{field} must contain only finite numbers")
        return
    if not isinstance(value, (Mapping, list)):
        raise _invalid(f"{field} must contain only JSON-compatible values")

    identity = id(value)
    if identity in ancestors:
        raise _invalid(f"{field} contains a cyclic reference")
    ancestors.add(identity)
    try:
        if isinstance(value, Mapping):
            mapping = _require_mapping(value, field)
            for key, nested in mapping.items():
                _validate_json_value(
                    nested,
                    f"{field}.{key}",
                    ancestors=ancestors,
                )
            return
        for index, nested in enumerate(value):
            _validate_json_value(
                nested,
                f"{field}[{index}]",
                ancestors=ancestors,
            )
    except RecursionError as exc:
        raise _invalid(f"{field} nesting exceeds the validation limit") from exc
    finally:
        ancestors.remove(identity)


def _require_trigger_name(value: object, field: str) -> str:
    name = _require_string(value, field, identifier=True)
    if not _TRIGGER_NAME_RE.fullmatch(name):
        raise _invalid(
            f"{field} has invalid format; use letters, numbers, underscore, and "
            "hyphen only"
        )
    return name


def _require_action_tier(value: object, field: str) -> ActionTier:
    tier = _require_string(value, field, identifier=True)
    if tier not in VALID_ACTION_TIERS:
        raise _invalid(f"{field} must be one of A, B, C, or D")
    return cast(ActionTier, tier)


def _parse_sensors(value: object) -> None:
    seen_sensor_types: set[str] = set()
    for index, item in enumerate(_require_array(value, "sensors_required")):
        field = f"sensors_required[{index}]"
        sensor = _require_mapping(item, field)
        sensor_type = _require_string(
            sensor.get("type"),
            f"{field}.type",
            identifier=True,
        )
        if sensor_type in seen_sensor_types:
            raise _invalid(f"duplicate sensor type {sensor_type!r}")
        seen_sensor_types.add(sensor_type)
        protocol = sensor.get("protocol")
        if protocol is not None:
            _require_string(protocol, f"{field}.protocol", identifier=True)


def _parse_triggers(value: object) -> tuple[_TriggerPolicy, ...]:
    raw_triggers = _require_array(value, "triggers", non_empty=True)
    triggers: list[_TriggerPolicy] = []
    seen_names: set[str] = set()

    for index, item in enumerate(raw_triggers):
        field = f"triggers[{index}]"
        trigger = _require_mapping(item, field)
        name = _require_trigger_name(trigger.get("name"), f"{field}.name")
        if name in seen_names:
            raise _invalid(f"duplicate trigger name {name!r}")
        seen_names.add(name)

        tier = _require_action_tier(
            trigger.get("action_tier"),
            f"triggers[{name}].action_tier",
        )
        _require_string(
            trigger.get("condition", ""),
            f"triggers[{name}].condition",
            non_empty=False,
        )
        _require_int(
            trigger.get("cooldown_seconds", 0),
            f"triggers[{name}].cooldown_seconds",
        )

        escalation_default = "rule" if tier == "D" else "local_slm"
        escalation = _require_string(
            trigger.get("escalate_to", escalation_default),
            f"triggers[{name}].escalate_to",
            identifier=True,
        )
        if escalation not in VALID_ESCALATION_TIERS:
            raise _invalid(
                f"triggers[{name}].escalate_to must be rule, local_slm, or gateway"
            )
        if tier == "D" and escalation != "rule":
            raise _invalid(f"Tier D trigger {name!r} must use escalate_to='rule'")

        bypass_llm = _require_bool(
            trigger.get("bypass_llm", False),
            f"triggers[{name}].bypass_llm",
        )
        if bypass_llm and tier != "D":
            raise _invalid(f"trigger {name!r} sets bypass_llm=true outside Tier D")

        reasoning_policy: str | None = None
        raw_reasoning_policy = trigger.get("reasoning_policy")
        if raw_reasoning_policy is not None:
            reasoning_policy = _require_string(
                raw_reasoning_policy,
                f"triggers[{name}].reasoning_policy",
                identifier=True,
            )
            if reasoning_policy != "post_action":
                raise _invalid(
                    f"trigger {name!r} has unsupported "
                    f"reasoning_policy={reasoning_policy!r}"
                )
            if tier != "B":
                raise _invalid(
                    f"trigger {name!r} uses reasoning_policy=post_action outside Tier B"
                )

        requires_approval = _require_bool(
            trigger.get("requires_approval", False),
            f"triggers[{name}].requires_approval",
        )
        _require_int(
            trigger.get("approval_timeout_seconds", 300),
            f"triggers[{name}].approval_timeout_seconds",
        )
        safe_default = _require_string(
            trigger.get("safe_default_action", "log_to_dashboard"),
            f"triggers[{name}].safe_default_action",
            non_empty=False,
            identifier=True,
        )
        if tier == "C" and not safe_default:
            raise _invalid(
                f"Tier C trigger {name!r} requires a non-empty safe_default_action"
            )

        triggers.append(
            _TriggerPolicy(
                name=name,
                action_tier=tier,
                requires_approval=requires_approval,
                reasoning_policy=reasoning_policy,
                safe_default_action=safe_default,
            )
        )

    return tuple(triggers)


def _parse_actions(
    value: object,
    triggers: tuple[_TriggerPolicy, ...],
) -> tuple[tuple[str, ...], frozenset[ActionTier]]:
    actions = _require_mapping(value, "actions")
    raw_available = _require_array(
        actions.get("available"),
        "actions.available",
        non_empty=True,
    )
    action_tiers: dict[str, ActionTier] = {}

    for index, item in enumerate(raw_available):
        field = f"actions.available[{index}]"
        action = _require_mapping(item, field)
        name = _require_string(
            action.get("name"),
            f"{field}.name",
            identifier=True,
        )
        if name in action_tiers:
            raise _invalid(f"duplicate action name {name!r}")
        action_tiers[name] = _require_action_tier(
            action.get("tier"),
            f"{field}.tier",
        )

    defaults = _require_mapping(actions.get("defaults"), "actions.defaults")
    trigger_names = {trigger.name for trigger in triggers}
    default_names = set(defaults)
    missing_defaults = sorted(trigger_names - default_names)
    extra_defaults = sorted(default_names - trigger_names)
    if missing_defaults:
        raise _invalid(
            "missing actions.defaults mapping for trigger(s): "
            + ", ".join(missing_defaults)
        )
    if extra_defaults:
        raise _invalid(
            "actions.defaults contains unknown trigger(s): " + ", ".join(extra_defaults)
        )

    for trigger in triggers:
        field = f"actions.defaults.{trigger.name}"
        raw_action_names = _require_array(defaults[trigger.name], field, non_empty=True)
        default_action_names: list[str] = []
        seen_default_actions: set[str] = set()
        for index, raw_action_name in enumerate(raw_action_names):
            action_name = _require_string(
                raw_action_name,
                f"{field}[{index}]",
                identifier=True,
            )
            if action_name in seen_default_actions:
                raise _invalid(
                    f"{field} contains duplicate action reference {action_name!r}"
                )
            seen_default_actions.add(action_name)
            if action_name not in action_tiers:
                raise _invalid(f"{field} references undeclared action {action_name!r}")
            if action_tiers[action_name] == "D" and trigger.action_tier != "D":
                raise _invalid(
                    f"{field} references Tier D action {action_name!r} from "
                    f"non-Tier-D trigger authority"
                )
            default_action_names.append(action_name)

        if (
            trigger.action_tier == "C"
            and trigger.safe_default_action != "log_to_dashboard"
        ):
            safe_default = trigger.safe_default_action
            if safe_default not in action_tiers:
                raise _invalid(
                    f"Tier C trigger {trigger.name!r} safe_default_action "
                    f"{safe_default!r} is not declared in actions.available"
                )
            if action_tiers[safe_default] != "A":
                raise _invalid(
                    f"Tier C trigger {trigger.name!r} safe_default_action "
                    f"{safe_default!r} must be a Tier A action"
                )

        has_physical_tier_b_action = any(
            action_tiers[action_name] == "B" for action_name in default_action_names
        )
        if not has_physical_tier_b_action or trigger.action_tier in {"C", "D"}:
            continue
        if not trigger.requires_approval and trigger.reasoning_policy != "post_action":
            raise _invalid(
                f"physical Tier B trigger {trigger.name!r} must declare "
                "requires_approval=true or reasoning_policy=post_action"
            )
        if trigger.reasoning_policy == "post_action" and not any(
            action_tiers[action_name] == "A" for action_name in default_action_names
        ):
            raise _invalid(
                f"physical Tier B post_action trigger {trigger.name!r} must include "
                "a Tier A default action for operator notification"
            )

    return tuple(action_tiers), frozenset(action_tiers.values())


def _parse_prompts(value: object, trigger_names: set[str]) -> None:
    prompts = _require_mapping(value, "prompts")
    for prompt_name, raw_template in prompts.items():
        template = _require_string(
            raw_template,
            f"prompts.{prompt_name}",
            non_empty=False,
        )
        placeholder_count = len(_HISTORY_PLACEHOLDER_RE.findall(template))
        if placeholder_count > MAX_HISTORY_PLACEHOLDERS:
            scope = "trigger" if prompt_name in trigger_names else "prompt key"
            raise _invalid(
                f"{scope} {prompt_name!r} contains {placeholder_count} history "
                f"placeholders; maximum allowed is {MAX_HISTORY_PLACEHOLDERS}"
            )


def validate_skill_metadata(skill_yaml: object) -> SkillValidationResult:
    """Validate decoded skill metadata and return its authority classification.

    Unknown top-level metadata remains allowed for runtime-compatible descriptive
    fields and extensions. Every field defined by ``skills-package/v1`` is
    validated when present, and all required behavioral fields are enforced.
    """

    root = _require_mapping(skill_yaml, "skill")
    _validate_json_value(root, "skill", ancestors=set())
    name = _require_string(root.get("name"), "name", identifier=True)
    version = _require_string(root.get("version"), "version", identifier=True)
    author = _require_string(root.get("author"), "author", identifier=True)

    signature = root.get("signature")
    if signature is not None:
        _require_string(signature, "signature", identifier=True)

    _parse_sensors(root.get("sensors_required", []))
    triggers = _parse_triggers(root.get("triggers"))
    action_names, action_tiers = _parse_actions(root.get("actions"), triggers)
    trigger_names = tuple(trigger.name for trigger in triggers)
    _parse_prompts(root.get("prompts", {}), set(trigger_names))
    _require_mapping(root.get("config", {}), "config")

    trigger_tiers = frozenset(trigger.action_tier for trigger in triggers)
    declared_tiers = trigger_tiers | action_tiers
    return SkillValidationResult(
        name=name,
        version=version,
        author=author,
        trigger_names=trigger_names,
        action_names=action_names,
        declared_tiers=declared_tiers,
    )


def validate_skill_metadata_shape(skill_yaml: Mapping[str, object]) -> None:
    """Backward-compatible validation entry point for decoded mappings."""

    validate_skill_metadata(skill_yaml)


__all__ = [
    "ActionTier",
    "MAX_HISTORY_PLACEHOLDERS",
    "SkillValidationResult",
    "VALID_ACTION_TIERS",
    "VALID_ESCALATION_TIERS",
    "validate_skill_metadata",
    "validate_skill_metadata_shape",
]
