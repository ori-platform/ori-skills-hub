# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Review gate helpers for Tier C/D skill packages."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from hub.core.models import PublishDecision, SkillStatus

_VALID_TIERS = {"A", "B", "C", "D"}
_MANUAL_REVIEW_TIERS = {"C", "D"}


def _tier_values(skill_yaml: Mapping[str, object]) -> list[object]:
    values: list[object] = []
    triggers = skill_yaml.get("triggers", [])
    if isinstance(triggers, Sequence) and not isinstance(triggers, (str, bytes)):
        for trigger in triggers:
            if isinstance(trigger, Mapping) and "action_tier" in trigger:
                values.append(trigger["action_tier"])

    actions = skill_yaml.get("actions", {})
    if isinstance(actions, Mapping):
        available = actions.get("available", [])
        if isinstance(available, Sequence) and not isinstance(available, (str, bytes)):
            for action in available:
                if isinstance(action, Mapping) and "tier" in action:
                    values.append(action["tier"])
    return values


def declares_tier_cd(skill_yaml: Mapping[str, object]) -> bool:
    return any(tier in _MANUAL_REVIEW_TIERS for tier in _tier_values(skill_yaml))


def declares_unknown_tier(skill_yaml: Mapping[str, object]) -> bool:
    return any(tier not in _VALID_TIERS for tier in _tier_values(skill_yaml))


def publish_decision(skill_yaml: Mapping[str, object]) -> PublishDecision:
    if declares_unknown_tier(skill_yaml):
        return PublishDecision(
            status=SkillStatus.PENDING_REVIEW,
            declares_tier_cd=False,
            reason="skill declares unknown action tier",
        )

    risky = declares_tier_cd(skill_yaml)
    if risky:
        return PublishDecision(
            status=SkillStatus.PENDING_REVIEW,
            declares_tier_cd=True,
            reason="skill declares Tier C/D authority",
        )
    return PublishDecision(
        status=SkillStatus.LISTED,
        declares_tier_cd=False,
        reason="skill has no Tier C/D authority",
    )
