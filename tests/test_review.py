# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from hub.core.errors import SkillValidationError
from hub.core.models import SkillStatus
from hub.core.review import declares_tier_cd, publish_decision


def _skill(
    *,
    trigger_tier: str = "A",
    action_tier: str = "A",
) -> dict[str, object]:
    return {
        "name": "review-test",
        "version": "1.0.0",
        "author": "test-author",
        "triggers": [
            {
                "name": "threshold",
                "condition": "value > 1",
                "action_tier": trigger_tier,
                "safe_default_action": "alert_operator",
            }
        ],
        "actions": {
            "available": [{"name": "alert_operator", "tier": action_tier}],
            "defaults": {"threshold": ["alert_operator"]},
        },
    }


def test_declares_tier_cd_from_trigger() -> None:
    skill = _skill(trigger_tier="C")
    assert declares_tier_cd(skill) is True
    decision = publish_decision(skill)
    assert decision.status is SkillStatus.PENDING_REVIEW


def test_declares_tier_cd_from_unused_action_capability() -> None:
    skill = _skill()
    actions = skill["actions"]
    assert isinstance(actions, dict)
    available = actions["available"]
    assert isinstance(available, list)
    available.append({"name": "emergency_shutdown", "tier": "D"})
    assert declares_tier_cd(skill) is True
    decision = publish_decision(skill)
    assert decision.status is SkillStatus.PENDING_REVIEW
    assert decision.declares_tier_cd is True


def test_tier_c_action_escalation_still_requires_review() -> None:
    skill = _skill(action_tier="C")

    decision = publish_decision(skill)

    assert decision.status is SkillStatus.PENDING_REVIEW
    assert decision.declares_tier_cd is True


def test_non_actuating_skill_lists_by_default() -> None:
    skill = _skill()
    decision = publish_decision(skill)
    assert decision.status is SkillStatus.LISTED
    assert decision.declares_tier_cd is False


def test_invalid_tier_cannot_reach_a_listing_decision() -> None:
    skill = _skill(trigger_tier="E")
    with pytest.raises(SkillValidationError, match="action_tier"):
        publish_decision(skill)


def test_malformed_tier_cd_metadata_cannot_bypass_validation() -> None:
    skill = _skill()
    skill["actions"] = {
        "available": [{"name": "shutdown", "tier": ["C"]}],
        "defaults": {"threshold": ["shutdown"]},
    }
    with pytest.raises(SkillValidationError, match="tier must be a string"):
        publish_decision(skill)
