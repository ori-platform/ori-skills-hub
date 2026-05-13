# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from hub.core.models import SkillStatus
from hub.core.review import declares_tier_cd, publish_decision


def test_declares_tier_cd_from_trigger() -> None:
    skill = {"triggers": [{"name": "shutdown", "action_tier": "C"}]}
    assert declares_tier_cd(skill) is True
    decision = publish_decision(skill)
    assert decision.status is SkillStatus.PENDING_REVIEW


def test_non_actuating_skill_lists_by_default() -> None:
    skill = {"triggers": [{"name": "alert", "action_tier": "A"}]}
    decision = publish_decision(skill)
    assert decision.status is SkillStatus.LISTED
    assert decision.declares_tier_cd is False


def test_unknown_tier_fails_closed_to_pending_review() -> None:
    skill = {"triggers": [{"name": "mystery", "action_tier": "E"}]}
    decision = publish_decision(skill)
    assert decision.status is SkillStatus.PENDING_REVIEW
    assert decision.reason == "skill declares unknown action tier"
