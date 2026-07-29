# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Review gate helpers for Tier C/D skill packages."""

from __future__ import annotations

from collections.abc import Mapping

from hub.core.models import PublishDecision, SkillStatus
from hub.core.validation import validate_skill_metadata


def declares_tier_cd(skill_yaml: Mapping[str, object]) -> bool:
    """Return Tier C/D authority only after validating the entire package."""

    return validate_skill_metadata(skill_yaml).declares_tier_cd


def publish_decision(skill_yaml: Mapping[str, object]) -> PublishDecision:
    """Classify a valid package, rejecting malformed metadata before listing."""

    validation = validate_skill_metadata(skill_yaml)
    if validation.declares_tier_cd:
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
