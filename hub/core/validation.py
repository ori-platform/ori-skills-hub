# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Skill metadata validation boundary.

Bootstrap keeps this layer contract-oriented. Direct runtime SkillLoader imports
must be version-pinned and covered by an integration matrix before production.
"""

from __future__ import annotations

from collections.abc import Mapping

_REQUIRED_FIELDS = {
    "name",
    "version",
    "author",
    "license",
    "signature",
    "triggers",
    "actions",
}


def validate_skill_metadata_shape(skill_yaml: Mapping[str, object]) -> None:
    missing = sorted(field for field in _REQUIRED_FIELDS if field not in skill_yaml)
    if missing:
        raise ValueError(
            f"skill metadata missing required fields: {', '.join(missing)}"
        )
