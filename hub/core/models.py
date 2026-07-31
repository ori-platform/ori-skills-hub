# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Core Skills Hub models independent of the web framework."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SkillStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    LISTED = "listed"
    REJECTED = "rejected"
    UNLISTED = "unlisted"


class ScannerVerdict(StrEnum):
    """Three-state malware scan outcome persisted for every publication."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class SkillRecord:
    name: str
    version: str
    author_github: str
    status: SkillStatus
    declares_tier_cd: bool
    tarball_path: str
    signature: str
    downloads: int = 0


@dataclass(frozen=True)
class PublishDecision:
    status: SkillStatus
    declares_tier_cd: bool
    reason: str


@dataclass(frozen=True)
class PublishResult:
    """Public summary of one completed publish pipeline run."""

    name: str
    version: str
    status: SkillStatus
    artifact_digest: str
    manifest_digest: str
