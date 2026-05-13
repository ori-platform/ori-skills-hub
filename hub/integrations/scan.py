# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Optional malware scan integration."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanResult:
    status: str
    detail: str


class VirusTotalScanner:
    def __init__(self, api_key: str | None) -> None:
        self.api_key = api_key

    def scan(self, _payload: bytes) -> ScanResult:
        if not self.api_key:
            return ScanResult(status="skipped", detail="HUB_VIRUSTOTAL_API_KEY not set")
        return ScanResult(
            status="pending_manual_review",
            detail="scanner transport not implemented in bootstrap",
        )
