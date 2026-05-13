# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Typed errors for Skills Hub security and contract failures."""

from __future__ import annotations


class HubError(Exception):
    """Base class for Skills Hub errors."""


class SignatureVerificationError(HubError):
    """Raised when a skill signature is missing, malformed, or invalid."""


class StorageSafetyError(HubError):
    """Raised when storage paths would escape the configured root."""


class ConfigError(HubError):
    """Raised when hub configuration is invalid."""
