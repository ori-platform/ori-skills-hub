# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Typed errors for Skills Hub security and contract failures."""

from __future__ import annotations


class HubError(Exception):
    """Base class for Skills Hub errors."""


class SignatureVerificationError(HubError):
    """Raised when a skill signature is missing, malformed, or invalid."""


class SkillValidationError(HubError):
    """Raised when decoded skill metadata violates the package v1 contract."""


class StorageSafetyError(HubError):
    """Raised when storage paths would escape the configured root."""


class TarballError(HubError):
    """Base class for malformed, unsafe, or over-limit skill archives."""


class TarballFormatError(TarballError):
    """Raised when an archive or its manifest is structurally malformed."""


class TarballSafetyError(TarballError):
    """Raised when archive members violate the safe package boundary."""


class TarballLimitError(TarballError):
    """Raised when compressed or expanded archive limits are exceeded."""


class ConfigError(HubError):
    """Raised when hub configuration is invalid."""
