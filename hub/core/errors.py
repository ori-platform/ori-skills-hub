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


class StorageIntegrityError(StorageSafetyError):
    """Raised when stored object bytes do not match their content address."""


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


class PublishError(HubError):
    """Base class for publish pipeline failures."""


class PublishReplayError(PublishError):
    """Raised when an idempotency key has already been consumed."""


class PublishConflictError(PublishError):
    """Raised when a publication conflicts with an existing durable record."""


class PublishAuthorMismatchError(PublishError):
    """Raised when the manifest author is not the authenticated author."""
