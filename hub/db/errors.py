# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Typed persistence errors for the Skills Hub."""

from __future__ import annotations

from hub.core.errors import HubError


class PersistenceError(HubError):
    """Base class for database failures exposed outside the persistence layer."""


class DatabaseConfigurationError(PersistenceError):
    """Raised when the configured database URL cannot support async access."""


class PersistenceConflictError(PersistenceError):
    """Raised when a durable uniqueness or idempotency constraint is violated."""


class RecordNotFoundError(PersistenceError):
    """Raised when a requested persistence record does not exist."""


class InvalidStateTransitionError(PersistenceError):
    """Raised when a skill publication state transition is not permitted."""


class ImmutableRecordError(PersistenceError):
    """Raised when code attempts to alter append-only persistence data."""
