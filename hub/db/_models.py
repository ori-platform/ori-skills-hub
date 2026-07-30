# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Internal SQLAlchemy mappings for durable Skills Hub state."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    UniqueConstraint,
    event,
    func,
)
from sqlalchemy.engine import Connection
from sqlalchemy.orm import DeclarativeBase, Mapped, Mapper, mapped_column

from hub.core.models import SkillStatus
from hub.db.errors import ImmutableRecordError, InvalidStateTransitionError

_STATUS_VALUES = ", ".join(f"'{status.value}'" for status in SkillStatus)
_SQLITE_SCHEMA_GUARDS = (
    """
    CREATE TRIGGER IF NOT EXISTS artifacts_reject_update
    BEFORE UPDATE ON artifacts
    BEGIN
        SELECT RAISE(ABORT, 'artifacts are immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS artifacts_reject_delete
    BEFORE DELETE ON artifacts
    BEGIN
        SELECT RAISE(ABORT, 'artifacts are immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_transition_audit_reject_update
    BEFORE UPDATE ON skill_transition_audit
    BEGIN
        SELECT RAISE(ABORT, 'skill transition audit is append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_transition_audit_reject_delete
    BEFORE DELETE ON skill_transition_audit
    BEGIN
        SELECT RAISE(ABORT, 'skill transition audit is append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_transition_audit_validate_timestamp
    BEFORE INSERT ON skill_transition_audit
    WHEN NEW.occurred_at <> CURRENT_TIMESTAMP
    BEGIN
        SELECT RAISE(ABORT, 'audit timestamps are database-generated');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_transition_audit_validate_state
    BEFORE INSERT ON skill_transition_audit
    WHEN NEW.prior_status IS NOT NULL
         AND NOT EXISTS (
             SELECT 1
             FROM skill_versions AS skill
             JOIN artifacts AS artifact ON artifact.id = skill.artifact_id
             WHERE skill.id = NEW.skill_version_id
               AND skill.status = NEW.prior_status
               AND skill.revision + 1 = NEW.transition_number
               AND artifact.artifact_digest = NEW.artifact_digest
               AND artifact.manifest_digest = NEW.manifest_digest
               AND (
                   (NEW.prior_status = 'pending_review'
                    AND NEW.new_status IN ('listed', 'rejected'))
                   OR (NEW.prior_status = 'listed'
                       AND NEW.new_status = 'unlisted')
               )
         )
    BEGIN
        SELECT RAISE(ABORT, 'audit does not match current skill state');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_transition_audit_apply_listing
    AFTER INSERT ON skill_transition_audit
    WHEN NEW.prior_status = 'pending_review'
         AND NEW.new_status = 'listed'
    BEGIN
        UPDATE skill_versions
        SET status = NEW.new_status,
            revision = NEW.transition_number,
            review_approved_at = NEW.occurred_at,
            review_approved_by = NEW.actor_id,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = NEW.skill_version_id
          AND status = NEW.prior_status
          AND revision + 1 = NEW.transition_number;
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'audit transition did not update skill state')
        END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_transition_audit_apply_nonlisting
    AFTER INSERT ON skill_transition_audit
    WHEN NEW.prior_status IS NOT NULL
         AND NEW.new_status IN ('rejected', 'unlisted')
    BEGIN
        UPDATE skill_versions
        SET status = NEW.new_status,
            revision = NEW.transition_number,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = NEW.skill_version_id
          AND status = NEW.prior_status
          AND revision + 1 = NEW.transition_number;
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'audit transition did not update skill state')
        END;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_versions_validate_initial_status
    BEFORE INSERT ON skill_versions
    WHEN NEW.status NOT IN ('pending_review', 'listed')
         OR (NEW.declares_tier_cd AND NEW.status = 'listed')
         OR NEW.revision <> 1
         OR NEW.downloads <> 0
         OR NEW.review_approved_at IS NOT NULL
         OR NEW.review_approved_by IS NOT NULL
         OR NOT EXISTS (
             SELECT 1
             FROM skill_transition_audit AS audit
             JOIN artifacts AS artifact ON artifact.id = NEW.artifact_id
             WHERE audit.skill_version_id = NEW.id
               AND audit.transition_number = 1
               AND audit.prior_status IS NULL
               AND audit.new_status = NEW.status
               AND audit.artifact_digest = artifact.artifact_digest
               AND audit.manifest_digest = artifact.manifest_digest
         )
    BEGIN
        SELECT RAISE(ABORT, 'invalid initial skill status');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_versions_reject_identity_authority_update
    BEFORE UPDATE OF id, name, version, author_id, artifact_id, declares_tier_cd
    ON skill_versions
    BEGIN
        SELECT RAISE(ABORT, 'skill identity and authority are immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_versions_reject_approval_update
    BEFORE UPDATE OF review_approved_at, review_approved_by ON skill_versions
    WHEN NOT (
        OLD.status = 'pending_review'
        AND NEW.status = 'listed'
        AND OLD.review_approved_at IS NULL
        AND OLD.review_approved_by IS NULL
        AND NEW.review_approved_at IS NOT NULL
        AND NEW.review_approved_by IS NOT NULL
    )
    BEGIN
        SELECT RAISE(ABORT, 'skill approval metadata is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_versions_validate_revision_transition
    BEFORE UPDATE OF revision ON skill_versions
    WHEN NEW.revision <> OLD.revision
         AND (
             NEW.status = OLD.status
             OR NEW.revision <> OLD.revision + 1
         )
    BEGIN
        SELECT RAISE(ABORT, 'invalid skill revision transition');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_versions_validate_status_transition
    BEFORE UPDATE OF status ON skill_versions
    WHEN NEW.status <> OLD.status
         AND NOT (
             (OLD.status = 'pending_review'
              AND NEW.status IN ('listed', 'rejected'))
             OR (OLD.status = 'listed' AND NEW.status = 'unlisted')
         )
    BEGIN
        SELECT RAISE(ABORT, 'invalid skill status transition');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_versions_require_transition_audit
    BEFORE UPDATE OF status ON skill_versions
    WHEN NEW.status <> OLD.status
         AND NOT EXISTS (
             SELECT 1
             FROM skill_transition_audit AS audit
             JOIN artifacts AS artifact ON artifact.id = OLD.artifact_id
             WHERE audit.skill_version_id = OLD.id
               AND audit.transition_number = NEW.revision
               AND audit.prior_status = OLD.status
               AND audit.new_status = NEW.status
               AND audit.artifact_digest = artifact.artifact_digest
               AND audit.manifest_digest = artifact.manifest_digest
               AND (
                   NEW.status <> 'listed'
                   OR (
                       NEW.review_approved_at = audit.occurred_at
                       AND NEW.review_approved_by = audit.actor_id
                   )
               )
         )
    BEGIN
        SELECT RAISE(ABORT, 'skill status transition requires matching audit');
    END
    """,
)

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def new_record_id() -> str:
    """Return an opaque identifier suitable for externally referenced records."""

    return uuid4().hex


class Base(DeclarativeBase):
    """Declarative base with deterministic migration constraint names."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _install_sqlite_schema_guards(
    _metadata: MetaData, connection: Connection, **_kwargs: Any
) -> None:
    if connection.dialect.name != "sqlite":
        return
    for statement in _SQLITE_SCHEMA_GUARDS:
        connection.exec_driver_sql(statement)


class AuthorModel(Base):
    """A registered skill author and their durable signing identity."""

    __tablename__ = "authors"
    __table_args__ = (
        CheckConstraint("length(external_subject) > 0", name="external_subject_set"),
        CheckConstraint("length(display_handle) > 0", name="display_handle_set"),
        CheckConstraint("length(public_key_b64) > 0", name="public_key_set"),
        CheckConstraint("status IN ('active', 'revoked')", name="status_valid"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_record_id)
    external_subject: Mapped[str] = mapped_column(String(255), unique=True)
    display_handle: Mapped[str] = mapped_column(String(255), unique=True)
    public_key_b64: Mapped[str] = mapped_column(String(255), unique=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="active", server_default="active"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )


class AuthorCredentialModel(Base):
    """An opaque credential lookup and one-way credential hash."""

    __tablename__ = "author_credentials"
    __table_args__ = (
        CheckConstraint("length(kind) > 0", name="kind_set"),
        CheckConstraint("length(lookup_id) > 0", name="lookup_id_set"),
        CheckConstraint(
            "credential_hash LIKE 'sha256:%' AND length(credential_hash) = 71",
            name="credential_hash_valid",
        ),
        CheckConstraint(
            "status IN ('active', 'revoked', 'expired')", name="status_valid"
        ),
        Index("ix_author_credentials_author_id", "author_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_record_id)
    author_id: Mapped[str] = mapped_column(
        ForeignKey("authors.id", ondelete="RESTRICT"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    lookup_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    credential_hash: Mapped[str] = mapped_column(
        String(71), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="active", server_default="active"
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )


class ArtifactModel(Base):
    """Immutable identity and signatures for a stored skill archive."""

    __tablename__ = "artifacts"
    __table_args__ = (
        CheckConstraint(
            "artifact_digest LIKE 'sha256:%' AND length(artifact_digest) = 71",
            name="artifact_digest_valid",
        ),
        CheckConstraint(
            "manifest_digest LIKE 'sha256:%' AND length(manifest_digest) = 71",
            name="manifest_digest_valid",
        ),
        CheckConstraint("length(storage_key) > 0", name="storage_key_set"),
        CheckConstraint("byte_size >= 0", name="byte_size_nonnegative"),
        CheckConstraint(
            "length(artifact_signature) > 0", name="artifact_signature_set"
        ),
        CheckConstraint(
            "length(manifest_signature) > 0", name="manifest_signature_set"
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_record_id)
    artifact_digest: Mapped[str] = mapped_column(
        String(71), nullable=False, unique=True
    )
    manifest_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    artifact_signature: Mapped[str] = mapped_column(String(512), nullable=False)
    manifest_signature: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )


class SkillVersionModel(Base):
    """A versioned skill publication and its current discoverability state."""

    __tablename__ = "skill_versions"
    __table_args__ = (
        UniqueConstraint("name", "version", name="skill_identity"),
        CheckConstraint("length(name) > 0", name="name_set"),
        CheckConstraint("length(version) > 0", name="version_set"),
        CheckConstraint(f"status IN ({_STATUS_VALUES})", name="status_valid"),
        CheckConstraint("downloads >= 0", name="downloads_nonnegative"),
        CheckConstraint("revision >= 1", name="revision_positive"),
        CheckConstraint(
            "(review_approved_at IS NULL) = (review_approved_by IS NULL)",
            name="approval_fields_paired",
        ),
        CheckConstraint(
            "status NOT IN ('pending_review', 'rejected') "
            "OR (review_approved_at IS NULL AND review_approved_by IS NULL)",
            name="approval_fields_match_status",
        ),
        CheckConstraint(
            "NOT declares_tier_cd OR status <> 'listed' "
            "OR (review_approved_at IS NOT NULL AND review_approved_by IS NOT NULL)",
            name="tier_cd_listing_reviewed",
        ),
        Index("ix_skill_versions_status", "status"),
        Index("ix_skill_versions_author_id", "author_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_record_id)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    author_id: Mapped[str] = mapped_column(
        ForeignKey("authors.id", ondelete="RESTRICT"), nullable=False
    )
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    declares_tier_cd: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
    downloads: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    review_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_approved_by: Mapped[str | None] = mapped_column(String(255))
    revision: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )


class SkillTransitionAuditModel(Base):
    """Append-only publication and review transition history."""

    __tablename__ = "skill_transition_audit"
    __table_args__ = (
        UniqueConstraint("actor_id", "idempotency_key", name="actor_idempotency"),
        UniqueConstraint(
            "skill_version_id",
            "transition_number",
            name="skill_transition_number",
        ),
        CheckConstraint(
            f"prior_status IS NULL OR prior_status IN ({_STATUS_VALUES})",
            name="prior_status_valid",
        ),
        CheckConstraint(f"new_status IN ({_STATUS_VALUES})", name="new_status_valid"),
        CheckConstraint(
            "prior_status IS NULL OR prior_status <> new_status",
            name="status_changed",
        ),
        CheckConstraint("length(actor_id) > 0", name="actor_set"),
        CheckConstraint("length(reason) > 0", name="reason_set"),
        CheckConstraint(
            "(prior_status IS NULL AND transition_number = 1) "
            "OR (prior_status IS NOT NULL AND transition_number >= 2)",
            name="transition_number_matches_state",
        ),
        CheckConstraint("length(correlation_id) > 0", name="correlation_id_set"),
        CheckConstraint("length(idempotency_key) > 0", name="idempotency_key_set"),
        CheckConstraint(
            "artifact_digest LIKE 'sha256:%' AND length(artifact_digest) = 71",
            name="artifact_digest_valid",
        ),
        CheckConstraint(
            "manifest_digest LIKE 'sha256:%' AND length(manifest_digest) = 71",
            name="manifest_digest_valid",
        ),
        Index(
            "ix_skill_transition_audit_skill_time",
            "skill_version_id",
            "occurred_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_record_id)
    skill_version_id: Mapped[str] = mapped_column(
        ForeignKey(
            "skill_versions.id",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        nullable=False,
    )
    transition_number: Mapped[int] = mapped_column(Integer, nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    prior_status: Mapped[str | None] = mapped_column(String(32))
    new_status: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(1024), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    correlation_id: Mapped[str] = mapped_column(String(255), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    artifact_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    manifest_digest: Mapped[str] = mapped_column(String(71), nullable=False)


def _reject_immutable_change(
    _mapper: Mapper[Any], _connection: Connection, target: object
) -> None:
    raise ImmutableRecordError(
        f"{type(target).__name__} records are append-only and cannot be changed"
    )


def _reject_skill_update(
    _mapper: Mapper[Any], _connection: Connection, _target: SkillVersionModel
) -> None:
    raise InvalidStateTransitionError(
        "skill changes must use HubRepository so state changes and audit rows "
        "commit atomically"
    )


def _validate_initial_skill(
    _mapper: Mapper[Any], _connection: Connection, target: SkillVersionModel
) -> None:
    if target.status not in {
        SkillStatus.PENDING_REVIEW.value,
        SkillStatus.LISTED.value,
    }:
        raise InvalidStateTransitionError(
            "a skill must be created as pending_review or listed"
        )
    if target.declares_tier_cd and target.status == SkillStatus.LISTED.value:
        raise InvalidStateTransitionError(
            "Tier C/D skills cannot be created in the listed state"
        )


def _reject_client_audit_timestamp(
    _mapper: Mapper[Any],
    _connection: Connection,
    target: SkillTransitionAuditModel,
) -> None:
    if target.occurred_at is not None:
        raise ImmutableRecordError("audit timestamps are database-generated")


event.listen(ArtifactModel, "before_update", _reject_immutable_change)
event.listen(ArtifactModel, "before_delete", _reject_immutable_change)
event.listen(SkillTransitionAuditModel, "before_update", _reject_immutable_change)
event.listen(SkillTransitionAuditModel, "before_delete", _reject_immutable_change)
event.listen(
    SkillTransitionAuditModel,
    "before_insert",
    _reject_client_audit_timestamp,
)
event.listen(SkillVersionModel, "before_insert", _validate_initial_skill)
event.listen(SkillVersionModel, "before_update", _reject_skill_update)
event.listen(Base.metadata, "after_create", _install_sqlite_schema_guards)
