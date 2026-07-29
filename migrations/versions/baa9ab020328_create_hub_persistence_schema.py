# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""create hub persistence schema

Revision ID: baa9ab020328
Revises:
Create Date: 2026-07-29 17:34:55.842615
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "baa9ab020328"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQLITE_SCHEMA_GUARDS = (
    """
    CREATE TRIGGER artifacts_reject_update
    BEFORE UPDATE ON artifacts
    BEGIN
        SELECT RAISE(ABORT, 'artifacts are immutable');
    END
    """,
    """
    CREATE TRIGGER artifacts_reject_delete
    BEFORE DELETE ON artifacts
    BEGIN
        SELECT RAISE(ABORT, 'artifacts are immutable');
    END
    """,
    """
    CREATE TRIGGER skill_transition_audit_reject_update
    BEFORE UPDATE ON skill_transition_audit
    BEGIN
        SELECT RAISE(ABORT, 'skill transition audit is append-only');
    END
    """,
    """
    CREATE TRIGGER skill_transition_audit_reject_delete
    BEFORE DELETE ON skill_transition_audit
    BEGIN
        SELECT RAISE(ABORT, 'skill transition audit is append-only');
    END
    """,
    """
    CREATE TRIGGER skill_transition_audit_validate_timestamp
    BEFORE INSERT ON skill_transition_audit
    WHEN NEW.occurred_at <> CURRENT_TIMESTAMP
    BEGIN
        SELECT RAISE(ABORT, 'audit timestamps are database-generated');
    END
    """,
    """
    CREATE TRIGGER skill_versions_validate_initial_status
    BEFORE INSERT ON skill_versions
    WHEN NEW.status NOT IN ('pending_review', 'listed')
         OR (NEW.declares_tier_cd AND NEW.status = 'listed')
    BEGIN
        SELECT RAISE(ABORT, 'invalid initial skill status');
    END
    """,
    """
    CREATE TRIGGER skill_versions_validate_status_transition
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
)


def upgrade() -> None:
    """Apply this schema revision."""

    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("artifact_digest", sa.String(length=71), nullable=False),
        sa.Column("manifest_digest", sa.String(length=71), nullable=False),
        sa.Column("storage_key", sa.String(length=1024), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("artifact_signature", sa.String(length=512), nullable=False),
        sa.Column("manifest_signature", sa.String(length=512), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "artifact_digest LIKE 'sha256:%' AND length(artifact_digest) = 71",
            name=op.f("ck_artifacts_artifact_digest_valid"),
        ),
        sa.CheckConstraint(
            "manifest_digest LIKE 'sha256:%' AND length(manifest_digest) = 71",
            name=op.f("ck_artifacts_manifest_digest_valid"),
        ),
        sa.CheckConstraint(
            "byte_size >= 0", name=op.f("ck_artifacts_byte_size_nonnegative")
        ),
        sa.CheckConstraint(
            "length(artifact_signature) > 0",
            name=op.f("ck_artifacts_artifact_signature_set"),
        ),
        sa.CheckConstraint(
            "length(manifest_signature) > 0",
            name=op.f("ck_artifacts_manifest_signature_set"),
        ),
        sa.CheckConstraint(
            "length(storage_key) > 0", name=op.f("ck_artifacts_storage_key_set")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_artifacts")),
        sa.UniqueConstraint(
            "artifact_digest", name=op.f("uq_artifacts_artifact_digest")
        ),
        sa.UniqueConstraint("storage_key", name=op.f("uq_artifacts_storage_key")),
    )
    op.create_table(
        "authors",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("external_subject", sa.String(length=255), nullable=False),
        sa.Column("display_handle", sa.String(length=255), nullable=False),
        sa.Column("public_key_b64", sa.String(length=255), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="active", nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name=op.f("ck_authors_status_valid")
        ),
        sa.CheckConstraint(
            "length(display_handle) > 0", name=op.f("ck_authors_display_handle_set")
        ),
        sa.CheckConstraint(
            "length(external_subject) > 0", name=op.f("ck_authors_external_subject_set")
        ),
        sa.CheckConstraint(
            "length(public_key_b64) > 0", name=op.f("ck_authors_public_key_set")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_authors")),
        sa.UniqueConstraint("display_handle", name=op.f("uq_authors_display_handle")),
        sa.UniqueConstraint(
            "external_subject", name=op.f("uq_authors_external_subject")
        ),
        sa.UniqueConstraint("public_key_b64", name=op.f("uq_authors_public_key_b64")),
    )
    op.create_table(
        "author_credentials",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("author_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("lookup_id", sa.String(length=255), nullable=False),
        sa.Column("credential_hash", sa.String(length=71), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="active", nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked', 'expired')",
            name=op.f("ck_author_credentials_status_valid"),
        ),
        sa.CheckConstraint(
            "credential_hash LIKE 'sha256:%' AND length(credential_hash) = 71",
            name=op.f("ck_author_credentials_credential_hash_valid"),
        ),
        sa.CheckConstraint(
            "length(kind) > 0", name=op.f("ck_author_credentials_kind_set")
        ),
        sa.CheckConstraint(
            "length(lookup_id) > 0", name=op.f("ck_author_credentials_lookup_id_set")
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["authors.id"],
            name=op.f("fk_author_credentials_author_id_authors"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_author_credentials")),
        sa.UniqueConstraint(
            "credential_hash", name=op.f("uq_author_credentials_credential_hash")
        ),
        sa.UniqueConstraint("lookup_id", name=op.f("uq_author_credentials_lookup_id")),
    )
    op.create_index(
        "ix_author_credentials_author_id",
        "author_credentials",
        ["author_id"],
        unique=False,
    )
    op.create_table(
        "skill_versions",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("author_id", sa.String(length=32), nullable=False),
        sa.Column("artifact_id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("declares_tier_cd", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("downloads", sa.Integer(), server_default="0", nullable=False),
        sa.Column("review_approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_approved_by", sa.String(length=255), nullable=True),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "NOT declares_tier_cd OR status <> 'listed' OR "
            "(review_approved_at IS NOT NULL AND review_approved_by IS NOT NULL)",
            name=op.f("ck_skill_versions_tier_cd_listing_reviewed"),
        ),
        sa.CheckConstraint(
            "status IN ('pending_review', 'listed', 'rejected', 'unlisted')",
            name=op.f("ck_skill_versions_status_valid"),
        ),
        sa.CheckConstraint(
            "(review_approved_at IS NULL) = (review_approved_by IS NULL)",
            name=op.f("ck_skill_versions_approval_fields_paired"),
        ),
        sa.CheckConstraint(
            "downloads >= 0", name=op.f("ck_skill_versions_downloads_nonnegative")
        ),
        sa.CheckConstraint("length(name) > 0", name=op.f("ck_skill_versions_name_set")),
        sa.CheckConstraint(
            "length(version) > 0", name=op.f("ck_skill_versions_version_set")
        ),
        sa.CheckConstraint(
            "revision >= 1", name=op.f("ck_skill_versions_revision_positive")
        ),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["artifacts.id"],
            name=op.f("fk_skill_versions_artifact_id_artifacts"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["authors.id"],
            name=op.f("fk_skill_versions_author_id_authors"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_skill_versions")),
        sa.UniqueConstraint("artifact_id", name=op.f("uq_skill_versions_artifact_id")),
        sa.UniqueConstraint("name", "version", name="skill_identity"),
    )
    op.create_index(
        "ix_skill_versions_author_id", "skill_versions", ["author_id"], unique=False
    )
    op.create_index(
        "ix_skill_versions_status", "skill_versions", ["status"], unique=False
    )
    op.create_table(
        "skill_transition_audit",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("skill_version_id", sa.String(length=32), nullable=False),
        sa.Column("transition_number", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=False),
        sa.Column("prior_status", sa.String(length=32), nullable=True),
        sa.Column("new_status", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=1024), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("correlation_id", sa.String(length=255), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("artifact_digest", sa.String(length=71), nullable=False),
        sa.Column("manifest_digest", sa.String(length=71), nullable=False),
        sa.CheckConstraint(
            "artifact_digest LIKE 'sha256:%' AND length(artifact_digest) = 71",
            name=op.f("ck_skill_transition_audit_artifact_digest_valid"),
        ),
        sa.CheckConstraint(
            "manifest_digest LIKE 'sha256:%' AND length(manifest_digest) = 71",
            name=op.f("ck_skill_transition_audit_manifest_digest_valid"),
        ),
        sa.CheckConstraint(
            "new_status IN ('pending_review', 'listed', 'rejected', 'unlisted')",
            name=op.f("ck_skill_transition_audit_new_status_valid"),
        ),
        sa.CheckConstraint(
            "prior_status IS NULL OR prior_status IN "
            "('pending_review', 'listed', 'rejected', 'unlisted')",
            name=op.f("ck_skill_transition_audit_prior_status_valid"),
        ),
        sa.CheckConstraint(
            "length(actor_id) > 0", name=op.f("ck_skill_transition_audit_actor_set")
        ),
        sa.CheckConstraint(
            "length(correlation_id) > 0",
            name=op.f("ck_skill_transition_audit_correlation_id_set"),
        ),
        sa.CheckConstraint(
            "length(idempotency_key) > 0",
            name=op.f("ck_skill_transition_audit_idempotency_key_set"),
        ),
        sa.CheckConstraint(
            "length(reason) > 0", name=op.f("ck_skill_transition_audit_reason_set")
        ),
        sa.CheckConstraint(
            "prior_status IS NULL OR prior_status <> new_status",
            name=op.f("ck_skill_transition_audit_status_changed"),
        ),
        sa.CheckConstraint(
            "transition_number >= 1",
            name=op.f("ck_skill_transition_audit_transition_number_positive"),
        ),
        sa.ForeignKeyConstraint(
            ["skill_version_id"],
            ["skill_versions.id"],
            name=op.f("fk_skill_transition_audit_skill_version_id_skill_versions"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_skill_transition_audit")),
        sa.UniqueConstraint("actor_id", "idempotency_key", name="actor_idempotency"),
        sa.UniqueConstraint(
            "skill_version_id",
            "transition_number",
            name="skill_transition_number",
        ),
    )
    op.create_index(
        "ix_skill_transition_audit_skill_time",
        "skill_transition_audit",
        ["skill_version_id", "occurred_at"],
        unique=False,
    )
    for statement in _SQLITE_SCHEMA_GUARDS:
        op.execute(statement)


def downgrade() -> None:
    """Revert this schema revision."""

    op.drop_index(
        "ix_skill_transition_audit_skill_time", table_name="skill_transition_audit"
    )
    op.drop_table("skill_transition_audit")
    op.drop_index("ix_skill_versions_status", table_name="skill_versions")
    op.drop_index("ix_skill_versions_author_id", table_name="skill_versions")
    op.drop_table("skill_versions")
    op.drop_index("ix_author_credentials_author_id", table_name="author_credentials")
    op.drop_table("author_credentials")
    op.drop_table("authors")
    op.drop_table("artifacts")
