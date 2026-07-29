# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""add author identity lifecycle

Revision ID: 1e9630e268d4
Revises: baa9ab020328
Create Date: 2026-07-29 19:24:41.647953
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "1e9630e268d4"
down_revision: str | None = "baa9ab020328"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQLITE_IDENTITY_GUARDS = (
    """
    CREATE TRIGGER authors_validate_status_transition
    BEFORE UPDATE OF status ON authors
    WHEN NEW.status <> OLD.status
         AND NOT (OLD.status = 'active' AND NEW.status = 'revoked')
    BEGIN
        SELECT RAISE(ABORT, 'invalid author status transition');
    END
    """,
    """
    CREATE TRIGGER authors_validate_identity_revision
    BEFORE UPDATE OF identity_revision ON authors
    WHEN NEW.identity_revision <> OLD.identity_revision + 1
    BEGIN
        SELECT RAISE(ABORT, 'invalid author identity revision');
    END
    """,
    """
    CREATE TRIGGER authors_require_identity_revision
    BEFORE UPDATE OF status, public_key_b64 ON authors
    WHEN NEW.identity_revision <> OLD.identity_revision + 1
    BEGIN
        SELECT RAISE(ABORT, 'author identity revision was not advanced');
    END
    """,
    """
    CREATE TRIGGER authors_validate_key_rotation
    BEFORE UPDATE OF public_key_b64 ON authors
    WHEN NOT EXISTS (
             SELECT 1
             FROM author_keys
             WHERE author_id = OLD.id
               AND public_key_b64 = NEW.public_key_b64
               AND status = 'active'
         )
         OR NOT EXISTS (
             SELECT 1
             FROM author_keys
             WHERE author_id = OLD.id
               AND public_key_b64 = OLD.public_key_b64
               AND status = 'revoked'
         )
    BEGIN
        SELECT RAISE(ABORT, 'author key rotation history is incomplete');
    END
    """,
    """
    CREATE TRIGGER authors_reject_identity_metadata_update
    BEFORE UPDATE OF external_subject, display_handle ON authors
    BEGIN
        SELECT RAISE(ABORT, 'author identity metadata is immutable');
    END
    """,
    """
    CREATE TRIGGER author_keys_reject_identity_update
    BEFORE UPDATE OF author_id, public_key_b64, fingerprint ON author_keys
    BEGIN
        SELECT RAISE(ABORT, 'author key identity is immutable');
    END
    """,
    """
    CREATE TRIGGER author_keys_reject_revoked_at_rewrite
    BEFORE UPDATE OF revoked_at ON author_keys
    WHEN NOT (
        OLD.status = 'active'
        AND NEW.status = 'revoked'
        AND OLD.revoked_at IS NULL
        AND NEW.revoked_at IS NOT NULL
    )
    BEGIN
        SELECT RAISE(ABORT, 'author key revocation timestamp is immutable');
    END
    """,
    """
    CREATE TRIGGER author_keys_validate_status_transition
    BEFORE UPDATE OF status ON author_keys
    WHEN NEW.status <> OLD.status
         AND NOT (
             OLD.status = 'active'
             AND NEW.status = 'revoked'
             AND NEW.revoked_at IS NOT NULL
         )
    BEGIN
        SELECT RAISE(ABORT, 'invalid author key status transition');
    END
    """,
    """
    CREATE TRIGGER author_keys_reject_delete
    BEFORE DELETE ON author_keys
    BEGIN
        SELECT RAISE(ABORT, 'author key history is append-only');
    END
    """,
    """
    CREATE TRIGGER author_credentials_validate_status_transition
    BEFORE UPDATE OF status ON author_credentials
    WHEN NEW.status <> OLD.status
         AND NOT (
             OLD.status = 'active'
             AND (
                 (NEW.status = 'revoked' AND NEW.revoked_at IS NOT NULL)
                 OR NEW.status = 'expired'
             )
         )
    BEGIN
        SELECT RAISE(ABORT, 'invalid author credential status transition');
    END
    """,
    """
    CREATE TRIGGER author_credentials_reject_identity_update
    BEFORE UPDATE OF author_id, kind, lookup_id, credential_hash, expires_at
    ON author_credentials
    BEGIN
        SELECT RAISE(ABORT, 'author credential identity is immutable');
    END
    """,
    """
    CREATE TRIGGER author_credentials_reject_revoked_at_rewrite
    BEFORE UPDATE OF revoked_at ON author_credentials
    WHEN NOT (
        OLD.status = 'active'
        AND NEW.status = 'revoked'
        AND OLD.revoked_at IS NULL
        AND NEW.revoked_at IS NOT NULL
    )
    BEGIN
        SELECT RAISE(ABORT, 'author credential revocation timestamp is immutable');
    END
    """,
    """
    CREATE TRIGGER author_credentials_reject_delete
    BEFORE DELETE ON author_credentials
    BEGIN
        SELECT RAISE(ABORT, 'author credential history is append-only');
    END
    """,
    """
    CREATE TRIGGER author_identity_audit_reject_update
    BEFORE UPDATE ON author_identity_audit
    BEGIN
        SELECT RAISE(ABORT, 'author identity audit is append-only');
    END
    """,
    """
    CREATE TRIGGER author_identity_audit_reject_delete
    BEFORE DELETE ON author_identity_audit
    BEGIN
        SELECT RAISE(ABORT, 'author identity audit is append-only');
    END
    """,
    """
    CREATE TRIGGER author_identity_audit_validate_timestamp
    BEFORE INSERT ON author_identity_audit
    WHEN NEW.occurred_at <> CURRENT_TIMESTAMP
    BEGIN
        SELECT RAISE(ABORT, 'identity audit timestamps are database-generated');
    END
    """,
    """
    CREATE TRIGGER author_identity_audit_validate_ownership
    BEFORE INSERT ON author_identity_audit
    WHEN NEW.transition_number <> (
             SELECT identity_revision
             FROM authors
             WHERE id = NEW.author_id
         )
         OR (
             NEW.prior_key_fingerprint IS NOT NULL
             AND NOT EXISTS (
                 SELECT 1
                 FROM author_keys
                 WHERE author_id = NEW.author_id
                   AND fingerprint = NEW.prior_key_fingerprint
             )
         )
         OR (
             NEW.new_key_fingerprint IS NOT NULL
             AND NOT EXISTS (
                 SELECT 1
                 FROM author_keys
                 WHERE author_id = NEW.author_id
                   AND fingerprint = NEW.new_key_fingerprint
             )
         )
         OR (
             NEW.prior_credential_id IS NOT NULL
             AND NOT EXISTS (
                 SELECT 1
                 FROM author_credentials
                 WHERE author_id = NEW.author_id
                   AND id = NEW.prior_credential_id
             )
         )
         OR (
             NEW.new_credential_id IS NOT NULL
             AND NOT EXISTS (
                 SELECT 1
                 FROM author_credentials
                 WHERE author_id = NEW.author_id
                   AND id = NEW.new_credential_id
             )
         )
    BEGIN
        SELECT RAISE(ABORT, 'identity audit references invalid author state');
    END
    """,
)
_SQLITE_IDENTITY_TRIGGER_NAMES = (
    "authors_validate_status_transition",
    "authors_validate_identity_revision",
    "authors_require_identity_revision",
    "authors_validate_key_rotation",
    "authors_reject_identity_metadata_update",
    "author_keys_reject_identity_update",
    "author_keys_reject_revoked_at_rewrite",
    "author_keys_validate_status_transition",
    "author_keys_reject_delete",
    "author_credentials_validate_status_transition",
    "author_credentials_reject_identity_update",
    "author_credentials_reject_revoked_at_rewrite",
    "author_credentials_reject_delete",
    "author_identity_audit_reject_update",
    "author_identity_audit_reject_delete",
    "author_identity_audit_validate_timestamp",
    "author_identity_audit_validate_ownership",
)


def upgrade() -> None:
    """Apply this schema revision."""

    legacy_author_count = (
        op.get_bind().execute(sa.text("SELECT count(*) FROM authors")).scalar_one()
    )
    if legacy_author_count:
        raise RuntimeError(
            "HUB-006 cannot promote legacy authors that lack authenticated "
            "registration and identity audit; migrate or remove those records "
            "before retrying"
        )

    with op.batch_alter_table("authors") as batch_op:
        batch_op.add_column(
            sa.Column(
                "identity_revision",
                sa.Integer(),
                server_default="1",
                nullable=False,
            )
        )
        batch_op.create_check_constraint(
            "ck_authors_identity_revision_positive",
            "identity_revision >= 1",
        )

    with op.batch_alter_table("author_credentials") as batch_op:
        batch_op.create_check_constraint(
            "ck_author_credentials_revocation_state_valid",
            "(status = 'active' AND revoked_at IS NULL) "
            "OR (status = 'revoked' AND revoked_at IS NOT NULL) "
            "OR (status = 'expired' AND revoked_at IS NULL)",
        )

    op.create_table(
        "author_keys",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("author_id", sa.String(length=32), nullable=False),
        sa.Column("public_key_b64", sa.String(length=255), nullable=False),
        sa.Column("fingerprint", sa.String(length=71), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="active", nullable=False
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(status = 'active' AND revoked_at IS NULL) "
            "OR (status = 'revoked' AND revoked_at IS NOT NULL)",
            name=op.f("ck_author_keys_revocation_state_valid"),
        ),
        sa.CheckConstraint(
            "fingerprint LIKE 'sha256:%' AND length(fingerprint) = 71",
            name=op.f("ck_author_keys_fingerprint_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name=op.f("ck_author_keys_status_valid")
        ),
        sa.CheckConstraint(
            "length(public_key_b64) > 0", name=op.f("ck_author_keys_public_key_set")
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["authors.id"],
            name=op.f("fk_author_keys_author_id_authors"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_author_keys")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_author_keys_fingerprint")),
        sa.UniqueConstraint(
            "public_key_b64", name=op.f("uq_author_keys_public_key_b64")
        ),
    )
    op.create_index(
        "ix_author_keys_author_id", "author_keys", ["author_id"], unique=False
    )
    op.create_index(
        "uq_author_keys_one_active_per_author",
        "author_keys",
        ["author_id"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
    )
    op.create_table(
        "author_identity_audit",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("author_id", sa.String(length=32), nullable=False),
        sa.Column("transition_number", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=1024), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("correlation_id", sa.String(length=255), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("prior_key_fingerprint", sa.String(length=71), nullable=True),
        sa.Column("new_key_fingerprint", sa.String(length=71), nullable=True),
        sa.Column("prior_credential_id", sa.String(length=32), nullable=True),
        sa.Column("new_credential_id", sa.String(length=32), nullable=True),
        sa.CheckConstraint(
            "(event_type = 'registered' "
            "AND prior_key_fingerprint IS NULL "
            "AND new_key_fingerprint IS NOT NULL "
            "AND prior_credential_id IS NULL "
            "AND new_credential_id IS NOT NULL) "
            "OR (event_type = 'key_rotated' "
            "AND prior_key_fingerprint IS NOT NULL "
            "AND new_key_fingerprint IS NOT NULL "
            "AND prior_key_fingerprint <> new_key_fingerprint "
            "AND prior_credential_id IS NULL "
            "AND new_credential_id IS NULL) "
            "OR (event_type = 'credential_rotated' "
            "AND prior_key_fingerprint IS NULL "
            "AND new_key_fingerprint IS NULL "
            "AND prior_credential_id IS NOT NULL "
            "AND new_credential_id IS NOT NULL "
            "AND prior_credential_id <> new_credential_id) "
            "OR (event_type = 'author_revoked' "
            "AND prior_key_fingerprint IS NOT NULL "
            "AND new_key_fingerprint IS NULL "
            "AND new_credential_id IS NULL)",
            name=op.f("ck_author_identity_audit_event_metadata_valid"),
        ),
        sa.CheckConstraint(
            "event_type IN "
            "('registered', 'key_rotated', 'credential_rotated', 'author_revoked')",
            name=op.f("ck_author_identity_audit_event_type_valid"),
        ),
        sa.CheckConstraint(
            "new_key_fingerprint IS NULL "
            "OR (new_key_fingerprint LIKE 'sha256:%' "
            "AND length(new_key_fingerprint) = 71)",
            name=op.f("ck_author_identity_audit_new_key_fingerprint_valid"),
        ),
        sa.CheckConstraint(
            "prior_key_fingerprint IS NULL "
            "OR (prior_key_fingerprint LIKE 'sha256:%' "
            "AND length(prior_key_fingerprint) = 71)",
            name=op.f("ck_author_identity_audit_prior_key_fingerprint_valid"),
        ),
        sa.CheckConstraint(
            "length(actor_id) > 0", name=op.f("ck_author_identity_audit_actor_set")
        ),
        sa.CheckConstraint(
            "length(correlation_id) > 0",
            name=op.f("ck_author_identity_audit_correlation_id_set"),
        ),
        sa.CheckConstraint(
            "length(idempotency_key) > 0",
            name=op.f("ck_author_identity_audit_idempotency_key_set"),
        ),
        sa.CheckConstraint(
            "length(reason) > 0", name=op.f("ck_author_identity_audit_reason_set")
        ),
        sa.CheckConstraint(
            "transition_number >= 1",
            name=op.f("ck_author_identity_audit_transition_number_positive"),
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["authors.id"],
            name=op.f("fk_author_identity_audit_author_id_authors"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["new_credential_id"],
            ["author_credentials.id"],
            name=op.f("fk_author_identity_audit_new_credential_id_author_credentials"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["prior_credential_id"],
            ["author_credentials.id"],
            name=op.f(
                "fk_author_identity_audit_prior_credential_id_author_credentials"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_author_identity_audit")),
        sa.UniqueConstraint("actor_id", "idempotency_key", name="actor_idempotency"),
        sa.UniqueConstraint(
            "author_id", "transition_number", name="author_transition_number"
        ),
    )
    op.create_index(
        "ix_author_identity_audit_author_time",
        "author_identity_audit",
        ["author_id", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "uq_author_credentials_one_active_kind",
        "author_credentials",
        ["author_id", "kind"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
    )
    for statement in _SQLITE_IDENTITY_GUARDS:
        op.execute(statement)


def downgrade() -> None:
    """Revert this schema revision."""

    identity_record_count = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT "
                "(SELECT count(*) FROM author_keys) + "
                "(SELECT count(*) FROM author_identity_audit)"
            )
        )
        .scalar_one()
    )
    if identity_record_count:
        raise RuntimeError(
            "HUB-006 cannot downgrade while author key or identity audit "
            "history exists; preserve or migrate those records first"
        )

    for trigger_name in reversed(_SQLITE_IDENTITY_TRIGGER_NAMES):
        op.execute(f"DROP TRIGGER IF EXISTS {trigger_name}")
    op.drop_index(
        "uq_author_credentials_one_active_kind",
        table_name="author_credentials",
        sqlite_where=sa.text("status = 'active'"),
    )
    with op.batch_alter_table("author_credentials") as batch_op:
        batch_op.drop_constraint(
            "ck_author_credentials_revocation_state_valid",
            type_="check",
        )
    op.drop_index(
        "ix_author_identity_audit_author_time", table_name="author_identity_audit"
    )
    op.drop_table("author_identity_audit")
    op.drop_index(
        "uq_author_keys_one_active_per_author",
        table_name="author_keys",
        sqlite_where=sa.text("status = 'active'"),
    )
    op.drop_index("ix_author_keys_author_id", table_name="author_keys")
    op.drop_table("author_keys")
    with op.batch_alter_table("authors") as batch_op:
        batch_op.drop_constraint(
            "ck_authors_identity_revision_positive",
            type_="check",
        )
        batch_op.drop_column("identity_revision")
