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

_SKILL_INITIAL_STATUS_GUARD = """
CREATE TRIGGER skill_versions_validate_initial_status
BEFORE INSERT ON skill_versions
WHEN NEW.status NOT IN ('pending_review', 'listed')
     OR (NEW.declares_tier_cd AND NEW.status = 'listed')
     OR NOT EXISTS (
         SELECT 1
         FROM authors
         WHERE id = NEW.author_id
           AND status = 'active'
     )
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
"""
_LEGACY_SKILL_INITIAL_STATUS_GUARD = """
CREATE TRIGGER skill_versions_validate_initial_status
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
"""
_SQLITE_IDENTITY_GUARDS = (
    """
    CREATE TRIGGER authors_validate_initial_identity
    BEFORE INSERT ON authors
    WHEN NEW.status <> 'pending_registration'
         OR NEW.identity_revision <> 1
    BEGIN
        SELECT RAISE(ABORT, 'author must start in pending registration');
    END
    """,
    """
    CREATE TRIGGER authors_validate_status_transition
    BEFORE UPDATE OF status ON authors
    WHEN NEW.status <> OLD.status
         AND NOT (
             (OLD.status = 'pending_registration' AND NEW.status = 'active')
             OR (OLD.status = 'active' AND NEW.status = 'revoked')
         )
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
    WHEN NOT (
             OLD.status = 'pending_registration'
             AND NEW.status = 'active'
             AND NEW.public_key_b64 = OLD.public_key_b64
             AND NEW.identity_revision = OLD.identity_revision
         )
         AND NEW.identity_revision <> OLD.identity_revision + 1
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
    CREATE TRIGGER authors_require_identity_audit
    BEFORE UPDATE OF status, public_key_b64, identity_revision ON authors
    WHEN (
             NEW.status <> OLD.status
             OR NEW.public_key_b64 <> OLD.public_key_b64
             OR NEW.identity_revision <> OLD.identity_revision
         )
         AND NOT EXISTS (
             SELECT 1
             FROM author_identity_audit AS audit
             WHERE audit.author_id = OLD.id
               AND audit.transition_number = NEW.identity_revision
               AND (
                   (
                       audit.event_type = 'registered'
                       AND OLD.status = 'pending_registration'
                       AND NEW.status = 'active'
                       AND NEW.public_key_b64 = OLD.public_key_b64
                       AND NEW.identity_revision = 1
                       AND EXISTS (
                           SELECT 1
                           FROM author_keys
                           WHERE author_id = OLD.id
                             AND fingerprint = audit.new_key_fingerprint
                             AND public_key_b64 = NEW.public_key_b64
                             AND status = 'active'
                       )
                       AND EXISTS (
                           SELECT 1
                           FROM author_credentials
                           WHERE author_id = OLD.id
                             AND id = audit.new_credential_id
                             AND status = 'active'
                       )
                   )
                   OR (
                       audit.event_type = 'key_rotated'
                       AND OLD.status = 'active'
                       AND NEW.status = 'active'
                       AND NEW.identity_revision = OLD.identity_revision + 1
                       AND EXISTS (
                           SELECT 1
                           FROM author_keys
                           WHERE author_id = OLD.id
                             AND fingerprint = audit.prior_key_fingerprint
                             AND public_key_b64 = OLD.public_key_b64
                             AND status = 'revoked'
                       )
                       AND EXISTS (
                           SELECT 1
                           FROM author_keys
                           WHERE author_id = OLD.id
                             AND fingerprint = audit.new_key_fingerprint
                             AND public_key_b64 = NEW.public_key_b64
                             AND status = 'active'
                       )
                   )
                   OR (
                       audit.event_type = 'credential_rotated'
                       AND OLD.status = 'active'
                       AND NEW.status = 'active'
                       AND NEW.public_key_b64 = OLD.public_key_b64
                       AND NEW.identity_revision = OLD.identity_revision + 1
                       AND EXISTS (
                           SELECT 1
                           FROM author_credentials
                           WHERE author_id = OLD.id
                             AND id = audit.prior_credential_id
                             AND status = 'revoked'
                       )
                       AND EXISTS (
                           SELECT 1
                           FROM author_credentials
                           WHERE author_id = OLD.id
                             AND id = audit.new_credential_id
                             AND status = 'active'
                       )
                   )
                   OR (
                       audit.event_type = 'author_revoked'
                       AND OLD.status = 'active'
                       AND NEW.status = 'revoked'
                       AND NEW.public_key_b64 = OLD.public_key_b64
                       AND NEW.identity_revision = OLD.identity_revision + 1
                       AND NOT EXISTS (
                           SELECT 1
                           FROM author_keys
                           WHERE author_id = OLD.id
                             AND status = 'active'
                       )
                       AND NOT EXISTS (
                           SELECT 1
                           FROM author_credentials
                           WHERE author_id = OLD.id
                             AND status = 'active'
                       )
                   )
               )
         )
    BEGIN
        SELECT RAISE(ABORT, 'author identity change requires matching audit');
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
    CREATE TRIGGER authors_reject_delete
    BEFORE DELETE ON authors
    BEGIN
        SELECT RAISE(ABORT, 'author identity is append-only');
    END
    """,
    """
    CREATE TRIGGER author_keys_validate_initial_identity
    BEFORE INSERT ON author_keys
    WHEN NEW.status <> 'pending'
         OR NEW.revoked_at IS NOT NULL
    BEGIN
        SELECT RAISE(ABORT, 'author key must start pending');
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
             (OLD.status = 'pending'
              AND NEW.status = 'active'
              AND NEW.revoked_at IS NULL)
             OR (OLD.status = 'active'
                 AND NEW.status = 'revoked'
                 AND NEW.revoked_at IS NOT NULL)
         )
    BEGIN
        SELECT RAISE(ABORT, 'invalid author key status transition');
    END
    """,
    """
    CREATE TRIGGER author_keys_require_identity_audit
    BEFORE UPDATE OF status, revoked_at ON author_keys
    WHEN (
             NEW.status <> OLD.status
             OR NEW.revoked_at IS NOT OLD.revoked_at
         )
         AND NOT EXISTS (
             SELECT 1
             FROM author_identity_audit AS audit
             JOIN authors AS author ON author.id = OLD.author_id
             WHERE audit.author_id = OLD.author_id
               AND (
                   (
                       OLD.status = 'pending'
                       AND NEW.status = 'active'
                       AND audit.new_key_fingerprint = OLD.fingerprint
                       AND (
                           (audit.event_type = 'registered'
                            AND audit.transition_number = 1)
                           OR (audit.event_type = 'key_rotated'
                               AND audit.transition_number =
                                   author.identity_revision + 1)
                       )
                   )
                   OR (
                       OLD.status = 'active'
                       AND NEW.status = 'revoked'
                       AND audit.prior_key_fingerprint = OLD.fingerprint
                       AND audit.transition_number = author.identity_revision + 1
                       AND audit.event_type IN ('key_rotated', 'author_revoked')
                   )
               )
         )
    BEGIN
        SELECT RAISE(ABORT, 'author key change requires matching identity audit');
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
    CREATE TRIGGER author_credentials_validate_initial_identity
    BEFORE INSERT ON author_credentials
    WHEN NEW.status <> 'pending'
         OR NEW.revoked_at IS NOT NULL
    BEGIN
        SELECT RAISE(ABORT, 'author credential must start pending');
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
             OR (
                 OLD.status = 'pending'
                 AND NEW.status = 'active'
                 AND NEW.revoked_at IS NULL
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
    CREATE TRIGGER author_credentials_require_identity_audit
    BEFORE UPDATE OF status, revoked_at ON author_credentials
    WHEN (
             NEW.status <> OLD.status
             OR NEW.revoked_at IS NOT OLD.revoked_at
         )
         AND NOT EXISTS (
             SELECT 1
             FROM author_identity_audit AS audit
             JOIN authors AS author ON author.id = OLD.author_id
             WHERE audit.author_id = OLD.author_id
               AND (
                   (
                       OLD.status = 'pending'
                       AND NEW.status = 'active'
                       AND audit.new_credential_id = OLD.id
                       AND (
                           (audit.event_type = 'registered'
                            AND audit.transition_number = 1)
                           OR (audit.event_type = 'credential_rotated'
                               AND audit.transition_number =
                                   author.identity_revision + 1)
                       )
                   )
                   OR (
                       OLD.status = 'active'
                       AND NEW.status = 'revoked'
                       AND audit.prior_credential_id = OLD.id
                       AND audit.transition_number = author.identity_revision + 1
                       AND audit.event_type IN (
                           'credential_rotated',
                           'author_revoked'
                       )
                   )
               )
         )
    BEGIN
        SELECT RAISE(
            ABORT,
            'author credential change requires matching identity audit'
        );
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
    WHEN (
             NEW.event_type = 'registered'
             AND NOT EXISTS (
                 SELECT 1
                 FROM authors AS author
                 JOIN author_keys AS author_key
                   ON author_key.author_id = author.id
                 JOIN author_credentials AS credential
                   ON credential.author_id = author.id
                 WHERE author.id = NEW.author_id
                   AND author.status = 'pending_registration'
                   AND author.identity_revision = 1
                   AND NEW.transition_number = 1
                   AND author_key.fingerprint = NEW.new_key_fingerprint
                   AND author_key.public_key_b64 = author.public_key_b64
                   AND author_key.status = 'pending'
                   AND credential.id = NEW.new_credential_id
                   AND credential.status = 'pending'
             )
         )
         OR (
             NEW.event_type = 'key_rotated'
             AND NOT EXISTS (
                 SELECT 1
                 FROM authors AS author
                 JOIN author_keys AS prior_key
                   ON prior_key.author_id = author.id
                 JOIN author_keys AS new_key
                   ON new_key.author_id = author.id
                 WHERE author.id = NEW.author_id
                   AND author.status = 'active'
                   AND author.identity_revision + 1 = NEW.transition_number
                   AND prior_key.fingerprint = NEW.prior_key_fingerprint
                   AND prior_key.status = 'active'
                   AND new_key.fingerprint = NEW.new_key_fingerprint
                   AND new_key.status = 'pending'
                   AND new_key.public_key_b64 <> prior_key.public_key_b64
             )
         )
         OR (
             NEW.event_type = 'credential_rotated'
             AND NOT EXISTS (
                 SELECT 1
                 FROM authors AS author
                 JOIN author_credentials AS prior_credential
                   ON prior_credential.author_id = author.id
                 JOIN author_credentials AS new_credential
                   ON new_credential.author_id = author.id
                 WHERE author.id = NEW.author_id
                   AND author.status = 'active'
                   AND author.identity_revision + 1 = NEW.transition_number
                   AND prior_credential.id = NEW.prior_credential_id
                   AND prior_credential.status = 'active'
                   AND new_credential.id = NEW.new_credential_id
                   AND new_credential.status = 'pending'
                   AND new_credential.kind = prior_credential.kind
             )
         )
         OR (
             NEW.event_type = 'author_revoked'
             AND NOT EXISTS (
                 SELECT 1
                 FROM authors AS author
                 JOIN author_keys AS author_key
                   ON author_key.author_id = author.id
                 WHERE author.id = NEW.author_id
                   AND author.status = 'active'
                   AND author.identity_revision + 1 = NEW.transition_number
                   AND author_key.fingerprint = NEW.prior_key_fingerprint
                   AND author_key.status = 'active'
                   AND (
                       (
                           NEW.prior_credential_id IS NULL
                           AND NOT EXISTS (
                               SELECT 1
                               FROM author_credentials
                               WHERE author_id = author.id
                                 AND status = 'active'
                           )
                       )
                       OR EXISTS (
                           SELECT 1
                           FROM author_credentials
                           WHERE author_id = author.id
                             AND id = NEW.prior_credential_id
                             AND status = 'active'
                       )
                   )
             )
         )
         OR (
             NEW.new_key_fingerprint IS NOT NULL
             AND EXISTS (
                 SELECT 1
                 FROM author_keys
                 WHERE fingerprint = NEW.new_key_fingerprint
                   AND author_id <> NEW.author_id
             )
         )
         OR (
             NEW.new_credential_id IS NOT NULL
             AND EXISTS (
                 SELECT 1
                 FROM author_credentials
                 WHERE id = NEW.new_credential_id
                   AND author_id <> NEW.author_id
             )
         )
    BEGIN
        SELECT RAISE(ABORT, 'identity audit references invalid author state');
    END
    """,
    """
    CREATE TRIGGER author_identity_audit_apply_registration
    AFTER INSERT ON author_identity_audit
    WHEN NEW.event_type = 'registered'
    BEGIN
        UPDATE author_keys
        SET status = 'active'
        WHERE author_id = NEW.author_id
          AND fingerprint = NEW.new_key_fingerprint
          AND status = 'pending';
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'registration did not activate author key')
        END;

        UPDATE author_credentials
        SET status = 'active'
        WHERE author_id = NEW.author_id
          AND id = NEW.new_credential_id
          AND status = 'pending';
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'registration did not activate author credential')
        END;

        UPDATE authors
        SET status = 'active',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = NEW.author_id
          AND status = 'pending_registration'
          AND identity_revision = 1;
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'registration did not activate author')
        END;
    END
    """,
    """
    CREATE TRIGGER author_identity_audit_apply_key_rotation
    AFTER INSERT ON author_identity_audit
    WHEN NEW.event_type = 'key_rotated'
    BEGIN
        UPDATE author_keys
        SET status = 'revoked',
            revoked_at = NEW.occurred_at
        WHERE author_id = NEW.author_id
          AND fingerprint = NEW.prior_key_fingerprint
          AND status = 'active';
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'key rotation did not revoke prior key')
        END;

        UPDATE author_keys
        SET status = 'active'
        WHERE author_id = NEW.author_id
          AND fingerprint = NEW.new_key_fingerprint
          AND status = 'pending';
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'key rotation did not activate new key')
        END;

        UPDATE authors
        SET public_key_b64 = (
                SELECT public_key_b64
                FROM author_keys
                WHERE author_id = NEW.author_id
                  AND fingerprint = NEW.new_key_fingerprint
            ),
            identity_revision = NEW.transition_number,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = NEW.author_id
          AND status = 'active'
          AND identity_revision + 1 = NEW.transition_number;
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'key rotation did not advance author identity')
        END;
    END
    """,
    """
    CREATE TRIGGER author_identity_audit_apply_credential_rotation
    AFTER INSERT ON author_identity_audit
    WHEN NEW.event_type = 'credential_rotated'
    BEGIN
        UPDATE author_credentials
        SET status = 'revoked',
            revoked_at = NEW.occurred_at
        WHERE author_id = NEW.author_id
          AND id = NEW.prior_credential_id
          AND status = 'active';
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'credential rotation did not revoke prior credential')
        END;

        UPDATE author_credentials
        SET status = 'active'
        WHERE author_id = NEW.author_id
          AND id = NEW.new_credential_id
          AND status = 'pending';
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'credential rotation did not activate new credential')
        END;

        UPDATE authors
        SET identity_revision = NEW.transition_number,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = NEW.author_id
          AND status = 'active'
          AND identity_revision + 1 = NEW.transition_number;
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'credential rotation did not advance author identity')
        END;
    END
    """,
    """
    CREATE TRIGGER author_identity_audit_apply_revocation
    AFTER INSERT ON author_identity_audit
    WHEN NEW.event_type = 'author_revoked'
    BEGIN
        UPDATE author_keys
        SET status = 'revoked',
            revoked_at = NEW.occurred_at
        WHERE author_id = NEW.author_id
          AND fingerprint = NEW.prior_key_fingerprint
          AND status = 'active';
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'author revocation did not revoke active key')
        END;

        UPDATE author_credentials
        SET status = 'revoked',
            revoked_at = NEW.occurred_at
        WHERE author_id = NEW.author_id
          AND id = NEW.prior_credential_id
          AND status = 'active';
        SELECT CASE
            WHEN NEW.prior_credential_id IS NOT NULL AND changes() <> 1
            THEN RAISE(ABORT, 'author revocation did not revoke credential')
        END;

        UPDATE authors
        SET status = 'revoked',
            identity_revision = NEW.transition_number,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = NEW.author_id
          AND status = 'active'
          AND identity_revision + 1 = NEW.transition_number;
        SELECT CASE
            WHEN changes() <> 1
            THEN RAISE(ABORT, 'author revocation did not advance author identity')
        END;
    END
    """,
)
_SQLITE_IDENTITY_TRIGGER_NAMES = (
    "authors_validate_initial_identity",
    "authors_validate_status_transition",
    "authors_validate_identity_revision",
    "authors_require_identity_revision",
    "authors_validate_key_rotation",
    "authors_require_identity_audit",
    "authors_reject_identity_metadata_update",
    "authors_reject_delete",
    "author_keys_validate_initial_identity",
    "author_keys_reject_identity_update",
    "author_keys_reject_revoked_at_rewrite",
    "author_keys_validate_status_transition",
    "author_keys_require_identity_audit",
    "author_keys_reject_delete",
    "author_credentials_validate_initial_identity",
    "author_credentials_validate_status_transition",
    "author_credentials_reject_identity_update",
    "author_credentials_reject_revoked_at_rewrite",
    "author_credentials_require_identity_audit",
    "author_credentials_reject_delete",
    "author_identity_audit_reject_update",
    "author_identity_audit_reject_delete",
    "author_identity_audit_validate_timestamp",
    "author_identity_audit_validate_ownership",
    "author_identity_audit_apply_registration",
    "author_identity_audit_apply_key_rotation",
    "author_identity_audit_apply_credential_rotation",
    "author_identity_audit_apply_revocation",
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
        batch_op.drop_constraint(op.f("ck_authors_status_valid"), type_="check")
        batch_op.alter_column(
            "status",
            existing_type=sa.String(length=16),
            type_=sa.String(length=24),
            existing_nullable=False,
            server_default="pending_registration",
        )
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
        batch_op.create_check_constraint(
            op.f("ck_authors_status_valid"),
            "status IN ('pending_registration', 'active', 'revoked')",
        )

    with op.batch_alter_table("author_credentials") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_author_credentials_status_valid"),
            type_="check",
        )
        batch_op.alter_column(
            "status",
            existing_type=sa.String(length=16),
            existing_nullable=False,
            server_default="pending",
        )
        batch_op.create_check_constraint(
            op.f("ck_author_credentials_status_valid"),
            "status IN ('pending', 'active', 'revoked', 'expired')",
        )
        batch_op.create_check_constraint(
            "ck_author_credentials_revocation_state_valid",
            "(status = 'pending' AND revoked_at IS NULL) "
            "OR (status = 'active' AND revoked_at IS NULL) "
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
            "status", sa.String(length=16), server_default="pending", nullable=False
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND revoked_at IS NULL) "
            "OR (status = 'active' AND revoked_at IS NULL) "
            "OR (status = 'revoked' AND revoked_at IS NOT NULL)",
            name=op.f("ck_author_keys_revocation_state_valid"),
        ),
        sa.CheckConstraint(
            "fingerprint LIKE 'sha256:%' AND length(fingerprint) = 71",
            name=op.f("ck_author_keys_fingerprint_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'active', 'revoked')",
            name=op.f("ck_author_keys_status_valid"),
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
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["new_credential_id"],
            ["author_credentials.id"],
            name=op.f("fk_author_identity_audit_new_credential_id_author_credentials"),
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["new_key_fingerprint"],
            ["author_keys.fingerprint"],
            name=op.f("fk_author_identity_audit_new_key_fingerprint_author_keys"),
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["prior_credential_id"],
            ["author_credentials.id"],
            name=op.f(
                "fk_author_identity_audit_prior_credential_id_author_credentials"
            ),
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["prior_key_fingerprint"],
            ["author_keys.fingerprint"],
            name=op.f("fk_author_identity_audit_prior_key_fingerprint_author_keys"),
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
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
    op.execute("DROP TRIGGER skill_versions_validate_initial_status")
    op.execute(_SKILL_INITIAL_STATUS_GUARD)
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
    op.execute("DROP TRIGGER skill_versions_validate_initial_status")
    op.execute(_LEGACY_SKILL_INITIAL_STATUS_GUARD)
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
        batch_op.drop_constraint(
            op.f("ck_author_credentials_status_valid"),
            type_="check",
        )
        batch_op.alter_column(
            "status",
            existing_type=sa.String(length=16),
            existing_nullable=False,
            server_default="active",
        )
        batch_op.create_check_constraint(
            op.f("ck_author_credentials_status_valid"),
            "status IN ('active', 'revoked', 'expired')",
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
        batch_op.drop_constraint(op.f("ck_authors_status_valid"), type_="check")
        batch_op.drop_constraint(
            "ck_authors_identity_revision_positive",
            type_="check",
        )
        batch_op.drop_column("identity_revision")
        batch_op.alter_column(
            "status",
            existing_type=sa.String(length=24),
            type_=sa.String(length=16),
            existing_nullable=False,
            server_default="active",
        )
        batch_op.create_check_constraint(
            op.f("ck_authors_status_valid"),
            "status IN ('active', 'revoked')",
        )
