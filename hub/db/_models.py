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
    text,
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
    """
    CREATE TRIGGER IF NOT EXISTS authors_validate_initial_identity
    BEFORE INSERT ON authors
    WHEN NEW.status <> 'pending_registration'
         OR NEW.identity_revision <> 1
    BEGIN
        SELECT RAISE(ABORT, 'author must start in pending registration');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS authors_validate_status_transition
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
    CREATE TRIGGER IF NOT EXISTS authors_validate_identity_revision
    BEFORE UPDATE OF identity_revision ON authors
    WHEN NEW.identity_revision <> OLD.identity_revision + 1
    BEGIN
        SELECT RAISE(ABORT, 'invalid author identity revision');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS authors_require_identity_revision
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
    CREATE TRIGGER IF NOT EXISTS authors_validate_key_rotation
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
    CREATE TRIGGER IF NOT EXISTS authors_require_identity_audit
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
    CREATE TRIGGER IF NOT EXISTS authors_reject_identity_metadata_update
    BEFORE UPDATE OF external_subject, display_handle ON authors
    BEGIN
        SELECT RAISE(ABORT, 'author identity metadata is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS authors_reject_delete
    BEFORE DELETE ON authors
    BEGIN
        SELECT RAISE(ABORT, 'author identity is append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS author_keys_validate_initial_identity
    BEFORE INSERT ON author_keys
    WHEN NEW.status <> 'pending'
         OR NEW.revoked_at IS NOT NULL
    BEGIN
        SELECT RAISE(ABORT, 'author key must start pending');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS author_keys_reject_identity_update
    BEFORE UPDATE OF author_id, public_key_b64, fingerprint ON author_keys
    BEGIN
        SELECT RAISE(ABORT, 'author key identity is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS author_keys_reject_revoked_at_rewrite
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
    CREATE TRIGGER IF NOT EXISTS author_keys_validate_status_transition
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
    CREATE TRIGGER IF NOT EXISTS author_keys_require_identity_audit
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
    CREATE TRIGGER IF NOT EXISTS author_keys_reject_delete
    BEFORE DELETE ON author_keys
    BEGIN
        SELECT RAISE(ABORT, 'author key history is append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS author_credentials_validate_initial_identity
    BEFORE INSERT ON author_credentials
    WHEN NEW.status <> 'pending'
         OR NEW.revoked_at IS NOT NULL
    BEGIN
        SELECT RAISE(ABORT, 'author credential must start pending');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS author_credentials_validate_status_transition
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
    CREATE TRIGGER IF NOT EXISTS author_credentials_reject_identity_update
    BEFORE UPDATE OF author_id, kind, lookup_id, credential_hash, expires_at
    ON author_credentials
    BEGIN
        SELECT RAISE(ABORT, 'author credential identity is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS author_credentials_reject_revoked_at_rewrite
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
    CREATE TRIGGER IF NOT EXISTS author_credentials_require_identity_audit
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
    CREATE TRIGGER IF NOT EXISTS author_credentials_reject_delete
    BEFORE DELETE ON author_credentials
    BEGIN
        SELECT RAISE(ABORT, 'author credential history is append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS author_identity_audit_reject_update
    BEFORE UPDATE ON author_identity_audit
    BEGIN
        SELECT RAISE(ABORT, 'author identity audit is append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS author_identity_audit_reject_delete
    BEFORE DELETE ON author_identity_audit
    BEGIN
        SELECT RAISE(ABORT, 'author identity audit is append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS author_identity_audit_validate_timestamp
    BEFORE INSERT ON author_identity_audit
    WHEN NEW.occurred_at <> CURRENT_TIMESTAMP
    BEGIN
        SELECT RAISE(ABORT, 'identity audit timestamps are database-generated');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS author_identity_audit_validate_ownership
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
    CREATE TRIGGER IF NOT EXISTS author_identity_audit_apply_registration
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
    CREATE TRIGGER IF NOT EXISTS author_identity_audit_apply_key_rotation
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
    CREATE TRIGGER IF NOT EXISTS author_identity_audit_apply_credential_rotation
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
    CREATE TRIGGER IF NOT EXISTS author_identity_audit_apply_revocation
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
    """
    CREATE TRIGGER IF NOT EXISTS scan_events_reject_update
    BEFORE UPDATE ON scan_events
    BEGIN
        SELECT RAISE(ABORT, 'scan events are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS scan_events_reject_delete
    BEFORE DELETE ON scan_events
    BEGIN
        SELECT RAISE(ABORT, 'scan events are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS scan_jobs_validate_initial_state
    BEFORE INSERT ON scan_jobs
    WHEN NEW.state <> 'pending_submission'
         OR NEW.attempt_count <> 0
         OR NEW.provider_analysis_id IS NOT NULL
         OR NEW.lease_owner IS NOT NULL
         OR NEW.lease_expires_at IS NOT NULL
         OR NOT EXISTS (
             SELECT 1 FROM artifacts
             WHERE id = NEW.artifact_id
               AND author_artifact_digest = NEW.author_upload_digest
         )
    BEGIN
        SELECT RAISE(ABORT, 'invalid initial scan job state');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS scan_jobs_validate_state_transition
    BEFORE UPDATE OF state ON scan_jobs
    WHEN NEW.state <> OLD.state
         AND NOT (
             (OLD.state = 'pending_submission'
              AND NEW.state IN ('submitted', 'manual_review', 'exhausted'))
             OR (OLD.state IN ('submitted', 'polling')
                 AND NEW.state IN (
                     'polling', 'clean', 'malicious', 'manual_review', 'exhausted'
                 ))
         )
    BEGIN
        SELECT RAISE(ABORT, 'invalid scan job state transition');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS scan_jobs_reject_terminal_rewrite
    BEFORE UPDATE ON scan_jobs
    WHEN OLD.state IN ('clean', 'malicious', 'manual_review', 'exhausted')
    BEGIN
        SELECT RAISE(ABORT, 'terminal scan evidence is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS scan_jobs_reject_delete
    BEFORE DELETE ON scan_jobs
    BEGIN
        SELECT RAISE(ABORT, 'scan jobs and evidence are durable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS scan_jobs_validate_state_evidence
    BEFORE UPDATE ON scan_jobs
    WHEN (
            NEW.state IN ('submitted', 'polling')
            AND (
                NEW.provider_analysis_id IS NULL
                OR NEW.submitted_at IS NULL
                OR NEW.completed_at IS NOT NULL
            )
         )
         OR (
            NEW.state IN ('clean', 'malicious')
            AND (
                NEW.provider_analysis_id IS NULL
                OR NEW.completed_at IS NULL
                OR NEW.verdict <> NEW.state
                OR NEW.stats_json = '{}'
            )
         )
         OR (
            NEW.state IN ('manual_review', 'exhausted')
            AND (NEW.completed_at IS NULL OR NEW.verdict IS NULL)
         )
         OR (
            NEW.state NOT IN ('clean', 'malicious', 'manual_review', 'exhausted')
            AND NEW.completed_at IS NOT NULL
         )
         OR (
            OLD.provider_analysis_id IS NOT NULL
            AND NEW.provider_analysis_id IS NOT OLD.provider_analysis_id
         )
    BEGIN
        SELECT RAISE(ABORT, 'scan job state lacks matching bounded evidence');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_versions_require_scan_job
    BEFORE INSERT ON skill_versions
    WHEN NEW.requires_scan
         AND (
             NEW.status <> 'pending_review'
             OR NOT EXISTS (
                 SELECT 1 FROM scan_jobs
                 WHERE artifact_id = NEW.artifact_id
                   AND state = 'pending_submission'
             )
         )
    BEGIN
        SELECT RAISE(ABORT, 'scan-required publication needs a pending scan job');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_versions_reject_scan_requirement_update
    BEFORE UPDATE OF requires_scan ON skill_versions
    BEGIN
        SELECT RAISE(ABORT, 'skill scan requirement is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS skill_transition_audit_require_scan_evidence
    BEFORE INSERT ON skill_transition_audit
    WHEN NEW.new_status = 'listed'
         AND EXISTS (
             SELECT 1 FROM skill_versions
             WHERE id = NEW.skill_version_id AND requires_scan
         )
         AND NOT EXISTS (
             SELECT 1
             FROM skill_versions AS skill
             JOIN scan_jobs AS job ON job.artifact_id = skill.artifact_id
             WHERE skill.id = NEW.skill_version_id
               AND job.state IN ('clean', 'manual_review', 'exhausted')
         )
    BEGIN
        SELECT RAISE(ABORT, 'listing requires persisted scanner evidence');
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
        CheckConstraint(
            "status IN ('pending_registration', 'active', 'revoked')",
            name="status_valid",
        ),
        CheckConstraint("identity_revision >= 1", name="identity_revision_positive"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_record_id)
    external_subject: Mapped[str] = mapped_column(String(255), unique=True)
    display_handle: Mapped[str] = mapped_column(String(255), unique=True)
    public_key_b64: Mapped[str] = mapped_column(String(255), unique=True)
    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default="pending_registration",
        server_default="pending_registration",
    )
    identity_revision: Mapped[int] = mapped_column(
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
            "status IN ('pending', 'active', 'revoked', 'expired')",
            name="status_valid",
        ),
        CheckConstraint(
            "(status = 'pending' AND revoked_at IS NULL) "
            "OR (status = 'active' AND revoked_at IS NULL) "
            "OR (status = 'revoked' AND revoked_at IS NOT NULL) "
            "OR (status = 'expired' AND revoked_at IS NULL)",
            name="revocation_state_valid",
        ),
        Index("ix_author_credentials_author_id", "author_id"),
        Index(
            "uq_author_credentials_one_active_kind",
            "author_id",
            "kind",
            unique=True,
            sqlite_where=text("status = 'active'"),
        ),
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
        String(16), nullable=False, default="pending", server_default="pending"
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )


class AuthorKeyModel(Base):
    """Immutable Ed25519 author-key identity with revocation history."""

    __tablename__ = "author_keys"
    __table_args__ = (
        CheckConstraint("length(public_key_b64) > 0", name="public_key_set"),
        CheckConstraint(
            "fingerprint LIKE 'sha256:%' AND length(fingerprint) = 71",
            name="fingerprint_valid",
        ),
        CheckConstraint(
            "status IN ('pending', 'active', 'revoked')", name="status_valid"
        ),
        CheckConstraint(
            "(status = 'pending' AND revoked_at IS NULL) "
            "OR (status = 'active' AND revoked_at IS NULL) "
            "OR (status = 'revoked' AND revoked_at IS NOT NULL)",
            name="revocation_state_valid",
        ),
        Index("ix_author_keys_author_id", "author_id"),
        Index(
            "uq_author_keys_one_active_per_author",
            "author_id",
            unique=True,
            sqlite_where=text("status = 'active'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_record_id)
    author_id: Mapped[str] = mapped_column(
        ForeignKey("authors.id", ondelete="RESTRICT"), nullable=False
    )
    public_key_b64: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True
    )
    fingerprint: Mapped[str] = mapped_column(String(71), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )


class AuthorIdentityAuditModel(Base):
    """Append-only author registration, rotation, and revocation history."""

    __tablename__ = "author_identity_audit"
    __table_args__ = (
        UniqueConstraint("actor_id", "idempotency_key", name="actor_idempotency"),
        UniqueConstraint(
            "author_id",
            "transition_number",
            name="author_transition_number",
        ),
        CheckConstraint(
            "event_type IN "
            "('registered', 'key_rotated', 'credential_rotated', 'author_revoked')",
            name="event_type_valid",
        ),
        CheckConstraint("transition_number >= 1", name="transition_number_positive"),
        CheckConstraint("length(actor_id) > 0", name="actor_set"),
        CheckConstraint("length(reason) > 0", name="reason_set"),
        CheckConstraint("length(correlation_id) > 0", name="correlation_id_set"),
        CheckConstraint("length(idempotency_key) > 0", name="idempotency_key_set"),
        CheckConstraint(
            "prior_key_fingerprint IS NULL "
            "OR (prior_key_fingerprint LIKE 'sha256:%' "
            "AND length(prior_key_fingerprint) = 71)",
            name="prior_key_fingerprint_valid",
        ),
        CheckConstraint(
            "new_key_fingerprint IS NULL "
            "OR (new_key_fingerprint LIKE 'sha256:%' "
            "AND length(new_key_fingerprint) = 71)",
            name="new_key_fingerprint_valid",
        ),
        CheckConstraint(
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
            name="event_metadata_valid",
        ),
        Index(
            "ix_author_identity_audit_author_time",
            "author_id",
            "occurred_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_record_id)
    author_id: Mapped[str] = mapped_column(
        ForeignKey(
            "authors.id",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        nullable=False,
    )
    transition_number: Mapped[int] = mapped_column(Integer, nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(1024), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    correlation_id: Mapped[str] = mapped_column(String(255), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    prior_key_fingerprint: Mapped[str | None] = mapped_column(
        String(71),
        ForeignKey(
            "author_keys.fingerprint",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
    )
    new_key_fingerprint: Mapped[str | None] = mapped_column(
        String(71),
        ForeignKey(
            "author_keys.fingerprint",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
    )
    prior_credential_id: Mapped[str | None] = mapped_column(
        ForeignKey(
            "author_credentials.id",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        )
    )
    new_credential_id: Mapped[str | None] = mapped_column(
        ForeignKey(
            "author_credentials.id",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        )
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
        CheckConstraint(
            "scanner_verdict IN ('clean', 'suspicious', 'unavailable')",
            name="scanner_verdict_valid",
        ),
        CheckConstraint(
            "length(scanner_detail) <= 1024", name="scanner_detail_bounded"
        ),
        CheckConstraint(
            "author_artifact_digest LIKE 'sha256:%' "
            "AND length(author_artifact_digest) = 71",
            name="author_artifact_digest_valid",
        ),
        CheckConstraint(
            "length(author_artifact_signature) > 0",
            name="author_artifact_signature_set",
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
    scanner_verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    scanner_detail: Mapped[str] = mapped_column(
        String(1024), nullable=False, default="", server_default=""
    )
    author_artifact_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    author_artifact_signature: Mapped[str] = mapped_column(String(512), nullable=False)
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
    requires_scan: Mapped[bool] = mapped_column(
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


class ScanJobModel(Base):
    """Mutable durable scanner work item; changes are recorded in scan_events."""

    __tablename__ = "scan_jobs"
    __table_args__ = (
        UniqueConstraint("artifact_id", name="one_scan_job_per_artifact"),
        CheckConstraint(
            "state IN ('pending_submission', 'submitted', 'polling', 'clean', "
            "'malicious', 'manual_review', 'exhausted')",
            name="state_valid",
        ),
        CheckConstraint("attempt_count >= 0", name="attempt_count_nonnegative"),
        CheckConstraint("length(provider) > 0", name="provider_set"),
        CheckConstraint(
            "provider_analysis_id IS NULL OR length(provider_analysis_id) <= 512",
            name="provider_analysis_id_bounded",
        ),
        CheckConstraint("length(detail) <= 1024", name="detail_bounded"),
        CheckConstraint("length(stats_json) <= 4096", name="stats_json_bounded"),
        CheckConstraint("json_valid(stats_json)", name="stats_json_valid"),
        CheckConstraint("length(correlation_id) > 0", name="correlation_id_set"),
        CheckConstraint("length(idempotency_key) > 0", name="idempotency_key_set"),
        CheckConstraint(
            "author_upload_digest LIKE 'sha256:%' "
            "AND length(author_upload_digest) = 71",
            name="author_upload_digest_valid",
        ),
        CheckConstraint("length(author_upload_storage_key) > 0", name="upload_key_set"),
        Index("ix_scan_jobs_due", "state", "next_attempt_at"),
        Index("ix_scan_jobs_lease", "lease_expires_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_record_id)
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_analysis_id: Mapped[str | None] = mapped_column(String(512))
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    lease_owner: Mapped[str | None] = mapped_column(String(255))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verdict: Mapped[str | None] = mapped_column(String(32))
    detail: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    stats_json: Mapped[str] = mapped_column(String(4096), nullable=False, default="{}")
    correlation_id: Mapped[str] = mapped_column(String(255), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    author_upload_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    author_upload_storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )


class ScanEventModel(Base):
    """Append-only scanner state and evidence history."""

    __tablename__ = "scan_events"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending_submission', 'submitted', 'polling', 'clean', "
            "'malicious', 'manual_review', 'exhausted')",
            name="state_valid",
        ),
        CheckConstraint("attempt_count >= 0", name="attempt_count_nonnegative"),
        CheckConstraint("length(detail) <= 1024", name="detail_bounded"),
        CheckConstraint("length(stats_json) <= 4096", name="stats_json_bounded"),
        CheckConstraint("json_valid(stats_json)", name="stats_json_valid"),
        Index("ix_scan_events_job_time", "scan_job_id", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_record_id)
    scan_job_id: Mapped[str] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="RESTRICT"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False)
    verdict: Mapped[str | None] = mapped_column(String(32))
    detail: Mapped[str] = mapped_column(String(1024), nullable=False)
    stats_json: Mapped[str] = mapped_column(String(4096), nullable=False)
    worker_id: Mapped[str | None] = mapped_column(String(255))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.current_timestamp()
    )


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
    if target.requires_scan and target.status == SkillStatus.LISTED.value:
        raise InvalidStateTransitionError(
            "scan-required skills cannot be created in the listed state"
        )


def _reject_client_audit_timestamp(
    _mapper: Mapper[Any],
    _connection: Connection,
    target: SkillTransitionAuditModel,
) -> None:
    if target.occurred_at is not None:
        raise ImmutableRecordError("audit timestamps are database-generated")


def _reject_author_update(
    _mapper: Mapper[Any], _connection: Connection, _target: AuthorModel
) -> None:
    raise InvalidStateTransitionError(
        "author identity transitions must use AuthorIdentityRepository"
    )


def _validate_identity_record_update(
    _mapper: Mapper[Any], _connection: Connection, _target: object
) -> None:
    raise InvalidStateTransitionError(
        "author key and credential transitions must use AuthorIdentityRepository"
    )


def _reject_scan_job_update(
    _mapper: Mapper[Any], _connection: Connection, _target: ScanJobModel
) -> None:
    raise InvalidStateTransitionError("scan job transitions must use ScanRepository")


def _reject_client_identity_audit_timestamp(
    _mapper: Mapper[Any],
    _connection: Connection,
    target: AuthorIdentityAuditModel,
) -> None:
    if target.occurred_at is not None:
        raise ImmutableRecordError("identity audit timestamps are database-generated")


event.listen(ArtifactModel, "before_update", _reject_immutable_change)
event.listen(ArtifactModel, "before_delete", _reject_immutable_change)
event.listen(AuthorIdentityAuditModel, "before_update", _reject_immutable_change)
event.listen(AuthorIdentityAuditModel, "before_delete", _reject_immutable_change)
event.listen(
    AuthorIdentityAuditModel,
    "before_insert",
    _reject_client_identity_audit_timestamp,
)
event.listen(AuthorModel, "before_update", _reject_author_update)
event.listen(AuthorKeyModel, "before_update", _validate_identity_record_update)
event.listen(AuthorCredentialModel, "before_update", _validate_identity_record_update)
event.listen(SkillTransitionAuditModel, "before_update", _reject_immutable_change)
event.listen(SkillTransitionAuditModel, "before_delete", _reject_immutable_change)
event.listen(
    SkillTransitionAuditModel,
    "before_insert",
    _reject_client_audit_timestamp,
)
event.listen(SkillVersionModel, "before_insert", _validate_initial_skill)
event.listen(SkillVersionModel, "before_update", _reject_skill_update)
event.listen(ScanJobModel, "before_update", _reject_scan_job_update)
event.listen(ScanEventModel, "before_update", _reject_immutable_change)
event.listen(ScanEventModel, "before_delete", _reject_immutable_change)
event.listen(Base.metadata, "after_create", _install_sqlite_schema_guards)
