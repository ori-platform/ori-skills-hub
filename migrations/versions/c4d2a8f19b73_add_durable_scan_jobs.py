# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""add durable asynchronous scan jobs

Revision ID: c4d2a8f19b73
Revises: 7a2b9c4d1e05
Create Date: 2026-08-02 19:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4d2a8f19b73"
down_revision: str | None = "7a2b9c4d1e05"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_GUARDS = (
    """
    CREATE TRIGGER scan_events_reject_update
    BEFORE UPDATE ON scan_events
    BEGIN SELECT RAISE(ABORT, 'scan events are append-only'); END
    """,
    """
    CREATE TRIGGER scan_events_reject_delete
    BEFORE DELETE ON scan_events
    BEGIN SELECT RAISE(ABORT, 'scan events are append-only'); END
    """,
    """
    CREATE TRIGGER scan_jobs_validate_initial_state
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
    BEGIN SELECT RAISE(ABORT, 'invalid initial scan job state'); END
    """,
    """
    CREATE TRIGGER scan_jobs_validate_state_transition
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
    BEGIN SELECT RAISE(ABORT, 'invalid scan job state transition'); END
    """,
    """
    CREATE TRIGGER scan_jobs_reject_terminal_rewrite
    BEFORE UPDATE ON scan_jobs
    WHEN OLD.state IN ('clean', 'malicious', 'manual_review', 'exhausted')
    BEGIN SELECT RAISE(ABORT, 'terminal scan evidence is immutable'); END
    """,
    """
    CREATE TRIGGER scan_jobs_reject_delete
    BEFORE DELETE ON scan_jobs
    BEGIN SELECT RAISE(ABORT, 'scan jobs and evidence are durable'); END
    """,
    """
    CREATE TRIGGER scan_jobs_validate_state_evidence
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
    CREATE TRIGGER skill_versions_require_scan_job
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
    CREATE TRIGGER skill_versions_reject_scan_requirement_update
    BEFORE UPDATE OF requires_scan ON skill_versions
    BEGIN SELECT RAISE(ABORT, 'skill scan requirement is immutable'); END
    """,
    """
    CREATE TRIGGER skill_transition_audit_require_scan_evidence
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


def upgrade() -> None:
    op.add_column(
        "skill_versions",
        sa.Column(
            "requires_scan",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column(
            "artifact_id",
            sa.String(length=32),
            sa.ForeignKey("artifacts.id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("provider_analysis_id", sa.String(length=512)),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column("lease_owner", sa.String(length=255)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("submitted_at", sa.DateTime(timezone=True)),
        sa.Column("last_polled_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("verdict", sa.String(length=32)),
        sa.Column("detail", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column(
            "stats_json", sa.String(length=4096), nullable=False, server_default="{}"
        ),
        sa.Column("correlation_id", sa.String(length=255), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("author_upload_digest", sa.String(length=71), nullable=False),
        sa.Column("author_upload_storage_key", sa.String(length=1024), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.CheckConstraint(
            "state IN ('pending_submission', 'submitted', 'polling', 'clean', "
            "'malicious', 'manual_review', 'exhausted')",
            name="state_valid",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="attempt_count_nonnegative"),
        sa.CheckConstraint("length(provider) > 0", name="provider_set"),
        sa.CheckConstraint("length(detail) <= 1024", name="detail_bounded"),
        sa.CheckConstraint("length(stats_json) <= 4096", name="stats_json_bounded"),
        sa.CheckConstraint("json_valid(stats_json)", name="stats_json_valid"),
        sa.CheckConstraint("length(correlation_id) > 0", name="correlation_id_set"),
        sa.CheckConstraint("length(idempotency_key) > 0", name="idempotency_key_set"),
        sa.CheckConstraint(
            "author_upload_digest LIKE 'sha256:%' "
            "AND length(author_upload_digest) = 71",
            name="author_upload_digest_valid",
        ),
    )
    op.create_index("ix_scan_jobs_due", "scan_jobs", ["state", "next_attempt_at"])
    op.create_index("ix_scan_jobs_lease", "scan_jobs", ["lease_expires_at"])
    op.create_table(
        "scan_events",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column(
            "scan_job_id",
            sa.String(length=32),
            sa.ForeignKey("scan_jobs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("verdict", sa.String(length=32)),
        sa.Column("detail", sa.String(length=1024), nullable=False),
        sa.Column("stats_json", sa.String(length=4096), nullable=False),
        sa.Column("worker_id", sa.String(length=255)),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.CheckConstraint("attempt_count >= 0", name="attempt_count_nonnegative"),
        sa.CheckConstraint(
            "state IN ('pending_submission', 'submitted', 'polling', 'clean', "
            "'malicious', 'manual_review', 'exhausted')",
            name="state_valid",
        ),
        sa.CheckConstraint("length(detail) <= 1024", name="detail_bounded"),
        sa.CheckConstraint("length(stats_json) <= 4096", name="stats_json_bounded"),
        sa.CheckConstraint("json_valid(stats_json)", name="stats_json_valid"),
    )
    op.create_index(
        "ix_scan_events_job_time", "scan_events", ["scan_job_id", "occurred_at"]
    )
    for statement in _GUARDS:
        op.execute(sa.text(statement))


def downgrade() -> None:
    count = (
        op.get_bind().execute(sa.text("SELECT count(*) FROM scan_jobs")).scalar_one()
    )
    if count:
        raise RuntimeError(
            "HUB-013 cannot downgrade while durable scan evidence exists"
        )
    for name in (
        "skill_transition_audit_require_scan_evidence",
        "skill_versions_reject_scan_requirement_update",
        "skill_versions_require_scan_job",
        "scan_jobs_reject_delete",
        "scan_jobs_reject_terminal_rewrite",
        "scan_jobs_validate_state_transition",
        "scan_jobs_validate_state_evidence",
        "scan_jobs_validate_initial_state",
        "scan_events_reject_delete",
        "scan_events_reject_update",
    ):
        op.execute(sa.text(f"DROP TRIGGER IF EXISTS {name}"))
    op.drop_table("scan_events")
    op.drop_table("scan_jobs")
    op.drop_column("skill_versions", "requires_scan")
