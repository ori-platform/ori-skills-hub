# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""add artifact scanner verdict and author provenance

Revision ID: 7a2b9c4d1e05
Revises: 1e9630e268d4
Create Date: 2026-07-30 21:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7a2b9c4d1e05"
down_revision: str | None = "1e9630e268d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_LEGACY_DIGEST_DEFAULT = f"sha256:{'0' * 64}"


def upgrade() -> None:
    legacy_artifact_count = (
        op.get_bind().execute(sa.text("SELECT count(*) FROM artifacts")).scalar_one()
    )
    if legacy_artifact_count:
        raise RuntimeError(
            "HUB-007 cannot backfill scanner verdicts or author provenance for "
            "existing artifacts; migrate or remove those records before retrying"
        )

    op.add_column(
        "artifacts",
        sa.Column(
            "scanner_verdict",
            sa.String(length=32),
            sa.CheckConstraint(
                "scanner_verdict IN ('clean', 'suspicious', 'unavailable')",
                name="scanner_verdict_valid",
            ),
            server_default="unavailable",
            nullable=False,
        ),
    )
    op.add_column(
        "artifacts",
        sa.Column(
            "scanner_detail",
            sa.String(length=1024),
            sa.CheckConstraint(
                "length(scanner_detail) <= 1024",
                name="scanner_detail_bounded",
            ),
            server_default="",
            nullable=False,
        ),
    )
    op.add_column(
        "artifacts",
        sa.Column(
            "author_artifact_digest",
            sa.String(length=71),
            sa.CheckConstraint(
                "author_artifact_digest LIKE 'sha256:%' "
                "AND length(author_artifact_digest) = 71",
                name="author_artifact_digest_valid",
            ),
            server_default=_LEGACY_DIGEST_DEFAULT,
            nullable=False,
        ),
    )
    op.add_column(
        "artifacts",
        sa.Column(
            "author_artifact_signature",
            sa.String(length=512),
            sa.CheckConstraint(
                "length(author_artifact_signature) > 0",
                name="author_artifact_signature_set",
            ),
            server_default="unavailable",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("artifacts", "author_artifact_signature")
    op.drop_column("artifacts", "author_artifact_digest")
    op.drop_column("artifacts", "scanner_detail")
    op.drop_column("artifacts", "scanner_verdict")
