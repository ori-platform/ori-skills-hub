# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import base64
import sqlite3
from collections.abc import Coroutine
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError

from hub.core.models import SkillStatus
from hub.db import (
    Database,
    DatabaseConfigurationError,
    HubRepository,
    ImmutableRecordError,
    InvalidStateTransitionError,
    PersistenceConflictError,
    RecordNotFoundError,
    normalise_async_database_url,
)
from hub.db._models import (
    ArtifactModel,
    SkillTransitionAuditModel,
    SkillVersionModel,
    new_record_id,
)
from hub.security.author_identity import AuthorIdentityService

_T = TypeVar("_T")
_ARTIFACT_DIGEST = f"sha256:{'a' * 64}"
_MANIFEST_DIGEST = f"sha256:{'b' * 64}"
_AUTHOR_PUBLIC_KEY = base64.b64encode(bytes(range(32))).decode("ascii")


def _run(awaitable: Coroutine[Any, Any, _T]) -> _T:
    return asyncio.run(awaitable)


async def _setup_repository(tmp_path: Path) -> tuple[Database, HubRepository, str]:
    database = Database(f"sqlite:///{tmp_path / 'hub.db'}")
    await database.bootstrap_schema()
    repository = HubRepository(database)
    identity_service = AuthorIdentityService(
        database,
        token_ttl_seconds=300,
    )
    registration = await identity_service.register(
        external_subject="github:123",
        display_handle="ori-author",
        public_key_b64=_AUTHOR_PUBLIC_KEY,
        authenticated_actor_id="test-bootstrap",
        correlation_id="test-bootstrap",
        idempotency_key="test-bootstrap",
    )
    return database, repository, registration.author.author_id


async def _publish(
    repository: HubRepository,
    *,
    author_id: str,
    name: str = "energy",
    version: str = "1.0.0",
    digest_character: str = "a",
    declares_tier_cd: bool = False,
    initial_status: SkillStatus = SkillStatus.LISTED,
    idempotency_key: str = "publish-energy-1.0.0",
) -> SkillVersionModel:
    return await repository.create_publication(
        name=name,
        version=version,
        artifact_digest=f"sha256:{digest_character * 64}",
        manifest_digest=_MANIFEST_DIGEST,
        storage_key=f"{name}/{version}/{digest_character}.tar.gz",
        byte_size=128,
        artifact_signature="artifact-signature",
        manifest_signature="manifest-signature",
        declares_tier_cd=declares_tier_cd,
        initial_status=initial_status,
        authenticated_actor_id=author_id,
        reason="validated publication",
        correlation_id=f"publish:{name}:{version}",
        idempotency_key=idempotency_key,
    )


def test_database_url_normalises_sqlite_and_rejects_sync_drivers() -> None:
    assert (
        normalise_async_database_url("sqlite:///hub.db").drivername
        == "sqlite+aiosqlite"
    )
    with pytest.raises(DatabaseConfigurationError, match="aiosqlite"):
        normalise_async_database_url("sqlite+pysqlite:///hub.db")
    with pytest.raises(DatabaseConfigurationError, match="only SQLite"):
        normalise_async_database_url("postgresql://hub@localhost/hub")


def test_bootstrap_is_idempotent(tmp_path: Path) -> None:
    async def scenario() -> set[str]:
        database = Database(f"sqlite:///{tmp_path / 'hub.db'}")
        try:
            await database.bootstrap_schema()
            await database.bootstrap_schema()
            async with database.engine.connect() as connection:
                table_names = await connection.run_sync(
                    lambda sync_connection: set(
                        sync_connection.dialect.get_table_names(sync_connection)
                    )
                )
            return table_names
        finally:
            await database.dispose()

    assert _run(scenario()) == {
        "artifacts",
        "author_credentials",
        "author_identity_audit",
        "author_keys",
        "authors",
        "skill_transition_audit",
        "skill_versions",
    }


def test_alembic_upgrade_is_repeatable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_path = tmp_path / "migrated.db"
    monkeypatch.setenv("HUB_DATABASE_URL", f"sqlite:///{database_path}")
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))

    command.upgrade(config, "head")
    command.upgrade(config, "head")

    with sqlite3.connect(database_path) as connection:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        triggers = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            )
        }
    assert revision == ("1e9630e268d4",)
    assert "skill_transition_audit" in tables
    assert triggers == {
        "artifacts_reject_delete",
        "artifacts_reject_update",
        "author_credentials_reject_delete",
        "author_credentials_reject_identity_update",
        "author_credentials_reject_revoked_at_rewrite",
        "author_credentials_validate_status_transition",
        "author_identity_audit_reject_delete",
        "author_identity_audit_reject_update",
        "author_identity_audit_validate_ownership",
        "author_identity_audit_validate_timestamp",
        "author_keys_reject_delete",
        "author_keys_reject_identity_update",
        "author_keys_reject_revoked_at_rewrite",
        "author_keys_validate_status_transition",
        "authors_reject_identity_metadata_update",
        "authors_require_identity_revision",
        "authors_validate_identity_revision",
        "authors_validate_key_rotation",
        "authors_validate_status_transition",
        "skill_transition_audit_reject_delete",
        "skill_transition_audit_reject_update",
        "skill_transition_audit_apply_listing",
        "skill_transition_audit_apply_nonlisting",
        "skill_transition_audit_validate_state",
        "skill_transition_audit_validate_timestamp",
        "skill_versions_reject_approval_update",
        "skill_versions_reject_identity_authority_update",
        "skill_versions_require_transition_audit",
        "skill_versions_validate_initial_status",
        "skill_versions_validate_revision_transition",
        "skill_versions_validate_status_transition",
    }


def test_identity_migration_rejects_unaudited_legacy_authors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "legacy-author.db"
    monkeypatch.setenv("HUB_DATABASE_URL", f"sqlite:///{database_path}")
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "baa9ab020328")

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO authors (
                id,
                external_subject,
                display_handle,
                public_key_b64
            ) VALUES (?, ?, ?, ?)
            """,
            ("a" * 32, "legacy:123", "legacy-author", _AUTHOR_PUBLIC_KEY),
        )

    with pytest.raises(RuntimeError, match="cannot promote legacy authors"):
        command.upgrade(config, "head")

    with sqlite3.connect(database_path) as connection:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        author_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(authors)")
        }

    assert revision == ("baa9ab020328",)
    assert "author_keys" not in tables
    assert "identity_revision" not in author_columns


def test_identity_migration_refuses_to_discard_identity_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "identity-downgrade.db"
    monkeypatch.setenv("HUB_DATABASE_URL", f"sqlite:///{database_path}")
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "head")

    async def register() -> None:
        database = Database(f"sqlite:///{database_path}")
        try:
            service = AuthorIdentityService(database, token_ttl_seconds=300)
            await service.register(
                external_subject="github:downgrade-test",
                display_handle="downgrade-test",
                public_key_b64=_AUTHOR_PUBLIC_KEY,
                authenticated_actor_id="test-bootstrap",
                correlation_id="test-downgrade",
                idempotency_key="test-downgrade",
            )
        finally:
            await database.dispose()

    _run(register())

    with pytest.raises(RuntimeError, match="cannot downgrade"):
        command.downgrade(config, "baa9ab020328")

    with sqlite3.connect(database_path) as connection:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert revision == ("1e9630e268d4",)
    assert {"author_keys", "author_identity_audit"} <= tables


def test_publication_writes_artifact_skill_and_initial_audit_atomically(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            skill = await _publish(repository, author_id=author_id)
            history = await repository.get_transition_history(
                name=skill.name, version=skill.version
            )

            assert skill.status == SkillStatus.LISTED.value
            assert len(history) == 1
            assert history[0].prior_status is None
            assert history[0].new_status == SkillStatus.LISTED.value
            assert history[0].artifact_digest == _ARTIFACT_DIGEST
            assert history[0].occurred_at is not None
        finally:
            await database.dispose()

    _run(scenario())


def test_initial_publication_requires_matching_initial_audit(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, _repository, author_id = await _setup_repository(tmp_path)
        artifact_id = new_record_id()
        try:
            with pytest.raises(IntegrityError, match="invalid initial skill status"):
                async with database.transaction() as session:
                    await session.execute(
                        insert(ArtifactModel).values(
                            id=artifact_id,
                            artifact_digest=_ARTIFACT_DIGEST,
                            manifest_digest=_MANIFEST_DIGEST,
                            storage_key="missing-audit/1.0.0/artifact.tar.gz",
                            byte_size=128,
                            artifact_signature="artifact-signature",
                            manifest_signature="manifest-signature",
                        )
                    )
                    await session.execute(
                        insert(SkillVersionModel).values(
                            id=new_record_id(),
                            name="missing-audit",
                            version="1.0.0",
                            author_id=author_id,
                            artifact_id=artifact_id,
                            status=SkillStatus.LISTED.value,
                            declares_tier_cd=False,
                        )
                    )

            async with database.transaction() as session:
                artifact = await session.get(ArtifactModel, artifact_id)
                assert artifact is None
        finally:
            await database.dispose()

    _run(scenario())


def test_failed_publication_rolls_back_its_artifact(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, repository, _author_id = await _setup_repository(tmp_path)
        try:
            with pytest.raises(PersistenceConflictError):
                await _publish(repository, author_id="missing-author")

            async with database.transaction() as session:
                artifact_count = await session.scalar(
                    select(func.count()).select_from(ArtifactModel)
                )
            assert artifact_count == 0
        finally:
            await database.dispose()

    _run(scenario())


def test_duplicate_skill_identity_and_artifact_digest_are_rejected(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            await _publish(repository, author_id=author_id)
            with pytest.raises(PersistenceConflictError):
                await _publish(
                    repository,
                    author_id=author_id,
                    digest_character="d",
                    idempotency_key="duplicate-name-version",
                )
            with pytest.raises(PersistenceConflictError):
                await _publish(
                    repository,
                    author_id=author_id,
                    name="different-name",
                    version="2.0.0",
                    idempotency_key="duplicate-digest",
                )
        finally:
            await database.dispose()

    _run(scenario())


def test_tier_cd_cannot_be_listed_without_review(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            with pytest.raises(InvalidStateTransitionError, match="pending review"):
                await _publish(
                    repository,
                    author_id=author_id,
                    declares_tier_cd=True,
                )

            skill = await _publish(
                repository,
                author_id=author_id,
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
            )
            async with database.transaction() as session:
                with pytest.raises(IntegrityError, match="matching audit"):
                    await session.execute(
                        update(SkillVersionModel)
                        .where(SkillVersionModel.id == skill.id)
                        .values(
                            status=SkillStatus.LISTED.value,
                            revision=2,
                            review_approved_at=func.current_timestamp(),
                            review_approved_by="forged-reviewer",
                        )
                    )

            stored = await repository.get_skill(name="energy", version="1.0.0")
            history = await repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert stored.status == SkillStatus.PENDING_REVIEW.value
            assert stored.review_approved_at is None
            assert stored.review_approved_by is None
            assert stored.revision == 1
            assert [entry.new_status for entry in history] == ["pending_review"]

            artifact_id = new_record_id()
            with pytest.raises(IntegrityError, match="invalid initial skill status"):
                async with database.transaction() as session:
                    await session.execute(
                        insert(ArtifactModel).values(
                            id=artifact_id,
                            artifact_digest=f"sha256:{'d' * 64}",
                            manifest_digest=f"sha256:{'e' * 64}",
                            storage_key="forged/1.0.0/artifact.tar.gz",
                            byte_size=128,
                            artifact_signature="forged-artifact-signature",
                            manifest_signature="forged-manifest-signature",
                        )
                    )
                    await session.execute(
                        insert(SkillVersionModel).values(
                            id=new_record_id(),
                            name="forged-tier-c",
                            version="1.0.0",
                            author_id=author_id,
                            artifact_id=artifact_id,
                            status=SkillStatus.LISTED.value,
                            declares_tier_cd=True,
                            review_approved_at=func.current_timestamp(),
                            review_approved_by="forged-reviewer",
                        )
                    )
        finally:
            await database.dispose()

    _run(scenario())


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("id", "f" * 32),
        ("name", "renamed"),
        ("version", "9.9.9"),
        ("author_id", "e" * 32),
        ("artifact_id", "d" * 32),
        ("declares_tier_cd", False),
    ],
)
def test_direct_sql_publication_identity_and_authority_are_immutable(
    tmp_path: Path,
    field_name: str,
    replacement: str | bool,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            skill = await _publish(
                repository,
                author_id=author_id,
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
            )
            with pytest.raises(IntegrityError, match="identity and authority"):
                async with database.transaction() as session:
                    await session.execute(
                        update(SkillVersionModel)
                        .where(SkillVersionModel.id == skill.id)
                        .values({field_name: replacement})
                    )

            unchanged = await repository.get_skill(name="energy", version="1.0.0")
            assert unchanged.id == skill.id
            assert unchanged.name == "energy"
            assert unchanged.version == "1.0.0"
            assert unchanged.author_id == author_id
            assert unchanged.artifact_id == skill.artifact_id
            assert unchanged.declares_tier_cd is True
        finally:
            await database.dispose()

    _run(scenario())


def test_direct_sql_audit_is_validated_and_applies_transition_atomically(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            skill = await _publish(
                repository,
                author_id=author_id,
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
            )
            audit_values = {
                "skill_version_id": skill.id,
                "transition_number": 2,
                "actor_id": "reviewer:direct-sql",
                "prior_status": SkillStatus.PENDING_REVIEW.value,
                "new_status": SkillStatus.LISTED.value,
                "reason": "manual Tier C/D review passed",
                "correlation_id": "review:direct-sql",
                "idempotency_key": "review:direct-sql",
                "manifest_digest": _MANIFEST_DIGEST,
            }

            with pytest.raises(IntegrityError, match="current skill state"):
                async with database.transaction() as session:
                    await session.execute(
                        insert(SkillTransitionAuditModel).values(
                            id=new_record_id(),
                            artifact_digest=f"sha256:{'d' * 64}",
                            **audit_values,
                        )
                    )

            unchanged = await repository.get_skill(name="energy", version="1.0.0")
            history = await repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert unchanged.status == SkillStatus.PENDING_REVIEW.value
            assert unchanged.revision == 1
            assert [entry.new_status for entry in history] == ["pending_review"]

            async with database.transaction() as session:
                await session.execute(
                    insert(SkillTransitionAuditModel).values(
                        id=new_record_id(),
                        artifact_digest=_ARTIFACT_DIGEST,
                        **audit_values,
                    )
                )

            approved = await repository.get_skill(name="energy", version="1.0.0")
            history = await repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert approved.status == SkillStatus.LISTED.value
            assert approved.revision == 2
            assert approved.review_approved_by == "reviewer:direct-sql"
            assert approved.review_approved_at == history[-1].occurred_at
            assert [entry.new_status for entry in history] == [
                "pending_review",
                "listed",
            ]
        finally:
            await database.dispose()

    _run(scenario())


def test_alembic_schema_blocks_direct_sql_review_gate_bypasses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "migrated-guards.db"
    monkeypatch.setenv("HUB_DATABASE_URL", f"sqlite:///{database_path}")
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "head")

    async def scenario() -> None:
        database = Database(f"sqlite:///{database_path}")
        repository = HubRepository(database)
        try:
            author = await repository.create_author(
                external_subject="github:migrated",
                display_handle="migrated-author",
                public_key_b64="migrated-author-public-key",
            )
            skill = await _publish(
                repository,
                author_id=author.id,
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
            )

            with pytest.raises(IntegrityError, match="matching audit"):
                async with database.transaction() as session:
                    await session.execute(
                        update(SkillVersionModel)
                        .where(SkillVersionModel.id == skill.id)
                        .values(
                            status=SkillStatus.LISTED.value,
                            revision=2,
                            review_approved_at=func.current_timestamp(),
                            review_approved_by="forged-reviewer",
                        )
                    )

            with pytest.raises(IntegrityError, match="identity and authority"):
                async with database.transaction() as session:
                    await session.execute(
                        update(SkillVersionModel)
                        .where(SkillVersionModel.id == skill.id)
                        .values(declares_tier_cd=False)
                    )

            unchanged = await repository.get_skill(name="energy", version="1.0.0")
            history = await repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert unchanged.status == SkillStatus.PENDING_REVIEW.value
            assert unchanged.declares_tier_cd is True
            assert unchanged.review_approved_at is None
            assert unchanged.review_approved_by is None
            assert unchanged.revision == 1
            assert [entry.new_status for entry in history] == ["pending_review"]
        finally:
            await database.dispose()

    _run(scenario())


def test_review_and_unlist_retain_complete_server_owned_history(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            await _publish(
                repository,
                author_id=author_id,
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
            )
            approved = await repository.transition_skill(
                name="energy",
                version="1.0.0",
                target_status=SkillStatus.LISTED,
                authenticated_actor_id="reviewer:42",
                reason="manual Tier C/D review passed",
                correlation_id="review:energy:1.0.0",
                idempotency_key="approve-energy-1.0.0",
            )
            assert approved.review_approved_by == "reviewer:42"
            assert approved.review_approved_at is not None

            await repository.transition_skill(
                name="energy",
                version="1.0.0",
                target_status=SkillStatus.UNLISTED,
                authenticated_actor_id="reviewer:84",
                reason="author signing key revoked",
                correlation_id="unlist:energy:1.0.0",
                idempotency_key="unlist-energy-1.0.0",
            )
            history = await repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert [
                (entry.prior_status, entry.new_status, entry.actor_id)
                for entry in history
            ] == [
                (None, "pending_review", author_id),
                ("pending_review", "listed", "reviewer:42"),
                ("listed", "unlisted", "reviewer:84"),
            ]
            assert all(entry.occurred_at is not None for entry in history)
        finally:
            await database.dispose()

    _run(scenario())


def test_review_metadata_and_revision_cannot_diverge_from_audit(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            await _publish(
                repository,
                author_id=author_id,
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
            )
            approved = await repository.transition_skill(
                name="energy",
                version="1.0.0",
                target_status=SkillStatus.LISTED,
                authenticated_actor_id="reviewer:42",
                reason="manual Tier C/D review passed",
                correlation_id="review:energy:1.0.0",
                idempotency_key="approve-energy-1.0.0",
            )

            with pytest.raises(IntegrityError, match="approval metadata"):
                async with database.transaction() as session:
                    await session.execute(
                        update(SkillVersionModel)
                        .where(SkillVersionModel.id == approved.id)
                        .values(review_approved_by="forged-reviewer")
                    )

            with pytest.raises(IntegrityError, match="revision transition"):
                async with database.transaction() as session:
                    await session.execute(
                        update(SkillVersionModel)
                        .where(SkillVersionModel.id == approved.id)
                        .values(revision=approved.revision + 1)
                    )

            unchanged = await repository.get_skill(name="energy", version="1.0.0")
            history = await repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert unchanged.review_approved_by == "reviewer:42"
            assert unchanged.review_approved_at == history[-1].occurred_at
            assert unchanged.revision == 2
            assert len(history) == 2
        finally:
            await database.dispose()

    _run(scenario())


def test_rejection_history_is_retained_and_terminal(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            await _publish(
                repository,
                author_id=author_id,
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
            )
            await repository.transition_skill(
                name="energy",
                version="1.0.0",
                target_status=SkillStatus.REJECTED,
                authenticated_actor_id="reviewer:42",
                reason="unsafe Tier C behavior",
                correlation_id="review:energy:1.0.0",
                idempotency_key="reject-energy-1.0.0",
            )
            with pytest.raises(InvalidStateTransitionError):
                await repository.transition_skill(
                    name="energy",
                    version="1.0.0",
                    target_status=SkillStatus.LISTED,
                    authenticated_actor_id="reviewer:42",
                    reason="second decision",
                    correlation_id="review:energy:1.0.0:second",
                    idempotency_key="approve-rejected-energy",
                )
            history = await repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert [entry.new_status for entry in history] == [
                "pending_review",
                "rejected",
            ]
        finally:
            await database.dispose()

    _run(scenario())


def test_artifacts_and_audit_rows_are_append_only(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            skill = await _publish(repository, author_id=author_id)
            async with database.transaction() as session:
                artifact = await session.get(ArtifactModel, skill.artifact_id)
                assert artifact is not None
                artifact.storage_key = "rewritten.tar.gz"
                with pytest.raises(ImmutableRecordError):
                    await session.flush()

            history = await repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            async with database.transaction() as session:
                audit = await session.get(SkillTransitionAuditModel, history[0].id)
                assert audit is not None
                await session.delete(audit)
                with pytest.raises(ImmutableRecordError):
                    await session.flush()

            with pytest.raises(IntegrityError, match="artifacts are immutable"):
                async with database.transaction() as session:
                    await session.execute(
                        update(ArtifactModel)
                        .where(ArtifactModel.id == skill.artifact_id)
                        .values(storage_key="sql-bypass.tar.gz")
                    )
            with pytest.raises(IntegrityError, match="append-only"):
                async with database.transaction() as session:
                    await session.execute(
                        delete(SkillTransitionAuditModel).where(
                            SkillTransitionAuditModel.id == history[0].id
                        )
                    )
        finally:
            await database.dispose()

    _run(scenario())


def test_direct_orm_status_changes_cannot_bypass_atomic_audit(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            skill = await _publish(
                repository,
                author_id=author_id,
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
            )
            async with database.transaction() as session:
                stored = await session.get(SkillVersionModel, skill.id)
                assert stored is not None
                stored.status = SkillStatus.REJECTED.value
                with pytest.raises(InvalidStateTransitionError, match="HubRepository"):
                    await session.flush()

            async with database.transaction() as session:
                stored = await session.get(SkillVersionModel, skill.id)
                assert stored is not None
                stored.declares_tier_cd = False
                with pytest.raises(InvalidStateTransitionError, match="HubRepository"):
                    await session.flush()

            unchanged = await repository.get_skill(name="energy", version="1.0.0")
            history = await repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert unchanged.status == SkillStatus.PENDING_REVIEW.value
            assert unchanged.declares_tier_cd is True
            assert [entry.new_status for entry in history] == ["pending_review"]
        finally:
            await database.dispose()

    _run(scenario())


def test_client_supplied_audit_timestamp_is_rejected(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            skill = await _publish(repository, author_id=author_id)
            history = await repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            forged = SkillTransitionAuditModel(
                skill_version_id=skill.id,
                transition_number=2,
                actor_id="forged-client-label",
                prior_status=SkillStatus.LISTED.value,
                new_status=SkillStatus.UNLISTED.value,
                reason="forged",
                occurred_at=history[0].occurred_at,
                correlation_id="forged",
                idempotency_key="forged",
                artifact_digest=_ARTIFACT_DIGEST,
                manifest_digest=_MANIFEST_DIGEST,
            )
            async with database.transaction() as session:
                session.add(forged)
                with pytest.raises(ImmutableRecordError, match="database-generated"):
                    await session.flush()

            with pytest.raises(IntegrityError, match="database-generated"):
                async with database.transaction() as session:
                    await session.execute(
                        insert(SkillTransitionAuditModel).values(
                            id=new_record_id(),
                            skill_version_id=skill.id,
                            transition_number=2,
                            actor_id="forged-client-label",
                            prior_status=SkillStatus.LISTED.value,
                            new_status=SkillStatus.UNLISTED.value,
                            reason="forged",
                            occurred_at=datetime(2000, 1, 1, tzinfo=UTC),
                            correlation_id="forged-sql",
                            idempotency_key="forged-sql",
                            artifact_digest=_ARTIFACT_DIGEST,
                            manifest_digest=_MANIFEST_DIGEST,
                        )
                    )
        finally:
            await database.dispose()

    _run(scenario())


def test_download_counts_are_atomic_and_limited_to_listed_skills(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            await _publish(repository, author_id=author_id)
            results = await asyncio.gather(
                *(
                    repository.increment_downloads(name="energy", version="1.0.0")
                    for _index in range(20)
                )
            )
            assert sorted(results) == list(range(1, 21))
            skill = await repository.get_skill(name="energy", version="1.0.0")
            assert skill.downloads == 20

            await _publish(
                repository,
                author_id=author_id,
                name="pending-skill",
                version="1.0.0",
                digest_character="d",
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
                idempotency_key="publish-pending",
            )
            with pytest.raises(
                InvalidStateTransitionError, match="cannot be downloaded"
            ):
                await repository.increment_downloads(
                    name="pending-skill", version="1.0.0"
                )
            with pytest.raises(RecordNotFoundError):
                await repository.increment_downloads(name="missing", version="1.0.0")
        finally:
            await database.dispose()

    _run(scenario())


def test_concurrent_publication_has_one_winner_and_no_orphan_artifact(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            outcomes = await asyncio.gather(
                _publish(
                    repository,
                    author_id=author_id,
                    digest_character="a",
                    idempotency_key="publish-race-a",
                ),
                _publish(
                    repository,
                    author_id=author_id,
                    digest_character="d",
                    idempotency_key="publish-race-d",
                ),
                return_exceptions=True,
            )
            assert sum(isinstance(item, SkillVersionModel) for item in outcomes) == 1
            assert (
                sum(isinstance(item, PersistenceConflictError) for item in outcomes)
                == 1
            )

            async with database.transaction() as session:
                artifact_count = await session.scalar(
                    select(func.count()).select_from(ArtifactModel)
                )
                audit_count = await session.scalar(
                    select(func.count()).select_from(SkillTransitionAuditModel)
                )
            assert artifact_count == 1
            assert audit_count == 1
        finally:
            await database.dispose()

    _run(scenario())


def test_concurrent_review_decisions_have_one_winner(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            await _publish(
                repository,
                author_id=author_id,
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
            )

            async def decide(status: SkillStatus, reviewer: str) -> SkillVersionModel:
                return await repository.transition_skill(
                    name="energy",
                    version="1.0.0",
                    target_status=status,
                    authenticated_actor_id=reviewer,
                    reason=f"{status.value} after manual review",
                    correlation_id=f"review:{status.value}",
                    idempotency_key=f"decision:{status.value}",
                )

            outcomes = await asyncio.gather(
                decide(SkillStatus.LISTED, "reviewer:approve"),
                decide(SkillStatus.REJECTED, "reviewer:reject"),
                return_exceptions=True,
            )
            assert sum(isinstance(item, SkillVersionModel) for item in outcomes) == 1
            assert (
                sum(isinstance(item, InvalidStateTransitionError) for item in outcomes)
                == 1
            )
            history = await repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert len(history) == 2
            assert history[-1].new_status in {"listed", "rejected"}
        finally:
            await database.dispose()

    _run(scenario())


def test_duplicate_idempotency_key_rolls_back_second_publication(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            await _publish(
                repository,
                author_id=author_id,
                idempotency_key="same-operation",
            )
            with pytest.raises(PersistenceConflictError):
                await _publish(
                    repository,
                    author_id=author_id,
                    name="guard",
                    version="2.0.0",
                    digest_character="d",
                    idempotency_key="same-operation",
                )
            with pytest.raises(RecordNotFoundError):
                await repository.get_skill(name="guard", version="2.0.0")

            async with database.transaction() as session:
                artifact_count = await session.scalar(
                    select(func.count()).select_from(ArtifactModel)
                )
            assert artifact_count == 1
        finally:
            await database.dispose()

    _run(scenario())


def test_duplicate_review_idempotency_rolls_back_status_change(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            await _publish(
                repository,
                author_id=author_id,
                name="energy",
                version="1.0.0",
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
                idempotency_key="publish-energy",
            )
            await _publish(
                repository,
                author_id=author_id,
                name="guard",
                version="1.0.0",
                digest_character="d",
                declares_tier_cd=True,
                initial_status=SkillStatus.PENDING_REVIEW,
                idempotency_key="publish-guard",
            )
            await repository.transition_skill(
                name="energy",
                version="1.0.0",
                target_status=SkillStatus.LISTED,
                authenticated_actor_id="reviewer:42",
                reason="approved",
                correlation_id="review:energy",
                idempotency_key="shared-review-operation",
            )

            with pytest.raises(PersistenceConflictError):
                await repository.transition_skill(
                    name="guard",
                    version="1.0.0",
                    target_status=SkillStatus.REJECTED,
                    authenticated_actor_id="reviewer:42",
                    reason="rejected",
                    correlation_id="review:guard",
                    idempotency_key="shared-review-operation",
                )

            guard = await repository.get_skill(name="guard", version="1.0.0")
            history = await repository.get_transition_history(
                name="guard", version="1.0.0"
            )
            assert guard.status == SkillStatus.PENDING_REVIEW.value
            assert [entry.new_status for entry in history] == ["pending_review"]
        finally:
            await database.dispose()

    _run(scenario())


def test_database_checks_reject_invalid_states_and_physical_history_deletion(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, author_id = await _setup_repository(tmp_path)
        try:
            skill = await _publish(repository, author_id=author_id)
            async with database.transaction() as session:
                with pytest.raises(IntegrityError):
                    await session.execute(
                        update(SkillVersionModel)
                        .where(SkillVersionModel.id == skill.id)
                        .values(status="unknown")
                    )

            with pytest.raises(IntegrityError, match="current skill state"):
                async with database.transaction() as session:
                    await session.execute(
                        insert(SkillTransitionAuditModel).values(
                            id=new_record_id(),
                            skill_version_id=skill.id,
                            transition_number=2,
                            actor_id="reviewer:42",
                            prior_status=SkillStatus.LISTED.value,
                            new_status=SkillStatus.REJECTED.value,
                            reason="invalid transition",
                            correlation_id="invalid-transition",
                            idempotency_key="invalid-transition",
                            artifact_digest=_ARTIFACT_DIGEST,
                            manifest_digest=_MANIFEST_DIGEST,
                        )
                    )

            with pytest.raises(IntegrityError, match="matching audit"):
                async with database.transaction() as session:
                    await session.execute(
                        update(SkillVersionModel)
                        .where(SkillVersionModel.id == skill.id)
                        .values(status=SkillStatus.REJECTED.value)
                    )

            with pytest.raises(IntegrityError):
                async with database.transaction() as session:
                    await session.execute(
                        delete(SkillVersionModel).where(
                            SkillVersionModel.id == skill.id
                        )
                    )
        finally:
            await database.dispose()

    _run(scenario())
