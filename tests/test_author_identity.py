# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import base64
import hashlib
from collections.abc import Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar

import pytest
from httpx import ASGITransport, AsyncClient
from httpx import Response as HttpxResponse
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError

from hub.db import Database
from hub.db._identity_repository import AuthorIdentityRepository
from hub.db._models import (
    AuthorCredentialModel,
    AuthorIdentityAuditModel,
    AuthorKeyModel,
    AuthorModel,
)
from hub.db.errors import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    RecordNotFoundError,
)
from hub.security.author_identity import (
    AuthenticatedAuthor,
    AuthorAuthenticationError,
    AuthorIdentity,
    AuthorIdentityService,
    AuthorRegistration,
    InvalidAuthorIdentityError,
)
from hub.web.authors import author_authentication_dependency
from hub.web.main import create_app

_T = TypeVar("_T")
_KEY_ONE = base64.b64encode(bytes(range(32))).decode("ascii")
_KEY_TWO = base64.b64encode(bytes(reversed(range(32)))).decode("ascii")
_KEY_THREE = base64.b64encode(bytes(value ^ 0xAA for value in range(32))).decode(
    "ascii"
)
_ADMIN_KEY = "a" * 48
_ADMIN_ACTOR = "admin:bootstrap"


@dataclass
class MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, *, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def _run(awaitable: Coroutine[Any, Any, _T]) -> _T:
    return asyncio.run(awaitable)


def _admin_headers(operation: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_ADMIN_KEY}",
        "Idempotency-Key": operation,
        "X-Correlation-ID": operation,
    }


def _tamper_token(token: str) -> str:
    prefix, lookup_id, secret = token.split(".")
    replacement = "A" if secret[0] != "A" else "B"
    return f"{prefix}.{lookup_id}.{replacement}{secret[1:]}"


async def _setup(
    tmp_path: Path,
) -> tuple[
    Database,
    AuthorIdentityRepository,
    AuthorIdentityService,
    MutableClock,
]:
    database = Database(f"sqlite:///{tmp_path / 'identity.db'}")
    await database.bootstrap_schema()
    repository = AuthorIdentityRepository(database)
    clock = MutableClock(datetime(2026, 7, 29, 12, 0, tzinfo=UTC))
    service = AuthorIdentityService(
        database,
        token_ttl_seconds=300,
        clock=clock,
    )
    return database, repository, service, clock


async def _register(
    service: AuthorIdentityService,
    *,
    external_subject: str = "github:123",
    display_handle: str = "ori-author",
    public_key_b64: str = _KEY_ONE,
    idempotency_key: str = "register:github:123",
) -> AuthorRegistration:
    return await service.register(
        external_subject=external_subject,
        display_handle=display_handle,
        public_key_b64=public_key_b64,
        authenticated_actor_id=_ADMIN_ACTOR,
        correlation_id=f"correlation:{external_subject}",
        idempotency_key=idempotency_key,
    )


def test_registration_returns_token_once_and_authenticates_stable_actor(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, service, _clock = await _setup(tmp_path)
        try:
            registration = await _register(service)
            token = registration.credential.bearer_token
            authenticated = await service.authenticate(token)
            credentials = await repository.get_credentials(
                author_id=registration.author.author_id
            )
            history = await repository.get_identity_history(
                author_id=registration.author.author_id
            )

            assert token.startswith("ori_author_v1.")
            assert token not in repr(registration)
            assert token not in repr(registration.credential)
            assert authenticated == AuthenticatedAuthor(
                actor_id=registration.author.author_id,
                external_subject="github:123",
                display_handle="ori-author",
                public_key_b64=_KEY_ONE,
                credential_id=credentials[0].id,
            )
            assert credentials[0].lookup_id == token.split(".")[1]
            assert credentials[0].credential_hash == (
                f"sha256:{hashlib.sha256(token.encode('ascii')).hexdigest()}"
            )
            assert token not in credentials[0].credential_hash
            assert history[0].actor_id == _ADMIN_ACTOR
            assert history[0].event_type == "registered"
            assert history[0].occurred_at is not None
            assert history[0].new_credential_id == credentials[0].id
        finally:
            await database.dispose()

    _run(scenario())


def test_invalid_key_and_duplicate_identity_fail_without_partial_records(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, service, _clock = await _setup(tmp_path)
        try:
            with pytest.raises(InvalidAuthorIdentityError, match="Ed25519"):
                await _register(service, public_key_b64="not-a-key")

            first = await _register(service)
            with pytest.raises(PersistenceConflictError):
                await _register(
                    service,
                    external_subject="github:123",
                    display_handle="second-handle",
                    public_key_b64=_KEY_TWO,
                    idempotency_key="duplicate-subject",
                )
            with pytest.raises(PersistenceConflictError):
                await _register(
                    service,
                    external_subject="github:456",
                    display_handle="different-author",
                    public_key_b64=_KEY_ONE,
                    idempotency_key="duplicate-key",
                )

            async with database.transaction() as session:
                author_count = await session.scalar(
                    select(func.count()).select_from(AuthorModel)
                )
                credential_count = await session.scalar(
                    select(func.count()).select_from(AuthorCredentialModel)
                )
                audit_count = await session.scalar(
                    select(func.count()).select_from(AuthorIdentityAuditModel)
                )
            assert first.author.author_id
            assert author_count == 1
            assert credential_count == 1
            assert audit_count == 1
        finally:
            await database.dispose()

    _run(scenario())


def test_expired_and_malformed_credentials_fail_with_one_generic_error(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, _repository, service, clock = await _setup(tmp_path)
        try:
            registration = await _register(service)
            token = registration.credential.bearer_token

            with pytest.raises(
                AuthorAuthenticationError, match="authentication failed"
            ):
                await service.authenticate("malformed")
            with pytest.raises(
                AuthorAuthenticationError, match="authentication failed"
            ):
                await service.authenticate(_tamper_token(token))

            clock.advance(seconds=300)
            with pytest.raises(
                AuthorAuthenticationError, match="authentication failed"
            ):
                await service.authenticate(token)
        finally:
            await database.dispose()

    _run(scenario())


def test_credential_rotation_revokes_old_token_and_is_fully_audited(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, service, _clock = await _setup(tmp_path)
        try:
            initial = await _register(service)
            rotated = await service.rotate_credential(
                author_id=initial.author.author_id,
                authenticated_actor_id=_ADMIN_ACTOR,
                reason="scheduled credential rotation",
                correlation_id="rotate-credential:1",
                idempotency_key="rotate-credential:1",
            )

            with pytest.raises(AuthorAuthenticationError):
                await service.authenticate(initial.credential.bearer_token)
            authenticated = await service.authenticate(rotated.credential.bearer_token)
            credentials = await repository.get_credentials(
                author_id=initial.author.author_id
            )
            history = await repository.get_identity_history(
                author_id=initial.author.author_id
            )

            assert authenticated.actor_id == initial.author.author_id
            credential_by_status = {
                credential.status: credential for credential in credentials
            }
            assert set(credential_by_status) == {"revoked", "active"}
            assert credential_by_status["revoked"].revoked_at is not None
            assert [event.event_type for event in history] == [
                "registered",
                "credential_rotated",
            ]
            assert history[1].prior_credential_id == credential_by_status["revoked"].id
            assert history[1].new_credential_id == credential_by_status["active"].id
            assert rotated.author.identity_revision == 2
        finally:
            await database.dispose()

    _run(scenario())


def test_credential_rotation_replay_rolls_back_without_replacing_valid_token(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, service, _clock = await _setup(tmp_path)
        try:
            initial = await _register(service)
            rotated = await service.rotate_credential(
                author_id=initial.author.author_id,
                authenticated_actor_id=_ADMIN_ACTOR,
                reason="scheduled credential rotation",
                correlation_id="rotate-credential:replay",
                idempotency_key="rotate-credential:replay",
            )

            with pytest.raises(PersistenceConflictError):
                await service.rotate_credential(
                    author_id=initial.author.author_id,
                    authenticated_actor_id=_ADMIN_ACTOR,
                    reason="replayed credential rotation",
                    correlation_id="rotate-credential:replay",
                    idempotency_key="rotate-credential:replay",
                )

            authenticated = await service.authenticate(rotated.credential.bearer_token)
            author = await repository.get_author(author_id=initial.author.author_id)
            credentials = await repository.get_credentials(
                author_id=initial.author.author_id
            )
            history = await repository.get_identity_history(
                author_id=initial.author.author_id
            )

            assert authenticated.credential_id == next(
                credential.id
                for credential in credentials
                if credential.status == "active"
            )
            assert len(credentials) == 2
            assert author.identity_revision == 2
            assert [event.event_type for event in history] == [
                "registered",
                "credential_rotated",
            ]
        finally:
            await database.dispose()

    _run(scenario())


def test_key_rotation_retains_revoked_key_and_updates_auth_context(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, service, _clock = await _setup(tmp_path)
        try:
            registration = await _register(service)
            rotated = await service.rotate_key(
                author_id=registration.author.author_id,
                public_key_b64=_KEY_TWO,
                authenticated_actor_id=_ADMIN_ACTOR,
                reason="author proved possession of replacement key",
                correlation_id="rotate-key:1",
                idempotency_key="rotate-key:1",
            )
            authenticated = await service.authenticate(
                registration.credential.bearer_token
            )
            keys = await repository.get_key_history(
                author_id=registration.author.author_id
            )
            history = await repository.get_identity_history(
                author_id=registration.author.author_id
            )

            assert rotated.public_key_b64 == _KEY_TWO
            assert authenticated.public_key_b64 == _KEY_TWO
            key_by_status = {key.status: key for key in keys}
            assert set(key_by_status) == {"revoked", "active"}
            assert key_by_status["revoked"].public_key_b64 == _KEY_ONE
            assert key_by_status["revoked"].revoked_at is not None
            assert history[1].event_type == "key_rotated"
            assert (
                history[1].prior_key_fingerprint,
                history[1].new_key_fingerprint,
            ) == (
                key_by_status["revoked"].fingerprint,
                key_by_status["active"].fingerprint,
            )

            with pytest.raises(PersistenceConflictError):
                await service.rotate_key(
                    author_id=registration.author.author_id,
                    public_key_b64=_KEY_ONE,
                    authenticated_actor_id=_ADMIN_ACTOR,
                    reason="attempt key reuse",
                    correlation_id="rotate-key:reuse",
                    idempotency_key="rotate-key:reuse",
                )
        finally:
            await database.dispose()

    _run(scenario())


def test_author_revocation_invalidates_token_key_and_future_mutations(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, service, _clock = await _setup(tmp_path)
        try:
            registration = await _register(service)
            revoked = await service.revoke(
                author_id=registration.author.author_id,
                authenticated_actor_id=_ADMIN_ACTOR,
                reason="author requested account revocation",
                correlation_id="revoke-author:1",
                idempotency_key="revoke-author:1",
            )

            assert revoked.status == "revoked"
            with pytest.raises(AuthorAuthenticationError):
                await service.authenticate(registration.credential.bearer_token)
            with pytest.raises(InvalidStateTransitionError, match="revoked"):
                await service.rotate_credential(
                    author_id=registration.author.author_id,
                    authenticated_actor_id=_ADMIN_ACTOR,
                    reason="must fail",
                    correlation_id="rotate-after-revoke",
                    idempotency_key="rotate-after-revoke",
                )
            keys = await repository.get_key_history(
                author_id=registration.author.author_id
            )
            credentials = await repository.get_credentials(
                author_id=registration.author.author_id
            )
            history = await repository.get_identity_history(
                author_id=registration.author.author_id
            )
            assert keys[-1].status == "revoked"
            assert credentials[-1].status == "revoked"
            assert history[-1].event_type == "author_revoked"
        finally:
            await database.dispose()

    _run(scenario())


def test_idempotency_conflict_rolls_back_entire_registration(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, service, _clock = await _setup(tmp_path)
        try:
            await _register(service, idempotency_key="shared-bootstrap")
            with pytest.raises(PersistenceConflictError):
                await _register(
                    service,
                    external_subject="github:456",
                    display_handle="second-author",
                    public_key_b64=_KEY_TWO,
                    idempotency_key="shared-bootstrap",
                )
            with pytest.raises(RecordNotFoundError):
                await repository.get_author(author_id="0" * 32)

            async with database.transaction() as session:
                assert (
                    await session.scalar(select(func.count()).select_from(AuthorModel))
                    == 1
                )
                assert (
                    await session.scalar(
                        select(func.count()).select_from(AuthorKeyModel)
                    )
                    == 1
                )
        finally:
            await database.dispose()

    _run(scenario())


def test_concurrent_key_rotation_has_one_winner_and_no_partial_history(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, service, _clock = await _setup(tmp_path)
        try:
            registration = await _register(service)

            async def rotate(key: str, suffix: str) -> AuthorIdentity:
                return await service.rotate_key(
                    author_id=registration.author.author_id,
                    public_key_b64=key,
                    authenticated_actor_id=_ADMIN_ACTOR,
                    reason=f"concurrent rotation {suffix}",
                    correlation_id=f"rotate-key:{suffix}",
                    idempotency_key=f"rotate-key:{suffix}",
                )

            outcomes = await asyncio.gather(
                rotate(_KEY_TWO, "two"),
                rotate(_KEY_THREE, "three"),
                return_exceptions=True,
            )
            assert sum(isinstance(outcome, AuthorIdentity) for outcome in outcomes) == 1
            assert (
                sum(
                    isinstance(
                        outcome,
                        (InvalidStateTransitionError, PersistenceConflictError),
                    )
                    for outcome in outcomes
                )
                == 1
            )
            keys = await repository.get_key_history(
                author_id=registration.author.author_id
            )
            history = await repository.get_identity_history(
                author_id=registration.author.author_id
            )
            assert [key.status for key in keys].count("active") == 1
            assert len(keys) == 2
            assert [event.event_type for event in history] == [
                "registered",
                "key_rotated",
            ]
        finally:
            await database.dispose()

    _run(scenario())


def test_concurrent_credential_rotation_has_one_winner_and_no_partial_history(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, service, _clock = await _setup(tmp_path)
        try:
            registration = await _register(service)

            async def rotate(suffix: str) -> AuthorRegistration:
                return await service.rotate_credential(
                    author_id=registration.author.author_id,
                    authenticated_actor_id=_ADMIN_ACTOR,
                    reason=f"concurrent credential rotation {suffix}",
                    correlation_id=f"rotate-credential:{suffix}",
                    idempotency_key=f"rotate-credential:{suffix}",
                )

            outcomes = await asyncio.gather(
                rotate("one"),
                rotate("two"),
                return_exceptions=True,
            )
            assert (
                sum(isinstance(outcome, AuthorRegistration) for outcome in outcomes)
                == 1
            )
            assert (
                sum(
                    isinstance(
                        outcome,
                        (InvalidStateTransitionError, PersistenceConflictError),
                    )
                    for outcome in outcomes
                )
                == 1
            )
            credentials = await repository.get_credentials(
                author_id=registration.author.author_id
            )
            history = await repository.get_identity_history(
                author_id=registration.author.author_id
            )
            assert [credential.status for credential in credentials].count(
                "active"
            ) == 1
            assert len(credentials) == 2
            assert [event.event_type for event in history] == [
                "registered",
                "credential_rotated",
            ]
        finally:
            await database.dispose()

    _run(scenario())


def test_database_guards_block_identity_and_history_bypasses(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, service, _clock = await _setup(tmp_path)
        try:
            registration = await _register(service)
            author_id = registration.author.author_id
            keys = await repository.get_key_history(author_id=author_id)
            credentials = await repository.get_credentials(author_id=author_id)
            history = await repository.get_identity_history(author_id=author_id)

            with pytest.raises(IntegrityError, match="revision was not advanced"):
                async with database.transaction() as session:
                    await session.execute(
                        update(AuthorModel)
                        .where(AuthorModel.id == author_id)
                        .values(status="revoked")
                    )
            with pytest.raises(IntegrityError, match="metadata is immutable"):
                async with database.transaction() as session:
                    await session.execute(
                        update(AuthorModel)
                        .where(AuthorModel.id == author_id)
                        .values(external_subject="github:forged")
                    )
            with pytest.raises(IntegrityError, match="identity is immutable"):
                async with database.transaction() as session:
                    await session.execute(
                        update(AuthorKeyModel)
                        .where(AuthorKeyModel.id == keys[0].id)
                        .values(fingerprint=f"sha256:{'f' * 64}")
                    )
            with pytest.raises(
                IntegrityError,
                match="revocation timestamp is immutable",
            ):
                async with database.transaction() as session:
                    await session.execute(
                        update(AuthorKeyModel)
                        .where(AuthorKeyModel.id == keys[0].id)
                        .values(revoked_at=datetime.now(UTC))
                    )
            with pytest.raises(IntegrityError, match="identity is immutable"):
                async with database.transaction() as session:
                    await session.execute(
                        update(AuthorCredentialModel)
                        .where(AuthorCredentialModel.id == credentials[0].id)
                        .values(credential_hash=f"sha256:{'f' * 64}")
                    )
            with pytest.raises(
                IntegrityError,
                match="revocation timestamp is immutable",
            ):
                async with database.transaction() as session:
                    await session.execute(
                        update(AuthorCredentialModel)
                        .where(AuthorCredentialModel.id == credentials[0].id)
                        .values(revoked_at=datetime.now(UTC))
                    )
            with pytest.raises(IntegrityError, match="append-only"):
                async with database.transaction() as session:
                    await session.execute(
                        delete(AuthorIdentityAuditModel).where(
                            AuthorIdentityAuditModel.id == history[0].id
                        )
                    )
            with pytest.raises(
                IntegrityError,
                match="timestamps are database-generated",
            ):
                async with database.transaction() as session:
                    await session.execute(
                        insert(AuthorIdentityAuditModel).values(
                            id="f" * 32,
                            author_id=author_id,
                            transition_number=1,
                            actor_id="forged-actor",
                            event_type="registered",
                            reason="attempt forged audit timestamp",
                            occurred_at=datetime(2000, 1, 1, tzinfo=UTC),
                            correlation_id="forged-correlation",
                            idempotency_key="forged-idempotency",
                            prior_key_fingerprint=None,
                            new_key_fingerprint=keys[0].fingerprint,
                            prior_credential_id=None,
                            new_credential_id=credentials[0].id,
                        )
                    )
            with pytest.raises(IntegrityError, match="invalid author state"):
                async with database.transaction() as session:
                    await session.execute(
                        insert(AuthorIdentityAuditModel).values(
                            id="e" * 32,
                            author_id=author_id,
                            transition_number=1,
                            actor_id="forged-actor",
                            event_type="key_rotated",
                            reason="attempt forged audit ownership",
                            correlation_id="forged-ownership",
                            idempotency_key="forged-ownership",
                            prior_key_fingerprint=keys[0].fingerprint,
                            new_key_fingerprint=f"sha256:{'e' * 64}",
                            prior_credential_id=None,
                            new_credential_id=None,
                        )
                    )
        finally:
            await database.dispose()

    _run(scenario())


def test_registration_endpoint_fails_closed_and_never_caches_token(
    tmp_path: Path,
) -> None:
    async def request(
        service: AuthorIdentityService,
        *,
        enabled: bool,
        authorization: str | None,
        idempotency_key: str | None = "register-api",
    ) -> HttpxResponse:
        app = create_app(
            author_identity_service=service,
            admin_api_key=_ADMIN_KEY,
            admin_actor_id=_ADMIN_ACTOR,
            author_registration_enabled=enabled,
        )
        headers = {"X-Correlation-ID": "api:register"}
        if authorization is not None:
            headers["Authorization"] = authorization
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://hub.test",
        ) as client:
            return await client.post(
                "/api/authors/register",
                headers=headers,
                json={
                    "external_subject": "github:123",
                    "display_handle": "ori-author",
                    "public_key_b64": _KEY_ONE,
                },
            )

    async def scenario() -> None:
        database, _repository, service, _clock = await _setup(tmp_path)
        try:
            unauthenticated = await request(
                service,
                enabled=True,
                authorization=None,
            )
            wrong_key = await request(
                service,
                enabled=True,
                authorization="Bearer wrong-key",
            )
            oversized_key = await request(
                service,
                enabled=True,
                authorization=f"Bearer {'a' * 4097}",
            )
            disabled = await request(
                service,
                enabled=False,
                authorization=f"Bearer {_ADMIN_KEY}",
            )
            missing_idempotency = await request(
                service,
                enabled=True,
                authorization=f"Bearer {_ADMIN_KEY}",
                idempotency_key=None,
            )
            success = await request(
                service,
                enabled=True,
                authorization=f"Bearer {_ADMIN_KEY}",
            )

            assert unauthenticated.status_code == 401
            assert wrong_key.status_code == 401
            assert oversized_key.status_code == 401
            assert disabled.status_code == 503
            assert missing_idempotency.status_code == 400
            assert success.status_code == 201
            assert success.headers["cache-control"] == "no-store"
            assert success.headers["pragma"] == "no-cache"
            payload = success.json()
            assert payload["credential"]["bearer_token"].startswith("ori_author_v1.")

            duplicate = await request(
                service,
                enabled=True,
                authorization=f"Bearer {_ADMIN_KEY}",
                idempotency_key="register-api-duplicate",
            )
            assert duplicate.status_code == 409
            assert "ori_author_v1" not in duplicate.text
        finally:
            await database.dispose()

    _run(scenario())


def test_author_router_rejects_weak_admin_authority(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, _repository, service, _clock = await _setup(tmp_path)
        try:
            with pytest.raises(ValueError, match="between 32 and 4096"):
                create_app(
                    author_identity_service=service,
                    admin_api_key="weak",
                    admin_actor_id=_ADMIN_ACTOR,
                    author_registration_enabled=False,
                )
            with pytest.raises(ValueError, match="without controls"):
                create_app(
                    author_identity_service=service,
                    admin_api_key=_ADMIN_KEY,
                    admin_actor_id=" \n ",
                    author_registration_enabled=False,
                )
        finally:
            await database.dispose()

    _run(scenario())


def test_admin_endpoints_complete_rotation_and_revocation_lifecycle(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, repository, service, _clock = await _setup(tmp_path)
        app = create_app(
            author_identity_service=service,
            admin_api_key=_ADMIN_KEY,
            admin_actor_id=_ADMIN_ACTOR,
            author_registration_enabled=True,
        )
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="https://hub.test",
            ) as client:
                registered = await client.post(
                    "/api/authors/register",
                    headers=_admin_headers("api-register"),
                    json={
                        "external_subject": "github:123",
                        "display_handle": "ori-author",
                        "public_key_b64": _KEY_ONE,
                    },
                )
                assert registered.status_code == 201
                author_id = registered.json()["author"]["author_id"]
                initial_token = registered.json()["credential"]["bearer_token"]

                key_rotated = await client.post(
                    f"/api/authors/{author_id}/keys/rotate",
                    headers=_admin_headers("api-key-rotate"),
                    json={
                        "public_key_b64": _KEY_TWO,
                        "reason": "scheduled signing-key rotation",
                    },
                )
                assert key_rotated.status_code == 200
                assert key_rotated.json()["author"]["public_key_b64"] == _KEY_TWO

                credential_rotated = await client.post(
                    f"/api/authors/{author_id}/credentials/rotate",
                    headers=_admin_headers("api-credential-rotate"),
                    json={"reason": "scheduled bearer rotation"},
                )
                assert credential_rotated.status_code == 200
                assert credential_rotated.headers["cache-control"] == "no-store"
                rotated_token = credential_rotated.json()["credential"]["bearer_token"]
                with pytest.raises(AuthorAuthenticationError):
                    await service.authenticate(initial_token)
                assert (await service.authenticate(rotated_token)).actor_id == author_id

                revoked = await client.post(
                    f"/api/authors/{author_id}/revoke",
                    headers=_admin_headers("api-author-revoke"),
                    json={"reason": "author account closed"},
                )
                assert revoked.status_code == 200
                assert revoked.json()["author"]["status"] == "revoked"
                with pytest.raises(AuthorAuthenticationError):
                    await service.authenticate(rotated_token)

            history = await repository.get_identity_history(author_id=author_id)
            assert [event.event_type for event in history] == [
                "registered",
                "key_rotated",
                "credential_rotated",
                "author_revoked",
            ]
            assert [event.transition_number for event in history] == [1, 2, 3, 4]
        finally:
            await database.dispose()

    _run(scenario())


def test_author_token_cannot_authorize_admin_and_dependency_returns_context(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, _repository, service, _clock = await _setup(tmp_path)
        try:
            registration = await _register(service)
            token = registration.credential.bearer_token
            app = create_app(
                author_identity_service=service,
                admin_api_key=_ADMIN_KEY,
                admin_actor_id=_ADMIN_ACTOR,
                author_registration_enabled=True,
            )
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="https://hub.test",
            ) as client:
                response = await client.post(
                    f"/api/authors/{registration.author.author_id}/revoke",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Idempotency-Key": "author-cannot-admin",
                        "X-Correlation-ID": "author-cannot-admin",
                    },
                    json={"reason": "must not be authorized"},
                )
            assert response.status_code == 401

            dependency = author_authentication_dependency(service)
            authenticated = await dependency(authorization=f"Bearer {token}")
            assert authenticated.actor_id == registration.author.author_id
            assert authenticated.public_key_b64 == _KEY_ONE
        finally:
            await database.dispose()

    _run(scenario())
