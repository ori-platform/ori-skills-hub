# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Internal atomic persistence for authenticated author identities."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from hub.db._models import (
    AuthorCredentialModel,
    AuthorIdentityAuditModel,
    AuthorKeyModel,
    AuthorModel,
    new_record_id,
)
from hub.db.errors import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    RecordNotFoundError,
)
from hub.db.session import Database


def _required(value: str, field_name: str) -> str:
    clean_value = value.strip()
    if not clean_value:
        raise ValueError(f"{field_name} must not be empty")
    return clean_value


def _sha256_digest(value: str, field_name: str) -> str:
    clean_value = _required(value, field_name)
    prefix, separator, hexadecimal = clean_value.partition(":")
    if (
        prefix != "sha256"
        or separator != ":"
        or len(hexadecimal) != 64
        or any(character not in "0123456789abcdef" for character in hexadecimal)
    ):
        raise ValueError(f"{field_name} must be a lowercase sha256 digest")
    return clean_value


def _conflict(operation: str) -> PersistenceConflictError:
    return PersistenceConflictError(
        f"{operation} conflicts with an existing durable identity record"
    )


class AuthorIdentityRepository:
    """Persist identity changes and their audit records in one transaction."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def register_author(
        self,
        *,
        external_subject: str,
        display_handle: str,
        public_key_b64: str,
        key_fingerprint: str,
        credential_kind: str,
        credential_lookup_id: str,
        credential_hash: str,
        credential_expires_at: datetime,
        authenticated_actor_id: str,
        reason: str,
        correlation_id: str,
        idempotency_key: str,
    ) -> tuple[AuthorModel, AuthorCredentialModel]:
        actor_id = _required(authenticated_actor_id, "authenticated_actor_id")
        fingerprint = _sha256_digest(key_fingerprint, "key_fingerprint")
        author = AuthorModel(
            id=new_record_id(),
            external_subject=_required(external_subject, "external_subject"),
            display_handle=_required(display_handle, "display_handle"),
            public_key_b64=_required(public_key_b64, "public_key_b64"),
            identity_revision=1,
        )
        key = AuthorKeyModel(
            id=new_record_id(),
            author_id=author.id,
            public_key_b64=author.public_key_b64,
            fingerprint=fingerprint,
        )
        credential = AuthorCredentialModel(
            id=new_record_id(),
            author_id=author.id,
            kind=_required(credential_kind, "credential_kind"),
            lookup_id=_required(credential_lookup_id, "credential_lookup_id"),
            credential_hash=_sha256_digest(credential_hash, "credential_hash"),
            expires_at=credential_expires_at,
        )
        audit = AuthorIdentityAuditModel(
            id=new_record_id(),
            author_id=author.id,
            transition_number=1,
            actor_id=actor_id,
            event_type="registered",
            reason=_required(reason, "reason"),
            correlation_id=_required(correlation_id, "correlation_id"),
            idempotency_key=_required(idempotency_key, "idempotency_key"),
            prior_key_fingerprint=None,
            new_key_fingerprint=fingerprint,
            prior_credential_id=None,
            new_credential_id=credential.id,
        )

        try:
            async with self._database.transaction() as session:
                session.add(author)
                await session.flush()
                session.add_all([key, credential])
                await session.flush()
                session.add(audit)
                await session.flush()
                await session.refresh(author)
                await session.refresh(credential)
        except IntegrityError as exc:
            raise _conflict("author registration") from exc
        return author, credential

    async def rotate_key(
        self,
        *,
        author_id: str,
        public_key_b64: str,
        key_fingerprint: str,
        expected_identity_revision: int,
        authenticated_actor_id: str,
        reason: str,
        correlation_id: str,
        idempotency_key: str,
    ) -> AuthorModel:
        clean_author_id = _required(author_id, "author_id")
        actor_id = _required(authenticated_actor_id, "authenticated_actor_id")
        clean_public_key = _required(public_key_b64, "public_key_b64")
        fingerprint = _sha256_digest(key_fingerprint, "key_fingerprint")
        clean_reason = _required(reason, "reason")
        clean_correlation_id = _required(correlation_id, "correlation_id")
        clean_idempotency_key = _required(idempotency_key, "idempotency_key")
        if (
            type(expected_identity_revision) is not int
            or expected_identity_revision < 1
        ):
            raise ValueError("expected_identity_revision must be a positive integer")

        try:
            async with self._database.transaction() as session:
                author = await self._get_active_author(
                    session=session, author_id=clean_author_id
                )
                if author.identity_revision != expected_identity_revision:
                    raise InvalidStateTransitionError(
                        "author identity revision no longer matches the request"
                    )
                current_key = await self._get_active_key(
                    session=session, author_id=author.id
                )
                if current_key.fingerprint == fingerprint:
                    raise InvalidStateTransitionError(
                        "new author key must differ from the active key"
                    )

                session.add(
                    AuthorKeyModel(
                        id=new_record_id(),
                        author_id=author.id,
                        public_key_b64=clean_public_key,
                        fingerprint=fingerprint,
                    )
                )
                await session.flush()
                session.add(
                    AuthorIdentityAuditModel(
                        id=new_record_id(),
                        author_id=author.id,
                        transition_number=author.identity_revision + 1,
                        actor_id=actor_id,
                        event_type="key_rotated",
                        reason=clean_reason,
                        correlation_id=clean_correlation_id,
                        idempotency_key=clean_idempotency_key,
                        prior_key_fingerprint=current_key.fingerprint,
                        new_key_fingerprint=fingerprint,
                        prior_credential_id=None,
                        new_credential_id=None,
                    )
                )
                await session.flush()
                await session.refresh(author)
                updated_author = author
        except IntegrityError as exc:
            raise _conflict("author key rotation") from exc
        return updated_author

    async def rotate_credential(
        self,
        *,
        author_id: str,
        credential_kind: str,
        credential_lookup_id: str,
        credential_hash: str,
        credential_expires_at: datetime,
        expected_identity_revision: int,
        authenticated_actor_id: str,
        reason: str,
        correlation_id: str,
        idempotency_key: str,
    ) -> tuple[AuthorModel, AuthorCredentialModel]:
        clean_author_id = _required(author_id, "author_id")
        clean_kind = _required(credential_kind, "credential_kind")
        actor_id = _required(authenticated_actor_id, "authenticated_actor_id")
        clean_reason = _required(reason, "reason")
        clean_correlation_id = _required(correlation_id, "correlation_id")
        clean_idempotency_key = _required(idempotency_key, "idempotency_key")
        if (
            type(expected_identity_revision) is not int
            or expected_identity_revision < 1
        ):
            raise ValueError("expected_identity_revision must be a positive integer")
        credential = AuthorCredentialModel(
            id=new_record_id(),
            author_id=clean_author_id,
            kind=clean_kind,
            lookup_id=_required(credential_lookup_id, "credential_lookup_id"),
            credential_hash=_sha256_digest(credential_hash, "credential_hash"),
            expires_at=credential_expires_at,
        )

        try:
            async with self._database.transaction() as session:
                author = await self._get_active_author(
                    session=session, author_id=clean_author_id
                )
                if author.identity_revision != expected_identity_revision:
                    raise InvalidStateTransitionError(
                        "author identity revision no longer matches the request"
                    )
                current_credential = await self._get_active_credential(
                    session=session,
                    author_id=author.id,
                    credential_kind=clean_kind,
                )
                session.add(credential)
                await session.flush()
                session.add(
                    AuthorIdentityAuditModel(
                        id=new_record_id(),
                        author_id=author.id,
                        transition_number=author.identity_revision + 1,
                        actor_id=actor_id,
                        event_type="credential_rotated",
                        reason=clean_reason,
                        correlation_id=clean_correlation_id,
                        idempotency_key=clean_idempotency_key,
                        prior_key_fingerprint=None,
                        new_key_fingerprint=None,
                        prior_credential_id=current_credential.id,
                        new_credential_id=credential.id,
                    )
                )
                await session.flush()
                await session.refresh(author)
                await session.refresh(credential)
                updated_author = author
        except IntegrityError as exc:
            raise _conflict("author credential rotation") from exc
        return updated_author, credential

    async def revoke_author(
        self,
        *,
        author_id: str,
        credential_kind: str,
        authenticated_actor_id: str,
        reason: str,
        correlation_id: str,
        idempotency_key: str,
    ) -> AuthorModel:
        clean_author_id = _required(author_id, "author_id")
        clean_kind = _required(credential_kind, "credential_kind")
        actor_id = _required(authenticated_actor_id, "authenticated_actor_id")
        clean_reason = _required(reason, "reason")
        clean_correlation_id = _required(correlation_id, "correlation_id")
        clean_idempotency_key = _required(idempotency_key, "idempotency_key")

        try:
            async with self._database.transaction() as session:
                author = await self._get_active_author(
                    session=session, author_id=clean_author_id
                )
                current_key = await self._get_active_key(
                    session=session, author_id=author.id
                )
                current_credential = await self._find_active_credential(
                    session=session,
                    author_id=author.id,
                    credential_kind=clean_kind,
                )
                session.add(
                    AuthorIdentityAuditModel(
                        id=new_record_id(),
                        author_id=author.id,
                        transition_number=author.identity_revision + 1,
                        actor_id=actor_id,
                        event_type="author_revoked",
                        reason=clean_reason,
                        correlation_id=clean_correlation_id,
                        idempotency_key=clean_idempotency_key,
                        prior_key_fingerprint=current_key.fingerprint,
                        new_key_fingerprint=None,
                        prior_credential_id=(
                            current_credential.id
                            if current_credential is not None
                            else None
                        ),
                        new_credential_id=None,
                    )
                )
                await session.flush()
                await session.refresh(author)
                updated_author = author
        except IntegrityError as exc:
            raise _conflict("author revocation") from exc
        return updated_author

    async def find_authentication_record(
        self, *, lookup_id: str
    ) -> tuple[AuthorCredentialModel, AuthorModel] | None:
        async with self._database.transaction() as session:
            result = await session.execute(
                select(AuthorCredentialModel, AuthorModel)
                .join(AuthorModel, AuthorModel.id == AuthorCredentialModel.author_id)
                .where(
                    AuthorCredentialModel.lookup_id == _required(lookup_id, "lookup_id")
                )
            )
            row = result.one_or_none()
            if row is None:
                return None
            credential, author = row
            return credential, author

    async def get_author(self, *, author_id: str) -> AuthorModel:
        async with self._database.transaction() as session:
            result = await session.scalars(
                select(AuthorModel).where(
                    AuthorModel.id == _required(author_id, "author_id")
                )
            )
            author = result.one_or_none()
            if author is None:
                raise RecordNotFoundError("author was not found")
            return author

    async def get_identity_history(
        self, *, author_id: str
    ) -> list[AuthorIdentityAuditModel]:
        async with self._database.transaction() as session:
            result = await session.scalars(
                select(AuthorIdentityAuditModel)
                .where(
                    AuthorIdentityAuditModel.author_id
                    == _required(author_id, "author_id")
                )
                .order_by(AuthorIdentityAuditModel.transition_number)
            )
            return list(result)

    async def get_key_history(self, *, author_id: str) -> list[AuthorKeyModel]:
        async with self._database.transaction() as session:
            result = await session.scalars(
                select(AuthorKeyModel)
                .where(AuthorKeyModel.author_id == _required(author_id, "author_id"))
                .order_by(AuthorKeyModel.created_at, AuthorKeyModel.id)
            )
            return list(result)

    async def get_credentials(self, *, author_id: str) -> list[AuthorCredentialModel]:
        async with self._database.transaction() as session:
            result = await session.scalars(
                select(AuthorCredentialModel)
                .where(
                    AuthorCredentialModel.author_id == _required(author_id, "author_id")
                )
                .order_by(
                    AuthorCredentialModel.created_at,
                    AuthorCredentialModel.id,
                )
            )
            return list(result)

    async def _get_active_author(
        self, *, session: AsyncSession, author_id: str
    ) -> AuthorModel:
        result = await session.scalars(
            select(AuthorModel).where(AuthorModel.id == author_id)
        )
        author = result.one_or_none()
        if author is None:
            raise RecordNotFoundError("author was not found")
        if author.status != "active":
            raise InvalidStateTransitionError("author identity is revoked")
        return author

    async def _get_active_key(
        self, *, session: AsyncSession, author_id: str
    ) -> AuthorKeyModel:
        result = await session.scalars(
            select(AuthorKeyModel).where(
                AuthorKeyModel.author_id == author_id,
                AuthorKeyModel.status == "active",
            )
        )
        key = result.one_or_none()
        if key is None:
            raise InvalidStateTransitionError("author has no active signing key")
        return key

    async def _get_active_credential(
        self,
        *,
        session: AsyncSession,
        author_id: str,
        credential_kind: str,
    ) -> AuthorCredentialModel:
        credential = await self._find_active_credential(
            session=session,
            author_id=author_id,
            credential_kind=credential_kind,
        )
        if credential is None:
            raise InvalidStateTransitionError("author has no active bearer credential")
        return credential

    async def _find_active_credential(
        self,
        *,
        session: AsyncSession,
        author_id: str,
        credential_kind: str,
    ) -> AuthorCredentialModel | None:
        result = await session.scalars(
            select(AuthorCredentialModel).where(
                AuthorCredentialModel.author_id == author_id,
                AuthorCredentialModel.kind == credential_kind,
                AuthorCredentialModel.status == "active",
            )
        )
        return result.one_or_none()
