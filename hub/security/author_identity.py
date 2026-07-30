# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed author bootstrap and bearer authentication."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from hub.core.errors import HubError, SignatureVerificationError
from hub.db._identity_repository import AuthorIdentityRepository
from hub.db._models import AuthorModel
from hub.db.session import Database
from hub.security.signing import decode_public_key

AUTHOR_BEARER_KIND: Final = "author_bearer_v1"
AUTHOR_BEARER_PREFIX: Final = "ori_author_v1"
MIN_TOKEN_TTL_SECONDS: Final = 300
MAX_TOKEN_TTL_SECONDS: Final = 90 * 24 * 60 * 60

_LOOKUP_BYTES = 16
_SECRET_BYTES = 32
_TOKEN_PATTERN = re.compile(
    rf"^{AUTHOR_BEARER_PREFIX}\.([A-Za-z0-9_-]{{20,24}})\."
    r"([A-Za-z0-9_-]{40,48})$"
)
_DUMMY_HASH = f"sha256:{'0' * 64}"


class AuthorIdentityError(HubError):
    """Base class for author identity failures."""


class InvalidAuthorIdentityError(AuthorIdentityError):
    """Raised when author bootstrap input is malformed."""


class AuthorAuthenticationError(AuthorIdentityError):
    """Raised for every invalid, expired, or revoked author credential."""


@dataclass(frozen=True)
class AuthorIdentity:
    """Stable non-secret author identity returned by lifecycle operations."""

    author_id: str
    external_subject: str
    display_handle: str
    public_key_b64: str
    status: str
    identity_revision: int


@dataclass(frozen=True)
class AuthenticatedAuthor:
    """Server-authenticated author context for publish operations."""

    actor_id: str
    external_subject: str
    display_handle: str
    public_key_b64: str
    credential_id: str


@dataclass(frozen=True, repr=False)
class IssuedAuthorCredential:
    """A bearer credential disclosed only by registration or rotation."""

    bearer_token: str
    expires_at: datetime

    def __repr__(self) -> str:
        return (
            "IssuedAuthorCredential("
            "bearer_token=<redacted>, "
            f"expires_at={self.expires_at!r})"
        )


@dataclass(frozen=True, repr=False)
class AuthorRegistration:
    """One-time registration result containing the initial bearer credential."""

    author: AuthorIdentity
    credential: IssuedAuthorCredential

    def __repr__(self) -> str:
        return f"AuthorRegistration(author={self.author!r}, credential=<redacted>)"


def _clean_text(value: str, *, field_name: str, maximum: int) -> str:
    clean_value = value.strip()
    if not clean_value:
        raise InvalidAuthorIdentityError(f"{field_name} must not be empty")
    if len(clean_value) > maximum:
        raise InvalidAuthorIdentityError(
            f"{field_name} must not exceed {maximum} characters"
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in clean_value):
        raise InvalidAuthorIdentityError(
            f"{field_name} must not contain control characters"
        )
    return clean_value


def _key_identity(public_key_b64: str) -> tuple[str, str]:
    clean_key = _clean_text(
        public_key_b64,
        field_name="public_key_b64",
        maximum=255,
    )
    try:
        public_key_bytes = decode_public_key(clean_key)
    except SignatureVerificationError as exc:
        raise InvalidAuthorIdentityError(
            "public_key_b64 is not a valid Ed25519 key"
        ) from exc
    return clean_key, f"sha256:{hashlib.sha256(public_key_bytes).hexdigest()}"


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _issue_token(now: datetime, *, ttl_seconds: int) -> tuple[str, str, str, datetime]:
    lookup_id = secrets.token_urlsafe(_LOOKUP_BYTES)
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    bearer_token = f"{AUTHOR_BEARER_PREFIX}.{lookup_id}.{secret}"
    credential_hash = (
        f"sha256:{hashlib.sha256(bearer_token.encode('ascii')).hexdigest()}"
    )
    return (
        bearer_token,
        lookup_id,
        credential_hash,
        _as_utc(now) + timedelta(seconds=ttl_seconds),
    )


def _parse_token(bearer_token: str) -> str:
    match = _TOKEN_PATTERN.fullmatch(bearer_token)
    if match is None:
        raise AuthorAuthenticationError("author authentication failed")
    return match.group(1)


def _identity(author: AuthorModel) -> AuthorIdentity:
    return AuthorIdentity(
        author_id=author.id,
        external_subject=author.external_subject,
        display_handle=author.display_handle,
        public_key_b64=author.public_key_b64,
        status=author.status,
        identity_revision=author.identity_revision,
    )


class AuthorIdentityService:
    """Issue, verify, rotate, and revoke author identities."""

    def __init__(
        self,
        database: Database,
        *,
        token_ttl_seconds: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not MIN_TOKEN_TTL_SECONDS <= token_ttl_seconds <= MAX_TOKEN_TTL_SECONDS:
            raise ValueError(
                "token_ttl_seconds must be between "
                f"{MIN_TOKEN_TTL_SECONDS} and {MAX_TOKEN_TTL_SECONDS}"
            )
        self._repository = AuthorIdentityRepository(database)
        self._token_ttl_seconds = token_ttl_seconds
        self._clock = clock or (lambda: datetime.now(UTC))

    async def register(
        self,
        *,
        external_subject: str,
        display_handle: str,
        public_key_b64: str,
        authenticated_actor_id: str,
        correlation_id: str,
        idempotency_key: str,
    ) -> AuthorRegistration:
        clean_key, fingerprint = _key_identity(public_key_b64)
        now = _as_utc(self._clock())
        token, lookup_id, credential_hash, expires_at = _issue_token(
            now,
            ttl_seconds=self._token_ttl_seconds,
        )
        author, _credential = await self._repository.register_author(
            external_subject=_clean_text(
                external_subject,
                field_name="external_subject",
                maximum=255,
            ),
            display_handle=_clean_text(
                display_handle,
                field_name="display_handle",
                maximum=255,
            ),
            public_key_b64=clean_key,
            key_fingerprint=fingerprint,
            credential_kind=AUTHOR_BEARER_KIND,
            credential_lookup_id=lookup_id,
            credential_hash=credential_hash,
            credential_expires_at=expires_at,
            authenticated_actor_id=_clean_text(
                authenticated_actor_id,
                field_name="authenticated_actor_id",
                maximum=255,
            ),
            reason="author registration",
            correlation_id=_clean_text(
                correlation_id,
                field_name="correlation_id",
                maximum=255,
            ),
            idempotency_key=_clean_text(
                idempotency_key,
                field_name="idempotency_key",
                maximum=255,
            ),
        )
        return AuthorRegistration(
            author=_identity(author),
            credential=IssuedAuthorCredential(
                bearer_token=token,
                expires_at=expires_at,
            ),
        )

    async def rotate_key(
        self,
        *,
        author_id: str,
        public_key_b64: str,
        authenticated_actor_id: str,
        reason: str,
        correlation_id: str,
        idempotency_key: str,
    ) -> AuthorIdentity:
        clean_key, fingerprint = _key_identity(public_key_b64)
        author = await self._repository.rotate_key(
            author_id=_clean_text(
                author_id,
                field_name="author_id",
                maximum=32,
            ),
            public_key_b64=clean_key,
            key_fingerprint=fingerprint,
            authenticated_actor_id=_clean_text(
                authenticated_actor_id,
                field_name="authenticated_actor_id",
                maximum=255,
            ),
            reason=_clean_text(reason, field_name="reason", maximum=1024),
            correlation_id=_clean_text(
                correlation_id,
                field_name="correlation_id",
                maximum=255,
            ),
            idempotency_key=_clean_text(
                idempotency_key,
                field_name="idempotency_key",
                maximum=255,
            ),
        )
        return _identity(author)

    async def rotate_credential(
        self,
        *,
        author_id: str,
        authenticated_actor_id: str,
        reason: str,
        correlation_id: str,
        idempotency_key: str,
    ) -> AuthorRegistration:
        now = _as_utc(self._clock())
        token, lookup_id, credential_hash, expires_at = _issue_token(
            now,
            ttl_seconds=self._token_ttl_seconds,
        )
        author, _credential = await self._repository.rotate_credential(
            author_id=_clean_text(
                author_id,
                field_name="author_id",
                maximum=32,
            ),
            credential_kind=AUTHOR_BEARER_KIND,
            credential_lookup_id=lookup_id,
            credential_hash=credential_hash,
            credential_expires_at=expires_at,
            authenticated_actor_id=_clean_text(
                authenticated_actor_id,
                field_name="authenticated_actor_id",
                maximum=255,
            ),
            reason=_clean_text(reason, field_name="reason", maximum=1024),
            correlation_id=_clean_text(
                correlation_id,
                field_name="correlation_id",
                maximum=255,
            ),
            idempotency_key=_clean_text(
                idempotency_key,
                field_name="idempotency_key",
                maximum=255,
            ),
        )
        return AuthorRegistration(
            author=_identity(author),
            credential=IssuedAuthorCredential(
                bearer_token=token,
                expires_at=expires_at,
            ),
        )

    async def revoke(
        self,
        *,
        author_id: str,
        authenticated_actor_id: str,
        reason: str,
        correlation_id: str,
        idempotency_key: str,
    ) -> AuthorIdentity:
        author = await self._repository.revoke_author(
            author_id=_clean_text(
                author_id,
                field_name="author_id",
                maximum=32,
            ),
            credential_kind=AUTHOR_BEARER_KIND,
            authenticated_actor_id=_clean_text(
                authenticated_actor_id,
                field_name="authenticated_actor_id",
                maximum=255,
            ),
            reason=_clean_text(reason, field_name="reason", maximum=1024),
            correlation_id=_clean_text(
                correlation_id,
                field_name="correlation_id",
                maximum=255,
            ),
            idempotency_key=_clean_text(
                idempotency_key,
                field_name="idempotency_key",
                maximum=255,
            ),
        )
        return _identity(author)

    async def authenticate(self, bearer_token: str) -> AuthenticatedAuthor:
        lookup_id = _parse_token(bearer_token)
        authentication_record = await self._repository.find_authentication_record(
            lookup_id=lookup_id
        )
        supplied_hash = (
            f"sha256:{hashlib.sha256(bearer_token.encode('ascii')).hexdigest()}"
        )
        expected_hash = (
            authentication_record[0].credential_hash
            if authentication_record is not None
            else _DUMMY_HASH
        )
        hash_matches = hmac.compare_digest(supplied_hash, expected_hash)
        if authentication_record is None:
            raise AuthorAuthenticationError("author authentication failed")

        credential, author = authentication_record
        now = _as_utc(self._clock())
        expires_at = (
            _as_utc(credential.expires_at) if credential.expires_at is not None else now
        )
        if (
            not hash_matches
            or credential.kind != AUTHOR_BEARER_KIND
            or credential.status != "active"
            or author.status != "active"
            or expires_at <= now
        ):
            raise AuthorAuthenticationError("author authentication failed")

        return AuthenticatedAuthor(
            actor_id=author.id,
            external_subject=author.external_subject,
            display_handle=author.display_handle,
            public_key_b64=author.public_key_b64,
            credential_id=credential.id,
        )
