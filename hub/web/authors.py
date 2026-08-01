# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Admin-gated author identity routes and publish authentication dependency."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status

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

_AUTHENTICATION_FAILED = "authentication failed"
_MAX_BEARER_LENGTH = 4096


@dataclass(frozen=True)
class RegisterAuthorRequest:
    external_subject: str
    display_handle: str
    public_key_b64: str


@dataclass(frozen=True)
class RotateAuthorKeyRequest:
    public_key_b64: str
    reason: str


@dataclass(frozen=True)
class AuthorLifecycleRequest:
    reason: str


def _bearer_value(authorization: str | None) -> str:
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_AUTHENTICATION_FAILED,
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, separator, value = authorization.partition(" ")
    if (
        scheme != "Bearer"
        or separator != " "
        or not value
        or " " in value
        or len(value) > _MAX_BEARER_LENGTH
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_AUTHENTICATION_FAILED,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return value


def _credentials_match(supplied: str, expected: str) -> bool:
    supplied_digest = hashlib.sha256(supplied.encode("utf-8")).digest()
    expected_digest = hashlib.sha256(expected.encode("utf-8")).digest()
    return hmac.compare_digest(supplied_digest, expected_digest)


def _required_header(value: str | None, *, name: str) -> str:
    if value is None or not value.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{name} header is required",
        )
    if len(value) > 255:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{name} header is too long",
        )
    return value.strip()


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _author_payload(author: AuthorIdentity) -> dict[str, object]:
    return asdict(author)


def _registration_payload(registration: AuthorRegistration) -> dict[str, object]:
    return {
        "author": _author_payload(registration.author),
        "credential": {
            "bearer_token": registration.credential.bearer_token,
            "token_type": "Bearer",
            "expires_at": registration.credential.expires_at,
        },
    }


def _raise_http_error(
    exc: InvalidAuthorIdentityError
    | RecordNotFoundError
    | PersistenceConflictError
    | InvalidStateTransitionError,
) -> NoReturn:
    if isinstance(exc, InvalidAuthorIdentityError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    if isinstance(exc, RecordNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="author was not found",
        ) from exc
    if isinstance(exc, (PersistenceConflictError, InvalidStateTransitionError)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="author identity operation conflicts with current state",
        ) from exc
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="unhandled author identity error",
    ) from exc


def admin_authentication_dependency(
    *, admin_api_key: str, admin_actor_id: str
) -> Callable[..., Awaitable[str]]:
    """Return the configured admin bearer authentication dependency."""

    if (
        not 32 <= len(admin_api_key) <= _MAX_BEARER_LENGTH
        or not admin_api_key.isascii()
        or not admin_api_key.isprintable()
        or any(character.isspace() for character in admin_api_key)
    ):
        raise ValueError(
            "admin_api_key must be a printable ASCII bearer value between "
            "32 and 4096 characters"
        )
    clean_admin_actor_id = admin_actor_id.strip()
    if (
        not clean_admin_actor_id
        or len(clean_admin_actor_id) > 255
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in clean_admin_actor_id
        )
    ):
        raise ValueError(
            "admin_actor_id must be at most 255 characters without controls"
        )

    async def require_admin(
        authorization: Annotated[str | None, Header()] = None,
    ) -> str:
        supplied_key = _bearer_value(authorization)
        if not _credentials_match(supplied_key, admin_api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_AUTHENTICATION_FAILED,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return clean_admin_actor_id

    return require_admin


def create_author_router(
    service: AuthorIdentityService,
    *,
    admin_api_key: str,
    admin_actor_id: str,
    registration_enabled: bool,
) -> APIRouter:
    """Build author routes around explicit trusted server configuration."""

    router = APIRouter(prefix="/api/authors", tags=["authors"])
    require_admin = admin_authentication_dependency(
        admin_api_key=admin_api_key, admin_actor_id=admin_actor_id
    )

    @router.post("/register", status_code=status.HTTP_201_CREATED)
    async def register_author(
        request: RegisterAuthorRequest,
        response: Response,
        actor_id: str = Depends(require_admin),
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        correlation_id: Annotated[str | None, Header(alias="X-Correlation-ID")] = None,
    ) -> dict[str, object]:
        if not registration_enabled:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="author registration is disabled",
            )
        _no_store(response)
        try:
            registration = await service.register(
                external_subject=request.external_subject,
                display_handle=request.display_handle,
                public_key_b64=request.public_key_b64,
                authenticated_actor_id=actor_id,
                correlation_id=_required_header(
                    correlation_id, name="X-Correlation-ID"
                ),
                idempotency_key=_required_header(
                    idempotency_key, name="Idempotency-Key"
                ),
            )
        except (
            InvalidAuthorIdentityError,
            RecordNotFoundError,
            PersistenceConflictError,
            InvalidStateTransitionError,
        ) as exc:
            _raise_http_error(exc)
        return _registration_payload(registration)

    @router.post("/{author_id}/keys/rotate")
    async def rotate_author_key(
        author_id: str,
        request: RotateAuthorKeyRequest,
        response: Response,
        actor_id: str = Depends(require_admin),
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        correlation_id: Annotated[str | None, Header(alias="X-Correlation-ID")] = None,
    ) -> dict[str, object]:
        _no_store(response)
        try:
            author = await service.rotate_key(
                author_id=author_id,
                public_key_b64=request.public_key_b64,
                authenticated_actor_id=actor_id,
                reason=request.reason,
                correlation_id=_required_header(
                    correlation_id, name="X-Correlation-ID"
                ),
                idempotency_key=_required_header(
                    idempotency_key, name="Idempotency-Key"
                ),
            )
        except (
            InvalidAuthorIdentityError,
            RecordNotFoundError,
            PersistenceConflictError,
            InvalidStateTransitionError,
        ) as exc:
            _raise_http_error(exc)
        return {"author": _author_payload(author)}

    @router.post("/{author_id}/credentials/rotate")
    async def rotate_author_credential(
        author_id: str,
        request: AuthorLifecycleRequest,
        response: Response,
        actor_id: str = Depends(require_admin),
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        correlation_id: Annotated[str | None, Header(alias="X-Correlation-ID")] = None,
    ) -> dict[str, object]:
        _no_store(response)
        try:
            registration = await service.rotate_credential(
                author_id=author_id,
                authenticated_actor_id=actor_id,
                reason=request.reason,
                correlation_id=_required_header(
                    correlation_id, name="X-Correlation-ID"
                ),
                idempotency_key=_required_header(
                    idempotency_key, name="Idempotency-Key"
                ),
            )
        except (
            InvalidAuthorIdentityError,
            RecordNotFoundError,
            PersistenceConflictError,
            InvalidStateTransitionError,
        ) as exc:
            _raise_http_error(exc)
        return _registration_payload(registration)

    @router.post("/{author_id}/revoke")
    async def revoke_author(
        author_id: str,
        request: AuthorLifecycleRequest,
        response: Response,
        actor_id: str = Depends(require_admin),
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        correlation_id: Annotated[str | None, Header(alias="X-Correlation-ID")] = None,
    ) -> dict[str, object]:
        _no_store(response)
        try:
            author = await service.revoke(
                author_id=author_id,
                authenticated_actor_id=actor_id,
                reason=request.reason,
                correlation_id=_required_header(
                    correlation_id, name="X-Correlation-ID"
                ),
                idempotency_key=_required_header(
                    idempotency_key, name="Idempotency-Key"
                ),
            )
        except (
            InvalidAuthorIdentityError,
            RecordNotFoundError,
            PersistenceConflictError,
            InvalidStateTransitionError,
        ) as exc:
            _raise_http_error(exc)
        return {"author": _author_payload(author)}

    return router


def author_authentication_dependency(
    service: AuthorIdentityService,
) -> Callable[..., Awaitable[AuthenticatedAuthor]]:
    """Return a FastAPI dependency that yields stable authenticated context."""

    async def require_author(
        authorization: Annotated[str | None, Header()] = None,
    ) -> AuthenticatedAuthor:
        bearer_token = _bearer_value(authorization)
        try:
            return await service.authenticate(bearer_token)
        except AuthorAuthenticationError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_AUTHENTICATION_FAILED,
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

    return require_author
