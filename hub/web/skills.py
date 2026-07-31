# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Publish routes for author-signed community skill uploads."""

from __future__ import annotations

from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from hub.core.errors import (
    PublishAuthorMismatchError,
    PublishConflictError,
    PublishReplayError,
    SignatureVerificationError,
    SkillValidationError,
    TarballError,
)
from hub.core.models import PublishResult
from hub.core.publish import Scanner, publish_skill
from hub.db.errors import PersistenceConflictError
from hub.db.repository import HubRepository
from hub.security.author_identity import AuthenticatedAuthor, AuthorIdentityService
from hub.security.hub_keys import HubSigningKeys
from hub.security.signing import parse_detached_metadata_json
from hub.storage.objects import ContentAddressedStorage
from hub.storage.tarball import DEFAULT_TARBALL_LIMITS, TarballLimits
from hub.web.authors import author_authentication_dependency

_PUBLISH_REASON = "skill publication"


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


async def _bounded_upload_bytes(request: Request, *, limit: int) -> bytes:
    """Read the request body while enforcing the raw archive limit."""

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="upload exceeds the archive size limit",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _raise_http_error(
    exc: SignatureVerificationError
    | TarballError
    | SkillValidationError
    | PublishAuthorMismatchError
    | PublishReplayError
    | PublishConflictError
    | PersistenceConflictError,
) -> NoReturn:
    if isinstance(exc, (PublishReplayError, PublishConflictError)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    if isinstance(exc, PersistenceConflictError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="publication conflicts with an existing durable record",
        ) from exc
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail=str(exc),
    ) from exc


def _publish_payload(result: PublishResult) -> dict[str, object]:
    return {
        "name": result.name,
        "version": result.version,
        "status": result.status.value,
        "artifact_digest": result.artifact_digest,
        "manifest_digest": result.manifest_digest,
    }


def create_skill_router(
    author_identity_service: AuthorIdentityService,
    *,
    repository: HubRepository,
    storage: ContentAddressedStorage,
    signing_keys: HubSigningKeys,
    scanner: Scanner,
    tarball_limits: TarballLimits = DEFAULT_TARBALL_LIMITS,
) -> APIRouter:
    """Build publish routes around explicit trusted server components."""

    router = APIRouter(prefix="/api/skills", tags=["skills"])
    require_author = author_authentication_dependency(author_identity_service)

    @router.post("", status_code=status.HTTP_201_CREATED)
    async def publish(
        request: Request,
        actor: AuthenticatedAuthor = Depends(require_author),  # noqa: B008
        x_author_artifact_metadata: Annotated[
            str | None, Header(alias="X-Author-Artifact-Metadata")
        ] = None,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        correlation_id: Annotated[str | None, Header(alias="X-Correlation-ID")] = None,
    ) -> dict[str, object]:
        upload_bytes = await _bounded_upload_bytes(
            request, limit=tarball_limits.max_archive_bytes
        )
        try:
            author_metadata = parse_detached_metadata_json(
                _required_header(
                    x_author_artifact_metadata,
                    name="X-Author-Artifact-Metadata",
                )
            )
            result = await publish_skill(
                upload_bytes=upload_bytes,
                author_metadata=author_metadata,
                actor=actor,
                repository=repository,
                storage=storage,
                signing_keys=signing_keys,
                scanner=scanner,
                reason=_PUBLISH_REASON,
                correlation_id=_required_header(
                    correlation_id, name="X-Correlation-ID"
                ),
                idempotency_key=_required_header(
                    idempotency_key, name="Idempotency-Key"
                ),
                tarball_limits=tarball_limits,
            )
        except (
            SignatureVerificationError,
            TarballError,
            SkillValidationError,
            PublishAuthorMismatchError,
            PublishReplayError,
            PublishConflictError,
            PersistenceConflictError,
        ) as exc:
            _raise_http_error(exc)
        return _publish_payload(result)

    return router
