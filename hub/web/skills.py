# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Publish routes for author-signed community skill uploads."""

from __future__ import annotations

import json
from typing import Annotated, NoReturn
from urllib.parse import quote

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from hub.core.errors import (
    PublishAuthorMismatchError,
    PublishConflictError,
    PublishReplayError,
    SignatureVerificationError,
    SkillValidationError,
    StorageIntegrityError,
    TarballError,
)
from hub.core.models import PublishResult
from hub.core.publish import Scanner, publish_skill
from hub.db.errors import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    RecordNotFoundError,
)
from hub.db.repository import HubRepository, PublicSkillVersion
from hub.security.author_identity import AuthenticatedAuthor, AuthorIdentityService
from hub.security.hub_keys import HubSigningKeys
from hub.security.signing import (
    ARTIFACT_SIGNATURE_SCHEMA,
    MAX_DETACHED_METADATA_BYTES,
    parse_detached_metadata_json,
)
from hub.storage.objects import ContentAddressedStorage
from hub.storage.tarball import DEFAULT_TARBALL_LIMITS, TarballLimits
from hub.web.authors import author_authentication_dependency

_PUBLISH_REASON = "skill publication"
_MAX_REQUEST_HEADER_CHARS = 255
_PUBLIC_LIST_LIMIT = 100
_HUB_ARTIFACT_METADATA_HEADER = "X-Hub-Artifact-Metadata"


def _required_request_header(value: str | None, *, name: str) -> str:
    if value is None or not value.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{name} header is required",
        )
    if len(value) > _MAX_REQUEST_HEADER_CHARS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{name} header is too long",
        )
    return value.strip()


def _required_metadata_header(value: str | None) -> str:
    if value is None or not value.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Author-Artifact-Metadata header is required",
        )
    return value


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


def _public_skill_payload(skill: PublicSkillVersion) -> dict[str, object]:
    return {
        "name": skill.name,
        "version": skill.version,
        "author": skill.author,
        "downloads": skill.downloads,
        "published_at": skill.created_at.isoformat(),
        "byte_size": skill.byte_size,
    }


def _not_found() -> NoReturn:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="skill was not found",
    )


def _hub_artifact_metadata_header(skill: PublicSkillVersion) -> str:
    metadata = json.dumps(
        {
            "artifact_sha256": skill.artifact_digest,
            "schema": ARTIFACT_SIGNATURE_SCHEMA,
            "signature": skill.artifact_signature,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(metadata.encode("utf-8")) > MAX_DETACHED_METADATA_BYTES:
        raise RuntimeError("Hub artifact metadata exceeds its response header limit")
    return metadata


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

    @router.get("")
    async def list_skills(
        limit: Annotated[int, Query(ge=1, le=_PUBLIC_LIST_LIMIT)] = 50,
    ) -> dict[str, object]:
        skills = await repository.list_listed_skills(limit=limit)
        return {"skills": [_public_skill_payload(skill) for skill in skills]}

    @router.get("/{name}")
    async def skill_detail(name: str) -> dict[str, object]:
        versions = await repository.list_listed_versions(name=name)
        if not versions:
            _not_found()
        return {
            "name": versions[0].name,
            "versions": [_public_skill_payload(skill) for skill in versions],
        }

    @router.get("/{name}/download")
    async def download_skill(
        name: str,
        version: str | None = Query(default=None),
    ) -> StreamingResponse:
        if version is None or not version.strip():
            _not_found()
        try:
            skill = await repository.get_listed_skill(name=name, version=version)
            artifact_bytes = storage.read(skill.artifact_digest)
            await repository.increment_downloads(name=skill.name, version=skill.version)
        except (RecordNotFoundError, InvalidStateTransitionError):
            _not_found()
        except (FileNotFoundError, StorageIntegrityError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="skill artifact is temporarily unavailable",
            ) from exc

        filename = quote(f"{skill.name}-{skill.version}.tar.gz", safe="")
        return StreamingResponse(
            iter((artifact_bytes,)),
            media_type="application/gzip",
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{filename}",
                _HUB_ARTIFACT_METADATA_HEADER: _hub_artifact_metadata_header(skill),
            },
        )

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
                _required_metadata_header(x_author_artifact_metadata)
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
                correlation_id=_required_request_header(
                    correlation_id, name="X-Correlation-ID"
                ),
                idempotency_key=_required_request_header(
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
