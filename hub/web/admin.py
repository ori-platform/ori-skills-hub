# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Authenticated administrator routes for skill review transitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status

from hub.core.models import SkillStatus
from hub.core.scan_worker import WorkerMetrics
from hub.db.errors import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    RecordNotFoundError,
)
from hub.db.repository import HubRepository, PendingSkillReview
from hub.db.scans import ScanRepository
from hub.web.authors import _required_header, admin_authentication_dependency

_REVIEW_LIST_LIMIT = 100


@dataclass(frozen=True)
class SkillReviewRequest:
    reason: str


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _pending_review_payload(review: PendingSkillReview) -> dict[str, object]:
    return {
        "name": review.name,
        "version": review.version,
        "author": review.author,
        "declares_tier_cd": review.declares_tier_cd,
        "scanner_verdict": review.scanner_verdict,
        "scanner_detail": review.scanner_detail,
        "published_at": review.created_at.isoformat(),
    }


def _raise_transition_error(
    exc: RecordNotFoundError | InvalidStateTransitionError | PersistenceConflictError,
) -> NoReturn:
    if isinstance(exc, RecordNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="skill was not found"
        ) from exc
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="skill transition conflicts with its current state",
    ) from exc


def create_admin_router(
    *,
    repository: HubRepository,
    admin_api_key: str,
    admin_actor_id: str,
    scan_repository: ScanRepository | None = None,
    worker_metrics: WorkerMetrics | None = None,
) -> APIRouter:
    """Build administrator-only review queue and state-transition routes."""

    router = APIRouter(prefix="/api/admin/skills", tags=["admin"])
    require_admin = admin_authentication_dependency(
        admin_api_key=admin_api_key, admin_actor_id=admin_actor_id
    )

    @router.get("")
    async def list_pending_reviews(
        response: Response,
        limit: Annotated[int, Query(ge=1, le=_REVIEW_LIST_LIMIT)] = 50,
        _actor_id: str = Depends(require_admin),
    ) -> dict[str, object]:
        _no_store(response)
        reviews = await repository.list_pending_reviews(limit=limit)
        return {"skills": [_pending_review_payload(review) for review in reviews]}

    @router.get("/scan-metrics")
    async def scan_metrics(
        response: Response,
        _actor_id: str = Depends(require_admin),
    ) -> dict[str, object]:
        if scan_repository is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="scanner orchestration is not enabled",
            )
        _no_store(response)
        queue = await scan_repository.metrics()
        runtime = worker_metrics or WorkerMetrics()
        return {
            "queue_depth": queue.queue_depth,
            "oldest_age_seconds": queue.oldest_age_seconds,
            "total_attempts": queue.total_attempts,
            "exhausted_jobs": queue.exhausted_jobs,
            "verdict_counts": dict(queue.verdict_counts),
            "worker": {
                "claims": runtime.claims,
                "submissions": runtime.submissions,
                "polls": runtime.polls,
                "rate_limits": runtime.rate_limits,
                "exhausted": runtime.exhausted,
                "completed": runtime.completed,
                "last_latency_seconds": runtime.last_latency_seconds,
            },
        }

    async def transition(
        *,
        name: str,
        version: str,
        request: SkillReviewRequest,
        response: Response,
        actor_id: str,
        target_status: SkillStatus,
        idempotency_key: str | None,
        correlation_id: str | None,
    ) -> dict[str, object]:
        _no_store(response)
        try:
            skill = await repository.transition_skill(
                name=name,
                version=version,
                target_status=target_status,
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
            RecordNotFoundError,
            InvalidStateTransitionError,
            PersistenceConflictError,
        ) as exc:
            _raise_transition_error(exc)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
            ) from exc
        return {"name": skill.name, "version": skill.version, "status": skill.status}

    @router.post("/{name}/{version}/approve")
    async def approve_skill(
        name: str,
        version: str,
        request: SkillReviewRequest,
        response: Response,
        actor_id: str = Depends(require_admin),
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        correlation_id: Annotated[str | None, Header(alias="X-Correlation-ID")] = None,
    ) -> dict[str, object]:
        return await transition(
            name=name,
            version=version,
            request=request,
            response=response,
            actor_id=actor_id,
            target_status=SkillStatus.LISTED,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
        )

    @router.post("/{name}/{version}/reject")
    async def reject_skill(
        name: str,
        version: str,
        request: SkillReviewRequest,
        response: Response,
        actor_id: str = Depends(require_admin),
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        correlation_id: Annotated[str | None, Header(alias="X-Correlation-ID")] = None,
    ) -> dict[str, object]:
        return await transition(
            name=name,
            version=version,
            request=request,
            response=response,
            actor_id=actor_id,
            target_status=SkillStatus.REJECTED,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
        )

    @router.post("/{name}/{version}/unlist")
    async def unlist_skill(
        name: str,
        version: str,
        request: SkillReviewRequest,
        response: Response,
        actor_id: str = Depends(require_admin),
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
        correlation_id: Annotated[str | None, Header(alias="X-Correlation-ID")] = None,
    ) -> dict[str, object]:
        return await transition(
            name=name,
            version=version,
            request=request,
            response=response,
            actor_id=actor_id,
            target_status=SkillStatus.UNLISTED,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
        )

    return router
