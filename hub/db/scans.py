# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Durable asynchronous scan-job persistence and audited completion."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, func, insert, literal, or_, select, update
from sqlalchemy.exc import IntegrityError

from hub.core.models import ScanJobState, SkillStatus
from hub.db._models import (
    ArtifactModel,
    ScanEventModel,
    ScanJobModel,
    SkillTransitionAuditModel,
    SkillVersionModel,
    new_record_id,
)
from hub.db.errors import PersistenceConflictError, RecordNotFoundError
from hub.db.session import Database

_TERMINAL_STATES = {
    ScanJobState.CLEAN.value,
    ScanJobState.MALICIOUS.value,
    ScanJobState.MANUAL_REVIEW.value,
    ScanJobState.EXHAUSTED.value,
}
_MAX_DETAIL = 1024
_MAX_STATS_JSON = 4096


@dataclass(frozen=True)
class ScanJobRecord:
    id: str
    name: str
    version: str
    author_id: str
    artifact_digest: str
    author_upload_digest: str
    author_upload_storage_key: str
    provider: str
    provider_analysis_id: str | None
    state: ScanJobState
    attempt_count: int
    next_attempt_at: datetime
    lease_owner: str | None
    lease_expires_at: datetime | None
    submitted_at: datetime | None
    last_polled_at: datetime | None
    completed_at: datetime | None
    verdict: str | None
    detail: str
    stats: Mapping[str, int]
    correlation_id: str
    idempotency_key: str
    declares_tier_cd: bool
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class ScanQueueMetrics:
    queue_depth: int
    oldest_age_seconds: float
    total_attempts: int
    exhausted_jobs: int
    verdict_counts: Mapping[str, int]


def _bounded(value: str, maximum: int, field: str) -> str:
    clean = value.strip()
    if not clean:
        raise ValueError(f"{field} must not be empty")
    if len(clean) > maximum:
        raise ValueError(f"{field} must not exceed {maximum} characters")
    return clean


def _stats_json(stats: Mapping[str, int] | None) -> str:
    normalized: dict[str, int] = {}
    for key, value in (stats or {}).items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > 64
            or type(value) is not int
            or value < 0
            or value > 1_000_000
        ):
            raise ValueError("scanner stats contain an invalid bounded count")
        normalized[key] = value
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    if len(payload) > _MAX_STATS_JSON:
        raise ValueError("scanner stats exceed 4096 characters")
    return payload


def _record(
    job: ScanJobModel, skill: SkillVersionModel, artifact: ArtifactModel
) -> ScanJobRecord:
    try:
        raw_stats = json.loads(job.stats_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PersistenceConflictError("scan evidence is malformed") from exc
    if not isinstance(raw_stats, dict):
        raise PersistenceConflictError("scan evidence is malformed")
    stats = {
        str(key): int(value)
        for key, value in raw_stats.items()
        if isinstance(key, str) and type(value) is int
    }
    if len(stats) != len(raw_stats):
        raise PersistenceConflictError("scan evidence is malformed")
    return ScanJobRecord(
        id=job.id,
        name=skill.name,
        version=skill.version,
        author_id=skill.author_id,
        artifact_digest=artifact.artifact_digest,
        author_upload_digest=job.author_upload_digest,
        author_upload_storage_key=job.author_upload_storage_key,
        provider=job.provider,
        provider_analysis_id=job.provider_analysis_id,
        state=ScanJobState(job.state),
        attempt_count=job.attempt_count,
        next_attempt_at=job.next_attempt_at,
        lease_owner=job.lease_owner,
        lease_expires_at=job.lease_expires_at,
        submitted_at=job.submitted_at,
        last_polled_at=job.last_polled_at,
        completed_at=job.completed_at,
        verdict=job.verdict,
        detail=job.detail,
        stats=stats,
        correlation_id=job.correlation_id,
        idempotency_key=job.idempotency_key,
        declares_tier_cd=skill.declares_tier_cd,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


class ScanRepository:
    """Atomic lease, evidence, retry, and completion operations."""

    def __init__(self, database: Database) -> None:
        self._database = database

    @staticmethod
    def _joined_job() -> Select[tuple[ScanJobModel, SkillVersionModel, ArtifactModel]]:
        return (
            select(ScanJobModel, SkillVersionModel, ArtifactModel)
            .join(ArtifactModel, ArtifactModel.id == ScanJobModel.artifact_id)
            .join(SkillVersionModel, SkillVersionModel.artifact_id == ArtifactModel.id)
        )

    async def get(self, job_id: str) -> ScanJobRecord:
        async with self._database.transaction() as session:
            row = (
                await session.execute(
                    self._joined_job().where(ScanJobModel.id == job_id.strip())
                )
            ).one_or_none()
            if row is None:
                raise RecordNotFoundError("scan job was not found")
            return _record(*row)

    async def get_for_publication(self, *, name: str, version: str) -> ScanJobRecord:
        async with self._database.transaction() as session:
            row = (
                await session.execute(
                    self._joined_job().where(
                        SkillVersionModel.name == name.strip(),
                        SkillVersionModel.version == version.strip(),
                    )
                )
            ).one_or_none()
            if row is None:
                raise RecordNotFoundError("scan job was not found")
            return _record(*row)

    async def claim_due(
        self,
        *,
        worker_id: str,
        now: datetime | None = None,
        lease_seconds: int = 30,
    ) -> ScanJobRecord | None:
        owner = _bounded(worker_id, 255, "worker_id")
        if not 1 <= lease_seconds <= 300:
            raise ValueError("lease_seconds must be between 1 and 300")
        claimed_at = now or datetime.now(UTC)
        lease_expires = claimed_at + timedelta(seconds=lease_seconds)
        candidate = (
            select(ScanJobModel.id)
            .where(
                ScanJobModel.state.not_in(_TERMINAL_STATES),
                ScanJobModel.next_attempt_at <= claimed_at,
                or_(
                    ScanJobModel.lease_expires_at.is_(None),
                    ScanJobModel.lease_expires_at <= claimed_at,
                ),
            )
            .order_by(ScanJobModel.next_attempt_at, ScanJobModel.created_at)
            .limit(1)
            .scalar_subquery()
        )
        statement = (
            update(ScanJobModel)
            .where(
                ScanJobModel.id == candidate,
                ScanJobModel.state.not_in(_TERMINAL_STATES),
                ScanJobModel.next_attempt_at <= claimed_at,
                or_(
                    ScanJobModel.lease_expires_at.is_(None),
                    ScanJobModel.lease_expires_at <= claimed_at,
                ),
            )
            .values(
                lease_owner=owner,
                lease_expires_at=lease_expires,
                attempt_count=ScanJobModel.attempt_count + 1,
                updated_at=claimed_at,
            )
            .returning(ScanJobModel.id)
        )
        async with self._database.transaction() as session:
            job_id = (await session.execute(statement)).scalar_one_or_none()
            if job_id is None:
                return None
            row = (
                await session.execute(
                    self._joined_job().where(ScanJobModel.id == job_id)
                )
            ).one()
            claimed = _record(*row)
            session.add(
                ScanEventModel(
                    id=new_record_id(),
                    scan_job_id=claimed.id,
                    state=claimed.state.value,
                    attempt_count=claimed.attempt_count,
                    verdict=claimed.verdict,
                    detail="job leased for bounded processing",
                    stats_json=json.dumps(
                        dict(claimed.stats), sort_keys=True, separators=(",", ":")
                    ),
                    worker_id=owner,
                )
            )
            return claimed

    async def record_submission(
        self,
        *,
        job_id: str,
        worker_id: str,
        analysis_id: str,
        next_attempt_at: datetime,
        detail: str,
    ) -> None:
        await self._record_progress(
            job_id=job_id,
            worker_id=worker_id,
            expected_states={ScanJobState.PENDING_SUBMISSION.value},
            state=ScanJobState.SUBMITTED,
            next_attempt_at=next_attempt_at,
            detail=detail,
            provider_analysis_id=_bounded(analysis_id, 512, "analysis_id"),
            submitted=True,
        )

    async def record_polling(
        self,
        *,
        job_id: str,
        worker_id: str,
        next_attempt_at: datetime,
        detail: str,
    ) -> None:
        await self._record_progress(
            job_id=job_id,
            worker_id=worker_id,
            expected_states={
                ScanJobState.SUBMITTED.value,
                ScanJobState.POLLING.value,
            },
            state=ScanJobState.POLLING,
            next_attempt_at=next_attempt_at,
            detail=detail,
            polled=True,
        )

    async def record_retry(
        self,
        *,
        job_id: str,
        worker_id: str,
        next_attempt_at: datetime,
        detail: str,
    ) -> None:
        job = await self.get(job_id)
        await self._record_progress(
            job_id=job_id,
            worker_id=worker_id,
            expected_states={job.state.value},
            state=job.state,
            next_attempt_at=next_attempt_at,
            detail=detail,
            polled=job.provider_analysis_id is not None,
        )

    async def _record_progress(
        self,
        *,
        job_id: str,
        worker_id: str,
        expected_states: set[str],
        state: ScanJobState,
        next_attempt_at: datetime,
        detail: str,
        provider_analysis_id: str | None = None,
        submitted: bool = False,
        polled: bool = False,
    ) -> None:
        owner = _bounded(worker_id, 255, "worker_id")
        safe_detail = _bounded(detail, _MAX_DETAIL, "detail")
        now = datetime.now(UTC)
        values: dict[str, object] = {
            "state": state.value,
            "next_attempt_at": next_attempt_at,
            "detail": safe_detail,
            "lease_owner": None,
            "lease_expires_at": None,
            "updated_at": now,
        }
        if provider_analysis_id is not None:
            values["provider_analysis_id"] = provider_analysis_id
        if submitted:
            values["submitted_at"] = now
        if polled:
            values["last_polled_at"] = now
        async with self._database.transaction() as session:
            result = await session.execute(
                update(ScanJobModel)
                .where(
                    ScanJobModel.id == job_id,
                    ScanJobModel.state.in_(expected_states),
                    ScanJobModel.lease_owner == owner,
                    ScanJobModel.lease_expires_at > now,
                )
                .values(**values)
                .returning(ScanJobModel.id, ScanJobModel.attempt_count)
            )
            row = result.one_or_none()
            if row is None:
                raise PersistenceConflictError("scan job lease is no longer owned")
            session.add(
                ScanEventModel(
                    id=new_record_id(),
                    scan_job_id=row.id,
                    state=state.value,
                    attempt_count=row.attempt_count,
                    verdict=None,
                    detail=safe_detail,
                    stats_json="{}",
                    worker_id=owner,
                )
            )

    async def complete(
        self,
        *,
        job_id: str,
        worker_id: str,
        state: ScanJobState,
        verdict: str,
        detail: str,
        stats: Mapping[str, int] | None = None,
    ) -> bool:
        if state not in {
            ScanJobState.CLEAN,
            ScanJobState.MALICIOUS,
            ScanJobState.MANUAL_REVIEW,
            ScanJobState.EXHAUSTED,
        }:
            raise ValueError("scan completion requires a terminal state")
        owner = _bounded(worker_id, 255, "worker_id")
        safe_detail = _bounded(detail, _MAX_DETAIL, "detail")
        encoded_stats = _stats_json(stats)
        now = datetime.now(UTC)
        try:
            async with self._database.transaction() as session:
                result = await session.execute(
                    update(ScanJobModel)
                    .where(
                        ScanJobModel.id == job_id,
                        ScanJobModel.state.not_in(_TERMINAL_STATES),
                        ScanJobModel.lease_owner == owner,
                        ScanJobModel.lease_expires_at > now,
                    )
                    .values(
                        state=state.value,
                        verdict=_bounded(verdict, 32, "verdict"),
                        detail=safe_detail,
                        stats_json=encoded_stats,
                        completed_at=now,
                        last_polled_at=now,
                        lease_owner=None,
                        lease_expires_at=None,
                        updated_at=now,
                    )
                    .returning(
                        ScanJobModel.artifact_id,
                        ScanJobModel.attempt_count,
                        ScanJobModel.correlation_id,
                    )
                )
                completed = result.one_or_none()
                if completed is None:
                    existing = await session.get(ScanJobModel, job_id)
                    if existing is not None and existing.state in _TERMINAL_STATES:
                        return False
                    raise PersistenceConflictError("scan job lease is no longer owned")

                session.add(
                    ScanEventModel(
                        id=new_record_id(),
                        scan_job_id=job_id,
                        state=state.value,
                        attempt_count=completed.attempt_count,
                        verdict=verdict,
                        detail=safe_detail,
                        stats_json=encoded_stats,
                        worker_id=owner,
                    )
                )
                await session.flush()

                target: SkillStatus | None = None
                if state is ScanJobState.CLEAN:
                    target = SkillStatus.LISTED
                elif state is ScanJobState.MALICIOUS:
                    target = SkillStatus.REJECTED
                if target is None:
                    return True

                prior = SkillStatus.PENDING_REVIEW
                transition = (
                    select(
                        literal(new_record_id()),
                        SkillVersionModel.id,
                        SkillVersionModel.revision + 1,
                        literal(owner),
                        literal(prior.value),
                        literal(target.value),
                        literal(safe_detail),
                        literal(completed.correlation_id),
                        literal(f"scan:{job_id}:{state.value}"),
                        ArtifactModel.artifact_digest,
                        ArtifactModel.manifest_digest,
                    )
                    .join(
                        ArtifactModel, ArtifactModel.id == SkillVersionModel.artifact_id
                    )
                    .where(
                        SkillVersionModel.artifact_id == completed.artifact_id,
                        SkillVersionModel.status == prior.value,
                        or_(
                            literal(target is SkillStatus.REJECTED),
                            SkillVersionModel.declares_tier_cd.is_(False),
                        ),
                    )
                )
                await session.execute(
                    insert(SkillTransitionAuditModel).from_select(
                        [
                            "id",
                            "skill_version_id",
                            "transition_number",
                            "actor_id",
                            "prior_status",
                            "new_status",
                            "reason",
                            "correlation_id",
                            "idempotency_key",
                            "artifact_digest",
                            "manifest_digest",
                        ],
                        transition,
                    )
                )
        except IntegrityError as exc:
            raise PersistenceConflictError(
                "scan completion conflicts with durable state"
            ) from exc
        return True

    async def metrics(self, *, now: datetime | None = None) -> ScanQueueMetrics:
        measured_at = now or datetime.now(UTC)
        async with self._database.transaction() as session:
            queue_depth = int(
                await session.scalar(
                    select(func.count())
                    .select_from(ScanJobModel)
                    .where(ScanJobModel.state.not_in(_TERMINAL_STATES))
                )
                or 0
            )
            oldest = await session.scalar(
                select(func.min(ScanJobModel.created_at)).where(
                    ScanJobModel.state.not_in(_TERMINAL_STATES)
                )
            )
            attempts = int(
                await session.scalar(select(func.sum(ScanJobModel.attempt_count))) or 0
            )
            exhausted = int(
                await session.scalar(
                    select(func.count())
                    .select_from(ScanJobModel)
                    .where(ScanJobModel.state == ScanJobState.EXHAUSTED.value)
                )
                or 0
            )
            rows = (
                await session.execute(
                    select(ScanJobModel.verdict, func.count())
                    .where(ScanJobModel.verdict.is_not(None))
                    .group_by(ScanJobModel.verdict)
                )
            ).all()
        age = (
            0.0
            if oldest is None
            else max(
                0.0,
                (
                    measured_at.replace(tzinfo=None) - oldest.replace(tzinfo=None)
                ).total_seconds(),
            )
        )
        return ScanQueueMetrics(
            queue_depth=queue_depth,
            oldest_age_seconds=age,
            total_attempts=attempts,
            exhausted_jobs=exhausted,
            verdict_counts={str(key): int(value) for key, value in rows},
        )
