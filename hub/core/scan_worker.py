# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Bounded background orchestration for durable malware scan jobs."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from hub.core.models import ScanJobState
from hub.db.scans import ScanJobRecord, ScanRepository
from hub.integrations.scan import (
    PollResult,
    ScannerAuthenticationError,
    ScannerProviderError,
    ScannerRateLimitError,
    ScannerTemporaryError,
)
from hub.storage.objects import ContentAddressedStorage


class AsyncScanProvider(Protocol):
    def submit(self, payload: bytes) -> str: ...

    def poll_once(self, analysis_id: str) -> PollResult: ...


@dataclass(frozen=True)
class ScanWorkerPolicy:
    lease_seconds: int = 30
    initial_backoff_seconds: float = 2.0
    maximum_backoff_seconds: float = 300.0
    jitter_seconds: float = 1.0
    maximum_attempts: int = 20
    maximum_job_age_seconds: int = 86_400

    def __post_init__(self) -> None:
        if not 1 <= self.lease_seconds <= 300:
            raise ValueError("lease_seconds must be between 1 and 300")
        if not 0 < self.initial_backoff_seconds <= self.maximum_backoff_seconds:
            raise ValueError("scanner backoff bounds are invalid")
        if not 0 <= self.jitter_seconds <= self.maximum_backoff_seconds:
            raise ValueError("scanner jitter is invalid")
        if not 1 <= self.maximum_attempts <= 1000:
            raise ValueError("maximum_attempts must be between 1 and 1000")
        if not 60 <= self.maximum_job_age_seconds <= 604_800:
            raise ValueError("maximum_job_age_seconds must be between 60 and 604800")


@dataclass
class WorkerMetrics:
    claims: int = 0
    submissions: int = 0
    polls: int = 0
    rate_limits: int = 0
    exhausted: int = 0
    completed: int = 0
    last_latency_seconds: float = 0.0


class ScanWorker:
    """Process at most one durable job per invocation."""

    def __init__(
        self,
        *,
        worker_id: str,
        repository: ScanRepository,
        storage: ContentAddressedStorage,
        provider: AsyncScanProvider,
        policy: ScanWorkerPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
        random_source: random.Random | None = None,
    ) -> None:
        self.worker_id = worker_id
        self.repository = repository
        self.storage = storage
        self.provider = provider
        self.policy = policy or ScanWorkerPolicy()
        self.clock = clock or (lambda: datetime.now(UTC))
        self.random: random.Random = random_source or random.SystemRandom()
        self.metrics = WorkerMetrics()

    async def run_once(self) -> bool:
        started = time.monotonic()
        now = self.clock()
        job = await self.repository.claim_due(
            worker_id=self.worker_id,
            now=now,
            lease_seconds=self.policy.lease_seconds,
        )
        if job is None:
            return False
        self.metrics.claims += 1
        try:
            if self._expired(job, now):
                await self._exhaust(job, "scan job exceeded its bounded lifetime")
            elif job.state is ScanJobState.PENDING_SUBMISSION:
                await self._submit(job)
            else:
                await self._poll(job)
        finally:
            self.metrics.last_latency_seconds = max(0.0, time.monotonic() - started)
        return True

    def _expired(self, job: ScanJobRecord, now: datetime) -> bool:
        age = now.replace(tzinfo=None) - job.created_at.replace(tzinfo=None)
        return (
            job.attempt_count > self.policy.maximum_attempts
            or age.total_seconds() > self.policy.maximum_job_age_seconds
        )

    def _delay(self, attempt_count: int) -> float:
        exponent = max(0, min(attempt_count - 1, 30))
        base: float = min(
            self.policy.initial_backoff_seconds * (2**exponent),
            self.policy.maximum_backoff_seconds,
        )
        jitter: float = self.random.uniform(0.0, self.policy.jitter_seconds)
        return float(min(base + jitter, self.policy.maximum_backoff_seconds))

    async def _submit(self, job: ScanJobRecord) -> None:
        try:
            payload = self.storage.read(job.author_upload_digest)
            analysis_id = await asyncio.to_thread(self.provider.submit, payload)
            self.metrics.submissions += 1
            await self.repository.record_submission(
                job_id=job.id,
                worker_id=self.worker_id,
                analysis_id=analysis_id,
                next_attempt_at=self.clock()
                + timedelta(seconds=self._delay(job.attempt_count)),
                detail="sample submitted; analysis pending",
            )
        except ScannerRateLimitError as exc:
            self.metrics.rate_limits += 1
            await self._retry(
                job,
                exc.retry_after_seconds,
                str(exc),
                maximum_delay=300.0,
            )
        except ScannerAuthenticationError as exc:
            await self._retry(job, self.policy.maximum_backoff_seconds, str(exc))
        except ScannerTemporaryError as exc:
            await self._retry(job, self._delay(job.attempt_count), str(exc))
        except (ScannerProviderError, FileNotFoundError) as exc:
            await self.repository.complete(
                job_id=job.id,
                worker_id=self.worker_id,
                state=ScanJobState.MANUAL_REVIEW,
                verdict="unavailable",
                detail=str(exc),
            )

    async def _poll(self, job: ScanJobRecord) -> None:
        if job.provider_analysis_id is None:
            await self.repository.complete(
                job_id=job.id,
                worker_id=self.worker_id,
                state=ScanJobState.MANUAL_REVIEW,
                verdict="unavailable",
                detail="submitted scan job has no provider analysis identifier",
            )
            return
        try:
            outcome = await asyncio.to_thread(
                self.provider.poll_once, job.provider_analysis_id
            )
            self.metrics.polls += 1
            if not outcome.completed:
                await self.repository.record_polling(
                    job_id=job.id,
                    worker_id=self.worker_id,
                    next_attempt_at=self.clock()
                    + timedelta(seconds=self._delay(job.attempt_count)),
                    detail="analysis remains queued or in progress",
                )
                return
            result = outcome.result
            if result is None:
                raise ScannerProviderError(
                    "scanner completed without a bounded verdict"
                )
            if result.status == "clean":
                state = ScanJobState.CLEAN
                verdict = "clean"
            elif result.status == "malicious":
                state = ScanJobState.MALICIOUS
                verdict = "malicious"
            else:
                state = ScanJobState.MANUAL_REVIEW
                verdict = "suspicious"
            changed = await self.repository.complete(
                job_id=job.id,
                worker_id=self.worker_id,
                state=state,
                verdict=verdict,
                detail=result.detail,
                stats=outcome.stats,
            )
            if changed:
                self.metrics.completed += 1
        except ScannerRateLimitError as exc:
            self.metrics.rate_limits += 1
            await self._retry(
                job,
                exc.retry_after_seconds,
                str(exc),
                maximum_delay=300.0,
            )
        except ScannerAuthenticationError as exc:
            await self._retry(job, self.policy.maximum_backoff_seconds, str(exc))
        except ScannerTemporaryError as exc:
            await self._retry(job, self._delay(job.attempt_count), str(exc))
        except ScannerProviderError as exc:
            await self.repository.complete(
                job_id=job.id,
                worker_id=self.worker_id,
                state=ScanJobState.MANUAL_REVIEW,
                verdict="unavailable",
                detail=str(exc),
            )

    async def _retry(
        self,
        job: ScanJobRecord,
        delay: float,
        detail: str,
        *,
        maximum_delay: float | None = None,
    ) -> None:
        if job.attempt_count >= self.policy.maximum_attempts:
            await self._exhaust(job, "scan attempt budget exhausted")
            return
        delay_cap = maximum_delay or self.policy.maximum_backoff_seconds
        bounded_delay = min(max(delay, 1.0), delay_cap)
        await self.repository.record_retry(
            job_id=job.id,
            worker_id=self.worker_id,
            next_attempt_at=self.clock() + timedelta(seconds=bounded_delay),
            detail=detail,
        )

    async def _exhaust(self, job: ScanJobRecord, detail: str) -> None:
        changed = await self.repository.complete(
            job_id=job.id,
            worker_id=self.worker_id,
            state=ScanJobState.EXHAUSTED,
            verdict="unavailable",
            detail=detail,
        )
        if changed:
            self.metrics.exhausted += 1
