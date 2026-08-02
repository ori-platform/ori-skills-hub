# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import json
import random
from collections import Counter
from collections.abc import Coroutine
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar, cast

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from hub.core.models import ScanJobState, ScannerVerdict, SkillStatus
from hub.core.scan_worker import ScanWorker, ScanWorkerPolicy
from hub.db._models import ScanEventModel, ScanJobModel, new_record_id
from hub.db.errors import PersistenceConflictError
from hub.db.repository import HubRepository, NewScanJob
from hub.db.scans import ScanRepository
from hub.db.session import Database
from hub.integrations.scan import (
    PollResult,
    ScannerAuthenticationError,
    ScannerProviderError,
    ScannerRateLimitError,
    ScannerTemporaryError,
    ScanResult,
)
from hub.security.author_identity import AuthorIdentityService
from hub.storage.objects import ContentAddressedStorage

_T = TypeVar("_T")
_VECTORS = cast(
    dict[str, object],
    json.loads(
        (
            Path(__file__).parent / "fixtures" / "skill_signing_vectors_v1.json"
        ).read_text(encoding="utf-8")
    ),
)
_PUBLIC_KEY = cast(str, _VECTORS["public_key_b64"])


def _run(awaitable: Coroutine[Any, Any, _T]) -> _T:
    return asyncio.run(awaitable)


class _Provider:
    def __init__(self, polls: list[PollResult | Exception]) -> None:
        self.submissions = 0
        self.polls = polls

    def submit(self, _payload: bytes) -> str:
        self.submissions += 1
        return "opaque-analysis-id"

    def poll_once(self, _analysis_id: str) -> PollResult:
        outcome = self.polls.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


async def _setup_job(
    tmp_path: Path,
    *,
    declares_tier_cd: bool = False,
) -> tuple[Database, HubRepository, ScanRepository, ContentAddressedStorage, str]:
    database = Database(f"sqlite:///{tmp_path / 'hub.db'}")
    await database.bootstrap_schema()
    identity = AuthorIdentityService(database, token_ttl_seconds=300)
    registration = await identity.register(
        external_subject="github:scan-author",
        display_handle="scan-author",
        public_key_b64=_PUBLIC_KEY,
        authenticated_actor_id="bootstrap-admin",
        correlation_id="register-scan-author",
        idempotency_key="register-scan-author",
    )
    storage = ContentAddressedStorage(tmp_path / "objects")
    author_upload = b"verified-author-upload"
    author_digest = storage.store(author_upload)
    final_digest = storage.store(b"hub-signed-final-artifact")
    job_id = new_record_id()
    repository = HubRepository(database)
    await repository.create_publication(
        name="guarded" if declares_tier_cd else "monitor",
        version="1.0.0",
        artifact_digest=final_digest,
        manifest_digest="sha256:" + "b" * 64,
        storage_key=final_digest,
        byte_size=25,
        artifact_signature="ed25519:hub-artifact",
        manifest_signature="ed25519:hub-manifest",
        scanner_verdict=ScannerVerdict.UNAVAILABLE,
        scanner_detail="asynchronous scan pending",
        author_artifact_digest=author_digest,
        author_artifact_signature="ed25519:author-artifact",
        declares_tier_cd=declares_tier_cd,
        initial_status=SkillStatus.PENDING_REVIEW,
        authenticated_actor_id=registration.author.author_id,
        reason="skill publication",
        correlation_id="publish-scan-job",
        idempotency_key="publish-scan-job",
        scan_job=NewScanJob(
            job_id=job_id,
            author_upload_digest=author_digest,
            author_upload_storage_key=author_digest,
            correlation_id="publish-scan-job",
            idempotency_key="publish-scan-job",
        ),
    )
    return database, repository, ScanRepository(database), storage, job_id


def _clean() -> PollResult:
    return PollResult(
        completed=True,
        result=ScanResult(status="clean", detail="affirmative harmless majority"),
        stats={"harmless": 52, "undetected": 8},
    )


def _malicious() -> PollResult:
    return PollResult(
        completed=True,
        result=ScanResult(status="malicious", detail="malicious=3"),
        stats={"malicious": 3},
    )


def test_job_survives_repository_restart_and_only_one_worker_claims(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, _hub, scans, _storage, job_id = await _setup_job(tmp_path)
        try:
            restarted = ScanRepository(database)
            assert (
                await restarted.get(job_id)
            ).state is ScanJobState.PENDING_SUBMISSION
            now = datetime.now(UTC)
            claims = await asyncio.gather(
                scans.claim_due(worker_id="worker-a", now=now),
                restarted.claim_due(worker_id="worker-b", now=now),
            )
            assert sum(claim is not None for claim in claims) == 1
        finally:
            await database.dispose()

    _run(scenario())


def test_expired_lease_is_recoverable(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, _hub, scans, _storage, _job_id = await _setup_job(tmp_path)
        try:
            now = datetime.now(UTC)
            first = await scans.claim_due(
                worker_id="dead-worker", now=now, lease_seconds=2
            )
            assert first is not None
            assert (
                await scans.claim_due(
                    worker_id="early-worker", now=now + timedelta(seconds=1)
                )
                is None
            )
            recovered = await scans.claim_due(
                worker_id="recovery-worker", now=now + timedelta(seconds=3)
            )
            assert recovered is not None
            assert recovered.id == first.id
            assert recovered.attempt_count == 2
        finally:
            await database.dispose()

    _run(scenario())


def test_clean_tier_ab_lists_only_after_persisted_evidence(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, hub, scans, storage, job_id = await _setup_job(tmp_path)
        provider = _Provider([_clean()])
        policy = ScanWorkerPolicy(
            initial_backoff_seconds=0.001,
            maximum_backoff_seconds=1,
            jitter_seconds=0,
        )
        worker = ScanWorker(
            worker_id="scanner-worker",
            repository=scans,
            storage=storage,
            provider=provider,
            policy=policy,
            random_source=random.Random(1),
        )
        try:
            assert (await hub.get_skill(name="monitor", version="1.0.0")).status == (
                SkillStatus.PENDING_REVIEW.value
            )
            assert await worker.run_once()
            submitted = await scans.get(job_id)
            assert submitted.state is ScanJobState.SUBMITTED
            assert (await hub.get_skill(name="monitor", version="1.0.0")).status == (
                SkillStatus.PENDING_REVIEW.value
            )
            await asyncio.sleep(0.01)
            assert await worker.run_once()
            completed = await scans.get(job_id)
            assert completed.state is ScanJobState.CLEAN
            assert completed.stats["harmless"] == 52
            assert (await hub.get_skill(name="monitor", version="1.0.0")).status == (
                SkillStatus.LISTED.value
            )
            assert (
                len(await hub.get_transition_history(name="monitor", version="1.0.0"))
                == 2
            )
            async with database.transaction() as session:
                events = list(
                    await session.scalars(
                        select(ScanEventModel)
                        .where(ScanEventModel.scan_job_id == job_id)
                        .order_by(ScanEventModel.attempt_count, ScanEventModel.id)
                    )
                )
            assert Counter(event.state for event in events) == Counter(
                {
                    "pending_submission": 2,
                    "submitted": 2,
                    "clean": 1,
                }
            )
            assert max(event.attempt_count for event in events) == 2
            assert not await scans.complete(
                job_id=job_id,
                worker_id="scanner-worker",
                state=ScanJobState.CLEAN,
                verdict="clean",
                detail="duplicate delivery",
            )
        finally:
            await database.dispose()

    _run(scenario())


def test_clean_tier_cd_remains_pending_and_malicious_rejects(tmp_path: Path) -> None:
    async def scenario() -> None:
        tier_c_path = tmp_path / "tier-c"
        malicious_path = tmp_path / "malicious"
        database_c, hub_c, scans_c, storage_c, _ = await _setup_job(
            tier_c_path, declares_tier_cd=True
        )
        database_m, hub_m, scans_m, storage_m, _ = await _setup_job(malicious_path)
        policy = ScanWorkerPolicy(
            initial_backoff_seconds=0.001,
            maximum_backoff_seconds=1,
            jitter_seconds=0,
        )
        try:
            clean_worker = ScanWorker(
                worker_id="clean-worker",
                repository=scans_c,
                storage=storage_c,
                provider=_Provider([_clean()]),
                policy=policy,
            )
            malicious_worker = ScanWorker(
                worker_id="malicious-worker",
                repository=scans_m,
                storage=storage_m,
                provider=_Provider([_malicious()]),
                policy=policy,
            )
            await clean_worker.run_once()
            await malicious_worker.run_once()
            await asyncio.sleep(0.01)
            await clean_worker.run_once()
            await malicious_worker.run_once()
            assert (await hub_c.get_skill(name="guarded", version="1.0.0")).status == (
                SkillStatus.PENDING_REVIEW.value
            )
            assert (await hub_m.get_skill(name="monitor", version="1.0.0")).status == (
                SkillStatus.REJECTED.value
            )
        finally:
            await database_c.dispose()
            await database_m.dispose()

    _run(scenario())


def test_rate_limit_honours_bounded_retry_after_without_listing(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, hub, scans, storage, job_id = await _setup_job(tmp_path)
        provider = _Provider([ScannerRateLimitError(120)])
        worker = ScanWorker(
            worker_id="rate-limited-worker",
            repository=scans,
            storage=storage,
            provider=provider,
            policy=ScanWorkerPolicy(
                initial_backoff_seconds=0.001,
                maximum_backoff_seconds=10,
                jitter_seconds=0,
            ),
        )
        try:
            await worker.run_once()
            await asyncio.sleep(0.01)
            before_poll = datetime.now(UTC)
            await worker.run_once()
            job = await scans.get(job_id)
            delay = job.next_attempt_at.replace(tzinfo=UTC) - before_poll
            assert 118 <= delay.total_seconds() <= 121
            assert job.state is ScanJobState.SUBMITTED
            assert (await hub.get_skill(name="monitor", version="1.0.0")).status == (
                SkillStatus.PENDING_REVIEW.value
            )
            assert worker.metrics.rate_limits == 1
        finally:
            await database.dispose()

    _run(scenario())


def test_exponential_backoff_and_jitter_are_bounded(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, _hub, scans, storage, _job_id = await _setup_job(tmp_path)
        worker = ScanWorker(
            worker_id="backoff-worker",
            repository=scans,
            storage=storage,
            provider=_Provider([]),
            policy=ScanWorkerPolicy(
                initial_backoff_seconds=2,
                maximum_backoff_seconds=10,
                jitter_seconds=1,
            ),
            random_source=random.Random(7),
        )
        try:
            delays = [worker._delay(attempt) for attempt in (1, 2, 3, 4, 20)]
            assert 2 < delays[0] < 3
            assert 4 < delays[1] < 5
            assert 8 < delays[2] < 9
            assert delays[3:] == [10, 10]
        finally:
            await database.dispose()

    _run(scenario())


def test_database_guards_block_listing_without_evidence_and_invalid_job_jump(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database, hub, scans, _storage, job_id = await _setup_job(tmp_path)
        try:
            with pytest.raises(PersistenceConflictError):
                await hub.transition_skill(
                    name="monitor",
                    version="1.0.0",
                    target_status=SkillStatus.LISTED,
                    authenticated_actor_id="admin-reviewer",
                    reason="premature approval",
                    correlation_id="premature-approval",
                    idempotency_key="premature-approval",
                )
            with pytest.raises(IntegrityError, match="scan job state"):
                async with database.transaction() as session:
                    await session.execute(
                        update(ScanJobModel)
                        .where(ScanJobModel.id == job_id)
                        .values(state=ScanJobState.CLEAN.value)
                    )
            assert (await scans.get(job_id)).state is ScanJobState.PENDING_SUBMISSION
            assert (await hub.get_skill(name="monitor", version="1.0.0")).status == (
                SkillStatus.PENDING_REVIEW.value
            )
        finally:
            await database.dispose()

    _run(scenario())


@pytest.mark.parametrize(
    ("failure", "expected_state"),
    [
        (ScannerAuthenticationError("authentication failed"), "pending_submission"),
        (ScannerTemporaryError("provider timeout"), "pending_submission"),
        (ScannerProviderError("malformed provider response"), "manual_review"),
    ],
)
def test_submission_failures_never_list_and_do_not_leak_credentials(
    tmp_path: Path,
    failure: Exception,
    expected_state: str,
) -> None:
    class _FailingProvider(_Provider):
        def submit(self, _payload: bytes) -> str:
            raise failure

    async def scenario() -> None:
        database, hub, scans, storage, job_id = await _setup_job(tmp_path)
        worker = ScanWorker(
            worker_id="failure-worker",
            repository=scans,
            storage=storage,
            provider=_FailingProvider([]),
            policy=ScanWorkerPolicy(
                initial_backoff_seconds=1,
                maximum_backoff_seconds=10,
                jitter_seconds=0,
            ),
        )
        try:
            await worker.run_once()
            job = await scans.get(job_id)
            assert job.state.value == expected_state
            assert (await hub.get_skill(name="monitor", version="1.0.0")).status == (
                SkillStatus.PENDING_REVIEW.value
            )
            assert "api-key-secret" not in job.detail
        finally:
            await database.dispose()

    _run(scenario())


def test_attempt_exhaustion_is_terminal_and_nonpublic(tmp_path: Path) -> None:
    class _UnavailableProvider(_Provider):
        def submit(self, _payload: bytes) -> str:
            raise ScannerTemporaryError("provider unavailable")

    async def scenario() -> None:
        database, hub, scans, storage, job_id = await _setup_job(tmp_path)
        worker = ScanWorker(
            worker_id="exhaustion-worker",
            repository=scans,
            storage=storage,
            provider=_UnavailableProvider([]),
            policy=ScanWorkerPolicy(maximum_attempts=1),
        )
        try:
            await worker.run_once()
            job = await scans.get(job_id)
            assert job.state is ScanJobState.EXHAUSTED
            assert job.verdict == "unavailable"
            assert (await hub.get_skill(name="monitor", version="1.0.0")).status == (
                SkillStatus.PENDING_REVIEW.value
            )
        finally:
            await database.dispose()

    _run(scenario())


def test_maximum_job_age_exhausts_without_provider_submission(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, hub, scans, storage, job_id = await _setup_job(tmp_path)
        created_at = (await scans.get(job_id)).created_at.replace(tzinfo=UTC)
        provider = _Provider([])
        worker = ScanWorker(
            worker_id="age-limit-worker",
            repository=scans,
            storage=storage,
            provider=provider,
            policy=ScanWorkerPolicy(maximum_job_age_seconds=60),
            clock=lambda: created_at + timedelta(seconds=61),
        )
        try:
            assert await worker.run_once()
            job = await scans.get(job_id)
            assert job.state is ScanJobState.EXHAUSTED
            assert provider.submissions == 0
            assert (await hub.get_skill(name="monitor", version="1.0.0")).status == (
                SkillStatus.PENDING_REVIEW.value
            )
        finally:
            await database.dispose()

    _run(scenario())


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_scan_evidence_events_are_database_immutable(
    tmp_path: Path, operation: str
) -> None:
    async def scenario() -> None:
        database, _hub, _scans, _storage, job_id = await _setup_job(tmp_path)
        try:
            with pytest.raises(IntegrityError, match="append-only"):
                async with database.transaction() as session:
                    statement = (
                        update(ScanEventModel)
                        .where(ScanEventModel.scan_job_id == job_id)
                        .values(detail="rewritten evidence")
                        if operation == "update"
                        else delete(ScanEventModel).where(
                            ScanEventModel.scan_job_id == job_id
                        )
                    )
                    await session.execute(statement)
        finally:
            await database.dispose()

    _run(scenario())


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_terminal_scan_job_evidence_is_database_immutable(
    tmp_path: Path, operation: str
) -> None:
    async def scenario() -> None:
        database, _hub, scans, storage, job_id = await _setup_job(tmp_path)
        worker = ScanWorker(
            worker_id="terminal-evidence-worker",
            repository=scans,
            storage=storage,
            provider=_Provider([_clean()]),
            policy=ScanWorkerPolicy(
                initial_backoff_seconds=0.001,
                maximum_backoff_seconds=1,
                jitter_seconds=0,
            ),
        )
        try:
            await worker.run_once()
            await asyncio.sleep(0.01)
            await worker.run_once()
            assert (await scans.get(job_id)).state is ScanJobState.CLEAN
            with pytest.raises(IntegrityError, match="immutable|durable"):
                async with database.transaction() as session:
                    statement = (
                        update(ScanJobModel)
                        .where(ScanJobModel.id == job_id)
                        .values(detail="rewritten terminal evidence")
                        if operation == "update"
                        else delete(ScanJobModel).where(ScanJobModel.id == job_id)
                    )
                    await session.execute(statement)
            assert (await scans.get(job_id)).state is ScanJobState.CLEAN
        finally:
            await database.dispose()

    _run(scenario())


def test_restart_after_provider_submission_is_hub_idempotent(tmp_path: Path) -> None:
    async def scenario() -> None:
        database, hub, scans, storage, job_id = await _setup_job(tmp_path)
        provider = _Provider([])
        try:
            # Simulate termination after the provider accepted the sample but before
            # the opaque analysis ID committed. The recovered job is still pending.
            assert provider.submit(b"verified-author-upload") == "opaque-analysis-id"
            restarted_repository = ScanRepository(database)
            assert (
                await restarted_repository.get(job_id)
            ).state is ScanJobState.PENDING_SUBMISSION

            recovered_worker = ScanWorker(
                worker_id="recovered-worker",
                repository=restarted_repository,
                storage=storage,
                provider=provider,
            )
            await recovered_worker.run_once()
            job = await scans.get(job_id)
            assert job.state is ScanJobState.SUBMITTED
            assert job.provider_analysis_id == "opaque-analysis-id"
            assert provider.submissions == 2
            assert (await hub.get_skill(name="monitor", version="1.0.0")).revision == 1
        finally:
            await database.dispose()

    _run(scenario())
