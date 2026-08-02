# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""FastAPI entrypoint for ori-skills-hub."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from hub import __version__
from hub.core.config import load_from_env
from hub.core.publish import Scanner
from hub.core.scan_worker import ScanWorker, ScanWorkerPolicy, WorkerMetrics
from hub.db.repository import HubRepository
from hub.db.scans import ScanRepository
from hub.db.session import Database
from hub.integrations.scan import VirusTotalScanner
from hub.security.author_identity import AuthorIdentityService
from hub.security.hub_keys import (
    HubPublicTrustAnchors,
    HubSigningKeys,
    load_hub_signing_keys_from_env,
)
from hub.security.signing import ARTIFACT_SIGNATURE_SCHEMA, SIGNING_VECTOR_SHA256
from hub.storage.objects import ContentAddressedStorage
from hub.web.admin import create_admin_router
from hub.web.authors import create_author_router
from hub.web.skills import create_skill_router

_SKILL_PACKAGE_CONTRACT_VERSION = "v1"
_SIGNING_CONTRACT_VERSION = "v1"
_LOGGER = logging.getLogger(__name__)


def health_payload(
    *, trust_anchors: HubPublicTrustAnchors | None = None
) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": "ok",
        "version": __version__,
        "contract_compatibility": {
            "skill_package": {"version": _SKILL_PACKAGE_CONTRACT_VERSION},
            "signing": {
                "version": _SIGNING_CONTRACT_VERSION,
                "artifact_signature_schema": ARTIFACT_SIGNATURE_SCHEMA,
                "vector_sha256": SIGNING_VECTOR_SHA256,
            },
        },
    }
    if trust_anchors is not None:
        payload["signing_trust_anchors"] = trust_anchors.as_dict()
    return payload


def create_app(
    *,
    trust_anchors: HubPublicTrustAnchors | None = None,
    author_identity_service: AuthorIdentityService | None = None,
    admin_api_key: str | None = None,
    admin_actor_id: str = "bootstrap-admin",
    author_registration_enabled: bool = False,
    skill_repository: HubRepository | None = None,
    artifact_storage: ContentAddressedStorage | None = None,
    hub_signing_keys: HubSigningKeys | None = None,
    scanner: Scanner | None = None,
    scan_repository: ScanRepository | None = None,
    scan_worker_metrics: WorkerMetrics | None = None,
    lifespan: Any | None = None,
) -> Any:
    try:
        from fastapi import FastAPI
    except ImportError as exc:  # pragma: no cover - dependency installed in service env
        raise RuntimeError("FastAPI is required to create the Skills Hub app") from exc

    app = FastAPI(title="Ori Skills Hub", version=__version__, lifespan=lifespan)
    if author_identity_service is not None:
        if admin_api_key is None:
            raise ValueError("admin_api_key is required when author routes are enabled")
        app.include_router(
            create_author_router(
                author_identity_service,
                admin_api_key=admin_api_key,
                admin_actor_id=admin_actor_id,
                registration_enabled=author_registration_enabled,
            )
        )

    publish_components = (
        skill_repository,
        artifact_storage,
        hub_signing_keys,
        scanner,
    )
    if any(component is not None for component in publish_components) and (
        skill_repository is None
        or artifact_storage is None
        or hub_signing_keys is None
        or scanner is None
    ):
        raise ValueError(
            "publish routes require repository, storage, signing keys, "
            "and scanner together"
        )
    if (
        skill_repository is not None
        and artifact_storage is not None
        and hub_signing_keys is not None
        and scanner is not None
    ):
        if author_identity_service is None:
            raise ValueError("publish routes require the author identity service")
        app.include_router(
            create_skill_router(
                author_identity_service,
                repository=skill_repository,
                storage=artifact_storage,
                signing_keys=hub_signing_keys,
                scanner=scanner,
                scan_repository=scan_repository,
            )
        )
        if admin_api_key is None:
            raise ValueError("admin_api_key is required when admin routes are enabled")
        app.include_router(
            create_admin_router(
                repository=skill_repository,
                admin_api_key=admin_api_key,
                admin_actor_id=admin_actor_id,
                scan_repository=scan_repository,
                worker_metrics=scan_worker_metrics,
            )
        )

    @app.get("/health")
    async def health() -> dict[str, object]:
        return health_payload(trust_anchors=trust_anchors)

    return app


def create_configured_app() -> Any:
    """Build the deployable app from explicit environment configuration."""

    config = load_from_env()
    database = Database(config.database_url)
    identity_service = AuthorIdentityService(
        database,
        token_ttl_seconds=config.author_token_ttl_seconds,
    )
    signing_keys = load_hub_signing_keys_from_env(
        publish_capable=config.publish_enabled
    )
    repository = HubRepository(database) if config.publish_enabled else None
    scan_repository = ScanRepository(database) if config.publish_enabled else None
    storage = (
        ContentAddressedStorage(config.storage_local_dir)
        if config.publish_enabled
        else None
    )
    scanner = (
        VirusTotalScanner(config.virustotal_api_key) if config.publish_enabled else None
    )
    worker = (
        ScanWorker(
            worker_id=f"{socket.gethostname()}:{uuid.uuid4().hex}",
            repository=scan_repository,
            storage=storage,
            provider=scanner,
            policy=ScanWorkerPolicy(
                lease_seconds=config.scan_lease_seconds,
                initial_backoff_seconds=config.scan_initial_backoff_seconds,
                maximum_backoff_seconds=config.scan_max_backoff_seconds,
                jitter_seconds=config.scan_jitter_seconds,
                maximum_attempts=config.scan_max_attempts,
                maximum_job_age_seconds=config.scan_max_age_seconds,
            ),
        )
        if config.scan_worker_enabled
        and scan_repository is not None
        and storage is not None
        and scanner is not None
        else None
    )

    async def run_worker() -> None:
        assert worker is not None
        while True:
            try:
                processed = await worker.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _LOGGER.error(
                    "scan worker iteration failed",
                    extra={
                        "scan_worker_id": worker.worker_id,
                        "error_type": type(exc).__name__,
                    },
                )
                await asyncio.sleep(1.0)
                continue
            if not processed:
                await asyncio.sleep(1.0)

    @asynccontextmanager
    async def lifespan(_app: Any) -> AsyncIterator[None]:
        worker_task: asyncio.Task[None] | None = None
        try:
            if worker is not None:
                worker_task = asyncio.create_task(run_worker())
            yield
        finally:
            if worker_task is not None:
                worker_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await worker_task
            await database.dispose()

    configured_app = create_app(
        trust_anchors=(
            signing_keys.public_trust_anchors if signing_keys is not None else None
        ),
        author_identity_service=identity_service,
        admin_api_key=config.admin_api_key,
        admin_actor_id=config.admin_actor_id,
        author_registration_enabled=config.author_registration_enabled,
        skill_repository=repository,
        artifact_storage=(storage),
        hub_signing_keys=signing_keys,
        scanner=(scanner),
        scan_repository=scan_repository,
        scan_worker_metrics=worker.metrics if worker is not None else None,
        lifespan=lifespan,
    )
    configured_app.state.hub_database = database
    configured_app.state.scan_worker = worker
    configured_app.state.scan_repository = scan_repository
    return configured_app


app = create_app()
