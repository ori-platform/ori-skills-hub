# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""FastAPI entrypoint for ori-skills-hub."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from hub import __version__
from hub.core.config import load_from_env
from hub.core.publish import Scanner
from hub.db.repository import HubRepository
from hub.db.session import Database
from hub.integrations.scan import VirusTotalScanner
from hub.security.author_identity import AuthorIdentityService
from hub.security.hub_keys import (
    HubPublicTrustAnchors,
    HubSigningKeys,
    load_hub_signing_keys_from_env,
)
from hub.storage.objects import ContentAddressedStorage
from hub.web.admin import create_admin_router
from hub.web.authors import create_author_router
from hub.web.skills import create_skill_router


def health_payload(
    *, trust_anchors: HubPublicTrustAnchors | None = None
) -> dict[str, object]:
    payload: dict[str, object] = {"status": "ok", "version": __version__}
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
            )
        )
        if admin_api_key is None:
            raise ValueError("admin_api_key is required when admin routes are enabled")
        app.include_router(
            create_admin_router(
                repository=skill_repository,
                admin_api_key=admin_api_key,
                admin_actor_id=admin_actor_id,
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
    signing_keys = load_hub_signing_keys_from_env(publish_capable=False)
    publish_enabled = signing_keys is not None

    @asynccontextmanager
    async def lifespan(_app: Any) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await database.dispose()

    configured_app = create_app(
        trust_anchors=(
            signing_keys.public_trust_anchors if signing_keys is not None else None
        ),
        author_identity_service=identity_service,
        admin_api_key=config.admin_api_key,
        admin_actor_id=config.admin_actor_id,
        author_registration_enabled=config.author_registration_enabled,
        skill_repository=HubRepository(database) if publish_enabled else None,
        artifact_storage=(
            ContentAddressedStorage(config.storage_local_dir)
            if publish_enabled
            else None
        ),
        hub_signing_keys=signing_keys,
        scanner=(
            VirusTotalScanner(config.virustotal_api_key) if publish_enabled else None
        ),
        lifespan=lifespan,
    )
    configured_app.state.hub_database = database
    return configured_app


app = create_app()
