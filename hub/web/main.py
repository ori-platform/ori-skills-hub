# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""FastAPI entrypoint for ori-skills-hub."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from hub import __version__
from hub.core.config import load_from_env
from hub.db.session import Database
from hub.security.author_identity import AuthorIdentityService
from hub.security.hub_keys import HubPublicTrustAnchors
from hub.web.authors import create_author_router


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

    @asynccontextmanager
    async def lifespan(_app: Any) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await database.dispose()

    configured_app = create_app(
        author_identity_service=identity_service,
        admin_api_key=config.admin_api_key,
        admin_actor_id=config.admin_actor_id,
        author_registration_enabled=config.author_registration_enabled,
        lifespan=lifespan,
    )
    configured_app.state.hub_database = database
    return configured_app


app = create_app()
