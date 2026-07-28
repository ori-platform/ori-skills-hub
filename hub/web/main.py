# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""FastAPI entrypoint for ori-skills-hub."""

from __future__ import annotations

from typing import Any

from hub import __version__
from hub.security.hub_keys import HubPublicTrustAnchors


def health_payload(
    *, trust_anchors: HubPublicTrustAnchors | None = None
) -> dict[str, object]:
    payload: dict[str, object] = {"status": "ok", "version": __version__}
    if trust_anchors is not None:
        payload["signing_trust_anchors"] = trust_anchors.as_dict()
    return payload


def create_app(*, trust_anchors: HubPublicTrustAnchors | None = None) -> Any:
    try:
        from fastapi import FastAPI
    except ImportError as exc:  # pragma: no cover - dependency installed in service env
        raise RuntimeError("FastAPI is required to create the Skills Hub app") from exc

    app = FastAPI(title="Ori Skills Hub", version=__version__)

    @app.get("/health")
    async def health() -> dict[str, object]:
        return health_payload(trust_anchors=trust_anchors)

    return app


app = create_app()
