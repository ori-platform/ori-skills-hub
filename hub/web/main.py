# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""FastAPI entrypoint for ori-skills-hub."""

from __future__ import annotations

from typing import Any

from hub import __version__


def create_app() -> Any:
    try:
        from fastapi import FastAPI
    except ImportError as exc:  # pragma: no cover - dependency installed in service env
        raise RuntimeError("FastAPI is required to create the Skills Hub app") from exc

    app = FastAPI(title="Ori Skills Hub", version=__version__)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


app = create_app()
