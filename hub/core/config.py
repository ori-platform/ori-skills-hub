# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Environment-backed configuration for the Skills Hub."""

from __future__ import annotations

from dataclasses import dataclass
from os import environ
from pathlib import Path

from hub.core.errors import ConfigError


@dataclass(frozen=True)
class HubConfig:
    env: str
    database_url: str
    storage_backend: str
    storage_local_dir: Path
    admin_api_key: str
    virustotal_api_key: str | None
    runtime_baseline: str
    specs_baseline: str


def load_from_env() -> HubConfig:
    storage_backend = environ.get("HUB_STORAGE_BACKEND", "local").strip().lower()
    if storage_backend != "local":
        raise ConfigError("only local storage backend is supported in bootstrap")

    admin_api_key = environ.get("HUB_ADMIN_API_KEY", "").strip()
    if not admin_api_key:
        raise ConfigError("HUB_ADMIN_API_KEY must be set")

    virustotal = environ.get("HUB_VIRUSTOTAL_API_KEY", "").strip() or None
    return HubConfig(
        env=environ.get("HUB_ENV", "development"),
        database_url=environ.get(
            "HUB_DATABASE_URL", "sqlite:///./.hub-data/skills-hub.db"
        ),
        storage_backend=storage_backend,
        storage_local_dir=Path(
            environ.get("HUB_STORAGE_LOCAL_DIR", "./.hub-data/tarballs")
        ),
        admin_api_key=admin_api_key,
        virustotal_api_key=virustotal,
        runtime_baseline=environ.get("HUB_RUNTIME_BASELINE", "v0.9.0-beta.2"),
        specs_baseline=environ.get("HUB_SPECS_BASELINE", "v1"),
    )
