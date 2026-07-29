# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Environment-backed configuration for the Skills Hub."""

from __future__ import annotations

from dataclasses import dataclass, field
from os import environ
from pathlib import Path

from hub.core.errors import ConfigError


@dataclass(frozen=True)
class HubConfig:
    env: str
    database_url: str
    storage_backend: str
    storage_local_dir: Path
    admin_api_key: str = field(repr=False)
    admin_actor_id: str
    author_registration_enabled: bool
    author_token_ttl_seconds: int
    virustotal_api_key: str | None = field(repr=False)
    runtime_baseline: str
    specs_baseline: str


def _boolean_env(name: str, *, default: bool) -> bool:
    raw_value = environ.get(name)
    if raw_value is None:
        return default
    value = raw_value.strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    raise ConfigError(f"{name} must be true or false")


def _integer_env(name: str, *, default: int) -> int:
    raw_value = environ.get(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc


def load_from_env() -> HubConfig:
    storage_backend = environ.get("HUB_STORAGE_BACKEND", "local").strip().lower()
    if storage_backend != "local":
        raise ConfigError("only local storage backend is supported in bootstrap")

    admin_api_key = environ.get("HUB_ADMIN_API_KEY", "").strip()
    if not admin_api_key:
        raise ConfigError("HUB_ADMIN_API_KEY must be set")
    if len(admin_api_key) < 32:
        raise ConfigError("HUB_ADMIN_API_KEY must contain at least 32 characters")
    if (
        len(admin_api_key) > 4096
        or not admin_api_key.isascii()
        or not admin_api_key.isprintable()
        or any(character.isspace() for character in admin_api_key)
    ):
        raise ConfigError(
            "HUB_ADMIN_API_KEY must be a printable ASCII bearer value no longer "
            "than 4096 characters"
        )
    registration_enabled = _boolean_env(
        "HUB_AUTHOR_REGISTRATION_ENABLED",
        default=False,
    )

    admin_actor_id = environ.get("HUB_ADMIN_ACTOR_ID", "bootstrap-admin").strip()
    if not admin_actor_id:
        raise ConfigError("HUB_ADMIN_ACTOR_ID must not be empty")
    if len(admin_actor_id) > 255 or any(
        ord(character) < 32 or ord(character) == 127 for character in admin_actor_id
    ):
        raise ConfigError(
            "HUB_ADMIN_ACTOR_ID must be at most 255 characters without controls"
        )
    token_ttl_seconds = _integer_env(
        "HUB_AUTHOR_TOKEN_TTL_SECONDS",
        default=2_592_000,
    )
    if not 300 <= token_ttl_seconds <= 7_776_000:
        raise ConfigError(
            "HUB_AUTHOR_TOKEN_TTL_SECONDS must be between 300 and 7776000"
        )

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
        admin_actor_id=admin_actor_id,
        author_registration_enabled=registration_enabled,
        author_token_ttl_seconds=token_ttl_seconds,
        virustotal_api_key=virustotal,
        runtime_baseline=environ.get("HUB_RUNTIME_BASELINE", "v0.9.0-beta.2"),
        specs_baseline=environ.get("HUB_SPECS_BASELINE", "v1"),
    )
