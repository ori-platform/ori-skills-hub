# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from hub.core.config import load_from_env
from hub.core.errors import ConfigError


def test_load_from_env_requires_admin_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HUB_ADMIN_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        load_from_env()


def test_load_from_env_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_API_KEY", "a" * 32)
    monkeypatch.delenv("HUB_ADMIN_ACTOR_ID", raising=False)
    monkeypatch.delenv("HUB_AUTHOR_REGISTRATION_ENABLED", raising=False)
    monkeypatch.delenv("HUB_AUTHOR_TOKEN_TTL_SECONDS", raising=False)
    monkeypatch.delenv("HUB_PUBLISH_ENABLED", raising=False)
    monkeypatch.delenv("HUB_SCAN_WORKER_ENABLED", raising=False)

    cfg = load_from_env()

    assert cfg.storage_backend == "local"
    assert cfg.admin_actor_id == "bootstrap-admin"
    assert cfg.author_registration_enabled is False
    assert cfg.author_token_ttl_seconds == 2_592_000
    assert cfg.publish_enabled is False
    assert cfg.scan_worker_enabled is True
    assert cfg.scan_lease_seconds == 30
    assert cfg.scan_max_attempts == 20
    assert cfg.scan_max_age_seconds == 86_400
    assert cfg.admin_api_key not in repr(cfg)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("HUB_AUTHOR_REGISTRATION_ENABLED", "sometimes"),
        ("HUB_AUTHOR_TOKEN_TTL_SECONDS", "not-an-integer"),
        ("HUB_AUTHOR_TOKEN_TTL_SECONDS", "299"),
        ("HUB_AUTHOR_TOKEN_TTL_SECONDS", "7776001"),
        ("HUB_PUBLISH_ENABLED", "sometimes"),
        ("HUB_SCAN_WORKER_ENABLED", "sometimes"),
        ("HUB_SCAN_LEASE_SECONDS", "0"),
        ("HUB_SCAN_MAX_ATTEMPTS", "1001"),
        ("HUB_SCAN_MAX_AGE_SECONDS", "59"),
        ("HUB_SCAN_INITIAL_BACKOFF_SECONDS", "301"),
        ("HUB_SCAN_MAX_BACKOFF_SECONDS", "0"),
        ("HUB_SCAN_JITTER_SECONDS", "301"),
    ],
)
def test_load_from_env_rejects_invalid_author_identity_config(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_API_KEY", "a" * 32)
    monkeypatch.setenv(name, value)

    with pytest.raises(ConfigError):
        load_from_env()


def test_load_from_env_rejects_weak_admin_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_API_KEY", "secret")

    with pytest.raises(ConfigError):
        load_from_env()


def test_publish_mode_rejects_disabled_local_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_API_KEY", "a" * 32)
    monkeypatch.setenv("HUB_PUBLISH_ENABLED", "true")
    monkeypatch.setenv("HUB_VIRUSTOTAL_API_KEY", "configured-provider-key")
    monkeypatch.setenv("HUB_SCAN_WORKER_ENABLED", "false")

    with pytest.raises(ConfigError, match="external worker mode"):
        load_from_env()


@pytest.mark.parametrize(
    "admin_key",
    [
        f"{'a' * 16} {'a' * 16}",
        f"{'a' * 16}\n{'a' * 16}",
        "\u00e9" * 32,
        "a" * 4097,
    ],
)
def test_load_from_env_rejects_unusable_admin_key(
    monkeypatch: pytest.MonkeyPatch,
    admin_key: str,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_API_KEY", admin_key)

    with pytest.raises(ConfigError):
        load_from_env()


@pytest.mark.parametrize("actor_id", [f"{'a' * 128}\n{'a' * 128}", "a" * 256])
def test_load_from_env_rejects_invalid_admin_actor_id(
    monkeypatch: pytest.MonkeyPatch,
    actor_id: str,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_API_KEY", "a" * 32)
    monkeypatch.setenv("HUB_ADMIN_ACTOR_ID", actor_id)

    with pytest.raises(ConfigError):
        load_from_env()


def test_load_from_env_enables_author_registration_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_API_KEY", "a" * 32)
    monkeypatch.setenv("HUB_ADMIN_ACTOR_ID", "security-operator")
    monkeypatch.setenv("HUB_AUTHOR_REGISTRATION_ENABLED", "true")
    monkeypatch.setenv("HUB_AUTHOR_TOKEN_TTL_SECONDS", "3600")

    cfg = load_from_env()

    assert cfg.admin_actor_id == "security-operator"
    assert cfg.author_registration_enabled is True
    assert cfg.author_token_ttl_seconds == 3600


def test_load_from_env_requires_scanner_key_for_publish_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_API_KEY", "a" * 32)
    monkeypatch.setenv("HUB_PUBLISH_ENABLED", "true")
    monkeypatch.delenv("HUB_VIRUSTOTAL_API_KEY", raising=False)

    with pytest.raises(ConfigError, match="HUB_VIRUSTOTAL_API_KEY"):
        load_from_env()
