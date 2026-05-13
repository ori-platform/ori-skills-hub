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
    monkeypatch.setenv("HUB_ADMIN_API_KEY", "secret")
    cfg = load_from_env()
    assert cfg.storage_backend == "local"
    assert cfg.runtime_baseline == "v0.9.0-beta.2"
