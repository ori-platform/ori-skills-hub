# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Compatibility entrypoint for ASGI servers."""

from __future__ import annotations

from hub.web.main import app, create_app

__all__ = ["app", "create_app"]
