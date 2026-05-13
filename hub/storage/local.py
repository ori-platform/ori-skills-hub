# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Storage backends for signed skill tarballs."""

from __future__ import annotations

import os
from pathlib import Path

from hub.core.errors import StorageSafetyError


class LocalStorage:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, skill_name: str, version: str) -> Path:
        if not skill_name or not version:
            raise StorageSafetyError("skill name and version are required")
        filename = f"{skill_name}-{version}.tar.gz"
        path = (self.root / filename).resolve()
        if os.path.commonpath([self.root, path]) != str(self.root):
            raise StorageSafetyError("storage path escapes root")
        return path

    def store(self, skill_name: str, version: str, tarball_bytes: bytes) -> Path:
        path = self._path_for(skill_name, version)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(tarball_bytes)
        tmp.replace(path)
        return path

    def read(self, skill_name: str, version: str) -> bytes:
        return self._path_for(skill_name, version).read_bytes()
