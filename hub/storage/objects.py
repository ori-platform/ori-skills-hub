# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Content-addressed immutable object store for hub artifacts."""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path
from typing import Final

from hub.core.errors import StorageIntegrityError, StorageSafetyError

_DIGEST_PREFIX: Final = "sha256:"
_DIGEST_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$")


class ContentAddressedStorage:
    """Store and read immutable objects addressed by their sha256 digest."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.objects_dir = self.root / "objects" / "sha256"
        self.objects_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _digest(artifact_bytes: bytes) -> str:
        return _DIGEST_PREFIX + hashlib.sha256(artifact_bytes).hexdigest()

    def _path_for(self, digest: str) -> Path:
        return self.objects_dir / digest[len(_DIGEST_PREFIX) :]

    def _sync_objects_directory(self) -> None:
        """Persist a newly linked object directory entry before returning."""
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(self.objects_dir, os.O_RDONLY | directory_flag)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def store(self, artifact_bytes: bytes) -> str:
        """Write artifact bytes once and return their content digest."""
        if not isinstance(artifact_bytes, bytes) or not artifact_bytes:
            raise StorageSafetyError("artifact payload must be non-empty bytes")

        digest = self._digest(artifact_bytes)
        final = self._path_for(digest)
        tmp = self.objects_dir / f".{final.name}.{uuid.uuid4().hex}.tmp"
        try:
            with tmp.open("xb") as handle:
                handle.write(artifact_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(tmp, final)
                self._sync_objects_directory()
            except FileExistsError:
                existing = final.read_bytes()
                if self._digest(existing) != digest:
                    raise StorageIntegrityError(
                        "existing object bytes do not match their content address"
                    ) from None
        finally:
            tmp.unlink(missing_ok=True)
        return digest

    def read(self, digest: str) -> bytes:
        """Read the object for a digest.

        Raises FileNotFoundError if no object exists for the digest.
        """
        if not isinstance(digest, str) or not _DIGEST_PATTERN.fullmatch(digest):
            raise StorageSafetyError("digest must be 'sha256:' plus 64 lowercase hex")

        artifact_bytes = self._path_for(digest).read_bytes()
        if self._digest(artifact_bytes) != digest:
            raise StorageIntegrityError(
                "stored object bytes do not match their content address"
            )
        return artifact_bytes
