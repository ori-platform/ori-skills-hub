# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from hub.storage.local import LocalStorage


def test_local_storage_round_trip(tmp_path) -> None:  # type: ignore[no-untyped-def]
    storage = LocalStorage(tmp_path)
    path = storage.store("energy", "0.1.0", b"tarball")
    assert path.exists()
    assert storage.read("energy", "0.1.0") == b"tarball"
