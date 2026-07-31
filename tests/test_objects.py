# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from hub.core.errors import StorageIntegrityError, StorageSafetyError
from hub.storage.objects import ContentAddressedStorage


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _object_entries(storage: ContentAddressedStorage) -> list[os.DirEntry[str]]:
    return list(os.scandir(storage.objects_dir))


def test_store_returns_digest_and_writes_object(tmp_path: Path) -> None:
    storage = ContentAddressedStorage(tmp_path)
    payload = b"immutable artifact bytes"
    digest = storage.store(payload)
    assert digest == _digest(payload)
    assert (storage.objects_dir / digest.removeprefix("sha256:")).read_bytes() == (
        payload
    )


def test_store_twice_keeps_single_object_without_temp_files(tmp_path: Path) -> None:
    storage = ContentAddressedStorage(tmp_path)
    payload = b"duplicate payload"
    assert storage.store(payload) == storage.store(payload)
    entries = _object_entries(storage)
    assert len(entries) == 1
    assert entries[0].name == _digest(payload).removeprefix("sha256:")


def test_store_adopts_pre_existing_matching_object(tmp_path: Path) -> None:
    storage = ContentAddressedStorage(tmp_path)
    payload = b"already on disk"
    digest = _digest(payload)
    (storage.objects_dir / digest.removeprefix("sha256:")).write_bytes(payload)
    assert storage.store(payload) == digest
    assert len(_object_entries(storage)) == 1


def test_store_refuses_pre_existing_mismatching_object(tmp_path: Path) -> None:
    storage = ContentAddressedStorage(tmp_path)
    payload = b"requested payload"
    wrong = b"different bytes already at the digest path"
    digest = _digest(payload)
    object_path = storage.objects_dir / digest.removeprefix("sha256:")
    object_path.write_bytes(wrong)
    with pytest.raises(StorageIntegrityError):
        storage.store(payload)
    assert object_path.read_bytes() == wrong
    assert len(_object_entries(storage)) == 1


def test_concurrent_identical_stores_converge_on_one_object(tmp_path: Path) -> None:
    storage = ContentAddressedStorage(tmp_path)
    payload = b"hot payload" * 1024
    digest = _digest(payload)
    with ThreadPoolExecutor(max_workers=8) as pool:
        digests = list(pool.map(lambda _: storage.store(payload), range(8)))
    assert digests == [digest] * 8
    entries = _object_entries(storage)
    assert len(entries) == 1
    assert entries[0].name == digest.removeprefix("sha256:")
    assert storage.read(digest) == payload


def test_concurrent_distinct_stores_each_write_own_object(tmp_path: Path) -> None:
    storage = ContentAddressedStorage(tmp_path)
    payloads = [f"payload-{index}".encode() for index in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        digests = list(pool.map(storage.store, payloads))
    assert digests == [_digest(payload) for payload in payloads]
    assert len(digests) == len(set(digests))
    assert len(_object_entries(storage)) == len(payloads)
    for payload, digest in zip(payloads, digests, strict=True):
        assert storage.read(digest) == payload


@pytest.mark.parametrize(
    "digest",
    [
        "0" * 64,
        "sha256:" + "A" * 64,
        "sha256:" + "0" * 63,
        "sha256:" + "0" * 65,
        "sha256:" + "../" + "0" * 62,
        "sha256:" + "0" * 10 + "/" + "0" * 53,
        "sha256:" + "0" * 10 + "\\" + "0" * 53,
        "sha1:" + "0" * 64,
        "",
    ],
)
def test_read_rejects_malformed_digests(tmp_path: Path, digest: str) -> None:
    storage = ContentAddressedStorage(tmp_path)
    with pytest.raises(StorageSafetyError):
        storage.read(digest)


def test_read_missing_object_raises_file_not_found(tmp_path: Path) -> None:
    storage = ContentAddressedStorage(tmp_path)
    with pytest.raises(FileNotFoundError):
        storage.read(_digest(b"never stored"))


def test_read_detects_corrupted_object(tmp_path: Path) -> None:
    storage = ContentAddressedStorage(tmp_path)
    digest = storage.store(b"original bytes")
    object_path = storage.objects_dir / digest.removeprefix("sha256:")
    object_path.write_bytes(b"corrupted bytes")
    with pytest.raises(StorageIntegrityError):
        storage.read(digest)


def test_store_rejects_empty_and_non_bytes(tmp_path: Path) -> None:
    storage = ContentAddressedStorage(tmp_path)
    with pytest.raises(StorageSafetyError):
        storage.store(b"")
    with pytest.raises(StorageSafetyError):
        storage.store("text")  # type: ignore[arg-type]
    assert _object_entries(storage) == []
