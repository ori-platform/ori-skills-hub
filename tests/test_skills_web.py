# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""HTTP-level tests for the publish router."""

from __future__ import annotations

import asyncio
import gzip
import io
import json
import tarfile
from collections.abc import Coroutine
from pathlib import Path
from typing import Any, TypeVar, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from hub.db.repository import HubRepository
from hub.db.session import Database
from hub.integrations.scan import ScanResult
from hub.security.author_identity import AuthorIdentityService
from hub.security.hub_keys import HubSigningKeys
from hub.storage.objects import ContentAddressedStorage
from hub.storage.tarball import TarballLimits
from hub.web.main import create_app
from hub.web.skills import create_skill_router

_T = TypeVar("_T")

VECTOR_PATH = Path(__file__).parent / "fixtures" / "skill_signing_vectors_v1.json"
VECTORS = cast(dict[str, object], json.loads(VECTOR_PATH.read_text(encoding="utf-8")))
PUBLIC_KEY_B64 = cast(str, VECTORS["public_key_b64"])
PRIVATE_SEED_B64 = cast(str, VECTORS["private_seed_b64"])

_ADMIN_API_KEY = "a" * 32

_MANIFEST_YAML = b"""\
name: energy
version: 1.0.0
author: test-author
triggers:
  - name: threshold
    condition: "value > 1"
    action_tier: A
    safe_default_action: alert_operator
actions:
  available:
    - name: alert_operator
      tier: A
  defaults:
    threshold:
      - alert_operator
"""

_TIER_C_MANIFEST_YAML = b"""\
name: guarded-energy
version: 1.0.0
author: test-author
triggers:
  - name: thermal
    condition: "temp > 80"
    action_tier: C
    safe_default_action: alert_operator
actions:
  available:
    - name: alert_operator
      tier: A
  defaults:
    thermal:
      - alert_operator
"""


def _run(awaitable: Coroutine[Any, Any, _T]) -> _T:
    return asyncio.run(awaitable)


def _tarball(manifest_yaml: bytes = _MANIFEST_YAML) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("skill.yaml")
        member.type = tarfile.REGTYPE
        member.mode = 0o644
        member.size = len(manifest_yaml)
        archive.addfile(member, io.BytesIO(manifest_yaml))
    return gzip.compress(raw.getvalue(), compresslevel=9, mtime=0)


def _signing_keys() -> HubSigningKeys:
    return HubSigningKeys.from_base64_seeds(
        manifest_seed_b64=PRIVATE_SEED_B64,
        artifact_seed_b64=PRIVATE_SEED_B64,
    )


class _CleanScanner:
    def scan(self, _payload: bytes) -> ScanResult:
        return ScanResult(status="clean", detail="scanner clean")


class _Fixture:
    def __init__(self, tmp_path: Path) -> None:
        self.database = Database(f"sqlite:///{tmp_path / 'hub.db'}")
        _run(self.database.bootstrap_schema())
        self.repository = HubRepository(self.database)
        self.identity_service = AuthorIdentityService(
            self.database, token_ttl_seconds=300
        )
        registration = _run(
            self.identity_service.register(
                external_subject="github:123",
                display_handle="test-author",
                public_key_b64=PUBLIC_KEY_B64,
                authenticated_actor_id="test-bootstrap",
                correlation_id="test-bootstrap",
                idempotency_key="test-bootstrap",
            )
        )
        self.bearer_token = registration.credential.bearer_token
        self.storage = ContentAddressedStorage(tmp_path / "artifact-store")
        self.upload = _tarball()
        self.metadata_json = json.dumps(_signing_keys().sign_artifact(self.upload))

    def app(self) -> Any:
        return create_app(
            author_identity_service=self.identity_service,
            admin_api_key=_ADMIN_API_KEY,
            skill_repository=self.repository,
            artifact_storage=self.storage,
            hub_signing_keys=_signing_keys(),
            scanner=_CleanScanner(),
        )

    def headers(self, *, idempotency_key: str = "publish-1") -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.bearer_token}",
            "X-Author-Artifact-Metadata": self.metadata_json,
            "Idempotency-Key": idempotency_key,
            "X-Correlation-ID": "correlation-1",
        }


@pytest.fixture()
def fixture(tmp_path: Path) -> Any:
    harness = _Fixture(tmp_path)
    yield harness
    _run(harness.database.dispose())


def test_publish_happy_path_returns_201_without_signature_values(
    fixture: Any,
) -> None:
    client = TestClient(fixture.app())
    response = client.post(
        "/api/skills", content=fixture.upload, headers=fixture.headers()
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["name"] == "energy"
    assert payload["status"] == "listed"
    assert payload["artifact_digest"].startswith("sha256:")
    assert payload["manifest_digest"].startswith("sha256:")
    assert "signature" not in payload


def test_publish_requires_author_bearer(fixture: Any) -> None:
    client = TestClient(fixture.app())
    headers = fixture.headers()
    del headers["Authorization"]
    response = client.post("/api/skills", content=fixture.upload, headers=headers)
    assert response.status_code == 401

    response = client.post(
        "/api/skills",
        content=fixture.upload,
        headers={**fixture.headers(), "Authorization": "Bearer wrong"},
    )
    assert response.status_code == 401


@pytest.mark.parametrize(
    "missing_header",
    ["X-Author-Artifact-Metadata", "Idempotency-Key", "X-Correlation-ID"],
)
def test_publish_requires_contract_headers(fixture: Any, missing_header: str) -> None:
    client = TestClient(fixture.app())
    headers = fixture.headers()
    del headers[missing_header]
    response = client.post("/api/skills", content=fixture.upload, headers=headers)
    assert response.status_code == 400


def test_publish_rejects_malformed_metadata_header(fixture: Any) -> None:
    client = TestClient(fixture.app())
    response = client.post(
        "/api/skills",
        content=fixture.upload,
        headers={
            **fixture.headers(),
            "X-Author-Artifact-Metadata": "not json",
        },
    )
    assert response.status_code == 422


def test_publish_accepts_metadata_header_larger_than_general_header_limit(
    fixture: Any,
) -> None:
    client = TestClient(fixture.app())
    headers = fixture.headers()
    headers["X-Author-Artifact-Metadata"] += " " * 300
    response = client.post("/api/skills", content=fixture.upload, headers=headers)
    assert response.status_code == 201


def test_publish_rejects_oversized_metadata_header(fixture: Any) -> None:
    client = TestClient(fixture.app())
    headers = fixture.headers()
    headers["X-Author-Artifact-Metadata"] += " " * 4097
    response = client.post("/api/skills", content=fixture.upload, headers=headers)
    assert response.status_code == 422


@pytest.mark.parametrize("header", ["Idempotency-Key", "X-Correlation-ID"])
def test_publish_rejects_oversized_request_headers(fixture: Any, header: str) -> None:
    client = TestClient(fixture.app())
    headers = fixture.headers()
    headers[header] = "x" * 256
    response = client.post("/api/skills", content=fixture.upload, headers=headers)
    assert response.status_code == 400


def test_publish_rejects_tampered_upload(fixture: Any) -> None:
    client = TestClient(fixture.app())
    response = client.post(
        "/api/skills",
        content=fixture.upload + b"!",
        headers=fixture.headers(),
    )
    assert response.status_code == 422


def test_publish_replay_returns_409(fixture: Any) -> None:
    client = TestClient(fixture.app())
    first = client.post(
        "/api/skills", content=fixture.upload, headers=fixture.headers()
    )
    assert first.status_code == 201
    replay = client.post(
        "/api/skills", content=fixture.upload, headers=fixture.headers()
    )
    assert replay.status_code == 409


def _publish_manifest(
    client: TestClient,
    fixture: Any,
    manifest_yaml: bytes,
    *,
    idempotency_key: str,
) -> None:
    upload = _tarball(manifest_yaml)
    headers = fixture.headers(idempotency_key=idempotency_key)
    headers["X-Author-Artifact-Metadata"] = json.dumps(
        _signing_keys().sign_artifact(upload)
    )
    response = client.post("/api/skills", content=upload, headers=headers)
    assert response.status_code == 201


def test_public_list_and_detail_exclude_pending_review_skills(fixture: Any) -> None:
    client = TestClient(fixture.app())
    _publish_manifest(client, fixture, _MANIFEST_YAML, idempotency_key="listed")
    _publish_manifest(
        client,
        fixture,
        _TIER_C_MANIFEST_YAML,
        idempotency_key="pending-review",
    )

    listing = client.get("/api/skills")
    assert listing.status_code == 200
    assert [skill["name"] for skill in listing.json()["skills"]] == ["energy"]

    detail = client.get("/api/skills/energy")
    assert detail.status_code == 200
    assert detail.json()["name"] == "energy"
    assert detail.json()["versions"][0]["version"] == "1.0.0"

    assert client.get("/api/skills/guarded-energy").status_code == 404


def test_download_returns_exact_listed_artifact_and_increments_once(
    fixture: Any,
) -> None:
    client = TestClient(fixture.app())
    _publish_manifest(client, fixture, _MANIFEST_YAML, idempotency_key="download")
    listed = _run(fixture.repository.get_listed_skill(name="energy", version="1.0.0"))

    response = client.get("/api/skills/energy/download?version=1.0.0")
    assert response.status_code == 200
    assert response.content == fixture.storage.read(listed.artifact_digest)
    assert response.headers["content-type"] == "application/gzip"
    assert (
        "filename*=UTF-8''energy-1.0.0.tar.gz"
        in response.headers["content-disposition"]
    )
    stored = _run(fixture.repository.get_skill(name="energy", version="1.0.0"))
    assert stored.downloads == 1


def test_download_hides_missing_or_nonpublic_versions(fixture: Any) -> None:
    client = TestClient(fixture.app())
    _publish_manifest(client, fixture, _TIER_C_MANIFEST_YAML, idempotency_key="pending")

    assert client.get("/api/skills/missing/download?version=1.0.0").status_code == 404
    guarded_download = client.get("/api/skills/guarded-energy/download?version=1.0.0")
    assert guarded_download.status_code == 404
    assert client.get("/api/skills/guarded-energy/download").status_code == 404


def test_download_does_not_increment_when_artifact_is_unavailable(fixture: Any) -> None:
    client = TestClient(fixture.app())
    _publish_manifest(client, fixture, _MANIFEST_YAML, idempotency_key="unavailable")
    listed = _run(fixture.repository.get_listed_skill(name="energy", version="1.0.0"))
    artifact_path = fixture.storage.objects_dir / listed.artifact_digest.removeprefix(
        "sha256:"
    )
    artifact_path.unlink()

    response = client.get("/api/skills/energy/download?version=1.0.0")
    assert response.status_code == 503
    stored = _run(fixture.repository.get_skill(name="energy", version="1.0.0"))
    assert stored.downloads == 0


def test_oversized_upload_is_rejected_at_ingress(tmp_path: Path) -> None:
    harness = _Fixture(tmp_path)
    try:
        app = FastAPI()
        app.include_router(
            create_skill_router(
                harness.identity_service,
                repository=harness.repository,
                storage=harness.storage,
                signing_keys=_signing_keys(),
                scanner=_CleanScanner(),
                tarball_limits=TarballLimits(max_archive_bytes=2048),
            )
        )
        client = TestClient(app)
        response = client.post(
            "/api/skills",
            content=b"\x00" * 4096,
            headers=harness.headers(),
        )
        assert response.status_code == 413
    finally:
        _run(harness.database.dispose())
