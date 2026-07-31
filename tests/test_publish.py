# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests for the HUB-007 publish pipeline orchestration."""

from __future__ import annotations

import asyncio
import base64
import gzip
import io
import json
import tarfile
import time
from collections.abc import Coroutine
from pathlib import Path
from typing import Any, TypeVar, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hub.core.errors import (
    PublishAuthorMismatchError,
    PublishConflictError,
    PublishReplayError,
    SignatureVerificationError,
)
from hub.core.models import ScannerVerdict, SkillStatus
from hub.core.publish import publish_skill
from hub.db._models import ArtifactModel
from hub.db.repository import HubRepository
from hub.db.session import Database
from hub.integrations.scan import ScanResult
from hub.security.author_identity import (
    AuthenticatedAuthor,
    AuthorIdentityService,
)
from hub.security.hub_keys import HubSigningKeys
from hub.security.signing import (
    ArtifactSignatureMetadata,
    verify_artifact_signature,
    verify_manifest_signature,
)
from hub.storage.objects import ContentAddressedStorage
from hub.storage.tarball import extract_skill_yaml

_T = TypeVar("_T")

VECTOR_PATH = Path(__file__).parent / "fixtures" / "skill_signing_vectors_v1.json"
VECTORS = cast(dict[str, object], json.loads(VECTOR_PATH.read_text(encoding="utf-8")))
PUBLIC_KEY_B64 = cast(str, VECTORS["public_key_b64"])
PRIVATE_SEED_B64 = cast(str, VECTORS["private_seed_b64"])

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
name: energy-guard
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


def _tarball(manifest_yaml: bytes) -> bytes:
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


def _author_metadata(upload_bytes: bytes) -> ArtifactSignatureMetadata:
    return _signing_keys().sign_artifact(upload_bytes)


def _attacker_metadata(upload_bytes: bytes) -> ArtifactSignatureMetadata:
    attacker = Ed25519PrivateKey.generate()
    seed = attacker.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    seed_b64 = base64.b64encode(seed).decode("ascii")
    return HubSigningKeys.from_base64_seeds(
        manifest_seed_b64=seed_b64,
        artifact_seed_b64=seed_b64,
    ).sign_artifact(upload_bytes)


class _CleanScanner:
    def scan(self, _payload: bytes) -> ScanResult:
        return ScanResult(status="clean", detail="scanner clean")


class _SuspiciousScanner:
    def scan(self, _payload: bytes) -> ScanResult:
        return ScanResult(status="suspicious", detail="matched malware signature")


class _SkippedScanner:
    def scan(self, _payload: bytes) -> ScanResult:
        return ScanResult(status="skipped", detail="HUB_VIRUSTOTAL_API_KEY not set")


class _RaisingScanner:
    def scan(self, _payload: bytes) -> ScanResult:
        raise RuntimeError("scanner transport exploded")


class _SlowScanner:
    def scan(self, _payload: bytes) -> ScanResult:
        time.sleep(0.3)
        return ScanResult(status="clean", detail="scanner clean")


class _Harness:
    def __init__(
        self,
        database: Database,
        repository: HubRepository,
        storage: ContentAddressedStorage,
        actor: AuthenticatedAuthor,
    ) -> None:
        self.database = database
        self.repository = repository
        self.storage = storage
        self.actor = actor

    async def publish(
        self,
        upload_bytes: bytes,
        *,
        author_metadata: ArtifactSignatureMetadata | None = None,
        scanner: object = None,
        idempotency_key: str = "publish-1",
        correlation_id: str = "correlation-1",
        scanner_timeout_seconds: float = 30.0,
    ) -> Any:
        return await publish_skill(
            upload_bytes=upload_bytes,
            author_metadata=(
                author_metadata
                if author_metadata is not None
                else _author_metadata(upload_bytes)
            ),
            actor=self.actor,
            repository=self.repository,
            storage=self.storage,
            signing_keys=_signing_keys(),
            scanner=scanner if scanner is not None else _CleanScanner(),
            reason="skill publication",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            scanner_timeout_seconds=scanner_timeout_seconds,
        )

    async def artifact_for(self, name: str, version: str) -> ArtifactModel:
        skill = await self.repository.get_skill(name=name, version=version)
        async with self.database.transaction() as session:
            artifact = await session.get(ArtifactModel, skill.artifact_id)
        assert artifact is not None
        return artifact


async def _setup(tmp_path: Path) -> _Harness:
    database = Database(f"sqlite:///{tmp_path / 'hub.db'}")
    await database.bootstrap_schema()
    repository = HubRepository(database)
    identity_service = AuthorIdentityService(database, token_ttl_seconds=300)
    registration = await identity_service.register(
        external_subject="github:123",
        display_handle="test-author",
        public_key_b64=PUBLIC_KEY_B64,
        authenticated_actor_id="test-bootstrap",
        correlation_id="test-bootstrap",
        idempotency_key="test-bootstrap",
    )
    actor = AuthenticatedAuthor(
        actor_id=registration.author.author_id,
        external_subject="github:123",
        display_handle="test-author",
        public_key_b64=PUBLIC_KEY_B64,
        credential_id="cred-1",
    )
    storage = ContentAddressedStorage(tmp_path / "artifact-store")
    return _Harness(database, repository, storage, actor)


def test_happy_path_lists_and_persists_dual_profile_artifacts(tmp_path: Path) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            upload = _tarball(_MANIFEST_YAML)
            result = await harness.publish(upload)

            assert result.status is SkillStatus.LISTED
            assert result.name == "energy"

            keys = _signing_keys()
            anchors = keys.public_trust_anchors
            final_bytes = harness.storage.read(result.artifact_digest)
            artifact_metadata = keys.sign_artifact(final_bytes)
            verify_artifact_signature(
                final_bytes, artifact_metadata, anchors.artifact_public_key_b64
            )
            signed_manifest = extract_skill_yaml(final_bytes).mapping
            verify_manifest_signature(signed_manifest, anchors.manifest_public_key_b64)

            artifact = await harness.artifact_for("energy", "1.0.0")
            assert artifact.scanner_verdict == ScannerVerdict.CLEAN.value
            assert (
                artifact.author_artifact_digest
                == _author_metadata(upload)["artifact_sha256"]
            )
            assert (
                artifact.author_artifact_signature
                == _author_metadata(upload)["signature"]
            )

            history = await harness.repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert [entry.new_status for entry in history] == [SkillStatus.LISTED.value]
        finally:
            await harness.database.dispose()

    _run(scenario())


def test_tier_c_skill_enters_pending_review_with_clean_scanner(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            result = await harness.publish(_tarball(_TIER_C_MANIFEST_YAML))
            assert result.status is SkillStatus.PENDING_REVIEW
            artifact = await harness.artifact_for("energy-guard", "1.0.0")
            assert artifact.scanner_verdict == ScannerVerdict.CLEAN.value
        finally:
            await harness.database.dispose()

    _run(scenario())


@pytest.mark.parametrize(
    ("scanner", "expected_verdict"),
    [
        (_SuspiciousScanner(), "suspicious"),
        (_SkippedScanner(), "unavailable"),
        (_RaisingScanner(), "unavailable"),
    ],
)
def test_non_clean_scanner_forces_pending_review_and_persists_verdict(
    tmp_path: Path,
    scanner: object,
    expected_verdict: str,
) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            result = await harness.publish(_tarball(_MANIFEST_YAML), scanner=scanner)
            assert result.status is SkillStatus.PENDING_REVIEW
            artifact = await harness.artifact_for("energy", "1.0.0")
            assert artifact.scanner_verdict == expected_verdict
            assert artifact.scanner_detail
        finally:
            await harness.database.dispose()

    _run(scenario())


def test_scanner_timeout_fails_closed(tmp_path: Path) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            result = await harness.publish(
                _tarball(_MANIFEST_YAML),
                scanner=_SlowScanner(),
                scanner_timeout_seconds=0.05,
            )
            assert result.status is SkillStatus.PENDING_REVIEW
            artifact = await harness.artifact_for("energy", "1.0.0")
            assert artifact.scanner_verdict == ScannerVerdict.UNAVAILABLE.value
        finally:
            await harness.database.dispose()

    _run(scenario())


def test_garbage_author_metadata_fails_before_any_side_effect(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            upload = _tarball(_MANIFEST_YAML)
            garbage = ArtifactSignatureMetadata(
                artifact_sha256="sha256:" + "0" * 64,
                schema="ori.skill_artifact_signature.v1",
                signature="ed25519:" + base64.b64encode(b"\x00" * 64).decode(),
            )
            with pytest.raises(SignatureVerificationError):
                await harness.publish(upload, author_metadata=garbage)

            assert not await harness.repository.skill_version_exists(
                name="energy", version="1.0.0"
            )
            assert list(harness.storage.objects_dir.iterdir()) == []
        finally:
            await harness.database.dispose()

    _run(scenario())


def test_wrong_author_key_is_rejected(tmp_path: Path) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            upload = _tarball(_MANIFEST_YAML)
            with pytest.raises(SignatureVerificationError):
                await harness.publish(
                    upload, author_metadata=_attacker_metadata(upload)
                )
            assert not await harness.repository.skill_version_exists(
                name="energy", version="1.0.0"
            )
        finally:
            await harness.database.dispose()

    _run(scenario())


def test_tampered_bytes_fail_digest_before_signature(tmp_path: Path) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            upload = _tarball(_MANIFEST_YAML)
            metadata = _author_metadata(upload)
            with pytest.raises(SignatureVerificationError, match="digest"):
                await harness.publish(upload + b"!", author_metadata=metadata)
            assert not await harness.repository.skill_version_exists(
                name="energy", version="1.0.0"
            )
        finally:
            await harness.database.dispose()

    _run(scenario())


def test_manifest_author_must_match_authenticated_author(tmp_path: Path) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            foreign_manifest = _MANIFEST_YAML.replace(
                b"author: test-author", b"author: someone-else"
            )
            upload = _tarball(foreign_manifest)
            with pytest.raises(PublishAuthorMismatchError):
                await harness.publish(upload)
            assert not await harness.repository.skill_version_exists(
                name="energy", version="1.0.0"
            )
        finally:
            await harness.database.dispose()

    _run(scenario())


def test_replay_is_rejected_before_signature_verification(tmp_path: Path) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            upload = _tarball(_MANIFEST_YAML)
            await harness.publish(upload, idempotency_key="publish-once")

            garbage = ArtifactSignatureMetadata(
                artifact_sha256="sha256:" + "0" * 64,
                schema="ori.skill_artifact_signature.v1",
                signature="ed25519:not-valid-at-all",
            )
            with pytest.raises(PublishReplayError):
                await harness.publish(
                    upload,
                    author_metadata=garbage,
                    idempotency_key="publish-once",
                )

            history = await harness.repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert len(history) == 1
        finally:
            await harness.database.dispose()

    _run(scenario())


def test_same_name_version_with_fresh_key_conflicts(tmp_path: Path) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            upload = _tarball(_MANIFEST_YAML)
            await harness.publish(upload, idempotency_key="publish-1")
            with pytest.raises(PublishConflictError):
                await harness.publish(upload, idempotency_key="publish-2")
        finally:
            await harness.database.dispose()

    _run(scenario())


def test_concurrent_publishes_have_exactly_one_winner(tmp_path: Path) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            upload = _tarball(_MANIFEST_YAML)
            outcomes = await asyncio.gather(
                harness.publish(upload, idempotency_key="race-1"),
                harness.publish(upload, idempotency_key="race-2"),
                return_exceptions=True,
            )
            winners = [
                outcome
                for outcome in outcomes
                if not isinstance(outcome, BaseException)
            ]
            conflicts = [
                outcome
                for outcome in outcomes
                if isinstance(outcome, PublishConflictError)
            ]
            assert len(winners) == 1
            assert len(conflicts) == 1

            history = await harness.repository.get_transition_history(
                name="energy", version="1.0.0"
            )
            assert len(history) == 1
        finally:
            await harness.database.dispose()

    _run(scenario())


def test_signature_profiles_are_not_interchanged(tmp_path: Path) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            upload = _tarball(_MANIFEST_YAML)
            result = await harness.publish(upload)

            artifact = await harness.artifact_for("energy", "1.0.0")
            assert artifact.artifact_signature != artifact.manifest_signature
            author_signature = _author_metadata(upload)["signature"]
            assert artifact.artifact_signature != author_signature
            assert artifact.manifest_signature != author_signature
            assert result.artifact_digest == artifact.artifact_digest
        finally:
            await harness.database.dispose()

    _run(scenario())


def test_persistence_failure_leaves_adoptable_orphan_and_no_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        harness = await _setup(tmp_path)
        try:
            upload = _tarball(_MANIFEST_YAML)

            async def injected_failure(**_kwargs: object) -> object:
                raise RuntimeError("injected persistence failure")

            monkeypatch.setattr(
                harness.repository, "create_publication", injected_failure
            )
            with pytest.raises(RuntimeError, match="injected persistence"):
                await harness.publish(upload, idempotency_key="fragile-1")

            assert not await harness.repository.skill_version_exists(
                name="energy", version="1.0.0"
            )
            orphans = list(harness.storage.objects_dir.iterdir())
            assert len(orphans) == 1

            monkeypatch.undo()
            result = await harness.publish(upload, idempotency_key="fragile-2")
            assert result.status is SkillStatus.LISTED
            assert len(list(harness.storage.objects_dir.iterdir())) == 1
        finally:
            await harness.database.dispose()

    _run(scenario())
