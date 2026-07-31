# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""HUB-007 publish pipeline orchestration for community skill uploads.

Sequences author-upload verification, bounded package inspection, review and
scanner policy, Hub profile signing, immutable content-addressed storage, and
atomic persistence with audit. This module has no web-framework imports so the
pipeline is fully testable without HTTP plumbing.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Final, Protocol

from hub.core.errors import (
    PublishAuthorMismatchError,
    PublishConflictError,
    PublishReplayError,
)
from hub.core.models import PublishResult, ScannerVerdict, SkillStatus
from hub.core.review import publish_decision
from hub.core.validation import validate_skill_metadata
from hub.db.errors import PersistenceConflictError
from hub.db.repository import HubRepository
from hub.integrations.scan import ScanResult
from hub.security.author_identity import AuthenticatedAuthor
from hub.security.hub_keys import HubSigningKeys
from hub.security.signing import (
    ArtifactSignatureMetadata,
    canonical_manifest_bytes,
    verify_artifact_signature,
    verify_manifest_signature,
)
from hub.storage.objects import ContentAddressedStorage
from hub.storage.tarball import (
    DEFAULT_TARBALL_LIMITS,
    TarballLimits,
    extract_skill_yaml,
    rebuild_tarball,
)

SCANNER_TIMEOUT_SECONDS: Final = 30.0
_MAX_SCANNER_DETAIL_CHARS: Final = 1024


class Scanner(Protocol):
    """Structural scanner seam; see ``hub.integrations.scan``."""

    def scan(self, payload: bytes) -> ScanResult: ...


def _verdict_for(result: ScanResult) -> tuple[ScannerVerdict, str]:
    detail = result.detail[:_MAX_SCANNER_DETAIL_CHARS]
    if result.status == "clean":
        return ScannerVerdict.CLEAN, detail
    if result.status == "skipped":
        return ScannerVerdict.UNAVAILABLE, detail
    return ScannerVerdict.SUSPICIOUS, detail


async def _scan_with_timeout(
    scanner: Scanner,
    payload: bytes,
    *,
    timeout_seconds: float,
) -> tuple[ScannerVerdict, str]:
    """Run the scanner in an executor and fail closed on any error."""

    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, scanner.scan, payload),
            timeout=timeout_seconds,
        )
    except Exception as exc:
        return (
            ScannerVerdict.UNAVAILABLE,
            f"scanner unavailable: {type(exc).__name__}",
        )
    return _verdict_for(result)


async def publish_skill(
    *,
    upload_bytes: bytes,
    author_metadata: ArtifactSignatureMetadata,
    actor: AuthenticatedAuthor,
    repository: HubRepository,
    storage: ContentAddressedStorage,
    signing_keys: HubSigningKeys,
    scanner: Scanner,
    reason: str,
    correlation_id: str,
    idempotency_key: str,
    tarball_limits: TarballLimits = DEFAULT_TARBALL_LIMITS,
    scanner_timeout_seconds: float = SCANNER_TIMEOUT_SECONDS,
) -> PublishResult:
    """Run the publish pipeline for one author-signed upload.

    Ordering is load-bearing: the idempotency replay check runs before any
    work, the author signature is verified over the exact upload bytes before
    extraction, and nothing is stored or persisted until every verification
    has passed.
    """

    if await repository.publication_recorded_for_idempotency_key(
        actor_id=actor.actor_id,
        idempotency_key=idempotency_key,
    ):
        raise PublishReplayError("idempotency key was already consumed")

    verify_artifact_signature(upload_bytes, author_metadata, actor.public_key_b64)

    document = extract_skill_yaml(upload_bytes, limits=tarball_limits)
    manifest = document.mapping
    validation = validate_skill_metadata(manifest)
    if validation.author != actor.display_handle:
        raise PublishAuthorMismatchError(
            "skill author does not match the authenticated author"
        )

    if await repository.skill_version_exists(
        name=validation.name, version=validation.version
    ):
        raise PublishConflictError("skill name and version are already published")

    decision = publish_decision(manifest)
    verdict, detail = await _scan_with_timeout(
        scanner,
        upload_bytes,
        timeout_seconds=scanner_timeout_seconds,
    )
    initial_status = (
        SkillStatus.LISTED
        if decision.status is SkillStatus.LISTED and verdict is ScannerVerdict.CLEAN
        else SkillStatus.PENDING_REVIEW
    )

    manifest_signature = signing_keys.sign_manifest(manifest)
    signed_manifest: dict[str, object] = {
        **manifest,
        "signature": manifest_signature,
    }
    final_bytes = rebuild_tarball(upload_bytes, signed_manifest, limits=tarball_limits)
    artifact_metadata = signing_keys.sign_artifact(final_bytes)

    anchors = signing_keys.public_trust_anchors
    verify_manifest_signature(signed_manifest, anchors.manifest_public_key_b64)
    verify_artifact_signature(
        final_bytes, artifact_metadata, anchors.artifact_public_key_b64
    )

    artifact_digest = storage.store(final_bytes)
    manifest_digest = (
        "sha256:"
        + hashlib.sha256(canonical_manifest_bytes(signed_manifest)).hexdigest()
    )

    try:
        skill = await repository.create_publication(
            name=validation.name,
            version=validation.version,
            artifact_digest=artifact_digest,
            manifest_digest=manifest_digest,
            storage_key=artifact_digest,
            byte_size=len(final_bytes),
            artifact_signature=artifact_metadata["signature"],
            manifest_signature=manifest_signature,
            scanner_verdict=verdict,
            scanner_detail=detail,
            author_artifact_digest=author_metadata["artifact_sha256"],
            author_artifact_signature=author_metadata["signature"],
            declares_tier_cd=decision.declares_tier_cd,
            initial_status=initial_status,
            authenticated_actor_id=actor.actor_id,
            reason=reason,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )
    except PersistenceConflictError as exc:
        raise PublishConflictError(
            "publication conflicts with an existing durable record"
        ) from exc

    return PublishResult(
        name=skill.name,
        version=skill.version,
        status=SkillStatus(skill.status),
        artifact_digest=artifact_digest,
        manifest_digest=manifest_digest,
    )
