# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Cross-repository tests for both skill-signing v1 profiles."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from hub.core.errors import SignatureVerificationError
from hub.security.hub_keys import HubSigningKeys
from hub.security.signing import (
    SIGNING_VECTOR_SHA256,
    ArtifactSignatureMetadata,
    canonical_manifest_bytes,
    decode_public_key,
    decode_signature,
    verify_artifact_signature,
    verify_manifest_signature,
)

VECTOR_PATH = Path(__file__).parent / "fixtures" / "skill_signing_vectors_v1.json"
VECTORS = cast(dict[str, object], json.loads(VECTOR_PATH.read_text(encoding="utf-8")))
PUBLIC_KEY_B64 = cast(str, VECTORS["public_key_b64"])
PRIVATE_SEED_B64 = cast(str, VECTORS["private_seed_b64"])
MANIFEST_PROFILE = cast(dict[str, object], VECTORS["manifest_profile"])
ARTIFACT_PROFILE = cast(dict[str, object], VECTORS["artifact_profile"])
PARSED_SKILL = cast(dict[str, object], MANIFEST_PROFILE["parsed_skill"])
ARTIFACT_BYTES = base64.b64decode(
    cast(str, ARTIFACT_PROFILE["artifact_bytes_b64"]), validate=True
)
ARTIFACT_METADATA = cast(
    ArtifactSignatureMetadata, ARTIFACT_PROFILE["detached_metadata"]
)


def _vector_keys() -> HubSigningKeys:
    return HubSigningKeys.from_base64_seeds(
        manifest_seed_b64=PRIVATE_SEED_B64,
        artifact_seed_b64=PRIVATE_SEED_B64,
    )


def test_shared_vector_file_is_byte_identical() -> None:
    assert hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest() == SIGNING_VECTOR_SHA256


def test_manifest_vector_canonical_bytes_hash_and_signature() -> None:
    canonical = canonical_manifest_bytes(PARSED_SKILL)
    assert base64.b64encode(canonical).decode("ascii") == cast(
        str, MANIFEST_PROFILE["canonical_unsigned_b64"]
    )
    assert hashlib.sha256(canonical).hexdigest() == cast(
        str, MANIFEST_PROFILE["canonical_unsigned_sha256"]
    )

    signed = dict(PARSED_SKILL)
    signed["signature"] = MANIFEST_PROFILE["signature"]
    verify_manifest_signature(signed, PUBLIC_KEY_B64)


def test_artifact_vector_digest_and_signature() -> None:
    verify_artifact_signature(ARTIFACT_BYTES, ARTIFACT_METADATA, PUBLIC_KEY_B64)


def test_hub_signing_round_trips_match_shared_vectors() -> None:
    keys = _vector_keys()

    assert keys.public_trust_anchors.manifest_public_key_b64 == PUBLIC_KEY_B64
    assert keys.public_trust_anchors.artifact_public_key_b64 == PUBLIC_KEY_B64
    assert keys.sign_manifest(PARSED_SKILL) == MANIFEST_PROFILE["signature"]
    assert keys.sign_artifact(ARTIFACT_BYTES) == ARTIFACT_METADATA


def test_profiles_cannot_be_substituted() -> None:
    wrong_artifact_metadata = dict(ARTIFACT_METADATA)
    wrong_artifact_metadata["signature"] = MANIFEST_PROFILE["signature"]
    with pytest.raises(
        SignatureVerificationError, match="artifact signature verification failed"
    ):
        verify_artifact_signature(
            ARTIFACT_BYTES, wrong_artifact_metadata, PUBLIC_KEY_B64
        )

    wrong_manifest = dict(PARSED_SKILL)
    wrong_manifest["signature"] = ARTIFACT_PROFILE["signature"]
    with pytest.raises(
        SignatureVerificationError, match="manifest signature verification failed"
    ):
        verify_manifest_signature(wrong_manifest, PUBLIC_KEY_B64)


def test_artifact_tamper_fails_at_digest_before_signature() -> None:
    with pytest.raises(SignatureVerificationError, match="digest does not match"):
        verify_artifact_signature(
            ARTIFACT_BYTES + b"!", ARTIFACT_METADATA, PUBLIC_KEY_B64
        )


def test_manifest_tamper_fails_signature_verification() -> None:
    signed = dict(PARSED_SKILL)
    signed["signature"] = MANIFEST_PROFILE["signature"]
    signed["version"] = "1.0.1"

    with pytest.raises(
        SignatureVerificationError, match="manifest signature verification failed"
    ):
        verify_manifest_signature(signed, PUBLIC_KEY_B64)


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {
            **ARTIFACT_METADATA,
            "signer": "untrusted-label",
        },
        {
            **ARTIFACT_METADATA,
            "schema": "ori.skill_artifact_signature.v2",
        },
        {
            **ARTIFACT_METADATA,
            "artifact_sha256": (
                "sha256:1E5E873D8474D17D22D04FA06CBBA1A54F3AD2F5B407773CDC71747279B9BAF0"
            ),
        },
        {
            **ARTIFACT_METADATA,
            "signature": 123,
        },
    ],
)
def test_artifact_metadata_is_strict(metadata: dict[str, object]) -> None:
    with pytest.raises(SignatureVerificationError):
        verify_artifact_signature(ARTIFACT_BYTES, metadata, PUBLIC_KEY_B64)


@pytest.mark.parametrize(
    "signature",
    [
        "bundled",
        "ED25519:"
        "mbOGxjLsq0V9uC/dDy7zYi9OqZlcx/OXmPMs9euY6DTuydpSAxFQA17RBpzkoep4"
        "IFOcoT715yO3HymxC3VUDg==",
        "ed25519:AA==",
        "ed25519:not-base64!",
        "ed25519:"
        "mbOGxjLsq0V9uC/dDy7zYi9OqZlcx/OXmPMs9euY6DTuydpSAxFQA17RBpzkoep4"
        "IFOcoT715yO3HymxC3VUDh==",
    ],
)
def test_decode_signature_rejects_non_contract_values(signature: str) -> None:
    with pytest.raises(SignatureVerificationError):
        decode_signature(signature)


@pytest.mark.parametrize(
    "public_key",
    [
        "",
        "not base64!!",
        "AA==",
        "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbh=",
    ],
)
def test_decode_public_key_rejects_non_contract_values(public_key: str) -> None:
    with pytest.raises(SignatureVerificationError):
        decode_public_key(public_key)


def test_manifest_signature_must_be_a_community_signature() -> None:
    unsigned = {key: value for key, value in PARSED_SKILL.items() if key != "signature"}
    with pytest.raises(SignatureVerificationError, match="must be a string"):
        verify_manifest_signature(unsigned, PUBLIC_KEY_B64)

    bundled = dict(PARSED_SKILL)
    bundled["signature"] = "bundled"
    with pytest.raises(SignatureVerificationError, match="not valid for community"):
        verify_manifest_signature(bundled, PUBLIC_KEY_B64)


@pytest.mark.parametrize(
    "invalid_value",
    [float("nan"), float("inf"), object(), range(3)],
)
def test_manifest_rejects_non_json_values(invalid_value: object) -> None:
    manifest = dict(PARSED_SKILL)
    manifest["invalid"] = invalid_value

    with pytest.raises(SignatureVerificationError):
        canonical_manifest_bytes(manifest)


def test_manifest_rejects_non_string_keys_and_cycles() -> None:
    non_string_key: dict[object, object] = {1: "value"}
    with pytest.raises(SignatureVerificationError, match="keys must be strings"):
        canonical_manifest_bytes(cast(dict[str, object], non_string_key))

    cyclic = copy.deepcopy(PARSED_SKILL)
    cyclic["cycle"] = cyclic
    with pytest.raises(SignatureVerificationError, match="contains a cycle"):
        canonical_manifest_bytes(cyclic)


def test_manifest_canonicalization_is_lexically_stable() -> None:
    reordered = {key: PARSED_SKILL[key] for key in reversed(list(PARSED_SKILL))}
    reordered["signature"] = "ed25519:ignored-by-canonicalization"

    assert canonical_manifest_bytes(reordered) == canonical_manifest_bytes(PARSED_SKILL)
