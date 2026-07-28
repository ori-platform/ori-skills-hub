# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Profile-separated Ed25519 primitives for community skill packages."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import Final, TypedDict, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from hub.core.errors import SignatureVerificationError

SIGNATURE_PREFIX: Final = "ed25519:"
ARTIFACT_DIGEST_PREFIX: Final = "sha256:"
ARTIFACT_SIGNATURE_SCHEMA: Final = "ori.skill_artifact_signature.v1"
BUNDLED_SENTINEL: Final = "bundled"
SIGNING_VECTOR_SHA256: Final = (
    "13832babac98468ddd368aafd04c5140bba771f568500c50d4bac60c8588fddc"
)

_SIGNATURE_BYTES = 64
_PUBLIC_KEY_BYTES = 32


class ArtifactSignatureMetadata(TypedDict):
    """Strict detached metadata for an exact-byte artifact signature."""

    artifact_sha256: str
    schema: str
    signature: str


def _decode_standard_base64(
    value: str,
    *,
    expected_length: int,
    field_name: str,
) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureVerificationError(
            f"{field_name} is not canonical standard base64"
        ) from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise SignatureVerificationError(
            f"{field_name} is not canonical padded standard base64"
        )
    if len(decoded) != expected_length:
        raise SignatureVerificationError(
            f"{field_name} must decode to exactly {expected_length} bytes"
        )
    return decoded


def decode_signature(signature: str) -> bytes:
    """Decode a strict community signature wire value."""

    if signature == BUNDLED_SENTINEL:
        raise SignatureVerificationError(
            "bundled is not valid for community signatures"
        )
    if not signature.startswith(SIGNATURE_PREFIX):
        raise SignatureVerificationError(
            "signature must use the exact ed25519:<base64> format"
        )
    return _decode_standard_base64(
        signature[len(SIGNATURE_PREFIX) :],
        expected_length=_SIGNATURE_BYTES,
        field_name="signature",
    )


def decode_public_key(public_key_b64: str) -> bytes:
    """Decode a strict raw Ed25519 public trust anchor."""

    return _decode_standard_base64(
        public_key_b64,
        expected_length=_PUBLIC_KEY_BYTES,
        field_name="public key",
    )


def _load_public_key(public_key_b64: str) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(decode_public_key(public_key_b64))
    except ValueError as exc:
        raise SignatureVerificationError(
            "public key is not valid Ed25519 material"
        ) from exc


def _wire_signature(signature: bytes) -> str:
    return SIGNATURE_PREFIX + base64.b64encode(signature).decode("ascii")


def _validate_json_value(value: object, *, ancestors: set[int]) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SignatureVerificationError("manifest contains a non-finite number")
        return
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in ancestors:
            raise SignatureVerificationError("manifest contains a cycle")
        ancestors.add(identity)
        try:
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise SignatureVerificationError(
                        "manifest mapping keys must be strings"
                    )
                _validate_json_value(nested, ancestors=ancestors)
        finally:
            ancestors.remove(identity)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        identity = id(value)
        if identity in ancestors:
            raise SignatureVerificationError("manifest contains a cycle")
        ancestors.add(identity)
        try:
            for nested in value:
                _validate_json_value(nested, ancestors=ancestors)
        finally:
            ancestors.remove(identity)
        return
    raise SignatureVerificationError(
        f"manifest contains non-JSON value of type {type(value).__name__}"
    )


def canonical_manifest_bytes(parsed_skill: Mapping[str, object]) -> bytes:
    """Return canonical unsigned bytes for the manifest signing profile."""

    try:
        _validate_json_value(parsed_skill, ancestors=set())
        unsigned = {
            key: value for key, value in parsed_skill.items() if key != "signature"
        }
        return json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except RecursionError as exc:
        raise SignatureVerificationError(
            "manifest nesting exceeds the canonicalization limit"
        ) from exc
    except (OverflowError, TypeError, ValueError) as exc:
        raise SignatureVerificationError(
            "manifest cannot be represented as canonical JSON"
        ) from exc


def _sign_manifest(
    parsed_skill: Mapping[str, object], private_key: Ed25519PrivateKey
) -> str:
    return _wire_signature(private_key.sign(canonical_manifest_bytes(parsed_skill)))


def verify_manifest_signature(
    parsed_skill: Mapping[str, object], public_key_b64: str
) -> None:
    """Verify the embedded signature over a canonical parsed manifest."""

    signature_field = parsed_skill.get("signature")
    if not isinstance(signature_field, str):
        raise SignatureVerificationError("manifest signature must be a string")
    signature = decode_signature(signature_field)
    try:
        _load_public_key(public_key_b64).verify(
            signature, canonical_manifest_bytes(parsed_skill)
        )
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            "manifest signature verification failed"
        ) from exc


def _sign_artifact(
    artifact_bytes: bytes, private_key: Ed25519PrivateKey
) -> ArtifactSignatureMetadata:
    return {
        "artifact_sha256": (
            ARTIFACT_DIGEST_PREFIX + hashlib.sha256(artifact_bytes).hexdigest()
        ),
        "schema": ARTIFACT_SIGNATURE_SCHEMA,
        "signature": _wire_signature(private_key.sign(artifact_bytes)),
    }


def _parse_artifact_metadata(
    metadata: Mapping[str, object],
) -> ArtifactSignatureMetadata:
    expected_fields = {"artifact_sha256", "schema", "signature"}
    if set(metadata) != expected_fields:
        raise SignatureVerificationError(
            "artifact signature metadata must contain exactly the v1 fields"
        )
    if not all(isinstance(metadata[field], str) for field in expected_fields):
        raise SignatureVerificationError(
            "artifact signature metadata fields must be strings"
        )

    parsed = cast(ArtifactSignatureMetadata, dict(metadata))
    if parsed["schema"] != ARTIFACT_SIGNATURE_SCHEMA:
        raise SignatureVerificationError(
            "unsupported artifact signature metadata schema"
        )
    digest = parsed["artifact_sha256"]
    if (
        not digest.startswith(ARTIFACT_DIGEST_PREFIX)
        or len(digest) != len(ARTIFACT_DIGEST_PREFIX) + 64
        or any(character not in "0123456789abcdef" for character in digest[7:])
    ):
        raise SignatureVerificationError(
            "artifact_sha256 must use sha256: followed by 64 lowercase hex digits"
        )
    return parsed


def verify_artifact_signature(
    artifact_bytes: bytes,
    metadata: Mapping[str, object],
    public_key_b64: str,
) -> None:
    """Verify strict detached metadata over exact opaque artifact bytes.

    JSON callers must reject duplicate object fields while parsing metadata.
    The expected public key comes from trusted context, never from metadata.
    """

    parsed = _parse_artifact_metadata(metadata)
    actual_digest = ARTIFACT_DIGEST_PREFIX + hashlib.sha256(artifact_bytes).hexdigest()
    if parsed["artifact_sha256"] != actual_digest:
        raise SignatureVerificationError(
            "artifact digest does not match the exact received bytes"
        )
    signature = decode_signature(parsed["signature"])
    try:
        _load_public_key(public_key_b64).verify(signature, artifact_bytes)
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            "artifact signature verification failed"
        ) from exc
