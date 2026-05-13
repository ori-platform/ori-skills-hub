# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Ed25519 verification helpers aligned with ori-runtime signing primitives."""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hub.core.errors import SignatureVerificationError

_SIGNATURE_PREFIX = "ed25519:"
_SIGNATURE_BYTES = 64
_PUBLIC_KEY_BYTES = 32


def decode_signature(signature: str) -> bytes:
    if not signature.startswith(_SIGNATURE_PREFIX):
        raise SignatureVerificationError("signature must use ed25519:<base64> format")
    encoded = signature.removeprefix(_SIGNATURE_PREFIX)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except Exception as exc:  # noqa: BLE001 - normalize base64 parser errors
        raise SignatureVerificationError("signature is not valid base64") from exc
    if len(decoded) != _SIGNATURE_BYTES:
        raise SignatureVerificationError("ed25519 signature must decode to 64 bytes")
    return decoded


def decode_public_key(public_key_b64: str) -> bytes:
    try:
        decoded = base64.b64decode(public_key_b64, validate=True)
    except Exception as exc:  # noqa: BLE001 - normalize base64 parser errors
        raise SignatureVerificationError("public key is not valid base64") from exc
    if len(decoded) != _PUBLIC_KEY_BYTES:
        raise SignatureVerificationError("ed25519 public key must decode to 32 bytes")
    return decoded


def verify_skill_signature(
    *, tarball_bytes: bytes, signature: str, public_key_b64: str
) -> bool:
    """Verify an author signature over uploaded tarball bytes.

    This is upload-time author verification only. Phase 2 Hub root signing will
    use the same ``cryptography`` Ed25519 primitives over the runtime canonical
    ``skill.yaml`` payload before a skill is downloadable by runtimes.
    """
    sig = decode_signature(signature)
    key = decode_public_key(public_key_b64)
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, tarball_bytes)
    except InvalidSignature as exc:
        raise SignatureVerificationError("skill signature verification failed") from exc
    except ValueError as exc:
        raise SignatureVerificationError("invalid ed25519 public key") from exc
    return True
