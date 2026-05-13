# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hub.core.errors import SignatureVerificationError
from hub.security.signing import (
    decode_public_key,
    decode_signature,
    verify_skill_signature,
)


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, base64.b64encode(public_key).decode()


def test_decode_signature_requires_ed25519_prefix() -> None:
    with pytest.raises(SignatureVerificationError):
        decode_signature("abc")


def test_decode_signature_requires_64_bytes() -> None:
    encoded = base64.b64encode(b"123").decode()
    with pytest.raises(SignatureVerificationError, match="64 bytes"):
        decode_signature(f"ed25519:{encoded}")


def test_decode_public_key_rejects_invalid_base64() -> None:
    with pytest.raises(SignatureVerificationError):
        decode_public_key("not base64!!")


def test_decode_public_key_requires_32_bytes() -> None:
    encoded = base64.b64encode(b"123").decode()
    with pytest.raises(SignatureVerificationError, match="32 bytes"):
        decode_public_key(encoded)


def test_verify_skill_signature_accepts_valid_signature() -> None:
    payload = b"signed skill tarball bytes"
    private_key, public_key_b64 = _keypair()
    signature = base64.b64encode(private_key.sign(payload)).decode()

    assert (
        verify_skill_signature(
            tarball_bytes=payload,
            signature=f"ed25519:{signature}",
            public_key_b64=public_key_b64,
        )
        is True
    )


def test_verify_skill_signature_rejects_tampered_payload() -> None:
    payload = b"signed skill tarball bytes"
    private_key, public_key_b64 = _keypair()
    signature = base64.b64encode(private_key.sign(payload)).decode()

    with pytest.raises(SignatureVerificationError):
        verify_skill_signature(
            tarball_bytes=b"tampered",
            signature=f"ed25519:{signature}",
            public_key_b64=public_key_b64,
        )
