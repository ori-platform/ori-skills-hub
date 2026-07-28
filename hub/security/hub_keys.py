# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed Hub signing-key loading and controlled bootstrap generation."""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hub.core.errors import ConfigError
from hub.security.signing import (
    ArtifactSignatureMetadata,
    _sign_artifact,
    _sign_manifest,
    decode_public_key,
)

ROOT_PRIVATE_KEY_B64_ENV: Final = "HUB_ROOT_SIGNING_PRIVATE_KEY_B64"
ROOT_PRIVATE_KEY_FILE_ENV: Final = "HUB_ROOT_SIGNING_PRIVATE_KEY_FILE"
MANIFEST_PRIVATE_KEY_B64_ENV: Final = "HUB_MANIFEST_SIGNING_PRIVATE_KEY_B64"
MANIFEST_PRIVATE_KEY_FILE_ENV: Final = "HUB_MANIFEST_SIGNING_PRIVATE_KEY_FILE"
ARTIFACT_PRIVATE_KEY_B64_ENV: Final = "HUB_ARTIFACT_SIGNING_PRIVATE_KEY_B64"
ARTIFACT_PRIVATE_KEY_FILE_ENV: Final = "HUB_ARTIFACT_SIGNING_PRIVATE_KEY_FILE"

_PRIVATE_KEY_BYTES = 32
_MAX_SECRET_FILE_BYTES = 4096
_GENERATED_KEY_FILES = frozenset(
    {
        "hub-root-private-key.b64",
        "hub-root-public-key.b64",
        "hub-manifest-private-key.b64",
        "hub-manifest-public-key.b64",
        "hub-artifact-private-key.b64",
        "hub-artifact-public-key.b64",
    }
)


@dataclass(frozen=True)
class HubPublicTrustAnchors:
    """Profile-labelled public values safe for configuration and health output."""

    manifest_public_key_b64: str
    artifact_public_key_b64: str

    def __post_init__(self) -> None:
        decode_public_key(self.manifest_public_key_b64)
        decode_public_key(self.artifact_public_key_b64)

    def as_dict(self) -> dict[str, str]:
        return {
            "manifest_public_key_b64": self.manifest_public_key_b64,
            "artifact_public_key_b64": self.artifact_public_key_b64,
        }


class HubSigningKeys:
    """In-memory Hub private keys with profile-specific signing methods."""

    __slots__ = ("__artifact_private_key", "__manifest_private_key", "_anchors")

    def __init__(self, *, manifest_seed: bytes, artifact_seed: bytes) -> None:
        self.__manifest_private_key = _private_key_from_seed(
            manifest_seed, profile="manifest"
        )
        self.__artifact_private_key = _private_key_from_seed(
            artifact_seed, profile="artifact"
        )
        self._anchors = HubPublicTrustAnchors(
            manifest_public_key_b64=_public_key_b64(self.__manifest_private_key),
            artifact_public_key_b64=_public_key_b64(self.__artifact_private_key),
        )

    def __repr__(self) -> str:
        return "HubSigningKeys(<private key material redacted>)"

    @classmethod
    def from_base64_seeds(
        cls, *, manifest_seed_b64: str, artifact_seed_b64: str
    ) -> HubSigningKeys:
        return cls(
            manifest_seed=_decode_private_seed(manifest_seed_b64, profile="manifest"),
            artifact_seed=_decode_private_seed(artifact_seed_b64, profile="artifact"),
        )

    @property
    def public_trust_anchors(self) -> HubPublicTrustAnchors:
        return self._anchors

    def sign_manifest(self, parsed_skill: Mapping[str, object]) -> str:
        return _sign_manifest(parsed_skill, self.__manifest_private_key)

    def sign_artifact(self, artifact_bytes: bytes) -> ArtifactSignatureMetadata:
        return _sign_artifact(artifact_bytes, self.__artifact_private_key)


def _decode_private_seed(value: str, *, profile: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigError(
            f"{profile} signing private key is not canonical standard base64"
        ) from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ConfigError(
            f"{profile} signing private key is not canonical padded standard base64"
        )
    if len(decoded) != _PRIVATE_KEY_BYTES:
        raise ConfigError(
            f"{profile} signing private key must decode to exactly 32 bytes"
        )
    return decoded


def _private_key_from_seed(seed: bytes, *, profile: str) -> Ed25519PrivateKey:
    if len(seed) != _PRIVATE_KEY_BYTES:
        raise ConfigError(
            f"{profile} signing private key seed must be exactly 32 bytes"
        )
    try:
        return Ed25519PrivateKey.from_private_bytes(seed)
    except ValueError as exc:
        raise ConfigError(
            f"{profile} signing private key is not valid Ed25519 material"
        ) from exc


def _public_key_b64(private_key: Ed25519PrivateKey) -> str:
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_bytes).decode("ascii")


def _configured(environment: Mapping[str, str], name: str) -> str | None:
    value = environment.get(name)
    if value is None or value == "":
        return None
    return value


def _read_secret_source(
    environment: Mapping[str, str],
    *,
    value_env: str,
    file_env: str,
) -> str | None:
    inline = _configured(environment, value_env)
    file_name = _configured(environment, file_env)
    if inline is not None and file_name is not None:
        raise ConfigError(
            f"{value_env} and {file_env} are ambiguous; configure exactly one"
        )
    if inline is not None:
        return inline
    if file_name is None:
        return None

    path = Path(file_name)
    try:
        raw_secret = path.read_bytes()
    except OSError as exc:
        raise ConfigError(
            f"could not read signing key file configured by {file_env}"
        ) from exc
    if len(raw_secret) > _MAX_SECRET_FILE_BYTES:
        raise ConfigError(f"signing key file configured by {file_env} is too large")
    try:
        secret = raw_secret.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ConfigError(
            f"signing key file configured by {file_env} must contain ASCII base64"
        ) from exc
    if secret.endswith("\n"):
        secret = secret[:-1]
        if secret.endswith("\r"):
            secret = secret[:-1]
    if not secret:
        raise ConfigError(f"signing key file configured by {file_env} is empty")
    return secret


def load_hub_signing_keys_from_env(
    *,
    publish_capable: bool,
    environment: Mapping[str, str] | None = None,
) -> HubSigningKeys | None:
    """Load either one shared root seed or two explicit profile seeds.

    Read-only service modes may omit all key sources. Any configured source is
    still validated, and publish-capable startup always requires a complete,
    unambiguous key configuration.
    """

    values = os.environ if environment is None else environment
    shared = _read_secret_source(
        values,
        value_env=ROOT_PRIVATE_KEY_B64_ENV,
        file_env=ROOT_PRIVATE_KEY_FILE_ENV,
    )
    manifest = _read_secret_source(
        values,
        value_env=MANIFEST_PRIVATE_KEY_B64_ENV,
        file_env=MANIFEST_PRIVATE_KEY_FILE_ENV,
    )
    artifact = _read_secret_source(
        values,
        value_env=ARTIFACT_PRIVATE_KEY_B64_ENV,
        file_env=ARTIFACT_PRIVATE_KEY_FILE_ENV,
    )

    if shared is not None and (manifest is not None or artifact is not None):
        raise ConfigError(
            "shared root signing key and profile-specific keys are ambiguous"
        )
    if shared is not None:
        return HubSigningKeys.from_base64_seeds(
            manifest_seed_b64=shared,
            artifact_seed_b64=shared,
        )
    if (manifest is None) != (artifact is None):
        raise ConfigError(
            "manifest and artifact signing keys must be configured together"
        )
    if manifest is not None and artifact is not None:
        return HubSigningKeys.from_base64_seeds(
            manifest_seed_b64=manifest,
            artifact_seed_b64=artifact,
        )
    if publish_capable:
        raise ConfigError(
            "publish-capable mode requires a shared root signing key or both "
            "profile-specific signing keys"
        )
    return None


def _private_seed(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _inside_git_worktree(path: Path) -> bool:
    resolved_parent = path.parent.resolve()
    for candidate in (resolved_parent, *resolved_parent.parents):
        metadata = candidate / ".git"
        if metadata.is_file():
            return True
        if metadata.is_dir() and (metadata / "HEAD").is_file():
            return True
    return False


def _open_key_file(path: Path, *, mode: int) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags, mode)


def _write_key_file(path: Path, value: str, *, mode: int) -> None:
    descriptor = _open_key_file(path, mode=mode)
    try:
        # Apply the final mode before writing so private bytes are never exposed
        # through a permissive process umask or a post-write chmod window.
        os.fchmod(descriptor, mode)
        output = os.fdopen(descriptor, "w", encoding="ascii")
        descriptor = -1
        with output:
            output.write(value)
            output.write("\n")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _clean_failed_generation(target: Path) -> None:
    try:
        children = tuple(target.iterdir())
    except OSError:
        return
    for child in children:
        if child.name not in _GENERATED_KEY_FILES or not child.is_file():
            continue
        try:
            child.unlink()
        except OSError:
            pass
    try:
        target.rmdir()
    except OSError:
        pass


def generate_hub_key_material(
    output_dir: Path,
    *,
    shared_root_key: bool = False,
) -> HubPublicTrustAnchors:
    """Generate non-overwriting bootstrap files without printing private keys."""

    target = output_dir.expanduser()
    if target.exists():
        raise ConfigError("key output directory already exists")
    if _inside_git_worktree(target):
        raise ConfigError("refusing to generate Hub private keys inside a Git worktree")
    if not target.parent.exists() or not target.parent.is_dir():
        raise ConfigError("key output parent directory must already exist")

    manifest_private = Ed25519PrivateKey.generate()
    artifact_private = (
        manifest_private if shared_root_key else Ed25519PrivateKey.generate()
    )
    manifest_seed = _private_seed(manifest_private)
    artifact_seed = _private_seed(artifact_private)
    keys = HubSigningKeys(
        manifest_seed=manifest_seed,
        artifact_seed=artifact_seed,
    )

    try:
        target.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ConfigError("key output directory already exists") from exc
    except OSError as exc:
        raise ConfigError("could not create key output directory") from exc
    try:
        target.chmod(0o700)
    except OSError as exc:
        _clean_failed_generation(target)
        raise ConfigError("could not secure key output directory") from exc

    try:
        if shared_root_key:
            _write_key_file(
                target / "hub-root-private-key.b64",
                _encode(manifest_seed),
                mode=0o600,
            )
            _write_key_file(
                target / "hub-root-public-key.b64",
                keys.public_trust_anchors.manifest_public_key_b64,
                mode=0o644,
            )
        else:
            _write_key_file(
                target / "hub-manifest-private-key.b64",
                _encode(manifest_seed),
                mode=0o600,
            )
            _write_key_file(
                target / "hub-manifest-public-key.b64",
                keys.public_trust_anchors.manifest_public_key_b64,
                mode=0o644,
            )
            _write_key_file(
                target / "hub-artifact-private-key.b64",
                _encode(artifact_seed),
                mode=0o600,
            )
            _write_key_file(
                target / "hub-artifact-public-key.b64",
                keys.public_trust_anchors.artifact_public_key_b64,
                mode=0o644,
            )
    except OSError as exc:
        _clean_failed_generation(target)
        raise ConfigError("could not write generated key material") from exc
    return keys.public_trust_anchors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ori-hub-keys",
        description="Controlled bootstrap for Ori Skills Hub signing keys.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser(
        "generate",
        help="generate new signing keys into a new, non-repository directory",
    )
    generate.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="new directory for generated key files; it must not already exist",
    )
    generate.add_argument(
        "--shared-root-key",
        action="store_true",
        help="use one key for both profiles instead of isolated profile keys",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "generate":  # pragma: no cover - argparse enforces choices
        raise AssertionError("unsupported key command")
    try:
        anchors = generate_hub_key_material(
            args.output_dir,
            shared_root_key=args.shared_root_key,
        )
    except ConfigError as exc:
        print(f"key generation failed: {exc}", file=sys.stderr)
        return 2

    output_dir = args.output_dir.expanduser().resolve()
    print(f"generated Hub signing keys in {output_dir}")
    if args.shared_root_key:
        print(
            f"configure {ROOT_PRIVATE_KEY_FILE_ENV}="
            f"{output_dir / 'hub-root-private-key.b64'}"
        )
    else:
        print(
            f"configure {MANIFEST_PRIVATE_KEY_FILE_ENV}="
            f"{output_dir / 'hub-manifest-private-key.b64'}"
        )
        print(
            f"configure {ARTIFACT_PRIVATE_KEY_FILE_ENV}="
            f"{output_dir / 'hub-artifact-private-key.b64'}"
        )
    print(f"manifest public trust anchor: {anchors.manifest_public_key_b64}")
    print(f"artifact public trust anchor: {anchors.artifact_public_key_b64}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
