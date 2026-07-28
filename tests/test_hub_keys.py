# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import base64
import stat
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient, Response

from hub.core.errors import ConfigError, SignatureVerificationError
from hub.security import hub_keys
from hub.security.hub_keys import (
    ARTIFACT_PRIVATE_KEY_B64_ENV,
    ARTIFACT_PRIVATE_KEY_FILE_ENV,
    MANIFEST_PRIVATE_KEY_B64_ENV,
    MANIFEST_PRIVATE_KEY_FILE_ENV,
    ROOT_PRIVATE_KEY_B64_ENV,
    ROOT_PRIVATE_KEY_FILE_ENV,
    HubPublicTrustAnchors,
    HubSigningKeys,
    generate_hub_key_material,
    load_hub_signing_keys_from_env,
    main,
)
from hub.security.signing import (
    verify_artifact_signature,
    verify_manifest_signature,
)
from hub.web.main import create_app, health_payload

_SEED_ONE = base64.b64encode(bytes(range(32))).decode("ascii")
_SEED_TWO = base64.b64encode(bytes(reversed(range(32)))).decode("ascii")
_MANIFEST: dict[str, object] = {
    "name": "key-management-test",
    "version": "1.0.0",
}
_ARTIFACT = b"exact artifact bytes"


def _assert_matching_profiles(keys: HubSigningKeys) -> None:
    manifest = dict(_MANIFEST)
    manifest["signature"] = keys.sign_manifest(manifest)
    verify_manifest_signature(
        manifest,
        keys.public_trust_anchors.manifest_public_key_b64,
    )
    verify_artifact_signature(
        _ARTIFACT,
        keys.sign_artifact(_ARTIFACT),
        keys.public_trust_anchors.artifact_public_key_b64,
    )


def test_read_only_mode_can_omit_all_key_material() -> None:
    assert (
        load_hub_signing_keys_from_env(
            publish_capable=False,
            environment={},
        )
        is None
    )


def test_publish_capable_mode_requires_key_material() -> None:
    with pytest.raises(ConfigError, match="publish-capable mode requires"):
        load_hub_signing_keys_from_env(
            publish_capable=True,
            environment={},
        )


def test_shared_root_seed_loads_both_profiles() -> None:
    keys = load_hub_signing_keys_from_env(
        publish_capable=True,
        environment={ROOT_PRIVATE_KEY_B64_ENV: _SEED_ONE},
    )

    assert keys is not None
    assert (
        keys.public_trust_anchors.manifest_public_key_b64
        == keys.public_trust_anchors.artifact_public_key_b64
    )
    _assert_matching_profiles(keys)


def test_profile_seeds_remain_isolated() -> None:
    keys = load_hub_signing_keys_from_env(
        publish_capable=True,
        environment={
            MANIFEST_PRIVATE_KEY_B64_ENV: _SEED_ONE,
            ARTIFACT_PRIVATE_KEY_B64_ENV: _SEED_TWO,
        },
    )

    assert keys is not None
    assert (
        keys.public_trust_anchors.manifest_public_key_b64
        != keys.public_trust_anchors.artifact_public_key_b64
    )
    _assert_matching_profiles(keys)

    manifest = dict(_MANIFEST)
    manifest["signature"] = keys.sign_manifest(manifest)
    with pytest.raises(
        SignatureVerificationError, match="manifest signature verification failed"
    ):
        verify_manifest_signature(
            manifest,
            keys.public_trust_anchors.artifact_public_key_b64,
        )
    with pytest.raises(
        SignatureVerificationError, match="artifact signature verification failed"
    ):
        verify_artifact_signature(
            _ARTIFACT,
            keys.sign_artifact(_ARTIFACT),
            keys.public_trust_anchors.manifest_public_key_b64,
        )


def test_private_seed_file_sources_are_supported(tmp_path: Path) -> None:
    manifest_file = tmp_path / "manifest.key"
    artifact_file = tmp_path / "artifact.key"
    manifest_file.write_text(f"{_SEED_ONE}\n", encoding="ascii")
    artifact_file.write_text(f"{_SEED_TWO}\n", encoding="ascii")

    keys = load_hub_signing_keys_from_env(
        publish_capable=True,
        environment={
            MANIFEST_PRIVATE_KEY_FILE_ENV: str(manifest_file),
            ARTIFACT_PRIVATE_KEY_FILE_ENV: str(artifact_file),
        },
    )

    assert keys is not None
    _assert_matching_profiles(keys)


@pytest.mark.parametrize(
    "environment, message",
    [
        (
            {
                ROOT_PRIVATE_KEY_B64_ENV: _SEED_ONE,
                MANIFEST_PRIVATE_KEY_B64_ENV: _SEED_ONE,
                ARTIFACT_PRIVATE_KEY_B64_ENV: _SEED_TWO,
            },
            "ambiguous",
        ),
        (
            {MANIFEST_PRIVATE_KEY_B64_ENV: _SEED_ONE},
            "must be configured together",
        ),
        (
            {ARTIFACT_PRIVATE_KEY_B64_ENV: _SEED_ONE},
            "must be configured together",
        ),
        (
            {
                ROOT_PRIVATE_KEY_B64_ENV: _SEED_ONE,
                ROOT_PRIVATE_KEY_FILE_ENV: "/unused",
            },
            "ambiguous",
        ),
        (
            {ROOT_PRIVATE_KEY_B64_ENV: "not-base64"},
            "canonical standard base64",
        ),
        (
            {ROOT_PRIVATE_KEY_B64_ENV: f" {_SEED_ONE}"},
            "canonical standard base64",
        ),
        (
            {ROOT_PRIVATE_KEY_B64_ENV: base64.b64encode(b"short").decode()},
            "exactly 32 bytes",
        ),
    ],
)
def test_invalid_or_ambiguous_key_configuration_fails_closed(
    environment: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(ConfigError, match=message):
        load_hub_signing_keys_from_env(
            publish_capable=False,
            environment=environment,
        )


def test_missing_and_oversized_key_files_fail_without_leaking_paths(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "secret-value-must-not-leak"
    with pytest.raises(ConfigError) as missing_error:
        load_hub_signing_keys_from_env(
            publish_capable=True,
            environment={ROOT_PRIVATE_KEY_FILE_ENV: str(missing)},
        )
    assert str(missing) not in str(missing_error.value)

    oversized = tmp_path / "oversized.key"
    oversized.write_bytes(b"A" * 4097)
    with pytest.raises(ConfigError, match="too large"):
        load_hub_signing_keys_from_env(
            publish_capable=True,
            environment={ROOT_PRIVATE_KEY_FILE_ENV: str(oversized)},
        )


@pytest.mark.parametrize("contents", [b"", b"\xff"])
def test_empty_or_non_ascii_key_files_fail_closed(
    tmp_path: Path, contents: bytes
) -> None:
    key_file = tmp_path / "invalid.key"
    key_file.write_bytes(contents)

    with pytest.raises(ConfigError):
        load_hub_signing_keys_from_env(
            publish_capable=True,
            environment={ROOT_PRIVATE_KEY_FILE_ENV: str(key_file)},
        )


def test_private_keys_are_absent_from_safe_surfaces_and_repr() -> None:
    keys = HubSigningKeys.from_base64_seeds(
        manifest_seed_b64=_SEED_ONE,
        artifact_seed_b64=_SEED_TWO,
    )

    public_config = keys.public_trust_anchors.as_dict()
    rendered = repr(keys)

    assert set(public_config) == {
        "manifest_public_key_b64",
        "artifact_public_key_b64",
    }
    assert _SEED_ONE not in repr(public_config)
    assert _SEED_TWO not in repr(public_config)
    assert _SEED_ONE not in rendered
    assert _SEED_TWO not in rendered
    assert "redacted" in rendered


def test_public_trust_anchor_constructor_rejects_malformed_values() -> None:
    with pytest.raises(SignatureVerificationError, match="exactly 32 bytes"):
        HubPublicTrustAnchors(
            manifest_public_key_b64="AA==",
            artifact_public_key_b64="AA==",
        )


def test_key_generation_defaults_to_isolated_profiles(tmp_path: Path) -> None:
    output_dir = tmp_path / "generated"
    anchors = generate_hub_key_material(output_dir)

    expected_files = {
        "hub-manifest-private-key.b64",
        "hub-manifest-public-key.b64",
        "hub-artifact-private-key.b64",
        "hub-artifact-public-key.b64",
    }
    assert {path.name for path in output_dir.iterdir()} == expected_files
    assert anchors.manifest_public_key_b64 != anchors.artifact_public_key_b64
    assert stat.S_IMODE(output_dir.stat().st_mode) == 0o700
    assert (
        stat.S_IMODE((output_dir / "hub-manifest-private-key.b64").stat().st_mode)
        == 0o600
    )
    assert (
        stat.S_IMODE((output_dir / "hub-artifact-private-key.b64").stat().st_mode)
        == 0o600
    )
    assert (
        stat.S_IMODE((output_dir / "hub-manifest-public-key.b64").stat().st_mode)
        == 0o644
    )
    assert (
        stat.S_IMODE((output_dir / "hub-artifact-public-key.b64").stat().st_mode)
        == 0o644
    )

    keys = load_hub_signing_keys_from_env(
        publish_capable=True,
        environment={
            MANIFEST_PRIVATE_KEY_FILE_ENV: str(
                output_dir / "hub-manifest-private-key.b64"
            ),
            ARTIFACT_PRIVATE_KEY_FILE_ENV: str(
                output_dir / "hub-artifact-private-key.b64"
            ),
        },
    )
    assert keys is not None
    assert keys.public_trust_anchors == anchors
    _assert_matching_profiles(keys)


def test_key_files_are_created_with_their_final_restrictive_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "generated"
    real_open = hub_keys._open_key_file
    creation_modes: dict[str, int] = {}

    def record_mode(path: Path, *, mode: int) -> int:
        creation_modes[path.name] = mode
        return real_open(path, mode=mode)

    monkeypatch.setattr(hub_keys, "_open_key_file", record_mode)

    generate_hub_key_material(output_dir)

    assert creation_modes == {
        "hub-manifest-private-key.b64": 0o600,
        "hub-manifest-public-key.b64": 0o644,
        "hub-artifact-private-key.b64": 0o600,
        "hub-artifact-public-key.b64": 0o644,
    }


def test_shared_key_generation_is_explicit(tmp_path: Path) -> None:
    output_dir = tmp_path / "generated"
    anchors = generate_hub_key_material(output_dir, shared_root_key=True)

    assert {path.name for path in output_dir.iterdir()} == {
        "hub-root-private-key.b64",
        "hub-root-public-key.b64",
    }
    assert anchors.manifest_public_key_b64 == anchors.artifact_public_key_b64


def test_key_generation_refuses_existing_directory(tmp_path: Path) -> None:
    output_dir = tmp_path / "existing"
    output_dir.mkdir()
    marker = output_dir / "do-not-overwrite"
    marker.write_text("preserve", encoding="utf-8")

    with pytest.raises(ConfigError, match="already exists"):
        generate_hub_key_material(output_dir)

    assert marker.read_text(encoding="utf-8") == "preserve"


def test_key_generation_refuses_git_worktree(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()
    (repository / ".git" / "HEAD").write_text(
        "ref: refs/heads/main\n", encoding="ascii"
    )

    with pytest.raises(ConfigError, match="inside a Git worktree"):
        generate_hub_key_material(repository / "private-keys")


def test_key_generation_cleans_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "generated"
    real_write = hub_keys._write_key_file
    writes = 0

    def fail_after_first_write(path: Path, value: str, *, mode: int) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("simulated bootstrap write failure")
        real_write(path, value, mode=mode)

    monkeypatch.setattr(hub_keys, "_write_key_file", fail_after_first_write)

    with pytest.raises(ConfigError, match="could not write"):
        generate_hub_key_material(output_dir)

    assert not output_dir.exists()


def test_key_generation_cleans_unsecured_output_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "generated"
    real_chmod = Path.chmod

    def reject_directory_mode(path: Path, mode: int) -> None:
        if path == output_dir:
            raise OSError("simulated chmod failure")
        real_chmod(path, mode)

    monkeypatch.setattr(Path, "chmod", reject_directory_mode)

    with pytest.raises(ConfigError, match="could not secure"):
        generate_hub_key_material(output_dir)

    assert not output_dir.exists()


def test_key_generation_command_never_prints_private_material(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_dir = tmp_path / "generated"

    assert main(["generate", "--output-dir", str(output_dir)]) == 0

    captured = capsys.readouterr()
    manifest_private = (
        (output_dir / "hub-manifest-private-key.b64")
        .read_text(encoding="ascii")
        .strip()
    )
    artifact_private = (
        (output_dir / "hub-artifact-private-key.b64")
        .read_text(encoding="ascii")
        .strip()
    )
    assert manifest_private not in captured.out
    assert artifact_private not in captured.out
    assert captured.err == ""


def test_health_exposes_only_profile_public_anchors() -> None:
    keys = HubSigningKeys.from_base64_seeds(
        manifest_seed_b64=_SEED_ONE,
        artifact_seed_b64=_SEED_TWO,
    )

    payload = health_payload(trust_anchors=keys.public_trust_anchors)
    rendered = repr(payload)

    assert payload["signing_trust_anchors"] == keys.public_trust_anchors.as_dict()
    assert _SEED_ONE not in rendered
    assert _SEED_TWO not in rendered


def test_health_route_exposes_only_profile_public_anchors() -> None:
    keys = HubSigningKeys.from_base64_seeds(
        manifest_seed_b64=_SEED_ONE,
        artifact_seed_b64=_SEED_TWO,
    )

    async def request_health() -> Response:
        transport = ASGITransport(
            app=create_app(trust_anchors=keys.public_trust_anchors)
        )
        async with AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.get("/health")

    response = asyncio.run(request_health())

    assert response.status_code == 200
    assert response.json()["signing_trust_anchors"] == {
        "manifest_public_key_b64": (keys.public_trust_anchors.manifest_public_key_b64),
        "artifact_public_key_b64": (keys.public_trust_anchors.artifact_public_key_b64),
    }
    assert _SEED_ONE not in response.text
    assert _SEED_TWO not in response.text
