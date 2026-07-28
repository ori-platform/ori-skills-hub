# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import gzip
import io
import tarfile
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from hub.core.errors import (
    TarballFormatError,
    TarballLimitError,
    TarballSafetyError,
)
from hub.storage.tarball import (
    DEFAULT_TARBALL_LIMITS,
    TarballLimits,
    extract_skill_yaml,
    rebuild_tarball,
)

_SKILL_YAML = b"""\
name: archive-test
version: 1.0.0
author: test-author
signature: author-placeholder
config:
  enabled: true
"""
_HUB_SIGNATURE = "ed25519:" + base64.b64encode(bytes(range(64))).decode("ascii")


def _regular(
    name: str,
    data: bytes,
    *,
    mode: int = 0o644,
) -> tuple[tarfile.TarInfo, bytes]:
    member = tarfile.TarInfo(name)
    member.type = tarfile.REGTYPE
    member.mode = mode
    member.size = len(data)
    return member, data


def _directory(name: str, *, mode: int = 0o755) -> tuple[tarfile.TarInfo, None]:
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE
    member.mode = mode
    member.size = 0
    return member, None


def _link(
    name: str,
    target: str,
    *,
    link_type: bytes,
) -> tuple[tarfile.TarInfo, None]:
    member = tarfile.TarInfo(name)
    member.type = link_type
    member.linkname = target
    member.size = 0
    return member, None


def _special(name: str, member_type: bytes) -> tuple[tarfile.TarInfo, None]:
    member = tarfile.TarInfo(name)
    member.type = member_type
    member.size = 0
    return member, None


def _tarball(
    *members: tuple[tarfile.TarInfo, bytes | None],
) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for member, data in members:
            archive.addfile(member, None if data is None else io.BytesIO(data))
    return gzip.compress(raw.getvalue(), compresslevel=9, mtime=0)


def _valid_tarball(
    *,
    manifest_path: str = "skill.yaml",
    extra_members: tuple[tuple[tarfile.TarInfo, bytes | None], ...] = (),
) -> bytes:
    return _tarball(_regular(manifest_path, _SKILL_YAML), *extra_members)


def _signed_mapping(archive_bytes: bytes) -> dict[str, object]:
    mapping = dict(extract_skill_yaml(archive_bytes).mapping)
    mapping["signature"] = _HUB_SIGNATURE
    return mapping


def _read_regular_files(archive_bytes: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            assert extracted is not None
            with extracted:
                files[member.name] = extracted.read()
    return files


def _member_metadata(
    archive_bytes: bytes,
) -> dict[str, tuple[int, int, int, str, str, int]]:
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        return {
            member.name.rstrip("/"): (
                member.mode,
                member.uid,
                member.gid,
                member.uname,
                member.gname,
                int(member.mtime),
            )
            for member in archive
        }


def test_extract_skill_yaml() -> None:
    document = extract_skill_yaml(_valid_tarball())

    assert document.path == "skill.yaml"
    assert document.mapping == {
        "name": "archive-test",
        "version": "1.0.0",
        "author": "test-author",
        "signature": "author-placeholder",
        "config": {"enabled": True},
    }


def test_extract_skill_yaml_one_directory_deep() -> None:
    archive_bytes = _valid_tarball(
        manifest_path="archive-test/skill.yaml",
        extra_members=(_directory("archive-test/"),),
    )

    document = extract_skill_yaml(archive_bytes)

    assert document.path == "archive-test/skill.yaml"
    assert document.mapping["name"] == "archive-test"


def test_one_directory_deep_package_rejects_members_outside_its_root() -> None:
    archive_bytes = _valid_tarball(
        manifest_path="archive-test/skill.yaml",
        extra_members=(_regular("outside.txt", b"ambiguous package root"),),
    )

    with pytest.raises(TarballSafetyError, match="outside their package root"):
        extract_skill_yaml(archive_bytes)


def test_extract_rejects_missing_yaml() -> None:
    archive_bytes = _tarball(_regular("README.md", b"no manifest"))

    with pytest.raises(TarballFormatError, match="must contain one skill.yaml"):
        extract_skill_yaml(archive_bytes)


def test_rebuild_replaces_yaml_only() -> None:
    archive_bytes = _valid_tarball(
        manifest_path="archive-test/skill.yaml",
        extra_members=(
            _directory("archive-test/"),
            _regular("archive-test/hooks.py", b"VALUE = 1\n", mode=0o711),
            _regular("archive-test/README.md", b"unchanged\n"),
        ),
    )
    original_files = _read_regular_files(archive_bytes)

    rebuilt = rebuild_tarball(archive_bytes, _signed_mapping(archive_bytes))
    rebuilt_files = _read_regular_files(rebuilt)

    assert (
        rebuilt_files["archive-test/hooks.py"]
        == original_files["archive-test/hooks.py"]
    )
    assert (
        rebuilt_files["archive-test/README.md"]
        == original_files["archive-test/README.md"]
    )
    assert (
        rebuilt_files["archive-test/skill.yaml"]
        != original_files["archive-test/skill.yaml"]
    )
    assert extract_skill_yaml(rebuilt).mapping["signature"] == _HUB_SIGNATURE


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "/absolute",
        "../escape",
        "directory/../../escape",
        "directory\\escape",
        "C:/windows-drive",
        "directory//file",
        "directory/./file",
        "line\nbreak",
        "archive-test/file:stream",
        "archive-test/CON",
        "archive-test/CONOUT$",
        "archive-test/trailing.",
        "archive-test/trailing ",
        "archive-test/cafe\u0301.txt",
        "archive-test/right-to-left-\u202e.txt",
    ],
)
def test_tarball_traversal_rejected(unsafe_name: str) -> None:
    archive_bytes = _valid_tarball(
        extra_members=(_regular(unsafe_name, b"unsafe"),),
    )

    with pytest.raises(TarballSafetyError):
        extract_skill_yaml(archive_bytes)


@pytest.mark.parametrize("link_type", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_links_are_rejected_before_target_resolution(link_type: bytes) -> None:
    archive_bytes = _valid_tarball(
        extra_members=(
            _link("archive-test/link", "../../outside", link_type=link_type),
        ),
    )

    with pytest.raises(TarballSafetyError, match="links are forbidden"):
        extract_skill_yaml(archive_bytes)


@pytest.mark.parametrize(
    "member_type",
    [tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE],
)
def test_special_file_types_are_rejected(member_type: bytes) -> None:
    archive_bytes = _valid_tarball(
        extra_members=(_special("archive-test/special", member_type),),
    )

    with pytest.raises(TarballSafetyError, match="only regular files"):
        extract_skill_yaml(archive_bytes)


def test_sparse_file_type_is_rejected() -> None:
    archive_bytes = _valid_tarball(
        extra_members=(_special("archive-test/sparse", tarfile.GNUTYPE_SPARSE),),
    )

    with pytest.raises(TarballSafetyError, match="sparse"):
        extract_skill_yaml(archive_bytes)


def test_duplicate_member_paths_are_rejected() -> None:
    archive_bytes = _valid_tarball(
        extra_members=(
            _regular("archive-test/data.txt", b"first"),
            _regular("archive-test/data.txt", b"second"),
        ),
    )

    with pytest.raises(TarballSafetyError, match="duplicate archive member"):
        extract_skill_yaml(archive_bytes)


def test_casefolded_member_collisions_are_rejected() -> None:
    archive_bytes = _valid_tarball(
        extra_members=(
            _regular("archive-test/Data.txt", b"first"),
            _regular("archive-test/data.txt", b"second"),
        ),
    )

    with pytest.raises(TarballSafetyError, match="duplicate archive member"):
        extract_skill_yaml(archive_bytes)


def test_casefolded_implicit_parent_collisions_are_rejected() -> None:
    archive_bytes = _valid_tarball(
        extra_members=(
            _regular("Archive-Test/one.txt", b"first"),
            _regular("archive-test/two.txt", b"second"),
        ),
    )

    with pytest.raises(TarballSafetyError, match="component collision"):
        extract_skill_yaml(archive_bytes)


def test_duplicate_skill_yaml_locations_are_rejected() -> None:
    archive_bytes = _tarball(
        _regular("skill.yaml", _SKILL_YAML),
        _regular("archive-test/skill.yaml", _SKILL_YAML),
    )

    with pytest.raises(TarballSafetyError, match="ambiguous duplicate"):
        extract_skill_yaml(archive_bytes)


@pytest.mark.parametrize(
    "members",
    [
        (
            _regular("archive-test", b"file"),
            _regular("archive-test/data.txt", b"child"),
        ),
        (
            _regular("archive-test/data.txt", b"child"),
            _regular("archive-test", b"file"),
        ),
    ],
)
def test_regular_file_parent_child_collisions_are_rejected(
    members: tuple[tuple[tarfile.TarInfo, bytes], ...],
) -> None:
    archive_bytes = _valid_tarball(extra_members=members)

    with pytest.raises(TarballSafetyError):
        extract_skill_yaml(archive_bytes)


@pytest.mark.parametrize(
    "manifest_path",
    [
        "archive-test/nested/skill.yaml",
        "archive-test/Skill.Yaml",
    ],
)
def test_manifest_path_must_match_the_exact_supported_layout(
    manifest_path: str,
) -> None:
    archive_bytes = _tarball(_regular(manifest_path, _SKILL_YAML))

    with pytest.raises(TarballSafetyError):
        extract_skill_yaml(archive_bytes)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"- list\n- not\n- mapping\n",
        b"scalar\n",
        b"name: first\nname: second\n",
        b"name: test\nconfig:\n  1: non-string-key\n",
        b"defaults: &defaults\n  enabled: true\nconfig:\n  <<: *defaults\n",
        b"shared: &shared\n  - one\ncopy: *shared\n",
        b"name: !untrusted-tag value\n",
        b"name: test\nreleased: 2026-07-28\n",
        b"name: test\nvalue: .nan\n",
        b"\xff",
    ],
)
def test_non_strict_skill_yaml_is_rejected(payload: bytes) -> None:
    archive_bytes = _tarball(_regular("skill.yaml", payload))

    with pytest.raises(TarballFormatError):
        extract_skill_yaml(archive_bytes)


@pytest.mark.parametrize(
    "archive_bytes",
    [
        b"",
        b"not gzip",
        gzip.compress(b"not tar data", mtime=0),
    ],
)
def test_malformed_gzip_or_tar_uses_typed_error(archive_bytes: bytes) -> None:
    with pytest.raises(TarballFormatError):
        extract_skill_yaml(archive_bytes)


def test_truncated_gzip_uses_typed_error() -> None:
    archive_bytes = _valid_tarball()

    with pytest.raises(TarballFormatError):
        extract_skill_yaml(archive_bytes[:-8])


def test_hidden_payload_after_tar_terminator_is_rejected() -> None:
    raw_tar = gzip.decompress(_valid_tarball())
    hidden = b"hidden payload"
    padding = b"\0" * (-len(hidden) % 512)
    archive_bytes = gzip.compress(raw_tar + hidden + padding, mtime=0)

    with pytest.raises(TarballFormatError, match="hidden payload"):
        extract_skill_yaml(archive_bytes)


def test_concatenated_gzip_archives_are_rejected() -> None:
    archive_bytes = _valid_tarball()

    with pytest.raises(TarballFormatError, match="hidden payload"):
        extract_skill_yaml(archive_bytes + archive_bytes)


def test_oversized_tarball_rejected_before_processing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_bytes = _valid_tarball()
    limits = replace(
        DEFAULT_TARBALL_LIMITS,
        max_archive_bytes=len(archive_bytes) - 1,
    )

    def unexpected_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("tar parser must not run for oversized input")

    monkeypatch.setattr(tarfile, "open", unexpected_open)

    with pytest.raises(TarballLimitError, match="max_archive_bytes"):
        extract_skill_yaml(archive_bytes, limits=limits)


def test_expanded_archive_limit_rejects_compression_bomb() -> None:
    archive_bytes = _valid_tarball()
    limits = TarballLimits(
        max_archive_bytes=len(archive_bytes) + 1,
        max_expanded_archive_bytes=1024,
        max_members=10,
        max_file_bytes=512,
        max_total_file_bytes=512,
        max_skill_yaml_bytes=512,
        max_path_bytes=128,
    )

    with pytest.raises(TarballLimitError, match="expanded tar stream"):
        extract_skill_yaml(archive_bytes, limits=limits)


def test_member_count_limit_is_enforced() -> None:
    archive_bytes = _valid_tarball(
        extra_members=(_regular("data.txt", b"data"),),
    )
    limits = replace(DEFAULT_TARBALL_LIMITS, max_members=1)

    with pytest.raises(TarballLimitError, match="max_members"):
        extract_skill_yaml(archive_bytes, limits=limits)


def test_individual_file_limit_is_enforced() -> None:
    archive_bytes = _valid_tarball(
        extra_members=(_regular("large.bin", b"x" * 1025),),
    )
    limits = replace(
        DEFAULT_TARBALL_LIMITS,
        max_file_bytes=1024,
        max_skill_yaml_bytes=1024,
    )

    with pytest.raises(TarballLimitError, match="max_file_bytes"):
        extract_skill_yaml(archive_bytes, limits=limits)


def test_total_file_limit_is_enforced() -> None:
    archive_bytes = _valid_tarball(
        extra_members=(
            _regular("one.bin", b"x" * 100),
            _regular("two.bin", b"x" * 100),
        ),
    )
    limits = replace(
        DEFAULT_TARBALL_LIMITS,
        max_file_bytes=150,
        max_total_file_bytes=250,
        max_skill_yaml_bytes=150,
    )

    with pytest.raises(TarballLimitError, match="max_total_file_bytes"):
        extract_skill_yaml(archive_bytes, limits=limits)


def test_skill_yaml_size_limit_is_enforced() -> None:
    archive_bytes = _valid_tarball()
    limits = replace(DEFAULT_TARBALL_LIMITS, max_skill_yaml_bytes=32)

    with pytest.raises(TarballLimitError, match="max_skill_yaml_bytes"):
        extract_skill_yaml(archive_bytes, limits=limits)


def test_member_path_size_limit_is_enforced() -> None:
    archive_bytes = _valid_tarball(
        extra_members=(_regular("archive-test/long-name.txt", b"data"),),
    )
    limits = replace(DEFAULT_TARBALL_LIMITS, max_path_bytes=16)

    with pytest.raises(TarballLimitError, match="max_path_bytes"):
        extract_skill_yaml(archive_bytes, limits=limits)


def test_member_path_component_size_limit_is_enforced() -> None:
    archive_bytes = _valid_tarball(
        extra_members=(_regular(f"archive-test/{'x' * 256}", b"data"),),
    )

    with pytest.raises(TarballLimitError, match="component"):
        extract_skill_yaml(archive_bytes)


def test_deeply_nested_yaml_uses_typed_error() -> None:
    depth_limit = 600
    lines = [f"{'  ' * depth}level_{depth}:" for depth in range(depth_limit)]
    lines.append(f"{'  ' * depth_limit}value: end")
    archive_bytes = _tarball(
        _regular("skill.yaml", ("\n".join(lines) + "\n").encode()),
    )

    with pytest.raises(TarballFormatError):
        extract_skill_yaml(archive_bytes)


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_archive_bytes", 0),
        ("max_members", -1),
        ("max_file_bytes", True),
        ("max_path_bytes", 1.5),
    ],
)
def test_tarball_limits_reject_invalid_values(field: str, value: object) -> None:
    values: dict[str, object] = {
        "max_archive_bytes": DEFAULT_TARBALL_LIMITS.max_archive_bytes,
        "max_expanded_archive_bytes": (
            DEFAULT_TARBALL_LIMITS.max_expanded_archive_bytes
        ),
        "max_members": DEFAULT_TARBALL_LIMITS.max_members,
        "max_file_bytes": DEFAULT_TARBALL_LIMITS.max_file_bytes,
        "max_total_file_bytes": DEFAULT_TARBALL_LIMITS.max_total_file_bytes,
        "max_skill_yaml_bytes": DEFAULT_TARBALL_LIMITS.max_skill_yaml_bytes,
        "max_path_bytes": DEFAULT_TARBALL_LIMITS.max_path_bytes,
    }
    values[field] = value

    with pytest.raises(ValueError, match=field):
        TarballLimits(**values)  # type: ignore[arg-type]


def test_tarball_limits_reject_inconsistent_relationships() -> None:
    with pytest.raises(ValueError, match="max_skill_yaml_bytes"):
        replace(
            DEFAULT_TARBALL_LIMITS,
            max_skill_yaml_bytes=2048,
            max_file_bytes=1024,
        )
    with pytest.raises(ValueError, match="max_file_bytes"):
        replace(
            DEFAULT_TARBALL_LIMITS,
            max_file_bytes=2048,
            max_total_file_bytes=1024,
            max_skill_yaml_bytes=1024,
        )
    with pytest.raises(ValueError, match="max_total_file_bytes"):
        replace(
            DEFAULT_TARBALL_LIMITS,
            max_total_file_bytes=2048,
            max_expanded_archive_bytes=1024,
            max_file_bytes=1024,
            max_skill_yaml_bytes=1024,
        )


@pytest.mark.parametrize(
    "signature",
    [
        None,
        "bundled",
        "ed25519:not-base64",
        "ed25519:AA==",
    ],
)
def test_rebuild_requires_strict_hub_signature(signature: object) -> None:
    archive_bytes = _valid_tarball()
    signed = dict(extract_skill_yaml(archive_bytes).mapping)
    signed["signature"] = signature

    with pytest.raises(TarballFormatError):
        rebuild_tarball(archive_bytes, signed)


def test_public_api_rejects_wrong_runtime_input_types() -> None:
    archive_bytes = _valid_tarball()

    with pytest.raises(TarballFormatError, match="must be bytes"):
        extract_skill_yaml(bytearray(archive_bytes))  # type: ignore[arg-type]
    with pytest.raises(TarballFormatError, match="must be a mapping"):
        rebuild_tarball(archive_bytes, [])  # type: ignore[arg-type]


def test_rebuild_rejects_non_string_mapping_keys_without_coercion() -> None:
    archive_bytes = _valid_tarball()
    signed = cast(dict[object, object], _signed_mapping(archive_bytes))
    signed[1] = "must not become a string key"

    with pytest.raises(TarballFormatError, match="keys must be strings"):
        rebuild_tarball(archive_bytes, signed)  # type: ignore[arg-type]


@pytest.mark.parametrize("invalid_value", [float("nan"), object()])
def test_rebuild_rejects_non_json_manifest_values(invalid_value: object) -> None:
    archive_bytes = _valid_tarball()
    signed = _signed_mapping(archive_bytes)
    signed["invalid"] = invalid_value

    with pytest.raises(TarballFormatError):
        rebuild_tarball(archive_bytes, signed)


def test_rebuild_rejects_cyclic_manifest_values() -> None:
    archive_bytes = _valid_tarball()
    signed = _signed_mapping(archive_bytes)
    signed["cycle"] = signed

    with pytest.raises(TarballFormatError, match="cycle"):
        rebuild_tarball(archive_bytes, signed)


def test_rebuild_rejects_non_signature_manifest_changes() -> None:
    archive_bytes = _valid_tarball()
    signed = _signed_mapping(archive_bytes)
    signed["author"] = "different-author"

    with pytest.raises(TarballSafetyError, match="only the top-level"):
        rebuild_tarball(archive_bytes, signed)


def test_rebuild_rejects_nested_manifest_changes() -> None:
    archive_bytes = _valid_tarball()
    signed = _signed_mapping(archive_bytes)
    signed["config"] = {"enabled": False}

    with pytest.raises(TarballSafetyError, match="only the top-level"):
        rebuild_tarball(archive_bytes, signed)


def test_rebuild_is_deterministic_and_normalises_metadata() -> None:
    directory, _ = _directory("archive-test/", mode=0o777)
    directory.uid = 123
    directory.gid = 456
    directory.uname = "untrusted"
    directory.gname = "untrusted"
    directory.mtime = 999
    archive_bytes = _valid_tarball(
        manifest_path="archive-test/skill.yaml",
        extra_members=(
            (directory, None),
            _regular("archive-test/hooks.py", b"VALUE = 1\n", mode=0o711),
        ),
    )
    signed = _signed_mapping(archive_bytes)

    first = rebuild_tarball(archive_bytes, signed)
    second = rebuild_tarball(archive_bytes, signed)

    assert first == second
    assert first[4:8] == b"\0\0\0\0"
    metadata = _member_metadata(first)
    assert metadata["archive-test"] == (0o755, 0, 0, "", "", 0)
    assert metadata["archive-test/hooks.py"] == (0o755, 0, 0, "", "", 0)
    assert metadata["archive-test/skill.yaml"] == (0o644, 0, 0, "", "", 0)


def test_archive_inspection_never_executes_hooks(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    hook = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n".encode()
    archive_bytes = _valid_tarball(
        extra_members=(_regular("hooks.py", hook),),
    )

    extract_skill_yaml(archive_bytes)

    assert not marker.exists()


def test_plain_uncompressed_tar_is_rejected() -> None:
    archive_bytes = _valid_tarball()
    raw_tar = gzip.decompress(archive_bytes)

    with pytest.raises(TarballFormatError, match="gzip"):
        extract_skill_yaml(raw_tar)
