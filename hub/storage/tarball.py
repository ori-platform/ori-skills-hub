# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Bounded, filesystem-free inspection and rebuild of skill tarballs."""

from __future__ import annotations

import gzip
import io
import math
import tarfile
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, cast

import yaml
from yaml.composer import ComposerError
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode

from hub.core.errors import (
    SignatureVerificationError,
    TarballError,
    TarballFormatError,
    TarballLimitError,
    TarballSafetyError,
)
from hub.security.signing import canonical_manifest_bytes, decode_signature

_TAR_BLOCK_SIZE: Final = 512
_TAR_END_SIZE: Final = _TAR_BLOCK_SIZE * 2
_SKILL_YAML_NAME: Final = "skill.yaml"
_WINDOWS_RESERVED_NAMES: Final = frozenset(
    {
        "aux",
        "con",
        "conin$",
        "conout$",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


@dataclass(frozen=True, slots=True)
class TarballLimits:
    """Resource limits applied before and during archive inspection."""

    max_archive_bytes: int = 10 * 1024 * 1024
    max_expanded_archive_bytes: int = 64 * 1024 * 1024
    max_members: int = 512
    max_file_bytes: int = 16 * 1024 * 1024
    max_total_file_bytes: int = 48 * 1024 * 1024
    max_skill_yaml_bytes: int = 512 * 1024
    max_path_bytes: int = 512

    def __post_init__(self) -> None:
        values = {
            "max_archive_bytes": self.max_archive_bytes,
            "max_expanded_archive_bytes": self.max_expanded_archive_bytes,
            "max_members": self.max_members,
            "max_file_bytes": self.max_file_bytes,
            "max_total_file_bytes": self.max_total_file_bytes,
            "max_skill_yaml_bytes": self.max_skill_yaml_bytes,
            "max_path_bytes": self.max_path_bytes,
        }
        for name, value in values.items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_skill_yaml_bytes > self.max_file_bytes:
            raise ValueError("max_skill_yaml_bytes cannot exceed max_file_bytes")
        if self.max_file_bytes > self.max_total_file_bytes:
            raise ValueError("max_file_bytes cannot exceed max_total_file_bytes")
        if self.max_total_file_bytes > self.max_expanded_archive_bytes:
            raise ValueError(
                "max_total_file_bytes cannot exceed max_expanded_archive_bytes"
            )


DEFAULT_TARBALL_LIMITS: Final = TarballLimits()


@dataclass(frozen=True, slots=True)
class SkillYamlDocument:
    """The single accepted manifest path and its strictly parsed mapping."""

    path: str
    mapping: dict[str, object]


@dataclass(frozen=True, slots=True)
class _ArchiveMember:
    name: str
    is_directory: bool
    mode: int
    data: bytes | None


@dataclass(frozen=True, slots=True)
class _ArchiveInspection:
    manifest: SkillYamlDocument
    members: tuple[_ArchiveMember, ...]


class _StrictSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """SafeLoader variant that rejects ambiguous or non-string mapping keys."""

    def compose_node(self, parent: object, index: object) -> object:
        if self.check_event(AliasEvent):
            event = self.peek_event()
            raise ComposerError(
                "while composing skill.yaml",
                None,
                "YAML aliases are not permitted",
                event.start_mark,
            )
        return cast(object, super().compose_node(parent, index))

    def construct_mapping(
        self,
        node: MappingNode,
        deep: bool = False,
    ) -> dict[str, object]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(
                None,
                None,
                "expected a mapping node",
                node.start_mark,
            )

        mapping: dict[str, object] = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "YAML merge keys are not permitted",
                    key_node.start_mark,
                )
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "mapping keys must be strings",
                    key_node.start_mark,
                )
            if key in mapping:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"duplicate mapping key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _decompress_tarball(tarball_bytes: bytes, limits: TarballLimits) -> bytes:
    if not isinstance(tarball_bytes, bytes):
        raise TarballFormatError("tarball payload must be bytes")
    if not tarball_bytes:
        raise TarballFormatError("tarball payload is empty")
    if len(tarball_bytes) > limits.max_archive_bytes:
        raise TarballLimitError("compressed tarball exceeds max_archive_bytes")

    try:
        with gzip.GzipFile(fileobj=io.BytesIO(tarball_bytes), mode="rb") as source:
            expanded = source.read(limits.max_expanded_archive_bytes + 1)
    except (EOFError, gzip.BadGzipFile, OSError) as exc:
        raise TarballFormatError("tarball is not a complete gzip stream") from exc

    if len(expanded) > limits.max_expanded_archive_bytes:
        raise TarballLimitError(
            "expanded tar stream exceeds max_expanded_archive_bytes"
        )
    if not expanded:
        raise TarballFormatError("gzip stream contains no tar archive")
    return expanded


def _canonical_member_name(member: tarfile.TarInfo, limits: TarballLimits) -> str:
    raw_name = member.name
    if not raw_name:
        raise TarballSafetyError("archive member name cannot be empty")
    if raw_name.startswith("/"):
        raise TarballSafetyError("absolute archive member paths are forbidden")
    if "\\" in raw_name:
        raise TarballSafetyError("archive member paths must use POSIX separators")
    if any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in raw_name
    ):
        raise TarballSafetyError("archive member paths cannot contain control bytes")

    parts = raw_name.split("/")
    if member.isdir() and parts[-1] == "":
        parts = parts[:-1]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise TarballSafetyError("archive member path is not canonical")
    first = parts[0]
    if len(first) >= 2 and first[0].isalpha() and first[1] == ":":
        raise TarballSafetyError("Windows drive archive paths are forbidden")

    canonical = "/".join(parts)
    if unicodedata.normalize("NFC", canonical) != canonical:
        raise TarballSafetyError("archive member paths must use NFC Unicode")
    try:
        encoded_path = canonical.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise TarballSafetyError("archive member path is not valid UTF-8") from exc
    if len(encoded_path) > limits.max_path_bytes:
        raise TarballLimitError("archive member path exceeds max_path_bytes")
    for component in parts:
        if len(component.encode("utf-8")) > 255:
            raise TarballLimitError("archive member path component exceeds 255 bytes")
        if component.endswith((" ", ".")):
            raise TarballSafetyError(
                "archive member path components cannot end with space or dot"
            )
        if ":" in component:
            raise TarballSafetyError(
                "archive member path components cannot contain a colon"
            )
        reserved_stem = component.split(".", 1)[0].casefold()
        if reserved_stem in _WINDOWS_RESERVED_NAMES:
            raise TarballSafetyError(
                "archive member path uses a reserved Windows device name"
            )
    return canonical


def _member_payload(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
) -> bytes:
    extracted = archive.extractfile(member)
    if extracted is None:
        raise TarballFormatError(f"could not read regular member {member.name!r}")
    try:
        payload = extracted.read(member.size + 1)
    finally:
        extracted.close()
    if len(payload) != member.size:
        raise TarballFormatError(f"archive member {member.name!r} is truncated")
    return payload


def _parse_skill_yaml(payload: bytes) -> dict[str, object]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TarballFormatError("skill.yaml must be valid UTF-8") from exc
    try:
        parsed: object = yaml.load(text, Loader=_StrictSafeLoader)
    except (RecursionError, yaml.YAMLError) as exc:
        raise TarballFormatError("skill.yaml is not strict valid YAML") from exc
    if not isinstance(parsed, Mapping):
        raise TarballFormatError("skill.yaml must contain a top-level mapping")

    mapping = cast(Mapping[str, object], parsed)
    document = dict(mapping)
    try:
        canonical_manifest_bytes(document)
    except SignatureVerificationError as exc:
        raise TarballFormatError(
            "skill.yaml must contain only JSON-compatible manifest values"
        ) from exc
    return document


def _validate_path_relationships(
    name: str,
    *,
    is_directory: bool,
    seen_paths: dict[str, bool],
    seen_prefix_spellings: dict[str, str],
) -> None:
    folded = name.casefold()
    if folded in seen_paths:
        raise TarballSafetyError(f"duplicate archive member path {name!r}")

    original_components = name.split("/")
    folded_components = folded.split("/")
    for index in range(1, len(folded_components) + 1):
        original_prefix = "/".join(original_components[:index])
        folded_prefix = "/".join(folded_components[:index])
        prior_spelling = seen_prefix_spellings.get(folded_prefix)
        if prior_spelling is not None and prior_spelling != original_prefix:
            raise TarballSafetyError(
                "archive member paths have a case-insensitive component collision"
            )
        seen_prefix_spellings[folded_prefix] = original_prefix

    for index in range(1, len(folded_components)):
        parent = "/".join(folded_components[:index])
        if parent in seen_paths and not seen_paths[parent]:
            raise TarballSafetyError(
                f"archive member {name!r} has a regular-file parent"
            )
    if not is_directory and any(
        existing.startswith(f"{folded}/") for existing in seen_paths
    ):
        raise TarballSafetyError(
            f"regular archive member {name!r} conflicts with an existing child"
        )
    seen_paths[folded] = is_directory


def _validate_tar_termination(raw_tar: bytes, last_member_end: int) -> None:
    if len(raw_tar) % _TAR_BLOCK_SIZE != 0:
        raise TarballFormatError("tar stream is not block aligned")
    trailing = raw_tar[last_member_end:]
    if len(trailing) < _TAR_END_SIZE or any(trailing):
        raise TarballFormatError(
            "tar stream must end after two zero blocks without hidden payload"
        )


def _inspect_tarball(
    tarball_bytes: bytes,
    limits: TarballLimits,
) -> _ArchiveInspection:
    raw_tar = _decompress_tarball(tarball_bytes, limits)
    members: list[_ArchiveMember] = []
    manifests: list[SkillYamlDocument] = []
    seen_paths: dict[str, bool] = {}
    seen_prefix_spellings: dict[str, str] = {}
    total_file_bytes = 0
    last_member_end = 0

    try:
        with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as archive:
            for index, member in enumerate(archive, start=1):
                if index > limits.max_members:
                    raise TarballLimitError("archive exceeds max_members")
                if member.issym() or member.islnk():
                    raise TarballSafetyError(
                        "symbolic and hard links are forbidden in skill archives"
                    )
                if not member.isfile() and not member.isdir():
                    raise TarballSafetyError(
                        "skill archives may contain only regular files and directories"
                    )
                if member.issparse():
                    raise TarballSafetyError("sparse archive members are forbidden")
                if member.size < 0:
                    raise TarballFormatError("archive member size cannot be negative")
                if member.isdir() and member.size != 0:
                    raise TarballFormatError(
                        "directory archive members must have size zero"
                    )

                name = _canonical_member_name(member, limits)
                _validate_path_relationships(
                    name,
                    is_directory=member.isdir(),
                    seen_paths=seen_paths,
                    seen_prefix_spellings=seen_prefix_spellings,
                )

                data: bytes | None = None
                if member.isfile():
                    if member.size > limits.max_file_bytes:
                        raise TarballLimitError(
                            f"archive member {name!r} exceeds max_file_bytes"
                        )
                    total_file_bytes += member.size
                    if total_file_bytes > limits.max_total_file_bytes:
                        raise TarballLimitError(
                            "archive contents exceed max_total_file_bytes"
                        )
                    if name.split("/")[-1].casefold() == _SKILL_YAML_NAME:
                        if name.split("/")[-1] != _SKILL_YAML_NAME:
                            raise TarballSafetyError(
                                "skill.yaml must use the exact lowercase filename"
                            )
                        if len(name.split("/")) > 2:
                            raise TarballSafetyError(
                                "skill.yaml must be at archive root or "
                                "one directory deep"
                            )
                        if member.size > limits.max_skill_yaml_bytes:
                            raise TarballLimitError(
                                "skill.yaml exceeds max_skill_yaml_bytes"
                            )
                    data = _member_payload(archive, member)

                basename = name.split("/")[-1]
                if basename.casefold() == _SKILL_YAML_NAME:
                    if member.isdir():
                        raise TarballSafetyError("skill.yaml must be a regular file")
                    assert data is not None
                    manifests.append(
                        SkillYamlDocument(
                            path=name,
                            mapping=_parse_skill_yaml(data),
                        )
                    )
                    if len(manifests) > 1:
                        raise TarballSafetyError(
                            "archive contains ambiguous duplicate skill.yaml files"
                        )

                members.append(
                    _ArchiveMember(
                        name=name,
                        is_directory=member.isdir(),
                        mode=member.mode,
                        data=data,
                    )
                )
                member_end = member.offset_data + member.size
                aligned_end = (
                    (member_end + _TAR_BLOCK_SIZE - 1) // _TAR_BLOCK_SIZE
                ) * _TAR_BLOCK_SIZE
                last_member_end = max(last_member_end, aligned_end)
    except TarballError:
        raise
    except (EOFError, OSError, tarfile.TarError) as exc:
        raise TarballFormatError("tarball contains malformed tar data") from exc

    _validate_tar_termination(raw_tar, last_member_end)
    if not manifests:
        raise TarballFormatError(
            "archive must contain one skill.yaml at root or one directory deep"
        )
    manifest = manifests[0]
    if "/" in manifest.path:
        package_root = manifest.path.split("/", 1)[0]
        if any(
            member.name != package_root
            and not member.name.startswith(f"{package_root}/")
            for member in members
        ):
            raise TarballSafetyError(
                "one-directory-deep packages cannot contain members outside "
                "their package root"
            )
    return _ArchiveInspection(manifest=manifest, members=tuple(members))


def extract_skill_yaml(
    tarball_bytes: bytes,
    *,
    limits: TarballLimits = DEFAULT_TARBALL_LIMITS,
) -> SkillYamlDocument:
    """Inspect a bounded archive and return its single strict manifest mapping."""

    return _inspect_tarball(tarball_bytes, limits).manifest


def _snapshot_json_value(
    value: object,
    *,
    active_container_ids: set[int],
) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TarballFormatError("signed skill.yaml contains a non-finite number")
        return value
    if not isinstance(value, (Mapping, list, tuple)):
        raise TarballFormatError("signed skill.yaml contains a non-JSON value")

    container_id = id(value)
    if container_id in active_container_ids:
        raise TarballFormatError("signed skill.yaml contains a cycle")
    active_container_ids.add(container_id)
    try:
        if isinstance(value, Mapping):
            snapshot: dict[str, object] = {}
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise TarballFormatError(
                        "signed skill.yaml mapping keys must be strings"
                    )
                if key in snapshot:
                    raise TarballFormatError(
                        f"signed skill.yaml contains duplicate key {key!r}"
                    )
                snapshot[key] = _snapshot_json_value(
                    nested,
                    active_container_ids=active_container_ids,
                )
            return snapshot
        return [
            _snapshot_json_value(
                nested,
                active_container_ids=active_container_ids,
            )
            for nested in value
        ]
    finally:
        active_container_ids.remove(container_id)


def _serialise_signed_manifest(
    original: Mapping[str, object],
    signed: Mapping[str, object],
    limits: TarballLimits,
) -> bytes:
    try:
        plain_value = _snapshot_json_value(
            signed,
            active_container_ids=set(),
        )
    except RecursionError as exc:
        raise TarballFormatError(
            "signed skill.yaml nesting exceeds the supported limit"
        ) from exc
    if not isinstance(plain_value, dict):
        raise TarballFormatError("signed skill.yaml must be a mapping")
    plain = cast(dict[str, object], plain_value)

    signature = plain.get("signature")
    if not isinstance(signature, str):
        raise TarballFormatError("rebuilt skill.yaml requires a string signature")
    try:
        decode_signature(signature)
        original_unsigned = canonical_manifest_bytes(original)
        signed_unsigned = canonical_manifest_bytes(plain)
    except SignatureVerificationError as exc:
        raise TarballFormatError(
            "signed skill.yaml violates the signing contract"
        ) from exc
    if original_unsigned != signed_unsigned:
        raise TarballSafetyError(
            "rebuild may replace only the top-level skill.yaml signature"
        )

    try:
        rendered = cast(
            str,
            yaml.safe_dump(
                plain,
                allow_unicode=True,
                sort_keys=True,
            ),
        )
        payload = rendered.encode("utf-8")
    except (RecursionError, TypeError, ValueError, yaml.YAMLError) as exc:
        raise TarballFormatError(
            "signed skill.yaml cannot be serialised safely"
        ) from exc
    if len(payload) > limits.max_skill_yaml_bytes:
        raise TarballLimitError("rebuilt skill.yaml exceeds max_skill_yaml_bytes")
    return payload


def _normalised_tar_info(member: _ArchiveMember, payload_size: int) -> tarfile.TarInfo:
    name = f"{member.name}/" if member.is_directory else member.name
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE if member.is_directory else tarfile.REGTYPE
    info.mode = 0o755 if member.is_directory or member.mode & 0o111 else 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.size = payload_size
    return info


def rebuild_tarball(
    tarball_bytes: bytes,
    signed_skill_yaml: Mapping[str, object],
    *,
    limits: TarballLimits = DEFAULT_TARBALL_LIMITS,
) -> bytes:
    """Replace only the manifest signature and emit deterministic gzip tar bytes."""

    if not isinstance(signed_skill_yaml, Mapping):
        raise TarballFormatError("signed_skill_yaml must be a mapping")
    inspection = _inspect_tarball(tarball_bytes, limits)
    signed_payload = _serialise_signed_manifest(
        inspection.manifest.mapping,
        signed_skill_yaml,
        limits,
    )

    output = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=output,
        mtime=0,
    ) as compressed:
        with tarfile.open(
            fileobj=compressed,
            mode="w|",
            format=tarfile.PAX_FORMAT,
        ) as rebuilt:
            for member in inspection.members:
                payload = (
                    signed_payload
                    if member.name == inspection.manifest.path
                    else member.data
                )
                payload_size = 0 if payload is None else len(payload)
                info = _normalised_tar_info(member, payload_size)
                rebuilt.addfile(
                    info,
                    None if payload is None else io.BytesIO(payload),
                )

    rebuilt_bytes = output.getvalue()
    if len(rebuilt_bytes) > limits.max_archive_bytes:
        raise TarballLimitError("rebuilt tarball exceeds max_archive_bytes")
    rebuilt_inspection = _inspect_tarball(rebuilt_bytes, limits)
    if rebuilt_inspection.manifest.path != inspection.manifest.path:
        raise TarballFormatError("rebuilt tarball changed the manifest path")
    return rebuilt_bytes
