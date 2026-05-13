#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Validate dependency intent files and pinned install artifacts stay aligned."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_NAME_RE = re.compile(r"^([A-Za-z0-9_.-]+)")


def _normalise_name(requirement: str) -> str:
    match = _NAME_RE.match(requirement.strip())
    if match is None:
        raise ValueError(f"could not parse requirement name: {requirement!r}")
    return match.group(1).lower().replace("_", "-")


def _read_intent(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith(("#", "-r "))
    ]


def _read_pinned_names(path: Path) -> set[str]:
    names: set[str] = set()
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-r ", "--")):
            continue
        if "==" not in line:
            continue
        names.add(_normalise_name(line.split("==", 1)[0]))
    return names


def _assert_equal(label: str, left: object, right: object) -> None:
    if left != right:
        raise AssertionError(f"{label} mismatch:\nleft={left!r}\nright={right!r}")


def main() -> int:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = pyproject["project"]

    runtime_intent = _read_intent(ROOT / "requirements.in")
    dev_intent = _read_intent(ROOT / "requirements-dev.in")
    runtime_project = list(project["dependencies"])
    dev_project = list(project["optional-dependencies"]["dev"])

    _assert_equal(
        "pyproject dependencies vs requirements.in", runtime_project, runtime_intent
    )
    _assert_equal(
        "pyproject dev dependencies vs requirements-dev.in", dev_project, dev_intent
    )

    runtime_names = {_normalise_name(dep) for dep in runtime_intent}
    dev_names = {_normalise_name(dep) for dep in dev_intent}
    _assert_equal(
        "requirements.txt pinned package names",
        _read_pinned_names(ROOT / "requirements.txt"),
        runtime_names,
    )
    _assert_equal(
        "requirements-dev.txt pinned package names",
        _read_pinned_names(ROOT / "requirements-dev.txt"),
        dev_names,
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - command-line guard should print cleanly
        print(f"dependency alignment check failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
