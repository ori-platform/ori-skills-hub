# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_CHECKER = Path("scripts/check_dependency_alignment.py")
_DEPENDENCY_FILES = (
    "pyproject.toml",
    "requirements.in",
    "requirements-dev.in",
    "requirements.txt",
    "requirements-dev.txt",
)
_PHASE_TWO_RUNTIME_DEPENDENCIES = {
    "aiosqlite",
    "alembic",
    "cryptography",
    "httpx",
    "python-multipart",
    "sqlalchemy",
}
_DEV_ONLY_DEPENDENCIES = {
    "cyclonedx-bom",
    "msgpack",
    "mypy",
    "pip",
    "pip-audit",
    "pre-commit",
    "pytest",
    "ruff",
}
_NAME_RE = re.compile(r"^([A-Za-z0-9_.-]+)")


def _dependency_names(path: Path) -> set[str]:
    names: set[str] = set()
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-r ", "--")):
            continue
        match = _NAME_RE.match(line)
        if match is not None:
            names.add(match.group(1).lower().replace("_", "-"))
    return names


def _run_alignment_check(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(root / _CHECKER)],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )


def test_dependency_alignment() -> None:
    result = _run_alignment_check(_ROOT)

    assert result.returncode == 0, result.stderr


def test_dependency_alignment_rejects_intent_drift(tmp_path: Path) -> None:
    for relative_path in _DEPENDENCY_FILES:
        shutil.copy2(_ROOT / relative_path, tmp_path / relative_path)
    (tmp_path / _CHECKER.parent).mkdir()
    shutil.copy2(_ROOT / _CHECKER, tmp_path / _CHECKER)
    with (tmp_path / "requirements.in").open("a", encoding="utf-8") as requirements:
        requirements.write("unexpected-package>=1\n")

    result = _run_alignment_check(tmp_path)

    assert result.returncode == 1
    assert "pyproject dependencies vs requirements.in mismatch" in result.stderr


def test_phase_two_dependencies_remain_runtime_only() -> None:
    runtime_names = _dependency_names(_ROOT / "requirements.in")
    dev_names = _dependency_names(_ROOT / "requirements-dev.in")
    runtime_lock_names = _dependency_names(_ROOT / "requirements.txt")
    dev_lock_names = _dependency_names(_ROOT / "requirements-dev.txt")

    assert _PHASE_TWO_RUNTIME_DEPENDENCIES <= runtime_names
    assert _PHASE_TWO_RUNTIME_DEPENDENCIES.isdisjoint(dev_names)
    assert _DEV_ONLY_DEPENDENCIES.isdisjoint(runtime_names)
    assert _DEV_ONLY_DEPENDENCIES.isdisjoint(runtime_lock_names)
    assert "pynacl" not in (
        runtime_names | dev_names | runtime_lock_names | dev_lock_names
    )
