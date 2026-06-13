from __future__ import annotations

import json
from pathlib import Path
from typing import Any


LATEST_SCHEMA = "rvmt.genesys2.latest_manifest.v1"
DEFAULT_LATEST_MANIFEST = Path("results/evaluation/genesys2-cva6/current/latest_manifest.json")


def repo_path(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_latest_manifest(root: Path, manifest_path: Path | None = None) -> tuple[Path, dict[str, Any]]:
    manifest = repo_path(root, manifest_path or DEFAULT_LATEST_MANIFEST)
    if not manifest.is_file():
        raise ValueError(f"latest manifest missing: {manifest}")
    data = load_json(manifest)
    if data.get("schema") != LATEST_SCHEMA:
        raise ValueError(f"{manifest}: schema must be {LATEST_SCHEMA}")
    if data.get("status") != "PASS":
        raise ValueError(f"{manifest}: status must be PASS")
    return manifest, data


def active_run_root(root: Path, key: str, manifest_path: Path | None = None) -> Path:
    manifest_path_resolved, manifest = load_latest_manifest(root, manifest_path)
    active_roots = manifest.get("active_run_roots")
    if not isinstance(active_roots, dict):
        raise ValueError(f"{manifest_path_resolved}: active_run_roots must be an object")
    value = active_roots.get(key)
    if not value:
        raise ValueError(f"{manifest_path_resolved}: active_run_roots.{key} missing")
    path = repo_path(root, str(value))
    if not path.exists():
        raise ValueError(f"{manifest_path_resolved}: active_run_roots.{key} does not exist: {value}")
    return path
