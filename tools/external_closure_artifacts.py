from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from check_genesys2_external_closure_intake import DEFAULT_EXTERNAL_ROOT, sha256_file, write_json


ROOT = Path(__file__).resolve().parents[1]


def repo_path(root: Path, value: Path | str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def repo_relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object")
            rows.append(value)
    return rows


def external_record_root(root: Path, record_id: str) -> Path:
    path = repo_path(root, DEFAULT_EXTERNAL_ROOT / record_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_text_artifact(root: Path, record_id: str, kind: str, text: str, suffix: str = ".txt") -> Path:
    path = external_record_root(root, record_id) / f"{kind}{suffix}"
    path.write_text(text.rstrip() + "\n", encoding="utf-8", newline="\n")
    return path


def write_json_artifact(root: Path, record_id: str, kind: str, value: dict[str, Any] | list[Any]) -> Path:
    path = external_record_root(root, record_id) / f"{kind}.json"
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return path


def copy_sample_artifact(root: Path, record_id: str, sample_id: str, source: Path, filename: str) -> Path:
    dest = external_record_root(root, record_id) / sample_id / filename
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)
    return dest


def evidence_rows(root: Path, artifacts: dict[str, Path]) -> list[dict[str, str]]:
    return [
        {
            "id": kind,
            "kind": kind,
            "path": repo_relative(root, path),
            "sha256": sha256_file(path),
        }
        for kind, path in sorted(artifacts.items())
    ]


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_summary(root: Path, out: Path, value: dict[str, Any]) -> Path:
    path = repo_path(root, out)
    write_json(path, value)
    return path
