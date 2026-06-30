from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def repo_path(root: Path, value: Any) -> Path:
    path = value if isinstance(value, Path) else Path(str(value))
    return path if path.is_absolute() else root / path


def repo_path_from(root: Path) -> Callable[[Any], Path]:
    return lambda value: repo_path(root, value)


def resolve(root: Path, value: Any) -> Path:
    return repo_path(root, value)


def repo_rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_rel_from(root: Path) -> Callable[[Path], str]:
    return lambda path: repo_rel(root, path)


def rel(path: Path, root: Path) -> str:
    return repo_rel(root, path)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(
    path: Path,
    *,
    missing_ok: bool = False,
    require_objects: bool = True,
    errors: str | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if missing_ok and not path.is_file():
        return rows
    with path.open("r", encoding="utf-8", errors=errors) as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            value = json.loads(text)
            if not isinstance(value, dict):
                if require_objects:
                    raise ValueError(f"{path}:{line_no}: expected JSON object")
                continue
            rows.append(value)
    return rows


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def read_json(path: Path, failures: list[str], root: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"missing {label}: {repo_rel(root, path)}")
        return {}
    try:
        return load_json(path)
    except Exception as exc:
        failures.append(f"invalid {label}: {repo_rel(root, path)}: {exc}")
        return {}


def read_text(path: Path, failures: list[str], root: Path, label: str) -> str:
    if not path.is_file():
        failures.append(f"missing {label}: {repo_rel(root, path)}")
        return ""
    return path.read_text(encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_file_if_present(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    return sha256_file(path)


def file_digest(path: Path) -> str:
    return sha256_file(path)


def file_record(path: Path, root: Path) -> dict[str, Any]:
    return {"path": repo_rel(root, path), "bytes": path.stat().st_size, "sha256": sha256_file(path)}


def class_digest(files: list[Path], root: Path) -> str | None:
    if not files:
        return None
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: repo_rel(root, item)):
        digest.update(repo_rel(root, path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(path.stat().st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def as_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def dict_rows(value: Any) -> list[dict[str, Any]]:
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def rows_by_id(rows: list[dict[str, Any]], key: str = "id") -> dict[str, dict[str, Any]]:
    return {str(row[key]): row for row in rows if row.get(key)}
