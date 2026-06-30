from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    repo_path,
    repo_rel,
    sha256_file,
    write_json,
)


DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
WILDCARD_RE = re.compile(r"[*?\[]")
WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:/")
REPO_PREFIXES = (
    "results/",
    "docs/",
    "tools/",
    "rtl/",
    "sim/",
    "src/",
    "scripts/",
    "docker/",
    "benchmarks/",
    "paper/",
)
PATH_KEYS = {
    "artifact",
    "artifact_path",
    "behavior_audit",
    "behavior_graph",
    "behavior_mapping",
    "command_transcript",
    "evidence",
    "external_summary_path",
    "integrated_validation",
    "latest_manifest",
    "manifest",
    "metric_summary",
    "path",
    "report",
    "repo_path",
    "resource_timing_summary",
    "runtime_process_map",
    "semantic_events",
    "source_artifact",
    "summary",
    "trace",
    "trace_source",
    "workload_manifest",
}
SKIP_MARKERS = (
    "NOT_",
    "MISSING",
    "UNREADABLE",
    "HOST_CONTROL_",
    "TODO",
    "TEMPLATE",
    "OPEN_",
    "BLOCKED_",
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def is_path_key(key: str) -> bool:
    key = key.lower()
    return key in PATH_KEYS or key.endswith(("_path", "_file", "_manifest", "_summary", "_log", "_json", "_trace"))


def is_skip_value(value: str) -> bool:
    stripped = value.strip()
    normalized = stripped.replace("\\", "/")
    return (
        not stripped
        or bool(WINDOWS_DRIVE_RE.match(normalized))
        or stripped.startswith(("http://", "https://", "uv run ", "python ", "vivado ", "<"))
        or stripped.endswith(":")
        or stripped.upper().startswith(SKIP_MARKERS)
        or "{" in stripped
        or "}" in stripped
        or "$" in stripped
    )


def is_repo_path_like(value: Any) -> bool:
    if not isinstance(value, str) or is_skip_value(value):
        return False
    normalized = value.replace("\\", "/").strip().strip("`'\".,)")
    if normalized.startswith(REPO_PREFIXES):
        return True
    return "/" in normalized and "." in Path(normalized).name


def normalized_path_value(value: str) -> str:
    return value.replace("\\", "/").strip().strip("`'\".,)")


def has_wildcard(value: Any) -> bool:
    return isinstance(value, str) and bool(WILDCARD_RE.search(value))


def context_is_pass(row: dict[str, Any]) -> bool:
    return row.get("status") == "PASS" or row.get("pass") is True


def concrete_path_fields(row: dict[str, Any]) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = []
    for key, value in row.items():
        if is_path_key(str(key)) and is_repo_path_like(value):
            fields.append((str(key), normalized_path_value(str(value))))
    return fields


def find_path_for_hash(row: dict[str, Any], hash_key: str = "sha256") -> tuple[str, str] | None:
    if hash_key != "sha256":
        stem = hash_key.removesuffix("_sha256")
        for candidate in (stem, f"{stem}_path", f"{stem}_file", f"{stem}_artifact"):
            value = row.get(candidate)
            if is_repo_path_like(value):
                return candidate, normalized_path_value(str(value))
        return None
    for preferred in ("path", "artifact_path", "external_summary_path", "report", "manifest", "summary"):
        value = row.get(preferred)
        if is_repo_path_like(value):
            return preferred, normalized_path_value(str(value))
    fields = concrete_path_fields(row)
    return fields[0] if fields else None


def check_json_row(root: Path, source: Path, row: dict[str, Any], json_path: str, errors: list[str]) -> None:
    for key, value in row.items():
        if isinstance(value, str) and HEX64_RE.fullmatch(value):
            path_field = find_path_for_hash(row, str(key))
            if path_field is None:
                continue
            path_key, path_value = path_field
            if has_wildcard(path_value):
                errors.append(f"{repo_rel(root, source)}:{json_path}.{path_key}: sha256 cannot point at wildcard path {path_value}")
                continue
            full_path = repo_path(root, path_value)
            if not full_path.is_file():
                errors.append(f"{repo_rel(root, source)}:{json_path}.{path_key}: hashed artifact missing: {path_value}")
                continue
            actual = sha256_file(full_path)
            if actual != value:
                errors.append(f"{repo_rel(root, source)}:{json_path}.{key}: sha256 mismatch for {path_value}")

    must_exist = context_is_pass(row) or row.get("exists") is True or row.get("external_summary_exists") is True
    if not must_exist:
        return
    for key, path_value in concrete_path_fields(row):
        if has_wildcard(path_value):
            errors.append(f"{repo_rel(root, source)}:{json_path}.{key}: PASS/existence row uses wildcard artifact path {path_value}")
            continue
        full_path = repo_path(root, path_value)
        if not full_path.exists():
            errors.append(f"{repo_rel(root, source)}:{json_path}.{key}: artifact path missing: {path_value}")


def walk_json(root: Path, source: Path, value: Any, json_path: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        check_json_row(root, source, value, json_path, errors)
        for key, nested in value.items():
            walk_json(root, source, nested, f"{json_path}.{key}", errors)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            walk_json(root, source, nested, f"{json_path}[{index}]", errors)


MD_PATH_RE = re.compile(r"(?P<path>(?:results|docs|tools|rtl|sim|src|scripts|docker|benchmarks|paper)/[A-Za-z0-9_./-]+)")


def markdown_files(root: Path, current_root: Path) -> list[Path]:
    files = list((root / current_root).rglob("*.md"))
    for path in [
        root / "README.md",
        root / "docs/07-evaluation-evidence/reports/genesys2_cva6_evidence_chain_20260611.md",
        root / "docs/09-planning/ndss_execution_status.md",
    ]:
        if path.is_file():
            files.append(path)
    return sorted(set(files))


def check_markdown(root: Path, path: Path, errors: list[str]) -> None:
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if "PASS" not in line and "sha256" not in line.lower() and "results/evaluation/genesys2-cva6/current" not in line:
            continue
        for match in MD_PATH_RE.finditer(line.replace("\\", "/")):
            value = normalized_path_value(match.group("path"))
            if has_wildcard(value) or is_skip_value(value):
                continue
            if not repo_path(root, value).exists():
                errors.append(f"{repo_rel(root, path)}:{line_no}: markdown artifact path missing: {value}")


def check_root(root: Path, current_root: Path = DEFAULT_CURRENT_ROOT) -> list[str]:
    errors: list[str] = []
    base = root / current_root
    if not base.is_dir():
        return [f"canonical evidence root missing: {current_root.as_posix()}"]
    for path in sorted(base.rglob("*.json")):
        try:
            value = load_json(path)
        except Exception as exc:
            errors.append(f"{repo_rel(root, path)}: invalid JSON: {exc}")
            continue
        walk_json(root, path, value, "$", errors)
    for path in markdown_files(root, current_root):
        check_markdown(root, path, errors)
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True)
        artifact = current / "artifact.txt"
        artifact.write_text("artifact\n", encoding="utf-8")
        write_json(
            current / "summary.json",
            {
                "schema": "rvmt.fixture.v1",
                "status": "PASS",
                "path": repo_rel(root, artifact),
                "sha256": sha256_file(artifact),
            },
        )
        (current / "README.md").write_text(f"PASS artifact `{repo_rel(root, artifact)}`\n", encoding="utf-8")
        errors = check_root(root)
        if errors:
            print("[FAIL] artifact integrity good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1

        write_json(
            current / "summary.json",
            {
                "schema": "rvmt.fixture.v1",
                "status": "PASS",
                "path": repo_rel(root, artifact),
                "sha256": "0" * 64,
            },
        )
        if not any("sha256 mismatch" in error for error in check_root(root)):
            print("[FAIL] artifact integrity missed sha mismatch", file=sys.stderr)
            return 1

        write_json(
            current / "summary.json",
            {
                "schema": "rvmt.fixture.v1",
                "status": "PASS",
                "evidence": "results/evaluation/genesys2-cva6/current/*.txt",
            },
        )
        if not any("wildcard" in error for error in check_root(root)):
            print("[FAIL] artifact integrity missed PASS wildcard", file=sys.stderr)
            return 1

        write_json(
            current / "summary.json",
            {
                "schema": "rvmt.fixture.v1",
                "status": "PASS",
                "path": "results/evaluation/genesys2-cva6/current/missing.txt",
            },
        )
        if not any("artifact path missing" in error for error in check_root(root)):
            print("[FAIL] artifact integrity missed missing path", file=sys.stderr)
            return 1

        write_json(
            current / "summary.json",
            {
                "schema": "rvmt.fixture.v1",
                "status": "PASS",
                "tool": {"path": "D:/Application/vivado/2025.2/Vivado/bin/vivado.bat"},
            },
        )
        errors = check_root(root)
        if errors:
            print("[FAIL] artifact integrity rejected host-only Windows tool path", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    print("[PASS] Genesys2 recursive artifact integrity checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recursively check Genesys2/CVA6 current artifacts, paths, and sha256 hashes.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    errors = check_root(root, args.current_root)
    if errors:
        print("[FAIL] Genesys2 recursive artifact integrity check failed")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] Genesys2 recursive artifact integrity accepted: {args.current_root.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
