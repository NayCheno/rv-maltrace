from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import package_genesys2_raw_artifact_release as packager


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/raw_artifact_release_manifest.json")
EXPECTED_SCHEMA = "rvmt.genesys2.raw_artifact_release.v1"
DOCUMENTED_ARCHIVE_HASH_PATHS = (
    Path("docs/07-evaluation-evidence/ndss_artifact_instructions.md"),
    Path("docs/09-planning/ndss_execution_status.md"),
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def repo_path(root: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def int_field(row: dict[str, Any], key: str, default: int = -1) -> int:
    value = row.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def check_documented_archive_hashes(data: dict[str, Any], root: Path, errors: list[str]) -> None:
    archive = as_dict(data.get("archive"))
    archive_sha = str(archive.get("sha256") or "").lower()
    archive_path = str(archive.get("path") or "")
    archive_name = Path(archive_path).name
    if not re.fullmatch(r"[0-9a-f]{64}", archive_sha):
        return
    for rel_path in DOCUMENTED_ARCHIVE_HASH_PATHS:
        path = repo_path(root, rel_path)
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if archive_name not in text and "raw artifact" not in text.lower():
            continue
        require(errors, archive_sha in text.lower(), f"{rel_path.as_posix()}: current raw archive sha256 missing")
        lines = text.splitlines()
        for index, line in enumerate(lines):
            line_lc = line.lower()
            if not (
                archive_name in line
                or "raw artifact" in line_lc
                or "raw-artifact" in line_lc
                or "final zip sha256" in line_lc
                or "file_count" in line_lc
            ):
                continue
            window = "\n".join(lines[max(0, index - 2) : index + 3])
            for found in re.findall(r"\b[0-9a-fA-F]{64}\b", window):
                if found.lower() != archive_sha:
                    errors.append(
                        f"{rel_path.as_posix()}: documented raw archive sha256 {found.lower()} "
                        f"does not match manifest/archive {archive_sha}"
                    )


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == EXPECTED_SCHEMA, "schema mismatch")
    require(errors, data.get("status") == "PASS_LOCAL_ARCHIVE_PRESENT", "status must be PASS_LOCAL_ARCHIVE_PRESENT")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("raw_board_artifacts_copied_into_git") is False, "raw artifacts must not be described as copied into git")
    require(errors, boundary.get("local_archive_created") is True, "local archive boundary missing")
    require(errors, boundary.get("archive_required_for_clean_checkout_raw_reproduction") is True, "clean-checkout archive boundary missing")
    require(errors, boundary.get("archive_extracts_current_ignored_artifacts") is False, "raw archive must not claim to extract the canonical current root")
    require(errors, boundary.get("archive_excludes_canonical_current_root") is True, "canonical current-root exclusion boundary missing")
    require(errors, boundary.get("archive_extracts_manifest_referenced_ignored_artifacts") is True, "manifest-referenced ignored artifact boundary missing")
    require(errors, boundary.get("archive_supports_local_quick_and_local_reproduction") is True, "local quick/local reproduction boundary missing")
    require(errors, boundary.get("real_malware_payloads_included") is False, "raw release must not include malware payloads")

    source = as_dict(data.get("source_reproducibility_manifest"))
    source_path = repo_path(root, source.get("path"))
    require(errors, source_path.is_file(), "source reproducibility manifest missing")
    if source_path.is_file():
        require(errors, source.get("sha256") == sha256_file(source_path), "source reproducibility manifest sha256 mismatch")
        try:
            source_data = load_json(source_path)
        except Exception as exc:
            errors.append(f"source reproducibility manifest invalid JSON: {exc}")
        else:
            require(errors, source_data.get("schema") == "rvmt.genesys2.reproducibility_manifest.v1", "source reproducibility manifest schema mismatch")

    files = as_list(data.get("files"))
    require(errors, bool(files), "files list missing")
    roots = as_list(data.get("raw_artifact_roots"))
    artifact_sets = as_list(data.get("included_artifact_sets"))
    raw_root_ids = {str(row.get("id") or "") for row in roots if isinstance(row, dict)}
    artifact_set_ids = {str(row.get("id") or "") for row in artifact_sets if isinstance(row, dict)}
    require(errors, "current_manifest_referenced_artifacts" in artifact_set_ids, "current manifest artifact set missing")
    require(errors, "local_bitstream_inventory_artifacts" in artifact_set_ids, "local bitstream artifact set missing")
    require(errors, "bootrom_counter_delegation_artifacts" in artifact_set_ids, "bootrom counter-delegation artifact set missing")
    for row in artifact_sets:
        if not isinstance(row, dict):
            errors.append("included_artifact_sets rows must be objects")
            continue
        set_id = str(row.get("id") or "")
        require(errors, bool(set_id), "artifact set id missing")
        require(errors, int_field(row, "file_count", 0) >= 0, f"{set_id}: file_count must be nonnegative")
        require(errors, int_field(row, "total_bytes", 0) >= 0, f"{set_id}: total_bytes must be nonnegative")
        if set_id == "bootrom_counter_delegation_artifacts":
            require(errors, int_field(row, "file_count", 0) > 0, "bootrom counter-delegation artifact set must contain files")
    seen_paths: set[str] = set()
    for index, row in enumerate(files, start=1):
        if not isinstance(row, dict):
            errors.append(f"files[{index}]: row must be object")
            continue
        path_value = str(row.get("path") or "")
        root_id = str(row.get("root_id") or "")
        require(errors, bool(path_value), f"files[{index}]: path missing")
        require(
            errors,
            not path_value.startswith("results/evaluation/genesys2-cva6/current/"),
            f"{path_value}: raw archive must not contain canonical current-root files",
        )
        require(errors, root_id in raw_root_ids or root_id in artifact_set_ids, f"{path_value}: root_id is not declared")
        require(errors, path_value not in seen_paths, f"{path_value}: duplicate file row")
        seen_paths.add(path_value)
        path = repo_path(root, path_value)
        require(errors, path.is_file(), f"{path_value}: source file missing")
        if path.is_file():
            require(errors, int_field(row, "size_bytes") == path.stat().st_size, f"{path_value}: source file size mismatch")
            require(errors, row.get("sha256") == sha256_file(path), f"{path_value}: source file sha256 mismatch")

    archive = as_dict(data.get("archive"))
    archive_path = repo_path(root, archive.get("path"))
    require(errors, archive.get("exists") is True, "archive.exists must be true")
    require(errors, archive_path.is_file(), f"archive missing: {archive.get('path')}")
    require(errors, archive.get("format") == "zip", "archive format must be zip")
    require(errors, int(archive.get("file_count") or -1) == len(files), "archive file_count mismatch")
    if archive_path.is_file():
        require(errors, archive.get("sha256") == sha256_file(archive_path), "archive sha256 mismatch")
        require(errors, int(archive.get("size_bytes") or -1) == archive_path.stat().st_size, "archive size mismatch")
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                names = sorted(name for name in zf.namelist() if not name.endswith("/"))
                require(errors, names == sorted(seen_paths), "archive members do not match manifest files")
                file_map = {str(row.get("path")): row for row in files if isinstance(row, dict)}
                for name in names:
                    info = zf.getinfo(name)
                    row = as_dict(file_map.get(name))
                    require(errors, info.file_size == int_field(row, "size_bytes"), f"{name}: archive member size mismatch")
                    digest = sha256_bytes(zf.read(name))
                    require(errors, digest == row.get("sha256"), f"{name}: archive member sha256 mismatch")
        except zipfile.BadZipFile as exc:
            errors.append(f"archive is not a valid zip file: {exc}")
    check_documented_archive_hashes(data, root, errors)

    require(errors, bool(roots), "raw_artifact_roots missing")
    for row in roots:
        if not isinstance(row, dict):
            errors.append("raw_artifact_roots rows must be objects")
            continue
        root_id = str(row.get("id") or "")
        require(errors, bool(root_id), "raw root id missing")
        require(errors, row.get("exists") is True, f"{root_id}: root must exist")
        require(errors, int(row.get("file_count") or 0) > 0, f"{root_id}: file_count must be positive")
        require(errors, int(row.get("total_bytes") or 0) > 0, f"{root_id}: total_bytes must be positive")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_raw_artifact_release.py" in commands, "packager validation command missing")
    require(errors, "tools/check_genesys2_raw_artifact_release.py --root ." in commands, "checker validation command missing")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / "results/evaluation/genesys2-cva6/current"
        raw_root = root / "results/board/run/sample/rep_01"
        raw_root.mkdir(parents=True)
        (raw_root / "bram_records.jsonl").write_text('{"evt":"MARKER"}\n', encoding="utf-8")
        (raw_root / "capture.log").write_text("capture\n", encoding="utf-8")
        (raw_root / "capture.err.log").write_text("", encoding="utf-8")
        (raw_root / "uart.log").write_text("uart\n", encoding="utf-8")
        current.mkdir(parents=True)
        repro = {
            "schema": "rvmt.genesys2.reproducibility_manifest.v1",
            "status": "PASS",
            "raw_artifact_roots": [{"id": "fixture_root", "path": "results/board/run", "exists": True, "file_counts": {"logs": 2}}],
        }
        repro_path = current / "reproducibility_manifest.json"
        write_json(repro_path, repro)
        bootrom = root / "build/bootrom/genesys2-cva6/build_manifest.json"
        bootrom.parent.mkdir(parents=True, exist_ok=True)
        bootrom.write_text('{"schema":"fixture"}\n', encoding="utf-8")
        archive = root / "build/raw.zip"
        summary = packager.package_release(root, repro_path, archive, write_zip=True)
        doc = root / "docs/07-evaluation-evidence/ndss_artifact_instructions.md"
        doc.parent.mkdir(parents=True, exist_ok=True)
        doc.write_text(
            "raw artifact archive build/raw.zip\n"
            f"SHA256 {summary['archive']['sha256']}\n",
            encoding="utf-8",
            newline="\n",
        )
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] raw artifact release good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        doc.write_text(
            "raw artifact archive build/raw.zip\n"
            f"SHA256 {'1' * 64}\n",
            encoding="utf-8",
            newline="\n",
        )
        errors = check_summary(summary, root)
        if not any("documented raw archive sha256" in error for error in errors):
            print("[FAIL] raw artifact release missed stale documented archive sha", file=sys.stderr)
            return 1
        doc.write_text(
            "raw artifact archive build/raw.zip\n"
            f"SHA256 {summary['archive']['sha256']}\n",
            encoding="utf-8",
            newline="\n",
        )
        summary["archive"]["sha256"] = "0" * 64
        errors = check_summary(summary, root)
        if not any("archive sha256 mismatch" in error for error in errors):
            print("[FAIL] raw artifact release missed archive sha mismatch", file=sys.stderr)
            return 1
        summary = packager.package_release(root, repro_path, archive, write_zip=True)
        summary["claim_boundary"]["raw_board_artifacts_copied_into_git"] = True
        errors = check_summary(summary, root)
        if not any("copied into git" in error for error in errors):
            print("[FAIL] raw artifact release missed raw-in-git boundary", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 raw artifact release checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the local Genesys2/CVA6 raw artifact release archive and manifest.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] raw artifact release manifest missing: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] raw artifact release checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] raw artifact release manifest is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] raw artifact release accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
