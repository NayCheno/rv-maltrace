from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    repo_path,
    require,
    sha256_file,
    write_json,
)

from genesys2_artifact_package_spec import REQUIRED_INCLUDED_PATHS, REQUIRED_RAW_ROOT_IDS


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/artifact_package_manifest.json")


def git_publishable(root: Path, path_value: str) -> bool | None:
    if not (root / ".git").exists():
        return None
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", path_value],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if tracked.returncode == 0:
        return True
    ignored = subprocess.run(
        ["git", "check-ignore", "-q", "--", path_value],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if ignored.returncode == 0:
        return False
    if ignored.returncode == 1:
        return True
    return None


def row_map(rows: list[Any], key: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get(key), str) and row.get(key):
            result[str(row[key])] = row
    return result


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.artifact_package.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("package_kind") == "lightweight-current-evidence-manifest", "package_kind mismatch")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    generated_from = data.get("generated_from")
    require(errors, generated_from == "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json", "generated_from must be current reproducibility manifest")
    if generated_from:
        repro = repo_path(root, generated_from)
        require(errors, repro.is_file(), f"generated_from missing: {generated_from}")
        if repro.is_file():
            try:
                repro_data = load_json(repro)
            except Exception as exc:
                errors.append(f"generated_from invalid JSON: {exc}")
            else:
                require(errors, repro_data.get("schema") == "rvmt.genesys2.reproducibility_manifest.v1", "generated_from schema mismatch")
                require(errors, repro_data.get("status") == "PASS", "generated_from status must be PASS")

    fresh = as_dict(data.get("fresh_clone_reproduction"))
    require(errors, fresh.get("script") == "tools/reproduce_genesys2_current.py", "fresh clone script mismatch")
    require(errors, fresh.get("requires_board_or_vivado") is False, "fresh clone checks must not require board/Vivado")
    require(errors, fresh.get("requires_network") is False, "fresh clone checks must not require network")
    quick = str(fresh.get("quick_command") or "")
    local = str(fresh.get("local_command") or "")
    full = str(fresh.get("full_command") or "")
    dry = str(fresh.get("dry_run_command") or "")
    raw_archive = str(fresh.get("raw_archive_check_command") or "")
    raw_extract = str(fresh.get("raw_archive_extract_command") or "")
    rvmt_quick = str(fresh.get("rvmt_quick_command") or "")
    rvmt_local = str(fresh.get("rvmt_local_command") or "")
    rvmt_full = str(fresh.get("rvmt_full_command") or "")
    rvmt_clean_export = str(fresh.get("rvmt_clean_export_command") or "")
    require(errors, "tools/reproduce_genesys2_current.py --quick" in quick, "quick reproduction command missing")
    require(errors, "tools/reproduce_genesys2_current.py --local" in local, "local reproduction command missing")
    require(errors, "tools/reproduce_genesys2_current.py --full" in full, "full reproduction command missing")
    require(errors, "tools/reproduce_genesys2_current.py --full --dry-run" in dry, "dry-run reproduction command missing")
    require(errors, "tools/check_genesys2_raw_artifact_release.py --root ." in raw_archive, "raw archive check command missing")
    require(errors, "Expand-Archive" in raw_extract and "-DestinationPath ." in raw_extract, "raw archive extraction command missing")
    require(errors, "rvmt repro:quick" in rvmt_quick, "rvmt quick reproduction command missing")
    require(errors, "rvmt repro:local" in rvmt_local, "rvmt local reproduction command missing")
    require(errors, "rvmt repro:full" in rvmt_full, "rvmt full reproduction command missing")
    require(errors, "rvmt repro:clean-export" in rvmt_clean_export, "rvmt clean-export reproduction command missing")
    require(errors, fresh.get("requires_raw_archive_extraction_for_clean_checkout_raw_reproduction") is True, "raw archive extraction boundary missing")

    included = row_map(as_list(data.get("included_files")), "path")
    missing_paths = sorted(REQUIRED_INCLUDED_PATHS - set(included))
    require(errors, not missing_paths, f"missing included files: {', '.join(missing_paths)}")
    for path_value, row in included.items():
        path = repo_path(root, path_value)
        require(errors, row.get("exists") is True, f"{path_value}: included file must exist")
        require(errors, path.is_file(), f"{path_value}: file missing")
        if path.is_file():
            require(errors, row.get("sha256") == sha256_file(path), f"{path_value}: sha256 mismatch")
            require(errors, int(row.get("size_bytes") or 0) == path.stat().st_size, f"{path_value}: size mismatch")
        publishable = git_publishable(root, path_value)
        if publishable is not None:
            require(errors, publishable is True, f"{path_value}: included file is ignored by git and would be omitted from the package")
            if "git_publishable" in row:
                require(errors, row.get("git_publishable") is True, f"{path_value}: git_publishable metadata must be true")

    raw_release = as_dict(data.get("raw_artifact_release"))
    raw_manifest = str(raw_release.get("manifest") or "")
    require(errors, raw_manifest == "results/evaluation/genesys2-cva6/current/raw_artifact_release_manifest.json", "raw release manifest path mismatch")
    if raw_manifest:
        raw_manifest_path = repo_path(root, raw_manifest)
        require(errors, raw_manifest_path.is_file(), "raw release manifest missing")
        if raw_manifest_path.is_file():
            require(errors, raw_release.get("manifest_sha256") == sha256_file(raw_manifest_path), "raw release manifest sha256 mismatch")
            try:
                raw_data = load_json(raw_manifest_path)
            except Exception as exc:
                errors.append(f"raw release manifest invalid JSON: {exc}")
            else:
                raw_boundary = as_dict(raw_data.get("claim_boundary"))
                require(errors, raw_data.get("schema") == "rvmt.genesys2.raw_artifact_release.v1", "raw release schema mismatch")
                require(errors, raw_data.get("status") == "PASS_LOCAL_ARCHIVE_PRESENT", "raw release status must be PASS_LOCAL_ARCHIVE_PRESENT")
                require(errors, raw_release.get("status") == raw_data.get("status"), "raw release embedded status mismatch")
                require(errors, raw_boundary.get("external_release_asset_published") is False, "raw release must not claim external publication")
                require(errors, raw_boundary.get("archive_required_for_clean_checkout_raw_reproduction") is True, "raw release must document archive requirement")

    raw_rows = row_map(as_list(data.get("referenced_raw_artifact_roots")), "id")
    missing_raw = sorted(REQUIRED_RAW_ROOT_IDS - set(raw_rows))
    require(errors, not missing_raw, f"missing raw roots: {', '.join(missing_raw)}")
    for root_id, row in raw_rows.items():
        require(errors, row.get("exists") is True, f"{root_id}: raw root must exist")
        path_value = row.get("path")
        require(errors, bool(path_value), f"{root_id}: raw root path missing")
        if path_value:
            require(errors, repo_path(root, path_value).is_dir(), f"{root_id}: raw root directory missing: {path_value}")
        counts = as_dict(row.get("file_counts"))
        require(errors, bool(counts) and any(int(value or 0) > 0 for value in counts.values()), f"{root_id}: raw root file_counts must be positive")
        policy = str(row.get("release_policy") or "").lower()
        require(errors, "not copied" in policy and "lightweight" in policy, f"{root_id}: raw root release policy must avoid copying")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_artifact_package.py" in commands, "validation command must include packager")
    require(errors, "tools/check_genesys2_artifact_package.py --root ." in commands, "validation command must include checker")
    require(errors, "tools/package_genesys2_raw_artifact_release.py" in commands, "validation command must include raw release packager")
    require(errors, "tools/check_genesys2_raw_artifact_release.py --root ." in commands, "validation command must include raw release checker")
    require(errors, "rvmt repro:clean-export" in commands, "validation command must include clean-export reproduction")
    require(errors, "tools/check_genesys2_clean_repro_bundle.py --root ." in commands, "validation command must include clean-export checker")
    require(errors, "tools/reproduce_genesys2_current.py --quick" in commands, "validation command must include quick reproduction")
    require(errors, "tools/reproduce_genesys2_current.py --local" in commands, "validation command must include local reproduction")
    require(errors, "rvmt repro:local" in commands, "validation command must include simplified rvmt reproduction")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("fresh_clone_reproduction_script_available") is True, "fresh clone boundary missing")
    require(errors, boundary.get("lightweight_manifest_package") is True, "lightweight boundary missing")
    require(errors, boundary.get("raw_board_artifacts_copied") is False, "raw board artifacts must not be copied")
    require(errors, boundary.get("local_raw_artifact_archive_created") is True, "local raw artifact archive boundary missing")
    require(errors, boundary.get("external_raw_release_asset_published") is False, "external raw release publication must not be claimed")
    require(errors, boundary.get("raw_archive_required_for_clean_checkout_raw_reproduction") is True, "clean-checkout raw archive boundary missing")
    require(errors, boundary.get("raw_archive_extraction_required_for_clean_checkout_raw_reproduction") is True, "clean-checkout raw archive extraction boundary missing")
    require(errors, boundary.get("requires_board_rerun_for_reproduction_checks") is False, "fresh clone checks must not require board rerun")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("production_streaming_dma_throughput_claimed") is False, "streaming/DMA throughput must not be claimed")
    if boundary.get("hardware_full_pointer_strings_claimed") is True:
        require(
            errors,
            boundary.get("external_full_hardware_pointer_strings_summary_accepted") is True,
            "full hardware pointer strings may be claimed only after artifact-backed external intake acceptance",
        )
    else:
        require(
            errors,
            boundary.get("hardware_full_pointer_strings_claimed") is False,
            "full hardware pointer string claim flag must be false unless externally accepted",
        )
    require(errors, boundary.get("board_native_source_line_attribution_claimed") is False, "board-native source-line attribution must not be claimed")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "does not copy large raw board artifacts" in non_claims, "non_claims must reject raw-copy package")
    require(errors, "not an external immutable release asset" in non_claims, "non_claims must reject unpublished raw archive")
    require(errors, "requires extracting the raw archive" in non_claims, "non_claims must document raw archive extraction")
    require(errors, "do not perform a new board run" in non_claims, "non_claims must reject board rerun")
    require(errors, "does not add real-malware validation" in non_claims, "non_claims must reject real malware validation")
    require(errors, "artifact-backed external-intake acceptance" in non_claims, "non_claims must preserve external-intake claim boundary")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for path_value in REQUIRED_INCLUDED_PATHS:
            path = root / path_value
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.name == "reproducibility_manifest.json":
                payload = {"schema": "rvmt.genesys2.reproducibility_manifest.v1", "status": "PASS"}
            elif path.name == "raw_artifact_release_manifest.json":
                payload = {
                    "schema": "rvmt.genesys2.raw_artifact_release.v1",
                    "status": "PASS_LOCAL_ARCHIVE_PRESENT",
                    "claim_boundary": {
                        "external_release_asset_published": False,
                        "archive_required_for_clean_checkout_raw_reproduction": True,
                    },
                }
            else:
                payload = "fixture\n"
            if isinstance(payload, dict):
                write_json(path, payload)
            else:
                path.write_text(payload, encoding="utf-8")
        raw = root / "raw"
        raw.mkdir()
        (raw / "artifact.log").write_text("fixture\n", encoding="utf-8")
        included = []
        for path_value in REQUIRED_INCLUDED_PATHS:
            path = root / path_value
            included.append({"path": path_value, "exists": True, "sha256": sha256_file(path), "size_bytes": path.stat().st_size})
        summary = {
            "schema": "rvmt.genesys2.artifact_package.v1",
            "status": "PASS",
            "package_kind": "lightweight-current-evidence-manifest",
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "generated_from": "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json",
            "fresh_clone_reproduction": {
                "script": "tools/reproduce_genesys2_current.py",
                "quick_command": "uv run python tools/reproduce_genesys2_current.py --quick",
                "local_command": "uv run python tools/reproduce_genesys2_current.py --local",
                "full_command": "uv run python tools/reproduce_genesys2_current.py --full",
                "dry_run_command": "uv run python tools/reproduce_genesys2_current.py --full --dry-run",
                "raw_archive_check_command": "uv run python tools/check_genesys2_raw_artifact_release.py --root .",
                "raw_archive_extract_command": "Expand-Archive build/ndss_artifacts/raw.zip -DestinationPath . -Force",
                "rvmt_quick_command": "uv run rvmt repro:quick",
                "rvmt_local_command": "uv run rvmt repro:local",
                "rvmt_full_command": "uv run rvmt repro:full",
                "rvmt_clean_export_command": "uv run rvmt repro:clean-export",
                "requires_board_or_vivado": False,
                "requires_network": False,
                "requires_external_raw_archive_for_clean_checkout_raw_reproduction": True,
                "requires_raw_archive_extraction_for_clean_checkout_raw_reproduction": True,
            },
            "raw_artifact_release": {
                "manifest": "results/evaluation/genesys2-cva6/current/raw_artifact_release_manifest.json",
                "manifest_exists": True,
                "manifest_sha256": sha256_file(root / "results/evaluation/genesys2-cva6/current/raw_artifact_release_manifest.json"),
                "status": "PASS_LOCAL_ARCHIVE_PRESENT",
                "archive_path": "build/ndss_artifacts/raw.zip",
                "archive_sha256": "0" * 64,
                "archive_size_bytes": 1,
                "archive_file_count": 1,
                "external_release_asset_published": False,
            },
            "included_files": included,
            "referenced_raw_artifact_roots": [
                {"id": root_id, "path": "raw", "exists": True, "file_counts": {"logs": 1}, "release_policy": "referenced-by-manifest; raw board artifacts are not copied into this lightweight package"}
                for root_id in REQUIRED_RAW_ROOT_IDS
            ],
            "validation_commands": [
                "uv run python tools/package_genesys2_artifact_package.py",
                "uv run python tools/check_genesys2_artifact_package.py --root .",
                "uv run python tools/package_genesys2_raw_artifact_release.py",
                "uv run python tools/check_genesys2_raw_artifact_release.py --root .",
                "uv run rvmt repro:clean-export",
                "uv run python tools/check_genesys2_clean_repro_bundle.py --root .",
                "uv run python tools/reproduce_genesys2_current.py --quick",
                "uv run python tools/reproduce_genesys2_current.py --local",
                "uv run rvmt repro:local --dry-run",
            ],
            "claim_boundary": {
                "fresh_clone_reproduction_script_available": True,
                "lightweight_manifest_package": True,
                "raw_board_artifacts_copied": False,
                "local_raw_artifact_archive_created": True,
                "external_raw_release_asset_published": False,
                "raw_archive_required_for_clean_checkout_raw_reproduction": True,
                "raw_archive_extraction_required_for_clean_checkout_raw_reproduction": True,
                "requires_board_rerun_for_reproduction_checks": False,
                "real_malware_validation_claimed": False,
                "production_streaming_dma_throughput_claimed": False,
                "hardware_full_pointer_strings_claimed": False,
                "external_full_hardware_pointer_strings_summary_accepted": False,
                "board_native_source_line_attribution_claimed": False,
            },
            "non_claims": [
                "This is a lightweight manifest package; it does not copy large raw board artifacts.",
                "The local raw artifact archive is not an external immutable release asset.",
                "Clean-checkout raw reproduction requires extracting the raw archive into the repository root.",
                "Fresh-clone reproduction commands do not perform a new board run.",
                "The package does not add real-malware validation.",
                "Claims that require artifact-backed external-intake acceptance are not inferred from readiness summaries.",
            ],
        }
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] artifact package good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["raw_board_artifacts_copied"] = True
        errors = check_summary(summary, root)
        if not errors:
            print("[FAIL] artifact package bad fixture passed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 artifact package checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the current Genesys2/CVA6 lightweight artifact package manifest.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing artifact package manifest: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] artifact package checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] artifact package manifest is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] artifact package manifest accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
