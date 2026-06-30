from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    repo_rel_from,
    sha256_file,
    write_json,
)

from genesys2_artifact_package_spec import CORE_REPRODUCTION_FILES as CORE_FILES


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_REPRO_MANIFEST = DEFAULT_CURRENT_ROOT / "reproducibility_manifest.json"
DEFAULT_RAW_RELEASE_MANIFEST = DEFAULT_CURRENT_ROOT / "raw_artifact_release_manifest.json"
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "artifact_package_manifest.json"



repo_rel = repo_rel_from(ROOT)


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
        ["git", "check-ignore", "-v", "--", path_value],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if ignored.returncode == 0:
        pattern_field = ignored.stdout.split("\t", 1)[0].rsplit(":", 1)[-1]
        return pattern_field.startswith("!")
    if ignored.returncode == 1:
        return True
    return None


def unique_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        result.append(path)
    return result


def file_row(path_value: str, role: str) -> dict[str, Any]:
    path = ROOT / path_value
    return {
        "path": path_value,
        "role": role,
        "exists": path.is_file(),
        "sha256": sha256_file(path) if path.is_file() else None,
        "size_bytes": path.stat().st_size if path.is_file() else None,
        "git_publishable": git_publishable(ROOT, path_value),
    }


def rows_from_repro(repro: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in repro.get("summary_artifacts", []):
        if isinstance(row, dict) and isinstance(row.get("path"), str):
            rows.append(file_row(row["path"], "summary_artifact"))
    for row in repro.get("report_rows", []):
        if isinstance(row, dict) and isinstance(row.get("report"), str):
            rows.append(file_row(row["report"], "paper_facing_report"))
    return rows


def package_manifest(current_root: Path, repro_path: Path) -> dict[str, Any]:
    repro = load_json(ROOT / repro_path)
    raw_release_path = ROOT / DEFAULT_RAW_RELEASE_MANIFEST
    raw_release = load_json(raw_release_path) if raw_release_path.is_file() else {}
    included_paths = unique_paths(
        [
            *CORE_FILES,
            repo_rel(ROOT / repro_path),
            repo_rel(raw_release_path),
            *[
                str(row.get("path"))
                for row in repro.get("summary_artifacts", [])
                if isinstance(row, dict) and isinstance(row.get("path"), str)
            ],
            *[
                str(row.get("report"))
                for row in repro.get("report_rows", [])
                if isinstance(row, dict) and isinstance(row.get("report"), str)
            ],
        ]
    )
    included = [file_row(path, "core_reproduction_file") for path in CORE_FILES]
    included.append(file_row(repo_rel(raw_release_path), "raw_artifact_release_manifest"))
    included.extend(row for row in rows_from_repro(repro) if row["path"] not in CORE_FILES)
    existing_paths = {row["path"] for row in included}
    for path in included_paths:
        if path not in existing_paths:
            included.append(file_row(path, "referenced_file"))
    raw_roots: list[dict[str, Any]] = []
    for row in repro.get("raw_artifact_roots", []):
        if not isinstance(row, dict):
            continue
        raw_roots.append(
            {
                "id": row.get("id"),
                "path": row.get("path"),
                "exists": row.get("exists"),
                "file_counts": row.get("file_counts"),
                "release_policy": "referenced-by-manifest; raw board artifacts are not copied into this lightweight package",
            }
        )
    status = "PASS"
    if repro.get("status") != "PASS":
        status = "FAIL"
    if any(row.get("exists") is not True for row in included):
        status = "FAIL"
    if raw_release.get("status") != "PASS_LOCAL_ARCHIVE_PRESENT":
        status = "FAIL"
    if not raw_roots or any(row.get("exists") is not True for row in raw_roots):
        status = "FAIL"
    raw_release_boundary = raw_release.get("claim_boundary") if isinstance(raw_release.get("claim_boundary"), dict) else {}
    raw_release_archive = raw_release.get("archive") if isinstance(raw_release.get("archive"), dict) else {}
    repro_boundary = repro.get("claim_boundary") if isinstance(repro.get("claim_boundary"), dict) else {}
    return {
        "schema": "rvmt.genesys2.artifact_package.v1",
        "status": status,
        "package_kind": "lightweight-current-evidence-manifest",
        "canonical_evaluation_root": repo_rel(ROOT / current_root),
        "generated_from": repo_rel(ROOT / repro_path),
        "fresh_clone_reproduction": {
            "script": "tools/reproduce_genesys2_current.py",
            "quick_command": "uv run python tools/reproduce_genesys2_current.py --quick",
            "local_command": "uv run python tools/reproduce_genesys2_current.py --local",
            "full_command": "uv run python tools/reproduce_genesys2_current.py --full",
            "dry_run_command": "uv run python tools/reproduce_genesys2_current.py --full --dry-run",
            "raw_archive_check_command": "uv run python tools/check_genesys2_raw_artifact_release.py --root .",
            "raw_archive_extract_command": "Expand-Archive build/ndss_artifacts/rv-maltrace-genesys2-cva6-current-raw-artifacts.zip -DestinationPath . -Force",
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
            "manifest": repo_rel(raw_release_path),
            "manifest_exists": raw_release_path.is_file(),
            "manifest_sha256": sha256_file(raw_release_path) if raw_release_path.is_file() else None,
            "status": raw_release.get("status"),
            "archive_path": raw_release_archive.get("path"),
            "archive_sha256": raw_release_archive.get("sha256"),
            "archive_size_bytes": raw_release_archive.get("size_bytes"),
            "archive_file_count": raw_release_archive.get("file_count"),
            "external_release_asset_published": raw_release_boundary.get("external_release_asset_published"),
        },
        "included_files": included,
        "referenced_raw_artifact_roots": raw_roots,
        "validation_commands": [
            "uv run python tools/package_genesys2_artifact_package.py",
            "uv run python tools/check_genesys2_artifact_package.py --root .",
            "uv run python tools/package_genesys2_raw_artifact_release.py",
            "uv run python tools/check_genesys2_raw_artifact_release.py --root .",
            "uv run rvmt repro:clean-export",
            "uv run python tools/check_genesys2_clean_repro_bundle.py --root .",
            "uv run python tools/reproduce_genesys2_current.py --quick",
            "uv run python tools/reproduce_genesys2_current.py --local",
            "uv run python tools/reproduce_genesys2_current.py --full --dry-run",
            "uv run rvmt repro:local --dry-run",
        ],
        "claim_boundary": {
            "fresh_clone_reproduction_script_available": True,
            "lightweight_manifest_package": True,
            "raw_board_artifacts_copied": False,
            "local_raw_artifact_archive_created": raw_release.get("status") == "PASS_LOCAL_ARCHIVE_PRESENT",
            "external_raw_release_asset_published": False,
            "raw_archive_required_for_clean_checkout_raw_reproduction": True,
            "raw_archive_extraction_required_for_clean_checkout_raw_reproduction": True,
            "requires_board_rerun_for_reproduction_checks": False,
            "real_malware_validation_claimed": False,
            "production_streaming_dma_throughput_claimed": False,
            "hardware_full_pointer_strings_claimed": repro_boundary.get("hardware_full_pointer_strings_claimed") is True,
            "board_native_source_line_attribution_claimed": False,
            "genesys2_board_benign_control_claimed": False,
            "external_full_hardware_pointer_strings_summary_accepted": repro_boundary.get("external_full_hardware_pointer_strings_summary_accepted") is True,
            "external_board_native_source_line_summary_accepted": repro_boundary.get("external_board_native_source_line_summary_accepted") is True,
            "external_genesys2_board_benign_control_summary_accepted": repro_boundary.get("external_genesys2_board_benign_control_summary_accepted") is True,
        },
        "non_claims": [
            "This is a lightweight manifest package for the controlled Genesys2/CVA6 evidence chain; it does not copy large raw board artifacts.",
            "The local raw artifact archive is a release candidate and is not an external immutable release asset until published outside the working tree.",
            "Clean-checkout raw reproduction requires extracting the raw archive into the repository root before running quick/local checkers.",
            "Fresh-clone reproduction commands re-run repository checkers over checked-in manifests and referenced artifact paths; they do not perform a new board run.",
            "The package does not add real-malware validation or production streaming/DMA throughput evidence.",
            "Full hardware pointer-string, board-native DWARF source-line, and Genesys2 board benign-control claims are included only when the reproducibility manifest records artifact-backed external-intake acceptance.",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        for path in CORE_FILES:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fixture\n", encoding="utf-8")
        write_json(
            root / DEFAULT_RAW_RELEASE_MANIFEST,
            {
                "schema": "rvmt.genesys2.raw_artifact_release.v1",
                "status": "PASS_LOCAL_ARCHIVE_PRESENT",
                "archive": {
                    "path": "build/ndss_artifacts/raw.zip",
                    "sha256": "0" * 64,
                    "size_bytes": 1,
                    "file_count": 1,
                },
                "claim_boundary": {
                    "external_release_asset_published": False,
                    "archive_required_for_clean_checkout_raw_reproduction": True,
                },
            },
        )
        report = root / "docs/07-evaluation-evidence/reports/ccfa_readiness_matrix.md"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("fixture\n", encoding="utf-8")
        summary = current / "summary.json"
        write_json(summary, {"schema": "fixture", "status": "PASS"})
        raw = root / "raw"
        raw.mkdir()
        repro = {
            "schema": "rvmt.genesys2.reproducibility_manifest.v1",
            "status": "PASS",
            "summary_artifacts": [{"id": "summary", "path": summary.relative_to(root).as_posix()}],
            "report_rows": [{"id": "report", "report": report.relative_to(root).as_posix()}],
            "raw_artifact_roots": [{"id": "raw", "path": "raw", "exists": True, "file_counts": {"logs": 1}}],
        }
        write_json(current / "reproducibility_manifest.json", repro)
        old_root = globals()["ROOT"]
        try:
            globals()["ROOT"] = root
            manifest = package_manifest(DEFAULT_CURRENT_ROOT, DEFAULT_REPRO_MANIFEST)
        finally:
            globals()["ROOT"] = old_root
    if manifest.get("status") != "PASS":
        print("[FAIL] expected artifact package fixture to pass", file=sys.stderr)
        return 1
    if manifest.get("claim_boundary", {}).get("raw_board_artifacts_copied") is not False:
        print("[FAIL] artifact package must not copy raw board artifacts", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 artifact package packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package the current Genesys2/CVA6 lightweight artifact manifest.")
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--reproducibility-manifest", type=Path, default=DEFAULT_REPRO_MANIFEST)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        manifest = package_manifest(args.current_root, args.reproducibility_manifest)
        write_json(args.out, manifest)
    except Exception as exc:
        print(f"package_genesys2_artifact_package: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{manifest['status']}] wrote Genesys2 artifact package manifest to {args.out}")
    return 0 if manifest["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
