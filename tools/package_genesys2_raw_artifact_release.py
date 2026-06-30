from __future__ import annotations

import argparse
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    repo_path,
    sha256_file,
    write_json,
)

from prepare_genesys2_clean_repro_bundle import BITSTREAM_REPRO_FILES, collect_manifest_referenced_artifacts


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_REPRO_MANIFEST = DEFAULT_CURRENT_ROOT / "reproducibility_manifest.json"
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "raw_artifact_release_manifest.json"
DEFAULT_ARCHIVE = Path("build/ndss_artifacts/rv-maltrace-genesys2-cva6-current-raw-artifacts.zip")
SCHEMA = "rvmt.genesys2.raw_artifact_release.v1"
SKIP_ARCHIVE_PREFIXES = (
    "build/clean_repro/",
    "build/ndss_artifacts/",
    DEFAULT_CURRENT_ROOT.as_posix() + "/",
)


def repo_rel(path: Path, root: Path = ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def iter_root_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())


def collect_rows(root: Path, repro: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root_rows: list[dict[str, Any]] = []
    file_rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in as_list(repro.get("raw_artifact_roots")):
        if not isinstance(raw, dict):
            continue
        root_id = str(raw.get("id") or "")
        path_value = raw.get("path")
        if not root_id or not isinstance(path_value, str) or not path_value:
            root_rows.append({"id": root_id or "UNKNOWN", "path": path_value, "exists": False, "file_count": 0, "total_bytes": 0})
            continue
        raw_root = repo_path(root, path_value)
        files = iter_root_files(raw_root) if raw_root.is_dir() else []
        root_rows.append(
            {
                "id": root_id,
                "path": repo_rel(raw_root, root),
                "exists": raw_root.is_dir(),
                "file_count": len(files),
                "total_bytes": sum(path.stat().st_size for path in files),
                "source_file_counts": raw.get("file_counts"),
            }
        )
        for file_path in files:
            rel = repo_rel(file_path, root)
            if rel in seen:
                continue
            seen.add(rel)
            file_rows.append(
                {
                    "path": rel,
                    "root_id": root_id,
                    "size_bytes": file_path.stat().st_size,
                    "sha256": sha256_file(file_path),
                }
            )
    return root_rows, sorted(file_rows, key=lambda row: str(row["path"]))


def collect_additional_release_files(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sets: list[dict[str, Any]] = []
    file_rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_set(set_id: str, role: str, paths: list[str]) -> None:
        copied = 0
        total_bytes = 0
        for rel in sorted(set(path.replace("\\", "/") for path in paths)):
            if not rel or rel in seen or rel.startswith(SKIP_ARCHIVE_PREFIXES):
                continue
            path = root / rel
            if not path.is_file():
                continue
            seen.add(rel)
            copied += 1
            total_bytes += path.stat().st_size
            file_rows.append(
                {
                    "path": rel,
                    "root_id": set_id,
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
        sets.append(
            {
                "id": set_id,
                "role": role,
                "file_count": copied,
                "total_bytes": total_bytes,
            }
        )

    bootrom_dir = root / "build/bootrom/genesys2-cva6"
    add_set(
        "bootrom_counter_delegation_artifacts",
        "bootrom ELF/bin/img/disassembly artifacts proving the firmware counter-delegation attempt used by the current cycle-source preflight gate",
        [repo_rel(path, root) for path in iter_root_files(bootrom_dir)] if bootrom_dir.is_dir() else [],
    )
    add_set(
        "current_manifest_referenced_artifacts",
        "ignored local artifacts outside the canonical current evidence root that are referenced by current manifests and required by recursive path/hash checks",
        collect_manifest_referenced_artifacts(root, DEFAULT_CURRENT_ROOT),
    )
    add_set(
        "local_bitstream_inventory_artifacts",
        "host Vivado bitstream, LTX, DCP, timing, route, and utilization artifacts required by repro:local",
        BITSTREAM_REPRO_FILES,
    )
    return sets, sorted(file_rows, key=lambda row: str(row["path"]))


def write_archive(root: Path, archive_path: Path, file_rows: list[dict[str, Any]]) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for row in file_rows:
            rel = str(row["path"])
            archive.write(root / rel, arcname=rel)


def package_release(root: Path, repro_manifest: Path, archive_path: Path, *, write_zip: bool) -> dict[str, Any]:
    repro = load_json(repro_manifest)
    root_rows, file_rows = collect_rows(root, repro)
    artifact_sets, additional_file_rows = collect_additional_release_files(root)
    seen = {str(row["path"]) for row in file_rows}
    for row in additional_file_rows:
        if str(row["path"]) in seen:
            continue
        seen.add(str(row["path"]))
        file_rows.append(row)
    file_rows = sorted(file_rows, key=lambda row: str(row["path"]))
    if write_zip:
        write_archive(root, archive_path, file_rows)
    archive_exists = archive_path.is_file()
    return {
        "schema": SCHEMA,
        "status": "PASS_LOCAL_ARCHIVE_PRESENT" if archive_exists else "BLOCKED_RAW_ARCHIVE_NOT_CREATED",
        "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
        "release_kind": "local_raw_board_artifact_archive",
        "source_reproducibility_manifest": {
            "path": repo_rel(repro_manifest, root),
            "sha256": sha256_file(repro_manifest) if repro_manifest.is_file() else None,
        },
        "archive": {
            "path": repo_rel(archive_path, root),
            "exists": archive_exists,
            "sha256": sha256_file(archive_path) if archive_exists else None,
            "size_bytes": archive_path.stat().st_size if archive_exists else None,
            "format": "zip",
            "file_count": len(file_rows),
        },
        "raw_artifact_roots": root_rows,
        "included_artifact_sets": artifact_sets,
        "files": file_rows,
        "claim_boundary": {
            "raw_board_artifacts_copied_into_git": False,
            "local_archive_created": archive_exists,
            "external_release_asset_published": False,
            "archive_required_for_clean_checkout_raw_reproduction": True,
            "archive_extracts_current_ignored_artifacts": False,
            "archive_excludes_canonical_current_root": True,
            "archive_extracts_manifest_referenced_ignored_artifacts": True,
            "archive_excludes_rebuildable_linux_build_outputs": True,
            "archive_supports_local_quick_and_local_reproduction": True,
            "real_malware_payloads_included": False,
        },
        "non_claims": [
            "This local archive is a raw-artifact release candidate; it is not an external immutable release asset until published outside the working tree.",
            "The archive does not add real-malware validation and contains only current controlled Genesys2/CVA6 raw-board roots and local build artifacts referenced by current manifests.",
            "Rebuildable Docker Linux outputs under build/linux/genesys2-cva6 are excluded; regenerate them with uv run rvmt ndss:linux-rebuild-prep --execute and uv run rvmt ndss:boot-sdcard-image.",
            "The canonical current evidence root is excluded from the raw ZIP because it is supplied by the repository snapshot and must not be self-hashed inside its own release manifest.",
            "A Git-only fresh clone still needs this archive extracted into the repository root or a board rerun to reproduce raw-board and local artifact-backed evidence.",
        ],
        "validation_commands": [
            "uv run python tools/package_genesys2_raw_artifact_release.py",
            "uv run python tools/check_genesys2_raw_artifact_release.py --root .",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        raw_root = root / "results/board/run/sample/rep_01"
        raw_root.mkdir(parents=True)
        (raw_root / "bram_records.jsonl").write_text('{"evt":"MARKER"}\n', encoding="utf-8")
        (raw_root / "capture.log").write_text("capture\n", encoding="utf-8")
        (raw_root / "uart.log").write_text("uart\n", encoding="utf-8")
        current.mkdir(parents=True)
        repro = {
            "schema": "rvmt.genesys2.reproducibility_manifest.v1",
            "status": "PASS",
            "raw_artifact_roots": [
                {
                    "id": "fixture_root",
                    "path": "results/board/run",
                    "exists": True,
                    "file_counts": {"bram_records": 1, "capture_logs": 1, "uart_logs": 1},
                }
            ],
        }
        repro_path = current / "reproducibility_manifest.json"
        write_json(repro_path, repro)
        bitstream = root / BITSTREAM_REPRO_FILES[0]
        bitstream.parent.mkdir(parents=True, exist_ok=True)
        bitstream.write_text("bitstream fixture\n", encoding="utf-8")
        bootrom = root / "build/bootrom/genesys2-cva6/build_manifest.json"
        bootrom.parent.mkdir(parents=True, exist_ok=True)
        bootrom.write_text('{"schema":"fixture"}\n', encoding="utf-8")
        write_json(current / "summary.json", {"path": BITSTREAM_REPRO_FILES[0]})
        archive = root / "build/raw.zip"
        summary = package_release(root, repro_path, archive, write_zip=True)
        if summary.get("status") != "PASS_LOCAL_ARCHIVE_PRESENT":
            print("[FAIL] expected local raw archive fixture to pass", file=sys.stderr)
            return 1
        if int(summary.get("archive", {}).get("file_count") or 0) != 5:
            print("[FAIL] expected fixture archive file count 5", file=sys.stderr)
            return 1
        sets = {row.get("id"): row for row in summary.get("included_artifact_sets", []) if isinstance(row, dict)}
        if int(sets.get("current_manifest_referenced_artifacts", {}).get("file_count") or 0) < 1:
            print("[FAIL] expected fixture manifest-referenced artifact set to include at least one file", file=sys.stderr)
            return 1
        if not any(
            row.get("path") == BITSTREAM_REPRO_FILES[0]
            and row.get("root_id") == "current_manifest_referenced_artifacts"
            for row in summary.get("files", [])
            if isinstance(row, dict)
        ):
            print("[FAIL] expected fixture bitstream to be included through manifest-referenced artifact set", file=sys.stderr)
            return 1
    print("[PASS] raw artifact release packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package active Genesys2/CVA6 raw artifact roots into a local release archive.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--repro-manifest", type=Path, default=DEFAULT_REPRO_MANIFEST)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--no-archive", action="store_true", help="Only write the manifest; do not create or update the archive.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    repro = args.repro_manifest if args.repro_manifest.is_absolute() else root / args.repro_manifest
    archive = args.archive if args.archive.is_absolute() else root / args.archive
    out = args.out if args.out.is_absolute() else root / args.out
    try:
        summary = package_release(root, repro, archive, write_zip=not args.no_archive)
        write_json(out, summary)
    except Exception as exc:
        print(f"package_genesys2_raw_artifact_release: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote raw artifact release manifest to {out}")
    if summary["status"] != "PASS_LOCAL_ARCHIVE_PRESENT":
        return 1
    print(f"[PASS] local archive: {summary['archive']['path']} sha256={summary['archive']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
