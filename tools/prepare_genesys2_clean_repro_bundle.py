from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from experiment_common import (
    repo_path,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "clean_repro_bundle_manifest.json"
DEFAULT_RAW_ARCHIVE = Path("build/ndss_artifacts/rv-maltrace-genesys2-cva6-current-raw-artifacts.zip")
SCHEMA = "rvmt.genesys2.clean_repro_bundle.v1"

BITSTREAM_REPRO_FILES = [
    "build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ariane_xilinx.bit",
    "build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ariane_xilinx.mcs",
    "build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ariane_xilinx.dcp",
    "build/vivado/genesys2-cv64a6_imafdc_sv39/reports/ariane.timing.rpt",
    "build/vivado/genesys2-cv64a6_imafdc_sv39/reports/ariane.utilization.rpt",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.bit",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.ltx",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx_routed.dcp",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx_timing_summary_routed.rpt",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports/ariane.utilization.rpt",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx_route_status.rpt",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.mcs",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/rvmt_trace_marker_build_manifest.json",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/xlnx_ila.xci",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx_routed.dcp",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/reports/ariane.timing.rpt",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/reports/ariane.utilization.rpt",
    "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx_route_status.rpt",
]

CVA6_REPRO_SOURCE_FILES = [
    "rtl/cva6/core/cva6_rvfi.sv",
    "rtl/cva6/corev_apu/fpga/src/ariane_xilinx.sv",
    "rtl/cva6/corev_apu/fpga/src/bootrom/bootrom_64.sv",
    "rtl/cva6/corev_apu/fpga/src/bootrom/src/main.c",
    "rtl/cva6/corev_apu/fpga/src/bootrom/cv64a6.dts.in",
    "rtl/cva6/corev_apu/fpga/src/bootrom/README.md",
    "rtl/cva6/corev_apu/fpga/xilinx/xlnx_ila/tcl/run.tcl",
    "rtl/cva6/corev_apu/bootrom/ariane.dts",
    "rtl/cva6/corev_apu/openpiton/bootrom/linux/ariane.dts",
    "rtl/cva6/verif/tb/core/bootrom/cva6.dts",
    "rtl/cva6/tutorials/fpga.md",
    "rtl/cva6/RESOURCES.md",
]

LINUX_REPRO_FILES = [
    "build/linux/genesys2-cva6/buildroot_defconfig.generated",
    "build/linux/genesys2-cva6/cv64a6.generated.dts",
    "build/linux/genesys2-cva6/sdcard_image_manifest.json",
    "build/linux/genesys2-cva6/sdcard.img",
    "build/linux/genesys2-cva6/images/fw_payload.bin",
    "build/linux/genesys2-cva6/images/fw_payload.elf",
    "build/linux/genesys2-cva6/images/rootfs.ext2",
    "build/linux/genesys2-cva6/images/rootfs.cpio",
]

EXCLUDED_EXPORT_DIRS = {
    ".git",
    ".uv-repro-cache",
    ".uv-repro-env",
    ".venv",
    "__pycache__",
}
REFERENCED_ARTIFACT_PREFIXES = ("build/", "results/")
SKIP_REFERENCED_PREFIXES = (
    "build/clean_repro",
    "build/clean_repro/",
    "build/ndss_artifacts",
    "build/ndss_artifacts/",
    # Docker Buildroot/OpenSBI/Linux outputs are reproducible build products,
    # not raw board evidence. Their manifests stay in the canonical evidence
    # root, but raw/clean bundles must not recursively copy the Buildroot tree.
    "build/linux/genesys2-cva6",
    "build/linux/genesys2-cva6/",
)
SKIP_REFERENCED_MANIFEST_NAMES = {
    # These manifests are inventories of copied/exported artifacts, not source
    # evidence manifests. Scanning them makes old release contents sticky across
    # regenerations and can reintroduce stale dated board roots.
    "clean_repro_bundle_manifest.json",
    "raw_artifact_release_manifest.json",
}
WILDCARD_CHARS = "*?["


def repo_rel(path: Path, root: Path = ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def run_text(command: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=root,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def git_files(root: Path) -> list[str]:
    if not (root / ".git").exists():
        return []
    result = run_text(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], root)
    if result.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {result.stderr.strip()}")
    return sorted(path for path in result.stdout.split("\0") if path)


def git_status_short(root: Path) -> str:
    if not (root / ".git").exists():
        return "NO_GIT_METADATA"
    result = run_text(["git", "status", "--short"], root)
    return result.stdout if result.returncode == 0 else f"git status failed: {result.stderr.strip()}"


def copy_file(root: Path, export_root: Path, rel: str, role: str) -> dict[str, Any]:
    source = repo_path(root, rel)
    row: dict[str, Any] = {
        "rel": rel,
        "role": role,
        "source_exists": source.exists(),
        "copied": False,
    }
    if not source.exists():
        return row
    if not source.is_file():
        row["skipped_reason"] = "not_a_regular_file"
        return row
    destination = export_root / rel
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    row.update(
        {
            "copied": True,
            "size_bytes": source.stat().st_size,
            "sha256": sha256_file(source),
        }
    )
    return row


def copy_selected_files(root: Path, export_root: Path, files: list[str], role: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rel in files:
        normalized = rel.replace("\\", "/")
        if normalized in seen:
            continue
        seen.add(normalized)
        rows.append(copy_file(root, export_root, normalized, role))
    return rows


def path_like_artifact(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.replace("\\", "/").strip().strip("`'\".,)")
    if (
        not normalized
        or normalized.startswith(("http://", "https://", "uv run ", "python ", "vivado ", "<"))
        or any(ch in normalized for ch in WILDCARD_CHARS)
        or any(normalized.startswith(prefix) for prefix in SKIP_REFERENCED_PREFIXES)
        or not normalized.startswith(REFERENCED_ARTIFACT_PREFIXES)
    ):
        return None
    return normalized


def walk_json_artifact_values(value: Any) -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for nested in value.values():
            paths.extend(walk_json_artifact_values(nested))
    elif isinstance(value, list):
        for nested in value:
            paths.extend(walk_json_artifact_values(nested))
    else:
        normalized = path_like_artifact(value)
        if normalized is not None:
            paths.append(normalized)
    return paths


def collect_manifest_referenced_artifacts(root: Path, current_root: Path) -> list[str]:
    base = root / current_root
    files: set[str] = set()
    if not base.is_dir():
        return []
    for manifest in sorted(base.rglob("*.json")):
        if manifest.name in SKIP_REFERENCED_MANIFEST_NAMES:
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except Exception:
            continue
        for rel in walk_json_artifact_values(data):
            full = root / rel
            if full.is_file():
                files.add(rel)
            elif full.is_dir():
                for child in full.rglob("*"):
                    if child.is_file():
                        files.add(repo_rel(child, root))
    return sorted(files)


def safe_zip_member(name: str) -> bool:
    path = Path(name)
    return not path.is_absolute() and ".." not in path.parts and bool(name.strip())


def extract_raw_archive(archive: Path, export_root: Path) -> dict[str, Any]:
    if not archive.is_file():
        return {"archive_exists": False, "extracted": False, "file_count": 0, "total_bytes": 0}
    file_count = 0
    total_bytes = 0
    with zipfile.ZipFile(archive, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if not safe_zip_member(info.filename):
                raise RuntimeError(f"unsafe zip member: {info.filename}")
            target = export_root / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as source, target.open("wb") as destination:
                shutil.copyfileobj(source, destination)
            file_count += 1
            total_bytes += info.file_size
    return {
        "archive_exists": True,
        "extracted": True,
        "file_count": file_count,
        "total_bytes": total_bytes,
    }


def iter_export_files(export_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in export_root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(export_root).parts
        if any(part in EXCLUDED_EXPORT_DIRS for part in rel_parts):
            continue
        files.append(path)
    return sorted(files)


def run_repro_command(export_root: Path, mode: str) -> dict[str, Any]:
    command = ["uv", "run", "rvmt", f"repro:{mode}"]
    log = export_root / "build/clean_repro_logs" / f"repro_{mode}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["UV_PROJECT_ENVIRONMENT"] = str(export_root / ".uv-repro-env")
    env["UV_CACHE_DIR"] = str(export_root / ".uv-repro-cache")
    started = dt.datetime.now(dt.UTC)
    completed = subprocess.run(
        command,
        cwd=export_root,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    ended = dt.datetime.now(dt.UTC)
    log.write_text(completed.stdout, encoding="utf-8", newline="\n")
    return {
        "command": " ".join(command),
        "mode": mode,
        "exit_code": completed.returncode,
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "started_utc": started.isoformat(),
        "ended_utc": ended.isoformat(),
        "duration_seconds": round((ended - started).total_seconds(), 3),
        "log": repo_rel(log, export_root),
    }


def command_modes(mode: str) -> list[str]:
    if mode == "both":
        return ["quick", "local"]
    return [mode]


def default_export_root(root: Path) -> Path:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
    return root / "build/clean_repro" / f"genesys2-cva6-current-{stamp}"


def prepare_bundle(
    root: Path,
    export_root: Path,
    raw_archive: Path,
    *,
    mode: str,
    run_commands: bool,
) -> dict[str, Any]:
    if export_root.exists() and any(export_root.iterdir()):
        raise RuntimeError(f"export root already exists and is not empty: {export_root}")
    export_root.mkdir(parents=True, exist_ok=True)

    git_file_rows = copy_selected_files(root, export_root, git_files(root), "git_tracked_or_untracked_publishable")
    raw_archive_rel = repo_rel(raw_archive, root)
    raw_archive_rows = copy_selected_files(root, export_root, [raw_archive_rel], "local_raw_archive_release_candidate")
    raw_extract = extract_raw_archive(raw_archive, export_root)
    referenced_rows = copy_selected_files(
        root,
        export_root,
        collect_manifest_referenced_artifacts(root, DEFAULT_CURRENT_ROOT),
        "manifest_referenced_local_artifact",
    )
    bitstream_rows = copy_selected_files(root, export_root, BITSTREAM_REPRO_FILES, "local_bitstream_checker_artifact")
    cva6_rows = copy_selected_files(root, export_root, CVA6_REPRO_SOURCE_FILES, "submodule_source_hash_input")
    linux_rows = copy_selected_files(root, export_root, LINUX_REPRO_FILES, "local_linux_image_artifact")

    commands = [run_repro_command(export_root, item) for item in command_modes(mode)] if run_commands else []
    all_copied_rows = [*git_file_rows, *raw_archive_rows, *referenced_rows, *bitstream_rows, *cva6_rows, *linux_rows]
    copied_count = sum(1 for row in all_copied_rows if row.get("copied") is True)
    missing_required = [
        str(row["rel"])
        for row in [*raw_archive_rows, *bitstream_rows, *cva6_rows, *linux_rows]
        if row.get("copied") is not True
    ]
    command_failures = [row for row in commands if row.get("exit_code") != 0]
    export_files = iter_export_files(export_root)
    status = "PASS_LOCAL_EXPORT_REPRODUCED"
    if missing_required:
        status = "BLOCKED_LOCAL_ARTIFACTS_MISSING"
    if run_commands and command_failures:
        status = "FAIL_LOCAL_EXPORT_REPRODUCTION"
    if not run_commands:
        status = "BLOCKED_LOCAL_REPRO_NOT_RUN"

    return {
        "schema": SCHEMA,
        "status": status,
        "canonical_evaluation_root": DEFAULT_CURRENT_ROOT.as_posix(),
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "source_worktree": {
            "git_status_short": git_status_short(root),
            "uncommitted_or_untracked_changes_included": bool(git_status_short(root).strip()),
        },
        "export": {
            "local_root": repo_rel(export_root, root),
            "file_count_excluding_uv_env": len(export_files),
            "total_bytes_excluding_uv_env": sum(path.stat().st_size for path in export_files),
            "copied_source_file_count": copied_count,
            "git_publishable_file_count": sum(1 for row in git_file_rows if row.get("copied") is True),
            "raw_archive_extracted_file_count": raw_extract.get("file_count", 0),
            "manifest_referenced_artifact_file_count": sum(1 for row in referenced_rows if row.get("copied") is True),
            "bitstream_artifact_file_count": sum(1 for row in bitstream_rows if row.get("copied") is True),
            "cva6_submodule_source_file_count": sum(1 for row in cva6_rows if row.get("copied") is True),
            "linux_repro_artifact_file_count": sum(1 for row in linux_rows if row.get("copied") is True),
        },
        "raw_archive": {
            "local_archive": raw_archive_rel,
            "copied_into_export": any(row.get("copied") is True for row in raw_archive_rows),
            "sha256": sha256_file(raw_archive) if raw_archive.is_file() else None,
            "size_bytes": raw_archive.stat().st_size if raw_archive.is_file() else None,
            "extraction": raw_extract,
        },
        "required_local_artifacts": {
            "missing": missing_required,
            "bitstream_files": BITSTREAM_REPRO_FILES,
            "cva6_source_files": CVA6_REPRO_SOURCE_FILES,
            "linux_repro_files": LINUX_REPRO_FILES,
        },
        "commands": commands,
        "claim_boundary": {
            "local_export_reproduced": status == "PASS_LOCAL_EXPORT_REPRODUCED",
            "true_git_fresh_clone_claimed": False,
            "external_release_asset_published": False,
            "uncommitted_worktree_snapshot_included": True,
            "requires_commit_tag_for_true_fresh_clone": True,
            "board_or_vivado_rerun_performed": False,
            "real_malware_validation_claimed": False,
        },
        "non_claims": [
            "This is a local clean-export reproduction of the current uncommitted worktree, not a committed/tagged Git fresh clone.",
            "The raw artifact ZIP is copied and extracted locally; it is still not an external immutable release asset.",
            "No Vivado, Genesys2/JTAG/UART, LaTeX, or real-malware experiment was run by this tool.",
        ],
        "validation_commands": [
            "uv run rvmt repro:clean-export",
            "uv run python tools/check_genesys2_clean_repro_bundle.py --root .",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        archive = root / DEFAULT_RAW_ARCHIVE
        archive.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("results/board/fixture/raw.log", "fixture\n")
        export = root / "export"
        for rel in [*BITSTREAM_REPRO_FILES, *CVA6_REPRO_SOURCE_FILES, *LINUX_REPRO_FILES, "pyproject.toml"]:
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{rel}\n", encoding="utf-8")
        stale = root / "results/board/stale/raw.log"
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text("stale\n", encoding="utf-8")
        release_manifest = root / DEFAULT_CURRENT_ROOT / "raw_artifact_release_manifest.json"
        release_manifest.parent.mkdir(parents=True, exist_ok=True)
        write_json(
            release_manifest,
            {
                "schema": "rvmt.genesys2.raw_artifact_release.v1",
                "files": [{"path": repo_rel(stale, root), "sha256": sha256_file(stale)}],
            },
        )
        manifest = prepare_bundle(root, export, archive, mode="quick", run_commands=False)
        if manifest["raw_archive"]["extraction"]["file_count"] != 1:
            print("[FAIL] clean repro self-test did not extract raw archive", file=sys.stderr)
            return 1
        if manifest["export"]["bitstream_artifact_file_count"] != len(BITSTREAM_REPRO_FILES):
            print("[FAIL] clean repro self-test did not copy bitstream fixtures", file=sys.stderr)
            return 1
        if manifest["export"]["linux_repro_artifact_file_count"] != len(LINUX_REPRO_FILES):
            print("[FAIL] clean repro self-test did not copy Linux reproduction fixtures", file=sys.stderr)
            return 1
        if not (export / "results/board/fixture/raw.log").is_file():
            print("[FAIL] clean repro self-test missing extracted raw file", file=sys.stderr)
            return 1
        if (export / "results/board/stale/raw.log").exists():
            print("[FAIL] clean repro self-test copied stale release-manifest inventory", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 clean-export reproduction preparer self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare and run a local clean-export Genesys2/CVA6 reproduction bundle.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--export-root", type=Path, help="Exact export directory. Defaults to build/clean_repro/<timestamp>.")
    parser.add_argument("--raw-archive", type=Path, default=DEFAULT_RAW_ARCHIVE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--mode", choices=("quick", "local", "both"), default="both")
    parser.add_argument("--no-run", action="store_true", help="Prepare the export and manifest without running rvmt reproduction commands.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    export_root = args.export_root if args.export_root is not None else default_export_root(root)
    if not export_root.is_absolute():
        export_root = root / export_root
    raw_archive = repo_path(root, args.raw_archive)
    out = repo_path(root, args.out)
    try:
        manifest = prepare_bundle(root, export_root.resolve(), raw_archive.resolve(), mode=args.mode, run_commands=not args.no_run)
        write_json(out, manifest)
    except Exception as exc:
        print(f"prepare_genesys2_clean_repro_bundle: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{manifest['status']}] wrote clean-export reproduction manifest to {out}")
    print(f"[INFO] export root: {manifest['export']['local_root']}")
    return 0 if manifest["status"] == "PASS_LOCAL_EXPORT_REPRODUCED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
