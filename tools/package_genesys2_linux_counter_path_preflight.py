from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    repo_path,
    repo_rel,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "linux_counter_path_preflight.json"
SCHEMA = "rvmt.genesys2.linux_counter_path_preflight.v1"

REQUIRED_KERNEL_SYMBOLS = {
    "CONFIG_PERF_EVENTS": "y",
    "CONFIG_IKCONFIG": "y",
    "CONFIG_IKCONFIG_PROC": "y",
}
PMU_SYMBOL_OPTIONS = (
    "CONFIG_RISCV_PMU",
    "CONFIG_RISCV_PMU_SBI",
    "CONFIG_HW_PERF_EVENTS",
)

ANCHORS: list[dict[str, Any]] = [
    {
        "id": "genesys2_cva6_linux_build_entrypoint",
        "required": True,
        "role": "repo-owned command or Docker entrypoint for rebuilding the Genesys2/CVA6 SD-card Linux payload",
        "mode": "build_entrypoint",
        "candidates": [
            "tools/prepare_genesys2_cva6_linux_rebuild.py",
            "tools/build_genesys2_cva6_linux_image.py",
            "docker/genesys2-cva6-linux/Dockerfile",
            "docker/genesys2-cva6-linux/build.sh",
            "board/genesys2-cva6/linux/build.sh",
            "board/genesys2_cva6/linux/build.sh",
        ],
    },
    {
        "id": "buildroot_source_or_defconfig",
        "required": True,
        "role": "Buildroot source, external tree, or board defconfig for the live Genesys2/CVA6 image",
        "mode": "buildroot_defconfig",
        "candidates": [
            "buildroot",
            "vendor/buildroot",
            "external/buildroot",
            "board/genesys2-cva6/linux/buildroot_defconfig",
            "board/genesys2_cva6/linux/buildroot_defconfig",
            "configs/genesys2_cva6_buildroot_defconfig",
        ],
    },
    {
        "id": "linux_kernel_counter_config",
        "required": True,
        "role": "Linux kernel config proving perf, PMU, and readable-config support for the board image",
        "mode": "kernel_config",
        "candidates": [
            "board/genesys2-cva6/linux/linux.config",
            "board/genesys2_cva6/linux/linux.config",
            "configs/genesys2_cva6_linux.config",
            "build/linux/genesys2-cva6/.config",
            "results/evaluation/genesys2-cva6/current/live_kernel_config.txt",
        ],
    },
    {
        "id": "opensbi_source_or_manifest",
        "required": True,
        "role": "OpenSBI source/build manifest for the firmware layer that owns counter delegation and SBI PMU exposure",
        "mode": "opensbi_manifest",
        "candidates": [
            "opensbi",
            "vendor/opensbi",
            "external/opensbi",
            "board/genesys2-cva6/linux/opensbi_manifest.json",
            "board/genesys2_cva6/linux/opensbi_manifest.json",
            "build/opensbi/genesys2-cva6/build_manifest.json",
        ],
    },
    {
        "id": "sd_card_image_manifest",
        "required": True,
        "role": "manifest for the exact SD-card payload booted by the board, including kernel/rootfs/DTB/OpenSBI hashes",
        "mode": "path",
        "candidates": [
            "results/evaluation/genesys2-cva6/current/sdcard_image_manifest.json",
            "board/genesys2-cva6/linux/sdcard_manifest.json",
            "board/genesys2_cva6/linux/sdcard_manifest.json",
            "build/board/genesys2-cva6/linux/sdcard_manifest.json",
            "build/linux/genesys2-cva6/sdcard_image_manifest.json",
            "results/evaluation/genesys2-cva6/current/sdcard_linux_manifest.json",
        ],
    },
    {
        "id": "device_tree_pmu_node_source",
        "required": True,
        "role": "device-tree source or exported DTB evidence with a PMU/perf node usable by Linux",
        "mode": "dtb_pmu",
        "candidates": [
            "board/genesys2-cva6/linux/genesys2-cva6.dts",
            "board/genesys2_cva6/linux/genesys2-cva6.dts",
            "rtl/cva6/corev_apu/fpga/src/bootrom/cv64a6.dts.in",
            "rtl/cva6/corev_apu/bootrom/ariane.dts",
            "rtl/cva6/corev_apu/openpiton/bootrom/linux/ariane.dts",
            "rtl/cva6/verif/tb/core/bootrom/cva6.dts",
            "build/bootrom/genesys2-cva6/cv64a6.dtb",
        ],
    },
    {
        "id": "live_kernel_config_export",
        "required": True,
        "role": "exported readable kernel config from the same live SD-card image used for board cycle probes",
        "mode": "kernel_config",
        "candidates": [
            "results/board/genesys2_trace_validation/20260623-cycle-source-diagnostics/proc_config.txt",
            "results/board/genesys2_trace_validation/20260623-cycle-source-diagnostics/kernel_config.txt",
            "results/evaluation/genesys2-cva6/current/live_kernel_config.txt",
        ],
    },
]

SUPPORTING_SUMMARIES = [
    ("bootrom_counter_delegation", "build/bootrom/genesys2-cva6/build_manifest.json", "rvmt.genesys2.bootrom_build.v1"),
    ("sdcard_linux_manifest", "results/evaluation/genesys2-cva6/current/sdcard_linux_manifest.json", "rvmt.genesys2.sdcard_linux_manifest.v1"),
    ("cycle_counter_smoke", "results/evaluation/genesys2-cva6/current/cycle_counter_smoke_summary.json", "rvmt.genesys2.cycle_counter_smoke.v1"),
    ("cycle_source_probe", "results/evaluation/genesys2-cva6/current/cycle_source_probe_summary.json", "rvmt.genesys2.cycle_source_probe.v1"),
    (
        "cycle_source_diagnostics",
        "results/evaluation/genesys2-cva6/current/cycle_source_diagnostics_summary.json",
        "rvmt.genesys2.cycle_source_diagnostics.v1",
    ),
    (
        "live_kernel_config_export",
        "results/evaluation/genesys2-cva6/current/live_kernel_config_export_summary.json",
        "rvmt.genesys2.live_kernel_config_export.v1",
    ),
    ("counter_access_matrix", "results/evaluation/genesys2-cva6/current/counter_access_matrix_summary.json", "rvmt.genesys2.counter_access_matrix.v1"),
]

DOCUMENTARY_REFERENCES = [
    "README.md",
    "docs/10-process/version_lock.md",
    "docs/07-evaluation-evidence/ndss_host_runbook.md",
    "rtl/cva6/tutorials/fpga.md",
    "rtl/cva6/RESOURCES.md",
    "rtl/cva6/corev_apu/fpga/src/bootrom/README.md",
]

REJECTED_NON_GENESYS2_PATHS = [
    (
        "artix7_litex_linux_builder",
        "docker/litex/build-artix7-linux-images.sh",
        "Artix-7 LiteX/VexRiscv image builder; not a Genesys2/CVA6 Linux source path",
    ),
    (
        "artix7_linux_user_programs",
        "board/artix7_35t/linux",
        "Artix-7 35T Linux user programs; not the Genesys2/CVA6 SD-card image source",
    ),
    (
        "vexriscv_sdcard_image",
        "vendor/litex/linux-on-litex-vexriscv/images/sdcard.img",
        "LiteX/VexRiscv prebuilt image; not acceptable for Genesys2/CVA6 cycle-source evidence",
    ),
    (
        "artix7_litex_linux_soc",
        "fpga/artix7_35t/litex/linux_nosd.py",
        "Artix-7 LiteX Linux SoC path; not a CVA6 Genesys2 SD-card rebuild path",
    ),
]


def file_or_dir_row(root: Path, path_value: str) -> dict[str, Any]:
    path = repo_path(root, path_value)
    row: dict[str, Any] = {
        "candidate": path_value,
        "exists": path.exists(),
        "kind": "missing",
    }
    if path.is_file():
        row.update(
            {
                "path": repo_rel(root, path),
                "kind": "file",
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    elif path.is_dir():
        row.update(
            {
                "path": repo_rel(root, path),
                "kind": "directory",
                "direct_file_count": sum(1 for item in path.iterdir() if item.is_file()),
                "direct_directory_count": sum(1 for item in path.iterdir() if item.is_dir()),
            }
        )
    return row


def parse_config_symbols(text: str) -> dict[str, str]:
    symbols: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        match = re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$", stripped)
        if match:
            symbols[match.group(1)] = match.group(2).strip()
            continue
        not_set = re.match(r"^#\s+(CONFIG_[A-Za-z0-9_]+)\s+is not set$", stripped)
        if not_set:
            symbols[not_set.group(1)] = "not_set"
    return symbols


def config_analysis(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    symbols = parse_config_symbols(text)
    required = {name: symbols.get(name) for name in REQUIRED_KERNEL_SYMBOLS}
    pmu_options = {name: symbols.get(name) for name in PMU_SYMBOL_OPTIONS}
    required_ok = all(symbols.get(name) == expected for name, expected in REQUIRED_KERNEL_SYMBOLS.items())
    pmu_ok = any(value in {"y", "m"} for value in pmu_options.values())
    return {
        "required_symbols": required,
        "pmu_symbol_options": pmu_options,
        "required_symbols_ok": required_ok,
        "pmu_symbol_ok": pmu_ok,
        "satisfies_counter_config": required_ok and pmu_ok,
    }


def normalized_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace").lower().replace("-", "_")


def build_entrypoint_analysis(path: Path) -> dict[str, Any]:
    text = normalized_text(path)
    required_terms = {
        "genesys2": "genesys2" in text,
        "cva6": "cva6" in text,
        "buildroot": "buildroot" in text,
        "opensbi": "opensbi" in text,
        "sdcard": "sdcard" in text or "sd_card" in text,
    }
    return {
        "required_terms": required_terms,
        "satisfies_build_entrypoint": path.is_file() and all(required_terms.values()),
    }


def buildroot_file_analysis(path: Path) -> dict[str, Any]:
    text = normalized_text(path)
    required_terms = {
        "riscv_target": "br2_riscv" in text,
        "linux_kernel": "br2_linux_kernel" in text,
        "opensbi": "br2_target_opensbi" in text or "opensbi" in text,
        "genesys2_cva6_identity": ("genesys2" in text and "cva6" in text) or "cv64a6" in text,
    }
    return {
        "kind": "defconfig_file",
        "required_terms": required_terms,
        "satisfies_buildroot_anchor": path.is_file() and all(required_terms.values()),
    }


def buildroot_dir_analysis(path: Path) -> dict[str, Any]:
    if not path.is_dir():
        return {
            "kind": "buildroot_directory",
            "contains_buildroot_tree": False,
            "matching_defconfig_count": 0,
            "satisfies_buildroot_anchor": False,
        }
    contains_buildroot_tree = (path / "Makefile").is_file() and (path / "package").is_dir() and (path / "configs").is_dir()
    matching: list[str] = []
    for candidate in list(path.glob("configs/*genesys*cva6*defconfig")) + list(path.glob("configs/*cva6*genesys*defconfig")):
        if buildroot_file_analysis(candidate).get("satisfies_buildroot_anchor") is True:
            matching.append(candidate.as_posix())
    return {
        "kind": "buildroot_directory",
        "contains_buildroot_tree": contains_buildroot_tree,
        "matching_defconfig_count": len(matching),
        "matching_defconfigs": matching[:10],
        "satisfies_buildroot_anchor": contains_buildroot_tree and bool(matching),
    }


def buildroot_analysis(path: Path) -> dict[str, Any]:
    if path.is_file():
        return buildroot_file_analysis(path)
    return buildroot_dir_analysis(path)


def opensbi_analysis(path: Path) -> dict[str, Any]:
    if path.is_dir():
        return {
            "kind": "opensbi_directory",
            "contains_opensbi_tree": (path / "lib" / "sbi").is_dir() and (path / "firmware").is_dir(),
            "satisfies_opensbi_anchor": False,
            "missing_reason": "OpenSBI source directory must be paired with a source/build manifest that records commit and artifact hashes.",
        }
    data: dict[str, Any] = {}
    if path.is_file():
        try:
            data = load_json(path)
        except Exception:
            data = {}
    schema_ok = data.get("schema") in {
        "rvmt.genesys2.opensbi_source_manifest.v1",
        "rvmt.genesys2.opensbi_build_manifest.v1",
    }
    source = data.get("source") if isinstance(data.get("source"), dict) else {}
    artifacts = data.get("artifacts") if isinstance(data.get("artifacts"), list) else []
    has_source_lock = bool(source.get("commit") or source.get("sha256") or source.get("archive_sha256"))
    has_artifact_hash = any(isinstance(row, dict) and row.get("sha256") for row in artifacts)
    return {
        "kind": "opensbi_manifest_file",
        "schema_ok": schema_ok,
        "has_source_lock": has_source_lock,
        "has_artifact_hash": has_artifact_hash,
        "satisfies_opensbi_anchor": path.is_file() and schema_ok and has_source_lock and has_artifact_hash,
    }


def dtb_pmu_analysis(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"contains_pmu_token": False, "contains_compatible_token": False, "satisfies_pmu_node": False}
    data = path.read_bytes()
    text = data.decode("utf-8", errors="ignore").lower()
    contains_pmu = "pmu" in text
    contains_compatible = "compatible" in text
    contains_sbi = "sbi" in text
    return {
        "contains_pmu_token": contains_pmu,
        "contains_compatible_token": contains_compatible,
        "contains_sbi_token": contains_sbi,
        "satisfies_pmu_node": contains_pmu and contains_compatible,
    }


def anchor_row(root: Path, spec: dict[str, Any]) -> dict[str, Any]:
    candidate_rows = [file_or_dir_row(root, path) for path in spec["candidates"]]
    satisfied_candidates: list[dict[str, Any]] = []
    if spec["mode"] == "build_entrypoint":
        for row in candidate_rows:
            if row.get("kind") != "file":
                continue
            analysis = build_entrypoint_analysis(repo_path(root, str(row["path"])))
            row["build_entrypoint_analysis"] = analysis
            if analysis["satisfies_build_entrypoint"]:
                satisfied_candidates.append(row)
    elif spec["mode"] == "buildroot_defconfig":
        for row in candidate_rows:
            if row.get("kind") not in {"file", "directory"}:
                continue
            analysis = buildroot_analysis(repo_path(root, str(row["path"])))
            row["buildroot_analysis"] = analysis
            if analysis["satisfies_buildroot_anchor"]:
                satisfied_candidates.append(row)
    elif spec["mode"] == "opensbi_manifest":
        for row in candidate_rows:
            if row.get("kind") not in {"file", "directory"}:
                continue
            analysis = opensbi_analysis(repo_path(root, str(row["path"])))
            row["opensbi_analysis"] = analysis
            if analysis["satisfies_opensbi_anchor"]:
                satisfied_candidates.append(row)
    elif spec["mode"] == "kernel_config":
        for row in candidate_rows:
            if row.get("kind") != "file":
                continue
            analysis = config_analysis(repo_path(root, str(row["path"])))
            row["config_analysis"] = analysis
            if analysis["satisfies_counter_config"]:
                satisfied_candidates.append(row)
    elif spec["mode"] == "dtb_pmu":
        for row in candidate_rows:
            if row.get("kind") != "file":
                continue
            analysis = dtb_pmu_analysis(repo_path(root, str(row["path"])))
            row["dtb_pmu_analysis"] = analysis
            if analysis["satisfies_pmu_node"]:
                satisfied_candidates.append(row)
    else:
        satisfied_candidates = [row for row in candidate_rows if row.get("exists") is True]
    return {
        "id": spec["id"],
        "required": spec["required"],
        "role": spec["role"],
        "mode": spec["mode"],
        "satisfied": bool(satisfied_candidates),
        "candidate_paths": list(spec["candidates"]),
        "present_candidates": [row for row in candidate_rows if row.get("exists") is True],
        "candidate_results": candidate_rows,
        "missing_reason": None if satisfied_candidates else f"no acceptable {spec['id']} candidate is present",
    }


def summary_row(root: Path, row_id: str, path_value: str, expected_schema: str) -> dict[str, Any]:
    path = repo_path(root, path_value)
    row: dict[str, Any] = {
        "id": row_id,
        "path": path_value,
        "exists": path.is_file(),
        "expected_schema": expected_schema,
        "schema": None,
        "status": None,
    }
    if not path.is_file():
        return row
    row.update({"path": repo_rel(root, path), "sha256": sha256_file(path), "size_bytes": path.stat().st_size})
    try:
        data = load_json(path)
    except Exception as exc:
        row["schema"] = "INVALID_JSON"
        row["status"] = "INVALID_JSON"
        row["error"] = str(exc)
        return row
    row["schema"] = data.get("schema")
    row["status"] = data.get("status")
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    row["claim_boundary"] = {
        key: boundary.get(key)
        for key in sorted(boundary)
        if key
        in {
            "board_rdcycle_smoke_claimed",
            "board_kernel_perf_cycle_source_claimed",
            "board_cycle_counter_claimed",
            "board_cycle_source_claimed",
            "cycle_level_overhead_claimed",
            "paper_runtime_overhead_claimed",
            "production_runtime_slowdown_claimed",
            "diagnostic_only",
        }
    }
    return row


def documentary_row(root: Path, path_value: str) -> dict[str, Any]:
    path = repo_path(root, path_value)
    row: dict[str, Any] = {"path": path_value, "exists": path.is_file()}
    if path.is_file():
        row.update({"path": repo_rel(root, path), "sha256": sha256_file(path), "size_bytes": path.stat().st_size})
    return row


def rejected_path_rows(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row_id, path_value, reason in REJECTED_NON_GENESYS2_PATHS:
        path = repo_path(root, path_value)
        rows.append(
            {
                "id": row_id,
                "path": path_value,
                "source_worktree_exists": path.exists(),
                "source_worktree_kind": "directory" if path.is_dir() else "file" if path.is_file() else "missing",
                "rejection_reason": reason,
                "accepted_as_counter_path_anchor": False,
            }
        )
    return rows


def live_cycle_source_available(summaries: list[dict[str, Any]]) -> bool:
    statuses = {row["id"]: row.get("status") for row in summaries}
    return statuses.get("cycle_counter_smoke") == "PASS" or statuses.get("cycle_source_probe") == "PASS" or statuses.get("counter_access_matrix") == "PASS"


def package_preflight(root: Path, current_root: Path) -> dict[str, Any]:
    anchors = [anchor_row(root, spec) for spec in ANCHORS]
    missing_required = [row["id"] for row in anchors if row.get("required") is True and row.get("satisfied") is not True]
    summaries = [summary_row(root, row_id, path, schema) for row_id, path, schema in SUPPORTING_SUMMARIES]
    if missing_required:
        status = "BLOCKED_SD_CARD_LINUX_SOURCE_MISSING"
        if missing_required == ["live_kernel_config_export"]:
            blocked_reason = "repo-local source anchors are present, but the live Genesys2/CVA6 SD-card Linux image still lacks a readable exported kernel config"
        else:
            blocked_reason = "repo lacks required Genesys2/CVA6 Buildroot/OpenSBI/Linux/SD-card counter-source rebuild anchors"
    elif not live_cycle_source_available(summaries):
        status = "BLOCKED_BOARD_COUNTER_SOURCE_UNAVAILABLE_AFTER_REBUILD_PREFLIGHT"
        blocked_reason = "local rebuild anchors are present, but live board cycle-source probes have not passed"
    else:
        status = "PASS_LOCAL_COUNTER_PATH_PREFLIGHT_READY"
        blocked_reason = None
    data: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "canonical_evaluation_root": current_root.as_posix(),
        "scope": "repo-local preflight for replacing or rebuilding the Genesys2/CVA6 SD-card Linux counter path",
        "required_anchor_count": len([row for row in anchors if row.get("required") is True]),
        "satisfied_required_anchor_count": len([row for row in anchors if row.get("required") is True and row.get("satisfied") is True]),
        "missing_required_anchor_ids": missing_required,
        "anchors": anchors,
        "supporting_summaries": summaries,
        "documentary_references": [documentary_row(root, path) for path in DOCUMENTARY_REFERENCES],
        "rejected_non_genesys2_linux_paths": rejected_path_rows(root),
        "required_kernel_options": {
            "required_exact": REQUIRED_KERNEL_SYMBOLS,
            "required_one_of": list(PMU_SYMBOL_OPTIONS),
            "notes": [
                "CONFIG_PERF_EVENTS must be enabled before kernel perf hardware-cycle probes can pass.",
                "At least one RISC-V PMU/SBI PMU or equivalent hardware perf option must be present.",
                "IKCONFIG/IKCONFIG_PROC are required so future board diagnostics can prove the live kernel config.",
            ],
        },
        "required_device_tree_or_firmware": [
            "Expose a PMU/perf device-tree node or equivalent RISC-V SBI PMU path visible to Linux.",
            "The repo-owned CVA6/Genesys2 bootrom DTS template must carry the PMU node before any rebuilt SD-card image can satisfy the live counter path.",
            "Lock OpenSBI source/build artifacts that prove SBI PMU or counter delegation behavior.",
            "Record exact kernel, rootfs, DTB, firmware, and SD-card image hashes in a repo artifact manifest.",
        ],
        "validation_commands": [
            "uv run rvmt ndss:linux-rebuild-prep --fetch --configure",
            "uv run python tools/check_genesys2_linux_rebuild_manifest.py --root .",
            "uv run rvmt ndss:sdcard-linux-manifest --port COM7 --baud 115200",
            "uv run python tools/check_genesys2_sdcard_linux_manifest.py --root .",
            "uv run rvmt ndss:live-kernel-config-export --port COM7 --baud 115200",
            "uv run python tools/check_genesys2_live_kernel_config_export.py --root .",
            "uv run python tools/check_genesys2_live_kernel_config_export.py --root . --require-pass",
            "uv run rvmt ndss:linux-counter-preflight",
            "uv run python tools/check_genesys2_linux_counter_path_preflight.py --root .",
            "uv run python tools/check_genesys2_linux_counter_path_preflight.py --root . --require-pass",
            "uv run rvmt ndss:cycle-smoke --port COM7 --baud 115200 --reps 5",
            "uv run python tools/check_genesys2_cycle_counter_smoke.py --root . --require-pass",
            "uv run rvmt ndss:cycle-source-probe --port COM7 --baud 115200 --reps 5",
            "uv run python tools/check_genesys2_cycle_source_probe.py --root . --require-pass",
            "uv run rvmt ndss:cycle-diagnostics --port COM7 --baud 115200",
            "uv run rvmt ndss:counter-access-matrix --port COM7 --baud 115200 --reps 5",
            "uv run python tools/check_genesys2_counter_access_matrix.py --root . --require-pass",
        ],
        "claim_boundary": {
            "linux_counter_path_preflight_only": True,
            "sd_card_linux_rebuild_path_claimed": status == "PASS_LOCAL_COUNTER_PATH_PREFLIGHT_READY",
            "board_cycle_source_claimed": False,
            "cycle_level_overhead_claimed": False,
            "production_runtime_slowdown_claimed": False,
            "qemu_or_strace_substitution_allowed": False,
            "artix7_or_vexriscv_substitution_allowed": False,
            "requires_host_board_rerun_after_fix": True,
        },
        "non_claims": [
            "This preflight does not build a new SD-card image and does not run Vivado or the Genesys2 board.",
            "A live SD-card manifest documents the booted image identity only; it is not a Buildroot, OpenSBI, kernel, or SD-card rebuild source path.",
            "A repo DTS template with a PMU node is source-level readiness only until the rebuilt DTB, OpenSBI, Linux kernel, SD-card payload, and live board diagnostics prove PMU visibility.",
            "Existing Artix-7/LiteX/VexRiscv Linux assets are rejected as substitutes for Genesys2/CVA6 counter-source evidence.",
            "QEMU, strace, and local Linux checks remain validation oracles and cannot replace board cycle-source probes.",
            "A local preflight PASS would not claim runtime overhead; the board cycle-source require-pass checkers must pass first.",
        ],
    }
    if blocked_reason:
        data["blocked_reason"] = blocked_reason
    return data


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-linux-counter-preflight-") as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        for row_id, path_value, schema in SUPPORTING_SUMMARIES:
            path = root / path_value
            path.parent.mkdir(parents=True, exist_ok=True)
            status = "PASS" if row_id == "bootrom_counter_delegation" else "BLOCKED_FIXTURE"
            if row_id == "sdcard_linux_manifest":
                status = "PASS"
            write_json(path, {"schema": schema, "status": status, "claim_boundary": {"cycle_level_overhead_claimed": False}})
        blocked = package_preflight(root, DEFAULT_CURRENT_ROOT)
        if blocked.get("status") != "BLOCKED_SD_CARD_LINUX_SOURCE_MISSING":
            print("[FAIL] expected missing source anchors to block preflight", file=sys.stderr)
            return 1

        for path_value in (
            "tools/build_genesys2_cva6_linux_image.py",
            "board/genesys2-cva6/linux/buildroot_defconfig",
            "board/genesys2-cva6/linux/opensbi_manifest.json",
            "board/genesys2-cva6/linux/sdcard_manifest.json",
        ):
            path = root / path_value
            path.parent.mkdir(parents=True, exist_ok=True)
            if path_value.endswith("build_genesys2_cva6_linux_image.py"):
                path.write_text(
                    "# fixture Genesys2 CVA6 Buildroot OpenSBI SD-card builder\n"
                    "print('build genesys2 cva6 buildroot opensbi sdcard')\n",
                    encoding="utf-8",
                    newline="\n",
                )
            elif path_value.endswith("buildroot_defconfig"):
                path.write_text(
                    "# Genesys2 CVA6 Buildroot fixture\n"
                    "BR2_riscv=y\n"
                    "BR2_RISCV_64=y\n"
                    "BR2_LINUX_KERNEL=y\n"
                    "BR2_TARGET_OPENSBI=y\n",
                    encoding="utf-8",
                    newline="\n",
                )
            elif path_value.endswith("opensbi_manifest.json"):
                write_json(
                    path,
                    {
                        "schema": "rvmt.genesys2.opensbi_source_manifest.v1",
                        "source": {"commit": "fixture"},
                        "artifacts": [{"path": "fw_jump.bin", "sha256": "0" * 64}],
                    },
                )
            else:
                path.write_text("fixture\n", encoding="utf-8", newline="\n")
        kernel_config = root / "board/genesys2-cva6/linux/linux.config"
        kernel_config.write_text(
            "CONFIG_PERF_EVENTS=y\n"
            "CONFIG_RISCV_PMU_SBI=y\n"
            "CONFIG_IKCONFIG=y\n"
            "CONFIG_IKCONFIG_PROC=y\n",
            encoding="utf-8",
            newline="\n",
        )
        dts = root / "board/genesys2-cva6/linux/genesys2-cva6.dts"
        dts.write_text('/ { pmu { compatible = "riscv,pmu"; }; };\n', encoding="utf-8", newline="\n")
        live_config = root / "results/evaluation/genesys2-cva6/current/live_kernel_config.txt"
        live_config.write_text(kernel_config.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
        ready = package_preflight(root, DEFAULT_CURRENT_ROOT)
        if ready.get("status") != "BLOCKED_BOARD_COUNTER_SOURCE_UNAVAILABLE_AFTER_REBUILD_PREFLIGHT":
            print("[FAIL] expected board probes to remain required after source preflight", file=sys.stderr)
            print(json.dumps(ready, indent=2), file=sys.stderr)
            return 1
        (root / "results/evaluation/genesys2-cva6/current/cycle_source_probe_summary.json").write_text(
            json.dumps(
                {
                    "schema": "rvmt.genesys2.cycle_source_probe.v1",
                    "status": "PASS",
                    "claim_boundary": {"board_kernel_perf_cycle_source_claimed": True, "cycle_level_overhead_claimed": False},
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        passed = package_preflight(root, DEFAULT_CURRENT_ROOT)
        if passed.get("status") != "PASS_LOCAL_COUNTER_PATH_PREFLIGHT_READY":
            print("[FAIL] expected complete source anchors plus cycle source PASS to pass preflight", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 Linux counter-path preflight packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package repo-local Genesys2/CVA6 SD-card Linux counter-path preflight evidence.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    out = repo_path(root, args.out)
    try:
        summary = package_preflight(root, args.current_root)
        write_json(out, summary)
    except Exception as exc:
        print(f"package_genesys2_linux_counter_path_preflight: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote Genesys2 Linux counter-path preflight to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
