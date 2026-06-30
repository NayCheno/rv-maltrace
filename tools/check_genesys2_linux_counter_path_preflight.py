from __future__ import annotations

import argparse
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


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/linux_counter_path_preflight.json")
SUMMARY_SCHEMA = "rvmt.genesys2.linux_counter_path_preflight.v1"
ACCEPTED_STATUSES = {
    "PASS_LOCAL_COUNTER_PATH_PREFLIGHT_READY",
    "BLOCKED_SD_CARD_LINUX_SOURCE_MISSING",
    "BLOCKED_BOARD_COUNTER_SOURCE_UNAVAILABLE_AFTER_REBUILD_PREFLIGHT",
}
REQUIRED_ANCHOR_IDS = {
    "genesys2_cva6_linux_build_entrypoint",
    "buildroot_source_or_defconfig",
    "linux_kernel_counter_config",
    "opensbi_source_or_manifest",
    "sd_card_image_manifest",
    "device_tree_pmu_node_source",
    "live_kernel_config_export",
}
REQUIRED_SUPPORTING_IDS = {
    "bootrom_counter_delegation",
    "sdcard_linux_manifest",
    "cycle_counter_smoke",
    "cycle_source_probe",
    "cycle_source_diagnostics",
    "live_kernel_config_export",
    "counter_access_matrix",
}
TRUTHFUL_SUPPORTING_NONPASS = {
    "cycle_counter_smoke": {"BLOCKED_BOARD_RDCYCLE_UNAVAILABLE"},
    "cycle_source_probe": {"BLOCKED_BOARD_KERNEL_PERF_CYCLES_UNAVAILABLE"},
    "cycle_source_diagnostics": {"BLOCKED_BOARD_KERNEL_PMU_AND_USER_CYCLE_UNAVAILABLE"},
    "live_kernel_config_export": {
        "BLOCKED_LIVE_KERNEL_CONFIG_UNAVAILABLE",
        "BLOCKED_LIVE_KERNEL_CONFIG_COUNTER_OPTIONS_MISSING",
    },
    "counter_access_matrix": {
        "BLOCKED_BOARD_CYCLE_COUNTER_UNAVAILABLE_NONCYCLE_TIME_AVAILABLE",
        "BLOCKED_BOARD_COUNTER_SOURCES_UNAVAILABLE",
    },
}


def row_map(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def int_value(value: Any, default: int = -1) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def check_hashed_row(errors: list[str], root: Path, row: dict[str, Any], label: str, *, require_file: bool = True) -> None:
    path_value = row.get("path")
    if not path_value:
        if require_file:
            errors.append(f"{label}: path missing")
        return
    path = repo_path(root, path_value)
    if require_file:
        require(errors, path.is_file(), f"{label}: file missing: {path_value}")
    else:
        require(errors, path.exists(), f"{label}: path missing: {path_value}")
    if path.is_file() and row.get("sha256") is not None:
        require(errors, row.get("sha256") == sha256_file(path), f"{label}: sha256 mismatch")
        if row.get("size_bytes") is not None:
            require(errors, int(row.get("size_bytes") or -1) == path.stat().st_size, f"{label}: size_bytes mismatch")


def supporting_status_ok(row_id: str, status: Any) -> bool:
    if status == "PASS":
        return True
    return str(status) in TRUTHFUL_SUPPORTING_NONPASS.get(row_id, set())


def candidate_satisfies_mode(row: dict[str, Any], mode: str) -> bool:
    if mode == "build_entrypoint":
        return as_dict(row.get("build_entrypoint_analysis")).get("satisfies_build_entrypoint") is True
    if mode == "buildroot_defconfig":
        return as_dict(row.get("buildroot_analysis")).get("satisfies_buildroot_anchor") is True
    if mode == "opensbi_manifest":
        return as_dict(row.get("opensbi_analysis")).get("satisfies_opensbi_anchor") is True
    if mode == "kernel_config":
        return as_dict(row.get("config_analysis")).get("satisfies_counter_config") is True
    if mode == "dtb_pmu":
        return as_dict(row.get("dtb_pmu_analysis")).get("satisfies_pmu_node") is True
    return row.get("exists") is True


def check_candidate_rows(errors: list[str], root: Path, anchor: dict[str, Any]) -> None:
    for row in as_list(anchor.get("present_candidates")):
        if not isinstance(row, dict):
            errors.append(f"{anchor.get('id')}: present candidate row must be object")
            continue
        kind = row.get("kind")
        path_value = row.get("path")
        require(errors, kind in {"file", "directory"}, f"{anchor.get('id')}: present candidate kind invalid")
        require(errors, bool(path_value), f"{anchor.get('id')}: present candidate path missing")
        if path_value:
            path = repo_path(root, path_value)
            require(errors, path.exists(), f"{anchor.get('id')}: present candidate missing: {path_value}")
            if kind == "file":
                require(errors, path.is_file(), f"{anchor.get('id')}: candidate must be file: {path_value}")
                require(errors, row.get("sha256") == sha256_file(path), f"{anchor.get('id')}: candidate sha256 mismatch: {path_value}")
            if kind == "directory":
                require(errors, path.is_dir(), f"{anchor.get('id')}: candidate must be directory: {path_value}")
        mode = str(anchor.get("mode") or "")
        if mode == "build_entrypoint" and kind == "file":
            analysis = as_dict(row.get("build_entrypoint_analysis"))
            require(errors, isinstance(analysis.get("required_terms"), dict), f"{anchor.get('id')}: build entrypoint analysis missing")
            require(errors, isinstance(analysis.get("satisfies_build_entrypoint"), bool), f"{anchor.get('id')}: build entrypoint satisfaction missing")
        elif mode == "buildroot_defconfig" and kind in {"file", "directory"}:
            analysis = as_dict(row.get("buildroot_analysis"))
            require(errors, isinstance(analysis.get("satisfies_buildroot_anchor"), bool), f"{anchor.get('id')}: Buildroot analysis missing")
        elif mode == "opensbi_manifest" and kind in {"file", "directory"}:
            analysis = as_dict(row.get("opensbi_analysis"))
            require(errors, isinstance(analysis.get("satisfies_opensbi_anchor"), bool), f"{anchor.get('id')}: OpenSBI analysis missing")
        elif mode == "kernel_config" and kind == "file":
            analysis = as_dict(row.get("config_analysis"))
            require(errors, isinstance(analysis.get("satisfies_counter_config"), bool), f"{anchor.get('id')}: kernel config analysis missing")
        elif mode == "dtb_pmu" and kind == "file":
            analysis = as_dict(row.get("dtb_pmu_analysis"))
            require(errors, isinstance(analysis.get("satisfies_pmu_node"), bool), f"{anchor.get('id')}: DTB PMU analysis missing")


def check_summary(data: dict[str, Any], root: Path, *, require_pass: bool) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == SUMMARY_SCHEMA, f"schema must be {SUMMARY_SCHEMA}")
    status = str(data.get("status") or "")
    if require_pass:
        require(errors, status == "PASS_LOCAL_COUNTER_PATH_PREFLIGHT_READY", f"status must be PASS_LOCAL_COUNTER_PATH_PREFLIGHT_READY under --require-pass, got {status}")
    else:
        require(errors, status in ACCEPTED_STATUSES, f"unexpected status: {status}")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical evidence root mismatch")

    anchors = row_map(as_list(data.get("anchors")))
    missing_anchor_ids = sorted(REQUIRED_ANCHOR_IDS - set(anchors))
    require(errors, not missing_anchor_ids, f"missing anchor rows: {', '.join(missing_anchor_ids)}")
    missing_required = [
        anchor_id
        for anchor_id, row in anchors.items()
        if row.get("required") is True and row.get("satisfied") is not True
    ]
    require(errors, sorted(as_list(data.get("missing_required_anchor_ids"))) == sorted(missing_required), "missing_required_anchor_ids mismatch")
    require(errors, int_value(data.get("required_anchor_count")) == len(REQUIRED_ANCHOR_IDS), "required_anchor_count mismatch")
    require(
        errors,
        int_value(data.get("satisfied_required_anchor_count")) == len(REQUIRED_ANCHOR_IDS) - len(missing_required),
        "satisfied_required_anchor_count mismatch",
    )
    for anchor_id, anchor in anchors.items():
        require(errors, isinstance(anchor.get("candidate_paths"), list), f"{anchor_id}: candidate_paths required")
        require(errors, isinstance(anchor.get("candidate_results"), list), f"{anchor_id}: candidate_results required")
        check_candidate_rows(errors, root, anchor)
        satisfying_present = [
            row
            for row in as_list(anchor.get("present_candidates"))
            if isinstance(row, dict) and candidate_satisfies_mode(row, str(anchor.get("mode") or ""))
        ]
        if anchor.get("satisfied") is True:
            require(errors, bool(as_list(anchor.get("present_candidates"))), f"{anchor_id}: satisfied anchor must list present candidates")
            require(errors, bool(satisfying_present), f"{anchor_id}: satisfied anchor lacks a semantically acceptable candidate")
        else:
            require(errors, bool(anchor.get("missing_reason")), f"{anchor_id}: unsatisfied anchor needs missing_reason")
            require(errors, not satisfying_present, f"{anchor_id}: unsatisfied anchor contains semantically acceptable candidate")

    supporting = row_map(as_list(data.get("supporting_summaries")))
    missing_supporting = sorted(REQUIRED_SUPPORTING_IDS - set(supporting))
    require(errors, not missing_supporting, f"missing supporting summaries: {', '.join(missing_supporting)}")
    for row_id, row in supporting.items():
        check_hashed_row(errors, root, row, f"supporting {row_id}")
        path = repo_path(root, row.get("path")) if row.get("path") else None
        if path and path.is_file():
            try:
                artifact = load_json(path)
            except Exception as exc:
                errors.append(f"{row_id}: supporting JSON invalid: {exc}")
                continue
            require(errors, row.get("schema") == artifact.get("schema"), f"{row_id}: schema mismatch")
            require(errors, row.get("status") == artifact.get("status"), f"{row_id}: status mismatch")
            require(errors, supporting_status_ok(row_id, row.get("status")), f"{row_id}: status is not PASS or accepted truthful non-PASS")

    if status == "BLOCKED_SD_CARD_LINUX_SOURCE_MISSING":
        require(errors, bool(missing_required), "source-missing BLOCKED status requires missing required anchors")
        blocked_reason = str(data.get("blocked_reason") or "")
        require(
            errors,
            "Buildroot/OpenSBI/Linux/SD-card" in blocked_reason or "live Genesys2/CVA6 SD-card Linux image" in blocked_reason,
            "blocked_reason must name missing Linux source path or live kernel-config export",
        )
    elif status == "BLOCKED_BOARD_COUNTER_SOURCE_UNAVAILABLE_AFTER_REBUILD_PREFLIGHT":
        require(errors, not missing_required, "board-counter BLOCKED status requires source anchors to be satisfied")
        require(errors, bool(data.get("blocked_reason")), "blocked status requires blocked_reason")
    elif status == "PASS_LOCAL_COUNTER_PATH_PREFLIGHT_READY":
        require(errors, not missing_required, "PASS preflight cannot have missing required anchors")

    rejected = as_list(data.get("rejected_non_genesys2_linux_paths"))
    require(errors, bool(rejected), "rejected non-Genesys2 Linux path rows required")
    for row in rejected:
        if not isinstance(row, dict):
            errors.append("rejected path row must be object")
            continue
        require(errors, row.get("accepted_as_counter_path_anchor") is False, f"{row.get('id')}: rejected row must not satisfy counter path")
        require(errors, isinstance(row.get("source_worktree_exists"), bool), f"{row.get('id')}: source_worktree_exists must be boolean")
        require(errors, row.get("source_worktree_kind") in {"file", "directory", "missing"}, f"{row.get('id')}: source_worktree_kind invalid")
        if row.get("source_worktree_exists") is True:
            path_value = row.get("path")
            path = repo_path(root, path_value) if path_value else None
            if path is not None and path.exists():
                expected_kind = "directory" if path.is_dir() else "file" if path.is_file() else "missing"
                require(errors, row.get("source_worktree_kind") == expected_kind, f"{row.get('id')}: rejected path metadata mismatch")

    for row in as_list(data.get("documentary_references")):
        if isinstance(row, dict) and row.get("exists") is True:
            check_hashed_row(errors, root, row, "documentary reference")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    for needle in (
        "rvmt ndss:linux-rebuild-prep",
        "check_genesys2_linux_rebuild_manifest.py --root .",
        "rvmt ndss:sdcard-linux-manifest",
        "check_genesys2_sdcard_linux_manifest.py --root .",
        "rvmt ndss:live-kernel-config-export",
        "check_genesys2_live_kernel_config_export.py --root . --require-pass",
        "rvmt ndss:linux-counter-preflight",
        "check_genesys2_linux_counter_path_preflight.py --root . --require-pass",
        "check_genesys2_cycle_counter_smoke.py --root . --require-pass",
        "check_genesys2_cycle_source_probe.py --root . --require-pass",
        "check_genesys2_counter_access_matrix.py --root . --require-pass",
    ):
        require(errors, needle in commands, f"validation command missing: {needle}")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("linux_counter_path_preflight_only") is True, "preflight-only boundary missing")
    require(errors, boundary.get("board_cycle_source_claimed") is False, "preflight must not claim board cycle source")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "preflight must not claim cycle-level overhead")
    require(errors, boundary.get("production_runtime_slowdown_claimed") is False, "preflight must not claim production slowdown")
    require(errors, boundary.get("qemu_or_strace_substitution_allowed") is False, "QEMU/strace substitution must be forbidden")
    require(errors, boundary.get("artix7_or_vexriscv_substitution_allowed") is False, "Artix-7/VexRiscv substitution must be forbidden")
    require(errors, boundary.get("requires_host_board_rerun_after_fix") is True, "host board rerun boundary missing")
    require(
        errors,
        boundary.get("sd_card_linux_rebuild_path_claimed") is (status == "PASS_LOCAL_COUNTER_PATH_PREFLIGHT_READY"),
        "sd_card_linux_rebuild_path_claimed must match PASS_LOCAL status",
    )

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "does not build a new sd-card image" in non_claims, "non_claims must reject unrun SD-card build")
    require(errors, "not a buildroot, opensbi, kernel, or sd-card rebuild source path" in non_claims, "non_claims must keep live manifest from becoming source evidence")
    require(errors, "artix-7/litex/vexriscv" in non_claims, "non_claims must reject non-Genesys2 substitutes")
    require(errors, "qemu, strace" in non_claims, "non_claims must reject oracle substitution")
    require(errors, "would not claim runtime overhead" in non_claims, "non_claims must preserve overhead boundary")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-linux-counter-preflight-check-") as tmp:
        root = Path(tmp)
        current = root / "results/evaluation/genesys2-cva6/current"
        current.mkdir(parents=True, exist_ok=True)
        supporting_rows = []
        for row_id, schema, status in (
            ("bootrom_counter_delegation", "rvmt.genesys2.bootrom_build.v1", "PASS"),
            ("sdcard_linux_manifest", "rvmt.genesys2.sdcard_linux_manifest.v1", "PASS"),
            ("cycle_counter_smoke", "rvmt.genesys2.cycle_counter_smoke.v1", "BLOCKED_BOARD_RDCYCLE_UNAVAILABLE"),
            ("cycle_source_probe", "rvmt.genesys2.cycle_source_probe.v1", "BLOCKED_BOARD_KERNEL_PERF_CYCLES_UNAVAILABLE"),
            ("cycle_source_diagnostics", "rvmt.genesys2.cycle_source_diagnostics.v1", "BLOCKED_BOARD_KERNEL_PMU_AND_USER_CYCLE_UNAVAILABLE"),
            ("live_kernel_config_export", "rvmt.genesys2.live_kernel_config_export.v1", "BLOCKED_LIVE_KERNEL_CONFIG_UNAVAILABLE"),
            ("counter_access_matrix", "rvmt.genesys2.counter_access_matrix.v1", "BLOCKED_BOARD_CYCLE_COUNTER_UNAVAILABLE_NONCYCLE_TIME_AVAILABLE"),
        ):
            path = current / f"{row_id}.json"
            write_json(path, {"schema": schema, "status": status})
            supporting_rows.append(
                {
                    "id": row_id,
                    "path": path.relative_to(root).as_posix(),
                    "exists": True,
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                    "schema": schema,
                    "status": status,
                }
            )
        anchors = [
            {
                "id": anchor_id,
                "required": True,
                "role": "fixture",
                "mode": "path",
                "satisfied": False,
                "candidate_paths": ["missing"],
                "present_candidates": [],
                "candidate_results": [{"candidate": "missing", "exists": False, "kind": "missing"}],
                "missing_reason": "missing fixture",
            }
            for anchor_id in sorted(REQUIRED_ANCHOR_IDS)
        ]
        summary = {
            "schema": SUMMARY_SCHEMA,
            "status": "BLOCKED_SD_CARD_LINUX_SOURCE_MISSING",
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "required_anchor_count": len(REQUIRED_ANCHOR_IDS),
            "satisfied_required_anchor_count": 0,
            "missing_required_anchor_ids": sorted(REQUIRED_ANCHOR_IDS),
            "anchors": anchors,
            "supporting_summaries": supporting_rows,
            "rejected_non_genesys2_linux_paths": [
                {
                    "id": "artix7",
                    "path": "missing-artix7",
                    "source_worktree_exists": False,
                    "source_worktree_kind": "missing",
                    "accepted_as_counter_path_anchor": False,
                    "rejection_reason": "fixture",
                }
            ],
            "validation_commands": [
                "uv run rvmt ndss:linux-counter-preflight",
                "uv run rvmt ndss:linux-rebuild-prep --fetch --configure",
                "uv run python tools/check_genesys2_linux_rebuild_manifest.py --root .",
                "uv run rvmt ndss:sdcard-linux-manifest --port COM7 --baud 115200",
                "uv run python tools/check_genesys2_sdcard_linux_manifest.py --root .",
                "uv run rvmt ndss:live-kernel-config-export --port COM7 --baud 115200",
                "uv run python tools/check_genesys2_live_kernel_config_export.py --root . --require-pass",
                "uv run python tools/check_genesys2_linux_counter_path_preflight.py --root . --require-pass",
                "uv run python tools/check_genesys2_cycle_counter_smoke.py --root . --require-pass",
                "uv run python tools/check_genesys2_cycle_source_probe.py --root . --require-pass",
                "uv run python tools/check_genesys2_counter_access_matrix.py --root . --require-pass",
            ],
            "claim_boundary": {
                "linux_counter_path_preflight_only": True,
                "sd_card_linux_rebuild_path_claimed": False,
                "board_cycle_source_claimed": False,
                "cycle_level_overhead_claimed": False,
                "production_runtime_slowdown_claimed": False,
                "qemu_or_strace_substitution_allowed": False,
                "artix7_or_vexriscv_substitution_allowed": False,
                "requires_host_board_rerun_after_fix": True,
            },
            "blocked_reason": "repo lacks required Genesys2/CVA6 Buildroot/OpenSBI/Linux/SD-card counter-source rebuild anchors",
            "non_claims": [
                "This preflight does not build a new SD-card image and does not run Vivado or the Genesys2 board.",
                "A live SD-card manifest documents the booted image identity only; it is not a Buildroot, OpenSBI, kernel, or SD-card rebuild source path.",
                "Existing Artix-7/LiteX/VexRiscv Linux assets are rejected as substitutes for Genesys2/CVA6 counter-source evidence.",
                "QEMU, strace, and local Linux checks remain validation oracles and cannot replace board cycle-source probes.",
                "A local preflight PASS would not claim runtime overhead; the board cycle-source require-pass checkers must pass first.",
            ],
        }
        errors = check_summary(summary, root, require_pass=False)
        if errors:
            print("[FAIL] Linux counter-path preflight checker good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        if not check_summary(summary, root, require_pass=True):
            print("[FAIL] --require-pass accepted blocked preflight", file=sys.stderr)
            return 1
        summary["claim_boundary"]["board_cycle_source_claimed"] = True
        errors = check_summary(summary, root, require_pass=False)
        if not any("must not claim board cycle source" in error for error in errors):
            print("[FAIL] checker missed board cycle overclaim", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 Linux counter-path preflight checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check repo-local Genesys2/CVA6 SD-card Linux counter-path preflight evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = repo_path(root, args.summary)
    if not summary.is_file():
        if args.require_pass:
            print(f"[FAIL] Linux counter-path preflight summary missing: {summary}", file=sys.stderr)
            return 1
        print(f"[BLOCKED_SD_CARD_LINUX_SOURCE_MISSING] Linux counter-path preflight summary missing: {summary}")
        return 0
    try:
        errors = check_summary(load_json(summary), root, require_pass=args.require_pass)
    except Exception as exc:
        print(f"[FAIL] Linux counter-path preflight checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] Linux counter-path preflight summary is not acceptable", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    data = load_json(summary)
    print(f"[PASS] Linux counter-path preflight accepted: {summary} status={data.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
