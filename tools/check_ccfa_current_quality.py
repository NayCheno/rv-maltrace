from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_list,
    load_json,
    require,
    sha256_file,
    write_json,
)

from ccfa_gate_common import ALL_CCFA_SAMPLES, P0_SAMPLES, SAFE_SURROGATE_SAMPLES, check_dynamic_mapping_attribution
from ccfa_current_quality_spec import (
    DEFAULT_CURRENT_ROOT,
    EXPECTED_EXECVE_TARGETS,
    EXPECTED_SAMPLE_SYSCALLS,
    FORBIDDEN_PLANNING_TEXT,
    PLANNING_DOCS,
    REQUIRED_PLANNING_TEXT,
    SUMMARY_SCHEMAS,
    UART_WALL_CLOCK_RUNTIME_METRIC,
)
from ccfa_current_quality_fixtures import write_fixture


def rel_or_abs(root: Path, path: Any) -> Path:
    candidate = Path(str(path))
    return candidate if candidate.is_absolute() else root / candidate


def sample_rows(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("sample_id") or row.get("id")): row
        for row in as_list(data.get("samples"))
        if isinstance(row, dict) and (row.get("sample_id") or row.get("id"))
    }


def external_intake_failure_is_truthful(data: dict[str, Any]) -> bool:
    if data.get("schema") != "rvmt.genesys2.external_closure_intake.v1":
        return False
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    return (
        data.get("status") == "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED"
        and int(data.get("accepted_external_blocker_count") or 0) < 4
        and boundary.get("unvalidated_external_summary_accepted") is False
        and boundary.get("all_non_real_external_blockers_closed") is False
    )


def dynamic_mapping_blocked_is_truthful(data: dict[str, Any]) -> bool:
    return (
        data.get("status") == "BLOCKED_BOARD_DYNAMIC_MAPPING_CASES"
        and not check_dynamic_mapping_attribution(data, Path("."))
    )


def status_allowed(filename: str, data: dict[str, Any]) -> bool:
    if data.get("status") == "PASS":
        return True
    if filename == "external_closure_intake.json":
        return external_intake_failure_is_truthful(data)
    if filename == "dynamic_mapping_attribution_summary.json":
        return dynamic_mapping_blocked_is_truthful(data)
    return False


def require_file(errors: list[str], root: Path, value: Any, context: str) -> Path | None:
    if not value:
        errors.append(f"{context}: path missing")
        return None
    path = rel_or_abs(root, value)
    if not path.is_file():
        errors.append(f"{context}: file missing: {value}")
        return None
    return path


def require_json_file(errors: list[str], root: Path, value: Any, context: str) -> dict[str, Any] | None:
    path = require_file(errors, root, value, context)
    if path is None:
        return None
    try:
        return load_json(path)
    except Exception as exc:
        errors.append(f"{context}: JSON load failed: {exc}")
        return None


def check_source_artifact_row(
    errors: list[str],
    root: Path,
    row: Any,
    *,
    context: str,
    expected_schema: str,
    expected_path: str | None = None,
) -> None:
    if not isinstance(row, dict):
        errors.append(f"{context}: source artifact missing")
        return
    path_value = row.get("path")
    require(errors, row.get("exists") is True, f"{context}: exists flag must be true")
    require(errors, row.get("expected_schema") == expected_schema, f"{context}: expected schema mismatch")
    require(errors, row.get("schema") == expected_schema, f"{context}: source schema mismatch")
    row_status = row.get("status")
    allowed_status = row_status == "PASS"
    if expected_schema == "rvmt.genesys2.external_closure_intake.v1" and row_status == "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED":
        source_data = require_json_file(errors, root, row.get("path"), f"{context}.source_status") if row.get("path") else None
        allowed_status = source_data is not None and external_intake_failure_is_truthful(source_data)
    if expected_schema == "rvmt.dynamic_mapping_attribution.v1" and row_status == "BLOCKED_BOARD_DYNAMIC_MAPPING_CASES":
        source_data = require_json_file(errors, root, row.get("path"), f"{context}.source_status") if row.get("path") else None
        allowed_status = source_data is not None and dynamic_mapping_blocked_is_truthful(source_data)
    require(errors, allowed_status, f"{context}: source status mismatch")
    if expected_path is not None:
        require(errors, path_value == expected_path, f"{context}: source path mismatch")
    path = require_file(errors, root, path_value, context) if path_value else None
    if path is not None:
        require(errors, row.get("sha256") == sha256_file(path), f"{context}: source sha256 mismatch")


def require_sample_set(errors: list[str], label: str, rows: dict[str, dict[str, Any]]) -> None:
    missing = [sample for sample in ALL_CCFA_SAMPLES if sample not in rows]
    extra = [sample for sample in rows if sample not in ALL_CCFA_SAMPLES]
    require(errors, not missing, f"{label}: missing samples: {', '.join(missing)}")
    require(errors, not extra, f"{label}: unexpected samples: {', '.join(extra)}")


def load_summaries(errors: list[str], root: Path, current_root: Path) -> dict[str, dict[str, Any]]:
    summaries: dict[str, dict[str, Any]] = {}
    for filename, schema in SUMMARY_SCHEMAS.items():
        path = current_root / filename
        if not path.is_file():
            errors.append(f"summary missing: {path}")
            continue
        try:
            data = load_json(path)
        except Exception as exc:
            errors.append(f"{filename}: JSON load failed: {exc}")
            continue
        require(errors, data.get("schema") == schema, f"{filename}: schema must be {schema}")
        require(
            errors,
            status_allowed(filename, data),
            f"{filename}: status must be PASS or a truthful blocked status",
        )
        summaries[filename] = data
    return summaries


def check_matrix_artifacts(errors: list[str], root: Path, matrix: dict[str, Any]) -> None:
    rows = sample_rows(matrix)
    require_sample_set(errors, "ccfa_evaluation_matrix", rows)
    require_file(errors, root, matrix.get("workload_manifest"), "ccfa_evaluation_matrix.workload_manifest")
    require_file(errors, root, matrix.get("resource_timing_summary"), "ccfa_evaluation_matrix.resource_timing_summary")
    for sample_id in ALL_CCFA_SAMPLES:
        row = rows.get(sample_id, {})
        require(errors, row.get("continuous_trace") is True, f"{sample_id}: continuous_trace must be true")
        require(errors, int(row.get("unaccounted_drop") or 0) == 0, f"{sample_id}: unaccounted_drop must be 0")
        for key in ("trace", "semantic_events", "behavior_graph", "baseline_logs", "metric_summary"):
            require_file(errors, root, row.get(key), f"{sample_id}.{key}")


def check_baseline_logs(errors: list[str], root: Path, matrix: dict[str, Any]) -> None:
    for sample_id, row in sample_rows(matrix).items():
        data = require_json_file(errors, root, row.get("baseline_logs"), f"{sample_id}.baseline_logs")
        if data is None:
            continue
        require(errors, data.get("schema") == "rvmt.sample_baseline_logs.v1", f"{sample_id}: baseline log schema mismatch")
        for key in ("host_strace", "qemu_strace"):
            trace = data.get(key) if isinstance(data.get(key), dict) else {}
            require(errors, trace.get("present") is True, f"{sample_id}.{key}: present must be true")
            require(errors, int(trace.get("line_count") or 0) > 0, f"{sample_id}.{key}: line_count must be positive")
            require_file(errors, root, trace.get("path"), f"{sample_id}.{key}.path")
        evidence = data.get("evidence") if isinstance(data.get("evidence"), dict) else {}
        for key in ("trace", "semantic_events", "behavior_graph", "code_map", "source_attribution", "runtime_process_map", "integrated_validation"):
            require_file(errors, root, evidence.get(key), f"{sample_id}.baseline_logs.evidence.{key}")


def check_semantics(errors: list[str], root: Path, semantic: dict[str, Any]) -> None:
    rows = sample_rows(semantic)
    require_sample_set(errors, "semantic_reconstruction", rows)
    non_claims = " ".join(str(item).lower() for item in as_list(semantic.get("non_claims")))
    require(errors, "no hardware" in non_claims and "pointer" in non_claims, "semantic summary must preserve hardware pointer non-claim")
    require(errors, "real malware" in non_claims and "not claimed" in non_claims, "semantic summary must preserve real-malware non-claim")
    for sample_id in ALL_CCFA_SAMPLES:
        row = rows.get(sample_id, {})
        require_file(errors, root, row.get("trace_source"), f"{sample_id}.semantic.trace_source")
        expected = set(str(item) for item in as_list(row.get("expected_syscalls")))
        require(errors, bool(expected), f"{sample_id}: expected_syscalls must be populated")
        alignment = row.get("ground_truth_alignment") if isinstance(row.get("ground_truth_alignment"), dict) else {}
        require_file(errors, root, alignment.get("host_or_control_strace"), f"{sample_id}.semantic.host_or_control_strace")
        require_file(errors, root, alignment.get("qemu_guest_strace"), f"{sample_id}.semantic.qemu_guest_strace")
        if row.get("has_openat"):
            require(errors, bool(as_list(row.get("openat_paths"))), f"{sample_id}: openat paths must be non-empty")
            require(errors, row.get("openat_path_source") in {"qemu_guest_strace", "host_or_control_strace"}, f"{sample_id}: openat_path_source invalid")
        else:
            require(errors, row.get("openat_path_source") == "NOT_OBSERVED", f"{sample_id}: openat_path_source must be NOT_OBSERVED")
        if row.get("has_execve"):
            paths = [str(item) for item in as_list(row.get("execve_paths"))]
            require(errors, bool(paths), f"{sample_id}: execve paths must be non-empty")
            require(errors, row.get("execve_path_source") in {"qemu_guest_strace", "host_or_control_strace"}, f"{sample_id}: execve_path_source invalid")
            if sample_id in EXPECTED_EXECVE_TARGETS:
                require(errors, EXPECTED_EXECVE_TARGETS[sample_id] in paths, f"{sample_id}: expected exec target missing")
        else:
            require(errors, row.get("execve_path_source") == "NOT_OBSERVED", f"{sample_id}: execve_path_source must be NOT_OBSERVED")
        if row.get("has_write"):
            prefixes = as_list(row.get("write_buffer_prefixes"))
            require(errors, row.get("write_buffer_prefix_recovered") is True, f"{sample_id}: write prefix must be recovered")
            require(errors, bool(prefixes), f"{sample_id}: write prefix list must be non-empty")
            require(errors, row.get("write_buffer_prefix_source") in {"qemu_guest_strace", "host_or_control_strace"}, f"{sample_id}: write prefix source invalid")
        else:
            require(errors, row.get("write_buffer_prefix_source") == "NOT_OBSERVED", f"{sample_id}: write prefix source must be NOT_OBSERVED")
        if sample_id in EXPECTED_SAMPLE_SYSCALLS:
            require(errors, EXPECTED_SAMPLE_SYSCALLS[sample_id] <= expected, f"{sample_id}: expected syscall coverage incomplete")
        if sample_id == "dynamic_executable_memory":
            require(errors, row.get("mmap_mprotect_behavior_node") is True, "dynamic_executable_memory: behavior node missing")
        if sample_id == "anti_debug_like":
            require(errors, row.get("anti_analysis_behavior_node") is True, "anti_debug_like: behavior node missing")


def check_fd_graph(errors: list[str], fd_summary: dict[str, Any]) -> None:
    rows = sample_rows(fd_summary)
    require_sample_set(errors, "fd_path_graph", rows)
    for sample_id, row in rows.items():
        graph = row.get("graph") if isinstance(row.get("graph"), dict) else {}
        if row.get("has_openat") or row.get("has_execve"):
            require(errors, bool(as_list(graph.get("nodes"))), f"{sample_id}: fd/path graph nodes required")
        require(errors, row.get("fd_graph_complete") is True, f"{sample_id}: fd graph must be complete")
        require(errors, int(row.get("unresolved_fd_count") or 0) == 0, f"{sample_id}: unresolved_fd_count must be 0")


def check_source_sidecar(errors: list[str], root: Path, current_root: Path, source_summary: dict[str, Any]) -> None:
    rows = sample_rows(source_summary)
    require_sample_set(errors, "source_line_attribution", rows)
    sidecar_path = current_root / "source_line_sidecar.json"
    if not sidecar_path.is_file():
        errors.append(f"source sidecar missing: {sidecar_path}")
        return
    sidecar = load_json(sidecar_path)
    require(errors, int(sidecar.get("expected_key_events") or 0) > 0, "source sidecar expected_key_events must be positive")
    require(errors, sidecar.get("expected_key_events") == sidecar.get("mapped_key_events"), "source sidecar must map every expected event")
    sidecar_rows = sample_rows(sidecar)
    require_sample_set(errors, "source_line_sidecar", sidecar_rows)
    for sample_id in ALL_CCFA_SAMPLES:
        row = rows.get(sample_id, {})
        require_file(errors, root, row.get("source_line_sidecar"), f"{sample_id}.source_line_sidecar")
        sidecar_row = sidecar_rows.get(sample_id, {})
        require(errors, sidecar_row.get("expected_key_events") == sidecar_row.get("mapped_key_events"), f"{sample_id}: sidecar mapped count mismatch")
        require(errors, float(sidecar_row.get("source_line_rate") or 0.0) >= 1.0, f"{sample_id}: source_line_rate must be 1.0")
        require_file(errors, root, sidecar_row.get("source"), f"{sample_id}.source")
        for event in as_list(sidecar_row.get("events")):
            if not isinstance(event, dict):
                errors.append(f"{sample_id}: sidecar event must be an object")
                continue
            require(errors, isinstance(event.get("line"), int) and int(event["line"]) > 0, f"{sample_id}: sidecar event line must be positive")


def check_source_line_toolchain_probe(errors: list[str], probe: dict[str, Any]) -> None:
    toolchain = probe.get("toolchain") if isinstance(probe.get("toolchain"), dict) else {}
    require(errors, toolchain.get("docker_service") == "linux-behavior", "source-line probe must use linux-behavior service")
    require(errors, "riscv64-linux-gnu-gcc" in str(toolchain.get("compiler") or ""), "source-line probe compiler version missing")
    require(errors, "addr2line" in str(toolchain.get("addr2line") or "").lower(), "source-line probe addr2line version missing")
    probe_row = probe.get("probe") if isinstance(probe.get("probe"), dict) else {}
    require(errors, probe_row.get("debug_sections_present") is True, "source-line probe debug sections missing")
    debug_sections = {str(item) for item in as_list(probe_row.get("debug_section_names"))}
    require(errors, ".debug_line" in debug_sections, "source-line probe .debug_line missing")
    require(errors, probe_row.get("addr2line_source_line_available") is True, "source-line probe addr2line mapping missing")
    require(errors, int(probe_row.get("source_location_count") or 0) > 0, "source-line probe source_location_count must be positive")
    boundary = probe.get("claim_boundary") if isinstance(probe.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("toolchain_source_line_probe_passed") is True, "source-line probe pass boundary missing")
    require(errors, boundary.get("debug_counterpart_source_line_available") is True, "source-line probe debug counterpart boundary missing")
    require(errors, boundary.get("current_board_elf_dwarf_available") is False, "current board ELF DWARF must not be claimed")
    require(errors, boundary.get("current_board_trace_source_line_available") is False, "current board trace source-line must not be claimed")
    require(errors, boundary.get("board_rerun_required_for_board_native_source_lines") is True, "source-line probe rerun boundary missing")
    board_rows = as_list(probe.get("current_board_elfs"))
    require(errors, len(board_rows) >= 4, "source-line probe must inspect current board ELFs")
    for row in board_rows:
        if not isinstance(row, dict):
            errors.append("source-line probe board rows must be objects")
            continue
        require(errors, row.get("exists") is True, f"{row.get('id')}: board ELF must exist")
        require(errors, row.get("debug_sections_present") is False, f"{row.get('id')}: current board ELF must not have DWARF debug sections")


def check_process_maps(errors: list[str], root: Path, process_summary: dict[str, Any]) -> None:
    rows = sample_rows(process_summary)
    require_sample_set(errors, "process_elf_ownership", rows)
    for sample_id, row in rows.items():
        data = require_json_file(errors, root, row.get("runtime_process_map"), f"{sample_id}.runtime_process_map")
        if data is None:
            continue
        require(errors, data.get("schema") == "rvmt.runtime_process_map.v1", f"{sample_id}: runtime process map schema mismatch")
        require(errors, data.get("status") == "PASS", f"{sample_id}: runtime process map status must be PASS")
        owners = data.get("owners") if isinstance(data.get("owners"), dict) else {}
        target = owners.get("target_child") if isinstance(owners.get("target_child"), dict) else {}
        require(errors, target.get("status") == "PASS", f"{sample_id}: target_child owner must be PASS")
        require(errors, bool(as_list(target.get("maps"))), f"{sample_id}: target_child maps must be non-empty")
        require(errors, str(row.get("sample_id")) == str(data.get("sample_id")), f"{sample_id}: runtime process map sample_id mismatch")


def check_bram_and_drop_roots(errors: list[str], root: Path, latest: dict[str, Any], safe_bram: dict[str, Any], p0_bram: dict[str, Any], drop: dict[str, Any]) -> None:
    active_roots = latest.get("active_run_roots") if isinstance(latest.get("active_run_roots"), dict) else {}
    require(errors, latest.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "latest_manifest canonical_evaluation_root must be current")
    policy = latest.get("policy") if isinstance(latest.get("policy"), dict) else {}
    require(errors, policy.get("latest_is_authoritative") is True, "latest_manifest must make latest authoritative")
    require(errors, policy.get("dated_run_roots_are_provenance_only") is True, "latest_manifest must make dated run roots provenance-only")
    require(errors, policy.get("do_not_select_by_chronological_order") is True, "latest_manifest must reject chronological run-root selection")
    run_root = str(safe_bram.get("run_root") or "")
    require(errors, run_root == active_roots.get("safe_surrogate_bram_repetitions"), "safe BRAM summary must match latest manifest")
    require_file(errors, root, safe_bram.get("bitstream"), "safe_bram.bitstream")
    require_file(errors, root, safe_bram.get("ltx"), "safe_bram.ltx")
    require(errors, str(drop.get("safe_surrogate_bram_run_root") or "") == run_root, "drop accounting safe BRAM run root must match safe BRAM summary")
    p0_run_root = str(p0_bram.get("run_root") or "")
    require(errors, p0_run_root == active_roots.get("p0_bram_repetitions"), "P0 BRAM summary must match latest manifest")
    require_file(errors, root, p0_bram.get("bitstream"), "p0_bram.bitstream")
    require_file(errors, root, p0_bram.get("ltx"), "p0_bram.ltx")
    require(errors, str(drop.get("p0_bram_run_root") or "") == p0_run_root, "drop accounting P0 BRAM run root must match P0 BRAM summary")
    require(errors, str(drop.get("p0_run_root") or "") == active_roots.get("p0_continuous_trace"), "drop accounting P0 continuous root must match latest manifest")


def check_runtime_benchmark(errors: list[str], root: Path, runtime: dict[str, Any]) -> None:
    expected_modes = {"trace_off", "event_only", "bram_ring", "pointer_snapshot_disabled"}
    min_reps = int(runtime.get("minimum_repetitions_per_mode_sample") or 0)
    require(errors, min_reps >= 3, "runtime benchmark must use at least 3 repetitions per sample/mode")
    run_root = runtime.get("run_root")
    if run_root:
        require(errors, rel_or_abs(root, run_root).is_dir(), f"production_runtime_benchmark.run_root missing: {run_root}")
    else:
        errors.append("production_runtime_benchmark.run_root missing")
    rows = sample_rows(runtime)
    missing = [sample for sample in SAFE_SURROGATE_SAMPLES if sample not in rows]
    extra = [sample for sample in rows if sample not in SAFE_SURROGATE_SAMPLES]
    require(errors, not missing, f"production_runtime_benchmark: missing safe samples: {', '.join(missing)}")
    require(errors, not extra, f"production_runtime_benchmark: unexpected samples: {', '.join(extra)}")
    mode_stats = runtime.get("mode_stats") if isinstance(runtime.get("mode_stats"), dict) else {}
    for mode in expected_modes:
        stats = mode_stats.get(mode) if isinstance(mode_stats.get(mode), dict) else {}
        require(errors, int(stats.get("count") or 0) >= len(SAFE_SURROGATE_SAMPLES) * min_reps, f"runtime mode {mode}: aggregate count below goal")
        for key in ("median_ns", "p95_ns", "variance_ns2"):
            require(errors, stats.get(key) is not None, f"runtime mode {mode}: {key} missing")
    raw = as_list(runtime.get("raw_repetitions"))
    require(errors, len(raw) >= len(SAFE_SURROGATE_SAMPLES) * len(expected_modes) * min_reps, "runtime raw repetition count below goal")
    for row in raw:
        if not isinstance(row, dict):
            errors.append("runtime raw repetition row must be object")
            continue
        require(errors, int(row.get("duration_ns") or 0) > 0, "runtime raw repetition duration must be positive")
        require(errors, int(row.get("rc") or 0) == 0, "runtime raw repetition rc must be 0")
        require_file(errors, root, row.get("program_log"), "runtime raw repetition program_log")
    for sample_id in SAFE_SURROGATE_SAMPLES:
        sample = rows.get(sample_id, {})
        modes = sample.get("modes") if isinstance(sample.get("modes"), dict) else {}
        require(errors, expected_modes <= set(modes), f"{sample_id}: runtime modes missing")
        for mode in expected_modes:
            row = modes.get(mode) if isinstance(modes.get(mode), dict) else {}
            require(errors, int(row.get("count") or 0) >= min_reps, f"{sample_id}/{mode}: count below goal")
            for key in ("median_ns", "p95_ns", "variance_ns2"):
                require(errors, row.get(key) is not None, f"{sample_id}/{mode}: {key} missing")
            if mode != "trace_off":
                require(errors, row.get("slowdown_vs_trace_off_median") is not None, f"{sample_id}/{mode}: median slowdown missing")


def check_resource_timing(errors: list[str], root: Path, resource: dict[str, Any], runtime: dict[str, Any]) -> None:
    require(errors, resource.get("status") == "PASS", "resource timing status must be PASS")
    bitstream = require_file(errors, root, resource.get("trace_bitstream"), "resource_timing.trace_bitstream")
    if bitstream is not None:
        require(
            errors,
            resource.get("trace_bitstream_sha256") == sha256_file(bitstream),
            "resource_timing.trace_bitstream_sha256 mismatch",
        )
    ltx = require_file(errors, root, resource.get("ltx"), "resource_timing.ltx")
    if ltx is not None:
        require(errors, resource.get("ltx_sha256") == sha256_file(ltx), "resource_timing.ltx_sha256 mismatch")
    marker = resource.get("marker_window_cycle_summary") if isinstance(resource.get("marker_window_cycle_summary"), dict) else {}
    require(errors, marker.get("unit") == "trace-cycle-or-index-delta", "resource timing marker unit mismatch")
    require(errors, marker.get("median") is not None, "resource timing marker median missing")
    require(errors, marker.get("p95") is not None, "resource timing marker p95 missing")
    slowdown = resource.get("production_runtime_slowdown") if isinstance(resource.get("production_runtime_slowdown"), dict) else {}
    require(
        errors,
        resource.get("production_runtime_benchmark") == "results/evaluation/genesys2-cva6/current/production_runtime_benchmark.json",
        "resource timing must reference current production_runtime_benchmark",
    )
    require(
        errors,
        slowdown.get("benchmark") == "results/evaluation/genesys2-cva6/current/production_runtime_benchmark.json",
        "runtime slowdown rollup must reference current production_runtime_benchmark",
    )
    require(errors, slowdown.get("board_execution_smoke_claimed") is True, "runtime benchmark should remain a board execution smoke claim")
    metric = str(runtime.get("metric") or "")
    require(errors, slowdown.get("metric") == metric, "runtime slowdown metric must match production benchmark metric")
    if metric == UART_WALL_CLOCK_RUNTIME_METRIC:
        require(errors, slowdown.get("claimed") is False, "UART wall-clock markers must not be claimed as runtime slowdown")
        require(errors, slowdown.get("cycle_level_overhead_claimed") is False, "UART wall-clock markers must not be cycle-level overhead")
        require(errors, slowdown.get("production_runtime_slowdown_claimed") is False, "UART wall-clock markers must not claim production slowdown")
        boundary = slowdown.get("claim_boundary") if isinstance(slowdown.get("claim_boundary"), dict) else {}
        require(errors, boundary.get("wall_clock_uart_marker_metric") is True, "runtime claim boundary must identify UART wall-clock metric")
        require(errors, boundary.get("uart_wall_clock_promoted_to_overhead_claim") is False, "UART metric must not be promoted to overhead")
        require(
            errors,
            boundary.get("requires_native_cycle_or_hardware_counter_artifact") is True,
            "runtime claim boundary must require cycle/native counter evidence",
        )
        non_claims = " ".join(str(item).lower() for item in as_list(slowdown.get("non_claims")))
        require(errors, "not a cycle-level" in non_claims, "runtime slowdown non-claims must reject cycle-level promotion")
        scope = str(resource.get("runtime_overhead_scope") or "").lower()
        require(errors, "smoke" in scope and "not claimed" in scope, "runtime overhead scope must be smoke-only/non-claim")


def check_hardware_pointer_prefixes(errors: list[str], latest: dict[str, Any], pointer_prefix: dict[str, Any]) -> None:
    active_roots = latest.get("active_run_roots") if isinstance(latest.get("active_run_roots"), dict) else {}
    require(
        errors,
        str(pointer_prefix.get("run_root") or "") == active_roots.get("pointer_snapshot_bram"),
        "hardware pointer prefix summary must match latest manifest pointer_snapshot_bram root",
    )
    require(errors, pointer_prefix.get("trace_sink_mode") == "bram_ring", "hardware pointer prefix trace_sink_mode must be bram_ring")
    require(errors, pointer_prefix.get("hardware_pointer_bytes_observed") is True, "hardware pointer prefix bytes must be observed")
    require(errors, pointer_prefix.get("hardware_pointer_prefixes_claimed") is True, "hardware pointer prefixes must be claimed")
    require(errors, pointer_prefix.get("hardware_pointer_strings_claimed") is False, "hardware pointer strings must not be claimed")
    require(errors, pointer_prefix.get("full_string_claimed") is False, "full pointer strings must not be claimed")
    require(errors, pointer_prefix.get("companion_derived_strings_as_hardware") is False, "companion strings must not be promoted to hardware")
    require(errors, int(pointer_prefix.get("total_repetitions") or 0) >= 30, "hardware pointer prefix repetitions below goal")
    require(errors, int(pointer_prefix.get("pointer_group_count") or 0) > 0, "hardware pointer prefix group count must be positive")
    require(errors, int(pointer_prefix.get("captured_byte_count") or 0) > 0, "hardware pointer prefix captured bytes must be positive")
    require(errors, int(pointer_prefix.get("kernel_fragment_count") or 0) == 0, "hardware pointer prefix kernel fragments must be zero")
    coverage = pointer_prefix.get("required_syscall_coverage") if isinstance(pointer_prefix.get("required_syscall_coverage"), dict) else {}
    for syscall in ("openat", "write", "execve"):
        require(errors, coverage.get(syscall) is True, f"hardware pointer prefix coverage missing: {syscall}")
    non_claims = " ".join(str(item).lower() for item in as_list(pointer_prefix.get("non_claims")))
    require(errors, "does not preserve full pointer strings" in non_claims, "hardware pointer prefix non-claims must reject full strings")
    require(errors, "not reported as hardware-derived pointer strings" in non_claims, "hardware pointer prefix non-claims must reject companion promotion")


def check_benign_control(errors: list[str], root: Path, benign: dict[str, Any], behavior: dict[str, Any]) -> None:
    require(errors, benign.get("run_root"), "benign control run_root missing")
    if benign.get("run_root"):
        require(errors, rel_or_abs(root, benign.get("run_root")).is_dir(), f"benign control run root missing: {benign.get('run_root')}")
    aggregate = benign.get("aggregate") if isinstance(benign.get("aggregate"), dict) else {}
    fp_rate = float(aggregate.get("benign_false_positive_rate") or 0.0)
    require(errors, int(aggregate.get("sample_count") or 0) >= 5, "benign control must include at least five samples")
    require(errors, int(aggregate.get("non_network_sample_count") or 0) >= 5, "benign control must include at least five non-network samples")
    require(errors, int(aggregate.get("unexpected_false_positive_count") or 0) == 0, "benign control unexpected false positives must be zero")
    require(errors, fp_rate == 0.0, "benign control false-positive rate must be 0.0")
    behavior_metrics = behavior.get("metrics") if isinstance(behavior.get("metrics"), dict) else {}
    require(
        errors,
        float(behavior_metrics.get("benign_false_positive_rate") or 0.0) == fp_rate,
        "behavior metrics benign false-positive rate must match benign control summary",
    )
    require(
        errors,
        str(behavior.get("benign_control_summary") or "") == "results/evaluation/genesys2-cva6/current/benign_control_summary.json",
        "behavior metrics must reference benign_control_summary",
    )
    boundary = benign.get("claim_boundary") if isinstance(benign.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("local_linux_behavior_control") is True, "benign control local Linux boundary missing")
    require(errors, boundary.get("genesys2_board_trace_claimed") is False, "benign control must not claim Genesys2 board trace")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "benign control must not claim real malware validation")
    rows = benign.get("samples") if isinstance(benign.get("samples"), list) else []
    require(errors, len(rows) >= 5, "benign control sample rows missing")
    for row in rows:
        if not isinstance(row, dict):
            errors.append("benign control sample row must be object")
            continue
        sample_id = str(row.get("sample_id") or "")
        require(errors, row.get("sample_class") == "benign", f"{sample_id}: benign control sample_class must be benign")
        require(errors, row.get("status") == "PASS", f"{sample_id}: benign control sample status must be PASS")
        require(errors, row.get("false_positive") is False, f"{sample_id}: benign control false_positive must be false")
        require(errors, not as_list(row.get("unexpected_matched_rules")), f"{sample_id}: benign control unexpected matches must be empty")
        for key in ("strace_log", "semantic_events", "behavior_graph", "behavior_audit"):
            require_file(errors, root, row.get(key), f"{sample_id}.benign_control.{key}")


def check_reproducibility_manifest(errors: list[str], repro: dict[str, Any]) -> None:
    require(errors, repro.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "reproducibility canonical root mismatch")
    boundary = repro.get("claim_boundary") if isinstance(repro.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("controlled_safe_surrogate_evidence") is True, "reproducibility manifest must mark controlled safe/surrogate evidence")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "reproducibility manifest must not claim real malware validation")
    if boundary.get("hardware_full_pointer_strings_claimed") is True:
        require(
            errors,
            boundary.get("external_full_hardware_pointer_strings_summary_accepted") is True,
            "reproducibility manifest may claim full hardware pointer strings only after accepted external intake",
        )
    else:
        require(errors, boundary.get("hardware_full_pointer_strings_claimed") is False, "reproducibility manifest full pointer-string claim must be boolean false or accepted true")
    require(errors, boundary.get("production_streaming_dma_throughput_claimed") is False, "reproducibility manifest must not claim production streaming/DMA throughput")
    summary_ids = {
        str(row.get("id"))
        for row in as_list(repro.get("summary_artifacts"))
        if isinstance(row, dict) and row.get("id")
    }
    for summary_id in (
        "latest_manifest",
        "hardware_pointer_prefixes",
        "ccfa_evaluation_matrix",
        "behavior_audit_metrics",
        "statistical_robustness",
        "case_study_manifest",
        "review_closure_audit",
        "external_closure_intake",
        "external_closure_plan",
        "external_closure_preflight",
        "external_operator_packet",
    ):
        require(errors, summary_id in summary_ids, f"reproducibility summary artifact missing: {summary_id}")
    raw_ids = {
        str(row.get("id"))
        for row in as_list(repro.get("raw_artifact_roots"))
        if isinstance(row, dict) and row.get("id")
    }
    for raw_id in ("p0_bram_repetitions", "safe_surrogate_bram_repetitions", "pointer_snapshot_bram"):
        require(errors, raw_id in raw_ids, f"reproducibility raw root missing: {raw_id}")
    commands = " ".join(str(item) for item in as_list(repro.get("validation_commands")))
    require(errors, "genesys2-current" in commands, "reproducibility commands must include genesys2-current")


def check_artifact_package(errors: list[str], root: Path, package: dict[str, Any]) -> None:
    require(errors, package.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "artifact package canonical root mismatch")
    require(errors, package.get("generated_from") == "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json", "artifact package generated_from mismatch")
    fresh = package.get("fresh_clone_reproduction") if isinstance(package.get("fresh_clone_reproduction"), dict) else {}
    require(errors, fresh.get("script") == "tools/reproduce_genesys2_current.py", "artifact package reproduction script mismatch")
    require(errors, fresh.get("requires_board_or_vivado") is False, "artifact package reproduction must not require board/Vivado")
    require(errors, fresh.get("requires_network") is False, "artifact package reproduction must not require network")
    commands = " ".join(str(value) for value in [fresh.get("quick_command"), fresh.get("full_command"), *as_list(package.get("validation_commands"))])
    require(errors, "tools/reproduce_genesys2_current.py --quick" in commands, "artifact package quick reproduction command missing")
    require(errors, "tools/reproduce_genesys2_current.py --full" in commands, "artifact package full reproduction command missing")
    included = {
        str(row.get("path")): row
        for row in as_list(package.get("included_files"))
        if isinstance(row, dict) and row.get("path")
    }
    for path_value in (
        "tools/reproduce_genesys2_current.py",
        "tools/check_genesys2_artifact_package.py",
        "tools/package_genesys2_artifact_package.py",
        "tools/check_ccfa_current_quality.py",
        "tools/package_genesys2_reproducibility_manifest.py",
        "tools/check_genesys2_reproducibility_manifest.py",
        "tools/package_genesys2_statistical_robustness.py",
        "tools/check_genesys2_statistical_robustness.py",
        "tools/package_ccfa_case_study_manifest.py",
        "tools/check_ccfa_case_study_manifest.py",
        "tools/package_genesys2_external_closure_intake.py",
        "tools/check_genesys2_external_closure_intake.py",
        "tools/package_genesys2_external_closure_plan.py",
        "tools/check_genesys2_external_closure_plan.py",
        "tools/package_genesys2_external_closure_preflight.py",
        "tools/check_genesys2_external_closure_preflight.py",
        "tools/prepare_genesys2_external_summary.py",
        "tools/package_genesys2_external_operator_packet.py",
        "tools/check_genesys2_external_operator_packet.py",
        "tools/package_genesys2_review_closure_audit.py",
        "tools/check_genesys2_review_closure_audit.py",
        "results/evaluation/genesys2-cva6/current/review_closure_audit.json",
        "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json",
        "results/evaluation/genesys2-cva6/current/external_closure_preflight.json",
        "results/evaluation/genesys2-cva6/current/external_operator_packet.json",
        "docs/07-evaluation-evidence/reports/ccfa_external_operator_packet.md",
        "docs/07-evaluation-evidence/reports/ccfa_review_closure_audit.md",
        "docs/07-evaluation-evidence/reports/ccfa_readiness_matrix.md",
    ):
        row = included.get(path_value)
        require(errors, row is not None, f"artifact package included file missing: {path_value}")
        if row is None:
            continue
        if "git_publishable" in row:
            require(errors, row.get("git_publishable") is True, f"artifact package file is not git-publishable: {path_value}")
        path = require_file(errors, root, path_value, f"artifact_package.{path_value}")
        if path is not None:
            require(errors, row.get("sha256") == sha256_file(path), f"artifact package sha256 mismatch: {path_value}")
    raw_roots = {
        str(row.get("id")): row
        for row in as_list(package.get("referenced_raw_artifact_roots"))
        if isinstance(row, dict) and row.get("id")
    }
    for raw_id in ("p0_bram_repetitions", "safe_surrogate_bram_repetitions", "pointer_snapshot_bram"):
        row = raw_roots.get(raw_id)
        require(errors, row is not None, f"artifact package raw root missing: {raw_id}")
        if row is None:
            continue
        require(errors, row.get("exists") is True, f"artifact package raw root must exist: {raw_id}")
        policy = str(row.get("release_policy") or "").lower()
        require(errors, "not copied" in policy, f"artifact package raw root policy must avoid copying: {raw_id}")
    boundary = package.get("claim_boundary") if isinstance(package.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("fresh_clone_reproduction_script_available") is True, "artifact package fresh-clone boundary missing")
    require(errors, boundary.get("lightweight_manifest_package") is True, "artifact package lightweight boundary missing")
    require(errors, boundary.get("raw_board_artifacts_copied") is False, "artifact package must not copy raw board artifacts")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "artifact package must not claim real malware validation")


def check_external_closure_readiness(errors: list[str], root: Path, readiness: dict[str, Any]) -> None:
    expected_statuses = {
        "board_native_dwarf_source_lines": "EXTERNAL_BOARD_RERUN_READY_NOT_EXECUTED",
        "full_hardware_pointer_strings": "RTL_EXTENSION_REQUIRED_NOT_EXECUTED",
        "production_streaming_dma_trace_sink": "STREAMING_DMA_EXPERIMENT_REQUIRED_NOT_EXECUTED",
        "genesys2_board_benign_control": "BOARD_BENIGN_CONTROL_RUN_REQUIRED_NOT_EXECUTED",
    }
    boundary = readiness.get("claim_boundary") if isinstance(readiness.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("readiness_contract_only") is True, "external closure readiness must be contract-only")
    for key in (
        "real_malware_validation_claimed",
        "hardware_full_pointer_strings_claimed",
        "production_streaming_dma_throughput_claimed",
        "board_native_source_line_attribution_claimed",
        "genesys2_board_benign_control_claimed",
    ):
        require(errors, boundary.get(key) is False, f"external closure readiness must not claim {key}")
    require(errors, boundary.get("current_board_elf_dwarf_available") is False, "external closure readiness must preserve no-DWARF current board ELF boundary")
    require(errors, boundary.get("current_board_trace_source_line_available") is False, "external closure readiness must preserve no board trace source-line boundary")
    require(errors, boundary.get("full_string_claimed") is False, "external closure readiness must preserve no full-string boundary")
    records = {
        str(row.get("id")): row
        for row in as_list(readiness.get("records"))
        if isinstance(row, dict) and row.get("id")
    }
    missing = sorted(set(expected_statuses) - set(records))
    extra = sorted(set(records) - set(expected_statuses))
    require(errors, not missing, f"external closure readiness missing records: {', '.join(missing)}")
    require(errors, not extra, f"external closure readiness unexpected records: {', '.join(extra)}")
    require(errors, int(readiness.get("external_blocker_count") or 0) == len(expected_statuses), "external closure blocker count mismatch")
    for record_id, status in expected_statuses.items():
        record = records.get(record_id, {})
        require(errors, record.get("readiness_status") == status, f"{record_id}: readiness status mismatch")
        require(errors, record.get("current_blocker") is True, f"{record_id}: current_blocker must be true")
        require(errors, record.get("completion_requires_external_state") is True, f"{record_id}: external-state requirement missing")
        require(errors, record.get("external_evidence_claimed") is False, f"{record_id}: external evidence must not be claimed")
        require(errors, len(as_list(record.get("required_external_artifacts"))) >= 4, f"{record_id}: external artifacts under-specified")
        require(errors, len(as_list(record.get("acceptance_criteria"))) >= 4, f"{record_id}: acceptance criteria under-specified")
        no_sub = str(record.get("no_substitution_rule") or "").lower()
        require(errors, "must not" in no_sub and "substitut" in no_sub, f"{record_id}: no-substitution rule is too weak")
        for index, evidence in enumerate(as_list(record.get("existing_evidence")), start=1):
            if not isinstance(evidence, dict):
                errors.append(f"{record_id}: evidence row {index} must be object")
                continue
            path_value = evidence.get("path")
            require(errors, evidence.get("exists") is True, f"{record_id}: evidence row {index} must exist")
            if path_value:
                require_file(errors, root, path_value, f"{record_id}.existing_evidence.{index}")
    interpretation = " ".join(str(item).lower() for item in as_list(readiness.get("interpretation")))
    require(errors, "does not upgrade current evidence" in interpretation, "external closure readiness interpretation must avoid evidence upgrade")


def check_external_closure_intake(errors: list[str], intake: dict[str, Any]) -> None:
    expected_paths = {
        "board_native_dwarf_source_lines": "results/evaluation/genesys2-cva6/current/external_closure/board_native_source_lines_summary.json",
        "full_hardware_pointer_strings": "results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json",
        "production_streaming_dma_trace_sink": "results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json",
        "genesys2_board_benign_control": "results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json",
    }
    boundary = intake.get("claim_boundary") if isinstance(intake.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("intake_gate_only") is True, "external closure intake must be an intake-only gate")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "external closure intake must not claim real malware validation")
    require(errors, boundary.get("unvalidated_external_summary_accepted") is False, "external closure intake must reject unvalidated summaries")
    require(errors, intake.get("external_summary_root") == "results/evaluation/genesys2-cva6/current/external_closure", "external closure intake root mismatch")
    require(errors, intake.get("closure_status") in {"OPEN_EXTERNAL_ARTIFACTS_REQUIRED", "ALL_NON_REAL_EXTERNAL_SUMMARIES_ACCEPTED"}, "external closure intake status mismatch")
    records = {
        str(row.get("id")): row
        for row in as_list(intake.get("records"))
        if isinstance(row, dict) and row.get("id")
    }
    missing = sorted(set(expected_paths) - set(records))
    extra = sorted(set(records) - set(expected_paths))
    require(errors, not missing, f"external closure intake missing records: {', '.join(missing)}")
    require(errors, not extra, f"external closure intake unexpected records: {', '.join(extra)}")
    accepted = open_count = invalid = 0
    for record_id, expected_path in expected_paths.items():
        record = records.get(record_id, {})
        require(errors, record.get("external_summary_path") == expected_path, f"{record_id}: external summary path mismatch")
        require(errors, record.get("acceptance_checker") == "tools/check_genesys2_external_closure_intake.py", f"{record_id}: intake checker mismatch")
        status = record.get("completion_status")
        valid = record.get("completion_evidence_valid")
        exists = record.get("external_summary_exists")
        if status == "EXTERNAL_SUMMARY_ACCEPTED":
            accepted += 1
            require(errors, exists is True and valid is True, f"{record_id}: accepted summary must exist and be valid")
            require(errors, record.get("current_blocker") is False, f"{record_id}: accepted summary should clear blocker")
        elif status == "OPEN_NO_EXTERNAL_SUMMARY":
            open_count += 1
            require(errors, exists is False and valid is False, f"{record_id}: open summary must be absent and invalid")
            require(errors, record.get("current_blocker") is True, f"{record_id}: open summary remains blocked")
        elif status == "EXTERNAL_SUMMARY_PRESENT_INVALID":
            invalid += 1
            require(errors, exists is True and valid is False, f"{record_id}: invalid summary must exist and be invalid")
            require(errors, bool(as_list(record.get("validation_errors"))), f"{record_id}: invalid summary must record errors")
        else:
            errors.append(f"{record_id}: unexpected completion_status {status!r}")
        no_sub = str(record.get("no_substitution_rule") or "").lower()
        require(errors, "must not" in no_sub and "substitut" in no_sub, f"{record_id}: intake no-substitution rule is too weak")
    require(errors, intake.get("accepted_external_blocker_count") == accepted, "external closure intake accepted count mismatch")
    require(errors, intake.get("open_external_blocker_count") == open_count, "external closure intake open count mismatch")
    require(errors, intake.get("invalid_external_blocker_count") == invalid, "external closure intake invalid count mismatch")
    expected_status = "PASS" if accepted == len(expected_paths) and open_count == 0 and invalid == 0 else "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED"
    require(errors, intake.get("status") == expected_status, "external closure intake status/count mismatch")
    if open_count or invalid:
        require(errors, intake.get("closure_status") == "OPEN_EXTERNAL_ARTIFACTS_REQUIRED", "external closure intake must remain open while summaries are absent")
    commands = " ".join(str(item) for item in as_list(intake.get("validation_commands")))
    require(errors, "tools/check_genesys2_external_closure_intake.py --root ." in commands, "external closure intake validation command missing")


def check_external_closure_plan(errors: list[str], root: Path, plan: dict[str, Any]) -> None:
    expected_paths = {
        "board_native_dwarf_source_lines": "results/evaluation/genesys2-cva6/current/external_closure/board_native_source_lines_summary.json",
        "full_hardware_pointer_strings": "results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json",
        "production_streaming_dma_trace_sink": "results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json",
        "genesys2_board_benign_control": "results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json",
    }
    boundary = plan.get("claim_boundary") if isinstance(plan.get("claim_boundary"), dict) else {}
    require(errors, "real_malware_validation" in as_list(plan.get("objective_exclusions")), "external closure plan real-malware exclusion missing")
    require(errors, boundary.get("plan_only") is True, "external closure plan must be plan-only")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "external closure plan must not claim real malware validation")
    require(errors, boundary.get("external_execution_completed") is False, "external closure plan must not claim external execution")
    require(errors, boundary.get("all_non_real_external_blockers_closed") is False, "external closure plan must keep blockers open")
    sources = {
        str(row.get("id")): row
        for row in as_list(plan.get("source_artifacts"))
        if isinstance(row, dict) and row.get("id")
    }
    for source_id, expected_schema, expected_path in (
        (
            "external_closure_readiness",
            "rvmt.genesys2.external_closure_readiness.v1",
            "results/evaluation/genesys2-cva6/current/external_closure_readiness.json",
        ),
        (
            "external_closure_intake",
            "rvmt.genesys2.external_closure_intake.v1",
            "results/evaluation/genesys2-cva6/current/external_closure_intake.json",
        ),
    ):
        check_source_artifact_row(
            errors,
            root,
            sources.get(source_id),
            context=f"external_closure_plan.{source_id}",
            expected_schema=expected_schema,
            expected_path=expected_path,
        )
    records = {
        str(row.get("id")): row
        for row in as_list(plan.get("records"))
        if isinstance(row, dict) and row.get("id")
    }
    missing = sorted(set(expected_paths) - set(records))
    extra = sorted(set(records) - set(expected_paths))
    require(errors, not missing, f"external closure plan missing records: {', '.join(missing)}")
    require(errors, not extra, f"external closure plan unexpected records: {', '.join(extra)}")
    for record_id, path_value in expected_paths.items():
        record = records.get(record_id, {})
        require(errors, record.get("external_summary_path") == path_value, f"{record_id}: plan summary path mismatch")
        require(errors, record.get("plan_status") in {"READY_TO_EXECUTE_WITH_EXTERNAL_STATE", "EXTERNAL_SUMMARY_ACCEPTED", "NEEDS_EXTERNAL_SUMMARY_CORRECTION"}, f"{record_id}: plan status mismatch")
        require(errors, len(as_list(record.get("operator_inputs"))) >= 3, f"{record_id}: operator inputs under-specified")
        require(errors, len(as_list(record.get("preflight_commands"))) >= 2, f"{record_id}: preflight commands under-specified")
        require(errors, len(as_list(record.get("collection_commands"))) >= 2, f"{record_id}: collection commands under-specified")
        require(errors, len(as_list(record.get("packaging_commands"))) >= 2, f"{record_id}: packaging commands under-specified")
        template = record.get("summary_template") if isinstance(record.get("summary_template"), dict) else {}
        require(errors, template.get("status") == "TEMPLATE_NOT_EVIDENCE", f"{record_id}: summary template must not be evidence")
        require(errors, template.get("template_only") is True, f"{record_id}: summary template must be template_only")
        no_sub = str(record.get("no_substitution_rule") or "").lower()
        require(errors, "must not" in no_sub and "substitut" in no_sub, f"{record_id}: plan no-substitution rule is too weak")
        exits = " ".join(str(item) for item in as_list(record.get("exit_criteria")))
        require(errors, "EXTERNAL_SUMMARY_ACCEPTED" in exits and "completion_evidence_valid=true" in exits, f"{record_id}: exit criteria incomplete")
    commands = " ".join(str(item) for item in as_list(plan.get("validation_commands")))
    require(errors, "tools/check_genesys2_external_closure_plan.py --root ." in commands, "external closure plan validation command missing")
    interpretation = " ".join(str(item).lower() for item in as_list(plan.get("interpretation")))
    require(errors, "templates are not evidence" in interpretation, "external closure plan must say templates are not evidence")


def check_external_closure_preflight(errors: list[str], root: Path, preflight: dict[str, Any]) -> None:
    expected_paths = {
        "board_native_dwarf_source_lines": "results/evaluation/genesys2-cva6/current/external_closure/board_native_source_lines_summary.json",
        "full_hardware_pointer_strings": "results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json",
        "production_streaming_dma_trace_sink": "results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json",
        "genesys2_board_benign_control": "results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json",
    }
    boundary = preflight.get("claim_boundary") if isinstance(preflight.get("claim_boundary"), dict) else {}
    require(errors, "real_malware_validation" in as_list(preflight.get("objective_exclusions")), "external closure preflight real-malware exclusion missing")
    require(errors, boundary.get("local_preflight_only") is True, "external closure preflight must be local-preflight-only")
    require(errors, boundary.get("external_execution_completed") is False, "external closure preflight must not claim external execution")
    require(errors, boundary.get("all_non_real_external_blockers_closed") is False, "external closure preflight must keep blockers open")
    for key in (
        "real_malware_validation_claimed",
        "hardware_full_pointer_strings_claimed",
        "production_streaming_dma_throughput_claimed",
        "board_native_source_line_attribution_claimed",
        "genesys2_board_benign_control_claimed",
    ):
        require(errors, boundary.get(key) is False, f"external closure preflight must not claim {key}")
    source_rows = {
        str(row.get("path")): row
        for row in as_list(preflight.get("source_artifacts"))
        if isinstance(row, dict) and row.get("path")
    }
    for expected_path, expected_schema in (
        (
            "results/evaluation/genesys2-cva6/current/external_closure_plan.json",
            "rvmt.genesys2.external_closure_plan.v1",
        ),
        (
            "results/evaluation/genesys2-cva6/current/external_closure_intake.json",
            "rvmt.genesys2.external_closure_intake.v1",
        ),
    ):
        check_source_artifact_row(
            errors,
            root,
            source_rows.get(expected_path),
            context=f"external_closure_preflight.{expected_path}",
            expected_schema=expected_schema,
            expected_path=expected_path,
        )
    records = {
        str(row.get("id")): row
        for row in as_list(preflight.get("records"))
        if isinstance(row, dict) and row.get("id")
    }
    missing = sorted(set(expected_paths) - set(records))
    extra = sorted(set(records) - set(expected_paths))
    require(errors, not missing, f"external closure preflight missing records: {', '.join(missing)}")
    require(errors, not extra, f"external closure preflight unexpected records: {', '.join(extra)}")
    preflight_open = preflight_accepted = preflight_invalid = 0
    for record_id, path_value in expected_paths.items():
        record = records.get(record_id, {})
        require(errors, record.get("status") == "PASS_LOCAL_PREFLIGHT_EXTERNAL_OPEN", f"{record_id}: preflight status mismatch")
        require(errors, record.get("external_summary_path") == path_value, f"{record_id}: preflight summary path mismatch")
        require(errors, record.get("local_preflight_ready") is True, f"{record_id}: local preflight must be ready")
        require(errors, record.get("tool_entrypoints_ready") is True, f"{record_id}: tool entrypoints must be ready")
        require(errors, record.get("schema_path_ready") is True, f"{record_id}: schema path must be ready")
        completion_status = record.get("completion_status")
        if completion_status == "EXTERNAL_SUMMARY_ACCEPTED":
            preflight_accepted += 1
            require(errors, record.get("external_execution_still_required") is False, f"{record_id}: accepted summary should not require external execution")
            require(errors, record.get("external_summary_exists") is True, f"{record_id}: accepted summary must exist")
            require(errors, record.get("current_blocker") is False, f"{record_id}: accepted summary should clear blocker")
        elif completion_status == "EXTERNAL_SUMMARY_PRESENT_INVALID":
            preflight_invalid += 1
            require(errors, record.get("external_execution_still_required") is True, f"{record_id}: invalid summary requires external correction")
            require(errors, record.get("external_summary_exists") is True, f"{record_id}: invalid summary must be retained")
            require(errors, record.get("current_blocker") is True, f"{record_id}: invalid summary remains blocked")
        else:
            preflight_open += 1
            require(errors, completion_status == "OPEN_NO_EXTERNAL_SUMMARY", f"{record_id}: preflight completion status mismatch")
            require(errors, record.get("external_execution_still_required") is True, f"{record_id}: external execution requirement missing")
            require(errors, record.get("external_summary_exists") is False, f"{record_id}: preflight missing summary must be absent")
            require(errors, record.get("current_blocker") is True, f"{record_id}: preflight blocker must remain open")
        require(errors, record.get("no_substitution_rule_present") is True, f"{record_id}: no-substitution rule missing")
        require(errors, int(record.get("operator_input_count") or 0) >= 3, f"{record_id}: operator inputs under-specified")
        require(errors, int(record.get("required_raw_artifact_count") or 0) >= 4, f"{record_id}: raw artifacts under-specified")
        require(errors, int(record.get("acceptance_criteria_count") or 0) >= 4, f"{record_id}: acceptance criteria under-specified")
        for command_group in ("preflight_commands", "collection_commands", "packaging_commands"):
            commands = as_list(record.get(command_group))
            require(errors, len(commands) >= 2, f"{record_id}: {command_group} under-specified")
            for index, command in enumerate(commands, start=1):
                if not isinstance(command, dict):
                    errors.append(f"{record_id}: {command_group}.{index} must be object")
                    continue
                require(errors, command.get("local_preflight_ready") is True, f"{record_id}: {command_group}.{index} is not locally ready")
                require(errors, isinstance(command.get("script"), str) and bool(command.get("script")), f"{record_id}: {command_group}.{index} script marker missing")
                require(errors, isinstance(command.get("script_exists"), bool), f"{record_id}: {command_group}.{index} script_exists marker missing")
                require(errors, command.get("dry_run_supported") in {True, False, "NOT_REQUESTED"}, f"{record_id}: {command_group}.{index} dry-run marker missing")
                require(errors, command.get("code_map_supported") in {True, False, "NOT_REQUESTED"}, f"{record_id}: {command_group}.{index} code-map marker missing")
                if command.get("kind") == "local_tool":
                    require(errors, command.get("script_exists") is True, f"{record_id}: {command_group}.{index} local tool missing")
                    script = str(command.get("script") or "")
                    require(errors, script.startswith("tools/") and script.endswith(".py"), f"{record_id}: {command_group}.{index} local tool script path invalid")
                    if script:
                        require_file(errors, root, script, f"{record_id}.{command_group}.{index}.script")
                    command_text = str(command.get("command") or "")
                    if "--dry-run" in command_text:
                        require(errors, command.get("dry_run_supported") is True, f"{record_id}: {command_group}.{index} dry-run support missing")
                    else:
                        require(errors, command.get("dry_run_supported") == "NOT_REQUESTED", f"{record_id}: {command_group}.{index} dry-run marker must be NOT_REQUESTED")
                    if "--code-map" in command_text:
                        require(errors, command.get("code_map_supported") is True, f"{record_id}: {command_group}.{index} code-map support missing")
                    else:
                        require(errors, command.get("code_map_supported") == "NOT_REQUESTED", f"{record_id}: {command_group}.{index} code-map marker must be NOT_REQUESTED")
                else:
                    require(errors, command.get("script") == "NOT_APPLICABLE", f"{record_id}: {command_group}.{index} operator script marker mismatch")
                    require(errors, command.get("script_exists") is False, f"{record_id}: {command_group}.{index} operator script_exists marker mismatch")
                    require(errors, command.get("dry_run_supported") == "NOT_REQUESTED", f"{record_id}: {command_group}.{index} operator dry-run marker mismatch")
                    require(errors, command.get("code_map_supported") == "NOT_REQUESTED", f"{record_id}: {command_group}.{index} operator code-map marker mismatch")
    require(errors, preflight.get("open_external_blocker_count") == preflight_open, "external closure preflight open count mismatch")
    require(errors, preflight.get("accepted_external_blocker_count") == preflight_accepted, "external closure preflight accepted count mismatch")
    require(errors, preflight.get("invalid_external_blocker_count") == preflight_invalid, "external closure preflight invalid count mismatch")
    commands = " ".join(str(item) for item in as_list(preflight.get("validation_commands")))
    require(errors, "tools/package_genesys2_external_closure_preflight.py" in commands, "external closure preflight packager command missing")
    require(errors, "tools/check_genesys2_external_closure_preflight.py --root ." in commands, "external closure preflight validation command missing")
    require(errors, "tools/check_genesys2_external_closure_plan.py --root ." in commands, "external closure preflight plan validation command missing")
    require(errors, "tools/check_genesys2_external_closure_intake.py --root ." in commands, "external closure preflight intake validation command missing")
    interpretation = " ".join(str(item).lower() for item in as_list(preflight.get("interpretation")))
    require(errors, "does not execute board" in interpretation, "external closure preflight must preserve external execution boundary")
    require(errors, "must not close external blockers" in interpretation, "external closure preflight must reject preflight-as-completion")
    require(errors, "intake gate remains authoritative" in interpretation, "external closure preflight must preserve intake authority")


def check_external_operator_packet(errors: list[str], root: Path, packet: dict[str, Any]) -> None:
    expected = {
        "board_native_dwarf_source_lines": {
            "path": "results/evaluation/genesys2-cva6/current/external_closure/board_native_source_lines_summary.json",
            "template": "results/evaluation/genesys2-cva6/current/external_closure_templates/board_native_source_lines_summary.template.json",
            "readiness": "EXTERNAL_BOARD_RERUN_READY_NOT_EXECUTED",
            "schema": "rvmt.genesys2.board_native_source_lines.v1",
        },
        "full_hardware_pointer_strings": {
            "path": "results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json",
            "template": "results/evaluation/genesys2-cva6/current/external_closure_templates/hardware_pointer_strings_summary.template.json",
            "readiness": "RTL_EXTENSION_REQUIRED_NOT_EXECUTED",
            "schema": "rvmt.genesys2.hardware_pointer_strings.v1",
        },
        "production_streaming_dma_trace_sink": {
            "path": "results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json",
            "template": "results/evaluation/genesys2-cva6/current/external_closure_templates/streaming_dma_throughput_summary.template.json",
            "readiness": "STREAMING_DMA_EXPERIMENT_REQUIRED_NOT_EXECUTED",
            "schema": "rvmt.genesys2.streaming_dma_throughput.v1",
        },
        "genesys2_board_benign_control": {
            "path": "results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json",
            "template": "results/evaluation/genesys2-cva6/current/external_closure_templates/board_benign_control_summary.template.json",
            "readiness": "BOARD_BENIGN_CONTROL_RUN_REQUIRED_NOT_EXECUTED",
            "schema": "rvmt.genesys2.board_benign_control.v1",
        },
    }
    boundary = packet.get("claim_boundary") if isinstance(packet.get("claim_boundary"), dict) else {}
    accepted = int(packet.get("accepted_external_blocker_count") or 0)
    open_count = int(packet.get("open_external_blocker_count") or 0)
    invalid = int(packet.get("invalid_external_blocker_count") or 0)
    require(errors, packet.get("closure_status") in {"OPEN_EXTERNAL_ARTIFACTS_REQUIRED", "ALL_NON_REAL_EXTERNAL_SUMMARIES_ACCEPTED"}, "external operator packet closure status mismatch")
    require(errors, "real_malware_validation" in as_list(packet.get("objective_exclusions")), "external operator packet real-malware exclusion missing")
    require(errors, boundary.get("operator_packet_only") is True, "external operator packet must be packet-only")
    require(errors, boundary.get("external_execution_completed") is False, "external operator packet must not claim external execution")
    require(errors, boundary.get("external_execution_completed_by_packet") is False, "external operator packet must not claim it created external execution")
    require(errors, boundary.get("accepted_external_summaries_present") is (accepted > 0), "external operator packet accepted-summary boundary mismatch")
    require(errors, boundary.get("accepted_external_summaries_hash_validated_by_intake") is (accepted > 0), "external operator packet accepted-summary hash boundary mismatch")
    require(errors, boundary.get("open_or_invalid_external_blockers_remain") is bool(open_count or invalid), "external operator packet open/invalid boundary mismatch")
    require(errors, boundary.get("external_readiness_substituted_for_completion") is False, "external operator packet must reject readiness substitution")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "external operator packet must not claim real malware validation")
    require(errors, boundary.get("templates_treated_as_evidence") is False, "external operator packet must not treat templates as evidence")
    require(errors, boundary.get("external_artifact_paths_scoped_to_external_closure") is True, "external operator packet must scope evidence artifacts to external_closure")
    require(errors, boundary.get("placeholder_values_treated_as_invalid") is True, "external operator packet must reject placeholder values")
    require(errors, accepted + open_count + invalid == len(expected), "external operator packet count mismatch")
    if open_count or invalid:
        require(errors, packet.get("closure_status") == "OPEN_EXTERNAL_ARTIFACTS_REQUIRED", "external operator packet must remain open while summaries are absent")
        require(errors, boundary.get("all_non_real_external_blockers_closed") is False, "external operator packet boundary must keep blockers open")
    sources = packet.get("source_artifacts") if isinstance(packet.get("source_artifacts"), dict) else {}
    for source_id, expected_schema in (
        ("external_closure_readiness", "rvmt.genesys2.external_closure_readiness.v1"),
        ("external_closure_intake", "rvmt.genesys2.external_closure_intake.v1"),
        ("external_closure_plan", "rvmt.genesys2.external_closure_plan.v1"),
        ("external_closure_preflight", "rvmt.genesys2.external_closure_preflight.v1"),
    ):
        row = sources.get(source_id) if isinstance(sources, dict) else None
        require(errors, isinstance(row, dict), f"external operator packet source missing: {source_id}")
        if not isinstance(row, dict):
            continue
        require(errors, row.get("exists") is True, f"external operator packet source must exist: {source_id}")
        require(errors, row.get("expected_schema") == expected_schema, f"external operator packet source expected schema mismatch: {source_id}")
        require(errors, row.get("schema") == expected_schema, f"external operator packet source schema mismatch: {source_id}")
        allowed_status = row.get("status") == "PASS"
        if source_id == "external_closure_intake" and row.get("status") == "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED":
            source_data = require_json_file(errors, root, row.get("path"), f"external_operator_packet.{source_id}.source_status") if row.get("path") else None
            allowed_status = source_data is not None and external_intake_failure_is_truthful(source_data)
        require(errors, allowed_status, f"external operator packet source status mismatch: {source_id}")
        path_value = row.get("path")
        path = require_file(errors, root, path_value, f"external_operator_packet.{source_id}") if path_value else None
        if path is not None:
            require(errors, row.get("sha256") == sha256_file(path), f"external operator packet source sha256 mismatch: {source_id}")
    sequence = " ".join(str(item).lower() for item in as_list(packet.get("operator_sequence")))
    for phrase in (
        "local preflight",
        "board, rtl, or host-transport",
        "candidate summaries",
        "external_closure artifacts",
        "sha256",
        "template placeholders",
        "intake",
    ):
        require(errors, phrase in sequence, f"external operator packet sequence missing: {phrase}")
    records = {
        str(row.get("id")): row
        for row in as_list(packet.get("records"))
        if isinstance(row, dict) and row.get("id")
    }
    missing = sorted(set(expected) - set(records))
    extra = sorted(set(records) - set(expected))
    require(errors, not missing, f"external operator packet missing records: {', '.join(missing)}")
    require(errors, not extra, f"external operator packet unexpected records: {', '.join(extra)}")
    open_records = accepted_records = invalid_records = 0
    for index, (record_id, expected_row) in enumerate(expected.items(), start=1):
        record = records.get(record_id, {})
        require(errors, record.get("order") == index, f"{record_id}: operator order mismatch")
        require(errors, record.get("external_summary_path") == expected_row["path"], f"{record_id}: operator summary path mismatch")
        require(errors, record.get("template_path") == expected_row["template"], f"{record_id}: operator template path mismatch")
        require(errors, record.get("plan_readiness_status") == expected_row["readiness"], f"{record_id}: operator plan readiness mismatch")
        require(errors, record.get("required_summary_schema") == expected_row["schema"], f"{record_id}: operator summary schema mismatch")
        require_file(errors, root, expected_row["template"], f"{record_id}.operator_template")
        status = record.get("intake_completion_status")
        if status == "OPEN_NO_EXTERNAL_SUMMARY":
            open_records += 1
            expected_record_status = "OPEN_NO_EXTERNAL_SUMMARY_REQUIRES_EXTERNAL_COLLECTION"
            require(errors, record.get("completion_requires_external_state") is True, f"{record_id}: open record must require external state")
            require(errors, record.get("completion_evidence_valid") is False, f"{record_id}: open record must not be valid completion evidence")
            require(errors, record.get("execution_steps_required_to_close_record") is True, f"{record_id}: open record must require closure steps")
            require(errors, record.get("accepted_summary_supersedes_plan_readiness") is False, f"{record_id}: open record must not supersede plan readiness")
            require(errors, record.get("accepted_summary_must_remain_hash_valid") is False, f"{record_id}: open record must not claim accepted hash validity")
        elif status == "EXTERNAL_SUMMARY_ACCEPTED":
            accepted_records += 1
            expected_record_status = "EXTERNAL_SUMMARY_ACCEPTED_ARTIFACT_BACKED"
            require(errors, record.get("completion_evidence_valid") is True, f"{record_id}: accepted record must be valid completion evidence")
            require(errors, record.get("execution_steps_required_to_close_record") is False, f"{record_id}: accepted record must not require closure steps")
            require(errors, record.get("accepted_summary_supersedes_plan_readiness") is True, f"{record_id}: accepted record must supersede plan readiness")
            require(errors, record.get("accepted_summary_must_remain_hash_valid") is True, f"{record_id}: accepted record hash validity boundary missing")
        elif status == "EXTERNAL_SUMMARY_PRESENT_INVALID":
            invalid_records += 1
            expected_record_status = "EXTERNAL_SUMMARY_PRESENT_INVALID_REQUIRES_RERUN_OR_REPAIR"
            require(errors, record.get("completion_requires_external_state") is True, f"{record_id}: invalid record must require external correction")
            require(errors, record.get("completion_evidence_valid") is False, f"{record_id}: invalid record must not be valid completion evidence")
            require(errors, record.get("execution_steps_required_to_close_record") is True, f"{record_id}: invalid record must require closure steps")
            require(errors, record.get("accepted_summary_supersedes_plan_readiness") is False, f"{record_id}: invalid record must not supersede plan readiness")
            require(errors, record.get("accepted_summary_must_remain_hash_valid") is False, f"{record_id}: invalid record must not claim accepted hash validity")
        else:
            errors.append(f"{record_id}: unexpected operator intake status {status!r}")
            expected_record_status = None
        if expected_record_status is not None:
            require(errors, record.get("record_status") == expected_record_status, f"{record_id}: operator effective status mismatch")
            require(errors, record.get("readiness_status") == expected_record_status, f"{record_id}: operator effective readiness mismatch")
        require(errors, record.get("plan_status") in {"READY_TO_EXECUTE_WITH_EXTERNAL_STATE", "EXTERNAL_SUMMARY_ACCEPTED", "NEEDS_EXTERNAL_SUMMARY_CORRECTION"}, f"{record_id}: operator plan status mismatch")
        require(errors, len(as_list(record.get("operator_inputs"))) >= 3, f"{record_id}: operator inputs under-specified")
        require(errors, len(as_list(record.get("required_raw_artifacts"))) >= 4, f"{record_id}: required raw artifacts under-specified")
        require(errors, len(as_list(record.get("required_evidence_artifact_kinds"))) >= 3, f"{record_id}: required evidence artifact kinds under-specified")
        require(errors, len(as_list(record.get("acceptance_criteria"))) >= 4, f"{record_id}: acceptance criteria under-specified")
        no_sub = str(record.get("no_substitution_rule") or "").lower()
        require(errors, "must not" in no_sub and "substitut" in no_sub, f"{record_id}: operator no-substitution rule is too weak")
        phases = {
            str(step.get("phase"))
            for step in as_list(record.get("execution_steps"))
            if isinstance(step, dict) and step.get("phase")
        }
        for phase in ("local_preflight", "external_collection", "candidate_summary_packaging", "intake_acceptance"):
            require(errors, phase in phases, f"{record_id}: operator phase missing: {phase}")
        exits = " ".join(str(item) for item in as_list(record.get("exit_criteria")))
        require(errors, "completion_evidence_valid=true" in exits, f"{record_id}: operator exit criteria incomplete")
    require(errors, open_records == open_count, "external operator packet open record count mismatch")
    require(errors, accepted_records == accepted, "external operator packet accepted record count mismatch")
    require(errors, invalid_records == invalid, "external operator packet invalid record count mismatch")
    commands = " ".join(str(item) for item in as_list(packet.get("validation_commands")))
    require(errors, "tools/check_genesys2_external_operator_packet.py --root ." in commands, "external operator packet validation command missing")
    require(errors, "tools/check_genesys2_external_closure_intake.py --root ." in commands, "external operator packet intake validation command missing")
    require(errors, "tools/check_genesys2_external_closure_preflight.py --root ." in commands, "external operator packet preflight validation command missing")


def check_case_study_manifest(errors: list[str], root: Path, manifest: dict[str, Any]) -> None:
    boundary = manifest.get("claim_boundary") if isinstance(manifest.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("controlled_safe_surrogate_case_studies") is True, "case-study manifest controlled boundary missing")
    for key in (
        "real_malware_validation_claimed",
        "malware_detection_accuracy_claimed",
        "hardware_full_pointer_strings_claimed",
        "board_native_source_line_attribution_claimed",
        "production_streaming_dma_throughput_claimed",
        "paper_ready_claimed",
    ):
        require(errors, boundary.get(key) is False, f"case-study manifest must not claim {key}")
    require(errors, int(manifest.get("case_study_count") or 0) == len(ALL_CCFA_SAMPLES), "case-study count mismatch")
    require(errors, int(manifest.get("p0_case_study_count") or 0) == len(P0_SAMPLES), "P0 case-study count mismatch")
    require(errors, int(manifest.get("safe_surrogate_case_study_count") or 0) == len(SAFE_SURROGATE_SAMPLES), "safe surrogate case-study count mismatch")
    rows = {
        str(row.get("sample_id")): row
        for row in as_list(manifest.get("case_studies"))
        if isinstance(row, dict) and row.get("sample_id")
    }
    missing = [sample for sample in ALL_CCFA_SAMPLES if sample not in rows]
    extra = [sample for sample in rows if sample not in ALL_CCFA_SAMPLES]
    require(errors, not missing, f"case-study manifest missing samples: {', '.join(missing)}")
    require(errors, not extra, f"case-study manifest unexpected samples: {', '.join(extra)}")
    for sample_id in ALL_CCFA_SAMPLES:
        row = rows.get(sample_id, {})
        expected_class = "p0_safe_synthetic" if sample_id in P0_SAMPLES else "malware_like_synthetic_syscall_only"
        require(errors, row.get("sample_class") == expected_class, f"{sample_id}: case-study sample_class mismatch")
        require(errors, row.get("case_study_complete") is True, f"{sample_id}: case-study must be complete")
        for key in ("case_study_summary", "trace", "semantic_events", "behavior_graph", "baseline_logs"):
            require_file(errors, root, row.get(key), f"{sample_id}.case_study.{key}")
        summary = require_json_file(errors, root, row.get("case_study_summary"), f"{sample_id}.case_study_summary")
        if summary is None:
            continue
        require(errors, summary.get("schema") == "rvmt.ccfa.case_study_summary.v1", f"{sample_id}: case summary schema mismatch")
        require(errors, summary.get("status") == "PASS", f"{sample_id}: case summary status must be PASS")
        require(errors, summary.get("real_malware") is False, f"{sample_id}: case summary must not be real malware")
        non_claims = " ".join(str(item).lower() for item in as_list(summary.get("non_claims")))
        require(errors, "not real malware validation" in non_claims, f"{sample_id}: case summary real-malware non-claim missing")
        require(errors, "full hardware-derived pointer strings are not claimed" in non_claims, f"{sample_id}: case summary full-string non-claim missing")
    commands = " ".join(str(item) for item in as_list(manifest.get("validation_commands")))
    require(errors, "tools/check_ccfa_case_study_manifest.py --root ." in commands, "case-study validation command missing")


def check_review_closure_audit(errors: list[str], root: Path, audit: dict[str, Any], intake: dict[str, Any]) -> None:
    expected_external_ids = {
        "board_native_dwarf_source_lines",
        "full_hardware_pointer_strings",
        "production_streaming_dma_trace_sink",
        "genesys2_board_benign_control",
    }
    require(errors, audit.get("closure_status") == "PASS_LOCAL_SCOPE_EXTERNAL_AND_BOARD_DYNAMIC_OPEN", "review closure audit closure status mismatch")
    summary = audit.get("summary") if isinstance(audit.get("summary"), dict) else {}
    require(errors, summary.get("local_items_evidence_present") is True, "review closure audit local evidence coverage missing")
    require(errors, summary.get("local_item_count") == 10, "review closure audit local item count mismatch")
    require(errors, summary.get("blocked_item_count") == 1, "review closure audit blocked item count mismatch")
    require(errors, summary.get("blocked_items_evidence_present") is True, "review closure audit blocked evidence coverage missing")
    require(errors, set(as_list(summary.get("blocked_item_ids"))) == {"phase_c_function_process_elf_attribution"}, "review closure audit blocked ids mismatch")
    accepted_ids = set(as_list(summary.get("accepted_external_ids")))
    open_ids = set(as_list(summary.get("open_external_ids")))
    require(errors, accepted_ids | open_ids == expected_external_ids, "review closure audit external ids coverage mismatch")
    require(errors, accepted_ids.isdisjoint(open_ids), "review closure audit accepted/open ids overlap")
    require(errors, int(summary.get("accepted_external_item_count") or 0) == len(accepted_ids), "review closure audit accepted external count mismatch")
    require(errors, int(summary.get("open_external_item_count") or 0) == len(open_ids), "review closure audit open external count mismatch")
    require(errors, summary.get("excluded_item_count") == 1, "review closure audit excluded item count mismatch")
    require(errors, "real_malware_validation" in as_list(summary.get("objective_exclusions")), "review closure audit real-malware exclusion missing")
    boundary = audit.get("claim_boundary") if isinstance(audit.get("claim_boundary"), dict) else {}
    for key in (
        "real_malware_validation_claimed",
        "external_readiness_substituted_for_completion",
        "local_linux_benign_substituted_for_board_benign",
        "bounded_prefix_substituted_for_full_strings",
        "toolchain_probe_substituted_for_board_native_dwarf",
    ):
        require(errors, boundary.get(key) is False, f"review closure audit boundary must reject {key}")
    require(errors, boundary.get("real_malware_validation_excluded_by_objective") is True, "review closure audit real-malware exclusion boundary missing")

    intake_records = {
        str(row.get("id")): row
        for row in as_list(intake.get("records"))
        if isinstance(row, dict) and row.get("id")
    }
    items = {
        str(row.get("id")): row
        for row in as_list(audit.get("items"))
        if isinstance(row, dict) and row.get("id")
    }
    require(errors, len(items) == 16, "review closure audit item count mismatch")
    external_items = [row for row in items.values() if row.get("status") in {"OPEN_EXTERNAL_ARTIFACTS_REQUIRED", "EXTERNAL_SUMMARY_ACCEPTED"}]
    require(errors, len(external_items) == len(expected_external_ids), "review closure audit external item count mismatch")
    excluded = [row for row in items.values() if row.get("status") == "EXCLUDED_BY_OBJECTIVE"]
    require(errors, len(excluded) == 1 and excluded[0].get("id") == "phase_g_real_malware_validation", "review closure audit excluded item mismatch")

    for item_id, item in items.items():
        evidence_rows = as_list(item.get("evidence"))
        require(errors, bool(evidence_rows), f"{item_id}: review closure audit evidence rows missing")
        for evidence in evidence_rows:
            if not isinstance(evidence, dict):
                errors.append(f"{item_id}: review closure audit evidence row must be object")
                continue
            path_value = evidence.get("path")
            path = require_file(errors, root, path_value, f"{item_id}.{evidence.get('id')}")
            require(errors, evidence.get("exists") is True, f"{item_id}: review closure audit evidence exists flag mismatch: {evidence.get('id')}")
            if path is not None:
                require(errors, evidence.get("sha256") == sha256_file(path), f"{item_id}: review closure audit evidence sha256 mismatch: {evidence.get('id')}")
            require(errors, isinstance(evidence.get("schema"), str) and bool(evidence.get("schema")), f"{item_id}: review closure audit evidence schema marker missing: {evidence.get('id')}")
            require(errors, isinstance(evidence.get("status"), str) and bool(evidence.get("status")), f"{item_id}: review closure audit evidence status marker missing: {evidence.get('id')}")
            if str(item.get("status") or "").startswith("PASS"):
                require(errors, evidence.get("status") in {"NOT_APPLICABLE", "PASS"}, f"{item_id}: review closure audit evidence status mismatch: {evidence.get('id')}")
        if item.get("status") not in {"OPEN_EXTERNAL_ARTIFACTS_REQUIRED", "EXTERNAL_SUMMARY_ACCEPTED"}:
            continue
        external_id = str(item.get("external_id") or "")
        require(errors, external_id in expected_external_ids, f"{item_id}: review closure audit unexpected external id")
        state = item.get("external_state") if isinstance(item.get("external_state"), dict) else {}
        live = intake_records.get(external_id, {})
        require(errors, live.get("completion_status") == state.get("completion_status"), f"{external_id}: review closure audit live intake status mismatch")
        if item.get("status") == "EXTERNAL_SUMMARY_ACCEPTED":
            require(errors, state.get("completion_status") == "EXTERNAL_SUMMARY_ACCEPTED", f"{external_id}: review closure audit accepted status mismatch")
            require(errors, state.get("external_summary_exists") is True, f"{external_id}: review closure audit accepted summary must exist")
            require(errors, state.get("completion_evidence_valid") is True, f"{external_id}: review closure audit accepted evidence validity mismatch")
            require(errors, state.get("current_blocker") is False, f"{external_id}: review closure audit accepted blocker mismatch")
        else:
            require(errors, state.get("completion_status") in {"OPEN_NO_EXTERNAL_SUMMARY", "EXTERNAL_SUMMARY_PRESENT_INVALID"}, f"{external_id}: review closure audit state must remain blocked")
            require(errors, state.get("completion_evidence_valid") is False, f"{external_id}: review closure audit evidence validity must be false while blocked")
            require(errors, state.get("current_blocker") is True, f"{external_id}: review closure audit blocked item must remain blocker")
    commands = " ".join(str(item) for item in as_list(audit.get("validation_commands")))
    require(errors, "tools/check_genesys2_review_closure_audit.py --root ." in commands, "review closure audit checker command missing")
    report = root / "docs/07-evaluation-evidence/reports/ccfa_review_closure_audit.md"
    require(errors, report.is_file(), "review closure audit markdown report missing")
    if report.is_file():
        report_text = report.read_text(encoding="utf-8", errors="replace")
        for token in ("PASS_LOCAL_SCOPE_EXTERNAL_AND_BOARD_DYNAMIC_OPEN", "Remaining Non-Real External Items", "real malware validation", *sorted(expected_external_ids)):
            require(errors, token in report_text, f"review closure audit markdown report missing token: {token}")


def check_baseline_alignment_transcripts(errors: list[str], root: Path, baseline: dict[str, Any]) -> None:
    rows = baseline.get("baselines") if isinstance(baseline.get("baselines"), dict) else {}
    for baseline_id, row in rows.items():
        if not isinstance(row, dict):
            errors.append(f"{baseline_id}: baseline row must be object")
            continue
        transcript = str(row.get("command_transcript") or "")
        if not transcript:
            errors.append(f"{baseline_id}: command_transcript missing")
            continue
        parts = [part.strip() for part in transcript.split(";") if part.strip()]
        for part in parts:
            path = rel_or_abs(root, part)
            if "*" in part:
                require(errors, bool(list(root.glob(part))), f"{baseline_id}: transcript glob has no matches: {part}")
            elif path.suffix in {".json", ".log", ".jsonl"}:
                require_file(errors, root, part, f"{baseline_id}.command_transcript")


def check_planning_doc_boundaries(errors: list[str], root: Path) -> None:
    for relative in PLANNING_DOCS:
        path = root / relative
        if not path.is_file():
            errors.append(f"planning doc missing: {relative.as_posix()}")
            continue
        text = path.read_text(encoding="utf-8")
        for forbidden in FORBIDDEN_PLANNING_TEXT:
            require(errors, forbidden not in text, f"{relative.as_posix()}: stale planning text remains: {forbidden}")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if "normal full-SoC multi-instruction tohost completion" in line and "open" in line.lower():
                errors.append(f"{relative.as_posix()}:{line_number}: normal full-SoC tohost completion must not remain an open blocker")
        for required in REQUIRED_PLANNING_TEXT:
            require(errors, required in text, f"{relative.as_posix()}: missing current boundary text: {required}")


def check_current_quality(root: Path, current_root: Path) -> list[str]:
    errors: list[str] = []
    summaries = load_summaries(errors, root, current_root)
    if errors:
        return errors
    check_matrix_artifacts(errors, root, summaries["ccfa_evaluation_matrix.json"])
    check_baseline_logs(errors, root, summaries["ccfa_evaluation_matrix.json"])
    check_semantics(errors, root, summaries["semantic_reconstruction_summary.json"])
    check_fd_graph(errors, summaries["fd_path_graph_summary.json"])
    check_source_sidecar(errors, root, current_root, summaries["source_line_attribution_summary.json"])
    check_source_line_toolchain_probe(errors, summaries["source_line_toolchain_probe.json"])
    check_process_maps(errors, root, summaries["process_elf_ownership_summary.json"])
    check_bram_and_drop_roots(
        errors,
        root,
        summaries["latest_manifest.json"],
        summaries["safe_surrogate_bram_trace_summary.json"],
        summaries["p0_bram_trace_summary.json"],
        summaries["drop_accounting_summary.json"],
    )
    check_runtime_benchmark(errors, root, summaries["production_runtime_benchmark.json"])
    check_resource_timing(errors, root, summaries["resource_timing_summary.json"], summaries["production_runtime_benchmark.json"])
    check_hardware_pointer_prefixes(errors, summaries["latest_manifest.json"], summaries["hardware_pointer_prefix_summary.json"])
    check_benign_control(errors, root, summaries["benign_control_summary.json"], summaries["behavior_audit_metrics.json"])
    check_case_study_manifest(errors, root, summaries["case_study_manifest.json"])
    check_review_closure_audit(errors, root, summaries["review_closure_audit.json"], summaries["external_closure_intake.json"])
    check_reproducibility_manifest(errors, summaries["reproducibility_manifest.json"])
    check_artifact_package(errors, root, summaries["artifact_package_manifest.json"])
    check_external_closure_readiness(errors, root, summaries["external_closure_readiness.json"])
    check_external_closure_intake(errors, summaries["external_closure_intake.json"])
    check_external_closure_plan(errors, root, summaries["external_closure_plan.json"])
    check_external_closure_preflight(errors, root, summaries["external_closure_preflight.json"])
    check_external_operator_packet(errors, root, summaries["external_operator_packet.json"])
    check_baseline_alignment_transcripts(errors, root, summaries["baseline_alignment_summary.json"])
    check_planning_doc_boundaries(errors, root)
    return errors




def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = write_fixture(root)
        errors = check_current_quality(root, current)
        if errors:
            print("[FAIL] current-quality good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = write_fixture(root)
        semantic = load_json(current / "semantic_reconstruction_summary.json")
        semantic["samples"][0]["write_buffer_prefixes"] = []
        write_json(current / "semantic_reconstruction_summary.json", semantic)
        errors = check_current_quality(root, current)
        if not errors:
            print("[FAIL] current-quality bad fixture passed", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = write_fixture(root)
        stale_doc = root / PLANNING_DOCS[0]
        stale_doc.write_text(
            "clock/reset, UART hello, bare-metal runtime are still TODO(BOARD)\n",
            encoding="utf-8",
            newline="\n",
        )
        errors = check_current_quality(root, current)
        if not any("stale planning text" in error for error in errors):
            print("[FAIL] current-quality stale planning fixture was not rejected", file=sys.stderr)
            return 1
    print("[PASS] current-quality checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Strict current-quality gate for non-real-malware CCF-A evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    current_root = rel_or_abs(root, args.current_root)
    errors = check_current_quality(root, current_root)
    if errors:
        print("[FAIL] current-quality evidence is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] current-quality evidence accepted: {current_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
