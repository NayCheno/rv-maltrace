from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from ccfa_gate_common import ALL_CCFA_SAMPLES, P0_SAMPLES, SAFE_SURROGATE_SAMPLES


DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")

SUMMARY_SCHEMAS = {
    "trace_sink_summary.json": "rvmt.genesys2.bram_trace_sink.v1",
    "safe_surrogate_bram_trace_summary.json": "rvmt.genesys2.safe_surrogate_bram_trace.v1",
    "drop_accounting_summary.json": "rvmt.trace_drop_accounting.v1",
    "pointer_snapshot_guardrails.json": "rvmt.pointer_snapshot_guardrails.v1",
    "production_runtime_benchmark.json": "rvmt.genesys2.production_runtime_benchmark.v1",
    "semantic_reconstruction_summary.json": "rvmt.syscall_semantic_reconstruction.v1",
    "fd_path_graph_summary.json": "rvmt.fd_path_graph.v1",
    "source_line_attribution_summary.json": "rvmt.source_line_attribution.v1",
    "process_elf_ownership_summary.json": "rvmt.process_elf_ownership.v1",
    "dynamic_mapping_attribution_summary.json": "rvmt.dynamic_mapping_attribution.v1",
    "ccfa_evaluation_matrix.json": "rvmt.ccfa_evaluation_matrix.v1",
    "baseline_alignment_summary.json": "rvmt.baseline_alignment.v1",
    "behavior_audit_metrics.json": "rvmt.behavior_audit_metrics.v1",
    "workload_manifest.json": "rvmt.ccfa.workload_manifest.v1",
    "resource_timing_summary.json": "rvmt.resource_timing_summary.v1",
}

EXPECTED_EXECVE_TARGETS = {
    "fork_exec": "/bin/true",
    "process_chain": "/bin/true",
}

EXPECTED_SAMPLE_SYSCALLS = {
    "dynamic_executable_memory": {"mmap", "mprotect", "munmap"},
    "anti_debug_like": {"clock_gettime", "ptrace", "openat", "read", "close"},
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def rel_or_abs(root: Path, path: Any) -> Path:
    candidate = Path(str(path))
    return candidate if candidate.is_absolute() else root / candidate


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def sample_rows(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("sample_id") or row.get("id")): row
        for row in as_list(data.get("samples"))
        if isinstance(row, dict) and (row.get("sample_id") or row.get("id"))
    }


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


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
        require(errors, data.get("status") == "PASS", f"{filename}: status must be PASS")
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
        if row.get("has_execve"):
            paths = [str(item) for item in as_list(row.get("execve_paths"))]
            require(errors, bool(paths), f"{sample_id}: execve paths must be non-empty")
            require(errors, row.get("execve_path_source") in {"qemu_guest_strace", "host_or_control_strace"}, f"{sample_id}: execve_path_source invalid")
            if sample_id in EXPECTED_EXECVE_TARGETS:
                require(errors, EXPECTED_EXECVE_TARGETS[sample_id] in paths, f"{sample_id}: expected exec target missing")
        if row.get("has_write"):
            prefixes = as_list(row.get("write_buffer_prefixes"))
            require(errors, row.get("write_buffer_prefix_recovered") is True, f"{sample_id}: write prefix must be recovered")
            require(errors, bool(prefixes), f"{sample_id}: write prefix list must be non-empty")
            require(errors, row.get("write_buffer_prefix_source") in {"qemu_guest_strace", "host_or_control_strace"}, f"{sample_id}: write prefix source invalid")
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


def check_bram_and_drop_roots(errors: list[str], root: Path, safe_bram: dict[str, Any], drop: dict[str, Any]) -> None:
    run_root = str(safe_bram.get("run_root") or "")
    require(errors, "20260611-safe-surrogate-bram-ring-busywait" in run_root, "safe BRAM summary must use busywait recapture run root")
    require_file(errors, root, safe_bram.get("bitstream"), "safe_bram.bitstream")
    require_file(errors, root, safe_bram.get("ltx"), "safe_bram.ltx")
    require(errors, str(drop.get("safe_surrogate_bram_run_root") or "") == run_root, "drop accounting safe BRAM run root must match safe BRAM summary")


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
    check_process_maps(errors, root, summaries["process_elf_ownership_summary.json"])
    check_bram_and_drop_roots(errors, root, summaries["safe_surrogate_bram_trace_summary.json"], summaries["drop_accounting_summary.json"])
    check_runtime_benchmark(errors, root, summaries["production_runtime_benchmark.json"])
    check_baseline_alignment_transcripts(errors, root, summaries["baseline_alignment_summary.json"])
    return errors


def touch(path: Path, text: str = "fixture\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def write_fixture(root: Path) -> Path:
    current = root / DEFAULT_CURRENT_ROOT
    current.mkdir(parents=True, exist_ok=True)
    artifact_root = root / "fixture_artifacts"
    bit = artifact_root / "ariane_xilinx.bit"
    ltx = artifact_root / "ariane_xilinx.ltx"
    touch(bit)
    touch(ltx)

    source_rows: list[dict[str, Any]] = []
    source_sidecar_rows: list[dict[str, Any]] = []
    semantic_rows: list[dict[str, Any]] = []
    fd_rows: list[dict[str, Any]] = []
    process_rows: list[dict[str, Any]] = []
    matrix_rows: list[dict[str, Any]] = []

    for sample_id in ALL_CCFA_SAMPLES:
        sample_dir = artifact_root / sample_id
        source = sample_dir / f"{sample_id}.c"
        touch(source, "int main(void) { return 0; }\n")
        trace = sample_dir / "trace.jsonl"
        semantic_events = sample_dir / "semantic_events.json"
        behavior_graph = sample_dir / "behavior_graph.json"
        code_map = sample_dir / "code_map.json"
        source_attr = sample_dir / "source_attribution_summary.json"
        integrated = sample_dir / "integrated_validation.json"
        for path in (trace, semantic_events, behavior_graph, code_map, source_attr, integrated):
            touch(path, "{}\n" if path.suffix == ".json" else "{\"evt\":\"fixture\"}\n")
        runtime_map = sample_dir / "runtime_process_map.json"
        write_json(
            runtime_map,
            {
                "schema": "rvmt.runtime_process_map.v1",
                "status": "PASS",
                "sample_id": sample_id,
                "owners": {"target_child": {"status": "PASS", "maps": [{"path": f"/tmp/{sample_id}"}]}},
            },
        )
        host = sample_dir / "host.strace.log"
        qemu = sample_dir / "qemu-riscv64.strace.log"
        touch(host, "1 write(1, \"x\", 1) = 1\n")
        touch(qemu, "1 write(1,0x1000,1) = 1\n")
        baseline = current / "samples" / sample_id / "baseline_logs.json"
        metric = current / "samples" / sample_id / "metric_summary.json"
        write_json(
            baseline,
            {
                "schema": "rvmt.sample_baseline_logs.v1",
                "sample_id": sample_id,
                "host_strace": {"present": True, "line_count": 1, "path": host.relative_to(root).as_posix()},
                "qemu_strace": {"present": True, "line_count": 1, "path": qemu.relative_to(root).as_posix()},
                "evidence": {
                    "trace": trace.relative_to(root).as_posix(),
                    "semantic_events": semantic_events.relative_to(root).as_posix(),
                    "behavior_graph": behavior_graph.relative_to(root).as_posix(),
                    "code_map": code_map.relative_to(root).as_posix(),
                    "source_attribution": source_attr.relative_to(root).as_posix(),
                    "runtime_process_map": runtime_map.relative_to(root).as_posix(),
                    "integrated_validation": integrated.relative_to(root).as_posix(),
                },
            },
        )
        write_json(metric, {"schema": "rvmt.sample_metric_summary.v1", "sample_id": sample_id, "metrics": {"unaccounted_drop": 0}})
        matrix_rows.append(
            {
                "sample_id": sample_id,
                "trace": trace.relative_to(root).as_posix(),
                "semantic_events": semantic_events.relative_to(root).as_posix(),
                "behavior_graph": behavior_graph.relative_to(root).as_posix(),
                "baseline_logs": baseline.relative_to(root).as_posix(),
                "metric_summary": metric.relative_to(root).as_posix(),
                "continuous_trace": True,
                "unaccounted_drop": 0,
            }
        )
        expected = ["write"]
        if sample_id in EXPECTED_EXECVE_TARGETS:
            expected = ["execve"]
        if sample_id in EXPECTED_SAMPLE_SYSCALLS:
            expected = sorted(EXPECTED_SAMPLE_SYSCALLS[sample_id])
        has_openat = "openat" in expected
        has_execve = "execve" in expected
        has_write = "write" in expected
        semantic_rows.append(
            {
                "sample_id": sample_id,
                "expected_syscalls": expected,
                "expected_syscall_recall": 1.0,
                "syscall_precision": 1.0,
                "argument_reconstruction_accuracy": 1.0,
                "has_openat": has_openat,
                "openat_paths": ["/proc/self/status"] if has_openat else [],
                "openat_path_source": "qemu_guest_strace" if has_openat else None,
                "has_execve": has_execve,
                "execve_paths": ["/bin/true"] if has_execve else [],
                "execve_path_source": "qemu_guest_strace" if has_execve else None,
                "has_write": has_write,
                "write_buffer_prefix_recovered": has_write,
                "write_buffer_prefixes": ["x"] if has_write else [],
                "write_buffer_prefix_source": "host_or_control_strace" if has_write else None,
                "mmap_mprotect_behavior_node": sample_id == "dynamic_executable_memory",
                "anti_analysis_behavior_node": sample_id == "anti_debug_like",
                "ground_truth_alignment": {
                    "host_or_control_strace": host.relative_to(root).as_posix(),
                    "qemu_guest_strace": qemu.relative_to(root).as_posix(),
                    "strace": True,
                    "qemu_strace": True,
                },
                "trace_source": trace.relative_to(root).as_posix(),
            }
        )
        fd_rows.append(
            {
                "sample_id": sample_id,
                "fd_graph_complete": True,
                "unresolved_fd_count": 0,
                "has_openat": has_openat,
                "has_execve": has_execve,
                "graph": {"nodes": ["/bin/true"] if (has_openat or has_execve) else [], "edges": []},
            }
        )
        process_rows.append(
            {
                "sample_id": sample_id,
                "runtime_process_attribution_proven": True,
                "pid": 1,
                "tgid": 1,
                "executable_path": f"/tmp/{sample_id}",
                "target_elf_attributed_events": 1,
                "dynamic_library_events_correctly_separated": True,
                "runtime_process_map": runtime_map.relative_to(root).as_posix(),
            }
        )
        source_rows.append(
            {
                "sample_id": sample_id,
                "key_event_count": 1,
                "unknown_key_events": 0,
                "function_attribution_available": True,
                "source_line_sidecar": (current / "source_line_sidecar.json").relative_to(root).as_posix(),
                "source_line_sidecar_rate": 1.0,
            }
        )
        source_sidecar_rows.append(
            {
                "sample_id": sample_id,
                "source": source.relative_to(root).as_posix(),
                "expected_key_events": 1,
                "mapped_key_events": 1,
                "source_line_rate": 1.0,
                "events": [{"ordinal": 1, "syscall": expected[0], "source": source.relative_to(root).as_posix(), "line": 1}],
            }
        )

    write_json(current / "source_line_sidecar.json", {"expected_key_events": len(ALL_CCFA_SAMPLES), "mapped_key_events": len(ALL_CCFA_SAMPLES), "samples": source_sidecar_rows})
    write_json(current / "trace_sink_summary.json", {"schema": SUMMARY_SCHEMAS["trace_sink_summary.json"], "status": "PASS", "samples": []})
    write_json(
        current / "safe_surrogate_bram_trace_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["safe_surrogate_bram_trace_summary.json"],
            "status": "PASS",
            "run_root": "results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait",
            "bitstream": bit.relative_to(root).as_posix(),
            "ltx": ltx.relative_to(root).as_posix(),
        },
    )
    write_json(
        current / "drop_accounting_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["drop_accounting_summary.json"],
            "status": "PASS",
            "safe_surrogate_bram_run_root": "results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait",
            "samples": [{"sample_id": sample_id, "unaccounted_drop": 0, "total_events": 1} for sample_id in ALL_CCFA_SAMPLES],
        },
    )
    write_json(current / "pointer_snapshot_guardrails.json", {"schema": SUMMARY_SCHEMAS["pointer_snapshot_guardrails.json"], "status": "PASS", "samples": []})
    runtime_root = artifact_root / "runtime_benchmark"
    runtime_samples: list[dict[str, Any]] = []
    raw_repetitions: list[dict[str, Any]] = []
    runtime_modes = ["trace_off", "event_only", "bram_ring", "pointer_snapshot_disabled"]
    for sample_id in SAFE_SURROGATE_SAMPLES:
        modes: dict[str, Any] = {}
        for mode in runtime_modes:
            reps: list[dict[str, Any]] = []
            for rep in range(1, 4):
                log = runtime_root / sample_id / mode / f"rep_{rep:02d}" / "uart.log"
                touch(
                    log,
                    f"RVMT_RUNTIME_BENCH_START sample={sample_id} mode={mode} rep=rep_{rep:02d} ns=1000\n"
                    f"RVMT_RUNTIME_BENCH_DONE sample={sample_id} mode={mode} rep=rep_{rep:02d} rc=0 ns=2000\n",
                )
                row = {
                    "sample_id": sample_id,
                    "mode": mode,
                    "repetition_id": f"rep_{rep:02d}",
                    "rc": 0,
                    "duration_ns": 1000,
                    "program_log": log.relative_to(root).as_posix(),
                }
                reps.append(row)
                raw_repetitions.append(row)
            modes[mode] = {
                "count": 3,
                "median_ns": 1000,
                "p95_ns": 1000,
                "variance_ns2": 0.0,
                "slowdown_vs_trace_off_median": 1.0 if mode != "trace_off" else None,
                "repetitions": reps,
            }
        runtime_samples.append({"sample_id": sample_id, "modes": modes})
    write_json(
        current / "production_runtime_benchmark.json",
        {
            "schema": SUMMARY_SCHEMAS["production_runtime_benchmark.json"],
            "status": "PASS",
            "run_root": runtime_root.relative_to(root).as_posix(),
            "minimum_repetitions_per_mode_sample": 3,
            "mode_stats": {
                mode: {"count": len(SAFE_SURROGATE_SAMPLES) * 3, "median_ns": 1000, "p95_ns": 1000, "variance_ns2": 0.0}
                for mode in runtime_modes
            },
            "samples": runtime_samples,
            "raw_repetitions": raw_repetitions,
        },
    )
    write_json(
        current / "semantic_reconstruction_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["semantic_reconstruction_summary.json"],
            "status": "PASS",
            "samples": semantic_rows,
            "non_claims": ["No hardware ARG_MEM/user-pointer byte snapshot is present.", "Real malware validation is not claimed."],
        },
    )
    write_json(current / "fd_path_graph_summary.json", {"schema": SUMMARY_SCHEMAS["fd_path_graph_summary.json"], "status": "PASS", "samples": fd_rows})
    write_json(current / "source_line_attribution_summary.json", {"schema": SUMMARY_SCHEMAS["source_line_attribution_summary.json"], "status": "PASS", "samples": source_rows})
    write_json(current / "process_elf_ownership_summary.json", {"schema": SUMMARY_SCHEMAS["process_elf_ownership_summary.json"], "status": "PASS", "samples": process_rows})
    write_json(current / "dynamic_mapping_attribution_summary.json", {"schema": SUMMARY_SCHEMAS["dynamic_mapping_attribution_summary.json"], "status": "PASS"})
    write_json(current / "workload_manifest.json", {"schema": SUMMARY_SCHEMAS["workload_manifest.json"], "status": "PASS", "samples": []})
    write_json(current / "resource_timing_summary.json", {"schema": SUMMARY_SCHEMAS["resource_timing_summary.json"], "status": "PASS"})
    write_json(
        current / "ccfa_evaluation_matrix.json",
        {
            "schema": SUMMARY_SCHEMAS["ccfa_evaluation_matrix.json"],
            "status": "PASS",
            "workload_manifest": (current / "workload_manifest.json").relative_to(root).as_posix(),
            "resource_timing_summary": (current / "resource_timing_summary.json").relative_to(root).as_posix(),
            "samples": matrix_rows,
        },
    )
    write_json(
        current / "baseline_alignment_summary.json",
        {
            "schema": SUMMARY_SCHEMAS["baseline_alignment_summary.json"],
            "status": "PASS",
            "baselines": {
                "rv_maltrace_event_only": {"present": True, "alignment_pass": True, "command_transcript": (current / "safe_surrogate_bram_trace_summary.json").relative_to(root).as_posix()},
                "rv_maltrace_pointer_snapshot": {"present": True, "alignment_pass": True, "command_transcript": (current / "pointer_snapshot_guardrails.json").relative_to(root).as_posix()},
                "rv_maltrace_kernel_helper": {"present": True, "alignment_pass": True, "command_transcript": (current / "semantic_reconstruction_summary.json").relative_to(root).as_posix()},
            },
        },
    )
    write_json(current / "behavior_audit_metrics.json", {"schema": SUMMARY_SCHEMAS["behavior_audit_metrics.json"], "status": "PASS"})
    return current


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
