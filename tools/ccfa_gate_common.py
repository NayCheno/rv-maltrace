from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


P0_SAMPLES = ["hello_write", "file_open_read_write", "fork_exec", "illegal_instruction"]
P0_BRAM_MARKERS = {
    "hello_write": ("0xb0000a01", "0xe0000a01"),
    "file_open_read_write": ("0xb0000a02", "0xe0000a02"),
    "fork_exec": ("0xb0000a03", "0xe0000a03"),
    "illegal_instruction": ("0xb0000a04", "0xe0000a04"),
}
SAFE_SURROGATE_SAMPLES = [
    "file_scan",
    "batch_open_read_write",
    "self_copy_sim",
    "abnormal_syscall_sequence",
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
    "anti_debug_like",
]
ALL_CCFA_SAMPLES = P0_SAMPLES + SAFE_SURROGATE_SAMPLES

BASELINES = [
    "rv_maltrace_event_only",
    "rv_maltrace_pointer_snapshot",
    "rv_maltrace_kernel_helper",
    "strace",
    "qemu_strace",
    "software_instrumentation",
]

ABLATIONS = [
    "event_only",
    "pointer_snapshot",
    "kernel_helper_companion",
]

PRIORITY_SYSCALLS = [
    "openat",
    "read",
    "write",
    "close",
    "execve",
    "clone",
    "wait4",
    "waitid",
    "mmap",
    "mprotect",
    "ptrace",
    "clock_gettime",
    "getdents64",
]


def repo_path(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def num(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def sample_rows(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = as_list(data.get("samples"))
    return {
        str(row.get("sample_id") or row.get("id")): row
        for row in rows
        if isinstance(row, dict) and (row.get("sample_id") or row.get("id"))
    }


def sample_metric_rows(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = data.get("samples")
    if isinstance(rows, dict):
        return {str(key): value for key, value in rows.items() if isinstance(value, dict)}
    return sample_rows(data)


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def require_schema_status(errors: list[str], data: dict[str, Any], schema: str) -> None:
    require(errors, data.get("schema") == schema, f"schema must be {schema}")
    require(errors, data.get("status") == "PASS", "status must be PASS")


def require_sample_set(errors: list[str], rows: dict[str, dict[str, Any]], expected: list[str]) -> None:
    missing = [sample for sample in expected if sample not in rows]
    extra = [sample for sample in rows if sample not in expected]
    require(errors, not missing, f"missing samples: {', '.join(missing)}")
    require(errors, not extra, f"unexpected samples: {', '.join(extra)}")


def has_all(container: Any, required: list[str]) -> bool:
    values = {str(item) for item in as_list(container)}
    return set(required) <= values


def check_bram_trace_sink(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.genesys2.bram_trace_sink.v1")
    require(errors, has_all(data.get("trace_sink_modes"), ["ila_debug", "bram_ring"]), "trace_sink_modes must include ila_debug and bram_ring")
    rows = sample_rows(data)
    require_sample_set(errors, rows, ["hello_write", "illegal_instruction"])
    for sample_id in ["hello_write", "illegal_instruction"]:
        row = rows.get(sample_id, {})
        reps = as_list(row.get("repetitions"))
        require(errors, len(reps) >= 10, f"{sample_id}: expected at least 10 repetitions")
        for index, rep in enumerate(reps, start=1):
            if not isinstance(rep, dict):
                errors.append(f"{sample_id}: repetition {index} must be an object")
                continue
            bram = rep.get("bram_ring", {}) if isinstance(rep.get("bram_ring"), dict) else {}
            require(errors, rep.get("trace_sink_mode") == "bram_ring", f"{sample_id}: rep {index} must use bram_ring")
            require(errors, rep.get("parse_success") is True, f"{sample_id}: rep {index} parse_success must be true")
            require(errors, num(rep.get("expected_event_recall")) >= 1.0, f"{sample_id}: rep {index} expected_event_recall must be 100%")
            require(errors, num(rep.get("unaccounted_drop")) == 0, f"{sample_id}: rep {index} unaccounted_drop must be 0")
            for key in ("sequence_number", "event_count", "dropped_count", "wrap_count", "start_timestamp", "end_timestamp"):
                require(errors, key in bram, f"{sample_id}: rep {index} bram_ring.{key} missing")
            require(errors, num(bram.get("event_count")) > 0, f"{sample_id}: rep {index} event_count must be positive")
            require(errors, num(bram.get("dropped_count")) == 0, f"{sample_id}: rep {index} dropped_count must be 0")
            require(errors, num(bram.get("end_timestamp")) >= num(bram.get("start_timestamp")), f"{sample_id}: rep {index} timestamp order invalid")
    return errors


def check_safe_surrogate_bram_trace(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.genesys2.safe_surrogate_bram_trace.v1")
    require(errors, data.get("evidence_scope") == "safe_syscall_only_surrogate_marker_windows", "evidence_scope mismatch")
    require(errors, data.get("trace_sink_mode") == "bram_ring", "trace_sink_mode must be bram_ring")
    require(errors, "begin-marker" in str(data.get("continuity_scope", "")).lower(), "continuity_scope must mention begin-marker clearing")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not real malware" in non_claims, "non_claims must state these are not real malware")
    require(errors, "does not claim pointer" in non_claims, "non_claims must avoid pointer semantic overclaim")
    require(errors, "does not complete" in non_claims, "non_claims must avoid CCF-A matrix overclaim")
    require(errors, num(data.get("sample_count")) == len(SAFE_SURROGATE_SAMPLES), "sample_count must match safe surrogate set")
    minimum_repetitions = max(int(num(data.get("minimum_repetitions_per_sample"), 1)), 1)
    robustness = data.get("statistical_robustness", {}) if isinstance(data.get("statistical_robustness"), dict) else {}
    if minimum_repetitions >= 10:
        require(errors, robustness.get("claimed") is True, "statistical_robustness.claimed must be true for >=10 repetition summaries")
        require(errors, num(robustness.get("minimum_observed_repetitions")) >= minimum_repetitions, "minimum observed repetitions below goal")
        require(errors, robustness.get("all_repetitions_parse_success") is True, "all repetitions must parse successfully")
        require(errors, num(robustness.get("max_unaccounted_drop")) == 0, "statistical robustness max_unaccounted_drop must be 0")
        require(errors, num(robustness.get("max_wrap_count")) == 0, "statistical robustness max_wrap_count must be 0")
    rows = sample_rows(data)
    require_sample_set(errors, rows, SAFE_SURROGATE_SAMPLES)
    for sample_id in SAFE_SURROGATE_SAMPLES:
        row = rows.get(sample_id, {})
        repetitions = as_list(row.get("repetitions")) or [row]
        require(errors, num(row.get("repetition_count", len(repetitions))) >= minimum_repetitions, f"{sample_id}: repetition_count below goal")
        require(
            errors,
            num(row.get("pass_repetition_count", len([rep for rep in repetitions if isinstance(rep, dict) and rep.get("parse_success") is True])))
            == num(row.get("repetition_count", len(repetitions))),
            f"{sample_id}: all repetitions must pass",
        )
        require(errors, row.get("trace_sink_mode") == "bram_ring", f"{sample_id}: trace_sink_mode must be bram_ring")
        require(errors, row.get("parse_success") is True, f"{sample_id}: parse_success must be true")
        require(errors, row.get("continuity_scope") == data.get("continuity_scope"), f"{sample_id}: continuity_scope mismatch")
        require(errors, num(row.get("expected_syscall_entries")) > 0, f"{sample_id}: expected_syscall_entries must be positive")
        require(
            errors,
            num(row.get("observed_syscall_entries")) >= num(row.get("expected_syscall_entries")),
            f"{sample_id}: observed syscall entries must cover build manifest",
        )
        require(errors, num(row.get("syscall_entry_recall")) >= 1.0, f"{sample_id}: syscall_entry_recall must be 100%")
        require(errors, num(row.get("unaccounted_drop")) == 0, f"{sample_id}: unaccounted_drop must be 0")
        require(errors, as_list(row.get("sequence_gaps")) == [], f"{sample_id}: sequence_gaps must be empty")
        for rep_index, rep in enumerate(repetitions, start=1):
            if not isinstance(rep, dict):
                errors.append(f"{sample_id}: repetition {rep_index} must be an object")
                continue
            rep_label = str(rep.get("repetition") or f"rep_{rep_index:02d}")
            require(errors, rep.get("trace_sink_mode") == "bram_ring", f"{sample_id}/{rep_label}: trace_sink_mode must be bram_ring")
            require(errors, rep.get("parse_success") is True, f"{sample_id}/{rep_label}: parse_success must be true")
            require(errors, num(rep.get("expected_syscall_entries")) > 0, f"{sample_id}/{rep_label}: expected_syscall_entries must be positive")
            require(
                errors,
                num(rep.get("observed_syscall_entries")) >= num(rep.get("expected_syscall_entries")),
                f"{sample_id}/{rep_label}: observed syscall entries must cover build manifest",
            )
            require(errors, num(rep.get("syscall_entry_recall")) >= 1.0, f"{sample_id}/{rep_label}: syscall_entry_recall must be 100%")
            require(errors, num(rep.get("unaccounted_drop")) == 0, f"{sample_id}/{rep_label}: unaccounted_drop must be 0")
            require(errors, as_list(rep.get("sequence_gaps")) == [], f"{sample_id}/{rep_label}: sequence_gaps must be empty")
            rep_marker = rep.get("marker_window", {}) if isinstance(rep.get("marker_window"), dict) else {}
            require(errors, rep_marker.get("begin_marker") == "0xb0000a11", f"{sample_id}/{rep_label}: begin_marker mismatch")
            require(errors, rep_marker.get("end_marker") == "0xe0000a11", f"{sample_id}/{rep_label}: end_marker mismatch")
            require(errors, num(rep_marker.get("begin_count")) == 1, f"{sample_id}/{rep_label}: expected exactly one begin marker")
            require(errors, num(rep_marker.get("end_count")) == 1, f"{sample_id}/{rep_label}: expected exactly one end marker")
            require(errors, num(rep_marker.get("begin_sequence")) == 0, f"{sample_id}/{rep_label}: begin marker must reset BRAM sequence to 0")
            require(errors, num(rep_marker.get("end_sequence")) > num(rep_marker.get("begin_sequence")), f"{sample_id}/{rep_label}: end marker must follow begin marker")
            rep_bram = rep.get("bram_ring", {}) if isinstance(rep.get("bram_ring"), dict) else {}
            require(errors, num(rep_bram.get("event_count")) > 0, f"{sample_id}/{rep_label}: bram event_count must be positive")
            require(errors, num(rep_bram.get("captured_count")) == num(rep_bram.get("event_count")), f"{sample_id}/{rep_label}: captured_count must equal event_count")
            require(errors, num(rep_bram.get("dropped_count")) == 0, f"{sample_id}/{rep_label}: dropped_count must be 0")
            require(errors, num(rep_bram.get("wrap_count")) == 0, f"{sample_id}/{rep_label}: wrap_count must be 0")
            require(errors, rep_bram.get("full") is False, f"{sample_id}/{rep_label}: BRAM ring must not be full")
            require(errors, num(rep_bram.get("end_timestamp")) >= num(rep_bram.get("start_timestamp")), f"{sample_id}/{rep_label}: timestamp order invalid")
            rep_artifacts = rep.get("artifacts", {}) if isinstance(rep.get("artifacts"), dict) else {}
            for key in ("bram_summary", "bram_records", "build_manifest", "binary", "uart_log", "capture_log"):
                value = rep_artifacts.get(key)
                require(errors, bool(value), f"{sample_id}/{rep_label}: artifact {key} missing")
                if value:
                    require(errors, repo_path(root, Path(str(value))).is_file(), f"{sample_id}/{rep_label}: artifact file missing: {value}")
            for key in ("ila_trace", "upload_log"):
                value = rep_artifacts.get(key)
                require(errors, isinstance(value, str) and bool(value), f"{sample_id}/{rep_label}: optional artifact {key} marker missing")
                if value and value != "NOT_CAPTURED":
                    require(errors, repo_path(root, Path(value)).is_file(), f"{sample_id}/{rep_label}: optional artifact file missing: {value}")
        marker = row.get("marker_window", {}) if isinstance(row.get("marker_window"), dict) else {}
        require(errors, marker.get("begin_marker") == "0xb0000a11", f"{sample_id}: begin_marker mismatch")
        require(errors, marker.get("end_marker") == "0xe0000a11", f"{sample_id}: end_marker mismatch")
        require(errors, num(marker.get("begin_count")) == 1, f"{sample_id}: expected exactly one begin marker")
        require(errors, num(marker.get("end_count")) == 1, f"{sample_id}: expected exactly one end marker")
        require(errors, num(marker.get("begin_sequence")) == 0, f"{sample_id}: begin marker must reset BRAM sequence to 0")
        require(errors, num(marker.get("end_sequence")) > num(marker.get("begin_sequence")), f"{sample_id}: end marker must follow begin marker")
        bram = row.get("bram_ring", {}) if isinstance(row.get("bram_ring"), dict) else {}
        require(errors, num(bram.get("event_count")) > 0, f"{sample_id}: bram event_count must be positive")
        require(errors, num(bram.get("captured_count")) == num(bram.get("event_count")), f"{sample_id}: captured_count must equal event_count")
        require(errors, num(bram.get("dropped_count")) == 0, f"{sample_id}: dropped_count must be 0")
        require(errors, num(bram.get("wrap_count")) == 0, f"{sample_id}: wrap_count must be 0")
        require(errors, bram.get("full") is False, f"{sample_id}: BRAM ring must not be full")
        require(errors, num(bram.get("end_timestamp")) >= num(bram.get("start_timestamp")), f"{sample_id}: timestamp order invalid")
        artifacts = row.get("artifacts", {}) if isinstance(row.get("artifacts"), dict) else {}
        for key in ("bram_summary", "bram_records", "build_manifest", "binary", "uart_log", "capture_log"):
            value = artifacts.get(key)
            require(errors, bool(value), f"{sample_id}: artifact {key} missing")
            if value:
                require(errors, repo_path(root, Path(str(value))).is_file(), f"{sample_id}: artifact file missing: {value}")
        for key in ("ila_trace", "upload_log"):
            value = artifacts.get(key)
            require(errors, isinstance(value, str) and bool(value), f"{sample_id}: optional artifact {key} marker missing")
            if value and value != "NOT_CAPTURED":
                require(errors, repo_path(root, Path(value)).is_file(), f"{sample_id}: optional artifact file missing: {value}")
        digest = str(artifacts.get("binary_sha256") or "")
        require(errors, len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest), f"{sample_id}: binary_sha256 invalid")
    return errors


def check_genesys2_p0_bram_trace(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.genesys2.p0_bram_trace.v1")
    require(errors, data.get("evidence_scope") == "p0_safe_synthetic_marker_windows", "evidence_scope mismatch")
    require(errors, data.get("trace_sink_mode") == "bram_ring", "trace_sink_mode must be bram_ring")
    require(errors, "begin-marker" in str(data.get("continuity_scope", "")).lower(), "continuity_scope must mention begin-marker clearing")
    require(errors, bool(data.get("bitstream_sha256")), "bitstream_sha256 required")
    require(errors, bool(data.get("ltx_sha256")), "ltx_sha256 required")
    for key in ("bitstream", "ltx"):
        value = data.get(key)
        require(errors, bool(value), f"{key} path required")
        if value:
            require(errors, repo_path(root, Path(str(value))).is_file(), f"{key} file missing: {value}")
    for key in ("bitstream_sha256", "ltx_sha256"):
        digest = str(data.get(key) or "")
        require(errors, len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest), f"{key} invalid")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not real malware" in non_claims, "non_claims must state P0 samples are not real malware")
    require(errors, "pointer" in non_claims and "not" in non_claims, "non_claims must avoid pointer-string overclaim")
    require(errors, "streaming" in non_claims or "throughput" in non_claims, "non_claims must avoid production streaming overclaim")
    require(errors, num(data.get("sample_count")) == len(P0_SAMPLES), "sample_count must match P0 set")
    minimum_repetitions = max(int(num(data.get("minimum_repetitions_per_sample"), 1)), 1)
    robustness = data.get("statistical_robustness", {}) if isinstance(data.get("statistical_robustness"), dict) else {}
    if minimum_repetitions >= 10:
        require(errors, robustness.get("claimed") is True, "statistical_robustness.claimed must be true for >=10 repetition summaries")
        require(errors, num(robustness.get("minimum_observed_repetitions")) >= minimum_repetitions, "minimum observed repetitions below goal")
        require(errors, robustness.get("all_repetitions_parse_success") is True, "all repetitions must parse successfully")
        require(errors, num(robustness.get("max_unaccounted_drop")) == 0, "statistical robustness max_unaccounted_drop must be 0")
        require(errors, num(robustness.get("max_wrap_count")) == 0, "statistical robustness max_wrap_count must be 0")
    rows = sample_rows(data)
    require_sample_set(errors, rows, P0_SAMPLES)
    for sample_id in P0_SAMPLES:
        row = rows.get(sample_id, {})
        repetitions = as_list(row.get("repetitions")) or [row]
        begin_marker, end_marker = P0_BRAM_MARKERS[sample_id]
        require(errors, num(row.get("repetition_count", len(repetitions))) >= minimum_repetitions, f"{sample_id}: repetition_count below goal")
        require(errors, num(row.get("pass_repetition_count", 0)) == num(row.get("repetition_count", len(repetitions))), f"{sample_id}: all repetitions must pass")
        require(errors, row.get("trace_sink_mode") == "bram_ring", f"{sample_id}: trace_sink_mode must be bram_ring")
        require(errors, row.get("parse_success") is True, f"{sample_id}: parse_success must be true")
        require(errors, num(row.get("observed_syscall_entries")) >= num(row.get("expected_syscall_entries")), f"{sample_id}: observed syscall entries must cover build manifest")
        require(errors, num(row.get("strict_pairable_syscall_entries")) >= num(row.get("expected_pairable_syscall_entries")), f"{sample_id}: pairable syscall entry/ret coverage incomplete")
        require(errors, num(row.get("unaccounted_drop")) == 0, f"{sample_id}: unaccounted_drop must be 0")
        require(errors, as_list(row.get("sequence_gaps")) == [], f"{sample_id}: sequence_gaps must be empty")
        for rep_index, rep in enumerate(repetitions, start=1):
            if not isinstance(rep, dict):
                errors.append(f"{sample_id}: repetition {rep_index} must be an object")
                continue
            rep_label = str(rep.get("repetition") or f"rep_{rep_index:02d}")
            require(errors, rep.get("trace_sink_mode") == "bram_ring", f"{sample_id}/{rep_label}: trace_sink_mode must be bram_ring")
            require(errors, rep.get("parse_success") is True, f"{sample_id}/{rep_label}: parse_success must be true")
            require(errors, num(rep.get("observed_syscall_entries")) >= num(rep.get("expected_syscall_entries")), f"{sample_id}/{rep_label}: observed syscall entries must cover build manifest")
            require(errors, num(rep.get("strict_pairable_syscall_entries")) >= num(rep.get("expected_pairable_syscall_entries")), f"{sample_id}/{rep_label}: pairable syscall entry/ret coverage incomplete")
            require(errors, num(rep.get("unaccounted_drop")) == 0, f"{sample_id}/{rep_label}: unaccounted_drop must be 0")
            require(errors, as_list(rep.get("sequence_gaps")) == [], f"{sample_id}/{rep_label}: sequence_gaps must be empty")
            rep_marker = rep.get("marker_window", {}) if isinstance(rep.get("marker_window"), dict) else {}
            require(errors, rep_marker.get("begin_marker") == begin_marker, f"{sample_id}/{rep_label}: begin_marker mismatch")
            require(errors, rep_marker.get("end_marker") == end_marker, f"{sample_id}/{rep_label}: end_marker mismatch")
            require(errors, num(rep_marker.get("begin_count")) == 1, f"{sample_id}/{rep_label}: expected exactly one begin marker")
            require(errors, num(rep_marker.get("end_count")) == 1, f"{sample_id}/{rep_label}: expected exactly one end marker")
            require(errors, num(rep_marker.get("begin_sequence")) == 0, f"{sample_id}/{rep_label}: begin marker must reset BRAM sequence to 0")
            require(errors, num(rep_marker.get("end_sequence")) > num(rep_marker.get("begin_sequence")), f"{sample_id}/{rep_label}: end marker must follow begin marker")
            rep_bram = rep.get("bram_ring", {}) if isinstance(rep.get("bram_ring"), dict) else {}
            require(errors, num(rep_bram.get("event_count")) > 0, f"{sample_id}/{rep_label}: bram event_count must be positive")
            require(errors, num(rep_bram.get("captured_count")) == num(rep_bram.get("event_count")), f"{sample_id}/{rep_label}: captured_count must equal event_count")
            require(errors, num(rep_bram.get("dropped_count")) == 0, f"{sample_id}/{rep_label}: dropped_count must be 0")
            require(errors, num(rep_bram.get("wrap_count")) == 0, f"{sample_id}/{rep_label}: wrap_count must be 0")
            require(errors, rep_bram.get("full") is False, f"{sample_id}/{rep_label}: BRAM ring must not be full")
            artifacts = rep.get("artifacts", {}) if isinstance(rep.get("artifacts"), dict) else {}
            for key in ("bram_summary", "bram_records", "build_manifest", "binary", "uart_log", "capture_log", "capture_err_log"):
                value = artifacts.get(key)
                require(errors, bool(value), f"{sample_id}/{rep_label}: artifact {key} missing")
                if value:
                    require(errors, repo_path(root, Path(str(value))).is_file(), f"{sample_id}/{rep_label}: artifact file missing: {value}")
        failed_attempts = as_list(row.get("failed_attempts"))
        require(errors, num(row.get("failed_attempt_count", len(failed_attempts))) == len(failed_attempts), f"{sample_id}: failed_attempt_count mismatch")
        for failed_index, failed in enumerate(failed_attempts, start=1):
            if not isinstance(failed, dict):
                errors.append(f"{sample_id}: failed attempt {failed_index} must be an object")
                continue
            failed_label = str(failed.get("repetition") or f"failed_{failed_index:02d}")
            require(errors, failed.get("parse_success") is False, f"{sample_id}/{failed_label}: failed attempt must not be parse_success")
            failed_artifacts = failed.get("artifacts", {}) if isinstance(failed.get("artifacts"), dict) else {}
            for key in ("bram_summary", "bram_records", "uart_log", "capture_log", "capture_err_log"):
                value = failed_artifacts.get(key)
                require(errors, bool(value), f"{sample_id}/{failed_label}: failed artifact {key} missing")
                if value:
                    require(errors, repo_path(root, Path(str(value))).is_file(), f"{sample_id}/{failed_label}: failed artifact file missing: {value}")
        marker = row.get("marker_window", {}) if isinstance(row.get("marker_window"), dict) else {}
        require(errors, marker.get("begin_marker") == begin_marker, f"{sample_id}: begin_marker mismatch")
        require(errors, marker.get("end_marker") == end_marker, f"{sample_id}: end_marker mismatch")
        artifacts = row.get("artifacts", {}) if isinstance(row.get("artifacts"), dict) else {}
        digest = str(artifacts.get("binary_sha256") or "")
        require(errors, len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest), f"{sample_id}: binary_sha256 invalid")
    return errors


def check_trace_drop_accounting(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.trace_drop_accounting.v1")
    require(errors, data.get("correctness_mode") is True, "correctness_mode must be true")
    require(
        errors,
        data.get("correctness_scope") in {"captured_trace_windows", "continuous_marker_window"},
        "correctness_scope must be captured_trace_windows or continuous_marker_window",
    )
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    if data.get("correctness_scope") == "captured_trace_windows":
        require(errors, "continuous" in non_claims and "not" in non_claims, "captured-window summaries must include a continuous-trace non-claim")
    rows = sample_rows(data)
    require_sample_set(errors, rows, ALL_CCFA_SAMPLES)
    for sample_id, row in rows.items():
        require(errors, num(row.get("unaccounted_drop")) == 0, f"{sample_id}: unaccounted_drop must be 0")
        require(errors, num(row.get("total_events")) > 0, f"{sample_id}: total_events must be positive")
        if num(row.get("drop_events")) > 0:
            require(errors, bool(row.get("impact_analysis")), f"{sample_id}: DROP events require impact_analysis")
            require(errors, bool(row.get("drop_locations")), f"{sample_id}: DROP events require drop_locations")
        for failed_index, failed in enumerate(as_list(row.get("failed_attempts")), start=1):
            if not isinstance(failed, dict):
                errors.append(f"{sample_id}: failed attempt {failed_index} must be an object")
                continue
            label = str(failed.get("repetition_id") or failed.get("repetition") or failed_index)
            require(errors, failed.get("status") == "FAIL", f"{sample_id}/{label}: failed attempt must have status FAIL")
            require(
                errors,
                num(failed.get("unaccounted_drop")) > 0 or num(failed.get("bram_wrap_count")) > 0,
                f"{sample_id}/{label}: failed attempt must record DROP or wrap impact",
            )
            require(errors, bool(failed.get("impact_analysis")), f"{sample_id}/{label}: failed attempt impact_analysis required")
    return errors


def check_syscall_semantic_reconstruction(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    source_values = {"qemu_guest_strace", "host_or_control_strace"}
    require_schema_status(errors, data, "rvmt.syscall_semantic_reconstruction.v1")
    rows = sample_rows(data)
    require_sample_set(errors, rows, ALL_CCFA_SAMPLES)
    for sample_id, row in rows.items():
        require(errors, num(row.get("expected_syscall_recall")) >= 0.95, f"{sample_id}: syscall recall below 95%")
        require(errors, num(row.get("syscall_precision")) >= 0.95, f"{sample_id}: syscall precision below 95%")
        require(errors, num(row.get("argument_reconstruction_accuracy")) >= 0.95, f"{sample_id}: argument accuracy below 95%")
        if row.get("has_openat"):
            require(errors, num(row.get("openat_pathname_accuracy")) >= 1.0, f"{sample_id}: openat pathname accuracy must be 100%")
            require(errors, row.get("openat_path_source") in source_values, f"{sample_id}: openat source invalid")
        else:
            require(errors, row.get("openat_path_source") == "NOT_OBSERVED", f"{sample_id}: openat source must be NOT_OBSERVED")
        if row.get("has_execve"):
            require(errors, num(row.get("execve_filename_accuracy")) >= 1.0, f"{sample_id}: execve filename accuracy must be 100%")
            require(errors, row.get("execve_path_source") in source_values, f"{sample_id}: execve source invalid")
        else:
            require(errors, row.get("execve_path_source") == "NOT_OBSERVED", f"{sample_id}: execve source must be NOT_OBSERVED")
        if row.get("has_write"):
            require(errors, row.get("write_buffer_prefix_recovered") is True, f"{sample_id}: write buffer prefix not recovered")
            require(errors, row.get("write_buffer_prefix_source") in source_values, f"{sample_id}: write prefix source invalid")
        else:
            require(errors, row.get("write_buffer_prefix_source") == "NOT_OBSERVED", f"{sample_id}: write prefix source must be NOT_OBSERVED")
        if sample_id == "dynamic_executable_memory":
            require(errors, row.get("mmap_mprotect_behavior_node") is True, "dynamic_executable_memory: executable-memory behavior node missing")
        if sample_id == "anti_debug_like":
            require(errors, row.get("anti_analysis_behavior_node") is True, "anti_debug_like: anti-analysis behavior node missing")
        alignment = row.get("ground_truth_alignment", {}) if isinstance(row.get("ground_truth_alignment"), dict) else {}
        require(errors, alignment.get("strace") is True and alignment.get("qemu_strace") is True, f"{sample_id}: strace/qemu-strace alignment required")
    return errors


def check_pointer_snapshot_guardrails(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.pointer_snapshot_guardrails.v1")
    require(errors, data.get("snapshot_mode") in {"disabled", "bounded_prefix"}, "snapshot_mode must be disabled or bounded_prefix")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    if data.get("snapshot_mode") == "disabled":
        require(errors, "semantic reconstruction" in non_claims and "not" in non_claims, "disabled snapshot mode must include a semantic-reconstruction non-claim")
    if data.get("snapshot_mode") == "bounded_prefix":
        require(errors, data.get("hardware_user_pointer_snapshot") is True, "bounded-prefix mode must include hardware user-pointer snapshots")
        require(errors, data.get("hardware_derived_pointer_strings") is False, "hardware_derived_pointer_strings must be false")
        require(errors, data.get("hardware_pointer_strings_claimed") is False, "hardware_pointer_strings_claimed must be false")
        require(errors, data.get("companion_derived_strings_as_hardware") is False, "companion-derived strings must not be claimed as hardware strings")
        require(errors, "companion" in non_claims and "hardware" in non_claims, "bounded-prefix non_claims must separate companion and hardware strings")
        coverage = data.get("hardware_snapshot_syscall_coverage", {}) if isinstance(data.get("hardware_snapshot_syscall_coverage"), dict) else {}
        for syscall_name in ["openat", "execve", "write"]:
            require(errors, coverage.get(syscall_name) is True, f"hardware ARG_MEM coverage missing for {syscall_name}")
    policy = data.get("policy", {}) if isinstance(data.get("policy"), dict) else {}
    require(errors, policy.get("full_memory_dump") is False, "full_memory_dump must be false")
    require(errors, policy.get("captures_kernel_memory") is False, "captures_kernel_memory must be false")
    require(errors, policy.get("network_default") in {"disabled", "isolated"}, "network_default must be disabled or isolated")
    require(errors, 0 < num(policy.get("max_bytes_per_pointer")) <= 4096, "max_bytes_per_pointer must be 1..4096")
    require(errors, has_all(policy.get("allowed_syscalls"), PRIORITY_SYSCALLS), "allowed_syscalls must cover priority syscalls")
    if data.get("snapshot_mode") == "bounded_prefix":
        require(errors, has_all(policy.get("hardware_snapshot_syscalls"), ["openat", "execve", "write"]), "hardware_snapshot_syscalls must cover openat/execve/write")
    require(errors, bool(policy.get("redaction_policy")), "redaction_policy required")
    require(errors, bool(policy.get("bounds_checking")), "bounds_checking required")
    rows = sample_rows(data)
    require_sample_set(errors, rows, ALL_CCFA_SAMPLES)
    for sample_id, row in rows.items():
        require(errors, row.get("guardrails_pass") is True, f"{sample_id}: guardrails_pass must be true")
        require(errors, num(row.get("snapshot_bytes")) <= num(policy.get("max_bytes_per_pointer")) * max(num(row.get("snapshot_count")), 1), f"{sample_id}: snapshot byte budget exceeded")
        require(errors, row.get("raw_payload_release") in {"none", "local_only_or_sanitized_summary"}, f"{sample_id}: raw payload release policy is too broad")
        require(errors, row.get("hardware_derived_pointer_strings") is False, f"{sample_id}: hardware_derived_pointer_strings must be false")
        require(errors, row.get("hardware_pointer_strings_claimed") is False, f"{sample_id}: hardware_pointer_strings_claimed must be false")
        require(errors, row.get("companion_derived_strings_as_hardware") is False, f"{sample_id}: companion-derived strings must not be claimed as hardware strings")
        if num(row.get("snapshot_count")) > 0:
            require(errors, row.get("snapshot_mode") == "bounded_prefix", f"{sample_id}: snapshot rows must use bounded_prefix mode")
            require(errors, row.get("hardware_user_pointer_snapshot") is True, f"{sample_id}: hardware snapshot flag missing")
            require(errors, num(row.get("kernel_address_snapshot_count")) == 0, f"{sample_id}: kernel pointer snapshot present")
    return errors


def check_fd_path_graph(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.fd_path_graph.v1")
    rows = sample_rows(data)
    require_sample_set(errors, rows, ALL_CCFA_SAMPLES)
    for sample_id, row in rows.items():
        require(errors, row.get("fd_graph_complete") is True, f"{sample_id}: fd_graph_complete must be true")
        require(errors, num(row.get("unresolved_fd_count")) == 0, f"{sample_id}: unresolved_fd_count must be 0")
        if row.get("has_openat"):
            require(errors, num(row.get("openat_pathname_accuracy")) >= 1.0, f"{sample_id}: openat pathname accuracy must be 100%")
        if row.get("has_execve"):
            require(errors, num(row.get("execve_filename_accuracy")) >= 1.0, f"{sample_id}: execve filename accuracy must be 100%")
        require(errors, row.get("graph_schema") == "rvmt.fd_path.graph.v1", f"{sample_id}: fd/path graph schema mismatch")
    return errors


def check_source_line_attribution(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.source_line_attribution.v1")
    require(errors, num(data.get("debug_no_pie_source_line_attribution_rate")) >= 0.95, "debug/no-PIE source-line attribution must be >= 95%")
    require(errors, num(data.get("release_no_debug_function_attribution_rate")) >= 0.90, "release/no-debug function attribution must be >= 90%")
    rows = sample_rows(data)
    require_sample_set(errors, rows, ALL_CCFA_SAMPLES)
    for sample_id, row in rows.items():
        require(errors, num(row.get("key_event_count")) > 0, f"{sample_id}: key_event_count must be positive")
        require(errors, num(row.get("unknown_key_events")) == 0, f"{sample_id}: unknown_key_events must be 0")
        require(errors, row.get("function_attribution_available") is True, f"{sample_id}: function attribution missing")
        if row.get("debug_build"):
            require(errors, row.get("source_line_attribution_available") is True, f"{sample_id}: debug source-line attribution missing")
    require(errors, data.get("fork_exec_child_target_attribution_proven") is True, "fork/exec child attribution must be proven")
    require(errors, data.get("dynamic_library_events_not_misattributed") is True, "dynamic library events must not be misattributed")
    return errors


def check_process_elf_ownership(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.process_elf_ownership.v1")
    rows = sample_rows(data)
    require_sample_set(errors, rows, ALL_CCFA_SAMPLES)
    for sample_id, row in rows.items():
        require(errors, row.get("runtime_process_attribution_proven") is True, f"{sample_id}: runtime process attribution not proven")
        require(errors, bool(row.get("pid")) and bool(row.get("tgid")), f"{sample_id}: PID/TGID missing")
        require(errors, bool(row.get("executable_path")), f"{sample_id}: executable_path missing")
        require(errors, num(row.get("target_elf_attributed_events")) > 0, f"{sample_id}: no target ELF events")
        require(errors, row.get("dynamic_library_events_correctly_separated") is True, f"{sample_id}: dynamic library separation missing")
    require(errors, rows.get("fork_exec", {}).get("child_process_target_attribution_proven") is True, "fork_exec child process target attribution must be proven")
    return errors


def check_dynamic_mapping_attribution(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.dynamic_mapping_attribution.v1")
    cases = data.get("cases", {}) if isinstance(data.get("cases"), dict) else {}
    for case in ["static_binary", "no_pie_binary", "pie_binary", "dynamic_loader", "shared_libraries", "fork_exec_child"]:
        row = cases.get(case, {}) if isinstance(cases.get(case), dict) else {}
        require(errors, row.get("pass") is True, f"{case}: pass must be true")
        require(errors, bool(row.get("evidence")), f"{case}: evidence required")
    require(errors, data.get("dynamic_library_events_not_target_binary") is True, "dynamic library events must not be attributed to target binary")
    require(errors, data.get("aslr_load_bias_accounted") is True, "ASLR/PIE load bias must be accounted")
    return errors


def check_ccfa_evaluation_matrix(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.ccfa_evaluation_matrix.v1")
    require(errors, bool(data.get("workload_manifest")), "workload_manifest required")
    require(errors, has_all(data.get("baselines"), BASELINES), "baseline matrix incomplete")
    require(errors, has_all(data.get("ablations"), ABLATIONS), "ablation matrix incomplete")
    require(errors, bool(data.get("resource_timing_summary")), "resource_timing_summary required")
    require(errors, bool(data.get("limitations")), "limitations required")
    rows = sample_rows(data)
    require_sample_set(errors, rows, ALL_CCFA_SAMPLES)
    for sample_id, row in rows.items():
        for key in (
            "trace",
            "semantic_events",
            "behavior_graph",
            "behavior_mapping",
            "integrated_validation",
            "behavior_audit_metrics",
            "baseline_logs",
            "metric_summary",
        ):
            value = row.get(key)
            require(errors, bool(value), f"{sample_id}: {key} required")
            if value and "*" not in str(value):
                require(errors, repo_path(root, Path(str(value))).is_file(), f"{sample_id}: {key} artifact missing: {value}")
        require(errors, row.get("continuous_trace") is True, f"{sample_id}: continuous_trace must be true")
        require(errors, num(row.get("unaccounted_drop")) == 0, f"{sample_id}: unaccounted_drop must be 0")
    return errors


def check_baseline_alignment(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.baseline_alignment.v1")
    rows = data.get("baselines", {}) if isinstance(data.get("baselines"), dict) else {}
    for baseline in BASELINES:
        row = rows.get(baseline, {}) if isinstance(rows.get(baseline), dict) else {}
        require(errors, row.get("present") is True, f"{baseline}: baseline missing")
        require(errors, row.get("alignment_pass") is True, f"{baseline}: alignment_pass must be true")
        require(errors, bool(row.get("command_transcript")), f"{baseline}: command_transcript required")
    require(errors, data.get("anti_analysis_baseline_comparison") is True, "anti-analysis baseline comparison required")
    require(errors, data.get("overhead_baseline_comparison") is True, "overhead baseline comparison required")
    return errors


def check_behavior_audit_metrics(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.behavior_audit_metrics.v1")
    metrics = data.get("metrics", {}) if isinstance(data.get("metrics"), dict) else {}
    thresholds = {
        "expected_syscall_recall": 0.95,
        "syscall_precision": 0.95,
        "argument_reconstruction_accuracy": 0.95,
        "behavior_rule_recall": 0.90,
        "anti_analysis_visibility": 1.0,
    }
    for key, threshold in thresholds.items():
        require(errors, num(metrics.get(key)) >= threshold, f"{key} below threshold {threshold}")
    require(errors, num(metrics.get("benign_false_positive_rate")) <= 0.05, "benign false positive rate must be <= 5%")
    require(errors, num(metrics.get("unaccounted_drop")) == 0, "unaccounted_drop must be 0")
    overhead = data.get("overhead", {}) if isinstance(data.get("overhead"), dict) else {}
    for key in ("median", "p95", "variance"):
        require(errors, key in overhead, f"overhead.{key} required")
    require(errors, bool(data.get("resource_overhead")), "resource_overhead required")
    require(errors, bool(data.get("baseline_comparison")), "baseline_comparison required")
    benign_control = data.get("benign_control_summary")
    require(errors, bool(benign_control), "benign_control_summary required")
    if benign_control:
        benign_path = repo_path(root, Path(str(benign_control)))
        require(errors, benign_path.is_file(), f"benign_control_summary missing: {benign_control}")
        if benign_path.is_file():
            try:
                benign_data = load_json(benign_path)
            except Exception as exc:
                errors.append(f"benign_control_summary invalid JSON: {exc}")
            else:
                require(errors, benign_data.get("schema") == "rvmt.genesys2.benign_control_summary.v1", "benign control schema mismatch")
                require(errors, benign_data.get("status") == "PASS", "benign control status must be PASS")
                aggregate = benign_data.get("aggregate", {}) if isinstance(benign_data.get("aggregate"), dict) else {}
                require(errors, num(aggregate.get("sample_count")) >= 5, "benign control must cover at least five samples")
                require(errors, num(aggregate.get("unexpected_false_positive_count")) == 0, "benign control unexpected false positives must be zero")
                require(
                    errors,
                    num(aggregate.get("benign_false_positive_rate")) == num(metrics.get("benign_false_positive_rate")),
                    "benign control false-positive rate must match behavior metrics",
                )
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not real-malware detection accuracy" in non_claims or "not real malware detection accuracy" in non_claims, "behavior metrics must not claim real-malware detection accuracy")
    rows = sample_metric_rows(data)
    missing_safe = [sample for sample in SAFE_SURROGATE_SAMPLES if sample not in rows]
    require(errors, not missing_safe, f"missing safe surrogate metric rows: {', '.join(missing_safe)}")
    artifact_root = repo_path(root, Path(str(data.get("sample_artifact_root") or "results/evaluation/genesys2-cva6/current/samples")))
    required_artifacts = [
        "semantic_events.json",
        "behavior_graph.json",
        "behavior_mapping.json",
        "integrated_validation.json",
        "behavior_audit_metrics.json",
    ]
    for sample_id in SAFE_SURROGATE_SAMPLES:
        row = rows.get(sample_id, {})
        for key, threshold in thresholds.items():
            require(errors, num(row.get(key)) >= threshold, f"{sample_id}: {key} below threshold {threshold}")
        require(errors, num(row.get("unaccounted_drop")) == 0, f"{sample_id}: unaccounted_drop must be 0")
        for artifact_name in required_artifacts:
            artifact_path = artifact_root / sample_id / artifact_name
            require(errors, artifact_path.is_file(), f"{sample_id}: missing audit artifact {artifact_path.as_posix()}")
            if not artifact_path.is_file():
                continue
            try:
                artifact = load_json(artifact_path)
            except Exception as exc:
                errors.append(f"{sample_id}: invalid audit artifact {artifact_path.as_posix()}: {exc}")
                continue
            require(errors, artifact.get("sample_id") == sample_id, f"{sample_id}: {artifact_name} sample_id mismatch")
            require(errors, artifact.get("real_malware") is False, f"{sample_id}: {artifact_name} must set real_malware=false")
            sample_class = str(artifact.get("sample_class") or "")
            require(errors, "malware_like" in sample_class and "synthetic" in sample_class, f"{sample_id}: {artifact_name} must be malware-like synthetic scope")
            artifact_non_claims = " ".join(str(item).lower() for item in as_list(artifact.get("non_claims")))
            require(errors, "not real malware" in artifact_non_claims or "not real-malware" in artifact_non_claims, f"{sample_id}: {artifact_name} must carry real-malware non-claim")
    return errors


def check_real_malware_containment(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require_schema_status(errors, data, "rvmt.real_malware_containment.v1")
    policy_path = repo_path(root, Path(str(data.get("policy_path") or "docs/ethics/real_malware_policy.md")))
    require(errors, policy_path.is_file(), f"policy file missing: {policy_path}")
    require(errors, data.get("payloads_in_repo") is False, "payloads_in_repo must be false")
    require(errors, data.get("network_default") == "disabled", "network_default must be disabled")
    require(errors, data.get("isolated_environment") is True, "isolated_environment must be true")
    require(errors, data.get("hash_metadata_only") is True, "hash_metadata_only must be true")
    require(errors, data.get("sanitized_reports_only") is True, "sanitized_reports_only must be true")
    require(errors, data.get("main_claim") == "optional real-malware case study", "main_claim must be optional real-malware case study")
    for forbidden in [
        root / "samples/real_malware",
        root / "experiments/linux_behavior/real_malware/samples",
        root / "experiments/linux_behavior/real_malware/payloads",
        root / "experiments/linux_behavior/real_malware/binaries",
    ]:
        if forbidden.exists():
            files = [path for path in forbidden.rglob("*") if path.is_file()]
            require(errors, not files, f"repository malware payload files present under {forbidden}")
    return errors


def good_sample(sample_id: str) -> dict[str, Any]:
    has_openat = sample_id in {"file_open_read_write", "file_scan", "batch_open_read_write", "self_copy_sim", "abnormal_syscall_sequence", "anti_debug_like"}
    has_execve = sample_id in {"fork_exec", "process_chain"}
    has_write = True
    return {
        "sample_id": sample_id,
        "total_events": 10,
        "drop_events": 0,
        "unaccounted_drop": 0,
        "expected_syscall_recall": 1.0,
        "syscall_precision": 1.0,
        "argument_reconstruction_accuracy": 1.0,
        "has_openat": has_openat,
        "openat_pathname_accuracy": 1.0,
        "openat_path_source": "qemu_guest_strace" if has_openat else "NOT_OBSERVED",
        "has_execve": has_execve,
        "execve_filename_accuracy": 1.0,
        "execve_path_source": "qemu_guest_strace" if has_execve else "NOT_OBSERVED",
        "has_write": has_write,
        "write_buffer_prefix_recovered": True,
        "write_buffer_prefix_source": "host_or_control_strace" if has_write else "NOT_OBSERVED",
        "mmap_mprotect_behavior_node": sample_id == "dynamic_executable_memory",
        "anti_analysis_behavior_node": sample_id == "anti_debug_like",
        "ground_truth_alignment": {"strace": True, "qemu_strace": True},
        "guardrails_pass": True,
        "snapshot_count": 1,
        "snapshot_bytes": 32,
        "snapshot_mode": "bounded_prefix",
        "snapshot_sources": ["hardware_bram_ring_compact"],
        "snapshot_syscalls": ["openat"],
        "hardware_snapshot_syscalls": ["openat"],
        "hardware_snapshot_syscall_coverage": {"openat": True, "execve": False, "write": False},
        "hardware_user_pointer_snapshot": True,
        "hardware_derived_pointer_strings": False,
        "hardware_pointer_strings_claimed": False,
        "companion_derived_strings_as_hardware": False,
        "kernel_address_snapshot_count": 0,
        "raw_payload_release": "local_only_or_sanitized_summary",
        "fd_graph_complete": True,
        "unresolved_fd_count": 0,
        "graph_schema": "rvmt.fd_path.graph.v1",
        "key_event_count": 10,
        "unknown_key_events": 0,
        "function_attribution_available": True,
        "debug_build": True,
        "source_line_attribution_available": True,
        "runtime_process_attribution_proven": True,
        "pid": 100,
        "tgid": 100,
        "executable_path": f"/tmp/rvmt/{sample_id}",
        "target_elf_attributed_events": 3,
        "dynamic_library_events_correctly_separated": True,
        "child_process_target_attribution_proven": sample_id == "fork_exec",
        "trace": f"{sample_id}/trace.jsonl",
        "semantic_events": f"{sample_id}/semantic_events.json",
        "behavior_graph": f"{sample_id}/behavior_graph.json",
        "behavior_mapping": f"{sample_id}/behavior_mapping.json",
        "integrated_validation": f"{sample_id}/integrated_validation.json",
        "behavior_audit_metrics": f"{sample_id}/behavior_audit_metrics.json",
        "baseline_logs": f"{sample_id}/baseline.log",
        "metric_summary": f"{sample_id}/metrics.json",
        "continuous_trace": True,
    }


def fixture_bram_trace_sink(path: Path) -> None:
    reps = [
        {
            "trace_sink_mode": "bram_ring",
            "parse_success": True,
            "expected_event_recall": 1.0,
            "unaccounted_drop": 0,
            "bram_ring": {
                "sequence_number": index,
                "event_count": 8,
                "dropped_count": 0,
                "wrap_count": 0,
                "start_timestamp": index * 100,
                "end_timestamp": index * 100 + 10,
            },
        }
        for index in range(10)
    ]
    write_json(
        path,
        {
            "schema": "rvmt.genesys2.bram_trace_sink.v1",
            "status": "PASS",
            "trace_sink_modes": ["ila_debug", "bram_ring"],
            "samples": [
                {"sample_id": "hello_write", "repetitions": reps},
                {"sample_id": "illegal_instruction", "repetitions": reps},
            ],
        },
    )


def fixture_safe_surrogate_bram_trace(path: Path) -> None:
    samples: list[dict[str, Any]] = []
    for index, sample_id in enumerate(SAFE_SURROGATE_SAMPLES, start=1):
        base = path.parent / "fixture-safe-bram" / sample_id
        rep_dir = base / "rep_01"
        build_dir = base / "build"
        rep_dir.mkdir(parents=True, exist_ok=True)
        build_dir.mkdir(parents=True, exist_ok=True)
        bram_summary = rep_dir / "bram_summary.json"
        bram_records = rep_dir / "bram_records.jsonl"
        build_manifest = build_dir / "build_manifest.json"
        binary = build_dir / f"{sample_id}.riscv64"
        uart_log = rep_dir / "uart.log"
        capture_log = rep_dir / "capture.log"
        write_json(
            bram_summary,
            {
                "schema": "rvmt.genesys2.bram_ring_dump.v1",
                "status": "PASS",
                "bram_ring": {"event_count": 5, "captured_count": 5, "dropped_count": 0, "wrap_count": 0},
            },
        )
        bram_records.write_text(
            "\n".join(
                [
                    json.dumps({"evt": "MARKER", "packed_primary": "0xb0000a11", "sequence_number": 0}),
                    json.dumps({"evt": "SYSCALL_ENTRY", "packed_primary": "0x00000038", "sequence_number": 1}),
                    json.dumps({"evt": "SYSCALL_ENTRY", "packed_primary": "0x00000040", "sequence_number": 2}),
                    json.dumps({"evt": "MARKER", "packed_primary": "0xe0000a11", "sequence_number": 3}),
                    json.dumps({"evt": "SYSCALL_ENTRY", "packed_primary": "0x0000005d", "sequence_number": 4}),
                ]
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        write_json(build_manifest, {"sample_id": sample_id, "syscall_sequence": ["rvmt_marker", "openat", "write", "rvmt_marker", "exit"]})
        binary.write_bytes(b"\x7fELFfixture")
        uart_log.write_text("fixture uart\n", encoding="utf-8", newline="\n")
        capture_log.write_text("fixture capture\n", encoding="utf-8", newline="\n")
        samples.append(
            {
                "sample_id": sample_id,
                "trace_sink_mode": "bram_ring",
                "continuity_scope": "begin-marker-cleared BRAM ring through capture readout",
                "parse_success": True,
                "expected_syscall_entries": 3,
                "observed_syscall_entries": 3,
                "syscall_entry_recall": 1.0,
                "unaccounted_drop": 0,
                "sequence_gaps": [],
                "marker_window": {
                    "begin_marker": "0xb0000a11",
                    "end_marker": "0xe0000a11",
                    "begin_count": 1,
                    "end_count": 1,
                    "begin_sequence": 0,
                    "end_sequence": 3,
                },
                "bram_ring": {
                    "event_count": 5,
                    "captured_count": 5,
                    "dropped_count": 0,
                    "wrap_count": 0,
                    "full": False,
                    "start_timestamp": index,
                    "end_timestamp": index + 1,
                },
                "artifacts": {
                    "bram_summary": bram_summary.as_posix(),
                    "bram_records": bram_records.as_posix(),
                    "build_manifest": build_manifest.as_posix(),
                    "binary": binary.as_posix(),
                    "binary_sha256": "0" * 64,
                    "uart_log": uart_log.as_posix(),
                    "capture_log": capture_log.as_posix(),
                    "ila_trace": "NOT_CAPTURED",
                    "upload_log": "NOT_CAPTURED",
                },
            }
        )
    write_json(
        path,
        {
            "schema": "rvmt.genesys2.safe_surrogate_bram_trace.v1",
            "status": "PASS",
            "evidence_scope": "safe_syscall_only_surrogate_marker_windows",
            "trace_sink_mode": "bram_ring",
            "continuity_scope": "begin-marker-cleared BRAM ring through capture readout",
            "sample_count": len(SAFE_SURROGATE_SAMPLES),
            "samples": samples,
            "non_claims": [
                "These are safe syscall-only surrogate workloads, not real malware payloads.",
                "This evidence does not claim pointer-payload semantic reconstruction.",
                "This evidence does not complete the CCF-A baseline/evaluation matrix.",
            ],
        },
    )


def fixture_genesys2_p0_bram_trace(path: Path) -> None:
    base = path.parent / "fixture-p0-bram"
    bitstream = base / "ariane_xilinx.bit"
    ltx = base / "ariane_xilinx.ltx"
    bitstream.parent.mkdir(parents=True, exist_ok=True)
    bitstream.write_bytes(b"fixture-bitstream")
    ltx.write_text("fixture ltx\n", encoding="utf-8", newline="\n")
    samples: list[dict[str, Any]] = []
    for sample_id in P0_SAMPLES:
        begin_marker, end_marker = P0_BRAM_MARKERS[sample_id]
        reps: list[dict[str, Any]] = []
        build_dir = base / sample_id / "build"
        build_dir.mkdir(parents=True, exist_ok=True)
        build_manifest = build_dir / "build_manifest.json"
        binary = build_dir / f"{sample_id}.riscv64"
        write_json(build_manifest, {"sample_id": sample_id, "syscall_sequence": ["rvmt_marker", "write", "rvmt_marker", "exit"]})
        binary.write_bytes(b"\x7fELFfixture")
        for rep_index in range(1, 11):
            rep_name = f"rep_{rep_index:02d}"
            rep_dir = base / sample_id / rep_name
            rep_dir.mkdir(parents=True, exist_ok=True)
            bram_summary = rep_dir / "bram_summary.json"
            bram_records = rep_dir / "bram_records.jsonl"
            uart_log = rep_dir / "uart.log"
            capture_log = rep_dir / "capture.log"
            capture_err_log = rep_dir / "capture.err.log"
            records = [
                {"evt": "MARKER", "packed_primary": begin_marker, "sequence_number": 0, "cycle": 1},
                {"evt": "SYSCALL_ENTRY", "packed_primary": "0x00000040", "packed_aux": "0x00000001", "sequence_number": 1, "cycle": 2},
                {"evt": "SYSCALL_RET", "packed_primary": "0x00000001", "sequence_number": 2, "cycle": 3},
                {"evt": "MARKER", "packed_primary": end_marker, "sequence_number": 3, "cycle": 4},
                {"evt": "SYSCALL_ENTRY", "packed_primary": "0x0000005d", "packed_aux": "0x00000002", "sequence_number": 4, "cycle": 5},
            ]
            bram_records.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8", newline="\n")
            write_json(
                bram_summary,
                {
                    "schema": "rvmt.genesys2.bram_ring_dump.v1",
                    "status": "PASS",
                    "event_counts": {"MARKER": 2, "SYSCALL_ENTRY": 2, "SYSCALL_RET": 1},
                    "bram_ring": {
                        "event_count": 5,
                        "captured_count": 5,
                        "dropped_count": 0,
                        "wrap_count": 0,
                        "full": False,
                        "start_timestamp": 1,
                        "end_timestamp": 5,
                    },
                },
            )
            uart_log.write_text("fixture uart\n", encoding="utf-8", newline="\n")
            capture_log.write_text("fixture capture\n", encoding="utf-8", newline="\n")
            capture_err_log.write_text("", encoding="utf-8", newline="\n")
            reps.append(
                {
                    "sample_id": sample_id,
                    "repetition": rep_name,
                    "sample_class": "p0_safe_synthetic",
                    "trace_sink_mode": "bram_ring",
                    "continuity_scope": "begin-marker-cleared BRAM ring through capture readout",
                    "parse_success": True,
                    "expected_syscall_entries": 2,
                    "observed_syscall_entries": 2,
                    "expected_pairable_syscall_entries": 1,
                    "strict_pairable_syscall_entries": 1,
                    "strict_syscall_id_pairs": [{"entry_sequence": 1, "return_sequence": 2, "syscall_id": "0x00000001", "number": 64}],
                    "sequence_gaps": [],
                    "unaccounted_drop": 0,
                    "marker_window": {
                        "begin_marker": begin_marker,
                        "end_marker": end_marker,
                        "begin_count": 1,
                        "end_count": 1,
                        "begin_sequence": 0,
                        "end_sequence": 3,
                    },
                    "bram_ring": {
                        "event_count": 5,
                        "captured_count": 5,
                        "dropped_count": 0,
                        "wrap_count": 0,
                        "full": False,
                        "start_timestamp": 1,
                        "end_timestamp": 5,
                    },
                    "artifacts": {
                        "bram_summary": bram_summary.as_posix(),
                        "bram_records": bram_records.as_posix(),
                        "build_manifest": build_manifest.as_posix(),
                        "binary": binary.as_posix(),
                        "binary_sha256": "0" * 64,
                        "uart_log": uart_log.as_posix(),
                        "capture_log": capture_log.as_posix(),
                        "capture_err_log": capture_err_log.as_posix(),
                    },
                }
            )
        representative = dict(reps[0])
        representative.update(
            {
                "repetition_count": len(reps),
                "pass_repetition_count": len(reps),
                "minimum_repetitions": 10,
                "repetitions": reps,
                "statistics": {
                    "repetition_count": len(reps),
                    "pass_repetition_count": len(reps),
                    "max_unaccounted_drop": 0,
                    "max_wrap_count": 0,
                    "min_pairable_syscall_entries": 1,
                },
            }
        )
        samples.append(representative)
    write_json(
        path,
        {
            "schema": "rvmt.genesys2.p0_bram_trace.v1",
            "status": "PASS",
            "evidence_scope": "p0_safe_synthetic_marker_windows",
            "continuity_scope": "begin-marker-cleared BRAM ring through capture readout",
            "trace_sink_mode": "bram_ring",
            "board": "Digilent Genesys2",
            "cpu": "CVA6 rv64gc sv39",
            "run_root": base.as_posix(),
            "bitstream": bitstream.as_posix(),
            "bitstream_sha256": "a" * 64,
            "ltx": ltx.as_posix(),
            "ltx_sha256": "b" * 64,
            "sample_count": len(P0_SAMPLES),
            "expected_samples": P0_SAMPLES,
            "minimum_repetitions_per_sample": 10,
            "total_repetitions": 40,
            "statistical_robustness": {
                "claimed": True,
                "minimum_observed_repetitions": 10,
                "sample_repetition_goal": 10,
                "total_repetitions": 40,
                "all_repetitions_parse_success": True,
                "max_unaccounted_drop": 0,
                "max_wrap_count": 0,
            },
            "non_claims": [
                "These are repository-authored safe synthetic P0 workloads, not real malware payloads.",
                "This BRAM repetition summary does not claim full hardware pointer-string reconstruction.",
                "This evidence is not a production streaming throughput claim.",
            ],
            "samples": samples,
        },
    )


def fixture_summary(path: Path, schema: str) -> None:
    if schema == "rvmt.trace_drop_accounting.v1":
        write_json(
            path,
            {
                "schema": schema,
                "status": "PASS",
                "correctness_mode": True,
                "correctness_scope": "captured_trace_windows",
                "non_claims": ["Captured-window drop accounting is not a continuous trace claim."],
                "samples": [good_sample(sample) for sample in ALL_CCFA_SAMPLES],
            },
        )
    elif schema == "rvmt.syscall_semantic_reconstruction.v1":
        write_json(path, {"schema": schema, "status": "PASS", "samples": [good_sample(sample) for sample in ALL_CCFA_SAMPLES]})
    elif schema == "rvmt.pointer_snapshot_guardrails.v1":
        write_json(
            path,
            {
                "schema": schema,
                "status": "PASS",
                "snapshot_mode": "disabled",
                "non_claims": ["Pointer snapshot semantic reconstruction is not claimed."],
                "policy": {
                    "full_memory_dump": False,
                    "captures_kernel_memory": False,
                    "network_default": "disabled",
                    "max_bytes_per_pointer": 256,
                    "allowed_syscalls": PRIORITY_SYSCALLS,
                    "redaction_policy": "prefix-only fixture",
                    "bounds_checking": "checked",
                },
                "samples": [good_sample(sample) for sample in ALL_CCFA_SAMPLES],
            },
        )
    elif schema == "rvmt.fd_path_graph.v1":
        write_json(path, {"schema": schema, "status": "PASS", "samples": [good_sample(sample) for sample in ALL_CCFA_SAMPLES]})
    elif schema == "rvmt.source_line_attribution.v1":
        write_json(
            path,
            {
                "schema": schema,
                "status": "PASS",
                "debug_no_pie_source_line_attribution_rate": 0.96,
                "release_no_debug_function_attribution_rate": 0.91,
                "fork_exec_child_target_attribution_proven": True,
                "dynamic_library_events_not_misattributed": True,
                "samples": [good_sample(sample) for sample in ALL_CCFA_SAMPLES],
            },
        )
    elif schema == "rvmt.process_elf_ownership.v1":
        write_json(path, {"schema": schema, "status": "PASS", "samples": [good_sample(sample) for sample in ALL_CCFA_SAMPLES]})
    elif schema == "rvmt.dynamic_mapping_attribution.v1":
        write_json(
            path,
            {
                "schema": schema,
                "status": "PASS",
                "cases": {
                    key: {"pass": True, "evidence": f"{key}.json"}
                    for key in ["static_binary", "no_pie_binary", "pie_binary", "dynamic_loader", "shared_libraries", "fork_exec_child"]
                },
                "dynamic_library_events_not_target_binary": True,
                "aslr_load_bias_accounted": True,
            },
        )
    elif schema == "rvmt.ccfa_evaluation_matrix.v1":
        for sample in ALL_CCFA_SAMPLES:
            sample_dir = path.parent / sample
            sample_dir.mkdir(parents=True, exist_ok=True)
            for artifact_name in [
                "trace.jsonl",
                "semantic_events.json",
                "behavior_graph.json",
                "behavior_mapping.json",
                "integrated_validation.json",
                "behavior_audit_metrics.json",
                "baseline.log",
                "metrics.json",
            ]:
                (sample_dir / artifact_name).write_text("{}\n", encoding="utf-8", newline="\n")
        write_json(
            path,
            {
                "schema": schema,
                "status": "PASS",
                "workload_manifest": "workload_manifest.json",
                "baselines": BASELINES,
                "ablations": ABLATIONS,
                "resource_timing_summary": "resource_timing_summary.json",
                "limitations": ["fixture limitation"],
                "samples": [good_sample(sample) for sample in ALL_CCFA_SAMPLES],
            },
        )
    elif schema == "rvmt.baseline_alignment.v1":
        write_json(
            path,
            {
                "schema": schema,
                "status": "PASS",
                "baselines": {
                    baseline: {"present": True, "alignment_pass": True, "command_transcript": f"{baseline}.log"}
                    for baseline in BASELINES
                },
                "anti_analysis_baseline_comparison": True,
                "overhead_baseline_comparison": True,
            },
        )
    elif schema == "rvmt.behavior_audit_metrics.v1":
        artifact_root = path.parent / "samples"
        benign_control = path.parent / "benign_control_summary.json"
        required_artifacts = [
            "semantic_events.json",
            "behavior_graph.json",
            "behavior_mapping.json",
            "integrated_validation.json",
            "behavior_audit_metrics.json",
        ]
        for sample in SAFE_SURROGATE_SAMPLES:
            sample_dir = artifact_root / sample
            sample_dir.mkdir(parents=True, exist_ok=True)
            for artifact_name in required_artifacts:
                write_json(
                    sample_dir / artifact_name,
                    {
                        "schema": f"rvmt.sample.{artifact_name.removesuffix('.json')}.v1",
                        "sample_id": sample,
                        "sample_class": "malware_like_synthetic_syscall_only",
                        "real_malware": False,
                        "non_claims": ["This safe surrogate audit artifact is not real malware validation."],
                    },
                )
        write_json(
            path,
            {
                "schema": schema,
                "status": "PASS",
                "metrics": {
                    "expected_syscall_recall": 0.96,
                    "syscall_precision": 0.96,
                    "argument_reconstruction_accuracy": 0.96,
                    "behavior_rule_recall": 0.91,
                    "anti_analysis_visibility": 1.0,
                    "benign_false_positive_rate": 0.0,
                    "unaccounted_drop": 0,
                },
                "overhead": {"median": 1.0, "p95": 1.2, "variance": 0.01},
                "resource_overhead": {"lut_delta_pct": 1.0},
                "baseline_comparison": {"strace": "fixture"},
                "sample_artifact_root": artifact_root.as_posix(),
                "samples": {
                    sample: {
                        "expected_syscall_recall": 0.96,
                        "syscall_precision": 0.96,
                        "argument_reconstruction_accuracy": 0.96,
                        "behavior_rule_recall": 0.91,
                        "anti_analysis_visibility": 1.0,
                        "benign_false_positive_rate": 0.0,
                        "unaccounted_drop": 0,
                    }
                    for sample in SAFE_SURROGATE_SAMPLES
                },
                "benign_control_summary": benign_control.as_posix(),
                "non_claims": ["Behavior audit metrics are controlled safe-workload metrics, not real-malware detection accuracy."],
            },
        )
        write_json(
            benign_control,
            {
                "schema": "rvmt.genesys2.benign_control_summary.v1",
                "status": "PASS",
                "aggregate": {"sample_count": 5, "unexpected_false_positive_count": 0, "benign_false_positive_rate": 0.0},
                "samples": [{"sample_id": f"benign_{index}", "sample_class": "benign"} for index in range(5)],
            },
        )
    elif schema == "rvmt.real_malware_containment.v1":
        policy = path.parent / "docs/ethics/real_malware_policy.md"
        policy.parent.mkdir(parents=True, exist_ok=True)
        policy.write_text("# Real Malware Policy\n", encoding="utf-8", newline="\n")
        write_json(
            path,
            {
                "schema": schema,
                "status": "PASS",
                "policy_path": "docs/ethics/real_malware_policy.md",
                "payloads_in_repo": False,
                "network_default": "disabled",
                "isolated_environment": True,
                "hash_metadata_only": True,
                "sanitized_reports_only": True,
                "main_claim": "optional real-malware case study",
            },
        )
    else:
        raise ValueError(f"unknown fixture schema {schema}")


CHECKERS: dict[str, tuple[str, str, Callable[[dict[str, Any], Path], list[str]], Callable[[Path], None]]] = {
    "genesys2_bram_trace_sink": (
        "trace_sink_summary.json",
        "rvmt.genesys2.bram_trace_sink.v1",
        check_bram_trace_sink,
        fixture_bram_trace_sink,
    ),
    "genesys2_safe_surrogate_bram_trace": (
        "safe_surrogate_bram_trace_summary.json",
        "rvmt.genesys2.safe_surrogate_bram_trace.v1",
        check_safe_surrogate_bram_trace,
        fixture_safe_surrogate_bram_trace,
    ),
    "genesys2_p0_bram_trace": (
        "p0_bram_trace_summary.json",
        "rvmt.genesys2.p0_bram_trace.v1",
        check_genesys2_p0_bram_trace,
        fixture_genesys2_p0_bram_trace,
    ),
    "trace_drop_accounting": (
        "drop_accounting_summary.json",
        "rvmt.trace_drop_accounting.v1",
        check_trace_drop_accounting,
        lambda path: fixture_summary(path, "rvmt.trace_drop_accounting.v1"),
    ),
    "syscall_semantic_reconstruction": (
        "semantic_reconstruction_summary.json",
        "rvmt.syscall_semantic_reconstruction.v1",
        check_syscall_semantic_reconstruction,
        lambda path: fixture_summary(path, "rvmt.syscall_semantic_reconstruction.v1"),
    ),
    "pointer_snapshot_guardrails": (
        "pointer_snapshot_guardrails.json",
        "rvmt.pointer_snapshot_guardrails.v1",
        check_pointer_snapshot_guardrails,
        lambda path: fixture_summary(path, "rvmt.pointer_snapshot_guardrails.v1"),
    ),
    "fd_path_graph": (
        "fd_path_graph_summary.json",
        "rvmt.fd_path_graph.v1",
        check_fd_path_graph,
        lambda path: fixture_summary(path, "rvmt.fd_path_graph.v1"),
    ),
    "source_line_attribution": (
        "source_line_attribution_summary.json",
        "rvmt.source_line_attribution.v1",
        check_source_line_attribution,
        lambda path: fixture_summary(path, "rvmt.source_line_attribution.v1"),
    ),
    "process_elf_ownership": (
        "process_elf_ownership_summary.json",
        "rvmt.process_elf_ownership.v1",
        check_process_elf_ownership,
        lambda path: fixture_summary(path, "rvmt.process_elf_ownership.v1"),
    ),
    "dynamic_mapping_attribution": (
        "dynamic_mapping_attribution_summary.json",
        "rvmt.dynamic_mapping_attribution.v1",
        check_dynamic_mapping_attribution,
        lambda path: fixture_summary(path, "rvmt.dynamic_mapping_attribution.v1"),
    ),
    "ccfa_evaluation_matrix": (
        "ccfa_evaluation_matrix.json",
        "rvmt.ccfa_evaluation_matrix.v1",
        check_ccfa_evaluation_matrix,
        lambda path: fixture_summary(path, "rvmt.ccfa_evaluation_matrix.v1"),
    ),
    "baseline_alignment": (
        "baseline_alignment_summary.json",
        "rvmt.baseline_alignment.v1",
        check_baseline_alignment,
        lambda path: fixture_summary(path, "rvmt.baseline_alignment.v1"),
    ),
    "behavior_audit_metrics": (
        "behavior_audit_metrics.json",
        "rvmt.behavior_audit_metrics.v1",
        check_behavior_audit_metrics,
        lambda path: fixture_summary(path, "rvmt.behavior_audit_metrics.v1"),
    ),
    "real_malware_containment": (
        "real_malware_containment.json",
        "rvmt.real_malware_containment.v1",
        check_real_malware_containment,
        lambda path: fixture_summary(path, "rvmt.real_malware_containment.v1"),
    ),
}


def self_test(gate: str) -> int:
    default_name, _schema, checker, fixture = CHECKERS[gate]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        path = root / default_name
        fixture(path)
        errors = checker(load_json(path), root)
        if errors:
            print(f"[FAIL] {gate} good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        path = root / default_name
        fixture(path)
        data = load_json(path)
        data["status"] = "FAIL"
        write_json(path, data)
        errors = checker(load_json(path), root)
        if not errors:
            print(f"[FAIL] {gate} bad fixture passed", file=sys.stderr)
            return 1
    print(f"[PASS] {gate} checker self-test")
    return 0


def main_for_gate(gate: str, argv: list[str] | None = None) -> int:
    default_name, _schema, checker, _fixture = CHECKERS[gate]
    parser = argparse.ArgumentParser(description=f"Check {gate.replace('_', ' ')} evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--run-root", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test(gate)
    root = args.root.resolve()
    if args.summary is not None:
        path = repo_path(root, args.summary)
    elif args.run_root is not None:
        path = repo_path(root, args.run_root) / default_name
    else:
        path = root / "results/evaluation/genesys2-cva6/current" / default_name
    if not path.is_file():
        print(f"[FAIL] missing evidence summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = checker(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] {gate} checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print(f"[FAIL] {gate} evidence is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] {gate} evidence accepted: {path}")
    return 0
