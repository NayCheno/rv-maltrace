from __future__ import annotations

import argparse
import json
import math
import re
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

from ccfa_gate_common import ALL_CCFA_SAMPLES


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/external_closure_intake.json")
DEFAULT_EXTERNAL_ROOT = Path("results/evaluation/genesys2-cva6/current/external_closure")

HEX64 = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER_VALUE_RE = re.compile(r"^<[^>]+>$")
EMBEDDED_PLACEHOLDER_RE = re.compile(r"<[^>]+>")
PLACEHOLDER_THRESHOLD_VALUES = {
    ">0",
    "> 0",
    ">=5",
    ">= 5",
    ">=0.95",
    ">= 0.95",
    "> required_sustained_bytes_per_second",
    "1.5 * p99_event_bytes_per_second",
}
NO_EXTERNAL_SUMMARY_FIELD = "NOT_PRESENT"
UNREADABLE_EXTERNAL_SUMMARY_FIELD = "UNREADABLE_JSON"
MISSING_EXTERNAL_SUMMARY_FIELD = "MISSING"

EXPECTED_EXTERNAL_SUMMARIES = {
    "board_native_dwarf_source_lines": {
        "schema": "rvmt.genesys2.board_native_source_lines.v1",
        "path": DEFAULT_EXTERNAL_ROOT / "board_native_source_lines_summary.json",
    },
    "full_hardware_pointer_strings": {
        "schema": "rvmt.genesys2.hardware_pointer_strings.v1",
        "path": DEFAULT_EXTERNAL_ROOT / "hardware_pointer_strings_summary.json",
    },
    "production_streaming_dma_trace_sink": {
        "schema": "rvmt.genesys2.streaming_dma_throughput.v1",
        "path": DEFAULT_EXTERNAL_ROOT / "streaming_dma_throughput_summary.json",
    },
    "genesys2_board_benign_control": {
        "schema": "rvmt.genesys2.board_benign_control.v1",
        "path": DEFAULT_EXTERNAL_ROOT / "board_benign_control_summary.json",
    },
}

REQUIRED_EVIDENCE_ARTIFACT_KINDS = {
    "board_native_dwarf_source_lines": {
        "debug_elf_manifest",
        "readelf_debug_line_transcript",
        "board_capture_manifest",
        "joined_trace_code_map_manifest",
    },
    "full_hardware_pointer_strings": {
        "rtl_design_manifest",
        "pointer_capture_manifest",
        "pointer_group_reconstruction",
        "mem_last_or_terminator_report",
        "redaction_policy",
        "kernel_space_filter_report",
        "companion_substitution_audit",
        "resource_timing_report",
    },
    "production_streaming_dma_trace_sink": {
        "transport_design_manifest",
        "streaming_bitstream_clock_report",
        "host_receiver_log",
        "parser_output_log",
        "drop_accounting_report",
        "timing_report",
        "resource_report",
        "noninterference_report",
    },
    "genesys2_board_benign_control": {
        "board_capture_manifest",
        "semantic_events_manifest",
        "behavior_graph_manifest",
        "behavior_audit_manifest",
        "false_positive_report",
    },
}


def observed_external_field(value: Any) -> str:
    return value if isinstance(value, str) and value else MISSING_EXTERNAL_SUMMARY_FIELD


def repo_relative_path(root: Path, value: Any) -> str:
    path = repo_path(root, value)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(value).replace("\\", "/")


def row_map(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def claim_boundary(data: dict[str, Any]) -> dict[str, Any]:
    return as_dict(data.get("claim_boundary"))


def metric(data: dict[str, Any], *path: str) -> Any:
    cursor: Any = data
    for key in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
    return cursor


def is_false(value: Any) -> bool:
    return value is False or value == 0


def number_or(value: Any, default: float) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def placeholder_paths(value: Any, path: str = "$") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            paths.extend(placeholder_paths(nested, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            paths.extend(placeholder_paths(nested, f"{path}[{index}]"))
    elif isinstance(value, str):
        stripped = value.strip()
        if PLACEHOLDER_VALUE_RE.fullmatch(stripped) or EMBEDDED_PLACEHOLDER_RE.search(stripped) or stripped in PLACEHOLDER_THRESHOLD_VALUES:
            paths.append(path)
    return paths


def validate_common_external_summary(record_id: str, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("template_only") is not True, f"{record_id}: template_only summaries are not evidence")
    require(errors, data.get("status") != "TEMPLATE_NOT_EVIDENCE", f"{record_id}: template summaries are not evidence")
    placeholders = placeholder_paths(data)
    require(errors, not placeholders, f"{record_id}: placeholder template values remain: {', '.join(placeholders[:8])}")
    return errors


def path_is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def validate_external_artifact_path(
    errors: list[str],
    root: Path,
    path_value: Any,
    context: str,
    record_id: str | None = None,
) -> Path | None:
    require(errors, isinstance(path_value, str) and bool(path_value), context + "path required")
    if not path_value:
        return None
    normalized = repo_relative_path(root, path_value).lower()
    external_root = DEFAULT_EXTERNAL_ROOT.as_posix().lower() + "/"
    require(errors, normalized.startswith(external_root), context + "artifact must live under external_closure/")
    if record_id is not None:
        record_root = (DEFAULT_EXTERNAL_ROOT / record_id).as_posix().lower().rstrip("/") + "/"
        require(errors, normalized.startswith(record_root), context + f"artifact must live under external_closure/{record_id}/")
    require(errors, "external_closure_templates/" not in normalized, context + "template files must not be evidence artifacts")
    require(errors, not normalized.endswith("_summary.template.json"), context + "summary templates must not be evidence artifacts")
    require(errors, not normalized.endswith("_summary.json"), context + "external summary files must not be reused as evidence artifacts")
    path = repo_path(root, path_value)
    external_root_path = repo_path(root, DEFAULT_EXTERNAL_ROOT)
    require(errors, path_is_relative_to(path, external_root_path), context + "resolved artifact path must stay under external_closure/")
    if record_id is not None:
        require(
            errors,
            path_is_relative_to(path, repo_path(root, DEFAULT_EXTERNAL_ROOT / record_id)),
            context + f"resolved artifact path must stay under external_closure/{record_id}/",
        )
    require(errors, not path.is_symlink(), context + "artifact must not be a symlink")
    require(errors, path.is_file(), context + f"artifact file missing: {path_value}")
    if path.is_file():
        require(errors, path.stat().st_size > 0, context + "artifact file must be nonempty")
    return path


def validate_evidence_artifacts(root: Path, record_id: str, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required_kinds = REQUIRED_EVIDENCE_ARTIFACT_KINDS[record_id]
    rows = as_list(data.get("evidence_artifacts"))
    require(errors, bool(rows), "evidence_artifacts must be nonempty and artifact-backed")
    seen_kinds: set[str] = set()
    seen_ids: set[str] = set()
    for index, row in enumerate(rows, start=1):
        prefix = f"evidence_artifacts[{index}]: "
        if not isinstance(row, dict):
            errors.append(prefix + "row must be an object")
            continue
        artifact_id = row.get("id")
        kind = row.get("kind")
        path_value = row.get("path")
        expected_sha = row.get("sha256")
        require(errors, isinstance(artifact_id, str) and bool(artifact_id), prefix + "id required")
        if isinstance(artifact_id, str):
            require(errors, artifact_id not in seen_ids, prefix + f"duplicate artifact id: {artifact_id}")
            seen_ids.add(artifact_id)
        require(errors, isinstance(kind, str) and bool(kind), prefix + "kind required")
        if isinstance(kind, str) and kind:
            require(errors, kind in required_kinds, prefix + f"unexpected artifact kind: {kind}")
            seen_kinds.add(kind)
        require(errors, isinstance(expected_sha, str) and bool(HEX64.match(expected_sha)), prefix + "sha256 must be 64 lowercase hex")
        path = validate_external_artifact_path(errors, root, path_value, prefix, record_id)
        if path is not None and path.is_file() and isinstance(expected_sha, str):
            require(errors, expected_sha == sha256_file(path), prefix + "sha256 mismatch")
    missing = sorted(required_kinds - seen_kinds)
    require(errors, not missing, f"missing evidence artifact kinds: {', '.join(missing)}")
    return errors


def validate_board_native_source_lines(root: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    boundary = claim_boundary(data)
    aggregate = as_dict(data.get("aggregate"))
    samples = row_map(as_list(data.get("samples")))
    errors.extend(validate_common_external_summary("board_native_dwarf_source_lines", data))
    errors.extend(validate_evidence_artifacts(root, "board_native_dwarf_source_lines", data))
    require(errors, data.get("schema") == "rvmt.genesys2.board_native_source_lines.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("board_native_source_line_attribution_claimed") is True, "board-native source-line claim must be explicit")
    require(errors, boundary.get("sidecar_source_lines_substituted") is False, "sidecar source lines must not be substituted")
    require(errors, boundary.get("captured_elf_sha256_exact_match") is True, "captured ELF sha256 exact match is required")
    require(errors, aggregate.get("sample_count") == len(ALL_CCFA_SAMPLES), "sample_count must cover all current samples")
    require(errors, number_or(aggregate.get("source_line_rate"), -1.0) >= 0.95, "aggregate source_line_rate must be >= 0.95")
    require(errors, aggregate.get("unknown_key_events") == 0, "unknown_key_events must be 0")
    require(errors, aggregate.get("unaccounted_drop") == 0, "unaccounted_drop must be 0")
    require(errors, aggregate.get("marker_windows_passed") is True, "marker windows must pass")
    missing = sorted(set(ALL_CCFA_SAMPLES) - set(samples))
    extra = sorted(set(samples) - set(ALL_CCFA_SAMPLES))
    require(errors, not missing, f"missing samples: {', '.join(missing)}")
    require(errors, not extra, f"unexpected samples: {', '.join(extra)}")
    for sample_id, sample in samples.items():
        prefix = f"{sample_id}: "
        require(errors, sample.get("genesys2_cva6_board_claimed") is True, prefix + "board trace claim required")
        require(errors, isinstance(sample.get("captured_elf_sha256"), str) and bool(HEX64.match(sample["captured_elf_sha256"])), prefix + "captured_elf_sha256 must be 64 lowercase hex")
        require(errors, sample.get("captured_elf_sha256_exact_match") is True, prefix + "captured ELF sha256 exact match required")
        require(errors, sample.get("debug_sections_present") is True, prefix + ".debug_line/debug sections required")
        require(errors, sample.get("readelf_debug_line_proven") is True, prefix + "readelf .debug_line transcript required")
        require(errors, sample.get("source_line_attribution_available") is True, prefix + "source-line attribution required")
        require(errors, sample.get("board_trace_source_line_available") is True, prefix + "board trace source lines required")
        require(errors, number_or(sample.get("source_line_rate"), -1.0) >= 0.95, prefix + "source_line_rate must be >= 0.95")
        require(errors, sample.get("unaccounted_drop") == 0, prefix + "unaccounted_drop must be 0")
    return errors


def validate_hardware_pointer_strings(root: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    boundary = claim_boundary(data)
    aggregate = as_dict(data.get("aggregate"))
    coverage = as_dict(data.get("syscall_coverage"))
    errors.extend(validate_common_external_summary("full_hardware_pointer_strings", data))
    errors.extend(validate_evidence_artifacts(root, "full_hardware_pointer_strings", data))
    require(errors, data.get("schema") == "rvmt.genesys2.hardware_pointer_strings.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("hardware_full_pointer_strings_claimed") is True, "full hardware pointer-string claim must be explicit")
    require(errors, boundary.get("companion_strings_substituted_as_hardware") is False, "companion strings must not be substituted")
    require(errors, boundary.get("kernel_or_full_memory_dump_claimed") is False, "kernel/full memory dump must not be claimed")
    require(errors, aggregate.get("full_string_claimed") is True, "full_string_claimed must be true")
    require(errors, aggregate.get("contiguous_from_offset_zero") is True, "bytes must be contiguous from offset 0")
    require(errors, aggregate.get("mem_last_observed") is True, "mem_last must be observed")
    require(errors, is_false(aggregate.get("companion_derived_strings_as_hardware")), "companion-derived strings counted as hardware must be 0/false")
    require(errors, aggregate.get("kernel_fragment_count") == 0, "kernel_fragment_count must be 0")
    require(errors, aggregate.get("full_memory_dump_count") == 0, "full_memory_dump_count must be 0")
    require(errors, int(number_or(data.get("full_string_group_count"), 0)) > 0, "full_string_group_count must be positive")
    require(errors, bool(data.get("redaction_policy")), "redaction_policy required")
    require(errors, isinstance(data.get("failed_attempts"), list), "failed_attempts list required")
    pointer_groups = as_list(data.get("pointer_groups"))
    require(errors, bool(pointer_groups), "pointer_groups must be nonempty")
    for index, group in enumerate(pointer_groups, start=1):
        if not isinstance(group, dict):
            errors.append(f"pointer_groups[{index}]: row must be an object")
            continue
        prefix = f"pointer_groups[{index}]: "
        require(errors, str(group.get("syscall_name") or "") in {"openat", "write", "execve"}, prefix + "syscall_name required")
        require(errors, group.get("full_string_claimed") is True, prefix + "full_string_claimed must be true")
        require(errors, group.get("contiguous_from_offset_zero") is True, prefix + "contiguous_from_offset_zero must be true")
        require(errors, group.get("mem_last_observed") is True, prefix + "mem_last_observed must be true")
        require(errors, is_false(group.get("companion_derived_strings_as_hardware")), prefix + "companion substitution must be false/0")
        require(errors, group.get("kernel_fragment_count") == 0, prefix + "kernel_fragment_count must be 0")
    for syscall_name in ("openat", "write", "execve"):
        row = as_dict(coverage.get(syscall_name))
        require(errors, bool(row), f"{syscall_name}: coverage row required")
        require(errors, int(number_or(row.get("full_string_group_count"), 0)) > 0, f"{syscall_name}: full_string_group_count must be positive")
        require(errors, row.get("gap_free") is True, f"{syscall_name}: gap_free must be true")
        require(errors, row.get("mem_last_observed") is True, f"{syscall_name}: mem_last_observed must be true")
        require(errors, is_false(row.get("companion_derived_strings_as_hardware")), f"{syscall_name}: companion substitution must be false/0")
    return errors


def validate_streaming_dma_throughput(root: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    boundary = claim_boundary(data)
    transport = str(data.get("transport") or "").lower()
    errors.extend(validate_common_external_summary("production_streaming_dma_trace_sink", data))
    errors.extend(validate_evidence_artifacts(root, "production_streaming_dma_trace_sink", data))
    require(errors, data.get("schema") == "rvmt.genesys2.streaming_dma_throughput.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("production_streaming_dma_throughput_claimed") is True, "streaming/DMA throughput claim must be explicit")
    require(errors, boundary.get("bram_jtag_substituted_for_streaming") is False, "BRAM/JTAG must not be substituted")
    require(errors, transport in {"axi_dma", "ethernet_streaming", "pcie_dma", "uart_streaming_dma"}, "transport must be a non-BRAM streaming/DMA route")
    require(errors, "bram" not in transport and "jtag" not in transport and "ila" not in transport, "transport must not be BRAM/JTAG/ILA")
    sustained = number_or(data.get("sustained_bytes_per_second"), 0.0)
    p95 = number_or(data.get("p95_event_bytes_per_second"), 0.0)
    p99 = number_or(data.get("p99_event_bytes_per_second"), 0.0)
    multiplier = number_or(data.get("minimum_sustained_throughput_multiplier"), 0.0)
    required = number_or(data.get("required_sustained_bytes_per_second"), 0.0)
    require(errors, sustained > 0, "sustained_bytes_per_second must be positive")
    require(errors, p95 > 0, "p95_event_bytes_per_second must be positive")
    require(errors, p99 > 0, "p99_event_bytes_per_second must be positive")
    require(errors, p99 >= p95, "p99 event production must be >= p95")
    require(errors, multiplier == 1.5, "minimum sustained throughput multiplier must be 1.5")
    require(errors, required > 0, "required_sustained_bytes_per_second must be positive")
    require(errors, math.isclose(required, p99 * multiplier, rel_tol=1e-12, abs_tol=0.0), "required sustained throughput must be 1.5x p99")
    require(errors, sustained > required, "sustained throughput must exceed required 1.5x p99 event production")
    require(errors, number_or(data.get("unaccounted_drop"), -1) == 0, "unaccounted_drop must be 0")
    require(errors, data.get("timing_passed") is True, "timing must pass")
    require(errors, data.get("noninterference_passed") is True, "noninterference must pass")
    require(errors, data.get("host_receiver_log_present") is True, "host receiver log required")
    require(errors, data.get("resource_report_present") is True, "resource report required")
    require(errors, data.get("failed_attempts_retained") is True, "failed attempts must be retained")
    return errors


def validate_board_benign_control(root: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    boundary = claim_boundary(data)
    aggregate = as_dict(data.get("aggregate"))
    samples = row_map(as_list(data.get("samples")))
    errors.extend(validate_common_external_summary("genesys2_board_benign_control", data))
    errors.extend(validate_evidence_artifacts(root, "genesys2_board_benign_control", data))
    require(errors, data.get("schema") == "rvmt.genesys2.board_benign_control.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("genesys2_board_benign_control_claimed") is True, "board benign-control claim must be explicit")
    require(errors, boundary.get("local_linux_benign_substituted") is False, "local Linux benign control must not be substituted")
    require(errors, aggregate.get("genesys2_board_trace_claimed") is True, "Genesys2 board trace claim required")
    require(errors, int(number_or(aggregate.get("sample_count"), 0)) >= 5, "at least five benign samples required")
    require(errors, number_or(aggregate.get("unexpected_false_positive_count"), -1) == 0, "unexpected false positives must be 0")
    require(errors, number_or(aggregate.get("benign_false_positive_rate"), 1.0) == 0.0, "benign_false_positive_rate must be 0.0")
    require(errors, len(samples) >= 5, "sample rows must include at least five benign workloads")
    for sample_id, sample in samples.items():
        prefix = f"{sample_id}: "
        require(errors, sample.get("genesys2_cva6_board_trace_claimed") is True, prefix + "board trace claim required")
        require(errors, sample.get("non_network") is True, prefix + "must be non-network")
        require(errors, sample.get("unexpected_false_positive") is False, prefix + "unexpected_false_positive must be false")
        for key in ("semantic_events", "behavior_graph", "behavior_audit"):
            validate_external_artifact_path(errors, root, sample.get(key), prefix + f"{key}: ", "genesys2_board_benign_control")
    return errors


def validate_external_summary(record_id: str, data: dict[str, Any], root: Path) -> list[str]:
    if record_id == "board_native_dwarf_source_lines":
        return validate_board_native_source_lines(root, data)
    if record_id == "full_hardware_pointer_strings":
        return validate_hardware_pointer_strings(root, data)
    if record_id == "production_streaming_dma_trace_sink":
        return validate_streaming_dma_throughput(root, data)
    if record_id == "genesys2_board_benign_control":
        return validate_board_benign_control(root, data)
    return [f"unknown external record id: {record_id}"]


def expected_record_state(root: Path, record_id: str, path_value: Path) -> dict[str, Any]:
    path = repo_path(root, path_value)
    exists = path.is_file()
    validation_errors: list[str] = []
    schema = NO_EXTERNAL_SUMMARY_FIELD
    summary_status = NO_EXTERNAL_SUMMARY_FIELD
    if exists:
        try:
            data = load_json(path)
        except Exception as exc:
            validation_errors = [f"JSON load failed: {exc}"]
            schema = UNREADABLE_EXTERNAL_SUMMARY_FIELD
            summary_status = UNREADABLE_EXTERNAL_SUMMARY_FIELD
        else:
            schema = observed_external_field(data.get("schema"))
            summary_status = observed_external_field(data.get("status"))
            try:
                validation_errors = validate_external_summary(record_id, data, root)
            except Exception as exc:
                validation_errors = [f"validation failed: {exc}"]
    valid = exists and not validation_errors
    if not exists:
        completion_status = "OPEN_NO_EXTERNAL_SUMMARY"
    elif valid:
        completion_status = "EXTERNAL_SUMMARY_ACCEPTED"
    else:
        completion_status = "EXTERNAL_SUMMARY_PRESENT_INVALID"
    return {
        "exists": exists,
        "schema": schema,
        "summary_status": summary_status,
        "valid": valid,
        "completion_status": completion_status,
        "validation_errors": validation_errors,
    }


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.external_closure_intake.v1", "schema mismatch")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(errors, data.get("external_summary_root") == DEFAULT_EXTERNAL_ROOT.as_posix(), "external summary root mismatch")
    require(errors, "real_malware_validation" in as_list(data.get("objective_exclusions")), "real-malware objective exclusion missing")
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("intake_gate_only") is True, "intake gate boundary missing")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("unvalidated_external_summary_accepted") is False, "unvalidated summaries must not be accepted")
    records = row_map(as_list(data.get("records")))
    expected_ids = set(EXPECTED_EXTERNAL_SUMMARIES)
    missing = sorted(expected_ids - set(records))
    extra = sorted(set(records) - expected_ids)
    require(errors, not missing, f"missing records: {', '.join(missing)}")
    require(errors, not extra, f"unexpected records: {', '.join(extra)}")
    accepted = open_count = invalid = 0
    for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
        record = records.get(record_id)
        if not record:
            continue
        expected_path = spec["path"].as_posix()
        expected_schema = str(spec["schema"])
        state = expected_record_state(root, record_id, spec["path"])
        require(errors, record.get("required_summary_schema") == expected_schema, f"{record_id}: required schema mismatch")
        require(errors, record.get("external_summary_path") == expected_path, f"{record_id}: external summary path mismatch")
        require(errors, record.get("external_summary_exists") is state["exists"], f"{record_id}: exists flag mismatch")
        require(errors, isinstance(record.get("external_summary_schema"), str) and bool(record.get("external_summary_schema")), f"{record_id}: external schema marker missing")
        require(errors, isinstance(record.get("external_summary_status"), str) and bool(record.get("external_summary_status")), f"{record_id}: external status marker missing")
        require(errors, record.get("external_summary_schema") == state["schema"], f"{record_id}: external schema mismatch")
        require(errors, record.get("external_summary_status") == state["summary_status"], f"{record_id}: external status mismatch")
        require(errors, record.get("completion_status") == state["completion_status"], f"{record_id}: completion status mismatch")
        require(errors, record.get("completion_evidence_valid") is state["valid"], f"{record_id}: validity flag mismatch")
        require(errors, as_list(record.get("validation_errors")) == state["validation_errors"], f"{record_id}: validation errors mismatch")
        require(errors, record.get("acceptance_checker") == "tools/check_genesys2_external_closure_intake.py", f"{record_id}: acceptance checker mismatch")
        if state["valid"]:
            accepted += 1
            require(errors, record.get("current_blocker") is False, f"{record_id}: accepted external evidence should clear blocker")
        elif state["exists"]:
            invalid += 1
            require(errors, record.get("current_blocker") is True, f"{record_id}: invalid external evidence remains blocked")
        else:
            open_count += 1
            require(errors, record.get("current_blocker") is True, f"{record_id}: missing external evidence remains blocked")
        no_sub = str(record.get("no_substitution_rule") or "").lower()
        require(errors, "must not" in no_sub and "substituted" in no_sub, f"{record_id}: no-substitution rule too weak")
    require(errors, data.get("accepted_external_blocker_count") == accepted, "accepted count mismatch")
    require(errors, data.get("open_external_blocker_count") == open_count, "open count mismatch")
    require(errors, data.get("invalid_external_blocker_count") == invalid, "invalid count mismatch")
    expected_closure = "ALL_NON_REAL_EXTERNAL_SUMMARIES_ACCEPTED" if accepted == len(EXPECTED_EXTERNAL_SUMMARIES) else "OPEN_EXTERNAL_ARTIFACTS_REQUIRED"
    require(errors, data.get("closure_status") == expected_closure, "closure_status mismatch")
    expected_status = "PASS" if accepted == len(EXPECTED_EXTERNAL_SUMMARIES) else "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED"
    require(errors, data.get("status") == expected_status, f"status must be {expected_status}")
    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_external_closure_intake.py" in commands, "packager command missing")
    require(errors, "tools/check_genesys2_external_closure_intake.py --root ." in commands, "checker command missing")
    interpretation = " ".join(str(item).lower() for item in as_list(data.get("interpretation")))
    require(errors, "does not replace board" in interpretation, "interpretation must preserve external evidence boundary")
    return errors


def fixture_evidence_artifacts(root: Path, record_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for kind in sorted(REQUIRED_EVIDENCE_ARTIFACT_KINDS[record_id]):
        path = DEFAULT_EXTERNAL_ROOT / record_id / f"{kind}.txt"
        full_path = root / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(f"{record_id} {kind}\n", encoding="utf-8")
        rows.append(
            {
                "id": kind,
                "kind": kind,
                "path": path.as_posix(),
                "sha256": sha256_file(full_path),
            }
        )
    if record_id == "genesys2_board_benign_control":
        for sample_id in ("hello", "ls", "cat", "cp", "sha256sum"):
            sample_dir = root / DEFAULT_EXTERNAL_ROOT / record_id / sample_id
            sample_dir.mkdir(parents=True, exist_ok=True)
            for filename in ("semantic_events.json", "behavior_graph.json", "behavior_audit.json"):
                (sample_dir / filename).write_text(
                    json.dumps({"sample_id": sample_id, "fixture": filename}) + "\n",
                    encoding="utf-8",
                )
    return rows


def good_external_summary(record_id: str, evidence_artifacts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    evidence_artifacts = evidence_artifacts or []
    if record_id == "board_native_dwarf_source_lines":
        return {
            "schema": "rvmt.genesys2.board_native_source_lines.v1",
            "status": "PASS",
            "evidence_artifacts": evidence_artifacts,
            "claim_boundary": {
                "real_malware_validation_claimed": False,
                "board_native_source_line_attribution_claimed": True,
                "sidecar_source_lines_substituted": False,
                "captured_elf_sha256_exact_match": True,
            },
            "aggregate": {
                "sample_count": len(ALL_CCFA_SAMPLES),
                "source_line_rate": 0.99,
                "unknown_key_events": 0,
                "unaccounted_drop": 0,
                "marker_windows_passed": True,
            },
            "samples": [
                {
                    "id": sample_id,
                    "genesys2_cva6_board_claimed": True,
                    "captured_elf_sha256": "a" * 64,
                    "captured_elf_sha256_exact_match": True,
                    "debug_sections_present": True,
                    "readelf_debug_line_proven": True,
                    "source_line_attribution_available": True,
                    "board_trace_source_line_available": True,
                    "source_line_rate": 0.99,
                    "unaccounted_drop": 0,
                }
                for sample_id in ALL_CCFA_SAMPLES
            ],
        }
    if record_id == "full_hardware_pointer_strings":
        return {
            "schema": "rvmt.genesys2.hardware_pointer_strings.v1",
            "status": "PASS",
            "evidence_artifacts": evidence_artifacts,
            "claim_boundary": {
                "real_malware_validation_claimed": False,
                "hardware_full_pointer_strings_claimed": True,
                "companion_strings_substituted_as_hardware": False,
                "kernel_or_full_memory_dump_claimed": False,
            },
            "aggregate": {
                "full_string_claimed": True,
                "contiguous_from_offset_zero": True,
                "mem_last_observed": True,
                "companion_derived_strings_as_hardware": 0,
                "kernel_fragment_count": 0,
                "full_memory_dump_count": 0,
            },
            "full_string_group_count": 3,
            "redaction_policy": "raw payload release is sanitized and artifact-backed",
            "failed_attempts": [],
            "pointer_groups": [
                {
                    "syscall_name": name,
                    "full_string_claimed": True,
                    "contiguous_from_offset_zero": True,
                    "mem_last_observed": True,
                    "companion_derived_strings_as_hardware": False,
                    "kernel_fragment_count": 0,
                }
                for name in ("openat", "write", "execve")
            ],
            "syscall_coverage": {
                name: {
                    "full_string_group_count": 1,
                    "gap_free": True,
                    "mem_last_observed": True,
                    "companion_derived_strings_as_hardware": False,
                }
                for name in ("openat", "write", "execve")
            },
        }
    if record_id == "production_streaming_dma_trace_sink":
        return {
            "schema": "rvmt.genesys2.streaming_dma_throughput.v1",
            "status": "PASS",
            "evidence_artifacts": evidence_artifacts,
            "claim_boundary": {
                "real_malware_validation_claimed": False,
                "production_streaming_dma_throughput_claimed": True,
                "bram_jtag_substituted_for_streaming": False,
            },
            "transport": "axi_dma",
            "sustained_bytes_per_second": 2000000,
            "p95_event_bytes_per_second": 1000000,
            "p99_event_bytes_per_second": 1200000,
            "minimum_sustained_throughput_multiplier": 1.5,
            "required_sustained_bytes_per_second": 1800000,
            "unaccounted_drop": 0,
            "timing_passed": True,
            "noninterference_passed": True,
            "host_receiver_log_present": True,
            "resource_report_present": True,
            "failed_attempts_retained": True,
        }
    if record_id == "genesys2_board_benign_control":
        return {
            "schema": "rvmt.genesys2.board_benign_control.v1",
            "status": "PASS",
            "evidence_artifacts": evidence_artifacts,
            "claim_boundary": {
                "real_malware_validation_claimed": False,
                "genesys2_board_benign_control_claimed": True,
                "local_linux_benign_substituted": False,
            },
            "aggregate": {
                "genesys2_board_trace_claimed": True,
                "sample_count": 5,
                "unexpected_false_positive_count": 0,
                "benign_false_positive_rate": 0.0,
            },
            "samples": [
                {
                    "id": sample_id,
                    "genesys2_cva6_board_trace_claimed": True,
                    "non_network": True,
                    "unexpected_false_positive": False,
                    "semantic_events": (DEFAULT_EXTERNAL_ROOT / "genesys2_board_benign_control" / sample_id / "semantic_events.json").as_posix(),
                    "behavior_graph": (DEFAULT_EXTERNAL_ROOT / "genesys2_board_benign_control" / sample_id / "behavior_graph.json").as_posix(),
                    "behavior_audit": (DEFAULT_EXTERNAL_ROOT / "genesys2_board_benign_control" / sample_id / "behavior_audit.json").as_posix(),
                }
                for sample_id in ("hello", "ls", "cat", "cp", "sha256sum")
            ],
        }
    raise KeyError(record_id)


def self_test() -> int:
    from package_genesys2_external_closure_intake import package_intake

    def record_validation_errors(summary: dict[str, Any], record_id: str) -> list[str]:
        for record in as_list(summary.get("records")):
            row = as_dict(record)
            if row.get("id") == record_id:
                return [str(error) for error in as_list(row.get("validation_errors"))]
        return []

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        summary = package_intake(root)
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] open intake fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
            write_json(root / spec["path"], good_external_summary(record_id, fixture_evidence_artifacts(root, record_id)))
        summary = package_intake(root)
        errors = check_summary(summary, root)
        if errors or summary.get("closure_status") != "ALL_NON_REAL_EXTERNAL_SUMMARIES_ACCEPTED":
            print("[FAIL] accepted intake fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        bad_path = root / EXPECTED_EXTERNAL_SUMMARIES["production_streaming_dma_trace_sink"]["path"]
        bad = load_json(bad_path)
        bad["evidence_artifacts"][0]["sha256"] = "0" * 64
        write_json(bad_path, bad)
        summary = package_intake(root)
        errors = check_summary(summary, root)
        record_errors = record_validation_errors(summary, "production_streaming_dma_trace_sink")
        if errors or summary.get("status") != "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED" or not any("sha256 mismatch" in error for error in record_errors):
            print("[FAIL] sha-mismatched external artifact fixture was not blocked truthfully", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        write_json(
            bad_path,
            good_external_summary(
                "production_streaming_dma_trace_sink",
                fixture_evidence_artifacts(root, "production_streaming_dma_trace_sink"),
            ),
        )
        out_of_scope = Path("results/evaluation/genesys2-cva6/current/outside_external_closure/artifact.txt")
        out_of_scope_full = root / out_of_scope
        out_of_scope_full.parent.mkdir(parents=True, exist_ok=True)
        out_of_scope_full.write_text("valid bytes in the wrong evidence directory\n", encoding="utf-8")
        bad = good_external_summary(
            "production_streaming_dma_trace_sink",
            fixture_evidence_artifacts(root, "production_streaming_dma_trace_sink"),
        )
        bad["evidence_artifacts"][0]["path"] = out_of_scope.as_posix()
        bad["evidence_artifacts"][0]["sha256"] = sha256_file(out_of_scope_full)
        write_json(bad_path, bad)
        summary = package_intake(root)
        errors = check_summary(summary, root)
        record_errors = record_validation_errors(summary, "production_streaming_dma_trace_sink")
        if errors or summary.get("status") != "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED" or not any("external_closure" in error for error in record_errors):
            print("[FAIL] out-of-scope external artifact fixture was not blocked truthfully", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        write_json(
            bad_path,
            good_external_summary(
                "production_streaming_dma_trace_sink",
                fixture_evidence_artifacts(root, "production_streaming_dma_trace_sink"),
            ),
        )
        bad = load_json(bad_path)
        empty_artifact = repo_path(root, bad["evidence_artifacts"][0]["path"])
        empty_artifact.write_text("", encoding="utf-8")
        bad["evidence_artifacts"][0]["sha256"] = sha256_file(empty_artifact)
        write_json(bad_path, bad)
        summary = package_intake(root)
        errors = check_summary(summary, root)
        record_errors = record_validation_errors(summary, "production_streaming_dma_trace_sink")
        if errors or summary.get("status") != "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED" or not any("nonempty" in error for error in record_errors):
            print("[FAIL] empty external artifact fixture was not blocked truthfully", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        write_json(
            bad_path,
            good_external_summary(
                "production_streaming_dma_trace_sink",
                fixture_evidence_artifacts(root, "production_streaming_dma_trace_sink"),
            ),
        )
        bad_path = root / EXPECTED_EXTERNAL_SUMMARIES["genesys2_board_benign_control"]["path"]
        rogue_sample_artifact = root / DEFAULT_EXTERNAL_ROOT / "hello" / "semantic_events.json"
        rogue_sample_artifact.parent.mkdir(parents=True, exist_ok=True)
        rogue_sample_artifact.write_text(json.dumps({"sample_id": "hello", "rogue": True}) + "\n", encoding="utf-8")
        bad = load_json(bad_path)
        bad["samples"][0]["semantic_events"] = (DEFAULT_EXTERNAL_ROOT / "hello" / "semantic_events.json").as_posix()
        write_json(bad_path, bad)
        summary = package_intake(root)
        errors = check_summary(summary, root)
        record_errors = record_validation_errors(summary, "genesys2_board_benign_control")
        if errors or summary.get("status") != "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED" or not any("genesys2_board_benign_control" in error for error in record_errors):
            print("[FAIL] cross-record board benign artifact fixture was not blocked truthfully", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        write_json(
            bad_path,
            good_external_summary(
                "genesys2_board_benign_control",
                fixture_evidence_artifacts(root, "genesys2_board_benign_control"),
            ),
        )
        bad_path = root / EXPECTED_EXTERNAL_SUMMARIES["full_hardware_pointer_strings"]["path"]
        bad = load_json(bad_path)
        bad["aggregate"]["companion_derived_strings_as_hardware"] = 1
        write_json(bad_path, bad)
        summary = package_intake(root)
        errors = check_summary(summary, root)
        record_errors = record_validation_errors(summary, "full_hardware_pointer_strings")
        if errors or summary.get("status") != "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED" or not any("companion" in error for error in record_errors):
            print("[FAIL] invalid external summary fixture was not blocked truthfully", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        bad = good_external_summary(
            "full_hardware_pointer_strings",
            fixture_evidence_artifacts(root, "full_hardware_pointer_strings"),
        )
        bad["redaction_policy"] = "<artifact-backed raw pointer payload redaction and release policy>"
        write_json(bad_path, bad)
        summary = package_intake(root)
        errors = check_summary(summary, root)
        record_errors = record_validation_errors(summary, "full_hardware_pointer_strings")
        if errors or summary.get("status") != "BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED" or not any("placeholder" in error for error in record_errors):
            print("[FAIL] placeholder external summary fixture was not blocked truthfully", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    print("[PASS] Genesys2 external closure intake checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check optional external evidence intake for remaining non-real-malware Genesys2/CVA6 blockers.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing external closure intake summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] external closure intake checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] external closure intake is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    data = load_json(path)
    print(f"[PASS] external closure intake accepted: {path} ({data.get('closure_status')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
