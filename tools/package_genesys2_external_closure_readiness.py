from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from ccfa_gate_common import ALL_CCFA_SAMPLES


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "external_closure_readiness.json"

P0_SOURCE_FILES = [
    Path("board/trace_validation/programs/hello_write.c"),
    Path("board/trace_validation/programs/file_open_read_write.c"),
    Path("board/trace_validation/programs/fork_exec.c"),
    Path("board/trace_validation/programs/illegal_instruction.c"),
]
SAFE_SOURCE_FILES = [
    Path("experiments/linux_behavior/malware_like/programs/file_scan.c"),
    Path("experiments/linux_behavior/malware_like/programs/batch_open_read_write.c"),
    Path("experiments/linux_behavior/malware_like/programs/self_copy_sim.c"),
    Path("experiments/linux_behavior/malware_like/programs/abnormal_syscall_sequence.c"),
    Path("experiments/linux_behavior/malware_like/programs/illegal_trap.c"),
    Path("experiments/linux_behavior/malware_like/programs/process_chain.c"),
    Path("experiments/linux_behavior/malware_like/programs/dynamic_executable_memory.c"),
    Path("experiments/linux_behavior/malware_like/programs/anti_debug_like.c"),
]


def repo_rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_path(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_row(root: Path, artifact_id: str, path_value: Path) -> dict[str, Any]:
    path = repo_path(root, path_value)
    row: dict[str, Any] = {
        "id": artifact_id,
        "path": repo_rel(path, root),
        "exists": path.is_file(),
        "sha256": sha256_file(path) if path.is_file() else None,
    }
    if path.suffix == ".json" and path.is_file():
        try:
            data = load_json(path)
        except Exception as exc:
            row["json_error"] = str(exc)
        else:
            row["schema"] = data.get("schema")
            row["status"] = data.get("status")
    return row


def current_flag_false(data: dict[str, Any], *keys: str) -> bool:
    cursor: Any = data
    for key in keys:
        if not isinstance(cursor, dict):
            return False
        cursor = cursor.get(key)
    return cursor is False


def source_line_record(root: Path, current_root: Path) -> dict[str, Any]:
    evidence = [
        evidence_row(root, "source_line_toolchain_probe", current_root / "source_line_toolchain_probe.json"),
        evidence_row(root, "debug_elf_readiness_summary", current_root / "debug_elf_readiness_summary.json"),
        evidence_row(root, "source_line_attribution_summary", current_root / "source_line_attribution_summary.json"),
        evidence_row(root, "source_line_sidecar", current_root / "source_line_sidecar.json"),
        evidence_row(root, "build_code_map_addr2line_support", Path("tools/build_code_map.py")),
        evidence_row(root, "join_trace_code_map_source_support", Path("tools/join_trace_code_map.py")),
    ]
    evidence.extend(evidence_row(root, f"p0_source_{path.stem}", path) for path in P0_SOURCE_FILES)
    evidence.extend(evidence_row(root, f"safe_source_{path.stem}", path) for path in SAFE_SOURCE_FILES)
    return {
        "id": "board_native_dwarf_source_lines",
        "current_status": "TOOLCHAIN_PROVEN_BOARD_RERUN_REQUIRED",
        "readiness_status": "EXTERNAL_BOARD_RERUN_READY_NOT_EXECUTED",
        "current_blocker": True,
        "completion_requires_external_state": True,
        "external_evidence_claimed": False,
        "sample_scope": ALL_CCFA_SAMPLES,
        "existing_evidence": evidence,
        "required_external_artifacts": [
            "debug/no-PIE board workload ELFs for every sample with retained .debug_line sections",
            "readelf -S transcripts proving .debug_line for each captured ELF",
            "board capture roots generated from those exact debug ELFs",
            "per-run manifest linking captured_elf_sha256 to the debug ELF sha256",
            "trace/code-map joins produced with addr2line source locations from the captured ELF",
        ],
        "acceptance_criteria": [
            "every accepted board trace references an exact captured_elf_sha256 that matches the debug ELF manifest",
            "every sample has board_trace_source_line_available=true and source_line_attribution_available=true",
            "source-line attribution rate is at least 0.95 across key syscall/trap events",
            "marker windows, syscall entry/return pairing, wrap count, and unaccounted DROP criteria still pass",
            "current sidecar-only source lines are not substituted for DWARF-derived board trace source lines",
        ],
        "future_checker_contract": {
            "required_summary_schema": "rvmt.genesys2.board_native_source_lines.v1",
            "must_fail_until_external_artifacts_present": True,
            "required_fields": [
                "evidence_artifacts",
                "captured_elf_sha256",
                "debug_sections_present",
                "source_line_attribution_available",
                "board_trace_source_line_available",
                "source_line_rate",
            ],
        },
        "no_substitution_rule": "Toolchain probes and source-equivalent sidecars must not be substituted for board-native DWARF source-line attribution.",
    }


def pointer_string_record(root: Path, current_root: Path) -> dict[str, Any]:
    return {
        "id": "full_hardware_pointer_strings",
        "current_status": "BOUNDED_PREFIX_ONLY_FULL_STRINGS_NOT_CLAIMED",
        "readiness_status": "RTL_EXTENSION_REQUIRED_NOT_EXECUTED",
        "current_blocker": True,
        "completion_requires_external_state": True,
        "external_evidence_claimed": False,
        "syscall_scope": ["openat", "write", "execve"],
        "existing_evidence": [
            evidence_row(root, "hardware_pointer_prefix_summary", current_root / "hardware_pointer_prefix_summary.json"),
            evidence_row(root, "pointer_string_readiness", current_root / "pointer_string_readiness_summary.json"),
            evidence_row(root, "pointer_snapshot_guardrails", current_root / "pointer_snapshot_guardrails.json"),
            evidence_row(root, "trace_format_arg_mem_schema", Path("docs/02-trace-architecture/trace_format.md")),
            evidence_row(root, "cva6_signal_map_pointer_hooks", Path("docs/02-trace-architecture/signal_map.md")),
            evidence_row(root, "trace_top_arg_mem_parameters", Path("rtl/trace/trace_top.sv")),
            evidence_row(root, "package_pointer_string_readiness", Path("tools/package_genesys2_pointer_string_readiness.py")),
            evidence_row(root, "check_pointer_string_readiness", Path("tools/check_genesys2_pointer_string_readiness.py")),
        ],
        "required_external_artifacts": [
            "CVA6 LSU/user-copy hook or equivalent RTL path that observes contiguous user-pointer bytes",
            "full-string ARG_MEM records with mem_last=true for null-terminated path/string arguments",
            "gap-free pointer-group reconstruction for openat, write, and execve where a full string is claimed",
            "board recapture roots proving the new RTL path on Genesys2/CVA6",
            "redaction/release policy for raw payload bytes and sanitized public summaries",
        ],
        "acceptance_criteria": [
            "full_string_claimed may become true only for pointer groups with contiguous bytes from offset 0 through terminator or documented bounded truncation",
            "fragmented or gapped ARG_MEM groups remain fragments and are not promoted to strings",
            "companion-derived strings are never counted as hardware-derived pointer strings",
            "kernel-space addresses and full memory dumps remain absent",
            "openat/write/execve hardware string coverage is reported with per-sample counts and negative cases",
        ],
        "future_checker_contract": {
            "required_summary_schema": "rvmt.genesys2.hardware_pointer_strings.v1",
            "must_fail_until_external_artifacts_present": True,
            "required_fields": [
                "evidence_artifacts",
                "full_string_claimed",
                "full_string_group_count",
                "pointer_groups",
                "contiguous_from_offset_zero",
                "mem_last_observed",
                "companion_derived_strings_as_hardware",
                "kernel_fragment_count",
                "redaction_policy",
                "failed_attempts",
            ],
        },
        "no_substitution_rule": "Bounded prefixes, fragments, qemu/strace strings, and trusted companion strings must not be substituted for full hardware-derived pointer strings.",
    }


def streaming_dma_record(root: Path, current_root: Path) -> dict[str, Any]:
    return {
        "id": "production_streaming_dma_trace_sink",
        "current_status": "BRAM_JTAG_SELECTED_STREAMING_DMA_THROUGHPUT_UNMEASURED",
        "readiness_status": "STREAMING_DMA_EXPERIMENT_REQUIRED_NOT_EXECUTED",
        "current_blocker": True,
        "completion_requires_external_state": True,
        "external_evidence_claimed": False,
        "existing_evidence": [
            evidence_row(root, "trace_export_decision", Path("docs/02-trace-architecture/trace_export_decision.md")),
            evidence_row(root, "trace_sink_summary", current_root / "trace_sink_summary.json"),
            evidence_row(root, "drop_accounting_summary", current_root / "drop_accounting_summary.json"),
            evidence_row(root, "streaming_dma_target_summary", current_root / "streaming_dma_target_summary.json"),
            evidence_row(root, "streaming_dma_readiness", current_root / "streaming_dma_readiness_summary.json"),
            evidence_row(root, "production_runtime_benchmark", current_root / "production_runtime_benchmark.json"),
            evidence_row(root, "package_streaming_dma_readiness", Path("tools/package_genesys2_streaming_dma_readiness.py")),
            evidence_row(root, "check_streaming_dma_readiness", Path("tools/check_genesys2_streaming_dma_readiness.py")),
        ],
        "required_external_artifacts": [
            "selected non-BRAM production transport design, such as AXI DMA or Ethernet streaming",
            "host receiver logs with byte counts, event counts, elapsed time, and parser success",
            "throughput benchmark showing sustained transport capacity against trace event production rate",
            "drop/wrap/backpressure accounting under stress and normal workloads",
            "resource, timing, and noninterference reports for trace_off versus streaming trace modes",
        ],
        "acceptance_criteria": [
            "transport is not reported as BRAM ring plus ILA/JTAG when claiming production streaming/DMA throughput",
            "sustained throughput exceeds the measured p95 event byte production rate recorded in streaming_dma_target_summary.json for the selected workload set",
            "unaccounted DROP is 0 for accepted throughput runs and every failed attempt is retained with impact analysis",
            "trace_on versus trace_off behavior remains equivalent for the workload pass/fail result",
            "timing closure and resource deltas are reported for the exact bitstream used in the throughput run",
        ],
        "future_checker_contract": {
            "required_summary_schema": "rvmt.genesys2.streaming_dma_throughput.v1",
            "must_fail_until_external_artifacts_present": True,
            "required_fields": [
                "evidence_artifacts",
                "transport",
                "sustained_bytes_per_second",
                "p95_event_bytes_per_second",
                "unaccounted_drop",
                "timing_passed",
                "noninterference_passed",
            ],
        },
        "no_substitution_rule": "BRAM ring captures, ILA/JTAG dumps, and local runtime benchmarks must not be substituted for production streaming or DMA throughput evidence.",
    }


def board_benign_record(root: Path, current_root: Path) -> dict[str, Any]:
    return {
        "id": "genesys2_board_benign_control",
        "current_status": "LOCAL_LINUX_BENIGN_PASS_BOARD_CONTROL_NOT_RUN",
        "readiness_status": "BOARD_BENIGN_CONTROL_RUN_REQUIRED_NOT_EXECUTED",
        "current_blocker": True,
        "completion_requires_external_state": True,
        "external_evidence_claimed": False,
        "existing_evidence": [
            evidence_row(root, "benign_control_summary", current_root / "benign_control_summary.json"),
            evidence_row(root, "board_benign_readiness", current_root / "board_benign_readiness_summary.json"),
            evidence_row(root, "behavior_audit_metrics", current_root / "behavior_audit_metrics.json"),
            evidence_row(root, "audit_behavior_tool", Path("tools/audit_behavior.py")),
            evidence_row(root, "package_benign_control_summary", Path("tools/package_benign_control_summary.py")),
            evidence_row(root, "package_board_benign_readiness", Path("tools/package_genesys2_board_benign_readiness.py")),
            evidence_row(root, "check_board_benign_readiness", Path("tools/check_genesys2_board_benign_readiness.py")),
        ],
        "required_external_artifacts": [
            "Genesys2/CVA6 board traces for representative non-network benign workloads",
            "per-benign-sample semantic_events, behavior_graph, and behavior_audit artifacts from board traces",
            "documented allowed benign overlaps versus unexpected behavior-rule matches",
            "board-run false-positive summary with sample count and unexpected false-positive rate",
        ],
        "acceptance_criteria": [
            "at least five non-network benign workloads execute on Genesys2/CVA6 under the current trace route",
            "unexpected false-positive rate is reported and is 0.0 for the accepted board benign control set",
            "allowed rule overlaps are explicitly listed and do not count as unexpected false positives",
            "board benign evidence is kept distinct from local Linux strace control evidence",
        ],
        "future_checker_contract": {
            "required_summary_schema": "rvmt.genesys2.board_benign_control.v1",
            "must_fail_until_external_artifacts_present": True,
            "required_fields": [
                "evidence_artifacts",
                "genesys2_board_trace_claimed",
                "sample_count",
                "unexpected_false_positive_count",
                "benign_false_positive_rate",
                "samples",
            ],
        },
        "no_substitution_rule": "Local Linux benign strace/control evidence must not be substituted for Genesys2 board benign false-positive evidence.",
    }


def package_readiness(root: Path, current_root: Path) -> dict[str, Any]:
    records = [
        source_line_record(root, current_root),
        pointer_string_record(root, current_root),
        streaming_dma_record(root, current_root),
        board_benign_record(root, current_root),
    ]
    failures: list[str] = []
    for record in records:
        missing = [row["path"] for row in record["existing_evidence"] if row.get("exists") is not True]
        if missing:
            failures.append(f"{record['id']}: missing evidence: {', '.join(missing)}")
    probe = load_json(current_root / "source_line_toolchain_probe.json") if (current_root / "source_line_toolchain_probe.json").is_file() else {}
    prefix = load_json(current_root / "hardware_pointer_prefix_summary.json") if (current_root / "hardware_pointer_prefix_summary.json").is_file() else {}
    package = {
        "schema": "rvmt.genesys2.external_closure_readiness.v1",
        "status": "PASS" if not failures else "FAIL",
        "canonical_evaluation_root": repo_rel(current_root, root),
        "scope": "non-real-malware external closure readiness for remaining Genesys2/CVA6 blockers",
        "objective_exclusions": ["real_malware_validation"],
        "claim_boundary": {
            "readiness_contract_only": True,
            "real_malware_validation_claimed": False,
            "hardware_full_pointer_strings_claimed": False,
            "production_streaming_dma_throughput_claimed": False,
            "board_native_source_line_attribution_claimed": False,
            "genesys2_board_benign_control_claimed": False,
            "current_board_elf_dwarf_available": probe.get("claim_boundary", {}).get("current_board_elf_dwarf_available"),
            "current_board_trace_source_line_available": probe.get("claim_boundary", {}).get("current_board_trace_source_line_available"),
            "full_string_claimed": prefix.get("full_string_claimed"),
        },
        "external_blocker_count": len(records),
        "records": records,
        "validation_commands": [
            "uv run python tools/package_genesys2_external_closure_readiness.py",
            "uv run python tools/check_genesys2_external_closure_readiness.py --root .",
        ],
        "interpretation": [
            "This artifact fixes the closure contract for remaining non-real-malware blockers.",
            "It does not upgrade current evidence to board-native DWARF source lines, full hardware pointer strings, production streaming/DMA throughput, or board benign-control evidence.",
            "Each remaining blocker still requires new board, RTL, or external reviewer execution before it can move from readiness to completed evidence.",
        ],
        "failures": failures,
    }
    if not current_flag_false(package, "claim_boundary", "real_malware_validation_claimed"):
        package["status"] = "FAIL"
    return package


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        write_json(
            current / "debug_elf_readiness_summary.json",
            {
                "schema": "rvmt.genesys2.debug_elf_readiness.v1",
                "status": "PASS",
                "claim_boundary": {
                    "debug_no_pie_elf_readiness_claimed": True,
                    "board_native_source_line_attribution_claimed": False,
                    "current_board_trace_source_line_available": False,
                    "real_malware_validation_claimed": False,
                },
            },
        )
        write_json(
            current / "source_line_toolchain_probe.json",
            {
                "schema": "rvmt.genesys2.source_line_toolchain_probe.v1",
                "status": "PASS",
                "claim_boundary": {
                    "current_board_elf_dwarf_available": False,
                    "current_board_trace_source_line_available": False,
                },
            },
        )
        write_json(current / "source_line_attribution_summary.json", {"schema": "rvmt.source_line_attribution.v1", "status": "PASS"})
        write_json(current / "source_line_sidecar.json", {"schema": "rvmt.source_line_sidecar.v1", "status": "PASS"})
        write_json(current / "hardware_pointer_prefix_summary.json", {"schema": "rvmt.hardware_pointer_prefixes.v1", "status": "PASS", "full_string_claimed": False})
        for name, schema in (
            ("pointer_snapshot_guardrails.json", "rvmt.pointer_snapshot_guardrails.v1"),
            ("pointer_string_readiness_summary.json", "rvmt.genesys2.pointer_string_readiness.v1"),
            ("trace_sink_summary.json", "rvmt.genesys2.bram_trace_sink.v1"),
            ("drop_accounting_summary.json", "rvmt.trace_drop_accounting.v1"),
            ("streaming_dma_target_summary.json", "rvmt.genesys2.streaming_dma_target.v1"),
            ("streaming_dma_readiness_summary.json", "rvmt.genesys2.streaming_dma_readiness.v1"),
            ("production_runtime_benchmark.json", "rvmt.genesys2.production_runtime_benchmark.v1"),
            ("benign_control_summary.json", "rvmt.genesys2.benign_control_summary.v1"),
            ("board_benign_readiness_summary.json", "rvmt.genesys2.board_benign_readiness.v1"),
            ("behavior_audit_metrics.json", "rvmt.behavior_audit_metrics.v1"),
        ):
            write_json(current / name, {"schema": schema, "status": "PASS"})
        for path in [
            Path("tools/build_code_map.py"),
            Path("tools/join_trace_code_map.py"),
            Path("tools/audit_behavior.py"),
            Path("tools/package_benign_control_summary.py"),
            Path("tools/package_genesys2_board_benign_readiness.py"),
            Path("tools/check_genesys2_board_benign_readiness.py"),
            Path("tools/package_genesys2_streaming_dma_readiness.py"),
            Path("tools/check_genesys2_streaming_dma_readiness.py"),
            Path("tools/package_genesys2_pointer_string_readiness.py"),
            Path("tools/check_genesys2_pointer_string_readiness.py"),
            Path("docs/02-trace-architecture/trace_format.md"),
            Path("docs/02-trace-architecture/signal_map.md"),
            Path("docs/02-trace-architecture/trace_export_decision.md"),
            Path("rtl/trace/trace_top.sv"),
            *P0_SOURCE_FILES,
            *SAFE_SOURCE_FILES,
        ]:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fixture\n", encoding="utf-8")
        package = package_readiness(root, current)
        if package["status"] != "PASS" or len(package["records"]) != 4:
            print("[FAIL] external closure readiness fixture failed", file=sys.stderr)
            print(json.dumps(package, indent=2), file=sys.stderr)
            return 1
        package["records"][0]["external_evidence_claimed"] = True
        if package["records"][0]["external_evidence_claimed"] is not True:
            print("[FAIL] fixture mutation failed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 external closure readiness packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package readiness contracts for remaining non-real-malware Genesys2/CVA6 blockers.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    current_root = repo_path(root, args.current_root)
    out = repo_path(root, args.out)
    try:
        package = package_readiness(root, current_root)
        write_json(out, package)
    except Exception as exc:
        print(f"package_genesys2_external_closure_readiness: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{package['status']}] wrote Genesys2 external closure readiness to {out}")
    return 0 if package["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
