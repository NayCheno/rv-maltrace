from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULT_ROOT = Path("results/experiments/35t")
FOCUS_SAMPLES = ("hello", "batch_open_read_write", "illegal_trap", "anti_debug_like")
STAGE2_SAMPLES = ("file_scan", "self_copy_sim", "abnormal_syscall_sequence", "dynamic_executable_memory")
PROCESS_CHAIN_SAMPLES = ("process_chain",)


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def repo_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def sample_row(gate: dict[str, Any], sample_id: str) -> dict[str, Any]:
    for row in gate.get("samples", []):
        if isinstance(row, dict) and row.get("sample_id") == sample_id:
            return row
    return {"sample_id": sample_id, "gate_status": "MISSING"}


def classify_sample(row: dict[str, Any]) -> dict[str, Any]:
    sample_id = str(row.get("sample_id"))
    audit = row.get("audit_rule_summary", {}) if isinstance(row.get("audit_rule_summary"), dict) else {}
    event_summary = row.get("event_summary", {}) if isinstance(row.get("event_summary"), dict) else {}
    missing = set(str(item) for item in audit.get("missing", []) if isinstance(item, str))
    unexpected = set(str(item) for item in audit.get("unexpected_matched", []) if isinstance(item, str))
    weak_expected = set(str(item) for item in audit.get("weak_matched_expected", []) if isinstance(item, str))
    weak_expected_behavior = set(str(item) for item in audit.get("weak_expected_behavior", []) if isinstance(item, str))
    stable_weak_expected_behavior = set(str(item) for item in audit.get("stable_weak_expected_behavior", []) if isinstance(item, str))
    unknown = int(event_summary.get("unknown_event_count", 0) or 0)
    corrupt = int(event_summary.get("corrupt_record_count", 0) or 0)
    base = {
        "sample": sample_id,
        "gate_status": row.get("gate_status", "MISSING"),
        "drop_rate_median": (row.get("drop_summary") or {}).get("drop_rate_median"),
        "capped_reps": (row.get("drop_summary") or {}).get("capped_reps", []),
        "ordered_lcs_ratio_median": (row.get("alignment_summary") or {}).get("ordered_lcs_ratio_median"),
        "unknown_event_count": unknown,
        "corrupt_record_count": corrupt,
        "weak_matched_expected": sorted(weak_expected),
        "weak_expected_behavior": sorted(weak_expected_behavior),
        "stable_weak_expected_behavior": sorted(stable_weak_expected_behavior),
        "matched_expected": sorted(audit.get("stable_matched_expected", [])),
        "missing_expected": sorted(missing),
        "unexpected_matched": sorted(unexpected),
    }
    if sample_id == "file_scan":
        if "many_file_scan" in base["matched_expected"]:
            return {
                **base,
                "observed_failure": "none",
                "failure_class": "expected_rule_stable",
                "suspected_root_cause": "n/a",
                "required_fix": "preserve openat/getdents64/close target-scoped evidence",
            }
        if "many_file_scan_shape" in stable_weak_expected_behavior or "many_file_scan_shape" in weak_expected_behavior:
            return {
                **base,
                "observed_failure": "weak many_file_scan_shape only",
                "failure_class": "p0c_close_boundary_not_recovered",
                "suspected_root_cause": "target openat plus repeated getdents64 is stable, but close is not trace-proven in p0c",
                "required_fix": "do not promote to strong many_file_scan without close evidence",
            }
        return {
            **base,
            "observed_failure": "missing many_file_scan expected evidence",
            "failure_class": "syscall_boundary_recovery_failure",
            "suspected_root_cause": "openat/getdents64/close shape was not recovered strongly or weakly",
            "required_fix": "recover target-scoped file scan syscall boundary or keep Stage 2 blocked",
        }
    if sample_id == "self_copy_sim":
        if "self_copy_simulation" in base["matched_expected"]:
            return {
                **base,
                "observed_failure": "none",
                "failure_class": "expected_rule_stable",
                "suspected_root_cause": "n/a",
                "required_fix": "preserve fd-flow plus self_path/executable_output evidence",
            }
        if "self_copy_shape_without_path_tags" in stable_weak_expected_behavior or "self_copy_shape_without_path_tags" in weak_expected_behavior:
            return {
                **base,
                "observed_failure": "weak self_copy_shape_without_path_tags only",
                "failure_class": "path_tag_semantics_missing",
                "suspected_root_cause": "p0c has syscall shape but no ARG_MEM/path evidence for self_path or executable_output",
                "required_fix": "do not promote to strong self_copy_simulation without path/tag evidence",
            }
        return {
            **base,
            "observed_failure": "missing self_copy_simulation expected evidence",
            "failure_class": "copy_shape_or_path_semantics_missing",
            "suspected_root_cause": "open/read/write/close copy shape or required tags are not recovered",
            "required_fix": "recover copy shape as weak minimum; keep strong blocked until tags are trace-proven",
        }
    if sample_id == "abnormal_syscall_sequence":
        if "abnormal_syscall_sequence" in base["matched_expected"]:
            return {
                **base,
                "observed_failure": "none",
                "failure_class": "expected_rule_stable",
                "suspected_root_cause": "n/a",
                "required_fix": "preserve RV32/RV64 negative errno decoding",
            }
        if "abnormal_failed_syscall_shape" in stable_weak_expected_behavior or "abnormal_failed_syscall_shape" in weak_expected_behavior:
            return {
                **base,
                "observed_failure": "weak abnormal_failed_syscall_shape only",
                "failure_class": "failed_return_not_proven",
                "suspected_root_cause": "close/openat/read/write shape is stable, but failed return evidence is incomplete",
                "required_fix": "repair return-value recovery before strong abnormal_syscall_sequence",
            }
        return {
            **base,
            "observed_failure": "missing abnormal_syscall_sequence expected evidence",
            "failure_class": "failed_return_or_sequence_recovery_failure",
            "suspected_root_cause": "failed syscall return was not recovered or decoded",
            "required_fix": "check RV32 negative errno values such as 0xfffffxxx",
        }
    if sample_id == "dynamic_executable_memory":
        if "dynamic_executable_memory" in base["matched_expected"]:
            return {
                **base,
                "observed_failure": "none",
                "failure_class": "expected_rule_stable",
                "suspected_root_cause": "n/a",
                "required_fix": "preserve target-argument fusion for mprotect.a2 PROT_EXEC",
            }
        if "dynamic_exec_memory_shape_without_arg_bits" in stable_weak_expected_behavior or "dynamic_exec_memory_shape_without_arg_bits" in weak_expected_behavior:
            return {
                **base,
                "observed_failure": "weak dynamic_exec_memory_shape_without_arg_bits only",
                "failure_class": "mprotect_arg_bits_not_proven",
                "suspected_root_cause": "mmap/mprotect order is stable, but mprotect.a2 PROT_EXEC bit is not trace-proven",
                "required_fix": "do not promote to strong dynamic_executable_memory without a2&0x4",
            }
        return {
            **base,
            "observed_failure": "missing dynamic_executable_memory expected evidence",
            "failure_class": "mmap_mprotect_recovery_failure",
            "suspected_root_cause": "mmap/mprotect boundary or mprotect argument recovery failed",
            "required_fix": "fuse target TRAP arguments with kernel syscall number, or keep Stage 2 blocked",
        }
    if sample_id == "process_chain":
        if "process_creation_chain" in base["matched_expected"]:
            return {
                **base,
                "observed_failure": "none",
                "failure_class": "expected_rule_stable",
                "suspected_root_cause": "n/a",
                "required_fix": "preserve clone/execve/waitid target attribution and parent/child wait boundary evidence",
            }
        if "process_chain_shape" in stable_weak_expected_behavior or "process_chain_shape" in weak_expected_behavior:
            missing_details = audit.get("missing_details", {}) if isinstance(audit.get("missing_details"), dict) else {}
            details = sorted(set(str(item) for values in missing_details.values() if isinstance(values, list) for item in values))
            if "target_process_syscall_attribution" in details:
                failure_class = "target_attribution_not_proven"
                root_cause = "clone/execve/wait-like order is visible, but target_sample attribution is incomplete"
            elif "parent_child_wait_boundary" in details:
                failure_class = "parent_child_boundary_not_proven"
                root_cause = "clone/execve/wait-like order is visible, but clone child pid to wait boundary is not trace-proven"
            else:
                failure_class = "process_shape_only"
                root_cause = "clone/execve/wait-like order is visible, but strong process-chain semantic evidence is incomplete"
            return {
                **base,
                "observed_failure": "weak process_chain_shape only",
                "failure_class": failure_class,
                "suspected_root_cause": root_cause,
                "required_fix": "do not promote to strong process_creation_chain without target attribution and parent/child boundary evidence",
            }
        if "execve" in audit.get("missing_details", {}).get("process_creation_chain", []):
            failure_class = "execve_trace_gap"
        elif "waitid" in audit.get("missing_details", {}).get("process_creation_chain", []):
            failure_class = "wait_syscall_mapping_or_trace_gap"
        elif "clone" in audit.get("missing_details", {}).get("process_creation_chain", []):
            failure_class = "clone_trace_gap"
        else:
            failure_class = "process_chain_rule_or_recovery_failure"
        return {
            **base,
            "observed_failure": "missing process_creation_chain expected evidence",
            "failure_class": failure_class,
            "suspected_root_cause": "clone/execve/wait chain was not recovered strongly or weakly",
            "required_fix": "inspect process-chain debug evidence and keep Stage 3 risk run blocked",
        }
    if sample_id == "hello":
        if "illegal_instruction_trap" in unexpected:
            return {
                **base,
                "observed_failure": "unexpected illegal_instruction_trap",
                "failure_class": "trap_rule_false_positive_or_missing_target_attribution",
                "suspected_root_cause": "CPU-wide trace window plus trap rule without target/code attribution",
                "required_fix": "require target_sample illegal-instruction code-site evidence before matching illegal_instruction_trap",
            }
        return {
            **base,
            "observed_failure": "none",
            "failure_class": "regression_fixed_or_not_observed",
            "suspected_root_cause": "n/a",
            "required_fix": "keep benign unexpected matched rules at 0 per rep",
        }
    if sample_id == "batch_open_read_write":
        if "batch_file_read_write" in weak_expected and "batch_file_read_write" in missing:
            return {
                **base,
                "observed_failure": "only weak batch_file_read_write_shape evidence",
                "failure_class": "fd_flow_and_path_semantics_missing",
                "suspected_root_cause": "p0c lacks ARG_MEM/path data and current syscall recovery is noisy",
                "required_fix": "add fd-flow/path semantics or target-scoped syscall attribution before claiming full batch_file_read_write",
            }
        if "batch_file_read_write" in missing:
            return {
                **base,
                "observed_failure": "missing batch_file_read_write",
                "failure_class": "syscall_sequence_or_fd_flow_recovery_failure",
                "suspected_root_cause": "open/read/close sequence is not stably recovered from board trace",
                "required_fix": "recover fd flow and target process boundary; weak shape is the minimum next target",
            }
        return {
            **base,
            "observed_failure": "none",
            "failure_class": "expected_rule_stable",
            "suspected_root_cause": "n/a",
            "required_fix": "preserve per-rep stability",
        }
    if sample_id == "illegal_trap":
        if "illegal_instruction_trap" in missing:
            return {
                **base,
                "observed_failure": "missing illegal_instruction_trap",
                "failure_class": "trap_pc_or_handler_write_not_attributed_to_target",
                "suspected_root_cause": "TRAP cause appears in the CPU-wide window but PC/code-site ownership is not target_sample",
                "required_fix": "target-scoped trace or OS context join so trap PC and handler write belong to illegal_trap",
            }
        return {
            **base,
            "observed_failure": "none",
            "failure_class": "expected_rule_stable",
            "suspected_root_cause": "n/a",
            "required_fix": "preserve target/code evidence requirement",
        }
    if sample_id == "anti_debug_like":
        if row.get("gate_status") == "PASS":
            return {
                **base,
                "observed_failure": "none",
                "failure_class": "positive_regression_kept",
                "suspected_root_cause": "n/a",
                "required_fix": "keep ptrace-based anti_analysis_indicator stable",
            }
        return {
            **base,
            "observed_failure": "anti_debug_like regression",
            "failure_class": "positive_regression_failed",
            "suspected_root_cause": "ptrace rule or syscall recovery instability",
            "required_fix": "restore ptrace recovery without broadening clock_gettime-only matches",
        }
    return {
        **base,
        "observed_failure": "not classified",
        "failure_class": "outside_focus_set",
        "suspected_root_cause": "n/a",
        "required_fix": "n/a",
    }


def promotion_checks(samples: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {row["sample"]: row for row in samples}
    if any(sample in by_id for sample in PROCESS_CHAIN_SAMPLES):
        checks = {
            "gate_status_pass": all(row.get("gate_status") == "PASS" for row in samples),
            "process_chain_at_least_expected_weak": (
                "process_creation_chain" in by_id.get("process_chain", {}).get("matched_expected", [])
                or "process_chain_shape" in by_id.get("process_chain", {}).get("stable_weak_expected_behavior", [])
            ),
            "unexpected_strong_matched_none": all(not row.get("unexpected_matched") for row in samples),
            "unknown_and_corrupt_events_zero": all(
                int(row.get("unknown_event_count", 0) or 0) == 0 and int(row.get("corrupt_record_count", 0) or 0) == 0
                for row in samples
            ),
        }
        checks["process_chain_risk_passed"] = all(checks.values())
        checks["staged_p0c_r512_matrix_ready"] = False
        checks["full_matrix_ready"] = False
        blocked_reasons = [
            key
            for key, value in checks.items()
            if key not in {"process_chain_risk_passed", "staged_p0c_r512_matrix_ready", "full_matrix_ready"} and not value
        ]
        return {"checks": checks, "blocked_reasons": blocked_reasons}
    if any(sample in by_id for sample in STAGE2_SAMPLES):
        checks = {
            "file_scan_at_least_expected_weak": (
                "many_file_scan" in by_id.get("file_scan", {}).get("matched_expected", [])
                or "many_file_scan_shape" in by_id.get("file_scan", {}).get("stable_weak_expected_behavior", [])
            ),
            "self_copy_at_least_expected_weak": (
                "self_copy_simulation" in by_id.get("self_copy_sim", {}).get("matched_expected", [])
                or "self_copy_shape_without_path_tags" in by_id.get("self_copy_sim", {}).get("stable_weak_expected_behavior", [])
            ),
            "abnormal_at_least_expected_weak": (
                "abnormal_syscall_sequence" in by_id.get("abnormal_syscall_sequence", {}).get("matched_expected", [])
                or "abnormal_failed_syscall_shape" in by_id.get("abnormal_syscall_sequence", {}).get("stable_weak_expected_behavior", [])
            ),
            "dynamic_at_least_expected_weak": (
                "dynamic_executable_memory" in by_id.get("dynamic_executable_memory", {}).get("matched_expected", [])
                or "dynamic_exec_memory_shape_without_arg_bits"
                in by_id.get("dynamic_executable_memory", {}).get("stable_weak_expected_behavior", [])
            ),
            "unexpected_strong_matched_none": all(not row.get("unexpected_matched") for row in samples),
            "unknown_and_corrupt_events_zero": all(
                int(row.get("unknown_event_count", 0) or 0) == 0 and int(row.get("corrupt_record_count", 0) or 0) == 0
                for row in samples
            ),
        }
        checks["allowed_to_enter_process_chain_risk"] = all(checks.values())
        checks["staged_p0c_r512_matrix_ready"] = False
        checks["full_matrix_ready"] = False
        blocked_reasons = [key for key, value in checks.items() if key not in {"allowed_to_enter_process_chain_risk", "staged_p0c_r512_matrix_ready", "full_matrix_ready"} and not value]
        return {"checks": checks, "blocked_reasons": blocked_reasons}
    checks = {
        "hello_no_illegal_instruction_trap_false_positive": "illegal_instruction_trap" not in by_id.get("hello", {}).get("unexpected_matched", []),
        "illegal_trap_stable_expected_rule": "illegal_instruction_trap" in by_id.get("illegal_trap", {}).get("matched_expected", []),
        "batch_open_read_write_at_least_weak": "batch_file_read_write" in by_id.get("batch_open_read_write", {}).get("weak_matched_expected", [])
        or "batch_file_read_write" in by_id.get("batch_open_read_write", {}).get("matched_expected", []),
        "unknown_and_corrupt_events_zero": all(
            int(row.get("unknown_event_count", 0) or 0) == 0 and int(row.get("corrupt_record_count", 0) or 0) == 0 for row in samples
        ),
    }
    checks["ready_for_35t_microbench"] = all(checks.values())
    blocked_reasons = [key for key, value in checks.items() if key != "ready_for_35t_microbench" and not value]
    return {"checks": checks, "blocked_reasons": blocked_reasons}


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 35T Semantic Failure Triage",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Artifact root: `{report['artifact_root']}`",
        "- Boundary: 35T/LiteX/VexRiscv synthetic behavior audit prototype only.",
        "- Non-claims: no CVA6 board claim; no real malware detection claim; no mature detector claim.",
        "",
        "| Sample | Gate | Failure class | Observed failure | Missing expected | Weak expected | Weak shapes | Unexpected matched | UNKNOWN/corrupt |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | ---: |",
    ]
    for row in report["samples"]:
        lines.append(
            f"| `{row['sample']}` | {row['gate_status']} | {row['failure_class']} | {row['observed_failure']} | "
            f"{', '.join(row.get('missing_expected', [])) or 'none'} | "
            f"{', '.join(row.get('weak_matched_expected', [])) or 'none'} | "
            f"{', '.join(row.get('stable_weak_expected_behavior', []) or row.get('weak_expected_behavior', [])) or 'none'} | "
            f"{', '.join(row.get('unexpected_matched', [])) or 'none'} | "
            f"{row.get('unknown_event_count', 0)}/{row.get('corrupt_record_count', 0)} |"
        )
    checks = report["promotion"]
    lines.extend(["", "## Promotion Checks", ""])
    for key, value in checks["checks"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(
        [
            "",
            f"- Blocked reasons: {', '.join(checks['blocked_reasons']) if checks['blocked_reasons'] else 'none'}",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(run_root: Path, sample_ids: tuple[str, ...]) -> dict[str, Any]:
    gate_path = run_root / "aggregate" / "gate_report.json"
    gate = load_json(gate_path)
    rows = [classify_sample(sample_row(gate, sample_id)) for sample_id in sample_ids]
    report = {
        "schema": "rvmt.35t.semantic_failure_triage.v1",
        "run_id": run_root.name,
        "artifact_root": repo_rel(run_root),
        "gate_report": repo_rel(gate_path),
        "samples": rows,
        "promotion": promotion_checks(rows),
        "non_claims": [
            "No CVA6 board claim.",
            "No real malware detection claim.",
            "No mature detector claim.",
        ],
    }
    out_dir = run_root / "aggregate"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "semantic_failure_triage.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "semantic_failure_triage.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")
    return report


def self_test() -> int:
    row = classify_sample(
        {
            "sample_id": "hello",
            "gate_status": "FAIL",
            "audit_rule_summary": {"unexpected_matched": ["illegal_instruction_trap"]},
            "event_summary": {"unknown_event_count": 0, "corrupt_record_count": 0},
        }
    )
    if row["failure_class"] != "trap_rule_false_positive_or_missing_target_attribution":
        print("[FAIL] triage self-test missed hello false-positive classification", file=sys.stderr)
        return 1
    process = classify_sample(
        {
            "sample_id": "process_chain",
            "gate_status": "PASS",
            "audit_rule_summary": {
                "stable_weak_expected_behavior": ["process_chain_shape"],
                "weak_expected_behavior": ["process_chain_shape"],
                "weak_matched_expected": ["process_creation_chain"],
                "missing": [],
                "unexpected_matched": [],
                "missing_details": {"process_creation_chain": ["parent_child_wait_boundary"]},
            },
            "event_summary": {"unknown_event_count": 0, "corrupt_record_count": 0},
        }
    )
    promotion = promotion_checks([process])
    if process["failure_class"] != "parent_child_boundary_not_proven" or not promotion["checks"].get("process_chain_risk_passed"):
        print("[FAIL] triage self-test missed process_chain weak-risk classification", file=sys.stderr)
        return 1
    print("[PASS] semantic failure triage self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Triage semantic failures in a 35T p0c/p0 run without rerunning the board.")
    parser.add_argument("--run-id", default="35t-p0c-abba-r512-20260520-com5")
    parser.add_argument("--root", type=Path, default=DEFAULT_RESULT_ROOT)
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    run_root = resolve(args.root) / args.run_id
    sample_ids = tuple(args.sample) if args.sample else FOCUS_SAMPLES
    try:
        report = write_outputs(run_root, sample_ids)
    except Exception as exc:
        print(f"triage_35t_semantic_failures: error: {exc}", file=sys.stderr)
        return 2
    print(f"[PASS] semantic failure triage written: {run_root / 'aggregate' / 'semantic_failure_triage.json'}")
    checks = report["promotion"]["checks"]
    if "ready_for_35t_microbench" in checks and not checks["ready_for_35t_microbench"]:
        print("[BLOCKED] 35T microbench promotion checks are not all satisfied")
    if "allowed_to_enter_process_chain_risk" in checks and not checks["allowed_to_enter_process_chain_risk"]:
        print("[BLOCKED] Stage 2 semantic recovery checks are not all satisfied")
    if "process_chain_risk_passed" in checks and not checks["process_chain_risk_passed"]:
        print("[BLOCKED] process_chain risk checks are not all satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
