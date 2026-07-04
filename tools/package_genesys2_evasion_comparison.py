from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_float,
    as_list,
    load_json,
    load_jsonl,
    repo_path,
    repo_rel,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "rvmt.genesys2.evasion_comparison.v1"
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "evasion_comparison_summary.json"
DEFAULT_REPORT = Path("docs/07-evaluation-evidence/reports/evasion_comparison.md")

RISCV_SYSCALL_NAMES = {
    56: "openat",
    57: "close",
    63: "read",
    64: "write",
    93: "exit",
    94: "exit_group",
    95: "waitid",
    113: "clock_gettime",
    117: "ptrace",
    134: "rt_sigaction",
    135: "rt_sigprocmask",
    215: "munmap",
    220: "clone",
    221: "execve",
    222: "mmap",
    226: "mprotect",
}

KEY_CASES = {
    "anti_debug_like": {
        "behavior_node": "anti_analysis_behavior_node",
        "expected_hardware_strings": ["/proc/self/status"],
        "software_failure_required": True,
        "paper_row": "anti-debug / tracer visibility",
    },
    "process_chain": {
        "behavior_node": "has_execve",
        "expected_hardware_strings": [],
        "software_failure_required": False,
        "paper_row": "direct syscall fork/exec chain",
    },
    "dynamic_executable_memory": {
        "behavior_node": "mmap_mprotect_behavior_node",
        "expected_hardware_strings": [],
        "software_failure_required": False,
        "paper_row": "dynamic executable memory",
    },
}


def artifact_record(root: Path, path_value: str | Path, role: str) -> dict[str, Any]:
    path = repo_path(root, path_value)
    return {
        "path": repo_rel(root, path),
        "role": role,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def parse_int(value: Any, default: int = 0) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = str(value or "").strip()
    if not text:
        return default
    try:
        return int(text, 0)
    except ValueError:
        return default


def syscall_name(number: int) -> str:
    return RISCV_SYSCALL_NAMES.get(number, f"sys_{number}")


def mem_bytes(row: dict[str, Any]) -> bytes:
    data = parse_int(row.get("mem_data_full") or row.get("mem_data"))
    size = parse_int(row.get("mem_size_full") or row.get("mem_size"), 8)
    size = max(0, min(size, 8))
    return data.to_bytes(8, "little", signed=False)[:size]


def decode_arg_mem_strings(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("evt") != "ARG_MEM":
            continue
        syscall_id = str(row.get("syscall_id") or row.get("syscall_id_full") or "")
        arg_index = parse_int(row.get("arg_index_full") if "arg_index_full" in row else row.get("arg_index"))
        groups.setdefault((syscall_id, arg_index), []).append(row)

    decoded: list[dict[str, Any]] = []
    for (syscall_id, arg_index), group in sorted(groups.items()):
        group = sorted(group, key=lambda item: (parse_int(item.get("mem_addr_full") or item.get("mem_addr")), parse_int(item.get("sequence_number"))))
        blob = b"".join(mem_bytes(item) for item in group)
        nul = blob.find(b"\0")
        if nul >= 0:
            blob = blob[:nul]
        text = blob.decode("utf-8", errors="replace")
        decoded.append(
            {
                "syscall_id": syscall_id,
                "arg_index": arg_index,
                "byte_count": len(blob),
                "string": text,
                "hardware_arg_mem": True,
                "mem_last_seen": any(item.get("mem_last") is True or item.get("mem_last_full") is True for item in group),
                "sequence_numbers": [parse_int(item.get("sequence_number")) for item in group],
            }
        )
    return decoded


def trace_summary(root: Path, trace_path_value: str) -> dict[str, Any]:
    trace_path = repo_path(root, trace_path_value)
    rows = load_jsonl(trace_path, errors="replace")
    event_counts = Counter(str(row.get("evt")) for row in rows)
    sequences = sorted(parse_int(row.get("sequence_number")) for row in rows if "sequence_number" in row)
    sequence_gaps = [
        {"after": left, "before": right}
        for left, right in zip(sequences, sequences[1:])
        if right != left + 1
    ]
    entries: list[dict[str, Any]] = []
    for row in rows:
        if row.get("evt") != "SYSCALL_ENTRY":
            continue
        number = parse_int(row.get("a7"))
        entries.append(
            {
                "sequence_number": parse_int(row.get("sequence_number")),
                "pc": row.get("pc"),
                "a7": row.get("a7"),
                "number": number,
                "name": syscall_name(number),
                "syscall_id": row.get("syscall_id"),
            }
        )

    max_unaccounted_drop = max((parse_int(row.get("dropped_count")) for row in rows), default=0)
    decoded_strings = decode_arg_mem_strings(rows)
    return {
        "trace": artifact_record(root, trace_path, "genesys2_bram_marker_window_trace"),
        "event_count": len(rows),
        "event_counts": dict(sorted(event_counts.items())),
        "syscall_entries": entries,
        "syscall_names": [entry["name"] for entry in entries],
        "decoded_arg_mem_strings": decoded_strings,
        "hardware_strings": [item["string"] for item in decoded_strings if item["string"]],
        "sequence_gaps": sequence_gaps,
        "max_unaccounted_drop": max_unaccounted_drop,
    }


def rows_by_sample(rows: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in as_list(rows):
        if isinstance(row, dict):
            sample_id = row.get("sample_id") or row.get("id")
            if sample_id:
                result[str(sample_id)] = row
    return result


def find_case(case_manifest: dict[str, Any], sample_id: str) -> dict[str, Any]:
    for row in as_list(case_manifest.get("case_studies")):
        if isinstance(row, dict) and row.get("sample_id") == sample_id:
            return row
    return {}


def syscall_set_contains(have: list[str], expected: list[str]) -> bool:
    have_counts = Counter(have)
    expected_counts = Counter(expected)
    return all(have_counts[name] >= count for name, count in expected_counts.items())


def baseline_syscalls(baseline: dict[str, Any], mode: str) -> dict[str, int]:
    value = as_dict(as_dict(baseline.get(mode)).get("syscalls"))
    return {str(key): parse_int(item) for key, item in value.items()}


def edge_lines(baseline: dict[str, Any], mode: str, op: str) -> list[str]:
    edges = as_list(as_dict(baseline.get(mode)).get("fd_edges"))
    return [str(row.get("line")) for row in edges if isinstance(row, dict) and row.get("op") == op and row.get("line")]


def software_failure_summary(tracer_visibility: dict[str, Any], baseline_logs: dict[str, Any], sample_id: str) -> dict[str, Any]:
    observations = as_dict(tracer_visibility.get("observations"))
    qemu_probe = as_dict(as_dict(as_dict(tracer_visibility.get("modes")).get("qemu_user")).get("probe"))
    qemu_strace_probe = as_dict(as_dict(as_dict(tracer_visibility.get("modes")).get("qemu_user_strace")).get("probe"))
    host_ptrace_lines = edge_lines(baseline_logs, "host_strace", "ptrace")
    qemu_ptrace_lines = edge_lines(baseline_logs, "qemu_strace", "ptrace")
    host_ptrace_failed = any("EPERM" in line or "= -1" in line for line in host_ptrace_lines)
    qemu_ptrace_unsupported = any("errno=38" in line or "Function not implemented" in line for line in qemu_ptrace_lines)
    global_strace_visible = observations.get("native_strace_detected_by_tracerpid_or_ptrace") is True
    qemu_probe_unsupported = (
        parse_int(qemu_probe.get("ptrace_traceme_rc"), 0) == -1
        and parse_int(qemu_probe.get("ptrace_errno"), 0) == 38
    ) or (
        parse_int(qemu_strace_probe.get("ptrace_traceme_rc"), 0) == -1
        and parse_int(qemu_strace_probe.get("ptrace_errno"), 0) == 38
    )
    failure = global_strace_visible or host_ptrace_failed or qemu_ptrace_unsupported or qemu_probe_unsupported
    if sample_id != "anti_debug_like":
        # Other current case studies are reconstruction support rows, not
        # software-tracer failure rows.
        failure = False
    return {
        "software_tracer_fails": failure,
        "native_strace_visible_by_tracerpid_or_ptrace": global_strace_visible,
        "anti_debug_host_strace_ptrace_failed": host_ptrace_failed,
        "anti_debug_qemu_ptrace_unsupported": qemu_ptrace_unsupported,
        "qemu_user_ptrace_unsupported_in_visibility_probe": qemu_probe_unsupported,
        "host_strace_ptrace_lines": host_ptrace_lines,
        "qemu_strace_ptrace_lines": qemu_ptrace_lines,
        "host_strace_syscalls": baseline_syscalls(baseline_logs, "host_strace"),
        "qemu_strace_syscalls": baseline_syscalls(baseline_logs, "qemu_strace"),
    }


def build_case(root: Path, current_root: Path, sample_id: str, case_manifest: dict[str, Any], tracer_visibility: dict[str, Any]) -> dict[str, Any]:
    case_row = find_case(case_manifest, sample_id)
    if not case_row:
        raise ValueError(f"missing case-study row for {sample_id}")
    case_summary_path = repo_path(root, case_row["case_study_summary"])
    case_summary = load_json(case_summary_path)
    baseline_logs_path = repo_path(root, case_summary["baseline_comparison"]["baseline_logs"])
    baseline_logs = load_json(baseline_logs_path)
    behavior_graph_path = repo_path(root, case_summary["behavior_analysis"]["behavior_graph"])
    behavior_graph = load_json(behavior_graph_path)
    behavior_metrics_path = repo_path(root, case_summary["behavior_analysis"]["behavior_audit_metrics"])
    behavior_metrics = load_json(behavior_metrics_path)
    trace_value = str(case_summary["hardware_trace"]["trace"])
    hw = trace_summary(root, trace_value)
    expected_syscalls = [str(item) for item in as_list(case_summary["semantic_reconstruction"].get("expected_syscalls"))]
    expected_strings = KEY_CASES[sample_id]["expected_hardware_strings"]
    node_name = str(KEY_CASES[sample_id]["behavior_node"])
    behavior_nodes = as_dict(behavior_graph.get("behavior_nodes"))
    metrics = as_dict(behavior_metrics.get("metrics"))
    expected_present = syscall_set_contains(hw["syscall_names"], expected_syscalls)
    strings_present = all(value in hw["hardware_strings"] for value in expected_strings)
    behavior_node_present = behavior_nodes.get(node_name) is True
    metric_pass = (
        as_float(metrics.get("expected_syscall_recall")) == 1.0
        and as_float(metrics.get("syscall_precision")) == 1.0
        and parse_int(metrics.get("unaccounted_drop")) == 0
    )
    rvmt_reconstructs = bool(expected_present and strings_present and behavior_node_present and metric_pass and hw["max_unaccounted_drop"] == 0)
    software = software_failure_summary(tracer_visibility, baseline_logs, sample_id)
    complete_failure_row = software["software_tracer_fails"] and rvmt_reconstructs
    support_row = (not software["software_tracer_fails"]) and rvmt_reconstructs
    verdict = (
        "PASS_SOFTWARE_TRACER_FAILS_RVMT_RECONSTRUCTS"
        if complete_failure_row
        else "PASS_RVMT_RECONSTRUCTS_NO_SOFTWARE_FAILURE_DEMONSTRATED"
        if support_row
        else "FAIL_EVASION_COMPARISON_ROW"
    )
    return {
        "sample_id": sample_id,
        "paper_row": KEY_CASES[sample_id]["paper_row"],
        "status": verdict,
        "complete_software_failure_row": complete_failure_row,
        "supporting_reconstruction_row": support_row,
        "software_baseline": software,
        "rvmt_reconstruction": {
            "rvmt_reconstructs": rvmt_reconstructs,
            "expected_syscalls": expected_syscalls,
            "hardware_syscalls": hw["syscall_names"],
            "expected_syscalls_present_in_hardware": expected_present,
            "expected_hardware_strings": expected_strings,
            "hardware_strings": hw["hardware_strings"],
            "expected_hardware_strings_present": strings_present,
            "behavior_node": node_name,
            "behavior_node_present": behavior_node_present,
            "metric_pass": metric_pass,
            "max_unaccounted_drop": hw["max_unaccounted_drop"],
        },
        "hardware_trace": hw,
        "artifacts": {
            "case_study_summary": artifact_record(root, case_summary_path, "case_study_summary"),
            "baseline_logs": artifact_record(root, baseline_logs_path, "software_baseline_logs"),
            "behavior_graph": artifact_record(root, behavior_graph_path, "behavior_graph"),
            "behavior_audit_metrics": artifact_record(root, behavior_metrics_path, "behavior_audit_metrics"),
        },
    }


def render_report(summary: dict[str, Any]) -> str:
    rows = as_list(summary.get("case_rows"))
    lines = [
        "# Evasion Comparison Summary",
        "",
        f"Status: `{summary.get('status')}`",
        "",
        "| Sample | Software baseline outcome | RV-MalTrace reconstruction | Verdict |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        software = as_dict(row.get("software_baseline"))
        rvmt = as_dict(row.get("rvmt_reconstruction"))
        if software.get("software_tracer_fails") is True:
            sw_text = "strace visible / ptrace perturbed"
        else:
            sw_text = "no software failure demonstrated"
        rvmt_text = ", ".join(as_list(rvmt.get("expected_syscalls"))) or "n/a"
        if as_list(rvmt.get("expected_hardware_strings")):
            rvmt_text += "; hardware ARG_MEM: " + ", ".join(as_list(rvmt.get("expected_hardware_strings")))
        lines.append(f"| `{row.get('sample_id')}` | {sw_text} | {rvmt_text} | `{row.get('status')}` |")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "- This summary supports one complete hardware-backed failure row: `anti_debug_like`.",
            "- Other rows are supporting reconstruction evidence, not software-tracer failure claims.",
            "- QEMU and strace outputs are comparison oracles only.",
            "- This is controlled safe-workload evidence, not real-malware validation or malware detection accuracy.",
            "",
        ]
    )
    return "\n".join(lines)


def build_summary(root: Path, current_root: Path) -> dict[str, Any]:
    tracer_visibility_path = current_root / "tracer_visibility_baseline_summary.json"
    case_manifest_path = current_root / "case_study_manifest.json"
    safe_surrogate_path = current_root / "safe_surrogate_bram_trace_summary.json"
    tracer_visibility = load_json(tracer_visibility_path)
    case_manifest = load_json(case_manifest_path)
    rows = [build_case(root, current_root, sample_id, case_manifest, tracer_visibility) for sample_id in KEY_CASES]
    complete_rows = [row for row in rows if row.get("complete_software_failure_row") is True]
    supporting_rows = [row for row in rows if row.get("supporting_reconstruction_row") is True]
    status = (
        "PASS_HARDWARE_BACKED_ANTI_DEBUG_EVASION_COMPARISON"
        if complete_rows and all(row.get("rvmt_reconstruction", {}).get("rvmt_reconstructs") is True for row in rows)
        else "FAIL_EVASION_COMPARISON_INCOMPLETE"
    )
    return {
        "schema": SCHEMA,
        "status": status,
        "canonical_evidence_root": repo_rel(root, current_root),
        "summary": {
            "hardware_backed_software_failure_rows": len(complete_rows),
            "supporting_reconstruction_rows": len(supporting_rows),
            "complete_failure_samples": [row["sample_id"] for row in complete_rows],
            "supporting_samples": [row["sample_id"] for row in supporting_rows],
        },
        "source_artifacts": {
            "tracer_visibility_baseline": artifact_record(root, tracer_visibility_path, "software_tracer_visibility_baseline"),
            "case_study_manifest": artifact_record(root, case_manifest_path, "case_study_manifest"),
            "safe_surrogate_bram_trace_summary": artifact_record(root, safe_surrogate_path, "genesys2_safe_surrogate_bram_trace_summary"),
        },
        "case_rows": rows,
        "claim_boundary": {
            "controlled_safe_workloads_only": True,
            "real_malware_validation_claimed": False,
            "malware_detection_accuracy_claimed": False,
            "general_hardware_invisibility_claimed": False,
            "production_streaming_dma_throughput_claimed": False,
            "qemu_and_strace_are_oracles_only": True,
            "complete_software_failure_rows_limited_to_listed_samples": True,
        },
        "non_claims": [
            "Only anti_debug_like currently forms a complete software-tracer-fails/RVMT-reconstructs row.",
            "process_chain and dynamic_executable_memory are supporting reconstruction rows; they do not demonstrate software tracer failure.",
            "This summary does not claim real-malware validation, malware-family coverage, or malware detection accuracy.",
        ],
        "validation_commands": [
            "uv run python tools/package_genesys2_evasion_comparison.py --root .",
            "uv run python tools/check_genesys2_evasion_comparison.py --root .",
        ],
    }


def write_self_test_fixture(root: Path) -> Path:
    current = root / DEFAULT_CURRENT_ROOT
    current.mkdir(parents=True, exist_ok=True)
    trace_root = root / "traces"
    trace_root.mkdir(exist_ok=True)
    write_json(
        current / "tracer_visibility_baseline_summary.json",
        {
            "schema": "rvmt.genesys2.tracer_visibility_baseline.v1",
            "status": "PASS_LOCAL_SOFTWARE_TRACER_BASELINE",
            "observations": {"native_strace_detected_by_tracerpid_or_ptrace": True},
            "modes": {
                "qemu_user": {"probe": {"ptrace_traceme_rc": -1, "ptrace_errno": 38}},
                "qemu_user_strace": {"probe": {"ptrace_traceme_rc": -1, "ptrace_errno": 38}},
            },
        },
    )
    case_rows = []
    for sample_id, syscalls, strings, node in (
        ("anti_debug_like", [113, 117, 56, 63, 57], ["/proc/self/status"], "anti_analysis_behavior_node"),
        ("process_chain", [220, 221, 95], [], "has_execve"),
        ("dynamic_executable_memory", [222, 226, 215], [], "mmap_mprotect_behavior_node"),
    ):
        sample_dir = current / "samples" / sample_id
        sample_dir.mkdir(parents=True)
        trace = trace_root / f"{sample_id}.jsonl"
        trace_rows: list[dict[str, Any]] = []
        seq = 0
        for number in syscalls:
            trace_rows.append({"evt": "SYSCALL_ENTRY", "sequence_number": seq, "a7": hex(number), "syscall_id": hex(seq)})
            seq += 1
        for text in strings:
            data = text.encode("utf-8") + b"\0"
            for offset in range(0, len(data), 8):
                chunk = data[offset : offset + 8]
                trace_rows.append(
                    {
                        "evt": "ARG_MEM",
                        "sequence_number": seq,
                        "syscall_id": "0x2",
                        "arg_index": 1,
                        "mem_addr": hex(0x1000 + offset),
                        "mem_data": hex(int.from_bytes(chunk.ljust(8, b"\0"), "little")),
                        "mem_size": len(chunk),
                        "mem_last": offset + 8 >= len(data),
                    }
                )
                seq += 1
        trace.write_text("".join(json.dumps(row) + "\n" for row in trace_rows), encoding="utf-8", newline="\n")
        baseline = {
            "schema": "fixture",
            "host_strace": {"syscalls": {"ptrace": 1}, "fd_edges": []},
            "qemu_strace": {"syscalls": {"ptrace": 1}, "fd_edges": []},
        }
        if sample_id == "anti_debug_like":
            baseline["host_strace"]["fd_edges"] = [{"op": "ptrace", "line": "ptrace(PTRACE_TRACEME) = -1 EPERM"}]
            baseline["qemu_strace"]["fd_edges"] = [{"op": "ptrace", "line": "ptrace(...) = -1 errno=38 (Function not implemented)"}]
        write_json(sample_dir / "baseline_logs.json", baseline)
        write_json(sample_dir / "behavior_graph.json", {"schema": "fixture", "behavior_nodes": {node: True}})
        write_json(
            sample_dir / "behavior_audit_metrics.json",
            {"schema": "fixture", "metrics": {"expected_syscall_recall": 1.0, "syscall_precision": 1.0, "unaccounted_drop": 0}},
        )
        write_json(
            sample_dir / "case_study_summary.json",
            {
                "schema": "fixture",
                "status": "PASS",
                "hardware_trace": {"trace": repo_rel(root, trace)},
                "semantic_reconstruction": {"expected_syscalls": [syscall_name(number) for number in syscalls]},
                "baseline_comparison": {"baseline_logs": repo_rel(root, sample_dir / "baseline_logs.json")},
                "behavior_analysis": {
                    "behavior_graph": repo_rel(root, sample_dir / "behavior_graph.json"),
                    "behavior_audit_metrics": repo_rel(root, sample_dir / "behavior_audit_metrics.json"),
                },
            },
        )
        case_rows.append({"sample_id": sample_id, "case_study_summary": repo_rel(root, sample_dir / "case_study_summary.json")})
    write_json(current / "case_study_manifest.json", {"schema": "fixture", "status": "PASS", "case_studies": case_rows})
    write_json(current / "safe_surrogate_bram_trace_summary.json", {"schema": "fixture", "status": "PASS"})
    return current


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-evasion-comparison-") as tmp:
        root = Path(tmp)
        current = write_self_test_fixture(root)
        summary = build_summary(root, current)
        if summary.get("status") != "PASS_HARDWARE_BACKED_ANTI_DEBUG_EVASION_COMPARISON":
            print("[FAIL] evasion comparison self-test did not pass", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 evasion comparison packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package software-tracer failure versus RV-MalTrace reconstruction evidence.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    current_root = repo_path(root, args.current_root)
    out = repo_path(root, args.out)
    report = repo_path(root, args.report)
    try:
        summary = build_summary(root, current_root)
        write_json(out, summary)
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(render_report(summary), encoding="utf-8", newline="\n")
    except Exception as exc:
        print(f"[FAIL] failed to package evasion comparison: {exc}", file=sys.stderr)
        return 1
    print(f"[{summary['status']}] wrote evasion comparison to {out}")
    print(f"[REPORT] wrote {report}")
    return 0 if str(summary["status"]).startswith("PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
