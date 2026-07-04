from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import as_dict, as_list, load_json, repo_path, require, sha256_file, write_json
from package_genesys2_evasion_comparison import DEFAULT_CURRENT_ROOT, DEFAULT_OUT, SCHEMA, build_summary, write_self_test_fixture


def check_artifact(errors: list[str], root: Path, row: dict[str, Any], label: str) -> None:
    value = row.get("path")
    if not isinstance(value, str) or not value:
        errors.append(f"{label}: missing path")
        return
    path = repo_path(root, value)
    if not path.is_file():
        errors.append(f"{label}: missing artifact {value}")
        return
    require(errors, row.get("sha256") == sha256_file(path), f"{label}: sha256 mismatch")
    require(errors, row.get("size_bytes") == path.stat().st_size, f"{label}: size_bytes mismatch")


def case_by_id(data: dict[str, Any], sample_id: str) -> dict[str, Any]:
    for row in as_list(data.get("case_rows")):
        if isinstance(row, dict) and row.get("sample_id") == sample_id:
            return row
    return {}


def check_case_common(errors: list[str], root: Path, row: dict[str, Any], label: str) -> None:
    require(errors, bool(row), f"{label}: missing row")
    artifacts = as_dict(row.get("artifacts"))
    for name in ("case_study_summary", "baseline_logs", "behavior_graph", "behavior_audit_metrics"):
        check_artifact(errors, root, as_dict(artifacts.get(name)), f"{label}.artifacts.{name}")
    check_artifact(errors, root, as_dict(as_dict(row.get("hardware_trace")).get("trace")), f"{label}.hardware_trace.trace")
    rvmt = as_dict(row.get("rvmt_reconstruction"))
    require(errors, rvmt.get("rvmt_reconstructs") is True, f"{label}: RV-MalTrace reconstruction must pass")
    require(errors, rvmt.get("expected_syscalls_present_in_hardware") is True, f"{label}: expected syscalls must be hardware-present")
    require(errors, rvmt.get("behavior_node_present") is True, f"{label}: behavior node must be present")
    require(errors, rvmt.get("metric_pass") is True, f"{label}: behavior metrics must pass")
    require(errors, rvmt.get("max_unaccounted_drop") == 0, f"{label}: max_unaccounted_drop must be zero")


def check_summary(root: Path, summary: Path) -> list[str]:
    errors: list[str] = []
    data = load_json(summary)
    require(errors, data.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    require(
        errors,
        data.get("status") == "PASS_HARDWARE_BACKED_ANTI_DEBUG_EVASION_COMPARISON",
        "status must be PASS_HARDWARE_BACKED_ANTI_DEBUG_EVASION_COMPARISON",
    )
    source_artifacts = as_dict(data.get("source_artifacts"))
    for name in ("tracer_visibility_baseline", "case_study_manifest", "safe_surrogate_bram_trace_summary"):
        check_artifact(errors, root, as_dict(source_artifacts.get(name)), f"source_artifacts.{name}")

    summary_row = as_dict(data.get("summary"))
    require(errors, summary_row.get("hardware_backed_software_failure_rows") == 1, "must have exactly one complete software-failure row")
    require(errors, summary_row.get("complete_failure_samples") == ["anti_debug_like"], "complete failure sample must be anti_debug_like")
    require(
        errors,
        set(summary_row.get("supporting_samples", [])) == {"process_chain", "dynamic_executable_memory"},
        "supporting samples must be process_chain and dynamic_executable_memory",
    )

    anti = case_by_id(data, "anti_debug_like")
    check_case_common(errors, root, anti, "anti_debug_like")
    require(errors, anti.get("complete_software_failure_row") is True, "anti_debug_like must be a complete software failure row")
    software = as_dict(anti.get("software_baseline"))
    require(errors, software.get("software_tracer_fails") is True, "anti_debug_like software_tracer_fails must be true")
    require(
        errors,
        software.get("native_strace_visible_by_tracerpid_or_ptrace") is True,
        "native strace visibility must be observed",
    )
    require(
        errors,
        software.get("anti_debug_host_strace_ptrace_failed") is True,
        "anti_debug_like host strace ptrace failure must be observed",
    )
    require(
        errors,
        software.get("anti_debug_qemu_ptrace_unsupported") is True,
        "anti_debug_like qemu ptrace unsupported must be observed",
    )
    anti_rvmt = as_dict(anti.get("rvmt_reconstruction"))
    require(errors, "ptrace" in as_list(anti_rvmt.get("hardware_syscalls")), "anti_debug_like hardware syscalls must include ptrace")
    require(errors, "openat" in as_list(anti_rvmt.get("hardware_syscalls")), "anti_debug_like hardware syscalls must include openat")
    require(
        errors,
        "/proc/self/status" in as_list(anti_rvmt.get("hardware_strings")),
        "anti_debug_like hardware ARG_MEM must decode /proc/self/status",
    )

    for sample_id in ("process_chain", "dynamic_executable_memory"):
        row = case_by_id(data, sample_id)
        check_case_common(errors, root, row, sample_id)
        require(errors, row.get("supporting_reconstruction_row") is True, f"{sample_id}: must be a support row")
        require(errors, row.get("complete_software_failure_row") is False, f"{sample_id}: must not claim software failure")
        require(
            errors,
            as_dict(row.get("software_baseline")).get("software_tracer_fails") is False,
            f"{sample_id}: software_tracer_fails must be false",
        )

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("controlled_safe_workloads_only") is True, "must be controlled-safe scoped")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "must not claim real malware validation")
    require(errors, boundary.get("malware_detection_accuracy_claimed") is False, "must not claim detection accuracy")
    require(errors, boundary.get("general_hardware_invisibility_claimed") is False, "must not claim general invisibility")
    require(errors, boundary.get("qemu_and_strace_are_oracles_only") is True, "qemu/strace must be oracle-only")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-check-evasion-comparison-") as tmp:
        root = Path(tmp)
        current = write_self_test_fixture(root)
        summary_path = current / "evasion_comparison_summary.json"
        write_json(summary_path, build_summary(root, current))
        errors = check_summary(root, summary_path)
        if errors:
            print("[FAIL] evasion comparison checker self-test rejected valid fixture", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1

        # Minimal negative check: missing summary should be reported.
        missing_errors: list[str]
        try:
            missing_errors = check_summary(root, current / "missing.json")
        except FileNotFoundError:
            missing_errors = ["missing"]
        if not missing_errors:
            print("[FAIL] evasion comparison checker self-test missed absent summary", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 evasion comparison checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check software-tracer failure versus RV-MalTrace reconstruction evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = repo_path(root, args.summary)
    errors = check_summary(root, summary)
    if errors:
        print("[FAIL] evasion comparison summary is not acceptable", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    # Rebuild in memory to catch stale summaries whose source evidence changed.
    rebuilt = build_summary(root, root / DEFAULT_CURRENT_ROOT)
    current = load_json(summary)
    require_errors: list[str] = []
    require(
        require_errors,
        rebuilt.get("summary") == current.get("summary"),
        "summary aggregate differs from source evidence; rerun package_genesys2_evasion_comparison.py",
    )
    if require_errors:
        print("[FAIL] evasion comparison summary is stale", file=sys.stderr)
        for error in require_errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"[PASS] evasion comparison accepted: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
