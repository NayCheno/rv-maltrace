from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_ASSESSMENT = Path("D:/Download/rv_maltrace_35t_assessment.md")
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_CLOSURE = DEFAULT_EVIDENCE_ROOT / "assessment_closure.json"
SCHEMA = "rvmt.35t.assessment_traceability.v1"
STATUS = "PASS_WITH_BOUNDED_REMAINING_WORK"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
GOAL_SPECS = {
    "P0_claim_boundary": {
        "assessment_heading": "P0",
        "accepted_statuses": {"PASS"},
        "required_tokens": [
            "35T hardware-trace-assisted synthetic malware-like behavior audit prototype",
            "35T 线不足以单独支撑 CCF-A 主论文观点",
            "low-cost FPGA feasibility / constrained-board prototype evaluation",
            "RV-MalTrace detects real malware",
            "The current result validates CVA6",
            "complete semantic reconstruction",
        ],
        "required_evidence_keys": {
            "manifest",
            "application_closure_check",
            "paper_evidence_check",
            "paper_positioning",
            "hardware_trace_prototype",
            "local_code_analysis",
            "malware_behavior_audit",
        },
        "completion_kind": "closed_current_scope",
    },
    "P1_fd_path_flow": {
        "assessment_heading": "P1",
        "accepted_statuses": {"PASS"},
        "required_tokens": [
            "恢复 openat path pointer",
            "关联 openat return fd",
            "fd -> read/write/getdents64/close",
            "file_scan",
            "batch_open_read_write",
            "self_copy_sim",
        ],
        "required_evidence_keys": {"summary", "case_studies"},
        "completion_kind": "closed_representative_case_studies",
    },
    "P2_process_tree": {
        "assessment_heading": "P2",
        "accepted_statuses": {"PASS"},
        "required_tokens": [
            "clone/fork positive child PID",
            "child execve boundary",
            "恢复 execve path string",
            "parent waitid",
            "parent-child process graph",
        ],
        "required_evidence_keys": {"summary", "case_study"},
        "completion_kind": "closed_representative_case_study",
    },
    "P3_pointer_argument_semantics": {
        "assessment_heading": "P3",
        "accepted_statuses": {"PARTIAL_BOUNDED_SYNTHETIC_ARG_MEM_GUARDRAILS"},
        "required_tokens": [
            "硬件 user-pointer memory snapshot",
            "trusted helper / eBPF companion",
            "openat pathname",
            "execve filename",
            "trusted kernel, user-mode malware",
            "不能声称抵抗 kernel rootkit",
        ],
        "required_evidence_keys": {
            "routes",
            "strategy",
            "pointer_preflight",
            "pointer_snapshot_gate",
            "pointer_snapshot_design_review",
            "threat_model",
            "helper_alignment",
        },
        "completion_kind": "bounded_helper_alignment_with_deferred_hardware_pointer_snapshot",
    },
    "P4_baseline_evaluation": {
        "assessment_heading": "P4",
        "accepted_statuses": {
            "HOST_QEMU_STRACE_AND_SOFTWARE_INSTRUMENTATION_PASS_WITH_MISSING_EBPF_QEMU_PLUGIN",
            "HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_AND_EBPF_PASS_WITH_MISSING_QEMU_PLUGIN",
            "HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS",
        },
        "required_tokens": [
            "`strace` / `ptrace`",
            "eBPF-only",
            "QEMU plugin",
            "software instrumentation",
            "RV-MalTrace event-only",
            "RV-MalTrace + pointer snapshot/helper",
            "syscall precision / recall",
            "anti-debug detectability",
        ],
        "required_evidence_keys": {
            "summary",
            "check",
            "execution_spec",
            "advanced_preflight",
            "qemu_plugin_baseline",
            "evaluation_table",
            "metric_coverage",
        },
        "completion_kind": "bounded_ebpf_and_qemu_plugin_pass",
    },
    "P5_synthetic_suite_extension": {
        "assessment_heading": "P5",
        "accepted_statuses": {"IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING"},
        "required_tokens": [
            "direct syscall",
            "timing anti-analysis",
            "TracerPid",
            "obfuscated syscall wrapper",
            "self-modifying code",
            "network client behavior",
            "file encryption simulation",
            "sample source policy",
            "artifact sanitization",
        ],
        "required_evidence_keys": {
            "manifest",
            "extension_plan",
            "extension_check",
            "host_smoke",
            "target_smoke",
            "behavior_smoke",
            "enablement_preflight",
        },
        "completion_kind": "source_implemented_35t_gating_deferred",
    },
    "P6_artifact_package": {
        "assessment_heading": "P6",
        "accepted_statuses": {"LIGHTWEIGHT_ARTIFACT_PASS_FULL_REPRO_DEFERRED"},
        "required_tokens": [
            "run_config.json",
            "raw_uart.log",
            "decoded trace.jsonl",
            "runtime_process_map.json",
            "semantic_events.json",
            "behavior_graph.json",
            "resource/timing reports",
            "ELF hashes",
            "negative/failed cases",
            "哪些 artifact 可公开",
        ],
        "required_evidence_keys": {
            "snapshot_manifest",
            "artifact_readiness",
            "paper_package_manifest",
            "raw_artifact_sanitization",
            "raw_artifact_escrow",
        },
        "completion_kind": "lightweight_release_ready_full_raw_deferred",
    },
}


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def goal_by_id(closure: dict[str, Any]) -> dict[str, dict[str, Any]]:
    goals = closure.get("goals", [])
    return {
        str(goal.get("id")): goal
        for goal in goals
        if isinstance(goal, dict) and goal.get("id")
    } if isinstance(goals, list) else {}


def evidence_file_exists(evidence_root: Path, value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value.startswith("experiments/") or value.startswith("results/") or value.startswith("docs/"):
        return Path(value).is_file()
    return (evidence_root / value).is_file()


def trace_goal(goal_id: str, spec: dict[str, Any], goal: dict[str, Any], assessment_text: str, evidence_root: Path) -> dict[str, Any]:
    evidence = goal.get("evidence", {}) if isinstance(goal.get("evidence"), dict) else {}
    required_keys = set(spec["required_evidence_keys"])
    present_keys = {key for key in required_keys if key in evidence and evidence.get(key)}
    evidence_exists = {
        key: evidence_file_exists(evidence_root, evidence.get(key))
        for key in present_keys
        if isinstance(evidence.get(key), str)
    }
    token_hits = {
        token: token in assessment_text
        for token in spec["required_tokens"]
    }
    checks = {
        "goal_present": bool(goal),
        "status_accepted": goal.get("status") in spec["accepted_statuses"],
        "assessment_tokens_present": all(token_hits.values()),
        "required_evidence_keys_present": required_keys.issubset(set(evidence)),
        "required_evidence_files_exist": all(evidence_exists.values()) if evidence_exists else False,
        "remaining_boundary_recorded": isinstance(goal.get("remaining_work"), list) and bool(goal.get("remaining_work")),
        "checks_recorded": isinstance(goal.get("checks"), dict) and bool(goal.get("checks")),
    }
    return {
        "id": goal_id,
        "assessment_heading": spec["assessment_heading"],
        "completion_kind": spec["completion_kind"],
        "status": goal.get("status"),
        "checks": checks,
        "assessment_token_hits": token_hits,
        "required_evidence_keys": sorted(required_keys),
        "present_evidence_keys": sorted(present_keys),
        "evidence_file_exists": evidence_exists,
        "remaining_work": goal.get("remaining_work", []),
        "failures": [key for key, ok in checks.items() if not ok],
    }


def build_report(repo_root: Path, assessment_arg: Path, evidence_root_arg: Path, closure_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    assessment_path = repo_path(repo_root, assessment_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    closure_path = repo_path(repo_root, closure_arg).resolve()
    failures: list[str] = []
    if not assessment_path.is_file():
        raise FileNotFoundError(f"missing assessment document: {assessment_path}")
    if not closure_path.is_file():
        raise FileNotFoundError(f"missing assessment closure: {closure_path}")
    assessment_text = assessment_path.read_text(encoding="utf-8")
    closure = load_json(closure_path)
    goals = goal_by_id(closure)
    goal_rows = [
        trace_goal(goal_id, spec, goals.get(goal_id, {}), assessment_text, evidence_root)
        for goal_id, spec in GOAL_SPECS.items()
    ]
    closure_checks = {
        "closure_schema": closure.get("schema") == "rvmt.35t.assessment_closure.v1",
        "closure_status": closure.get("status") == STATUS,
        "closure_claim_level": closure.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "all_goals_mapped": set(GOAL_SPECS).issubset(set(goals)),
        "no_goal_trace_failures": all(not row["failures"] for row in goal_rows),
    }
    for key, ok in closure_checks.items():
        if not ok:
            failures.append(f"assessment traceability check failed: {key}")
    for row in goal_rows:
        for failure in row["failures"]:
            failures.append(f"{row['id']}: {failure}")
    status = STATUS if not failures else "FAIL"
    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "status": status,
        "assessment_source": str(assessment_path),
        "closure": rel(closure_path, repo_root),
        "closure_checks": closure_checks,
        "goals": goal_rows,
        "interpretation": [
            "P0-P2 are closed under the current 35T prototype boundary",
            "P3, P4, P5, and P6 remain bounded or deferred where current hardware, baseline, extension-run, or raw-artifact conditions are unavailable",
            "this traceability report maps the assessment document requirements to concrete evidence without upgrading bounded statuses to completed external work",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Assessment Traceability: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Assessment source: `{report['assessment_source']}`",
        "",
        f"Closure: `{report['closure']}`",
        "",
        "## Closure Checks",
        "",
    ]
    for key, ok in report["closure_checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Goal Traceability",
        "",
        "| Goal | Status | Completion Kind | Evidence Keys | Remaining Boundary |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["goals"]:
        remaining = "; ".join(str(item) for item in row.get("remaining_work", [])[:2])
        lines.append(
            f"| `{row['id']}` | `{row['status']}` | `{row['completion_kind']}` | {', '.join(row['present_evidence_keys'])} | {remaining} |"
        )
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "assessment_traceability.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "assessment_traceability.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def fixture_assessment(path: Path) -> None:
    tokens = []
    for spec in GOAL_SPECS.values():
        tokens.extend(spec["required_tokens"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(tokens) + "\n", encoding="utf-8")


def fixture_closure(root: Path, evidence_root: Path, *, bad_status: bool = False) -> None:
    goals = []
    for goal_id, spec in GOAL_SPECS.items():
        evidence = {}
        for key in spec["required_evidence_keys"]:
            filename = f"{goal_id}_{key}.json"
            write_json(evidence_root / filename, {"fixture": True})
            evidence[key] = filename
        goals.append(
            {
                "id": goal_id,
                "status": "FAIL" if bad_status and goal_id == "P1_fd_path_flow" else sorted(spec["accepted_statuses"])[0],
                "checks": {"fixture": True},
                "evidence": evidence,
                "remaining_work": ["bounded fixture"],
            }
        )
    write_json(
        evidence_root / "assessment_closure.json",
        {
            "schema": "rvmt.35t.assessment_closure.v1",
            "status": STATUS,
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "goals": goals,
        },
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = root / "assessment.md"
        evidence_root = root / DEFAULT_EVIDENCE_ROOT
        fixture_assessment(assessment)
        fixture_closure(root, evidence_root)
        report = build_report(root, assessment, DEFAULT_EVIDENCE_ROOT, DEFAULT_CLOSURE)
        if report["status"] != STATUS:
            print("[FAIL] expected assessment traceability fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, evidence_root)
        if not (evidence_root / "assessment_traceability.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = root / "assessment.md"
        evidence_root = root / DEFAULT_EVIDENCE_ROOT
        fixture_assessment(assessment)
        fixture_closure(root, evidence_root, bad_status=True)
        report = build_report(root, assessment, DEFAULT_EVIDENCE_ROOT, DEFAULT_CLOSURE)
        if report["status"] != "FAIL" or not any("P1_fd_path_flow" in item for item in report["failures"]):
            print("[FAIL] expected bad goal status fixture to fail", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = root / "assessment.md"
        evidence_root = root / DEFAULT_EVIDENCE_ROOT
        fixture_assessment(assessment)
        text = assessment.read_text(encoding="utf-8").replace("QEMU plugin", "QEMU missing", 1)
        assessment.write_text(text, encoding="utf-8")
        fixture_closure(root, evidence_root)
        report = build_report(root, assessment, DEFAULT_EVIDENCE_ROOT, DEFAULT_CLOSURE)
        if report["status"] != "FAIL" or not any("assessment_tokens_present" in item for item in report["failures"]):
            print("[FAIL] expected missing source token fixture to fail", file=sys.stderr)
            return 1
    print("[PASS] 35T assessment traceability self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Map the 35T assessment P0-P6 requirements to current evidence.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--assessment", type=Path, default=DEFAULT_ASSESSMENT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--closure", type=Path, default=DEFAULT_CLOSURE)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.assessment, args.evidence_root, args.closure)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_assessment_traceability: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T assessment traceability")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
