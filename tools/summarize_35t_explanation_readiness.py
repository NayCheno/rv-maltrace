from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rv_maltrace.fd_path_flow import load_semantic_events as load_fd_events  # noqa: E402
from rv_maltrace.fd_path_flow import recover_fd_path_flow  # noqa: E402
from rv_maltrace.process_tree import load_semantic_events as load_process_events  # noqa: E402
from rv_maltrace.process_tree import recover_process_tree  # noqa: E402


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
FD_PATH_SAMPLES = ["file_scan", "batch_open_read_write", "self_copy_sim"]
PROCESS_TREE_SAMPLES = ["process_chain"]
SOURCE_ATTRIBUTION_SAMPLES = [
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
    "file_scan",
    "batch_open_read_write",
    "self_copy_sim",
]


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def rep_semantic_paths(results_root: Path, sample: str) -> list[Path]:
    base = results_root / "samples/malware_like_synthetic" / sample / "board/trace-on"
    return [base / f"rep_{rep:02d}/behavior_recovery/semantic_events.json" for rep in range(5)]


def summarize_fd_paths(results_root: Path) -> dict[str, Any]:
    samples: dict[str, Any] = {}
    for sample in FD_PATH_SAMPLES:
        reps = []
        missing = []
        for path in rep_semantic_paths(results_root, sample):
            if not path.exists():
                missing.append(path.as_posix())
                continue
            summary = recover_fd_path_flow(load_fd_events(path), sample=sample)
            reps.append(
                {
                    "rep": path.parent.parent.name,
                    "path": path.as_posix(),
                    "status": summary["status"],
                    "flows": len(summary.get("flows", [])),
                    "pending_openats": len(summary.get("pending_openats", [])),
                    "unresolved_fds": len(summary.get("unresolved_fds", [])),
                    "return_only_fd_ops": len(summary.get("return_only_fd_ops", [])),
                    "open_fds_at_end": len(summary.get("open_fds_at_end", [])),
                    "limitations": summary.get("limitations", []),
                }
            )
        statuses = [row["status"] for row in reps]
        if "PASS" in statuses:
            status = "PASS"
        elif reps:
            status = "PARTIAL"
        else:
            status = "UNAVAILABLE"
        samples[sample] = {
            "status": status,
            "rep_count": len(reps),
            "missing_reps": missing,
            "total_flows": sum(int(row["flows"]) for row in reps),
            "total_return_only_fd_ops": sum(int(row["return_only_fd_ops"]) for row in reps),
            "limitations": sorted({item for row in reps for item in row.get("limitations", [])}),
            "reps": reps,
        }
    return {
        "status": "PASS" if all(row["status"] == "PASS" for row in samples.values()) else "PARTIAL",
        "samples": samples,
    }


def summarize_process_trees(results_root: Path) -> dict[str, Any]:
    samples: dict[str, Any] = {}
    for sample in PROCESS_TREE_SAMPLES:
        reps = []
        missing = []
        for path in rep_semantic_paths(results_root, sample):
            if not path.exists():
                missing.append(path.as_posix())
                continue
            summary = recover_process_tree(load_process_events(path), sample=sample)
            reps.append(
                {
                    "rep": path.parent.parent.name,
                    "path": path.as_posix(),
                    "status": summary["status"],
                    "edges": len(summary.get("edges", [])),
                    "clone_return_candidates": len(summary.get("clone_return_candidates", [])),
                    "wait_pid_candidates": summary.get("wait_pid_candidates", []),
                    "limitations": summary.get("limitations", []),
                }
            )
        statuses = [row["status"] for row in reps]
        if "PASS" in statuses:
            status = "PASS"
        elif reps:
            status = "PARTIAL"
        else:
            status = "UNAVAILABLE"
        samples[sample] = {
            "status": status,
            "rep_count": len(reps),
            "missing_reps": missing,
            "total_edges": sum(int(row["edges"]) for row in reps),
            "limitations": sorted({item for row in reps for item in row.get("limitations", [])}),
            "reps": reps,
        }
    return {
        "status": "PASS" if all(row["status"] == "PASS" for row in samples.values()) else "PARTIAL",
        "samples": samples,
    }


def summarize_source_attribution(results_root: Path) -> dict[str, Any]:
    samples: dict[str, Any] = {}
    for sample in SOURCE_ATTRIBUTION_SAMPLES:
        code_map_path = results_root / "samples/malware_like_synthetic" / sample / "build" / f"{sample}.code_map.json"
        if not code_map_path.exists():
            samples[sample] = {"status": "UNAVAILABLE", "reason": "code_map missing", "path": code_map_path.as_posix()}
            continue
        code_map = load_json(code_map_path)
        symbols = code_map.get("symbols", [])
        function_ranges = code_map.get("function_ranges", [])
        source_locations = code_map.get("source_locations", [])
        function_count = len(function_ranges) if isinstance(function_ranges, list) and function_ranges else len(symbols) if isinstance(symbols, list) else 0
        source_line_count = len(source_locations) if isinstance(source_locations, list) else 0
        samples[sample] = {
            "status": "PARTIAL" if function_count else "UNAVAILABLE",
            "path": code_map_path.as_posix(),
            "function_level": "available" if function_count else "unavailable",
            "function_count": function_count,
            "source_line_level": "available" if source_line_count else "unavailable",
            "source_line_count": source_line_count,
            "limitations": [
                "function-level attribution is symbol/range based",
                "source-line attribution is unavailable unless source_locations or DWARF-derived line records are present",
            ],
        }
    return {
        "status": "PARTIAL",
        "samples": samples,
    }


def summarize_benign_overlap(evidence_root: Path) -> dict[str, Any]:
    matrix_path = evidence_root / "sample_matrix_summary.json"
    if not matrix_path.exists():
        return {
            "status": "UNAVAILABLE",
            "reason": "sample_matrix_summary.json missing",
            "benign_overlap_samples": [],
        }
    matrix = load_json(matrix_path)
    rows = matrix.get("sample_matrix", [])
    benign_overlap_samples = []
    synthetic_rule_samples = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            overlap = row.get("benign_expected_rule_overlap", [])
            if overlap:
                benign_overlap_samples.append(
                    {
                        "sample": row.get("sample"),
                        "class": row.get("class"),
                        "overlap_rules": overlap,
                        "interpretation": "expected benign overlap; not malware detection success",
                    }
                )
            expected = row.get("expected_rules", [])
            if expected:
                synthetic_rule_samples.append(
                    {
                        "sample": row.get("sample"),
                        "class": row.get("class"),
                        "expected_rules": expected,
                        "interpretation": "controlled synthetic behavior-audit evidence",
                    }
                )
    return {
        "status": "PASS" if benign_overlap_samples else "PARTIAL",
        "benign_overlap_samples": benign_overlap_samples,
        "synthetic_rule_samples": synthetic_rule_samples,
        "non_claim": "benign overlap must not be reported as malware detection success",
    }


def build_report(repo_root: Path, results_root: Path, evidence_root: Path) -> dict[str, Any]:
    manifest_path = evidence_root / "evidence_manifest.json"
    closure_check_path = evidence_root / "application_closure_check.json"
    manifest = load_json(manifest_path) if manifest_path.exists() else {}
    closure_check = load_json(closure_check_path) if closure_check_path.exists() else {}
    local_results_available = results_root.exists()

    fd_summary = summarize_fd_paths(results_root) if local_results_available else {"status": "UNAVAILABLE", "samples": {}}
    process_summary = summarize_process_trees(results_root) if local_results_available else {"status": "UNAVAILABLE", "samples": {}}
    source_summary = summarize_source_attribution(results_root) if local_results_available else {"status": "UNAVAILABLE", "samples": {}}
    benign_overlap = summarize_benign_overlap(evidence_root)

    board_requirements = [
        "capture reliable target syscall entry/return pairing for fd operations",
        "capture or side-channel dereferenced path strings for openat and execve",
        "capture parent-side positive clone/fork return child PID and wait PID in the same evidence window",
        "capture child runtime process map or equivalent PID/SATP/ASID ownership evidence across exec",
        "retain DWARF/debug-line metadata or an addr2line-compatible source-location side channel for source-line attribution",
    ]
    status = "READY_FOR_TARGETED_BOARD_VALIDATION"
    if closure_check.get("status") != "PASS":
        status = "BLOCKED_CLOSURE_CHECK_NOT_PASS"
    elif not local_results_available:
        status = "LOCAL_RESULTS_UNAVAILABLE"

    return {
        "schema": "rvmt.35t.explanation_readiness.v1",
        "run_id": RUN_ID,
        "scope": "Artix-7 35T / LiteX / VexRiscv",
        "claim_level": "35T hardware-trace-assisted synthetic malware-like behavior audit prototype",
        "status": status,
        "local_results_available": local_results_available,
        "closure_check_status": closure_check.get("status", "MISSING"),
        "manifest_fields": {
            "trace_records": manifest.get("trace_records"),
            "trace_profile_policy": manifest.get("trace_profile_policy"),
            "samples": manifest.get("samples"),
            "gate": manifest.get("gate"),
            "full_matrix_ready": manifest.get("full_matrix_ready"),
        },
        "fd_path_flow": fd_summary,
        "process_tree": process_summary,
        "source_attribution": source_summary,
        "benign_overlap_separation": benign_overlap,
        "board_validation_required": True,
        "board_validation_requirements": board_requirements,
        "local_closure_assessment": "sufficient for the current 35T synthetic behavior-audit prototype; not sufficient for real malware detection or complete semantic reconstruction",
        "non_claims": [
            "no CVA6 board claim",
            "no real malware detection claim",
            "no mature detector claim",
            "no classifier accuracy claim",
            "no complete semantic reconstruction claim",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Explanation Readiness: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        "Scope: Artix-7 35T / LiteX / VexRiscv only.",
        "",
        f"Claim level: {report['claim_level']}.",
        "",
        f"Closure check: {report['closure_check_status']}",
        "",
        "## Local Assessment",
        "",
        report["local_closure_assessment"],
        "",
        "## fd/path Flow",
        "",
        f"Overall: {report['fd_path_flow']['status']}",
        "",
    ]
    for sample, row in report["fd_path_flow"].get("samples", {}).items():
        lines.append(f"- {sample}: {row['status']}; reps={row['rep_count']}; flows={row['total_flows']}")
    lines += ["", "## Process Tree", "", f"Overall: {report['process_tree']['status']}", ""]
    for sample, row in report["process_tree"].get("samples", {}).items():
        lines.append(f"- {sample}: {row['status']}; reps={row['rep_count']}; strict_edges={row['total_edges']}")
    lines += ["", "## Function / Source Attribution", "", f"Overall: {report['source_attribution']['status']}", ""]
    for sample, row in report["source_attribution"].get("samples", {}).items():
        lines.append(
            f"- {sample}: function={row.get('function_level')}; source_line={row.get('source_line_level')}"
        )
    lines += ["", "## Strong / Weak / Benign-overlap Separation", ""]
    overlap = report.get("benign_overlap_separation", {})
    lines.append(f"Overall: {overlap.get('status')}")
    for row in overlap.get("benign_overlap_samples", []):
        rules = ", ".join(str(item) for item in row.get("overlap_rules", []))
        lines.append(f"- {row.get('sample')}: {rules}; expected benign overlap")
    lines += ["", "## Targeted Board Validation Requirements", ""]
    for item in report["board_validation_requirements"]:
        lines.append(f"- {item}")
    lines += ["", "## Non-claims", ""]
    for item in report["non_claims"]:
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "explanation_readiness_summary.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "explanation_readiness_summary.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        results = root / "results/experiments/35t" / RUN_ID
        evidence = root / "docs/07-evaluation-evidence/evidence" / RUN_ID
        evidence.mkdir(parents=True)
        (evidence / "evidence_manifest.json").write_text(
            json.dumps(
                {
                    "trace_records": 512,
                    "trace_profile_policy": "35t_small_capacity",
                    "samples": 13,
                    "gate": "13/13 PASS",
                    "full_matrix_ready": True,
                }
            ),
            encoding="utf-8",
        )
        (evidence / "application_closure_check.json").write_text(json.dumps({"status": "PASS"}), encoding="utf-8")
        sem = {
            "schema": "rvmt.behavior.semantic.v1",
            "syscall_sequence": [
                {
                    "seq": 0,
                    "name": "openat",
                    "process_owner": "target_child",
                    "args": {"a0": "0xffffffffffffff9c", "a1": "0x1000", "a1_string": "/tmp/a"},
                    "return_value": "0x3",
                    "confidence": "paired_target_ecall_return",
                },
                {
                    "seq": 1,
                    "name": "close",
                    "process_owner": "target_child",
                    "args": {"a0": "0x3"},
                    "return_value": "0x0",
                    "confidence": "paired_target_ecall_return",
                },
            ],
        }
        path = results / "samples/malware_like_synthetic/file_scan/board/trace-on/rep_00/behavior_recovery"
        path.mkdir(parents=True)
        (path / "semantic_events.json").write_text(json.dumps(sem), encoding="utf-8")
        report = build_report(root, results, evidence)
        if report["status"] != "READY_FOR_TARGETED_BOARD_VALIDATION":
            print("[FAIL] readiness self-test expected board-validation-ready status", file=sys.stderr)
            return 1
        if report["fd_path_flow"]["samples"]["file_scan"]["status"] != "PASS":
            print("[FAIL] readiness self-test missed fd/path sample status", file=sys.stderr)
            return 1
    print("[PASS] 35T explanation readiness self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize 35T explanation readiness and board-validation boundary.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    results_root = args.results_root or repo_root / "results/experiments/35t" / RUN_ID
    evidence_root = args.evidence_root or repo_root / "docs/07-evaluation-evidence/evidence" / RUN_ID
    try:
        report = build_report(repo_root, results_root.resolve(), evidence_root.resolve())
        write_outputs(report, evidence_root.resolve())
    except Exception as exc:
        print(f"summarize_35t_explanation_readiness: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T explanation readiness")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
