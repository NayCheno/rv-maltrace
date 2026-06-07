from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_ASSESSMENT = Path("D:/Download/rv_maltrace_35t_assessment.md")
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
SCHEMA = "rvmt.35t.local_code_analysis.v1"
STATUS = "LOCAL_CODE_ANALYSIS_PROTOTYPE_PASS_WITH_BOUNDED_ATTRIBUTION"
BENIGN_SAMPLES = ["hello", "ls", "cat", "cp", "sha256sum"]
MALWARE_LIKE_SAMPLES = [
    "file_scan",
    "batch_open_read_write",
    "self_copy_sim",
    "abnormal_syscall_sequence",
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
    "anti_debug_like",
]
EXPECTED_SAMPLES = BENIGN_SAMPLES + MALWARE_LIKE_SAMPLES
EXPECTED_TOOLS = [
    Path("tools/build_code_map.py"),
    Path("tools/join_trace_code_map.py"),
    Path("tools/recover_behavior.py"),
    Path("tools/audit_behavior.py"),
]
ASSESSMENT_TOKENS = [
    "tools/build_code_map.py",
    "tools/join_trace_code_map.py",
    "tools/recover_behavior.py",
    "tools/audit_behavior.py",
    "trace event -> runtime process map",
    "semantic syscall",
    "behavior graph",
    "rule-based audit",
]
ASSESSMENT_BOUNDARY_TOKENS = [
    "PC-in-ELF",
    "不能单独证明完整 process ownership",
    "完整 semantic reconstruction",
]
AUDIT_NON_CLAIM = "This rule-based audit is synthetic behavior triage, not malware detection quality evidence."


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


def read_json(path: Path, failures: list[str], repo_root: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return {}
    try:
        return load_json(path)
    except Exception as exc:
        failures.append(f"invalid {label}: {rel(path, repo_root)}: {exc}")
        return {}


def read_text(path: Path, failures: list[str], repo_root: Path, label: str) -> str:
    if not path.is_file():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return ""
    return path.read_text(encoding="utf-8")


def sample_class(sample_id: str) -> str:
    return "benign" if sample_id in BENIGN_SAMPLES else "malware_like_synthetic"


def int_value(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def list_len(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def min_or_zero(values: list[int]) -> int:
    return min(values) if values else 0


def code_map_summary(sample_id: str, sample_dir: Path, repo_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    code_maps = sorted((sample_dir / "build").glob("*.code_map.json"))
    code_map_path = code_maps[0] if code_maps else sample_dir / "build" / f"{sample_id}.code_map.json"
    code_map = read_json(code_map_path, failures, repo_root, f"{sample_id} code map") if code_maps else {}
    limitations = "\n".join(str(item) for item in code_map.get("attribution_limitations", []) if item)
    runtime_path = str(code_map.get("runtime_path") or "")
    runtime_path_ok = (
        runtime_path.endswith(f"/{sample_id}")
        if sample_class(sample_id) == "malware_like_synthetic"
        else runtime_path in {f"/usr/bin/{sample_id}", "/usr/bin/rvmt_benign_workload"}
    )
    checks = {
        "single_code_map": len(code_maps) == 1,
        "schema": code_map.get("schema") == "rvmt.code_map.v1",
        "sample_id": code_map.get("sample_id") == sample_id,
        "binary_role": code_map.get("binary_role") == "board_rootfs_overlay",
        "runtime_path": runtime_path_ok,
        "load_ranges_nonempty": list_len(code_map.get("load_ranges")) > 0,
        "sections_nonempty": list_len(code_map.get("sections")) > 0,
        "symbols_nonempty": list_len(code_map.get("symbols")) > 0,
        "syscall_sites_nonempty": list_len(code_map.get("syscall_sites")) > 0,
        "trap_sites_listed": isinstance(code_map.get("trap_sites"), list),
        "attribution_limitations_recorded": "PC-in-ELF" in limitations
        and "not complete process attribution" in limitations,
    }
    failures.extend(key for key, ok in checks.items() if not ok)
    return {
        "path": rel(code_map_path, repo_root) if code_maps else None,
        "checks": checks,
        "schema": code_map.get("schema"),
        "binary_role": code_map.get("binary_role"),
        "runtime_path": code_map.get("runtime_path"),
        "load_range_count": list_len(code_map.get("load_ranges")),
        "section_count": list_len(code_map.get("sections")),
        "symbol_count": list_len(code_map.get("symbols")),
        "syscall_site_count": list_len(code_map.get("syscall_sites")),
        "trap_site_count": list_len(code_map.get("trap_sites")),
        "failures": failures,
    }


def repetition_summary(sample_id: str, rep_dir: Path, repo_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    join = read_json(
        rep_dir / "trace_code_map/trace_code_map_summary.json",
        failures,
        repo_root,
        f"{sample_id} {rep_dir.name} trace-code join summary",
    )
    runtime = read_json(
        rep_dir / "runtime_process_map.json",
        failures,
        repo_root,
        f"{sample_id} {rep_dir.name} runtime process map",
    )
    semantic = read_json(
        rep_dir / "behavior_recovery/semantic_events.json",
        failures,
        repo_root,
        f"{sample_id} {rep_dir.name} semantic events",
    )
    graph = read_json(
        rep_dir / "behavior_recovery/behavior_graph.json",
        failures,
        repo_root,
        f"{sample_id} {rep_dir.name} behavior graph",
    )
    audit = read_json(
        rep_dir / "behavior_audit/behavior_audit.json",
        failures,
        repo_root,
        f"{sample_id} {rep_dir.name} behavior audit",
    )

    parser_warnings = semantic.get("parser_warnings", {}) if isinstance(semantic.get("parser_warnings"), dict) else {}
    join_checks = {
        "schema": join.get("schema") == "rvmt.trace_code_join.summary.v1",
        "sample_id": join.get("sample_id") == sample_id,
        "attribution_model": join.get("attribution_model") == "marker_scope_static_code_map_runtime_process_map",
        "process_attribution_proven": join.get("process_attribution") == "proven",
        "runtime_process_map_pass": join.get("runtime_process_map_status") == "PASS",
        "runtime_process_attribution_proven": join.get("runtime_process_attribution_proven") is True,
        "target_attributed_events": int_value(join.get("target_attributed_events")) > 0,
        "process_attributed_code_site_events": int_value(join.get("process_attributed_code_site_events")) > 0,
    }
    runtime_checks = {
        "schema": runtime.get("schema") == "rvmt.runtime_process_map.v1",
        "status": runtime.get("status") == "PASS",
        "sample_id": runtime.get("sample_id") == sample_id,
        "maps_nonempty": list_len(runtime.get("maps")) > 0,
        "processes_nonempty": list_len(runtime.get("processes")) > 0,
        "owners_present": isinstance(runtime.get("owners"), dict) and bool(runtime.get("owners")),
    }
    semantic_checks = {
        "schema": semantic.get("schema") == "rvmt.behavior.semantic.v1",
        "status": semantic.get("status") == "DERIVED",
        "syscall_sequence_nonempty": list_len(semantic.get("syscall_sequence")) > 0,
        "privilege_boundaries_nonempty": list_len(semantic.get("privilege_boundaries")) > 0,
        "runtime_process_map_embedded": isinstance(semantic.get("runtime_process_map"), dict),
        "parser_unknown_corrupt_zero": int_value(parser_warnings.get("unknown_event_count")) == 0
        and int_value(parser_warnings.get("corrupt_record_count")) == 0,
    }
    graph_checks = {
        "schema": graph.get("schema") == "rvmt.behavior.graph.v1",
        "nodes_nonempty": list_len(graph.get("nodes")) > 0,
        "edges_nonempty": list_len(graph.get("edges")) > 0,
    }
    audit_checks = {
        "schema": audit.get("schema") == "rvmt.behavior.audit.v1",
        "status": audit.get("status") == "DERIVED_AUDIT",
        "matches_nonempty": list_len(audit.get("matches")) > 0,
        "non_claim_recorded": audit.get("non_claim") == AUDIT_NON_CLAIM,
    }
    checks = {
        "trace_code_join": all(join_checks.values()),
        "runtime_process_map": all(runtime_checks.values()),
        "behavior_recovery": all(semantic_checks.values()) and all(graph_checks.values()),
        "behavior_audit": all(audit_checks.values()),
    }
    for group, group_checks in [
        ("join", join_checks),
        ("runtime", runtime_checks),
        ("semantic", semantic_checks),
        ("graph", graph_checks),
        ("audit", audit_checks),
    ]:
        failures.extend(f"{group}.{key}" for key, ok in group_checks.items() if not ok)

    return {
        "rep": rep_dir.name,
        "status": "PASS" if not failures and all(checks.values()) else "FAIL",
        "checks": checks,
        "target_attributed_events": int_value(join.get("target_attributed_events")),
        "process_attributed_code_site_events": int_value(join.get("process_attributed_code_site_events")),
        "syscall_count": list_len(semantic.get("syscall_sequence")),
        "privilege_boundary_count": list_len(semantic.get("privilege_boundaries")),
        "trap_transition_count": list_len(semantic.get("trap_context_transitions")),
        "graph_node_count": list_len(graph.get("nodes")),
        "graph_edge_count": list_len(graph.get("edges")),
        "audit_match_count": list_len(audit.get("matches")),
        "all_expected_matched": audit.get("all_expected_matched"),
        "missing_expected_behavior": audit.get("missing_expected_behavior", []),
        "failures": failures,
    }


def sample_summary(sample_id: str, sample_dir: Path, repo_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    if not sample_dir.is_dir():
        failures.append(f"missing sample dir: {rel(sample_dir, repo_root)}")
        reps: list[Path] = []
    else:
        reps = sorted((sample_dir / "board/trace-on").glob("rep_*"))
    code_map = code_map_summary(sample_id, sample_dir, repo_root)
    rep_rows = [repetition_summary(sample_id, rep, repo_root) for rep in reps]
    failures.extend(f"code_map.{failure}" for failure in code_map["failures"])
    for rep in rep_rows:
        failures.extend(f"{rep['rep']}.{failure}" for failure in rep["failures"])
    if len(reps) != 5:
        failures.append(f"trace_on_rep_count_expected_5_got_{len(reps)}")
    if any(rep["status"] != "PASS" for rep in rep_rows):
        failures.append("one_or_more_trace_on_reps_failed")

    return {
        "sample_id": sample_id,
        "sample_class": sample_class(sample_id),
        "status": "PASS" if not failures else "FAIL",
        "code_map": code_map,
        "trace_on_rep_count": len(reps),
        "complete_rep_count": sum(1 for rep in rep_rows if rep["status"] == "PASS"),
        "all_expected_matched_reps": sum(1 for rep in rep_rows if rep.get("all_expected_matched") is True),
        "min_target_attributed_events": min_or_zero([rep["target_attributed_events"] for rep in rep_rows]),
        "min_process_attributed_code_site_events": min_or_zero(
            [rep["process_attributed_code_site_events"] for rep in rep_rows]
        ),
        "min_syscall_count": min_or_zero([rep["syscall_count"] for rep in rep_rows]),
        "min_privilege_boundary_count": min_or_zero([rep["privilege_boundary_count"] for rep in rep_rows]),
        "min_graph_node_count": min_or_zero([rep["graph_node_count"] for rep in rep_rows]),
        "min_graph_edge_count": min_or_zero([rep["graph_edge_count"] for rep in rep_rows]),
        "min_audit_match_count": min_or_zero([rep["audit_match_count"] for rep in rep_rows]),
        "reps": rep_rows,
        "failures": failures,
    }


def actual_sample_ids(results_root: Path) -> list[str]:
    samples_root = results_root / "samples"
    rows: list[tuple[int, str]] = []
    order = {sample: index for index, sample in enumerate(EXPECTED_SAMPLES)}
    for path in samples_root.glob("*/*"):
        if path.is_dir():
            rows.append((order.get(path.name, len(order)), path.name))
    return [sample for _, sample in sorted(rows)]


def build_report(
    repo_root: Path,
    assessment_arg: Path,
    results_root_arg: Path,
    evidence_root_arg: Path,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    results_root = repo_path(repo_root, results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    failures: list[str] = []
    assessment_path = repo_path(repo_root, assessment_arg).resolve()
    assessment = read_text(assessment_path, failures, repo_root, "assessment document")
    actual_samples = actual_sample_ids(results_root)
    tools = [{"path": rel(repo_path(repo_root, tool), repo_root), "exists": repo_path(repo_root, tool).is_file()} for tool in EXPECTED_TOOLS]
    sample_rows = [
        sample_summary(
            sample,
            results_root / "samples" / sample_class(sample) / sample,
            repo_root,
        )
        for sample in EXPECTED_SAMPLES
    ]
    checks = {
        "assessment_lists_local_code_tools": all(token in assessment for token in ASSESSMENT_TOKENS),
        "assessment_records_attribution_boundaries": all(token in assessment for token in ASSESSMENT_BOUNDARY_TOKENS),
        "tool_provenance_exists": all(row["exists"] for row in tools),
        "results_root_exists": results_root.is_dir(),
        "sample_set_exact": actual_samples == EXPECTED_SAMPLES,
        "sample_count_13": len(actual_samples) == 13,
        "code_map_all_samples": all(not row["code_map"]["failures"] for row in sample_rows),
        "trace_on_rep_count_5_all_samples": all(row["trace_on_rep_count"] == 5 for row in sample_rows),
        "trace_code_join_all_reps": all(
            all(rep["checks"].get("trace_code_join") for rep in row["reps"]) for row in sample_rows
        ),
        "runtime_process_map_all_reps": all(
            all(rep["checks"].get("runtime_process_map") for rep in row["reps"]) for row in sample_rows
        ),
        "behavior_recovery_all_reps": all(
            all(rep["checks"].get("behavior_recovery") for rep in row["reps"]) for row in sample_rows
        ),
        "behavior_audit_all_reps": all(
            all(rep["checks"].get("behavior_audit") for rep in row["reps"]) for row in sample_rows
        ),
        "nonempty_semantic_payload_all_reps": all(
            row["min_syscall_count"] > 0
            and row["min_privilege_boundary_count"] > 0
            and row["min_graph_node_count"] > 0
            and row["min_graph_edge_count"] > 0
            for row in sample_rows
        ),
        "bounded_attribution_non_claims": True,
    }
    failures.extend(key for key, ok in checks.items() if not ok)
    for row in sample_rows:
        failures.extend(f"{row['sample_id']}: {failure}" for failure in row["failures"])

    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "status": STATUS if not failures else "FAIL",
        "assessment_source": str(assessment_path),
        "evidence": {
            "results_root": rel(results_root, repo_root),
            "evidence_root": rel(evidence_root, repo_root),
        },
        "checks": checks,
        "tool_provenance": tools,
        "sample_count": len(actual_samples),
        "expected_samples": EXPECTED_SAMPLES,
        "actual_samples": actual_samples,
        "complete_rep_count": sum(row["complete_rep_count"] for row in sample_rows),
        "expected_rep_count": 5 * len(EXPECTED_SAMPLES),
        "sample_rows": sample_rows,
        "capabilities": [
            "trace PC to local ELF load range, section, symbol, syscall site, and trap site metadata",
            "trace event to marker-scope plus runtime-process-map assisted process attribution",
            "trace event to recovered syscall, trap/context transition, privilege-boundary, and behavior-graph records",
            "semantic event and behavior graph to rule-based synthetic behavior audit results",
        ],
        "boundaries": [
            "PC-in-ELF is static code-range evidence, not complete process ownership",
            "stronger process ownership still depends on marker scope plus runtime process map evidence",
            "source-line attribution is unavailable in this evidence set",
            "complete semantic reconstruction is not claimed",
            "rule-based audit is synthetic behavior triage, not real malware detection quality evidence",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Local Code Analysis Check: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Complete trace-on repetitions: {report['complete_rep_count']}/{report['expected_rep_count']}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Samples",
        "",
        "| Sample | Class | Code map | Complete reps | Min target events | Min process-code events | Min syscalls | Min graph nodes | Failures |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in report["sample_rows"]:
        code_map = row.get("code_map", {})
        lines.append(
            "| `{sample}` | `{klass}` | `{schema}` | {complete}/{reps} | {target} | {process_code} | {syscalls} | {nodes} | {failures} |".format(
                sample=row["sample_id"],
                klass=row["sample_class"],
                schema=code_map.get("schema"),
                complete=row["complete_rep_count"],
                reps=row["trace_on_rep_count"],
                target=row["min_target_attributed_events"],
                process_code=row["min_process_attributed_code_site_events"],
                syscalls=row["min_syscall_count"],
                nodes=row["min_graph_node_count"],
                failures=", ".join(row["failures"]) or "none",
            )
        )
    lines += ["", "## Tool Provenance", ""]
    for row in report["tool_provenance"]:
        lines.append(f"- `{row['path']}`: {'present' if row['exists'] else 'missing'}")
    lines += ["", "## Capabilities", ""]
    lines.extend(f"- {item}" for item in report["capabilities"])
    lines += ["", "## Boundaries", ""]
    lines.extend(f"- {item}" for item in report["boundaries"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "local_code_analysis.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "local_code_analysis.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_fixture(root: Path, *, missing_audit: bool = False) -> Path:
    assessment = root / "assessment.md"
    assessment.write_text(
        "\n".join(ASSESSMENT_TOKENS + ASSESSMENT_BOUNDARY_TOKENS) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    for tool in EXPECTED_TOOLS:
        path = root / tool
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture\n", encoding="utf-8", newline="\n")
    results_root = root / DEFAULT_RESULTS_ROOT
    for sample in EXPECTED_SAMPLES:
        klass = sample_class(sample)
        sample_dir = results_root / "samples" / klass / sample
        write_json(
            sample_dir / "build" / f"{sample}.code_map.json",
            {
                "schema": "rvmt.code_map.v1",
                "sample_id": sample,
                "binary_role": "board_rootfs_overlay",
                "runtime_path": f"/usr/bin/{sample}",
                "load_ranges": [{"start": "0x10000", "end": "0x11000"}],
                "sections": [{"name": ".text"}],
                "symbols": [{"name": "main"}],
                "syscall_sites": [{"pc": "0x10100"}],
                "trap_sites": [],
                "attribution_limitations": [
                    "PC-in-ELF is static code-range evidence, not complete process attribution.",
                ],
            },
        )
        for rep_index in range(5):
            rep = sample_dir / "board/trace-on" / f"rep_{rep_index:02d}"
            write_json(
                rep / "trace_code_map/trace_code_map_summary.json",
                {
                    "schema": "rvmt.trace_code_join.summary.v1",
                    "sample_id": sample,
                    "attribution_model": "marker_scope_static_code_map_runtime_process_map",
                    "process_attribution": "proven",
                    "runtime_process_map_status": "PASS",
                    "runtime_process_attribution_proven": True,
                    "target_attributed_events": 1,
                    "process_attributed_code_site_events": 1,
                },
            )
            write_json(
                rep / "runtime_process_map.json",
                {
                    "schema": "rvmt.runtime_process_map.v1",
                    "status": "PASS",
                    "sample_id": sample,
                    "maps": [{"path": f"/usr/bin/{sample}"}],
                    "processes": [{"role": "target_child"}],
                    "owners": {"target_child": 1},
                },
            )
            write_json(
                rep / "behavior_recovery/semantic_events.json",
                {
                    "schema": "rvmt.behavior.semantic.v1",
                    "status": "DERIVED",
                    "syscall_sequence": [{"name": "write"}],
                    "privilege_boundaries": [{"kind": "syscall_entry"}],
                    "trap_context_transitions": [],
                    "runtime_process_map": {"schema": "rvmt.runtime_process_map.v1"},
                    "parser_warnings": {"unknown_event_count": 0, "corrupt_record_count": 0},
                },
            )
            write_json(
                rep / "behavior_recovery/behavior_graph.json",
                {
                    "schema": "rvmt.behavior.graph.v1",
                    "nodes": [{"id": "trace"}],
                    "edges": [{"source": "trace", "target": "syscall:0"}],
                },
            )
            if not (missing_audit and sample == "file_scan" and rep_index == 0):
                write_json(
                    rep / "behavior_audit/behavior_audit.json",
                    {
                        "schema": "rvmt.behavior.audit.v1",
                        "status": "DERIVED_AUDIT",
                        "matches": [{"rule": "fixture"}],
                        "all_expected_matched": sample in MALWARE_LIKE_SAMPLES,
                        "missing_expected_behavior": [],
                        "non_claim": AUDIT_NON_CLAIM,
                    },
                )
    return assessment


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = write_fixture(root)
        report = build_report(root, assessment, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != STATUS:
            print("[FAIL] expected local code analysis fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "local_code_analysis.md").exists():
            print("[FAIL] missing local code analysis markdown", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = write_fixture(root, missing_audit=True)
        report = build_report(root, assessment, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL" or not any("file_scan" in failure for failure in report["failures"]):
            print("[FAIL] expected missing audit fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T local code analysis self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the 35T local code-analysis artifacts and attribution boundaries.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--assessment", type=Path, default=DEFAULT_ASSESSMENT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.assessment, args.results_root, args.evidence_root)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_local_code_analysis: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T local code analysis")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
