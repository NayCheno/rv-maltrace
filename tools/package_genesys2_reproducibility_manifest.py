from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "reproducibility_manifest.json"

SUMMARY_ARTIFACTS = [
    ("latest_manifest", "latest_manifest.json", "uv run python tools/check_genesys2_latest_standard.py --root ."),
    ("trace_sink", "trace_sink_summary.json", "uv run python tools/check_genesys2_bram_trace_sink.py --root ."),
    ("safe_surrogate_bram_trace", "safe_surrogate_bram_trace_summary.json", "uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root ."),
    ("p0_bram_trace", "p0_bram_trace_summary.json", "uv run python tools/check_genesys2_p0_bram_trace.py --root ."),
    ("drop_accounting", "drop_accounting_summary.json", "uv run python tools/check_trace_drop_accounting.py --root ."),
    ("statistical_robustness", "statistical_robustness_summary.json", "uv run python tools/check_genesys2_statistical_robustness.py --root ."),
    ("streaming_dma_target", "streaming_dma_target_summary.json", "uv run python tools/check_genesys2_streaming_dma_target.py --root ."),
    ("streaming_dma_readiness", "streaming_dma_readiness_summary.json", "uv run python tools/check_genesys2_streaming_dma_readiness.py --root ."),
    ("pointer_snapshot_guardrails", "pointer_snapshot_guardrails.json", "uv run python tools/check_pointer_snapshot_guardrails.py --root ."),
    ("hardware_pointer_prefixes", "hardware_pointer_prefix_summary.json", "uv run python tools/check_hardware_pointer_prefixes.py --root ."),
    ("pointer_string_readiness", "pointer_string_readiness_summary.json", "uv run python tools/check_genesys2_pointer_string_readiness.py --root ."),
    ("benign_control", "benign_control_summary.json", "uv run python tools/check_benign_control_summary.py --root ."),
    ("board_benign_readiness", "board_benign_readiness_summary.json", "uv run python tools/check_genesys2_board_benign_readiness.py --root ."),
    ("production_runtime_benchmark", "production_runtime_benchmark.json", "uv run python tools/check_ccfa_current_quality.py --root ."),
    ("semantic_reconstruction", "semantic_reconstruction_summary.json", "uv run python tools/check_syscall_semantic_reconstruction.py --root ."),
    ("fd_path_graph", "fd_path_graph_summary.json", "uv run python tools/check_fd_path_graph.py --root ."),
    ("source_line_attribution", "source_line_attribution_summary.json", "uv run python tools/check_source_line_attribution.py --root ."),
    ("source_line_sidecar", "source_line_sidecar.json", "uv run python tools/check_source_line_attribution.py --root ."),
    ("source_line_toolchain_probe", "source_line_toolchain_probe.json", "uv run python tools/check_source_line_toolchain_probe.py --root ."),
    ("debug_elf_readiness", "debug_elf_readiness_summary.json", "uv run python tools/check_genesys2_debug_elf_readiness.py --root ."),
    ("external_closure_readiness", "external_closure_readiness.json", "uv run python tools/check_genesys2_external_closure_readiness.py --root ."),
    ("external_closure_intake", "external_closure_intake.json", "uv run python tools/check_genesys2_external_closure_intake.py --root ."),
    ("external_closure_plan", "external_closure_plan.json", "uv run python tools/check_genesys2_external_closure_plan.py --root ."),
    ("external_closure_preflight", "external_closure_preflight.json", "uv run python tools/check_genesys2_external_closure_preflight.py --root ."),
    ("external_operator_packet", "external_operator_packet.json", "uv run python tools/check_genesys2_external_operator_packet.py --root ."),
    ("external_template_board_native_source_lines", "external_closure_templates/board_native_source_lines_summary.template.json", "uv run python tools/prepare_genesys2_external_summary.py --check-templates"),
    ("external_template_hardware_pointer_strings", "external_closure_templates/hardware_pointer_strings_summary.template.json", "uv run python tools/prepare_genesys2_external_summary.py --check-templates"),
    ("external_template_streaming_dma_throughput", "external_closure_templates/streaming_dma_throughput_summary.template.json", "uv run python tools/prepare_genesys2_external_summary.py --check-templates"),
    ("external_template_board_benign_control", "external_closure_templates/board_benign_control_summary.template.json", "uv run python tools/prepare_genesys2_external_summary.py --check-templates"),
    ("process_elf_ownership", "process_elf_ownership_summary.json", "uv run python tools/check_process_elf_ownership.py --root ."),
    ("dynamic_mapping_attribution", "dynamic_mapping_attribution_summary.json", "uv run python tools/check_dynamic_mapping_attribution.py --root ."),
    ("ccfa_evaluation_matrix", "ccfa_evaluation_matrix.json", "uv run python tools/check_ccfa_evaluation_matrix.py --root ."),
    ("baseline_alignment", "baseline_alignment_summary.json", "uv run python tools/check_baseline_alignment.py --root ."),
    ("behavior_audit_metrics", "behavior_audit_metrics.json", "uv run python tools/check_behavior_audit_metrics.py --root ."),
    ("case_study_manifest", "case_study_manifest.json", "uv run python tools/check_ccfa_case_study_manifest.py --root ."),
    ("review_closure_audit", "review_closure_audit.json", "uv run python tools/check_genesys2_review_closure_audit.py --root ."),
    ("real_malware_containment", "real_malware_containment.json", "uv run python tools/check_real_malware_containment.py --root ."),
]

RAW_ROOT_PATTERNS = {
    "p0_bram_repetitions": {
        "bram_records": "*/*/bram_records.jsonl",
        "capture_logs": "*/*/capture.log",
        "uart_logs": "*/*/uart.log",
    },
    "safe_surrogate_bram_repetitions": {
        "bram_records": "*/*/bram_records.jsonl",
        "capture_logs": "*/*/capture.log",
        "uart_logs": "*/*/uart.log",
    },
    "pointer_snapshot_bram": {
        "bram_records": "*/*/bram_records.jsonl",
        "capture_logs": "*/*/capture.log",
        "uart_logs": "*/*/uart.log",
    },
    "p0_continuous_trace": {
        "decoded_traces": "*/trace.jsonl",
        "trace_summaries": "*/trace_summary.json",
        "uart_logs": "*/uart_run.log",
    },
    "safe_surrogate_runtime_map": {
        "runtime_process_maps": "*/runtime_process_map.json",
        "helper_logs": "*/runtime_process_map_helper.log",
    },
    "production_runtime_benchmark": {
        "program_logs": "**/uart.log",
    },
}
TEMPLATE_SUMMARY_IDS = {
    "external_template_board_native_source_lines",
    "external_template_hardware_pointer_strings",
    "external_template_streaming_dma_throughput",
    "external_template_board_benign_control",
}


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


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


def artifact_row(current_root: Path, artifact_id: str, filename: str, checker: str) -> dict[str, Any]:
    path = current_root / filename
    data = load_json(path)
    return {
        "id": artifact_id,
        "path": repo_rel(path),
        "sha256": sha256_file(path),
        "schema": data.get("schema"),
        "status": data.get("status"),
        "checker_command": checker,
    }


def count_glob(root: Path, pattern: str) -> int:
    return sum(1 for path in root.glob(pattern) if path.is_file())


def raw_root_rows(latest: dict[str, Any]) -> list[dict[str, Any]]:
    active_roots = latest.get("active_run_roots") if isinstance(latest.get("active_run_roots"), dict) else {}
    rows: list[dict[str, Any]] = []
    for root_id, patterns in RAW_ROOT_PATTERNS.items():
        value = active_roots.get(root_id)
        if not isinstance(value, str) or not value:
            rows.append({"id": root_id, "path": None, "exists": False, "file_counts": {}})
            continue
        path = ROOT / value
        rows.append(
            {
                "id": root_id,
                "path": value,
                "exists": path.is_dir(),
                "file_counts": {name: count_glob(path, pattern) for name, pattern in patterns.items()},
                "glob_patterns": patterns,
            }
        )
    return rows


def report_rows() -> list[dict[str, Any]]:
    return [
        {
            "id": "baseline_pass_criteria_current_status",
            "report": "docs/03-platform-architecture/genesys2/baseline_pass_criteria.md",
            "source_summary_ids": ["latest_manifest"],
            "raw_root_ids": [],
            "checker_commands": [
                "uv run python tools/check_baseline_pass_criteria.py --root .",
            ],
        },
        {
            "id": "readiness_claim_gates",
            "report": "docs/07-evaluation-evidence/reports/ccfa_readiness_matrix.md",
            "source_summary_ids": [
                "latest_manifest",
                "p0_bram_trace",
                "safe_surrogate_bram_trace",
                "statistical_robustness",
                "streaming_dma_target",
                "streaming_dma_readiness",
                "pointer_snapshot_guardrails",
                "hardware_pointer_prefixes",
                "pointer_string_readiness",
                "benign_control",
                "board_benign_readiness",
                "drop_accounting",
                "semantic_reconstruction",
                "fd_path_graph",
                "source_line_attribution",
                "source_line_toolchain_probe",
                "debug_elf_readiness",
                "external_closure_readiness",
                "external_closure_intake",
                "external_closure_plan",
                "external_closure_preflight",
                "external_operator_packet",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "external_template_board_benign_control",
                "process_elf_ownership",
                "ccfa_evaluation_matrix",
                "behavior_audit_metrics",
                "case_study_manifest",
                "statistical_robustness",
            ],
            "raw_root_ids": [
                "p0_bram_repetitions",
                "safe_surrogate_bram_repetitions",
                "pointer_snapshot_bram",
                "p0_continuous_trace",
                "safe_surrogate_runtime_map",
            ],
            "checker_commands": [
                "uv run python tools/run_check_suite.py --suite genesys2-current",
                "uv run python tools/check_ccfa_claim_boundaries.py --root .",
                "uv run python tools/check_source_line_toolchain_probe.py --root .",
                "uv run python tools/check_genesys2_debug_elf_readiness.py --root .",
                "uv run python tools/check_ccfa_case_study_manifest.py --root .",
                "uv run python tools/check_genesys2_board_benign_readiness.py --root .",
                "uv run python tools/check_genesys2_statistical_robustness.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
                "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
            ],
        },
        {
            "id": "next_closure_completed_items",
            "report": "docs/07-evaluation-evidence/reports/ccfa_next_closure_plan.md",
            "source_summary_ids": [
                "latest_manifest",
                "p0_bram_trace",
                "safe_surrogate_bram_trace",
                "statistical_robustness",
                "streaming_dma_target",
                "streaming_dma_readiness",
                "pointer_snapshot_guardrails",
                "hardware_pointer_prefixes",
                "pointer_string_readiness",
                "benign_control",
                "board_benign_readiness",
                "case_study_manifest",
                "production_runtime_benchmark",
                "external_closure_plan",
                "external_closure_preflight",
                "external_operator_packet",
                "debug_elf_readiness",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "external_template_board_benign_control",
            ],
            "raw_root_ids": ["p0_bram_repetitions", "safe_surrogate_bram_repetitions", "pointer_snapshot_bram", "production_runtime_benchmark"],
            "checker_commands": [
                "uv run python tools/check_hardware_pointer_prefixes.py --root .",
                "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                "uv run python tools/check_ccfa_case_study_manifest.py --root .",
                "uv run python tools/check_ccfa_current_quality.py --root .",
                "uv run python tools/check_genesys2_statistical_robustness.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
                "uv run python tools/check_genesys2_debug_elf_readiness.py --root .",
                "uv run python tools/check_genesys2_board_benign_readiness.py --root .",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
            ],
        },
        {
            "id": "evaluation_plan_current_status",
            "report": "docs/07-evaluation-evidence/evaluation_plan.md",
            "source_summary_ids": [
                "ccfa_evaluation_matrix",
                "baseline_alignment",
                "behavior_audit_metrics",
                "case_study_manifest",
                "statistical_robustness",
                "streaming_dma_target",
                "streaming_dma_readiness",
                "pointer_string_readiness",
                "production_runtime_benchmark",
                "latest_manifest",
                "external_closure_readiness",
                "external_closure_intake",
                "external_closure_plan",
                "external_closure_preflight",
                "external_operator_packet",
                "board_benign_readiness",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "external_template_board_benign_control",
            ],
            "raw_root_ids": [
                "p0_bram_repetitions",
                "safe_surrogate_bram_repetitions",
                "pointer_snapshot_bram",
                "production_runtime_benchmark",
            ],
            "checker_commands": [
                "uv run python tools/check_evaluation_plan.py --root .",
                "uv run python tools/check_ccfa_evaluation_matrix.py --root .",
                "uv run python tools/check_baseline_alignment.py --root .",
                "uv run python tools/check_genesys2_statistical_robustness.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
                "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                "uv run python tools/check_genesys2_board_benign_readiness.py --root .",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
            ],
        },
        {
            "id": "review_closure_audit",
            "report": "docs/07-evaluation-evidence/reports/ccfa_review_closure_audit.md",
            "source_summary_ids": [
                "review_closure_audit",
                "latest_manifest",
                "external_closure_readiness",
                "external_closure_intake",
                "external_closure_plan",
                "external_closure_preflight",
                "external_operator_packet",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "streaming_dma_target",
                "streaming_dma_readiness",
                "pointer_string_readiness",
                "external_template_board_benign_control",
                "board_benign_readiness",
            ],
            "raw_root_ids": [],
            "checker_commands": [
                "uv run python tools/package_genesys2_review_closure_audit.py",
                "uv run python tools/check_genesys2_review_closure_audit.py --root .",
                "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
            ],
        },
        {
            "id": "external_operator_packet_handoff",
            "report": "docs/07-evaluation-evidence/reports/ccfa_external_operator_packet.md",
            "source_summary_ids": [
                "external_operator_packet",
                "external_closure_readiness",
                "external_closure_intake",
                "external_closure_plan",
                "external_closure_preflight",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "external_template_board_benign_control",
            ],
            "raw_root_ids": [],
            "checker_commands": [
                "uv run python tools/package_genesys2_external_operator_packet.py",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/check_genesys2_external_closure_intake.py --root .",
                "uv run python tools/check_genesys2_external_closure_preflight.py --root .",
            ],
        },
        {
            "id": "p0_evidence_chain",
            "report": "docs/07-evaluation-evidence/reports/genesys2_cva6_evidence_chain_20260611.md",
            "source_summary_ids": [
                "p0_bram_trace",
                "trace_sink",
                "safe_surrogate_bram_trace",
                "drop_accounting",
                "statistical_robustness",
                "streaming_dma_target",
                "streaming_dma_readiness",
                "pointer_string_readiness",
                "external_operator_packet",
                "external_template_board_native_source_lines",
                "external_template_hardware_pointer_strings",
                "external_template_streaming_dma_throughput",
                "external_template_board_benign_control",
            ],
            "raw_root_ids": ["p0_bram_repetitions", "safe_surrogate_bram_repetitions", "p0_continuous_trace"],
            "checker_commands": [
                "uv run python tools/check_genesys2_p0_bram_trace.py --root .",
                "uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .",
                "uv run python tools/check_genesys2_statistical_robustness.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_target.py --root .",
                "uv run python tools/check_genesys2_streaming_dma_readiness.py --root .",
                "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
                "uv run python tools/check_genesys2_external_operator_packet.py --root .",
                "uv run python tools/prepare_genesys2_external_summary.py --check-templates",
            ],
        },
    ]


def package_manifest(current_root: Path) -> dict[str, Any]:
    latest = load_json(current_root / "latest_manifest.json")
    summary_rows = [artifact_row(current_root, artifact_id, filename, checker) for artifact_id, filename, checker in SUMMARY_ARTIFACTS]
    raw_rows = raw_root_rows(latest)
    status = "PASS"
    if latest.get("status") != "PASS":
        status = "FAIL"
    if any(row.get("status") != "PASS" for row in summary_rows if row.get("id") not in {"source_line_sidecar", *TEMPLATE_SUMMARY_IDS}):
        status = "FAIL"
    if any(row.get("status") != "TEMPLATE_NOT_EVIDENCE" for row in summary_rows if row.get("id") in TEMPLATE_SUMMARY_IDS):
        status = "FAIL"
    if any(row.get("exists") is not True for row in raw_rows):
        status = "FAIL"
    if any(not any(int(count) > 0 for count in row.get("file_counts", {}).values()) for row in raw_rows):
        status = "FAIL"
    return {
        "schema": "rvmt.genesys2.reproducibility_manifest.v1",
        "status": status,
        "canonical_evaluation_root": repo_rel(current_root),
        "latest_manifest": repo_rel(current_root / "latest_manifest.json"),
        "claim_boundary": {
            "controlled_safe_surrogate_evidence": True,
            "real_malware_validation_claimed": False,
            "hardware_full_pointer_strings_claimed": False,
            "production_streaming_dma_throughput_claimed": False,
            "board_native_source_line_attribution_claimed": False,
            "debug_toolchain_source_line_probe_available": True,
            "debug_no_pie_elf_readiness_available": True,
            "board_benign_readiness_available": True,
            "streaming_dma_readiness_available": True,
            "pointer_string_readiness_available": True,
            "dated_roots_are_provenance_only": True,
        },
        "summary_artifacts": summary_rows,
        "raw_artifact_roots": raw_rows,
        "report_rows": report_rows(),
        "validation_commands": [
            "uv run python tools/run_check_suite.py --suite genesys2-current",
            "uv run python tools/run_check_suite.py --suite genesys2-artifacts",
            "uv run python tools/run_check_suite.py --suite genesys2-self-test",
            "uv run python tools/run_check_suite.py --suite ccfa-gate-self-test",
        ],
        "non_claims": [
            "This manifest ties existing controlled board artifacts and summaries to checker commands; it does not add real-malware validation.",
            "Raw dated board directories are provenance and are selected only through current/latest_manifest.json.",
            "Hardware pointer strings remain bounded-prefix/fragment evidence only.",
            "The pointer string readiness summary prepares future gap-free hardware full-string collection but does not complete full hardware pointer-string evidence.",
            "The source-line toolchain probe does not make current board traces DWARF source-line attributed.",
            "The debug ELF readiness summary prepares debug/no-PIE rerun candidates but does not make current board traces DWARF source-line attributed.",
            "The board benign readiness summary prepares future Genesys2 benign-control collection but does not complete board benign false-positive evidence.",
            "The streaming/DMA readiness summary prepares future non-BRAM transport collection but does not complete production streaming/DMA throughput evidence.",
            "The external closure readiness contract records remaining non-real-malware blockers but does not complete them.",
            "The external closure intake gate validates optional future external summaries but remains open until board/RTL summaries are present.",
            "The external closure plan provides executable runbooks and templates but does not replace board/RTL execution.",
            "The external closure preflight proves only local scripts, dry-run hooks, schema paths, and guardrails are ready; it does not replace external execution.",
            "The external operator packet is an execution handoff and does not replace external board, RTL, host transport, or reviewer execution.",
            "The external summary templates are TEMPLATE_NOT_EVIDENCE scaffolding and must not be treated as accepted external summaries.",
            "The statistical robustness summary audits controlled repetitions and retained failures, but it does not make randomized workload or real-malware generalization claims.",
            "The streaming/DMA target summary is a cycle-normalized local target baseline only; it does not complete production streaming/DMA throughput evidence.",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        raw = root / "raw" / "p0"
        raw.mkdir(parents=True, exist_ok=True)
        for rel in (
            "sample/rep_01/bram_records.jsonl",
            "sample/rep_01/capture.log",
            "sample/rep_01/uart.log",
            "sample/trace.jsonl",
            "sample/trace_summary.json",
            "sample/uart_run.log",
            "sample/runtime_process_map.json",
            "sample/runtime_process_map_helper.log",
            "sample/mode/rep_01/uart.log",
        ):
            path = raw / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
        latest_roots = {key: "raw/p0" for key in RAW_ROOT_PATTERNS}
        write_json(current / "latest_manifest.json", {"schema": "rvmt.genesys2.latest_manifest.v1", "status": "PASS", "active_run_roots": latest_roots})
        for artifact_id, filename, _checker in SUMMARY_ARTIFACTS:
            path = current / filename
            if path.name == "latest_manifest.json":
                continue
            status = "TEMPLATE_NOT_EVIDENCE" if artifact_id in TEMPLATE_SUMMARY_IDS else "PASS"
            write_json(path, {"schema": f"rvmt.fixture.{path.stem}.v1", "status": status})
        old_root = globals()["ROOT"]
        try:
            globals()["ROOT"] = root
            manifest = package_manifest(current)
        finally:
            globals()["ROOT"] = old_root
    if manifest.get("status") != "PASS":
        print("[FAIL] expected reproducibility fixture to pass", file=sys.stderr)
        return 1
    if len(manifest.get("summary_artifacts", [])) != len(SUMMARY_ARTIFACTS):
        print("[FAIL] missing summary artifact rows", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 reproducibility manifest packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package current Genesys2/CVA6 reproducibility manifest.")
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    current_root = args.current_root
    try:
        manifest = package_manifest(current_root)
        write_json(args.out, manifest)
    except Exception as exc:
        print(f"package_genesys2_reproducibility_manifest: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{manifest['status']}] wrote Genesys2 reproducibility manifest to {args.out}")
    return 0 if manifest["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
