from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
DEFAULT_RAW_ESCROW_DIR = DEFAULT_RESULTS_ROOT / "raw_artifact_escrow_package"
DEFAULT_EXTENSION_BEHAVIOR_RESULTS = Path("results/experiments/35t/35t-extension-behavior-smoke-20260523")
EXTENSION_PROGRAMS_ROOT = Path("experiments/linux_behavior/malware_like/extension_programs")
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]


@dataclass(frozen=True)
class ArtifactClass:
    artifact_id: str
    description: str
    public_policy: str
    min_count: int
    globs: tuple[str, ...]
    explicit_paths: tuple[Path, ...] = ()


ARTIFACT_CLASSES = (
    ArtifactClass(
        "run_config",
        "experiment run configuration",
        "public",
        1,
        (),
        (DEFAULT_RESULTS_ROOT / "run_config.json",),
    ),
    ArtifactClass(
        "raw_uart_log",
        "raw board UART capture logs",
        "local_only_raw_or_sanitized_excerpt",
        1,
        ("**/raw_uart.log",),
    ),
    ArtifactClass(
        "decoded_trace_jsonl",
        "decoded per-repetition trace JSONL",
        "local_only_hash_or_summary",
        13,
        ("samples/**/board/trace-on/rep_*/trace.jsonl",),
    ),
    ArtifactClass(
        "runtime_process_map",
        "runtime process attribution maps",
        "public_or_summary",
        13,
        ("samples/**/board/trace-on/rep_*/runtime_process_map.json",),
    ),
    ArtifactClass(
        "code_map",
        "ELF code-map artifacts",
        "public_or_summary",
        13,
        ("samples/**/*.code_map.json",),
    ),
    ArtifactClass(
        "trace_code_map_summary",
        "trace-to-code join summaries",
        "public_or_summary",
        13,
        ("samples/**/board/trace-on/rep_*/trace_code_map/trace_code_map_summary.json",),
    ),
    ArtifactClass(
        "semantic_events",
        "recovered semantic events",
        "public_or_summary",
        13,
        ("samples/**/board/trace-on/rep_*/behavior_recovery/semantic_events.json",),
    ),
    ArtifactClass(
        "behavior_graph",
        "behavior graph artifacts",
        "public_or_summary",
        13,
        ("samples/**/board/trace-on/rep_*/behavior_recovery/behavior_graph.json",),
    ),
    ArtifactClass(
        "behavior_audit",
        "rule-based behavior audit artifacts",
        "public_or_summary",
        13,
        ("samples/**/board/trace-on/rep_*/behavior_audit/behavior_audit.json",),
    ),
    ArtifactClass(
        "alignment",
        "trace-to-groundtruth alignment artifacts",
        "public_or_summary",
        13,
        ("samples/**/board/trace-on/rep_*/alignment/alignment.json",),
    ),
    ArtifactClass(
        "metrics",
        "aggregate metrics and tables",
        "public",
        1,
        ("aggregate/metrics.json", "aggregate/metrics.csv"),
    ),
    ArtifactClass(
        "resource_timing_reports",
        "runtime overhead, bandwidth, FPGA resource, and timing reports",
        "public_summary",
        3,
        ("aggregate/overhead_report.md", "aggregate/bandwidth_report.md"),
        (Path("docs/reports/resource_report.md"), Path("docs/board/vivado_authorization.md")),
    ),
    ArtifactClass(
        "elf_hashes",
        "source, host ELF, and RISC-V ELF SHA-256 records",
        "public_hashes",
        13,
        ("samples/**/*.sha256",),
    ),
    ArtifactClass(
        "bitstream_metadata",
        "bitstream/resource metadata without committing generated bitstreams",
        "public_summary_no_bitstream_binary",
        1,
        (),
        (
            Path("docs/reports/resource_report.md"),
            Path("docs/board/vivado_authorization.md"),
            DEFAULT_EVIDENCE_ROOT / "board_validation_status.json",
            DEFAULT_EVIDENCE_ROOT / "board_validation_attempt_summary.json",
        ),
    ),
    ArtifactClass(
        "scripts_and_commands",
        "scripts, workflow docs, and command provenance",
        "public",
        4,
        (),
        (
            Path("tools/experiment_35t.py"),
            Path("tools/package_35t_board_validation.py"),
            Path("tools/check_35t_paper_evidence.py"),
            Path("tools/check_35t_paper_positioning.py"),
            Path("tools/check_35t_assessment_reconciliation.py"),
            Path("tools/check_35t_assessment_gate_criteria.py"),
            Path("tools/check_35t_hardware_trace_prototype.py"),
            Path("tools/check_35t_local_code_analysis.py"),
            Path("tools/check_35t_malware_behavior_audit.py"),
            Path("tools/check_35t_assessment_closure.py"),
            Path("tools/check_35t_assessment_traceability.py"),
            Path("tools/check_35t_assessment_requirement_matrix.py"),
            Path("tools/check_35t_remaining_external_work.py"),
            Path("tools/check_35t_evidence_consistency.py"),
            Path("tools/check_35t_fd_path_case_studies.py"),
            Path("tools/check_35t_process_tree_case_study.py"),
            Path("tools/check_35t_metric_coverage.py"),
            Path("tools/check_35t_pointer_snapshot_design_review.py"),
            Path("tools/check_35t_pointer_semantics_preflight.py"),
            Path("tools/check_35t_pointer_snapshot_gate.py"),
            Path("tools/check_35t_threat_model.py"),
            Path("tools/check_35t_helper_alignment.py"),
            Path("tools/check_35t_evaluation_table.py"),
            Path("tools/check_35t_baseline_execution_spec.py"),
            Path("tools/check_35t_qemu_plugin_build_preflight.py"),
            Path("tools/run_35t_qemu_plugin_baseline.py"),
            Path("tools/check_35t_synthetic_suite_extension.py"),
            Path("tools/check_35t_synthetic_extension_host_smoke.py"),
            Path("tools/check_35t_synthetic_extension_target_smoke.py"),
            Path("tools/check_35t_synthetic_extension_behavior_smoke.py"),
            Path("tools/check_35t_extension_35t_enablement.py"),
            Path("tools/check_35t_raw_artifact_sanitization.py"),
            Path("tools/check_35t_raw_artifact_escrow.py"),
            Path("tools/package_35t_paper_artifacts.py"),
            Path("docs/process/uv_workflow.md"),
            Path("experiments/linux_behavior/baseline_execution_spec.json"),
            Path("experiments/linux_behavior/pointer_snapshot_enablement_gate.json"),
            Path("experiments/linux_behavior/pointer_snapshot_design_review.json"),
            Path("docs/research/semantic/pointer_snapshot_design_review.md"),
            DEFAULT_EVIDENCE_ROOT / "command_log.md",
        ),
    ),
    ArtifactClass(
        "synthetic_extension_sources",
        "source-implemented synthetic malware-like extension candidates that remain outside the default 35T claim until gated",
        "public",
        14,
        (),
        (
            Path("experiments/linux_behavior/malware_like/extension_plan.json"),
            EXTENSION_PROGRAMS_ROOT / "direct_syscall_open_read.c",
            EXTENSION_PROGRAMS_ROOT / "timing_anti_analysis_loop.c",
            EXTENSION_PROGRAMS_ROOT / "proc_status_tracerpid_check.c",
            EXTENSION_PROGRAMS_ROOT / "obfuscated_syscall_wrapper.c",
            EXTENSION_PROGRAMS_ROOT / "self_modifying_code_sim.c",
            EXTENSION_PROGRAMS_ROOT / "mprotect_exec_variant.c",
            EXTENSION_PROGRAMS_ROOT / "multi_level_process_chain.c",
            EXTENSION_PROGRAMS_ROOT / "loopback_network_client.c",
            EXTENSION_PROGRAMS_ROOT / "file_encryption_sim_non_destructive.c",
            EXTENSION_PROGRAMS_ROOT / "mirai_proc_scan_sim.c",
            EXTENSION_PROGRAMS_ROOT / "mirai_watchdog_probe_sim.c",
            EXTENSION_PROGRAMS_ROOT / "mirai_encoded_table_sim.c",
            EXTENSION_PROGRAMS_ROOT / "mirai_c2_loopback_probe.c",
        ),
    ),
    ArtifactClass(
        "synthetic_extension_behavior_smoke_evidence",
        "host and QEMU behavior smoke evidence for non-network synthetic extension candidates",
        "public_summary",
        3,
        (),
        (
            DEFAULT_EVIDENCE_ROOT / "synthetic_extension_behavior_smoke.json",
            DEFAULT_EVIDENCE_ROOT / "synthetic_extension_behavior_smoke.md",
            DEFAULT_EXTENSION_BEHAVIOR_RESULTS / "aggregate/synthetic_extension_behavior_smoke_raw.json",
        ),
    ),
    ArtifactClass(
        "qemu_plugin_baseline_evidence",
        "QEMU user-mode TCG-plugin syscall-count baseline summary and local raw output for all 13 samples",
        "public_summary",
        3,
        (),
        (
            DEFAULT_EVIDENCE_ROOT / "qemu_plugin_baseline_summary.json",
            DEFAULT_EVIDENCE_ROOT / "qemu_plugin_baseline_summary.md",
            Path("results/experiments/35t/35t-qemu-plugin-baseline-20260523/aggregate/qemu_plugin_baseline_raw.json"),
        ),
    ),
    ArtifactClass(
        "raw_artifact_sanitization_evidence",
        "raw UART and decoded trace hash inventory with sanitized public excerpts",
        "public",
        2,
        (),
        (
            DEFAULT_EVIDENCE_ROOT / "raw_artifact_sanitization.json",
            DEFAULT_EVIDENCE_ROOT / "raw_artifact_sanitization.md",
        ),
    ),
    ArtifactClass(
        "pointer_snapshot_design_review_evidence",
        "bounded pointer snapshot design review and default-disabled safety evidence",
        "public",
        4,
        (),
        (
            DEFAULT_EVIDENCE_ROOT / "pointer_snapshot_design_review.json",
            DEFAULT_EVIDENCE_ROOT / "pointer_snapshot_design_review.md",
            Path("experiments/linux_behavior/pointer_snapshot_design_review.json"),
            Path("docs/research/semantic/pointer_snapshot_design_review.md"),
        ),
    ),
    ArtifactClass(
        "raw_artifact_escrow_package",
        "local controlled escrow package for full raw UART and decoded trace payloads",
        "local_only_raw_or_sanitized_excerpt",
        6,
        (),
        (
            DEFAULT_EVIDENCE_ROOT / "raw_artifact_escrow.json",
            DEFAULT_EVIDENCE_ROOT / "raw_artifact_escrow.md",
            DEFAULT_RAW_ESCROW_DIR / "README.md",
            DEFAULT_RAW_ESCROW_DIR / "payload_manifest.json",
            DEFAULT_RAW_ESCROW_DIR / "payload_hash_manifest.md",
            DEFAULT_RAW_ESCROW_DIR / "access_policy.md",
        ),
    ),
    ArtifactClass(
        "negative_failed_cases",
        "negative, failed, partial, or bounded-case evidence",
        "public_summary",
        3,
        (
            "aggregate/semantic_failure_triage.json",
            "aggregate/process_chain_capacity_debug.json",
            "aggregate/rule_evidence_debug_summary.json",
        ),
        (
            DEFAULT_EVIDENCE_ROOT / "advanced_baseline_preflight.json",
            DEFAULT_EVIDENCE_ROOT / "qemu_plugin_build_preflight.json",
            DEFAULT_EVIDENCE_ROOT / "extension_35t_enablement_preflight.json",
            DEFAULT_EVIDENCE_ROOT / "pointer_semantics_preflight.json",
            DEFAULT_EVIDENCE_ROOT / "evaluation_table.json",
            DEFAULT_EVIDENCE_ROOT / "paper_evidence_check.json",
        ),
    ),
    ArtifactClass(
        "reproduction_readme",
        "README and workflow notes for reproducing or auditing the package",
        "public",
        2,
        (),
        (DEFAULT_EVIDENCE_ROOT / "README.md", Path("docs/process/uv_workflow.md"), DEFAULT_EVIDENCE_ROOT / "command_log.md"),
    ),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def class_digest(files: list[Path], repo_root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(files, key=lambda p: rel(p, repo_root)):
        h.update(rel(path, repo_root).encode("utf-8"))
        h.update(b"\0")
        h.update(str(path.stat().st_size).encode("ascii"))
        h.update(b"\0")
        h.update(file_digest(path).encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def resolve_files(repo_root: Path, results_root: Path, spec: ArtifactClass) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    for pattern in spec.globs:
        base = results_root
        for path in base.glob(pattern):
            if path.is_file():
                resolved = path.resolve()
                if resolved not in seen:
                    files.append(path)
                    seen.add(resolved)
    for explicit in spec.explicit_paths:
        path = repo_path(repo_root, explicit)
        if path.is_file():
            resolved = path.resolve()
            if resolved not in seen:
                files.append(path)
                seen.add(resolved)
    return sorted(files, key=lambda p: rel(p, repo_root))


def status_for(spec: ArtifactClass, count: int) -> str:
    if count < spec.min_count:
        return "MISSING"
    if spec.public_policy == "public":
        return "READY_PUBLIC"
    if spec.public_policy in {"public_summary", "public_or_summary", "public_hashes", "public_summary_no_bitstream_binary"}:
        return "READY_PUBLIC_SUMMARY_OR_HASH"
    return "READY_LOCAL_ONLY"


def build_class_row(repo_root: Path, results_root: Path, spec: ArtifactClass) -> dict[str, Any]:
    files = resolve_files(repo_root, results_root, spec)
    total_bytes = sum(path.stat().st_size for path in files)
    representative = []
    for path in files[:8]:
        representative.append(
            {
                "path": rel(path, repo_root),
                "bytes": path.stat().st_size,
                "sha256": file_digest(path),
            }
        )
    return {
        "artifact_id": spec.artifact_id,
        "description": spec.description,
        "status": status_for(spec, len(files)),
        "public_policy": spec.public_policy,
        "count": len(files),
        "min_count": spec.min_count,
        "total_bytes": total_bytes,
        "class_digest": class_digest(files, repo_root) if files else None,
        "representative_files": representative,
        "missing": len(files) < spec.min_count,
    }


def build_report(repo_root: Path, results_root_arg: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    results_root = repo_path(repo_root, results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    classes = [build_class_row(repo_root, results_root, spec) for spec in ARTIFACT_CLASSES]
    missing = [row for row in classes if row["status"] == "MISSING"]
    local_only = [row for row in classes if row["status"] == "READY_LOCAL_ONLY"]
    summary_or_hash = [row for row in classes if row["status"] == "READY_PUBLIC_SUMMARY_OR_HASH"]
    status = "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED" if not missing else "INCOMPLETE"
    checks = {
        "results_root_exists": results_root.exists(),
        "evidence_root_exists": evidence_root.exists(),
        "all_required_classes_accounted": not missing,
        "raw_large_artifacts_have_policy": all(row["public_policy"] != "public" for row in local_only),
        "non_claims_present": bool(NON_CLAIMS),
    }
    if not all(checks.values()):
        status = "INCOMPLETE"
    return {
        "schema": "rvmt.35t.artifact_package_readiness.v1",
        "run_id": RUN_ID,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "generated_utc": utc_now(),
        "status": status,
        "source_results_root": rel(results_root, repo_root),
        "evidence_root": rel(evidence_root, repo_root),
        "checks": checks,
        "artifact_classes": classes,
        "class_count": len(classes),
        "missing_classes": [row["artifact_id"] for row in missing],
        "local_only_classes": [row["artifact_id"] for row in local_only],
        "summary_or_hash_classes": [row["artifact_id"] for row in summary_or_hash],
        "interpretation": [
            "current repository can describe the paper artifact inventory and verify required artifact classes locally",
            "large raw traces, raw UART logs, generated bitstreams, board build directories, and ELF binaries remain outside the lightweight committed snapshot",
            "full reproduction packaging remains deferred until raw artifacts are sanitized or explicitly released with hashes and access policy",
        ],
        "non_claims": NON_CLAIMS,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Artifact Package Readiness: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Scope: {report['scope']}.",
        "",
        f"Claim level: {report['claim_level']}.",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Artifact Classes",
        "",
        "| Class | Status | Count | Policy | Bytes |",
        "| --- | --- | ---: | --- | ---: |",
    ]
    for row in report["artifact_classes"]:
        lines.append(
            "| `{artifact_id}` | `{status}` | {count}/{min_count} | `{policy}` | {bytes} |".format(
                artifact_id=row["artifact_id"],
                status=row["status"],
                count=row["count"],
                min_count=row["min_count"],
                policy=row["public_policy"],
                bytes=row["total_bytes"],
            )
        )
    lines += ["", "## Missing Classes", ""]
    lines.extend(f"- {item}" for item in report["missing_classes"] or ["none"])
    lines += ["", "## Local-Only Classes", ""]
    lines.extend(f"- {item}" for item in report["local_only_classes"] or ["none"])
    lines += ["", "## Summary/Hash Classes", ""]
    lines.extend(f"- {item}" for item in report["summary_or_hash_classes"] or ["none"])
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "artifact_package_readiness.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "artifact_package_readiness.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_fixture(root: Path) -> None:
    results = root / DEFAULT_RESULTS_ROOT
    evidence = root / DEFAULT_EVIDENCE_ROOT
    for path in [
        results / "run_config.json",
        results / "board/raw_uart.log",
        results / "aggregate/metrics.json",
        results / "aggregate/metrics.csv",
        results / "aggregate/overhead_report.md",
        results / "aggregate/bandwidth_report.md",
        results / "aggregate/semantic_failure_triage.json",
        results / "aggregate/process_chain_capacity_debug.json",
        results / "aggregate/rule_evidence_debug_summary.json",
        evidence / "advanced_baseline_preflight.json",
        evidence / "qemu_plugin_build_preflight.json",
        evidence / "qemu_plugin_baseline_summary.json",
        evidence / "qemu_plugin_baseline_summary.md",
        evidence / "pointer_semantics_preflight.json",
        evidence / "evaluation_table.json",
        evidence / "paper_evidence_check.json",
        evidence / "board_validation_status.json",
        evidence / "board_validation_attempt_summary.json",
        evidence / "README.md",
        evidence / "command_log.md",
        root / "docs/reports/resource_report.md",
        root / "docs/board/vivado_authorization.md",
        root / "docs/process/uv_workflow.md",
        root / "tools/experiment_35t.py",
        root / "tools/package_35t_board_validation.py",
        root / "tools/check_35t_paper_evidence.py",
        root / "tools/check_35t_paper_positioning.py",
        root / "tools/check_35t_assessment_reconciliation.py",
        root / "tools/check_35t_assessment_gate_criteria.py",
        root / "tools/check_35t_hardware_trace_prototype.py",
        root / "tools/check_35t_local_code_analysis.py",
        root / "tools/check_35t_malware_behavior_audit.py",
        root / "tools/check_35t_assessment_closure.py",
        root / "tools/check_35t_assessment_traceability.py",
        root / "tools/check_35t_assessment_requirement_matrix.py",
        root / "tools/check_35t_remaining_external_work.py",
        root / "tools/check_35t_evidence_consistency.py",
        root / "tools/check_35t_fd_path_case_studies.py",
        root / "tools/check_35t_process_tree_case_study.py",
        root / "tools/check_35t_metric_coverage.py",
        root / "tools/check_35t_pointer_snapshot_design_review.py",
        root / "tools/check_35t_pointer_semantics_preflight.py",
        root / "tools/check_35t_pointer_snapshot_gate.py",
        root / "tools/check_35t_threat_model.py",
        root / "tools/check_35t_helper_alignment.py",
        root / "tools/check_35t_evaluation_table.py",
        root / "tools/check_35t_baseline_execution_spec.py",
        root / "tools/check_35t_qemu_plugin_build_preflight.py",
        root / "tools/run_35t_qemu_plugin_baseline.py",
        root / "tools/check_35t_synthetic_suite_extension.py",
        root / "tools/check_35t_synthetic_extension_host_smoke.py",
        root / "tools/check_35t_synthetic_extension_target_smoke.py",
        root / "tools/check_35t_synthetic_extension_behavior_smoke.py",
        root / "tools/check_35t_extension_35t_enablement.py",
        root / "tools/check_35t_raw_artifact_sanitization.py",
        root / "tools/check_35t_raw_artifact_escrow.py",
        root / "tools/package_35t_paper_artifacts.py",
        root / "experiments/linux_behavior/baseline_execution_spec.json",
        root / "experiments/linux_behavior/pointer_snapshot_enablement_gate.json",
        root / "experiments/linux_behavior/pointer_snapshot_design_review.json",
        root / "docs/research/semantic/pointer_snapshot_design_review.md",
        root / "experiments/linux_behavior/malware_like/extension_plan.json",
        evidence / "raw_artifact_sanitization.json",
        evidence / "raw_artifact_sanitization.md",
        evidence / "pointer_snapshot_design_review.json",
        evidence / "pointer_snapshot_design_review.md",
        evidence / "raw_artifact_escrow.json",
        evidence / "raw_artifact_escrow.md",
        root / DEFAULT_RAW_ESCROW_DIR / "README.md",
        root / DEFAULT_RAW_ESCROW_DIR / "payload_manifest.json",
        root / DEFAULT_RAW_ESCROW_DIR / "payload_hash_manifest.md",
        root / DEFAULT_RAW_ESCROW_DIR / "access_policy.md",
        evidence / "extension_35t_enablement_preflight.json",
        evidence / "extension_35t_enablement_preflight.md",
        evidence / "synthetic_extension_behavior_smoke.json",
        evidence / "synthetic_extension_behavior_smoke.md",
        root / DEFAULT_EXTENSION_BEHAVIOR_RESULTS / "aggregate/synthetic_extension_behavior_smoke_raw.json",
        root / "results/experiments/35t/35t-qemu-plugin-baseline-20260523/aggregate/qemu_plugin_baseline_raw.json",
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
    for name in [
        "direct_syscall_open_read.c",
        "timing_anti_analysis_loop.c",
        "proc_status_tracerpid_check.c",
        "obfuscated_syscall_wrapper.c",
        "self_modifying_code_sim.c",
        "mprotect_exec_variant.c",
        "multi_level_process_chain.c",
        "loopback_network_client.c",
        "file_encryption_sim_non_destructive.c",
        "mirai_proc_scan_sim.c",
        "mirai_watchdog_probe_sim.c",
        "mirai_encoded_table_sim.c",
        "mirai_c2_loopback_probe.c",
    ]:
        path = root / EXTENSION_PROGRAMS_ROOT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
    for index in range(13):
        sample = results / "samples/malware_like_synthetic" / f"sample_{index}"
        for path in [
            sample / "build" / f"sample_{index}.code_map.json",
            sample / "build/source.sha256",
            sample / "board/trace-on/rep_00/trace.jsonl",
            sample / "board/trace-on/rep_00/runtime_process_map.json",
            sample / "board/trace-on/rep_00/trace_code_map/trace_code_map_summary.json",
            sample / "board/trace-on/rep_00/behavior_recovery/semantic_events.json",
            sample / "board/trace-on/rep_00/behavior_recovery/behavior_graph.json",
            sample / "board/trace-on/rep_00/behavior_audit/behavior_audit.json",
            sample / "board/trace-on/rep_00/alignment/alignment.json",
        ]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED":
            print("[FAIL] expected complete fixture to pass artifact package readiness", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "artifact_package_readiness.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_RESULTS_ROOT / "run_config.json").unlink()
        report = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "INCOMPLETE" or "run_config" not in report["missing_classes"]:
            print("[FAIL] expected missing run_config fixture to fail", file=sys.stderr)
            return 1
    print("[PASS] 35T artifact package readiness self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check 35T paper artifact package readiness without copying large artifacts.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
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
        report = build_report(repo_root, args.results_root, args.evidence_root)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_artifact_package_readiness: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T artifact package readiness")
    for missing in report["missing_classes"]:
        print(f"missing: {missing}", file=sys.stderr)
    return 0 if report["status"] == "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
