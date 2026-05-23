from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
STATUS = "PASS_CURRENT_EXTERNAL_CONDITIONS_RECORDED"
ASSESSMENT_STATUS = "PASS_WITH_BOUNDED_REMAINING_WORK"
P3_STATUS = "PARTIAL_BOUNDED_SYNTHETIC_ARG_MEM_GUARDRAILS"
P4_STATUS = "HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS"
P5_STATUS = "IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING"
P6_STATUS = "LIGHTWEIGHT_ARTIFACT_PASS_FULL_REPRO_DEFERRED"
POINTER_DESIGN_REVIEW_STATUS = "POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED"
EXTENSION_HOST_SMOKE_PASS_STATUS = "HOST_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED"
EXTENSION_TARGET_SMOKE_PASS_STATUS = "TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED"
EXTENSION_BEHAVIOR_SMOKE_PASS_STATUS = "HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED"
EXTENSION_ENABLEMENT_PREFLIGHT_STATUS = "EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED"
RAW_ARTIFACT_SANITIZATION_STATUS = "RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED"
RAW_ARTIFACT_ESCROW_STATUS = "LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED"
HELPER_ALIGNMENT_STATUS = "TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL"
QEMU_PLUGIN_BUILD_PREFLIGHT_STATUS = "QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED"
QEMU_PLUGIN_BASELINE_STATUS = "QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES"


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


def goal_by_id(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    goals = report.get("goals", [])
    return {
        str(row.get("id")): row
        for row in goals
        if isinstance(row, dict) and row.get("id")
    } if isinstance(goals, list) else {}


def baseline_status(preflight: dict[str, Any], name: str) -> str:
    baselines = preflight.get("baselines", {}) if isinstance(preflight.get("baselines"), dict) else {}
    row = baselines.get(name, {}) if isinstance(baselines.get(name), dict) else {}
    return str(row.get("status") or "MISSING")


def baseline_reason(preflight: dict[str, Any], name: str) -> str:
    baselines = preflight.get("baselines", {}) if isinstance(preflight.get("baselines"), dict) else {}
    row = baselines.get(name, {}) if isinstance(baselines.get(name), dict) else {}
    return str(row.get("reason") or "")


def item(
    *,
    item_id: str,
    goal_id: str,
    current_status: str,
    evidence: list[str],
    current_condition: str,
    required_conditions: list[str],
    unblock_criteria: list[str],
    no_substitution_rule: str,
) -> dict[str, Any]:
    return {
        "id": item_id,
        "goal_id": goal_id,
        "current_status": current_status,
        "evidence": evidence,
        "current_condition": current_condition,
        "required_conditions": required_conditions,
        "unblock_criteria": unblock_criteria,
        "no_substitution_rule": no_substitution_rule,
    }


def evidence_paths_exist(repo_root: Path, evidence_root: Path, paths: list[str]) -> bool:
    for value in paths:
        path = Path(value)
        full_path = repo_path(repo_root, path) if path.parts and path.parts[0] in {"docs", "experiments", "results", "tools"} else evidence_root / path
        if not full_path.is_file():
            return False
    return True


def build_report(repo_root: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    failures: list[str] = []

    closure = read_json(evidence_root / "assessment_closure.json", failures, repo_root, "assessment closure")
    traceability = read_json(evidence_root / "assessment_traceability.json", failures, repo_root, "assessment traceability")
    pointer_gate = read_json(evidence_root / "pointer_snapshot_enablement_gate.json", failures, repo_root, "pointer snapshot gate")
    pointer_preflight = read_json(evidence_root / "pointer_semantics_preflight.json", failures, repo_root, "pointer semantics preflight")
    pointer_design = read_json(evidence_root / "pointer_snapshot_design_review.json", failures, repo_root, "pointer snapshot design review")
    advanced_preflight = read_json(evidence_root / "advanced_baseline_preflight.json", failures, repo_root, "advanced baseline preflight")
    baseline_summary = read_json(evidence_root / "baseline_evaluation_summary.json", failures, repo_root, "baseline evaluation summary")
    baseline_spec = read_json(repo_root / "experiments/linux_behavior/baseline_execution_spec.json", failures, repo_root, "baseline execution spec")
    extension_check = read_json(evidence_root / "synthetic_suite_extension_check.json", failures, repo_root, "synthetic suite extension check")
    extension_host = read_json(evidence_root / "synthetic_extension_host_smoke.json", failures, repo_root, "synthetic extension host smoke")
    extension_target = read_json(evidence_root / "synthetic_extension_target_smoke.json", failures, repo_root, "synthetic extension target smoke")
    extension_behavior = read_json(evidence_root / "synthetic_extension_behavior_smoke.json", failures, repo_root, "synthetic extension behavior smoke")
    extension_enablement = read_json(
        evidence_root / "extension_35t_enablement_preflight.json",
        failures,
        repo_root,
        "extension 35T enablement preflight",
    )
    raw_sanitization = read_json(evidence_root / "raw_artifact_sanitization.json", failures, repo_root, "raw artifact sanitization")
    raw_escrow = read_json(evidence_root / "raw_artifact_escrow.json", failures, repo_root, "raw artifact escrow")
    artifact_readiness = read_json(evidence_root / "artifact_package_readiness.json", failures, repo_root, "artifact package readiness")
    package_manifest = read_json(evidence_root / "paper_artifact_package_manifest.json", failures, repo_root, "paper artifact package manifest")
    helper_alignment = load_json(evidence_root / "helper_alignment.json") if (evidence_root / "helper_alignment.json").is_file() else {}
    qemu_plugin_build = (
        load_json(evidence_root / "qemu_plugin_build_preflight.json")
        if (evidence_root / "qemu_plugin_build_preflight.json").is_file()
        else {}
    )
    qemu_plugin_baseline = (
        load_json(evidence_root / "qemu_plugin_baseline_summary.json")
        if (evidence_root / "qemu_plugin_baseline_summary.json").is_file()
        else {}
    )

    closure_goals = goal_by_id(closure)
    trace_goals = goal_by_id(traceability)
    p3 = closure_goals.get("P3_pointer_argument_semantics", {})
    p4 = closure_goals.get("P4_baseline_evaluation", {})
    p5 = closure_goals.get("P5_synthetic_suite_extension", {})
    p6 = closure_goals.get("P6_artifact_package", {})

    host = extension_host.get("host", {}) if isinstance(extension_host.get("host"), dict) else {}
    local_only = artifact_readiness.get("local_only_classes", []) if isinstance(artifact_readiness.get("local_only_classes"), list) else []
    release_policy = package_manifest.get("release_policy", {}) if isinstance(package_manifest.get("release_policy"), dict) else {}
    local_only_release_classes = release_policy.get("local_only_classes", []) if isinstance(release_policy.get("local_only_classes"), list) else []
    summary_baselines = baseline_summary.get("baselines", {}) if isinstance(baseline_summary.get("baselines"), dict) else {}
    qemu_summary_row = summary_baselines.get("qemu_plugin", {}) if isinstance(summary_baselines.get("qemu_plugin"), dict) else {}
    qemu_plugin_baseline_passed = (
        qemu_plugin_baseline.get("status") == QEMU_PLUGIN_BASELINE_STATUS
        and qemu_plugin_baseline.get("pass_count") == 13
        and qemu_summary_row.get("status") == "PASS"
        and qemu_summary_row.get("samples_with_evidence") == 13
    )

    helper_record = item(
        item_id="p3_trusted_helper_or_ebpf_alignment",
        goal_id="P3_pointer_argument_semantics",
        current_status=str(helper_alignment.get("status") or "DEFERRED_NOT_ALIGNED"),
        evidence=[
            "helper_alignment.json",
            "threat_model_boundary.json",
            "board_syscall_side_channel_smoke.json",
            "results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle/bundle_manifest.json",
        ]
        if helper_alignment
        else [
            "threat_model_boundary.json",
            "experiments/linux_behavior/semantic_threat_model.json",
            "experiments/linux_behavior/baseline_execution_spec.json",
        ],
        current_condition=str(
            helper_alignment.get("current_condition")
            or "helper/eBPF companion route remains optional and deferred"
        ),
        required_conditions=[
            "trusted helper or eBPF companion log",
            "alignment report tying helper/eBPF data to hardware trace evidence",
            "trusted-kernel/user-mode threat model update",
        ],
        unblock_criteria=[
            "helper/eBPF companion route is explicitly enabled",
            "alignment report exists for the 35T run",
            "kernel-rootkit and eBPF-tamper resistance remain non-claims",
        ],
        no_substitution_rule="helper/eBPF companion evidence must not be reported as hardware-only tracing",
    )

    records = [
        item(
            item_id="p3_hardware_user_pointer_snapshot",
            goal_id="P3_pointer_argument_semantics",
            current_status="DEFERRED_NOT_ENABLED",
            evidence=[
                "pointer_snapshot_enablement_gate.json",
                "pointer_semantics_preflight.json",
                "pointer_snapshot_design_review.json",
                "experiments/linux_behavior/pointer_snapshot_enablement_gate.json",
                "experiments/linux_behavior/pointer_snapshot_design_review.json",
            ],
            current_condition=f"{pointer_gate.get('status') or 'MISSING'}; design_review={pointer_design.get('status') or 'MISSING'}",
            required_conditions=[
                "timing/resource measurements",
                "bandwidth/drop accounting",
                "noninterference evidence",
                "semantic accuracy evidence",
                "artifact release policy",
            ],
            unblock_criteria=[
                "pointer gate no longer reports POINTER_SNAPSHOT_ENABLEMENT_GATES_RECORDED_NOT_ENABLED",
                "pointer preflight no longer reports hardware_user_pointer_snapshot=DEFERRED",
                "enabled 35T run records timing, bandwidth, DROP, and noninterference measurements",
            ],
            no_substitution_rule="synthetic ARG_MEM fixtures or syscall side-channel paths cannot be substituted for enabled hardware pointer snapshot evidence",
        ),
        item(
            item_id="p4_qemu_plugin_baseline",
            goal_id="P4_baseline_evaluation",
            current_status="PASS" if qemu_plugin_baseline_passed else baseline_status(advanced_preflight, "qemu_plugin"),
            evidence=(
                ["qemu_plugin_baseline_summary.json"]
                if qemu_plugin_baseline_passed
                else []
            )
            + [
                "qemu_plugin_build_preflight.json",
                "advanced_baseline_preflight.json",
                "baseline_execution_spec_check.json",
                "experiments/linux_behavior/baseline_execution_spec.json",
            ],
            current_condition=(
                "13-sample QEMU-plugin syscall-count baseline recorded"
                if qemu_plugin_baseline_passed
                else (
                f"{qemu_plugin_build.get('current_condition')}; {baseline_reason(advanced_preflight, 'qemu_plugin')}"
                if qemu_plugin_build.get("status") == QEMU_PLUGIN_BUILD_PREFLIGHT_STATUS
                else baseline_reason(advanced_preflight, "qemu_plugin")
                )
            ),
            required_conditions=[
                "QEMU user/system binary with TCG plugin support",
                "qemu-plugin.h and plugin build transcript",
                "13-sample QEMU-plugin trace and timing run",
            ],
            unblock_criteria=[
                "qemu_plugin_baseline_summary.json reports QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES",
                "baseline_evaluation_summary.json reports qemu_plugin PASS with 13/13 sample evidence",
            ],
            no_substitution_rule="QEMU-plugin syscall-count evidence is simulator software evidence, not hardware trace, DBI, or real malware evidence",
        ),
        item(
            item_id="p5_extension_35t_gating",
            goal_id="P5_synthetic_suite_extension",
            current_status="DEFERRED_35T_RUN_REQUIRED",
            evidence=[
                "synthetic_suite_extension_check.json",
                "synthetic_extension_host_smoke.json",
                "synthetic_extension_target_smoke.json",
                "synthetic_extension_behavior_smoke.json",
                "extension_35t_enablement_preflight.json",
                "experiments/linux_behavior/malware_like/extension_plan.json",
            ],
            current_condition=(
                f"{extension_check.get('implemented_candidate_count')} source candidates implemented, "
                f"host_compiled={extension_host.get('compiled_candidate_count')}/{extension_host.get('candidate_count')}, "
                f"target_compiled={extension_target.get('compiled_candidate_count')}/{extension_target.get('candidate_count')}, "
                f"behavior_smoke={extension_behavior.get('summary_counts', {}).get('execution_pass_count')}/"
                f"{extension_behavior.get('summary_counts', {}).get('executed_candidate_count')}, "
                f"enablement={extension_enablement.get('status') or 'MISSING'}, "
                "no expanded 35T coverage claim"
            ),
            required_conditions=[
                "explicitly enable selected extension candidates",
                "deploy selected candidates into the 35T image or rootfs overlay",
                "run selected candidates through the same marker, attribution, drop, capacity, and strong-evidence gates",
            ],
            unblock_criteria=[
                "new 35T run records selected extension samples in the matrix",
                "gate report passes for enabled extension samples",
            ],
            no_substitution_rule="source implementation and host/QEMU behavior smoke cannot be substituted for expanded 35T coverage",
        ),
        item(
            item_id="p6_full_raw_artifact_release",
            goal_id="P6_artifact_package",
            current_status="HASH_EXCERPT_READY_FULL_RAW_DEFERRED",
            evidence=[
                "raw_artifact_sanitization.json",
                "raw_artifact_sanitization.md",
                "raw_artifact_escrow.json",
                "raw_artifact_escrow.md",
                "artifact_package_readiness.json",
                "paper_artifact_package_manifest.json",
                "paper_artifact_release_policy.json",
                "evidence_manifest.json",
            ],
            current_condition=(
                f"raw_sanitization_status={raw_sanitization.get('status')}; "
                f"raw_escrow_status={raw_escrow.get('status')}; "
                f"escrow_payload_files={raw_escrow.get('payload_file_count')}; "
                f"local_only={local_only}; release_local_only={local_only_release_classes}"
            ),
            required_conditions=[
                "sanitize or approve raw UART logs and decoded traces",
                "decide controlled-release policy for large raw artifacts",
                "publish or escrow raw artifacts with hashes and access policy",
            ],
            unblock_criteria=[
                "paper package status no longer reports full raw deferred",
                "raw/local-only artifact classes have release approval or sanitized public replacements",
            ],
            no_substitution_rule="lightweight summaries and hashes are not a full raw artifact release",
        ),
    ]
    host_smoke_record = item(
        item_id="p5_extension_host_compile_smoke",
        goal_id="P5_synthetic_suite_extension",
        current_status=str(extension_host.get("status") or "MISSING"),
        evidence=[
            "synthetic_extension_host_smoke.json",
            "synthetic_suite_extension_check.json",
            "experiments/linux_behavior/malware_like/extension_plan.json",
        ],
        current_condition=", ".join(str(reason) for reason in host.get("blocked_reasons", []) if reason)
        if isinstance(host.get("blocked_reasons"), list) and host.get("blocked_reasons")
        else f"compiled={extension_host.get('compiled_candidate_count')}/{extension_host.get('candidate_count')}",
        required_conditions=[
            "Linux host or target-like build environment",
            "available C compiler",
            "compile-only check for all source-implemented candidates",
        ],
        unblock_criteria=[
            "synthetic_extension_host_smoke.json reports HOST_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED",
            "compiled_candidate_count equals candidate_count",
        ],
        no_substitution_rule="host compile smoke is not execution evidence and is not a 35T gate pass",
    )
    host_smoke_passed = (
        extension_host.get("status") == EXTENSION_HOST_SMOKE_PASS_STATUS
        and extension_host.get("compiled_candidate_count") == extension_host.get("candidate_count")
    )
    satisfied_conditions = [host_smoke_record] if host_smoke_passed else []
    qemu_baseline_record = next((row for row in records if row["id"] == "p4_qemu_plugin_baseline"), None)
    if qemu_plugin_baseline_passed and qemu_baseline_record:
        records = [row for row in records if row["id"] != "p4_qemu_plugin_baseline"]
        satisfied_conditions.append(qemu_baseline_record)
    if not host_smoke_passed:
        records.append(host_smoke_record)

    target_smoke_record = item(
        item_id="p5_extension_riscv_target_compile_smoke",
        goal_id="P5_synthetic_suite_extension",
        current_status=str(extension_target.get("status") or "MISSING"),
        evidence=[
            "synthetic_extension_target_smoke.json",
            "synthetic_suite_extension_check.json",
            "experiments/linux_behavior/malware_like/extension_plan.json",
        ],
        current_condition=f"compiled={extension_target.get('compiled_candidate_count')}/{extension_target.get('candidate_count')}",
        required_conditions=[
            "Docker linux-behavior target compiler",
            "static RISC-V Linux ELF build for all source-implemented candidates",
            "ELF machine header validation",
        ],
        unblock_criteria=[
            "synthetic_extension_target_smoke.json reports TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED",
            "compiled_candidate_count equals candidate_count",
        ],
        no_substitution_rule="target compile smoke is not execution evidence and is not a 35T gate pass",
    )
    target_smoke_passed = (
        extension_target.get("status") == EXTENSION_TARGET_SMOKE_PASS_STATUS
        and extension_target.get("compiled_candidate_count") == extension_target.get("candidate_count")
    )
    if target_smoke_passed:
        satisfied_conditions.append(target_smoke_record)
    else:
        records.append(target_smoke_record)

    behavior_counts = extension_behavior.get("summary_counts", {}) if isinstance(extension_behavior.get("summary_counts"), dict) else {}
    behavior_checks = extension_behavior.get("checks", {}) if isinstance(extension_behavior.get("checks"), dict) else {}
    behavior_smoke_record = item(
        item_id="p5_extension_host_qemu_behavior_smoke",
        goal_id="P5_synthetic_suite_extension",
        current_status=str(extension_behavior.get("status") or "MISSING"),
        evidence=[
            "synthetic_extension_behavior_smoke.json",
            "synthetic_extension_behavior_smoke.md",
            "synthetic_extension_target_smoke.json",
            "experiments/linux_behavior/malware_like/extension_plan.json",
            "results/experiments/35t/35t-extension-behavior-smoke-20260523/aggregate/synthetic_extension_behavior_smoke_raw.json",
        ],
        current_condition=(
            f"executed_non_network={behavior_counts.get('execution_pass_count')}/"
            f"{behavior_counts.get('executed_candidate_count')}; "
            f"network_skipped={behavior_counts.get('network_skipped_count')}; "
            "host native, host strace, QEMU native, and QEMU strace smoke recorded"
        ),
        required_conditions=[
            "compile extension candidates for host and RISC-V target",
            "execute non-network candidates under host native and QEMU native",
            "record host strace and QEMU guest strace evidence",
            "observe expected guest syscalls for each executed non-network candidate",
            "keep loopback network candidate skipped by default",
        ],
        unblock_criteria=[
            "synthetic_extension_behavior_smoke.json reports HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED",
            "execution_pass_count equals executed_candidate_count for non-network candidates",
            "loopback network candidate remains skipped unless explicitly selected",
        ],
        no_substitution_rule="host/QEMU behavior smoke is not 35T board execution and is not a gate pass",
    )
    behavior_smoke_passed = (
        extension_behavior.get("status") == EXTENSION_BEHAVIOR_SMOKE_PASS_STATUS
        and behavior_counts.get("execution_pass_count") == behavior_counts.get("executed_candidate_count") == 8
        and behavior_counts.get("network_skipped_count") == 1
        and behavior_checks.get("expected_syscalls_observed_for_executed") is True
        and behavior_checks.get("no_35t_execution_claim") is True
    )
    if behavior_smoke_passed:
        satisfied_conditions.append(behavior_smoke_record)
    else:
        records.append(behavior_smoke_record)

    extension_enablement_record = item(
        item_id="p5_extension_35t_enablement_preflight",
        goal_id="P5_synthetic_suite_extension",
        current_status=str(extension_enablement.get("status") or "MISSING"),
        evidence=[
            "extension_35t_enablement_preflight.json",
            "synthetic_extension_target_smoke.json",
            "experiments/linux_behavior/malware_like/extension_plan.json",
            "board/artix7_35t/linux/rvmt_exp_runner.c",
            "docker/litex/build-artix7-linux-images.sh",
            "tools/experiment_35t.py",
        ],
        current_condition=str(
            extension_enablement.get("current_condition")
            or "extension runner/rootfs/CLI enablement preflight is not recorded"
        ),
        required_conditions=[
            "default-disabled extension entries in the 35T runner",
            "rootfs build path compiles extension candidates",
            "experiment CLI can explicitly select non-network extension candidates",
            "dry-run command evidence that does not execute the board",
        ],
        unblock_criteria=[
            "extension_35t_enablement_preflight.json reports EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED",
            "full extension 35T gate run remains separate from this preflight",
        ],
        no_substitution_rule="extension enablement preflight is not a 35T execution or gate pass",
    )
    extension_enablement_passed = extension_enablement.get("status") == EXTENSION_ENABLEMENT_PREFLIGHT_STATUS
    if extension_enablement_passed:
        satisfied_conditions.append(extension_enablement_record)
    else:
        records.append(extension_enablement_record)

    helper_alignment_passed = helper_alignment.get("status") == HELPER_ALIGNMENT_STATUS
    if helper_alignment_passed:
        satisfied_conditions.append(helper_record)
    else:
        records.append(helper_record)

    qemu_build_record = item(
        item_id="p4_qemu_plugin_system_build_load_preflight",
        goal_id="P4_baseline_evaluation",
        current_status=str(qemu_plugin_build.get("status") or "MISSING"),
        evidence=[
            "qemu_plugin_build_preflight.json",
            "advanced_baseline_preflight.json",
        ],
        current_condition=str(qemu_plugin_build.get("current_condition") or "QEMU-plugin build/load preflight is not recorded"),
        required_conditions=[
            "qemu-system-riscv64 with -plugin support",
            "matching qemu-plugin.h",
            "minimal plugin build transcript",
            "plugin load observation",
        ],
        unblock_criteria=[
            "qemu_plugin_build_preflight.json reports QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED",
            "full 13-sample QEMU-plugin baseline remains separate from this preflight",
        ],
        no_substitution_rule="QEMU-plugin build/load preflight is not a 13-sample QEMU-plugin trace baseline",
    )
    qemu_build_passed = qemu_plugin_build.get("status") == QEMU_PLUGIN_BUILD_PREFLIGHT_STATUS
    if qemu_build_passed:
        satisfied_conditions.append(qemu_build_record)
    else:
        records.append(qemu_build_record)

    ebpf_summary_row = summary_baselines.get("ebpf_only", {}) if isinstance(summary_baselines.get("ebpf_only"), dict) else {}
    ebpf_passed = ebpf_summary_row.get("status") == "PASS" and ebpf_summary_row.get("samples_with_evidence") == 13
    ebpf_record = item(
        item_id="p4_ebpf_only_baseline",
        goal_id="P4_baseline_evaluation",
        current_status=str(ebpf_summary_row.get("status") or baseline_status(advanced_preflight, "ebpf_only")),
        evidence=[
            "ebpf_baseline_summary.json",
            "advanced_baseline_preflight.json",
            "baseline_execution_spec_check.json",
            "experiments/linux_behavior/baseline_execution_spec.json",
        ],
        current_condition="13-sample host eBPF/bpftrace baseline recorded"
        if ebpf_passed
        else baseline_reason(advanced_preflight, "ebpf_only"),
        required_conditions=[
            "BPF compiler tooling such as clang/llc",
            "BPF loader or tracer tooling such as bpftrace",
            "mounted writable tracefs or kprobe access",
            "13-sample eBPF-only event and overhead run",
        ],
        unblock_criteria=[
            "advanced_baseline_preflight.json reports ebpf_only READY",
            "ebpf_baseline_summary.json supplies 13/13 sample evidence",
        ],
        no_substitution_rule="host eBPF/bpftrace evidence must not be reported as hardware-only tracing or QEMU-plugin evidence",
    )
    if ebpf_passed:
        satisfied_conditions.append(ebpf_record)
    else:
        records.append(ebpf_record)

    pointer_design_record = item(
        item_id="p3_pointer_snapshot_design_review",
        goal_id="P3_pointer_argument_semantics",
        current_status=str(pointer_design.get("status") or "MISSING"),
        evidence=[
            "pointer_snapshot_design_review.json",
            "pointer_snapshot_design_review.md",
            "experiments/linux_behavior/pointer_snapshot_design_review.json",
            "docs/research/semantic/pointer_snapshot_design_review.md",
            "pointer_snapshot_enablement_gate.json",
        ],
        current_condition=(
            "bounded openat/execve pointer snapshot design, allowlist, limits, default-disabled policy, "
            "guardrails, artifact policy, and non-substitution rules recorded; hardware capture remains disabled"
        ),
        required_conditions=[
            "bounded syscall/argument allowlist",
            "maximum bytes per pointer",
            "default-disabled current policy",
            "safety guardrails and non-substitution rules",
            "measurement gates kept as pre-enable requirements",
        ],
        unblock_criteria=[
            "pointer_snapshot_design_review.json reports POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED",
            "trace profiles keep p2 ARG_MEM disabled and gated",
            "small-capacity 35T profiles keep ARG_MEM disabled",
        ],
        no_substitution_rule="design review is not enabled hardware pointer snapshot evidence",
    )
    pointer_design_checks = pointer_design.get("checks", {}) if isinstance(pointer_design.get("checks"), dict) else {}
    pointer_design_passed = (
        pointer_design.get("status") == POINTER_DESIGN_REVIEW_STATUS
        and pointer_design_checks.get("current_policy_default_disabled") is True
        and pointer_design_checks.get("required_allowlist_present") is True
        and pointer_design_checks.get("small_capacity_profiles_arg_mem_disabled") is True
    )
    if pointer_design_passed:
        satisfied_conditions.append(pointer_design_record)
    else:
        records.append(pointer_design_record)

    raw_escrow_record = item(
        item_id="p6_local_raw_artifact_escrow",
        goal_id="P6_artifact_package",
        current_status=str(raw_escrow.get("status") or "MISSING"),
        evidence=[
            "raw_artifact_escrow.json",
            "raw_artifact_escrow.md",
            "raw_artifact_sanitization.json",
            "results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_escrow_package/payload_manifest.json",
            "results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_escrow_package/access_policy.md",
        ],
        current_condition=(
            f"local escrow payload files={raw_escrow.get('payload_file_count')}; "
            f"bytes={raw_escrow.get('payload_total_bytes')}; public release remains deferred"
        ),
        required_conditions=[
            "copy full raw UART logs and decoded trace JSONL into a local controlled escrow package",
            "record a complete payload manifest with sizes and SHA-256 hashes",
            "record an access policy that keeps public release deferred until approval",
        ],
        unblock_criteria=[
            "raw_artifact_escrow.json reports LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED",
            "payload files in the local escrow package match the recorded hashes",
        ],
        no_substitution_rule="local escrow is not a public raw artifact release and does not remove the P6 full-release condition",
    )
    raw_escrow_checks = raw_escrow.get("checks", {}) if isinstance(raw_escrow.get("checks"), dict) else {}
    raw_escrow_passed = (
        raw_escrow.get("status") == RAW_ARTIFACT_ESCROW_STATUS
        and raw_escrow_checks.get("payload_files_present_and_hashed") is True
        and raw_escrow_checks.get("public_release_deferred") is True
    )
    if raw_escrow_passed:
        satisfied_conditions.append(raw_escrow_record)
    else:
        records.append(raw_escrow_record)

    expected_goal_status = {
        "P3_pointer_argument_semantics": P3_STATUS,
        "P4_baseline_evaluation": P4_STATUS,
        "P5_synthetic_suite_extension": P5_STATUS,
        "P6_artifact_package": P6_STATUS,
    }
    checks = {
        "closure_status_bounded": closure.get("status") == ASSESSMENT_STATUS,
        "traceability_status_bounded": traceability.get("status") == ASSESSMENT_STATUS,
        "p3_status_bounded": p3.get("status") == P3_STATUS,
        "p4_status_bounded": p4.get("status") == P4_STATUS,
        "p5_status_bounded": p5.get("status") == P5_STATUS,
        "p6_status_bounded": p6.get("status") == P6_STATUS,
        "traceability_goal_statuses_match": all(
            trace_goals.get(goal_id, {}).get("status") == status for goal_id, status in expected_goal_status.items()
        ),
        "all_records_have_evidence": all(bool(row["evidence"]) for row in records),
        "all_record_evidence_paths_exist": all(evidence_paths_exist(repo_root, evidence_root, row["evidence"]) for row in records),
        "all_records_have_required_conditions": all(bool(row["required_conditions"]) for row in records),
        "all_records_have_unblock_criteria": all(bool(row["unblock_criteria"]) for row in records),
        "all_records_have_no_substitution_rules": all(bool(row["no_substitution_rule"]) for row in records),
        "satisfied_conditions_have_no_substitution_rules": all(
            bool(row["no_substitution_rule"]) for row in satisfied_conditions
        ),
        "helper_alignment_passed_or_recorded": helper_alignment_passed
        or any(row["id"] == "p3_trusted_helper_or_ebpf_alignment" for row in records),
        "qemu_plugin_build_preflight_passed_or_recorded": qemu_build_passed
        or any(row["id"] == "p4_qemu_plugin_system_build_load_preflight" for row in records),
        "qemu_plugin_baseline_passed_or_recorded": qemu_plugin_baseline_passed
        or any(row["id"] == "p4_qemu_plugin_baseline" for row in records),
        "pointer_snapshot_still_default_disabled": pointer_gate.get("current_policy", {}).get("default_enabled") is False
        if isinstance(pointer_gate.get("current_policy"), dict)
        else False,
        "pointer_snapshot_design_review_passed_or_recorded": pointer_design_passed
        or any(row["id"] == "p3_pointer_snapshot_design_review" for row in records),
        "advanced_baselines_not_silently_passed": baseline_status(advanced_preflight, "ebpf_only") != "PASS"
        and baseline_status(advanced_preflight, "qemu_plugin") != "PASS",
        "ebpf_pass_has_summary_evidence": baseline_status(advanced_preflight, "ebpf_only") != "PASS"
        and (not ebpf_passed or ebpf_summary_row.get("evidence")),
        "baseline_spec_has_blocked_rows": any(
            isinstance(row, dict) and row.get("current_status") in {"BLOCKED_CURRENT_ENVIRONMENT", "DEFERRED"}
            for row in baseline_spec.get("baselines", [])
        )
        if isinstance(baseline_spec.get("baselines"), list)
        else False,
        "extension_sources_no_35t_claim": extension_host.get("checks", {}).get("no_35t_gating_claim") is True
        if isinstance(extension_host.get("checks"), dict)
        else False,
        "raw_artifact_hash_excerpt_ready": raw_sanitization.get("status") == RAW_ARTIFACT_SANITIZATION_STATUS
        and (
            raw_sanitization.get("checks", {}).get("sanitized_excerpts_do_not_expose_scanned_patterns") is True
            if isinstance(raw_sanitization.get("checks"), dict)
            else False
        ),
        "raw_artifact_escrow_passed_or_recorded": raw_escrow_passed
        or any(row["id"] == "p6_local_raw_artifact_escrow" for row in records),
        "host_compile_smoke_passed_or_recorded": host_smoke_passed
        or any(row["id"] == "p5_extension_host_compile_smoke" for row in records),
        "target_compile_smoke_passed_or_recorded": target_smoke_passed
        or any(row["id"] == "p5_extension_riscv_target_compile_smoke" for row in records),
        "extension_behavior_smoke_passed_or_recorded": behavior_smoke_passed
        or any(row["id"] == "p5_extension_host_qemu_behavior_smoke" for row in records),
        "extension_enablement_preflight_passed_or_recorded": extension_enablement_passed
        or any(row["id"] == "p5_extension_35t_enablement_preflight" for row in records),
        "artifact_release_deferred": artifact_readiness.get("status") == "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED"
        and package_manifest.get("status") == "LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED",
    }
    for key, ok in checks.items():
        if not ok:
            failures.append(key)

    return {
        "schema": "rvmt.35t.remaining_external_work.v1",
        "run_id": RUN_ID,
        "status": STATUS if not failures else "FAIL",
        "evidence_root": rel(evidence_root, repo_root),
        "checks": checks,
        "records": records,
        "satisfied_conditions": satisfied_conditions,
        "interpretation": [
            "P3-P6 have external or deferred conditions that are explicitly recorded rather than treated as completed work",
            "current bounded PASS statuses remain valid only under the 35T synthetic prototype claim boundary",
            "each record lists the evidence that explains the current condition and the criteria required before the status can be upgraded",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Remaining External Work: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Records",
        "",
        "| Item | Goal | Current Status | Current Condition | Unblock Criteria |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["records"]:
        criteria = "; ".join(str(item) for item in row.get("unblock_criteria", [])[:2])
        condition = str(row.get("current_condition") or "").replace("|", "\\|")
        lines.append(
            f"| `{row['id']}` | `{row['goal_id']}` | `{row['current_status']}` | {condition} | {criteria} |"
        )
    lines += ["", "## Satisfied Conditions", ""]
    if report.get("satisfied_conditions"):
        for row in report["satisfied_conditions"]:
            condition = str(row.get("current_condition") or "").replace("|", "\\|")
            lines.append(f"- `{row['id']}`: `{row['current_status']}` ({condition})")
    else:
        lines.append("- none")
    lines += ["", "## No-Substitution Rules", ""]
    lines.extend(
        f"- `{row['id']}`: {row['no_substitution_rule']}"
        for row in [*report["records"], *report.get("satisfied_conditions", [])]
    )
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "remaining_external_work.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "remaining_external_work.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_fixture(
    root: Path,
    *,
    missing_ebpf_block: bool = False,
    host_smoke_pass: bool = False,
    helper_alignment_pass: bool = False,
) -> None:
    evidence = root / DEFAULT_EVIDENCE_ROOT
    goals = [
        {"id": "P3_pointer_argument_semantics", "status": P3_STATUS},
        {"id": "P4_baseline_evaluation", "status": P4_STATUS},
        {"id": "P5_synthetic_suite_extension", "status": P5_STATUS},
        {"id": "P6_artifact_package", "status": P6_STATUS},
    ]
    write_json(evidence / "assessment_closure.json", {"schema": "rvmt.35t.assessment_closure.v1", "status": ASSESSMENT_STATUS, "goals": goals})
    write_json(evidence / "assessment_traceability.json", {"schema": "rvmt.35t.assessment_traceability.v1", "status": ASSESSMENT_STATUS, "goals": goals})
    write_json(
        evidence / "pointer_snapshot_enablement_gate.json",
        {
            "schema": "rvmt.35t.pointer_snapshot_enablement_gate.check.v1",
            "status": "POINTER_SNAPSHOT_ENABLEMENT_GATES_RECORDED_NOT_ENABLED",
            "current_policy": {"default_enabled": False},
        },
    )
    write_json(
        evidence / "pointer_semantics_preflight.json",
        {"schema": "rvmt.35t.pointer_semantics_preflight.v1", "current_35t_pointer_semantics": {"hardware_user_pointer_snapshot": "DEFERRED"}},
    )
    write_json(
        evidence / "pointer_snapshot_design_review.json",
        {
            "schema": "rvmt.35t.pointer_snapshot_design_review.check.v1",
            "status": POINTER_DESIGN_REVIEW_STATUS,
            "checks": {
                "current_policy_default_disabled": True,
                "required_allowlist_present": True,
                "small_capacity_profiles_arg_mem_disabled": True,
            },
        },
    )
    (evidence / "pointer_snapshot_design_review.md").write_text("fixture\n", encoding="utf-8")
    write_json(root / "experiments/linux_behavior/pointer_snapshot_design_review.json", {"schema": "fixture"})
    note = root / "docs/research/semantic/pointer_snapshot_design_review.md"
    note.parent.mkdir(parents=True, exist_ok=True)
    note.write_text("fixture\n", encoding="utf-8")
    ebpf_status = "PASS" if missing_ebpf_block else "BLOCKED_CURRENT_ENVIRONMENT"
    write_json(
        evidence / "advanced_baseline_preflight.json",
        {
            "schema": "rvmt.35t.advanced_baseline_preflight.v1",
            "baselines": {
                "ebpf_only": {"status": ebpf_status, "reason": "fixture ebpf"},
                "qemu_plugin": {"status": "BLOCKED_CURRENT_ENVIRONMENT", "reason": "fixture qemu"},
            },
        },
    )
    write_json(evidence / "baseline_execution_spec_check.json", {"schema": "rvmt.35t.baseline_execution_spec.check.v1", "status": "PASS"})
    if not missing_ebpf_block:
        write_json(
            evidence / "baseline_evaluation_summary.json",
            {
                "schema": "rvmt.35t.baseline_evaluation.summary.v1",
                "baselines": {"ebpf_only": {"status": "PASS", "samples_with_evidence": 13, "evidence": "ebpf_baseline_summary.json"}},
            },
        )
        write_json(evidence / "ebpf_baseline_summary.json", {"schema": "rvmt.35t.ebpf_baseline.v1", "status": "PASS"})
    else:
        write_json(
            evidence / "baseline_evaluation_summary.json",
            {
                "schema": "rvmt.35t.baseline_evaluation.summary.v1",
                "baselines": {"ebpf_only": {"status": "READY_NOT_RUN", "samples_with_evidence": 0}},
            },
        )
    write_json(
        root / "experiments/linux_behavior/baseline_execution_spec.json",
        {"schema": "rvmt.35t.baseline_execution_spec.v1", "baselines": [{"current_status": "BLOCKED_CURRENT_ENVIRONMENT"}]},
    )
    write_json(root / "experiments/linux_behavior/pointer_snapshot_enablement_gate.json", {"schema": "fixture"})
    write_json(root / "experiments/linux_behavior/semantic_threat_model.json", {"schema": "fixture"})
    write_json(root / "experiments/linux_behavior/malware_like/extension_plan.json", {"schema": "fixture"})
    write_json(
        evidence / "synthetic_suite_extension_check.json",
        {
            "schema": "rvmt.35t.synthetic_suite_extension.check.v1",
            "candidate_count": 9,
            "implemented_candidate_count": 9,
        },
    )
    write_json(
        evidence / "synthetic_extension_host_smoke.json",
        {
            "schema": "rvmt.35t.synthetic_extension_host_smoke.v1",
            "status": EXTENSION_HOST_SMOKE_PASS_STATUS if host_smoke_pass else "HOST_COMPILE_SMOKE_BLOCKED_CURRENT_ENVIRONMENT",
            "candidate_count": 9,
            "compiled_candidate_count": 9 if host_smoke_pass else 0,
            "checks": {"no_35t_gating_claim": True},
            "host": {"blocked_reasons": [] if host_smoke_pass else ["fixture"]},
        },
    )
    write_json(
        evidence / "synthetic_extension_target_smoke.json",
        {
            "schema": "rvmt.35t.synthetic_extension_target_smoke.v1",
            "status": EXTENSION_TARGET_SMOKE_PASS_STATUS,
            "candidate_count": 9,
            "compiled_candidate_count": 9,
            "checks": {"no_35t_gating_claim": True, "no_execution_attempted": True},
        },
    )
    write_json(
        evidence / "synthetic_extension_behavior_smoke.json",
        {
            "schema": "rvmt.35t.synthetic_extension_behavior_smoke.v1",
            "status": EXTENSION_BEHAVIOR_SMOKE_PASS_STATUS,
            "summary_counts": {
                "candidate_count": 9,
                "compile_pass_count": 9,
                "executed_candidate_count": 8,
                "execution_pass_count": 8,
                "network_skipped_count": 1,
            },
            "checks": {
                "expected_syscalls_observed_for_executed": True,
                "no_35t_execution_claim": True,
                "no_expanded_35t_coverage_claim": True,
            },
        },
    )
    (evidence / "synthetic_extension_behavior_smoke.md").write_text("fixture\n", encoding="utf-8")
    write_json(
        root / "results/experiments/35t/35t-extension-behavior-smoke-20260523/aggregate/synthetic_extension_behavior_smoke_raw.json",
        {"schema": "fixture"},
    )
    write_json(
        evidence / "extension_35t_enablement_preflight.json",
        {
            "schema": "rvmt.35t.extension_35t_enablement_preflight.v1",
            "status": EXTENSION_ENABLEMENT_PREFLIGHT_STATUS,
            "current_condition": "fixture extension runner/rootfs/CLI enablement preflight",
        },
    )
    write_json(
        evidence / "raw_artifact_sanitization.json",
        {
            "schema": "rvmt.35t.raw_artifact_sanitization.v1",
            "status": RAW_ARTIFACT_SANITIZATION_STATUS,
            "checks": {"sanitized_excerpts_do_not_expose_scanned_patterns": True},
        },
    )
    (evidence / "raw_artifact_sanitization.md").write_text("fixture\n", encoding="utf-8")
    write_json(
        evidence / "raw_artifact_escrow.json",
        {
            "schema": "rvmt.35t.raw_artifact_escrow.v1",
            "status": RAW_ARTIFACT_ESCROW_STATUS,
            "payload_file_count": 14,
            "payload_total_bytes": 1024,
            "checks": {"payload_files_present_and_hashed": True, "public_release_deferred": True},
        },
    )
    (evidence / "raw_artifact_escrow.md").write_text("fixture\n", encoding="utf-8")
    raw_escrow = root / "results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_escrow_package"
    write_json(raw_escrow / "payload_manifest.json", {"schema": "fixture"})
    (raw_escrow / "access_policy.md").write_text("fixture\n", encoding="utf-8")
    write_json(
        evidence / "artifact_package_readiness.json",
        {"schema": "rvmt.35t.artifact_package_readiness.v1", "status": "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED", "local_only_classes": ["raw_uart_log"]},
    )
    write_json(
        evidence / "paper_artifact_package_manifest.json",
        {
            "schema": "rvmt.35t.paper_artifact_package_manifest.v1",
            "status": "LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED",
            "release_policy": {"local_only_classes": ["raw_uart_log"]},
        },
    )
    write_json(evidence / "paper_artifact_release_policy.json", {"schema": "rvmt.35t.paper_artifact_release_policy.v1"})
    write_json(evidence / "evidence_manifest.json", {"schema": "rvmt.35t.evidence_snapshot.v1"})
    write_json(evidence / "threat_model_boundary.json", {"schema": "rvmt.35t.threat_model_boundary.v1"})
    if helper_alignment_pass:
        write_json(
            evidence / "helper_alignment.json",
            {
                "schema": "rvmt.35t.helper_alignment.v1",
                "status": HELPER_ALIGNMENT_STATUS,
                "current_condition": "fixture helper alignment",
            },
        )
        write_json(evidence / "board_syscall_side_channel_smoke.json", {"schema": "fixture"})
        bundle = root / "results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle"
        write_json(bundle / "bundle_manifest.json", {"schema": "fixture"})
    write_json(
        evidence / "qemu_plugin_build_preflight.json",
        {
            "schema": "rvmt.35t.qemu_plugin_build_preflight.v1",
            "status": QEMU_PLUGIN_BUILD_PREFLIGHT_STATUS,
            "current_condition": "fixture qemu-system plugin build/load preflight",
        },
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != STATUS:
            print("[FAIL] expected remaining external work fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "remaining_external_work.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, missing_ebpf_block=True)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL" or "advanced_baselines_not_silently_passed" not in report["failures"]:
            print("[FAIL] expected silent eBPF PASS fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, host_smoke_pass=True)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        remaining_ids = {row["id"] for row in report["records"]}
        satisfied_ids = {row["id"] for row in report["satisfied_conditions"]}
        if (
            report["status"] != STATUS
            or "p5_extension_host_compile_smoke" in remaining_ids
            or "p5_extension_host_compile_smoke" not in satisfied_ids
        ):
            print("[FAIL] expected passed host-smoke fixture to move into satisfied conditions", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, helper_alignment_pass=True)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        remaining_ids = {row["id"] for row in report["records"]}
        satisfied_ids = {row["id"] for row in report["satisfied_conditions"]}
        if (
            report["status"] != STATUS
            or "p3_trusted_helper_or_ebpf_alignment" in remaining_ids
            or "p3_trusted_helper_or_ebpf_alignment" not in satisfied_ids
        ):
            print("[FAIL] expected passed helper alignment fixture to move into satisfied conditions", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T remaining external work self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record and verify remaining external work for bounded 35T P3-P6 goals.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.evidence_root)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_remaining_external_work: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T remaining external work")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
