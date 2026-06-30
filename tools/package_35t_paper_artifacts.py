from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    repo_path,
    write_json,
)


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_OUT_DIR = DEFAULT_RESULTS_ROOT / "paper_artifact_package"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
READINESS_SCHEMA = "rvmt.35t.artifact_package_readiness.v1"
READINESS_STATUS = "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED"
PACKAGE_STATUS = "LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]
GENERATED_NAMES = (
    "README.md",
    "package_manifest.json",
    "package_manifest.md",
    "release_policy.json",
    "release_policy.md",
    "hash_manifest.json",
    "hash_manifest.md",
    "reproduction_commands.md",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def artifact_classes(readiness: dict[str, Any]) -> list[dict[str, Any]]:
    rows = readiness.get("artifact_classes", [])
    return [row for row in rows if isinstance(row, dict)]


def release_decision(row: dict[str, Any]) -> dict[str, Any]:
    policy = str(row.get("public_policy") or "")
    if policy == "public":
        release_mode = "include_or_reference"
        release_action = "may be included directly in a public lightweight artifact package"
    elif policy in {"public_summary", "public_or_summary", "public_hashes", "public_summary_no_bitstream_binary"}:
        release_mode = "summary_or_hash_only"
        release_action = "publish summaries, class digests, representative hashes, and paths; do not require raw payload release"
    else:
        release_mode = "local_only_or_sanitized_excerpt"
        release_action = "keep local by default; publish only after sanitization or explicit controlled-release approval"
    return {
        "artifact_id": row.get("artifact_id"),
        "description": row.get("description"),
        "status": row.get("status"),
        "count": row.get("count"),
        "total_bytes": row.get("total_bytes"),
        "class_digest": row.get("class_digest"),
        "public_policy": policy,
        "release_mode": release_mode,
        "release_action": release_action,
    }


def build_release_policy(readiness: dict[str, Any]) -> dict[str, Any]:
    rows = [release_decision(row) for row in artifact_classes(readiness)]
    return {
        "schema": "rvmt.35t.paper_artifact_release_policy.v1",
        "run_id": RUN_ID,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "generated_utc": utc_now(),
        "status": "PASS",
        "classes": rows,
        "local_only_classes": [row["artifact_id"] for row in rows if row["release_mode"] == "local_only_or_sanitized_excerpt"],
        "summary_or_hash_classes": [row["artifact_id"] for row in rows if row["release_mode"] == "summary_or_hash_only"],
        "public_classes": [row["artifact_id"] for row in rows if row["release_mode"] == "include_or_reference"],
        "non_claims": NON_CLAIMS,
    }


def build_hash_manifest(readiness: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for row in artifact_classes(readiness):
        rows.append(
            {
                "artifact_id": row.get("artifact_id"),
                "count": row.get("count"),
                "total_bytes": row.get("total_bytes"),
                "class_digest": row.get("class_digest"),
                "public_policy": row.get("public_policy"),
                "representative_files": row.get("representative_files", []),
            }
        )
    return {
        "schema": "rvmt.35t.paper_artifact_hash_manifest.v1",
        "run_id": RUN_ID,
        "generated_utc": utc_now(),
        "classes": rows,
    }


def validation_commands() -> list[str]:
    return [
        "uv run --no-sync python tools/check_35t_application_closure.py --repo-root . --no-write",
        "uv run --no-sync python tools/check_35t_paper_evidence.py --no-write",
        "uv run --no-sync python tools/check_35t_fd_path_case_studies.py --no-write",
        "uv run --no-sync python tools/check_35t_process_tree_case_study.py --no-write",
        "uv run --no-sync python tools/check_35t_metric_coverage.py --no-write",
        "uv run --no-sync python tools/check_35t_pointer_snapshot_design_review.py --no-write",
        "uv run --no-sync python tools/check_35t_pointer_semantics_preflight.py --no-write",
        "uv run --no-sync python tools/check_35t_pointer_snapshot_gate.py --no-write",
        "uv run --no-sync python tools/check_35t_threat_model.py --no-write",
        "uv run --no-sync python tools/check_35t_helper_alignment.py --no-write",
        "uv run --no-sync python tools/check_35t_evaluation_table.py --no-write",
        "uv run --no-sync python tools/check_35t_baseline_evaluation.py --no-write",
        "uv run --no-sync python tools/check_35t_baseline_execution_spec.py --no-write",
        "uv run --no-sync python tools/check_35t_qemu_plugin_build_preflight.py --self-test",
        "uv run --no-sync python tools/run_35t_qemu_plugin_baseline.py --self-test",
        "uv run --no-sync python tools/run_35t_ebpf_baseline.py --self-test",
        "uv run --no-sync python tools/check_35t_synthetic_suite_extension.py --no-write",
        "uv run --no-sync python tools/check_35t_synthetic_extension_host_smoke.py --no-write",
        "uv run --no-sync python tools/check_35t_synthetic_extension_target_smoke.py --no-write",
        "uv run --no-sync python tools/check_35t_synthetic_extension_behavior_smoke.py --no-write",
        "uv run --no-sync python tools/check_35t_extension_35t_enablement.py --no-write",
        "uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --no-write",
        "uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --no-write",
        "uv run --no-sync python tools/check_35t_artifact_package_readiness.py --no-write",
        "uv run --no-sync python tools/check_35t_assessment_closure.py --no-write",
        "uv run --no-sync python tools/check_35t_assessment_traceability.py --no-write",
        "uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --no-write",
        "uv run --no-sync python tools/check_35t_remaining_external_work.py --no-write",
        "uv run --no-sync python tools/check_35t_paper_positioning.py --no-write",
        "uv run --no-sync python tools/check_35t_assessment_reconciliation.py --no-write",
        "uv run --no-sync python tools/check_35t_assessment_gate_criteria.py --no-write",
        "uv run --no-sync python tools/check_35t_hardware_trace_prototype.py --no-write",
        "uv run --no-sync python tools/check_35t_local_code_analysis.py --no-write",
        "uv run --no-sync python tools/check_35t_malware_behavior_audit.py --no-write",
        "uv run --no-sync python tools/check_35t_evidence_consistency.py --no-write",
    ]


def reproduction_commands() -> list[str]:
    return [
        "uv run --no-sync python tools/check_35t_fd_path_case_studies.py --repo-root .",
        "uv run --no-sync python tools/check_35t_process_tree_case_study.py --repo-root .",
        "uv run --no-sync python tools/check_35t_metric_coverage.py --repo-root .",
        "uv run --no-sync python tools/check_35t_pointer_snapshot_design_review.py --repo-root .",
        "uv run --no-sync python tools/check_35t_pointer_semantics_preflight.py --repo-root .",
        "uv run --no-sync python tools/check_35t_pointer_snapshot_gate.py --repo-root .",
        "uv run --no-sync python tools/check_35t_threat_model.py --repo-root .",
        "uv run --no-sync python tools/check_35t_helper_alignment.py --repo-root .",
        "uv run --no-sync python tools/check_35t_evaluation_table.py --repo-root .",
        "uv run --no-sync python tools/check_35t_baseline_execution_spec.py --repo-root .",
        "uv run --no-sync python tools/check_35t_qemu_plugin_build_preflight.py --repo-root .",
        "uv run --no-sync python tools/run_35t_qemu_plugin_baseline.py --repo-root . --reps 3",
        "uv run --no-sync python tools/run_35t_ebpf_baseline.py --reps 3",
        "uv run --no-sync python tools/check_35t_synthetic_suite_extension.py --repo-root .",
        "uv run --no-sync python tools/check_35t_synthetic_extension_host_smoke.py --repo-root .",
        "uv run --no-sync python tools/check_35t_synthetic_extension_target_smoke.py --repo-root .",
        "uv run --no-sync python tools/check_35t_synthetic_extension_behavior_smoke.py --repo-root .",
        "uv run --no-sync python tools/check_35t_extension_35t_enablement.py --repo-root .",
        "uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --repo-root .",
        "uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --repo-root .",
        "uv run --no-sync python tools/check_35t_artifact_package_readiness.py --repo-root .",
        "uv run --no-sync python tools/package_35t_paper_artifacts.py --repo-root .",
        "uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .",
        "uv run --no-sync python tools/check_35t_assessment_traceability.py --repo-root .",
        "uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --repo-root .",
        "uv run --no-sync python tools/check_35t_remaining_external_work.py --repo-root .",
        "uv run --no-sync python tools/check_35t_paper_positioning.py --repo-root .",
        "uv run --no-sync python tools/check_35t_assessment_reconciliation.py --repo-root .",
        "uv run --no-sync python tools/check_35t_assessment_gate_criteria.py --repo-root .",
        "uv run --no-sync python tools/check_35t_hardware_trace_prototype.py --repo-root .",
        "uv run --no-sync python tools/check_35t_local_code_analysis.py --repo-root .",
        "uv run --no-sync python tools/check_35t_malware_behavior_audit.py --repo-root .",
        "uv run --no-sync python tools/check_35t_evidence_consistency.py --repo-root .",
    ]


def lightweight_evidence_files(evidence_root: Path) -> list[Path]:
    names = (
        "README.md",
        "evidence_manifest.json",
        "assessment_closure.json",
        "assessment_closure.md",
        "assessment_traceability.json",
        "assessment_traceability.md",
        "assessment_requirement_matrix.json",
        "assessment_requirement_matrix.md",
        "assessment_reconciliation.json",
        "assessment_reconciliation.md",
        "assessment_gate_criteria.json",
        "assessment_gate_criteria.md",
        "hardware_trace_prototype.json",
        "hardware_trace_prototype.md",
        "local_code_analysis.json",
        "local_code_analysis.md",
        "malware_behavior_audit.json",
        "malware_behavior_audit.md",
        "remaining_external_work.json",
        "remaining_external_work.md",
        "paper_positioning.json",
        "paper_positioning.md",
        "paper_evidence_check.json",
        "paper_evidence_check.md",
        "fd_path_case_studies.json",
        "fd_path_case_studies.md",
        "process_tree_case_study.json",
        "process_tree_case_study.md",
        "metric_coverage.json",
        "metric_coverage.md",
        "pointer_snapshot_design_review.json",
        "pointer_snapshot_design_review.md",
        "pointer_semantics_preflight.json",
        "pointer_semantics_preflight.md",
        "pointer_snapshot_enablement_gate.json",
        "pointer_snapshot_enablement_gate.md",
        "threat_model_boundary.json",
        "threat_model_boundary.md",
        "helper_alignment.json",
        "helper_alignment.md",
        "baseline_evaluation_summary.json",
        "baseline_evaluation_summary.md",
        "baseline_evaluation_check.json",
        "baseline_evaluation_check.md",
        "baseline_execution_spec_check.json",
        "baseline_execution_spec_check.md",
        "ebpf_baseline_summary.json",
        "ebpf_baseline_summary.md",
        "evaluation_table.json",
        "evaluation_table.md",
        "advanced_baseline_preflight.json",
        "advanced_baseline_preflight.md",
        "qemu_plugin_build_preflight.json",
        "qemu_plugin_build_preflight.md",
        "qemu_plugin_baseline_summary.json",
        "qemu_plugin_baseline_summary.md",
        "artifact_package_readiness.json",
        "artifact_package_readiness.md",
        "synthetic_suite_extension_check.json",
        "synthetic_suite_extension_check.md",
        "synthetic_extension_host_smoke.json",
        "synthetic_extension_host_smoke.md",
        "synthetic_extension_target_smoke.json",
        "synthetic_extension_target_smoke.md",
        "synthetic_extension_behavior_smoke.json",
        "synthetic_extension_behavior_smoke.md",
        "extension_35t_enablement_preflight.json",
        "extension_35t_enablement_preflight.md",
        "raw_artifact_sanitization.json",
        "raw_artifact_sanitization.md",
        "raw_artifact_escrow.json",
        "raw_artifact_escrow.md",
        "software_instrumentation_baseline_summary.json",
        "software_instrumentation_baseline_summary.md",
        "command_log.md",
    )
    return [evidence_root / name for name in names if (evidence_root / name).is_file()]


def build_package_manifest(
    repo_root: Path,
    out_dir: Path,
    evidence_root: Path,
    readiness_path: Path,
    readiness: dict[str, Any],
    release_policy: dict[str, Any],
    hash_manifest: dict[str, Any],
) -> dict[str, Any]:
    readiness_ok = readiness.get("schema") == READINESS_SCHEMA and readiness.get("status") == READINESS_STATUS
    public_files = lightweight_evidence_files(evidence_root)
    return {
        "schema": "rvmt.35t.paper_artifact_package_manifest.v1",
        "run_id": RUN_ID,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "generated_utc": utc_now(),
        "status": PACKAGE_STATUS if readiness_ok else "INCOMPLETE",
        "package_dir": rel(out_dir, repo_root),
        "readiness": {
            "path": rel(readiness_path, repo_root),
            "schema": readiness.get("schema"),
            "status": readiness.get("status"),
            "class_count": readiness.get("class_count"),
            "missing_classes": readiness.get("missing_classes", []),
        },
        "generated_files": [rel(out_dir / name, repo_root) for name in GENERATED_NAMES],
        "lightweight_evidence_files": [rel(path, repo_root) for path in public_files],
        "release_policy": {
            "status": release_policy.get("status"),
            "public_classes": release_policy.get("public_classes", []),
            "summary_or_hash_classes": release_policy.get("summary_or_hash_classes", []),
            "local_only_classes": release_policy.get("local_only_classes", []),
        },
        "hash_manifest_class_count": len(hash_manifest.get("classes", [])),
        "validation_commands": validation_commands(),
        "reproduction_commands": reproduction_commands(),
        "non_claims": NON_CLAIMS,
    }


def render_release_policy(policy: dict[str, Any]) -> str:
    lines = [
        f"# 35T Paper Artifact Release Policy: {policy['run_id']}",
        "",
        f"Status: {policy['status']}",
        "",
        "| Class | Release Mode | Count | Action |",
        "| --- | --- | ---: | --- |",
    ]
    for row in policy["classes"]:
        lines.append(
            f"| `{row['artifact_id']}` | `{row['release_mode']}` | {row.get('count')} | {row['release_action']} |"
        )
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in policy["non_claims"])
    return "\n".join(lines) + "\n"


def render_hash_manifest(manifest: dict[str, Any]) -> str:
    lines = [
        f"# 35T Paper Artifact Hash Manifest: {manifest['run_id']}",
        "",
        "| Class | Count | Bytes | Class Digest | Policy |",
        "| --- | ---: | ---: | --- | --- |",
    ]
    for row in manifest["classes"]:
        lines.append(
            "| `{artifact_id}` | {count} | {bytes} | `{digest}` | `{policy}` |".format(
                artifact_id=row.get("artifact_id"),
                count=row.get("count"),
                bytes=row.get("total_bytes"),
                digest=row.get("class_digest"),
                policy=row.get("public_policy"),
            )
        )
    return "\n".join(lines) + "\n"


def render_reproduction(commands: list[str]) -> str:
    lines = [
        "# 35T Paper Artifact Reproduction Commands",
        "",
        "Run from the repository root.",
        "",
    ]
    for command in commands:
        lines += ["```powershell", command, "```", ""]
    return "\n".join(lines)


def render_readme(manifest: dict[str, Any]) -> str:
    lines = [
        f"# RV-MalTrace 35T Paper Artifact Package: {manifest['run_id']}",
        "",
        f"Status: {manifest['status']}",
        "",
        f"Scope: {manifest['scope']}.",
        "",
        f"Claim level: {manifest['claim_level']}.",
        "",
        "This is a lightweight release-candidate package. It includes manifests, release policy, hashes, and reproduction commands. It does not copy raw UART logs, decoded trace JSONL, generated bitstreams, board build directories, or ELF binaries.",
        "",
        "## Generated Files",
        "",
    ]
    lines.extend(f"- `{path}`" for path in manifest["generated_files"])
    lines += ["", "## Validation Commands", ""]
    lines.extend(f"- `{command}`" for command in manifest["validation_commands"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in manifest["non_claims"])
    return "\n".join(lines) + "\n"


def render_package_manifest(manifest: dict[str, Any]) -> str:
    lines = [
        f"# 35T Paper Artifact Package Manifest: {manifest['run_id']}",
        "",
        f"Status: {manifest['status']}",
        "",
        f"Package dir: `{manifest['package_dir']}`",
        "",
        f"Readiness: `{manifest['readiness']['status']}` from `{manifest['readiness']['path']}`",
        "",
        "## Release Policy Summary",
        "",
        f"- public classes: {len(manifest['release_policy']['public_classes'])}",
        f"- summary/hash classes: {len(manifest['release_policy']['summary_or_hash_classes'])}",
        f"- local-only classes: {len(manifest['release_policy']['local_only_classes'])}",
        "",
        "## Validation Commands",
        "",
    ]
    lines.extend(f"- `{command}`" for command in manifest["validation_commands"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in manifest["non_claims"])
    return "\n".join(lines) + "\n"


def clear_known_outputs(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in GENERATED_NAMES:
        path = out_dir / name
        if path.exists():
            path.unlink()


def copy_evidence_summary_files(repo_root: Path, evidence_root: Path, out_dir: Path) -> list[str]:
    dest_dir = out_dir / "lightweight_evidence"
    dest_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for source in lightweight_evidence_files(evidence_root):
        dest = dest_dir / source.name
        shutil.copyfile(source, dest)
        copied.append(rel(dest, repo_root))
    return copied


def package_artifacts(repo_root: Path, readiness_path_arg: Path, evidence_root_arg: Path, out_dir_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    readiness_path = repo_path(repo_root, readiness_path_arg).resolve()
    out_dir = repo_path(repo_root, out_dir_arg).resolve()
    readiness = load_json(readiness_path)
    release_policy = build_release_policy(readiness)
    hash_manifest = build_hash_manifest(readiness)
    manifest = build_package_manifest(repo_root, out_dir, evidence_root, readiness_path, readiness, release_policy, hash_manifest)

    clear_known_outputs(out_dir)
    write_json(out_dir / "release_policy.json", release_policy)
    (out_dir / "release_policy.md").write_text(render_release_policy(release_policy), encoding="utf-8", newline="\n")
    write_json(out_dir / "hash_manifest.json", hash_manifest)
    (out_dir / "hash_manifest.md").write_text(render_hash_manifest(hash_manifest), encoding="utf-8", newline="\n")
    (out_dir / "reproduction_commands.md").write_text(
        render_reproduction(manifest["reproduction_commands"]),
        encoding="utf-8",
        newline="\n",
    )
    (out_dir / "README.md").write_text(render_readme(manifest), encoding="utf-8", newline="\n")
    copied = copy_evidence_summary_files(repo_root, evidence_root, out_dir)
    manifest["copied_lightweight_evidence_files"] = copied
    write_json(out_dir / "package_manifest.json", manifest)
    (out_dir / "package_manifest.md").write_text(render_package_manifest(manifest), encoding="utf-8", newline="\n")

    write_json(evidence_root / "paper_artifact_package_manifest.json", manifest)
    (evidence_root / "paper_artifact_package_manifest.md").write_text(
        render_package_manifest(manifest),
        encoding="utf-8",
        newline="\n",
    )
    write_json(evidence_root / "paper_artifact_release_policy.json", release_policy)
    (evidence_root / "paper_artifact_release_policy.md").write_text(
        render_release_policy(release_policy),
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def write_readiness_fixture(path: Path) -> None:
    classes = [
        {
            "artifact_id": "run_config",
            "description": "fixture public",
            "status": "READY_PUBLIC",
            "public_policy": "public",
            "count": 1,
            "total_bytes": 1,
            "class_digest": "a",
            "representative_files": [],
        },
        {
            "artifact_id": "raw_uart_log",
            "description": "fixture local",
            "status": "READY_LOCAL_ONLY",
            "public_policy": "local_only_raw_or_sanitized_excerpt",
            "count": 1,
            "total_bytes": 2,
            "class_digest": "b",
            "representative_files": [],
        },
        {
            "artifact_id": "elf_hashes",
            "description": "fixture hashes",
            "status": "READY_PUBLIC_SUMMARY_OR_HASH",
            "public_policy": "public_hashes",
            "count": 13,
            "total_bytes": 3,
            "class_digest": "c",
            "representative_files": [],
        },
    ]
    write_json(
        path,
        {
            "schema": READINESS_SCHEMA,
            "run_id": RUN_ID,
            "status": READINESS_STATUS,
            "class_count": len(classes),
            "missing_classes": [],
            "artifact_classes": classes,
        },
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        readiness = evidence / "artifact_package_readiness.json"
        write_readiness_fixture(readiness)
        for name in ["README.md", "evidence_manifest.json", "command_log.md"]:
            (evidence / name).parent.mkdir(parents=True, exist_ok=True)
            (evidence / name).write_text("fixture\n", encoding="utf-8")
        manifest = package_artifacts(root, DEFAULT_EVIDENCE_ROOT / "artifact_package_readiness.json", DEFAULT_EVIDENCE_ROOT, DEFAULT_OUT_DIR)
        if manifest["status"] != PACKAGE_STATUS:
            print("[FAIL] expected fixture package manifest to pass", file=sys.stderr)
            return 1
        if not (root / DEFAULT_OUT_DIR / "release_policy.md").exists():
            print("[FAIL] missing generated release policy", file=sys.stderr)
            return 1
        if not (evidence / "paper_artifact_package_manifest.json").exists():
            print("[FAIL] missing evidence package manifest", file=sys.stderr)
            return 1
    print("[PASS] 35T paper artifact packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a lightweight 35T paper artifact package candidate.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--readiness", type=Path, default=DEFAULT_EVIDENCE_ROOT / "artifact_package_readiness.json")
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        manifest = package_artifacts(args.repo_root, args.readiness, args.evidence_root, args.out_dir)
    except Exception as exc:
        print(f"package_35t_paper_artifacts: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{manifest['status']}] 35T paper artifact package at {manifest['package_dir']}")
    return 0 if manifest["status"] == PACKAGE_STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
