from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
SEMANTIC_RUN_ID = "35t-targeted-board-validation-20260522"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_SEMANTIC_RESULTS_ROOT = Path("results/experiments/35t") / SEMANTIC_RUN_ID
DEFAULT_BUNDLE_ROOT = DEFAULT_SEMANTIC_RESULTS_ROOT / "board_validation_bundle"
SCHEMA = "rvmt.35t.helper_alignment.v1"
STATUS = "TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL"
BOARD_SMOKE_STATUS = "STRICT_BOARD_VALIDATION_PASS_AFTER_SIDE_CHANNEL_BOOT"
THREAT_MODEL_STATUS = "TRUSTED_KERNEL_USER_MODE_THREAT_MODEL_BOUNDARY_SPECIFIED"
CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
SCOPE = "Artix-7 35T / LiteX / VexRiscv"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


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


def final_smoke(smoke: dict[str, Any]) -> dict[str, Any]:
    rows = smoke.get("smoke_runs", [])
    if not isinstance(rows, list):
        return {}
    pass_rows = [
        row
        for row in rows
        if isinstance(row, dict) and row.get("status") == "SIDE_CHANNEL_SMOKE_PASS"
    ]
    return pass_rows[-1] if pass_rows else {}


def selected_sources(fd_cases: dict[str, Any], process_case: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    samples = fd_cases.get("samples", {})
    if isinstance(samples, dict):
        for sample, payload in sorted(samples.items()):
            if not isinstance(payload, dict):
                continue
            selected = payload.get("selected_candidate", {})
            if not isinstance(selected, dict):
                continue
            rows.append(
                {
                    "sample": str(sample),
                    "source": str(selected.get("source") or ""),
                    "source_type": str(selected.get("source_type") or ""),
                }
            )
    case_study = process_case.get("case_study", {})
    selected = case_study.get("selected_candidate", {}) if isinstance(case_study, dict) else {}
    if isinstance(selected, dict):
        rows.append(
            {
                "sample": str(process_case.get("sample") or "process_chain"),
                "source": str(selected.get("source") or ""),
                "source_type": str(selected.get("source_type") or ""),
            }
        )
    return rows


def side_channel_row(repo_root: Path, source: dict[str, str]) -> dict[str, Any]:
    path = repo_path(repo_root, Path(source["source"])) if source.get("source") else Path()
    payload: dict[str, Any] = {}
    errors: list[str] = []
    if not source.get("source"):
        errors.append("missing source path")
    elif not path.is_file():
        errors.append(f"missing source file: {rel(path, repo_root)}")
    else:
        try:
            payload = load_json(path)
        except Exception as exc:
            errors.append(f"invalid source file: {rel(path, repo_root)}: {exc}")
    events = payload.get("events", []) if isinstance(payload.get("events"), list) else []
    return {
        "sample": source.get("sample"),
        "source": source.get("source"),
        "source_type": source.get("source_type"),
        "exists": path.is_file() if source.get("source") else False,
        "schema": payload.get("schema"),
        "event_count": len(events),
        "has_events": bool(events),
        "errors": errors,
    }


def build_report(repo_root: Path, evidence_root_arg: Path, semantic_results_arg: Path, bundle_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    semantic_results_root = repo_path(repo_root, semantic_results_arg).resolve()
    bundle_root = repo_path(repo_root, bundle_root_arg).resolve()
    failures: list[str] = []

    board_smoke = read_json(evidence_root / "board_syscall_side_channel_smoke.json", failures, repo_root, "board syscall side-channel smoke")
    bundle = read_json(bundle_root / "bundle_manifest.json", failures, repo_root, "board validation bundle manifest")
    fd_cases = read_json(evidence_root / "fd_path_case_studies.json", failures, repo_root, "fd/path case studies")
    process_case = read_json(evidence_root / "process_tree_case_study.json", failures, repo_root, "process-tree case study")
    threat_model = read_json(evidence_root / "threat_model_boundary.json", failures, repo_root, "threat model boundary")

    smoke = final_smoke(board_smoke)
    strict = board_smoke.get("strict_validation_follow_up", {})
    strict = strict if isinstance(strict, dict) else {}
    selected = selected_sources(fd_cases, process_case)
    side_channel_sources = [side_channel_row(repo_root, source) for source in selected]
    bundle_statuses = bundle.get("selected_statuses", {}) if isinstance(bundle.get("selected_statuses"), dict) else {}
    threat_routes = threat_model.get("routes", {}) if isinstance(threat_model.get("routes"), dict) else {}
    helper_route = threat_routes.get("kernel_helper_metadata", {}) if isinstance(threat_routes.get("kernel_helper_metadata"), dict) else {}
    ebpf_route = threat_routes.get("ebpf_metadata_alignment", {}) if isinstance(threat_routes.get("ebpf_metadata_alignment"), dict) else {}

    checks = {
        "board_smoke_schema": board_smoke.get("schema") == "rvmt.35t.board_syscall_side_channel_smoke.v1",
        "board_smoke_status": board_smoke.get("status") == BOARD_SMOKE_STATUS,
        "board_smoke_hardware_validated": board_smoke.get("hardware_validated") is True,
        "final_smoke_pass": smoke.get("status") == "SIDE_CHANNEL_SMOKE_PASS",
        "final_smoke_side_channel_files": int(smoke.get("syscall_side_channel_files") or 0) >= 2,
        "strict_follow_up_pass": strict.get("status") == "PASS",
        "strict_fd_path_pass": strict.get("fd_path_flow") == "PASS",
        "strict_process_tree_pass": strict.get("process_tree") == "PASS",
        "strict_source_attribution_partial_recorded": strict.get("source_attribution") == "PARTIAL",
        "bundle_schema": bundle.get("schema") == "rvmt.35t.board_validation_bundle.v1",
        "bundle_status_pass": bundle.get("status") == "PASS",
        "bundle_checker_pass": bundle.get("checker_status") == "PASS",
        "bundle_hardware_validated": bundle.get("hardware_validated") is True,
        "bundle_dual_channel": bundle.get("validation_mode") == "dual_channel",
        "bundle_trace_gate_run_id": bundle.get("trace_gate_run_id") == RUN_ID,
        "bundle_semantic_run_id": bundle.get("semantic_run_id") == SEMANTIC_RUN_ID,
        "bundle_fd_path_pass": bundle_statuses.get("fd_path_flow") == "PASS",
        "bundle_process_tree_pass": bundle_statuses.get("process_tree") == "PASS",
        "bundle_source_attribution_partial": bundle_statuses.get("source_attribution") == "PARTIAL",
        "fd_path_case_studies_pass": fd_cases.get("status") == "PASS",
        "process_tree_case_study_pass": process_case.get("status") == "PASS",
        "selected_sources_from_side_channel": bool(selected) and all(row.get("source_type") == "syscall_side_channel" for row in selected),
        "selected_sources_exist_and_have_events": bool(side_channel_sources) and all(row["exists"] and row["has_events"] for row in side_channel_sources),
        "semantic_results_root_exists": semantic_results_root.is_dir(),
        "threat_model_schema": threat_model.get("schema") == "rvmt.35t.threat_model_boundary.v1",
        "threat_model_status": threat_model.get("status") == THREAT_MODEL_STATUS,
        "trusted_kernel_boundary": "linux_kernel" in set(threat_model.get("trusted_components", []))
        if isinstance(threat_model.get("trusted_components"), list)
        else False,
        "user_mode_scope": "user_mode_malware_like_workload" in set(threat_model.get("in_scope", []))
        if isinstance(threat_model.get("in_scope"), list)
        else False,
        "kernel_rootkit_out_of_scope": "kernel_rootkit" in set(threat_model.get("out_of_scope", []))
        if isinstance(threat_model.get("out_of_scope"), list)
        else False,
        "helper_route_recorded": helper_route.get("status") == "OPTIONAL_DEFERRED_COMPANION",
        "ebpf_route_recorded": ebpf_route.get("status") == "OPTIONAL_DEFERRED_COMPANION",
    }
    for key, ok in checks.items():
        if not ok:
            failures.append(key)
    for row in side_channel_sources:
        failures.extend(row.get("errors", []))

    status = STATUS if not failures else "FAIL"
    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "semantic_run_id": SEMANTIC_RUN_ID,
        "generated_utc": utc_now(),
        "status": status,
        "scope": SCOPE,
        "claim_level": CLAIM_LEVEL,
        "evidence_root": rel(evidence_root, repo_root),
        "semantic_results_root": rel(semantic_results_root, repo_root),
        "bundle_root": rel(bundle_root, repo_root),
        "satisfied_condition_id": "p3_trusted_helper_or_ebpf_alignment",
        "alignment_route": "trusted_linux_kernel_syscall_side_channel_dual_channel",
        "checks": checks,
        "selected_side_channel_sources": side_channel_sources,
        "evidence_files": [
            "board_syscall_side_channel_smoke.json",
            "fd_path_case_studies.json",
            "process_tree_case_study.json",
            "threat_model_boundary.json",
            rel(bundle_root / "bundle_manifest.json", repo_root),
        ],
        "current_condition": (
            "representative fd/path and process-tree helper evidence is aligned with 35T hardware trace evidence "
            "through the targeted dual-channel board validation bundle"
        ),
        "remaining_work": [
            "hardware user-pointer memory snapshot remains deferred and default-disabled",
            "source-line attribution remains partial until DWARF or equivalent source-location evidence is added",
            "helper or eBPF evidence must remain a trusted-kernel companion rather than a hardware-only tracing claim",
        ],
        "no_substitution_rules": [
            "not a hardware user-pointer memory snapshot",
            "not hardware-only tracing evidence",
            "not complete semantic reconstruction",
            "not a QEMU-plugin or eBPF baseline substitute",
            "not a malicious-kernel or kernel-rootkit resistance claim",
        ],
        "non_claims": [
            "no complete pointer semantic reconstruction claim",
            "no kernel rootkit resistance claim",
            "no real malware detection claim",
            "no classifier accuracy claim",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Trusted Helper Alignment: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Semantic run: `{report['semantic_run_id']}`",
        "",
        f"Route: `{report['alignment_route']}`",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Selected Side-Channel Sources", ""]
    for row in report["selected_side_channel_sources"]:
        lines.append(f"- `{row['sample']}`: `{row['source']}` ({row['event_count']} events)")
    lines += ["", "## Current Condition", "", f"- {report['current_condition']}"]
    lines += ["", "## Remaining Work", ""]
    lines.extend(f"- {item}" for item in report["remaining_work"])
    lines += ["", "## No-Substitution Rules", ""]
    lines.extend(f"- {item}" for item in report["no_substitution_rules"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "helper_alignment.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "helper_alignment.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_side_channel(path: Path) -> None:
    write_json(path, {"schema": "rvmt.syscall_side_channel.capture.v1", "events": [{"name": "openat"}, {"name": "close"}]})


def write_fixture(root: Path, *, bad_bundle: bool = False) -> None:
    evidence = root / DEFAULT_EVIDENCE_ROOT
    bundle = root / DEFAULT_BUNDLE_ROOT
    results = root / DEFAULT_SEMANTIC_RESULTS_ROOT
    write_json(
        evidence / "board_syscall_side_channel_smoke.json",
        {
            "schema": "rvmt.35t.board_syscall_side_channel_smoke.v1",
            "status": BOARD_SMOKE_STATUS,
            "hardware_validated": True,
            "smoke_runs": [{"status": "SIDE_CHANNEL_SMOKE_PASS", "syscall_side_channel_files": 2}],
            "strict_validation_follow_up": {
                "status": "PASS",
                "fd_path_flow": "PASS",
                "process_tree": "PASS",
                "source_attribution": "PARTIAL",
            },
        },
    )
    write_json(
        bundle / "bundle_manifest.json",
        {
            "schema": "rvmt.35t.board_validation_bundle.v1",
            "status": "PASS",
            "checker_status": "PASS",
            "hardware_validated": True,
            "validation_mode": "single_channel" if bad_bundle else "dual_channel",
            "trace_gate_run_id": RUN_ID,
            "semantic_run_id": SEMANTIC_RUN_ID,
            "selected_statuses": {
                "fd_path_flow": "PASS",
                "process_tree": "PASS",
                "source_attribution": "PARTIAL",
            },
        },
    )
    fd_source = f"{DEFAULT_SEMANTIC_RESULTS_ROOT.as_posix()}/samples/malware_like_synthetic/file_scan/board/trace-on/rep_00/syscall_side_channel.json"
    proc_source = f"{DEFAULT_SEMANTIC_RESULTS_ROOT.as_posix()}/samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/syscall_side_channel.json"
    write_side_channel(root / fd_source)
    write_side_channel(root / proc_source)
    write_json(
        evidence / "fd_path_case_studies.json",
        {
            "schema": "rvmt.35t.fd_path_case_studies.v1",
            "status": "PASS",
            "samples": {
                "file_scan": {
                    "status": "PASS",
                    "selected_candidate": {"source": fd_source, "source_type": "syscall_side_channel"},
                }
            },
        },
    )
    write_json(
        evidence / "process_tree_case_study.json",
        {
            "schema": "rvmt.35t.process_tree_case_study.v1",
            "status": "PASS",
            "sample": "process_chain",
            "case_study": {
                "status": "PASS",
                "selected_candidate": {"source": proc_source, "source_type": "syscall_side_channel"},
            },
        },
    )
    write_json(
        evidence / "threat_model_boundary.json",
        {
            "schema": "rvmt.35t.threat_model_boundary.v1",
            "status": THREAT_MODEL_STATUS,
            "trusted_components": ["linux_kernel"],
            "in_scope": ["user_mode_malware_like_workload"],
            "out_of_scope": ["kernel_rootkit"],
            "routes": {
                "kernel_helper_metadata": {"status": "OPTIONAL_DEFERRED_COMPANION"},
                "ebpf_metadata_alignment": {"status": "OPTIONAL_DEFERRED_COMPANION"},
            },
        },
    )
    results.mkdir(parents=True, exist_ok=True)


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT, DEFAULT_SEMANTIC_RESULTS_ROOT, DEFAULT_BUNDLE_ROOT)
        if report["status"] != STATUS:
            print("[FAIL] expected helper alignment fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "helper_alignment.md").is_file():
            print("[FAIL] missing helper alignment markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, bad_bundle=True)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT, DEFAULT_SEMANTIC_RESULTS_ROOT, DEFAULT_BUNDLE_ROOT)
        if report["status"] != "FAIL" or "bundle_dual_channel" not in report["failures"]:
            print("[FAIL] expected non-dual-channel fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T helper alignment self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check 35T trusted helper/syscall side-channel alignment evidence.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--semantic-results-root", type=Path, default=DEFAULT_SEMANTIC_RESULTS_ROOT)
    parser.add_argument("--bundle-root", type=Path, default=DEFAULT_BUNDLE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.evidence_root, args.semantic_results_root, args.bundle_root)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_helper_alignment: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T helper alignment")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
