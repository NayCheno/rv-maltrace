from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_GATE = Path("experiments/linux_behavior/pointer_snapshot_enablement_gate.json")
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
DEFAULT_POINTER_PREFLIGHT = DEFAULT_EVIDENCE_ROOT / "pointer_semantics_preflight.json"
DEFAULT_THREAT_MODEL = DEFAULT_EVIDENCE_ROOT / "threat_model_boundary.json"
DEFAULT_ARTIFACT_READINESS = DEFAULT_EVIDENCE_ROOT / "artifact_package_readiness.json"
DEFAULT_ROUTES = Path("experiments/linux_behavior/semantic_enrichment_routes.json")
DEFAULT_STRATEGY = Path("experiments/linux_behavior/semantic_enrichment_strategy.json")
SCHEMA = "rvmt.35t.pointer_snapshot_enablement_gate.v1"
CHECK_SCHEMA = "rvmt.35t.pointer_snapshot_enablement_gate.check.v1"
STATUS = "GATED_NOT_ENABLED"
PASS_STATUS = "POINTER_SNAPSHOT_ENABLEMENT_GATES_RECORDED_NOT_ENABLED"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
POINTER_PREFLIGHT_STATUS = "SYNTHETIC_ARG_MEM_GUARDRAILS_PASS_SIDE_CHANNEL_CLOSURE_HARDWARE_POINTER_DEFERRED"
THREAT_MODEL_STATUS = "TRUSTED_KERNEL_USER_MODE_THREAT_MODEL_BOUNDARY_SPECIFIED"
REQUIRED_REQUIREMENTS = {
    "design_review",
    "safety_guardrails",
    "timing_resource_gate",
    "bandwidth_drop_gate",
    "noninterference_gate",
    "semantic_accuracy_gate",
    "artifact_policy_gate",
    "threat_model_gate",
}
REQUIRED_NON_CLAIMS = [
    "no 35T hardware user-pointer snapshot PASS claim until all gates pass",
    "no default memory payload tracing",
    "no complete syscall argument reconstruction claim",
    "no malicious-kernel or kernel-rootkit resistance claim",
    "no real malware detection claim",
]


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
    if not path.exists():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return {}
    try:
        return load_json(path)
    except Exception as exc:
        failures.append(f"invalid {label}: {rel(path, repo_root)}: {exc}")
        return {}


def requirement_rows(gate: dict[str, Any]) -> list[dict[str, Any]]:
    rows = gate.get("enablement_requirements", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def route_rows(routes: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = routes.get("routes", [])
    if not isinstance(rows, list):
        return {}
    return {str(row.get("id")): row for row in rows if isinstance(row, dict) and row.get("id")}


def build_report(repo_root: Path, gate_arg: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    gate_path = repo_path(repo_root, gate_arg).resolve()
    failures: list[str] = []
    gate = read_json(gate_path, failures, repo_root, "pointer snapshot enablement gate")
    pointer = read_json(repo_path(repo_root, DEFAULT_POINTER_PREFLIGHT), failures, repo_root, "pointer semantics preflight")
    threat = read_json(repo_path(repo_root, DEFAULT_THREAT_MODEL), failures, repo_root, "threat model boundary")
    artifact = read_json(repo_path(repo_root, DEFAULT_ARTIFACT_READINESS), failures, repo_root, "artifact package readiness")
    routes = read_json(repo_path(repo_root, DEFAULT_ROUTES), failures, repo_root, "semantic enrichment routes")
    strategy = read_json(repo_path(repo_root, DEFAULT_STRATEGY), failures, repo_root, "semantic enrichment strategy")

    requirements = requirement_rows(gate)
    req_by_id = {str(row.get("id")): row for row in requirements if row.get("id")}
    route_by_id = route_rows(routes)
    current_policy = gate.get("current_policy", {}) if isinstance(gate.get("current_policy"), dict) else {}
    pointer_current = (
        pointer.get("current_35t_pointer_semantics", {})
        if isinstance(pointer.get("current_35t_pointer_semantics"), dict)
        else {}
    )
    selective_route = route_by_id.get("selective_memory_snapshot", {})
    requirement_evidence_counts = {
        req_id: len(row.get("evidence_required", [])) if isinstance(row.get("evidence_required"), list) else 0
        for req_id, row in req_by_id.items()
    }
    checks = {
        "gate_schema": gate.get("schema") == SCHEMA,
        "gate_status": gate.get("status") == STATUS,
        "gate_run_id": gate.get("run_id") == RUN_ID,
        "gate_scope": gate.get("scope") == EXPECTED_SCOPE,
        "gate_claim_level": gate.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "all_required_requirements_present": REQUIRED_REQUIREMENTS.issubset(set(req_by_id)),
        "requirements_are_pre_enablement": all(
            row.get("status") == "REQUIRED_BEFORE_ENABLEMENT" for row in requirements
        ),
        "requirements_have_evidence_lists": all(count >= 2 for count in requirement_evidence_counts.values()),
        "current_policy_default_disabled": current_policy.get("default_enabled") is False,
        "current_policy_trace_mem_none": current_policy.get("trace_mem_mode") == "TRACE_MEM_MODE_NONE",
        "current_policy_hardware_deferred": current_policy.get("hardware_user_pointer_snapshot") == "DEFERRED",
        "pointer_preflight_deferred": pointer.get("status") == POINTER_PREFLIGHT_STATUS
        and pointer_current.get("hardware_user_pointer_snapshot") == "DEFERRED",
        "routes_selective_snapshot_deferred": routes.get("current_trace_mem_mode") == "TRACE_MEM_MODE_NONE"
        and selective_route.get("status") == "DEFERRED_POST_FPGA",
        "strategy_keeps_snapshot_optional": strategy.get("current_mvp_policy") == "NO_EBPF_NO_KERNEL_HELPER_NO_MEMORY_SNAPSHOT",
        "artifact_policy_available": artifact.get("schema") == "rvmt.35t.artifact_package_readiness.v1"
        and artifact.get("status") == "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED",
        "threat_model_boundary_available": threat.get("schema") == "rvmt.35t.threat_model_boundary.v1"
        and threat.get("status") == THREAT_MODEL_STATUS,
        "non_claims_present": all(item in set(gate.get("required_non_claims", [])) for item in REQUIRED_NON_CLAIMS)
        if isinstance(gate.get("required_non_claims"), list)
        else False,
    }
    for key, ok in checks.items():
        if not ok:
            failures.append(f"pointer snapshot gate check failed: {key}")
    status = PASS_STATUS if not failures else "FAIL"
    return {
        "schema": CHECK_SCHEMA,
        "run_id": RUN_ID,
        "status": status,
        "gate": rel(gate_path, repo_root),
        "checks": checks,
        "requirement_evidence_counts": requirement_evidence_counts,
        "current_policy": current_policy,
        "evidence": {
            "pointer_preflight": rel(repo_path(repo_root, DEFAULT_POINTER_PREFLIGHT), repo_root),
            "threat_model": rel(repo_path(repo_root, DEFAULT_THREAT_MODEL), repo_root),
            "artifact_readiness": rel(repo_path(repo_root, DEFAULT_ARTIFACT_READINESS), repo_root),
            "semantic_routes": rel(repo_path(repo_root, DEFAULT_ROUTES), repo_root),
            "semantic_strategy": rel(repo_path(repo_root, DEFAULT_STRATEGY), repo_root),
        },
        "interpretation": [
            "hardware user-pointer snapshot remains explicitly gated and disabled in current 35T evidence",
            "the gate records the design, safety, timing, bandwidth, noninterference, semantic accuracy, artifact, and threat-model evidence required before enablement",
            "synthetic ARG_MEM and syscall side-channel closure cannot be substituted for enabled hardware pointer snapshot evidence",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Pointer Snapshot Enablement Gate: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Gate: `{report['gate']}`",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Requirement Evidence Counts", ""]
    for key, count in report["requirement_evidence_counts"].items():
        lines.append(f"- {key}: {count}")
    lines += ["", "## Current Policy", ""]
    for key, value in report["current_policy"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "pointer_snapshot_enablement_gate.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "pointer_snapshot_enablement_gate.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def fixture_gate(root: Path, *, missing_requirement: bool = False) -> None:
    requirements = []
    for req_id in sorted(REQUIRED_REQUIREMENTS):
        if missing_requirement and req_id == "noninterference_gate":
            continue
        requirements.append(
            {
                "id": req_id,
                "status": "REQUIRED_BEFORE_ENABLEMENT",
                "evidence_required": ["artifact_a", "artifact_b"],
            }
        )
    write_json(
        root / DEFAULT_GATE,
        {
            "schema": SCHEMA,
            "run_id": RUN_ID,
            "scope": EXPECTED_SCOPE,
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "status": STATUS,
            "current_policy": {
                "trace_mem_mode": "TRACE_MEM_MODE_NONE",
                "hardware_user_pointer_snapshot": "DEFERRED",
                "default_enabled": False,
            },
            "enablement_requirements": requirements,
            "required_non_claims": REQUIRED_NON_CLAIMS,
        },
    )


def fixture_evidence(root: Path) -> None:
    write_json(
        root / DEFAULT_POINTER_PREFLIGHT,
        {
            "schema": "rvmt.35t.pointer_semantics_preflight.v1",
            "status": POINTER_PREFLIGHT_STATUS,
            "current_35t_pointer_semantics": {"hardware_user_pointer_snapshot": "DEFERRED"},
        },
    )
    write_json(
        root / DEFAULT_THREAT_MODEL,
        {
            "schema": "rvmt.35t.threat_model_boundary.v1",
            "status": THREAT_MODEL_STATUS,
        },
    )
    write_json(
        root / DEFAULT_ARTIFACT_READINESS,
        {
            "schema": "rvmt.35t.artifact_package_readiness.v1",
            "status": "LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED",
        },
    )
    write_json(
        root / DEFAULT_ROUTES,
        {
            "current_trace_mem_mode": "TRACE_MEM_MODE_NONE",
            "routes": [{"id": "selective_memory_snapshot", "status": "DEFERRED_POST_FPGA"}],
        },
    )
    write_json(
        root / DEFAULT_STRATEGY,
        {"current_mvp_policy": "NO_EBPF_NO_KERNEL_HELPER_NO_MEMORY_SNAPSHOT"},
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture_gate(root)
        fixture_evidence(root)
        report = build_report(root, DEFAULT_GATE, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != PASS_STATUS:
            print("[FAIL] expected pointer snapshot gate fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "pointer_snapshot_enablement_gate.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture_gate(root, missing_requirement=True)
        fixture_evidence(root)
        report = build_report(root, DEFAULT_GATE, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL" or "pointer snapshot gate check failed: all_required_requirements_present" not in report["failures"]:
            print("[FAIL] expected missing requirement fixture to fail", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture_gate(root)
        fixture_evidence(root)
        gate = load_json(root / DEFAULT_GATE)
        gate["current_policy"]["default_enabled"] = True
        write_json(root / DEFAULT_GATE, gate)
        report = build_report(root, DEFAULT_GATE, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL" or "pointer snapshot gate check failed: current_policy_default_disabled" not in report["failures"]:
            print("[FAIL] expected default-enabled fixture to fail", file=sys.stderr)
            return 1
    print("[PASS] 35T pointer snapshot enablement gate self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the gated 35T pointer snapshot enablement conditions.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--gate", type=Path, default=DEFAULT_GATE)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.gate, args.evidence_root)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_pointer_snapshot_gate: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T pointer snapshot enablement gate")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == PASS_STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
