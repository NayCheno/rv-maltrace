from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_DESIGN = Path("experiments/linux_behavior/pointer_snapshot_design_review.json")
DEFAULT_DESIGN_NOTE = Path("docs/research/semantic/pointer_snapshot_design_review.md")
DEFAULT_GATE = Path("experiments/linux_behavior/pointer_snapshot_enablement_gate.json")
DEFAULT_ROUTES = Path("experiments/linux_behavior/semantic_enrichment_routes.json")
DEFAULT_STRATEGY = Path("experiments/linux_behavior/semantic_enrichment_strategy.json")
DEFAULT_TRACE_PROFILES = Path("src/rv_maltrace/trace_profiles.py")
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
SCHEMA = "rvmt.35t.pointer_snapshot_design_review.check.v1"
DESIGN_SCHEMA = "rvmt.35t.pointer_snapshot_design_review.v1"
STATUS = "POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
DESIGN_STATUS = "DESIGN_REVIEW_RECORDED_NOT_ENABLED"
REQUIRED_SYSCALLS = {
    ("openat", "a1"),
    ("execve", "a0"),
}
REQUIRED_GUARDRAILS = {
    "default_disabled_control_path",
    "page_boundary_clipping",
    "fault_timeout_handling",
    "no_load_store_payload_trace_mode",
    "no_core_backpressure",
    "drop_record_on_overflow",
}
REQUIRED_MEASUREMENT_GATES = {
    "timing_resource_gate",
    "bandwidth_drop_gate",
    "noninterference_gate",
    "semantic_accuracy_gate",
}
REQUIRED_NON_CLAIMS = {
    "no 35T hardware user-pointer snapshot PASS claim",
    "no default memory payload tracing",
    "no complete syscall argument reconstruction claim",
    "no malicious-kernel or kernel-rootkit resistance claim",
    "no real malware detection claim",
}


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


def block_for_profile(text: str, profile_name: str) -> str:
    match = re.search(rf'"{re.escape(profile_name)}"\s*:\s*TraceProfile\((.*?)\n\s*\),', text, re.DOTALL)
    return match.group(1) if match else ""


def profile_arg_mem_disabled(text: str, profile_name: str) -> bool:
    block = re.sub(r"\s+", "", block_for_profile(text, profile_name))
    return bool(block) and "enable_arg_mem=True" not in block


def allowlist_pairs(design: dict[str, Any]) -> set[tuple[str, str]]:
    rows = design.get("syscall_allowlist", [])
    if not isinstance(rows, list):
        return set()
    return {
        (str(row.get("name")), str(row.get("argument")))
        for row in rows
        if isinstance(row, dict)
    }


def allowlist_limits_ok(design: dict[str, Any]) -> bool:
    rows = design.get("syscall_allowlist", [])
    if not isinstance(rows, list):
        return False
    required_rows = [
        row
        for row in rows
        if isinstance(row, dict) and (str(row.get("name")), str(row.get("argument"))) in REQUIRED_SYSCALLS
    ]
    return bool(required_rows) and all(
        isinstance(row.get("max_bytes"), int)
        and 0 < int(row["max_bytes"]) <= 64
        and row.get("termination") == "nul_or_max_bytes"
        for row in required_rows
    )


def measurement_gate_ids(design: dict[str, Any]) -> set[str]:
    rows = design.get("measurement_gates", [])
    if not isinstance(rows, list):
        return set()
    return {str(row.get("id")) for row in rows if isinstance(row, dict)}


def measurement_gates_pre_enablement(design: dict[str, Any]) -> bool:
    rows = design.get("measurement_gates", [])
    if not isinstance(rows, list):
        return False
    return all(
        isinstance(row, dict)
        and row.get("status") == "REQUIRED_BEFORE_ENABLEMENT"
        and isinstance(row.get("evidence_required"), list)
        and len(row["evidence_required"]) >= 3
        for row in rows
        if row.get("id") in REQUIRED_MEASUREMENT_GATES
    )


def gate_requirement_ids(gate: dict[str, Any]) -> set[str]:
    rows = gate.get("enablement_requirements", [])
    if not isinstance(rows, list):
        return set()
    return {str(row.get("id")) for row in rows if isinstance(row, dict)}


def route_by_id(routes: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = routes.get("routes", [])
    if not isinstance(rows, list):
        return {}
    return {str(row.get("id")): row for row in rows if isinstance(row, dict) and row.get("id")}


def strategy_row_by_id(strategy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = strategy.get("strategy", [])
    if not isinstance(rows, list):
        return {}
    return {str(row.get("id")): row for row in rows if isinstance(row, dict) and row.get("id")}


def note_has_tokens(text: str) -> bool:
    tokens = [
        "TRACE_MEM_MODE_NONE",
        "hardware_user_pointer_snapshot = DEFERRED",
        "default_enabled = false",
        "openat",
        "execve",
        "64 bytes",
        "no core backpressure",
        "Synthetic ARG_MEM fixtures",
    ]
    return all(token in text for token in tokens)


def build_report(repo_root: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    design_path = repo_path(repo_root, DEFAULT_DESIGN)
    note_path = repo_path(repo_root, DEFAULT_DESIGN_NOTE)
    gate_path = repo_path(repo_root, DEFAULT_GATE)
    routes_path = repo_path(repo_root, DEFAULT_ROUTES)
    strategy_path = repo_path(repo_root, DEFAULT_STRATEGY)
    profiles_path = repo_path(repo_root, DEFAULT_TRACE_PROFILES)
    failures: list[str] = []

    design = read_json(design_path, failures, repo_root, "pointer snapshot design review")
    gate = read_json(gate_path, failures, repo_root, "pointer snapshot enablement gate")
    routes = read_json(routes_path, failures, repo_root, "semantic enrichment routes")
    strategy = read_json(strategy_path, failures, repo_root, "semantic enrichment strategy")
    note_text = note_path.read_text(encoding="utf-8") if note_path.is_file() else ""
    if not note_text:
        failures.append(f"missing pointer snapshot design note: {rel(note_path, repo_root)}")
    profiles_text = profiles_path.read_text(encoding="utf-8") if profiles_path.is_file() else ""
    if not profiles_text:
        failures.append(f"missing trace profiles: {rel(profiles_path, repo_root)}")

    current_policy = design.get("current_policy", {}) if isinstance(design.get("current_policy"), dict) else {}
    artifact_policy = design.get("artifact_policy", {}) if isinstance(design.get("artifact_policy"), dict) else {}
    route_rows = route_by_id(routes)
    strategy_rows = strategy_row_by_id(strategy)
    selective_route = route_rows.get("selective_memory_snapshot", {})
    selective_strategy = strategy_rows.get("evaluate_selective_memory_snapshot", {})
    checks = {
        "design_schema": design.get("schema") == DESIGN_SCHEMA,
        "design_status": design.get("status") == DESIGN_STATUS,
        "design_run_id": design.get("run_id") == RUN_ID,
        "design_scope": design.get("scope") == EXPECTED_SCOPE,
        "design_claim_level": design.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "route_selective_memory_snapshot": design.get("route") == "selective_memory_snapshot",
        "current_policy_default_disabled": current_policy.get("default_enabled") is False,
        "current_policy_trace_mem_none": current_policy.get("trace_mem_mode") == "TRACE_MEM_MODE_NONE",
        "current_policy_hardware_deferred": current_policy.get("hardware_user_pointer_snapshot") == "DEFERRED",
        "required_allowlist_present": REQUIRED_SYSCALLS <= allowlist_pairs(design),
        "allowlist_limits_bounded": allowlist_limits_ok(design),
        "required_guardrails_present": REQUIRED_GUARDRAILS <= set(design.get("safety_guardrails", []))
        if isinstance(design.get("safety_guardrails"), list)
        else False,
        "required_measurement_gates_present": REQUIRED_MEASUREMENT_GATES <= measurement_gate_ids(design),
        "measurement_gates_pre_enablement": measurement_gates_pre_enablement(design),
        "artifact_policy_deferred": artifact_policy.get("raw_pointer_payloads") == "local_only_or_controlled_release"
        and artifact_policy.get("sanitization_required_before_publication") is True,
        "non_claims_present": REQUIRED_NON_CLAIMS <= set(design.get("non_claims", []))
        if isinstance(design.get("non_claims"), list)
        else False,
        "non_substitution_rules_present": len(design.get("non_substitution_rules", [])) >= 3
        if isinstance(design.get("non_substitution_rules"), list)
        else False,
        "gate_design_review_required": "design_review" in gate_requirement_ids(gate),
        "routes_still_deferred": routes.get("current_trace_mem_mode") == "TRACE_MEM_MODE_NONE"
        and selective_route.get("status") == "DEFERRED_POST_FPGA",
        "strategy_allows_design_review_only": "bounded_pointer_snapshot_design_review" in set(
            selective_strategy.get("allowed_work", [])
        )
        and "default_memory_trace_enable" in set(selective_strategy.get("forbidden_work", []))
        and "core_backpressure" in set(selective_strategy.get("forbidden_work", [])),
        "p2_profile_arg_mem_disabled": profile_arg_mem_disabled(profiles_text, "p2_pointer_snapshot")
        and 'arg_mem_policy="gated"' in re.sub(r"\s+", "", block_for_profile(profiles_text, "p2_pointer_snapshot")),
        "small_capacity_profiles_arg_mem_disabled": all(
            profile_arg_mem_disabled(profiles_text, name)
            for name in ("p0a_syscall_drop", "p0b_trap_drop", "p0c_syscall_trap_drop")
        ),
        "design_note_tokens_present": note_has_tokens(note_text),
    }
    failures.extend(key for key, ok in checks.items() if not ok)
    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "generated_utc": utc_now(),
        "status": STATUS if not failures else "FAIL",
        "evidence_root": rel(evidence_root, repo_root),
        "design": rel(design_path, repo_root),
        "design_note": rel(note_path, repo_root),
        "checks": checks,
        "allowlist": design.get("syscall_allowlist", []),
        "safety_guardrails": design.get("safety_guardrails", []),
        "measurement_gates": design.get("measurement_gates", []),
        "current_policy": current_policy,
        "artifact_policy": artifact_policy,
        "interpretation": [
            "bounded pointer snapshot design review is recorded for openat and execve pathname prefixes",
            "the current 35T policy still keeps hardware user-pointer snapshots default-disabled and deferred",
            "this design review is not timing, bandwidth, noninterference, semantic accuracy, or enabled-board evidence",
        ],
        "non_claims": design.get("non_claims", []),
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Pointer Snapshot Design Review: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Design: `{report['design']}`",
        "",
        f"Design note: `{report['design_note']}`",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Current Policy", ""]
    for key, value in report["current_policy"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Allowlist", "", "| Syscall | Argument | Max Bytes | Payload |", "| --- | --- | ---: | --- |"]
    for row in report["allowlist"]:
        if not isinstance(row, dict):
            continue
        lines.append(
            f"| `{row.get('name')}` | `{row.get('argument')}` | {row.get('max_bytes')} | `{row.get('payload')}` |"
        )
    lines += ["", "## Safety Guardrails", ""]
    lines.extend(f"- {item}" for item in report["safety_guardrails"])
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "pointer_snapshot_design_review.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "pointer_snapshot_design_review.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_fixture(root: Path, *, missing_guardrail: bool = False, default_enabled: bool = False) -> None:
    design = {
        "schema": DESIGN_SCHEMA,
        "run_id": RUN_ID,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "status": DESIGN_STATUS,
        "route": "selective_memory_snapshot",
        "current_policy": {
            "trace_mem_mode": "TRACE_MEM_MODE_NONE",
            "hardware_user_pointer_snapshot": "DEFERRED",
            "default_enabled": default_enabled,
            "small_capacity_profiles": "ARG_MEM_DISABLED",
        },
        "syscall_allowlist": [
            {"name": "openat", "argument": "a1", "payload": "pathname_prefix", "max_bytes": 64, "termination": "nul_or_max_bytes"},
            {"name": "execve", "argument": "a0", "payload": "pathname_prefix", "max_bytes": 64, "termination": "nul_or_max_bytes"},
        ],
        "safety_guardrails": sorted(REQUIRED_GUARDRAILS - ({"no_core_backpressure"} if missing_guardrail else set())),
        "measurement_gates": [
            {"id": item, "status": "REQUIRED_BEFORE_ENABLEMENT", "evidence_required": ["a", "b", "c"]}
            for item in sorted(REQUIRED_MEASUREMENT_GATES)
        ],
        "artifact_policy": {
            "raw_pointer_payloads": "local_only_or_controlled_release",
            "sanitization_required_before_publication": True,
        },
        "non_claims": sorted(REQUIRED_NON_CLAIMS),
        "non_substitution_rules": ["a", "b", "c"],
    }
    write_json(root / DEFAULT_DESIGN, design)
    note = (
        "TRACE_MEM_MODE_NONE\n"
        "hardware_user_pointer_snapshot = DEFERRED\n"
        "default_enabled = false\n"
        "openat\nexecve\n64 bytes\nno core backpressure\nSynthetic ARG_MEM fixtures\n"
    )
    (root / DEFAULT_DESIGN_NOTE).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_DESIGN_NOTE).write_text(note, encoding="utf-8")
    write_json(
        root / DEFAULT_GATE,
        {"enablement_requirements": [{"id": "design_review"}]},
    )
    write_json(
        root / DEFAULT_ROUTES,
        {"current_trace_mem_mode": "TRACE_MEM_MODE_NONE", "routes": [{"id": "selective_memory_snapshot", "status": "DEFERRED_POST_FPGA"}]},
    )
    write_json(
        root / DEFAULT_STRATEGY,
        {
            "strategy": [
                {
                    "id": "evaluate_selective_memory_snapshot",
                    "allowed_work": ["bounded_pointer_snapshot_design_review"],
                    "forbidden_work": ["default_memory_trace_enable", "core_backpressure"],
                }
            ]
        },
    )
    profiles = (
        'TRACE_PROFILES = {\n'
        '    "p2_pointer_snapshot": TraceProfile(\n'
        "        enable_arg_mem=False,\n"
        '        arg_mem_policy="gated",\n'
        "    ),\n"
        '    "p0a_syscall_drop": TraceProfile(\n'
        "        enable_arg_mem=False,\n"
        "    ),\n"
        '    "p0b_trap_drop": TraceProfile(\n'
        "        enable_arg_mem=False,\n"
        "    ),\n"
        '    "p0c_syscall_trap_drop": TraceProfile(\n'
        "        enable_arg_mem=False,\n"
        "    ),\n"
        "}\n"
    )
    (root / DEFAULT_TRACE_PROFILES).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_TRACE_PROFILES).write_text(profiles, encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != STATUS:
            print("[FAIL] expected pointer snapshot design review fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "pointer_snapshot_design_review.md").is_file():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    cases = [
        ({"missing_guardrail": True}, "required_guardrails_present"),
        ({"default_enabled": True}, "current_policy_default_disabled"),
    ]
    for kwargs, expected_failure in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, **kwargs)
            report = build_report(root, DEFAULT_EVIDENCE_ROOT)
            if report["status"] != "FAIL" or expected_failure not in report["failures"]:
                print(f"[FAIL] expected design review regression: {expected_failure}", file=sys.stderr)
                print(json.dumps(report, indent=2), file=sys.stderr)
                return 1
    print("[PASS] 35T pointer snapshot design review self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the bounded 35T pointer snapshot design review without enabling pointer snapshots.")
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
        print(f"check_35t_pointer_snapshot_design_review: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T pointer snapshot design review")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
