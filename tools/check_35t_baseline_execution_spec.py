from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_SPEC = Path("experiments/linux_behavior/baseline_execution_spec.json")
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_SUMMARY = DEFAULT_EVIDENCE_ROOT / "baseline_evaluation_summary.json"
DEFAULT_ADVANCED_PREFLIGHT = DEFAULT_EVIDENCE_ROOT / "advanced_baseline_preflight.json"
DEFAULT_POINTER_PREFLIGHT = DEFAULT_EVIDENCE_ROOT / "pointer_semantics_preflight.json"
DEFAULT_THREAT_MODEL = DEFAULT_EVIDENCE_ROOT / "threat_model_boundary.json"
SPEC_SCHEMA = "rvmt.35t.baseline_execution_spec.v1"
CHECK_SCHEMA = "rvmt.35t.baseline_execution_spec.check.v1"
SUMMARY_SCHEMA = "rvmt.35t.baseline_evaluation.summary.v1"
ADVANCED_PREFLIGHT_SCHEMA = "rvmt.35t.advanced_baseline_preflight.v1"
POINTER_PREFLIGHT_SCHEMA = "rvmt.35t.pointer_semantics_preflight.v1"
THREAT_MODEL_SCHEMA = "rvmt.35t.threat_model_boundary.v1"
PASS_STATUS = "PASS"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
REQUIRED_ASSESSMENT_BASELINES = {
    "strace_ptrace",
    "ebpf_only",
    "qemu_plugin",
    "software_instrumentation_or_dbi",
    "rvmaltrace_event_only",
    "rvmaltrace_pointer_snapshot_or_helper",
}
REQUIRED_BASELINE_IDS = {
    "host_strace",
    "qemu_strace",
    "ebpf_only",
    "qemu_plugin",
    "software_instrumentation",
    "rvmaltrace_event_only",
    "rvmaltrace_pointer_snapshot",
    "rvmaltrace_helper_or_ebpf_companion",
}
ALLOWED_CURRENT_STATUSES = {"PASS", "BLOCKED_CURRENT_ENVIRONMENT", "READY_NOT_RUN", "NOT_RUN", "DEFERRED"}
REQUIRED_NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
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


def baseline_rows(spec: dict[str, Any]) -> list[dict[str, Any]]:
    rows = spec.get("baselines", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def list_field(row: dict[str, Any], key: str) -> list[Any]:
    value = row.get(key, [])
    return value if isinstance(value, list) else []


def baseline_statuses(summary: dict[str, Any]) -> dict[str, str]:
    baselines = summary.get("baselines", {}) if isinstance(summary.get("baselines"), dict) else {}
    return {
        str(name): str(row.get("status"))
        for name, row in baselines.items()
        if isinstance(row, dict) and row.get("status") is not None
    }


def mapped_values(mapping: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for rows in mapping.values():
        if isinstance(rows, list):
            values.update(str(item) for item in rows if item)
    return values


def substitutions_are_strict(rows: list[dict[str, Any]]) -> bool:
    for row in rows:
        text = " ".join(str(item) for item in list_field(row, "substitution_rules")).lower()
        if "not" not in text and "must not" not in text:
            return False
    return True


def pass_rows_have_artifacts_and_commands(rows: list[dict[str, Any]]) -> bool:
    for row in rows:
        if row.get("current_status") != "PASS":
            continue
        if not list_field(row, "required_artifacts") or not list_field(row, "reproduction_commands"):
            return False
    return True


def blocked_or_deferred_rows_have_gates(rows: list[dict[str, Any]]) -> bool:
    for row in rows:
        if row.get("current_status") not in {"BLOCKED_CURRENT_ENVIRONMENT", "READY_NOT_RUN", "NOT_RUN", "DEFERRED"}:
            continue
        criteria = " ".join(str(item) for item in list_field(row, "pass_criteria")).lower()
        commands = " ".join(str(item) for item in list_field(row, "reproduction_commands")).lower()
        if not criteria or not commands:
            return False
        if row.get("current_status") == "DEFERRED" and not any(token in criteria for token in ("must", "separate", "no longer")):
            return False
        if row.get("current_status") == "BLOCKED_CURRENT_ENVIRONMENT" and "preflight" not in commands:
            return False
    return True


def build_report(repo_root: Path, spec_arg: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    spec_path = repo_path(repo_root, spec_arg).resolve()
    failures: list[str] = []
    spec = read_json(spec_path, failures, repo_root, "baseline execution spec")
    summary = read_json(repo_path(repo_root, DEFAULT_SUMMARY), failures, repo_root, "baseline evaluation summary")
    advanced = read_json(repo_path(repo_root, DEFAULT_ADVANCED_PREFLIGHT), failures, repo_root, "advanced baseline preflight")
    pointer = read_json(repo_path(repo_root, DEFAULT_POINTER_PREFLIGHT), failures, repo_root, "pointer semantics preflight")
    threat = read_json(repo_path(repo_root, DEFAULT_THREAT_MODEL), failures, repo_root, "threat model boundary")

    rows = baseline_rows(spec)
    row_by_id = {str(row.get("id")): row for row in rows if row.get("id")}
    coverage = spec.get("coverage_map", {}) if isinstance(spec.get("coverage_map"), dict) else {}
    summary_status = baseline_statuses(summary)
    current_status_matches: dict[str, bool] = {}
    for baseline_id, row in row_by_id.items():
        summary_key = str(row.get("summary_key") or baseline_id)
        if summary_key in summary_status:
            current_status_matches[baseline_id] = row.get("current_status") == summary_status.get(summary_key)
        else:
            current_status_matches[baseline_id] = row.get("current_status") == "DEFERRED"

    checks = {
        "spec_schema": spec.get("schema") == SPEC_SCHEMA,
        "spec_run_id": spec.get("run_id") == RUN_ID,
        "spec_scope": spec.get("scope") == EXPECTED_SCOPE,
        "spec_claim_level": spec.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "summary_schema": summary.get("schema") == SUMMARY_SCHEMA,
        "summary_sample_count": summary.get("sample_count") == 13,
        "advanced_preflight_schema": advanced.get("schema") == ADVANCED_PREFLIGHT_SCHEMA,
        "pointer_preflight_schema": pointer.get("schema") == POINTER_PREFLIGHT_SCHEMA,
        "threat_model_schema": threat.get("schema") == THREAT_MODEL_SCHEMA,
        "assessment_baselines_covered": REQUIRED_ASSESSMENT_BASELINES.issubset(set(coverage)),
        "required_baseline_ids_present": REQUIRED_BASELINE_IDS.issubset(set(row_by_id)),
        "coverage_map_targets_declared_rows": mapped_values(coverage).issubset(set(row_by_id)),
        "current_statuses_allowed": all(row.get("current_status") in ALLOWED_CURRENT_STATUSES for row in rows),
        "current_statuses_match_summary": bool(current_status_matches) and all(current_status_matches.values()),
        "pass_rows_have_artifacts_and_commands": pass_rows_have_artifacts_and_commands(rows),
        "blocked_or_deferred_rows_have_gates": blocked_or_deferred_rows_have_gates(rows),
        "substitution_rules_present": all(bool(list_field(row, "substitution_rules")) for row in rows),
        "substitution_rules_strict": substitutions_are_strict(rows),
        "non_claims_present": all(item in set(spec.get("non_claims", [])) for item in REQUIRED_NON_CLAIMS)
        if isinstance(spec.get("non_claims"), list)
        else False,
    }
    for key, ok in checks.items():
        if not ok:
            failures.append(f"baseline execution spec check failed: {key}")
    status = PASS_STATUS if not failures else "FAIL"
    return {
        "schema": CHECK_SCHEMA,
        "run_id": RUN_ID,
        "status": status,
        "spec": rel(spec_path, repo_root),
        "summary": rel(repo_path(repo_root, DEFAULT_SUMMARY), repo_root),
        "checks": checks,
        "coverage_map": coverage,
        "baseline_statuses": {
            baseline_id: {
                "family": row.get("family"),
                "summary_key": row.get("summary_key"),
                "spec_status": row.get("current_status"),
                "summary_status": summary_status.get(str(row.get("summary_key") or baseline_id), "DEFERRED"),
                "status_matches_summary": current_status_matches.get(baseline_id),
            }
            for baseline_id, row in sorted(row_by_id.items())
        },
        "interpretation": [
            "the spec maps the assessment's required baseline families to concrete current evidence rows",
            "blocked or deferred rows have preflight or enablement gates and cannot silently become PASS",
            "substitution rules prevent strace, software instrumentation, QEMU timing, or side-channel evidence from replacing missing eBPF/QEMU-plugin/pointer evidence",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Baseline Execution Spec Check: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Spec: `{report['spec']}`",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Baseline Statuses", ""]
    for baseline_id, row in report["baseline_statuses"].items():
        lines.append(
            f"- `{baseline_id}`: spec={row['spec_status']}, summary={row['summary_status']}, family={row['family']}"
        )
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "baseline_execution_spec_check.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "baseline_execution_spec_check.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def fixture_spec(root: Path, *, missing_rule: bool = False) -> None:
    baselines = []
    statuses = {
        "host_strace": "PASS",
        "qemu_strace": "PASS",
        "ebpf_only": "BLOCKED_CURRENT_ENVIRONMENT",
        "qemu_plugin": "BLOCKED_CURRENT_ENVIRONMENT",
        "software_instrumentation": "PASS",
        "rvmaltrace_event_only": "PASS",
        "rvmaltrace_pointer_snapshot": "DEFERRED",
        "rvmaltrace_helper_or_ebpf_companion": "DEFERRED",
    }
    for baseline_id, status in statuses.items():
        baselines.append(
            {
                "id": baseline_id,
                "family": baseline_id,
                "summary_key": baseline_id,
                "current_status": status,
                "required_artifacts": ["artifact"],
                "reproduction_commands": ["uv run preflight" if status == "BLOCKED_CURRENT_ENVIRONMENT" else "uv run check"],
                "pass_criteria": ["separate enabled run must pass" if status == "DEFERRED" else "criteria"],
                "substitution_rules": [] if missing_rule and baseline_id == "qemu_plugin" else ["must not substitute"],
            }
        )
    write_json(
        root / DEFAULT_SPEC,
        {
            "schema": SPEC_SCHEMA,
            "run_id": RUN_ID,
            "scope": EXPECTED_SCOPE,
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "coverage_map": {
                "strace_ptrace": ["host_strace", "qemu_strace"],
                "ebpf_only": ["ebpf_only"],
                "qemu_plugin": ["qemu_plugin"],
                "software_instrumentation_or_dbi": ["software_instrumentation"],
                "rvmaltrace_event_only": ["rvmaltrace_event_only"],
                "rvmaltrace_pointer_snapshot_or_helper": [
                    "rvmaltrace_pointer_snapshot",
                    "rvmaltrace_helper_or_ebpf_companion",
                ],
            },
            "baselines": baselines,
            "non_claims": REQUIRED_NON_CLAIMS,
        },
    )


def fixture_evidence(root: Path) -> None:
    baselines = {
        "host_strace": {"status": "PASS"},
        "qemu_strace": {"status": "PASS"},
        "ebpf_only": {"status": "BLOCKED_CURRENT_ENVIRONMENT"},
        "qemu_plugin": {"status": "BLOCKED_CURRENT_ENVIRONMENT"},
        "software_instrumentation": {"status": "PASS"},
        "rvmaltrace_event_only": {"status": "PASS"},
        "rvmaltrace_pointer_snapshot": {"status": "DEFERRED"},
        "rvmaltrace_helper_or_ebpf_companion": {"status": "DEFERRED"},
    }
    write_json(
        root / DEFAULT_SUMMARY,
        {"schema": SUMMARY_SCHEMA, "run_id": RUN_ID, "sample_count": 13, "baselines": baselines},
    )
    write_json(root / DEFAULT_ADVANCED_PREFLIGHT, {"schema": ADVANCED_PREFLIGHT_SCHEMA})
    write_json(root / DEFAULT_POINTER_PREFLIGHT, {"schema": POINTER_PREFLIGHT_SCHEMA})
    write_json(root / DEFAULT_THREAT_MODEL, {"schema": THREAT_MODEL_SCHEMA})


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture_spec(root)
        fixture_evidence(root)
        report = build_report(root, DEFAULT_SPEC, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "PASS":
            print("[FAIL] expected baseline execution spec fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "baseline_execution_spec_check.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture_spec(root, missing_rule=True)
        fixture_evidence(root)
        report = build_report(root, DEFAULT_SPEC, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL":
            print("[FAIL] expected missing substitution rule fixture to fail", file=sys.stderr)
            return 1
    print("[PASS] 35T baseline execution spec self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the 35T baseline execution specification against current evidence.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.spec, args.evidence_root)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_baseline_execution_spec: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T baseline execution spec")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == PASS_STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
