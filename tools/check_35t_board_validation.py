from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
EXPECTED_SCHEMA = "rvmt.35t.targeted_board_validation_plan.v1"
EXPECTED_STATUS = "AWAITING_BOARD_RUN"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
REQUIRED_NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]
REQUIRED_OUTPUT_ARTIFACTS = [
    "run_config.json",
    "gate_report.json",
    "gate_report.md",
    "fd_path_flow_summary.json",
    "fd_path_flow_summary.md",
    "process_tree_summary.json",
    "process_tree_summary.md",
    "source_attribution_summary.json",
    "source_attribution_summary.md",
    "command_log.md",
]


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def missing_result_artifacts(results_root: Path) -> list[str]:
    return [artifact for artifact in REQUIRED_OUTPUT_ARTIFACTS if not (results_root / artifact).exists()]


def all_gate_samples_pass(gate_report: dict[str, Any]) -> bool:
    sample_status = gate_report.get("sample_status", {})
    if not isinstance(sample_status, dict) or not sample_status:
        return False
    return all(isinstance(row, dict) and row.get("status") == "PASS" for row in sample_status.values())


def check_result_contents(results_root: Path) -> dict[str, Any]:
    checks: dict[str, Any] = {}

    def check_json(name: str) -> dict[str, Any]:
        path = results_root / name
        if not path.exists():
            return {"ok": False, "reason": "missing"}
        try:
            return {"ok": True, "json": load_json(path)}
        except Exception as exc:
            return {"ok": False, "reason": f"invalid JSON: {exc}"}

    bundle_manifest = check_json("bundle_manifest.json")
    bundle_json = bundle_manifest.get("json", {}) if bundle_manifest.get("ok") else {}
    manifest_present = (results_root / "bundle_manifest.json").exists()
    validation_run_id = RUN_ID
    if manifest_present and isinstance(bundle_json.get("validation_run_id"), str) and bundle_json.get("validation_run_id"):
        validation_run_id = str(bundle_json["validation_run_id"])
    checks["bundle_manifest"] = {
        "ok": bool(
            not manifest_present
            or (
                bundle_manifest.get("ok")
                and bundle_json.get("schema") == "rvmt.35t.board_validation_bundle.v1"
                and bundle_json.get("source_run_id") == RUN_ID
                and bundle_json.get("scope") == EXPECTED_SCOPE
                and bundle_json.get("claim_level") == EXPECTED_CLAIM_LEVEL
                and bundle_json.get("validation_run_id") == validation_run_id
            )
        ),
        "status": "checked" if manifest_present else "not present; validation_run_id defaults to source run",
        "validation_run_id": validation_run_id,
    }

    run_config = check_json("run_config.json")
    run_config_json = run_config.get("json", {}) if run_config.get("ok") else {}
    checks["run_config"] = {
        "ok": bool(
            run_config.get("ok")
            and run_config_json.get("run_id") == validation_run_id
            and run_config_json.get("trace_records") == 512
            and run_config_json.get("trace_profile_policy") == "35t_small_capacity"
        ),
        "status": run_config.get("reason", "checked"),
        "validation_run_id": validation_run_id,
    }

    gate_report = check_json("gate_report.json")
    gate_json = gate_report.get("json", {}) if gate_report.get("ok") else {}
    checks["gate_report"] = {
        "ok": bool(
            gate_report.get("ok")
            and gate_json.get("schema") == "rvmt.35t.next_gate.v2"
            and gate_json.get("run_id") == validation_run_id
            and gate_json.get("trace_records") == 512
            and gate_json.get("trace_profile_policy") == "35t_small_capacity"
            and all_gate_samples_pass(gate_json)
        ),
        "status": gate_report.get("reason", "checked"),
        "validation_run_id": validation_run_id,
    }

    fd_flow = check_json("fd_path_flow_summary.json")
    fd_json = fd_flow.get("json", {}) if fd_flow.get("ok") else {}
    checks["fd_path_flow"] = {
        "ok": bool(fd_flow.get("ok") and fd_json.get("schema") == "rvmt.fd_path_flow.summary.v1" and fd_json.get("status") == "PASS"),
        "status": fd_json.get("status", fd_flow.get("reason", "checked")),
    }

    process_tree = check_json("process_tree_summary.json")
    process_json = process_tree.get("json", {}) if process_tree.get("ok") else {}
    checks["process_tree"] = {
        "ok": bool(
            process_tree.get("ok")
            and process_json.get("schema") == "rvmt.process_tree.summary.v1"
            and process_json.get("status") == "PASS"
        ),
        "status": process_json.get("status", process_tree.get("reason", "checked")),
    }

    source_attr = check_json("source_attribution_summary.json")
    source_json = source_attr.get("json", {}) if source_attr.get("ok") else {}
    function_level = source_json.get("function_level", {}) if isinstance(source_json.get("function_level"), dict) else {}
    checks["source_attribution"] = {
        "ok": bool(
            source_attr.get("ok")
            and source_json.get("schema") == "rvmt.35t.source_attribution_summary.v1"
            and source_json.get("status") in {"PASS", "PARTIAL"}
            and function_level.get("status") == "available"
        ),
        "status": source_json.get("status", source_attr.get("reason", "checked")),
    }

    command_log = results_root / "command_log.md"
    checks["command_log"] = {"ok": command_log.exists(), "status": "present" if command_log.exists() else "missing"}
    return checks


def write_report(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "board_validation_status.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    lines = [
        f"# 35T Board Validation Status: {report['source_run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        "Scope: Artix-7 35T / LiteX / VexRiscv only.",
        "",
        f"Hardware validated: {str(report['hardware_validated']).lower()}",
        "",
        "## Plan Check",
        "",
    ]
    for key, ok in report["plan_checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Result Artifacts", ""]
    if not report["result_artifacts"]["results_available"]:
        lines.append("- not checked: no board validation results root was provided")
    elif report["result_artifacts"]["missing"]:
        for item in report["result_artifacts"]["missing"]:
            lines.append(f"- missing: {item}")
    else:
        lines.append("- all required result artifacts present")
    lines += ["", "## Result Content Checks", ""]
    if report["result_content_checks"]:
        for key, row in report["result_content_checks"].items():
            lines.append(f"- {key}: {'PASS' if row.get('ok') else 'FAIL'} ({row.get('status')})")
    else:
        lines.append("- not checked")
    lines += ["", "## Required Capture", ""]
    for item in report["required_capture_items"]:
        lines.append(f"- {item}")
    lines += ["", "## Non-claims", ""]
    for item in report["non_claims"]:
        lines.append(f"- {item}")
    if report["failures"]:
        lines += ["", "## Failures", ""]
        for item in report["failures"]:
            lines.append(f"- {item}")
    (evidence_root / "board_validation_status.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def check_board_validation(
    repo_root: Path,
    evidence_root_arg: Path,
    results_root_arg: Path | None,
    require_results: bool,
    write_outputs: bool,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    plan_path = evidence_root / "board_validation_plan.json"
    failures: list[str] = []
    plan: dict[str, Any] = {}
    if not plan_path.exists():
        failures.append(f"missing board validation plan: {rel(plan_path, repo_root)}")
    else:
        try:
            plan = load_json(plan_path)
        except Exception as exc:
            failures.append(f"invalid board validation plan JSON: {exc}")

    plan_non_claims = plan.get("non_claims", [])
    plan_non_claim_text = "\n".join(str(item) for item in plan_non_claims) if isinstance(plan_non_claims, list) else ""
    plan_checks = {
        "schema": plan.get("schema") == EXPECTED_SCHEMA,
        "source_run_id": plan.get("source_run_id") == RUN_ID,
        "scope": plan.get("scope") == EXPECTED_SCOPE,
        "claim_level": plan.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "status": plan.get("status") == EXPECTED_STATUS,
        "board_validation_required": plan.get("board_validation_required") is True,
        "hardware_validated_false_until_results": plan.get("hardware_validated") is False,
        "non_claims": all(item.lower() in plan_non_claim_text.lower() for item in REQUIRED_NON_CLAIMS),
    }
    for key, ok in plan_checks.items():
        if not ok:
            failures.append(f"board validation plan check failed: {key}")

    results_root = repo_path(repo_root, results_root_arg).resolve() if results_root_arg else None
    missing = []
    results_available = results_root is not None and results_root.exists()
    if results_available and results_root is not None:
        missing = missing_result_artifacts(results_root)
        if missing:
            failures.append("board validation result artifact set is incomplete")
    elif require_results:
        failures.append("board validation results are required but no results root exists")
        missing = list(REQUIRED_OUTPUT_ARTIFACTS)
    else:
        missing = list(REQUIRED_OUTPUT_ARTIFACTS)

    content_checks: dict[str, Any] = {}
    if results_available and results_root is not None and not missing:
        content_checks = check_result_contents(results_root)
        for key, row in content_checks.items():
            if not row.get("ok"):
                failures.append(f"board validation result content check failed: {key}")

    content_checked = bool(content_checks)
    content_ok = bool(content_checked and all(row.get("ok") for row in content_checks.values()))
    hardware_validated = bool(results_available and not missing and content_ok)
    plan_failed = any("plan check failed" in item for item in failures)
    if plan_failed:
        status = "FAIL"
    elif hardware_validated:
        status = "PASS"
    elif results_available and not missing and content_checked:
        status = "RESULTS_PARTIAL"
    elif require_results:
        status = "FAIL"
    else:
        status = "AWAITING_BOARD_RUN"

    report = {
        "schema": "rvmt.35t.board_validation_status.v1",
        "source_run_id": RUN_ID,
        "status": status,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "hardware_validated": hardware_validated,
        "plan_path": rel(plan_path, repo_root),
        "plan_checks": plan_checks,
        "required_capture_items": plan.get("required_capture_items", []),
        "result_artifacts": {
            "results_root": rel(results_root, repo_root) if results_root is not None else None,
            "results_available": results_available,
            "required": REQUIRED_OUTPUT_ARTIFACTS,
            "missing": missing,
        },
        "result_content_checks": content_checks,
        "failures": failures,
        "non_claims": REQUIRED_NON_CLAIMS,
    }
    if write_outputs:
        write_report(report, evidence_root)
    return report


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        evidence.mkdir(parents=True)
        plan = {
            "schema": EXPECTED_SCHEMA,
            "source_run_id": RUN_ID,
            "scope": EXPECTED_SCOPE,
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "status": EXPECTED_STATUS,
            "board_validation_required": True,
            "hardware_validated": False,
            "required_capture_items": ["target-scoped marker begin/end"],
            "non_claims": REQUIRED_NON_CLAIMS,
        }
        (evidence / "board_validation_plan.json").write_text(json.dumps(plan), encoding="utf-8")
        awaiting = check_board_validation(root, DEFAULT_EVIDENCE_ROOT, None, require_results=False, write_outputs=True)
        if awaiting["status"] != "AWAITING_BOARD_RUN":
            print("[FAIL] expected missing board results to be AWAITING_BOARD_RUN", file=sys.stderr)
            return 1
        required = check_board_validation(root, DEFAULT_EVIDENCE_ROOT, None, require_results=True, write_outputs=False)
        if required["status"] != "FAIL":
            print("[FAIL] expected --require-results missing board results to fail", file=sys.stderr)
            return 1
        results = root / "board-results"
        results.mkdir()
        (results / "run_config.json").write_text(
            json.dumps({"run_id": RUN_ID, "trace_records": 512, "trace_profile_policy": "35t_small_capacity"}),
            encoding="utf-8",
        )
        (results / "gate_report.json").write_text(
            json.dumps(
                {
                    "schema": "rvmt.35t.next_gate.v2",
                    "run_id": RUN_ID,
                    "trace_records": 512,
                    "trace_profile_policy": "35t_small_capacity",
                    "sample_status": {"file_scan": {"status": "PASS"}},
                }
            ),
            encoding="utf-8",
        )
        (results / "fd_path_flow_summary.json").write_text(
            json.dumps({"schema": "rvmt.fd_path_flow.summary.v1", "status": "PASS"}),
            encoding="utf-8",
        )
        (results / "process_tree_summary.json").write_text(
            json.dumps({"schema": "rvmt.process_tree.summary.v1", "status": "PASS"}),
            encoding="utf-8",
        )
        (results / "source_attribution_summary.json").write_text(
            json.dumps(
                {
                    "schema": "rvmt.35t.source_attribution_summary.v1",
                    "status": "PARTIAL",
                    "function_level": {"status": "available"},
                }
            ),
            encoding="utf-8",
        )
        for artifact in REQUIRED_OUTPUT_ARTIFACTS:
            path = results / artifact
            if not path.exists():
                path.write_text("ok\n", encoding="utf-8")
        passed = check_board_validation(root, DEFAULT_EVIDENCE_ROOT, results, require_results=True, write_outputs=False)
        if passed["status"] != "PASS" or not passed["hardware_validated"]:
            print("[FAIL] expected complete fake board artifact set to pass", file=sys.stderr)
            return 1
        (results / "fd_path_flow_summary.json").write_text(
            json.dumps({"schema": "rvmt.fd_path_flow.summary.v1", "status": "PARTIAL"}),
            encoding="utf-8",
        )
        partial = check_board_validation(root, DEFAULT_EVIDENCE_ROOT, results, require_results=True, write_outputs=False)
        if partial["status"] != "RESULTS_PARTIAL" or partial["hardware_validated"]:
            print("[FAIL] expected partial fake board artifact set to be RESULTS_PARTIAL", file=sys.stderr)
            print(json.dumps(partial, indent=2), file=sys.stderr)
            return 1
        (results / "fd_path_flow_summary.json").write_text(
            json.dumps({"schema": "rvmt.fd_path_flow.summary.v1", "status": "PASS"}),
            encoding="utf-8",
        )
        alt_run_id = "35t-targeted-board-validation-self-test"
        alt_results = root / "alt-board-results"
        alt_results.mkdir()
        for artifact in REQUIRED_OUTPUT_ARTIFACTS:
            shutil.copyfile(results / artifact, alt_results / artifact)
        (alt_results / "run_config.json").write_text(
            json.dumps({"run_id": alt_run_id, "trace_records": 512, "trace_profile_policy": "35t_small_capacity"}),
            encoding="utf-8",
        )
        (alt_results / "gate_report.json").write_text(
            json.dumps(
                {
                    "schema": "rvmt.35t.next_gate.v2",
                    "run_id": alt_run_id,
                    "trace_records": 512,
                    "trace_profile_policy": "35t_small_capacity",
                    "sample_status": {"file_scan": {"status": "PASS"}},
                }
            ),
            encoding="utf-8",
        )
        (alt_results / "bundle_manifest.json").write_text(
            json.dumps(
                {
                    "schema": "rvmt.35t.board_validation_bundle.v1",
                    "source_run_id": RUN_ID,
                    "validation_run_id": alt_run_id,
                    "scope": EXPECTED_SCOPE,
                    "claim_level": EXPECTED_CLAIM_LEVEL,
                }
            ),
            encoding="utf-8",
        )
        alt_passed = check_board_validation(root, DEFAULT_EVIDENCE_ROOT, alt_results, require_results=True, write_outputs=False)
        if alt_passed["status"] != "PASS" or not alt_passed["hardware_validated"]:
            print("[FAIL] expected alternate validation_run_id bundle to pass", file=sys.stderr)
            print(json.dumps(alt_passed, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T board validation checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the 35T targeted board-validation plan and optional result bundle.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--require-results", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        report = check_board_validation(args.repo_root, args.evidence_root, args.results_root, args.require_results, True)
    except Exception as exc:
        print(f"check_35t_board_validation: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T board validation status")
    for failure in report["failures"]:
        print(f"FAIL: {failure}", file=sys.stderr)
    if report["status"] == "PASS":
        return 0
    if report["status"] in {"AWAITING_BOARD_RUN", "RESULTS_PARTIAL"} and not args.require_results:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
