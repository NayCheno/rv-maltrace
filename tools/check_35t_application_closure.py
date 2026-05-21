from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
EXPECTED_FIELDS: dict[str, Any] = {
    "run_id": RUN_ID,
    "trace_records": 512,
    "trace_profile_policy": "35t_small_capacity",
    "samples": 13,
    "gate": "13/13 PASS",
    "full_matrix_ready": True,
}
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
REQUIRED_NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]
REQUIRED_CASE_STUDIES = [
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
]
CASE_STUDY_ALTERNATIVES = [["file_scan", "batch_open_read_write"]]
FORBIDDEN_PATTERNS = [
    "real malware detector",
    "real-malware detector",
    "real malware detection accuracy",
    "real malware accuracy",
    "validated CVA6",
    "CVA6 validation",
    "mature detector",
    "complete semantic reconstruction",
    "malware family coverage",
    "IOC coverage",
    "TTP coverage",
]
NEGATION_MARKERS = [
    "no ",
    "not ",
    "does not",
    "do not",
    "without",
    "forbidden",
    "non-claim",
    "non_claim",
    "nonclaims",
    "what this does not prove",
    "what is not included",
    "do not use wording",
    "cannot",
    "can't",
    "doesn't",
    "is not",
    "are not",
    "never",
    "明确不包含",
    "不能声称",
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


def text_contains_value(text: str, key: str, expected: Any) -> bool:
    if isinstance(expected, bool):
        pattern = rf"{re.escape(key)}\s*:\s*{expected}"
        return re.search(pattern, text, flags=re.IGNORECASE) is not None
    pattern = rf"{re.escape(key)}\s*:\s*{re.escape(str(expected))}"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def find_forbidden_positive_claims(text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    lowered = text.lower()
    for phrase in FORBIDDEN_PATTERNS:
        pattern = re.compile(re.escape(phrase.lower()), flags=re.IGNORECASE)
        for match in pattern.finditer(text):
            before = lowered[max(0, match.start() - 140) : match.start()]
            section_before = lowered[max(0, match.start() - 600) : match.start()]
            after = lowered[match.end() : min(len(text), match.end() + 80)]
            context = before + lowered[match.start() : match.end()] + after
            if any(marker in context for marker in NEGATION_MARKERS) or "do not use wording" in section_before:
                continue
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end == -1:
                line_end = len(text)
            findings.append({"phrase": phrase, "context": text[line_start:line_end].strip()})
    return findings


def write_report(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    json_path = evidence_root / "application_closure_check.json"
    md_path = evidence_root / "application_closure_check.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

    lines = [
        f"# 35T Application Closure Check: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        "## Checked Files",
        "",
    ]
    for item in report["checked_files"]:
        lines.append(f"- {item}")
    lines += ["", "## Required Fields", ""]
    for key, row in report["required_fields"].items():
        status = "PASS" if row.get("ok") else "FAIL"
        lines.append(f"- {key}: {status}")
    lines += ["", "## Case Study Coverage", ""]
    for key, row in report["case_study_coverage"].items():
        status = "PASS" if row.get("ok") else "FAIL"
        lines.append(f"- {key}: {status}")
    lines += ["", "## Non-claims", ""]
    for key, present in report["non_claims"].items():
        status = "PASS" if present else "FAIL"
        lines.append(f"- {key}: {status}")
    lines += ["", "## Explanation Readiness", ""]
    readiness = report.get("explanation_readiness", {})
    lines.append(f"- schema: {'PASS' if readiness.get('schema_ok') else 'FAIL'}")
    lines.append(f"- status: {readiness.get('status')}")
    lines.append(f"- board_validation_required: {'PASS' if readiness.get('board_validation_required_ok') else 'FAIL'}")
    lines += ["", "## Source Attribution", ""]
    source_attr = report.get("source_attribution", {})
    lines.append(f"- schema: {'PASS' if source_attr.get('schema_ok') else 'FAIL'}")
    lines.append(f"- status: {source_attr.get('status')}")
    lines.append(f"- function_level: {source_attr.get('function_level')}")
    lines += ["", "## Board Validation Attempt", ""]
    board_attempt = report.get("board_validation_attempt", {})
    lines.append(f"- schema: {'PASS' if board_attempt.get('schema_ok') else 'FAIL'}")
    lines.append(f"- status: {board_attempt.get('status')}")
    lines.append(f"- hardware_validated_consistent: {'PASS' if board_attempt.get('hardware_validated_consistent') else 'FAIL'}")
    lines += ["", "## Board Validation Status", ""]
    board_status = report.get("board_validation_status", {})
    lines.append(f"- schema: {'PASS' if board_status.get('schema_ok') else 'FAIL'}")
    lines.append(f"- status: {board_status.get('status')}")
    lines.append(f"- hardware_validated: {board_status.get('hardware_validated')}")
    lines += ["", "## Board Validation Runbook", ""]
    board_runbook = report.get("board_validation_runbook", {})
    lines.append(f"- schema: {'PASS' if board_runbook.get('schema_ok') else 'FAIL'}")
    lines.append(f"- status: {board_runbook.get('status')}")
    lines.append(f"- hardware_required: {'PASS' if board_runbook.get('hardware_required_ok') else 'FAIL'}")
    lines += ["", "## Board Validation Preflight", ""]
    board_preflight = report.get("board_validation_preflight", {})
    lines.append(f"- schema: {'PASS' if board_preflight.get('schema_ok') else 'FAIL'}")
    lines.append(f"- status: {board_preflight.get('status')}")
    lines.append(f"- hardware_ready_consistent: {'PASS' if board_preflight.get('hardware_ready_consistent') else 'FAIL'}")
    lines.append(f"- hardware_ready_basis: {'PASS' if board_preflight.get('hardware_ready_basis_ok') else 'FAIL'}")
    lines += ["", "## Warnings", ""]
    if report["warnings"]:
        for item in report["warnings"]:
            lines.append(f"- {item}")
    else:
        lines.append("- none")
    lines += ["", "## Failures", ""]
    if report["failures"]:
        for item in report["failures"]:
            lines.append(f"- {item}")
    else:
        lines.append("- none")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def check_repo(repo_root: Path, evidence_root_arg: Path, write_outputs: bool) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    closure_path = repo_root / "docs/results/rv_maltrace_35t_application_closure.md"
    case_path = repo_root / "docs/results/rv_maltrace_35t_application_case_studies.md"
    manifest_path = evidence_root / "evidence_manifest.json"
    readiness_path = evidence_root / "explanation_readiness_summary.json"
    board_attempt_path = evidence_root / "board_validation_attempt_summary.json"
    board_status_path = evidence_root / "board_validation_status.json"
    board_runbook_path = evidence_root / "board_validation_runbook.json"
    board_preflight_path = evidence_root / "board_validation_preflight.json"
    source_attr_path = evidence_root / "source_attribution_summary.json"
    checked = [
        closure_path,
        case_path,
        manifest_path,
        readiness_path,
        source_attr_path,
        board_attempt_path,
        board_status_path,
        board_runbook_path,
        board_preflight_path,
    ]
    failures: list[str] = []
    warnings: list[str] = []

    for path in checked:
        if not path.exists():
            failures.append(f"missing required file: {rel(path, repo_root)}")

    closure_text = closure_path.read_text(encoding="utf-8") if closure_path.exists() else ""
    case_text = case_path.read_text(encoding="utf-8") if case_path.exists() else ""
    manifest: dict[str, Any] = {}
    if manifest_path.exists():
        try:
            manifest = load_json(manifest_path)
        except Exception as exc:  # pragma: no cover - covered through CLI behavior
            failures.append(f"invalid manifest JSON: {exc}")
    readiness: dict[str, Any] = {}
    if readiness_path.exists():
        try:
            readiness = load_json(readiness_path)
        except Exception as exc:  # pragma: no cover - covered through CLI behavior
            failures.append(f"invalid explanation readiness JSON: {exc}")
    board_status: dict[str, Any] = {}
    board_attempt: dict[str, Any] = {}
    if board_attempt_path.exists():
        try:
            board_attempt = load_json(board_attempt_path)
        except Exception as exc:  # pragma: no cover - covered through CLI behavior
            failures.append(f"invalid board validation attempt summary JSON: {exc}")
    if board_status_path.exists():
        try:
            board_status = load_json(board_status_path)
        except Exception as exc:  # pragma: no cover - covered through CLI behavior
            failures.append(f"invalid board validation status JSON: {exc}")
    board_runbook: dict[str, Any] = {}
    if board_runbook_path.exists():
        try:
            board_runbook = load_json(board_runbook_path)
        except Exception as exc:  # pragma: no cover - covered through CLI behavior
            failures.append(f"invalid board validation runbook JSON: {exc}")
    board_preflight: dict[str, Any] = {}
    if board_preflight_path.exists():
        try:
            board_preflight = load_json(board_preflight_path)
        except Exception as exc:  # pragma: no cover - covered through CLI behavior
            failures.append(f"invalid board validation preflight JSON: {exc}")
    source_attr: dict[str, Any] = {}
    if source_attr_path.exists():
        try:
            source_attr = load_json(source_attr_path)
        except Exception as exc:  # pragma: no cover - covered through CLI behavior
            failures.append(f"invalid source attribution summary JSON: {exc}")

    combined_text = "\n".join(
        [
            closure_text,
            case_text,
            json.dumps(manifest, sort_keys=True),
            json.dumps(readiness, sort_keys=True),
            json.dumps(source_attr, sort_keys=True),
            json.dumps(board_attempt, sort_keys=True),
            json.dumps(board_status, sort_keys=True),
            json.dumps(board_runbook, sort_keys=True),
            json.dumps(board_preflight, sort_keys=True),
        ]
    )
    field_results: dict[str, Any] = {}
    for key, expected in EXPECTED_FIELDS.items():
        manifest_value = manifest.get(key)
        manifest_ok = manifest_value == expected
        closure_ok = text_contains_value(closure_text, key, expected)
        case_ok = text_contains_value(case_text, key, expected)
        ok = manifest_ok and closure_ok and case_ok
        field_results[key] = {
            "expected": expected,
            "manifest_value": manifest_value,
            "manifest_ok": manifest_ok,
            "closure_doc_ok": closure_ok,
            "case_study_doc_ok": case_ok,
            "ok": ok,
        }
        if not ok:
            failures.append(f"field mismatch or missing: {key}")

    claim_level_ok = EXPECTED_CLAIM_LEVEL in combined_text
    if not claim_level_ok:
        failures.append("expected 35T synthetic prototype claim level is missing")
    if manifest.get("real_malware") is not False:
        failures.append("manifest real_malware must be false")
    if manifest.get("cva6_in_scope") is not False:
        failures.append("manifest cva6_in_scope must be false")

    case_lower = case_text.lower()
    coverage: dict[str, Any] = {}
    for item in REQUIRED_CASE_STUDIES:
        ok = item.lower() in case_lower
        coverage[item] = {"ok": ok, "alternatives": None}
        if not ok:
            failures.append(f"missing required case-study coverage: {item}")
    for alternatives in CASE_STUDY_ALTERNATIVES:
        ok = any(item.lower() in case_lower for item in alternatives)
        key = " or ".join(alternatives)
        coverage[key] = {"ok": ok, "alternatives": alternatives}
        if not ok:
            failures.append(f"missing required case-study alternative coverage: {key}")

    manifest_non_claims = manifest.get("non_claims", [])
    manifest_non_claim_text = "\n".join(str(item) for item in manifest_non_claims) if isinstance(manifest_non_claims, list) else ""
    non_claim_text = "\n".join([closure_text, case_text, manifest_non_claim_text]).lower()
    non_claim_results = {}
    for item in REQUIRED_NON_CLAIMS:
        present = item.lower() in non_claim_text
        non_claim_results[item] = present
        if not present:
            failures.append(f"missing required non-claim: {item}")

    forbidden_findings = find_forbidden_positive_claims(closure_text + "\n" + case_text)
    for finding in forbidden_findings:
        failures.append(f"possible positive forbidden claim `{finding['phrase']}`: {finding['context']}")

    if manifest.get("schema") != "rvmt.35t.evidence_snapshot.v1":
        failures.append("manifest schema must be rvmt.35t.evidence_snapshot.v1")
    if manifest.get("source_results_root") != f"results/experiments/35t/{RUN_ID}":
        failures.append("manifest source_results_root does not point to the primary 35T run")
    if "docs/results/evidence/" not in closure_text:
        failures.append("closure doc does not reference the committed evidence snapshot path")
    readiness_results = {
        "schema_ok": readiness.get("schema") == "rvmt.35t.explanation_readiness.v1",
        "status": readiness.get("status"),
        "status_ok": readiness.get("status") == "READY_FOR_TARGETED_BOARD_VALIDATION",
        "board_validation_required": readiness.get("board_validation_required"),
        "board_validation_required_ok": readiness.get("board_validation_required") is True,
    }
    if not readiness_results["schema_ok"]:
        failures.append("explanation readiness schema must be rvmt.35t.explanation_readiness.v1")
    if not readiness_results["status_ok"]:
        failures.append("explanation readiness status must be READY_FOR_TARGETED_BOARD_VALIDATION")
    if not readiness_results["board_validation_required_ok"]:
        failures.append("explanation readiness must keep board_validation_required true")
    board_attempt_results = {
        "schema_ok": board_attempt.get("schema") == "rvmt.35t.board_validation_attempt_summary.v1",
        "source_run_id_ok": board_attempt.get("source_run_id") == RUN_ID,
        "scope_ok": board_attempt.get("scope") == "Artix-7 35T / LiteX / VexRiscv",
        "claim_level_ok": board_attempt.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "status": board_attempt.get("status"),
        "status_ok": board_attempt.get("status") in {"BOARD_RUN_COMPLETE_VALIDATION_PARTIAL", "BOARD_VALIDATION_PASS"},
        "hardware_validated_consistent": (
            (board_attempt.get("status") == "BOARD_VALIDATION_PASS" and board_attempt.get("hardware_validated") is True)
            or (
                board_attempt.get("status") == "BOARD_RUN_COMPLETE_VALIDATION_PARTIAL"
                and board_attempt.get("hardware_validated") is False
            )
        ),
    }
    for key, ok in board_attempt_results.items():
        if key == "status":
            continue
        if not ok:
            failures.append(f"board validation attempt summary check failed: {key}")
    board_status_results = {
        "schema_ok": board_status.get("schema") == "rvmt.35t.board_validation_status.v1",
        "status": board_status.get("status"),
        "status_ok": board_status.get("status") in {"AWAITING_BOARD_RUN", "RESULTS_PARTIAL", "PASS"},
        "hardware_validated": board_status.get("hardware_validated"),
        "hardware_validated_ok": (
            (board_status.get("status") == "PASS" and board_status.get("hardware_validated") is True)
            or (
                board_status.get("status") in {"AWAITING_BOARD_RUN", "RESULTS_PARTIAL"}
                and board_status.get("hardware_validated") is False
            )
        ),
    }
    if not board_status_results["schema_ok"]:
        failures.append("board validation status schema must be rvmt.35t.board_validation_status.v1")
    if not board_status_results["status_ok"]:
        failures.append("board validation status must be AWAITING_BOARD_RUN, RESULTS_PARTIAL, or PASS")
    if not board_status_results["hardware_validated_ok"]:
        failures.append("board validation hardware_validated flag is inconsistent with status")
    board_runbook_non_claims = board_runbook.get("non_claims", [])
    board_runbook_non_claim_text = "\n".join(str(item) for item in board_runbook_non_claims) if isinstance(board_runbook_non_claims, list) else ""
    board_runbook_results = {
        "schema_ok": board_runbook.get("schema") == "rvmt.35t.board_validation_runbook.v1",
        "source_run_id_ok": board_runbook.get("source_run_id") == RUN_ID,
        "scope_ok": board_runbook.get("scope") == "Artix-7 35T / LiteX / VexRiscv",
        "claim_level_ok": board_runbook.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "hardware_required_ok": board_runbook.get("hardware_required") is True,
        "status": board_runbook.get("status"),
        "status_ok": board_runbook.get("status") == "READY_TO_RUN_ON_35T_BOARD",
        "non_claims_ok": all(item.lower() in board_runbook_non_claim_text.lower() for item in REQUIRED_NON_CLAIMS),
    }
    for key, ok in board_runbook_results.items():
        if key == "status":
            continue
        if not ok:
            failures.append(f"board validation runbook check failed: {key}")
    board_preflight_non_claims = board_preflight.get("non_claims", [])
    board_preflight_non_claim_text = "\n".join(str(item) for item in board_preflight_non_claims) if isinstance(board_preflight_non_claims, list) else ""
    board_preflight_results = {
        "schema_ok": board_preflight.get("schema") == "rvmt.35t.board_validation_preflight.v1",
        "source_run_id_ok": board_preflight.get("source_run_id") == RUN_ID,
        "scope_ok": board_preflight.get("scope") == "Artix-7 35T / LiteX / VexRiscv",
        "claim_level_ok": board_preflight.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "status": board_preflight.get("status"),
        "status_ok": board_preflight.get("status") in {"READY_PENDING_BOARD_CONNECTION", "READY_FOR_BOARD_RUN"},
        "hardware_ready_consistent": (
            (board_preflight.get("status") == "READY_FOR_BOARD_RUN" and board_preflight.get("hardware_ready") is True)
            or (
                board_preflight.get("status") == "READY_PENDING_BOARD_CONNECTION"
                and board_preflight.get("hardware_ready") is False
            )
        ),
        "hardware_ready_basis_ok": "does not prove" in str(board_preflight.get("hardware_ready_basis", "")).lower(),
        "non_claims_ok": all(item.lower() in board_preflight_non_claim_text.lower() for item in REQUIRED_NON_CLAIMS),
    }
    for key, ok in board_preflight_results.items():
        if key == "status":
            continue
        if not ok:
            failures.append(f"board validation preflight check failed: {key}")
    source_attr_results = {
        "schema_ok": source_attr.get("schema") == "rvmt.35t.source_attribution_summary.v1",
        "status": source_attr.get("status"),
        "status_ok": source_attr.get("status") in {"PASS", "PARTIAL"},
        "function_level": source_attr.get("function_level", {}).get("status") if isinstance(source_attr.get("function_level"), dict) else None,
        "function_level_ok": isinstance(source_attr.get("function_level"), dict)
        and source_attr.get("function_level", {}).get("status") == "available",
    }
    if not source_attr_results["schema_ok"]:
        failures.append("source attribution summary schema must be rvmt.35t.source_attribution_summary.v1")
    if not source_attr_results["status_ok"]:
        failures.append("source attribution summary status must be PASS or PARTIAL")
    if not source_attr_results["function_level_ok"]:
        failures.append("source attribution summary must keep function-level attribution available")

    report = {
        "schema": "rvmt.35t.application_closure_check.v1",
        "status": "PASS" if not failures else "FAIL",
        "run_id": RUN_ID,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "checked_files": [rel(path, repo_root) for path in checked],
        "required_fields": field_results,
        "case_study_coverage": coverage,
        "non_claims": non_claim_results,
        "explanation_readiness": readiness_results,
        "source_attribution": source_attr_results,
        "board_validation_attempt": board_attempt_results,
        "board_validation_status": board_status_results,
        "board_validation_runbook": board_runbook_results,
        "board_validation_preflight": board_preflight_results,
        "warnings": warnings,
        "failures": failures,
    }
    if write_outputs:
        write_report(report, evidence_root)
    return report


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        docs = root / "docs/results"
        evidence = root / DEFAULT_EVIDENCE_ROOT
        docs.mkdir(parents=True)
        evidence.mkdir(parents=True)
        field_block = "\n".join(f"{key}: {value}" for key, value in EXPECTED_FIELDS.items())
        non_claims = "\n".join(f"- {item}" for item in REQUIRED_NON_CLAIMS)
        closure = (
            "# Closure\n\n"
            "Scope: Artix-7 35T / LiteX / VexRiscv only.\n\n"
            f"Current claim level: {EXPECTED_CLAIM_LEVEL}\n\n"
            f"{field_block}\n\n"
            f"{non_claims}\n\n"
            f"Committed snapshot: {DEFAULT_EVIDENCE_ROOT.as_posix()}\n"
        )
        cases = (
            "# Case Studies\n\n"
            f"{field_block}\n\n"
            f"{non_claims}\n\n"
            "Case Study: illegal_trap\n\n"
            "Case Study: process_chain\n\n"
            "Case Study: dynamic_executable_memory\n\n"
            "Case Study: file_scan\n"
        )
        (docs / "rv_maltrace_35t_application_closure.md").write_text(closure, encoding="utf-8", newline="\n")
        (docs / "rv_maltrace_35t_application_case_studies.md").write_text(cases, encoding="utf-8", newline="\n")
        manifest = {
            "schema": "rvmt.35t.evidence_snapshot.v1",
            **EXPECTED_FIELDS,
            "scope": "Artix-7 35T / LiteX / VexRiscv",
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "real_malware": False,
            "cva6_in_scope": False,
            "non_claims": REQUIRED_NON_CLAIMS,
            "committed_artifacts": [],
            "missing_artifacts": [],
            "source_results_root": f"results/experiments/35t/{RUN_ID}",
        }
        (evidence / "evidence_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        readiness = {
            "schema": "rvmt.35t.explanation_readiness.v1",
            "status": "READY_FOR_TARGETED_BOARD_VALIDATION",
            "board_validation_required": True,
            "non_claims": REQUIRED_NON_CLAIMS,
        }
        (evidence / "explanation_readiness_summary.json").write_text(json.dumps(readiness), encoding="utf-8")
        source_attr = {
            "schema": "rvmt.35t.source_attribution_summary.v1",
            "status": "PARTIAL",
            "function_level": {"status": "available"},
            "non_claims": REQUIRED_NON_CLAIMS,
        }
        (evidence / "source_attribution_summary.json").write_text(json.dumps(source_attr), encoding="utf-8")
        board_attempt = {
            "schema": "rvmt.35t.board_validation_attempt_summary.v1",
            "source_run_id": RUN_ID,
            "validation_run_id": "35t-targeted-board-validation-self-test",
            "scope": "Artix-7 35T / LiteX / VexRiscv",
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "status": "BOARD_RUN_COMPLETE_VALIDATION_PARTIAL",
            "hardware_validated": False,
            "non_claims": REQUIRED_NON_CLAIMS,
        }
        (evidence / "board_validation_attempt_summary.json").write_text(json.dumps(board_attempt), encoding="utf-8")
        board_status = {
            "schema": "rvmt.35t.board_validation_status.v1",
            "status": "RESULTS_PARTIAL",
            "hardware_validated": False,
            "non_claims": REQUIRED_NON_CLAIMS,
        }
        (evidence / "board_validation_status.json").write_text(json.dumps(board_status), encoding="utf-8")
        board_runbook = {
            "schema": "rvmt.35t.board_validation_runbook.v1",
            "source_run_id": RUN_ID,
            "validation_run_id": "35t-targeted-board-validation-self-test",
            "scope": "Artix-7 35T / LiteX / VexRiscv",
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "hardware_required": True,
            "status": "READY_TO_RUN_ON_35T_BOARD",
            "non_claims": REQUIRED_NON_CLAIMS,
        }
        (evidence / "board_validation_runbook.json").write_text(json.dumps(board_runbook), encoding="utf-8")
        board_preflight = {
            "schema": "rvmt.35t.board_validation_preflight.v1",
            "source_run_id": RUN_ID,
            "validation_run_id": "35t-targeted-board-validation-self-test",
            "scope": "Artix-7 35T / LiteX / VexRiscv",
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "status": "READY_PENDING_BOARD_CONNECTION",
            "hardware_ready": False,
            "hardware_ready_basis": "requested UART port is not visible; this does not prove the 35T board image is running",
            "non_claims": REQUIRED_NON_CLAIMS,
        }
        (evidence / "board_validation_preflight.json").write_text(json.dumps(board_preflight), encoding="utf-8")
        report = check_repo(root, DEFAULT_EVIDENCE_ROOT, write_outputs=True)
        if report["status"] != "PASS":
            print("[FAIL] expected valid self-test fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1

        drift_text = closure + "\nThis validates a real malware detector.\n"
        (docs / "rv_maltrace_35t_application_closure.md").write_text(drift_text, encoding="utf-8", newline="\n")
        drift_report = check_repo(root, DEFAULT_EVIDENCE_ROOT, write_outputs=False)
        if drift_report["status"] != "FAIL":
            print("[FAIL] expected forbidden positive claim fixture to fail", file=sys.stderr)
            return 1
    print("[PASS] 35T application closure self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check 35T application closure docs and evidence snapshot consistency.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    try:
        report = check_repo(args.repo_root, args.evidence_root, write_outputs=True)
    except Exception as exc:
        print(f"check_35t_application_closure: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T application closure check")
    for failure in report["failures"]:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
