from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_ASSESSMENT = Path("D:/Download/rv_maltrace_35t_assessment.md")
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
DEFAULT_PAPER_EVIDENCE_DOC = Path("docs/results/rv_maltrace_35t_paper_evidence.md")
DEFAULT_CLOSURE_DOC = Path("docs/results/rv_maltrace_35t_application_closure.md")
DEFAULT_EVALUATION_PLAN = Path("docs/research/evaluation_plan.md")
SCHEMA = "rvmt.35t.paper_positioning.v1"
STATUS = "BOUNDED_FEASIBILITY_POSITIONING_READY"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
SUPPORTED_POSITIONING = [
    "prototype feasibility",
    "small-capacity trace policy evaluation",
    "low-cost board case study",
    "engineering validation before CVA6",
    "low-cost FPGA feasibility / constrained-board prototype evaluation",
]
FORBIDDEN_POSITIONING = [
    "main malware detection result",
    "main real-world malware analysis dataset",
    "main architecture validation for CVA6",
    "main CCF-A contribution by itself",
    "real malware detection accuracy",
    "CVA6 validation",
    "complete semantic reconstruction",
    "mature detector",
]
REQUIRED_NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]
POSITIVE_FORBIDDEN_PATTERNS = [
    re.compile(r"\bcurrent\s+35T\s+line\s+(?:is\s+)?(?:sufficient|enough)\s+to\s+support\s+(?:the\s+)?CCF-A\s+main", re.IGNORECASE),
    re.compile(r"\b35T\s+(?:alone|by itself)\s+(?:supports|is sufficient for)\s+(?:a\s+)?CCF-A", re.IGNORECASE),
    re.compile(r"\bRV-MalTrace\s+detects\s+real\s+malware\b", re.IGNORECASE),
    re.compile(r"\breal\s+malware\s+detection\s+accuracy\s+(?:is|was|has been)\s+(?:measured|reported|validated)\b", re.IGNORECASE),
    re.compile(r"\bcurrent\s+result\s+validates\s+CVA6\b", re.IGNORECASE),
    re.compile(r"\bcomplete\s+semantic\s+reconstruction\s+(?:is|was|has been)\s+(?:achieved|validated|proven)\b", re.IGNORECASE),
]
NEGATION_MARKERS = [
    "no ",
    "not ",
    "does not",
    "do not",
    "cannot",
    "forbidden",
    "non-claim",
    "what this does not prove",
    "do not claim",
    "do not use wording",
    "not a",
    "not sufficient",
    "不足以",
    "不能",
    "不应",
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
    if not path.is_file():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return {}
    try:
        return load_json(path)
    except Exception as exc:
        failures.append(f"invalid {label}: {rel(path, repo_root)}: {exc}")
        return {}


def read_text(path: Path, failures: list[str], repo_root: Path, label: str) -> str:
    if not path.is_file():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return ""
    return path.read_text(encoding="utf-8")


def contains_all(text: str, tokens: list[str]) -> bool:
    return all(token in text for token in tokens)


def contains_any(text: str, tokens: list[str]) -> bool:
    return any(token in text for token in tokens)


def list_contains_all(values: Any, tokens: list[str]) -> bool:
    text = "\n".join(str(value) for value in values if value) if isinstance(values, list) else ""
    return contains_all(text, tokens)


def no_positive_forbidden_claims(*texts: str) -> tuple[bool, list[str]]:
    findings: list[str] = []
    for text in texts:
        lowered = text.lower()
        for pattern in POSITIVE_FORBIDDEN_PATTERNS:
            for match in pattern.finditer(text):
                context = lowered[max(0, match.start() - 240) : min(len(lowered), match.end() + 120)]
                if any(marker in context for marker in NEGATION_MARKERS):
                    continue
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end == -1:
                    line_end = len(text)
                findings.append(text[line_start:line_end].strip())
    return not findings, findings


def build_report(
    repo_root: Path,
    assessment_arg: Path,
    evidence_root_arg: Path,
    paper_doc_arg: Path,
    closure_doc_arg: Path,
    evaluation_plan_arg: Path,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    failures: list[str] = []
    assessment = read_text(repo_path(repo_root, assessment_arg), failures, repo_root, "assessment document")
    paper_doc = read_text(repo_path(repo_root, paper_doc_arg), failures, repo_root, "paper evidence document")
    closure_doc = read_text(repo_path(repo_root, closure_doc_arg), failures, repo_root, "application closure document")
    evaluation_plan = read_text(repo_path(repo_root, evaluation_plan_arg), failures, repo_root, "evaluation plan")
    paper = read_json(evidence_root / "paper_evidence_check.json", failures, repo_root, "paper evidence check")
    closure = read_json(evidence_root / "assessment_closure.json", failures, repo_root, "assessment closure")
    traceability = read_json(evidence_root / "assessment_traceability.json", failures, repo_root, "assessment traceability")
    remaining = read_json(evidence_root / "remaining_external_work.json", failures, repo_root, "remaining external work")

    no_positive, positive_findings = no_positive_forbidden_claims(paper_doc, closure_doc, evaluation_plan)
    supported_claims = paper.get("supported_claims", [])
    forbidden_claims = paper.get("forbidden_claims", [])
    non_claims = paper.get("non_claims", [])
    limitations = paper.get("limitations", [])
    remaining_records = remaining.get("records", []) if isinstance(remaining.get("records"), list) else []
    remaining_ids = {str(row.get("id")) for row in remaining_records if isinstance(row, dict)}
    checks = {
        "assessment_has_ccfa_boundary": "35T 线不足以单独支撑 CCF-A 主论文观点" in assessment
        and "main CCF-A contribution by itself" in assessment,
        "assessment_has_supported_positioning": contains_all(assessment, SUPPORTED_POSITIONING),
        "assessment_has_forbidden_positioning": contains_all(assessment, FORBIDDEN_POSITIONING),
        "paper_status_bounded": paper.get("paper_support_status") == "SUPPORTED_WITH_BOUNDED_CLAIMS",
        "paper_claim_level": paper.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "paper_scope": paper.get("scope") == EXPECTED_SCOPE,
        "paper_supported_claims_limited": contains_any(
            "\n".join(str(item) for item in supported_claims if item),
            [
                "prototype scope",
                "controlled benign and synthetic malware-like workload matrix",
                "real-malware-derived behavior evidence",
                "512-record 35T small-capacity",
                "targeted dual-channel validation bundle",
            ],
        ),
        "paper_forbidden_claims_present": contains_all(
            "\n".join(str(item) for item in forbidden_claims if item),
            [
                "CVA6 validation",
                "uncontrolled or network-enabled real-malware payload execution",
                "payload equivalence",
                "classifier accuracy",
                "mature production detector readiness",
                "complete semantic reconstruction",
            ],
        ),
        "paper_non_claims_present": list_contains_all(non_claims, REQUIRED_NON_CLAIMS),
        "paper_limitations_dual_channel": any(
            "side-channel semantic capture is not itself a strict single-trace all-gates PASS" in str(item)
            for item in limitations
        ),
        "paper_doc_supported_wording": "bounded prototype paper claim" in paper_doc
        and "35T hardware-trace-assisted malware-behavior evidence-chain prototype" in paper_doc,
        "paper_doc_forbidden_wording": "Forbidden Wording" in paper_doc
        and "single-trace all-gates PASS for the side-channel semantic capture" in paper_doc,
        "closure_doc_has_recommended_wording": "Recommended Paper Wording" in closure_doc
        and EXPECTED_CLAIM_LEVEL in closure_doc,
        "evaluation_plan_keeps_ccfa_non_goal": "Do not treat the committed-event MVP alone as sufficient for a CCF-A" in evaluation_plan,
        "evaluation_plan_separates_35t_from_cva6": "35T line has a separate LiteX/VexRiscv experiment route" in evaluation_plan,
        "assessment_closure_bounded": closure.get("status") == "PASS_WITH_BOUNDED_REMAINING_WORK",
        "assessment_traceability_bounded": traceability.get("status") == "PASS_WITH_BOUNDED_REMAINING_WORK",
        "remaining_external_work_recorded": remaining.get("status") == "PASS_CURRENT_EXTERNAL_CONDITIONS_RECORDED",
        "remaining_records_cover_positioning_blockers": {
            "p3_hardware_user_pointer_snapshot",
            "p5_extension_35t_gating",
            "p6_full_raw_artifact_release",
        }
        <= remaining_ids,
        "no_positive_forbidden_claims": no_positive,
    }
    for key, ok in checks.items():
        if not ok:
            failures.append(key)
    failures.extend(f"positive forbidden claim: {item}" for item in positive_findings)

    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "status": STATUS if not failures else "FAIL",
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "checks": checks,
        "supported_positioning": SUPPORTED_POSITIONING,
        "forbidden_positioning": FORBIDDEN_POSITIONING,
        "evidence": {
            "assessment_source": str(repo_path(repo_root, assessment_arg)),
            "paper_evidence_check": rel(evidence_root / "paper_evidence_check.json", repo_root),
            "paper_evidence_doc": rel(repo_path(repo_root, paper_doc_arg), repo_root),
            "application_closure_doc": rel(repo_path(repo_root, closure_doc_arg), repo_root),
            "evaluation_plan": rel(repo_path(repo_root, evaluation_plan_arg), repo_root),
            "assessment_closure": rel(evidence_root / "assessment_closure.json", repo_root),
            "assessment_traceability": rel(evidence_root / "assessment_traceability.json", repo_root),
            "remaining_external_work": rel(evidence_root / "remaining_external_work.json", repo_root),
        },
        "interpretation": [
            "35T evidence supports a bounded feasibility/constrained-board prototype result",
            "35T evidence does not by itself support a CCF-A main contribution, malware-family accuracy, CVA6 validation, or complete reconstruction claim",
            "paper-facing wording must keep the dual-channel trace-gate and side-channel semantic evidence separated",
        ],
        "positive_forbidden_findings": positive_findings,
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Paper Positioning: {report['run_id']}",
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
    lines += ["", "## Supported Positioning", ""]
    lines.extend(f"- {item}" for item in report["supported_positioning"])
    lines += ["", "## Forbidden Positioning", ""]
    lines.extend(f"- {item}" for item in report["forbidden_positioning"])
    lines += ["", "## Evidence", ""]
    for key, value in report["evidence"].items():
        lines.append(f"- {key}: `{value}`")
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Positive Forbidden Findings", ""]
    lines.extend(f"- {item}" for item in report["positive_forbidden_findings"] or ["none"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "paper_positioning.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "paper_positioning.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_fixture(root: Path, *, bad_positive: bool = False) -> Path:
    evidence = root / DEFAULT_EVIDENCE_ROOT
    assessment = root / "assessment.md"
    assessment.write_text(
        "\n".join(
            [
                "35T 线不足以单独支撑 CCF-A 主论文观点。",
                "low-cost FPGA feasibility / constrained-board prototype evaluation",
                "main CCF-A contribution by itself",
                *SUPPORTED_POSITIONING,
                *FORBIDDEN_POSITIONING,
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    paper_doc = root / DEFAULT_PAPER_EVIDENCE_DOC
    paper_doc.parent.mkdir(parents=True, exist_ok=True)
    paper_doc.write_text(
        "# Paper\n\nThe current evidence supports a bounded prototype paper claim.\n"
        "35T hardware-trace-assisted malware-behavior evidence-chain prototype.\n\n"
        "## Forbidden Wording\n\n- single-trace all-gates PASS for the side-channel semantic capture\n",
        encoding="utf-8",
    )
    closure_doc = root / DEFAULT_CLOSURE_DOC
    closure_doc.parent.mkdir(parents=True, exist_ok=True)
    closure_doc.write_text(
        "## Recommended Paper Wording\n\n"
        f"{EXPECTED_CLAIM_LEVEL}\n"
        + ("Current 35T line is sufficient to support the CCF-A main contribution.\n" if bad_positive else ""),
        encoding="utf-8",
    )
    evaluation_plan = root / DEFAULT_EVALUATION_PLAN
    evaluation_plan.parent.mkdir(parents=True, exist_ok=True)
    evaluation_plan.write_text(
        "Do not treat the committed-event MVP alone as sufficient for a CCF-A submission.\n"
        "35T line has a separate LiteX/VexRiscv experiment route.\n",
        encoding="utf-8",
    )
    write_json(
        evidence / "paper_evidence_check.json",
        {
            "schema": "rvmt.35t.paper_evidence_check.v1",
            "paper_support_status": "SUPPORTED_WITH_BOUNDED_CLAIMS",
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "scope": EXPECTED_SCOPE,
            "supported_claims": [
                "35T / LiteX / VexRiscv prototype scope",
                "controlled benign and synthetic malware-like workload matrix",
                "real-malware-derived behavior evidence",
                "512-record 35T small-capacity primary trace gate with 13/13 sample gate PASS",
                "targeted dual-channel validation bundle",
            ],
            "forbidden_claims": [
                "CVA6 validation",
                "uncontrolled or network-enabled real-malware payload execution",
                "payload equivalence",
                "malware-family detection accuracy, classifier accuracy, family coverage, IOC coverage, or TTP coverage",
                "mature production detector readiness",
                "complete semantic reconstruction",
            ],
            "non_claims": REQUIRED_NON_CLAIMS,
            "limitations": ["The side-channel semantic capture is not itself a strict single-trace all-gates PASS and must not be used as the trace-gate channel."],
        },
    )
    write_json(evidence / "assessment_closure.json", {"schema": "rvmt.35t.assessment_closure.v1", "status": "PASS_WITH_BOUNDED_REMAINING_WORK"})
    write_json(evidence / "assessment_traceability.json", {"schema": "rvmt.35t.assessment_traceability.v1", "status": "PASS_WITH_BOUNDED_REMAINING_WORK"})
    write_json(
        evidence / "remaining_external_work.json",
        {
            "schema": "rvmt.35t.remaining_external_work.v1",
            "status": "PASS_CURRENT_EXTERNAL_CONDITIONS_RECORDED",
            "records": [{"id": item} for item in [
                "p3_hardware_user_pointer_snapshot",
                "p5_extension_35t_gating",
                "p6_full_raw_artifact_release",
            ]],
            "satisfied_conditions": [{"id": "p4_qemu_plugin_baseline"}],
        },
    )
    return assessment


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = write_fixture(root)
        report = build_report(root, assessment, DEFAULT_EVIDENCE_ROOT, DEFAULT_PAPER_EVIDENCE_DOC, DEFAULT_CLOSURE_DOC, DEFAULT_EVALUATION_PLAN)
        if report["status"] != STATUS:
            print("[FAIL] expected paper positioning fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "paper_positioning.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = write_fixture(root, bad_positive=True)
        report = build_report(root, assessment, DEFAULT_EVIDENCE_ROOT, DEFAULT_PAPER_EVIDENCE_DOC, DEFAULT_CLOSURE_DOC, DEFAULT_EVALUATION_PLAN)
        if report["status"] != "FAIL" or "no_positive_forbidden_claims" not in report["failures"]:
            print("[FAIL] expected positive CCF-A overclaim fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assessment = write_fixture(root)
        text = assessment.read_text(encoding="utf-8").replace("low-cost FPGA feasibility / constrained-board prototype evaluation", "generic prototype evaluation")
        assessment.write_text(text, encoding="utf-8")
        report = build_report(root, assessment, DEFAULT_EVIDENCE_ROOT, DEFAULT_PAPER_EVIDENCE_DOC, DEFAULT_CLOSURE_DOC, DEFAULT_EVALUATION_PLAN)
        if report["status"] != "FAIL" or "assessment_has_supported_positioning" not in report["failures"]:
            print("[FAIL] expected missing assessment positioning token fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T paper positioning self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check bounded paper positioning for the 35T assessment evidence.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--assessment", type=Path, default=DEFAULT_ASSESSMENT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--paper-evidence-doc", type=Path, default=DEFAULT_PAPER_EVIDENCE_DOC)
    parser.add_argument("--closure-doc", type=Path, default=DEFAULT_CLOSURE_DOC)
    parser.add_argument("--evaluation-plan", type=Path, default=DEFAULT_EVALUATION_PLAN)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.assessment, args.evidence_root, args.paper_evidence_doc, args.closure_doc, args.evaluation_plan)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_paper_positioning: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T paper positioning")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
