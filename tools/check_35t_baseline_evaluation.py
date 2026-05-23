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
SUMMARY_NAME = "baseline_evaluation_summary.json"
EXPECTED_SCHEMA = "rvmt.35t.baseline_evaluation.summary.v1"
HOST_QEMU_STRACE_STATUS = "HOST_QEMU_STRACE_BASELINE_PASS_WITH_MISSING_ADVANCED_BASELINES"
SOFTWARE_INSTRUMENTATION_STATUS = "HOST_QEMU_STRACE_AND_SOFTWARE_INSTRUMENTATION_PASS_WITH_MISSING_EBPF_QEMU_PLUGIN"
SOFTWARE_INSTRUMENTATION_AND_EBPF_STATUS = "HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_AND_EBPF_PASS_WITH_MISSING_QEMU_PLUGIN"
SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS = "HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS"
EXPECTED_STATUSES = {
    HOST_QEMU_STRACE_STATUS,
    SOFTWARE_INSTRUMENTATION_STATUS,
    SOFTWARE_INSTRUMENTATION_AND_EBPF_STATUS,
    SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS,
}
GROUNDTRUTH_BASELINES = ("host_native", "host_strace", "qemu_native", "qemu_strace")
ADVANCED_BASELINES = ("ebpf_only", "qemu_plugin")
REQUIRED_NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]
REPORTED_BASELINES = {"ebpf_only": "eBPF-only", "qemu_plugin": "QEMU plugin", "software_instrumentation": "software instrumentation"}
FORBIDDEN_POSITIVE_CLAIMS = (
    re.compile(r"\breal malware detection accuracy\b", re.IGNORECASE),
    re.compile(r"\breal malware detector\b", re.IGNORECASE),
    re.compile(r"\bvalidated CVA6\b", re.IGNORECASE),
    re.compile(r"\bcomplete semantic reconstruction\b", re.IGNORECASE),
)


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


def contains_non_claims(summary: dict[str, Any]) -> bool:
    text = "\n".join(str(item) for item in summary.get("non_claims", []) if item)
    return all(item in text for item in REQUIRED_NON_CLAIMS)


def positive_claim_findings(summary: dict[str, Any]) -> list[str]:
    text = json.dumps(summary, sort_keys=True)
    findings = []
    for pattern in FORBIDDEN_POSITIVE_CLAIMS:
        for match in pattern.finditer(text):
            context = text[max(0, match.start() - 180) : min(len(text), match.end() + 120)].lower()
            if any(marker in context for marker in ("no ", "not ", "does not", "non-claim", "forbidden", "must not")):
                continue
            findings.append(match.group(0))
            break
    return findings


def check_summary(summary: dict[str, Any]) -> dict[str, Any]:
    baselines = summary.get("baselines", {}) if isinstance(summary.get("baselines"), dict) else {}
    samples = summary.get("samples", []) if isinstance(summary.get("samples"), list) else []
    summary_status = summary.get("status")
    software = baselines.get("software_instrumentation", {})
    software_pass = (
        isinstance(software, dict)
        and software.get("status") == "PASS"
        and software.get("samples_with_evidence") == 13
        and bool(software.get("evidence"))
    )
    ebpf = baselines.get("ebpf_only", {})
    ebpf_pass = (
        isinstance(ebpf, dict)
        and ebpf.get("status") == "PASS"
        and ebpf.get("samples_with_evidence") == 13
        and bool(ebpf.get("evidence"))
    )
    qemu = baselines.get("qemu_plugin", {})
    qemu_not_pass = not (isinstance(qemu, dict) and qemu.get("status") == "PASS")
    qemu_pass = (
        isinstance(qemu, dict)
        and qemu.get("status") == "PASS"
        and qemu.get("samples_with_evidence") == 13
        and bool(qemu.get("evidence"))
    )
    checks = {
        "schema": summary.get("schema") == EXPECTED_SCHEMA,
        "run_id": summary.get("run_id") == RUN_ID,
        "status": summary_status in EXPECTED_STATUSES,
        "sample_count": summary.get("sample_count") == 13 and len(samples) == 13,
        "groundtruth_baselines_pass": all(
            isinstance(baselines.get(name), dict)
            and baselines[name].get("status") == "PASS"
            and baselines[name].get("samples_with_evidence") == 13
            for name in GROUNDTRUTH_BASELINES
        ),
        "qemu_plugin_status_consistent": (
            (summary_status == SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS and qemu_pass)
            or (summary_status != SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS and qemu_not_pass)
        ),
        "software_instrumentation_status_consistent": (
            (
                summary_status
                in {
                    SOFTWARE_INSTRUMENTATION_STATUS,
                    SOFTWARE_INSTRUMENTATION_AND_EBPF_STATUS,
                    SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS,
                }
                and software_pass
            )
            or (
                summary_status == HOST_QEMU_STRACE_STATUS
                and not (isinstance(software, dict) and software.get("status") == "PASS")
            )
        ),
        "ebpf_status_consistent": (
            (summary_status == SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS and ebpf_pass and qemu_pass)
            or (summary_status == SOFTWARE_INSTRUMENTATION_AND_EBPF_STATUS and ebpf_pass and qemu_not_pass)
            or (summary_status in {HOST_QEMU_STRACE_STATUS, SOFTWARE_INSTRUMENTATION_STATUS} and not ebpf_pass and qemu_not_pass)
        ),
        "sample_groundtruth_complete": all(
            isinstance(row, dict) and not row.get("missing_groundtruth") for row in samples
        ),
        "non_claims": contains_non_claims(summary),
        "no_positive_forbidden_claims": not positive_claim_findings(summary),
    }
    return checks


def build_report(repo_root: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    summary_path = evidence_root / SUMMARY_NAME
    failures: list[str] = []
    if not summary_path.exists():
        failures.append(f"missing baseline summary: {rel(summary_path, repo_root)}")
        summary: dict[str, Any] = {}
    else:
        try:
            summary = load_json(summary_path)
        except Exception as exc:
            failures.append(f"invalid baseline summary: {rel(summary_path, repo_root)}: {exc}")
            summary = {}

    checks = check_summary(summary)
    for key, ok in checks.items():
        if not ok:
            failures.append(f"baseline evaluation check failed: {key}")

    baselines = summary.get("baselines", {}) if isinstance(summary.get("baselines"), dict) else {}
    advanced_status = {
        label: baselines.get(key, {}).get("status") if isinstance(baselines.get(key), dict) else "MISSING"
        for key, label in REPORTED_BASELINES.items()
    }
    return {
        "schema": "rvmt.35t.baseline_evaluation.check.v1",
        "status": "PASS" if not failures else "FAIL",
        "run_id": RUN_ID,
        "summary": rel(summary_path, repo_root),
        "checks": checks,
        "groundtruth_baselines": {
            name: baselines.get(name, {}) for name in GROUNDTRUTH_BASELINES
        },
        "advanced_baselines": advanced_status,
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Baseline Evaluation Check: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Summary: `{report['summary']}`",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Advanced Baseline Status", ""]
    for key, status in report["advanced_baselines"].items():
        lines.append(f"- {key}: {status}")
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_report(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "baseline_evaluation_check.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "baseline_evaluation_check.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_summary_fixture(
    path: Path,
    *,
    software_pass: bool = False,
    ebpf_pass: bool = False,
    forbidden_qemu_pass: bool = False,
    valid_qemu_pass: bool = False,
) -> None:
    baselines = {
        name: {"status": "PASS", "samples_with_evidence": 13, "sample_count": 13}
        for name in GROUNDTRUTH_BASELINES
    }
    baselines["ebpf_only"] = {
        "status": "PASS" if ebpf_pass else "NOT_RUN",
        "samples_with_evidence": 13 if ebpf_pass else 0,
        "sample_count": 13,
        "evidence": "ebpf_baseline_summary.json" if ebpf_pass else "not present in current committed/local 35T evidence",
    }
    baselines["qemu_plugin"] = {
        "status": "PASS" if forbidden_qemu_pass or valid_qemu_pass else "NOT_RUN",
        "samples_with_evidence": 13 if forbidden_qemu_pass or valid_qemu_pass else 0,
        "sample_count": 13,
        "evidence": "qemu_plugin_baseline_summary.json" if forbidden_qemu_pass or valid_qemu_pass else "not present in current committed/local 35T evidence",
    }
    baselines["software_instrumentation"] = {
        "status": "PASS" if software_pass else "NOT_RUN",
        "samples_with_evidence": 13 if software_pass else 0,
        "sample_count": 13,
        "evidence": "software_instrumentation_baseline_summary.json" if software_pass else "not present in current committed/local 35T evidence",
    }
    samples = [
        {"sample_id": f"sample_{index}", "missing_groundtruth": []}
        for index in range(13)
    ]
    if software_pass and ebpf_pass and valid_qemu_pass:
        status = SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_STATUS
    elif software_pass and ebpf_pass:
        status = SOFTWARE_INSTRUMENTATION_AND_EBPF_STATUS
    elif software_pass:
        status = SOFTWARE_INSTRUMENTATION_STATUS
    else:
        status = HOST_QEMU_STRACE_STATUS
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": EXPECTED_SCHEMA,
                "run_id": RUN_ID,
                "status": status,
                "sample_count": 13,
                "baselines": baselines,
                "samples": samples,
                "non_claims": REQUIRED_NON_CLAIMS,
                "limitations": ["QEMU-plugin baseline must not be described as PASS without evidence"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        write_summary_fixture(evidence / SUMMARY_NAME)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "PASS":
            print("[FAIL] expected valid baseline summary fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_report(report, evidence)
        if not (evidence / "baseline_evaluation_check.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        write_summary_fixture(evidence / SUMMARY_NAME, software_pass=True)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "PASS":
            print("[FAIL] expected software instrumentation baseline summary fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        write_summary_fixture(evidence / SUMMARY_NAME, software_pass=True, ebpf_pass=True)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "PASS":
            print("[FAIL] expected eBPF baseline summary fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        write_summary_fixture(evidence / SUMMARY_NAME, software_pass=True, ebpf_pass=True, valid_qemu_pass=True)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "PASS":
            print("[FAIL] expected valid QEMU-plugin baseline summary fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        write_summary_fixture(evidence / SUMMARY_NAME, software_pass=True, ebpf_pass=True, forbidden_qemu_pass=True)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL":
            print("[FAIL] expected QEMU-plugin PASS overclaim to fail", file=sys.stderr)
            return 1
    print("[PASS] 35T baseline evaluation check self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check bounded 35T baseline evaluation evidence.")
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
            write_report(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_baseline_evaluation: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T baseline evaluation check")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
