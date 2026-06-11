from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_RESOURCE_REPORT = Path("docs/07-evaluation-evidence/reports/resource_report.md")
DEFAULT_EVIDENCE_REPORT = Path("docs/07-evaluation-evidence/reports/genesys2_cva6_evidence_chain_20260610.md")
DEFAULT_BASELINE_TIMING = Path("build/vivado/genesys2-cv64a6_imafdc_sv39/reports/ariane.timing.rpt")
DEFAULT_TRACE_TIMING = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/reports/ariane.timing.rpt")
DEFAULT_SAFE_SUMMARY = Path("results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610/safe_surrogate_summary.json")
DEFAULT_TRACE_WINDOW_DIAGNOSIS = Path("results/board/genesys2_trace_validation/20260609-2345-phase6-syscall-ret-fix/trace_window_diagnosis.md")
DEFAULT_RUNTIME_ATTRIBUTION = Path(
    "results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610/illegal_trap/runtime_process_attribution/summary.json"
)
EXPECTED_BOARD = "Digilent Genesys2"
EXPECTED_CPU = "CVA6"


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def display(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def parse_timing(path: Path) -> tuple[str, float]:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Slack\s+\(([^)]+)\)\s*:\s*([-+]?[0-9]+(?:\.[0-9]+)?)ns", text)
    if not match:
        raise ValueError(f"{path}: no Slack (...) line found")
    return match.group(1), float(match.group(2))


def fmt(value: float) -> str:
    return f"{value:.3f}"


def require_text(path: Path, text: str, tokens: tuple[str, ...], errors: list[str]) -> None:
    normalized = " ".join(text.split())
    for token in tokens:
        normalized_token = " ".join(token.split())
        if token not in text and normalized_token not in normalized:
            errors.append(f"{path}: missing boundary text {token!r}")


def check_resource_report(root: Path, report_path: Path, baseline_timing: Path, trace_timing: Path) -> list[str]:
    errors: list[str] = []
    report = resolve(root, report_path)
    baseline = resolve(root, baseline_timing)
    trace = resolve(root, trace_timing)
    for label, path in (("resource report", report), ("baseline timing", baseline), ("trace timing", trace)):
        if not path.is_file():
            return [f"missing {label}: {display(path, root)}"]

    text = report.read_text(encoding="utf-8", errors="replace")
    baseline_status, baseline_slack = parse_timing(baseline)
    trace_status, trace_slack = parse_timing(trace)
    require_text(
        report,
        text,
        (
            "Trace-Enabled FPGA Delta",
            "| Timing status |",
            f"| Timing status | {baseline_status} | {trace_status} | n/a |",
            f"| Slack (ns) | {fmt(baseline_slack)} | {fmt(trace_slack)} | {fmt(trace_slack - baseline_slack)} |",
        ),
        errors,
    )
    if trace_status != "MET" or trace_slack < 0.0:
        require_text(
            report,
            text,
            (
                "Trace-enabled timing boundary",
                "not timing-closed",
                "must not be cited as a trace-enabled Fmax, timing-closure, or performance-improvement result",
            ),
            errors,
        )
    else:
        require_text(
            report,
            text,
            (
                "Trace-Enabled FPGA Delta",
                "Trace timing",
            ),
            errors,
        )
    return errors


def check_safe_summary(root: Path, summary_path: Path) -> list[str]:
    errors: list[str] = []
    summary_file = resolve(root, summary_path)
    if not summary_file.is_file():
        return [f"missing safe surrogate summary: {display(summary_file, root)}"]
    summary = load_json(summary_file)
    if summary.get("schema") != "rvmt.genesys2.safe_surrogate.run_summary.v1":
        errors.append(f"{display(summary_file, root)}: schema mismatch")
    if summary.get("board") != EXPECTED_BOARD:
        errors.append(f"{display(summary_file, root)}: board must be {EXPECTED_BOARD}")
    if summary.get("cpu") != EXPECTED_CPU:
        errors.append(f"{display(summary_file, root)}: cpu must be {EXPECTED_CPU}")
    samples = summary.get("samples")
    if not isinstance(samples, list) or len(samples) != 8:
        errors.append(f"{display(summary_file, root)}: expected 8 safe surrogate samples")
        return errors
    for sample in samples:
        if not isinstance(sample, dict):
            errors.append(f"{display(summary_file, root)}: sample entries must be objects")
            continue
        sample_id = sample.get("sample_id", "<unknown>")
        if sample.get("real_malware") is not False:
            errors.append(f"{sample_id}: real_malware must be false")
        status = str(sample.get("status") or "")
        if "PASS_SAFE_SURROGATE" not in status or "LIMITATIONS" not in status:
            errors.append(f"{sample_id}: status must pass with explicit limitations")
    non_claims = "\n".join(str(item) for item in summary.get("non_claims", []))
    require_text(
        summary_file,
        non_claims,
        (
            "No real malware validation",
            "No single continuous entry/trap/return hardware trace window",
            "No strong runtime process attribution",
        ),
        errors,
    )
    return errors


def check_runtime_attribution(root: Path, attribution_path: Path) -> list[str]:
    errors: list[str] = []
    path = resolve(root, attribution_path)
    if not path.is_file():
        return [f"missing runtime attribution summary: {display(path, root)}"]
    summary = load_json(path)
    if summary.get("status") != "MARKER_SCOPE_RUNTIME_PROCESS_ATTRIBUTION_PASS":
        errors.append(f"{display(path, root)}: expected marker-scope runtime-attribution PASS status")
    if summary.get("runtime_process_map_status") != "PASS":
        errors.append(f"{display(path, root)}: runtime process map must be PASS")
    if summary.get("marker_scope_status") != "PASS":
        errors.append(f"{display(path, root)}: marker_scope_status must be PASS")
    if summary.get("runtime_process_attribution_proven") is not True:
        errors.append(f"{display(path, root)}: runtime_process_attribution_proven must be true")
    if summary.get("process_attribution") != "proven":
        errors.append(f"{display(path, root)}: process_attribution must be proven")
    if int(summary.get("process_attributed_code_site_events") or 0) < 1:
        errors.append(f"{display(path, root)}: expected marker-scoped runtime/code-site events")
    requirements = summary.get("requirements")
    if not isinstance(requirements, dict):
        errors.append(f"{display(path, root)}: requirements must be an object")
        requirements = {}
    for key in (
        "marker_scope_pair",
        "runtime_process_map_pass",
        "target_child_maps_runtime_elf",
        "target_code_sites_observed",
        "illegal_instruction_trap_observed",
        "handler_write_syscall_observed",
        "safe_synthetic_only",
    ):
        row = requirements.get(key)
        if not isinstance(row, dict) or row.get("pass") is not True:
            errors.append(f"{display(path, root)}: requirement {key} must pass")
    text = json.dumps(summary, sort_keys=True)
    require_text(
        path,
        text,
        (
            "Marker-scoped runtime process/code-site attribution is proven for the safe illegal_trap surrogate window only",
            "not real malware validation",
            "packed marker capture does not provide SATP/ASID attribution",
            "Older P0 traces remain multi-window/weak",
        ),
        errors,
    )
    return errors


def check_trace_window_diagnosis(root: Path, diagnosis_path: Path) -> list[str]:
    path = resolve(root, diagnosis_path)
    if not path.is_file():
        return [f"missing trace window diagnosis: {display(path, root)}"]
    text = path.read_text(encoding="utf-8", errors="replace")
    errors: list[str] = []
    require_text(
        path,
        text,
        (
            "not yet demonstrated a target syscall entry and its matching return in one capture window",
            "multi-capture evidence packages",
            "not single continuous invocation traces",
        ),
        errors,
    )
    return errors


def check_evidence_report(root: Path, report_path: Path) -> list[str]:
    path = resolve(root, report_path)
    if not path.is_file():
        return [f"missing evidence report: {display(path, root)}"]
    text = path.read_text(encoding="utf-8", errors="replace")
    errors: list[str] = []
    require_text(
        path,
        text,
        (
            "Artix-7 35T material is excluded",
            "No real malware validation is demonstrated",
            "Marker-scoped runtime process/code-site attribution is now demonstrated for the safe `illegal_trap` surrogate",
            "No broad per-process runtime attribution is claimed for the older P0 traces",
            "No SATP/ASID-backed attribution is claimed for the packed marker capture",
            "Timing closure alone is not claimed as runtime attribution",
        ),
        errors,
    )
    return errors


def run_checks(root: Path) -> list[str]:
    errors: list[str] = []
    errors.extend(check_resource_report(root, DEFAULT_RESOURCE_REPORT, DEFAULT_BASELINE_TIMING, DEFAULT_TRACE_TIMING))
    errors.extend(check_safe_summary(root, DEFAULT_SAFE_SUMMARY))
    errors.extend(check_runtime_attribution(root, DEFAULT_RUNTIME_ATTRIBUTION))
    errors.extend(check_trace_window_diagnosis(root, DEFAULT_TRACE_WINDOW_DIAGNOSIS))
    errors.extend(check_evidence_report(root, DEFAULT_EVIDENCE_REPORT))
    return errors


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_fixture(root: Path) -> None:
    (root / DEFAULT_BASELINE_TIMING).parent.mkdir(parents=True)
    (root / DEFAULT_TRACE_TIMING).parent.mkdir(parents=True)
    (root / DEFAULT_BASELINE_TIMING).write_text("Slack (MET) :             0.177ns\n", encoding="utf-8")
    (root / DEFAULT_TRACE_TIMING).write_text("Slack (MET) :             0.177ns\n", encoding="utf-8")
    (root / DEFAULT_RESOURCE_REPORT).parent.mkdir(parents=True)
    (root / DEFAULT_RESOURCE_REPORT).write_text(
        "\n".join(
            [
                "# Resource Report",
                "## Trace-Enabled FPGA Delta",
                "- Trace timing: `build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/reports/ariane.timing.rpt`",
                "| Timing status | MET | MET | n/a |",
                "| Slack (ns) | 0.177 | 0.177 | 0.000 |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    write_json(
        root / DEFAULT_SAFE_SUMMARY,
        {
            "schema": "rvmt.genesys2.safe_surrogate.run_summary.v1",
            "board": EXPECTED_BOARD,
            "cpu": EXPECTED_CPU,
            "non_claims": [
                "No real malware validation is demonstrated.",
                "No single continuous entry/trap/return hardware trace window is claimed.",
                "No strong runtime process attribution is claimed.",
            ],
            "samples": [
                {
                    "sample_id": f"sample_{index}",
                    "status": "PASS_SAFE_SURROGATE_EVIDENCE_CHAIN_WITH_LIMITATIONS",
                    "real_malware": False,
                }
                for index in range(8)
            ],
        },
    )
    write_json(
        root / DEFAULT_RUNTIME_ATTRIBUTION,
        {
            "status": "MARKER_SCOPE_RUNTIME_PROCESS_ATTRIBUTION_PASS",
            "runtime_process_map_status": "PASS",
            "marker_scope_status": "PASS",
            "runtime_process_attribution_proven": True,
            "process_attribution": "proven",
            "process_attributed_code_site_events": 3,
            "requirements": {
                "marker_scope_pair": {"pass": True},
                "runtime_process_map_pass": {"pass": True},
                "target_child_maps_runtime_elf": {"pass": True},
                "target_code_sites_observed": {"pass": True},
                "illegal_instruction_trap_observed": {"pass": True},
                "handler_write_syscall_observed": {"pass": True},
                "safe_synthetic_only": {"pass": True},
            },
            "claim_boundary": [
                "Marker-scoped runtime process/code-site attribution is proven for the safe illegal_trap surrogate window only.",
                "This is safe synthetic/surrogate evidence, not real malware validation.",
                "Older P0 traces remain multi-window/weak unless separately marker-scoped and runtime-mapped.",
                "The packed marker capture does not provide SATP/ASID attribution.",
            ],
        },
    )
    (root / DEFAULT_TRACE_WINDOW_DIAGNOSIS).parent.mkdir(parents=True)
    (root / DEFAULT_TRACE_WINDOW_DIAGNOSIS).write_text(
        "not yet demonstrated a target syscall entry and its matching return in one capture window\n"
        "multi-capture evidence packages\n"
        "not single continuous invocation traces\n",
        encoding="utf-8",
    )
    (root / DEFAULT_EVIDENCE_REPORT).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_EVIDENCE_REPORT).write_text(
        "Artix-7 35T material is excluded\n"
        "No real malware validation is demonstrated\n"
        "Marker-scoped runtime process/code-site attribution is now demonstrated for the safe `illegal_trap` surrogate\n"
        "No broad per-process runtime attribution is claimed for the older P0 traces\n"
        "No SATP/ASID-backed attribution is claimed for the packed marker capture\n"
        "Timing closure alone is not claimed as runtime attribution\n",
        encoding="utf-8",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root)
        if errors:
            for error in errors:
                print(f"[FAIL] {error}", file=sys.stderr)
            return 1
        resource_report = root / DEFAULT_RESOURCE_REPORT
        resource_report.write_text(resource_report.read_text(encoding="utf-8").replace("| Slack (ns) | 0.177 | 0.177 | 0.000 |", "| Slack (ns) | 0.177 | -0.427 | -0.604 |"), encoding="utf-8")
        errors = run_checks(root)
        if not any("Slack (ns)" in error for error in errors):
            print("[FAIL] self-test missed stale resource timing slack", file=sys.stderr)
            return 1
    print("[PASS] Genesys2/CVA evidence-boundary self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2/CVA6 current evidence boundaries.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    try:
        errors = run_checks(root)
    except Exception as exc:
        print(f"check_genesys2_cva_evidence_boundary: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Genesys2/CVA6 evidence boundaries are explicit and artifact-consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
