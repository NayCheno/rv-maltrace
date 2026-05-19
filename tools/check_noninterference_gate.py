from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SPEC = Path("experiments/hardware/noninterference_gate.json")
DEFAULT_DOC = Path("docs/validation/noninterference_resource_gate.md")
DEFAULT_SUMMARY = Path("results/vivado_sim/summary.json")
DEFAULT_RESOURCE_REPORT = Path("docs/reports/resource_report.md")
DEFAULT_TIMING_CHECK = Path("tools/check_timing_principles.py")
DEFAULT_REPORT_TOOL = Path("tools/generate_noninterference_report.py")
DEFAULT_UV_DOC = Path("docs/process/uv_workflow.md")
EXPECTED_CHECKS = [
    "no_core_backpressure_ports",
    "pipelined_sideband_snapshot",
    "drop_accounting_not_stall",
    "direct_core_trace_no_trace_parity",
    "baseline_resource_snapshot",
    "trace_enabled_fpga_resource_delta",
]
EXPECTED_STATUSES = {
    "no_core_backpressure_ports": "CHECKED(REPO)",
    "pipelined_sideband_snapshot": "CHECKED(REPO)",
    "drop_accounting_not_stall": "CHECKED(SIM)",
    "direct_core_trace_no_trace_parity": "CHECKED(SIM)",
    "baseline_resource_snapshot": "CHECKED(BASELINE)",
    "trace_enabled_fpga_resource_delta": "CHECKED(TRACE_SYNTHESIS)",
}
DIRECT_CORE_CASES = ["cva6_smoke", "cva6_branch", "cva6_jump", "cva6_ecall", "cva6_trap_illegal", "cva6_ebreak"]
ALLOWED_BLOCKED_SIM_TESTS = {
    "cva6_full_soc_tohost_normal": "normal full-SoC tohost/MMIO gate is tracked separately from noninterference",
}
REQUIRED_DOC_TEXT = (
    "Phase 3.4 defines the noninterference and resource boundary for the trace logic.",
    "experiments/hardware/noninterference_gate.json",
    "no_core_backpressure_ports",
    "pipelined_sideband_snapshot",
    "drop_accounting_not_stall",
    "direct_core_trace_no_trace_parity",
    "trace_enabled_fpga_resource_delta",
    "tools/generate_noninterference_report.py",
    "noninterference_summary.json",
    "noninterference_report.md",
    "must not claim CVA6 IPC improvement",
    "Trace-enabled FPGA LUT/FF/BRAM/DSP/slack delta",
)
FORBIDDEN_DOC_PATTERNS = (
    re.compile(r"\bCVA6\s+(?:IPC|Fmax)\s+improvement\s+(?:is\s+)?(?:passed|validated|complete|measured|proven)\b", re.IGNORECASE),
    re.compile(r"\bboard\s+runtime\s+overhead\s+(?:is\s+)?(?:passed|validated|complete|measured)\b", re.IGNORECASE),
)
TRACE_PASS_RE = re.compile(r"^\[rvmt\]\s+Direct CVA6 xsim trace PASS\b", re.MULTILINE)
NO_TRACE_PASS_RE = re.compile(r"^\[rvmt\]\s+Direct CVA6 xsim no-trace PASS\b", re.MULTILINE)


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def check_forbidden_claims(path: Path, text: str) -> list[str]:
    return [
        f"{path}: must not claim trace-enabled resource/performance completion"
        for pattern in FORBIDDEN_DOC_PATTERNS
        if pattern.search(text)
    ]


def check_spec(path: Path) -> list[str]:
    spec = load_json(path)
    errors: list[str] = []
    if spec.get("phase") != "3.4":
        errors.append(f"{path}: phase must be 3.4")
    if spec.get("status") != "CHECKED(TRACE_SYNTHESIS)":
        errors.append(f"{path}: status must be CHECKED(TRACE_SYNTHESIS)")
    if spec.get("scope") != "trace_sideband_noninterference_and_resource_gate":
        errors.append(f"{path}: unexpected scope")
    refs = spec.get("evidence_refs", [])
    for ref in (
        "docs/architecture/timing_principles.md",
        "docs/reports/resource_report.md",
        "results/vivado_sim/summary.json",
        "tools/check_timing_principles.py",
        "tools/generate_resource_report.py",
        "tools/generate_noninterference_report.py",
    ):
        if ref not in refs:
            errors.append(f"{path}: evidence_refs missing {ref}")
    checks = spec.get("checks", [])
    if not isinstance(checks, list):
        return errors + [f"{path}: checks must be a list"]
    by_id = {check.get("id"): check for check in checks if isinstance(check, dict)}
    if list(by_id) != EXPECTED_CHECKS:
        errors.append(f"{path}: checks must appear in expected order: {EXPECTED_CHECKS}")
    for check_id in EXPECTED_CHECKS:
        check = by_id.get(check_id, {})
        if check.get("status") != EXPECTED_STATUSES[check_id]:
            errors.append(f"{path}: {check_id}.status must be {EXPECTED_STATUSES[check_id]}")
        if not isinstance(check.get("command"), str) or not check.get("command"):
            errors.append(f"{path}: {check_id}.command must be set")
        if not isinstance(check.get("evidence"), str) or not check.get("evidence"):
            errors.append(f"{path}: {check_id}.evidence must be set")
    non_goals = spec.get("non_goals", [])
    for required in (
        "CVA6 IPC improvement",
        "CVA6 Fmax improvement",
        "trace-enabled FPGA resource delta claim without implementation reports",
        "board-level performance claim without board artifacts",
    ):
        if required not in non_goals:
            errors.append(f"{path}: non_goals missing {required}")
    return errors


def parse_table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        if cells and cells[0] == "Order":
            continue
        rows.append(cells)
    return rows


def check_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    normalized = normalized_text(text)
    errors: list[str] = []
    for required in REQUIRED_DOC_TEXT:
        if normalized_text(required) not in normalized:
            errors.append(f"{path}: missing required text: {required}")
    errors.extend(check_forbidden_claims(path, text))
    rows = parse_table_rows(text)
    by_check = {row[1]: row for row in rows if len(row) >= 4}
    for index, check_id in enumerate(EXPECTED_CHECKS, start=1):
        row = by_check.get(check_id)
        if row is None:
            errors.append(f"{path}: missing row for {check_id}")
            continue
        if row[0] != str(index):
            errors.append(f"{path}: {check_id} order must be {index}")
        if row[3] != EXPECTED_STATUSES[check_id]:
            errors.append(f"{path}: {check_id} row status must be {EXPECTED_STATUSES[check_id]}")
    return errors


def parse_drop_value(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    return 0


def resolve_summary_artifact(root: Path, summary_path: Path, raw_path: object) -> Path:
    path = Path(str(raw_path).replace("\\", "/"))
    if path.is_absolute():
        return path
    root_relative = root / path
    if root_relative.exists():
        return root_relative
    return summary_path.parent / path


def check_summary(root: Path, path: Path) -> list[str]:
    summary = load_json(path)
    errors: list[str] = []
    tests = summary.get("tests", {})
    if not isinstance(tests, dict):
        return errors + [f"{path}: tests must be an object"]
    malformed = sorted(name for name, row in tests.items() if not isinstance(row, dict))
    if malformed:
        errors.append(f"{path}: malformed test rows: {', '.join(malformed)}")
    failing = sorted(
        name
        for name, row in tests.items()
        if not isinstance(row, dict) or row.get("status") != "PASS"
    )
    allowed_blocked = sorted(
        name
        for name in failing
        if name in ALLOWED_BLOCKED_SIM_TESTS
        and isinstance(tests.get(name), dict)
        and tests[name].get("status") == "BLOCKED"
    )
    unexpected_failing = sorted(name for name in failing if name not in allowed_blocked)
    overall = summary.get("overall")
    if overall == "PASS":
        if failing:
            errors.append(f"{path}: failing tests: {', '.join(failing)}")
    elif overall == "PASS_WITH_BLOCKED":
        if unexpected_failing:
            errors.append(f"{path}: unexpected failing tests: {', '.join(unexpected_failing)}")
        if not allowed_blocked:
            errors.append(f"{path}: overall PASS_WITH_BLOCKED but no allowed BLOCKED tests found")
    else:
        errors.append(f"{path}: overall must be PASS or controlled PASS_WITH_BLOCKED for this gate")
    for name in allowed_blocked:
        row = tests[name]
        for key in ("trace", "compare_log"):
            raw_path = row.get(key)
            if not raw_path:
                errors.append(f"{path}: allowed BLOCKED {name} missing {key}")
                continue
            artifact = resolve_summary_artifact(root, path, raw_path)
            if not artifact.is_file():
                errors.append(f"{path}: allowed BLOCKED {name}.{key} is missing: {artifact}")
    backpressure = tests.get("backpressure", {})
    if backpressure.get("status") != "PASS":
        errors.append(f"{path}: backpressure status must be PASS")
    if int(backpressure.get("counts", {}).get("DROP", 0)) <= 0:
        errors.append(f"{path}: backpressure must include DROP records")
    trace_path = resolve(root, Path(str(backpressure.get("trace", "")).replace("\\", "/")))
    if not trace_path.exists():
        errors.append(f"{path}: backpressure trace is missing: {trace_path}")
    else:
        drop_sum = 0
        for line in trace_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("evt") == "DROP":
                drop_sum += parse_drop_value(event.get("value"))
        if drop_sum <= 0:
            errors.append(f"{trace_path}: DROP.value sum must be positive")

    for case in DIRECT_CORE_CASES:
        item = tests.get(case, {})
        if item.get("status") != "PASS":
            errors.append(f"{path}: {case} status must be PASS")
        case_dir = root / "results" / "vivado_sim" / case
        trace_log = case_dir / "xsim.log"
        no_trace_log = case_dir / "xsim_notrace.log"
        trace_text = trace_log.read_text(encoding="utf-8", errors="replace") if trace_log.exists() else ""
        no_trace_text = no_trace_log.read_text(encoding="utf-8", errors="replace") if no_trace_log.exists() else ""
        if not trace_log.exists() or not TRACE_PASS_RE.search(trace_text):
            errors.append(f"{trace_log}: missing direct-core trace PASS evidence")
        if not no_trace_log.exists() or not NO_TRACE_PASS_RE.search(no_trace_text):
            errors.append(f"{no_trace_log}: missing direct-core no-trace PASS evidence")
    return errors


def check_resource_report(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for required in (
        "existing Genesys 2 routed `ariane_xilinx` report",
        "Trace-specific queue/drop rows",
        "Max DROP test",
        "Max dropped event count",
        "Trace-Enabled FPGA Delta",
        "build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports/ariane.utilization.rpt",
        "| LUT |",
        "| FF |",
    ):
        if required not in text:
            errors.append(f"{path}: missing resource boundary text: {required}")
    errors.extend(check_forbidden_claims(path, text))
    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token, label in (
        ("tools/check_noninterference_gate.py", "Phase 3.4 checker command"),
        ("tools/generate_noninterference_report.py --self-test", "Phase 3.4 report self-test command"),
        ("tools/generate_noninterference_report.py --out-dir build/noninterference_gate", "Phase 3.4 report command"),
        ("docs/validation/noninterference_resource_gate.md", "Phase 3.4 doc reference"),
        ("experiments/hardware/noninterference_gate.json", "Phase 3.4 spec reference"),
    ):
        if token not in text:
            errors.append(f"{path}: missing {label}")
    return errors


def check_timing_tool(root: Path, tool: Path) -> list[str]:
    result = subprocess.run([sys.executable, str(resolve(root, tool))], cwd=root, text=True, capture_output=True)
    if result.returncode != 0:
        return [f"{tool}: timing-principle check failed: {result.stderr.strip() or result.stdout.strip()}"]
    return []


def check_report_tool(root: Path, tool: Path, summary: Path) -> list[str]:
    errors: list[str] = []
    tool_path = resolve(root, tool)
    if not tool_path.exists():
        return [f"missing noninterference report tool: {tool_path}"]
    result = subprocess.run([sys.executable, str(tool_path), "--self-test"], cwd=root, text=True, capture_output=True)
    if result.returncode != 0:
        errors.append(f"noninterference report self-test failed: {result.stderr.strip() or result.stdout.strip()}")
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "noninterference"
        result = subprocess.run(
            [sys.executable, str(tool_path), "--summary", str(resolve(root, summary)), "--out-dir", str(out_dir)],
            cwd=root,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            errors.append(f"noninterference report generation failed: {result.stderr.strip() or result.stdout.strip()}")
        json_path = out_dir / "noninterference_summary.json"
        md_path = out_dir / "noninterference_report.md"
        if not json_path.exists():
            errors.append("noninterference report generation did not write noninterference_summary.json")
        else:
            payload = load_json(json_path)
            if payload.get("status") != "PASS":
                errors.append("noninterference summary did not record PASS")
            if "trace-enabled FPGA resource delta" not in str(payload.get("claim_boundary", "")):
                errors.append("noninterference summary is missing trace-enabled resource-delta boundary")
        if not md_path.exists():
            errors.append("noninterference report generation did not write noninterference_report.md")
        elif "does not claim CVA6 IPC/Fmax improvement" not in md_path.read_text(encoding="utf-8"):
            errors.append("noninterference markdown report is missing CVA6 IPC/Fmax non-claim")
    return errors


def run_checks(root: Path, spec: Path, doc: Path, summary: Path, resource_report: Path, timing_check: Path, report_tool: Path, uv_doc: Path) -> list[str]:
    paths = {
        "spec": resolve(root, spec),
        "doc": resolve(root, doc),
        "summary": resolve(root, summary),
        "resource report": resolve(root, resource_report),
        "timing check": resolve(root, timing_check),
        "report tool": resolve(root, report_tool),
        "uv workflow": resolve(root, uv_doc),
    }
    errors = [f"missing {label}: {path}" for label, path in paths.items() if not path.exists()]
    if errors:
        return errors
    errors.extend(check_spec(paths["spec"]))
    errors.extend(check_doc(paths["doc"]))
    errors.extend(check_summary(root, paths["summary"]))
    errors.extend(check_resource_report(paths["resource report"]))
    errors.extend(check_uv_doc(paths["uv workflow"]))
    errors.extend(check_timing_tool(root, timing_check))
    errors.extend(check_report_tool(root, report_tool, summary))
    return errors


def write_fixture(root: Path) -> None:
    (root / "experiments/hardware").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    (root / "tools").mkdir(parents=True)
    (root / "results/vivado_sim/backpressure").mkdir(parents=True)
    for case in DIRECT_CORE_CASES:
        case_dir = root / "results" / "vivado_sim" / case
        case_dir.mkdir(parents=True)
        (case_dir / "xsim.log").write_text("[rvmt] Direct CVA6 xsim trace PASS after 1 cycles\n", encoding="utf-8")
        (case_dir / "xsim_notrace.log").write_text("[rvmt] Direct CVA6 xsim no-trace PASS after 1 cycles\n", encoding="utf-8")
    (root / "results/vivado_sim/backpressure/trace.jsonl").write_text('{"evt":"DROP","value":"0x2"}\n', encoding="utf-8")
    tests = {
        "backpressure": {"status": "PASS", "counts": {"DROP": 1}, "trace": "results/vivado_sim/backpressure/trace.jsonl"}
    }
    for case in DIRECT_CORE_CASES:
        tests[case] = {"status": "PASS", "counts": {}, "trace": f"results/vivado_sim/{case}/trace.jsonl"}
    (root / DEFAULT_SUMMARY).write_text(json.dumps({"overall": "PASS", "tests": tests}), encoding="utf-8")
    checks = [
        {"id": check_id, "status": EXPECTED_STATUSES[check_id], "command": "cmd", "evidence": "evidence"}
        for check_id in EXPECTED_CHECKS
    ]
    (root / DEFAULT_SPEC).write_text(
        json.dumps(
            {
                "phase": "3.4",
                "status": "CHECKED(TRACE_SYNTHESIS)",
                "scope": "trace_sideband_noninterference_and_resource_gate",
                "evidence_refs": [
                    "docs/architecture/timing_principles.md",
                    "docs/reports/resource_report.md",
                    "results/vivado_sim/summary.json",
                    "tools/check_timing_principles.py",
                    "tools/generate_resource_report.py",
                    "tools/generate_noninterference_report.py",
                ],
                "checks": checks,
                "non_goals": [
                    "CVA6 IPC improvement",
                    "CVA6 Fmax improvement",
                    "trace-enabled FPGA resource delta claim without implementation reports",
                    "board-level performance claim without board artifacts",
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Noninterference And Resource Gate

Phase 3.4 defines the noninterference and resource boundary for the trace logic.
experiments/hardware/noninterference_gate.json
tools/generate_noninterference_report.py
noninterference_summary.json
noninterference_report.md

| Order | Check | Evidence | Status |
| ---: | --- | --- | --- |
| 1 | no_core_backpressure_ports | timing | CHECKED(REPO) |
| 2 | pipelined_sideband_snapshot | timing | CHECKED(REPO) |
| 3 | drop_accounting_not_stall | drop | CHECKED(SIM) |
| 4 | direct_core_trace_no_trace_parity | parity | CHECKED(SIM) |
| 5 | baseline_resource_snapshot | resource | CHECKED(BASELINE) |
| 6 | trace_enabled_fpga_resource_delta | delta | CHECKED(TRACE_SYNTHESIS) |

must not claim CVA6 IPC improvement
Trace-enabled FPGA LUT/FF/BRAM/DSP/slack delta
""",
        encoding="utf-8",
    )
    (root / DEFAULT_RESOURCE_REPORT).write_text(
        "The Vivado numbers below are from the existing Genesys 2 routed `ariane_xilinx` report.\n"
        "Trace-specific queue/drop rows are taken from current trace RTL parameters.\n"
        "Max DROP test\nMax dropped event count\n"
        "Trace-Enabled FPGA Delta\n"
        "build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports/ariane.utilization.rpt\n"
        "| LUT |\n| FF |\n",
        encoding="utf-8",
    )
    (root / DEFAULT_TIMING_CHECK).write_text("print('[PASS] timing stub')\n", encoding="utf-8")
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/generate_noninterference_report.py --self-test\n"
        "uv run python tools/generate_noninterference_report.py --out-dir build/noninterference_gate\n"
        "uv run python tools/check_noninterference_gate.py\n"
        "docs/validation/noninterference_resource_gate.md\n"
        "experiments/hardware/noninterference_gate.json\n",
        encoding="utf-8",
    )


def expect_error(root: Path, expected: str) -> bool:
    errors = []
    errors.extend(check_spec(root / DEFAULT_SPEC))
    errors.extend(check_doc(root / DEFAULT_DOC))
    errors.extend(check_summary(root, root / DEFAULT_SUMMARY))
    errors.extend(check_resource_report(root / DEFAULT_RESOURCE_REPORT))
    errors.extend(check_uv_doc(root / DEFAULT_UV_DOC))
    return any(expected in error for error in errors)


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = []
        errors.extend(check_spec(root / DEFAULT_SPEC))
        errors.extend(check_doc(root / DEFAULT_DOC))
        errors.extend(check_summary(root, root / DEFAULT_SUMMARY))
        errors.extend(check_resource_report(root / DEFAULT_RESOURCE_REPORT))
        errors.extend(check_uv_doc(root / DEFAULT_UV_DOC))
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1
        source_tool = Path.cwd() / DEFAULT_REPORT_TOOL
        fixture_tool = root / DEFAULT_REPORT_TOOL
        shutil.copyfile(source_tool, fixture_tool)
        tool_errors = check_report_tool(root, DEFAULT_REPORT_TOOL, DEFAULT_SUMMARY)
        if tool_errors:
            for error in tool_errors:
                print(f"[FAIL] self-test report-output gate failed: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        blocked_dir = root / "results/vivado_sim/cva6_full_soc_tohost_normal"
        blocked_dir.mkdir(parents=True)
        (blocked_dir / "trace.jsonl").write_text('{"evt":"RETIRE","value":1}\n', encoding="utf-8")
        (blocked_dir / "compare.log").write_text("[BLOCKED] timed out before observing tohost store\n", encoding="utf-8")
        summary = load_json(root / DEFAULT_SUMMARY)
        summary["overall"] = "PASS_WITH_BLOCKED"
        summary["tests"]["cva6_full_soc_tohost_normal"] = {
            "status": "BLOCKED",
            "trace": "results/vivado_sim/cva6_full_soc_tohost_normal/trace.jsonl",
            "compare_log": "results/vivado_sim/cva6_full_soc_tohost_normal/compare.log",
        }
        (root / DEFAULT_SUMMARY).write_text(json.dumps(summary), encoding="utf-8")
        errors = check_summary(root, root / DEFAULT_SUMMARY)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test rejected allowed BLOCKED tohost boundary: {error}", file=sys.stderr)
            return 1
        shutil.copyfile(Path.cwd() / DEFAULT_REPORT_TOOL, root / DEFAULT_REPORT_TOOL)
        tool_errors = check_report_tool(root, DEFAULT_REPORT_TOOL, DEFAULT_SUMMARY)
        if tool_errors:
            for error in tool_errors:
                print(f"[FAIL] self-test report-output rejected allowed BLOCKED tohost boundary: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["checks"][-1]["status"] = "TODO(TRACE_ENABLED_SYNTHESIS)"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "trace_enabled_fpga_resource_delta.status must be CHECKED"):
            print("[FAIL] self-test missed regressed trace-enabled resource delta status", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["checks"][3]["status"] = "PASS(BOARD)"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "direct_core_trace_no_trace_parity.status must be CHECKED(SIM)"):
            print("[FAIL] self-test missed drifted JSON status", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8").replace("direct_core_trace_no_trace_parity | parity | CHECKED(SIM)", "direct_core_trace_no_trace_parity | parity | PASS(BOARD)"), encoding="utf-8")
        if not expect_error(root, "direct_core_trace_no_trace_parity row status must be CHECKED(SIM)"):
            print("[FAIL] self-test missed drifted markdown status", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        summary = load_json(root / DEFAULT_SUMMARY)
        summary["tests"]["backpressure"]["counts"] = {}
        (root / DEFAULT_SUMMARY).write_text(json.dumps(summary), encoding="utf-8")
        if not expect_error(root, "backpressure must include DROP"):
            print("[FAIL] self-test missed missing DROP accounting", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / "results/vivado_sim/cva6_smoke/xsim.log").write_text("[rvmt] Direct CVA6 xsim no-trace PASS after 1 cycles\n", encoding="utf-8")
        if not expect_error(root, "missing direct-core trace PASS evidence"):
            print("[FAIL] self-test missed trace log containing only no-trace PASS", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / "results/vivado_sim/cva6_smoke/xsim_notrace.log").write_text("no pass\n", encoding="utf-8")
        if not expect_error(root, "missing direct-core no-trace PASS evidence"):
            print("[FAIL] self-test missed missing no-trace parity evidence", file=sys.stderr)
            return 1

    for phrase in (
        "CVA6 IPC improvement is validated",
        "board runtime overhead is measured",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            doc = root / DEFAULT_DOC
            doc.write_text(doc.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must not claim trace-enabled resource/performance completion"):
                print(f"[FAIL] self-test missed unsafe doc phrase: {phrase}", file=sys.stderr)
                return 1

    for phrase in (
        "board runtime overhead is measured",
        "CVA6 Fmax improvement is validated",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            report = root / DEFAULT_RESOURCE_REPORT
            report.write_text(report.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must not claim trace-enabled resource/performance completion"):
                print(f"[FAIL] self-test missed unsafe resource report phrase: {phrase}", file=sys.stderr)
                return 1

    print("[PASS] noninterference/resource gate self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check trace noninterference/resource claim boundary.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--resource-report", type=Path, default=DEFAULT_RESOURCE_REPORT)
    parser.add_argument("--timing-check", type=Path, default=DEFAULT_TIMING_CHECK)
    parser.add_argument("--report-tool", type=Path, default=DEFAULT_REPORT_TOOL)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(
            args.root.resolve(),
            args.spec,
            args.doc,
            args.summary,
            args.resource_report,
            args.timing_check,
            args.report_tool,
            args.uv_doc,
        )
    except Exception as exc:
        print(f"check_noninterference_gate: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] trace noninterference/resource gate is specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
