from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
)


DIRECT_CORE_CASES = ["cva6_smoke", "cva6_branch", "cva6_jump", "cva6_ecall", "cva6_trap_illegal", "cva6_ebreak"]
ALLOWED_BLOCKED_SIM_TESTS = {
    "cva6_full_soc_tohost_normal": "normal full-SoC tohost/MMIO gate is tracked separately from noninterference",
}
TRACE_PASS_RE = re.compile(r"^\[rvmt\]\s+Direct CVA6 xsim trace PASS\b", re.MULTILINE)
NO_TRACE_PASS_RE = re.compile(r"^\[rvmt\]\s+Direct CVA6 xsim no-trace PASS\b", re.MULTILINE)


def parse_drop_value(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    return 0


def drop_value_sum(path: Path) -> int:
    total = 0
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError(f"{path}:{line_no}: event must be a JSON object")
        if event.get("evt") == "DROP":
            total += parse_drop_value(event.get("value"))
    return total


def read_text_if_exists(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def classify_simulation_boundary(summary: dict[str, Any], tests: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
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
    unexpected = sorted(name for name in failing if name not in allowed_blocked)
    overall = summary.get("overall")
    if overall == "PASS":
        return not failing, [], failing
    if overall == "PASS_WITH_BLOCKED":
        return not unexpected and bool(allowed_blocked), allowed_blocked, unexpected
    return False, allowed_blocked, unexpected or [f"overall={overall!r}"]


def analyze(root: Path, summary_path: Path) -> dict[str, Any]:
    summary = load_json(summary_path)
    tests = summary.get("tests", {})
    if not isinstance(tests, dict):
        raise ValueError(f"{summary_path}: tests must be an object")
    simulation_boundary_ok, allowed_blocked, unexpected_nonpass = classify_simulation_boundary(summary, tests)

    backpressure = tests.get("backpressure", {})
    if not isinstance(backpressure, dict):
        backpressure = {}
    trace_rel = str(backpressure.get("trace", "")).replace("\\", "/")
    trace_path = root / trace_rel if trace_rel else Path()
    drop_sum = drop_value_sum(trace_path) if trace_path.exists() else 0
    counts = backpressure.get("counts", {})
    drop = {
        "test_status": backpressure.get("status"),
        "drop_records": int(counts.get("DROP", 0)) if isinstance(counts, dict) else 0,
        "dropped_event_count": drop_sum,
        "trace": trace_rel or None,
    }

    parity_cases: list[dict[str, Any]] = []
    for case in DIRECT_CORE_CASES:
        item = tests.get(case, {})
        if not isinstance(item, dict):
            item = {}
        case_dir = root / "results" / "vivado_sim" / case
        trace_log = case_dir / "xsim.log"
        no_trace_log = case_dir / "xsim_notrace.log"
        trace_pass = bool(TRACE_PASS_RE.search(read_text_if_exists(trace_log)))
        no_trace_pass = bool(NO_TRACE_PASS_RE.search(read_text_if_exists(no_trace_log)))
        parity_cases.append(
            {
                "case": case,
                "summary_status": item.get("status"),
                "trace_log": trace_log.as_posix(),
                "no_trace_log": no_trace_log.as_posix(),
                "trace_pass": trace_pass,
                "no_trace_pass": no_trace_pass,
                "parity_pass": item.get("status") == "PASS" and trace_pass and no_trace_pass,
            }
        )

    overall_pass = (
        simulation_boundary_ok
        and drop["test_status"] == "PASS"
        and drop["drop_records"] > 0
        and drop["dropped_event_count"] > 0
        and all(item["parity_pass"] for item in parity_cases)
    )
    return {
        "schema": "rvmt.noninterference.summary.v1",
        "summary": summary_path.as_posix(),
        "status": "PASS" if overall_pass else "FAIL",
        "simulation_overall": summary.get("overall"),
        "allowed_blocked_sim_tests": allowed_blocked,
        "unexpected_nonpass_sim_tests": unexpected_nonpass,
        "drop_accounting": drop,
        "direct_core_trace_no_trace_parity": parity_cases,
        "claim_boundary": "Simulation and repository evidence only; no CVA6 IPC/Fmax improvement or trace-enabled FPGA resource delta is claimed.",
    }


def render_report(report: dict[str, Any]) -> str:
    drop = report["drop_accounting"]
    lines = [
        "# Noninterference Summary",
        "",
        f"- Source summary: `{report['summary']}`",
        f"- Status: {report['status']}",
        f"- Simulation overall: {report['simulation_overall']}",
        f"- Allowed blocked simulation tests: {', '.join(report['allowed_blocked_sim_tests']) if report['allowed_blocked_sim_tests'] else 'none'}",
        f"- DROP records: {drop['drop_records']}",
        f"- Dropped event count: {drop['dropped_event_count']}",
        "",
        "| Case | Summary status | Trace pass | No-trace pass | Parity pass |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in report["direct_core_trace_no_trace_parity"]:
        lines.append(
            f"| `{item['case']}` | {item['summary_status']} | {item['trace_pass']} | {item['no_trace_pass']} | {item['parity_pass']} |"
        )
    lines.extend(
        [
            "",
            "This report is simulation and repository evidence only. It does not claim CVA6 IPC/Fmax improvement, board runtime overhead, or trace-enabled FPGA resource delta.",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(root: Path, summary_path: Path, out_dir: Path) -> dict[str, Any]:
    report = analyze(root, summary_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "noninterference_summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "noninterference_report.md").write_text(render_report(report), encoding="utf-8", newline="\n")
    return report


def write_fixture(root: Path) -> Path:
    results = root / "results" / "vivado_sim"
    (results / "backpressure").mkdir(parents=True)
    (results / "backpressure" / "trace.jsonl").write_text('{"evt":"DROP","value":"0x2"}\n', encoding="utf-8")
    tests: dict[str, Any] = {
        "backpressure": {
            "status": "PASS",
            "counts": {"DROP": 1},
            "trace": "results/vivado_sim/backpressure/trace.jsonl",
        }
    }
    for case in DIRECT_CORE_CASES:
        case_dir = results / case
        case_dir.mkdir(parents=True)
        (case_dir / "xsim.log").write_text("[rvmt] Direct CVA6 xsim trace PASS after 1 cycles\n", encoding="utf-8")
        (case_dir / "xsim_notrace.log").write_text("[rvmt] Direct CVA6 xsim no-trace PASS after 1 cycles\n", encoding="utf-8")
        tests[case] = {"status": "PASS"}
    summary_path = results / "summary.json"
    summary_path.write_text(json.dumps({"overall": "PASS", "tests": tests}), encoding="utf-8")
    return summary_path


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        summary_path = write_fixture(root)
        out_dir = root / "out"
        report = write_outputs(root, summary_path, out_dir)
        if report["status"] != "PASS":
            print("[FAIL] self-test rejected valid noninterference fixture", file=sys.stderr)
            return 1
        if report["drop_accounting"]["dropped_event_count"] != 2:
            print("[FAIL] self-test missed DROP accounting", file=sys.stderr)
            return 1
        markdown = (out_dir / "noninterference_report.md").read_text(encoding="utf-8")
        if "does not claim CVA6 IPC/Fmax improvement" not in markdown:
            print("[FAIL] self-test missed non-claim wording", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        summary_path = write_fixture(root)
        summary = load_json(summary_path)
        summary["overall"] = "PASS_WITH_BLOCKED"
        summary["tests"]["cva6_full_soc_tohost_normal"] = {"status": "BLOCKED"}
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        report = write_outputs(root, summary_path, root / "out")
        if report["status"] != "PASS":
            print("[FAIL] self-test rejected allowed BLOCKED tohost boundary", file=sys.stderr)
            return 1
        if report["allowed_blocked_sim_tests"] != ["cva6_full_soc_tohost_normal"]:
            print("[FAIL] self-test did not record allowed BLOCKED tohost boundary", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        summary_path = write_fixture(root)
        (root / "results" / "vivado_sim" / "cva6_smoke" / "xsim_notrace.log").write_text("missing pass\n", encoding="utf-8")
        report = write_outputs(root, summary_path, root / "out")
        if report["status"] != "FAIL":
            print("[FAIL] self-test missed no-trace parity failure", file=sys.stderr)
            return 1

    print("[PASS] noninterference report self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a simulation-level noninterference evidence summary.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--summary", type=Path, default=Path("results/vivado_sim/summary.json"))
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.out_dir is None:
        parser.error("--out-dir is required unless --self-test is used")
    root = args.root.resolve()
    summary_path = args.summary if args.summary.is_absolute() else root / args.summary
    try:
        report = write_outputs(root, summary_path, args.out_dir)
    except Exception as exc:
        print(f"generate_noninterference_report: error: {exc}", file=sys.stderr)
        return 2
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
