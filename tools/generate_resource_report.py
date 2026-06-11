from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_UTIL_REPORT = Path("build/vivado/genesys2-cv64a6_imafdc_sv39/reports/ariane.utilization.rpt")
DEFAULT_TIMING_REPORT = Path("build/vivado/genesys2-cv64a6_imafdc_sv39/reports/ariane.timing.rpt")
DEFAULT_TRACE_UTIL_REPORT = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports/ariane.utilization.rpt")
DEFAULT_TRACE_TIMING_REPORT = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports/ariane.timing.rpt")
DEFAULT_SIM_SUMMARY = Path("results/vivado_sim/summary.json")
DEFAULT_OUT = Path("docs/07-evaluation-evidence/reports/resource_report.md")
TRACE_PARAM_FILES = (
    Path("rtl/trace/trace_top.sv"),
    Path("rtl/trace/cva6_rvfi_trace_adapter.sv"),
)


def parse_int(value: str) -> int:
    return int(value.strip().replace(",", ""))


def parse_report_header(text: str) -> dict[str, str]:
    header: dict[str, str] = {}
    for key in ("Tool Version", "Date", "Design", "Device", "Design State"):
        match = re.search(rf"\|\s*{re.escape(key)}\s*:\s*(.+)", text)
        if match:
            header[key.lower().replace(" ", "_")] = match.group(1).strip()
    return header


def parse_utilization(path: Path, instance: str = "ariane_xilinx") -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    header = parse_report_header(text)
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 10 or cells[0] != instance:
            continue
        try:
            return {
                **header,
                "instance": cells[0],
                "module": cells[1],
                "total_luts": parse_int(cells[2]),
                "logic_luts": parse_int(cells[3]),
                "lutrams": parse_int(cells[4]),
                "srls": parse_int(cells[5]),
                "ffs": parse_int(cells[6]),
                "ramb36": parse_int(cells[7]),
                "ramb18": parse_int(cells[8]),
                "dsp": parse_int(cells[9]),
            }
        except ValueError:
            continue
    raise ValueError(f"{path}: could not find utilization row for {instance}")


def first_field(block: str, label: str) -> str | None:
    match = re.search(rf"^\s*{re.escape(label)}:\s*(.+)$", block, re.MULTILINE)
    if not match:
        return None
    return match.group(1).strip()


def parse_timing(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    header = parse_report_header(text)
    start = text.find("Slack (")
    if start < 0:
        raise ValueError(f"{path}: no timing slack path found")
    end = text.find("\nSlack (", start + 1)
    block = text[start:] if end < 0 else text[start:end]

    slack_match = re.search(r"Slack\s+\(([^)]+)\)\s*:\s*([-+]?[0-9.]+)ns", block)
    requirement_match = re.search(r"Requirement:\s*([-+]?[0-9.]+)ns", block)
    data_delay_match = re.search(r"Data Path Delay:\s*([-+]?[0-9.]+)ns", block)
    logic_levels_match = re.search(r"Logic Levels:\s*([0-9]+)", block)
    if not slack_match or not requirement_match:
        raise ValueError(f"{path}: incomplete first timing path")

    slack_ns = float(slack_match.group(2))
    requirement_ns = float(requirement_match.group(1))
    achieved_period_ns = requirement_ns - slack_ns
    achieved_fmax_mhz = 1000.0 / achieved_period_ns if achieved_period_ns > 0 else None
    target_fmax_mhz = 1000.0 / requirement_ns if requirement_ns > 0 else None
    return {
        **header,
        "slack_status": slack_match.group(1),
        "slack_ns": slack_ns,
        "requirement_ns": requirement_ns,
        "target_fmax_mhz": target_fmax_mhz,
        "achieved_fmax_mhz": achieved_fmax_mhz,
        "data_path_delay_ns": float(data_delay_match.group(1)) if data_delay_match else None,
        "logic_levels": int(logic_levels_match.group(1)) if logic_levels_match else None,
        "source": first_field(block, "Source"),
        "destination": first_field(block, "Destination"),
        "path_group": first_field(block, "Path Group"),
    }


def parse_trace_params(paths: tuple[Path, ...] = TRACE_PARAM_FILES) -> dict[str, dict[str, int]]:
    params: dict[str, dict[str, int]] = {}
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        entry: dict[str, int] = {}
        for name in ("EVENT_QUEUE_DEPTH", "PIPELINE_INPUTS"):
            match = re.search(rf"parameter\s+int\s+{name}\s*=\s*([0-9]+)", text)
            if match:
                entry[name] = int(match.group(1))
        for name in ("INTERNAL_EVENT_QUEUE_DEPTH",):
            match = re.search(rf"localparam\s+int\s+{name}\s*=\s*([^;]+);", text)
            if not match:
                continue
            expr = match.group(1).strip()
            if expr.isdigit():
                entry[name] = int(expr)
                continue
            add_match = re.fullmatch(r"EVENT_QUEUE_DEPTH\s*\+\s*([0-9]+)", expr)
            if add_match and "EVENT_QUEUE_DEPTH" in entry:
                entry[name] = entry["EVENT_QUEUE_DEPTH"] + int(add_match.group(1))
        params[path.as_posix()] = entry
    return params


def parse_drop_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    return 0


def resolve_summary_trace(summary_path: Path, raw_trace: Any) -> Path:
    trace = Path(str(raw_trace).replace("\\", "/"))
    if trace.is_absolute():
        return trace
    return summary_path.parent.parent.parent / trace


def parse_drop_summary(summary_path: Path) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    tests = summary.get("tests", {})
    drop_rows: list[dict[str, Any]] = []
    for test_name, test in tests.items():
        drop_records = int(test.get("counts", {}).get("DROP", 0))
        drop_value_sum = 0
        trace_path = resolve_summary_trace(summary_path, test.get("trace", ""))
        if trace_path.exists():
            for line in trace_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                event = json.loads(line)
                if event.get("evt") == "DROP":
                    drop_value_sum += parse_drop_value(event.get("value", 0))
        elif drop_records:
            raise FileNotFoundError(f"{summary_path}: DROP count for {test_name} requires readable trace: {trace_path}")
        if drop_records or drop_value_sum:
            drop_rows.append(
                {
                    "test": test_name,
                    "drop_records": drop_records,
                    "drop_value_sum": drop_value_sum,
                    "status": test.get("status", ""),
                }
            )
    max_drop = max(drop_rows, key=lambda row: row["drop_value_sum"], default=None)
    return {
        "overall": summary.get("overall", ""),
        "drop_rows": drop_rows,
        "max_drop": max_drop,
    }


def fmt_float(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def delta_value(trace: int, baseline: int) -> str:
    delta = trace - baseline
    pct = (delta / baseline * 100.0) if baseline else 0.0
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta} ({sign}{pct:.2f}%)"


def build_report(
    util: dict[str, Any],
    timing: dict[str, Any],
    trace_params: dict[str, dict[str, int]],
    drops: dict[str, Any],
    util_report: Path = DEFAULT_UTIL_REPORT,
    timing_report: Path = DEFAULT_TIMING_REPORT,
    sim_summary: Path = DEFAULT_SIM_SUMMARY,
    trace_util: dict[str, Any] | None = None,
    trace_timing: dict[str, Any] | None = None,
    trace_util_report: Path = DEFAULT_TRACE_UTIL_REPORT,
    trace_timing_report: Path = DEFAULT_TRACE_TIMING_REPORT,
) -> str:
    bram18_equiv = util["ramb36"] * 2 + util["ramb18"]
    max_drop = drops["max_drop"] or {"test": "none", "drop_records": 0, "drop_value_sum": 0, "status": ""}
    lines = [
        "# Resource Report",
        "",
        "Phase 3.3 resource and timing snapshot.",
        "",
        "## Source Reports",
        "",
        f"- Utilization: `{util_report.as_posix()}`",
        f"- Timing: `{timing_report.as_posix()}`",
        f"- Simulation summary: `{sim_summary.as_posix()}`",
        "",
        "The Vivado numbers below are from the existing Genesys 2 routed `ariane_xilinx` report.",
        "Trace-specific queue/drop rows are taken from current trace RTL parameters and the latest `sim:trace-unit` summary.",
        "",
        "## Routed Utilization",
        "",
        "| Design | Device | State | LUT | FF | RAMB36 | RAMB18 | BRAM18 equiv | DSP |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {util.get('instance', 'n/a')} | {util.get('device', 'n/a')} | {util.get('design_state', 'n/a')} | "
            f"{util['total_luts']} | {util['ffs']} | {util['ramb36']} | {util['ramb18']} | {bram18_equiv} | {util['dsp']} |"
        ),
        "",
        "## Timing",
        "",
        "| Path group | Slack status | Slack (ns) | Requirement (ns) | Target Fmax (MHz) | Approx. achieved Fmax (MHz) | Data path delay (ns) | Logic levels |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {timing.get('path_group', 'n/a')} | {timing.get('slack_status', 'n/a')} | {fmt_float(timing['slack_ns'])} | "
            f"{fmt_float(timing['requirement_ns'])} | {fmt_float(timing['target_fmax_mhz'], 1)} | "
            f"{fmt_float(timing['achieved_fmax_mhz'], 1)} | {fmt_float(timing['data_path_delay_ns'])} | "
            f"{timing.get('logic_levels', 'n/a')} |"
        ),
        "",
        "Critical path:",
        "",
        f"- Source: `{timing.get('source', 'n/a')}`",
        f"- Destination: `{timing.get('destination', 'n/a')}`",
        "",
        "## Trace Queue And Drop",
        "",
        "| Item | Value |",
        "| --- | ---: |",
    ]
    for path, params in trace_params.items():
        if "EVENT_QUEUE_DEPTH" in params:
            lines.append(f"| `{path}` EVENT_QUEUE_DEPTH | {params['EVENT_QUEUE_DEPTH']} |")
        if "PIPELINE_INPUTS" in params:
            lines.append(f"| `{path}` PIPELINE_INPUTS | {params['PIPELINE_INPUTS']} |")
        if "INTERNAL_EVENT_QUEUE_DEPTH" in params:
            lines.append(f"| `{path}` INTERNAL_EVENT_QUEUE_DEPTH | {params['INTERNAL_EVENT_QUEUE_DEPTH']} |")
    lines.extend(
        [
            f"| Simulation overall | {drops.get('overall', 'n/a')} |",
            f"| Max DROP test | {max_drop['test']} |",
            f"| Max DROP records | {max_drop['drop_records']} |",
            f"| Max dropped event count | {max_drop['drop_value_sum']} |",
            "",
            "Drop rows:",
            "",
            "| Test | Status | DROP records | Dropped event count |",
            "| --- | --- | ---: | ---: |",
        ]
    )
    if drops["drop_rows"]:
        for row in drops["drop_rows"]:
            lines.append(f"| {row['test']} | {row['status']} | {row['drop_records']} | {row['drop_value_sum']} |")
    else:
        lines.append("| none | n/a | 0 | 0 |")
    lines.extend(
        [
            "",
            "## Trace-Enabled FPGA Delta",
            "",
        ]
    )
    if trace_util and trace_timing:
        trace_bram18_equiv = trace_util["ramb36"] * 2 + trace_util["ramb18"]
        trace_timing_closed = trace_timing.get("slack_status") == "MET" and float(trace_timing.get("slack_ns") or 0.0) >= 0.0
        trace_fmax = fmt_float(trace_timing["achieved_fmax_mhz"], 1) if trace_timing_closed else "not timing-closed"
        fmax_delta = (
            fmt_float((trace_timing["achieved_fmax_mhz"] or 0.0) - (timing["achieved_fmax_mhz"] or 0.0), 1)
            if trace_timing_closed
            else "n/a"
        )
        lines.extend(
            [
                f"- Trace utilization: `{trace_util_report.as_posix()}`",
                f"- Trace timing: `{trace_timing_report.as_posix()}`",
                "",
                "| Metric | Baseline | Trace-enabled | Delta |",
                "| --- | ---: | ---: | ---: |",
                f"| LUT | {util['total_luts']} | {trace_util['total_luts']} | {delta_value(trace_util['total_luts'], util['total_luts'])} |",
                f"| FF | {util['ffs']} | {trace_util['ffs']} | {delta_value(trace_util['ffs'], util['ffs'])} |",
                f"| BRAM18 equiv | {bram18_equiv} | {trace_bram18_equiv} | {delta_value(trace_bram18_equiv, bram18_equiv)} |",
                f"| DSP | {util['dsp']} | {trace_util['dsp']} | {delta_value(trace_util['dsp'], util['dsp'])} |",
                f"| Timing status | {timing.get('slack_status', 'n/a')} | {trace_timing.get('slack_status', 'n/a')} | n/a |",
                f"| Slack (ns) | {fmt_float(timing['slack_ns'])} | {fmt_float(trace_timing['slack_ns'])} | {fmt_float(trace_timing['slack_ns'] - timing['slack_ns'])} |",
                f"| Approx. achieved Fmax (MHz) | {fmt_float(timing['achieved_fmax_mhz'], 1)} | {trace_fmax} | {fmax_delta} |",
            ]
        )
        if not trace_timing_closed:
            lines.extend(
                [
                    "",
                    "Trace-enabled timing boundary: the current trace-enabled implementation report is not timing-closed. "
                    "This resource delta records routed utilization and observed timing status only; it must not be cited as "
                    "a trace-enabled Fmax, timing-closure, or performance-improvement result until a routed trace build reports `Slack (MET)`.",
                ]
            )
    else:
        lines.extend(
            [
                f"- Trace utilization report missing: `{trace_util_report.as_posix()}`",
                f"- Trace timing report missing: `{trace_timing_report.as_posix()}`",
                "",
                "Trace-enabled implementation delta is not available until `uv run rvmt bitstream:build-trace` completes.",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        util = root / "util.rpt"
        timing = root / "timing.rpt"
        trace_top = root / "trace_top.sv"
        adapter = root / "adapter.sv"
        summary = root / "summary.json"
        trace = root / "trace.jsonl"
        util.write_text(
            """
| Tool Version : Vivado v.2025.2
| Date         : Fri May  8 13:11:43 2026
| Design       : ariane_xilinx
| Device       : xc7k325tffg900-2
| Design State : Routed
| ariane_xilinx | (top) | 10 | 9 | 1 | 0 | 20 | 2 | 1 | 3 |
""",
            encoding="utf-8",
        )
        timing.write_text(
            """
Slack (MET) :             0.500ns  (required time - arrival time)
  Source:                 src_reg/C
  Destination:            dst_reg/D
  Path Group:             clk
  Requirement:            5.000ns
  Data Path Delay:        4.000ns
  Logic Levels:           7
""",
            encoding="utf-8",
        )
        trace_top.write_text("module trace_top #(parameter int EVENT_QUEUE_DEPTH = 8, parameter int PIPELINE_INPUTS = 1) (); endmodule\n", encoding="utf-8")
        adapter.write_text(
            "module cva6_rvfi_trace_adapter #(parameter int EVENT_QUEUE_DEPTH = 16, parameter int PIPELINE_INPUTS = 1) ();\n"
            "  localparam int INTERNAL_EVENT_QUEUE_DEPTH = EVENT_QUEUE_DEPTH + 1;\n"
            "endmodule\n",
            encoding="utf-8",
        )
        trace.write_text('{"evt":"DROP","value":"0x3"}\n{"evt":"DROP","value":"0x2"}\n', encoding="utf-8")
        summary.write_text(
            json.dumps(
                {
                    "overall": "PASS",
                    "tests": {
                        "drop": {
                            "status": "PASS",
                            "counts": {"DROP": 2},
                            "trace": str(trace),
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        parsed_util = parse_utilization(util)
        parsed_timing = parse_timing(timing)
        parsed_params = parse_trace_params((trace_top, adapter))
        parsed_drops = parse_drop_summary(summary)
        parsed_trace_util = {
            **parsed_util,
            "total_luts": 12,
            "ffs": 25,
            "ramb36": 2,
            "ramb18": 2,
            "dsp": 3,
        }
        parsed_trace_timing = {**parsed_timing, "slack_ns": 0.400, "achieved_fmax_mhz": 925.9}
        report = build_report(
            parsed_util,
            parsed_timing,
            parsed_params,
            parsed_drops,
            util,
            timing,
            summary,
            parsed_trace_util,
            parsed_trace_timing,
            root / "trace_util.rpt",
            root / "trace_timing.rpt",
        )
        if "| ariane_xilinx | xc7k325tffg900-2 | Routed | 10 | 20 | 2 | 1 | 5 | 3 |" not in report or "Max dropped event count | 5" not in report:
            print("[FAIL] resource report self-test output mismatch", file=sys.stderr)
            return 1
        if "| LUT | 10 | 12 | +2 (+20.00%) |" not in report:
            print("[FAIL] resource report self-test missed trace-enabled delta", file=sys.stderr)
            return 1
        if "| Timing status | MET | MET | n/a |" not in report:
            print("[FAIL] resource report self-test missed timing status row", file=sys.stderr)
            return 1
        if "INTERNAL_EVENT_QUEUE_DEPTH | 17" not in report:
            print("[FAIL] resource report self-test missed internal trace queue depth", file=sys.stderr)
            return 1

        repo_relative_trace = root / "results" / "vivado_sim" / "windows_path" / "trace.jsonl"
        repo_relative_trace.parent.mkdir(parents=True)
        repo_relative_trace.write_text('{"evt":"DROP","value":"0x4"}\n', encoding="utf-8")
        windows_path_summary = root / "results" / "vivado_sim" / "summary.json"
        windows_path_summary.write_text(
            json.dumps(
                {
                    "overall": "PASS",
                    "tests": {
                        "windows_path": {
                            "status": "PASS",
                            "counts": {"DROP": 1},
                            "trace": r"results\vivado_sim\windows_path\trace.jsonl",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        windows_path_drops = parse_drop_summary(windows_path_summary)
        if windows_path_drops["max_drop"]["drop_value_sum"] != 4:
            print("[FAIL] resource report self-test missed Windows-style relative trace path", file=sys.stderr)
            return 1

        missing_trace_summary = root / "missing_summary.json"
        missing_trace_summary.write_text(
            json.dumps(
                {
                    "overall": "PASS",
                    "tests": {
                        "drop": {
                            "status": "PASS",
                            "counts": {"DROP": 1},
                            "trace": "results/vivado_sim/drop/missing.trace.jsonl",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        try:
            parse_drop_summary(missing_trace_summary)
        except FileNotFoundError:
            pass
        else:
            print("[FAIL] resource report self-test missed unreadable DROP trace", file=sys.stderr)
            return 1
    print("[PASS] resource report self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the rv-maltrace Phase 3.3 resource report.")
    parser.add_argument("--util-report", type=Path, default=DEFAULT_UTIL_REPORT)
    parser.add_argument("--timing-report", type=Path, default=DEFAULT_TIMING_REPORT)
    parser.add_argument("--trace-util-report", type=Path, default=DEFAULT_TRACE_UTIL_REPORT)
    parser.add_argument("--trace-timing-report", type=Path, default=DEFAULT_TRACE_TIMING_REPORT)
    parser.add_argument("--sim-summary", type=Path, default=DEFAULT_SIM_SUMMARY)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true", help="Run parser/generator self-test.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        util = parse_utilization(args.util_report)
        timing = parse_timing(args.timing_report)
        trace_util = parse_utilization(args.trace_util_report) if args.trace_util_report.exists() else None
        trace_timing = parse_timing(args.trace_timing_report) if args.trace_timing_report.exists() else None
        trace_params = parse_trace_params()
        drops = parse_drop_summary(args.sim_summary)
        report = build_report(
            util,
            timing,
            trace_params,
            drops,
            args.util_report,
            args.timing_report,
            args.sim_summary,
            trace_util,
            trace_timing,
            args.trace_util_report,
            args.trace_timing_report,
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8", newline="\n")
    except Exception as exc:
        print(f"generate_resource_report: error: {exc}", file=sys.stderr)
        return 1

    print(f"[PASS] wrote resource report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
