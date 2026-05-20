from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = Path("docs/reports/artix7_35t_resource_report.md")
LOLV_BUILD = Path("vendor/litex/linux-on-litex-vexriscv/build")


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def parse_header(text: str) -> dict[str, str]:
    result = {}
    for key in ("Tool Version", "Date", "Design", "Device", "Design State"):
        match = re.search(rf"\|\s*{re.escape(key)}\s*:\s*(.+)", text)
        if match:
            result[key.lower().replace(" ", "_")] = match.group(1).strip()
    return result


def table_value(text: str, label: str) -> float | None:
    pattern = re.compile(rf"\|\s*{re.escape(label)}\s*\|\s*([0-9.]+)")
    match = pattern.search(text)
    return float(match.group(1)) if match else None


def parse_util(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    header = parse_header(text)
    lut = table_value(text, "Slice LUTs")
    ff = table_value(text, "Slice Registers")
    ramb36 = table_value(text, "RAMB36/FIFO*")
    ramb18 = table_value(text, "RAMB18")
    dsp = table_value(text, "DSPs")
    if None in (lut, ff, ramb36, ramb18, dsp):
        raise ValueError(f"{path}: incomplete utilization report")
    return {
        **header,
        "lut": int(lut),
        "ff": int(ff),
        "ramb36": ramb36,
        "ramb18": ramb18,
        "bram18_equiv": (ramb36 * 2.0) + ramb18,
        "dsp": int(dsp),
        "source": path.as_posix(),
    }


def parse_timing(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    header = parse_header(text)
    wns = None
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "WNS(ns)" not in line:
            continue
        for candidate in lines[index + 1 : index + 8]:
            cells = candidate.split()
            if len(cells) >= 2:
                try:
                    wns = float(cells[0])
                    break
                except ValueError:
                    continue
        if wns is not None:
            break
    if wns is None:
        match = re.search(r"Slack\s+\([^)]+\)\s*:\s*([-+]?[0-9.]+)ns", text)
        if match:
            wns = float(match.group(1))
    target = None
    clock_match = re.search(r"\b50\.000\b", text)
    if clock_match:
        target = "50 MHz"
    return {
        **header,
        "wns": wns,
        "clock_target": target or "50 MHz",
        "source": path.as_posix(),
    }


def blocked_reason(gateware: Path, util_path: Path, timing_path: Path) -> str:
    vivado_log = gateware / "vivado.log"
    if vivado_log.exists():
        text = vivado_log.read_text(encoding="utf-8", errors="replace")
        errors = []
        for line in text.splitlines():
            if "ERROR: [DRC UTLZ-1]" in line or "place_design failed" in line:
                errors.append(re.sub(r"\s+", " ", line).strip())
        if errors:
            return "; ".join(errors[:4])
    missing = []
    if not util_path.exists():
        missing.append(util_path.name)
    if not timing_path.exists():
        missing.append(timing_path.name)
    return f"missing {', '.join(missing)} under {gateware.as_posix()}"


def row_from_build(label: str, build_name: str, trace_records: int, profile: str) -> dict[str, Any]:
    gateware = resolve(LOLV_BUILD / build_name / "gateware")
    util_path = gateware / "embedfire_rise_pro_utilization_place.rpt"
    timing_path = gateware / "embedfire_rise_pro_timing.rpt"
    if not util_path.exists() or not timing_path.exists():
        return {
            "label": label,
            "status": "BLOCKED",
            "reason": blocked_reason(gateware, util_path, timing_path),
            "trace_records": trace_records,
            "profile": profile,
        }
    util = parse_util(util_path)
    timing = parse_timing(timing_path)
    return {
        "label": label,
        "status": "PRESENT",
        "lut": util["lut"],
        "ff": util["ff"],
        "bram18_equiv": util["bram18_equiv"],
        "dsp": util["dsp"],
        "wns": timing["wns"],
        "clock_target": timing["clock_target"],
        "trace_records": trace_records,
        "profile": profile,
        "util_report": util["source"],
        "timing_report": timing["source"],
    }


def pct_delta(value: float, baseline: float) -> str:
    delta = value - baseline
    pct = (delta / baseline * 100.0) if baseline else 0.0
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta:g} ({sign}{pct:.1f}%)"


def build_report(rows: list[dict[str, Any]]) -> str:
    baseline = next((row for row in rows if row["label"].startswith("baseline") and row["status"] == "PRESENT"), None)
    lines = [
        "# Artix-7 35T Resource Report",
        "",
        "This report covers the LiteX/VexRiscv 35T prototype only. It is not CVA6 resource evidence.",
        "",
        "| Config | Status | LUT | FF | BRAM18 equiv | DSP | WNS | Clock target | trace_records | profile |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |",
    ]
    for row in rows:
        if row["status"] != "PRESENT":
            lines.append(
                f"| {row['label']} | {row['status']}: {row['reason']} | n/a | n/a | n/a | n/a | n/a | n/a | {row['trace_records']} | {row['profile']} |"
            )
            continue
        lines.append(
            f"| {row['label']} | PRESENT | {row['lut']} | {row['ff']} | {row['bram18_equiv']:g} | {row['dsp']} | "
            f"{row['wns']} | {row['clock_target']} | {row['trace_records']} | {row['profile']} |"
        )
    if baseline is not None:
        lines.extend(["", "## Delta From Baseline", "", "| Config | LUT delta | FF delta | BRAM18 equiv delta | DSP delta | WNS delta |", "| --- | ---: | ---: | ---: | ---: | ---: |"])
        for row in rows:
            if row is baseline or row["status"] != "PRESENT":
                continue
            wns_delta = "n/a"
            if row.get("wns") is not None and baseline.get("wns") is not None:
                wns_delta = f"{row['wns'] - baseline['wns']:.3f}"
            lines.append(
                f"| {row['label']} | {pct_delta(row['lut'], baseline['lut'])} | {pct_delta(row['ff'], baseline['ff'])} | "
                f"{pct_delta(row['bram18_equiv'], baseline['bram18_equiv'])} | {pct_delta(row['dsp'], baseline['dsp'])} | {wns_delta} |"
            )
    lines.extend(
        [
            "",
            "## Sources",
            "",
        ]
    )
    for row in rows:
        if row["status"] == "PRESENT":
            lines.append(f"- `{row['label']}` utilization: `{row['util_report']}`")
            lines.append(f"- `{row['label']}` timing: `{row['timing_report']}`")
    lines.extend(
        [
            "",
            "Rows marked BLOCKED have no routed utilization/timing evidence and cannot support hardware cost claims.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(out: Path) -> None:
    rows = [
        row_from_build("baseline LiteX/VexRiscv", "embedfire_rise_pro", 0, "no-trace"),
        row_from_build("p0 trace 256", "embedfire_rise_pro_trace", 256, "p0"),
        row_from_build("p0 trace 512", "embedfire_rise_pro_trace_r512", 512, "p0"),
        row_from_build("p0 trace 1024", "embedfire_rise_pro_trace_r1024", 1024, "p0"),
        row_from_build("p0 trace 2048", "embedfire_rise_pro_trace_r2048", 2048, "p0"),
    ]
    out = resolve(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_report(rows), encoding="utf-8", newline="\n")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "util.rpt"
        path.write_text(
            """
| Device       : xc7a35tfgg484-2
| Design State : Fully Placed
| Slice LUTs                 | 10 | 0 | 0 | 20 | 50.00 |
| Slice Registers            | 12 | 0 | 0 | 40 | 30.00 |
|   RAMB36/FIFO*    |   2 | 0 | 0 | 50 | 4.00 |
|   RAMB18          |    1 | 0 | 0 | 100 | 1.00 |
| DSPs           |    3 | 0 | 0 | 90 | 3.33 |
""",
            encoding="utf-8",
        )
        util = parse_util(path)
        if util["lut"] != 10 or util["bram18_equiv"] != 5:
            print("[FAIL] 35T resource self-test missed utilization values", file=sys.stderr)
            return 1
        report = build_report([
            {"label": "baseline", "status": "PRESENT", "lut": 10, "ff": 12, "bram18_equiv": 5, "dsp": 3, "wns": 0.1, "clock_target": "50 MHz", "trace_records": 0, "profile": "no-trace", "util_report": "u", "timing_report": "t"},
            {"label": "trace", "status": "BLOCKED", "reason": "missing", "trace_records": 256, "profile": "p0"},
        ])
        if "BLOCKED" not in report or "LiteX/VexRiscv 35T" not in report:
            print("[FAIL] 35T resource self-test missed report boundary", file=sys.stderr)
            return 1
    print("[PASS] 35T resource report self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the Artix-7 35T LiteX/VexRiscv resource report.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    write_report(args.out)
    print(f"[PASS] 35T resource report written: {resolve(args.out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
