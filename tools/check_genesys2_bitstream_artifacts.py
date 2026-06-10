from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple


DEFAULT_BASELINE_DIR = Path("build/vivado/genesys2-cv64a6_imafdc_sv39")
DEFAULT_TRACE_DIR = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace")


class Check(NamedTuple):
    label: str
    level: str
    evidence: str

    @property
    def ok(self) -> bool:
        return self.level == "PASS"


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def display(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def check_file(root: Path, path: Path, label: str, *, missing_level: str = "FAIL") -> Check:
    full_path = resolve(root, path)
    if not full_path.exists():
        return Check(label, missing_level, f"missing {display(full_path, root)}")
    if not full_path.is_file():
        return Check(label, "FAIL", f"not a regular file: {display(full_path, root)}")
    size = full_path.stat().st_size
    if size <= 0:
        return Check(label, "FAIL", f"empty file: {display(full_path, root)}")
    return Check(label, "PASS", f"{display(full_path, root)} ({size} bytes)")


def parse_design_state(text: str) -> str | None:
    match = re.search(r"Design State\s*:\s*([^\r\n|]+)", text)
    return match.group(1).strip() if match else None


def parse_timing_status(path: Path) -> tuple[str, float, str | None]:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Slack\s+\(([^)]+)\)\s*:\s*([-+]?[0-9]+(?:\.[0-9]+)?)ns", text)
    if not match:
        raise ValueError("no Slack (...) timing line found")
    return match.group(1), float(match.group(2)), parse_design_state(text)


def check_timing(
    root: Path,
    path: Path,
    label: str,
    *,
    missing_level: str = "FAIL",
    expected_design_state: str | None = None,
) -> Check:
    full_path = resolve(root, path)
    if not full_path.exists():
        return Check(label, missing_level, f"missing {display(full_path, root)}")
    try:
        status, slack_ns, design_state = parse_timing_status(full_path)
    except ValueError as exc:
        return Check(label, "FAIL", f"{display(full_path, root)}: {exc}")
    if expected_design_state is not None and design_state != expected_design_state:
        return Check(
            label,
            "FAIL",
            f"Design State {design_state or 'UNKNOWN'} in {display(full_path, root)}; expected {expected_design_state}",
        )
    if status != "MET" or slack_ns < 0:
        return Check(label, "FAIL", f"Slack ({status}) {slack_ns:.3f} ns in {display(full_path, root)}")
    state = f", Design State {design_state}" if design_state else ""
    return Check(label, "PASS", f"Slack (MET) {slack_ns:.3f} ns{state} in {display(full_path, root)}")


def collect_checks(root: Path, baseline_dir: Path, trace_dir: Path) -> list[Check]:
    baseline = resolve(root, baseline_dir)
    trace = resolve(root, trace_dir)
    return [
        check_file(root, baseline / "work-fpga/ariane_xilinx.bit", "Baseline bitstream"),
        check_file(root, baseline / "work-fpga/ariane_xilinx.mcs", "Baseline flash image"),
        check_file(root, baseline / "work-fpga/ariane_xilinx.dcp", "Baseline routed checkpoint"),
        check_timing(
            root,
            baseline / "reports/ariane.timing.rpt",
            "Baseline routed timing",
            expected_design_state="Routed",
        ),
        check_file(root, baseline / "reports/ariane.utilization.rpt", "Baseline utilization report"),
        check_file(root, trace / "work-fpga/ariane_xilinx.bit", "Trace bitstream reuse artifact", missing_level="WARN"),
        check_file(root, trace / "work-fpga/ariane_xilinx.ltx", "Trace ILA probes"),
        check_file(root, trace / "work-fpga/ariane_xilinx_routed.dcp", "Trace routed checkpoint"),
        check_timing(
            root,
            trace / "work-fpga/ariane_xilinx_timing_summary_routed.rpt",
            "Trace routed timing",
            expected_design_state="Routed",
        ),
        check_file(root, trace / "reports/ariane.utilization.rpt", "Trace utilization report"),
        check_file(root, trace / "work-fpga/ariane_xilinx_route_status.rpt", "Trace route status report"),
    ]


def print_checks(checks: list[Check]) -> None:
    for check in checks:
        stream = sys.stderr if check.level == "FAIL" else sys.stdout
        print(f"[{check.level}] {check.label}: {check.evidence}", file=stream)


def exit_code(checks: list[Check], *, strict: bool) -> int:
    if any(check.level == "FAIL" for check in checks):
        return 1
    if strict and any(check.level == "WARN" for check in checks):
        return 1
    return 0


def self_test() -> int:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        baseline = root / DEFAULT_BASELINE_DIR
        trace = root / DEFAULT_TRACE_DIR
        for directory in (baseline / "work-fpga", baseline / "reports", trace / "work-fpga", trace / "reports"):
            directory.mkdir(parents=True, exist_ok=True)
        for path in (
            baseline / "work-fpga/ariane_xilinx.bit",
            baseline / "work-fpga/ariane_xilinx.mcs",
            baseline / "work-fpga/ariane_xilinx.dcp",
            baseline / "reports/ariane.utilization.rpt",
            trace / "work-fpga/ariane_xilinx.ltx",
            trace / "work-fpga/ariane_xilinx_routed.dcp",
            trace / "reports/ariane.utilization.rpt",
            trace / "work-fpga/ariane_xilinx_route_status.rpt",
        ):
            path.write_text("x\n", encoding="utf-8")
        (baseline / "reports/ariane.timing.rpt").write_text(
            "| Design State : Routed\nSlack (MET) : 0.177ns\n",
            encoding="utf-8",
        )
        (trace / "work-fpga/ariane_xilinx_timing_summary_routed.rpt").write_text(
            "| Design State : Routed\nSlack (MET) : 0.100ns\n",
            encoding="utf-8",
        )

        checks = collect_checks(root, DEFAULT_BASELINE_DIR, DEFAULT_TRACE_DIR)
        if exit_code(checks, strict=False) != 0:
            print("[FAIL] default inventory must tolerate a missing trace bitstream as WARN", file=sys.stderr)
            return 1
        if exit_code(checks, strict=True) == 0:
            print("[FAIL] strict inventory must fail on a missing trace bitstream", file=sys.stderr)
            return 1

        (trace / "work-fpga/ariane_xilinx.bit").write_text("x\n", encoding="utf-8")
        checks = collect_checks(root, DEFAULT_BASELINE_DIR, DEFAULT_TRACE_DIR)
        if exit_code(checks, strict=True) != 0:
            print("[FAIL] strict inventory must pass after trace bitstream is present", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 bitstream artifact checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventory Genesys2/CVA6 baseline and trace bitstream artifacts.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to current directory.")
    parser.add_argument("--baseline-dir", type=Path, default=DEFAULT_BASELINE_DIR)
    parser.add_argument("--trace-dir", type=Path, default=DEFAULT_TRACE_DIR)
    parser.add_argument("--strict", action="store_true", help="Treat WARN items as failures.")
    parser.add_argument("--self-test", action="store_true", help="Run fixture-based self-test.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = args.root.resolve()
    checks = collect_checks(root, args.baseline_dir, args.trace_dir)
    print_checks(checks)
    code = exit_code(checks, strict=args.strict)
    if code:
        mode = "strict artifact gate" if args.strict else "artifact inventory"
        print(f"[FAIL] Genesys2/CVA6 {mode}", file=sys.stderr)
        return code
    if any(check.level == "WARN" for check in checks):
        print("[WARN] Genesys2/CVA6 artifact inventory has reuse warnings; no Vivado command was run")
    else:
        print("[PASS] Genesys2/CVA6 artifact inventory")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
