from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

from experiment_common import (
    resolve,
)


DEFAULT_ARTIFACT_DIR = Path("build/vivado/genesys2-cv64a6_imafdc_sv39")
DEFAULT_SIM_SUMMARY = Path("results/vivado_sim/summary.json")
DEFAULT_CONSTRAINTS = Path("rtl/cva6/corev_apu/fpga/constraints/genesys-2.xdc")
DEFAULT_FPGA_RUN_TCL = Path("rtl/cva6/corev_apu/fpga/scripts/run.tcl")
DEFAULT_FPGA_SOURCES_TCL = Path("rtl/cva6/corev_apu/fpga/scripts/add_sources.tcl")
DEFAULT_BOARD_DIR = Path("vendor/vivado-boards/new/board_files/genesys2/H")

REQUIRED_WORK_ARTIFACTS = (
    ("bitstream", Path("work-fpga/ariane_xilinx.bit")),
    ("flash image", Path("work-fpga/ariane_xilinx.mcs")),
    ("post-route checkpoint", Path("work-fpga/ariane_xilinx.dcp")),
    ("GUI project", Path("project/ariane.xpr")),
)
REQUIRED_REPORTS = (
    ("utilization report", Path("reports/ariane.utilization.rpt")),
    ("timing report", Path("reports/ariane.timing.rpt")),
    ("route status report", Path("work-fpga/ariane_xilinx_route_status.rpt")),
)
REQUIRED_BOARD_FILES = ("board.xml", "mig.prj", "part0_pins.xml", "preset.xml")
REQUIRED_WORK_IP = (
    "xlnx_mig_7_ddr3.xci",
    "xlnx_clk_gen.xci",
    "xlnx_dpti_clk.xci",
)
EXPECTED_SIM_TESTS = (
    "smoke",
    "branch",
    "jump",
    "ecall",
    "syscall_ret",
    "pointer_string",
    "pointer_guardrails",
    "trap_illegal",
    "ebreak",
    "csr",
    "context",
    "backpressure",
    "filter",
    "rvfi_adapter",
    "cva6_smoke",
    "cva6_branch",
    "cva6_jump",
    "cva6_ecall",
    "cva6_trap_illegal",
    "cva6_ebreak",
)
ALLOWED_BLOCKED_SIM_TESTS = {
    "cva6_full_soc_tohost_normal": "normal full-SoC tohost/MMIO gate is tracked separately from board baseline",
}
ALLOWED_CHECK_TIMING_OPEN = {
    "no_clock",
    "unconstrained_internal_endpoints",
    "no_input_delay",
    "no_output_delay",
    "partial_input_delay",
}


class Check(NamedTuple):
    label: str
    ok: bool
    evidence: str
    level: str = "PASS"


def display(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def parse_int(value: str) -> int:
    return int(value.strip().replace(",", ""))


def check_nonempty_file(root: Path, path: Path, label: str) -> Check:
    full_path = resolve(root, path)
    if not full_path.exists():
        return Check(label, False, f"missing {display(full_path, root)}")
    if not full_path.is_file():
        return Check(label, False, f"not a regular file: {display(full_path, root)}")
    size = full_path.stat().st_size
    if size <= 0:
        return Check(label, False, f"empty file: {display(full_path, root)}")
    return Check(label, True, f"{display(full_path, root)} ({size} bytes)")


def resolve_summary_artifact(root: Path, summary_path: Path, raw_path: object) -> Path:
    path = Path(str(raw_path).replace("\\", "/"))
    if path.is_absolute():
        return path
    root_relative = root / path
    if root_relative.exists():
        return root_relative
    return summary_path.parent / path


def check_sim_summary(root: Path, summary: Path) -> Check:
    full_path = resolve(root, summary)
    if not full_path.exists():
        return Check("Vivado baseline simulation summary", False, f"missing {display(full_path, root)}")
    try:
        payload = json.loads(full_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return Check("Vivado baseline simulation summary", False, f"{display(full_path, root)} JSON error: {exc}")
    overall = payload.get("overall")
    tests = payload.get("tests", {})
    if not isinstance(tests, dict) or not tests:
        return Check("Vivado baseline simulation summary", False, "summary must contain a nonempty tests object")
    missing = [name for name in EXPECTED_SIM_TESTS if name not in tests]
    if missing:
        return Check("Vivado baseline simulation summary", False, f"missing expected tests: {', '.join(missing)}")
    malformed = sorted(name for name, row in tests.items() if not isinstance(row, dict))
    if malformed:
        return Check("Vivado baseline simulation summary", False, f"malformed test rows: {', '.join(malformed)}")
    failing = sorted(name for name, row in tests.items() if row.get("status") != "PASS")
    allowed_blocked = sorted(
        name
        for name in failing
        if name in ALLOWED_BLOCKED_SIM_TESTS and tests[name].get("status") == "BLOCKED"
    )
    unexpected_failing = sorted(name for name in failing if name not in allowed_blocked)
    if overall == "PASS":
        if failing:
            return Check("Vivado baseline simulation summary", False, f"failing tests: {', '.join(failing)}")
    elif overall == "PASS_WITH_BLOCKED":
        if unexpected_failing:
            return Check("Vivado baseline simulation summary", False, f"unexpected failing tests: {', '.join(unexpected_failing)}")
        if not allowed_blocked:
            return Check("Vivado baseline simulation summary", False, "overall PASS_WITH_BLOCKED but no allowed BLOCKED tests found")
    else:
        return Check("Vivado baseline simulation summary", False, f"overall={overall!r}")
    missing_artifacts: list[str] = []
    for name in (*EXPECTED_SIM_TESTS, *allowed_blocked):
        row = tests[name]
        for key in ("trace", "compare_log"):
            raw_path = row.get(key)
            if not raw_path:
                missing_artifacts.append(f"{name}.{key}")
                continue
            artifact = resolve_summary_artifact(root, full_path, raw_path)
            if not artifact.is_file():
                missing_artifacts.append(f"{name}.{key}: {display(artifact, root)}")
    if missing_artifacts:
        return Check(
            "Vivado baseline simulation summary",
            False,
            "missing referenced artifacts: " + ", ".join(missing_artifacts[:8]),
        )
    return Check(
        "Vivado baseline simulation summary",
        True,
        f"{display(full_path, root)} overall {overall}, {len(EXPECTED_SIM_TESTS)} expected tests PASS"
        + (f", allowed BLOCKED: {', '.join(allowed_blocked)}" if allowed_blocked else ""),
    )


def parse_timing_status(path: Path) -> tuple[str, float]:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Slack\s+\(([^)]+)\)\s*:\s*([-+]?[0-9]+(?:\.[0-9]+)?)ns", text)
    if not match:
        raise ValueError("no Slack (...) timing line found")
    return match.group(1), float(match.group(2))


def check_timing(root: Path, timing_report: Path) -> Check:
    full_path = resolve(root, timing_report)
    if not full_path.exists():
        return Check("Baseline routed timing", False, f"missing {display(full_path, root)}")
    try:
        status, slack_ns = parse_timing_status(full_path)
    except ValueError as exc:
        return Check("Baseline routed timing", False, f"{display(full_path, root)}: {exc}")
    if status != "MET" or slack_ns < 0:
        return Check("Baseline routed timing", False, f"Slack ({status}) {slack_ns:.3f} ns")
    return Check("Baseline routed timing", True, f"Slack (MET) {slack_ns:.3f} ns in {display(full_path, root)}")


def parse_check_timing_counts(path: Path) -> dict[str, int]:
    text = path.read_text(encoding="utf-8", errors="replace")
    counts: dict[str, int] = {}
    for name, count in re.findall(r"^\d+\.\s+checking\s+([A-Za-z0-9_]+)\s+\(([0-9,]+)\)", text, re.MULTILINE):
        counts[name] = parse_int(count)
    if not counts:
        raise ValueError("no check_timing table of contents found")
    return counts


def check_timing_constraints(root: Path, check_timing_report: Path) -> Check:
    full_path = resolve(root, check_timing_report)
    if not full_path.exists():
        return Check("Baseline check_timing constraints", False, f"missing {display(full_path, root)}")
    try:
        counts = parse_check_timing_counts(full_path)
    except ValueError as exc:
        return Check("Baseline check_timing constraints", False, f"{display(full_path, root)}: {exc}")

    unexpected = {name: count for name, count in counts.items() if count > 0 and name not in ALLOWED_CHECK_TIMING_OPEN}
    if unexpected:
        details = ", ".join(f"{name}={count}" for name, count in sorted(unexpected.items()))
        return Check("Baseline check_timing constraints", False, f"unexpected nonzero check_timing sections: {details}")

    open_items = {name: counts.get(name, 0) for name in sorted(ALLOWED_CHECK_TIMING_OPEN) if counts.get(name, 0) > 0}
    if open_items:
        details = ", ".join(f"{name}={count}" for name, count in open_items.items())
        return Check(
            "Baseline check_timing constraints",
            True,
            f"{display(full_path, root)} parsed; known open constraint warnings: {details}",
            "WARN",
        )

    return Check("Baseline check_timing constraints", True, f"{display(full_path, root)} parsed with all sections at 0")


def route_value(text: str, label: str) -> int:
    match = re.search(rf"# of {re.escape(label)}\.+\s*:\s*([0-9,]+)\s*:", text)
    if not match:
        raise ValueError(f"missing route counter: {label}")
    return parse_int(match.group(1))


def check_route_status(root: Path, route_report: Path) -> Check:
    full_path = resolve(root, route_report)
    if not full_path.exists():
        return Check("Baseline route status", False, f"missing {display(full_path, root)}")
    text = full_path.read_text(encoding="utf-8", errors="replace")
    try:
        routable = route_value(text, "routable nets")
        fully_routed = route_value(text, "fully routed nets")
        errors = route_value(text, "nets with routing errors")
    except ValueError as exc:
        return Check("Baseline route status", False, f"{display(full_path, root)}: {exc}")
    if errors or fully_routed != routable:
        return Check(
            "Baseline route status",
            False,
            f"{fully_routed}/{routable} routable nets fully routed, {errors} routing errors",
        )
    return Check("Baseline route status", True, f"{fully_routed}/{routable} routable nets fully routed, 0 routing errors")


def active_text(path: Path) -> str:
    lines = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(raw_line.split("#", 1)[0])
    return "\n".join(lines)


def active_commands(path: Path) -> list[str]:
    commands: list[str] = []
    current = ""
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        continued = line.endswith("\\")
        piece = line[:-1].rstrip() if continued else line
        current = f"{current} {piece.strip()}".strip()
        if not continued:
            commands.append(current)
            current = ""
    if current:
        commands.append(current)
    return commands


def tcl_command_matches(command: str, command_name: str, tokens: tuple[str, ...]) -> bool:
    return bool(re.match(rf"^\s*{re.escape(command_name)}\b", command)) and all(token in command for token in tokens)


def check_active_tcl_commands(
    root: Path,
    path: Path,
    label: str,
    specs: tuple[tuple[str, tuple[str, ...]], ...],
) -> Check:
    full_path = resolve(root, path)
    if not full_path.exists():
        return Check(label, False, f"missing {display(full_path, root)}")
    commands = active_commands(full_path)
    missing = [
        f"{command_name}({', '.join(tokens)})"
        for command_name, tokens in specs
        if not any(tcl_command_matches(command, command_name, tokens) for command in commands)
    ]
    if missing:
        return Check(label, False, f"{display(full_path, root)} missing active commands: {', '.join(missing)}")
    details = "; ".join(f"{command_name}: {', '.join(tokens)}" for command_name, tokens in specs)
    return Check(label, True, f"{display(full_path, root)} active commands match {details}")


def active_get_port_re(port: str) -> re.Pattern[str]:
    return re.compile(rf"\[get_ports\s+(?:\{{\s*)?{re.escape(port)}(?:\s*\}})?\]")


def xdc_pin_constraint_matches(command: str, port: str) -> bool:
    if not re.match(r"^\s*set_property\b", command):
        return False
    return "PACKAGE_PIN" in command and "IOSTANDARD" in command and bool(active_get_port_re(port).search(command))


def check_active_xdc_pin_constraints(root: Path, path: Path, label: str, ports: tuple[str, ...]) -> Check:
    full_path = resolve(root, path)
    if not full_path.exists():
        return Check(label, False, f"missing {display(full_path, root)}")
    commands = active_commands(full_path)
    missing = [port for port in ports if not any(xdc_pin_constraint_matches(command, port) for command in commands)]
    if missing:
        return Check(label, False, f"{display(full_path, root)} missing active pin/IO constraints: {', '.join(missing)}")
    return Check(label, True, f"{display(full_path, root)} active PACKAGE_PIN/IOSTANDARD constraints cover {', '.join(ports)}")


def check_board_files(root: Path, board_dir: Path) -> Check:
    full_dir = resolve(root, board_dir)
    missing = [name for name in REQUIRED_BOARD_FILES if not (full_dir / name).is_file()]
    if missing:
        return Check("Genesys 2 board files", False, f"{display(full_dir, root)} missing: {', '.join(missing)}")
    return Check("Genesys 2 board files", True, f"{display(full_dir, root)} has {', '.join(REQUIRED_BOARD_FILES)}")


def check_work_ip(root: Path, artifact_dir: Path) -> Check:
    work_dir = resolve(root, artifact_dir) / "work-fpga"
    missing = [name for name in REQUIRED_WORK_IP if not (work_dir / name).is_file()]
    if missing:
        return Check("DDR/clock generated IP artifacts", False, f"{display(work_dir, root)} missing: {', '.join(missing)}")
    return Check("DDR/clock generated IP artifacts", True, f"{display(work_dir, root)} has {', '.join(REQUIRED_WORK_IP)}")


def run_checks(
    root: Path,
    artifact_dir: Path,
    sim_summary: Path,
    constraints: Path,
    fpga_run_tcl: Path,
    fpga_sources_tcl: Path,
    board_dir: Path,
) -> list[Check]:
    checks = [check_sim_summary(root, sim_summary)]
    checks.extend(check_nonempty_file(root, artifact_dir / path, label) for label, path in REQUIRED_WORK_ARTIFACTS)
    checks.extend(check_nonempty_file(root, artifact_dir / path, label) for label, path in REQUIRED_REPORTS)
    checks.append(check_timing(root, artifact_dir / Path("reports/ariane.timing.rpt")))
    checks.append(check_timing_constraints(root, artifact_dir / Path("reports/ariane.check_timing.rpt")))
    checks.append(check_route_status(root, artifact_dir / Path("work-fpga/ariane_xilinx_route_status.rpt")))
    checks.append(
        check_active_xdc_pin_constraints(
            root,
            constraints,
            "Genesys 2 reset/clock/UART constraints",
            ("cpu_resetn", "prog_clko", "tx", "rx"),
        )
    )
    checks.append(
        check_active_tcl_commands(
            root,
            fpga_run_tcl,
            "Genesys 2 DDR/clock build path",
            (
                ("add_files", ("constraints/genesys-2.xdc",)),
                ("read_ip", ("xlnx_mig_7_ddr3",)),
                ("read_ip", ("xlnx_clk_gen",)),
                ("read_ip", ("xlnx_dpti_clk",)),
            ),
        )
    )
    checks.append(
        check_active_tcl_commands(
            root,
            fpga_sources_tcl,
            "Genesys 2 UART source path",
            (("read_vhdl", ("apb_uart.vhd", "uart_receiver.vhd", "uart_transmitter.vhd")),),
        )
    )
    checks.append(check_board_files(root, board_dir))
    checks.append(check_work_ip(root, artifact_dir))
    return checks


def write_fixture(root: Path) -> None:
    artifact_dir = root / DEFAULT_ARTIFACT_DIR
    work_dir = artifact_dir / "work-fpga"
    reports_dir = artifact_dir / "reports"
    board_dir = root / DEFAULT_BOARD_DIR
    for directory in (work_dir, reports_dir, board_dir, root / DEFAULT_CONSTRAINTS.parent, root / DEFAULT_FPGA_RUN_TCL.parent, root / DEFAULT_SIM_SUMMARY.parent):
        directory.mkdir(parents=True, exist_ok=True)

    for _, path in REQUIRED_WORK_ARTIFACTS:
        full_path = artifact_dir / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_bytes(b"artifact\n")
    for _, path in REQUIRED_REPORTS:
        full_path = artifact_dir / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text("report\n", encoding="utf-8")

    (reports_dir / "ariane.timing.rpt").write_text("Slack (MET) : 0.177ns\n", encoding="utf-8")
    (reports_dir / "ariane.check_timing.rpt").write_text(
        "\n".join(
            [
                "1. checking no_clock (0)",
                "2. checking constant_clock (0)",
                "3. checking pulse_width_clock (0)",
                "4. checking unconstrained_internal_endpoints (0)",
                "5. checking no_input_delay (0)",
                "6. checking no_output_delay (0)",
                "7. checking multiple_clock (0)",
                "8. checking generated_clocks (0)",
                "9. checking loops (0)",
                "10. checking partial_input_delay (0)",
                "11. checking partial_output_delay (0)",
                "12. checking latch_loops (0)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (work_dir / "ariane_xilinx_route_status.rpt").write_text(
        "\n".join(
            [
                "# of routable nets..................... :      130576 :",
                "# of fully routed nets............. :      130576 :",
                "# of nets with routing errors.......... :           0 :",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    for name in REQUIRED_BOARD_FILES:
        (board_dir / name).write_text("board\n", encoding="utf-8")
    for name in REQUIRED_WORK_IP:
        (work_dir / name).write_text("ip\n", encoding="utf-8")

    (root / DEFAULT_CONSTRAINTS).write_text(
        "set_property -dict {PACKAGE_PIN A1 IOSTANDARD LVCMOS33} [get_ports cpu_resetn]\n"
        "set_property -dict {PACKAGE_PIN A2 IOSTANDARD LVCMOS33} [get_ports prog_clko]\n"
        "## UART\n"
        "set_property -dict {PACKAGE_PIN A3 IOSTANDARD LVCMOS33} [get_ports tx]\n"
        "set_property -dict {PACKAGE_PIN A4 IOSTANDARD LVCMOS33} [get_ports rx]\n",
        encoding="utf-8",
    )
    (root / DEFAULT_FPGA_RUN_TCL).write_text(
        "add_files constraints/genesys-2.xdc\n"
        "read_ip xlnx_mig_7_ddr3\n"
        "read_ip xlnx_clk_gen\n"
        "read_ip xlnx_dpti_clk\n",
        encoding="utf-8",
    )
    (root / DEFAULT_FPGA_SOURCES_TCL).write_text(
        "read_vhdl {apb_uart.vhd uart_receiver.vhd uart_transmitter.vhd}\n",
        encoding="utf-8",
    )
    tests = {}
    for test_name in EXPECTED_SIM_TESTS:
        test_dir = root / "results" / "vivado_sim" / test_name
        test_dir.mkdir(parents=True, exist_ok=True)
        (test_dir / "trace.jsonl").write_text("{}\n", encoding="utf-8")
        (test_dir / "compare.log").write_text("[PASS]\n", encoding="utf-8")
        tests[test_name] = {
            "status": "PASS",
            "trace": f"results\\vivado_sim\\{test_name}\\trace.jsonl",
            "compare_log": f"results\\vivado_sim\\{test_name}\\compare.log",
        }
    (root / DEFAULT_SIM_SUMMARY).write_text(
        json.dumps({"overall": "PASS", "tests": tests}),
        encoding="utf-8",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        checks = run_checks(
            root,
            DEFAULT_ARTIFACT_DIR,
            DEFAULT_SIM_SUMMARY,
            DEFAULT_CONSTRAINTS,
            DEFAULT_FPGA_RUN_TCL,
            DEFAULT_FPGA_SOURCES_TCL,
            DEFAULT_BOARD_DIR,
        )
        if any(not check.ok for check in checks):
            for check in checks:
                if not check.ok:
                    print(f"[FAIL] self-test false positive: {check.label}: {check.evidence}", file=sys.stderr)
            return 1

        (root / DEFAULT_ARTIFACT_DIR / "work-fpga" / "ariane_xilinx.bit").unlink()
        checks = run_checks(
            root,
            DEFAULT_ARTIFACT_DIR,
            DEFAULT_SIM_SUMMARY,
            DEFAULT_CONSTRAINTS,
            DEFAULT_FPGA_RUN_TCL,
            DEFAULT_FPGA_SOURCES_TCL,
            DEFAULT_BOARD_DIR,
        )
        if not any("bitstream" in check.label and not check.ok for check in checks):
            print("[FAIL] self-test missed missing bitstream", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        summary_path = root / DEFAULT_SIM_SUMMARY
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
        blocked_dir = root / "results" / "vivado_sim" / "cva6_full_soc_tohost_normal"
        blocked_dir.mkdir(parents=True, exist_ok=True)
        (blocked_dir / "trace.jsonl").write_text('{"evt":"RETIRE"}\n', encoding="utf-8")
        (blocked_dir / "compare.log").write_text("[BLOCKED] full SoC normal tohost timeout\n", encoding="utf-8")
        payload["overall"] = "PASS_WITH_BLOCKED"
        payload["tests"]["cva6_full_soc_tohost_normal"] = {
            "status": "BLOCKED",
            "trace": "results\\vivado_sim\\cva6_full_soc_tohost_normal\\trace.jsonl",
            "compare_log": "results\\vivado_sim\\cva6_full_soc_tohost_normal\\compare.log",
        }
        summary_path.write_text(json.dumps(payload), encoding="utf-8")
        checks = run_checks(
            root,
            DEFAULT_ARTIFACT_DIR,
            DEFAULT_SIM_SUMMARY,
            DEFAULT_CONSTRAINTS,
            DEFAULT_FPGA_RUN_TCL,
            DEFAULT_FPGA_SOURCES_TCL,
            DEFAULT_BOARD_DIR,
        )
        if any(not check.ok for check in checks):
            for check in checks:
                if not check.ok:
                    print(f"[FAIL] self-test rejected allowed blocked tohost gate: {check.label}: {check.evidence}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_SIM_SUMMARY).write_text(json.dumps({"overall": "PASS", "tests": {}}), encoding="utf-8")
        checks = run_checks(
            root,
            DEFAULT_ARTIFACT_DIR,
            DEFAULT_SIM_SUMMARY,
            DEFAULT_CONSTRAINTS,
            DEFAULT_FPGA_RUN_TCL,
            DEFAULT_FPGA_SOURCES_TCL,
            DEFAULT_BOARD_DIR,
        )
        if not any(check.label == "Vivado baseline simulation summary" and not check.ok for check in checks):
            print("[FAIL] self-test missed empty simulation test matrix", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_ARTIFACT_DIR / "work-fpga" / "ariane_xilinx_route_status.rpt").write_text(
            "\n".join(
                [
                    "# of routable nets..................... :      130576 :",
                    "# of fully routed nets............. :      130575 :",
                    "# of nets with routing errors.......... :           1 :",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        checks = run_checks(
            root,
            DEFAULT_ARTIFACT_DIR,
            DEFAULT_SIM_SUMMARY,
            DEFAULT_CONSTRAINTS,
            DEFAULT_FPGA_RUN_TCL,
            DEFAULT_FPGA_SOURCES_TCL,
            DEFAULT_BOARD_DIR,
        )
        if not any(check.label == "Baseline route status" and not check.ok for check in checks):
            print("[FAIL] self-test missed route errors", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_ARTIFACT_DIR / "reports" / "ariane.check_timing.rpt").write_text(
            "\n".join(
                [
                    "1. checking no_clock (0)",
                    "2. checking constant_clock (0)",
                    "3. checking pulse_width_clock (0)",
                    "4. checking unconstrained_internal_endpoints (0)",
                    "5. checking no_input_delay (0)",
                    "6. checking no_output_delay (0)",
                    "7. checking multiple_clock (0)",
                    "8. checking generated_clocks (0)",
                    "9. checking loops (1)",
                    "10. checking partial_input_delay (0)",
                    "11. checking partial_output_delay (0)",
                    "12. checking latch_loops (0)",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        checks = run_checks(
            root,
            DEFAULT_ARTIFACT_DIR,
            DEFAULT_SIM_SUMMARY,
            DEFAULT_CONSTRAINTS,
            DEFAULT_FPGA_RUN_TCL,
            DEFAULT_FPGA_SOURCES_TCL,
            DEFAULT_BOARD_DIR,
        )
        if not any(check.label == "Baseline check_timing constraints" and not check.ok for check in checks):
            print("[FAIL] self-test missed unexpected check_timing issue", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_ARTIFACT_DIR / "reports" / "ariane.timing.rpt").write_text("Slack (VIOLATED) : -0.125ns\n", encoding="utf-8")
        checks = run_checks(
            root,
            DEFAULT_ARTIFACT_DIR,
            DEFAULT_SIM_SUMMARY,
            DEFAULT_CONSTRAINTS,
            DEFAULT_FPGA_RUN_TCL,
            DEFAULT_FPGA_SOURCES_TCL,
            DEFAULT_BOARD_DIR,
        )
        if not any(check.label == "Baseline routed timing" and not check.ok for check in checks):
            print("[FAIL] self-test missed violated timing", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_CONSTRAINTS).write_text(
            "# set_property -dict {} [get_ports cpu_resetn]\n"
            "# set_property -dict {} [get_ports prog_clko]\n"
            "# set_property -dict {} [get_ports tx]\n"
            "# set_property -dict {} [get_ports rx]\n",
            encoding="utf-8",
        )
        checks = run_checks(
            root,
            DEFAULT_ARTIFACT_DIR,
            DEFAULT_SIM_SUMMARY,
            DEFAULT_CONSTRAINTS,
            DEFAULT_FPGA_RUN_TCL,
            DEFAULT_FPGA_SOURCES_TCL,
            DEFAULT_BOARD_DIR,
        )
        if not any(check.label == "Genesys 2 reset/clock/UART constraints" and not check.ok for check in checks):
            print("[FAIL] self-test missed commented-only constraints", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_CONSTRAINTS).write_text(
            "set_false_path -from [get_ports cpu_resetn]\n"
            "set_false_path -from [get_ports prog_clko]\n"
            "set_false_path -from [get_ports tx]\n"
            "set_false_path -from [get_ports rx]\n",
            encoding="utf-8",
        )
        checks = run_checks(
            root,
            DEFAULT_ARTIFACT_DIR,
            DEFAULT_SIM_SUMMARY,
            DEFAULT_CONSTRAINTS,
            DEFAULT_FPGA_RUN_TCL,
            DEFAULT_FPGA_SOURCES_TCL,
            DEFAULT_BOARD_DIR,
        )
        if not any(check.label == "Genesys 2 reset/clock/UART constraints" and not check.ok for check in checks):
            print("[FAIL] self-test missed non-pin XDC commands", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_FPGA_RUN_TCL).write_text(
            'puts "constraints/genesys-2.xdc xlnx_mig_7_ddr3 xlnx_clk_gen xlnx_dpti_clk"\n',
            encoding="utf-8",
        )
        checks = run_checks(
            root,
            DEFAULT_ARTIFACT_DIR,
            DEFAULT_SIM_SUMMARY,
            DEFAULT_CONSTRAINTS,
            DEFAULT_FPGA_RUN_TCL,
            DEFAULT_FPGA_SOURCES_TCL,
            DEFAULT_BOARD_DIR,
        )
        if not any(check.label == "Genesys 2 DDR/clock build path" and not check.ok for check in checks):
            print("[FAIL] self-test missed non-command DDR/clock Tcl evidence", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_FPGA_SOURCES_TCL).write_text(
            'puts "apb_uart.vhd uart_receiver.vhd uart_transmitter.vhd"\n',
            encoding="utf-8",
        )
        checks = run_checks(
            root,
            DEFAULT_ARTIFACT_DIR,
            DEFAULT_SIM_SUMMARY,
            DEFAULT_CONSTRAINTS,
            DEFAULT_FPGA_RUN_TCL,
            DEFAULT_FPGA_SOURCES_TCL,
            DEFAULT_BOARD_DIR,
        )
        if not any(check.label == "Genesys 2 UART source path" and not check.ok for check in checks):
            print("[FAIL] self-test missed non-command UART source Tcl evidence", file=sys.stderr)
            return 1

    print("[PASS] board baseline self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check rv-maltrace Phase 4.1 Genesys 2 baseline preflight evidence.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to the current directory.")
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    parser.add_argument("--sim-summary", type=Path, default=DEFAULT_SIM_SUMMARY)
    parser.add_argument("--constraints", type=Path, default=DEFAULT_CONSTRAINTS)
    parser.add_argument("--fpga-run-tcl", type=Path, default=DEFAULT_FPGA_RUN_TCL)
    parser.add_argument("--fpga-sources-tcl", type=Path, default=DEFAULT_FPGA_SOURCES_TCL)
    parser.add_argument("--board-dir", type=Path, default=DEFAULT_BOARD_DIR)
    parser.add_argument("--self-test", action="store_true", help="Run positive and negative coverage checks for the preflight.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = args.root.resolve()
    checks = run_checks(
        root,
        args.artifact_dir,
        args.sim_summary,
        args.constraints,
        args.fpga_run_tcl,
        args.fpga_sources_tcl,
        args.board_dir,
    )
    for check in checks:
        status = check.level if check.ok else "FAIL"
        stream = sys.stdout if check.ok else sys.stderr
        print(f"[{status}] {check.label}: {check.evidence}", file=stream)

    if any(not check.ok for check in checks):
        return 1

    if any(check.level == "WARN" for check in checks):
        print("[PASS] Genesys 2 baseline preflight evidence is present; review WARN rows before board use")
    else:
        print("[PASS] Genesys 2 baseline preflight evidence is present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
