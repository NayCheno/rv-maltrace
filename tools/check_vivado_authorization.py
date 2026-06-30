from __future__ import annotations

import argparse
import re
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import NamedTuple

from experiment_common import (
    resolve,
)


DEFAULT_CONFIG = Path("pyproject.toml")
DEFAULT_ARTIFACT_DIR = Path("build/vivado/genesys2-cv64a6_imafdc_sv39")
DEFAULT_BOARD_DIR = Path("vendor/vivado-boards/new/board_files/genesys2/H")
GENESYS2_PART = "xc7k325tffg900-2"
GENESYS2_REPORT_DEVICE = "7k325t-ffg900"
GENESYS2_BOARD = "digilentinc.com:genesys2:part0:1.1"
REQUIRED_BOARD_FILES = ("board.xml", "mig.prj", "part0_pins.xml", "preset.xml")
REQUIRED_BITSTREAM_ARTIFACTS = (
    ("bitstream", Path("work-fpga/ariane_xilinx.bit")),
    ("cfgmem flash image", Path("work-fpga/ariane_xilinx.mcs")),
    ("post-route checkpoint", Path("work-fpga/ariane_xilinx.dcp")),
    ("routed timing report", Path("reports/ariane.timing.rpt")),
    ("route status report", Path("work-fpga/ariane_xilinx_route_status.rpt")),
)


class Check(NamedTuple):
    label: str
    ok: bool
    evidence: str


def display(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def parse_int(value: str) -> int:
    return int(value.strip().replace(",", ""))


def load_config(root: Path, config_path: Path) -> dict:
    full_path = resolve(root, config_path)
    data = tomllib.loads(full_path.read_text(encoding="utf-8"))
    return data.get("tool", {}).get("rv-maltrace", {})


def configured_path(root: Path, value: object) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def check_config_target(root: Path, config_path: Path) -> Check:
    full_path = resolve(root, config_path)
    if not full_path.exists():
        return Check("Configured Vivado target", False, f"missing {display(full_path, root)}")
    try:
        config = load_config(root, config_path)
    except tomllib.TOMLDecodeError as exc:
        return Check("Configured Vivado target", False, f"{display(full_path, root)} TOML error: {exc}")

    board = str(config.get("board", ""))
    part = str(config.get("xilinx_part", GENESYS2_PART))
    board_part = str(config.get("xilinx_board", GENESYS2_BOARD))
    vivado = configured_path(root, config.get("vivado", "vivado"))
    if board != "genesys2":
        return Check("Configured Vivado target", False, f"board={board!r}, expected 'genesys2'")
    if part != GENESYS2_PART:
        return Check("Configured Vivado target", False, f"xilinx_part={part!r}, expected {GENESYS2_PART}")
    if board_part != GENESYS2_BOARD:
        return Check("Configured Vivado target", False, f"xilinx_board={board_part!r}, expected {GENESYS2_BOARD}")
    if any(sep in str(config.get("vivado", "")) for sep in ("/", "\\")) and not vivado.exists():
        return Check("Configured Vivado target", False, f"configured Vivado executable missing: {display(vivado, root)}")
    return Check(
        "Configured Vivado target",
        True,
        f"{display(full_path, root)} selects {GENESYS2_PART} / {GENESYS2_BOARD} with Vivado {display(vivado, root)}",
    )


def check_board_files(root: Path, board_dir: Path) -> Check:
    full_dir = resolve(root, board_dir)
    missing = [name for name in REQUIRED_BOARD_FILES if not (full_dir / name).is_file()]
    if missing:
        return Check("Genesys 2 board files", False, f"{display(full_dir, root)} missing: {', '.join(missing)}")
    return Check("Genesys 2 board files", True, f"{display(full_dir, root)} has {', '.join(REQUIRED_BOARD_FILES)}")


def check_artifacts(root: Path, artifact_dir: Path) -> Check:
    full_dir = resolve(root, artifact_dir)
    missing = []
    for label, path in REQUIRED_BITSTREAM_ARTIFACTS:
        full_path = full_dir / path
        if not full_path.is_file() or full_path.stat().st_size <= 0:
            missing.append(f"{label}: {display(full_path, root)}")
    if missing:
        return Check("Bitstream/license artifact evidence", False, "missing or empty " + ", ".join(missing))
    bit = full_dir / "work-fpga" / "ariane_xilinx.bit"
    mcs = full_dir / "work-fpga" / "ariane_xilinx.mcs"
    dcp = full_dir / "work-fpga" / "ariane_xilinx.dcp"
    return Check(
        "Bitstream/license artifact evidence",
        True,
        f"{display(bit, root)} ({bit.stat().st_size} bytes), {display(mcs, root)}, and {display(dcp, root)} exist",
    )


def parse_report_header(text: str) -> dict[str, str]:
    header: dict[str, str] = {}
    for key in ("Tool Version", "Date", "Design", "Device", "Design State"):
        match = re.search(rf"\|\s*{re.escape(key)}\s*:\s*(.+)", text)
        if match:
            header[key] = match.group(1).strip()
    return header


def parse_timing_status(text: str) -> tuple[str, float]:
    match = re.search(r"Slack\s+\(([^)]+)\)\s*:\s*([-+]?[0-9]+(?:\.[0-9]+)?)ns", text)
    if not match:
        raise ValueError("no Slack (...) timing line found")
    return match.group(1), float(match.group(2))


def check_routed_report(root: Path, artifact_dir: Path) -> Check:
    report = resolve(root, artifact_dir) / "reports" / "ariane.timing.rpt"
    if not report.exists():
        return Check("Routed implementation report", False, f"missing {display(report, root)}")
    text = report.read_text(encoding="utf-8", errors="replace")
    header = parse_report_header(text)
    design_state = header.get("Design State", "")
    device = header.get("Device", "")
    tool = header.get("Tool Version", "unknown Vivado")
    date = header.get("Date", "unknown date")
    try:
        slack_status, slack_ns = parse_timing_status(text)
    except ValueError as exc:
        return Check("Routed implementation report", False, f"{display(report, root)}: {exc}")
    if design_state != "Routed":
        return Check("Routed implementation report", False, f"Design State={design_state!r}, expected Routed")
    if GENESYS2_REPORT_DEVICE not in device and GENESYS2_PART not in device:
        return Check("Routed implementation report", False, f"Device={device!r}, expected Genesys 2 Kintex-7 target")
    if slack_status != "MET" or slack_ns < 0:
        return Check("Routed implementation report", False, f"Slack ({slack_status}) {slack_ns:.3f} ns")
    return Check(
        "Routed implementation report",
        True,
        f"{display(report, root)} is Routed for {device}, Slack (MET) {slack_ns:.3f} ns, {tool}, {date}",
    )


def route_value(text: str, label: str) -> int:
    match = re.search(rf"# of {re.escape(label)}\.+\s*:\s*([0-9,]+)\s*:", text)
    if not match:
        raise ValueError(f"missing route counter: {label}")
    return parse_int(match.group(1))


def check_route_status(root: Path, artifact_dir: Path) -> Check:
    report = resolve(root, artifact_dir) / "work-fpga" / "ariane_xilinx_route_status.rpt"
    if not report.exists():
        return Check("Route implementation status", False, f"missing {display(report, root)}")
    text = report.read_text(encoding="utf-8", errors="replace")
    try:
        routable = route_value(text, "routable nets")
        fully_routed = route_value(text, "fully routed nets")
        errors = route_value(text, "nets with routing errors")
    except ValueError as exc:
        return Check("Route implementation status", False, f"{display(report, root)}: {exc}")
    if errors or fully_routed != routable:
        return Check("Route implementation status", False, f"{fully_routed}/{routable} routed, {errors} routing errors")
    return Check("Route implementation status", True, f"{fully_routed}/{routable} routable nets fully routed, 0 routing errors")


def run_checks(root: Path, config_path: Path, artifact_dir: Path, board_dir: Path) -> list[Check]:
    return [
        check_config_target(root, config_path),
        check_board_files(root, board_dir),
        check_artifacts(root, artifact_dir),
        check_routed_report(root, artifact_dir),
        check_route_status(root, artifact_dir),
    ]


def write_fixture(root: Path) -> None:
    artifact_dir = root / DEFAULT_ARTIFACT_DIR
    work_dir = artifact_dir / "work-fpga"
    reports_dir = artifact_dir / "reports"
    board_dir = root / DEFAULT_BOARD_DIR
    work_dir.mkdir(parents=True)
    reports_dir.mkdir(parents=True)
    board_dir.mkdir(parents=True)
    vivado = root / "Vivado" / "bin" / "vivado.bat"
    vivado.parent.mkdir(parents=True)
    vivado.write_text("@echo off\n", encoding="utf-8")
    (root / DEFAULT_CONFIG).write_text(
        f"""
[tool.rv-maltrace]
vivado = "{vivado.as_posix()}"
board = "genesys2"
xilinx_part = "{GENESYS2_PART}"
xilinx_board = "{GENESYS2_BOARD}"
""",
        encoding="utf-8",
    )
    for name in REQUIRED_BOARD_FILES:
        (board_dir / name).write_text("board\n", encoding="utf-8")
    for _, path in REQUIRED_BITSTREAM_ARTIFACTS:
        full_path = artifact_dir / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text("artifact\n", encoding="utf-8")
    (reports_dir / "ariane.timing.rpt").write_text(
        f"""
| Tool Version : Vivado v.2025.2
| Date         : Fri May  8 13:11:40 2026
| Design       : ariane_xilinx
| Device       : {GENESYS2_REPORT_DEVICE}
| Design State : Routed

Slack (MET) :             0.177ns
""",
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


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        checks = run_checks(root, DEFAULT_CONFIG, DEFAULT_ARTIFACT_DIR, DEFAULT_BOARD_DIR)
        if any(not check.ok for check in checks):
            for check in checks:
                if not check.ok:
                    print(f"[FAIL] self-test false positive: {check.label}: {check.evidence}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_ARTIFACT_DIR / "work-fpga" / "ariane_xilinx.bit").unlink()
        checks = run_checks(root, DEFAULT_CONFIG, DEFAULT_ARTIFACT_DIR, DEFAULT_BOARD_DIR)
        if not any(check.label == "Bitstream/license artifact evidence" and not check.ok for check in checks):
            print("[FAIL] self-test missed missing bitstream", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_ARTIFACT_DIR / "reports" / "ariane.timing.rpt").write_text(
            f"""
| Tool Version : Vivado v.2025.2
| Device       : {GENESYS2_REPORT_DEVICE}
| Design State : Synthesized
Slack (MET) : 0.100ns
""",
            encoding="utf-8",
        )
        checks = run_checks(root, DEFAULT_CONFIG, DEFAULT_ARTIFACT_DIR, DEFAULT_BOARD_DIR)
        if not any(check.label == "Routed implementation report" and not check.ok for check in checks):
            print("[FAIL] self-test missed non-routed timing report", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_BOARD_DIR / "board.xml").unlink()
        checks = run_checks(root, DEFAULT_CONFIG, DEFAULT_ARTIFACT_DIR, DEFAULT_BOARD_DIR)
        if not any(check.label == "Genesys 2 board files" and not check.ok for check in checks):
            print("[FAIL] self-test missed missing board file", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_CONFIG).write_text(
            f"""
[tool.rv-maltrace]
vivado = "{(root / "Vivado" / "bin" / "vivado.bat").as_posix()}"
board = "genesys2"
xilinx_part = "xc7a200tfbg484-1"
xilinx_board = "{GENESYS2_BOARD}"
""",
            encoding="utf-8",
        )
        checks = run_checks(root, DEFAULT_CONFIG, DEFAULT_ARTIFACT_DIR, DEFAULT_BOARD_DIR)
        if not any(check.label == "Configured Vivado target" and not check.ok for check in checks):
            print("[FAIL] self-test missed wrong configured part", file=sys.stderr)
            return 1

    print("[PASS] Vivado authorization self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check rv-maltrace Phase 4.2 Genesys 2 Vivado authorization evidence.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to the current directory.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    parser.add_argument("--board-dir", type=Path, default=DEFAULT_BOARD_DIR)
    parser.add_argument("--self-test", action="store_true", help="Run positive and negative coverage checks.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = args.root.resolve()
    checks = run_checks(root, args.config, args.artifact_dir, args.board_dir)
    for check in checks:
        status = "PASS" if check.ok else "FAIL"
        stream = sys.stdout if check.ok else sys.stderr
        print(f"[{status}] {check.label}: {check.evidence}", file=stream)

    if any(not check.ok for check in checks):
        return 1

    print("[PASS] Vivado authorization evidence is present; rerun vivado:check before rebuilding")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
