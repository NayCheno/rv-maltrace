from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple


DEFAULT_BASELINE_DIR = Path("build/vivado/genesys2-cv64a6_imafdc_sv39")
DEFAULT_TRACE_DIR = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace")
DEFAULT_TRACE_MARKER_DIR = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker")
TRACE_MARKER_ILA_XCI = Path("work-fpga/xlnx_ila.xci")
TRACE_MARKER_MANIFEST = Path("work-fpga/rvmt_trace_marker_build_manifest.json")
TRACE_MARKER_ILA_EXPECTED = {
    "C_NUM_OF_PROBES": "3",
    "C_PROBE1_WIDTH": "136",
    "C_PROBE2_WIDTH": "484",
    "C_DATA_DEPTH": "8192",
    "C_INPUT_PIPE_STAGES": "2",
    "C_EN_STRG_QUAL": "1",
    "C_ADV_TRIGGER": "TRUE",
}
TRACE_MARKER_SOURCE_HASH_FILES = [
    "rtl/cva6/corev_apu/fpga/src/ariane_xilinx.sv",
    "rtl/cva6/corev_apu/fpga/xilinx/xlnx_ila/tcl/run.tcl",
    "rtl/trace/trace_pkg.sv",
    "rtl/trace/trace_bram_ring.sv",
    "rtl/trace/cva6_rvfi_trace_adapter.sv",
    "tools/capture_genesys2_ila_event.tcl",
    "tools/decode_genesys2_ila_trace.py",
    "tools/decode_genesys2_bram_ring_dump.py",
    "tools/package_genesys2_bram_trace_sink_summary.py",
    "tools/run_genesys2_ila_command_capture.py",
]


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


def xci_config_value(text: str, key: str) -> str | None:
    match = re.search(rf'"{re.escape(key)}"\s*:\s*\[\s*\{{\s*"value"\s*:\s*"([^"]+)"', text)
    return match.group(1) if match else None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_ila_xci(root: Path, path: Path, label: str) -> Check:
    full_path = resolve(root, path)
    if not full_path.exists():
        return Check(label, "FAIL", f"missing {display(full_path, root)}")
    text = full_path.read_text(encoding="utf-8", errors="replace")
    mismatches: list[str] = []
    for key, expected in TRACE_MARKER_ILA_EXPECTED.items():
        actual = xci_config_value(text, key)
        if actual is None or actual.upper() != expected.upper():
            mismatches.append(f"{key}={actual or 'MISSING'} expected {expected}")
    if mismatches:
        return Check(label, "FAIL", f"{display(full_path, root)}: " + "; ".join(mismatches))
    configured = ", ".join(f"{key}={value}" for key, value in TRACE_MARKER_ILA_EXPECTED.items())
    return Check(label, "PASS", f"{display(full_path, root)} ({configured})")


def check_trace_marker_source_hashes(root: Path, manifest_path: Path, data: dict) -> Check | None:
    hashes = data.get("source_hashes")
    if hashes is None:
        return Check(
            "Trace-marker source hashes",
            "WARN",
            f"{display(manifest_path, root)}: source_hashes missing; rebuild trace-marker bitstream to bind artifact to current RTL/decoder sources",
        )
    if not isinstance(hashes, dict):
        return Check("Trace-marker source hashes", "FAIL", f"{display(manifest_path, root)}: source_hashes must be an object")
    if str(hashes.get("hash_algorithm", "")).lower() != "sha256":
        return Check("Trace-marker source hashes", "FAIL", f"{display(manifest_path, root)}: source_hashes.hash_algorithm must be sha256")
    files = hashes.get("files")
    if not isinstance(files, dict):
        return Check("Trace-marker source hashes", "FAIL", f"{display(manifest_path, root)}: source_hashes.files missing")
    missing = [path for path in TRACE_MARKER_SOURCE_HASH_FILES if path not in files]
    if missing:
        return Check("Trace-marker source hashes", "FAIL", f"{display(manifest_path, root)}: missing source hashes {', '.join(missing)}")
    mismatches: list[str] = []
    for path in TRACE_MARKER_SOURCE_HASH_FILES:
        full_path = root / path
        if not full_path.is_file():
            mismatches.append(f"{path}=missing")
            continue
        expected = str(files[path]).lower()
        actual = sha256_file(full_path)
        if actual.lower() != expected:
            mismatches.append(f"{path}=current {actual[:12]}... manifest {expected[:12]}...")
    if mismatches:
        return Check("Trace-marker source hashes", "FAIL", f"{display(manifest_path, root)}: " + "; ".join(mismatches))
    return Check("Trace-marker source hashes", "PASS", f"{display(manifest_path, root)} source hashes match current sources")


def check_trace_marker_manifest(root: Path, path: Path) -> Check:
    full_path = resolve(root, path)
    if not full_path.exists():
        return Check("Trace-marker build manifest", "FAIL", f"missing {display(full_path, root)}")
    try:
        data = json.loads(full_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return Check("Trace-marker build manifest", "FAIL", f"{display(full_path, root)}: invalid JSON: {exc}")
    defines = data.get("verilog_defines")
    if not isinstance(defines, list):
        return Check("Trace-marker build manifest", "FAIL", f"{display(full_path, root)}: verilog_defines missing")
    required = {"RV_MALTRACE_FPGA_TRACE", "RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE"}
    missing = sorted(required - set(str(item) for item in defines))
    policy = data.get("marker_scope_policy") if isinstance(data.get("marker_scope_policy"), dict) else {}
    if missing:
        return Check("Trace-marker build manifest", "FAIL", f"{display(full_path, root)}: missing defines {', '.join(missing)}")
    if data.get("trace_marker_scope") is not True:
        return Check("Trace-marker build manifest", "FAIL", f"{display(full_path, root)}: trace_marker_scope is not true")
    if policy.get("enable_marker") is not True or policy.get("enable_branch") is not False:
        return Check(
            "Trace-marker build manifest",
            "FAIL",
            f"{display(full_path, root)}: expected marker enabled and branch disabled policy",
        )
    hash_check = check_trace_marker_source_hashes(root, full_path, data)
    if hash_check is not None and hash_check.level != "PASS":
        return hash_check
    return Check(
        "Trace-marker build manifest",
        "PASS",
        f"{display(full_path, root)} ({', '.join(str(item) for item in defines)})",
    )


def collect_checks(root: Path, baseline_dir: Path, trace_dir: Path, trace_marker_dir: Path) -> list[Check]:
    baseline = resolve(root, baseline_dir)
    trace = resolve(root, trace_dir)
    trace_marker = resolve(root, trace_marker_dir)
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
        check_file(root, trace_marker / "work-fpga/ariane_xilinx.bit", "Trace-marker bitstream"),
        check_file(root, trace_marker / "work-fpga/ariane_xilinx.mcs", "Trace-marker flash image"),
        check_file(root, trace_marker / "work-fpga/ariane_xilinx.ltx", "Trace-marker ILA probes"),
        check_trace_marker_manifest(root, trace_marker / TRACE_MARKER_MANIFEST),
        check_ila_xci(root, trace_marker / TRACE_MARKER_ILA_XCI, "Trace-marker ILA XCI configuration"),
        check_file(root, trace_marker / "work-fpga/ariane_xilinx_routed.dcp", "Trace-marker routed checkpoint"),
        check_timing(
            root,
            trace_marker / "reports/ariane.timing.rpt",
            "Trace-marker routed timing",
            expected_design_state="Routed",
        ),
        check_file(root, trace_marker / "reports/ariane.utilization.rpt", "Trace-marker utilization report"),
        check_file(root, trace_marker / "work-fpga/ariane_xilinx_route_status.rpt", "Trace-marker route status report"),
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
        trace_marker = root / DEFAULT_TRACE_MARKER_DIR
        for directory in (
            baseline / "work-fpga",
            baseline / "reports",
            trace / "work-fpga",
            trace / "reports",
            trace_marker / "work-fpga",
            trace_marker / "reports",
            root / "rtl/cva6/corev_apu/fpga/src",
            root / "rtl/cva6/corev_apu/fpga/xilinx/xlnx_ila/tcl",
            root / "rtl/trace",
            root / "tools",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        for source in TRACE_MARKER_SOURCE_HASH_FILES:
            (root / source).write_text(f"{source}\n", encoding="utf-8")
        for path in (
            baseline / "work-fpga/ariane_xilinx.bit",
            baseline / "work-fpga/ariane_xilinx.mcs",
            baseline / "work-fpga/ariane_xilinx.dcp",
            baseline / "reports/ariane.utilization.rpt",
            trace / "work-fpga/ariane_xilinx.ltx",
            trace / "work-fpga/ariane_xilinx_routed.dcp",
            trace / "reports/ariane.utilization.rpt",
            trace / "work-fpga/ariane_xilinx_route_status.rpt",
            trace_marker / "work-fpga/ariane_xilinx.bit",
            trace_marker / "work-fpga/ariane_xilinx.mcs",
            trace_marker / "work-fpga/ariane_xilinx.ltx",
            trace_marker / TRACE_MARKER_MANIFEST,
            trace_marker / TRACE_MARKER_ILA_XCI,
            trace_marker / "work-fpga/ariane_xilinx_routed.dcp",
            trace_marker / "reports/ariane.utilization.rpt",
            trace_marker / "work-fpga/ariane_xilinx_route_status.rpt",
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
        (trace_marker / "reports/ariane.timing.rpt").write_text(
            "| Design State : Routed\nSlack (MET) : 0.177ns\n",
            encoding="utf-8",
        )
        (trace_marker / TRACE_MARKER_ILA_XCI).write_text(
            "\n".join(
                f'"{key}": [ {{ "value": "{value}", "resolve_type": "user" }} ],'
                for key, value in TRACE_MARKER_ILA_EXPECTED.items()
            )
            + "\n",
            encoding="utf-8",
        )
        (trace_marker / TRACE_MARKER_MANIFEST).write_text(
            json.dumps(
                {
                    "schema": "rvmt.trace_marker_build_manifest.v1",
                    "trace_marker_scope": True,
                    "verilog_defines": ["RV_MALTRACE_FPGA_TRACE", "RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE"],
                    "marker_scope_policy": {"enable_marker": True, "enable_branch": False},
                    "source_hashes": {
                        "hash_algorithm": "sha256",
                        "files": {path: sha256_file(root / path) for path in TRACE_MARKER_SOURCE_HASH_FILES},
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )

        checks = collect_checks(root, DEFAULT_BASELINE_DIR, DEFAULT_TRACE_DIR, DEFAULT_TRACE_MARKER_DIR)
        if exit_code(checks, strict=False) != 0:
            print("[FAIL] default inventory must tolerate a missing trace bitstream as WARN", file=sys.stderr)
            return 1
        if exit_code(checks, strict=True) == 0:
            print("[FAIL] strict inventory must fail on a missing trace bitstream", file=sys.stderr)
            return 1

        (trace / "work-fpga/ariane_xilinx.bit").write_text("x\n", encoding="utf-8")
        checks = collect_checks(root, DEFAULT_BASELINE_DIR, DEFAULT_TRACE_DIR, DEFAULT_TRACE_MARKER_DIR)
        if exit_code(checks, strict=True) != 0:
            print("[FAIL] strict inventory must pass after trace bitstream is present", file=sys.stderr)
            return 1
        (trace_marker / TRACE_MARKER_ILA_XCI).write_text(
            '"C_DATA_DEPTH": [ { "value": "1024", "resolve_type": "user" } ],\n',
            encoding="utf-8",
        )
        checks = collect_checks(root, DEFAULT_BASELINE_DIR, DEFAULT_TRACE_DIR, DEFAULT_TRACE_MARKER_DIR)
        if exit_code(checks, strict=True) == 0:
            print("[FAIL] strict inventory must fail on stale trace-marker ILA XCI", file=sys.stderr)
            return 1
        (trace_marker / TRACE_MARKER_ILA_XCI).write_text(
            "\n".join(
                f'"{key}": [ {{ "value": "{value}", "resolve_type": "user" }} ],'
                for key, value in TRACE_MARKER_ILA_EXPECTED.items()
            )
            + "\n",
            encoding="utf-8",
        )
        (trace_marker / TRACE_MARKER_MANIFEST).write_text(
            json.dumps(
                {
                    "schema": "rvmt.trace_marker_build_manifest.v1",
                    "trace_marker_scope": True,
                    "verilog_defines": ["RV_MALTRACE_FPGA_TRACE"],
                    "marker_scope_policy": {"enable_marker": True, "enable_branch": False},
                    "source_hashes": {
                        "hash_algorithm": "sha256",
                        "files": {path: sha256_file(root / path) for path in TRACE_MARKER_SOURCE_HASH_FILES},
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        checks = collect_checks(root, DEFAULT_BASELINE_DIR, DEFAULT_TRACE_DIR, DEFAULT_TRACE_MARKER_DIR)
        if exit_code(checks, strict=True) == 0:
            print("[FAIL] strict inventory must fail when marker-scope define is missing", file=sys.stderr)
            return 1
        (trace_marker / TRACE_MARKER_MANIFEST).write_text(
            json.dumps(
                {
                    "schema": "rvmt.trace_marker_build_manifest.v1",
                    "trace_marker_scope": True,
                    "verilog_defines": ["RV_MALTRACE_FPGA_TRACE", "RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE"],
                    "marker_scope_policy": {"enable_marker": True, "enable_branch": False},
                    "source_hashes": {
                        "hash_algorithm": "sha256",
                        "files": {path: sha256_file(root / path) for path in TRACE_MARKER_SOURCE_HASH_FILES},
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "tools/decode_genesys2_ila_trace.py").write_text("modified\n", encoding="utf-8")
        checks = collect_checks(root, DEFAULT_BASELINE_DIR, DEFAULT_TRACE_DIR, DEFAULT_TRACE_MARKER_DIR)
        if exit_code(checks, strict=True) == 0:
            print("[FAIL] strict inventory must fail when source hashes are stale", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 bitstream artifact checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventory Genesys2/CVA6 baseline and trace bitstream artifacts.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to current directory.")
    parser.add_argument("--baseline-dir", type=Path, default=DEFAULT_BASELINE_DIR)
    parser.add_argument("--trace-dir", type=Path, default=DEFAULT_TRACE_DIR)
    parser.add_argument("--trace-marker-dir", type=Path, default=DEFAULT_TRACE_MARKER_DIR)
    parser.add_argument("--strict", action="store_true", help="Treat WARN items as failures.")
    parser.add_argument("--self-test", action="store_true", help="Run fixture-based self-test.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = args.root.resolve()
    checks = collect_checks(root, args.baseline_dir, args.trace_dir, args.trace_marker_dir)
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
