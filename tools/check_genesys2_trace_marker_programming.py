from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    repo_path,
    require,
    sha256_file,
    write_json,
)


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/trace_marker_programming_summary.json")
SCHEMA = "rvmt.genesys2.trace_marker_programming.v1"
PASS_STATUS = "PASS_TRACE_MARKER_PROGRAMMED"
EXPECTED_BITSTREAM = "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit"
EXPECTED_LTX = "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx"
EXPECTED_BUILD_MANIFEST = "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/rvmt_trace_marker_build_manifest.json"
EXPECTED_CURRENT_LOG = "results/evaluation/genesys2-cva6/current/trace_marker_programming.log"
EXPECTED_TARGET_FRAGMENT = "localhost:3121/xilinx_tcf/Digilent/200300B81858B"
EXPECTED_DEVICE = "xc7k325t_0"


def read_log_text(path: Path) -> str:
    raw = path.read_bytes()
    candidates: list[tuple[int, str]] = []
    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            text = raw.decode(encoding, errors="replace")
        score = (
            10 * text.count("RVMT_")
            + 10 * text.count("Vivado")
            + 5 * text.count("program_hw_devices")
            + 5 * text.count("ILA core")
            - 20 * text.count("\x00")
            - 5 * text.count("\ufffd")
        )
        candidates.append((score, text))
    return max(candidates, key=lambda item: item[0])[1]


def marker(text: str, name: str) -> str | None:
    match = re.search(rf"^{re.escape(name)}=(.+)$", text, flags=re.MULTILINE)
    return match.group(1).strip() if match else None


def normalized(value: Any) -> str:
    return str(value or "").replace("\\", "/")


def logged_path_matches(value: Any, expected_rel: str) -> bool:
    logged = normalized(value)
    return logged == expected_rel or logged.endswith("/" + expected_rel)


def check_file_row(errors: list[str], root: Path, row: dict[str, Any], expected_path: str, label: str) -> Path | None:
    path_value = row.get("path")
    require(errors, path_value == expected_path, f"{label}: path must be {expected_path}")
    path = repo_path(root, path_value) if isinstance(path_value, str) else None
    if path is None:
        return None
    require(errors, path.is_file(), f"{label}: file missing: {path_value}")
    if path.is_file():
        require(errors, row.get("sha256") == sha256_file(path), f"{label}: sha256 mismatch")
        require(errors, int(row.get("size_bytes") or -1) == path.stat().st_size, f"{label}: size mismatch")
    return path


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    require(errors, data.get("status") == PASS_STATUS, f"status must be {PASS_STATUS}")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(errors, data.get("returncode") == 0, "returncode must be 0")
    require(errors, "program_genesys2_bitstream.tcl" in str(data.get("command") or ""), "command must record the JTAG programming Tcl")
    require(errors, EXPECTED_BITSTREAM in str(data.get("command") or ""), "command must record trace-marker bitstream")
    require(errors, EXPECTED_LTX in str(data.get("command") or ""), "command must record trace-marker LTX")
    require(errors, data.get("vivado_version") == "2025.2", "vivado_version must be 2025.2 for this host run")

    artifacts = as_dict(data.get("trace_marker_artifacts"))
    bitstream = as_dict(artifacts.get("bitstream"))
    ltx = as_dict(artifacts.get("ltx"))
    build_manifest = as_dict(artifacts.get("build_manifest"))
    check_file_row(errors, root, bitstream, EXPECTED_BITSTREAM, "bitstream")
    check_file_row(errors, root, ltx, EXPECTED_LTX, "ltx")
    build_path = check_file_row(errors, root, build_manifest, EXPECTED_BUILD_MANIFEST, "build_manifest")
    require(errors, logged_path_matches(bitstream.get("logged_path"), EXPECTED_BITSTREAM), "bitstream logged_path does not match expected artifact")
    require(errors, logged_path_matches(ltx.get("logged_path"), EXPECTED_LTX), "ltx logged_path does not match expected artifact")
    require(errors, build_manifest.get("trace_marker_scope") is True, "build manifest must record trace_marker_scope true")
    defines = set(str(item) for item in as_list(build_manifest.get("verilog_defines")))
    require(errors, {"RV_MALTRACE_FPGA_TRACE", "RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE"} <= defines, "build manifest must include trace-marker defines")
    require(errors, build_manifest.get("xilinx_part") == "xc7k325tffg900-2", "xilinx_part mismatch")
    require(errors, build_manifest.get("xilinx_board") == "digilentinc.com:genesys2:part0:1.1", "xilinx_board mismatch")
    if build_path and build_path.is_file():
        try:
            build_data = load_json(build_path)
        except Exception as exc:
            errors.append(f"build manifest invalid JSON: {exc}")
        else:
            require(errors, build_data.get("schema") == "rvmt.trace_marker_build_manifest.v1", "build manifest schema mismatch")
            require(errors, build_data.get("trace_marker_scope") is True, "build manifest file trace_marker_scope mismatch")

    logs = as_dict(data.get("logs"))
    source_log = as_dict(logs.get("source"))
    current_log = as_dict(logs.get("current"))
    source_path_value = source_log.get("path")
    require(errors, isinstance(source_path_value, str) and source_path_value.startswith("results/board/"), "source log must be under results/board")
    source_path = repo_path(root, source_path_value) if isinstance(source_path_value, str) else None
    if source_path is not None:
        require(errors, source_path.is_file(), f"source log missing: {source_path_value}")
        if source_path.is_file():
            require(errors, source_log.get("sha256") == sha256_file(source_path), "source log sha256 mismatch")
            require(errors, int(source_log.get("size_bytes") or -1) == source_path.stat().st_size, "source log size mismatch")
    current_path = check_file_row(errors, root, current_log, EXPECTED_CURRENT_LOG, "current log")
    log_text = read_log_text(current_path) if current_path and current_path.is_file() else ""
    if source_path is not None and source_path.is_file() and current_path is not None and current_path.is_file():
        require(errors, source_log.get("sha256") == current_log.get("sha256"), "source/current log hashes should match copied log")

    hardware = as_dict(data.get("hardware"))
    require(errors, hardware.get("hw_server_url") == "localhost:3121", "hw_server_url mismatch")
    require(errors, hardware.get("target") == EXPECTED_TARGET_FRAGMENT, "target mismatch")
    require(errors, hardware.get("device") == EXPECTED_DEVICE, "device mismatch")
    require(errors, hardware.get("ila_core_count") == 1, "ila_core_count must be 1")

    markers = as_dict(data.get("required_log_markers"))
    require(errors, markers.get("RVMT_PROGRAM_DONE") is True, "summary marker RVMT_PROGRAM_DONE missing")
    require(errors, markers.get("program_hw_devices") is True, "summary marker program_hw_devices missing")
    require(errors, markers.get("refresh_reports_one_ila") is True, "summary marker one ILA missing")
    require(errors, "RVMT_PROGRAM_DONE" in log_text, "log missing RVMT_PROGRAM_DONE")
    require(errors, "program_hw_devices" in log_text, "log missing program_hw_devices")
    require(errors, marker(log_text, "RVMT_HW_TARGETS") == EXPECTED_TARGET_FRAGMENT, "log target marker mismatch")
    require(errors, marker(log_text, "RVMT_HW_DEVICES") == EXPECTED_DEVICE, "log device marker mismatch")
    require(errors, marker(log_text, "RVMT_HW_SERVER_URL") == "localhost:3121", "log hw_server marker mismatch")
    require(errors, "has 1 ILA core(s)" in log_text, "log missing one-ILA refresh evidence")
    require(errors, "Vivado v2025.2" in log_text, "log missing Vivado 2025.2 banner")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("trace_marker_bitstream_rebuilt") is True, "trace-marker rebuild boundary missing")
    require(errors, boundary.get("genesys2_programmed") is True, "Genesys2 programmed boundary missing")
    require(errors, boundary.get("board_runtime_boot_claimed") is False, "must not claim board runtime boot")
    require(errors, boundary.get("sdcard_image_written") is False, "must not claim SD-card write")
    require(errors, boundary.get("genesys2_booted_written_sdcard_image") is False, "must not claim booted written SD image")
    require(errors, boundary.get("cycle_source_claimed") is False, "must not claim cycle source")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "must not claim cycle-level overhead")
    require(errors, boundary.get("production_streaming_claimed") is False, "must not claim production streaming")
    require(errors, boundary.get("real_malware_claimed") is False, "must not claim real malware validation")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "sd-card image was written or booted" in non_claims, "non_claims must reject SD-card write/boot")
    require(errors, "cycle-level overhead" in non_claims, "non_claims must reject overhead claim")
    require(errors, "real-malware validation" in non_claims, "non_claims must reject real-malware claim")
    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "check_genesys2_trace_marker_programming.py --root ." in commands, "validation command missing checker")
    require(errors, "check_genesys2_bitstream_artifacts.py --root ." in commands, "validation command missing bitstream artifact checker")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-programming-checker-") as tmp:
        root = Path(tmp)
        for rel in (EXPECTED_BITSTREAM, EXPECTED_LTX, EXPECTED_BUILD_MANIFEST, "results/board/run/program_trace_marker.log", EXPECTED_CURRENT_LOG):
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
        (root / EXPECTED_BITSTREAM).write_bytes(b"bitstream\n")
        (root / EXPECTED_LTX).write_text("ltx\n", encoding="utf-8")
        write_json(
            root / EXPECTED_BUILD_MANIFEST,
            {
                "schema": "rvmt.trace_marker_build_manifest.v1",
                "trace_marker_scope": True,
                "verilog_defines": ["RV_MALTRACE_FPGA_TRACE", "RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE"],
                "xilinx_part": "xc7k325tffg900-2",
                "xilinx_board": "digilentinc.com:genesys2:part0:1.1",
            },
        )
        log_text = (
            "****** Vivado v2025.2 (64-bit)\n"
            f"RVMT_BIT_FILE={EXPECTED_BITSTREAM}\n"
            f"RVMT_LTX_FILE={EXPECTED_LTX}\n"
            "RVMT_HW_SERVER_URL=localhost:3121\n"
            f"RVMT_HW_TARGETS={EXPECTED_TARGET_FRAGMENT}\n"
            f"RVMT_HW_DEVICES={EXPECTED_DEVICE}\n"
            "program_hw_devices: Time (s): cpu = 00:00:01 ; elapsed = 00:00:01 .\n"
            "Device xc7k325t (JTAG device index = 0) is programmed with a design that has 1 ILA core(s).\n"
            "RVMT_PROGRAM_DONE\n"
        )
        source_log = root / "results/board/run/program_trace_marker.log"
        current_log = root / EXPECTED_CURRENT_LOG
        source_log.write_text(log_text, encoding="utf-8")
        current_log.write_text(log_text, encoding="utf-8")
        summary = {
            "schema": SCHEMA,
            "status": PASS_STATUS,
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "command": f"vivado -mode batch -source tools/program_genesys2_bitstream.tcl -tclargs {EXPECTED_BITSTREAM} {EXPECTED_LTX} localhost:3121",
            "returncode": 0,
            "vivado_version": "2025.2",
            "hardware": {
                "hw_server_url": "localhost:3121",
                "target": EXPECTED_TARGET_FRAGMENT,
                "device": EXPECTED_DEVICE,
                "ila_core_count": 1,
            },
            "trace_marker_artifacts": {
                "bitstream": {
                    "path": EXPECTED_BITSTREAM,
                    "sha256": sha256_file(root / EXPECTED_BITSTREAM),
                    "size_bytes": (root / EXPECTED_BITSTREAM).stat().st_size,
                    "logged_path": EXPECTED_BITSTREAM,
                },
                "ltx": {
                    "path": EXPECTED_LTX,
                    "sha256": sha256_file(root / EXPECTED_LTX),
                    "size_bytes": (root / EXPECTED_LTX).stat().st_size,
                    "logged_path": EXPECTED_LTX,
                },
                "build_manifest": {
                    "path": EXPECTED_BUILD_MANIFEST,
                    "sha256": sha256_file(root / EXPECTED_BUILD_MANIFEST),
                    "size_bytes": (root / EXPECTED_BUILD_MANIFEST).stat().st_size,
                    "trace_marker_scope": True,
                    "verilog_defines": ["RV_MALTRACE_FPGA_TRACE", "RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE"],
                    "xilinx_part": "xc7k325tffg900-2",
                    "xilinx_board": "digilentinc.com:genesys2:part0:1.1",
                },
            },
            "logs": {
                "source": {
                    "path": "results/board/run/program_trace_marker.log",
                    "sha256": sha256_file(source_log),
                    "size_bytes": source_log.stat().st_size,
                },
                "current": {
                    "path": EXPECTED_CURRENT_LOG,
                    "sha256": sha256_file(current_log),
                    "size_bytes": current_log.stat().st_size,
                },
            },
            "required_log_markers": {
                "RVMT_PROGRAM_DONE": True,
                "program_hw_devices": True,
                "refresh_reports_one_ila": True,
            },
            "claim_boundary": {
                "trace_marker_bitstream_rebuilt": True,
                "genesys2_programmed": True,
                "board_runtime_boot_claimed": False,
                "sdcard_image_written": False,
                "genesys2_booted_written_sdcard_image": False,
                "cycle_source_claimed": False,
                "cycle_level_overhead_claimed": False,
                "production_streaming_claimed": False,
                "real_malware_claimed": False,
            },
            "non_claims": [
                "No SD-card image was written or booted.",
                "No cycle-level overhead or cycle source is claimed.",
                "No real-malware validation is claimed.",
            ],
            "validation_commands": [
                "uv run python tools/check_genesys2_trace_marker_programming.py --root .",
                "uv run python tools/check_genesys2_bitstream_artifacts.py --root .",
            ],
        }
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] trace-marker programming good fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["sdcard_image_written"] = True
        errors = check_summary(summary, root)
        if not any("SD-card write" in error for error in errors):
            print("[FAIL] trace-marker programming checker accepted false SD-card claim", file=sys.stderr)
            return 1
        summary["claim_boundary"]["sdcard_image_written"] = False
        current_log.write_text(log_text.replace("RVMT_PROGRAM_DONE\n", ""), encoding="utf-8")
        errors = check_summary(summary, root)
        if not any("RVMT_PROGRAM_DONE" in error for error in errors):
            print("[FAIL] trace-marker programming checker missed absent done marker", file=sys.stderr)
            return 1
    print("[PASS] trace-marker programming checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2 trace-marker JTAG programming evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = repo_path(root, args.summary)
    if not summary.is_file():
        print(f"[FAIL] missing trace-marker programming summary: {summary}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(summary), root)
    except Exception as exc:
        print(f"[FAIL] trace-marker programming checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] trace-marker programming summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] trace-marker programming summary accepted: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
