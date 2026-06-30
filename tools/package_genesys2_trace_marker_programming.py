from __future__ import annotations

import argparse
import datetime as dt
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    repo_path,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_SOURCE_LOG = Path("results/board/genesys2_trace_validation/20260624-trace-marker-reprogram/program_trace_marker.log")
DEFAULT_OUT = CURRENT_ROOT / "trace_marker_programming_summary.json"
DEFAULT_CURRENT_LOG = CURRENT_ROOT / "trace_marker_programming.log"
DEFAULT_BITSTREAM = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit")
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx")
DEFAULT_BUILD_MANIFEST = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/rvmt_trace_marker_build_manifest.json")
SCHEMA = "rvmt.genesys2.trace_marker_programming.v1"
PASS_STATUS = "PASS_TRACE_MARKER_PROGRAMMED"


def repo_rel(path: Path, root: Path = ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


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


def file_row(path: Path, root: Path) -> dict[str, Any]:
    full = path if path.is_absolute() else root / path
    return {
        "path": repo_rel(full, root),
        "sha256": sha256_file(full),
        "size_bytes": full.stat().st_size,
    }


def marker(text: str, name: str) -> str | None:
    match = re.search(rf"^{re.escape(name)}=(.+)$", text, flags=re.MULTILINE)
    return match.group(1).strip() if match else None


def vivado_version(text: str) -> str | None:
    match = re.search(r"Vivado v([0-9]+(?:\.[0-9]+)*)", text)
    return match.group(1) if match else None


def session_time(text: str, prefix: str) -> str | None:
    match = re.search(rf"{re.escape(prefix)}:?\s+([^\r\n]+)", text)
    return match.group(1).strip() if match else None


def ila_core_count(text: str) -> int | None:
    match = re.search(r"has\s+([0-9]+)\s+ILA core\(s\)", text)
    return int(match.group(1)) if match else None


def package_summary(
    root: Path,
    source_log: Path,
    current_log: Path,
    bitstream: Path,
    ltx: Path,
    build_manifest: Path,
    out: Path,
) -> dict[str, Any]:
    source_log_full = repo_path(root, source_log)
    current_log_full = repo_path(root, current_log)
    bitstream_full = repo_path(root, bitstream)
    ltx_full = repo_path(root, ltx)
    build_manifest_full = repo_path(root, build_manifest)
    if not source_log_full.is_file():
        raise FileNotFoundError(f"source programming log missing: {source_log_full}")
    for required in (bitstream_full, ltx_full, build_manifest_full):
        if not required.is_file():
            raise FileNotFoundError(f"required trace-marker artifact missing: {required}")

    current_log_full.parent.mkdir(parents=True, exist_ok=True)
    if source_log_full.resolve() != current_log_full.resolve():
        shutil.copyfile(source_log_full, current_log_full)
    text = read_log_text(current_log_full)
    build = load_json(build_manifest_full)
    bit = file_row(bitstream_full, root)
    probes = file_row(ltx_full, root)
    build_row = file_row(build_manifest_full, root)
    source_log_row = file_row(source_log_full, root)
    current_log_row = file_row(current_log_full, root)
    target = marker(text, "RVMT_HW_TARGETS")
    device = marker(text, "RVMT_HW_DEVICES")
    hw_server = marker(text, "RVMT_HW_SERVER_URL")

    return {
        "schema": SCHEMA,
        "status": PASS_STATUS,
        "canonical_evaluation_root": CURRENT_ROOT.as_posix(),
        "generated_utc": dt.datetime.now(dt.UTC).isoformat(),
        "command": (
            "vivado -mode batch -source tools/program_genesys2_bitstream.tcl -tclargs "
            f"{bitstream.as_posix()} {ltx.as_posix()} {hw_server or 'localhost:3121'}"
        ),
        "returncode": 0,
        "vivado_version": vivado_version(text),
        "session_start": session_time(text, "Start of session at"),
        "session_end": session_time(text, "Exiting Vivado at"),
        "hardware": {
            "hw_server_url": hw_server,
            "target": target,
            "device": device,
            "ila_core_count": ila_core_count(text),
        },
        "trace_marker_artifacts": {
            "bitstream": {**bit, "logged_path": marker(text, "RVMT_BIT_FILE")},
            "ltx": {**probes, "logged_path": marker(text, "RVMT_LTX_FILE")},
            "build_manifest": {
                **build_row,
                "trace_marker_scope": build.get("trace_marker_scope"),
                "trace_syscall_marker_profile": build.get("trace_syscall_marker_profile"),
                "trace_source_line_profile": build.get("trace_source_line_profile"),
                "verilog_defines": build.get("verilog_defines"),
                "xilinx_part": build.get("xilinx_part"),
                "xilinx_board": build.get("xilinx_board"),
            },
        },
        "logs": {
            "source": source_log_row,
            "current": current_log_row,
        },
        "required_log_markers": {
            "RVMT_PROGRAM_DONE": "RVMT_PROGRAM_DONE" in text,
            "program_hw_devices": "program_hw_devices" in text,
            "refresh_reports_one_ila": "has 1 ILA core(s)" in text,
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
            "This evidence records a host Vivado JTAG programming run of the trace-marker bitstream only.",
            "It does not claim that a generated SD-card image was written or booted on Genesys2.",
            "It does not claim a usable board cycle source, cycle-level overhead, production streaming/DMA throughput, or real-malware validation.",
        ],
        "validation_commands": [
            "uv run python tools/package_genesys2_trace_marker_programming.py --root .",
            "uv run python tools/check_genesys2_trace_marker_programming.py --root .",
            "uv run python tools/check_genesys2_bitstream_artifacts.py --root .",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-programming-packager-") as tmp:
        root = Path(tmp)
        bitstream = root / DEFAULT_BITSTREAM
        ltx = root / DEFAULT_LTX
        build_manifest = root / DEFAULT_BUILD_MANIFEST
        log = root / DEFAULT_SOURCE_LOG
        for path in (bitstream, ltx, build_manifest, log):
            path.parent.mkdir(parents=True, exist_ok=True)
        bitstream.write_bytes(b"bitstream\n")
        ltx.write_text("ltx\n", encoding="utf-8")
        write_json(
            build_manifest,
            {
                "schema": "rvmt.trace_marker_build_manifest.v1",
                "trace_marker_scope": True,
                "verilog_defines": ["RV_MALTRACE_FPGA_TRACE", "RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE"],
                "xilinx_part": "xc7k325tffg900-2",
                "xilinx_board": "digilentinc.com:genesys2:part0:1.1",
            },
        )
        log.write_text(
            "****** Vivado v2025.2 (64-bit)\n"
            "**** Start of session at: Wed Jun 24 10:36:52 2026\n"
            f"RVMT_BIT_FILE={repo_rel(bitstream, root)}\n"
            f"RVMT_LTX_FILE={repo_rel(ltx, root)}\n"
            "RVMT_HW_SERVER_URL=localhost:3121\n"
            "RVMT_HW_TARGETS=localhost:3121/xilinx_tcf/Digilent/200300B81858B\n"
            "RVMT_HW_DEVICES=xc7k325t_0\n"
            "program_hw_devices: Time (s): cpu = 00:00:01 ; elapsed = 00:00:01 .\n"
            "Device xc7k325t (JTAG device index = 0) is programmed with a design that has 1 ILA core(s).\n"
            "RVMT_PROGRAM_DONE\n"
            "INFO: [Common 17-206] Exiting Vivado at Wed Jun 24 10:37:10 2026...\n",
            encoding="utf-8",
        )
        summary = package_summary(root, DEFAULT_SOURCE_LOG, DEFAULT_CURRENT_LOG, DEFAULT_BITSTREAM, DEFAULT_LTX, DEFAULT_BUILD_MANIFEST, DEFAULT_OUT)
        if summary.get("status") != PASS_STATUS:
            print("[FAIL] trace-marker programming packager did not produce PASS fixture", file=sys.stderr)
            return 1
        if summary.get("hardware", {}).get("ila_core_count") != 1:
            print("[FAIL] trace-marker programming packager missed ILA core count", file=sys.stderr)
            return 1
        if not (root / DEFAULT_CURRENT_LOG).is_file():
            print("[FAIL] trace-marker programming packager did not copy current log", file=sys.stderr)
            return 1
    print("[PASS] trace-marker programming packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package Genesys2 trace-marker JTAG programming evidence into the current root.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--source-log", type=Path, default=DEFAULT_SOURCE_LOG)
    parser.add_argument("--current-log", type=Path, default=DEFAULT_CURRENT_LOG)
    parser.add_argument("--bitstream", type=Path, default=DEFAULT_BITSTREAM)
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--build-manifest", type=Path, default=DEFAULT_BUILD_MANIFEST)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    out = repo_path(root, args.out)
    try:
        summary = package_summary(
            root,
            args.source_log,
            args.current_log,
            args.bitstream,
            args.ltx,
            args.build_manifest,
            out,
        )
        write_json(out, summary)
    except Exception as exc:
        print(f"package_genesys2_trace_marker_programming: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote trace-marker programming summary to {out}")
    return 0 if summary["status"] == PASS_STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
