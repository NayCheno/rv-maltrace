from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path


ADAPTER = Path("rtl/trace/cva6_rvfi_trace_adapter.sv")
ILA_TCL = Path("rtl/cva6/corev_apu/fpga/xilinx/xlnx_ila/tcl/run.tcl")
CAPTURE_TCL = Path("tools/capture_genesys2_ila_event.tcl")
DECODER = Path("tools/decode_genesys2_ila_trace.py")
CLI = Path("src/rv_maltrace/cli.py")
PREPARE_CAPTURE = Path("tools/prepare_genesys2_safe_surrogate_capture.py")
PACKAGE_SAFE = Path("tools/package_genesys2_safe_surrogate_evidence.py")
RUN_CAPTURE = Path("tools/run_genesys2_ila_command_capture.py")
INSPECT_ILA = Path("tools/inspect_genesys2_ila_properties.tcl")


def read(root: Path, path: Path) -> str:
    full = root / path
    if not full.exists():
        raise FileNotFoundError(path.as_posix())
    return full.read_text(encoding="utf-8", errors="replace")


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def check_adapter(root: Path) -> list[str]:
    text = read(root, ADAPTER)
    errors: list[str] = []
    require(errors, "direct_candidate_output" not in text, f"{ADAPTER}: candidate-to-output bypass must stay removed")
    require(errors, "trace_packet_o = candidates[0]" not in text, f"{ADAPTER}: output must come from pending_q, not candidates[0]")
    require(errors, "candidates[" not in text, f"{ADAPTER}: synthesized candidate packet array must stay removed")
    require(errors, "pending_n" not in text, f"{ADAPTER}: synthesized pending next-state packet array must stay removed")
    require(errors, "INTERNAL_EVENT_QUEUE_DEPTH" in text, f"{ADAPTER}: internal queue cushion must replace removed direct output bypass")
    require(errors, "offer_candidate" in text, f"{ADAPTER}: direct candidate append path missing")
    require(errors, "accepted_candidate_count" in text, f"{ADAPTER}: queue overflow accounting path missing")
    require(errors, "pending_count_next" in text, f"{ADAPTER}: queue count next-state path missing")
    require(errors, "trace_packet_o = pending_q[0]" in text, f"{ADAPTER}: queued packet output path missing")
    return errors


def check_ila_generator(root: Path) -> list[str]:
    text = read(root, ILA_TCL)
    errors: list[str] = []
    expected = {
        "RVMT_ILA_DATA_DEPTH 8192": "default ILA data depth must cover paired syscall windows",
        "RVMT_ILA_INPUT_PIPE_STAGES 2": "ILA input pipeline must add timing isolation",
        "RVMT_ILA_STORAGE_QUAL 1": "storage qualification must default on for event-only capture",
        "RVMT_ILA_ADV_TRIGGER TRUE": "advanced trigger must default on for qualified capture",
    }
    for needle, message in expected.items():
        require(errors, needle in text, f"{ILA_TCL}: {message}")
    return errors


def check_capture_tcl(root: Path) -> list[str]:
    text = read(root, CAPTURE_TCL)
    errors: list[str] = []
    for needle, message in (
        ("set_property CONTROL.CAPTURE_MODE BASIC", "event-only mode must request BASIC capture"),
        ("set_property CAPTURE_COMPARE_VALUE eq1'b1", "event-only mode must qualify storage on trace fire"),
        ("RVMT_EVENT_ONLY_CAPTURE_UNSUPPORTED", "unsupported event-only capture must be explicit"),
        ("RVMT_EVENT_ONLY_CAPTURE_NOT_APPLIED", "failed capture-mode readback must be explicit"),
        ("exit 8", "event-only capture failures must stop the run"),
    ):
        require(errors, needle in text, f"{CAPTURE_TCL}: {message}")
    return errors


def check_decoder(root: Path) -> list[str]:
    text = read(root, DECODER)
    package_text = read(root, PACKAGE_SAFE)
    errors: list[str] = []
    for needle, message in (
        ("SATP_MODE_NAMES", "decoder must name SATP modes"),
        ("satp_asid", "decoder must extract SATP ASID for wide captures"),
        ("satp_ppn", "decoder must extract SATP PPN for wide captures"),
        ("unavailable_packed_32bit_primary", "decoder must bound packed SATP attribution"),
    ):
        require(errors, needle in text, f"{DECODER}: {message}")
    require(errors, "paired_syscall_windows" in package_text, f"{PACKAGE_SAFE}: same-window syscall pairs must be summarized")
    require(errors, "satp_context" in package_text, f"{PACKAGE_SAFE}: SATP/ASID context summary missing")
    return errors


def check_marker_scope(root: Path) -> list[str]:
    text = read(root, CLI)
    plan_text = read(root, PREPARE_CAPTURE)
    capture_text = read(root, RUN_CAPTURE)
    capture_tcl_text = read(root, CAPTURE_TCL)
    inspect_text = read(root, INSPECT_ILA)
    errors: list[str] = []
    require(errors, "bitstream:build-trace-marker" in text, f"{CLI}: marker-scope trace build command missing")
    require(errors, "RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE" in text, f"{CLI}: marker-scope Verilog define missing")
    require(errors, "refresh_xlnx_ila_ip" in text, f"{CLI}: trace builds must refresh the ILA IP before FPGA make")
    require(errors, "check_xlnx_ila_xci" in text, f"{CLI}: trace builds must verify refreshed ILA XCI parameters")
    require(errors, "sync_xlnx_ila_artifact_xci" in text, f"{CLI}: refreshed ILA XCI must be copied into trace artifacts")
    require(errors, '"C_DATA_DEPTH": "8192"' in text, f"{CLI}: ILA XCI data depth expectation missing")
    require(errors, '"C_EN_STRG_QUAL": "1"' in text, f"{CLI}: ILA storage-qualification expectation missing")
    require(errors, "trace-marker" in plan_text, f"{PREPARE_CAPTURE}: capture plan must use marker-scope LTX")
    require(errors, "--ltx" in plan_text, f"{PREPARE_CAPTURE}: capture plan must pass the marker-scope LTX")
    require(errors, "--event-only-capture" in plan_text, f"{PREPARE_CAPTURE}: capture plan must request event-only capture")
    require(errors, "trace-marker" in capture_text, f"{RUN_CAPTURE}: default LTX must target marker-scope build")
    require(errors, "trace-marker" in capture_tcl_text, f"{CAPTURE_TCL}: default LTX must target marker-scope build")
    require(errors, "trace-marker" in inspect_text, f"{INSPECT_ILA}: default LTX must target marker-scope build")
    return errors


def run_checks(root: Path) -> list[str]:
    errors: list[str] = []
    for check in (check_adapter, check_ila_generator, check_capture_tcl, check_decoder, check_marker_scope):
        try:
            errors.extend(check(root))
        except Exception as exc:
            errors.append(str(exc))
    return errors


def write_fixture(root: Path) -> None:
    (root / ADAPTER.parent).mkdir(parents=True, exist_ok=True)
    (root / ILA_TCL.parent).mkdir(parents=True, exist_ok=True)
    (root / CAPTURE_TCL.parent).mkdir(parents=True, exist_ok=True)
    (root / DECODER.parent).mkdir(parents=True, exist_ok=True)
    (root / CLI.parent).mkdir(parents=True, exist_ok=True)
    (root / PREPARE_CAPTURE.parent).mkdir(parents=True, exist_ok=True)
    (root / PACKAGE_SAFE.parent).mkdir(parents=True, exist_ok=True)
    (root / RUN_CAPTURE.parent).mkdir(parents=True, exist_ok=True)
    (root / INSPECT_ILA.parent).mkdir(parents=True, exist_ok=True)
    (root / ADAPTER).write_text(
        "function automatic void offer_candidate(); endfunction\n"
        "localparam int INTERNAL_EVENT_QUEUE_DEPTH = 17;\n"
        "logic accepted_candidate_count;\n"
        "logic pending_count_next;\n"
        "trace_packet_o = pending_q[0];\n",
        encoding="utf-8",
    )
    (root / ILA_TCL).write_text(
        "set dataDepth [rvmt_env_or_default RVMT_ILA_DATA_DEPTH 8192]\n"
        "set inputPipeStages [rvmt_env_or_default RVMT_ILA_INPUT_PIPE_STAGES 2]\n"
        "set storageQual [rvmt_env_or_default RVMT_ILA_STORAGE_QUAL 1]\n"
        "set advTrigger [rvmt_env_or_default RVMT_ILA_ADV_TRIGGER TRUE]\n",
        encoding="utf-8",
    )
    (root / CAPTURE_TCL).write_text(
        "set ltx_file {build/vivado/target-trace-marker/work-fpga/ariane_xilinx.ltx}\n"
        "set_property CONTROL.CAPTURE_MODE BASIC $ila\n"
        "set_property CAPTURE_COMPARE_VALUE eq1'b1 $fire_probe\n"
        "puts RVMT_EVENT_ONLY_CAPTURE_UNSUPPORTED\n"
        "puts RVMT_EVENT_ONLY_CAPTURE_NOT_APPLIED\n"
        "exit 8\n",
        encoding="utf-8",
    )
    (root / DECODER).write_text(
        "SATP_MODE_NAMES = {}\n"
        "event['satp_asid'] = '0x0000'\n"
        "event['satp_ppn'] = '0x0'\n"
        "event['satp_asid_source'] = 'unavailable_packed_32bit_primary'\n",
        encoding="utf-8",
    )
    (root / PACKAGE_SAFE).write_text("paired_syscall_windows = []\nsatp_context = {}\n", encoding="utf-8")
    (root / CLI).write_text(
        "bitstream:build-trace-marker\n"
        "RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE\n"
        "def refresh_xlnx_ila_ip(): pass\n"
        "def check_xlnx_ila_xci(): pass\n"
        "def sync_xlnx_ila_artifact_xci(): pass\n"
        '"C_DATA_DEPTH": "8192"\n'
        '"C_EN_STRG_QUAL": "1"\n',
        encoding="utf-8",
    )
    (root / PREPARE_CAPTURE).write_text(
        "build/vivado/target-trace-marker/work-fpga/ariane_xilinx.ltx\n--ltx\n--event-only-capture\n",
        encoding="utf-8",
    )
    (root / RUN_CAPTURE).write_text(
        "DEFAULT_LTX = 'build/vivado/target-trace-marker/work-fpga/ariane_xilinx.ltx'\n",
        encoding="utf-8",
    )
    (root / INSPECT_ILA).write_text(
        "set ltx_file {build/vivado/target-trace-marker/work-fpga/ariane_xilinx.ltx}\n",
        encoding="utf-8",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root)
        if errors:
            print("[FAIL] positive fixture failed", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        (root / ADAPTER).write_text("trace_packet_o = candidates[0];\n", encoding="utf-8")
        errors = run_checks(root)
        if not errors:
            print("[FAIL] self-test missed candidate bypass regression", file=sys.stderr)
            return 1
    print("[PASS] Genesys2/CVA6 closure readiness self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check repository readiness for the next Genesys2/CVA6 trace closure run.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    errors = run_checks(args.root.resolve())
    if errors:
        print("[FAIL] Genesys2/CVA6 closure readiness")
        for error in errors:
            print(f"- {error}")
        return 1
    print("[PASS] Genesys2/CVA6 closure readiness: timing, ILA, marker, and SATP/ASID hooks are configured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
