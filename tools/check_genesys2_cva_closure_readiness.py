from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

from experiment_common import (
    require,
)


ADAPTER = Path("rtl/trace/cva6_rvfi_trace_adapter.sv")
FPGA_TOP = Path("rtl/cva6/corev_apu/fpga/src/ariane_xilinx.sv")
ILA_TCL = Path("rtl/cva6/corev_apu/fpga/xilinx/xlnx_ila/tcl/run.tcl")
CAPTURE_TCL = Path("tools/capture_genesys2_ila_event.tcl")
DECODER = Path("tools/decode_genesys2_ila_trace.py")
BRAM_DECODER = Path("tools/decode_genesys2_bram_ring_dump.py")
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


def compact_sv(text: str) -> str:
    return re.sub(r"\s+", "", text)


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


def check_fpga_top_payload(root: Path) -> list[str]:
    text = read(root, FPGA_TOP)
    compact = compact_sv(text)
    errors: list[str] = []
    require(
        errors,
        re.search(r"localparam\s+int\s+unsigned\s+RVMT_TRACE_ILA_PAYLOAD_WIDTH\s*=\s*136\s*;", text) is not None,
        f"{FPGA_TOP}: packed ILA payload width must be 136 bits",
    )
    require(
        errors,
        re.search(r"logic\s*\[\s*31\s*:\s*0\s*\]\s*rvmt_trace_probe_aux\s*;", text) is not None,
        f"{FPGA_TOP}: packed aux field for entry-side syscall_id missing",
    )
    require(
        errors,
        "trace_pkg::EVT_SYSCALL_ENTRY:begin"
        "rvmt_trace_probe_primary=rvmt_trace_packet.a7[31:0];"
        "rvmt_trace_probe_aux=rvmt_trace_packet.syscall_id[31:0];"
        "end" in compact,
        f"{FPGA_TOP}: SYSCALL_ENTRY must pack a7 in primary and syscall_id in aux",
    )
    require(
        errors,
        "trace_pkg::EVT_SYSCALL_RET:begin"
        "rvmt_trace_probe_primary=rvmt_trace_packet.syscall_id[31:0];"
        "end" in compact,
        f"{FPGA_TOP}: SYSCALL_RET must pack syscall_id in primary",
    )
    require(
        errors,
        "assignrvmt_trace_probe_payload={"
        "rvmt_trace_probe_aux,"
        "4'd0,"
        "rvmt_trace_probe_primary,"
        "rvmt_trace_packet.pc[31:0],"
        "rvmt_trace_packet.cycle[31:0],"
        "rvmt_trace_packet.evt"
        "};" in compact,
        f"{FPGA_TOP}: packed payload order must be aux, pad, primary, pc, cycle, event",
    )
    require(
        errors,
        ".probe1(rvmt_trace_probe_payload)" in compact,
        f"{FPGA_TOP}: ILA probe1 must expose the packed payload",
    )
    require(
        errors,
        re.search(r"localparam\s+int\s+unsigned\s+RVMT_TRACE_BRAM_PROBE_WIDTH\s*=\s*716\s*;", text) is not None,
        f"{FPGA_TOP}: BRAM probe payload width must be 716 bits",
    )
    require(
        errors,
        "assignrvmt_trace_bram_probe_payload={"
        "rvmt_trace_bram_event_count,"
        "rvmt_trace_bram_captured_count,"
        "rvmt_trace_bram_dropped_count,"
        "rvmt_trace_bram_wrap_count,"
        "rvmt_trace_bram_next_sequence,"
        "rvmt_trace_bram_oldest_index,"
        "rvmt_trace_bram_write_index,"
        "rvmt_trace_bram_dump_index,"
        "rvmt_trace_bram_full,"
        "rvmt_trace_bram_dump_valid,"
        "rvmt_trace_bram_dump_mem_base,"
        "rvmt_trace_bram_dump_mem_addr,"
        "rvmt_trace_bram_dump_mem_data,"
        "rvmt_trace_bram_dump_syscall_id,"
        "rvmt_trace_bram_dump_arg_index,"
        "rvmt_trace_bram_dump_mem_size,"
        "rvmt_trace_bram_dump_mem_last,"
        "rvmt_trace_bram_dump_sequence,"
        "rvmt_trace_bram_dump_aux,"
        "rvmt_trace_bram_dump_primary,"
        "rvmt_trace_bram_dump_pc,"
        "rvmt_trace_bram_dump_cycle,"
        "rvmt_trace_bram_dump_evt"
        "};" in compact,
        f"{FPGA_TOP}: BRAM ring dump/accounting payload must be exposed",
    )
    require(
        errors,
        ".probe2(rvmt_trace_bram_probe_payload)" in compact,
        f"{FPGA_TOP}: ILA probe2 must expose BRAM ring dump/accounting payload",
    )
    require(
        errors,
        "assignrvmt_trace_bram_marker_begin=rvmt_trace_fire&&rvmt_trace_packet.evt==trace_pkg::EVT_MARKER&&rvmt_trace_packet.value[31:28]==4'hb;" in compact
        and "assignrvmt_trace_bram_marker_end=rvmt_trace_fire&&rvmt_trace_packet.evt==trace_pkg::EVT_MARKER&&rvmt_trace_packet.value[31:28]==4'he;" in compact
        and "assignrvmt_trace_bram_clear=rvmt_trace_bram_marker_begin;" in compact
        and ".freeze_i(rvmt_trace_bram_freeze)" in compact,
        f"{FPGA_TOP}: BRAM marker window must clear on begin marker and freeze after end marker",
    )
    return errors


def check_ila_generator(root: Path) -> list[str]:
    text = read(root, ILA_TCL)
    errors: list[str] = []
    expected = {
        "CONFIG.C_NUM_OF_PROBES {3}": "ILA must expose fire, event payload, and BRAM ring payload",
        "CONFIG.C_PROBE1_WIDTH {136}": "packed ILA payload must expose syscall-id aux for entry records",
        "CONFIG.C_PROBE2_WIDTH {716}": "BRAM ring dump/accounting payload width missing",
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
        ("eq${payload_width}'h", "trigger compare must use the configured packed payload width"),
        ("set payload_width 136", "trigger compare width must match the 136-bit packed payload"),
        ("string repeat X 9", "primary compare must skip aux plus pad before primary"),
        ("[string repeat X 16]", "primary compare must skip pc plus cycle before event"),
        ("exit 8", "event-only capture failures must stop the run"),
    ):
        require(errors, needle in text, f"{CAPTURE_TCL}: {message}")
    return errors


def check_decoder(root: Path) -> list[str]:
    text = read(root, DECODER)
    bram_text = read(root, BRAM_DECODER)
    package_text = read(root, PACKAGE_SAFE)
    errors: list[str] = []
    for needle, message in (
        ("SATP_MODE_NAMES", "decoder must name SATP modes"),
        ("satp_asid", "decoder must extract SATP ASID for wide captures"),
        ("satp_ppn", "decoder must extract SATP PPN for wide captures"),
        ("packed_aux", "decoder must decode packed aux for entry-side syscall_id"),
        ("unavailable_packed_32bit_primary", "decoder must bound packed SATP attribution"),
    ):
        require(errors, needle in text, f"{DECODER}: {message}")
    require(errors, "paired_syscall_windows" in package_text, f"{PACKAGE_SAFE}: same-window syscall pairs must be summarized")
    require(errors, "satp_context" in package_text, f"{PACKAGE_SAFE}: SATP/ASID context summary missing")
    require(errors, "rvmt_trace_bram_probe_payload" in bram_text, f"{BRAM_DECODER}: BRAM probe payload decoder missing")
    require(errors, "BRAM_PAYLOAD_WIDTH_V3 = 716" in bram_text, f"{BRAM_DECODER}: BRAM payload width mismatch")
    require(errors, "dropped_count" in bram_text and "wrap_count" in bram_text, f"{BRAM_DECODER}: drop/wrap accounting decode missing")
    require(errors, "start_timestamp" in bram_text and "end_timestamp" in bram_text, f"{BRAM_DECODER}: timestamp summary missing")
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
    require(errors, '"C_NUM_OF_PROBES": "3"' in text, f"{CLI}: ILA probe-count expectation missing")
    require(errors, '"C_PROBE1_WIDTH": "136"' in text, f"{CLI}: ILA packed payload width expectation missing")
    require(errors, '"C_PROBE2_WIDTH": "716"' in text, f"{CLI}: ILA BRAM payload width expectation missing")
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
    for check in (
        check_adapter,
        check_fpga_top_payload,
        check_ila_generator,
        check_capture_tcl,
        check_decoder,
        check_marker_scope,
    ):
        try:
            errors.extend(check(root))
        except Exception as exc:
            errors.append(str(exc))
    return errors


def write_fixture(root: Path) -> None:
    (root / ADAPTER.parent).mkdir(parents=True, exist_ok=True)
    (root / FPGA_TOP.parent).mkdir(parents=True, exist_ok=True)
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
    (root / FPGA_TOP).write_text(
        "localparam int unsigned RVMT_TRACE_ILA_PAYLOAD_WIDTH = 136;\n"
        "localparam int unsigned RVMT_TRACE_BRAM_PROBE_WIDTH = 716;\n"
        "logic [31:0] rvmt_trace_probe_primary;\n"
        "logic [31:0] rvmt_trace_probe_aux;\n"
        "logic [RVMT_TRACE_ILA_PAYLOAD_WIDTH-1:0] rvmt_trace_probe_payload;\n"
        "logic [RVMT_TRACE_BRAM_PROBE_WIDTH-1:0] rvmt_trace_bram_probe_payload;\n"
        "logic rvmt_trace_bram_clear, rvmt_trace_bram_freeze, rvmt_trace_bram_marker_begin, rvmt_trace_bram_marker_end;\n"
        "always_comb begin\n"
        "  rvmt_trace_probe_primary = 32'd0;\n"
        "  rvmt_trace_probe_aux = 32'd0;\n"
        "  unique case (rvmt_trace_packet.evt)\n"
        "    trace_pkg::EVT_SYSCALL_ENTRY: begin\n"
        "      rvmt_trace_probe_primary = rvmt_trace_packet.a7[31:0];\n"
        "      rvmt_trace_probe_aux = rvmt_trace_packet.syscall_id[31:0];\n"
        "    end\n"
        "    trace_pkg::EVT_SYSCALL_RET: begin\n"
        "      rvmt_trace_probe_primary = rvmt_trace_packet.syscall_id[31:0];\n"
        "    end\n"
        "    default: begin\n"
        "      rvmt_trace_probe_primary = 32'd0;\n"
        "    end\n"
        "  endcase\n"
        "end\n"
        "assign rvmt_trace_probe_payload = {\n"
        "    rvmt_trace_probe_aux,\n"
        "    4'd0,\n"
        "    rvmt_trace_probe_primary,\n"
        "    rvmt_trace_packet.pc[31:0],\n"
        "    rvmt_trace_packet.cycle[31:0],\n"
        "    rvmt_trace_packet.evt\n"
        "};\n"
        "assign rvmt_trace_bram_probe_payload = {\n"
        "    rvmt_trace_bram_event_count,\n"
        "    rvmt_trace_bram_captured_count,\n"
        "    rvmt_trace_bram_dropped_count,\n"
        "    rvmt_trace_bram_wrap_count,\n"
        "    rvmt_trace_bram_next_sequence,\n"
        "    rvmt_trace_bram_oldest_index,\n"
        "    rvmt_trace_bram_write_index,\n"
        "    rvmt_trace_bram_dump_index,\n"
        "    rvmt_trace_bram_full,\n"
        "    rvmt_trace_bram_dump_valid,\n"
        "    rvmt_trace_bram_dump_mem_base,\n"
        "    rvmt_trace_bram_dump_mem_addr,\n"
        "    rvmt_trace_bram_dump_mem_data,\n"
        "    rvmt_trace_bram_dump_syscall_id,\n"
        "    rvmt_trace_bram_dump_arg_index,\n"
        "    rvmt_trace_bram_dump_mem_size,\n"
        "    rvmt_trace_bram_dump_mem_last,\n"
        "    rvmt_trace_bram_dump_sequence,\n"
        "    rvmt_trace_bram_dump_aux,\n"
        "    rvmt_trace_bram_dump_primary,\n"
        "    rvmt_trace_bram_dump_pc,\n"
        "    rvmt_trace_bram_dump_cycle,\n"
        "    rvmt_trace_bram_dump_evt\n"
        "};\n"
        "assign rvmt_trace_bram_marker_begin = rvmt_trace_fire && rvmt_trace_packet.evt == trace_pkg::EVT_MARKER && rvmt_trace_packet.value[31:28] == 4'hb;\n"
        "assign rvmt_trace_bram_marker_end = rvmt_trace_fire && rvmt_trace_packet.evt == trace_pkg::EVT_MARKER && rvmt_trace_packet.value[31:28] == 4'he;\n"
        "assign rvmt_trace_bram_clear = rvmt_trace_bram_marker_begin;\n"
        "trace_bram_ring i_rvmt_trace_bram_ring (\n"
        "    .clear_i(rvmt_trace_bram_clear),\n"
        "    .freeze_i(rvmt_trace_bram_freeze)\n"
        ");\n"
        "xlnx_ila i_rvmt_trace_ila (\n"
        "    .probe1(rvmt_trace_probe_payload),\n"
        "    .probe2(rvmt_trace_bram_probe_payload)\n"
        ");\n",
        encoding="utf-8",
    )
    (root / ILA_TCL).write_text(
        "set dataDepth [rvmt_env_or_default RVMT_ILA_DATA_DEPTH 8192]\n"
        "set inputPipeStages [rvmt_env_or_default RVMT_ILA_INPUT_PIPE_STAGES 2]\n"
        "set storageQual [rvmt_env_or_default RVMT_ILA_STORAGE_QUAL 1]\n"
        "CONFIG.C_NUM_OF_PROBES {3}\n"
        "CONFIG.C_PROBE1_WIDTH {136}\n"
        "CONFIG.C_PROBE2_WIDTH {716}\n"
        "set advTrigger [rvmt_env_or_default RVMT_ILA_ADV_TRIGGER TRUE]\n",
        encoding="utf-8",
    )
    (root / CAPTURE_TCL).write_text(
        "set ltx_file {build/vivado/target-trace-marker/work-fpga/ariane_xilinx.ltx}\n"
        "set payload_width 136\n"
        "set compare \"eq${payload_width}'h\"\n"
        "set compare \"eq${payload_width}'h[string repeat X 9]${primary_hex}[string repeat X 16]${evt_hex}\"\n"
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
        "event['packed_aux'] = '0x00000000'\n"
        "event['satp_asid_source'] = 'unavailable_packed_32bit_primary'\n",
        encoding="utf-8",
    )
    (root / BRAM_DECODER).write_text(
        "BRAM_PAYLOAD_WIDTH_V3 = 716\n"
        "rvmt_trace_bram_probe_payload\n"
        "dropped_count\n"
        "wrap_count\n"
        "start_timestamp\n"
        "end_timestamp\n",
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
        '"C_NUM_OF_PROBES": "3"\n'
        '"C_PROBE1_WIDTH": "136"\n'
        '"C_PROBE2_WIDTH": "716"\n'
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
        write_fixture(root)
        (root / FPGA_TOP).write_text(
            (root / FPGA_TOP).read_text(encoding="utf-8").replace(
                "rvmt_trace_probe_aux = rvmt_trace_packet.syscall_id[31:0];",
                "rvmt_trace_probe_aux = 32'd0;",
            ),
            encoding="utf-8",
        )
        errors = run_checks(root)
        if not errors:
            print("[FAIL] self-test missed packed entry syscall_id regression", file=sys.stderr)
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
