from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path


TRACE_PKG = Path("rtl/trace/trace_pkg.sv")
BRAM_RING = Path("rtl/trace/trace_bram_ring.sv")
FPGA_TOP = Path("rtl/cva6/corev_apu/fpga/src/ariane_xilinx.sv")
ADD_SOURCES = Path("rtl/cva6/corev_apu/fpga/scripts/add_sources.tcl")
TRACE_RTL_F = Path("sim/vivado/trace_rtl.f")
TRACE_SIM_F = Path("sim/vivado/trace_sim.f")
RUN_ALL_TESTS = Path("sim/vivado/run_all_tests.tcl")
RUN_XSIM = Path("sim/vivado/run_xsim.tcl")
SUMMARIZE_RESULTS = Path("tools/summarize_results.py")
CLI = Path("src/rv_maltrace/cli.py")
BRAM_DECODER = Path("tools/decode_genesys2_bram_ring_dump.py")
BRAM_PACKAGER = Path("tools/package_genesys2_bram_trace_sink_summary.py")
ILA_COMMAND_CAPTURE = Path("tools/run_genesys2_ila_command_capture.py")


def read(root: Path, path: Path) -> str:
    full = root / path
    if not full.is_file():
        raise FileNotFoundError(path.as_posix())
    return full.read_text(encoding="utf-8", errors="replace")


def compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def check_trace_pkg(root: Path) -> list[str]:
    text = read(root, TRACE_PKG)
    compact_text = compact(text)
    errors: list[str] = []
    for needle in (
        "trace_compact_record_t",
        "logic [31:0] seq",
        "logic [31:0] aux",
        "logic [31:0] primary",
        "logic [31:0] pc",
        "logic [31:0] cycle",
        "trace_evt_e  evt",
        "trace_packet_primary32",
        "trace_packet_aux32",
        "trace_compact_record",
    ):
        require(errors, needle in text, f"{TRACE_PKG}: missing {needle}")
    for needle in (
        "EVT_SYSCALL_ENTRY:begintrace_packet_primary32=packet.a7[31:0];end",
        "EVT_SYSCALL_ENTRY:begintrace_packet_aux32=packet.syscall_id[31:0];end",
        "EVT_SYSCALL_RET:begintrace_packet_primary32=packet.syscall_id[31:0];end",
        "EVT_SYSCALL_RET:begintrace_packet_aux32=packet.a0[31:0];end",
        "trace_compact_record.seq=seq;",
        "trace_compact_record.aux=trace_packet_aux32(packet);",
        "trace_compact_record.primary=trace_packet_primary32(packet);",
    ):
        require(errors, needle in compact_text, f"{TRACE_PKG}: compact record mapping missing {needle}")
    return errors


def check_bram_ring(root: Path) -> list[str]:
    text = read(root, BRAM_RING)
    compact_text = compact(text)
    errors: list[str] = []
    for needle in (
        "module trace_bram_ring",
        "import trace_pkg::*",
        "parameter int unsigned DEPTH = 1024",
        "localparam int unsigned RECORD_WIDTH = $bits(trace_compact_record_t)",
        '(* ram_style = "block" *)',
        "logic [RECORD_WIDTH-1:0] ring_mem_q [DEPTH]",
        "dropped_count_o",
        "wrap_count_o",
        "start_timestamp_o",
        "end_timestamp_o",
        "dump_record_q",
        "dump_valid_q",
    ):
        require(errors, needle in text, f"{BRAM_RING}: missing {needle}")
    for needle in (
        "assigncapture_fire=capture_enable_i&&!freeze_i&&trace_valid_i&&trace_packet_i.valid;",
        "assigncapture_write=rst_ni&&capture_fire;",
        "assignwrite_index_d=clear_i?'0:write_index_q;",
        "assignwrite_sequence_d=clear_i?32'd0:next_sequence_q;",
        "dump_record_q<=trace_compact_record_t'(ring_mem_q[dump_index_i]);",
        "ring_mem_q[write_index_d]<=trace_compact_record(trace_packet_i,write_sequence_d);",
        "event_count_q<=clear_i?64'd1:event_count_q+64'd1;",
        "dropped_count_q<=clear_i?64'd0:(full_q?dropped_count_q+64'd1:dropped_count_q);",
        "wrap_count_q<=clear_i?(write_wrap?64'd1:64'd0):(write_wrap?wrap_count_q+64'd1:wrap_count_q);",
        "start_timestamp_q<=(clear_i||!seen_event_q)?trace_packet_i.cycle:start_timestamp_q;",
        "end_timestamp_q<=trace_packet_i.cycle;",
    ):
        require(errors, needle in compact_text, f"{BRAM_RING}: missing implementation path {needle}")
    require(errors, "trace_ready" not in compact_text, f"{BRAM_RING}: readiness gate expects no backpressure-ready contract")
    return errors


def check_fpga_top(root: Path) -> list[str]:
    text = read(root, FPGA_TOP)
    compact_text = compact(text)
    errors: list[str] = []
    for needle in (
        "RVMT_TRACE_BRAM_RING_DEPTH = 1024",
        "RVMT_TRACE_BRAM_RING_ADDR_WIDTH",
        "rvmt_trace_bram_dump_index",
        "rvmt_trace_bram_dropped_count",
        "rvmt_trace_bram_wrap_count",
        "rvmt_trace_bram_start_timestamp",
        "rvmt_trace_bram_end_timestamp",
        "rvmt_trace_bram_dump_sequence",
        "rvmt_trace_bram_dump_primary",
        "rvmt_trace_bram_clear",
        "RVMT_TRACE_BRAM_PROBE_WIDTH = 484",
        "rvmt_trace_bram_probe_payload",
        "mark_debug",
    ):
        require(errors, needle in text, f"{FPGA_TOP}: missing {needle}")
    for needle in (
        "`ifdefRV_MALTRACE_FPGA_TRACE",
        "assignrvmt_trace_bram_clear=rvmt_trace_fire&&rvmt_trace_packet.evt==trace_pkg::EVT_MARKER&&rvmt_trace_packet.value[31:28]==4'hb;",
        "trace_bram_ring#(.DEPTH(RVMT_TRACE_BRAM_RING_DEPTH),.ADDR_WIDTH(RVMT_TRACE_BRAM_RING_ADDR_WIDTH))i_rvmt_trace_bram_ring",
        ".clear_i(rvmt_trace_bram_clear)",
        ".trace_valid_i(rvmt_trace_valid)",
        ".trace_packet_i(rvmt_trace_packet)",
        ".dropped_count_o(rvmt_trace_bram_dropped_count)",
        ".wrap_count_o(rvmt_trace_bram_wrap_count)",
        "rvmt_trace_bram_dump_index<=rvmt_trace_bram_dump_index+1'b1;",
        "assignrvmt_trace_bram_probe_payload={rvmt_trace_bram_event_count,rvmt_trace_bram_captured_count,rvmt_trace_bram_dropped_count,rvmt_trace_bram_wrap_count,rvmt_trace_bram_next_sequence,rvmt_trace_bram_oldest_index,rvmt_trace_bram_write_index,rvmt_trace_bram_dump_index,rvmt_trace_bram_full,rvmt_trace_bram_dump_valid,rvmt_trace_bram_dump_sequence,rvmt_trace_bram_dump_aux,rvmt_trace_bram_dump_primary,rvmt_trace_bram_dump_pc,rvmt_trace_bram_dump_cycle,rvmt_trace_bram_dump_evt};",
        "xlnx_ilai_rvmt_trace_ila",
        ".probe2(rvmt_trace_bram_probe_payload)",
    ):
        require(errors, needle in compact_text, f"{FPGA_TOP}: missing BRAM/ILA integration path {needle}")
    return errors


def check_build_and_sim(root: Path) -> list[str]:
    errors: list[str] = []
    add_sources = read(root, ADD_SOURCES)
    trace_rtl = read(root, TRACE_RTL_F)
    trace_sim = read(root, TRACE_SIM_F)
    run_all = read(root, RUN_ALL_TESTS)
    run_xsim = read(root, RUN_XSIM)
    summarize = read(root, SUMMARIZE_RESULTS)
    cli = read(root, CLI)
    bram_decoder = read(root, BRAM_DECODER)
    bram_packager = read(root, BRAM_PACKAGER)
    ila_command_capture = read(root, ILA_COMMAND_CAPTURE)
    add_sources_has_ring = "R:/rtl/trace/trace_bram_ring.sv" in add_sources
    wrapper_injects_ring = (
        "trace_bram_ring.sv" in cli
        and "trace_board_minimal_ctrl.sv R:/rtl/trace/trace_bram_ring.sv" in cli
        and "RV_MALTRACE_FPGA_TRACE" in cli
    )
    require(
        errors,
        add_sources_has_ring or wrapper_injects_ring,
        f"{ADD_SOURCES}: trace_bram_ring.sv must be present or injected by the trace-build wrapper",
    )
    require(errors, wrapper_injects_ring, f"{CLI}: trace-build wrapper must inject trace_bram_ring.sv after generated add_sources.tcl is normalized")
    require(errors, "rtl/trace/trace_bram_ring.sv" in trace_rtl, f"{TRACE_RTL_F}: trace_bram_ring.sv missing from RTL filelist")
    require(errors, "sim/tb/tb_trace_bram_ring.sv" in trace_sim, f"{TRACE_SIM_F}: tb_trace_bram_ring.sv missing from sim filelist")
    require(errors, "bram_ring" in run_all and "tb_trace_bram_ring" in run_all, f"{RUN_ALL_TESTS}: bram_ring test missing")
    require(errors, "rvmt_run_xsim_top_no_compare" in run_xsim, f"{RUN_XSIM}: no-compare xsim helper missing")
    require(errors, "xsim_status.log" in summarize, f"{SUMMARIZE_RESULTS}: no-compare xsim summaries missing")
    require(errors, '"rtl/trace/trace_bram_ring.sv"' in cli, f"{CLI}: trace-marker source hash manifest must include trace_bram_ring.sv")
    require(errors, '"tools/decode_genesys2_bram_ring_dump.py"' in cli, f"{CLI}: trace-marker source hash manifest must include BRAM dump decoder")
    require(errors, '"tools/package_genesys2_bram_trace_sink_summary.py"' in cli, f"{CLI}: trace-marker source hash manifest must include BRAM trace sink packager")
    require(errors, '"tools/run_genesys2_ila_command_capture.py"' in cli, f"{CLI}: trace-marker source hash manifest must include ILA command capture helper")
    require(errors, "rvmt_trace_bram_probe_payload" in bram_decoder, f"{BRAM_DECODER}: BRAM probe payload decoder missing")
    require(errors, "BRAM_PAYLOAD_WIDTH = 484" in bram_decoder, f"{BRAM_DECODER}: BRAM payload width mismatch")
    require(errors, "rvmt.genesys2.bram_trace_sink.v1" in bram_packager, f"{BRAM_PACKAGER}: Phase C trace sink summary schema missing")
    require(errors, "expected_event_recall" in bram_packager, f"{BRAM_PACKAGER}: expected event recall packaging missing")
    require(errors, "--bram-summary" in ila_command_capture, f"{ILA_COMMAND_CAPTURE}: BRAM summary capture option missing")
    return errors


def run_checks(root: Path) -> list[str]:
    errors: list[str] = []
    for check in (check_trace_pkg, check_bram_ring, check_fpga_top, check_build_and_sim):
        try:
            errors.extend(check(root))
        except Exception as exc:
            errors.append(str(exc))
    return errors


def write_fixture(root: Path) -> None:
    for path in (
        TRACE_PKG,
        BRAM_RING,
        FPGA_TOP,
        ADD_SOURCES,
        TRACE_RTL_F,
        TRACE_SIM_F,
        RUN_ALL_TESTS,
        RUN_XSIM,
        SUMMARIZE_RESULTS,
        CLI,
        BRAM_DECODER,
        BRAM_PACKAGER,
        ILA_COMMAND_CAPTURE,
    ):
        (root / path.parent).mkdir(parents=True, exist_ok=True)
    (root / TRACE_PKG).write_text(
        "typedef struct packed {\n"
        "  logic [31:0] seq;\n"
        "  logic [31:0] aux;\n"
        "  logic [31:0] primary;\n"
        "  logic [31:0] pc;\n"
        "  logic [31:0] cycle;\n"
        "  trace_evt_e  evt;\n"
        "} trace_compact_record_t;\n"
        "function automatic logic [31:0] trace_packet_primary32(input trace_packet_t packet);\n"
        "  unique case (packet.evt)\n"
        "    EVT_SYSCALL_ENTRY: begin trace_packet_primary32 = packet.a7[31:0]; end\n"
        "    EVT_SYSCALL_RET: begin trace_packet_primary32 = packet.syscall_id[31:0]; end\n"
        "  endcase\n"
        "endfunction\n"
        "function automatic logic [31:0] trace_packet_aux32(input trace_packet_t packet);\n"
        "  unique case (packet.evt)\n"
        "    EVT_SYSCALL_ENTRY: begin trace_packet_aux32 = packet.syscall_id[31:0]; end\n"
        "    EVT_SYSCALL_RET: begin trace_packet_aux32 = packet.a0[31:0]; end\n"
        "  endcase\n"
        "endfunction\n"
        "function automatic trace_compact_record_t trace_compact_record(input trace_packet_t packet, input logic [31:0] seq);\n"
        "  trace_compact_record.seq = seq;\n"
        "  trace_compact_record.aux = trace_packet_aux32(packet);\n"
        "  trace_compact_record.primary = trace_packet_primary32(packet);\n"
        "endfunction\n",
        encoding="utf-8",
    )
    (root / BRAM_RING).write_text(
        "module trace_bram_ring\n"
        "  import trace_pkg::*;\n"
        "#(parameter int unsigned DEPTH = 1024) ();\n"
        "  localparam int unsigned RECORD_WIDTH = $bits(trace_compact_record_t);\n"
        "  (* ram_style = \"block\" *) logic [RECORD_WIDTH-1:0] ring_mem_q [DEPTH];\n"
        "  trace_compact_record_t dump_record_q;\n"
        "  logic dump_valid_q;\n"
        "  logic dropped_count_o, wrap_count_o, start_timestamp_o, end_timestamp_o;\n"
        "  assign capture_fire = capture_enable_i && !freeze_i && trace_valid_i && trace_packet_i.valid;\n"
        "  assign capture_write = rst_ni && capture_fire;\n"
        "  assign write_index_d = clear_i ? '0 : write_index_q;\n"
        "  assign write_sequence_d = clear_i ? 32'd0 : next_sequence_q;\n"
        "  always_ff @(posedge clk_i) begin\n"
        "    dump_record_q <= trace_compact_record_t'(ring_mem_q[dump_index_i]);\n"
        "    ring_mem_q[write_index_d] <= trace_compact_record(trace_packet_i, write_sequence_d);\n"
        "    event_count_q <= clear_i ? 64'd1 : event_count_q + 64'd1;\n"
        "    dropped_count_q <= clear_i ? 64'd0 : (full_q ? dropped_count_q + 64'd1 : dropped_count_q);\n"
        "    wrap_count_q <= clear_i ? (write_wrap ? 64'd1 : 64'd0) : (write_wrap ? wrap_count_q + 64'd1 : wrap_count_q);\n"
        "    start_timestamp_q <= (clear_i || !seen_event_q) ? trace_packet_i.cycle : start_timestamp_q;\n"
        "    end_timestamp_q <= trace_packet_i.cycle;\n"
        "  end\n"
        "endmodule\n",
        encoding="utf-8",
    )
    (root / FPGA_TOP).write_text(
        "`ifdef RV_MALTRACE_FPGA_TRACE\n"
        "localparam int unsigned RVMT_TRACE_BRAM_RING_DEPTH = 1024;\n"
        "localparam int unsigned RVMT_TRACE_BRAM_RING_ADDR_WIDTH = $clog2(RVMT_TRACE_BRAM_RING_DEPTH);\n"
        "localparam int unsigned RVMT_TRACE_BRAM_PROBE_WIDTH = 484;\n"
        "(* mark_debug = \"true\" *) logic rvmt_trace_bram_dump_index;\n"
        "logic rvmt_trace_bram_dropped_count, rvmt_trace_bram_wrap_count, rvmt_trace_bram_start_timestamp, rvmt_trace_bram_end_timestamp;\n"
        "logic rvmt_trace_bram_dump_sequence, rvmt_trace_bram_dump_primary;\n"
        "logic rvmt_trace_bram_event_count, rvmt_trace_bram_captured_count, rvmt_trace_bram_next_sequence, rvmt_trace_bram_oldest_index, rvmt_trace_bram_write_index;\n"
        "logic rvmt_trace_bram_full, rvmt_trace_bram_dump_valid, rvmt_trace_bram_dump_aux, rvmt_trace_bram_dump_pc, rvmt_trace_bram_dump_cycle, rvmt_trace_bram_dump_evt;\n"
        "logic [RVMT_TRACE_BRAM_PROBE_WIDTH-1:0] rvmt_trace_bram_probe_payload;\n"
        "assign rvmt_trace_bram_clear = rvmt_trace_fire && rvmt_trace_packet.evt == trace_pkg::EVT_MARKER && rvmt_trace_packet.value[31:28] == 4'hb;\n"
        "trace_bram_ring #(\n"
        "  .DEPTH(RVMT_TRACE_BRAM_RING_DEPTH),\n"
        "  .ADDR_WIDTH(RVMT_TRACE_BRAM_RING_ADDR_WIDTH)\n"
        ") i_rvmt_trace_bram_ring (\n"
        "  .clear_i(rvmt_trace_bram_clear),\n"
        "  .trace_valid_i(rvmt_trace_valid),\n"
        "  .trace_packet_i(rvmt_trace_packet),\n"
        "  .dropped_count_o(rvmt_trace_bram_dropped_count),\n"
        "  .wrap_count_o(rvmt_trace_bram_wrap_count)\n"
        ");\n"
        "always_ff @(posedge clk) rvmt_trace_bram_dump_index <= rvmt_trace_bram_dump_index + 1'b1;\n"
        "assign rvmt_trace_bram_probe_payload = {rvmt_trace_bram_event_count, rvmt_trace_bram_captured_count, rvmt_trace_bram_dropped_count, rvmt_trace_bram_wrap_count, rvmt_trace_bram_next_sequence, rvmt_trace_bram_oldest_index, rvmt_trace_bram_write_index, rvmt_trace_bram_dump_index, rvmt_trace_bram_full, rvmt_trace_bram_dump_valid, rvmt_trace_bram_dump_sequence, rvmt_trace_bram_dump_aux, rvmt_trace_bram_dump_primary, rvmt_trace_bram_dump_pc, rvmt_trace_bram_dump_cycle, rvmt_trace_bram_dump_evt};\n"
        "xlnx_ila i_rvmt_trace_ila(.probe2(rvmt_trace_bram_probe_payload));\n"
        "`endif\n",
        encoding="utf-8",
    )
    (root / ADD_SOURCES).write_text("read_verilog -sv {R:/rtl/trace/trace_bram_ring.sv}\n", encoding="utf-8")
    (root / TRACE_RTL_F).write_text("rtl/trace/trace_bram_ring.sv\n", encoding="utf-8")
    (root / TRACE_SIM_F).write_text("sim/tb/tb_trace_bram_ring.sv\n", encoding="utf-8")
    (root / RUN_ALL_TESTS).write_text("set no_compare_tests {bram_ring}\nrvmt_run_xsim_top_no_compare $test tb_trace_bram_ring\n", encoding="utf-8")
    (root / RUN_XSIM).write_text("proc rvmt_run_xsim_top_no_compare {test top} {}\n", encoding="utf-8")
    (root / SUMMARIZE_RESULTS).write_text("xsim_status.log\n", encoding="utf-8")
    (root / CLI).write_text(
        '"rtl/trace/trace_bram_ring.sv": ("repo", "rtl/trace/trace_bram_ring.sv")\n'
        '"tools/decode_genesys2_bram_ring_dump.py": ("repo", "tools/decode_genesys2_bram_ring_dump.py")\n'
        '"tools/package_genesys2_bram_trace_sink_summary.py": ("repo", "tools/package_genesys2_bram_trace_sink_summary.py")\n'
        '"tools/run_genesys2_ila_command_capture.py": ("repo", "tools/run_genesys2_ila_command_capture.py")\n'
        'RV_MALTRACE_FPGA_TRACE trace_board_minimal_ctrl.sv R:/rtl/trace/trace_bram_ring.sv\n',
        encoding="utf-8",
    )
    (root / BRAM_DECODER).write_text(
        "BRAM_PAYLOAD_WIDTH = 484\nrvmt_trace_bram_probe_payload\n",
        encoding="utf-8",
    )
    (root / BRAM_PACKAGER).write_text(
        "rvmt.genesys2.bram_trace_sink.v1\nexpected_event_recall\n",
        encoding="utf-8",
    )
    (root / ILA_COMMAND_CAPTURE).write_text(
        "parser.add_argument('--bram-summary')\n",
        encoding="utf-8",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root)
        if errors:
            print("[FAIL] positive fixture rejected:", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
            return 1

        (root / BRAM_RING).write_text("module trace_bram_ring; endmodule\n", encoding="utf-8")
        errors = run_checks(root)
        if not errors:
            print("[FAIL] negative fixture accepted", file=sys.stderr)
            return 1
    print("[PASS] BRAM trace sink readiness checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2/CVA6 BRAM trace sink RTL and build-path readiness.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to current directory.")
    parser.add_argument("--self-test", action="store_true", help="Run fixture-based self-test.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    errors = run_checks(args.root)
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Genesys2/CVA6 BRAM trace sink RTL readiness")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
