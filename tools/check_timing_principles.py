from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path


DEFAULT_RTL_FILELIST = Path("sim/vivado/trace_rtl.f")
BACKPRESSURE_PORT_RE = re.compile(
    r"\b(?:input|output|inout)\b[^;\n]*(?:ready|stall|backpressure|waitrequest)\w*\b",
    re.IGNORECASE,
)
PIPELINE_DEFAULT_RE = re.compile(r"parameter\s+int\s+PIPELINE_INPUTS\s*=\s*1\b")
PIPELINE_DISABLED_RE = re.compile(r"parameter\s+int\s+PIPELINE_INPUTS\s*=\s*0\b")

TRACE_TOP_SNAPSHOTS = (
    ("commit_valid_s", "commit_valid_i"),
    ("commit_pc_s", "commit_pc_i"),
    ("commit_instr_s", "commit_instr_i"),
    ("next_pc_s", "next_pc_i"),
    ("sret_to_user_s", "sret_to_user_i"),
    ("jalr_target_valid_s", "jalr_target_valid_i"),
    ("jalr_target_s", "jalr_target_i"),
    ("commit_exception_s", "commit_exception_i"),
    ("commit_kill_s", "commit_kill_i"),
    ("wb_valid_s", "wb_valid_i"),
    ("wb_kill_s", "wb_kill_i"),
    ("wb_rd_s", "wb_rd_i"),
    ("wb_data_s", "wb_data_i"),
    ("trap_valid_s", "trap_valid_i"),
    ("trap_pc_s", "trap_pc_i"),
    ("trap_cause_s", "trap_cause_i"),
    ("trap_tval_s", "trap_tval_i"),
    ("csr_valid_s", "csr_valid_i"),
    ("csr_addr_s", "csr_addr_i"),
    ("csr_wdata_s", "csr_wdata_i"),
    ("priv_lvl_s", "priv_lvl_i"),
    ("satp_s", "satp_i"),
    ("trace_mem_mode_s", "trace_mem_mode_i"),
    ("mem_load_valid_s", "mem_load_valid_i"),
    ("mem_load_pc_s", "mem_load_pc_i"),
    ("mem_load_addr_s", "mem_load_addr_i"),
    ("mem_load_data_s", "mem_load_data_i"),
    ("mem_load_size_s", "mem_load_size_i"),
    ("trace_enable_retire_s", "trace_enable_retire_i"),
    ("trace_enable_branch_s", "trace_enable_branch_i"),
    ("trace_enable_jump_s", "trace_enable_jump_i"),
    ("trace_enable_syscall_s", "trace_enable_syscall_i"),
    ("trace_enable_trap_s", "trace_enable_trap_i"),
    ("trace_enable_context_s", "trace_enable_context_i"),
    ("trace_enable_marker_s", "trace_enable_marker_i"),
    ("trace_enable_drop_s", "trace_enable_drop_i"),
    ("trace_pc_filter_enable_s", "trace_pc_filter_enable_i"),
    ("trace_pc_start_s", "trace_pc_start_i"),
    ("trace_pc_end_s", "trace_pc_end_i"),
    ("trace_priv_filter_enable_s", "trace_priv_filter_enable_i"),
    ("trace_priv_mask_s", "trace_priv_mask_i"),
)
ADAPTER_SNAPSHOTS = (
    ("rvfi_valid_s", "rvfi_valid_i"),
    ("rvfi_insn_s", "rvfi_insn_i"),
    ("rvfi_trap_s", "rvfi_trap_i"),
    ("rvfi_cause_s", "rvfi_cause_i"),
    ("rvfi_tval_s", "rvfi_tval_i"),
    ("rvfi_mode_s", "rvfi_mode_i"),
    ("rvfi_compressed_s", "rvfi_compressed_i"),
    ("rvfi_pc_rdata_s", "rvfi_pc_rdata_i"),
    ("rvfi_pc_wdata_s", "rvfi_pc_wdata_i"),
    ("rvfi_sret_to_user_s", "rvfi_sret_to_user_i"),
    ("rvfi_rs1_rdata_s", "rvfi_rs1_rdata_i"),
    ("rvfi_rs2_rdata_s", "rvfi_rs2_rdata_i"),
    ("rvfi_rd_addr_s", "rvfi_rd_addr_i"),
    ("rvfi_rd_wdata_s", "rvfi_rd_wdata_i"),
    ("csr_valid_s", "csr_valid_i"),
    ("csr_addr_s", "csr_addr_i"),
    ("csr_wdata_s", "csr_wdata_i"),
    ("satp_s", "satp_i"),
)
PIPELINE_SPECS = {
    "rtl/trace/trace_top.sv": {
        "snapshots": TRACE_TOP_SNAPSHOTS,
        "consumers": (
            "commit_valid_s",
            "wb_valid_s",
            "trap_valid_s",
            "csr_valid_s",
            "trace_mem_mode_s",
            "mem_load_valid_s",
            "trace_enable_drop_s",
        ),
    },
    "rtl/trace/cva6_rvfi_trace_adapter.sv": {
        "snapshots": ADAPTER_SNAPSHOTS,
        "consumers": ("rvfi_valid_s", "rvfi_trap_s", "rvfi_insn_s", "rvfi_pc_rdata_s", "csr_valid_s", "satp_s"),
    },
}


def strip_comment(line: str) -> str:
    return line.split("//", 1)[0]


def read_filelist(path: Path) -> list[Path]:
    entries: list[Path] = []
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = strip_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("-"):
            raise ValueError(f"{path}:{line_no}: unsupported filelist option in trace RTL timing check: {line}")
        entries.append(Path(line))
    return entries


def normalized(path: Path) -> str:
    return path.as_posix().replace("\\", "/")


def clean_lines(path: Path) -> list[tuple[int, str]]:
    return [
        (line_no, strip_comment(raw_line))
        for line_no, raw_line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1)
    ]


def check_no_backpressure_ports(entries: list[Path]) -> list[str]:
    errors: list[str] = []
    for entry in entries:
        if not entry.exists():
            errors.append(f"RTL file does not exist: {entry}")
            continue
        for line_no, line in clean_lines(entry):
            if BACKPRESSURE_PORT_RE.search(line):
                errors.append(f"{entry}:{line_no}: trace RTL must not expose ready/stall/backpressure ports")
    return errors


def raw_input_re(raw_name: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![.\w]){re.escape(raw_name)}\b")


def check_pipeline_defaults(entries: list[Path]) -> list[str]:
    errors: list[str] = []
    by_name = {normalized(entry): entry for entry in entries}
    for required, spec in PIPELINE_SPECS.items():
        entry = by_name.get(required)
        if entry is None:
            errors.append(f"missing pipelined trace top from RTL filelist: {required}")
            continue
        lines = clean_lines(entry)
        text = "\n".join(line for _, line in lines)
        if PIPELINE_DISABLED_RE.search(text):
            errors.append(f"{entry}: PIPELINE_INPUTS must default to 1 for timing isolation")
        elif not PIPELINE_DEFAULT_RE.search(text):
            errors.append(f"{entry}: missing PIPELINE_INPUTS default-1 parameter")
        if "begin : g_input_pipeline" not in text:
            errors.append(f"{entry}: missing g_input_pipeline sideband register block")
        if "always_ff" not in text:
            errors.append(f"{entry}: input pipeline must use sequential registers")

        for snapshot_name, raw_name in spec["snapshots"]:
            assignment_re = re.compile(rf"\b{re.escape(snapshot_name)}\s*<=\s*{re.escape(raw_name)}\b")
            if not assignment_re.search(text):
                errors.append(f"{entry}: missing registered snapshot assignment {snapshot_name} <= {raw_name}")

        consumer_start = next((idx + 1 for idx, (_, line) in enumerate(lines) if "endgenerate" in line), None)
        if consumer_start is None:
            errors.append(f"{entry}: missing endgenerate after input pipeline")
            continue
        consumer_lines = lines[consumer_start:]
        consumer_text = "\n".join(line for _, line in consumer_lines)
        for consumer in spec["consumers"]:
            if not re.search(rf"\b{re.escape(consumer)}\b", consumer_text):
                errors.append(f"{entry}: decode/output logic does not consume snapshot {consumer}")
        for _, raw_name in spec["snapshots"]:
            pattern = raw_input_re(raw_name)
            for line_no, line in consumer_lines:
                if pattern.search(line):
                    snapshot_name = raw_name[:-2] + "_s" if raw_name.endswith("_i") else f"{raw_name}_s"
                    errors.append(f"{entry}:{line_no}: decode/output logic must consume {snapshot_name}, not {raw_name}")
    return errors


def run_checks(rtl_filelist: Path) -> list[str]:
    entries = read_filelist(rtl_filelist)
    errors: list[str] = []
    errors.extend(check_no_backpressure_ports(entries))
    errors.extend(check_pipeline_defaults(entries))
    return errors


def synthetic_pipelined_module(
    module_name: str,
    snapshots: tuple[tuple[str, str], ...],
    consumers: tuple[str, ...],
    *,
    pipeline_default: int = 1,
    direct_raw_consumer: str | None = None,
) -> str:
    ports = ["input logic clk_i", "input logic rst_ni"]
    ports.extend(f"input logic {raw_name}" for _, raw_name in snapshots)
    ports.append("output logic trace_valid_o")
    declarations = "\n".join(f"  logic {snapshot_name};" for snapshot_name, _ in snapshots)
    reset_assignments = "\n".join(f"          {snapshot_name} <= 1'b0;" for snapshot_name, _ in snapshots)
    registered_assignments = "\n".join(
        f"          {snapshot_name} <= {raw_name};" for snapshot_name, raw_name in snapshots
    )
    bypass_assignments = "\n".join(f"      assign {snapshot_name} = {raw_name};" for snapshot_name, raw_name in snapshots)
    consumer_expr = " | ".join(consumers)
    if direct_raw_consumer:
        consumer_expr = f"{consumer_expr} | {direct_raw_consumer}"
    return (
        f"module {module_name} #(parameter int PIPELINE_INPUTS = {pipeline_default}) ({', '.join(ports)});\n"
        f"{declarations}\n"
        "  generate\n"
        "    if (PIPELINE_INPUTS != 0) begin : g_input_pipeline\n"
        "      always_ff @(posedge clk_i or negedge rst_ni) begin\n"
        "        if (!rst_ni) begin\n"
        f"{reset_assignments}\n"
        "        end else begin\n"
        f"{registered_assignments}\n"
        "        end\n"
        "      end\n"
        "    end else begin : g_no_input_pipeline\n"
        f"{bypass_assignments}\n"
        "    end\n"
        "  endgenerate\n"
        "  always_comb begin\n"
        f"    trace_valid_o = {consumer_expr};\n"
        "  end\n"
        "endmodule\n"
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        rtl_dir = root / "rtl" / "trace"
        list_dir = root / "sim" / "vivado"
        rtl_dir.mkdir(parents=True)
        list_dir.mkdir(parents=True)
        filelist = list_dir / "trace_rtl.f"

        good_top = rtl_dir / "trace_top.sv"
        good_adapter = rtl_dir / "cva6_rvfi_trace_adapter.sv"
        good_top.write_text(
            synthetic_pipelined_module(
                "trace_top",
                TRACE_TOP_SNAPSHOTS,
                PIPELINE_SPECS["rtl/trace/trace_top.sv"]["consumers"],
            ),
            encoding="utf-8",
        )
        good_adapter.write_text(
            synthetic_pipelined_module(
                "cva6_rvfi_trace_adapter",
                ADAPTER_SNAPSHOTS,
                PIPELINE_SPECS["rtl/trace/cva6_rvfi_trace_adapter.sv"]["consumers"],
            ),
            encoding="utf-8",
        )
        filelist.write_text(
            "rtl/trace/trace_top.sv\nrtl/trace/cva6_rvfi_trace_adapter.sv\n",
            encoding="utf-8",
        )

        cwd = Path.cwd()
        try:
            os.chdir(root)
            errors = run_checks(filelist)
            if errors:
                for error in errors:
                    print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
                return 1

            bad_port = rtl_dir / "bad_port.sv"
            bad_port.write_text("module bad_port(output logic core_stall_o); endmodule\n", encoding="utf-8")
            filelist.write_text(
                "rtl/trace/trace_top.sv\nrtl/trace/cva6_rvfi_trace_adapter.sv\nrtl/trace/bad_port.sv\n",
                encoding="utf-8",
            )
            errors = run_checks(filelist)
            if not any("backpressure ports" in error for error in errors):
                print("[FAIL] self-test missed backpressure-style port", file=sys.stderr)
                return 1

            good_top.write_text(
                synthetic_pipelined_module(
                    "trace_top",
                    TRACE_TOP_SNAPSHOTS,
                    PIPELINE_SPECS["rtl/trace/trace_top.sv"]["consumers"],
                    direct_raw_consumer="commit_valid_i",
                ),
                encoding="utf-8",
            )
            filelist.write_text(
                "rtl/trace/trace_top.sv\nrtl/trace/cva6_rvfi_trace_adapter.sv\n",
                encoding="utf-8",
            )
            errors = run_checks(filelist)
            if not any("commit_valid_s, not commit_valid_i" in error for error in errors):
                print("[FAIL] self-test missed direct trace_top raw input consumer", file=sys.stderr)
                return 1

            good_top.write_text(
                synthetic_pipelined_module(
                    "trace_top",
                    TRACE_TOP_SNAPSHOTS,
                    PIPELINE_SPECS["rtl/trace/trace_top.sv"]["consumers"],
                ),
                encoding="utf-8",
            )
            good_adapter.write_text(
                synthetic_pipelined_module(
                    "cva6_rvfi_trace_adapter",
                    ADAPTER_SNAPSHOTS,
                    PIPELINE_SPECS["rtl/trace/cva6_rvfi_trace_adapter.sv"]["consumers"],
                    direct_raw_consumer="rvfi_valid_i",
                ),
                encoding="utf-8",
            )
            errors = run_checks(filelist)
            if not any("rvfi_valid_s, not rvfi_valid_i" in error for error in errors):
                print("[FAIL] self-test missed direct adapter raw input consumer", file=sys.stderr)
                return 1

            good_adapter.write_text(
                synthetic_pipelined_module(
                    "cva6_rvfi_trace_adapter",
                    ADAPTER_SNAPSHOTS,
                    PIPELINE_SPECS["rtl/trace/cva6_rvfi_trace_adapter.sv"]["consumers"],
                ),
                encoding="utf-8",
            )
            good_top.write_text(
                synthetic_pipelined_module(
                    "trace_top",
                    TRACE_TOP_SNAPSHOTS,
                    PIPELINE_SPECS["rtl/trace/trace_top.sv"]["consumers"],
                    pipeline_default=0,
                ),
                encoding="utf-8",
            )
            filelist.write_text(
                "rtl/trace/trace_top.sv\nrtl/trace/cva6_rvfi_trace_adapter.sv\n",
                encoding="utf-8",
            )
            errors = run_checks(filelist)
            if not any("default to 1" in error for error in errors):
                print("[FAIL] self-test missed disabled pipeline default", file=sys.stderr)
                return 1
        finally:
            os.chdir(cwd)

    print("[PASS] trace timing principles self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check rv-maltrace Phase 3.2 timing isolation principles.")
    parser.add_argument("--rtl-filelist", type=Path, default=DEFAULT_RTL_FILELIST)
    parser.add_argument("--self-test", action="store_true", help="Run negative coverage checks for the timing checker.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.rtl_filelist)
    except Exception as exc:
        print(f"check_timing_principles: error: {exc}", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    print("[PASS] trace timing principles: pipelined sideband capture, no backpressure ports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
